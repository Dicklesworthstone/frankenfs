#![forbid(unsafe_code)]

//! Statistically robust regression comparator with anti-flake hysteresis.
//!
//! Replaces simplistic threshold-only comparisons with a pipeline that:
//!
//! 1. Computes descriptive statistics (mean, std, CV) from multi-run samples.
//! 2. Estimates effect size (Cohen's d) to quantify regression magnitude.
//! 3. Performs Welch's t-test for statistical significance.
//! 4. Applies acceptance envelope classification (noise / ok / warn / fail).
//! 5. Uses hysteresis tracking to suppress transient flakes.
//!
//! # Contract version
//!
//! The current comparator version is [`COMPARATOR_VERSION`]. Any change to
//! the statistical model or classification logic MUST bump this version.

use crate::benchmark_taxonomy::{AcceptanceEnvelope, EnvelopeVerdict};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use tracing::{debug, info, warn};

/// Comparator contract version. Bump on any breaking change.
pub const COMPARATOR_VERSION: u32 = 1;

/// Minimum sample size for meaningful statistical comparison.
/// Below this, we fall back to simple threshold classification.
pub const MIN_SAMPLE_SIZE: usize = 3;

/// Default significance level (alpha) for Welch's t-test.
pub const DEFAULT_ALPHA: f64 = 0.05;

/// Default minimum effect size (Cohen's d) to consider meaningful.
/// 0.2 = "small effect" per Cohen's conventions.
pub const DEFAULT_MIN_EFFECT_SIZE: f64 = 0.2;

/// Default hysteresis window: must see regression in N of last M runs.
pub const DEFAULT_HYSTERESIS_REQUIRED: usize = 2;
pub const DEFAULT_HYSTERESIS_WINDOW: usize = 3;

// ── Descriptive statistics ───────────────────────────────────────────────

/// Descriptive statistics for a sample of measurements.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SampleStats {
    /// Number of observations.
    pub n: usize,
    /// Arithmetic mean.
    pub mean: f64,
    /// Sample standard deviation (Bessel-corrected, n-1 denominator).
    pub std_dev: f64,
    /// Coefficient of variation (std_dev / mean), expressed as percentage.
    pub cv_percent: f64,
    /// Minimum observed value.
    pub min: f64,
    /// Maximum observed value.
    pub max: f64,
    /// Median (p50).
    pub median: f64,
}

/// Compute descriptive statistics for a sample.
///
/// Returns `None` if the sample is empty.
#[must_use]
pub fn compute_stats(values: &[f64]) -> Option<SampleStats> {
    if values.is_empty() {
        return None;
    }

    let n = values.len();
    let sum: f64 = values.iter().sum();
    let mean = sum / n as f64;

    let variance = if n > 1 {
        values.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / (n - 1) as f64
    } else {
        0.0
    };
    let std_dev = variance.sqrt();

    let cv_percent = if mean.abs() > f64::EPSILON {
        (std_dev / mean.abs()) * 100.0
    } else {
        0.0
    };

    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let min = *sorted.first()?;
    let max = *sorted.last()?;
    let median = if n.is_multiple_of(2) {
        let lower = *sorted.get(n / 2 - 1)?;
        let upper = *sorted.get(n / 2)?;
        f64::midpoint(lower, upper)
    } else {
        *sorted.get(n / 2)?
    };

    Some(SampleStats {
        n,
        mean,
        std_dev,
        cv_percent,
        min,
        max,
        median,
    })
}

// ── Effect size ──────────────────────────────────────────────────────────

/// Cohen's d: standardized difference between two sample means.
///
/// Uses pooled standard deviation (appropriate for Welch-like comparisons).
/// Returns 0.0 if both standard deviations are zero.
///
/// Interpretation (Cohen's conventions):
/// - |d| < 0.2: negligible
/// - 0.2 <= |d| < 0.5: small
/// - 0.5 <= |d| < 0.8: medium
/// - |d| >= 0.8: large
#[must_use]
pub fn cohens_d(baseline: &SampleStats, current: &SampleStats) -> f64 {
    let pooled_var = if baseline.n + current.n > 2 {
        let df_b = (baseline.n - 1) as f64;
        let df_c = (current.n - 1) as f64;
        (df_b * baseline.std_dev.powi(2) + df_c * current.std_dev.powi(2)) / (df_b + df_c)
    } else {
        0.0
    };

    let pooled_sd = pooled_var.sqrt();
    if pooled_sd < f64::EPSILON {
        return 0.0;
    }

    (current.mean - baseline.mean) / pooled_sd
}

/// Human-readable effect size label.
#[must_use]
pub fn effect_size_label(d: f64) -> &'static str {
    let abs_d = d.abs();
    if abs_d < 0.2 {
        "negligible"
    } else if abs_d < 0.5 {
        "small"
    } else if abs_d < 0.8 {
        "medium"
    } else {
        "large"
    }
}

// ── Welch's t-test ──────────────────────────────────────────────────────

/// Result of a Welch's t-test.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TTestResult {
    /// Welch's t-statistic.
    pub t_stat: f64,
    /// Approximate degrees of freedom (Welch-Satterthwaite).
    pub df: f64,
    /// Approximate two-tailed p-value.
    pub p_value: f64,
}

/// Perform Welch's t-test (unequal variance, two-sample, two-tailed).
///
/// Returns `None` if either sample has fewer than 2 observations or both
/// have zero variance.
#[must_use]
pub fn welch_t_test(baseline: &SampleStats, current: &SampleStats) -> Option<TTestResult> {
    if baseline.n < 2 || current.n < 2 {
        return None;
    }

    let var_b = baseline.std_dev.powi(2);
    let var_c = current.std_dev.powi(2);
    let se_b = var_b / baseline.n as f64;
    let se_c = var_c / current.n as f64;

    let se_total = se_b + se_c;
    if se_total < f64::EPSILON {
        return None;
    }

    let t_stat = (current.mean - baseline.mean) / se_total.sqrt();

    // Welch-Satterthwaite degrees of freedom.
    let df_num = se_total.powi(2);
    let df_den = se_b.powi(2) / (baseline.n - 1) as f64 + se_c.powi(2) / (current.n - 1) as f64;

    let df = if df_den > f64::EPSILON {
        df_num / df_den
    } else {
        (baseline.n + current.n - 2) as f64
    };

    // Approximate two-tailed p-value using the t-distribution.
    let p_value = approx_t_p_value(t_stat.abs(), df);

    Some(TTestResult {
        t_stat,
        df,
        p_value,
    })
}

/// Approximate two-tailed p-value for a t-distribution.
///
/// Uses a rational approximation to the incomplete beta function. This is
/// sufficient for regression detection (we only need to distinguish
/// p < 0.05 from p >= 0.05 reliably).
#[must_use]
fn approx_t_p_value(t_abs: f64, df: f64) -> f64 {
    if df <= 0.0 {
        return 1.0;
    }
    // Use the relationship: p = I_{x}(df/2, 1/2) where x = df/(df + t^2)
    // For our purposes, a good approximation suffices.
    let x_val = df / t_abs.mul_add(t_abs, df);
    let p_one_tail = 0.5 * regularized_incomplete_beta(x_val, df / 2.0, 0.5);
    (2.0 * p_one_tail).min(1.0)
}

/// Regularized incomplete beta function I_x(a, b) via continued fraction.
///
/// Uses Lentz's method for the continued fraction representation.
/// Accurate to ~8 significant digits for typical regression test parameters.
#[allow(clippy::many_single_char_names)]
fn regularized_incomplete_beta(x_val: f64, alpha: f64, beta: f64) -> f64 {
    const MAX_ITER: usize = 200;
    const CONVERGENCE_EPS: f64 = 1e-14;
    const TINY: f64 = 1e-30;

    if x_val <= 0.0 {
        return 0.0;
    }
    if x_val >= 1.0 {
        return 1.0;
    }

    // Use the symmetry relation when x > (a+1)/(a+b+2) for convergence.
    let threshold = (alpha + 1.0) / (alpha + beta + 2.0);
    if x_val > threshold {
        return 1.0 - regularized_incomplete_beta(1.0 - x_val, beta, alpha);
    }

    // Continued fraction via Lentz's modified method.
    let ln_prefix =
        alpha.mul_add(x_val.ln(), beta * (1.0 - x_val).ln()) - ln_beta(alpha, beta) - alpha.ln();
    let prefix = ln_prefix.exp();

    let mut cf_c = 1.0;
    let mut cf_d = 1.0 - (alpha + beta) * x_val / (alpha + 1.0);
    if cf_d.abs() < TINY {
        cf_d = TINY;
    }
    cf_d = 1.0 / cf_d;
    let mut result = cf_d;

    for iter in 1..=MAX_ITER {
        let m_f64 = iter as f64;
        let two_m = 2.0 * m_f64;

        // Even step: d_{2m}
        let denom_even_lo = 2.0f64.mul_add(m_f64, alpha) - 1.0;
        let denom_even_hi = 2.0f64.mul_add(m_f64, alpha);
        let numerator_even = m_f64 * (beta - m_f64) * x_val / (denom_even_lo * denom_even_hi);
        cf_d = numerator_even.mul_add(cf_d, 1.0);
        if cf_d.abs() < TINY {
            cf_d = TINY;
        }
        cf_c = 1.0 + numerator_even / cf_c;
        if cf_c.abs() < TINY {
            cf_c = TINY;
        }
        cf_d = 1.0 / cf_d;
        result *= cf_d * cf_c;

        // Odd step: d_{2m+1}
        let denom_odd_lo = 2.0f64.mul_add(m_f64, alpha);
        let denom_odd_hi = two_m.mul_add(1.0, alpha + 1.0);
        let numerator_odd =
            -(alpha + m_f64) * (alpha + beta + m_f64) * x_val / (denom_odd_lo * denom_odd_hi);
        cf_d = numerator_odd.mul_add(cf_d, 1.0);
        if cf_d.abs() < TINY {
            cf_d = TINY;
        }
        cf_c = 1.0 + numerator_odd / cf_c;
        if cf_c.abs() < TINY {
            cf_c = TINY;
        }
        cf_d = 1.0 / cf_d;
        let delta = cf_d * cf_c;
        result *= delta;

        if (delta - 1.0).abs() < CONVERGENCE_EPS {
            break;
        }
    }

    prefix * result
}

/// Log of the Beta function: ln(B(a, b)) = ln(Gamma(a)) + ln(Gamma(b)) - ln(Gamma(a+b)).
fn ln_beta(alpha: f64, beta: f64) -> f64 {
    ln_gamma(alpha) + ln_gamma(beta) - ln_gamma(alpha + beta)
}

/// Stirling's approximation for ln(Gamma(x)) with Lanczos correction.
///
/// Accurate to ~15 significant digits for x > 0.5.
#[allow(clippy::excessive_precision)]
fn ln_gamma(val: f64) -> f64 {
    // Lanczos approximation (g=7, n=9).
    const COEFFS: [f64; 9] = [
        0.999_999_999_999_809_93,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_8,
        771.323_428_777_653_08,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];

    if val < 0.5 {
        // Reflection formula: Gamma(x) * Gamma(1-x) = pi / sin(pi*x)
        let pi = std::f64::consts::PI;
        return (pi / (pi * val).sin()).ln() - ln_gamma(1.0 - val);
    }

    let shifted = val - 1.0;
    let [first_coeff, rest_coeffs @ ..] = COEFFS;
    let mut sum = first_coeff;
    for (offset, coeff) in rest_coeffs.into_iter().enumerate() {
        let idx = offset + 1;
        sum += coeff / (shifted + idx as f64);
    }

    let tau = shifted + 7.5; // g + 0.5
    let half_ln2pi = 0.5 * (2.0 * std::f64::consts::PI).ln();
    (shifted + 0.5).mul_add(tau.ln(), half_ln2pi) - tau + sum.ln()
}

// ── Comparison result ────────────────────────────────────────────────────

/// Full comparison result for a single operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComparisonResult {
    /// Operation identifier (e.g., "metadata_parity_cli").
    pub operation_id: String,
    /// Baseline sample statistics.
    pub baseline: SampleStats,
    /// Current sample statistics.
    pub current: SampleStats,
    /// Percentage change: ((current.mean - baseline.mean) / baseline.mean) * 100.
    pub delta_percent: f64,
    /// Cohen's d effect size (positive = regression for latency).
    pub effect_size: f64,
    /// Human-readable effect size label.
    pub effect_label: &'static str,
    /// Welch's t-test result (None if samples too small).
    pub t_test: Option<TTestResult>,
    /// Whether the difference is statistically significant at the configured alpha.
    pub significant: bool,
    /// Envelope verdict from threshold classification.
    pub envelope_verdict: EnvelopeVerdict,
    /// Final verdict after applying effect size and significance gates.
    pub final_verdict: ComparisonVerdict,
    /// Human-readable explanation of the verdict.
    pub explanation: String,
}

/// Final verdict after full statistical analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonVerdict {
    /// No regression detected (noise, not significant, or small effect).
    Pass,
    /// Possible regression — statistically significant but small effect or
    /// within warning threshold.
    Warn,
    /// Confirmed regression — significant, meaningful effect, exceeds fail threshold.
    Fail,
    /// Insufficient data for statistical comparison (fell back to threshold only).
    Inconclusive,
}

// ── Regression comparator ────────────────────────────────────────────────

/// Configuration for the regression comparator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComparatorConfig {
    /// Significance level for Welch's t-test.
    pub alpha: f64,
    /// Minimum Cohen's d to consider a regression meaningful.
    pub min_effect_size: f64,
    /// Whether to require statistical significance for Warn/Fail.
    pub require_significance: bool,
}

impl Default for ComparatorConfig {
    fn default() -> Self {
        Self {
            alpha: DEFAULT_ALPHA,
            min_effect_size: DEFAULT_MIN_EFFECT_SIZE,
            require_significance: true,
        }
    }
}

/// Optional context for structured logging of comparison decisions.
///
/// Provides `benchmark_id`, `profile_id`, and `baseline_ref` fields that
/// appear in the comparison log event for post-mortem correlation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComparisonContext {
    /// Benchmark identifier (e.g., `"metadata_parity_cli"`).
    pub benchmark_id: String,
    /// Host profile used for threshold normalization (e.g., `"csd-threadripper"`).
    pub profile_id: String,
    /// Git ref or tag of the baseline measurement (e.g., `"v1.0.3"` or a commit SHA).
    pub baseline_ref: String,
}

/// Statistically robust regression comparator.
///
/// Combines envelope thresholds with effect size and significance testing
/// to reduce false positives from run-to-run noise.
pub struct RegressionComparator {
    config: ComparatorConfig,
}

impl RegressionComparator {
    #[must_use]
    pub fn new(config: ComparatorConfig) -> Self {
        Self { config }
    }

    /// Compare baseline and current samples for a single operation.
    ///
    /// The `envelope` provides family-aware thresholds. The statistical
    /// pipeline augments threshold classification with effect size and
    /// significance testing.
    #[must_use]
    pub fn compare(
        &self,
        operation_id: &str,
        baseline_values: &[f64],
        current_values: &[f64],
        envelope: &AcceptanceEnvelope,
    ) -> ComparisonResult {
        self.compare_with_context(
            operation_id,
            baseline_values,
            current_values,
            envelope,
            None,
        )
    }

    /// Compare with optional benchmark context for structured logging.
    ///
    /// When `ctx` is provided, the structured log includes `benchmark_id`,
    /// `profile_id`, and `baseline_ref` fields for post-mortem correlation.
    #[must_use]
    pub fn compare_with_context(
        &self,
        operation_id: &str,
        baseline_values: &[f64],
        current_values: &[f64],
        envelope: &AcceptanceEnvelope,
        ctx: Option<&ComparisonContext>,
    ) -> ComparisonResult {
        let baseline = compute_stats(baseline_values).unwrap_or(SampleStats {
            n: 0,
            mean: 0.0,
            std_dev: 0.0,
            cv_percent: 0.0,
            min: 0.0,
            max: 0.0,
            median: 0.0,
        });
        let current = compute_stats(current_values).unwrap_or(SampleStats {
            n: 0,
            mean: 0.0,
            std_dev: 0.0,
            cv_percent: 0.0,
            min: 0.0,
            max: 0.0,
            median: 0.0,
        });

        let delta_percent = if baseline.mean.abs() > f64::EPSILON {
            ((current.mean - baseline.mean) / baseline.mean) * 100.0
        } else {
            0.0
        };

        let effect_size = if baseline.n >= 2 && current.n >= 2 {
            cohens_d(&baseline, &current)
        } else {
            0.0
        };
        let effect_label = effect_size_label(effect_size);

        let t_test = if baseline.n >= MIN_SAMPLE_SIZE && current.n >= MIN_SAMPLE_SIZE {
            welch_t_test(&baseline, &current)
        } else {
            None
        };

        let significant = t_test.is_some_and(|t| t.p_value < self.config.alpha);

        let envelope_verdict = envelope.classify(delta_percent);

        // Determine final verdict by combining envelope + statistics.
        let (final_verdict, explanation) = self.determine_verdict(
            operation_id,
            delta_percent,
            effect_size,
            significant,
            envelope_verdict,
            &baseline,
            &current,
        );

        let benchmark_id = ctx.map_or("", |c| c.benchmark_id.as_str());
        let profile_id = ctx.map_or("", |c| c.profile_id.as_str());
        let baseline_ref = ctx.map_or("", |c| c.baseline_ref.as_str());
        debug!(
            operation_id,
            benchmark_id,
            profile_id,
            baseline_ref,
            delta_percent,
            effect_size,
            effect_label,
            ?envelope_verdict,
            ?final_verdict,
            significant,
            "regression comparison complete"
        );

        ComparisonResult {
            operation_id: operation_id.to_owned(),
            baseline,
            current,
            delta_percent,
            effect_size,
            effect_label,
            t_test,
            significant,
            envelope_verdict,
            final_verdict,
            explanation,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn determine_verdict(
        &self,
        operation_id: &str,
        delta_percent: f64,
        effect_size: f64,
        significant: bool,
        envelope_verdict: EnvelopeVerdict,
        baseline: &SampleStats,
        current: &SampleStats,
    ) -> (ComparisonVerdict, String) {
        // Case 1: Below noise floor — always pass.
        if envelope_verdict == EnvelopeVerdict::Noise {
            return (
                ComparisonVerdict::Pass,
                format!("{operation_id}: delta {delta_percent:.1}% within noise floor — pass"),
            );
        }

        // Case 2: Insufficient data — fall back to threshold only.
        if baseline.n < MIN_SAMPLE_SIZE || current.n < MIN_SAMPLE_SIZE {
            let verdict = match envelope_verdict {
                EnvelopeVerdict::Fail => ComparisonVerdict::Fail,
                EnvelopeVerdict::Warn => ComparisonVerdict::Warn,
                _ => ComparisonVerdict::Inconclusive,
            };
            return (
                verdict,
                format!(
                    "{operation_id}: insufficient samples (baseline={}, current={}) — \
                     envelope says {envelope_verdict:?}, marking {verdict:?}",
                    baseline.n, current.n,
                ),
            );
        }

        // Case 3: Not statistically significant — downgrade to Pass.
        if self.config.require_significance && !significant {
            let p_str = Self::format_p_value(baseline, current);
            return (
                ComparisonVerdict::Pass,
                format!(
                    "{operation_id}: delta {delta_percent:.1}% not statistically significant \
                     ({p_str}) — pass despite envelope={envelope_verdict:?}"
                ),
            );
        }

        // Case 4: Significant but effect size is negligible — downgrade to Pass.
        if effect_size.abs() < self.config.min_effect_size {
            return (
                ComparisonVerdict::Pass,
                format!(
                    "{operation_id}: delta {delta_percent:.1}% significant but effect size \
                     {effect_size:.3} ({}) is below threshold {:.1} — pass",
                    effect_size_label(effect_size),
                    self.config.min_effect_size,
                ),
            );
        }

        // Case 5: Significant + meaningful effect — use envelope verdict.
        match envelope_verdict {
            EnvelopeVerdict::Fail => (
                ComparisonVerdict::Fail,
                format!(
                    "{operation_id}: REGRESSION delta={delta_percent:.1}% \
                     effect_size={effect_size:.2} ({}) p<{:.2} — FAIL",
                    effect_size_label(effect_size),
                    self.config.alpha,
                ),
            ),
            EnvelopeVerdict::Warn => (
                ComparisonVerdict::Warn,
                format!(
                    "{operation_id}: possible regression delta={delta_percent:.1}% \
                     effect_size={effect_size:.2} ({}) p<{:.2} — WARN",
                    effect_size_label(effect_size),
                    self.config.alpha,
                ),
            ),
            EnvelopeVerdict::Ok => (
                ComparisonVerdict::Pass,
                format!("{operation_id}: delta {delta_percent:.1}% within threshold — pass"),
            ),
            EnvelopeVerdict::Noise => unreachable!("handled above"),
        }
    }

    fn format_p_value(baseline: &SampleStats, current: &SampleStats) -> String {
        welch_t_test(baseline, current)
            .map_or_else(|| "p=N/A".to_owned(), |t| format!("p={:.4}", t.p_value))
    }
}

// ── Hysteresis tracker ───────────────────────────────────────────────────

/// Anti-flake hysteresis tracker for a single operation.
///
/// Maintains a sliding window of recent verdicts and only confirms a
/// regression when the threshold count is met within the window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HysteresisTracker {
    /// Operation this tracker covers.
    pub operation_id: String,
    /// Sliding window of recent comparison verdicts.
    pub recent_verdicts: VecDeque<ComparisonVerdict>,
    /// Window size (how many recent runs to consider).
    pub window_size: usize,
    /// How many Warn/Fail verdicts within the window to confirm.
    pub required_count: usize,
}

/// Hysteresis-aware final verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HystereticVerdict {
    /// No regression signal (or insufficient history).
    NoSignal,
    /// Single-run warning, not yet confirmed by hysteresis.
    EarlyWarning,
    /// Warning confirmed by multiple consecutive runs.
    ConfirmedWarn,
    /// Failure confirmed by multiple consecutive runs.
    ConfirmedFail,
}

impl HysteresisTracker {
    /// Create a new tracker with the given window size and confirmation count.
    #[must_use]
    pub fn new(operation_id: &str, window_size: usize, required_count: usize) -> Self {
        Self {
            operation_id: operation_id.to_owned(),
            recent_verdicts: VecDeque::with_capacity(window_size),
            window_size,
            required_count,
        }
    }

    /// Create a tracker with default hysteresis parameters.
    #[must_use]
    pub fn with_defaults(operation_id: &str) -> Self {
        Self::new(
            operation_id,
            DEFAULT_HYSTERESIS_WINDOW,
            DEFAULT_HYSTERESIS_REQUIRED,
        )
    }

    /// Record a new comparison verdict and return the hysteresis-aware result.
    pub fn record(&mut self, verdict: ComparisonVerdict) -> HystereticVerdict {
        // Maintain window size.
        while self.recent_verdicts.len() >= self.window_size {
            self.recent_verdicts.pop_front();
        }
        self.recent_verdicts.push_back(verdict);

        let fail_count = self
            .recent_verdicts
            .iter()
            .filter(|v| **v == ComparisonVerdict::Fail)
            .count();
        let warn_count = self
            .recent_verdicts
            .iter()
            .filter(|v| **v == ComparisonVerdict::Warn)
            .count();
        let problem_count = fail_count + warn_count;

        if fail_count >= self.required_count {
            info!(
                operation_id = %self.operation_id,
                fail_count,
                window_size = self.window_size,
                "hysteresis confirmed FAIL"
            );
            HystereticVerdict::ConfirmedFail
        } else if problem_count >= self.required_count {
            warn!(
                operation_id = %self.operation_id,
                warn_count,
                fail_count,
                window_size = self.window_size,
                "hysteresis confirmed WARN"
            );
            HystereticVerdict::ConfirmedWarn
        } else if verdict == ComparisonVerdict::Warn || verdict == ComparisonVerdict::Fail {
            debug!(
                operation_id = %self.operation_id,
                ?verdict,
                problem_count,
                required = self.required_count,
                "early warning — not yet confirmed"
            );
            HystereticVerdict::EarlyWarning
        } else {
            HystereticVerdict::NoSignal
        }
    }

    /// Reset the tracker (e.g., after a baseline update).
    pub fn reset(&mut self) {
        self.recent_verdicts.clear();
    }
}

// ── Human-readable report ────────────────────────────────────────────────

/// Format a comparison result as a human-readable report line.
///
/// Output format:
/// ```text
/// [PASS] metadata_parity_cli: +3.2% (d=0.15 negligible, p=0.42) — within noise floor
/// [WARN] wal_commit_1: +18.5% (d=0.65 medium, p=0.003) — possible regression
/// [FAIL] scrub_clean_256blocks: +32.1% (d=1.20 large, p<0.001) — REGRESSION
/// ```
#[must_use]
pub fn format_report_line(result: &ComparisonResult) -> String {
    let verdict_tag = match result.final_verdict {
        ComparisonVerdict::Pass => "PASS",
        ComparisonVerdict::Warn => "WARN",
        ComparisonVerdict::Fail => "FAIL",
        ComparisonVerdict::Inconclusive => "INCONCLUSIVE",
    };

    let p_str = result.t_test.map_or_else(
        || "p=N/A".to_owned(),
        |t| {
            if t.p_value < 0.001 {
                "p<0.001".to_owned()
            } else {
                format!("p={:.3}", t.p_value)
            }
        },
    );

    format!(
        "[{verdict_tag}] {}: {:+.1}% (d={:.2} {}, {p_str}) — {}",
        result.operation_id,
        result.delta_percent,
        result.effect_size,
        result.effect_label,
        result.explanation.split(" — ").last().unwrap_or(""),
    )
}

/// Format a full comparison report for multiple operations.
#[must_use]
pub fn format_full_report(results: &[ComparisonResult]) -> String {
    let mut lines = Vec::with_capacity(results.len() + 5);
    lines.push(format!(
        "Performance Regression Report (comparator v{COMPARATOR_VERSION})"
    ));
    lines.push("=".repeat(72));

    let pass_count = results
        .iter()
        .filter(|r| r.final_verdict == ComparisonVerdict::Pass)
        .count();
    let warn_count = results
        .iter()
        .filter(|r| r.final_verdict == ComparisonVerdict::Warn)
        .count();
    let fail_count = results
        .iter()
        .filter(|r| r.final_verdict == ComparisonVerdict::Fail)
        .count();
    let inconclusive_count = results
        .iter()
        .filter(|r| r.final_verdict == ComparisonVerdict::Inconclusive)
        .count();

    lines.push(format!(
        "Summary: {pass_count} pass, {warn_count} warn, \
         {fail_count} fail, {inconclusive_count} inconclusive"
    ));
    lines.push(String::new());

    for result in results {
        lines.push(format_report_line(result));
    }

    lines.join("\n")
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result};

    // ── compute_stats tests ──────────────────────────────────────────

    #[test]
    fn stats_empty_returns_none() {
        assert!(compute_stats(&[]).is_none());
    }

    #[test]
    fn stats_single_value() -> Result<()> {
        let stats = sample_stats(&[42.0])?;
        assert_eq!(stats.n, 1);
        assert!((stats.mean - 42.0).abs() < f64::EPSILON);
        assert!((stats.std_dev - 0.0).abs() < f64::EPSILON);
        assert!((stats.median - 42.0).abs() < f64::EPSILON);
        Ok(())
    }

    #[test]
    fn stats_known_values() -> Result<()> {
        // Mean=5.0, std_dev=sqrt(2.5) ≈ 1.5811
        let stats = sample_stats(&[3.0, 4.0, 5.0, 6.0, 7.0])?;
        assert_eq!(stats.n, 5);
        assert!((stats.mean - 5.0).abs() < 1e-10);
        assert!((stats.std_dev - 2.5_f64.sqrt()).abs() < 1e-10);
        assert!((stats.median - 5.0).abs() < f64::EPSILON);
        assert!((stats.min - 3.0).abs() < f64::EPSILON);
        assert!((stats.max - 7.0).abs() < f64::EPSILON);
        Ok(())
    }

    #[test]
    fn stats_even_count_median() -> Result<()> {
        let stats = sample_stats(&[1.0, 2.0, 3.0, 4.0])?;
        assert!((stats.median - 2.5).abs() < f64::EPSILON);
        Ok(())
    }

    #[test]
    fn stats_cv_percent_is_correct() -> Result<()> {
        let stats = sample_stats(&[100.0, 100.0, 100.0])?;
        assert!((stats.cv_percent - 0.0).abs() < f64::EPSILON);

        // CV = std/mean * 100
        let stats = sample_stats(&[90.0, 100.0, 110.0])?;
        assert!(stats.cv_percent > 0.0);
        Ok(())
    }

    // ── Cohen's d tests ──────────────────────────────────────────────

    #[test]
    fn cohens_d_identical_samples() -> Result<()> {
        let s = sample_stats(&[10.0, 10.0, 10.0, 10.0])?;
        let d = cohens_d(&s, &s);
        assert!((d - 0.0).abs() < f64::EPSILON);
        Ok(())
    }

    #[test]
    fn cohens_d_known_large_effect() -> Result<()> {
        let baseline = sample_stats(&[100.0, 100.0, 100.0, 100.0, 100.0])?;
        let current = sample_stats(&[120.0, 120.0, 120.0, 120.0, 120.0])?;
        // Both have std_dev ≈ 0, so d is very large (or infinite).
        // With equal values, std_dev = 0 → d = 0 (our guard).
        let d = cohens_d(&baseline, &current);
        // Both samples have zero variance → pooled_sd = 0 → d = 0.
        assert!((d - 0.0).abs() < f64::EPSILON);
        Ok(())
    }

    #[test]
    fn cohens_d_with_variance() -> Result<()> {
        let baseline = sample_stats(&[100.0, 102.0, 98.0, 101.0, 99.0])?;
        let current = sample_stats(&[110.0, 112.0, 108.0, 111.0, 109.0])?;
        let d = cohens_d(&baseline, &current);
        // Both have similar std_dev (~1.58), difference in means = 10.
        // d ≈ 10 / 1.58 ≈ 6.3 — a very large effect.
        assert!(d > 5.0, "expected large effect, got d={d}");
        assert_eq!(effect_size_label(d), "large");
        Ok(())
    }

    #[test]
    fn cohens_d_small_effect() -> Result<()> {
        let baseline = sample_stats(&[100.0, 105.0, 95.0, 102.0, 98.0])?;
        let current = sample_stats(&[101.0, 106.0, 96.0, 103.0, 99.0])?;
        let d = cohens_d(&baseline, &current);
        // Means differ by ~1, std_dev ~3.5 → d ≈ 0.28 (small).
        assert!(d > 0.0, "expected positive d");
        assert!(d < 0.5, "expected small effect, got d={d}");
        Ok(())
    }

    #[test]
    fn effect_size_labels_correct() {
        assert_eq!(effect_size_label(0.0), "negligible");
        assert_eq!(effect_size_label(0.1), "negligible");
        assert_eq!(effect_size_label(0.2), "small");
        assert_eq!(effect_size_label(0.49), "small");
        assert_eq!(effect_size_label(0.5), "medium");
        assert_eq!(effect_size_label(0.79), "medium");
        assert_eq!(effect_size_label(0.8), "large");
        assert_eq!(effect_size_label(2.0), "large");
        assert_eq!(effect_size_label(-0.5), "medium");
    }

    // ── Welch's t-test tests ─────────────────────────────────────────

    #[test]
    fn t_test_too_small_samples() -> Result<()> {
        let s1 = sample_stats(&[1.0])?;
        let s2 = sample_stats(&[2.0, 3.0])?;
        assert!(welch_t_test(&s1, &s2).is_none());
        Ok(())
    }

    #[test]
    fn t_test_identical_samples_high_p() -> Result<()> {
        let s = sample_stats(&[10.0, 11.0, 9.0, 10.5, 9.5])?;
        let result = t_test(&s, &s)?;
        assert!(
            result.p_value > 0.9,
            "identical samples should have p ≈ 1.0, got {}",
            result.p_value,
        );
        Ok(())
    }

    #[test]
    fn t_test_clearly_different_samples_low_p() -> Result<()> {
        let baseline = sample_stats(&[100.0, 101.0, 99.0, 100.5, 99.5])?;
        let current = sample_stats(&[120.0, 121.0, 119.0, 120.5, 119.5])?;
        let result = t_test(&baseline, &current)?;
        assert!(
            result.p_value < 0.001,
            "clearly different samples should have p < 0.001, got {}",
            result.p_value,
        );
        Ok(())
    }

    #[test]
    fn t_test_symmetry() -> Result<()> {
        let s1 = sample_stats(&[100.0, 102.0, 98.0, 101.0, 99.0])?;
        let s2 = sample_stats(&[105.0, 107.0, 103.0, 106.0, 104.0])?;
        let r1 = t_test(&s1, &s2)?;
        let r2 = t_test(&s2, &s1)?;
        assert!(
            (r1.p_value - r2.p_value).abs() < 1e-10,
            "t-test should be symmetric in p-value",
        );
        assert!(
            (r1.t_stat + r2.t_stat).abs() < 1e-10,
            "t-test t_stat should flip sign",
        );
        Ok(())
    }

    fn sample_stats(values: &[f64]) -> Result<SampleStats> {
        compute_stats(values).context("sample stats")
    }

    fn t_test(baseline: &SampleStats, current: &SampleStats) -> Result<TTestResult> {
        welch_t_test(baseline, current).context("welch t-test result")
    }

    // ── ln_gamma accuracy ────────────────────────────────────────────

    #[test]
    fn ln_gamma_known_values() {
        // Gamma(1) = 0! = 1 → ln(1) = 0
        assert!((ln_gamma(1.0) - 0.0).abs() < 1e-10);
        // Gamma(2) = 1! = 1 → ln(1) = 0
        assert!((ln_gamma(2.0) - 0.0).abs() < 1e-10);
        // Gamma(3) = 2! = 2 → ln(2) ≈ 0.6931
        assert!((ln_gamma(3.0) - 2.0_f64.ln()).abs() < 1e-10);
        // Gamma(5) = 4! = 24 → ln(24) ≈ 3.178
        assert!((ln_gamma(5.0) - 24.0_f64.ln()).abs() < 1e-8);
    }

    // ── RegressionComparator tests ───────────────────────────────────

    fn test_envelope() -> AcceptanceEnvelope {
        AcceptanceEnvelope {
            warn_percent: 10.0,
            fail_percent: 20.0,
            noise_floor_percent: 5.0,
            rationale: "test envelope",
        }
    }

    #[test]
    fn comparator_noise_floor_passes() {
        let comparator = RegressionComparator::new(ComparatorConfig::default());
        let baseline = &[100.0, 100.5, 99.5, 100.2, 99.8];
        let current = &[102.0, 102.5, 101.5, 102.2, 101.8]; // ~2% delta

        let result = comparator.compare("test_op", baseline, current, &test_envelope());
        assert_eq!(result.final_verdict, ComparisonVerdict::Pass);
        assert!(result.delta_percent < 5.0);
    }

    #[test]
    fn comparator_significant_large_regression_fails() {
        let comparator = RegressionComparator::new(ComparatorConfig::default());
        let baseline = &[
            100.0, 101.0, 99.0, 100.5, 99.5, 100.2, 99.8, 100.3, 99.7, 100.1,
        ];
        let current = &[
            130.0, 131.0, 129.0, 130.5, 129.5, 130.2, 129.8, 130.3, 129.7, 130.1,
        ];

        let result = comparator.compare("test_op", baseline, current, &test_envelope());
        assert_eq!(result.final_verdict, ComparisonVerdict::Fail);
        assert!(result.delta_percent > 20.0);
        assert!(result.significant);
        assert!(result.effect_size > 0.8);
    }

    #[test]
    fn comparator_not_significant_passes_despite_delta() {
        let comparator = RegressionComparator::new(ComparatorConfig::default());
        // High variance samples where the mean difference is within noise.
        let baseline = &[80.0, 120.0, 90.0, 110.0, 100.0];
        let current = &[90.0, 130.0, 100.0, 120.0, 110.0]; // ~10% higher mean

        let result = comparator.compare("test_op", baseline, current, &test_envelope());
        // With high variance, 10% shift should not be significant.
        assert_eq!(
            result.final_verdict,
            ComparisonVerdict::Pass,
            "high-variance 10% shift should not be significant: {}",
            result.explanation,
        );
    }

    #[test]
    fn comparator_insufficient_samples_inconclusive() {
        let comparator = RegressionComparator::new(ComparatorConfig::default());
        let baseline = &[100.0, 101.0]; // < MIN_SAMPLE_SIZE
        let current = &[130.0, 131.0]; // 30% regression but too few samples

        let result = comparator.compare("test_op", baseline, current, &test_envelope());
        // With 2 samples, can't do t-test → falls back to envelope.
        // 30% delta > 20% fail threshold → Fail (even without stats).
        assert_eq!(result.final_verdict, ComparisonVerdict::Fail);
    }

    #[test]
    fn comparator_warn_zone_with_significance() {
        let comparator = RegressionComparator::new(ComparatorConfig::default());
        let baseline = &[
            100.0, 100.5, 99.5, 100.2, 99.8, 100.1, 99.9, 100.3, 99.7, 100.0,
        ];
        // ~15% higher mean — warn zone (10-20%)
        let current = &[
            115.0, 115.5, 114.5, 115.2, 114.8, 115.1, 114.9, 115.3, 114.7, 115.0,
        ];

        let result = comparator.compare("test_op", baseline, current, &test_envelope());
        assert_eq!(result.final_verdict, ComparisonVerdict::Warn);
        assert!(result.significant);
    }

    #[test]
    fn comparator_negligible_effect_passes() {
        let comparator = RegressionComparator::new(ComparatorConfig {
            min_effect_size: 0.5, // Require medium effect.
            ..ComparatorConfig::default()
        });
        // Small but significant shift with very low variance.
        let baseline = &[100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0];
        let current = &[100.1, 100.1, 100.1, 100.1, 100.1, 100.1, 100.1, 100.1];

        let result = comparator.compare(
            "test_op",
            baseline,
            current,
            &AcceptanceEnvelope {
                warn_percent: 0.05,
                fail_percent: 0.1,
                noise_floor_percent: 0.01,
                rationale: "very tight",
            },
        );
        // Even though envelope says Fail (0.1% > 0.1% fail), effect is tiny.
        // But zero variance means cohens_d returns 0 (guard), so effect gate catches it.
        assert_eq!(result.final_verdict, ComparisonVerdict::Pass);
    }

    // ── Hysteresis tracker tests ─────────────────────────────────────

    #[test]
    fn hysteresis_single_fail_is_early_warning() {
        let mut tracker = HysteresisTracker::with_defaults("test_op");
        let verdict = tracker.record(ComparisonVerdict::Fail);
        assert_eq!(verdict, HystereticVerdict::EarlyWarning);
    }

    #[test]
    fn hysteresis_two_fails_in_window_confirmed() {
        let mut tracker = HysteresisTracker::with_defaults("test_op");
        tracker.record(ComparisonVerdict::Fail);
        let verdict = tracker.record(ComparisonVerdict::Fail);
        assert_eq!(verdict, HystereticVerdict::ConfirmedFail);
    }

    #[test]
    fn hysteresis_fail_then_pass_then_fail_confirmed() {
        let mut tracker = HysteresisTracker::with_defaults("test_op");
        tracker.record(ComparisonVerdict::Fail);
        tracker.record(ComparisonVerdict::Pass);
        let verdict = tracker.record(ComparisonVerdict::Fail);
        // Window=[Fail, Pass, Fail] → 2 fails in window of 3 → confirmed.
        assert_eq!(verdict, HystereticVerdict::ConfirmedFail);
    }

    #[test]
    fn hysteresis_pass_clears_signal() {
        let mut tracker = HysteresisTracker::with_defaults("test_op");
        tracker.record(ComparisonVerdict::Fail);
        tracker.record(ComparisonVerdict::Pass);
        let verdict = tracker.record(ComparisonVerdict::Pass);
        // Window=[Fail, Pass, Pass] → only 1 fail → no signal.
        assert_eq!(verdict, HystereticVerdict::NoSignal);
    }

    #[test]
    fn hysteresis_warn_plus_fail_confirms_warn() {
        let mut tracker = HysteresisTracker::with_defaults("test_op");
        tracker.record(ComparisonVerdict::Warn);
        let verdict = tracker.record(ComparisonVerdict::Warn);
        // 2 warns → confirmed warn (not confirmed fail since fail_count < required).
        assert_eq!(verdict, HystereticVerdict::ConfirmedWarn);
    }

    #[test]
    fn hysteresis_window_evicts_old() {
        let mut tracker = HysteresisTracker::new("test_op", 3, 2);
        tracker.record(ComparisonVerdict::Fail);
        tracker.record(ComparisonVerdict::Fail); // confirmed
        tracker.record(ComparisonVerdict::Pass); // window=[Fail, Pass]... no, window=[Fail, Fail, Pass] → evicts first
        // After 3rd: window=[Fail, Fail, Pass] → 2 fails → still confirmed.
        // After 4th Pass: window=[Fail, Pass, Pass] → 1 fail → early warning? No, Pass.
        let verdict = tracker.record(ComparisonVerdict::Pass);
        // Window is now [Fail, Pass, Pass] (first Fail was evicted).
        assert_eq!(verdict, HystereticVerdict::NoSignal);
    }

    #[test]
    fn hysteresis_reset_clears_history() {
        let mut tracker = HysteresisTracker::with_defaults("test_op");
        tracker.record(ComparisonVerdict::Fail);
        tracker.record(ComparisonVerdict::Fail);
        tracker.reset();
        let verdict = tracker.record(ComparisonVerdict::Fail);
        assert_eq!(verdict, HystereticVerdict::EarlyWarning);
    }

    #[test]
    fn hysteresis_tracker_json_round_trip_preserves_window_order() -> Result<(), serde_json::Error>
    {
        let mut tracker = HysteresisTracker::new("metadata_parity_cli", 3, 2);
        tracker.record(ComparisonVerdict::Warn);
        tracker.record(ComparisonVerdict::Pass);
        tracker.record(ComparisonVerdict::Fail);
        tracker.record(ComparisonVerdict::Fail);

        let json = serde_json::to_string_pretty(&tracker)?;
        insta::assert_snapshot!("hysteresis_tracker_json_shape", json);
        let parsed: HysteresisTracker = serde_json::from_str(&json)?;

        assert_eq!(parsed, tracker);
        assert_eq!(
            parsed.recent_verdicts.into_iter().collect::<Vec<_>>(),
            vec![
                ComparisonVerdict::Pass,
                ComparisonVerdict::Fail,
                ComparisonVerdict::Fail
            ]
        );
        Ok(())
    }

    // ── Report formatting tests ──────────────────────────────────────

    #[test]
    fn report_line_format() {
        let comparator = RegressionComparator::new(ComparatorConfig::default());
        let baseline = &[100.0, 100.5, 99.5, 100.2, 99.8];
        let current = &[100.0, 100.5, 99.5, 100.2, 99.8]; // identical

        let result = comparator.compare("test_op", baseline, current, &test_envelope());
        let line = format_report_line(&result);
        assert!(line.starts_with("[PASS]"));
        assert!(line.contains("test_op"));
    }

    #[test]
    fn full_report_has_summary() {
        let comparator = RegressionComparator::new(ComparatorConfig::default());
        let results = vec![comparator.compare(
            "op_a",
            &[100.0, 100.0, 100.0, 100.0, 100.0],
            &[100.0, 100.0, 100.0, 100.0, 100.0],
            &test_envelope(),
        )];
        let report = format_full_report(&results);
        assert!(report.contains("Performance Regression Report"));
        assert!(report.contains("1 pass"));
    }

    /// bd-by4bc — golden-output snapshot for `format_full_report` on the
    /// most stable case (single all-PASS result with delta=0%, zero variance,
    /// p_value branch = "p=N/A"). Pins the title, the 72-char "=" separator,
    /// the summary clause structure, and the per-result line shape so any
    /// silent drift in the human-readable perf report is caught immediately.
    /// Substring assertions in `full_report_has_summary` and
    /// `report_line_format` cannot detect such drift.
    #[test]
    fn full_report_pass_only_snapshot() {
        let comparator = RegressionComparator::new(ComparatorConfig::default());
        let result = comparator.compare(
            "op_pass",
            &[100.0, 100.0, 100.0, 100.0, 100.0],
            &[100.0, 100.0, 100.0, 100.0, 100.0],
            &test_envelope(),
        );
        let report = format_full_report(&[result]);
        insta::assert_snapshot!("full_report_pass_only", report);
    }

    /// bd-m8tc7 — golden-output snapshot for `format_full_report`
    /// with all four ComparisonVerdict variants present. The
    /// existing `full_report_pass_only_snapshot` covers the single
    /// PASS path but the multi-result summary line ("Summary:
    /// {pass} pass, {warn} warn, {fail} fail, {inconclusive}
    /// inconclusive") with NON-zero counts in each category is
    /// uncovered. A regression that swapped any two count labels
    /// (e.g., "warn"→"warning"), reordered the summary categories,
    /// or broke the multi-line layout would silently break
    /// downstream report parsers but pass the four
    /// `report_line_*_snapshot` tests (which only cover individual
    /// lines). Reuses the deterministic fixtures from each verdict
    /// branch's per-line snapshot.
    #[test]
    fn full_report_mixed_verdicts_snapshot() {
        let comparator = RegressionComparator::new(ComparatorConfig::default());
        let pass = comparator.compare(
            "op_pass",
            &[100.0, 100.0, 100.0, 100.0, 100.0],
            &[100.0, 100.0, 100.0, 100.0, 100.0],
            &test_envelope(),
        );
        assert_eq!(pass.final_verdict, ComparisonVerdict::Pass);
        let warn = comparator.compare(
            "op_warn",
            &[
                100.0, 100.5, 99.5, 100.2, 99.8, 100.1, 99.9, 100.3, 99.7, 100.0,
            ],
            &[
                115.0, 115.5, 114.5, 115.2, 114.8, 115.1, 114.9, 115.3, 114.7, 115.0,
            ],
            &test_envelope(),
        );
        assert_eq!(warn.final_verdict, ComparisonVerdict::Warn);
        let fail = comparator.compare(
            "op_fail",
            &[100.0, 101.0],
            &[130.0, 131.0],
            &test_envelope(),
        );
        assert_eq!(fail.final_verdict, ComparisonVerdict::Fail);
        let inconclusive = comparator.compare(
            "op_inconclusive",
            &[100.0, 101.0],
            &[107.0, 108.0],
            &test_envelope(),
        );
        assert_eq!(inconclusive.final_verdict, ComparisonVerdict::Inconclusive);

        let report = format_full_report(&[pass, warn, fail, inconclusive]);
        insta::assert_snapshot!("full_report_mixed_verdicts", report);
    }

    /// bd-by4bc — golden-output snapshot for a single `format_report_line`
    /// invocation. Independent of the full-report wrapper so future drift
    /// in the line shape (verdict tag dictionary, percent precision, effect
    /// label, p-value branch, " — " explanation suffix) is pinned even when
    /// `format_full_report` itself is unchanged.
    #[test]
    fn report_line_pass_snapshot() {
        let comparator = RegressionComparator::new(ComparatorConfig::default());
        let result = comparator.compare(
            "op_pass",
            &[100.0, 100.0, 100.0, 100.0, 100.0],
            &[100.0, 100.0, 100.0, 100.0, 100.0],
            &test_envelope(),
        );
        let line = format_report_line(&result);
        insta::assert_snapshot!("report_line_pass", line);
    }

    /// bd-cjg3l — golden-output snapshot for the FAIL verdict branch of
    /// `format_report_line`. The PASS-only snapshot at
    /// `report_line_pass_snapshot` cannot detect a regression that
    /// swapped the FAIL/WARN/INCONCLUSIVE tag dictionary, broke the
    /// p<0.001 / p=N/A formatter, or misrouted the explanation
    /// suffix on the regression code path. Reuses the deterministic
    /// inputs from `comparator_insufficient_samples_inconclusive`
    /// (baseline=[100.0, 101.0], current=[130.0, 131.0]) which yield
    /// a stable +29.9% delta, t_test=None (insufficient samples →
    /// p=N/A branch), and a Fail verdict via the envelope fallback.
    #[test]
    fn report_line_fail_snapshot() {
        let comparator = RegressionComparator::new(ComparatorConfig::default());
        let result = comparator.compare(
            "op_fail",
            &[100.0, 101.0],
            &[130.0, 131.0],
            &test_envelope(),
        );
        assert_eq!(
            result.final_verdict,
            ComparisonVerdict::Fail,
            "fixture must reach the FAIL branch"
        );
        let line = format_report_line(&result);
        insta::assert_snapshot!("report_line_fail", line);
    }

    /// bd-2hfj9 — golden-output snapshot for the INCONCLUSIVE verdict
    /// branch of `format_report_line`. Completes the four-verdict
    /// coverage trio (PASS/WARN/FAIL/INCONCLUSIVE). Inconclusive is
    /// reached when sample counts are below MIN_SAMPLE_SIZE AND the
    /// envelope verdict is Pass (delta in (noise_floor, warn_percent]).
    /// Uses baseline=[100,101] / current=[107,108] (n=2, ~7% delta)
    /// which yields a stable Inconclusive via the envelope fallback.
    #[test]
    fn report_line_inconclusive_snapshot() {
        let comparator = RegressionComparator::new(ComparatorConfig::default());
        let result = comparator.compare(
            "op_inconclusive",
            &[100.0, 101.0],
            &[107.0, 108.0],
            &test_envelope(),
        );
        assert_eq!(
            result.final_verdict,
            ComparisonVerdict::Inconclusive,
            "fixture must reach the INCONCLUSIVE branch"
        );
        let line = format_report_line(&result);
        insta::assert_snapshot!("report_line_inconclusive", line);
    }

    /// bd-pwyiy — golden-output snapshot for the WARN verdict branch
    /// of `format_report_line`. Pairs with `report_line_pass_snapshot`
    /// and `report_line_fail_snapshot` to cover three of the four
    /// ComparisonVerdict tag mappings (Inconclusive covered by
    /// bd-2hfj9 above).
    /// Reuses the deterministic 10-sample inputs from
    /// `comparator_warn_zone_with_significance` which yield a stable
    /// ~+15% delta with high t-test significance, exercising the
    /// p<0.001 formatter branch (vs the p=N/A branch covered by the
    /// PASS and FAIL snapshots).
    #[test]
    fn report_line_warn_snapshot() {
        let comparator = RegressionComparator::new(ComparatorConfig::default());
        let baseline = &[
            100.0, 100.5, 99.5, 100.2, 99.8, 100.1, 99.9, 100.3, 99.7, 100.0,
        ];
        let current = &[
            115.0, 115.5, 114.5, 115.2, 114.8, 115.1, 114.9, 115.3, 114.7, 115.0,
        ];
        let result = comparator.compare("op_warn", baseline, current, &test_envelope());
        assert_eq!(
            result.final_verdict,
            ComparisonVerdict::Warn,
            "fixture must reach the WARN branch"
        );
        let line = format_report_line(&result);
        insta::assert_snapshot!("report_line_warn", line);
    }

    // ── Negative / invariant tests ───────────────────────────────────

    #[test]
    fn improvement_is_not_regression() {
        let comparator = RegressionComparator::new(ComparatorConfig::default());
        let baseline = &[120.0, 121.0, 119.0, 120.5, 119.5, 120.2, 119.8];
        let current = &[100.0, 101.0, 99.0, 100.5, 99.5, 100.2, 99.8];

        let result = comparator.compare("test_op", baseline, current, &test_envelope());
        assert_eq!(result.final_verdict, ComparisonVerdict::Pass);
        assert!(
            result.delta_percent < 0.0,
            "improvement should be negative delta"
        );
    }

    #[test]
    fn zero_baseline_handled() {
        let comparator = RegressionComparator::new(ComparatorConfig::default());
        let result = comparator.compare(
            "test_op",
            &[0.0, 0.0, 0.0],
            &[1.0, 1.0, 1.0],
            &test_envelope(),
        );
        // Should not panic or produce NaN.
        assert!(!result.delta_percent.is_nan());
    }

    #[test]
    fn comparator_version_is_set() {
        const { assert!(COMPARATOR_VERSION >= 1) };
    }

    // ── ComparisonContext tests ──────────────────────────────────────

    #[test]
    fn compare_with_context_produces_same_verdict() {
        let comparator = RegressionComparator::new(ComparatorConfig::default());
        let baseline = &[100.0, 100.5, 99.5, 100.2, 99.8];
        let current = &[100.0, 100.5, 99.5, 100.2, 99.8];
        let ctx = ComparisonContext {
            benchmark_id: "metadata_parity_cli".to_owned(),
            profile_id: "csd-threadripper".to_owned(),
            baseline_ref: "abc1234".to_owned(),
        };

        let without = comparator.compare("test_op", baseline, current, &test_envelope());
        let with = comparator.compare_with_context(
            "test_op",
            baseline,
            current,
            &test_envelope(),
            Some(&ctx),
        );
        assert_eq!(without.final_verdict, with.final_verdict);
        assert!((without.delta_percent - with.delta_percent).abs() < f64::EPSILON);
    }

    #[test]
    fn comparison_context_json_round_trip() -> Result<(), serde_json::Error> {
        let ctx = ComparisonContext {
            benchmark_id: "block_cache_arc_scan".to_owned(),
            profile_id: "ci-github-actions".to_owned(),
            baseline_ref: "v1.0.3".to_owned(),
        };
        let json = serde_json::to_string_pretty(&ctx)?;
        insta::assert_snapshot!("comparison_context_json_shape", json);
        let parsed: ComparisonContext = serde_json::from_str(&json)?;
        assert_eq!(parsed, ctx);
        Ok(())
    }
}
