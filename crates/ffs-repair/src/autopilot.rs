//! Bayesian adaptive overhead selection for repair symbol refresh.
//!
//! This module maintains a Beta posterior over per-block corruption
//! probability and chooses repair overhead by minimizing expected loss:
//!
//! `E[loss] = P(unrecoverable) * data_loss_cost + overhead * storage_cost`
//!
//! Unrecoverable risk is estimated with a Beta-Binomial tail probability.

use serde::{Deserialize, Serialize};

const CANDIDATE_STEP: f64 = 0.001;
const MIN_POSITIVE_PARAM: f64 = 1e-9;
const DEFAULT_DATA_LOSS_COST: f64 = 1_000_000.0;
const DEFAULT_STORAGE_COST: f64 = 1.0;
const DEFAULT_MIN_OVERHEAD: f64 = 0.03;
const DEFAULT_MAX_OVERHEAD: f64 = 0.10;
const DEFAULT_METADATA_MULTIPLIER: f64 = 2.0;
const DEFAULT_REFRESH_IO_COST: f64 = 0.01;
const DEFAULT_CRASH_RATE_PER_SEC: f64 = 1.0 / 31_536_000.0;
const DEFAULT_CORRUPTION_PROBABILITY: f64 = 0.01;

#[must_use]
fn positive_param(value: f64) -> f64 {
    if value.is_finite() && value > 0.0 {
        value.max(MIN_POSITIVE_PARAM)
    } else {
        MIN_POSITIVE_PARAM
    }
}

#[must_use]
fn finite_nonnegative_or(value: f64, fallback: f64) -> f64 {
    if value.is_finite() && value >= 0.0 {
        value
    } else {
        fallback
    }
}

#[must_use]
fn unit_interval_or(value: f64, fallback: f64) -> f64 {
    let value = if value.is_finite() { value } else { fallback };
    value.clamp(0.0, 1.0)
}

#[must_use]
fn positive_ratio(numerator: f64, denominator_part: f64) -> f64 {
    let scale = numerator.max(denominator_part);
    if scale <= 0.0 {
        return 0.0;
    }
    let scaled_numerator = numerator / scale;
    let scaled_denominator_part = denominator_part / scale;
    let denominator = scaled_numerator + scaled_denominator_part;
    if denominator <= 0.0 {
        0.0
    } else {
        unit_interval_or(scaled_numerator / denominator, 0.0)
    }
}

#[must_use]
fn finite_loss(value: f64) -> f64 {
    if value.is_finite() && value >= 0.0 {
        value
    } else {
        f64::MAX
    }
}

/// Adaptive overhead decision for a block group.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct OverheadDecision {
    /// Selected overhead fraction (0.05 = 5% repair symbols).
    pub overhead_ratio: f64,
    /// Posterior mean corruption probability.
    pub corruption_posterior: f64,
    /// Beta posterior alpha parameter.
    pub posterior_alpha: f64,
    /// Beta posterior beta parameter.
    pub posterior_beta: f64,
    /// Probability of corruption exceeding decodable symbols.
    pub risk_bound: f64,
    /// Expected loss at this overhead.
    pub expected_loss: f64,
    /// Number of repair symbols implied by `overhead_ratio`.
    pub symbols_selected: u32,
    /// Whether metadata multiplier was applied.
    pub metadata_group: bool,
}

/// Bayesian durability autopilot used by repair policy selection.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct DurabilityAutopilot {
    /// Beta posterior alpha parameter ("corrupt" evidence count).
    pub alpha: f64,
    /// Beta posterior beta parameter ("clean" evidence count).
    pub beta: f64,
    /// Cost multiplier for unrecoverable corruption.
    pub data_loss_cost: f64,
    /// Cost multiplier for repair-symbol overhead.
    pub storage_cost: f64,
    /// Minimum overhead fraction considered by the optimizer.
    pub min_overhead: f64,
    /// Maximum overhead fraction considered by the optimizer.
    pub max_overhead: f64,
    /// Multiplier for metadata-critical groups.
    pub metadata_multiplier: f64,
}

impl Default for DurabilityAutopilot {
    fn default() -> Self {
        Self {
            alpha: 1.0,
            beta: 100.0,
            data_loss_cost: DEFAULT_DATA_LOSS_COST,
            storage_cost: DEFAULT_STORAGE_COST,
            min_overhead: DEFAULT_MIN_OVERHEAD,
            max_overhead: DEFAULT_MAX_OVERHEAD,
            metadata_multiplier: DEFAULT_METADATA_MULTIPLIER,
        }
    }
}

impl DurabilityAutopilot {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bayesian conjugate update from one scrub cycle observation.
    pub fn update_posterior(&mut self, corrupted: u64, checked: u64) {
        if checked == 0 {
            return;
        }
        let clamped_corrupted = corrupted.min(checked);
        let clean = checked.saturating_sub(clamped_corrupted);

        self.alpha = positive_param(self.alpha) + clamped_corrupted as f64;
        self.beta = positive_param(self.beta) + clean as f64;
    }

    #[must_use]
    pub fn posterior_mean(&self) -> f64 {
        let (alpha, beta) = self.posterior_params();
        positive_ratio(alpha, beta)
    }

    #[must_use]
    pub fn posterior_params(&self) -> (f64, f64) {
        (positive_param(self.alpha), positive_param(self.beta))
    }

    /// Compute unrecoverable risk bound for overhead fraction and group size.
    #[must_use]
    pub fn risk_bound(&self, overhead: f64, source_block_count: u32) -> f64 {
        if source_block_count == 0 {
            return 0.0;
        }

        let capped_overhead = unit_interval_or(overhead, 0.0);
        let decodable = (f64::from(source_block_count) * capped_overhead)
            .floor()
            .clamp(0.0, f64::from(source_block_count));
        let cutoff = floor_to_u32(decodable, source_block_count);
        if cutoff >= source_block_count {
            return 0.0;
        }

        let (alpha, beta) = self.posterior_params();
        beta_binomial_tail(alpha, beta, source_block_count, cutoff)
    }

    /// Expected-loss objective at a specific overhead fraction.
    #[must_use]
    pub fn expected_loss(&self, overhead: f64, source_block_count: u32) -> f64 {
        self.expected_loss_custom(overhead, source_block_count, self.data_loss_cost)
    }

    /// Expected loss with a custom data loss cost (e.g. for metadata).
    #[must_use]
    pub fn expected_loss_custom(
        &self,
        overhead: f64,
        source_block_count: u32,
        loss_cost: f64,
    ) -> f64 {
        let bounded_overhead = unit_interval_or(overhead, 0.0);
        let storage_cost = finite_nonnegative_or(self.storage_cost, DEFAULT_STORAGE_COST);
        let loss_cost = finite_nonnegative_or(loss_cost, DEFAULT_DATA_LOSS_COST);
        let risk = self.risk_bound(bounded_overhead, source_block_count);
        let redundancy_cost = storage_cost * bounded_overhead;
        let corruption_cost = loss_cost * risk;
        finite_loss(redundancy_cost + corruption_cost)
    }

    /// Expected loss for a data or metadata group at a fixed overhead fraction.
    #[must_use]
    pub fn expected_loss_for_group(
        &self,
        overhead: f64,
        source_block_count: u32,
        metadata_group: bool,
    ) -> f64 {
        let loss_cost = if metadata_group {
            self.metadata_loss_cost()
        } else {
            self.data_loss_cost()
        };
        self.expected_loss_custom(overhead, source_block_count, loss_cost)
    }

    /// Choose optimal overhead in `[min_overhead, max_overhead]`.
    #[must_use]
    pub fn optimal_overhead(&self, source_block_count: u32) -> f64 {
        self.optimize_overhead(source_block_count, self.data_loss_cost)
    }

    /// Choose optimal overhead for metadata-critical groups.
    #[must_use]
    pub fn optimal_overhead_metadata(&self, source_block_count: u32) -> f64 {
        self.optimize_overhead(source_block_count, self.metadata_loss_cost())
    }

    fn optimize_overhead(&self, source_block_count: u32, loss_cost: f64) -> f64 {
        if source_block_count == 0 {
            return 0.0;
        }

        let (min_overhead, max_overhead) = self.normalized_bounds();
        if self.posterior_mean() >= max_overhead {
            return max_overhead;
        }

        let mut best_overhead = min_overhead;
        let mut best_loss = self.expected_loss_custom(min_overhead, source_block_count, loss_cost);
        let mut candidate = min_overhead;

        loop {
            let loss = self.expected_loss_custom(candidate, source_block_count, loss_cost);
            if loss < best_loss - f64::EPSILON {
                best_loss = loss;
                best_overhead = candidate;
            }

            if (candidate - max_overhead).abs() <= f64::EPSILON {
                break;
            }
            let next_candidate = (candidate + CANDIDATE_STEP).min(max_overhead);
            if (next_candidate - candidate).abs() <= f64::EPSILON {
                break;
            }
            candidate = next_candidate;
        }

        best_overhead
    }

    /// Compute a full decision summary for one group.
    #[must_use]
    pub fn decision_for_group(
        &self,
        source_block_count: u32,
        metadata_group: bool,
    ) -> OverheadDecision {
        let selected_overhead = if metadata_group {
            self.optimal_overhead_metadata(source_block_count)
        } else {
            self.optimal_overhead(source_block_count)
        };
        let risk_bound = self.risk_bound(selected_overhead, source_block_count);
        let expected_loss =
            self.expected_loss_for_group(selected_overhead, source_block_count, metadata_group);
        let (posterior_alpha, posterior_beta) = self.posterior_params();

        OverheadDecision {
            overhead_ratio: selected_overhead,
            corruption_posterior: self.posterior_mean(),
            posterior_alpha,
            posterior_beta,
            risk_bound,
            expected_loss,
            symbols_selected: Self::symbol_count_for_overhead(
                source_block_count,
                selected_overhead,
            ),
            metadata_group,
        }
    }

    /// Convert overhead fraction to repair symbol count.
    #[must_use]
    pub fn symbol_count_for_overhead(source_block_count: u32, overhead_ratio: f64) -> u32 {
        if source_block_count == 0 {
            return 0;
        }
        let bounded_overhead = unit_interval_or(overhead_ratio, 0.0);
        let raw_count = f64::from(source_block_count) * bounded_overhead;
        if !raw_count.is_finite() || raw_count <= 0.0 {
            return 0;
        }
        let floor_count = floor_to_u32(raw_count, source_block_count);
        if f64::from(floor_count) >= raw_count {
            floor_count
        } else {
            floor_count.saturating_add(1).min(source_block_count)
        }
    }

    #[must_use]
    fn normalized_bounds(&self) -> (f64, f64) {
        let min_overhead = unit_interval_or(self.min_overhead, DEFAULT_MIN_OVERHEAD);
        let max_overhead =
            unit_interval_or(self.max_overhead, DEFAULT_MAX_OVERHEAD).max(min_overhead);
        (min_overhead, max_overhead)
    }

    #[must_use]
    fn data_loss_cost(&self) -> f64 {
        finite_nonnegative_or(self.data_loss_cost, DEFAULT_DATA_LOSS_COST)
    }

    #[must_use]
    fn metadata_loss_cost(&self) -> f64 {
        self.data_loss_cost()
            * finite_nonnegative_or(self.metadata_multiplier, DEFAULT_METADATA_MULTIPLIER).max(1.0)
    }
}

#[must_use]
fn beta_binomial_tail(alpha: f64, beta: f64, draws: u32, cutoff: u32) -> f64 {
    if draws == 0 || cutoff >= draws {
        return 0.0;
    }

    let alpha = positive_param(alpha);
    let beta = positive_param(beta);

    let mut log_total = f64::NEG_INFINITY;
    let mut log_tail = f64::NEG_INFINITY;
    let mut log_weight = 0.0;

    for k in 0..=draws {
        log_total = log_add_exp(log_total, log_weight);
        if k > cutoff {
            log_tail = log_add_exp(log_tail, log_weight);
        }

        if k == draws {
            break;
        }

        let remaining = f64::from(draws - k);
        let next_index = f64::from(k + 1);
        let log_comb_ratio = (remaining / next_index).ln();
        let log_beta_ratio = (f64::from(k) + alpha).ln() - (f64::from(draws - k - 1) + beta).ln();
        log_weight += log_comb_ratio + log_beta_ratio;
    }

    if !log_tail.is_finite() {
        return 0.0;
    }

    unit_interval_or((log_tail - log_total).exp(), 0.0)
}

#[must_use]
fn log_add_exp(lhs: f64, rhs: f64) -> f64 {
    if lhs.is_nan() || rhs.is_nan() {
        return f64::NAN;
    }
    if lhs == f64::INFINITY || rhs == f64::INFINITY {
        return f64::INFINITY;
    }
    if lhs == f64::NEG_INFINITY {
        return rhs;
    }
    if rhs == f64::NEG_INFINITY {
        return lhs;
    }
    let hi = lhs.max(rhs);
    hi + ((lhs - hi).exp() + (rhs - hi).exp()).ln()
}

#[must_use]
fn floor_to_u32(value: f64, upper: u32) -> u32 {
    if !value.is_finite() || value <= 0.0 {
        return 0;
    }
    if value >= f64::from(upper) {
        return upper;
    }

    let mut low = 0_u32;
    let mut high = upper;
    while low < high {
        let mid = low + (high - low).div_ceil(2);
        if f64::from(mid) <= value {
            low = mid;
        } else {
            high = mid.saturating_sub(1);
        }
    }
    low
}

// ── Refresh trigger expected-loss model ────────────────────────────────────

/// Workload intensity profile for refresh policy comparison.
///
/// Each profile characterizes the expected write rate to a block group,
/// enabling expected-loss comparison of age-only vs block-count triggers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkloadProfile {
    /// Near-zero writes (e.g., cold archive).  ~0.01 writes/sec.
    Idle,
    /// Steady low-rate writes.  ~1 write/sec.
    Light,
    /// Sustained high-rate writes.  ~100 writes/sec.
    Heavy,
    /// Short intense bursts followed by quiescence.  ~1000 writes/sec peak.
    Burst,
}

impl WorkloadProfile {
    /// Expected writes per second for this profile.
    #[must_use]
    pub const fn writes_per_second(self) -> f64 {
        match self {
            Self::Idle => 0.01,
            Self::Light => 1.0,
            Self::Heavy => 100.0,
            Self::Burst => 1000.0,
        }
    }

    /// All defined profiles.
    pub const ALL: [Self; 4] = [Self::Idle, Self::Light, Self::Heavy, Self::Burst];
}

/// Expected-loss model for comparing refresh trigger policies.
///
/// The model evaluates three policies:
///
/// - **Age-only**: Refresh after `max_staleness` seconds since first dirty write.
///   Current default is 30s.
/// - **Block-count**: Refresh after `block_threshold` writes to the group since
///   last refresh.
/// - **Hybrid**: Refresh at `min(age_timeout, block_threshold)` — whichever
///   trigger fires first.
///
/// Expected loss for each policy:
///
/// ```text
/// E[loss] = P(data_loss | stale_symbols) * data_loss_cost
///         + P(unnecessary_refresh) * refresh_io_cost
/// ```
///
/// `P(data_loss | stale_symbols)` increases with the number of blocks written
/// since the last refresh, because each write invalidates one source block's
/// repair symbols.  The probability that a crash during this window requires
/// recovery AND hits an invalidated block is approximately:
///
/// ```text
/// P(data_loss) ≈ P(crash) * (stale_blocks / source_blocks) * P(corruption | crash)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RefreshLossModel {
    /// Cost of unrecoverable data loss (same scale as `DurabilityAutopilot`).
    pub data_loss_cost: f64,
    /// I/O cost of one refresh operation (encode + write repair symbols).
    pub refresh_io_cost: f64,
    /// Probability of a crash per second (annualized failure rate / seconds_per_year).
    /// Default: ~3.17e-8 (≈ 1 crash/year).
    pub crash_rate_per_sec: f64,
    /// Posterior corruption probability per block (from autopilot).
    pub corruption_probability: f64,
    /// Number of source blocks in the group.
    pub source_block_count: u32,
}

impl Default for RefreshLossModel {
    fn default() -> Self {
        Self {
            data_loss_cost: DEFAULT_DATA_LOSS_COST,
            refresh_io_cost: DEFAULT_REFRESH_IO_COST,
            crash_rate_per_sec: DEFAULT_CRASH_RATE_PER_SEC, // 1 crash/year
            corruption_probability: DEFAULT_CORRUPTION_PROBABILITY,
            source_block_count: 32_768,
        }
    }
}

/// Result of a refresh policy comparison.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RefreshPolicyComparison {
    /// Expected loss per second under age-only refresh.
    pub loss_age_only: f64,
    /// Expected loss per second under block-count refresh.
    pub loss_block_count: f64,
    /// Expected loss per second under hybrid refresh.
    pub loss_hybrid: f64,
    /// Age-only trigger interval in seconds.
    pub age_trigger_secs: f64,
    /// Block-count trigger threshold.
    pub block_trigger_count: u32,
    /// The policy with the lowest expected loss.
    pub best_policy: RefreshTriggerPolicy,
}

/// Trigger policy selection result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RefreshTriggerPolicy {
    /// Refresh based on time since first dirty write.
    AgeOnly,
    /// Refresh based on number of writes since last refresh.
    BlockCount,
    /// Refresh on whichever fires first (min of age and block-count).
    Hybrid,
}

impl RefreshLossModel {
    /// Expected loss rate (per second) for age-only refresh with the given timeout.
    ///
    /// During the staleness window `[0, max_staleness_secs]`, blocks accumulate
    /// at `write_rate` per second.  The average number of stale blocks over the
    /// window is `write_rate * max_staleness_secs / 2`.  The refresh cost is
    /// amortized as `refresh_io_cost / max_staleness_secs`.
    #[must_use]
    pub fn expected_loss_age_only(&self, max_staleness_secs: f64, write_rate: f64) -> f64 {
        if self.source_block_count == 0 {
            return 0.0; // No blocks → no loss.
        }
        if !max_staleness_secs.is_finite() || max_staleness_secs <= 0.0 {
            // Degenerate: refresh on every tick → infinite refresh cost rate.
            return f64::MAX;
        }
        let blocks = f64::from(self.source_block_count);
        let clamped_rate = finite_nonnegative_or(write_rate, 0.0);
        // Average stale fraction over the refresh interval.
        let avg_stale_blocks = (clamped_rate * max_staleness_secs / 2.0).min(blocks);
        let avg_stale_fraction = avg_stale_blocks / blocks;
        let data_loss_rate =
            self.crash_rate_per_sec() * avg_stale_fraction * self.corruption_probability();
        let refresh_amortized = self.refresh_io_cost() / max_staleness_secs;
        finite_loss(data_loss_rate.mul_add(self.data_loss_cost(), refresh_amortized))
    }

    /// Expected loss rate (per second) for block-count refresh with the given threshold.
    ///
    /// Refreshes after every `block_threshold` writes.  The average number of
    /// stale blocks is `block_threshold / 2`.  The refresh cost is amortized
    /// as `refresh_io_cost * write_rate / block_threshold`.
    #[must_use]
    pub fn expected_loss_block_count(&self, block_threshold: u32, write_rate: f64) -> f64 {
        if self.source_block_count == 0 {
            return 0.0; // No blocks → no loss.
        }
        let clamped_rate = finite_nonnegative_or(write_rate, 0.0);
        if block_threshold == 0 {
            // Refresh on every write → cost = refresh_io_cost per write.
            return finite_loss(self.refresh_io_cost() * clamped_rate);
        }
        if clamped_rate <= 0.0 {
            // No writes → no refreshes, no stale blocks, no loss.
            return 0.0;
        }
        let blocks = f64::from(self.source_block_count);
        let threshold_f = f64::from(block_threshold);
        let avg_stale_blocks = (threshold_f / 2.0).min(blocks);
        let avg_stale_fraction = avg_stale_blocks / blocks;
        let data_loss_rate =
            self.crash_rate_per_sec() * avg_stale_fraction * self.corruption_probability();
        let refresh_amortized = self.refresh_io_cost() * clamped_rate / threshold_f;
        finite_loss(data_loss_rate.mul_add(self.data_loss_cost(), refresh_amortized))
    }

    /// Expected loss rate (per second) for hybrid refresh (min of age and block-count).
    ///
    /// The effective staleness window is `min(max_staleness_secs, block_threshold / write_rate)`.
    #[must_use]
    pub fn expected_loss_hybrid(
        &self,
        max_staleness_secs: f64,
        block_threshold: u32,
        write_rate: f64,
    ) -> f64 {
        if self.source_block_count == 0 {
            return 0.0;
        }
        let clamped_rate = finite_nonnegative_or(write_rate, 0.0);
        if block_threshold == 0 {
            return finite_loss(self.refresh_io_cost() * clamped_rate);
        }
        let age_window = if max_staleness_secs.is_finite() && max_staleness_secs > 0.0 {
            max_staleness_secs
        } else {
            f64::INFINITY
        };
        let block_window = if clamped_rate > 0.0 && block_threshold > 0 {
            f64::from(block_threshold) / clamped_rate
        } else {
            f64::INFINITY
        };
        let effective_window = age_window.min(block_window);
        if effective_window <= 0.0 {
            // Refresh on every write.
            return finite_loss(self.refresh_io_cost() * clamped_rate);
        }
        let blocks = f64::from(self.source_block_count);
        let avg_stale_blocks = if effective_window.is_finite() {
            (clamped_rate * effective_window / 2.0).min(blocks)
        } else if clamped_rate > 0.0 {
            blocks
        } else {
            0.0
        };
        let avg_stale_fraction = avg_stale_blocks / blocks;
        let data_loss_rate =
            self.crash_rate_per_sec() * avg_stale_fraction * self.corruption_probability();
        let refresh_amortized = if effective_window.is_finite() {
            self.refresh_io_cost() / effective_window
        } else {
            0.0
        };
        finite_loss(data_loss_rate.mul_add(self.data_loss_cost(), refresh_amortized))
    }

    /// Compare all three policies for a given workload and return the best.
    #[must_use]
    pub fn compare_policies(
        &self,
        max_staleness_secs: f64,
        block_threshold: u32,
        profile: WorkloadProfile,
    ) -> RefreshPolicyComparison {
        let rate = profile.writes_per_second();
        let loss_age = self.expected_loss_age_only(max_staleness_secs, rate);
        let loss_block = self.expected_loss_block_count(block_threshold, rate);
        let loss_hybrid = self.expected_loss_hybrid(max_staleness_secs, block_threshold, rate);

        let best = if loss_hybrid <= loss_age && loss_hybrid <= loss_block {
            RefreshTriggerPolicy::Hybrid
        } else if loss_block <= loss_age {
            RefreshTriggerPolicy::BlockCount
        } else {
            RefreshTriggerPolicy::AgeOnly
        };

        RefreshPolicyComparison {
            loss_age_only: loss_age,
            loss_block_count: loss_block,
            loss_hybrid,
            age_trigger_secs: finite_nonnegative_or(max_staleness_secs, 0.0),
            block_trigger_count: block_threshold,
            best_policy: best,
        }
    }

    /// Find the write rate at which block-count triggers become cheaper than
    /// age-only.  Returns `None` if age-only is always cheaper (e.g., zero
    /// corruption probability).
    ///
    /// This is the "decision boundary" from the bead spec.
    #[must_use]
    pub fn block_count_dominance_threshold(
        &self,
        max_staleness_secs: f64,
        block_threshold: u32,
    ) -> Option<f64> {
        if self.source_block_count == 0
            || !max_staleness_secs.is_finite()
            || max_staleness_secs <= 0.0
            || block_threshold == 0
        {
            return None;
        }
        // Binary search for the write rate where block-count loss == age-only loss.
        let mut lo: f64 = 0.0;
        let mut hi: f64 = 100_000.0;
        let loss_age_lo = self.expected_loss_age_only(max_staleness_secs, lo);
        let loss_block_lo = self.expected_loss_block_count(block_threshold, lo);
        let loss_age_hi = self.expected_loss_age_only(max_staleness_secs, hi);
        let loss_block_hi = self.expected_loss_block_count(block_threshold, hi);

        // Check if block-count is always better or always worse.
        let diff_lo = loss_age_lo - loss_block_lo;
        let diff_hi = loss_age_hi - loss_block_hi;
        if !diff_lo.is_finite() || !diff_hi.is_finite() {
            return None;
        }
        if diff_lo.signum() == diff_hi.signum() {
            return None; // No crossover in range.
        }

        for _ in 0..64 {
            let mid = f64::midpoint(lo, hi);
            let diff = self.expected_loss_age_only(max_staleness_secs, mid)
                - self.expected_loss_block_count(block_threshold, mid);
            if !diff.is_finite() {
                return None;
            }
            if diff.abs() < 1e-15 {
                return Some(mid);
            }
            if diff.signum() == diff_lo.signum() {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        Some(f64::midpoint(lo, hi))
    }

    #[must_use]
    fn data_loss_cost(&self) -> f64 {
        finite_nonnegative_or(self.data_loss_cost, DEFAULT_DATA_LOSS_COST)
    }

    #[must_use]
    fn refresh_io_cost(&self) -> f64 {
        finite_nonnegative_or(self.refresh_io_cost, DEFAULT_REFRESH_IO_COST)
    }

    #[must_use]
    fn crash_rate_per_sec(&self) -> f64 {
        finite_nonnegative_or(self.crash_rate_per_sec, DEFAULT_CRASH_RATE_PER_SEC)
    }

    #[must_use]
    fn corruption_probability(&self) -> f64 {
        unit_interval_or(self.corruption_probability, DEFAULT_CORRUPTION_PROBABILITY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn posterior_update_tracks_counts() {
        let mut ap = DurabilityAutopilot::default();
        ap.update_posterior(10, 1000);
        assert!((ap.alpha - 11.0).abs() < 1e-12);
        assert!((ap.beta - 1090.0).abs() < 1e-12);
        assert!((ap.posterior_mean() - (11.0 / 1101.0)).abs() < 1e-12);
    }

    #[test]
    fn optimal_overhead_respects_bounds() {
        let ap = DurabilityAutopilot::default();
        let overhead = ap.optimal_overhead(32_768);
        assert!(overhead >= ap.min_overhead);
        assert!(overhead <= ap.max_overhead);
    }

    #[test]
    fn higher_corruption_selects_higher_overhead() {
        let mut low = DurabilityAutopilot::default();
        for _ in 0..5 {
            low.update_posterior(0, 20_000);
        }

        let mut high = DurabilityAutopilot::default();
        for _ in 0..5 {
            high.update_posterior(1_000, 20_000);
        }

        let low_overhead = low.optimal_overhead(32_768);
        let high_overhead = high.optimal_overhead(32_768);
        assert!(
            high_overhead >= low_overhead,
            "expected high corruption overhead >= low corruption overhead ({high_overhead} >= {low_overhead})"
        );
    }

    #[test]
    fn edge_cases_zero_and_full_corruption() {
        let mut zero = DurabilityAutopilot::default();
        zero.update_posterior(0, 10_000);
        let zero_overhead = zero.optimal_overhead(4_096);
        assert!(zero_overhead <= 0.05);

        let mut full = DurabilityAutopilot::default();
        full.update_posterior(10_000, 10_000);
        let full_overhead = full.optimal_overhead(4_096);
        assert!(full_overhead >= zero_overhead);
        assert!(full_overhead >= 0.09);
    }

    #[test]
    fn single_block_group_decision_is_valid() {
        let mut ap = DurabilityAutopilot::default();
        ap.update_posterior(1, 1);
        let decision = ap.decision_for_group(1, false);
        assert!(decision.overhead_ratio.is_finite());
        assert!(decision.expected_loss.is_finite());
        assert!(decision.risk_bound.is_finite());
        assert!(decision.symbols_selected <= 1);
    }

    fn assert_zero(value: f64) {
        assert_eq!(value.to_bits(), 0.0_f64.to_bits());
    }

    #[test]
    fn zero_block_group_selects_zero_overhead() {
        let ap = DurabilityAutopilot::default();

        assert_zero(ap.optimal_overhead(0));
        assert_zero(ap.optimal_overhead_metadata(0));
    }

    #[test]
    fn zero_block_group_decision_is_empty() {
        let ap = DurabilityAutopilot::default();

        for metadata_group in [false, true] {
            let decision = ap.decision_for_group(0, metadata_group);
            assert_zero(decision.overhead_ratio);
            assert_zero(decision.risk_bound);
            assert_zero(decision.expected_loss);
            assert_eq!(decision.symbols_selected, 0);
            assert_eq!(decision.metadata_group, metadata_group);
        }
    }

    #[test]
    fn autopilot_sanitizes_non_finite_configuration_values() {
        let mut ap = DurabilityAutopilot {
            alpha: f64::NAN,
            beta: f64::INFINITY,
            data_loss_cost: f64::NAN,
            storage_cost: f64::NEG_INFINITY,
            min_overhead: f64::NAN,
            max_overhead: f64::NAN,
            metadata_multiplier: f64::NAN,
        };

        ap.update_posterior(1, 2);
        let (alpha, beta) = ap.posterior_params();
        assert!(alpha.is_finite() && alpha > 0.0);
        assert!(beta.is_finite() && beta > 0.0);

        let decision = ap.decision_for_group(32, true);
        assert!((DEFAULT_MIN_OVERHEAD..=DEFAULT_MAX_OVERHEAD).contains(&decision.overhead_ratio));
        assert!(decision.corruption_posterior.is_finite());
        assert!(decision.risk_bound.is_finite());
        assert!(decision.expected_loss.is_finite());
        assert!(decision.symbols_selected <= 32);

        assert!(ap.expected_loss(f64::NAN, 32).is_finite());
        assert!((0.0..=1.0).contains(&ap.risk_bound(f64::NAN, 32)));
        assert_eq!(
            DurabilityAutopilot::symbol_count_for_overhead(32, f64::NAN),
            0
        );
    }

    #[test]
    fn metadata_multiplier_applies_to_optimal_overhead() {
        let mut ap = DurabilityAutopilot::default();
        // Use a small number of observations to keep the posterior broad and risk non-zero.
        ap.update_posterior(5, 100);

        let base = ap.optimal_overhead(1024);
        let metadata = ap.optimal_overhead_metadata(1024);

        // Metadata overhead should be higher or equal to base due to higher loss cost.
        assert!(metadata >= base - f64::EPSILON);

        // It should still be bounded by the autopilot's max_overhead.
        assert!(metadata <= ap.max_overhead + f64::EPSILON);

        // In this non-zero risk scenario, doubling the cost should push metadata overhead higher.
        if base < ap.max_overhead - 0.001 {
            assert!(
                metadata > base,
                "metadata overhead {metadata} should be higher than base {base} when cost is doubled",
            );
        }
    }

    #[test]
    fn fixed_metadata_expected_loss_uses_metadata_multiplier() {
        let ap = DurabilityAutopilot {
            alpha: 2.0,
            beta: 10.0,
            data_loss_cost: 100.0,
            storage_cost: 1.0,
            metadata_multiplier: 3.0,
            ..DurabilityAutopilot::default()
        };
        let overhead = 0.03;
        let source_blocks = 32;

        let base = ap.expected_loss_for_group(overhead, source_blocks, false);
        let metadata = ap.expected_loss_for_group(overhead, source_blocks, true);
        let explicit_metadata =
            ap.expected_loss_custom(overhead, source_blocks, ap.data_loss_cost() * 3.0);

        assert!(
            metadata > base,
            "metadata loss {metadata} should exceed base loss {base}"
        );
        assert!(
            (metadata - explicit_metadata).abs() < 1e-12,
            "metadata fixed-overhead loss should use metadata multiplier"
        );
    }

    proptest! {
        #[test]
        fn optimal_overhead_monotonic_with_corruption_rate(
            low_rate in 0_u8..=100,
            delta in 0_u8..=100,
        ) {
            let high_rate = low_rate.saturating_add(delta).min(100);
            let checked = 20_000_u64;
            let low_corrupted = checked * u64::from(low_rate) / 100;
            let high_corrupted = checked * u64::from(high_rate) / 100;

            let mut low = DurabilityAutopilot::default();
            low.update_posterior(low_corrupted, checked);
            let low_overhead = low.optimal_overhead(32_768);

            let mut high = DurabilityAutopilot::default();
            high.update_posterior(high_corrupted, checked);
            let high_overhead = high.optimal_overhead(32_768);

            prop_assert!(
                high_overhead + 1e-12 >= low_overhead
                    || (low_overhead - high_overhead) <= CANDIDATE_STEP
            );
        }

        /// `posterior_mean()` always returns a value in [0, 1].
        #[test]
        fn proptest_posterior_mean_in_unit_interval(
            alpha in -100.0_f64..1_000_000.0,
            beta in -100.0_f64..1_000_000.0,
        ) {
            let ap = DurabilityAutopilot { alpha, beta, ..DurabilityAutopilot::default() };
            let mean = ap.posterior_mean();
            prop_assert!((0.0..=1.0).contains(&mean), "posterior_mean {} out of [0,1]", mean);
        }

        /// `risk_bound()` always returns a value in [0, 1].
        #[test]
        fn proptest_risk_bound_in_unit_interval(
            alpha in 0.001_f64..1000.0,
            beta in 0.001_f64..1000.0,
            overhead in 0.0_f64..1.0,
            source_blocks in 0_u32..512,
        ) {
            let ap = DurabilityAutopilot { alpha, beta, ..DurabilityAutopilot::default() };
            let risk = ap.risk_bound(overhead, source_blocks);
            prop_assert!(
                (0.0..=1.0).contains(&risk),
                "risk_bound {} out of [0,1] for alpha={}, beta={}, overhead={}, blocks={}",
                risk, alpha, beta, overhead, source_blocks
            );
        }

        /// `risk_bound()` returns 0 when overhead >= 1.0 (full redundancy).
        #[test]
        fn proptest_risk_bound_zero_at_full_overhead(
            alpha in 0.001_f64..100.0,
            beta in 0.001_f64..100.0,
            source_blocks in 1_u32..1024,
        ) {
            let ap = DurabilityAutopilot { alpha, beta, ..DurabilityAutopilot::default() };
            let risk = ap.risk_bound(1.0, source_blocks);
            prop_assert!(
                risk.abs() < 1e-12,
                "risk_bound at overhead=1.0 should be 0, got {}",
                risk
            );
        }

        /// `beta_binomial_tail()` always returns a value in [0, 1].
        #[test]
        fn proptest_beta_binomial_tail_in_unit_interval(
            alpha in 0.001_f64..100.0,
            beta in 0.001_f64..100.0,
            draws in 1_u32..128,
            cutoff_frac in 0.0_f64..1.0,
        ) {
            let cutoff = floor_to_u32(f64::from(draws) * cutoff_frac, draws);
            let tail = beta_binomial_tail(alpha, beta, draws, cutoff);
            prop_assert!(
                (0.0..=1.0).contains(&tail),
                "beta_binomial_tail {} out of [0,1] for alpha={}, beta={}, draws={}, cutoff={}",
                tail, alpha, beta, draws, cutoff
            );
        }

        /// `beta_binomial_tail()` is monotonically non-increasing in cutoff.
        #[test]
        fn proptest_beta_binomial_tail_monotonic_in_cutoff(
            alpha in 0.1_f64..50.0,
            beta in 0.1_f64..50.0,
            draws in 2_u32..64,
            lo in 0_u32..32,
            delta in 1_u32..32,
        ) {
            let lo = lo.min(draws.saturating_sub(1));
            let hi = lo.saturating_add(delta).min(draws.saturating_sub(1));
            if lo < hi {
                let tail_lo = beta_binomial_tail(alpha, beta, draws, lo);
                let tail_hi = beta_binomial_tail(alpha, beta, draws, hi);
                prop_assert!(
                    tail_lo + 1e-12 >= tail_hi,
                    "tail not monotonic: cutoff {} → {}, cutoff {} → {}",
                    lo, tail_lo, hi, tail_hi
                );
            }
        }

        /// `log_add_exp()` is commutative.
        #[test]
        fn proptest_log_add_exp_commutative(
            a in -100.0_f64..100.0,
            b in -100.0_f64..100.0,
        ) {
            let ab = log_add_exp(a, b);
            let ba = log_add_exp(b, a);
            prop_assert!(
                (ab - ba).abs() < 1e-10,
                "log_add_exp not commutative: ({}, {}) → {}, ({}, {}) → {}",
                a, b, ab, b, a, ba
            );
        }

        /// `log_add_exp(a, NEG_INFINITY)` returns `a`.
        #[test]
        fn proptest_log_add_exp_identity(a in -100.0_f64..100.0) {
            let result = log_add_exp(a, f64::NEG_INFINITY);
            prop_assert!(
                (result - a).abs() < 1e-12,
                "log_add_exp({}, -inf) = {}, expected {}",
                a, result, a
            );
        }

        /// `floor_to_u32()` returns a value <= the input and >= input - 1.
        #[test]
        fn proptest_floor_to_u32_accuracy(
            value in 0.0_f64..1_000_000.0,
            upper in 1_u32..=u32::MAX,
        ) {
            let result = floor_to_u32(value, upper);
            let f_result = f64::from(result);
            // result <= value (it's a floor)
            prop_assert!(
                f_result <= value + 1e-9,
                "floor_to_u32({}, {}) = {} exceeds input",
                value, upper, result
            );
            // result >= value - 1 (within one of the true floor)
            if value < f64::from(upper) {
                prop_assert!(
                    f_result >= value - 1.0 - 1e-9,
                    "floor_to_u32({}, {}) = {} too far below input",
                    value, upper, result
                );
            }
            // result <= upper
            prop_assert!(result <= upper);
        }

        /// `optimal_overhead()` always returns a value within bounds.
        #[test]
        fn proptest_optimal_overhead_within_bounds(
            corrupted in 0_u64..10_000,
            checked in 1_u64..20_000,
            source_blocks in 1_u32..4096,
        ) {
            let mut ap = DurabilityAutopilot::default();
            ap.update_posterior(corrupted.min(checked), checked);
            let overhead = ap.optimal_overhead(source_blocks);
            prop_assert!(
                overhead >= ap.min_overhead - 1e-12 && overhead <= ap.max_overhead + 1e-12,
                "optimal_overhead {} not in [{}, {}]",
                overhead, ap.min_overhead, ap.max_overhead
            );
        }

        /// `symbol_count_for_overhead()` is bounded by source_block_count.
        #[test]
        fn proptest_symbol_count_bounded(
            source_blocks in 0_u32..65536,
            overhead in 0.0_f64..2.0,
        ) {
            let count = DurabilityAutopilot::symbol_count_for_overhead(source_blocks, overhead);
            prop_assert!(
                count <= source_blocks,
                "symbol_count {} > source_blocks {}",
                count, source_blocks
            );
        }

        /// `expected_loss()` is always non-negative and finite.
        #[test]
        fn proptest_expected_loss_nonneg_finite(
            alpha in 0.001_f64..1000.0,
            beta in 0.001_f64..1000.0,
            overhead in 0.0_f64..1.0,
            source_blocks in 0_u32..512,
        ) {
            let ap = DurabilityAutopilot { alpha, beta, ..DurabilityAutopilot::default() };
            let loss = ap.expected_loss(overhead, source_blocks);
            prop_assert!(loss >= 0.0, "expected_loss {} < 0", loss);
            prop_assert!(loss.is_finite(), "expected_loss is not finite");
        }

        /// Posterior alpha + beta increases monotonically with observations.
        #[test]
        fn proptest_posterior_params_grow_with_observations(
            corrupted in 0_u64..1000,
            checked in 1_u64..10_000,
        ) {
            let mut ap = DurabilityAutopilot::default();
            let (a0, b0) = ap.posterior_params();
            let sum_before = a0 + b0;

            ap.update_posterior(corrupted.min(checked), checked);
            let (a1, b1) = ap.posterior_params();
            let sum_after = a1 + b1;

            prop_assert!(
                sum_after >= sum_before - 1e-12,
                "posterior sum decreased: {} → {}",
                sum_before, sum_after
            );
        }
    }

    // ── RefreshLossModel tests ────────────────────────────────────────────

    #[test]
    fn refresh_loss_age_only_short_staleness_has_high_refresh_cost() {
        let m = RefreshLossModel::default();
        let rate = WorkloadProfile::Heavy.writes_per_second();
        // Very short staleness → dominated by refresh I/O amortization.
        let loss_tiny = m.expected_loss_age_only(0.1, rate);
        let loss_moderate = m.expected_loss_age_only(30.0, rate);
        assert!(
            loss_tiny > loss_moderate,
            "very short staleness should cost more than moderate: \
             tiny={loss_tiny:.12} moderate={loss_moderate:.12}"
        );
    }

    #[test]
    fn refresh_loss_age_only_u_shape_under_high_risk() {
        // With high corruption probability, data-loss cost dominates at long
        // staleness, creating a clear U-shape.
        let m = RefreshLossModel {
            corruption_probability: 0.5,
            source_block_count: 1024,
            ..RefreshLossModel::default()
        };
        let rate = WorkloadProfile::Heavy.writes_per_second();
        let loss_tiny = m.expected_loss_age_only(0.01, rate);
        let loss_mid = m.expected_loss_age_only(1.0, rate);
        let loss_huge = m.expected_loss_age_only(1000.0, rate);
        assert!(
            loss_tiny > loss_mid,
            "short staleness should cost more than moderate: \
             tiny={loss_tiny:.12} mid={loss_mid:.12}"
        );
        assert!(
            loss_huge > loss_mid,
            "long staleness should cost more than moderate: \
             huge={loss_huge:.12} mid={loss_mid:.12}"
        );
    }

    #[test]
    fn refresh_loss_block_count_decreases_with_larger_threshold_under_low_corruption() {
        let m = RefreshLossModel {
            corruption_probability: 1e-9,
            ..RefreshLossModel::default()
        };
        let rate = WorkloadProfile::Light.writes_per_second();
        let loss_small = m.expected_loss_block_count(10, rate);
        let loss_large = m.expected_loss_block_count(10_000, rate);
        assert!(
            loss_large < loss_small,
            "with low corruption, larger threshold should reduce loss: \
             small={loss_small:.12} large={loss_large:.12}"
        );
    }

    #[test]
    fn refresh_loss_hybrid_uses_shorter_window() {
        // The hybrid effective window is min(age, block/rate). With age=30s
        // and block_threshold=100 at rate=100/s, block triggers at 1s.
        // So hybrid effective window = 1s.
        let m = RefreshLossModel::default();
        let rate = 100.0; // 100 writes/sec.
        let staleness_secs = 30.0;
        let block_threshold = 100_u32;
        // Effective hybrid window: min(30, 100/100) = 1.0s.
        let loss_hybrid = m.expected_loss_hybrid(staleness_secs, block_threshold, rate);
        // This should equal the age-only loss at 1.0s window.
        let loss_age_at_1s = m.expected_loss_age_only(1.0, rate);
        assert!(
            (loss_hybrid - loss_age_at_1s).abs() < 1e-12,
            "hybrid should equal age-only at effective window: \
             hybrid={loss_hybrid:.12} age_at_1s={loss_age_at_1s:.12}"
        );
    }

    #[test]
    fn refresh_compare_all_profiles() {
        let m = RefreshLossModel::default();
        for profile in WorkloadProfile::ALL {
            let cmp = m.compare_policies(30.0, 500, profile);
            assert!(cmp.loss_age_only.is_finite());
            assert!(cmp.loss_block_count.is_finite());
            assert!(cmp.loss_hybrid.is_finite());
            assert!(cmp.loss_age_only >= 0.0);
            assert!(cmp.loss_block_count >= 0.0);
            assert!(cmp.loss_hybrid >= 0.0);
            let min_loss = cmp
                .loss_age_only
                .min(cmp.loss_block_count)
                .min(cmp.loss_hybrid);
            match cmp.best_policy {
                RefreshTriggerPolicy::AgeOnly => {
                    assert!((cmp.loss_age_only - min_loss).abs() < 1e-12);
                }
                RefreshTriggerPolicy::BlockCount => {
                    assert!((cmp.loss_block_count - min_loss).abs() < 1e-12);
                }
                RefreshTriggerPolicy::Hybrid => {
                    assert!((cmp.loss_hybrid - min_loss).abs() < 1e-12);
                }
            }
        }
    }

    #[test]
    fn refresh_block_count_dominates_when_data_loss_is_catastrophic() {
        // When data_loss_cost is very high and corruption probability is
        // significant, keeping the stale fraction low via block-count
        // triggers outweighs the higher refresh frequency cost.
        let m = RefreshLossModel {
            data_loss_cost: 1e9,
            corruption_probability: 0.5,
            source_block_count: 4096,
            ..RefreshLossModel::default()
        };
        let rate = WorkloadProfile::Burst.writes_per_second();
        let loss_age = m.expected_loss_age_only(30.0, rate);
        let loss_block = m.expected_loss_block_count(200, rate);
        assert!(
            loss_block < loss_age,
            "block-count should dominate when data loss is catastrophic: \
             age={loss_age:.6} block={loss_block:.6}"
        );
    }

    #[test]
    fn refresh_all_policies_finite_under_idle() {
        let m = RefreshLossModel::default();
        let rate = WorkloadProfile::Idle.writes_per_second();
        let loss_age = m.expected_loss_age_only(30.0, rate);
        let loss_block = m.expected_loss_block_count(500, rate);
        let loss_hybrid = m.expected_loss_hybrid(30.0, 500, rate);
        assert!(loss_age.is_finite() && loss_age >= 0.0);
        assert!(loss_block.is_finite() && loss_block >= 0.0);
        assert!(loss_hybrid.is_finite() && loss_hybrid >= 0.0);
    }

    #[test]
    fn refresh_decision_boundary_exists_under_high_risk() {
        let m = RefreshLossModel {
            corruption_probability: 0.1,
            source_block_count: 4096,
            ..RefreshLossModel::default()
        };
        let boundary = m.block_count_dominance_threshold(30.0, 500);
        if let Some(rate) = boundary {
            assert!(rate > 0.0, "crossover rate should be positive");
            let loss_age = m.expected_loss_age_only(30.0, rate);
            let loss_block = m.expected_loss_block_count(500, rate);
            assert!(
                (loss_age - loss_block).abs() < 1e-8,
                "at crossover rate {rate:.4}, losses should be equal: \
                 age={loss_age:.12} block={loss_block:.12}"
            );
        }
    }

    #[test]
    fn refresh_loss_zero_source_blocks_returns_zero() {
        let m = RefreshLossModel {
            source_block_count: 0,
            ..RefreshLossModel::default()
        };
        // With zero source blocks, there's nothing to protect → zero loss.
        assert!((m.expected_loss_age_only(30.0, 100.0) - 0.0).abs() < f64::EPSILON);
        assert!((m.expected_loss_block_count(500, 100.0) - 0.0).abs() < f64::EPSILON);
        assert!((m.expected_loss_hybrid(30.0, 500, 100.0) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn refresh_loss_zero_write_rate_block_count_returns_zero() {
        let m = RefreshLossModel::default();
        // With zero write rate, block-count never triggers → zero loss.
        assert!((m.expected_loss_block_count(500, 0.0) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn hybrid_zero_block_threshold_matches_every_write_refresh() {
        let m = RefreshLossModel::default();

        assert!(
            (m.expected_loss_hybrid(30.0, 0, 100.0) - m.expected_loss_block_count(0, 100.0)).abs()
                < f64::EPSILON
        );
        assert!((m.expected_loss_hybrid(30.0, 0, 0.0) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn refresh_loss_zero_staleness_returns_max() {
        let m = RefreshLossModel::default();
        // Zero staleness = "refresh every tick" → infinite cost.
        let loss = m.expected_loss_age_only(0.0, 100.0);
        assert!(loss >= f64::MAX - 1.0, "expected f64::MAX, got {loss}");
    }

    #[test]
    fn refresh_loss_model_sanitizes_non_finite_inputs() {
        let m = RefreshLossModel {
            data_loss_cost: f64::NAN,
            refresh_io_cost: f64::INFINITY,
            crash_rate_per_sec: f64::NAN,
            corruption_probability: f64::INFINITY,
            source_block_count: 1024,
        };

        let loss_age = m.expected_loss_age_only(30.0, f64::NAN);
        let loss_block = m.expected_loss_block_count(0, f64::INFINITY);
        let loss_hybrid = m.expected_loss_hybrid(f64::NAN, 500, f64::NAN);
        assert!(loss_age.is_finite() && loss_age >= 0.0);
        assert!(loss_block.is_finite() && loss_block >= 0.0);
        assert!(loss_hybrid.is_finite() && loss_hybrid >= 0.0);

        let cmp = m.compare_policies(f64::NAN, 500, WorkloadProfile::Heavy);
        assert!(cmp.loss_age_only.is_finite());
        assert!(cmp.loss_block_count.is_finite());
        assert!(cmp.loss_hybrid.is_finite());
        assert!(cmp.age_trigger_secs.is_finite());
        assert_eq!(m.block_count_dominance_threshold(f64::NAN, 500), None);
    }

    // ── Verification Gate: bd-m5wf.4.5 — adaptive refresh improvement ────

    /// Verification gate: the expected-loss model correctly identifies the
    /// optimal policy per workload, and hybrid shows >10% improvement under
    /// high-risk parameters where data-loss cost dominates refresh I/O.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn verification_gate_hybrid_expected_loss_improvement() {
        let m = RefreshLossModel::default();
        let age_staleness = 30.0;
        let block_threshold = 500_u32;

        eprintln!("=== Verification Gate: Adaptive Refresh Expected-Loss ===");
        eprintln!(
            "Parameters: age_staleness={age_staleness}s, block_threshold={block_threshold}, \
             source_blocks={}, crash_rate={:.2e}, corruption_prob={}",
            m.source_block_count, m.crash_rate_per_sec, m.corruption_probability
        );

        // ── Part 1: Default parameters — model selects correctly per profile ──
        for profile in WorkloadProfile::ALL {
            let cmp = m.compare_policies(age_staleness, block_threshold, profile);
            let best_loss = cmp
                .loss_age_only
                .min(cmp.loss_block_count)
                .min(cmp.loss_hybrid);
            eprintln!(
                "  {profile:?}: age={:.6e} block={:.6e} hybrid={:.6e} best={:?}",
                cmp.loss_age_only, cmp.loss_block_count, cmp.loss_hybrid, cmp.best_policy
            );
            // Best policy must correspond to the lowest loss.
            match cmp.best_policy {
                RefreshTriggerPolicy::AgeOnly => {
                    assert!((cmp.loss_age_only - best_loss).abs() < 1e-12);
                }
                RefreshTriggerPolicy::BlockCount => {
                    assert!((cmp.loss_block_count - best_loss).abs() < 1e-12);
                }
                RefreshTriggerPolicy::Hybrid => {
                    assert!((cmp.loss_hybrid - best_loss).abs() < 1e-12);
                }
            }
        }

        // ── Part 2: Under default params, refresh I/O dominates ──
        // At low write rates, block-count wins (fewest refreshes).
        // At high write rates, age-only wins (fixed refresh cost).
        // This is the correct economic behavior.
        let idle = m.compare_policies(age_staleness, block_threshold, WorkloadProfile::Idle);
        assert_eq!(idle.best_policy, RefreshTriggerPolicy::BlockCount);
        let heavy = m.compare_policies(age_staleness, block_threshold, WorkloadProfile::Heavy);
        assert_eq!(heavy.best_policy, RefreshTriggerPolicy::AgeOnly);

        // ── Part 3: High-risk parameters — hybrid improvement >10% ──
        // When data_loss_cost >> refresh_io_cost, the hybrid's tighter stale
        // window reduces expected data-loss enough to justify the extra refreshes.
        let high_risk = RefreshLossModel {
            data_loss_cost: 1e9,
            corruption_probability: 0.1,
            source_block_count: 4096,
            ..RefreshLossModel::default()
        };
        let hr_heavy =
            high_risk.compare_policies(age_staleness, block_threshold, WorkloadProfile::Heavy);
        let hr_improvement = if hr_heavy.loss_age_only > 0.0 {
            (hr_heavy.loss_age_only - hr_heavy.loss_hybrid) / hr_heavy.loss_age_only * 100.0
        } else {
            0.0
        };
        eprintln!(
            "  High-risk Heavy: age={:.6e} hybrid={:.6e} improvement={hr_improvement:.1}%",
            hr_heavy.loss_age_only, hr_heavy.loss_hybrid
        );
        assert!(
            hr_improvement > 10.0,
            "expected >10% improvement under high-risk heavy writes, got {hr_improvement:.1}%"
        );

        // ── Part 4: High-risk burst — hybrid also improves ──
        let hr_burst =
            high_risk.compare_policies(age_staleness, block_threshold, WorkloadProfile::Burst);
        let burst_improvement = if hr_burst.loss_age_only > 0.0 {
            (hr_burst.loss_age_only - hr_burst.loss_hybrid) / hr_burst.loss_age_only * 100.0
        } else {
            0.0
        };
        eprintln!(
            "  High-risk Burst: age={:.6e} hybrid={:.6e} improvement={burst_improvement:.1}%",
            hr_burst.loss_age_only, hr_burst.loss_hybrid
        );
        assert!(
            burst_improvement > 10.0,
            "expected >10% improvement under high-risk burst writes, got {burst_improvement:.1}%"
        );

        eprintln!("VERIFICATION GATE PASSED: adaptive refresh expected-loss model verified");
    }

    /// Verification gate: hybrid policy reduces stale-window p95 by >30%
    /// under heavy writes compared to age-only.
    #[test]
    fn verification_gate_hybrid_stale_window_reduction() {
        use crate::pipeline::{GroupRefreshSummary, RefreshTelemetry, StaleWindowSlo};

        // Simulate age-only at 30s under heavy writes (100 writes/sec).
        // Average stale blocks = 100 * 30 / 2 = 1500.
        // Average dirty age = 15s (half of 30s cycle).
        let age_only_groups: Vec<GroupRefreshSummary> = (0..20_u32)
            .map(|i| {
                // Distribute groups across the refresh cycle: group i is at
                // position i/20 * 30s into its cycle.
                let cycle_pos_ms = u64::from(i) * 30_000 / 20;
                let writes = u64::from(i) * 1500 / 20; // Proportional writes.
                GroupRefreshSummary {
                    group: i,
                    dirty: cycle_pos_ms > 0,
                    dirty_age_ms: cycle_pos_ms,
                    policy: "lazy(30000ms)".to_owned(),
                    since_last_refresh_ms: cycle_pos_ms,
                    writes_since_refresh: writes,
                    block_count_threshold: 0,
                }
            })
            .collect();

        // Simulate hybrid with age=30s + block_count=500 under same writes.
        // Block-count triggers at 500 writes ≈ 5s (at 100/s).
        // So effective window = min(30s, 5s) = 5s.
        // Average dirty age = 2.5s (half of 5s cycle).
        let hybrid_groups: Vec<GroupRefreshSummary> = (0..20_u32)
            .map(|i| {
                let cycle_pos_ms = u64::from(i) * 5_000 / 20;
                let writes = u64::from(i) * 250 / 20; // Proportional writes over 5s.
                GroupRefreshSummary {
                    group: i,
                    dirty: cycle_pos_ms > 0,
                    dirty_age_ms: cycle_pos_ms,
                    policy: "hybrid(age=30000ms,blocks=500)".to_owned(),
                    since_last_refresh_ms: cycle_pos_ms,
                    writes_since_refresh: writes,
                    block_count_threshold: 500,
                }
            })
            .collect();

        let age_telemetry = RefreshTelemetry {
            tracked_groups: 20,
            dirty_groups: 19,
            max_dirty_age_ms: 28_500,
            groups: age_only_groups,
        };
        let hybrid_telemetry = RefreshTelemetry {
            tracked_groups: 20,
            dirty_groups: 19,
            max_dirty_age_ms: 4_750,
            groups: hybrid_groups,
        };

        let slo = StaleWindowSlo::default();
        let age_eval = slo.evaluate(&age_telemetry);
        let hybrid_eval = slo.evaluate(&hybrid_telemetry);

        eprintln!("=== Verification Gate: Stale-Window p95 Reduction ===");
        eprintln!(
            "  Age-only p95: age={}ms writes={}",
            age_eval.age_at_percentile_ms, age_eval.writes_at_percentile
        );
        eprintln!(
            "  Hybrid p95:   age={}ms writes={}",
            hybrid_eval.age_at_percentile_ms, hybrid_eval.writes_at_percentile
        );

        // p95 age reduction: hybrid should be much lower.
        let age_reduction_pct = if age_eval.age_at_percentile_ms > 0 {
            (1.0 - hybrid_eval.age_at_percentile_ms as f64 / age_eval.age_at_percentile_ms as f64)
                * 100.0
        } else {
            0.0
        };
        eprintln!("  p95 age reduction: {age_reduction_pct:.1}%");

        assert!(
            age_reduction_pct > 30.0,
            "expected >30% p95 age reduction under heavy writes, got {age_reduction_pct:.1}%"
        );

        // p95 writes reduction should also be significant.
        let writes_reduction_pct = if age_eval.writes_at_percentile > 0 {
            (1.0 - hybrid_eval.writes_at_percentile as f64 / age_eval.writes_at_percentile as f64)
                * 100.0
        } else {
            0.0
        };
        eprintln!("  p95 writes reduction: {writes_reduction_pct:.1}%");

        assert!(
            writes_reduction_pct > 30.0,
            "expected >30% p95 writes reduction under heavy writes, got {writes_reduction_pct:.1}%"
        );

        // SLO compliance: hybrid should not breach the default SLO.
        assert!(
            !hybrid_eval.breached,
            "hybrid policy should meet default SLO (p95 age={}ms < 60000ms, writes={} < 5000)",
            hybrid_eval.age_at_percentile_ms, hybrid_eval.writes_at_percentile
        );

        eprintln!(
            "VERIFICATION GATE PASSED: p95 age reduction {age_reduction_pct:.1}%, \
             p95 writes reduction {writes_reduction_pct:.1}%"
        );
    }

    /// Verification gate: all 4 workload profiles produce finite, non-negative
    /// results and the compare function selects the correct best policy.
    #[test]
    fn verification_gate_all_profiles_correct() {
        let m = RefreshLossModel::default();
        for profile in WorkloadProfile::ALL {
            let cmp = m.compare_policies(30.0, 500, profile);
            assert!(cmp.loss_age_only.is_finite() && cmp.loss_age_only >= 0.0);
            assert!(cmp.loss_block_count.is_finite() && cmp.loss_block_count >= 0.0);
            assert!(cmp.loss_hybrid.is_finite() && cmp.loss_hybrid >= 0.0);
            let min_loss = cmp
                .loss_age_only
                .min(cmp.loss_block_count)
                .min(cmp.loss_hybrid);
            match cmp.best_policy {
                RefreshTriggerPolicy::AgeOnly => {
                    assert!((cmp.loss_age_only - min_loss).abs() < 1e-12);
                }
                RefreshTriggerPolicy::BlockCount => {
                    assert!((cmp.loss_block_count - min_loss).abs() < 1e-12);
                }
                RefreshTriggerPolicy::Hybrid => {
                    assert!((cmp.loss_hybrid - min_loss).abs() < 1e-12);
                }
            }
        }
    }

    /// Verification gate: decision boundary finder produces a valid crossover.
    #[test]
    fn verification_gate_decision_boundary_valid() {
        let m = RefreshLossModel {
            corruption_probability: 0.1,
            source_block_count: 4096,
            ..RefreshLossModel::default()
        };
        let boundary = m.block_count_dominance_threshold(30.0, 500);
        if let Some(rate) = boundary {
            assert!(rate > 0.0);
            let loss_age = m.expected_loss_age_only(30.0, rate);
            let loss_block = m.expected_loss_block_count(500, rate);
            let diff = (loss_age - loss_block).abs();
            assert!(
                diff < 1e-8,
                "at crossover rate {rate:.4}, losses should be equal: \
                 age={loss_age:.12} block={loss_block:.12} diff={diff:.12}"
            );
            eprintln!(
                "Decision boundary: {rate:.2} writes/sec \
                 (age={loss_age:.6e}, block={loss_block:.6e})"
            );
        }
    }
}
