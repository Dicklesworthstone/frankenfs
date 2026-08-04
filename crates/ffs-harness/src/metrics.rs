#![forbid(unsafe_code)]

//! Lightweight runtime metrics framework using atomics.
//!
//! Provides [`MetricKind::Counter`], [`MetricKind::Gauge`], and [`MetricKind::Histogram`] metric types with
//! zero-contention atomic updates. A global [`MetricsRegistry`] manages
//! registration and snapshot collection.
//!
//! ## Design
//!
//! - All recording operations use atomic instructions (no locks on hot path).
//! - Registry lookup uses `parking_lot::RwLock` (only on registration, not recording).
//! - Snapshots are O(metrics_count), not O(events).
//! - When metrics are not enabled, the `enabled` flag short-circuits all recording.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use ffs_harness::metrics::{MetricsRegistry, MetricKind};
//!
//! let registry = MetricsRegistry::new();
//! registry.enable();
//!
//! let ops = registry.register("fs.ops_total", MetricKind::Counter);
//! ops.increment(1);
//!
//! let snapshot = registry.snapshot();
//! let json = serde_json::to_string_pretty(&snapshot)?;
//! # let _ = json;
//! # Ok::<(), serde_json::Error>(())
//! ```

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::time::Instant;

// ── Metric Kind ────────────────────────────────────────────────────────────

/// Classification of metric type for registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricKind {
    /// Monotonically increasing counter (e.g. total operations).
    Counter,
    /// Point-in-time gauge (e.g. current cache size).
    Gauge,
    /// Latency distribution with fixed buckets.
    Histogram,
}

// ── Metric Handle ──────────────────────────────────────────────────────────

/// A thin handle for recording metric values via atomic operations.
///
/// Handles are returned by [`MetricsRegistry::register`] and are safe
/// to clone and share across threads.
#[derive(Debug, Clone)]
pub struct MetricHandle {
    inner: Arc<MetricInner>,
}

#[derive(Debug)]
struct MetricInner {
    name: String,
    kind: MetricKind,
    enabled: Arc<AtomicBool>,
    // Counter / Gauge value
    value: AtomicI64,
    // Histogram-specific
    histogram: HistogramState,
}

/// Fixed-bucket histogram state.
///
/// Buckets are defined at construction time. Each bucket stores a count of
/// observations assigned to its upper bound. A final +Inf bucket captures
/// everything above the last explicit bound.
#[derive(Debug)]
struct HistogramState {
    /// Upper bounds of each bucket (sorted ascending).
    bounds: Vec<u64>,
    /// Counts per bucket (len = bounds.len() + 1 for the +Inf bucket).
    counts: Vec<AtomicU64>,
    /// Sum of all observed values.
    sum: AtomicU64,
    /// Total observation count.
    total: AtomicU64,
}

fn saturating_fetch_add_i64(value: &AtomicI64, delta: i64) {
    let _ = value.try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(delta))
    });
}

fn saturating_fetch_add_u64(value: &AtomicU64, delta: u64) {
    let _ = value.try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(delta))
    });
}

impl Default for HistogramState {
    fn default() -> Self {
        Self::with_bounds(&DEFAULT_HISTOGRAM_BOUNDS)
    }
}

/// Default histogram bounds for latency measurements (microseconds).
/// Covers sub-microsecond to 10s range.
const DEFAULT_HISTOGRAM_BOUNDS: [u64; 12] = [
    1,         // 1us
    5,         // 5us
    10,        // 10us
    50,        // 50us
    100,       // 100us
    500,       // 500us
    1_000,     // 1ms
    5_000,     // 5ms
    10_000,    // 10ms
    50_000,    // 50ms
    100_000,   // 100ms
    1_000_000, // 1s
];

impl HistogramState {
    fn with_bounds(bounds: &[u64]) -> Self {
        let mut bounds = bounds.to_vec();
        bounds.sort_unstable();
        bounds.dedup();

        let counts = (0..=bounds.len()).map(|_| AtomicU64::new(0)).collect();
        Self {
            bounds,
            counts,
            sum: AtomicU64::new(0),
            total: AtomicU64::new(0),
        }
    }

    fn observe(&self, value: u64) {
        // Find the first bucket whose bound >= value
        let idx = self.bounds.partition_point(|&b| b < value);
        if let Some(count) = self.counts.get(idx) {
            saturating_fetch_add_u64(count, 1);
        }
        saturating_fetch_add_u64(&self.sum, value);
        saturating_fetch_add_u64(&self.total, 1);
    }

    fn snapshot(&self) -> HistogramSnapshot {
        let buckets: Vec<BucketSnapshot> = self
            .bounds
            .iter()
            .zip(self.counts.iter())
            .map(|(&bound, count)| BucketSnapshot {
                le: bound,
                count: count.load(Ordering::Relaxed),
            })
            .collect();
        let inf_count = self
            .counts
            .get(self.bounds.len())
            .map_or(0, |count| count.load(Ordering::Relaxed));

        HistogramSnapshot {
            buckets,
            inf_count,
            sum: self.sum.load(Ordering::Relaxed),
            count: self.total.load(Ordering::Relaxed),
        }
    }
}

impl MetricHandle {
    /// Increment a counter by the given amount.
    /// No-op for non-counter metrics or when metrics are disabled.
    pub fn increment(&self, n: u64) {
        if !self.inner.enabled.load(Ordering::Relaxed) {
            return;
        }
        if self.inner.kind == MetricKind::Counter {
            saturating_fetch_add_i64(&self.inner.value, i64::try_from(n).unwrap_or(i64::MAX));
        }
    }

    /// Set a gauge to the given value.
    /// No-op for non-gauge metrics or when metrics are disabled.
    pub fn set(&self, val: i64) {
        if !self.inner.enabled.load(Ordering::Relaxed) {
            return;
        }
        if self.inner.kind == MetricKind::Gauge {
            self.inner.value.store(val, Ordering::Relaxed);
        }
    }

    /// Adjust a gauge by the given delta (positive or negative).
    /// No-op for non-gauge metrics or when metrics are disabled.
    pub fn adjust(&self, delta: i64) {
        if !self.inner.enabled.load(Ordering::Relaxed) {
            return;
        }
        if self.inner.kind == MetricKind::Gauge {
            saturating_fetch_add_i64(&self.inner.value, delta);
        }
    }

    /// Record a histogram observation (e.g. latency in microseconds).
    /// No-op for non-histogram metrics or when metrics are disabled.
    pub fn observe(&self, value: u64) {
        if !self.inner.enabled.load(Ordering::Relaxed) {
            return;
        }
        if self.inner.kind == MetricKind::Histogram {
            self.inner.histogram.observe(value);
        }
    }

    /// Returns the metric name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.inner.name
    }

    /// Returns the metric kind.
    #[must_use]
    pub fn kind(&self) -> MetricKind {
        self.inner.kind
    }
}

// ── Snapshot Types ─────────────────────────────────────────────────────────

/// A point-in-time snapshot of all registered metrics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    /// Timestamp when the snapshot was taken (seconds since registry creation).
    pub elapsed_secs: f64,
    /// Individual metric snapshots, keyed by metric name.
    pub metrics: BTreeMap<String, MetricSnapshot>,
}

/// Snapshot of a single metric.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricSnapshot {
    pub kind: MetricKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub histogram: Option<HistogramSnapshot>,
}

/// Snapshot of histogram bucket distribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistogramSnapshot {
    pub buckets: Vec<BucketSnapshot>,
    pub inf_count: u64,
    pub sum: u64,
    pub count: u64,
}

/// A single histogram bucket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BucketSnapshot {
    /// Upper bound of this bucket (exclusive for values, inclusive for counts).
    pub le: u64,
    /// Number of observations in this bucket.
    pub count: u64,
}

// ── Metrics Registry ───────────────────────────────────────────────────────

/// Thread-safe metrics registry.
///
/// Manages metric registration and snapshot collection. The registry starts
/// disabled; call [`enable`](Self::enable) to start recording.
#[derive(Debug)]
pub struct MetricsRegistry {
    /// Whether metrics recording is active.
    enabled: Arc<AtomicBool>,
    /// Registered metrics, protected by read-write lock.
    /// Writes (registration) are infrequent; reads (snapshot) are occasional.
    metrics: RwLock<BTreeMap<String, MetricHandle>>,
    /// Creation time for elapsed_secs calculation.
    created_at: Instant,
    /// Rolling window size for per-second snapshots.
    window_secs: u64,
    /// Snapshot history for rolling window aggregation.
    snapshots: RwLock<Vec<MetricsSnapshot>>,
}

impl MetricsRegistry {
    /// Create a new disabled metrics registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            enabled: Arc::new(AtomicBool::new(false)),
            metrics: RwLock::new(BTreeMap::new()),
            created_at: Instant::now(),
            window_secs: 60,
            snapshots: RwLock::new(Vec::new()),
        }
    }

    /// Create a new registry with a custom rolling window size.
    #[must_use]
    pub fn with_window(window_secs: u64) -> Self {
        Self {
            window_secs,
            ..Self::new()
        }
    }

    /// Enable metrics recording.
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::Relaxed);
    }

    /// Disable metrics recording.
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::Relaxed);
    }

    /// Returns true if metrics are currently enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Register a new metric. Returns a handle for recording values.
    ///
    /// If a metric with the same name already exists, the existing handle
    /// is returned (idempotent registration).
    pub fn register(&self, name: &str, kind: MetricKind) -> MetricHandle {
        // Fast path: check if already registered
        {
            let guard = self.metrics.read();
            if let Some(handle) = guard.get(name) {
                return handle.clone();
            }
        }

        // Slow path: register new metric
        let mut guard = self.metrics.write();
        // Double-check after acquiring write lock
        if let Some(handle) = guard.get(name) {
            return handle.clone();
        }

        let handle = MetricHandle {
            inner: Arc::new(MetricInner {
                name: name.to_owned(),
                kind,
                enabled: Arc::clone(&self.enabled),
                value: AtomicI64::new(0),
                histogram: HistogramState::default(),
            }),
        };
        guard.insert(name.to_owned(), handle.clone());
        handle
    }

    /// Register a histogram with custom bucket bounds.
    pub fn register_histogram(&self, name: &str, bounds: &[u64]) -> MetricHandle {
        // Fast path
        {
            let guard = self.metrics.read();
            if let Some(handle) = guard.get(name) {
                return handle.clone();
            }
        }

        let mut guard = self.metrics.write();
        if let Some(handle) = guard.get(name) {
            return handle.clone();
        }

        let handle = MetricHandle {
            inner: Arc::new(MetricInner {
                name: name.to_owned(),
                kind: MetricKind::Histogram,
                enabled: Arc::clone(&self.enabled),
                value: AtomicI64::new(0),
                histogram: HistogramState::with_bounds(bounds),
            }),
        };
        guard.insert(name.to_owned(), handle.clone());
        handle
    }

    /// Take a point-in-time snapshot of all registered metrics.
    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        let elapsed = self.created_at.elapsed().as_secs_f64();
        let metrics = self
            .metrics
            .read()
            .iter()
            .map(|(name, handle)| {
                let snap = match handle.inner.kind {
                    MetricKind::Counter | MetricKind::Gauge => MetricSnapshot {
                        kind: handle.inner.kind,
                        value: Some(handle.inner.value.load(Ordering::Relaxed)),
                        histogram: None,
                    },
                    MetricKind::Histogram => MetricSnapshot {
                        kind: handle.inner.kind,
                        value: None,
                        histogram: Some(handle.inner.histogram.snapshot()),
                    },
                };
                (name.clone(), snap)
            })
            .collect();

        MetricsSnapshot {
            elapsed_secs: elapsed,
            metrics,
        }
    }

    /// Take a snapshot and store it in the rolling window.
    /// Prunes snapshots older than `window_secs`.
    pub fn record_snapshot(&self) {
        let snap = self.snapshot();
        let cutoff = snap.elapsed_secs - self.window_secs as f64;

        let mut history = self.snapshots.write();
        history.push(snap);
        history.retain(|s| s.elapsed_secs >= cutoff);
    }

    /// Returns the number of snapshots in the rolling window.
    #[must_use]
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.read().len()
    }

    /// Returns the number of registered metrics.
    #[must_use]
    pub fn metric_count(&self) -> usize {
        self.metrics.read().len()
    }

    /// Emit a snapshot as a structured tracing event.
    pub fn emit_snapshot(&self) {
        let snap = self.snapshot();
        if let Ok(json) = serde_json::to_string(&snap) {
            tracing::info!(
                target: "ffs::metrics",
                metrics_json = %json,
                metric_count = snap.metrics.len(),
                elapsed_secs = snap.elapsed_secs,
                "metrics_snapshot"
            );
        }
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Convenience Functions ──────────────────────────────────────────────────

/// Create a no-op metric handle that never records anything.
/// Useful for code paths where metrics are optional.
#[must_use]
pub fn noop_handle(name: &str, kind: MetricKind) -> MetricHandle {
    MetricHandle {
        inner: Arc::new(MetricInner {
            name: name.to_owned(),
            kind,
            enabled: Arc::new(AtomicBool::new(false)),
            value: AtomicI64::new(0),
            histogram: HistogramState::default(),
        }),
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn histogram_snapshot<'a>(
        snap: &'a MetricsSnapshot,
        name: &str,
    ) -> Result<&'a HistogramSnapshot, String> {
        snap.metrics
            .get(name)
            .and_then(|metric| metric.histogram.as_ref())
            .ok_or_else(|| format!("missing histogram metric {name}"))
    }

    fn metric_snapshot<'a>(
        snap: &'a MetricsSnapshot,
        name: &str,
    ) -> Result<&'a MetricSnapshot, String> {
        snap.metrics
            .get(name)
            .ok_or_else(|| format!("missing metric {name}"))
    }

    #[test]
    fn counter_increment() -> Result<(), String> {
        let registry = MetricsRegistry::new();
        registry.enable();
        let counter = registry.register("test.ops", MetricKind::Counter);
        counter.increment(1);
        counter.increment(5);
        let snap = registry.snapshot();
        let m = metric_snapshot(&snap, "test.ops")?;
        assert_eq!(m.kind, MetricKind::Counter);
        assert_eq!(m.value, Some(6));
        Ok(())
    }

    #[test]
    fn counter_increment_saturates_at_i64_max() {
        let registry = MetricsRegistry::new();
        registry.enable();
        let counter = registry.register("test.ops", MetricKind::Counter);
        counter.increment(u64::MAX);
        counter.increment(1);

        let snap = registry.snapshot();
        assert_eq!(snap.metrics["test.ops"].value, Some(i64::MAX));
    }

    #[test]
    fn counter_disabled_is_noop() {
        let registry = MetricsRegistry::new();
        // Not enabled
        let counter = registry.register("test.noop", MetricKind::Counter);
        counter.increment(100);
        let snap = registry.snapshot();
        assert_eq!(snap.metrics["test.noop"].value, Some(0));
    }

    #[test]
    fn gauge_set_and_adjust() {
        let registry = MetricsRegistry::new();
        registry.enable();
        let gauge = registry.register("cache.size", MetricKind::Gauge);
        gauge.set(42);
        let snap = registry.snapshot();
        assert_eq!(snap.metrics["cache.size"].value, Some(42));

        gauge.adjust(-10);
        let snap = registry.snapshot();
        assert_eq!(snap.metrics["cache.size"].value, Some(32));

        gauge.adjust(5);
        let snap = registry.snapshot();
        assert_eq!(snap.metrics["cache.size"].value, Some(37));
    }

    #[test]
    fn gauge_adjust_saturates_at_numeric_bounds() {
        let registry = MetricsRegistry::new();
        registry.enable();
        let gauge = registry.register("cache.size", MetricKind::Gauge);

        gauge.set(i64::MAX);
        gauge.adjust(1);
        let snap = registry.snapshot();
        assert_eq!(snap.metrics["cache.size"].value, Some(i64::MAX));

        gauge.set(i64::MIN);
        gauge.adjust(-1);
        let snap = registry.snapshot();
        assert_eq!(snap.metrics["cache.size"].value, Some(i64::MIN));
    }

    #[test]
    fn histogram_observe() -> Result<(), String> {
        let registry = MetricsRegistry::new();
        registry.enable();
        let hist = registry.register("latency.us", MetricKind::Histogram);

        // Observe values in different buckets
        hist.observe(3); // 5us bucket
        hist.observe(50); // 50us bucket
        hist.observe(500); // 500us bucket
        hist.observe(999_999); // 1s bucket
        hist.observe(5_000_000); // +Inf bucket

        let snap = registry.snapshot();
        let h = histogram_snapshot(&snap, "latency.us")?;
        assert_eq!(h.count, 5);
        assert_eq!(h.sum, 3 + 50 + 500 + 999_999 + 5_000_000);

        // Check bucket distribution
        // bounds: [1, 5, 10, 50, 100, 500, 1000, 5000, 10000, 50000, 100000, 1000000]
        // 3 -> bucket index 1 (le=5)
        // 50 -> bucket index 3 (le=50)
        // 500 -> bucket index 5 (le=500)
        // 999_999 -> bucket index 11 (le=1_000_000)
        // 5_000_000 -> inf bucket
        assert_eq!(bucket(h, 1)?.count, 1); // le=5
        assert_eq!(bucket(h, 3)?.count, 1); // le=50
        assert_eq!(bucket(h, 5)?.count, 1); // le=500
        assert_eq!(bucket(h, 11)?.count, 1); // le=1_000_000
        assert_eq!(h.inf_count, 1);
        Ok(())
    }

    #[test]
    fn histogram_custom_bounds() -> Result<(), String> {
        let registry = MetricsRegistry::new();
        registry.enable();
        let hist = registry.register_histogram("custom.hist", &[10, 100, 1000]);

        hist.observe(5); // bucket 0 (le=10)
        hist.observe(50); // bucket 1 (le=100)
        hist.observe(500); // bucket 2 (le=1000)
        hist.observe(5000); // inf

        let snap = registry.snapshot();
        let h = histogram_snapshot(&snap, "custom.hist")?;
        assert_eq!(h.count, 4);
        assert_eq!(h.buckets.len(), 3);
        assert_eq!(bucket(h, 0)?.count, 1);
        assert_eq!(bucket(h, 1)?.count, 1);
        assert_eq!(bucket(h, 2)?.count, 1);
        assert_eq!(h.inf_count, 1);
        Ok(())
    }

    #[test]
    fn histogram_custom_bounds_are_sorted_and_deduplicated() -> Result<(), String> {
        let registry = MetricsRegistry::new();
        registry.enable();
        let hist = registry.register_histogram("custom.hist", &[100, 10, 100, 1000]);

        hist.observe(5);
        hist.observe(50);
        hist.observe(500);
        hist.observe(5000);

        let snap = registry.snapshot();
        let h = histogram_snapshot(&snap, "custom.hist")?;
        let bounds = h.buckets.iter().map(|bucket| bucket.le).collect::<Vec<_>>();
        assert_eq!(bounds, vec![10, 100, 1000]);
        assert_eq!(bucket(h, 0)?.count, 1);
        assert_eq!(bucket(h, 1)?.count, 1);
        assert_eq!(bucket(h, 2)?.count, 1);
        assert_eq!(h.inf_count, 1);
        Ok(())
    }

    #[test]
    fn histogram_totals_saturate_on_overflow() -> Result<(), String> {
        let registry = MetricsRegistry::new();
        registry.enable();
        let custom_bounds = [10_u64];
        let hist = registry.register_histogram("custom.hist", &custom_bounds);
        hist.inner
            .histogram
            .sum
            .store(u64::MAX - 1, Ordering::Relaxed);
        hist.inner
            .histogram
            .total
            .store(u64::MAX, Ordering::Relaxed);
        histogram_count(&hist, 0)?.store(u64::MAX, Ordering::Relaxed);

        hist.observe(5);

        let snap = registry.snapshot();
        let h = histogram_snapshot(&snap, "custom.hist")?;
        assert_eq!(h.sum, u64::MAX);
        assert_eq!(h.count, u64::MAX);
        assert_eq!(bucket(h, 0)?.count, u64::MAX);
        Ok(())
    }

    #[test]
    fn idempotent_registration() {
        let registry = MetricsRegistry::new();
        registry.enable();
        let h1 = registry.register("same.metric", MetricKind::Counter);
        h1.increment(10);
        let h2 = registry.register("same.metric", MetricKind::Counter);
        h2.increment(5);
        // Both handles point to the same metric
        let snap = registry.snapshot();
        assert_eq!(snap.metrics["same.metric"].value, Some(15));
    }

    #[test]
    fn enable_disable_toggle() {
        let registry = MetricsRegistry::new();
        let counter = registry.register("toggle.ops", MetricKind::Counter);

        // Disabled: no recording
        counter.increment(10);
        let snap = registry.snapshot();
        assert_eq!(snap.metrics["toggle.ops"].value, Some(0));

        // Enable
        registry.enable();
        counter.increment(10);
        let snap = registry.snapshot();
        assert_eq!(snap.metrics["toggle.ops"].value, Some(10));

        // Disable again
        registry.disable();
        counter.increment(100);
        let snap = registry.snapshot();
        assert_eq!(snap.metrics["toggle.ops"].value, Some(10)); // unchanged
    }

    #[test]
    fn snapshot_json_serialization() -> Result<(), serde_json::Error> {
        let registry = MetricsRegistry::new();
        registry.enable();
        let _ = registry.register("json.counter", MetricKind::Counter);
        let _ = registry.register("json.gauge", MetricKind::Gauge);
        let _ = registry.register("json.hist", MetricKind::Histogram);

        let snap = registry.snapshot();
        let json = serde_json::to_string_pretty(&snap)?;
        let deser: MetricsSnapshot = serde_json::from_str(&json)?;
        assert_eq!(deser, snap);
        assert_eq!(deser.metrics.len(), 3);
        assert!(deser.metrics.contains_key("json.counter"));
        assert!(deser.metrics.contains_key("json.gauge"));
        assert!(deser.metrics.contains_key("json.hist"));
        Ok(())
    }

    #[test]
    fn snapshot_json_serialization_shape() -> Result<(), serde_json::Error> {
        let registry = MetricsRegistry::new();
        registry.enable();
        let counter = registry.register("json.counter", MetricKind::Counter);
        let gauge = registry.register("json.gauge", MetricKind::Gauge);
        let hist = registry.register_histogram("json.hist", &[10, 100]);

        counter.increment(7);
        gauge.set(-3);
        hist.observe(1);
        hist.observe(10);
        hist.observe(11);
        hist.observe(500);

        let mut snap = registry.snapshot();
        snap.elapsed_secs = 0.0;
        let json = serde_json::to_string_pretty(&snap)?;
        let deser: MetricsSnapshot = serde_json::from_str(&json)?;

        assert_eq!(deser, snap);
        insta::assert_snapshot!("snapshot_json_serialization_shape", json);
        Ok(())
    }

    #[test]
    fn rolling_window_pruning() {
        let registry = MetricsRegistry::with_window(1); // 1-second window
        registry.enable();
        let _ = registry.register("window.ops", MetricKind::Counter);

        // Record multiple snapshots
        registry.record_snapshot();
        registry.record_snapshot();
        assert_eq!(registry.snapshot_count(), 2);
    }

    #[test]
    fn concurrent_counter_updates() -> Result<(), String> {
        let registry = Arc::new(MetricsRegistry::new());
        registry.enable();
        let counter = registry.register("concurrent.ops", MetricKind::Counter);

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let c = counter.clone();
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        c.increment(1);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().map_err(|_| "concurrent counter worker panicked")?;
        }

        let snap = registry.snapshot();
        assert_eq!(snap.metrics["concurrent.ops"].value, Some(8000));
        Ok(())
    }

    #[test]
    fn concurrent_histogram_observations() -> Result<(), String> {
        let registry = Arc::new(MetricsRegistry::new());
        registry.enable();
        let hist = registry.register("concurrent.latency", MetricKind::Histogram);

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let h = hist.clone();
                std::thread::spawn(move || {
                    for i in 0..100 {
                        h.observe(i);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join()
                .map_err(|_| "concurrent histogram worker panicked")?;
        }

        let snap = registry.snapshot();
        let hs = histogram_snapshot(&snap, "concurrent.latency")?;
        assert_eq!(hs.count, 400); // 4 threads * 100 observations
        Ok(())
    }

    #[test]
    fn noop_handle_never_records() {
        let handle = noop_handle("noop.metric", MetricKind::Counter);
        handle.increment(1000);
        // Can't directly check, but this verifies no panic.
        assert_eq!(handle.name(), "noop.metric");
        assert_eq!(handle.kind(), MetricKind::Counter);
    }

    #[test]
    fn metric_count() {
        let registry = MetricsRegistry::new();
        assert_eq!(registry.metric_count(), 0);
        let _ = registry.register("a", MetricKind::Counter);
        assert_eq!(registry.metric_count(), 1);
        let _ = registry.register("b", MetricKind::Gauge);
        assert_eq!(registry.metric_count(), 2);
        // Re-register same metric
        let _ = registry.register("a", MetricKind::Counter);
        assert_eq!(registry.metric_count(), 2);
    }

    fn bucket(snapshot: &HistogramSnapshot, index: usize) -> Result<&BucketSnapshot, String> {
        snapshot
            .buckets
            .get(index)
            .ok_or_else(|| format!("missing histogram bucket {index}"))
    }

    fn histogram_count(handle: &MetricHandle, index: usize) -> Result<&AtomicU64, String> {
        handle
            .inner
            .histogram
            .counts
            .get(index)
            .ok_or_else(|| format!("missing histogram count {index}"))
    }
}
