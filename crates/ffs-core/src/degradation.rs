//! Compute budget, degradation FSM, and backpressure gating.
//!
//! This module implements the pressure-monitoring and graceful-degradation
//! subsystem for FrankenFS. It provides:
//!
//! - [`ComputeBudget`] — samples system load from `/proc/loadavg`
//! - [`DegradationLevel`] — five-level degradation FSM state
//! - [`DegradationFsm`] — hysteresis-based state machine that escalates
//!   immediately under pressure but requires sustained improvement to recover
//! - [`BackpressureGate`] — per-operation decision (proceed/throttle/shed)
//! - [`PressureMonitor`] — aggregated entry point tying budget + FSM together

use super::vfs::RequestOp;
use asupersync::SystemPressure;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{info, trace};

fn saturating_increment_relaxed(counter: &AtomicU64) {
    while counter
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            Some(current.saturating_add(1))
        })
        .is_err()
    {
        std::hint::spin_loop();
    }
}

// ── Compute budget and degradation ─────────────────────────────────────────

/// Compute budget monitor that samples system load and updates pressure state.
///
/// Reads `/proc/loadavg` on Linux and converts the 1-minute load average
/// into a headroom value (0.0–1.0) based on the number of CPU cores.
pub struct ComputeBudget {
    pressure: Arc<SystemPressure>,
    cpu_count: f32,
}

impl ComputeBudget {
    /// Create a new compute budget monitor.
    ///
    /// `pressure` is the shared handle that will be updated on each sample.
    #[must_use]
    pub fn new(pressure: Arc<SystemPressure>) -> Self {
        #[allow(clippy::cast_precision_loss)]
        let cpu_count =
            std::thread::available_parallelism().map_or(1, std::num::NonZero::get) as f32;
        Self {
            pressure,
            cpu_count,
        }
    }

    /// Sample the current system load and update the pressure handle.
    ///
    /// On Linux, reads `/proc/loadavg`. On other platforms, returns 1.0 (idle).
    /// Returns the computed headroom value.
    pub fn sample(&self) -> f32 {
        let headroom = self.sample_headroom();
        self.pressure.set_headroom(headroom);
        trace!(
            target: "ffs::budget",
            headroom,
            cpu_count = self.cpu_count,
            level = self.pressure.level_label(),
            "budget_sample"
        );
        headroom
    }

    /// Read the current headroom without updating pressure.
    #[must_use]
    pub fn current_headroom(&self) -> f32 {
        self.pressure.headroom()
    }

    /// The shared pressure handle.
    #[must_use]
    pub fn pressure(&self) -> &Arc<SystemPressure> {
        &self.pressure
    }

    fn sample_headroom(&self) -> f32 {
        Self::read_load_avg().map_or(1.0, |load_1m| {
            // headroom = 1.0 - (load / cpus), clamped to [0, 1]
            let ratio = load_1m / self.cpu_count;
            (1.0 - ratio).clamp(0.0, 1.0)
        })
    }

    /// Read 1-minute load average from `/proc/loadavg` on Linux.
    fn read_load_avg() -> Option<f32> {
        let content = std::fs::read_to_string("/proc/loadavg").ok()?;
        let first = content.split_whitespace().next()?;
        first.parse::<f32>().ok()
    }
}

impl std::fmt::Debug for ComputeBudget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ComputeBudget")
            .field("headroom", &self.pressure.headroom())
            .field("cpu_count", &self.cpu_count)
            .field("level", &self.pressure.level_label())
            .finish()
    }
}

/// Policy that reacts to system pressure changes.
///
/// Implementations adjust their behavior based on the current headroom value
/// (0.0 = critically overloaded, 1.0 = idle).
pub trait DegradationPolicy: Send + Sync {
    /// Apply the policy based on current headroom.
    ///
    /// Called periodically by the budget monitor. Implementations should
    /// adjust internal parameters (cache sizes, intervals, thresholds)
    /// based on the headroom value.
    fn apply(&self, headroom: f32);

    /// Human-readable name for this policy.
    fn name(&self) -> &str;
}

// ── Degradation FSM ─────────────────────────────────────────────────────────

/// Formal degradation levels matching `SystemPressure::degradation_level()`.
/// asupersync 0.3 thresholds: >= 0.9 normal, >= 0.65 light, >= 0.35 moderate, >= 0.1 heavy, < 0.1 emergency
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum DegradationLevel {
    /// headroom >= 0.9 — full service
    Normal = 0,
    /// headroom >= 0.65 — background tasks paused (asupersync: "light")
    Warning = 1,
    /// headroom >= 0.35 — caches reduced (asupersync: "moderate")
    Degraded = 2,
    /// headroom >= 0.1 — writes throttled (asupersync: "heavy")
    Critical = 3,
    /// headroom < 0.1 — read-only mode
    Emergency = 4,
}

impl DegradationLevel {
    /// Convert from a `SystemPressure::degradation_level()` u8 value.
    #[must_use]
    pub fn from_raw(raw: u8) -> Self {
        match raw {
            0 => Self::Normal,
            1 => Self::Warning,
            2 => Self::Degraded,
            3 => Self::Critical,
            _ => Self::Emergency,
        }
    }

    /// Human-readable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Warning => "warning",
            Self::Degraded => "degraded",
            Self::Critical => "critical",
            Self::Emergency => "emergency",
        }
    }

    /// Whether background work (scrub, GC) should be paused at this level.
    #[must_use]
    pub fn should_pause_background(self) -> bool {
        self >= Self::Warning
    }

    /// Whether caches should be reduced at this level.
    #[must_use]
    pub fn should_reduce_cache(self) -> bool {
        self >= Self::Degraded
    }

    /// Whether writes should be throttled at this level.
    #[must_use]
    pub fn should_throttle_writes(self) -> bool {
        self >= Self::Critical
    }

    /// Whether the filesystem should be read-only at this level.
    #[must_use]
    pub fn should_read_only(self) -> bool {
        self == Self::Emergency
    }
}

impl std::fmt::Display for DegradationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

impl From<DegradationLevel> for u8 {
    fn from(level: DegradationLevel) -> Self {
        level as Self
    }
}

/// Degradation FSM with hysteresis to prevent oscillation.
///
/// The FSM escalates immediately when pressure worsens but requires a
/// sustained improvement (configurable via `recovery_samples`) before
/// de-escalating. This prevents rapid flickering between levels.
///
/// # Lock-ordering invariant (bd-2rxal)
///
/// `DegradationFsm` holds two `parking_lot::Mutex`es —
/// `current: Mutex<FsmState>` and
/// `policies: Mutex<Vec<Arc<dyn DegradationPolicy>>>`. **They MUST
/// NEVER be held simultaneously.** Methods on this struct comply
/// with the following protocol:
///
/// | Method               | current | policies | Notes                       |
/// |----------------------|---------|----------|-----------------------------|
/// | `add_policy`         | -       | W        | leaf                        |
/// | `transition_count`   | R       | -        | leaf                        |
/// | `level`              | -       | -        | atomic-only (`level_cache`) |
/// | `tick`               | W       | W        | strictly sequential, see ↓  |
/// | `Debug::fmt`         | R       | -        | leaf                        |
/// | `BackpressureGate::check` | -  | -        | atomic-only (via `level`)   |
///
/// `tick` is the only method that touches both. It must use the
/// **drain-clone-release** pattern:
///
///   1. Lock `current`, mutate state, drop the guard.
///   2. Lock `policies`, clone the `Arc<dyn DegradationPolicy>`
///      pointers into a local `Vec`, drop the guard.
///   3. Call `policy.apply()` on each cloned `Arc` while no lock is
///      held.
///
/// Step 3 is critical: if `policy.apply()` re-enters the FSM (e.g.,
/// reads `level()` or registers a new policy), it must do so without
/// any lock being held by the caller, or the FSM will self-deadlock.
/// The `degradation_fsm_concurrent_tick_and_register_no_hang`
/// regression test exercises this contract under contention with a
/// watchdog timeout.
///
/// **Any new method that needs both must follow the same sequential
/// pattern: read out of one lock into a local, drop that lock, then
/// take the other.** A nested acquisition would silently introduce a
/// deadlock against any concurrent caller that took the locks in the
/// opposite order.
pub struct DegradationFsm {
    /// FSM state machine (level, recovery counter, transition count).
    /// **Never held simultaneously with `policies`.** `tick` MUST
    /// `drop(state)` before acquiring `policies`.
    current: parking_lot::Mutex<FsmState>,
    level_cache: std::sync::atomic::AtomicU8,
    pressure: Arc<SystemPressure>,
    /// Registered policies notified on each tick. **Never held
    /// simultaneously with `current`.** `tick` MUST clone the
    /// `Arc` pointers into a local Vec, drop the guard, then call
    /// `apply()` outside the lock.
    policies: parking_lot::Mutex<Vec<Arc<dyn DegradationPolicy>>>,
    recovery_samples: u32,
}

struct FsmState {
    level: DegradationLevel,
    /// Counter of consecutive samples at a level better than current.
    /// Must reach `recovery_samples` before de-escalation.
    recovery_count: u32,
    /// Total transitions since creation.
    transition_count: u64,
}

/// Record of a degradation level transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DegradationTransition {
    pub from: DegradationLevel,
    pub to: DegradationLevel,
    pub headroom: u32, // headroom * 1000, stored as integer to be Eq
}

impl DegradationFsm {
    /// Create a new FSM starting at `Normal`.
    ///
    /// `recovery_samples` is how many consecutive improved samples are needed
    /// before de-escalating (default: 3).
    #[must_use]
    pub fn new(pressure: Arc<SystemPressure>, recovery_samples: u32) -> Self {
        Self {
            current: parking_lot::Mutex::new(FsmState {
                level: DegradationLevel::Normal,
                recovery_count: 0,
                transition_count: 0,
            }),
            level_cache: std::sync::atomic::AtomicU8::new(u8::from(DegradationLevel::Normal)),
            pressure,
            policies: parking_lot::Mutex::new(Vec::new()),
            recovery_samples,
        }
    }

    /// Register a policy to be notified on level changes.
    pub fn add_policy(&self, policy: Arc<dyn DegradationPolicy>) {
        self.policies.lock().push(policy);
    }

    /// Current degradation level.
    #[must_use]
    pub fn level(&self) -> DegradationLevel {
        DegradationLevel::from_raw(self.level_cache.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Total number of transitions since creation.
    #[must_use]
    pub fn transition_count(&self) -> u64 {
        self.current.lock().transition_count
    }

    /// Tick the FSM with a fresh pressure reading.
    ///
    /// Returns `Some(transition)` if the level changed, `None` otherwise.
    pub fn tick(&self) -> Option<DegradationTransition> {
        let headroom = self.pressure.headroom();
        let observed = DegradationLevel::from_raw(self.pressure.degradation_level());

        let mut state = self.current.lock();
        let prev = state.level;

        match observed.cmp(&prev) {
            std::cmp::Ordering::Greater => {
                // Escalate immediately.
                state.level = observed;
                state.recovery_count = 0;
                state.transition_count = state.transition_count.saturating_add(1);
            }
            std::cmp::Ordering::Less => {
                // Require sustained improvement before de-escalating.
                state.recovery_count = state.recovery_count.saturating_add(1);
                if state.recovery_count >= self.recovery_samples {
                    state.level = observed;
                    state.recovery_count = 0;
                    state.transition_count = state.transition_count.saturating_add(1);
                }
            }
            std::cmp::Ordering::Equal => {
                state.recovery_count = 0;
            }
        }

        let new = state.level;
        self.level_cache
            .store(u8::from(new), std::sync::atomic::Ordering::Relaxed);
        drop(state);

        // Notify policies with current headroom (regardless of transition).
        // Clone Arc pointers and release lock before calling apply() to prevent
        // self-deadlock if any policy implementation calls back into the FSM.
        let policies: Vec<_> = self.policies.lock().iter().cloned().collect();
        for policy in policies {
            policy.apply(headroom);
        }

        if new == prev {
            None
        } else {
            info!(
                target: "ffs::backpressure",
                from = prev.label(),
                to = new.label(),
                headroom,
                "degradation_transition"
            );
            Some(DegradationTransition {
                from: prev,
                to: new,
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                headroom: (headroom * 1000.0) as u32,
            })
        }
    }
}

impl std::fmt::Debug for DegradationFsm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.current.lock();
        f.debug_struct("DegradationFsm")
            .field("level", &state.level)
            .field("recovery_count", &state.recovery_count)
            .field("transitions", &state.transition_count)
            .field("recovery_samples", &self.recovery_samples)
            .finish_non_exhaustive()
    }
}

// ── Backpressure gate ───────────────────────────────────────────────────────

/// Decision returned by [`BackpressureGate::check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackpressureDecision {
    /// Proceed normally.
    Proceed,
    /// Operation should be throttled (delay before proceeding).
    Throttle,
    /// Operation should be shed (rejected with EBUSY or ENOSPC).
    Shed,
}

/// Per-operation backpressure check.
///
/// Given a `DegradationFsm` and the type of operation, returns a decision
/// on whether to proceed, throttle, or shed the request.
pub struct BackpressureGate {
    fsm: Arc<DegradationFsm>,
}

impl BackpressureGate {
    /// Create a new gate wrapping the given FSM.
    #[must_use]
    pub fn new(fsm: Arc<DegradationFsm>) -> Self {
        Self { fsm }
    }

    /// Check whether the given operation should proceed.
    #[must_use]
    pub fn check(&self, op: RequestOp) -> BackpressureDecision {
        let level = self.fsm.level();
        match level {
            DegradationLevel::Normal | DegradationLevel::Warning => {
                // Normal and warning: all ops proceed (background pausing
                // is handled separately by the scrub/GC scheduler).
                BackpressureDecision::Proceed
            }
            DegradationLevel::Degraded => {
                // Reads always proceed; writes proceed but may be throttled.
                if op.is_write() {
                    BackpressureDecision::Throttle
                } else {
                    BackpressureDecision::Proceed
                }
            }
            DegradationLevel::Critical => {
                // Writes throttled, metadata writes shed.
                if op.is_metadata_write() {
                    BackpressureDecision::Shed
                } else if op.is_write() {
                    BackpressureDecision::Throttle
                } else {
                    BackpressureDecision::Proceed
                }
            }
            DegradationLevel::Emergency => {
                // Read-only mode: all writes shed.
                if op.is_write() {
                    BackpressureDecision::Shed
                } else {
                    BackpressureDecision::Proceed
                }
            }
        }
    }

    /// Current degradation level.
    #[must_use]
    pub fn level(&self) -> DegradationLevel {
        self.fsm.level()
    }
}

impl std::fmt::Debug for BackpressureGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackpressureGate")
            .field("level", &self.fsm.level())
            .finish()
    }
}

// ── Pressure monitor ────────────────────────────────────────────────────────

/// Aggregated pressure monitor that drives the degradation FSM.
///
/// Combines CPU load sampling (via `ComputeBudget`) with the FSM to provide
/// a single entry point for periodic pressure updates.
pub struct PressureMonitor {
    budget: ComputeBudget,
    fsm: Arc<DegradationFsm>,
    sample_count: AtomicU64,
}

impl PressureMonitor {
    /// Create a new monitor with a shared pressure handle and FSM.
    #[must_use]
    pub fn new(pressure: Arc<SystemPressure>, recovery_samples: u32) -> Self {
        let budget = ComputeBudget::new(Arc::clone(&pressure));
        let fsm = Arc::new(DegradationFsm::new(pressure, recovery_samples));
        Self {
            budget,
            fsm,
            sample_count: AtomicU64::new(0),
        }
    }

    /// Sample system pressure and tick the FSM.
    ///
    /// Returns any transition that occurred.
    pub fn sample(&self) -> Option<DegradationTransition> {
        self.budget.sample();
        saturating_increment_relaxed(&self.sample_count);
        self.fsm.tick()
    }

    /// Get a `BackpressureGate` for checking individual operations.
    #[must_use]
    pub fn gate(&self) -> BackpressureGate {
        BackpressureGate::new(Arc::clone(&self.fsm))
    }

    /// The underlying FSM.
    #[must_use]
    pub fn fsm(&self) -> &Arc<DegradationFsm> {
        &self.fsm
    }

    /// The underlying compute budget.
    #[must_use]
    pub fn budget(&self) -> &ComputeBudget {
        &self.budget
    }

    /// Number of samples taken.
    #[must_use]
    pub fn sample_count(&self) -> u64 {
        self.sample_count.load(Ordering::Relaxed)
    }

    /// Current degradation level.
    #[must_use]
    pub fn level(&self) -> DegradationLevel {
        self.fsm.level()
    }

    /// Register a degradation policy.
    pub fn add_policy(&self, policy: Arc<dyn DegradationPolicy>) {
        self.fsm.add_policy(policy);
    }
}

impl std::fmt::Debug for PressureMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PressureMonitor")
            .field("budget", &self.budget)
            .field("fsm", &self.fsm)
            .field("samples", &self.sample_count())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pressure_monitor_sample_count_saturates_at_numeric_limit() {
        let pressure = Arc::new(SystemPressure::new());
        let monitor = PressureMonitor::new(pressure, 1);
        monitor.sample_count.store(u64::MAX - 1, Ordering::Relaxed);

        monitor.sample();
        assert_eq!(monitor.sample_count(), u64::MAX);

        monitor.sample();
        assert_eq!(monitor.sample_count(), u64::MAX);
    }

    #[test]
    fn degradation_fsm_counters_saturate_at_numeric_limits() {
        let pressure = Arc::new(SystemPressure::new());
        let fsm = DegradationFsm::new(Arc::clone(&pressure), u32::MAX);

        {
            let mut state = fsm.current.lock();
            state.level = DegradationLevel::Normal;
            state.transition_count = u64::MAX;
        }

        pressure.set_headroom(0.05);
        let transition = fsm.tick().expect("escalation transition");
        assert_eq!(transition.from, DegradationLevel::Normal);
        assert_eq!(transition.to, DegradationLevel::Emergency);
        assert_eq!(fsm.transition_count(), u64::MAX);

        {
            let mut state = fsm.current.lock();
            state.level = DegradationLevel::Emergency;
            state.recovery_count = u32::MAX - 1;
            state.transition_count = u64::MAX;
        }

        pressure.set_headroom(0.95);
        let transition = fsm.tick().expect("recovery transition");
        assert_eq!(transition.from, DegradationLevel::Emergency);
        assert_eq!(transition.to, DegradationLevel::Normal);
        assert_eq!(fsm.transition_count(), u64::MAX);
        assert_eq!(fsm.current.lock().recovery_count, 0);
    }

    fn spawn_degradation_watchdog(
        stop: Arc<std::sync::atomic::AtomicBool>,
        completed: Arc<std::sync::atomic::AtomicBool>,
        timeout: std::time::Duration,
    ) -> std::thread::JoinHandle<bool> {
        const DEGRADATION_WATCHDOG_POLL_INTERVAL: std::time::Duration =
            std::time::Duration::from_millis(10);

        std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + timeout;
            loop {
                if completed.load(Ordering::Acquire) {
                    return false;
                }
                let now = std::time::Instant::now();
                if now >= deadline {
                    break;
                }
                std::thread::sleep(
                    DEGRADATION_WATCHDOG_POLL_INTERVAL.min(deadline.saturating_duration_since(now)),
                );
            }
            stop.store(true, Ordering::Release);
            true
        })
    }

    struct ReentrantCountingPolicy {
        apply_count: std::sync::atomic::AtomicUsize,
        fsm: parking_lot::Mutex<Option<Arc<DegradationFsm>>>,
    }

    impl ReentrantCountingPolicy {
        fn new(fsm: Arc<DegradationFsm>) -> Self {
            Self {
                apply_count: std::sync::atomic::AtomicUsize::new(0),
                fsm: parking_lot::Mutex::new(Some(fsm)),
            }
        }
    }

    impl DegradationPolicy for ReentrantCountingPolicy {
        fn apply(&self, _headroom: f32) {
            self.apply_count.fetch_add(1, Ordering::Relaxed);
            // Re-enter the FSM from the policy callback. This is
            // exactly the scenario that would self-deadlock if
            // tick() held either lock across the apply() call.
            let maybe_fsm = self.fsm.lock().clone();
            if let Some(fsm) = maybe_fsm {
                let _ = fsm.level();
                let _ = fsm.transition_count();
            }
        }

        fn name(&self) -> &'static str {
            "bd-2rxal-reentrant-counter"
        }
    }

    struct NopPolicy;

    impl DegradationPolicy for NopPolicy {
        fn apply(&self, _: f32) {}

        fn name(&self) -> &'static str {
            "bd-2rxal-nop"
        }
    }

    /// bd-2rxal — concurrent regression test for the
    /// never-held-simultaneously invariant on `current` and `policies`.
    /// If a future regression nested either lock under the other, OR
    /// held a lock across `policy.apply()`, this test would deadlock
    /// (caught by the watchdog) or panic when the policy callback
    /// re-entered the FSM. The callback intentionally calls back into
    /// `level()` and `transition_count()` to exercise the re-entry
    /// path that motivated the drain-clone-release pattern.
    #[test]
    fn degradation_fsm_concurrent_tick_and_register_no_hang() {
        use std::sync::atomic::AtomicBool;
        use std::time::{Duration, Instant};

        const ITERATIONS: usize = 256;
        const TICKERS: usize = 4;
        const REGISTERERS: usize = 2;
        const WATCHDOG_SECS: u64 = 5;

        let pressure = Arc::new(SystemPressure::new());
        let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 3));
        let policy = Arc::new(ReentrantCountingPolicy::new(Arc::clone(&fsm)));
        fsm.add_policy(Arc::clone(&policy) as Arc<dyn DegradationPolicy>);

        let stop = Arc::new(AtomicBool::new(false));
        let completed = Arc::new(AtomicBool::new(false));
        let mut ticker_handles = Vec::new();
        let mut registerer_handles = Vec::new();

        for _ in 0..TICKERS {
            let fsm = Arc::clone(&fsm);
            let pressure = Arc::clone(&pressure);
            let stop = Arc::clone(&stop);
            ticker_handles.push(std::thread::spawn(move || {
                for i in 0..ITERATIONS {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    // Alternate pressure to force escalations + recoveries.
                    pressure.set_headroom(if i % 2 == 0 { 0.05 } else { 0.95 });
                    let _ = fsm.tick();
                }
            }));
        }

        for _ in 0..REGISTERERS {
            let fsm = Arc::clone(&fsm);
            let stop = Arc::clone(&stop);
            registerer_handles.push(std::thread::spawn(move || {
                for _ in 0..ITERATIONS {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    fsm.add_policy(Arc::new(NopPolicy));
                }
            }));
        }

        let watchdog_handle = spawn_degradation_watchdog(
            Arc::clone(&stop),
            Arc::clone(&completed),
            Duration::from_secs(WATCHDOG_SECS),
        );

        let start = Instant::now();
        for handle in ticker_handles {
            handle.join().expect("ticker thread joins cleanly");
        }
        for handle in registerer_handles {
            handle.join().expect("registerer thread joins cleanly");
        }
        let elapsed = start.elapsed();
        completed.store(true, Ordering::Release);
        let watchdog_join_start = Instant::now();
        let watchdog_timed_out = watchdog_handle
            .join()
            .expect("watchdog thread joins cleanly");
        let watchdog_join_elapsed = watchdog_join_start.elapsed();

        assert!(
            elapsed < Duration::from_secs(WATCHDOG_SECS),
            "concurrent tick + add_policy must not deadlock; elapsed={elapsed:?}"
        );
        assert!(
            !watchdog_timed_out,
            "watchdog should not time out after workers completed successfully"
        );
        assert!(
            watchdog_join_elapsed < Duration::from_millis(250),
            "watchdog join should observe completion promptly; elapsed={watchdog_join_elapsed:?}"
        );
        assert!(
            policy.apply_count.load(Ordering::Relaxed) > 0,
            "policy.apply() must run at least once across the contention window"
        );
    }
}
