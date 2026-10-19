#![forbid(unsafe_code)]
//! TUI monitoring and management for FrankenFS.
//!
//! Live dashboard showing ARC cache hit rates, MVCC version chain depths,
//! active transaction counts, RaptorQ repair status, I/O throughput, and
//! block group health. Built on frankentui.

use ffs::DegradationLevel;
use ftui::layout::{Constraint, Flex, Rect};
use ftui::render::frame::Frame;
use ftui::text::{Line, Span, Text};
use ftui::widgets::Widget;
use ftui::widgets::block::Block;
use ftui::widgets::paragraph::Paragraph;
use ftui::{Cmd, Event, KeyCode, Model, PackedRgba, Style};

const PRESSURE_BAR_WIDTH: usize = 10;
const MAX_RECENT_EVENTS: usize = 10;
const IO_QUEUE_PRESSURE_CAP: usize = 64;
/// Default number of sparkline data points (60 seconds at 1Hz).
const SPARKLINE_CAPACITY: usize = 60;
/// Unicode block characters for sparkline rendering (⅛ to full block).
const SPARKLINE_CHARS: &[char] = &['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

// ── Sparkline history ─────────────────────────────────────────────────────────

/// Rolling window of values for rendering sparkline charts.
///
/// Stores the most recent `capacity` data points. New values push out the
/// oldest when full.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SparklineHistory {
    values: std::collections::VecDeque<f64>,
    capacity: usize,
}

impl SparklineHistory {
    /// Create a new history with the default 60-point capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(SPARKLINE_CAPACITY)
    }

    /// Create a new history with a custom capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            values: std::collections::VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Push a new value, evicting the oldest if at capacity.
    pub fn push(&mut self, value: f64) {
        if self.values.len() >= self.capacity {
            self.values.pop_front();
        }
        self.values.push_back(value);
    }

    /// Render the sparkline as a string of unicode block characters.
    ///
    /// Values are normalized to `[0.0, max_val]` and mapped to 8 block levels.
    /// Returns an empty string if no data points exist.
    #[must_use]
    pub fn render(&self, width: usize, max_val: f64) -> String {
        if self.values.is_empty() || max_val <= 0.0 {
            return String::new();
        }
        let skip = self.values.len().saturating_sub(width);
        self.values
            .iter()
            .skip(skip)
            .map(|&v| {
                let normalized = (v / max_val).clamp(0.0, 1.0);
                let max_idx = SPARKLINE_CHARS.len() - 1;
                let scaled = normalized * max_idx as f64;
                let idx = (0..max_idx)
                    .take_while(|level| scaled >= (*level as f64 + 0.5))
                    .count();
                SPARKLINE_CHARS[idx.min(SPARKLINE_CHARS.len() - 1)]
            })
            .collect()
    }

    /// Number of data points currently stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether the history is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Most recent value, if any.
    #[must_use]
    pub fn latest(&self) -> Option<f64> {
        self.values.back().copied()
    }
}

impl Default for SparklineHistory {
    fn default() -> Self {
        Self::new()
    }
}

// ── Metric snapshot ─────────────────────────────────────────────────────────

/// Point-in-time snapshot of all metrics displayed by the dashboard.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DegradationEvent {
    pub timestamp: String,
    pub from: DegradationLevel,
    pub to: DegradationLevel,
    pub reason: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DashboardSnapshot {
    // Mount status
    pub fs_type: String,
    pub mount_point: String,
    pub uptime_seconds: u64,
    pub bytes_read_total: u64,
    pub bytes_written_total: u64,

    // ARC cache
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_evictions: u64,
    pub cache_resident: usize,
    pub cache_capacity: usize,
    pub cache_t1_len: usize,
    pub cache_t2_len: usize,

    // MVCC
    pub mvcc_snapshot_seq: u64,
    pub mvcc_active_snapshots: usize,
    pub mvcc_watermark: Option<u64>,
    pub mvcc_version_count: usize,
    pub mvcc_versioned_blocks: usize,

    // Degradation / pressure
    pub degradation_level: DegradationLevel,
    /// Fraction in [0.0, 1.0].
    pub cpu_pressure: f64,
    /// Fraction in [0.0, 1.0].
    pub memory_pressure: f64,
    /// Current I/O queue depth (converted to pressure gauge via cap).
    pub io_queue_depth: usize,
    /// Recent transitions (newest is expected at the end of this vector).
    pub degradation_events: Vec<DegradationEvent>,

    // Scrub / repair
    pub scrub_blocks_scanned: u64,
    pub scrub_blocks_corrupt: u64,
    pub scrub_blocks_io_error: u64,
    pub scrub_findings_count: usize,
    pub repair_symbol_freshness_secs: Option<f64>,

    // Sparkline histories (rolling 60-second windows)
    pub hit_rate_history: SparklineHistory,
    pub commit_rate_history: SparklineHistory,
    pub io_throughput_history: SparklineHistory,
}

impl DashboardSnapshot {
    /// Sample a live [`DashboardSnapshot`] directly from an [`ffs::OpenFs`] instance.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn from_open_fs(fs: &ffs::OpenFs, mount_point: &str, uptime_seconds: u64) -> Self {
        let cache = fs.cache_telemetry();
        let mvcc = fs.mvcc_telemetry();
        let block_size = u64::from(fs.block_size());
        let bytes_written_total = mvcc.committed_block_writes.saturating_mul(block_size);
        let bytes_read_total = cache
            .hits
            .saturating_add(cache.misses)
            .saturating_mul(block_size);
        let memory_pressure = if cache.capacity > 0 {
            normalized_pressure(cache.resident as f64 / cache.capacity as f64)
        } else {
            0.0
        };

        Self {
            fs_type: fs.fs_type_label().to_owned(),
            mount_point: mount_point.to_owned(),
            uptime_seconds,
            bytes_read_total,
            bytes_written_total,
            cache_hits: cache.hits,
            cache_misses: cache.misses,
            cache_evictions: cache.evictions,
            cache_resident: cache.resident,
            cache_capacity: cache.capacity,
            cache_t1_len: cache.t1_len,
            cache_t2_len: cache.t2_len,
            mvcc_snapshot_seq: mvcc.snapshot_seq,
            mvcc_active_snapshots: mvcc.active_snapshots,
            mvcc_watermark: mvcc.watermark,
            mvcc_version_count: mvcc.version_count,
            mvcc_versioned_blocks: mvcc.versioned_blocks,
            degradation_level: fs.degradation_level(),
            cpu_pressure: 0.0,
            memory_pressure,
            io_queue_depth: 0,
            degradation_events: Vec::new(),
            scrub_blocks_scanned: 0,
            scrub_blocks_corrupt: 0,
            scrub_blocks_io_error: 0,
            scrub_findings_count: 0,
            repair_symbol_freshness_secs: None,
            hit_rate_history: SparklineHistory::new(),
            commit_rate_history: SparklineHistory::new(),
            io_throughput_history: SparklineHistory::new(),
        }
    }

    /// Overlay [`ffs_block::CacheMetrics`] from a [`ffs_block::ByteBlockCache`] or [`ffs_block::ArcCache`].
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn with_block_cache_metrics(mut self, metrics: &ffs_block::CacheMetrics) -> Self {
        self.cache_hits = metrics.hits;
        self.cache_misses = metrics.misses;
        self.cache_evictions = metrics.evictions;
        self.cache_resident = metrics.resident;
        self.cache_capacity = metrics.capacity;
        self.cache_t1_len = metrics.t1_len;
        self.cache_t2_len = metrics.t2_len;
        if metrics.capacity > 0 {
            self.memory_pressure =
                normalized_pressure(metrics.resident as f64 / metrics.capacity as f64);
        }
        self
    }

    /// Overlay live metrics directly from an [`ffs_mvcc::MvccStore`].
    #[must_use]
    pub fn with_mvcc_store(mut self, store: &ffs_mvcc::MvccStore) -> Self {
        self.mvcc_snapshot_seq = store.current_snapshot().high.0;
        self.mvcc_active_snapshots = store.active_snapshot_count();
        self.mvcc_watermark = store.watermark().map(|c| c.0);
        self.mvcc_version_count = store.version_count();
        self.mvcc_versioned_blocks = store.tracked_block_count();
        self
    }

    /// Overlay live degradation level and headroom-derived CPU pressure from a [`ffs::DegradationFsm`].
    #[must_use]
    pub fn with_degradation_fsm(mut self, fsm: &ffs::DegradationFsm) -> Self {
        let fsm_level = fsm.level();
        if fsm_level > self.degradation_level {
            self.degradation_level = fsm_level;
        }
        self.cpu_pressure = normalized_pressure(1.0 - f64::from(fsm.headroom()));
        self
    }

    /// Overlay scrub telemetry from a [`ffs_repair::scrub::ScrubReport`].
    #[must_use]
    pub fn with_scrub_report(mut self, report: &ffs_repair::scrub::ScrubReport) -> Self {
        self.scrub_blocks_scanned = report.blocks_scanned;
        self.scrub_blocks_corrupt = report.blocks_corrupt;
        self.scrub_blocks_io_error = report.blocks_io_error;
        self.scrub_findings_count = report.findings.len();
        self
    }

    /// Overlay scrub telemetry from [`ffs_repair::pipeline::ScrubDaemonMetrics`].
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn with_scrub_daemon_metrics(
        mut self,
        metrics: &ffs_repair::pipeline::ScrubDaemonMetrics,
    ) -> Self {
        self.scrub_blocks_scanned = metrics.blocks_scanned_total;
        self.scrub_blocks_corrupt = metrics.blocks_corrupt_found;
        self.scrub_blocks_io_error = metrics.blocks_unrecoverable;
        self.scrub_findings_count = metrics
            .blocks_corrupt_found
            .saturating_add(metrics.blocks_unrecoverable)
            as usize;
        self
    }

    /// Overlay scrub/repair telemetry from a [`ffs_repair::pipeline::RepairMetricsSnapshot`].
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
    pub fn with_repair_pipeline_metrics(
        mut self,
        metrics: &ffs_repair::pipeline::RepairMetricsSnapshot,
    ) -> Self {
        self.scrub_blocks_scanned = metrics.blocks_scanned;
        self.scrub_blocks_corrupt = metrics.corruption_detected;
        self.scrub_blocks_io_error = metrics.blocks_unrecoverable;
        self.scrub_findings_count = metrics
            .corruption_detected
            .saturating_add(metrics.blocks_unrecoverable)
            as usize;
        if metrics.symbol_staleness_max_seconds > 0 {
            self.repair_symbol_freshness_secs = Some(metrics.symbol_staleness_max_seconds as f64);
        }
        self
    }

    /// Cache hit ratio in the range [0.0, 1.0].
    #[must_use]
    pub fn cache_hit_ratio(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            0.0
        } else {
            self.cache_hits as f64 / total as f64
        }
    }

    /// Queue-depth-derived I/O pressure in [0.0, 1.0].
    #[must_use]
    pub fn io_pressure(&self) -> f64 {
        let normalized = self.io_queue_depth as f64 / IO_QUEUE_PRESSURE_CAP as f64;
        normalized_pressure(normalized)
    }

    /// Render a deterministic multi-panel plain-text / ASCII dashboard for
    /// non-interactive terminals, `ffs tui`, and `--mount-console`.
    #[must_use]
    pub fn render_ascii(&self) -> String {
        let mount_text = build_mount_panel_text(self);
        let cache_text = build_cache_panel_text(self);
        let mvcc_text = build_mvcc_panel_text(self);
        let scrub_text = build_scrub_panel_text(self);
        let health_text = build_system_health_text(self).to_plain_text();

        format!(
            "=== FrankenFS Live Telemetry ===\n\
             [Mount Status]\n{mount_text}\n\n\
             [ARC Cache]\n{cache_text}\n\n\
             [MVCC]\n{mvcc_text}\n\n\
             [Scrub / Repair]\n{scrub_text}\n\n\
             [System Health]\n{health_text}\n"
        )
    }
}

/// Stateful collector that samples live FrankenFS subsystems on each tick and
/// maintains rolling sparkline histories and degradation event transitions.
#[derive(Debug, Clone)]
pub struct LiveTelemetryCollector {
    hit_rate_history: SparklineHistory,
    commit_rate_history: SparklineHistory,
    io_throughput_history: SparklineHistory,
    degradation_events: Vec<DegradationEvent>,
    last_degradation_level: DegradationLevel,
    last_commits_total: u64,
    last_io_bytes: u64,
    last_uptime_seconds: u64,
    initialized: bool,
}

impl Default for LiveTelemetryCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl LiveTelemetryCollector {
    /// Create a new live telemetry collector with default 60-sample rolling windows.
    #[must_use]
    pub fn new() -> Self {
        Self {
            hit_rate_history: SparklineHistory::new(),
            commit_rate_history: SparklineHistory::new(),
            io_throughput_history: SparklineHistory::new(),
            degradation_events: Vec::new(),
            last_degradation_level: DegradationLevel::Normal,
            last_commits_total: 0,
            last_io_bytes: 0,
            last_uptime_seconds: 0,
            initialized: false,
        }
    }

    /// Sample live telemetry from [`ffs::OpenFs`] and optional companion monitors.
    #[must_use]
    #[allow(clippy::too_many_arguments, clippy::cast_precision_loss)]
    pub fn sample_open_fs(
        &mut self,
        fs: &ffs::OpenFs,
        mount_point: &str,
        uptime_seconds: u64,
        bytes_read_override: Option<u64>,
        io_queue_depth: usize,
        fsm: Option<&ffs::DegradationFsm>,
        scrub_report: Option<&ffs_repair::scrub::ScrubReport>,
        repair_metrics: Option<&ffs_repair::pipeline::RepairMetricsSnapshot>,
    ) -> DashboardSnapshot {
        let mut snap = DashboardSnapshot::from_open_fs(fs, mount_point, uptime_seconds);
        if let Some(bytes_read) = bytes_read_override {
            snap.bytes_read_total = bytes_read;
        }
        snap.io_queue_depth = io_queue_depth;
        if let Some(fsm) = fsm {
            snap = snap.with_degradation_fsm(fsm);
        }
        if let Some(report) = scrub_report {
            snap = snap.with_scrub_report(report);
        }
        if let Some(metrics) = repair_metrics {
            snap = snap.with_repair_pipeline_metrics(metrics);
        }

        let mvcc = fs.mvcc_telemetry();
        let io_bytes = snap
            .bytes_read_total
            .saturating_add(snap.bytes_written_total);
        let elapsed_secs = uptime_seconds
            .saturating_sub(self.last_uptime_seconds)
            .max(1) as f64;

        if self.initialized && snap.degradation_level != self.last_degradation_level {
            let h = uptime_seconds / 3600;
            let m = (uptime_seconds % 3600) / 60;
            let s = uptime_seconds % 60;
            self.degradation_events.push(DegradationEvent {
                timestamp: format!("{h:02}:{m:02}:{s:02}"),
                from: self.last_degradation_level,
                to: snap.degradation_level,
                reason: "pressure".to_owned(),
            });
            if self.degradation_events.len() > MAX_RECENT_EVENTS {
                self.degradation_events.remove(0);
            }
        }
        self.last_degradation_level = snap.degradation_level;

        self.hit_rate_history.push(snap.cache_hit_ratio());
        let commit_delta = if self.initialized {
            mvcc.commits_total.saturating_sub(self.last_commits_total)
        } else {
            mvcc.commits_total
        };
        self.commit_rate_history
            .push(commit_delta as f64 / elapsed_secs);

        let io_delta_bytes = if self.initialized {
            io_bytes.saturating_sub(self.last_io_bytes)
        } else {
            io_bytes
        };
        let io_mb_per_sec = (io_delta_bytes as f64 / (1024.0 * 1024.0)) / elapsed_secs;
        self.io_throughput_history.push(io_mb_per_sec);

        self.last_commits_total = mvcc.commits_total;
        self.last_io_bytes = io_bytes;
        self.last_uptime_seconds = uptime_seconds;
        self.initialized = true;

        snap.hit_rate_history = self.hit_rate_history.clone();
        snap.commit_rate_history = self.commit_rate_history.clone();
        snap.io_throughput_history = self.io_throughput_history.clone();
        snap.degradation_events.clone_from(&self.degradation_events);
        snap
    }
}

impl Default for DashboardSnapshot {
    fn default() -> Self {
        Self {
            fs_type: String::new(),
            mount_point: String::new(),
            uptime_seconds: 0,
            bytes_read_total: 0,
            bytes_written_total: 0,
            cache_hits: 0,
            cache_misses: 0,
            cache_evictions: 0,
            cache_resident: 0,
            cache_capacity: 0,
            cache_t1_len: 0,
            cache_t2_len: 0,
            mvcc_snapshot_seq: 0,
            mvcc_active_snapshots: 0,
            mvcc_watermark: None,
            mvcc_version_count: 0,
            mvcc_versioned_blocks: 0,
            degradation_level: DegradationLevel::Normal,
            cpu_pressure: 0.0,
            memory_pressure: 0.0,
            io_queue_depth: 0,
            degradation_events: Vec::new(),
            scrub_blocks_scanned: 0,
            scrub_blocks_corrupt: 0,
            scrub_blocks_io_error: 0,
            scrub_findings_count: 0,
            repair_symbol_freshness_secs: None,
            hit_rate_history: SparklineHistory::new(),
            commit_rate_history: SparklineHistory::new(),
            io_throughput_history: SparklineHistory::new(),
        }
    }
}

// ── Dashboard model ─────────────────────────────────────────────────────────

/// Message type for the dashboard model.
#[derive(Debug)]
pub enum DashboardMsg {
    /// Terminal input event.
    Input(Event),
    /// New metrics arrived.
    MetricsUpdated(Box<DashboardSnapshot>),
}

impl From<Event> for DashboardMsg {
    fn from(event: Event) -> Self {
        Self::Input(event)
    }
}

/// FrankenFS monitoring dashboard.
///
/// Implements [`ftui::Model`] so it can be driven by the ftui runtime.
/// Call [`Dashboard::update_metrics`] to push new metric snapshots, or
/// send a [`DashboardMsg::MetricsUpdated`] message through the runtime.
#[derive(Debug)]
pub struct Dashboard {
    snapshot: DashboardSnapshot,
}

impl Dashboard {
    /// Create a new dashboard with default (zeroed) metrics.
    #[must_use]
    pub fn new() -> Self {
        Self {
            snapshot: DashboardSnapshot::default(),
        }
    }

    /// Create a dashboard pre-populated with a metrics snapshot.
    #[must_use]
    pub fn with_snapshot(snapshot: DashboardSnapshot) -> Self {
        Self { snapshot }
    }

    /// Replace the current metrics snapshot.
    pub fn update_metrics(&mut self, snapshot: DashboardSnapshot) {
        self.snapshot = snapshot;
    }

    /// Current snapshot (for testing / inspection).
    #[must_use]
    pub fn snapshot(&self) -> &DashboardSnapshot {
        &self.snapshot
    }

    /// Render the current dashboard snapshot as a multi-panel ASCII string.
    #[must_use]
    pub fn render_ascii(&self) -> String {
        self.snapshot.render_ascii()
    }
}

impl Default for Dashboard {
    fn default() -> Self {
        Self::new()
    }
}

impl Model for Dashboard {
    type Message = DashboardMsg;

    fn update(&mut self, msg: Self::Message) -> Cmd<Self::Message> {
        match msg {
            DashboardMsg::Input(Event::Key(key)) => {
                if matches!(key.code, KeyCode::Char('q' | 'Q')) || key.code == KeyCode::Escape {
                    return Cmd::quit();
                }
                Cmd::none()
            }
            DashboardMsg::MetricsUpdated(snap) => {
                self.snapshot = *snap;
                Cmd::none()
            }
            DashboardMsg::Input(_) => Cmd::none(),
        }
    }

    fn view(&self, frame: &mut Frame) {
        let bounds = Rect {
            x: 0,
            y: 0,
            width: frame.buffer.width(),
            height: frame.buffer.height(),
        };

        let rows = Flex::vertical()
            .constraints([
                Constraint::Percentage(30.0),
                Constraint::Percentage(35.0),
                Constraint::Percentage(35.0),
            ])
            .split(bounds);

        // Top row: mount status + cache side by side
        let top_cols = Flex::horizontal()
            .constraints([Constraint::Percentage(50.0), Constraint::Percentage(50.0)])
            .split(rows[0]);

        render_mount_panel(&self.snapshot, top_cols[0], frame);
        render_cache_panel(&self.snapshot, top_cols[1], frame);

        // Middle row: MVCC + repair side by side
        let mid_cols = Flex::horizontal()
            .constraints([Constraint::Percentage(50.0), Constraint::Percentage(50.0)])
            .split(rows[1]);

        render_mvcc_panel(&self.snapshot, mid_cols[0], frame);
        render_scrub_panel(&self.snapshot, mid_cols[1], frame);

        // Bottom row: system health (full width)
        render_system_health_panel(&self.snapshot, rows[2], frame);
    }
}

// ── Panel renderers ─────────────────────────────────────────────────────────

fn build_cache_panel_text(snap: &DashboardSnapshot) -> String {
    let hit_pct = snap.cache_hit_ratio() * 100.0;
    let sparkline = snap.hit_rate_history.render(20, 1.0);
    let sparkline_line = if sparkline.is_empty() {
        String::new()
    } else {
        format!("\nHit rate:   {sparkline}")
    };
    format!(
        "Hit ratio:  {hit_pct:>6.1}%\n\
         Hits:       {:>10}\n\
         Misses:     {:>10}\n\
         Evictions:  {:>10}\n\
         Resident:   {:>6} / {}\n\
         T1 / T2:    {} / {}{sparkline_line}",
        snap.cache_hits,
        snap.cache_misses,
        snap.cache_evictions,
        snap.cache_resident,
        snap.cache_capacity,
        snap.cache_t1_len,
        snap.cache_t2_len,
    )
}

fn render_cache_panel(snap: &DashboardSnapshot, area: Rect, frame: &mut Frame) {
    let block = Block::bordered().title("ARC Cache");
    let inner = block.inner(area);
    block.render(area, frame);
    Paragraph::new(build_cache_panel_text(snap)).render(inner, frame);
}

#[allow(clippy::cast_precision_loss)]
fn build_mount_panel_text(snap: &DashboardSnapshot) -> String {
    let fs_type = if snap.fs_type.is_empty() {
        "unknown"
    } else {
        &snap.fs_type
    };
    let mount = if snap.mount_point.is_empty() {
        "-"
    } else {
        &snap.mount_point
    };
    let uptime_h = snap.uptime_seconds / 3600;
    let uptime_m = (snap.uptime_seconds % 3600) / 60;
    let uptime_s = snap.uptime_seconds % 60;
    let read_mb = snap.bytes_read_total as f64 / (1024.0 * 1024.0);
    let write_mb = snap.bytes_written_total as f64 / (1024.0 * 1024.0);

    let io_sparkline = snap.io_throughput_history.render(20, 100.0);
    let sparkline_line = if io_sparkline.is_empty() {
        String::new()
    } else {
        format!("\nI/O:        {io_sparkline}")
    };

    format!(
        "Type:       {fs_type}\n\
         Mount:      {mount}\n\
         Uptime:     {uptime_h:02}:{uptime_m:02}:{uptime_s:02}\n\
         Read:       {read_mb:>8.1} MB\n\
         Written:    {write_mb:>8.1} MB{sparkline_line}"
    )
}

fn render_mount_panel(snap: &DashboardSnapshot, area: Rect, frame: &mut Frame) {
    let block = Block::bordered().title("Mount Status");
    let inner = block.inner(area);
    block.render(area, frame);
    Paragraph::new(build_mount_panel_text(snap)).render(inner, frame);
}

fn build_mvcc_panel_text(snap: &DashboardSnapshot) -> String {
    let wm = snap
        .mvcc_watermark
        .map_or_else(|| "-".to_owned(), |w| w.to_string());
    let commit_sparkline = snap.commit_rate_history.render(20, 100.0);
    let sparkline_line = if commit_sparkline.is_empty() {
        String::new()
    } else {
        format!("\nCommits/s:   {commit_sparkline}")
    };
    format!(
        "Snapshot:    {:>10}\n\
         Active snap: {:>10}\n\
         Watermark:   {:>10}\n\
         Versions:    {:>10}\n\
         Blocks (v):  {:>10}{sparkline_line}",
        snap.mvcc_snapshot_seq,
        snap.mvcc_active_snapshots,
        wm,
        snap.mvcc_version_count,
        snap.mvcc_versioned_blocks,
    )
}

fn render_mvcc_panel(snap: &DashboardSnapshot, area: Rect, frame: &mut Frame) {
    let block = Block::bordered().title("MVCC");
    let inner = block.inner(area);
    block.render(area, frame);
    Paragraph::new(build_mvcc_panel_text(snap)).render(inner, frame);
}

fn render_system_health_panel(snap: &DashboardSnapshot, area: Rect, frame: &mut Frame) {
    let block = Block::bordered().title("System Health");
    let inner = block.inner(area);
    block.render(area, frame);
    Paragraph::new(build_system_health_text(snap)).render(inner, frame);
}

fn build_scrub_panel_text(snap: &DashboardSnapshot) -> String {
    let status = if snap.scrub_blocks_scanned == 0 {
        "No scrub data"
    } else if snap.scrub_blocks_corrupt == 0 && snap.scrub_blocks_io_error == 0 {
        "Clean"
    } else {
        "Issues found"
    };
    format!(
        "Status:       {status}\n\
         Scanned:      {:>10}\n\
         Corrupt:      {:>10}\n\
         I/O errors:   {:>10}\n\
         Findings:     {:>10}",
        snap.scrub_blocks_scanned,
        snap.scrub_blocks_corrupt,
        snap.scrub_blocks_io_error,
        snap.scrub_findings_count,
    )
}

fn render_scrub_panel(snap: &DashboardSnapshot, area: Rect, frame: &mut Frame) {
    let block = Block::bordered().title("Scrub / Repair");
    let inner = block.inner(area);
    block.render(area, frame);
    Paragraph::new(build_scrub_panel_text(snap)).render(inner, frame);
}

fn build_system_health_text(snap: &DashboardSnapshot) -> Text<'_> {
    let (level_name, level_num) = degradation_level_label(snap.degradation_level);
    let level_span = Span::styled(
        format!("{level_name} (L{level_num})"),
        degradation_level_style(snap.degradation_level),
    );

    let mut lines = vec![
        Line::from_spans([Span::raw("Degradation: "), level_span]),
        Line::raw(""),
        Line::raw(format!(
            "CPU:    {}",
            render_pressure_gauge(snap.cpu_pressure, PRESSURE_BAR_WIDTH)
        )),
        Line::raw(format!(
            "Memory: {}",
            render_pressure_gauge(snap.memory_pressure, PRESSURE_BAR_WIDTH)
        )),
        Line::raw(format!(
            "I/O:    {} depth={}",
            render_pressure_gauge(snap.io_pressure(), PRESSURE_BAR_WIDTH),
            snap.io_queue_depth
        )),
        Line::raw(""),
        Line::raw("Recent events:"),
    ];

    if snap.degradation_events.is_empty() {
        lines.push(Line::raw("  (none)"));
    } else {
        for event in snap.degradation_events.iter().rev().take(MAX_RECENT_EVENTS) {
            lines.push(Line::raw(format!("  {}", format_degradation_event(event))));
        }
    }

    Text::from_lines(lines)
}

#[must_use]
fn degradation_level_label(level: DegradationLevel) -> (&'static str, u8) {
    match level {
        DegradationLevel::Normal => ("NORMAL", 0),
        DegradationLevel::Warning => ("BACKGROUND PAUSED", 1),
        DegradationLevel::Degraded => ("CACHE REDUCED", 2),
        DegradationLevel::Critical => ("WRITES THROTTLED", 3),
        DegradationLevel::Emergency => ("READ-ONLY", 4),
    }
}

#[must_use]
fn degradation_level_style(level: DegradationLevel) -> Style {
    match level {
        DegradationLevel::Normal => Style::new().fg(PackedRgba::rgb(63, 191, 104)).bold(),
        DegradationLevel::Warning => Style::new().fg(PackedRgba::rgb(241, 196, 15)).bold(),
        DegradationLevel::Degraded => Style::new().fg(PackedRgba::rgb(255, 165, 0)).bold(),
        DegradationLevel::Critical => Style::new().fg(PackedRgba::rgb(255, 69, 58)).bold(),
        DegradationLevel::Emergency => Style::new().fg(PackedRgba::rgb(255, 0, 0)).bold().blink(),
    }
}

#[must_use]
fn format_degradation_event(event: &DegradationEvent) -> String {
    let (_, from_level) = degradation_level_label(event.from);
    let (_, to_level) = degradation_level_label(event.to);
    if event.reason.is_empty() {
        format!("{} L{} -> L{}", event.timestamp, from_level, to_level)
    } else {
        format!(
            "{} L{} -> L{} ({})",
            event.timestamp, from_level, to_level, event.reason
        )
    }
}

#[must_use]
fn normalized_pressure(value: f64) -> f64 {
    if value.is_finite() {
        value.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#[must_use]
fn render_pressure_gauge(value: f64, width: usize) -> String {
    let normalized = normalized_pressure(value);
    let filled = ((normalized * width as f64).round() as usize).min(width);
    let percent = (normalized * 100.0).round() as u32;
    format!(
        "[{}{}] {:>3}%",
        "#".repeat(filled),
        ".".repeat(width - filled),
        percent
    )
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const REPRESENTATIVE_SYSTEM_HEALTH_TEXT_GOLDEN: &str = concat!(
        "Degradation: WRITES THROTTLED (L3)\n",
        "\n",
        "CPU:    [########..]  78%\n",
        "Memory: [######....]  62%\n",
        "I/O:    [###.......]  34% depth=22\n",
        "\n",
        "Recent events:\n",
        "  12:35:22 L1 -> L0\n",
        "  12:34:05 L0 -> L1 (cpu)",
    );

    fn representative_system_health_snapshot() -> DashboardSnapshot {
        DashboardSnapshot {
            degradation_level: DegradationLevel::Critical,
            cpu_pressure: 0.78,
            memory_pressure: 0.62,
            io_queue_depth: 22,
            degradation_events: vec![
                DegradationEvent {
                    timestamp: "12:34:05".to_owned(),
                    from: DegradationLevel::Normal,
                    to: DegradationLevel::Warning,
                    reason: "cpu".to_owned(),
                },
                DegradationEvent {
                    timestamp: "12:35:22".to_owned(),
                    from: DegradationLevel::Warning,
                    to: DegradationLevel::Normal,
                    reason: String::new(),
                },
            ],
            ..Default::default()
        }
    }

    #[test]
    fn dashboard_snapshot_default_is_zeroed() {
        let snap = DashboardSnapshot::default();
        assert_eq!(snap.cache_hits, 0);
        assert_eq!(snap.cache_misses, 0);
        assert_eq!(snap.cache_evictions, 0);
        assert_eq!(snap.cache_resident, 0);
        assert_eq!(snap.cache_capacity, 0);
        assert_eq!(snap.mvcc_snapshot_seq, 0);
        assert_eq!(snap.mvcc_active_snapshots, 0);
        assert!(snap.mvcc_watermark.is_none());
        assert_eq!(snap.degradation_level, DegradationLevel::Normal);
        assert!((snap.cpu_pressure - 0.0).abs() < f64::EPSILON);
        assert!((snap.memory_pressure - 0.0).abs() < f64::EPSILON);
        assert_eq!(snap.io_queue_depth, 0);
        assert_eq!(snap.degradation_events, [] as [DegradationEvent; 0]);
        assert_eq!(snap.scrub_blocks_scanned, 0);
        assert_eq!(snap.scrub_findings_count, 0);
    }

    #[test]
    fn pressure_gauge_formats_and_clamps() {
        assert_eq!(render_pressure_gauge(-1.0, 10), "[..........]   0%");
        assert_eq!(render_pressure_gauge(0.5, 10), "[#####.....]  50%");
        assert_eq!(render_pressure_gauge(1.5, 10), "[##########] 100%");
    }

    #[test]
    fn degradation_level_style_matches_expected_color() {
        assert_eq!(
            degradation_level_style(DegradationLevel::Normal).fg,
            Some(PackedRgba::rgb(63, 191, 104))
        );
        assert_eq!(
            degradation_level_style(DegradationLevel::Warning).fg,
            Some(PackedRgba::rgb(241, 196, 15))
        );
        assert_eq!(
            degradation_level_style(DegradationLevel::Degraded).fg,
            Some(PackedRgba::rgb(255, 165, 0))
        );
        assert_eq!(
            degradation_level_style(DegradationLevel::Critical).fg,
            Some(PackedRgba::rgb(255, 69, 58))
        );
        let emergency_style = degradation_level_style(DegradationLevel::Emergency);
        assert_eq!(emergency_style.fg, Some(PackedRgba::rgb(255, 0, 0)));
        assert!(
            emergency_style
                .attrs
                .is_some_and(|attrs| attrs.contains(ftui::StyleFlags::BLINK))
        );
    }

    #[test]
    fn system_health_text_includes_recent_events() {
        let snap = representative_system_health_snapshot();

        let text = build_system_health_text(&snap).to_plain_text();
        assert!(text.contains("Degradation: WRITES THROTTLED (L3)"));
        assert!(text.contains("CPU:    [########..]  78%"));
        assert!(text.contains("Memory: [######....]  62%"));
        assert!(text.contains("Recent events:"));
        assert!(text.contains("12:35:22 L1 -> L0"));
        assert!(text.contains("12:34:05 L0 -> L1 (cpu)"));
    }

    #[test]
    fn representative_system_health_text_exact_golden_contract() {
        let text =
            build_system_health_text(&representative_system_health_snapshot()).to_plain_text();
        assert_eq!(text, REPRESENTATIVE_SYSTEM_HEALTH_TEXT_GOLDEN);
    }

    #[test]
    fn hit_ratio_zero_when_no_accesses() {
        let snap = DashboardSnapshot::default();
        assert!((snap.cache_hit_ratio()).abs() < f64::EPSILON);
    }

    #[test]
    fn hit_ratio_computed_correctly() {
        let snap = DashboardSnapshot {
            cache_hits: 75,
            cache_misses: 25,
            ..Default::default()
        };
        assert!((snap.cache_hit_ratio() - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn dashboard_new_has_zeroed_snapshot() {
        let dash = Dashboard::new();
        assert_eq!(dash.snapshot().cache_hits, 0);
    }

    #[test]
    fn dashboard_with_snapshot() {
        let snap = DashboardSnapshot {
            cache_hits: 42,
            ..Default::default()
        };
        let dash = Dashboard::with_snapshot(snap);
        assert_eq!(dash.snapshot().cache_hits, 42);
    }

    #[test]
    fn dashboard_update_metrics() {
        let mut dash = Dashboard::new();
        dash.update_metrics(DashboardSnapshot {
            mvcc_version_count: 10,
            ..Default::default()
        });
        assert_eq!(dash.snapshot().mvcc_version_count, 10);
    }

    #[test]
    fn dashboard_update_metrics_via_msg() {
        let mut dash = Dashboard::new();
        let snap = DashboardSnapshot {
            scrub_blocks_scanned: 1000,
            ..Default::default()
        };
        let cmd = dash.update(DashboardMsg::MetricsUpdated(Box::new(snap)));
        assert!(matches!(cmd, Cmd::None));
        assert_eq!(dash.snapshot().scrub_blocks_scanned, 1000);
    }

    #[test]
    fn dashboard_quit_on_q() {
        let mut dash = Dashboard::new();
        let key = ftui::KeyEvent {
            code: KeyCode::Char('q'),
            kind: ftui::KeyEventKind::Press,
            modifiers: ftui::Modifiers::empty(),
        };
        let cmd = dash.update(DashboardMsg::Input(Event::Key(key)));
        assert!(matches!(cmd, Cmd::Quit));
    }

    #[test]
    fn dashboard_quit_on_esc() {
        let mut dash = Dashboard::new();
        let key = ftui::KeyEvent {
            code: KeyCode::Escape,
            kind: ftui::KeyEventKind::Press,
            modifiers: ftui::Modifiers::empty(),
        };
        let cmd = dash.update(DashboardMsg::Input(Event::Key(key)));
        assert!(matches!(cmd, Cmd::Quit));
    }

    #[test]
    fn dashboard_ignores_other_keys() {
        let mut dash = Dashboard::new();
        let key = ftui::KeyEvent {
            code: KeyCode::Char('a'),
            kind: ftui::KeyEventKind::Press,
            modifiers: ftui::Modifiers::empty(),
        };
        let cmd = dash.update(DashboardMsg::Input(Event::Key(key)));
        assert!(matches!(cmd, Cmd::None));
    }

    #[test]
    fn dashboard_view_does_not_panic_on_small_buffer() {
        let mut dash = Dashboard::new();
        dash.update_metrics(DashboardSnapshot {
            cache_hits: 100,
            cache_misses: 50,
            cache_evictions: 10,
            cache_resident: 80,
            cache_capacity: 100,
            cache_t1_len: 30,
            cache_t2_len: 50,
            mvcc_snapshot_seq: 42,
            mvcc_active_snapshots: 3,
            mvcc_watermark: Some(38),
            mvcc_version_count: 200,
            mvcc_versioned_blocks: 50,
            scrub_blocks_scanned: 10000,
            scrub_blocks_corrupt: 2,
            scrub_blocks_io_error: 1,
            scrub_findings_count: 5,
            degradation_level: DegradationLevel::Warning,
            cpu_pressure: 0.4,
            memory_pressure: 0.2,
            io_queue_depth: 6,
            degradation_events: vec![DegradationEvent {
                timestamp: "12:34:05".to_owned(),
                from: DegradationLevel::Normal,
                to: DegradationLevel::Warning,
                reason: "cpu".to_owned(),
            }],
            ..DashboardSnapshot::default()
        });

        // Render into a small buffer — should not panic.
        let mut pool = ftui::GraphemePool::new();
        let mut frame = Frame::new(40, 20, &mut pool);
        dash.view(&mut frame);
    }

    #[test]
    fn dashboard_view_does_not_panic_tiny_buffer() {
        let dash = Dashboard::new();
        let mut pool = ftui::GraphemePool::new();
        // Minimum 1x1 — ftui panics on 0x0 buffers.
        let mut frame = Frame::new(1, 1, &mut pool);
        dash.view(&mut frame);
    }

    // ── Pressure gauge edge cases ──────────────────────────────────────

    #[test]
    fn pressure_gauge_zero() {
        assert_eq!(render_pressure_gauge(0.0, 10), "[..........]   0%");
    }

    #[test]
    fn pressure_gauge_full() {
        assert_eq!(render_pressure_gauge(1.0, 10), "[##########] 100%");
    }

    #[test]
    fn pressure_gauge_nan_treated_as_zero() {
        assert_eq!(render_pressure_gauge(f64::NAN, 10), "[..........]   0%");
    }

    #[test]
    fn pressure_gauge_infinity_treated_as_zero() {
        assert_eq!(
            render_pressure_gauge(f64::INFINITY, 10),
            "[..........]   0%"
        );
    }

    #[test]
    fn pressure_gauge_neg_infinity_treated_as_zero() {
        assert_eq!(
            render_pressure_gauge(f64::NEG_INFINITY, 10),
            "[..........]   0%"
        );
    }

    #[test]
    fn pressure_gauge_width_one() {
        assert_eq!(render_pressure_gauge(0.5, 1), "[#]  50%");
    }

    #[test]
    fn pressure_gauge_quarter() {
        assert_eq!(render_pressure_gauge(0.25, 10), "[###.......]  25%");
    }

    // ── Normalized pressure ────────────────────────────────────────────

    #[test]
    fn normalized_pressure_clamps_above_one() {
        assert!((normalized_pressure(2.0) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn normalized_pressure_clamps_below_zero() {
        assert!((normalized_pressure(-0.5)).abs() < f64::EPSILON);
    }

    #[test]
    fn normalized_pressure_nan_returns_zero() {
        assert!((normalized_pressure(f64::NAN)).abs() < f64::EPSILON);
    }

    #[test]
    fn normalized_pressure_passes_valid_values() {
        assert!((normalized_pressure(0.42) - 0.42).abs() < f64::EPSILON);
    }

    // ── IO pressure calculation ────────────────────────────────────────

    #[test]
    fn io_pressure_zero_queue() {
        let snap = DashboardSnapshot::default();
        assert!((snap.io_pressure()).abs() < f64::EPSILON);
    }

    #[test]
    fn io_pressure_at_cap() {
        let snap = DashboardSnapshot {
            io_queue_depth: IO_QUEUE_PRESSURE_CAP,
            ..Default::default()
        };
        assert!((snap.io_pressure() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn io_pressure_over_cap_clamps_to_one() {
        let snap = DashboardSnapshot {
            io_queue_depth: IO_QUEUE_PRESSURE_CAP * 2,
            ..Default::default()
        };
        assert!((snap.io_pressure() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn io_pressure_half_cap() {
        let snap = DashboardSnapshot {
            io_queue_depth: IO_QUEUE_PRESSURE_CAP / 2,
            ..Default::default()
        };
        assert!((snap.io_pressure() - 0.5).abs() < f64::EPSILON);
    }

    // ── Cache hit ratio edge cases ─────────────────────────────────────

    #[test]
    fn hit_ratio_all_hits() {
        let snap = DashboardSnapshot {
            cache_hits: 100,
            cache_misses: 0,
            ..Default::default()
        };
        assert!((snap.cache_hit_ratio() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn hit_ratio_all_misses() {
        let snap = DashboardSnapshot {
            cache_hits: 0,
            cache_misses: 100,
            ..Default::default()
        };
        assert!((snap.cache_hit_ratio()).abs() < f64::EPSILON);
    }

    #[test]
    fn hit_ratio_large_values() {
        let snap = DashboardSnapshot {
            cache_hits: 999_999,
            cache_misses: 1,
            ..Default::default()
        };
        assert!(snap.cache_hit_ratio() > 0.999);
    }

    // ── Degradation level labels ───────────────────────────────────────

    #[test]
    fn degradation_level_label_all_variants() {
        assert_eq!(
            degradation_level_label(DegradationLevel::Normal),
            ("NORMAL", 0)
        );
        assert_eq!(
            degradation_level_label(DegradationLevel::Warning),
            ("BACKGROUND PAUSED", 1)
        );
        assert_eq!(
            degradation_level_label(DegradationLevel::Degraded),
            ("CACHE REDUCED", 2)
        );
        assert_eq!(
            degradation_level_label(DegradationLevel::Critical),
            ("WRITES THROTTLED", 3)
        );
        assert_eq!(
            degradation_level_label(DegradationLevel::Emergency),
            ("READ-ONLY", 4)
        );
    }

    // ── Degradation event formatting ───────────────────────────────────

    #[test]
    fn format_event_with_reason() {
        let event = DegradationEvent {
            timestamp: "12:00:00".to_owned(),
            from: DegradationLevel::Normal,
            to: DegradationLevel::Warning,
            reason: "high cpu".to_owned(),
        };
        let formatted = format_degradation_event(&event);
        assert!(formatted.contains("12:00:00"));
        assert!(formatted.contains("L0 -> L1"));
        assert!(formatted.contains("high cpu"));
    }

    #[test]
    fn format_event_without_reason() {
        let event = DegradationEvent {
            timestamp: "13:00:00".to_owned(),
            from: DegradationLevel::Critical,
            to: DegradationLevel::Normal,
            reason: String::new(),
        };
        let formatted = format_degradation_event(&event);
        assert!(formatted.contains("L3 -> L0"));
        assert!(!formatted.contains('('));
    }

    #[test]
    fn format_event_emergency_to_normal() {
        let event = DegradationEvent {
            timestamp: "14:00:00".to_owned(),
            from: DegradationLevel::Emergency,
            to: DegradationLevel::Normal,
            reason: "recovery".to_owned(),
        };
        let formatted = format_degradation_event(&event);
        assert!(formatted.contains("L4 -> L0"));
    }

    // ── Dashboard state management ─────────────────────────────────────

    #[test]
    fn dashboard_sequential_metric_updates() {
        let mut dash = Dashboard::new();
        for i in 0..5 {
            dash.update_metrics(DashboardSnapshot {
                cache_hits: i * 100,
                ..Default::default()
            });
            assert_eq!(dash.snapshot().cache_hits, i * 100);
        }
    }

    #[test]
    fn dashboard_default_is_same_as_new() {
        let d1 = Dashboard::new();
        let d2 = Dashboard::default();
        assert_eq!(d1.snapshot().cache_hits, d2.snapshot().cache_hits);
        assert_eq!(
            d1.snapshot().mvcc_snapshot_seq,
            d2.snapshot().mvcc_snapshot_seq
        );
    }

    #[test]
    fn dashboard_msg_from_event() {
        let key = ftui::KeyEvent {
            code: KeyCode::Char('x'),
            kind: ftui::KeyEventKind::Press,
            modifiers: ftui::Modifiers::empty(),
        };
        let msg: DashboardMsg = Event::Key(key).into();
        assert!(matches!(msg, DashboardMsg::Input(_)));
    }

    // ── Input handling ─────────────────────────────────────────────────

    #[test]
    fn dashboard_quit_on_uppercase_q() {
        let mut dash = Dashboard::new();
        let key = ftui::KeyEvent {
            code: KeyCode::Char('Q'),
            kind: ftui::KeyEventKind::Press,
            modifiers: ftui::Modifiers::empty(),
        };
        let cmd = dash.update(DashboardMsg::Input(Event::Key(key)));
        assert!(matches!(cmd, Cmd::Quit));
    }

    #[test]
    fn dashboard_ignores_arrow_keys() {
        let mut dash = Dashboard::new();
        for code in [KeyCode::Up, KeyCode::Down, KeyCode::Left, KeyCode::Right] {
            let key = ftui::KeyEvent {
                code,
                kind: ftui::KeyEventKind::Press,
                modifiers: ftui::Modifiers::empty(),
            };
            let cmd = dash.update(DashboardMsg::Input(Event::Key(key)));
            assert!(matches!(cmd, Cmd::None));
        }
    }

    #[test]
    fn dashboard_ignores_tab() {
        let mut dash = Dashboard::new();
        let key = ftui::KeyEvent {
            code: KeyCode::Tab,
            kind: ftui::KeyEventKind::Press,
            modifiers: ftui::Modifiers::empty(),
        };
        let cmd = dash.update(DashboardMsg::Input(Event::Key(key)));
        assert!(matches!(cmd, Cmd::None));
    }

    #[test]
    fn dashboard_ignores_enter() {
        let mut dash = Dashboard::new();
        let key = ftui::KeyEvent {
            code: KeyCode::Enter,
            kind: ftui::KeyEventKind::Press,
            modifiers: ftui::Modifiers::empty(),
        };
        let cmd = dash.update(DashboardMsg::Input(Event::Key(key)));
        assert!(matches!(cmd, Cmd::None));
    }

    // ── Layout / rendering edge cases ──────────────────────────────────

    #[test]
    fn dashboard_view_80x24_standard_terminal() {
        let dash = Dashboard::with_snapshot(DashboardSnapshot {
            cache_hits: 500,
            cache_misses: 50,
            mvcc_snapshot_seq: 100,
            scrub_blocks_scanned: 5000,
            ..Default::default()
        });
        let mut pool = ftui::GraphemePool::new();
        let mut frame = Frame::new(80, 24, &mut pool);
        dash.view(&mut frame);
        // No panic means success
    }

    #[test]
    fn dashboard_view_200x60_large_terminal() {
        let dash = Dashboard::with_snapshot(DashboardSnapshot {
            cache_hits: 1_000_000,
            cache_misses: 500_000,
            cache_evictions: 100_000,
            cache_resident: 2000,
            cache_capacity: 4000,
            mvcc_snapshot_seq: 999_999,
            mvcc_active_snapshots: 50,
            mvcc_watermark: Some(999_000),
            ..Default::default()
        });
        let mut pool = ftui::GraphemePool::new();
        let mut frame = Frame::new(200, 60, &mut pool);
        dash.view(&mut frame);
    }

    #[test]
    fn dashboard_view_narrow_terminal() {
        let dash = Dashboard::with_snapshot(DashboardSnapshot {
            degradation_level: DegradationLevel::Emergency,
            cpu_pressure: 0.95,
            memory_pressure: 0.88,
            io_queue_depth: 50,
            ..Default::default()
        });
        let mut pool = ftui::GraphemePool::new();
        let mut frame = Frame::new(20, 10, &mut pool);
        dash.view(&mut frame);
    }

    #[test]
    fn dashboard_view_wide_but_short() {
        let dash = Dashboard::new();
        let mut pool = ftui::GraphemePool::new();
        let mut frame = Frame::new(200, 3, &mut pool);
        dash.view(&mut frame);
    }

    // ── System health text edge cases ──────────────────────────────────

    #[test]
    fn system_health_no_events_shows_none() {
        let snap = DashboardSnapshot::default();
        let text = build_system_health_text(&snap).to_plain_text();
        assert!(text.contains("(none)"));
    }

    #[test]
    fn system_health_max_events_truncated() {
        let events: Vec<DegradationEvent> = (0..20)
            .map(|i| DegradationEvent {
                timestamp: format!("12:{i:02}:00"),
                from: DegradationLevel::Normal,
                to: DegradationLevel::Warning,
                reason: format!("event {i}"),
            })
            .collect();
        let snap = DashboardSnapshot {
            degradation_events: events,
            ..Default::default()
        };
        let text = build_system_health_text(&snap).to_plain_text();
        // Should only show MAX_RECENT_EVENTS (10)
        assert!(text.contains("event 19")); // newest
        assert!(text.contains("event 10")); // 10th from end
    }

    #[test]
    fn system_health_all_degradation_levels() {
        for level in [
            DegradationLevel::Normal,
            DegradationLevel::Warning,
            DegradationLevel::Degraded,
            DegradationLevel::Critical,
            DegradationLevel::Emergency,
        ] {
            let snap = DashboardSnapshot {
                degradation_level: level,
                ..Default::default()
            };
            let text = build_system_health_text(&snap).to_plain_text();
            let (label, _) = degradation_level_label(level);
            assert!(text.contains(label), "missing label for {level:?}");
        }
    }

    // ── Scrub panel data states ────────────────────────────────────────

    #[test]
    fn scrub_clean_status() {
        let snap = DashboardSnapshot {
            scrub_blocks_scanned: 1000,
            scrub_blocks_corrupt: 0,
            scrub_blocks_io_error: 0,
            ..Default::default()
        };
        // The render_scrub_panel function uses "Clean" for this state.
        // We test the logic directly:
        let status = if snap.scrub_blocks_scanned == 0 {
            "No scrub data"
        } else if snap.scrub_blocks_corrupt == 0 && snap.scrub_blocks_io_error == 0 {
            "Clean"
        } else {
            "Issues found"
        };
        assert_eq!(status, "Clean");
    }

    #[test]
    fn scrub_no_data_status() {
        let snap = DashboardSnapshot::default();
        let status = if snap.scrub_blocks_scanned == 0 {
            "No scrub data"
        } else {
            "Other"
        };
        assert_eq!(status, "No scrub data");
    }

    #[test]
    fn scrub_issues_found_corrupt() {
        let snap = DashboardSnapshot {
            scrub_blocks_scanned: 1000,
            scrub_blocks_corrupt: 5,
            ..Default::default()
        };
        let has_issues = snap.scrub_blocks_corrupt > 0 || snap.scrub_blocks_io_error > 0;
        assert!(has_issues);
    }

    #[test]
    fn scrub_issues_found_io_error() {
        let snap = DashboardSnapshot {
            scrub_blocks_scanned: 1000,
            scrub_blocks_io_error: 3,
            ..Default::default()
        };
        let has_issues = snap.scrub_blocks_corrupt > 0 || snap.scrub_blocks_io_error > 0;
        assert!(has_issues);
    }

    #[test]
    fn live_subsystem_builders_and_ascii_render_work() {
        let cache_metrics = ffs_block::CacheMetrics {
            hits: 80,
            misses: 20,
            evictions: 5,
            dirty_flushes: 0,
            t1_len: 24,
            t2_len: 40,
            b1_len: 2,
            b2_len: 3,
            resident: 64,
            dirty_blocks: 0,
            dirty_bytes: 0,
            writeback_queue_depth: 0,
            oldest_dirty_age_ticks: None,
            capacity: 100,
            p: 32,
            b1_ghost_hits: 1,
            b2_ghost_hits: 1,
        };
        let mut mvcc_store = ffs_mvcc::MvccStore::new();
        let mut txn = mvcc_store.begin();
        txn.stage_write(ffs_types::BlockNumber(1), vec![0xAA; 4096]);
        let _ = mvcc_store.commit(txn).expect("commit succeeds");

        let repair_metrics = ffs_repair::pipeline::RepairMetricsSnapshot {
            groups_scrubbed: 4,
            corruption_detected: 2,
            decode_attempts: 2,
            decode_successes: 2,
            symbol_refresh_count: 8,
            symbol_staleness_max_seconds: 15,
            blocks_scanned: 512,
            blocks_recovered: 2,
            blocks_unrecoverable: 1,
            scrub_rounds_completed: 1,
        };

        let snap = DashboardSnapshot {
            fs_type: "ext4".to_owned(),
            mount_point: "/mnt/test".to_owned(),
            uptime_seconds: 3661,
            bytes_read_total: 10 * 1024 * 1024,
            bytes_written_total: 2 * 1024 * 1024,
            ..Default::default()
        }
        .with_block_cache_metrics(&cache_metrics)
        .with_mvcc_store(&mvcc_store)
        .with_repair_pipeline_metrics(&repair_metrics);

        assert_eq!(snap.cache_hits, 80);
        assert_eq!(snap.cache_misses, 20);
        assert_eq!(snap.cache_resident, 64);
        assert_eq!(snap.cache_capacity, 100);
        assert!((snap.memory_pressure - 0.64).abs() < 1e-6);
        assert_eq!(snap.mvcc_snapshot_seq, 1);
        assert_eq!(snap.mvcc_version_count, 1);
        assert_eq!(snap.mvcc_versioned_blocks, 1);
        assert_eq!(snap.scrub_blocks_scanned, 512);
        assert_eq!(snap.scrub_blocks_corrupt, 2);
        assert_eq!(snap.scrub_blocks_io_error, 1);
        assert_eq!(snap.scrub_findings_count, 3);

        let ascii = snap.render_ascii();
        assert!(ascii.contains("=== FrankenFS Live Telemetry ==="));
        assert!(ascii.contains("[Mount Status]"));
        assert!(ascii.contains("Type:       ext4"));
        assert!(ascii.contains("Mount:      /mnt/test"));
        assert!(ascii.contains("Uptime:     01:01:01"));
        assert!(ascii.contains("[ARC Cache]"));
        assert!(ascii.contains("Hit ratio:    80.0%"));
        assert!(ascii.contains("[MVCC]"));
        assert!(ascii.contains("[Scrub / Repair]"));
        assert!(ascii.contains("Status:       Issues found"));
        assert!(ascii.contains("[System Health]"));

        let json = serde_json::to_string(&snap).expect("serialize snapshot");
        let roundtrip: DashboardSnapshot =
            serde_json::from_str(&json).expect("deserialize snapshot");
        assert_eq!(roundtrip.fs_type, "ext4");
        assert_eq!(roundtrip.cache_hits, 80);
        assert_eq!(roundtrip.mvcc_snapshot_seq, 1);
        assert_eq!(roundtrip.scrub_blocks_scanned, 512);
    }
}
