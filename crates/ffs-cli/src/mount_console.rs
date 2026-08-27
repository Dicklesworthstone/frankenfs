//! Operator runtime console artifact emission for `ffs mount`.
//!
//! The runtime console turns a managed or per-core mount's existing runtime
//! signals into a bounded, redacted, schema-pinned `runtime_console_report`
//! artifact an operator (or an agent swarm) can inspect after a run. It is
//! deliberately operational observability only: nothing it emits promotes
//! `swarm.responsiveness` or `adaptive_runtime` readiness, and the artifact
//! carries `product_evidence_claim=none`.
//!
//! Layering: this module depends on `ffs-harness` (the console contract and
//! snapshot builder) and `ffs-core` (the degradation level). It takes plain
//! observation values from the mount paths in `main.rs`; the FUSE crate never
//! reaches into CLI-only code.

use anyhow::{Context, Result, bail};
use ffs_core::degradation::DegradationLevel;
use ffs_harness::runtime_console_report::{
    RuntimeConsoleBackpressureObservation, RuntimeConsoleCaptureRequest,
    RuntimeConsoleCleanupStatus, RuntimeConsoleCoreObservation, RuntimeConsoleDegradationLevel,
    RuntimeConsoleMode, RuntimeConsoleObservation, build_runtime_console_report,
    render_runtime_console_report_markdown, validate_runtime_console_report,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

/// Default directory for console artifacts when no explicit path is given.
const CONSOLE_ARTIFACT_DIR: &str = "artifacts/runtime-console";

/// Operator-facing console configuration parsed from `ffs mount` flags.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MountConsoleConfig {
    enabled: bool,
    json_path: Option<PathBuf>,
    summary_path: Option<PathBuf>,
}

impl MountConsoleConfig {
    /// Build the console config from CLI flags, rejecting incompatible combinations.
    pub fn from_cli(
        console: bool,
        json_path: Option<PathBuf>,
        summary_path: Option<PathBuf>,
    ) -> Result<Self> {
        if !console && (json_path.is_some() || summary_path.is_some()) {
            bail!(
                "--console-json/--console-summary require --console; \
                 enable the runtime console before requesting its artifacts"
            );
        }
        Ok(Self {
            enabled: console,
            json_path,
            summary_path,
        })
    }

    /// Reject `--console` on the standard runtime mode, which has no managed
    /// runtime metrics surface to snapshot.
    pub fn reject_unsupported_runtime(&self, runtime_mode_is_standard: bool) -> Result<()> {
        if self.enabled && runtime_mode_is_standard {
            bail!(
                "--console requires --runtime-mode managed or --runtime-mode per-core; \
                 the standard runtime exposes no managed metrics to snapshot"
            );
        }
        Ok(())
    }

    /// Whether the operator enabled the console.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    #[cfg(test)]
    const fn disabled() -> Self {
        Self {
            enabled: false,
            json_path: None,
            summary_path: None,
        }
    }
}

/// One per-core runtime observation captured from the per-core dispatcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MountConsoleCore {
    pub core_id: u32,
    pub requests: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

/// Plain runtime observation handed to the console from a managed/per-core mount.
#[derive(Debug, Clone)]
pub struct MountConsoleObservation {
    pub operation_id: String,
    pub scenario_id: String,
    pub runtime_mode: RuntimeConsoleMode,
    pub read_write: bool,
    pub started_at: SystemTime,
    pub shutdown_at: SystemTime,
    pub requests_total: u64,
    pub requests_err: u64,
    pub bytes_read: u64,
    pub requests_throttled: u64,
    pub requests_shed: u64,
    pub degradation_level: DegradationLevel,
    pub per_core: Vec<MountConsoleCore>,
    pub clean_shutdown: bool,
    pub reproduction_command: String,
}

/// Emit the console artifact(s) for a finished mount.
///
/// A disabled console is a true no-op: the builder is never invoked and no
/// runtime observation is gathered. When enabled, the console always writes a
/// JSON artifact (defaulting under `artifacts/runtime-console/`) so a run never
/// leaves a hollow, evidence-free console claim, and writes a Markdown summary
/// when `--console-summary` is set.
pub fn emit_mount_console(
    config: &MountConsoleConfig,
    observation: &MountConsoleObservation,
) -> Result<()> {
    if !config.is_enabled() {
        return Ok(());
    }

    let json_path = config.json_path.clone().unwrap_or_else(|| {
        PathBuf::from(CONSOLE_ARTIFACT_DIR).join(format!("{}.json", observation.operation_id))
    });
    let mut artifact_paths = vec![console_artifact_label(&json_path)];
    if let Some(summary_path) = &config.summary_path {
        artifact_paths.push(console_artifact_label(summary_path));
    }

    let console_observation = build_console_observation(observation, artifact_paths);
    let report = match build_runtime_console_report(&console_observation) {
        Ok(report) => report,
        Err(error) => {
            // A console failure must not be silent: classify it loudly and
            // skip artifact emission rather than persist a misleading report.
            warn!(
                target: "ffs::cli::mount",
                operation_id = %observation.operation_id,
                scenario_id = %observation.scenario_id,
                outcome = "runtime_console_snapshot_skipped",
                reason = %error,
                "runtime_console_snapshot_skipped"
            );
            return Ok(());
        }
    };

    let validation = validate_runtime_console_report(&report);
    if !validation.valid {
        warn!(
            target: "ffs::cli::mount",
            operation_id = %observation.operation_id,
            scenario_id = %observation.scenario_id,
            outcome = "runtime_console_report_advisory_only",
            issue_count = validation.errors.len(),
            "runtime_console_report_advisory_only"
        );
    }

    let json = serde_json::to_string_pretty(&report).context("serialize runtime console report")?;
    write_console_artifact(&json_path, json.as_bytes(), "runtime console JSON")?;

    if let Some(summary_path) = &config.summary_path {
        let markdown = render_runtime_console_report_markdown(&validation);
        write_console_artifact(
            summary_path,
            markdown.as_bytes(),
            "runtime console Markdown",
        )?;
    }

    info!(
        target: "ffs::cli::mount",
        operation_id = %observation.operation_id,
        scenario_id = %observation.scenario_id,
        outcome = "runtime_console_report_emitted",
        runtime_mode = report.runtime_mode.label(),
        worker_count = report.worker_count,
        requests_total = report.counters.requests_total,
        errors_total = report.counters.errors_total,
        requests_throttled = report.counters.throttled_requests,
        requests_shed = report.counters.shed_requests,
        degradation_level = report.degradation_level.label(),
        imbalance_ratio = report.per_core_distribution.imbalance_ratio,
        cleanup_status = report.cleanup_status.label(),
        report_valid = validation.valid,
        json_path = %json_path.display(),
        "runtime_console_report_emitted"
    );
    Ok(())
}

fn build_console_observation(
    observation: &MountConsoleObservation,
    artifact_paths: Vec<String>,
) -> RuntimeConsoleObservation {
    let requests_total = observation.requests_total;
    // Backpressure effect counts can only ever be a subset of dispatched
    // requests; clamp defensively so an inconsistent metrics snapshot still
    // produces a builder-valid observation instead of dropping the evidence.
    let throttled = observation.requests_throttled.min(requests_total);
    let shed = observation
        .requests_shed
        .min(requests_total.saturating_sub(throttled));

    let (worker_count, per_core) = match observation.runtime_mode {
        RuntimeConsoleMode::Managed => (1, Vec::new()),
        RuntimeConsoleMode::PerCore => {
            let rows: Vec<RuntimeConsoleCoreObservation> = observation
                .per_core
                .iter()
                .map(|core| RuntimeConsoleCoreObservation {
                    core_id: core.core_id,
                    request_count: core.requests,
                    cache_hits: core.cache_hits,
                    cache_misses: core.cache_misses,
                })
                .collect();
            (u32::try_from(rows.len()).unwrap_or(u32::MAX), rows)
        }
    };

    RuntimeConsoleObservation {
        operation_id: observation.operation_id.clone(),
        scenario_id: observation.scenario_id.clone(),
        runtime_mode: observation.runtime_mode,
        read_write: observation.read_write,
        worker_count,
        started_at: format_rfc3339_utc(observation.started_at),
        shutdown_at: format_rfc3339_utc(observation.shutdown_at),
        // The FUSE runtime counts dispatched requests without tagging op
        // classes, so the whole count is surfaced under `requests_metadata`.
        requests_total,
        requests_read: 0,
        requests_write: 0,
        requests_metadata: requests_total,
        bytes_read: observation.bytes_read,
        bytes_written: 0,
        errors_total: observation.requests_err,
        backpressure: RuntimeConsoleBackpressureObservation {
            throttled,
            shed,
            emergency: 0,
        },
        degradation_level: map_degradation_level(observation.degradation_level),
        per_core,
        adaptive_runtime_manifest: None,
        artifact_paths,
        cleanup_status: if observation.clean_shutdown {
            RuntimeConsoleCleanupStatus::Clean
        } else {
            RuntimeConsoleCleanupStatus::PreservedArtifacts
        },
        reproduction_command: observation.reproduction_command.clone(),
        capture: RuntimeConsoleCaptureRequest::single_shutdown_snapshot(),
    }
}

/// Map the FUSE degradation level onto the console contract's level band.
const fn map_degradation_level(level: DegradationLevel) -> RuntimeConsoleDegradationLevel {
    match level {
        DegradationLevel::Normal => RuntimeConsoleDegradationLevel::Normal,
        DegradationLevel::Warning => RuntimeConsoleDegradationLevel::Degraded,
        DegradationLevel::Degraded => RuntimeConsoleDegradationLevel::Throttling,
        DegradationLevel::Critical => RuntimeConsoleDegradationLevel::Shedding,
        DegradationLevel::Emergency => RuntimeConsoleDegradationLevel::Emergency,
    }
}

/// Produce a redacted, artifact-scoped label for a console output path.
///
/// Paths already scoped to `artifacts/` (or a FrankenFS artifact temp root)
/// without parent traversal or secret-bearing components are kept verbatim.
/// Anything else is redacted to `artifacts/runtime-console/<file_name>` so a
/// persisted console report never leaks an operator host path.
fn console_artifact_label(path: &Path) -> String {
    let raw = path.to_string_lossy();
    if is_safe_artifact_path(&raw) {
        return raw.into_owned();
    }
    let file_name = path.file_name().map_or_else(
        || "console_report".to_owned(),
        |name| name.to_string_lossy().into_owned(),
    );
    format!("{CONSOLE_ARTIFACT_DIR}/{file_name}")
}

fn is_safe_artifact_path(value: &str) -> bool {
    if value.contains("..") {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    for token in [
        "/.aws/",
        "/.config/",
        "/.gnupg/",
        "/.ssh/",
        "/etc/",
        "id_rsa",
        "secret",
        "token",
    ] {
        if lower.contains(token) {
            return false;
        }
    }
    if value.starts_with("artifacts/") || value == "artifacts" {
        return true;
    }
    value.starts_with('/')
        && (value.contains("/artifacts/")
            || value.starts_with("/tmp/frankenfs-")
            || value.starts_with("/data/tmp/frankenfs-"))
}

fn write_console_artifact(path: &Path, bytes: &[u8], label: &str) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create {label} directory {}", parent.display()))?;
        }
    fs::write(path, bytes).with_context(|| format!("write {label} {}", path.display()))
}

/// Format a `SystemTime` as a UTC RFC3339 timestamp (`YYYY-MM-DDTHH:MM:SSZ`).
fn format_rfc3339_utc(time: SystemTime) -> String {
    let secs = time
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let tod = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hours = tod / 3_600;
    let minutes = (tod % 3_600) / 60;
    let seconds = tod % 60;
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Convert days since the Unix epoch to a civil `(year, month, day)` date.
///
/// Howard Hinnant's `civil_from_days` algorithm (public domain). All arithmetic
/// stays in `i64`; the intermediate quantities (`day_of_era` in `[0, 146_096]`,
/// `day`/`month` in calendar range) are small and non-negative by construction,
/// so the final `try_from` conversions never fail for any realistic timestamp.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    (
        year,
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn observation(mode: RuntimeConsoleMode) -> MountConsoleObservation {
        MountConsoleObservation {
            operation_id: "runtime-console-op-test".to_owned(),
            scenario_id: "cli_mount_runtime_managed_ro".to_owned(),
            runtime_mode: mode,
            read_write: false,
            started_at: UNIX_EPOCH + Duration::from_mins(29650000),
            shutdown_at: UNIX_EPOCH + Duration::from_mins(29650010),
            requests_total: 300,
            requests_err: 2,
            bytes_read: 65_536,
            requests_throttled: 12,
            requests_shed: 3,
            degradation_level: DegradationLevel::Degraded,
            per_core: Vec::new(),
            clean_shutdown: true,
            reproduction_command: "ffs mount image.img /mnt --runtime-mode managed --console"
                .to_owned(),
        }
    }

    #[test]
    fn from_cli_rejects_console_paths_without_console_flag() {
        let error = MountConsoleConfig::from_cli(false, Some(PathBuf::from("c.json")), None)
            .expect_err("paths without --console must be rejected");
        assert!(error.to_string().contains("require --console"), "{error}");
    }

    #[test]
    fn from_cli_accepts_console_with_paths() {
        let config = MountConsoleConfig::from_cli(
            true,
            Some(PathBuf::from("artifacts/runtime-console/run.json")),
            None,
        )
        .expect("console with a path is valid");
        assert!(config.is_enabled());
    }

    #[test]
    fn console_rejects_standard_runtime_mode() {
        let config = MountConsoleConfig::from_cli(true, None, None).unwrap();
        let error = config
            .reject_unsupported_runtime(true)
            .expect_err("standard runtime mode has no managed metrics");
        assert!(error.to_string().contains("managed"), "{error}");
        config
            .reject_unsupported_runtime(false)
            .expect("managed/per-core runtime is accepted");
    }

    #[test]
    fn disabled_console_config_is_a_no_op() {
        let config = MountConsoleConfig::disabled();
        assert!(!config.is_enabled());
        emit_mount_console(&config, &observation(RuntimeConsoleMode::Managed))
            .expect("disabled console must be a no-op");
    }

    #[test]
    fn managed_observation_builds_a_contract_valid_report() {
        let console = build_console_observation(
            &observation(RuntimeConsoleMode::Managed),
            vec!["artifacts/runtime-console/run.json".to_owned()],
        );
        assert_eq!(console.worker_count, 1);
        let report = build_runtime_console_report(&console).expect("managed report builds");
        let validation = validate_runtime_console_report(&report);
        assert!(validation.valid, "{:?}", validation.errors);
    }

    #[test]
    fn per_core_observation_builds_a_contract_valid_report() {
        let mut obs = observation(RuntimeConsoleMode::PerCore);
        obs.scenario_id = "cli_mount_runtime_per_core_rw".to_owned();
        obs.read_write = true;
        obs.per_core = vec![
            MountConsoleCore {
                core_id: 0,
                requests: 200,
                cache_hits: 150,
                cache_misses: 30,
            },
            MountConsoleCore {
                core_id: 1,
                requests: 100,
                cache_hits: 70,
                cache_misses: 20,
            },
        ];
        let console =
            build_console_observation(&obs, vec!["artifacts/runtime-console/run.json".to_owned()]);
        assert_eq!(console.worker_count, 2);
        let report = build_runtime_console_report(&console).expect("per-core report builds");
        let validation = validate_runtime_console_report(&report);
        assert!(validation.valid, "{:?}", validation.errors);
        assert!((report.per_core_distribution.imbalance_ratio - 2.0).abs() < 0.01);
    }

    #[test]
    fn backpressure_counts_are_clamped_to_the_request_total() {
        let mut obs = observation(RuntimeConsoleMode::Managed);
        obs.requests_throttled = 10_000;
        obs.requests_shed = 10_000;
        let console = build_console_observation(&obs, vec!["artifacts/x.json".to_owned()]);
        assert!(
            console.backpressure.throttled + console.backpressure.shed <= console.requests_total
        );
        build_runtime_console_report(&console).expect("clamped observation builds");
    }

    #[test]
    fn unclean_shutdown_is_classified_as_preserved_artifacts() {
        let mut obs = observation(RuntimeConsoleMode::Managed);
        obs.clean_shutdown = false;
        let console = build_console_observation(&obs, vec!["artifacts/x.json".to_owned()]);
        assert_eq!(
            console.cleanup_status,
            RuntimeConsoleCleanupStatus::PreservedArtifacts
        );
    }

    #[test]
    fn console_artifact_label_redacts_host_paths() {
        assert_eq!(
            console_artifact_label(Path::new("artifacts/runtime-console/run.json")),
            "artifacts/runtime-console/run.json"
        );
        assert_eq!(
            console_artifact_label(Path::new("/home/operator/secret/run.json")),
            "artifacts/runtime-console/run.json"
        );
        assert_eq!(
            console_artifact_label(Path::new("../../etc/run.json")),
            "artifacts/runtime-console/run.json"
        );
    }

    #[test]
    fn degradation_levels_map_onto_the_console_band() {
        assert_eq!(
            map_degradation_level(DegradationLevel::Normal),
            RuntimeConsoleDegradationLevel::Normal
        );
        assert_eq!(
            map_degradation_level(DegradationLevel::Emergency),
            RuntimeConsoleDegradationLevel::Emergency
        );
    }

    #[test]
    fn rfc3339_formatting_round_trips_a_known_epoch() {
        // 1_700_000_000 = 2023-11-14T22:13:20Z
        let formatted = format_rfc3339_utc(UNIX_EPOCH + Duration::from_secs(1_700_000_000));
        assert_eq!(formatted, "2023-11-14T22:13:20Z");
    }
}
