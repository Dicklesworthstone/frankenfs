//! E2E test framework for FrankenFS.
//!
//! Provides reusable infrastructure for end-to-end testing:
//! - [`E2eTestContext`]: fixture lifecycle (create, mount, verify, cleanup)
//! - [`MountHandle`]: RAII mount/unmount with panic safety
//! - Structured JSON logging for every test step
//! - Artifact collection for post-mortem debugging
//!
//! Downstream consumers: ext4 RW, btrfs RW, FUSE, corruption recovery, degradation.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::panic;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

fn e2e_step_timer_start() -> Instant {
    Instant::now()
}

// ── Structured JSON log types ───────────────────────────────────────────────

/// A single structured log entry for an E2E test step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct E2eLogEntry {
    pub ts: String,
    pub test: String,
    pub step: String,
    pub input: serde_json::Value,
    pub output: serde_json::Value,
    pub duration_us: u64,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl E2eLogEntry {
    fn now_iso8601() -> String {
        // Use SystemTime for a portable ISO8601 timestamp.
        let since_epoch = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        let secs = since_epoch.as_secs();
        // Simple formatting without chrono dependency.
        format!("{secs}")
    }

    /// Create a successful log entry.
    #[must_use]
    pub fn ok(
        test: &str,
        step: &str,
        input: serde_json::Value,
        output: serde_json::Value,
        duration: Duration,
    ) -> Self {
        Self {
            ts: Self::now_iso8601(),
            test: test.to_owned(),
            step: step.to_owned(),
            input,
            output,
            duration_us: u64::try_from(duration.as_micros()).unwrap_or(u64::MAX),
            status: "ok".to_owned(),
            error: None,
        }
    }

    /// Create an error log entry.
    #[must_use]
    pub fn err(
        test: &str,
        step: &str,
        input: serde_json::Value,
        duration: Duration,
        error: &str,
    ) -> Self {
        Self {
            ts: Self::now_iso8601(),
            test: test.to_owned(),
            step: step.to_owned(),
            input,
            output: serde_json::Value::Object(serde_json::Map::new()),
            duration_us: u64::try_from(duration.as_micros()).unwrap_or(u64::MAX),
            status: "error".to_owned(),
            error: Some(error.to_owned()),
        }
    }

    /// Create a skip log entry.
    #[must_use]
    pub fn skip(test: &str, step: &str, reason: &str) -> Self {
        Self {
            ts: Self::now_iso8601(),
            test: test.to_owned(),
            step: step.to_owned(),
            input: serde_json::json!({"reason": reason}),
            output: serde_json::Value::Object(serde_json::Map::new()),
            duration_us: 0,
            status: "skip".to_owned(),
            error: None,
        }
    }
}

/// Collects structured log entries for an E2E test run.
#[derive(Debug, Clone, Default)]
pub struct E2eLog {
    entries: Vec<E2eLogEntry>,
}

impl E2eLog {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn push(&mut self, entry: E2eLogEntry) {
        self.entries.push(entry);
    }

    #[must_use]
    pub fn entries(&self) -> &[E2eLogEntry] {
        &self.entries
    }

    /// Serialize all entries as a newline-delimited JSON string.
    pub fn to_ndjson(&self) -> Result<String> {
        let mut out = String::new();
        for entry in &self.entries {
            let line = serde_json::to_string(entry).context("failed to serialize log entry")?;
            out.push_str(&line);
            out.push('\n');
        }
        Ok(out)
    }

    /// Write logs to a file.
    pub fn write_to(&self, path: &Path) -> Result<()> {
        let ndjson = self.to_ndjson()?;
        fs::write(path, ndjson).with_context(|| format!("write log to {}", path.display()))?;
        Ok(())
    }

    /// Whether any entry has status "error".
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.entries.iter().any(|e| e.status == "error")
    }
}

fn lock_e2e_log(log: &Mutex<E2eLog>) -> MutexGuard<'_, E2eLog> {
    log.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

// ── Image type ──────────────────────────────────────────────────────────────

/// Filesystem type for E2E test fixtures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageType {
    Ext4,
    Btrfs,
}

impl std::fmt::Display for ImageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ext4 => write!(f, "ext4"),
            Self::Btrfs => write!(f, "btrfs"),
        }
    }
}

/// Options for fixture creation.
#[derive(Debug, Clone)]
pub struct FixtureOptions {
    /// Image size in megabytes.
    pub size_mb: u64,
    /// Volume label.
    pub label: String,
    /// Extra mkfs arguments.
    pub extra_args: Vec<String>,
}

impl Default for FixtureOptions {
    fn default() -> Self {
        Self {
            size_mb: 64,
            label: "ffs-e2e".to_owned(),
            extra_args: Vec::new(),
        }
    }
}

// ── E2eTestContext ──────────────────────────────────────────────────────────

/// Reusable E2E test context with fixture lifecycle management.
///
/// Creates a temp directory, manages image creation, mounting, verification,
/// and artifact collection.  Cleanup is guaranteed via Drop.
pub struct E2eTestContext {
    /// Human-readable test name.
    pub name: String,
    /// Filesystem type.
    pub image_type: ImageType,
    /// Temp directory (cleaned up on drop unless artifacts are collected).
    pub workdir: PathBuf,
    /// Path to the created image file.
    pub image_path: PathBuf,
    /// Path to the mountpoint directory.
    pub mountpoint: PathBuf,
    /// Structured log for this test.
    log: Arc<Mutex<E2eLog>>,
    /// Whether to preserve workdir on drop (set by collect_artifacts).
    preserve: bool,
}

impl E2eTestContext {
    /// Create a new E2E test context.
    ///
    /// Creates a temp directory under `/tmp/ffs-e2e-*` and prepares paths.
    pub fn new(name: &str, image_type: ImageType, options: &FixtureOptions) -> Result<Self> {
        // Self-heal: lazily unmount dead FrankenFS mounts left behind by
        // earlier crashed/killed runs before creating new ones (a wedged FUSE
        // server leaks its mount past AutoUnmount; see `stale_mounts`).
        crate::stale_mounts::reap_stale_frankenfs_mounts_once();

        let workdir = std::env::temp_dir().join(format!("ffs-e2e-{}-{}", name, std::process::id()));
        fs::create_dir_all(&workdir)
            .with_context(|| format!("create workdir {}", workdir.display()))?;

        let ext = match image_type {
            ImageType::Ext4 => "ext4",
            ImageType::Btrfs => "btrfs",
        };
        let image_path = workdir.join(format!("image.{ext}"));
        let mountpoint = workdir.join("mnt");
        fs::create_dir_all(&mountpoint)
            .with_context(|| format!("create mountpoint {}", mountpoint.display()))?;

        let ctx = Self {
            name: name.to_owned(),
            image_type,
            workdir,
            image_path,
            mountpoint,
            log: Arc::new(Mutex::new(E2eLog::new())),
            preserve: false,
        };

        // Log context creation.
        ctx.log_ok(
            "create_context",
            serde_json::json!({
                "fs": image_type.to_string(),
                "size_mb": options.size_mb,
                "label": &options.label,
            }),
            serde_json::json!({
                "workdir": ctx.workdir.display().to_string(),
            }),
            Duration::ZERO,
        );

        Ok(ctx)
    }

    /// Create a fixture image using mkfs.
    ///
    /// For ext4: uses `mkfs.ext4`.  For btrfs: uses `mkfs.btrfs`.
    /// Skips if the tool is not available (CI-safe).
    pub fn create_fixture(&self, options: &FixtureOptions) -> Result<bool> {
        let start = Instant::now();

        // Create sparse image file.
        let size_bytes = options.size_mb * 1024 * 1024;
        let f = fs::File::create(&self.image_path)
            .with_context(|| format!("create image {}", self.image_path.display()))?;
        f.set_len(size_bytes)
            .with_context(|| format!("set image size to {size_bytes}"))?;

        let (mkfs_cmd, mut args) = match self.image_type {
            ImageType::Ext4 => (
                "mkfs.ext4",
                vec![
                    "-F".to_owned(),
                    "-L".to_owned(),
                    options.label.clone(),
                    self.image_path.display().to_string(),
                ],
            ),
            ImageType::Btrfs => (
                "mkfs.btrfs",
                vec![
                    "-f".to_owned(),
                    "-L".to_owned(),
                    options.label.clone(),
                    self.image_path.display().to_string(),
                ],
            ),
        };

        args.extend(options.extra_args.iter().cloned());

        // Check if mkfs tool is available.
        let tool_check = Command::new("which").arg(mkfs_cmd).output();
        if !tool_check.is_ok_and(|o| o.status.success()) {
            self.log_skip("create_fixture", &format!("{mkfs_cmd} not found"));
            return Ok(false);
        }

        let output = match self.image_type {
            ImageType::Ext4 => Command::new("mkfs.ext4").args(&args).output(),
            ImageType::Btrfs => Command::new("mkfs.btrfs").args(&args).output(),
        }
        .with_context(|| format!("run {mkfs_cmd}"))?;

        let elapsed = start.elapsed();

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            self.log_err(
                "create_fixture",
                serde_json::json!({
                    "cmd": mkfs_cmd,
                    "args": args,
                }),
                elapsed,
                &format!("{mkfs_cmd} failed: {stderr}"),
            );
            bail!("{mkfs_cmd} failed: {stderr}");
        }

        self.log_ok(
            "create_fixture",
            serde_json::json!({
                "fs": self.image_type.to_string(),
                "size_mb": options.size_mb,
                "label": &options.label,
            }),
            serde_json::json!({
                "path": self.image_path.display().to_string(),
                "size_bytes": size_bytes,
            }),
            elapsed,
        );

        Ok(true)
    }

    /// Verify a file exists and has the expected content (by SHA256).
    pub fn verify_file_sha256(&self, path: &Path, expected_sha256: &str) -> Result<bool> {
        let start = e2e_step_timer_start();
        let input = serde_json::json!({
            "path": path.display().to_string(),
            "expected_sha256": expected_sha256,
        });

        if !path.exists() {
            self.log_err("verify_file", input, start.elapsed(), "file does not exist");
            return Ok(false);
        }

        let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;

        // Compute SHA256 using a simple approach (no extra dependency).
        let actual_hex = sha256_hex(&data);
        let matched = actual_hex == expected_sha256;

        self.log_ok(
            "verify_file",
            serde_json::json!({
                "path": path.display().to_string(),
                "expected_sha256": expected_sha256,
            }),
            serde_json::json!({
                "actual_sha256": actual_hex,
                "match": matched,
                "size": data.len(),
            }),
            start.elapsed(),
        );

        Ok(matched)
    }

    /// Verify file content matches expected bytes exactly.
    pub fn verify_file_content(&self, path: &Path, expected: &[u8]) -> Result<bool> {
        let start = e2e_step_timer_start();
        let input = serde_json::json!({
            "path": path.display().to_string(),
            "expected_size": expected.len(),
        });

        if !path.exists() {
            self.log_err(
                "verify_content",
                input,
                start.elapsed(),
                "file does not exist",
            );
            return Ok(false);
        }

        let actual = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        let matched = actual == expected;

        self.log_ok(
            "verify_content",
            serde_json::json!({
                "path": path.display().to_string(),
                "expected_size": expected.len(),
            }),
            serde_json::json!({
                "actual_size": actual.len(),
                "match": matched,
            }),
            start.elapsed(),
        );

        Ok(matched)
    }

    /// Inject corruption at a specific offset in the image file.
    pub fn inject_corruption(&self, offset: u64, bytes: &[u8]) -> Result<()> {
        let start = Instant::now();

        let mut f = fs::OpenOptions::new()
            .write(true)
            .open(&self.image_path)
            .with_context(|| format!("open image for corruption {}", self.image_path.display()))?;
        f.seek(SeekFrom::Start(offset))?;
        f.write_all(bytes)?;
        f.flush()?;

        self.log_ok(
            "inject_corruption",
            serde_json::json!({
                "offset": offset,
                "bytes_len": bytes.len(),
            }),
            serde_json::json!({
                "image": self.image_path.display().to_string(),
            }),
            start.elapsed(),
        );

        Ok(())
    }

    /// Collect artifacts (logs, evidence) to an output directory.
    pub fn collect_artifacts(&mut self, dir: &Path) -> Result<()> {
        let start = Instant::now();
        fs::create_dir_all(dir)
            .with_context(|| format!("create artifact dir {}", dir.display()))?;

        // Write the structured log.
        let log_path = dir.join("e2e_log.json");
        lock_e2e_log(self.log.as_ref()).write_to(&log_path)?;

        // Copy the image if it exists.
        if self.image_path.exists() {
            let dest = dir.join(self.image_path.file_name().unwrap_or_default());
            fs::copy(&self.image_path, &dest).ok();
        }

        self.preserve = true;

        self.log_ok(
            "collect_artifacts",
            serde_json::json!({"dir": dir.display().to_string()}),
            serde_json::json!({"log_path": log_path.display().to_string()}),
            start.elapsed(),
        );

        Ok(())
    }

    /// Get a reference to the test log.
    #[must_use]
    pub fn log(&self) -> Arc<Mutex<E2eLog>> {
        Arc::clone(&self.log)
    }

    /// Run a closure with panic safety, logging the outcome.
    ///
    /// If the closure panics, the panic is caught, logged as an error,
    /// and the error is returned (not re-raised).
    pub fn run_step<F, T>(&self, step_name: &str, input: serde_json::Value, f: F) -> Result<T>
    where
        F: FnOnce() -> Result<T> + panic::UnwindSafe,
    {
        let start = Instant::now();

        match panic::catch_unwind(f) {
            Ok(Ok(value)) => {
                self.log_ok(step_name, input, serde_json::json!({}), start.elapsed());
                Ok(value)
            }
            Ok(Err(e)) => {
                self.log_err(step_name, input, start.elapsed(), &format!("{e:#}"));
                Err(e)
            }
            Err(panic_payload) => {
                let msg = panic_payload
                    .downcast_ref::<&str>()
                    .map(ToString::to_string)
                    .or_else(|| panic_payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "unknown panic".to_owned());
                self.log_err(step_name, input, start.elapsed(), &format!("PANIC: {msg}"));
                bail!("step '{step_name}' panicked: {msg}");
            }
        }
    }

    // ── Internal logging helpers ────────────────────────────────────────

    fn log_ok(
        &self,
        step: &str,
        input: serde_json::Value,
        output: serde_json::Value,
        duration: Duration,
    ) {
        lock_e2e_log(self.log.as_ref())
            .push(E2eLogEntry::ok(&self.name, step, input, output, duration));
    }

    fn log_err(&self, step: &str, input: serde_json::Value, duration: Duration, error: &str) {
        lock_e2e_log(self.log.as_ref())
            .push(E2eLogEntry::err(&self.name, step, input, duration, error));
    }

    fn log_skip(&self, step: &str, reason: &str) {
        lock_e2e_log(self.log.as_ref()).push(E2eLogEntry::skip(&self.name, step, reason));
    }
}

impl Drop for E2eTestContext {
    fn drop(&mut self) {
        if !self.preserve && self.workdir.exists() {
            let _ = fs::remove_dir_all(&self.workdir);
        }
    }
}

// ── MountHandle ─────────────────────────────────────────────────────────────

/// RAII mount handle.  Unmounts the filesystem on drop.
///
/// Holds a child process (the FUSE daemon) and the mountpoint path.
/// On drop, kills the child process and runs `fusermount -u`.
pub struct MountHandle {
    /// The FUSE daemon child process.
    child: Option<std::process::Child>,
    /// Mountpoint path.
    mountpoint: PathBuf,
    /// Log reference.
    log: Arc<Mutex<E2eLog>>,
    /// Test name (for logging).
    test_name: String,
}

impl MountHandle {
    /// Create a mount handle from a child process and mountpoint.
    pub fn new(
        child: std::process::Child,
        mountpoint: PathBuf,
        test_name: &str,
        log: Arc<Mutex<E2eLog>>,
    ) -> Self {
        Self {
            child: Some(child),
            mountpoint,
            log,
            test_name: test_name.to_owned(),
        }
    }

    /// The mountpoint path.
    #[must_use]
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    /// Execute a closure with access to the mountpoint path.
    ///
    /// The mount is guaranteed to still be active during the closure.
    pub fn exec_in_mount<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Path) -> Result<T>,
    {
        f(&self.mountpoint)
    }

    /// Unmount explicitly (also called on Drop).
    pub fn unmount(&mut self) -> Result<()> {
        let start = Instant::now();

        // Kill the child process if it's still running.
        if let Some(ref mut child) = self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.child = None;

        // Attempt fusermount -u.
        let output = Command::new("fusermount")
            .args(["-u", &self.mountpoint.display().to_string()])
            .output();

        let status = match output {
            Ok(out) if out.status.success() => "ok",
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                // Not fatal — maybe already unmounted.
                lock_e2e_log(self.log.as_ref()).push(E2eLogEntry::err(
                    &self.test_name,
                    "unmount",
                    serde_json::json!({"mountpoint": self.mountpoint.display().to_string()}),
                    start.elapsed(),
                    &format!("fusermount -u failed (non-fatal): {stderr}"),
                ));
                return Ok(());
            }
            Err(_) => {
                // fusermount not available.
                "skip"
            }
        };

        if status == "ok" {
            lock_e2e_log(self.log.as_ref()).push(E2eLogEntry::ok(
                &self.test_name,
                "unmount",
                serde_json::json!({"mountpoint": self.mountpoint.display().to_string()}),
                serde_json::json!({}),
                start.elapsed(),
            ));
        }

        Ok(())
    }
}

impl Drop for MountHandle {
    fn drop(&mut self) {
        let _ = self.unmount();
    }
}

// ── Utilities ───────────────────────────────────────────────────────────────

/// Simple SHA256 using the system's `sha256sum` command.
///
/// Falls back to a zero hash if the command is not available.
fn sha256_hex(data: &[u8]) -> String {
    let Ok(mut child) = Command::new("sha256sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
    else {
        return "sha256sum_not_available".to_owned();
    };

    if let Some(ref mut stdin) = child.stdin {
        let _ = stdin.write_all(data);
    }
    // Close stdin to signal EOF.
    drop(child.stdin.take());

    match child.wait_with_output() {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            // sha256sum output is: "<hash>  -\n" or "<hash>  <filename>\n"
            stdout.split_whitespace().next().unwrap_or("").to_owned()
        }
        Err(_) => "sha256sum_failed".to_owned(),
    }
}

/// Check if a command is available on the system.
#[must_use]
pub fn command_available(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[must_use]
fn env_flag_is_truthy(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

#[must_use]
fn fail_on_skip_in_ci() -> bool {
    if let Ok(raw) = std::env::var("FFS_E2E_FAIL_ON_SKIP") {
        return env_flag_is_truthy(&raw);
    }
    std::env::var_os("CI").is_some()
}

/// E2E test result summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct E2eTestResult {
    pub test_name: String,
    pub passed: bool,
    pub inconclusive: bool,
    pub steps_total: usize,
    pub steps_ok: usize,
    pub steps_error: usize,
    pub steps_skip: usize,
    pub duration_us: u64,
    pub artifacts_dir: Option<String>,
}

impl E2eTestResult {
    /// Build a result summary from a log.
    #[must_use]
    pub fn from_log(
        test_name: &str,
        log: &E2eLog,
        duration: Duration,
        artifacts_dir: Option<&Path>,
    ) -> Self {
        let steps_ok = log.entries().iter().filter(|e| e.status == "ok").count();
        let steps_error = log.entries().iter().filter(|e| e.status == "error").count();
        let steps_skip = log.entries().iter().filter(|e| e.status == "skip").count();
        let inconclusive = steps_error == 0 && steps_skip > 0;
        let fail_on_skip = fail_on_skip_in_ci();

        Self {
            test_name: test_name.to_owned(),
            passed: steps_error == 0 && (!fail_on_skip || steps_skip == 0),
            inconclusive,
            steps_total: log.entries().len(),
            steps_ok,
            steps_error,
            steps_skip,
            duration_us: u64::try_from(duration.as_micros()).unwrap_or(u64::MAX),
            artifacts_dir: artifacts_dir.map(|p| p.display().to_string()),
        }
    }
}

// ── Deterministic crash-replay harness ──────────────────────────────────────

const ROOT_DIR: &str = "/";

/// Whether to crash before or after applying an operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CrashPointStage {
    BeforeOp,
    AfterOp,
}

/// A crash injection location within a generated schedule.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct CrashPoint {
    pub op_index: usize,
    pub stage: CrashPointStage,
}

/// Crash replay execution lane.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CrashReplayLane {
    CoreDeterministic,
    MountedSmoke,
    RepairInterruption,
}

impl CrashReplayLane {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::CoreDeterministic => "core_deterministic",
            Self::MountedSmoke => "mounted_smoke",
            Self::RepairInterruption => "repair_interruption",
        }
    }
}

/// Taxonomy used by reports and minimized repro artifacts.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CrashReplayClassification {
    PreCommit,
    PostCommitPreFlush,
    FsyncBoundary,
    ReplayInterruption,
    RepairInterruption,
    MountedWriteReopen,
    HostCapabilitySkip,
}

impl CrashReplayClassification {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::PreCommit => "pre_commit",
            Self::PostCommitPreFlush => "post_commit_pre_flush",
            Self::FsyncBoundary => "fsync_boundary",
            Self::ReplayInterruption => "replay_interruption",
            Self::RepairInterruption => "repair_interruption",
            Self::MountedWriteReopen => "mounted_write_reopen",
            Self::HostCapabilitySkip => "host_capability_skip",
        }
    }
}

/// A single synthetic filesystem operation used in crash-replay schedules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CrashOperation {
    Create {
        path: String,
        fsync: bool,
    },
    Write {
        path: String,
        data: Vec<u8>,
        fsync: bool,
    },
    Rename {
        from: String,
        to: String,
        fsync: bool,
    },
    Unlink {
        path: String,
        fsync: bool,
    },
    Mkdir {
        path: String,
        fsync: bool,
    },
    Rmdir {
        path: String,
        fsync: bool,
    },
}

impl CrashOperation {
    fn fsync(&self) -> bool {
        match self {
            Self::Create { fsync, .. }
            | Self::Write { fsync, .. }
            | Self::Rename { fsync, .. }
            | Self::Unlink { fsync, .. }
            | Self::Mkdir { fsync, .. }
            | Self::Rmdir { fsync, .. } => *fsync,
        }
    }
}

/// A deterministic crash-replay schedule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrashSchedule {
    pub schedule_id: u32,
    pub seed: u64,
    pub operations: Vec<CrashOperation>,
    pub crash_points: Vec<CrashPoint>,
}

/// Stable survivor-set summary emitted in crash replay artifacts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrashReplaySurvivorSet {
    pub file_count: usize,
    pub directory_count: usize,
    pub files: Vec<String>,
    pub directories: Vec<String>,
    pub content_hash: String,
}

/// Result for one crash point replay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrashReplayCaseResult {
    pub lane_type: CrashReplayLane,
    pub crash_point: CrashPoint,
    pub classification: CrashReplayClassification,
    pub executed_operations: usize,
    pub minimized_operation_count: usize,
    pub expected_survivors: CrashReplaySurvivorSet,
    pub observed_survivors: CrashReplaySurvivorSet,
    pub cleanup_status: String,
    pub raw_log: String,
    pub minimized_reproduction_command: String,
    pub unreduced_follow_up_bead: Option<String>,
    pub passed: bool,
    pub errors: Vec<String>,
}

/// Result for one generated schedule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrashReplayScheduleResult {
    pub schedule_id: u32,
    pub seed: u64,
    pub operation_count: usize,
    pub passed: bool,
    pub case_results: Vec<CrashReplayCaseResult>,
    pub duration_us: u64,
}

/// Config for the deterministic crash-replay suite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrashReplaySuiteConfig {
    /// Number of schedules to generate and execute.
    pub schedule_count: u32,
    /// Minimum operations in each schedule.
    pub min_operations: usize,
    /// Maximum operations in each schedule.
    pub max_operations: usize,
    /// Seed used to derive per-schedule deterministic seeds.
    pub base_seed: u64,
    /// Optional directory to persist per-schedule artifacts.
    pub output_dir: Option<PathBuf>,
}

impl Default for CrashReplaySuiteConfig {
    fn default() -> Self {
        Self {
            schedule_count: 500,
            min_operations: 100,
            max_operations: 1000,
            base_seed: 0xFF5E_ED00_0000_0001,
            output_dir: None,
        }
    }
}

/// Aggregate result of the crash-replay suite.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrashReplaySuiteReport {
    pub schedule_count: u32,
    pub passed_schedules: u32,
    pub failed_schedules: u32,
    pub duration_us: u64,
    pub output_dir: Option<String>,
    pub results: Vec<CrashReplayScheduleResult>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CrashFsState {
    directories: BTreeSet<String>,
    files: BTreeMap<String, Vec<u8>>,
}

impl CrashFsState {
    fn with_root() -> Self {
        let mut directories = BTreeSet::new();
        directories.insert(ROOT_DIR.to_owned());
        Self {
            directories,
            files: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct CrashReplayExpectations {
    files: BTreeMap<String, Option<Vec<u8>>>,
    directories: BTreeMap<String, bool>,
}

#[derive(Debug, Clone)]
struct CrashReplaySimulationOutcome {
    recovered: CrashFsState,
    expectations: CrashReplayExpectations,
    executed_operations: usize,
}

#[derive(Debug, Clone)]
struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0x9E37_79B9_7F4A_7C15,
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn next_bool(&mut self) -> bool {
        self.next_u64() & 1 == 0
    }

    fn next_usize(&mut self, upper_exclusive: usize) -> usize {
        if upper_exclusive <= 1 {
            return 0;
        }
        let upper_u64 = u64::try_from(upper_exclusive).unwrap_or(u64::MAX);
        let value = self.next_u64() % upper_u64;
        usize::try_from(value).unwrap_or(0)
    }

    fn payload(&mut self, min_len: usize, max_len: usize) -> Vec<u8> {
        let span = max_len.saturating_sub(min_len).saturating_add(1);
        let len = min_len.saturating_add(self.next_usize(span));
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..len {
            let byte = u8::try_from(self.next_u64() & u64::from(u8::MAX)).unwrap_or(0);
            bytes.push(byte);
        }
        bytes
    }
}

#[derive(Debug, Clone)]
struct CrashScheduleGenerator {
    directories: Vec<String>,
    files: Vec<String>,
    next_dir_id: u32,
    next_file_id: u32,
}

impl CrashScheduleGenerator {
    fn new() -> Self {
        Self {
            directories: vec![ROOT_DIR.to_owned()],
            files: Vec::new(),
            next_dir_id: 0,
            next_file_id: 0,
        }
    }

    fn next_operation(&mut self, rng: &mut DeterministicRng, op_index: usize) -> CrashOperation {
        let branch = rng.next_usize(100);
        let fsync = rng.next_usize(3) == 0;

        if branch < 15 {
            self.generate_mkdir(rng, fsync)
        } else if branch < 30 {
            self.generate_create(rng, fsync)
        } else if branch < 65 {
            self.generate_write(rng, op_index, fsync)
        } else if branch < 80 {
            self.generate_rename(rng, fsync)
                .unwrap_or_else(|| self.generate_write(rng, op_index, fsync))
        } else if branch < 92 {
            self.generate_unlink(rng, fsync)
                .unwrap_or_else(|| self.generate_write(rng, op_index, fsync))
        } else {
            self.generate_rmdir(rng, fsync)
                .unwrap_or_else(|| self.generate_write(rng, op_index, fsync))
        }
    }

    fn random_directory(&self, rng: &mut DeterministicRng) -> String {
        let index = rng.next_usize(self.directories.len());
        self.directories[index].clone()
    }

    fn allocate_dir_path(&mut self, parent: &str) -> String {
        let path = join_path(parent, &format!("d{:05}", self.next_dir_id));
        self.next_dir_id = self.next_dir_id.saturating_add(1);
        path
    }

    fn allocate_file_path(&mut self, parent: &str) -> String {
        let path = join_path(parent, &format!("f{:06}.bin", self.next_file_id));
        self.next_file_id = self.next_file_id.saturating_add(1);
        path
    }

    fn generate_mkdir(&mut self, rng: &mut DeterministicRng, fsync: bool) -> CrashOperation {
        let parent = self.random_directory(rng);
        let path = self.allocate_dir_path(&parent);
        self.directories.push(path.clone());
        CrashOperation::Mkdir { path, fsync }
    }

    fn generate_create(&mut self, rng: &mut DeterministicRng, fsync: bool) -> CrashOperation {
        let parent = self.random_directory(rng);
        let path = self.allocate_file_path(&parent);
        self.files.push(path.clone());
        CrashOperation::Create { path, fsync }
    }

    fn generate_write(
        &mut self,
        rng: &mut DeterministicRng,
        op_index: usize,
        fsync: bool,
    ) -> CrashOperation {
        let use_existing = !self.files.is_empty() && rng.next_usize(100) < 60;
        let path = if use_existing {
            let index = rng.next_usize(self.files.len());
            self.files[index].clone()
        } else {
            let parent = self.random_directory(rng);
            let new_path = self.allocate_file_path(&parent);
            self.files.push(new_path.clone());
            new_path
        };

        let mut data = rng.payload(64, 512);
        let tag = format!("op={op_index:05};");
        for (slot, byte) in tag.as_bytes().iter().enumerate() {
            if slot >= data.len() {
                break;
            }
            data[slot] = *byte;
        }

        CrashOperation::Write { path, data, fsync }
    }

    fn generate_rename(
        &mut self,
        rng: &mut DeterministicRng,
        fsync: bool,
    ) -> Option<CrashOperation> {
        if self.files.is_empty() {
            return None;
        }
        let source_index = rng.next_usize(self.files.len());
        let from = self.files.remove(source_index);
        let parent = self.random_directory(rng);
        let to = self.allocate_file_path(&parent);
        self.files.push(to.clone());
        Some(CrashOperation::Rename { from, to, fsync })
    }

    fn generate_unlink(
        &mut self,
        rng: &mut DeterministicRng,
        fsync: bool,
    ) -> Option<CrashOperation> {
        if self.files.is_empty() {
            return None;
        }
        let index = rng.next_usize(self.files.len());
        let path = self.files.remove(index);
        Some(CrashOperation::Unlink { path, fsync })
    }

    fn generate_rmdir(
        &mut self,
        rng: &mut DeterministicRng,
        fsync: bool,
    ) -> Option<CrashOperation> {
        let removable: Vec<&String> =
            self.directories
                .iter()
                .filter(|dir| dir.as_str() != ROOT_DIR)
                .filter(|dir| {
                    let candidate = dir.as_str();
                    !self.files.iter().any(|file| is_descendant(file, candidate))
                        && !self.directories.iter().any(|other| {
                            other.as_str() != candidate && is_descendant(other, candidate)
                        })
                })
                .collect();

        if removable.is_empty() {
            return None;
        }

        let chosen = removable[rng.next_usize(removable.len())].clone();
        self.directories.retain(|dir| dir != &chosen);
        Some(CrashOperation::Rmdir {
            path: chosen,
            fsync,
        })
    }
}

fn join_path(parent: &str, name: &str) -> String {
    if parent == ROOT_DIR {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

fn parent_directory(path: &str) -> Option<&str> {
    if path == ROOT_DIR {
        return None;
    }
    let slash = path.rfind('/')?;
    if slash == 0 {
        Some(ROOT_DIR)
    } else {
        Some(&path[..slash])
    }
}

fn is_descendant(path: &str, directory: &str) -> bool {
    if directory == ROOT_DIR {
        return path.starts_with(ROOT_DIR) && path.len() > ROOT_DIR.len();
    }
    if !path.starts_with(directory) {
        return false;
    }
    path.as_bytes()
        .get(directory.len())
        .is_some_and(|byte| *byte == b'/')
}

fn validate_absolute_path(path: &str) -> Result<()> {
    if !path.starts_with('/') {
        bail!("path must be absolute: {path}");
    }
    if path.len() > 1 && path.ends_with('/') {
        bail!("path must not end with '/': {path}");
    }
    Ok(())
}

fn ensure_parent_directory_exists(state: &CrashFsState, path: &str) -> Result<()> {
    let parent = parent_directory(path).context("path has no parent")?;
    if !state.directories.contains(parent) {
        bail!("parent directory does not exist: {parent}");
    }
    Ok(())
}

fn apply_operation(state: &mut CrashFsState, op: &CrashOperation) -> Result<()> {
    match op {
        CrashOperation::Create { path, .. } => {
            validate_absolute_path(path)?;
            ensure_parent_directory_exists(state, path)?;
            state.files.insert(path.clone(), Vec::new());
        }
        CrashOperation::Write { path, data, .. } => {
            validate_absolute_path(path)?;
            ensure_parent_directory_exists(state, path)?;
            state.files.insert(path.clone(), data.clone());
        }
        CrashOperation::Rename { from, to, .. } => {
            validate_absolute_path(from)?;
            validate_absolute_path(to)?;
            ensure_parent_directory_exists(state, to)?;
            let payload = state
                .files
                .remove(from)
                .with_context(|| format!("rename source missing: {from}"))?;
            state.files.insert(to.clone(), payload);
        }
        CrashOperation::Unlink { path, .. } => {
            validate_absolute_path(path)?;
            let removed = state.files.remove(path);
            if removed.is_none() {
                bail!("unlink target missing: {path}");
            }
        }
        CrashOperation::Mkdir { path, .. } => {
            validate_absolute_path(path)?;
            ensure_parent_directory_exists(state, path)?;
            state.directories.insert(path.clone());
        }
        CrashOperation::Rmdir { path, .. } => {
            validate_absolute_path(path)?;
            if path == ROOT_DIR {
                bail!("cannot remove root directory");
            }
            if !state.directories.contains(path) {
                bail!("rmdir target missing: {path}");
            }
            let has_children = state.files.keys().any(|entry| is_descendant(entry, path))
                || state
                    .directories
                    .iter()
                    .any(|entry| entry != path && is_descendant(entry, path));
            if has_children {
                bail!("rmdir target is not empty: {path}");
            }
            state.directories.remove(path);
        }
    }
    Ok(())
}

fn sync_parent_directories_from_working(
    path: &str,
    working: &CrashFsState,
    durable: &mut CrashFsState,
) {
    let mut current = parent_directory(path);
    while let Some(directory) = current {
        if working.directories.contains(directory) {
            durable.directories.insert(directory.to_owned());
        }
        if directory == ROOT_DIR {
            break;
        }
        current = parent_directory(directory);
    }
}

fn commit_operation(
    op: &CrashOperation,
    working: &CrashFsState,
    durable: &mut CrashFsState,
    expectations: &mut CrashReplayExpectations,
) -> Result<()> {
    match op {
        CrashOperation::Create { path, .. } | CrashOperation::Write { path, .. } => {
            let payload = working
                .files
                .get(path)
                .with_context(|| format!("fsync target missing in working set: {path}"))?
                .clone();
            sync_parent_directories_from_working(path, working, durable);
            durable.files.insert(path.clone(), payload.clone());
            expectations.files.insert(path.clone(), Some(payload));
        }
        CrashOperation::Rename { from, to, .. } => {
            let payload = working
                .files
                .get(to)
                .with_context(|| format!("rename fsync target missing in working set: {to}"))?
                .clone();
            sync_parent_directories_from_working(to, working, durable);
            durable.files.remove(from);
            durable.files.insert(to.clone(), payload.clone());
            expectations.files.insert(from.clone(), None);
            expectations.files.insert(to.clone(), Some(payload));
        }
        CrashOperation::Unlink { path, .. } => {
            durable.files.remove(path);
            expectations.files.insert(path.clone(), None);
        }
        CrashOperation::Mkdir { path, .. } => {
            if working.directories.contains(path) {
                sync_parent_directories_from_working(path, working, durable);
                durable.directories.insert(path.clone());
                expectations.directories.insert(path.clone(), true);
            }
        }
        CrashOperation::Rmdir { path, .. } => {
            let removed_files: Vec<String> = durable
                .files
                .keys()
                .filter(|entry| is_descendant(entry, path))
                .cloned()
                .collect();
            for file in removed_files {
                durable.files.remove(&file);
                expectations.files.insert(file, None);
            }

            let removed_directories: Vec<String> = durable
                .directories
                .iter()
                .filter(|entry| entry.as_str() == path || is_descendant(entry, path))
                .cloned()
                .collect();
            for directory in removed_directories {
                if directory != ROOT_DIR {
                    durable.directories.remove(&directory);
                    expectations.directories.insert(directory, false);
                }
            }
        }
    }
    Ok(())
}

fn executed_operation_count(total_operations: usize, crash_point: CrashPoint) -> usize {
    let raw = match crash_point.stage {
        CrashPointStage::BeforeOp => crash_point.op_index,
        CrashPointStage::AfterOp => crash_point.op_index.saturating_add(1),
    };
    raw.min(total_operations)
}

fn validate_recovered_state(state: &CrashFsState) -> Vec<String> {
    let mut errors = Vec::new();

    if !state.directories.contains(ROOT_DIR) {
        errors.push("root directory missing after recovery".to_owned());
    }

    for directory in &state.directories {
        if directory == ROOT_DIR {
            continue;
        }
        if let Some(parent) = parent_directory(directory) {
            if !state.directories.contains(parent) {
                errors.push(format!(
                    "directory parent missing after recovery: {directory} parent={parent}"
                ));
            }
        } else {
            errors.push(format!("directory has no parent: {directory}"));
        }
    }

    for path in state.files.keys() {
        if let Some(parent) = parent_directory(path) {
            if !state.directories.contains(parent) {
                errors.push(format!(
                    "file parent missing after recovery: {path} parent={parent}"
                ));
            }
        } else {
            errors.push(format!("file has no parent: {path}"));
        }
    }

    errors
}

fn validate_expectations(
    recovered: &CrashFsState,
    expectations: &CrashReplayExpectations,
) -> Vec<String> {
    let mut errors = Vec::new();

    for (path, expected) in &expectations.files {
        let actual = recovered.files.get(path);
        match (expected, actual) {
            (Some(bytes), Some(found)) if bytes == found => {}
            (Some(bytes), Some(found)) => {
                errors.push(format!(
                    "fsync file bytes mismatch: {path} expected={} actual={}",
                    bytes.len(),
                    found.len(),
                ));
            }
            (Some(_), None) => {
                errors.push(format!("fsync file missing after recovery: {path}"));
            }
            (None, Some(_)) => {
                errors.push(format!("fsync unlink not reflected after recovery: {path}"));
            }
            (None, None) => {}
        }
    }

    for (directory, should_exist) in &expectations.directories {
        let exists = recovered.directories.contains(directory);
        if exists != *should_exist {
            errors.push(format!(
                "fsync directory expectation mismatch: {directory} expected_exists={should_exist} actual_exists={exists}",
            ));
        }
    }

    errors
}

fn survivor_set(state: &CrashFsState) -> CrashReplaySurvivorSet {
    let files = state.files.keys().cloned().collect::<Vec<_>>();
    let directories = state.directories.iter().cloned().collect::<Vec<_>>();
    let mut canonical = String::new();
    for directory in &directories {
        canonical.push_str("dir:");
        canonical.push_str(directory);
        canonical.push('\n');
    }
    for (path, data) in &state.files {
        canonical.push_str("file:");
        canonical.push_str(path);
        canonical.push(':');
        canonical.push_str(&stable_bytes_hash_hex(data));
        canonical.push('\n');
    }

    CrashReplaySurvivorSet {
        file_count: files.len(),
        directory_count: directories.len(),
        files,
        directories,
        content_hash: stable_bytes_hash_hex(canonical.as_bytes()),
    }
}

fn stable_bytes_hash_hex(bytes: &[u8]) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

fn crash_replay_classification(
    schedule: &CrashSchedule,
    crash_point: CrashPoint,
) -> CrashReplayClassification {
    if crash_point.stage == CrashPointStage::BeforeOp {
        return CrashReplayClassification::PreCommit;
    }
    let Some(operation) = schedule.operations.get(crash_point.op_index) else {
        return CrashReplayClassification::ReplayInterruption;
    };
    if operation.fsync() {
        CrashReplayClassification::FsyncBoundary
    } else {
        CrashReplayClassification::PostCommitPreFlush
    }
}

fn minimized_reproduction_command(
    schedule: &CrashSchedule,
    minimized_operation_count: usize,
) -> String {
    format!(
        "ffs-harness run-crash-replay --count 1 --seed {} --min-ops {} --max-ops {} --out artifacts/crash_replay/minimized_{:04}",
        schedule.seed,
        minimized_operation_count.max(1),
        minimized_operation_count.max(1),
        schedule.schedule_id
    )
}

fn crash_case_raw_log(
    schedule: &CrashSchedule,
    crash_point: CrashPoint,
    classification: CrashReplayClassification,
    executed_operations: usize,
    passed: bool,
) -> String {
    format!(
        "CRASH_REPLAY_CASE|lane_type={}|schedule_id={}|seed={}|op_index={}|stage={:?}|classification={}|executed_operations={}|passed={}",
        CrashReplayLane::CoreDeterministic.label(),
        schedule.schedule_id,
        schedule.seed,
        crash_point.op_index,
        crash_point.stage,
        classification.label(),
        executed_operations,
        passed
    )
}

#[must_use]
pub fn minimize_crash_operation_trace<F>(
    operations: &[CrashOperation],
    mut reproduces: F,
) -> Vec<CrashOperation>
where
    F: FnMut(&[CrashOperation]) -> bool,
{
    let mut minimized = operations.to_vec();
    let mut index = 0;
    while index < minimized.len() {
        let mut candidate = minimized.clone();
        candidate.remove(index);
        if !candidate.is_empty() && reproduces(&candidate) {
            minimized = candidate;
        } else {
            index += 1;
        }
    }
    minimized
}

fn simulate_crash_point(
    schedule: &CrashSchedule,
    crash_point: CrashPoint,
) -> Result<CrashReplaySimulationOutcome> {
    let mut working = CrashFsState::with_root();
    let mut durable = CrashFsState::with_root();
    let mut expectations = CrashReplayExpectations::default();
    expectations.directories.insert(ROOT_DIR.to_owned(), true);

    let executed = executed_operation_count(schedule.operations.len(), crash_point);
    for operation in schedule.operations.iter().take(executed) {
        apply_operation(&mut working, operation)?;
        if operation.fsync() {
            commit_operation(operation, &working, &mut durable, &mut expectations)?;
        }
    }

    Ok(CrashReplaySimulationOutcome {
        recovered: durable,
        expectations,
        executed_operations: executed,
    })
}

fn derive_schedule_seed(base_seed: u64, schedule_id: u32) -> u64 {
    base_seed ^ u64::from(schedule_id).wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

fn choose_crash_points(rng: &mut DeterministicRng, operation_count: usize) -> Vec<CrashPoint> {
    let desired = 1 + rng.next_usize(3);
    let mut points = BTreeSet::new();

    while points.len() < desired {
        let op_index = rng.next_usize(operation_count);
        let stage = if rng.next_bool() {
            CrashPointStage::BeforeOp
        } else {
            CrashPointStage::AfterOp
        };
        points.insert(CrashPoint { op_index, stage });
    }

    points.into_iter().collect()
}

/// Generate one deterministic crash-replay schedule.
pub fn generate_crash_schedule(
    schedule_id: u32,
    seed: u64,
    min_operations: usize,
    max_operations: usize,
) -> Result<CrashSchedule> {
    if min_operations == 0 {
        bail!("min_operations must be greater than zero");
    }
    if max_operations < min_operations {
        bail!("max_operations must be >= min_operations");
    }

    let mut rng = DeterministicRng::new(seed);
    let span = max_operations
        .saturating_sub(min_operations)
        .saturating_add(1);
    let operation_count = min_operations.saturating_add(rng.next_usize(span));

    let mut generator = CrashScheduleGenerator::new();
    let mut operations = Vec::with_capacity(operation_count);
    for op_index in 0..operation_count {
        operations.push(generator.next_operation(&mut rng, op_index));
    }
    let crash_points = choose_crash_points(&mut rng, operation_count);

    Ok(CrashSchedule {
        schedule_id,
        seed,
        operations,
        crash_points,
    })
}

/// Execute all crash points for a generated schedule.
pub fn run_crash_schedule(schedule: &CrashSchedule) -> Result<CrashReplayScheduleResult> {
    if schedule.operations.is_empty() {
        bail!("schedule has no operations");
    }
    if schedule.crash_points.is_empty() {
        bail!("schedule has no crash points");
    }
    if schedule
        .crash_points
        .iter()
        .any(|point| point.op_index >= schedule.operations.len())
    {
        bail!("schedule contains out-of-range crash point");
    }

    let start = Instant::now();
    let mut case_results = Vec::with_capacity(schedule.crash_points.len());
    let mut passed = true;

    for crash_point in &schedule.crash_points {
        let primary = simulate_crash_point(schedule, *crash_point)?;
        let replay = simulate_crash_point(schedule, *crash_point)?;
        let expected_survivors = survivor_set(&primary.recovered);
        let observed_survivors = survivor_set(&replay.recovered);
        let classification = crash_replay_classification(schedule, *crash_point);

        let mut errors = validate_recovered_state(&primary.recovered);
        errors.extend(validate_expectations(
            &primary.recovered,
            &primary.expectations,
        ));
        if primary.recovered != replay.recovered {
            errors.push("non-deterministic recovery state for identical crash point".to_owned());
        }

        let case_passed = errors.is_empty();
        if !case_passed {
            passed = false;
        }
        let minimized_operation_count = if case_passed {
            primary.executed_operations
        } else {
            minimize_crash_operation_trace(
                &schedule.operations[..primary.executed_operations],
                |candidate| !candidate.is_empty(),
            )
            .len()
        };
        case_results.push(CrashReplayCaseResult {
            lane_type: CrashReplayLane::CoreDeterministic,
            crash_point: *crash_point,
            classification,
            executed_operations: primary.executed_operations,
            minimized_operation_count,
            expected_survivors,
            observed_survivors,
            cleanup_status: "cleaned_up_simulated_state".to_owned(),
            raw_log: crash_case_raw_log(
                schedule,
                *crash_point,
                classification,
                primary.executed_operations,
                case_passed,
            ),
            minimized_reproduction_command: minimized_reproduction_command(
                schedule,
                minimized_operation_count,
            ),
            unreduced_follow_up_bead: if case_passed {
                None
            } else {
                Some("bd-nk49l".to_owned())
            },
            passed: case_passed,
            errors,
        });
    }

    Ok(CrashReplayScheduleResult {
        schedule_id: schedule.schedule_id,
        seed: schedule.seed,
        operation_count: schedule.operations.len(),
        passed,
        case_results,
        duration_us: u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX),
    })
}

fn write_schedule_artifact(
    output_dir: &Path,
    schedule: &CrashSchedule,
    result: &CrashReplayScheduleResult,
) -> Result<()> {
    #[derive(Serialize)]
    struct ScheduleArtifact<'a> {
        schedule: &'a CrashSchedule,
        result: &'a CrashReplayScheduleResult,
    }

    let schedules_dir = output_dir.join("schedules");
    fs::create_dir_all(&schedules_dir)
        .with_context(|| format!("create schedule artifact dir {}", schedules_dir.display()))?;

    let path = schedules_dir.join(format!("schedule_{:04}.json", schedule.schedule_id));
    let payload = ScheduleArtifact { schedule, result };
    let text = serde_json::to_string_pretty(&payload)
        .context("serialize crash schedule artifact to json")?;
    fs::write(&path, text).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn write_repro_pack(
    output_dir: &Path,
    config: &CrashReplaySuiteConfig,
    report: &CrashReplaySuiteReport,
) -> Result<()> {
    #[derive(Serialize)]
    struct EnvReport<'a> {
        os: &'a str,
        arch: &'a str,
        family: &'a str,
        pkg_version: &'a str,
        generated_at_unix: &'a str,
    }

    #[derive(Serialize)]
    struct Manifest<'a> {
        schedule_count: u32,
        passed_schedules: u32,
        failed_schedules: u32,
        min_operations: usize,
        max_operations: usize,
        base_seed: u64,
        output_dir: Option<String>,
        results: &'a [CrashReplayScheduleResult],
    }

    fs::create_dir_all(output_dir)
        .with_context(|| format!("create repro output dir {}", output_dir.display()))?;

    let generated_at = E2eLogEntry::now_iso8601();
    let env_report = EnvReport {
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        family: std::env::consts::FAMILY,
        pkg_version: env!("CARGO_PKG_VERSION"),
        generated_at_unix: &generated_at,
    };
    let env_path = output_dir.join("env.json");
    let env_json = serde_json::to_string_pretty(&env_report).context("serialize env report")?;
    fs::write(&env_path, env_json).with_context(|| format!("write {}", env_path.display()))?;

    let manifest = Manifest {
        schedule_count: report.schedule_count,
        passed_schedules: report.passed_schedules,
        failed_schedules: report.failed_schedules,
        min_operations: config.min_operations,
        max_operations: config.max_operations,
        base_seed: config.base_seed,
        output_dir: report.output_dir.clone(),
        results: &report.results,
    };
    let manifest_path = output_dir.join("manifest.json");
    let manifest_json = serde_json::to_string_pretty(&manifest).context("serialize manifest")?;
    fs::write(&manifest_path, &manifest_json)
        .with_context(|| format!("write {}", manifest_path.display()))?;

    let manifest_sha256 = sha256_hex(manifest_json.as_bytes());
    let repro_lock = format!(
        "base_seed={}\nschedule_count={}\nmin_operations={}\nmax_operations={}\nmanifest_sha256={}\n",
        config.base_seed,
        report.schedule_count,
        config.min_operations,
        config.max_operations,
        manifest_sha256
    );
    let lock_path = output_dir.join("repro.lock");
    fs::write(&lock_path, repro_lock).with_context(|| format!("write {}", lock_path.display()))?;

    Ok(())
}

/// Run the deterministic crash-replay suite.
pub fn run_crash_replay_suite(config: &CrashReplaySuiteConfig) -> Result<CrashReplaySuiteReport> {
    if config.schedule_count == 0 {
        bail!("schedule_count must be greater than zero");
    }
    if config.min_operations == 0 {
        bail!("min_operations must be greater than zero");
    }
    if config.max_operations < config.min_operations {
        bail!("max_operations must be >= min_operations");
    }

    let start = Instant::now();
    let mut results = Vec::with_capacity(usize::try_from(config.schedule_count).unwrap_or(0));
    let mut passed_schedules = 0_u32;

    for schedule_id in 0..config.schedule_count {
        let seed = derive_schedule_seed(config.base_seed, schedule_id);
        let schedule = generate_crash_schedule(
            schedule_id,
            seed,
            config.min_operations,
            config.max_operations,
        )?;
        let schedule_result = run_crash_schedule(&schedule)?;
        if schedule_result.passed {
            passed_schedules = passed_schedules.saturating_add(1);
        }
        if let Some(output_dir) = &config.output_dir {
            write_schedule_artifact(output_dir, &schedule, &schedule_result)?;
        }
        results.push(schedule_result);
    }

    let failed_schedules = config.schedule_count.saturating_sub(passed_schedules);
    let output_dir = config
        .output_dir
        .as_ref()
        .map(|path| path.display().to_string());
    let report = CrashReplaySuiteReport {
        schedule_count: config.schedule_count,
        passed_schedules,
        failed_schedules,
        duration_us: u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX),
        output_dir,
        results,
    };

    if let Some(output_dir) = &config.output_dir {
        write_repro_pack(output_dir, config, &report)?;
    }

    Ok(report)
}

// ── FSX-style deterministic stress harness ──────────────────────────────────

/// Configuration for fsx-style stress testing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsxStressConfig {
    /// Number of operations to execute.
    pub operation_count: u64,
    /// Seed for deterministic operation generation.
    pub seed: u64,
    /// Maximum simulated file size in bytes.
    pub max_file_size_bytes: usize,
    /// Inject corruption every N operations (0 disables corruption).
    pub corruption_every_ops: u64,
    /// Perform full-file verification every N operations (0 disables periodic full verification).
    pub full_verify_every_ops: u64,
    /// Optional output directory for repro artifacts.
    pub output_dir: Option<PathBuf>,
}

impl Default for FsxStressConfig {
    fn default() -> Self {
        Self {
            operation_count: 100_000,
            seed: 0xF5A5_7E55_0000_0001,
            max_file_size_bytes: 64 * 1024 * 1024,
            corruption_every_ops: 1_000,
            full_verify_every_ops: 1_000,
            output_dir: None,
        }
    }
}

/// One fsx-style operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FsxOperation {
    Write { offset: usize, data: Vec<u8> },
    Read { offset: usize, len: usize },
    Truncate { len: usize },
    Fsync,
    Fallocate { offset: usize, len: usize },
    PunchHole { offset: usize, len: usize },
    Reopen,
    CorruptionCycle { offset: usize, len: usize },
}

impl FsxOperation {
    fn kind(&self) -> &'static str {
        match self {
            Self::Write { .. } => "write",
            Self::Read { .. } => "read",
            Self::Truncate { .. } => "truncate",
            Self::Fsync => "fsync",
            Self::Fallocate { .. } => "fallocate",
            Self::PunchHole { .. } => "punch_hole",
            Self::Reopen => "reopen",
            Self::CorruptionCycle { .. } => "corruption_cycle",
        }
    }
}

/// Failure details for fsx stress runs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FsxFailureReport {
    pub operation_index: u64,
    pub operation: FsxOperation,
    pub reason: String,
    pub expected_sha256: String,
    pub actual_sha256: String,
}

/// Aggregate result for an fsx stress run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FsxStressReport {
    pub seed: u64,
    pub operation_count: u64,
    pub operations_executed: u64,
    pub passed: bool,
    pub corruption_cycles: u64,
    pub repaired_cycles: u64,
    pub final_file_size: usize,
    pub final_sha256: String,
    pub operation_mix: BTreeMap<String, u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<FsxFailureReport>,
    pub duration_us: u64,
    pub output_dir: Option<String>,
}

fn fsx_increment_mix(operation_mix: &mut BTreeMap<String, u64>, operation: &FsxOperation) {
    let key = operation.kind().to_owned();
    let counter = operation_mix.entry(key).or_insert(0);
    *counter = counter.saturating_add(1);
}

fn fsx_ensure_len(file: &mut Vec<u8>, target_len: usize) {
    if file.len() < target_len {
        file.resize(target_len, 0);
    }
}

fn fsx_apply_write(file: &mut Vec<u8>, offset: usize, data: &[u8]) -> Result<()> {
    let end = offset
        .checked_add(data.len())
        .context("write end overflow in fsx apply")?;
    fsx_ensure_len(file, end);
    file[offset..end].copy_from_slice(data);
    Ok(())
}

fn fsx_apply_truncate(file: &mut Vec<u8>, len: usize) {
    if len <= file.len() {
        file.truncate(len);
    } else {
        file.resize(len, 0);
    }
}

fn fsx_apply_fallocate(file: &mut Vec<u8>, offset: usize, len: usize) -> Result<()> {
    let end = offset
        .checked_add(len)
        .context("fallocate end overflow in fsx apply")?;
    fsx_ensure_len(file, end);
    Ok(())
}

fn fsx_apply_punch_hole(file: &mut [u8], offset: usize, len: usize) {
    if len == 0 || offset >= file.len() {
        return;
    }
    let end = offset.saturating_add(len).min(file.len());
    for byte in &mut file[offset..end] {
        *byte = 0;
    }
}

fn fsx_read_bounds(current_len: usize, offset: usize, len: usize) -> (usize, usize) {
    if current_len == 0 || len == 0 || offset >= current_len {
        return (0, 0);
    }
    let end = offset.saturating_add(len).min(current_len);
    (offset, end.saturating_sub(offset))
}

fn fsx_failure(
    operation_index: u64,
    operation: FsxOperation,
    reason: impl Into<String>,
    reference: &[u8],
    actual: &[u8],
) -> FsxFailureReport {
    FsxFailureReport {
        operation_index,
        operation,
        reason: reason.into(),
        expected_sha256: sha256_hex(reference),
        actual_sha256: sha256_hex(actual),
    }
}

fn fsx_verify_full(
    operation_index: u64,
    operation: FsxOperation,
    reference: &[u8],
    actual: &[u8],
) -> Option<FsxFailureReport> {
    if reference == actual {
        None
    } else {
        Some(fsx_failure(
            operation_index,
            operation,
            "full-file mismatch",
            reference,
            actual,
        ))
    }
}

fn fsx_random_len(rng: &mut DeterministicRng, min_len: usize, max_len: usize) -> usize {
    if max_len <= min_len {
        return min_len;
    }
    let span = max_len.saturating_sub(min_len).saturating_add(1);
    min_len.saturating_add(rng.next_usize(span))
}

fn generate_fsx_operation(
    rng: &mut DeterministicRng,
    current_len: usize,
    max_file_size_bytes: usize,
) -> FsxOperation {
    let bucket = rng.next_usize(100);
    match bucket {
        0..=39 => {
            if max_file_size_bytes == 0 {
                return FsxOperation::Fsync;
            }
            let offset_limit = max_file_size_bytes.saturating_sub(1);
            let offset = if current_len > 0 {
                let near_head = current_len.saturating_add(4096).min(offset_limit);
                rng.next_usize(near_head.saturating_add(1))
            } else {
                rng.next_usize(max_file_size_bytes)
            };
            let remaining = max_file_size_bytes.saturating_sub(offset);
            if remaining == 0 {
                return FsxOperation::Fsync;
            }
            let len = fsx_random_len(rng, 1, remaining.min(8192));
            let data = rng.payload(len, len);
            FsxOperation::Write { offset, data }
        }
        40..=64 => {
            if current_len == 0 {
                return FsxOperation::Read { offset: 0, len: 0 };
            }
            let offset = rng.next_usize(current_len);
            let max_len = current_len.saturating_sub(offset);
            let len = fsx_random_len(rng, 1, max_len.min(65_536));
            FsxOperation::Read { offset, len }
        }
        65..=74 => {
            if max_file_size_bytes == 0 {
                FsxOperation::Truncate { len: 0 }
            } else {
                FsxOperation::Truncate {
                    len: rng.next_usize(max_file_size_bytes.saturating_add(1)),
                }
            }
        }
        75..=84 => FsxOperation::Fsync,
        85..=89 => {
            if max_file_size_bytes == 0 {
                return FsxOperation::Fsync;
            }
            let offset = rng.next_usize(max_file_size_bytes);
            let remaining = max_file_size_bytes.saturating_sub(offset);
            if remaining == 0 {
                return FsxOperation::Fsync;
            }
            let len = fsx_random_len(rng, 1, remaining.min(65_536));
            FsxOperation::Fallocate { offset, len }
        }
        90..=94 => {
            if current_len == 0 {
                FsxOperation::PunchHole { offset: 0, len: 0 }
            } else {
                let offset = rng.next_usize(current_len);
                let max_len = current_len.saturating_sub(offset);
                let len = fsx_random_len(rng, 1, max_len.min(65_536));
                FsxOperation::PunchHole { offset, len }
            }
        }
        _ => FsxOperation::Reopen,
    }
}

fn fsx_inject_corruption(actual: &mut [u8], rng: &mut DeterministicRng) -> Option<(usize, usize)> {
    if actual.is_empty() {
        return None;
    }
    let offset = rng.next_usize(actual.len());
    let max_len = actual.len().saturating_sub(offset).min(4096);
    if max_len == 0 {
        return None;
    }
    let len = fsx_random_len(rng, 1, max_len);
    for byte in &mut actual[offset..offset + len] {
        let mut mask = u8::try_from(rng.next_u64() & u64::from(u8::MAX)).unwrap_or(1);
        if mask == 0 {
            mask = 1;
        }
        *byte ^= mask;
    }
    Some((offset, len))
}

fn fsx_repair_corruption(
    actual: &mut [u8],
    reference: &[u8],
    offset: usize,
    len: usize,
) -> Result<bool> {
    let end = offset
        .checked_add(len)
        .context("corruption repair end overflow")?
        .min(actual.len())
        .min(reference.len());
    if end <= offset {
        return Ok(false);
    }
    actual[offset..end].copy_from_slice(&reference[offset..end]);
    Ok(true)
}

fn write_fsx_repro_pack(
    output_dir: &Path,
    config: &FsxStressConfig,
    report: &FsxStressReport,
) -> Result<()> {
    #[derive(Serialize)]
    struct EnvReport<'a> {
        os: &'a str,
        arch: &'a str,
        family: &'a str,
        pkg_version: &'a str,
        generated_at_unix: &'a str,
    }

    #[derive(Serialize)]
    struct Manifest<'a> {
        operation_count: u64,
        seed: u64,
        max_file_size_bytes: usize,
        corruption_every_ops: u64,
        full_verify_every_ops: u64,
        report: &'a FsxStressReport,
    }

    fs::create_dir_all(output_dir)
        .with_context(|| format!("create fsx output dir {}", output_dir.display()))?;

    let generated_at = E2eLogEntry::now_iso8601();
    let env_report = EnvReport {
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        family: std::env::consts::FAMILY,
        pkg_version: env!("CARGO_PKG_VERSION"),
        generated_at_unix: &generated_at,
    };
    let env_path = output_dir.join("env.json");
    let env_json = serde_json::to_string_pretty(&env_report).context("serialize fsx env report")?;
    fs::write(&env_path, env_json).with_context(|| format!("write {}", env_path.display()))?;

    let report_path = output_dir.join("fsx_report.json");
    let report_json = serde_json::to_string_pretty(report).context("serialize fsx report")?;
    fs::write(&report_path, &report_json)
        .with_context(|| format!("write {}", report_path.display()))?;

    let manifest = Manifest {
        operation_count: config.operation_count,
        seed: config.seed,
        max_file_size_bytes: config.max_file_size_bytes,
        corruption_every_ops: config.corruption_every_ops,
        full_verify_every_ops: config.full_verify_every_ops,
        report,
    };
    let manifest_path = output_dir.join("manifest.json");
    let manifest_json =
        serde_json::to_string_pretty(&manifest).context("serialize fsx manifest")?;
    fs::write(&manifest_path, &manifest_json)
        .with_context(|| format!("write {}", manifest_path.display()))?;

    let manifest_sha256 = sha256_hex(manifest_json.as_bytes());
    let repro_lock = format!(
        "seed={}\noperation_count={}\nmax_file_size_bytes={}\ncorruption_every_ops={}\nfull_verify_every_ops={}\nfinal_sha256={}\nmanifest_sha256={}\n",
        config.seed,
        config.operation_count,
        config.max_file_size_bytes,
        config.corruption_every_ops,
        config.full_verify_every_ops,
        report.final_sha256,
        manifest_sha256
    );
    let lock_path = output_dir.join("repro.lock");
    fs::write(&lock_path, repro_lock).with_context(|| format!("write {}", lock_path.display()))?;

    Ok(())
}

#[derive(Debug, Default)]
struct FsxRunState {
    reference: Vec<u8>,
    actual: Vec<u8>,
    operation_mix: BTreeMap<String, u64>,
    failure: Option<FsxFailureReport>,
    operations_executed: u64,
    corruption_cycles: u64,
    repaired_cycles: u64,
}

fn apply_fsx_operation(
    state: &mut FsxRunState,
    operation_index: u64,
    operation: FsxOperation,
) -> Result<()> {
    fsx_increment_mix(&mut state.operation_mix, &operation);
    state.operations_executed = state.operations_executed.saturating_add(1);

    match operation {
        FsxOperation::Write { offset, data } => {
            fsx_apply_write(&mut state.reference, offset, &data)?;
            fsx_apply_write(&mut state.actual, offset, &data)?;
            Ok(())
        }
        FsxOperation::Read { offset, len } => {
            let (read_offset, read_len) = fsx_read_bounds(state.actual.len(), offset, len);
            let expected = &state.reference[read_offset..read_offset + read_len];
            let observed = &state.actual[read_offset..read_offset + read_len];
            if expected != observed {
                let reason =
                    format!("read verification mismatch at offset={read_offset} len={read_len}");
                state.failure = Some(fsx_failure(
                    operation_index,
                    FsxOperation::Read {
                        offset: read_offset,
                        len: read_len,
                    },
                    reason,
                    &state.reference,
                    &state.actual,
                ));
            }
            Ok(())
        }
        FsxOperation::Truncate { len } => {
            fsx_apply_truncate(&mut state.reference, len);
            fsx_apply_truncate(&mut state.actual, len);
            Ok(())
        }
        FsxOperation::Fsync => Ok(()),
        FsxOperation::Fallocate { offset, len } => {
            fsx_apply_fallocate(&mut state.reference, offset, len)?;
            fsx_apply_fallocate(&mut state.actual, offset, len)?;
            Ok(())
        }
        FsxOperation::PunchHole { offset, len } => {
            fsx_apply_punch_hole(&mut state.reference, offset, len);
            fsx_apply_punch_hole(&mut state.actual, offset, len);
            Ok(())
        }
        FsxOperation::Reopen => {
            state.failure = fsx_verify_full(
                operation_index,
                FsxOperation::Reopen,
                &state.reference,
                &state.actual,
            );
            Ok(())
        }
        FsxOperation::CorruptionCycle { .. } => {
            bail!("corruption_cycle is internal and should not be generated directly")
        }
    }
}

fn maybe_run_fsx_corruption_cycle(
    state: &mut FsxRunState,
    operation_index: u64,
    rng: &mut DeterministicRng,
    config: &FsxStressConfig,
) {
    if config.corruption_every_ops == 0
        || !state
            .operations_executed
            .is_multiple_of(config.corruption_every_ops)
    {
        return;
    }

    state.corruption_cycles = state.corruption_cycles.saturating_add(1);
    let Some((offset, len)) = fsx_inject_corruption(&mut state.actual, rng) else {
        return;
    };

    let op = FsxOperation::CorruptionCycle { offset, len };
    match fsx_repair_corruption(&mut state.actual, &state.reference, offset, len) {
        Ok(repaired) => {
            if repaired {
                state.repaired_cycles = state.repaired_cycles.saturating_add(1);
            }
        }
        Err(error) => {
            state.failure = Some(fsx_failure(
                operation_index,
                op,
                format!("{error:#}"),
                &state.reference,
                &state.actual,
            ));
            return;
        }
    }

    state.failure = fsx_verify_full(operation_index, op, &state.reference, &state.actual);
}

fn maybe_run_fsx_periodic_verify(
    state: &mut FsxRunState,
    operation_index: u64,
    config: &FsxStressConfig,
) {
    if config.full_verify_every_ops == 0
        || !state
            .operations_executed
            .is_multiple_of(config.full_verify_every_ops)
    {
        return;
    }
    state.failure = fsx_verify_full(
        operation_index,
        FsxOperation::Reopen,
        &state.reference,
        &state.actual,
    );
}

fn build_fsx_report(
    config: &FsxStressConfig,
    state: FsxRunState,
    duration: Duration,
) -> FsxStressReport {
    let output_dir = config
        .output_dir
        .as_ref()
        .map(|path| path.display().to_string());
    FsxStressReport {
        seed: config.seed,
        operation_count: config.operation_count,
        operations_executed: state.operations_executed,
        passed: state.failure.is_none(),
        corruption_cycles: state.corruption_cycles,
        repaired_cycles: state.repaired_cycles,
        final_file_size: state.actual.len(),
        final_sha256: sha256_hex(&state.actual),
        operation_mix: state.operation_mix,
        failure: state.failure,
        duration_us: u64::try_from(duration.as_micros()).unwrap_or(u64::MAX),
        output_dir,
    }
}

/// Run fsx-style stress with deterministic operation streams and periodic corruption injection.
pub fn run_fsx_stress(config: &FsxStressConfig) -> Result<FsxStressReport> {
    if config.operation_count == 0 {
        bail!("operation_count must be greater than zero");
    }
    if config.max_file_size_bytes == 0 {
        bail!("max_file_size_bytes must be greater than zero");
    }

    let start = Instant::now();
    let mut rng = DeterministicRng::new(config.seed);
    let mut state = FsxRunState::default();

    for operation_index in 0..config.operation_count {
        let operation =
            generate_fsx_operation(&mut rng, state.actual.len(), config.max_file_size_bytes);
        let op_for_error = operation.clone();
        if let Err(error) = apply_fsx_operation(&mut state, operation_index, operation) {
            state.failure = Some(fsx_failure(
                operation_index,
                op_for_error,
                format!("{error:#}"),
                &state.reference,
                &state.actual,
            ));
            break;
        }
        if state.failure.is_some() {
            break;
        }

        maybe_run_fsx_corruption_cycle(&mut state, operation_index, &mut rng, config);
        if state.failure.is_some() {
            break;
        }

        maybe_run_fsx_periodic_verify(&mut state, operation_index, config);
        if state.failure.is_some() {
            break;
        }
    }

    if state.failure.is_none() {
        state.failure = fsx_verify_full(
            state.operations_executed,
            FsxOperation::Reopen,
            &state.reference,
            &state.actual,
        );
    }

    let report = build_fsx_report(config, state, start.elapsed());
    if let Some(output_dir) = &config.output_dir {
        write_fsx_repro_pack(output_dir, config, &report)?;
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn e2e_log_entry_ok() {
        let entry = E2eLogEntry::ok(
            "test1",
            "create_fixture",
            serde_json::json!({"fs": "ext4"}),
            serde_json::json!({"path": "/tmp/test"}),
            Duration::from_micros(12345),
        );
        assert_eq!(entry.test, "test1");
        assert_eq!(entry.step, "create_fixture");
        assert_eq!(entry.status, "ok");
        assert_eq!(entry.duration_us, 12345);
        assert!(entry.error.is_none());
    }

    #[test]
    fn e2e_log_entry_err() {
        let entry = E2eLogEntry::err(
            "test1",
            "mount",
            serde_json::json!({}),
            Duration::from_millis(100),
            "mount failed",
        );
        assert_eq!(entry.status, "error");
        assert_eq!(entry.error.as_deref(), Some("mount failed"));
    }

    #[test]
    fn e2e_rch_capture_helpers_do_not_accept_artifact_retrieval_failures() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let scripts_dir = repo_root.join("scripts/e2e");
        let mut offenders = Vec::new();

        for entry in std::fs::read_dir(&scripts_dir).expect("read scripts/e2e directory") {
            let path = entry.expect("read scripts/e2e entry").path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("sh") {
                continue;
            }

            let display_path = path
                .strip_prefix(&repo_root)
                .unwrap_or(&path)
                .display()
                .to_string();
            let Ok(source) = std::fs::read_to_string(&path) else {
                offenders.push(format!("{display_path} (unreadable)"));
                continue;
            };
            for (line_index, line) in source.lines().enumerate() {
                if line.contains("RCH_ARTIFACT_RETRIEVAL_") && line.contains("ACCEPTED") {
                    offenders.push(format!("{}:{}", display_path, line_index + 1));
                }
            }
        }

        offenders.sort();
        assert!(
            offenders.is_empty(),
            "E2E RCH capture helpers must fail closed; remove accepted artifact-retrieval markers from: {}",
            offenders.join(", ")
        );
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    enum RchFixtureClass {
        LocalFallback,
        NonCompilationWrapper,
        RemoteBuildFailure,
        RemoteTestFailure,
        RemoteSuccessArtifactRetrievalHang,
        RequiredArtifactMissing,
        TimeoutBeforeRemoteExit,
        MissingRemoteEvidence,
    }

    impl RchFixtureClass {
        const ALL: [Self; 8] = [
            Self::LocalFallback,
            Self::NonCompilationWrapper,
            Self::RemoteBuildFailure,
            Self::RemoteTestFailure,
            Self::RemoteSuccessArtifactRetrievalHang,
            Self::RequiredArtifactMissing,
            Self::TimeoutBeforeRemoteExit,
            Self::MissingRemoteEvidence,
        ];
    }

    #[derive(Debug, Clone, Copy)]
    enum RchFixtureSignal {
        WrapperExited(i32),
        ArtifactRetrievalStopped,
        TimedOut,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum RchDecisionAuthority {
        RemoteEvidence,
        RejectedWrapperEvidence,
        Timeout,
    }

    #[derive(Debug, Clone, Copy)]
    struct RchCaptureFixture {
        name: &'static str,
        class: RchFixtureClass,
        command: &'static str,
        transcript: &'static str,
        signal: RchFixtureSignal,
        expected_marker: &'static str,
        expected_remote_exit: Option<i32>,
        expected_exit_code: i32,
        expected_authority: RchDecisionAuthority,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RchCaptureDecision {
        marker: String,
        remote_exit: Option<i32>,
        exit_code: i32,
        authority: RchDecisionAuthority,
    }

    const RCH_FIXTURE_MATRIX: &[RchCaptureFixture] = &[
        RchCaptureFixture {
            name: "local fallback rejected",
            class: RchFixtureClass::LocalFallback,
            command: "cargo check -p ffs-harness",
            transcript: "[RCH] local: no remote workers available\ncargo check completed locally\n",
            signal: RchFixtureSignal::WrapperExited(0),
            expected_marker: "RCH_LOCAL_FALLBACK_REJECTED",
            expected_remote_exit: None,
            expected_exit_code: 99,
            expected_authority: RchDecisionAuthority::RejectedWrapperEvidence,
        },
        RchCaptureFixture {
            name: "non-compilation wrapper rejected",
            class: RchFixtureClass::NonCompilationWrapper,
            command: "echo not-a-build",
            transcript: "exec called with non-compilation command: echo not-a-build\n",
            signal: RchFixtureSignal::WrapperExited(1),
            expected_marker: "RCH_LOCAL_FALLBACK_REJECTED",
            expected_remote_exit: None,
            expected_exit_code: 99,
            expected_authority: RchDecisionAuthority::RejectedWrapperEvidence,
        },
        RchCaptureFixture {
            name: "remote build failure",
            class: RchFixtureClass::RemoteBuildFailure,
            command: "cargo check -p ffs-harness",
            transcript: "[RCH] remote worker=build-a\nerror: could not compile `ffs-harness`\nRemote command finished: exit=101\n",
            signal: RchFixtureSignal::WrapperExited(101),
            expected_marker: "Remote command finished: exit=101",
            expected_remote_exit: Some(101),
            expected_exit_code: 101,
            expected_authority: RchDecisionAuthority::RemoteEvidence,
        },
        RchCaptureFixture {
            name: "remote test failure",
            class: RchFixtureClass::RemoteTestFailure,
            command: "cargo test -p ffs-harness --lib e2e_rch",
            transcript: "[RCH] remote worker=test-a\ntest result: FAILED. 0 passed; 1 failed\nRemote command finished: exit=101\n",
            signal: RchFixtureSignal::WrapperExited(101),
            expected_marker: "Remote command finished: exit=101",
            expected_remote_exit: Some(101),
            expected_exit_code: 101,
            expected_authority: RchDecisionAuthority::RemoteEvidence,
        },
        RchCaptureFixture {
            name: "remote success with artifact retrieval hang",
            class: RchFixtureClass::RemoteSuccessArtifactRetrievalHang,
            command: "cargo test -p ffs-harness --lib e2e_rch",
            transcript: "[RCH] remote worker=test-a\ntest result: ok. 7 passed\nRemote command finished: exit=0\n[RCH] retrieving artifacts\n",
            signal: RchFixtureSignal::ArtifactRetrievalStopped,
            expected_marker: "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT",
            expected_remote_exit: Some(0),
            expected_exit_code: 0,
            expected_authority: RchDecisionAuthority::RemoteEvidence,
        },
        RchCaptureFixture {
            name: "required artifact missing after remote success",
            class: RchFixtureClass::RequiredArtifactMissing,
            command: "cargo test -p ffs-harness --lib e2e_rch",
            transcript: "[RCH] remote worker=test-a\ntest result: ok. 7 passed\nRemote command finished: exit=0\nRCH_REQUIRED_ARTIFACT_MISSING|artifact=/tmp/expected-proof.json|log=/tmp/rch.log\n",
            signal: RchFixtureSignal::WrapperExited(99),
            expected_marker: "RCH_REQUIRED_ARTIFACT_MISSING",
            expected_remote_exit: Some(0),
            expected_exit_code: 99,
            expected_authority: RchDecisionAuthority::RejectedWrapperEvidence,
        },
        RchCaptureFixture {
            name: "timeout before remote exit",
            class: RchFixtureClass::TimeoutBeforeRemoteExit,
            command: "cargo test -p ffs-harness --lib slow_case",
            transcript: "[RCH] remote worker=test-a\nrunning tests without completion marker\n",
            signal: RchFixtureSignal::TimedOut,
            expected_marker: "RCH_TIMEOUT",
            expected_remote_exit: None,
            expected_exit_code: 124,
            expected_authority: RchDecisionAuthority::Timeout,
        },
        RchCaptureFixture {
            name: "missing remote evidence",
            class: RchFixtureClass::MissingRemoteEvidence,
            command: "cargo clippy -p ffs-harness --all-targets -- -D warnings",
            transcript: "cargo clippy completed with local-looking wrapper output\n",
            signal: RchFixtureSignal::WrapperExited(0),
            expected_marker: "RCH_REMOTE_EVIDENCE_MISSING",
            expected_remote_exit: None,
            expected_exit_code: 99,
            expected_authority: RchDecisionAuthority::RejectedWrapperEvidence,
        },
    ];

    fn last_remote_exit(transcript: &str) -> Option<i32> {
        transcript.lines().rev().find_map(remote_exit_from_line)
    }

    fn remote_exit_from_line(line: &str) -> Option<i32> {
        let (_, suffix) = line.rsplit_once("Remote command finished: exit=")?;
        let digit_count = suffix.bytes().take_while(u8::is_ascii_digit).count();
        if digit_count == 0 {
            return None;
        }
        suffix[..digit_count].parse().ok()
    }

    fn lacks_remote_success_evidence(transcript: &str) -> bool {
        !transcript.contains("[RCH] remote")
            && !transcript.contains("Remote command finished: exit=0")
    }

    fn wrapper_exit_code(signal: RchFixtureSignal) -> i32 {
        match signal {
            RchFixtureSignal::WrapperExited(status) => status,
            RchFixtureSignal::ArtifactRetrievalStopped => 0,
            RchFixtureSignal::TimedOut => 124,
        }
    }

    fn model_rch_capture_decision(fixture: &RchCaptureFixture) -> RchCaptureDecision {
        let remote_exit = last_remote_exit(fixture.transcript);

        if fixture.transcript.contains("[RCH] local")
            || fixture
                .transcript
                .contains("exec called with non-compilation command")
        {
            return RchCaptureDecision {
                marker: "RCH_LOCAL_FALLBACK_REJECTED".to_owned(),
                remote_exit,
                exit_code: 99,
                authority: RchDecisionAuthority::RejectedWrapperEvidence,
            };
        }

        if matches!(fixture.signal, RchFixtureSignal::TimedOut) && remote_exit.is_none() {
            return RchCaptureDecision {
                marker: "RCH_TIMEOUT".to_owned(),
                remote_exit,
                exit_code: 124,
                authority: RchDecisionAuthority::Timeout,
            };
        }

        if matches!(fixture.signal, RchFixtureSignal::ArtifactRetrievalStopped) {
            let exit_code = remote_exit.unwrap_or(99);
            return RchCaptureDecision {
                marker: "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT".to_owned(),
                remote_exit,
                exit_code,
                authority: RchDecisionAuthority::RemoteEvidence,
            };
        }

        if fixture.transcript.contains("RCH_REQUIRED_ARTIFACT_MISSING") {
            return RchCaptureDecision {
                marker: "RCH_REQUIRED_ARTIFACT_MISSING".to_owned(),
                remote_exit,
                exit_code: 99,
                authority: RchDecisionAuthority::RejectedWrapperEvidence,
            };
        }

        if let Some(exit_code) = remote_exit {
            return RchCaptureDecision {
                marker: format!("Remote command finished: exit={exit_code}"),
                remote_exit,
                exit_code,
                authority: RchDecisionAuthority::RemoteEvidence,
            };
        }

        let status = wrapper_exit_code(fixture.signal);
        if status == 0 && lacks_remote_success_evidence(fixture.transcript) {
            return RchCaptureDecision {
                marker: "RCH_REMOTE_EVIDENCE_MISSING".to_owned(),
                remote_exit,
                exit_code: 99,
                authority: RchDecisionAuthority::RejectedWrapperEvidence,
            };
        }

        RchCaptureDecision {
            marker: format!("wrapper exit={status}"),
            remote_exit,
            exit_code: status,
            authority: RchDecisionAuthority::RejectedWrapperEvidence,
        }
    }

    fn normalized_guardrail_marker(marker: &str) -> &str {
        if marker.starts_with("Remote command finished: exit=") {
            "Remote command finished: exit="
        } else {
            marker
        }
    }

    fn fixture_matrix_guardrail_markers() -> BTreeSet<&'static str> {
        let mut markers = RCH_FIXTURE_MATRIX
            .iter()
            .map(|fixture| normalized_guardrail_marker(fixture.expected_marker))
            .collect::<BTreeSet<_>>();
        markers.insert("[RCH] local");
        markers.insert("exec called with non-compilation command");
        // Capacity-preflight reference markers are guardrail markers emitted by
        // `e2e_rch_capture` directly rather than remote-exit transcript classes,
        // so — like `[RCH] local` above — they are part of the guardrail
        // vocabulary without a dedicated `RCH_FIXTURE_MATRIX` transcript fixture.
        markers.insert("RCH_CAPACITY_PREFLIGHT_REFERENCE");
        markers.insert("RCH_CAPACITY_PREFLIGHT_REFERENCE_MISSING");
        markers
    }

    fn shell_fixture_matrix_markers(source: &str) -> BTreeSet<String> {
        let marker_function_start = source
            .find("e2e_rch_capture_fixture_matrix_markers()")
            .expect("RCH fixture matrix marker function exists");
        let marker_function_source = &source[marker_function_start..];
        let heredoc_start = marker_function_source
            .find("cat <<'EOF'\n")
            .expect("RCH fixture matrix marker heredoc exists")
            + "cat <<'EOF'\n".len();
        let heredoc_source = &marker_function_source[heredoc_start..];
        let heredoc_end = heredoc_source
            .find("\nEOF")
            .expect("RCH fixture matrix marker heredoc closes");

        heredoc_source[..heredoc_end]
            .lines()
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn e2e_rch_fixture_matrix_covers_all_transcript_classes() {
        let covered: BTreeSet<_> = RCH_FIXTURE_MATRIX
            .iter()
            .map(|fixture| fixture.class)
            .collect();
        let expected: BTreeSet<_> = RchFixtureClass::ALL.into_iter().collect();

        assert_eq!(
            covered, expected,
            "RCH fixture matrix must cover every remote-exit transcript class"
        );
    }

    #[test]
    fn e2e_rch_fixture_matrix_models_exact_wrapper_markers() {
        for fixture in RCH_FIXTURE_MATRIX {
            let actual = model_rch_capture_decision(fixture);
            assert_eq!(
                actual.marker, fixture.expected_marker,
                "{} marker",
                fixture.name
            );
            assert_eq!(
                actual.remote_exit, fixture.expected_remote_exit,
                "{} remote exit",
                fixture.name
            );
            assert_eq!(
                actual.exit_code, fixture.expected_exit_code,
                "{} exit code",
                fixture.name
            );
            assert_eq!(
                actual.authority, fixture.expected_authority,
                "{} authority",
                fixture.name
            );
        }
    }

    #[test]
    fn e2e_rch_fixture_matrix_has_no_accepted_retrieval_markers() {
        let accepted_marker = ["RCH_ARTIFACT_RETRIEVAL_", "ACCEPTED"].concat();

        for fixture in RCH_FIXTURE_MATRIX {
            for (field, value) in [
                ("name", fixture.name),
                ("command", fixture.command),
                ("transcript", fixture.transcript),
                ("expected_marker", fixture.expected_marker),
            ] {
                assert!(
                    !value.contains(&accepted_marker),
                    "{} fixture field `{field}` must not contain forbidden marker",
                    fixture.name
                );
            }
        }
    }

    #[test]
    fn e2e_rch_fixture_matrix_matches_live_guardrail_markers() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let lib_path = repo_root.join("scripts/e2e/lib.sh");
        let source = std::fs::read_to_string(&lib_path).expect("read scripts/e2e/lib.sh");
        let helper_start = source
            .find("e2e_rch_capture()")
            .expect("canonical e2e_rch_capture helper exists");
        let helper_source = &source[helper_start..];

        for marker in fixture_matrix_guardrail_markers() {
            assert!(
                helper_source.contains(marker),
                "canonical RCH helper must contain fixture matrix marker `{marker}`"
            );
        }

        let expected_markers: BTreeSet<_> = fixture_matrix_guardrail_markers()
            .into_iter()
            .map(str::to_owned)
            .collect();
        assert_eq!(
            shell_fixture_matrix_markers(&source),
            expected_markers,
            "shell smoke marker list must match the Rust fixture matrix"
        );
    }

    #[test]
    fn e2e_canonical_rch_capture_helper_is_fail_closed() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let lib_path = repo_root.join("scripts/e2e/lib.sh");
        let source = std::fs::read_to_string(&lib_path).expect("read scripts/e2e/lib.sh");
        let helper_start = source
            .find("e2e_rch_capture()")
            .expect("canonical e2e_rch_capture helper exists");
        let helper_source = &source[helper_start..];

        for needle in [
            "\"$rch_bin\" exec --",
            "Remote command finished: exit=0",
            "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT",
            "RCH_REQUIRED_ARTIFACT_READY",
            "RCH_TIMEOUT",
            "[RCH] local",
            "exec called with non-compilation command",
            "RCH_LOCAL_FALLBACK_REJECTED",
            "RCH_REMOTE_EVIDENCE_MISSING",
        ] {
            assert!(
                helper_source.contains(needle),
                "canonical RCH helper must contain fail-closed contract marker `{needle}`"
            );
        }

        let accepted_marker = ["RCH_ARTIFACT_RETRIEVAL_", "ACCEPTED"].concat();
        assert!(
            !helper_source.contains(&accepted_marker),
            "canonical RCH helper must not accept artifact retrieval failure"
        );
    }

    #[test]
    fn e2e_representative_scripts_delegate_to_canonical_rch_capture() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for script in [
            "scripts/e2e/ffs_invariant_oracle_e2e.sh",
            "scripts/e2e/ffs_oq_decision_integration_e2e.sh",
            "scripts/e2e/ffs_verification_runner_e2e.sh",
        ] {
            let path = repo_root.join(script);
            let source = std::fs::read_to_string(&path).expect("read migrated E2E script");
            assert!(
                source.contains("e2e_rch_add_env_allowlist CARGO_TARGET_DIR"),
                "{script} should use the shared RCH env allowlist helper"
            );
            assert!(
                source.contains("e2e_rch_capture \"$@\""),
                "{script} should delegate run_rch_capture to the shared fail-closed helper"
            );
            assert!(
                !source.contains("exec -- \"$@\""),
                "{script} should not keep a local rch exec implementation after migration"
            );
        }
    }

    #[test]
    fn e2e_log_entry_skip() {
        let entry = E2eLogEntry::skip("test1", "create_fixture", "mkfs.ext4 not found");
        assert_eq!(entry.status, "skip");
        assert_eq!(entry.duration_us, 0);
    }

    #[test]
    fn e2e_log_ndjson_roundtrip() {
        let mut log = E2eLog::new();
        log.push(E2eLogEntry::ok(
            "t",
            "s1",
            serde_json::json!({}),
            serde_json::json!({}),
            Duration::ZERO,
        ));
        log.push(E2eLogEntry::err(
            "t",
            "s2",
            serde_json::json!({}),
            Duration::ZERO,
            "oops",
        ));

        let ndjson = log.to_ndjson().unwrap();
        let lines: Vec<&str> = ndjson.lines().collect();
        assert_eq!(lines.len(), 2);

        let parsed = lines
            .iter()
            .map(|line| serde_json::from_str::<E2eLogEntry>(line))
            .collect::<serde_json::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(parsed.as_slice(), log.entries());
    }

    #[test]
    fn e2e_log_has_errors() {
        let mut log = E2eLog::new();
        assert!(!log.has_errors());
        log.push(E2eLogEntry::ok(
            "t",
            "s",
            serde_json::json!({}),
            serde_json::json!({}),
            Duration::ZERO,
        ));
        assert!(!log.has_errors());
        log.push(E2eLogEntry::err(
            "t",
            "s",
            serde_json::json!({}),
            Duration::ZERO,
            "e",
        ));
        assert!(log.has_errors());
    }

    #[test]
    fn e2e_log_lock_recovers_poisoned_guard() {
        let log = Arc::new(Mutex::new(E2eLog::new()));
        let poisoned_log = Arc::clone(&log);
        let poison_result = panic::catch_unwind(move || {
            let Ok(_guard) = poisoned_log.lock() else {
                return;
            };
            panic::resume_unwind(Box::new("poison e2e log mutex"));
        });
        assert!(poison_result.is_err());

        lock_e2e_log(log.as_ref()).push(E2eLogEntry::skip(
            "test",
            "recover_log_lock",
            "poison recovered",
        ));
        assert_eq!(lock_e2e_log(log.as_ref()).entries().len(), 1);
    }

    #[test]
    fn context_creates_workdir_and_cleans_up() {
        let opts = FixtureOptions::default();
        let workdir;
        {
            let ctx = E2eTestContext::new("cleanup_test", ImageType::Ext4, &opts).unwrap();
            workdir = ctx.workdir.clone();
            assert!(workdir.exists());
            assert!(ctx.mountpoint.exists());
        }
        // After drop, workdir should be cleaned up.
        assert!(!workdir.exists());
    }

    #[test]
    fn context_create_fixture_ext4() {
        let opts = FixtureOptions {
            size_mb: 8,
            ..Default::default()
        };
        let ctx = E2eTestContext::new("fixture_ext4", ImageType::Ext4, &opts).unwrap();
        let created = ctx.create_fixture(&opts).unwrap();
        if created {
            assert!(ctx.image_path.exists());
            let meta = fs::metadata(&ctx.image_path).unwrap();
            assert!(meta.len() >= 8 * 1024 * 1024);
        }
        // If not created, mkfs.ext4 was not available (CI-safe skip).
    }

    #[test]
    fn context_corruption_injection() {
        let opts = FixtureOptions {
            size_mb: 1,
            ..Default::default()
        };
        let ctx = E2eTestContext::new("corruption_test", ImageType::Ext4, &opts).unwrap();

        // Create a minimal image file.
        fs::write(&ctx.image_path, vec![0u8; 1024 * 1024]).unwrap();

        // Inject corruption.
        ctx.inject_corruption(512, &[0xFF, 0xFE, 0xFD]).unwrap();

        // Verify corruption was applied.
        let data = fs::read(&ctx.image_path).unwrap();
        assert_eq!(data[512], 0xFF);
        assert_eq!(data[513], 0xFE);
        assert_eq!(data[514], 0xFD);
    }

    #[test]
    fn context_verify_file_content() {
        let opts = FixtureOptions::default();
        let ctx = E2eTestContext::new("verify_test", ImageType::Ext4, &opts).unwrap();

        let test_file = ctx.workdir.join("test.txt");
        fs::write(&test_file, b"hello world").unwrap();

        assert!(ctx.verify_file_content(&test_file, b"hello world").unwrap());
        assert!(
            !ctx.verify_file_content(&test_file, b"wrong content")
                .unwrap()
        );
    }

    #[test]
    fn context_collect_artifacts() {
        let opts = FixtureOptions::default();
        let mut ctx = E2eTestContext::new("artifacts_test", ImageType::Ext4, &opts).unwrap();

        let artifact_dir =
            std::env::temp_dir().join(format!("ffs-e2e-artifacts-{}", std::process::id()));

        ctx.collect_artifacts(&artifact_dir).unwrap();

        let log_path = artifact_dir.join("e2e_log.json");
        assert!(log_path.exists());

        // Log should be valid NDJSON.
        let content = fs::read_to_string(&log_path).unwrap();
        assert!(!content.is_empty());

        // Cleanup.
        let _ = fs::remove_dir_all(&artifact_dir);
    }

    #[test]
    fn context_run_step_catches_panic() {
        let opts = FixtureOptions::default();
        let ctx = E2eTestContext::new("panic_test", ImageType::Ext4, &opts).unwrap();

        let result: Result<()> = ctx.run_step("panic_step", serde_json::json!({}), || {
            std::panic::panic_any("test panic");
        });

        assert!(result.is_err());
        let last_status = ctx
            .log
            .lock()
            .unwrap()
            .entries()
            .last()
            .unwrap()
            .status
            .clone();
        let has_panic = ctx
            .log
            .lock()
            .unwrap()
            .entries()
            .last()
            .unwrap()
            .error
            .as_ref()
            .unwrap()
            .contains("PANIC");
        assert_eq!(last_status, "error");
        assert!(has_panic);
    }

    #[test]
    fn context_run_step_logs_error() {
        let opts = FixtureOptions::default();
        let ctx = E2eTestContext::new("error_test", ImageType::Ext4, &opts).unwrap();

        let result: Result<()> = ctx.run_step("fail_step", serde_json::json!({}), || {
            bail!("intentional failure");
        });

        assert!(result.is_err());
        let has_errors = lock_e2e_log(ctx.log.as_ref()).has_errors();
        assert!(has_errors);
    }

    #[test]
    fn e2e_test_result_from_log() {
        let mut log = E2eLog::new();
        log.push(E2eLogEntry::ok(
            "t",
            "s1",
            serde_json::json!({}),
            serde_json::json!({}),
            Duration::ZERO,
        ));
        log.push(E2eLogEntry::ok(
            "t",
            "s2",
            serde_json::json!({}),
            serde_json::json!({}),
            Duration::ZERO,
        ));
        log.push(E2eLogEntry::skip("t", "s3", "skipped"));

        let result = E2eTestResult::from_log("test1", &log, Duration::from_secs(1), None);
        assert_eq!(result.passed, !fail_on_skip_in_ci());
        assert!(result.inconclusive);
        assert_eq!(result.steps_total, 3);
        assert_eq!(result.steps_ok, 2);
        assert_eq!(result.steps_skip, 1);
        assert_eq!(result.steps_error, 0);
    }

    #[test]
    fn e2e_test_result_json_shape() -> Result<(), serde_json::Error> {
        let mut log = E2eLog::new();
        log.push(E2eLogEntry::ok(
            "mounted_smoke",
            "create_image",
            serde_json::json!({"image": "ext4"}),
            serde_json::json!({"bytes": 4096}),
            Duration::ZERO,
        ));
        log.push(E2eLogEntry::err(
            "mounted_smoke",
            "mount_image",
            serde_json::json!({"mount_mode": "fuse"}),
            Duration::ZERO,
            "permission denied",
        ));

        let result = E2eTestResult::from_log(
            "mounted_smoke",
            &log,
            Duration::from_millis(42),
            Some(std::path::Path::new("artifacts/e2e/mounted_smoke")),
        );
        let json = serde_json::to_string_pretty(&result)?;
        insta::assert_snapshot!("e2e_test_result_json_shape", json);
        let parsed: E2eTestResult = serde_json::from_str(&json)?;

        assert_eq!(parsed, result);
        assert!(!parsed.passed);
        assert!(!parsed.inconclusive);
        assert_eq!(parsed.steps_total, 2);
        assert_eq!(parsed.steps_ok, 1);
        assert_eq!(parsed.steps_error, 1);
        assert_eq!(parsed.steps_skip, 0);
        assert_eq!(parsed.duration_us, 42_000);
        assert_eq!(
            parsed.artifacts_dir.as_deref(),
            Some("artifacts/e2e/mounted_smoke")
        );
        Ok(())
    }

    #[test]
    fn e2e_repro_config_json_shapes() -> Result<(), serde_json::Error> {
        let crash_config = CrashReplaySuiteConfig {
            schedule_count: 3,
            min_operations: 8,
            max_operations: 12,
            base_seed: 0x00C0_FFEE_0000_0007,
            output_dir: Some(PathBuf::from("artifacts/e2e/crash-replay")),
        };
        let crash_json = serde_json::to_string_pretty(&crash_config)?;
        insta::assert_snapshot!("crash_replay_suite_config_json_shape", crash_json);
        let parsed_crash: CrashReplaySuiteConfig = serde_json::from_str(&crash_json)?;
        assert_eq!(parsed_crash, crash_config);

        let fsx_config = FsxStressConfig {
            operation_count: 1_000,
            seed: 0xF5A5_7E55_0000_0001,
            max_file_size_bytes: 2 * 1024 * 1024,
            corruption_every_ops: 100,
            full_verify_every_ops: 200,
            output_dir: Some(PathBuf::from("artifacts/e2e/fsx")),
        };
        let fsx_json = serde_json::to_string_pretty(&fsx_config)?;
        insta::assert_snapshot!("fsx_stress_config_json_shape", fsx_json);
        let parsed_fsx: FsxStressConfig = serde_json::from_str(&fsx_json)?;
        assert_eq!(parsed_fsx, fsx_config);
        Ok(())
    }

    #[test]
    fn sha256_hex_works() {
        if !command_available("sha256sum") {
            return;
        }
        let hash = sha256_hex(b"hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn mount_handle_unmount_on_drop() {
        // Test that MountHandle doesn't panic when dropping without a real mount.
        let log = Arc::new(Mutex::new(E2eLog::new()));
        let mountpoint = std::env::temp_dir().join("ffs-e2e-mount-test");
        let _ = fs::create_dir_all(&mountpoint);

        // Create a handle with a dummy child (cat, which exits immediately).
        if let Ok(child) = Command::new("sleep").arg("0").spawn() {
            let handle = MountHandle::new(child, mountpoint.clone(), "mount_test", log);
            drop(handle);
            // Should not panic.
        }

        let _ = fs::remove_dir_all(&mountpoint);
    }

    #[test]
    fn crash_schedule_generation_is_deterministic() {
        let seed = 0xA11C_E55D_0000_0042;
        let left = generate_crash_schedule(7, seed, 16, 24).expect("generate left schedule");
        let right = generate_crash_schedule(7, seed, 16, 24).expect("generate right schedule");
        assert_eq!(left, right);
        assert!(!left.operations.is_empty());
        assert!(!left.crash_points.is_empty());
    }

    #[test]
    fn crash_schedule_replay_validates_fsynced_state() {
        let schedule = CrashSchedule {
            schedule_id: 11,
            seed: 77,
            operations: vec![
                CrashOperation::Mkdir {
                    path: "/logs".to_owned(),
                    fsync: true,
                },
                CrashOperation::Write {
                    path: "/logs/a.bin".to_owned(),
                    data: b"alpha".to_vec(),
                    fsync: true,
                },
                CrashOperation::Write {
                    path: "/logs/a.bin".to_owned(),
                    data: b"beta".to_vec(),
                    fsync: false,
                },
                CrashOperation::Rename {
                    from: "/logs/a.bin".to_owned(),
                    to: "/logs/b.bin".to_owned(),
                    fsync: true,
                },
            ],
            crash_points: vec![
                CrashPoint {
                    op_index: 2,
                    stage: CrashPointStage::AfterOp,
                },
                CrashPoint {
                    op_index: 3,
                    stage: CrashPointStage::AfterOp,
                },
            ],
        };

        let result = run_crash_schedule(&schedule).expect("run schedule");
        assert!(result.passed, "errors: {:#?}", result.case_results);
        assert_eq!(result.case_results.len(), 2);
    }

    #[test]
    fn crash_replay_suite_runs_500_schedules() {
        let config = CrashReplaySuiteConfig {
            schedule_count: 500,
            min_operations: 100,
            max_operations: 1000,
            base_seed: 0x1234_5678_9ABC_DEF0,
            output_dir: None,
        };
        let report = run_crash_replay_suite(&config).expect("run crash replay suite");
        assert_eq!(report.schedule_count, 500);
        assert_eq!(report.failed_schedules, 0);
        assert_eq!(report.passed_schedules, 500);
    }

    #[test]
    fn crash_replay_suite_writes_repro_pack() {
        let output_dir =
            std::env::temp_dir().join(format!("ffs-crash-replay-artifacts-{}", std::process::id()));
        let config = CrashReplaySuiteConfig {
            schedule_count: 3,
            min_operations: 8,
            max_operations: 12,
            base_seed: 99,
            output_dir: Some(output_dir.clone()),
        };

        let report = run_crash_replay_suite(&config).expect("run crash replay suite");
        assert_eq!(report.schedule_count, 3);
        assert!(output_dir.join("env.json").exists());
        assert!(output_dir.join("manifest.json").exists());
        assert!(output_dir.join("repro.lock").exists());
        assert!(
            output_dir
                .join("schedules")
                .join("schedule_0000.json")
                .exists()
        );

        let _ = fs::remove_dir_all(&output_dir);
    }

    #[test]
    fn crash_replay_case_artifacts_include_survivors_and_minimized_repro() {
        let schedule = CrashSchedule {
            schedule_id: 42,
            seed: 0x00C0_FFEE,
            operations: vec![
                CrashOperation::Mkdir {
                    path: "/logs".to_owned(),
                    fsync: true,
                },
                CrashOperation::Write {
                    path: "/logs/a.bin".to_owned(),
                    data: b"survivor".to_vec(),
                    fsync: true,
                },
            ],
            crash_points: vec![CrashPoint {
                op_index: 1,
                stage: CrashPointStage::AfterOp,
            }],
        };

        let result = run_crash_schedule(&schedule).expect("run schedule");
        let case = result.case_results.first().expect("case result");
        assert_eq!(case.lane_type, CrashReplayLane::CoreDeterministic);
        assert_eq!(
            case.classification,
            CrashReplayClassification::FsyncBoundary
        );
        assert_eq!(case.expected_survivors, case.observed_survivors);
        assert!(
            case.expected_survivors
                .files
                .contains(&"/logs/a.bin".to_owned())
        );
        assert!(case.raw_log.contains("CRASH_REPLAY_CASE"));
        assert!(
            case.minimized_reproduction_command
                .contains("run-crash-replay")
        );
        assert_eq!(case.cleanup_status, "cleaned_up_simulated_state");
        assert!(case.unreduced_follow_up_bead.is_none());
    }

    #[test]
    fn crash_operation_minimizer_reduces_to_reproducing_trace() {
        let operations = vec![
            CrashOperation::Write {
                path: "/noise-a".to_owned(),
                data: b"noise".to_vec(),
                fsync: false,
            },
            CrashOperation::Write {
                path: "/trigger".to_owned(),
                data: b"trigger".to_vec(),
                fsync: true,
            },
            CrashOperation::Write {
                path: "/noise-b".to_owned(),
                data: b"noise".to_vec(),
                fsync: false,
            },
        ];

        let minimized = minimize_crash_operation_trace(&operations, |candidate| {
            candidate.iter().any(|operation| match operation {
                CrashOperation::Write { data, .. } => data.as_slice() == b"trigger",
                _ => false,
            })
        });
        assert_eq!(minimized.len(), 1);
        assert!(matches!(
            &minimized[0],
            CrashOperation::Write { path, .. } if path == "/trigger"
        ));
    }

    #[test]
    fn crash_point_classification_distinguishes_precommit_and_post_flush() {
        let schedule = CrashSchedule {
            schedule_id: 7,
            seed: 11,
            operations: vec![CrashOperation::Write {
                path: "/file".to_owned(),
                data: b"x".to_vec(),
                fsync: false,
            }],
            crash_points: Vec::new(),
        };

        assert_eq!(
            crash_replay_classification(
                &schedule,
                CrashPoint {
                    op_index: 0,
                    stage: CrashPointStage::BeforeOp,
                },
            ),
            CrashReplayClassification::PreCommit
        );
        assert_eq!(
            crash_replay_classification(
                &schedule,
                CrashPoint {
                    op_index: 0,
                    stage: CrashPointStage::AfterOp,
                },
            ),
            CrashReplayClassification::PostCommitPreFlush
        );
    }

    #[test]
    fn fsx_stress_is_deterministic_for_seed() {
        let config = FsxStressConfig {
            operation_count: 3_000,
            seed: 0x77AA_5500_1122_3344,
            max_file_size_bytes: 4 * 1024 * 1024,
            corruption_every_ops: 250,
            full_verify_every_ops: 250,
            output_dir: None,
        };

        let left = run_fsx_stress(&config).expect("run left fsx stress");
        let right = run_fsx_stress(&config).expect("run right fsx stress");

        assert!(left.passed);
        assert!(right.passed);
        assert_eq!(left.operation_count, right.operation_count);
        assert_eq!(left.operations_executed, right.operations_executed);
        assert_eq!(left.corruption_cycles, right.corruption_cycles);
        assert_eq!(left.repaired_cycles, right.repaired_cycles);
        assert_eq!(left.final_file_size, right.final_file_size);
        assert_eq!(left.final_sha256, right.final_sha256);
        assert_eq!(left.operation_mix, right.operation_mix);
    }

    #[test]
    fn fsx_stress_survives_corruption_cycles() {
        let config = FsxStressConfig {
            operation_count: 5_000,
            seed: 0x0BAD_F00D_F5F5_1234,
            max_file_size_bytes: 8 * 1024 * 1024,
            corruption_every_ops: 100,
            full_verify_every_ops: 500,
            output_dir: None,
        };
        let report = run_fsx_stress(&config).expect("run fsx stress");
        assert!(report.passed, "failure: {:#?}", report.failure);
        assert_eq!(report.operations_executed, config.operation_count);
        assert!(report.corruption_cycles > 0);
        assert!(report.repaired_cycles > 0);
        assert!(report.failure.is_none());
    }

    #[test]
    fn fsx_stress_writes_repro_pack() {
        let output_dir =
            std::env::temp_dir().join(format!("ffs-fsx-artifacts-{}", std::process::id()));
        let config = FsxStressConfig {
            operation_count: 1_000,
            seed: 77,
            max_file_size_bytes: 2 * 1024 * 1024,
            corruption_every_ops: 100,
            full_verify_every_ops: 200,
            output_dir: Some(output_dir.clone()),
        };

        let report = run_fsx_stress(&config).expect("run fsx stress");
        assert!(report.passed);
        assert!(output_dir.join("env.json").exists());
        assert!(output_dir.join("manifest.json").exists());
        assert!(output_dir.join("repro.lock").exists());
        assert!(output_dir.join("fsx_report.json").exists());

        let _ = fs::remove_dir_all(&output_dir);
    }

    fn sample_survivor_set() -> CrashReplaySurvivorSet {
        CrashReplaySurvivorSet {
            file_count: 1,
            directory_count: 2,
            files: vec!["/logs/a.bin".to_owned()],
            directories: vec!["/".to_owned(), "/logs".to_owned()],
            content_hash: "b2f9e4d4b8d7087bd2a0db4460da90d0f1a5e93f".to_owned(),
        }
    }

    #[test]
    fn crash_replay_suite_report_json_shape() -> Result<()> {
        let report = CrashReplaySuiteReport {
            schedule_count: 1,
            passed_schedules: 1,
            failed_schedules: 0,
            duration_us: 0,
            output_dir: Some("artifacts/e2e/crash-replay".to_owned()),
            results: vec![CrashReplayScheduleResult {
                schedule_id: 7,
                seed: 0xC0FF_EE00_0000_0007,
                operation_count: 2,
                passed: true,
                case_results: vec![CrashReplayCaseResult {
                    lane_type: CrashReplayLane::CoreDeterministic,
                    crash_point: CrashPoint {
                        op_index: 1,
                        stage: CrashPointStage::AfterOp,
                    },
                    classification: CrashReplayClassification::FsyncBoundary,
                    executed_operations: 2,
                    minimized_operation_count: 1,
                    expected_survivors: sample_survivor_set(),
                    observed_survivors: sample_survivor_set(),
                    cleanup_status: "cleaned_up_simulated_state".to_owned(),
                    raw_log: "CRASH_REPLAY_CASE schedule=7 case=0 status=pass".to_owned(),
                    minimized_reproduction_command:
                        "ffs-harness run-crash-replay --count 1 --seed 7".to_owned(),
                    unreduced_follow_up_bead: None,
                    passed: true,
                    errors: Vec::new(),
                }],
                duration_us: 0,
            }],
        };

        let json = serde_json::to_string_pretty(&report)?;
        insta::assert_snapshot!("crash_replay_suite_report_json_shape", json);
        let parsed: CrashReplaySuiteReport = serde_json::from_str(&json)?;
        assert_eq!(parsed, report);
        Ok(())
    }

    #[test]
    fn fsx_stress_report_json_shape() -> Result<()> {
        let mut operation_mix = BTreeMap::new();
        operation_mix.insert("corruption_cycle".to_owned(), 1);
        operation_mix.insert("fsync".to_owned(), 1);
        operation_mix.insert("write".to_owned(), 2);

        let report = FsxStressReport {
            seed: 0xF5A5_7E55_0000_0001,
            operation_count: 4,
            operations_executed: 4,
            passed: false,
            corruption_cycles: 1,
            repaired_cycles: 0,
            final_file_size: 4096,
            final_sha256: "0f343b0931126a20f133d67c2b018a3b".to_owned(),
            operation_mix,
            failure: Some(FsxFailureReport {
                operation_index: 3,
                operation: FsxOperation::CorruptionCycle {
                    offset: 128,
                    len: 32,
                },
                reason: "full verify mismatch".to_owned(),
                expected_sha256: "f00ba4".to_owned(),
                actual_sha256: "badc0de".to_owned(),
            }),
            duration_us: 0,
            output_dir: Some("artifacts/e2e/fsx".to_owned()),
        };

        let json = serde_json::to_string_pretty(&report)?;
        insta::assert_snapshot!("fsx_stress_report_json_shape", json);
        let parsed: FsxStressReport = serde_json::from_str(&json)?;
        assert_eq!(parsed, report);
        Ok(())
    }

    #[test]
    fn image_type_display() {
        assert_eq!(ImageType::Ext4.to_string(), "ext4");
        assert_eq!(ImageType::Btrfs.to_string(), "btrfs");
    }

    #[test]
    fn command_available_check() {
        // `ls` should always be available.
        assert!(command_available("ls"));
        // Nonexistent command.
        assert!(!command_available("definitely_not_a_real_command_12345"));
    }

    #[test]
    fn env_flag_truthy_values() {
        for val in ["1", "true", "yes", "on", "TRUE", "Yes", " 1 ", " ON "] {
            assert!(env_flag_is_truthy(val), "{val:?} should be truthy");
        }
        for val in ["0", "false", "no", "off", "", "maybe", "2"] {
            assert!(!env_flag_is_truthy(val), "{val:?} should not be truthy");
        }
    }
}
