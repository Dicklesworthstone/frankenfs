//! Process-execution evidence that cannot be forged from JSON.
//!
//! `ExecutedEvidence` carries proof that a command was actually run: command,
//! args, exit code, output hashes, timing, git state, and host class. It is
//! intentionally **not** `Deserialize` — the only way to construct one is to
//! actually execute the process. This prevents hand-authored JSON from faking
//! evidence and turns the harness into the executor of record.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

/// Evidence of a process execution, constructible only by running the process.
///
/// This type implements `Serialize` (for reporting/logging) but intentionally
/// does NOT implement `Deserialize`. The only constructor is [`ExecutedEvidence::run`],
/// which actually executes the command. This prevents forgery via JSON files.
#[derive(Debug, Clone, Serialize)]
pub struct ExecutedEvidence {
    /// The command that was executed (e.g., "cargo", "/bin/bash").
    command: String,
    /// Arguments passed to the command.
    args: Vec<String>,
    /// Process exit code (None if terminated by signal).
    exit_code: Option<i32>,
    /// SHA-256 hash of stdout as hex string.
    stdout_sha256: String,
    /// SHA-256 hash of stderr as hex string.
    stderr_sha256: String,
    /// Execution duration in milliseconds.
    duration_ms: u64,
    /// Unix timestamp (seconds since epoch) when execution started.
    ran_at: u64,
    /// Git commit SHA at execution time.
    git_sha: String,
    /// Host classification for capability gating.
    host_class: HostClass,
    /// Execution outcome classification.
    outcome: ExecutionOutcome,
}

/// Host capability classification for execution gating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostClass {
    /// Full capabilities: FUSE, root, all test prerequisites.
    Full,
    /// CI environment with limited capabilities (no FUSE mount).
    Ci,
    /// Local development without elevated privileges.
    LocalUnprivileged,
    /// Remote RCH worker with compilation capabilities.
    RchWorker,
    /// Unknown or unclassified host.
    Unknown,
}

/// Execution outcome distinguishing success, failure, and skip states.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionOutcome {
    /// Process ran and exited with code 0.
    Success,
    /// Process ran but exited with non-zero code.
    Failed { exit_code: i32 },
    /// Process was terminated by a signal.
    Signaled,
    /// Execution was skipped because the host lacks required capabilities.
    Skipped { reason: String },
    /// Execution failed to start (command not found, permission denied, etc.).
    LaunchFailed { error: String },
}

impl ExecutionOutcome {
    /// Whether this outcome represents a successful execution.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }

    /// Whether execution was skipped (host-incapable), distinct from failure.
    #[must_use]
    pub fn is_skipped(&self) -> bool {
        matches!(self, Self::Skipped { .. })
    }

    /// Whether execution ran but failed (non-zero exit or signal).
    #[must_use]
    pub fn is_failure(&self) -> bool {
        matches!(self, Self::Failed { .. } | Self::Signaled)
    }
}

impl ExecutedEvidence {
    /// Command that was executed.
    #[must_use]
    pub fn command(&self) -> &str {
        &self.command
    }

    /// Arguments passed to the command.
    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// Process exit code, if the process exited normally.
    #[must_use]
    pub const fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    /// SHA-256 hash of captured stdout.
    #[must_use]
    pub fn stdout_sha256(&self) -> &str {
        &self.stdout_sha256
    }

    /// SHA-256 hash of captured stderr.
    #[must_use]
    pub fn stderr_sha256(&self) -> &str {
        &self.stderr_sha256
    }

    /// Execution duration in milliseconds.
    #[must_use]
    pub const fn duration_ms(&self) -> u64 {
        self.duration_ms
    }

    /// Unix timestamp when execution started.
    #[must_use]
    pub const fn ran_at(&self) -> u64 {
        self.ran_at
    }

    /// Git commit SHA at execution time.
    #[must_use]
    pub fn git_sha(&self) -> &str {
        &self.git_sha
    }

    /// Host classification for capability gating.
    #[must_use]
    pub const fn host_class(&self) -> HostClass {
        self.host_class
    }

    /// Execution outcome classification.
    #[must_use]
    pub const fn outcome(&self) -> &ExecutionOutcome {
        &self.outcome
    }

    /// Execute a command and capture evidence.
    ///
    /// This is the ONLY way to construct `ExecutedEvidence`. The process is
    /// actually executed, and evidence is captured from the real execution.
    ///
    /// # Arguments
    /// * `command` - The command to execute.
    /// * `args` - Arguments to pass to the command.
    ///
    /// # Returns
    /// Evidence of the execution, including outcome and output hashes.
    #[must_use]
    pub fn run(command: &str, args: &[&str]) -> Self {
        Self::run_captured(command, args).0
    }

    fn run_captured(command: &str, args: &[&str]) -> (Self, Vec<u8>, Vec<u8>) {
        let git_sha = Self::current_git_sha();
        let host_class = Self::detect_host_class();
        let ran_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        info!(
            target: "ffs::harness::evidence",
            command,
            args = ?args,
            git_sha = %git_sha,
            host_class = ?host_class,
            "executing_for_evidence"
        );

        let start = Instant::now();
        let mut process = Command::new(command);
        if command == "rch" {
            process.env("RCH_REQUIRE_REMOTE", "1");
        }
        let result = process
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();

        let duration = start.elapsed();
        let duration_ms = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);

        match result {
            Ok(output) => (
                Self::from_output(
                    command,
                    args,
                    &output,
                    duration_ms,
                    ran_at,
                    git_sha,
                    host_class,
                ),
                output.stdout,
                output.stderr,
            ),
            Err(e) => {
                warn!(
                    target: "ffs::harness::evidence",
                    command,
                    error = %e,
                    "execution_launch_failed"
                );
                (
                    Self {
                        command: command.to_string(),
                        args: args.iter().copied().map(String::from).collect(),
                        exit_code: None,
                        stdout_sha256: Self::hash_bytes(&[]),
                        stderr_sha256: Self::hash_bytes(&[]),
                        duration_ms,
                        ran_at,
                        git_sha,
                        host_class,
                        outcome: ExecutionOutcome::LaunchFailed {
                            error: e.to_string(),
                        },
                    },
                    Vec::new(),
                    Vec::new(),
                )
            }
        }
    }

    /// Execute with a capability prerequisite check.
    ///
    /// If `prerequisite` returns `Err(reason)`, execution is skipped and the
    /// evidence records `Skipped { reason }`. This distinguishes host-incapable
    /// skip from ran-and-failed.
    #[must_use]
    pub fn run_with_prerequisite<F>(command: &str, args: &[&str], prerequisite: F) -> Self
    where
        F: FnOnce() -> Result<(), String>,
    {
        if let Err(reason) = prerequisite() {
            let git_sha = Self::current_git_sha();
            let host_class = Self::detect_host_class();
            let ran_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());

            info!(
                target: "ffs::harness::evidence",
                command,
                args = ?args,
                skip_reason = %reason,
                "execution_skipped_prerequisite"
            );

            return Self {
                command: command.to_string(),
                args: args.iter().copied().map(String::from).collect(),
                exit_code: None,
                stdout_sha256: Self::hash_bytes(&[]),
                stderr_sha256: Self::hash_bytes(&[]),
                duration_ms: 0,
                ran_at,
                git_sha,
                host_class,
                outcome: ExecutionOutcome::Skipped { reason },
            };
        }

        Self::run(command, args)
    }

    /// Check if this evidence is fresh relative to current git state.
    ///
    /// Evidence is fresh if:
    /// 1. `git_sha` matches the current HEAD
    /// 2. `ran_at` is within `max_age` of now
    #[must_use]
    pub fn is_fresh(&self, max_age: Duration) -> bool {
        let current_sha = Self::current_git_sha();
        if self.git_sha != current_sha {
            debug!(
                target: "ffs::harness::evidence",
                evidence_sha = %self.git_sha,
                current_sha = %current_sha,
                "evidence_stale_git_mismatch"
            );
            return false;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        let age_secs = now.saturating_sub(self.ran_at);
        let fresh = self.ran_at <= now && age_secs <= max_age.as_secs();

        if !fresh {
            debug!(
                target: "ffs::harness::evidence",
                age_secs,
                max_age_secs = max_age.as_secs(),
                "evidence_stale_age"
            );
        }

        fresh
    }

    /// Check freshness with a custom git SHA (for testing or pinned comparisons).
    #[must_use]
    pub fn is_fresh_against(&self, expected_sha: &str, max_age: Duration) -> bool {
        if self.git_sha != expected_sha {
            return false;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        self.ran_at <= now && now - self.ran_at <= max_age.as_secs()
    }

    fn from_output(
        command: &str,
        args: &[&str],
        output: &Output,
        duration_ms: u64,
        ran_at: u64,
        git_sha: String,
        host_class: HostClass,
    ) -> Self {
        let exit_code = output.status.code();
        let stdout_sha256 = Self::hash_bytes(&output.stdout);
        let stderr_sha256 = Self::hash_bytes(&output.stderr);

        let outcome = match output.status.code() {
            Some(0) => ExecutionOutcome::Success,
            Some(code) => ExecutionOutcome::Failed { exit_code: code },
            None => ExecutionOutcome::Signaled,
        };

        info!(
            target: "ffs::harness::evidence",
            command,
            exit_code = ?exit_code,
            duration_ms,
            outcome = ?outcome,
            stdout_bytes = output.stdout.len(),
            stderr_bytes = output.stderr.len(),
            "execution_completed"
        );

        Self {
            command: command.to_string(),
            args: args.iter().copied().map(String::from).collect(),
            exit_code,
            stdout_sha256,
            stderr_sha256,
            duration_ms,
            ran_at,
            git_sha,
            host_class,
            outcome,
        }
    }

    fn hash_bytes(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    fn current_git_sha() -> String {
        Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    String::from_utf8(o.stdout)
                        .ok()
                        .map(|s| s.trim().to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "unknown".to_string())
    }

    fn detect_host_class() -> HostClass {
        if std::env::var("CI").is_ok() || std::env::var("GITHUB_ACTIONS").is_ok() {
            return HostClass::Ci;
        }

        if std::env::var("RCH_WORKER").is_ok() {
            return HostClass::RchWorker;
        }

        if std::path::Path::new("/dev/fuse").exists() {
            if Self::is_root() {
                return HostClass::Full;
            }
            return HostClass::LocalUnprivileged;
        }

        HostClass::Unknown
    }

    fn is_root() -> bool {
        Command::new("id")
            .args(["-u"])
            .output()
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    String::from_utf8(o.stdout).ok().map(|s| s.trim() == "0")
                } else {
                    None
                }
            })
            .unwrap_or(false)
    }
}

/// Source identity for a local execution. Missing Git metadata is an error, not
/// an identity shared by unrelated builds. The digest includes staged and
/// unstaged changes plus untracked source inputs; tracker bookkeeping is excluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceIdentity {
    pub git_sha: String,
    pub dirty_source_sha256: String,
}

impl SourceIdentity {
    pub fn capture() -> Result<Self, String> {
        Self::capture_at(&std::env::current_dir().map_err(|e| e.to_string())?)
    }

    fn capture_at(directory: &std::path::Path) -> Result<Self, String> {
        let revision = Command::new("git")
            .current_dir(directory)
            .args(["rev-parse", "HEAD"])
            .output()
            .map_err(|e| e.to_string())?;
        if !revision.status.success() {
            return Err("cannot bind execution to a Git revision".to_owned());
        }
        let git_sha = String::from_utf8(revision.stdout).map_err(|e| e.to_string())?;
        let git_sha = git_sha.trim().to_owned();
        let root = Command::new("git")
            .current_dir(directory)
            .args(["rev-parse", "--show-toplevel"])
            .output()
            .map_err(|e| e.to_string())?;
        if !root.status.success() {
            return Err("cannot locate source root".to_owned());
        }
        let root = String::from_utf8(root.stdout).map_err(|e| e.to_string())?;
        let root = std::path::Path::new(root.trim());
        let diff = Command::new("git")
            .current_dir(root)
            .args([
                "diff",
                "--binary",
                "--no-ext-diff",
                "--no-textconv",
                "HEAD",
                "--",
                ".",
                ":(exclude).beads",
            ])
            .output()
            .map_err(|e| e.to_string())?;
        let untracked = Command::new("git")
            .current_dir(root)
            .args(["ls-files", "--others", "--exclude-standard", "-z"])
            .output()
            .map_err(|e| e.to_string())?;
        if !diff.status.success() || !untracked.status.success() {
            return Err("cannot enumerate dirty source inputs".to_owned());
        }
        let mut hash = Sha256::new();
        hash.update(&diff.stdout);
        for path in untracked
            .stdout
            .split(|&b| b == 0)
            .filter(|p| !p.is_empty())
        {
            let path = std::str::from_utf8(path).map_err(|e| e.to_string())?;
            if path.starts_with(".beads/") || path.starts_with(".rch-") {
                continue;
            }
            hash.update(path.as_bytes());
            hash.update([0]);
            let absolute = root.join(path);
            let metadata = std::fs::symlink_metadata(&absolute).map_err(|e| e.to_string())?;
            let bytes = if metadata.is_symlink() {
                std::fs::read_link(&absolute)
                    .map_err(|e| e.to_string())?
                    .as_os_str()
                    .as_encoded_bytes()
                    .to_vec()
            } else {
                std::fs::read(&absolute).map_err(|e| e.to_string())?
            };
            hash.update(bytes.len().to_le_bytes());
            hash.update(bytes);
        }
        Ok(Self {
            git_sha,
            dirty_source_sha256: hex::encode(hash.finalize()),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TestOutcome {
    Passed,
    Failed,
    Skipped,
}

/// Counts and exact test names read from one libtest JSON stream. There must be
/// one start, one completion and matching per-test events for the selected suite.
#[derive(Debug, Clone, Default, Serialize)]
pub struct TestResults {
    pub selected: u64,
    pub executed: u64,
    pub passed: u64,
    pub failed: u64,
    pub skipped: u64,
    pub filtered_out: u64,
    pub tests: std::collections::BTreeMap<String, TestOutcome>,
    pub error: Option<String>,
}

impl TestResults {
    // RCH reserves stdout for its own protocol and forwards both worker streams
    // to stderr. Cargo/RCH diagnostics may surround the libtest JSON stream.
    // Keep the event parser strict: never select only successful test events.
    fn parse_rch(stderr: &[u8]) -> Self {
        let Ok(transcript) = std::str::from_utf8(stderr) else {
            return Self {
                error: Some("RCH transcript is not UTF-8".to_owned()),
                ..Self::default()
            };
        };
        let mut events = String::new();
        let mut in_suite = false;
        for line in transcript.lines() {
            let line = line.trim();
            if line.starts_with('{') {
                if let Ok(event) = serde_json::from_str::<serde_json::Value>(line)
                    && event["type"] == "suite"
                {
                    in_suite = event["event"] == "started";
                }
                events.push_str(line);
                events.push('\n');
            } else if in_suite && !line.is_empty() && !line.starts_with("[RCH]") {
                return Self {
                    error: Some("unexpected output inside RCH libtest stream".to_owned()),
                    ..Self::default()
                };
            }
        }
        Self::parse(events.as_bytes())
    }

    fn parse(stdout: &[u8]) -> Self {
        let mut results = Self::default();
        if let Err(error) = results.read_stream(stdout) {
            results.error = Some(error);
        }
        results
    }

    fn read_stream(&mut self, stdout: &[u8]) -> Result<(), String> {
        let mut started = false;
        let mut finished = false;
        let mut pending = std::collections::BTreeSet::new();
        let mut reported_ignored = 0;
        let mut soft_skipped = 0;
        for line in std::str::from_utf8(stdout)
            .map_err(|e| e.to_string())?
            .lines()
        {
            if line.trim().is_empty() {
                continue;
            }
            let event: serde_json::Value =
                serde_json::from_str(line).map_err(|e| format!("invalid libtest JSON: {e}"))?;
            let count = |name: &str| {
                event[name]
                    .as_u64()
                    .ok_or_else(|| format!("libtest event lacks {name}"))
            };
            match (event["type"].as_str(), event["event"].as_str()) {
                (Some("suite"), Some("started")) if !started => {
                    started = true;
                    self.selected = count("test_count")?;
                }
                (Some("test"), Some(kind)) if started && !finished => {
                    let name = event["name"].as_str().ok_or("test event lacks name")?;
                    if kind == "started" {
                        if self.tests.contains_key(name) || !pending.insert(name.to_owned()) {
                            return Err(format!("duplicate test start: {name}"));
                        }
                        continue;
                    }
                    if self.tests.contains_key(name) {
                        return Err(format!("duplicate test result: {name}"));
                    }
                    let outcome = match kind {
                        "ok" | "failed" if pending.remove(name) => {
                            self.executed += 1;
                            if kind == "failed" {
                                self.failed += 1;
                                TestOutcome::Failed
                            } else if event["stdout"].as_str().is_some_and(has_skip_marker) {
                                soft_skipped += 1;
                                self.skipped += 1;
                                TestOutcome::Skipped
                            } else {
                                self.passed += 1;
                                TestOutcome::Passed
                            }
                        }
                        "ignored" => {
                            pending.remove(name);
                            reported_ignored += 1;
                            self.skipped += 1;
                            TestOutcome::Skipped
                        }
                        _ => return Err(format!("unexpected test event {kind}: {name}")),
                    };
                    self.tests.insert(name.to_owned(), outcome);
                }
                (Some("suite"), Some("ok" | "failed")) if started && !finished => {
                    finished = true;
                    self.filtered_out = count("filtered_out")?;
                    if count("passed")? != self.passed + soft_skipped
                        || count("failed")? != self.failed
                        || count("ignored")? != reported_ignored
                        || self.selected != self.executed + reported_ignored
                        || !pending.is_empty()
                    {
                        return Err("libtest summary disagrees with named test events".to_owned());
                    }
                    if event["event"] == "ok" && self.failed != 0 {
                        return Err("successful suite contains failing tests".to_owned());
                    }
                }
                _ => return Err("unexpected or repeated libtest suite event".to_owned()),
            }
        }
        if !finished || self.selected == 0 || self.executed == 0 {
            return Err("no complete, nonempty test execution".to_owned());
        }
        Ok(())
    }
}

fn has_skip_marker(output: &str) -> bool {
    output.lines().any(|line| {
        let line = line.trim().to_ascii_uppercase();
        line.starts_with("SKIP")
            || line.starts_with("[SKIP]")
            || (line.starts_with("SCENARIO_RESULT|")
                && line.split('|').any(|field| field == "OUTCOME=SKIP"))
    })
}

/// Test evidence is produced in memory by the executor, never deserialized from
/// a report. Serialized output is an audit artifact, not an input granting credit.
#[derive(Debug, Clone, Serialize)]
pub struct TestRunEvidence {
    execution: ExecutedEvidence,
    source: Option<SourceIdentity>,
    results: TestResults,
    binding_error: Option<String>,
    remote_source_receipt: Option<serde_json::Value>,
    build_environment: std::collections::BTreeMap<String, Option<String>>,
}

impl TestRunEvidence {
    /// Execute exactly one libtest target with `-Z unstable-options --format=json
    /// --show-output`. Callers choose the execution mechanism (RCH or local CI).
    #[must_use]
    pub fn run(command: &str, args: &[&str]) -> Self {
        let before = SourceIdentity::capture();
        let (execution, stdout, stderr) = ExecutedEvidence::run_captured(command, args);
        let results = if command == "rch" {
            TestResults::parse_rch(&stderr)
        } else {
            TestResults::parse(&stdout)
        };
        // Keep compiler errors, RCH diagnostics and test stderr visible.
        eprint!("{}", String::from_utf8_lossy(&stderr));
        let after = SourceIdentity::capture();
        let mut binding_error = match (&before, &after) {
            (Ok(before), Ok(after)) if before == after => None,
            (Ok(_), Ok(_)) => Some("source changed during test execution".to_owned()),
            (Err(error), _) | (_, Err(error)) => Some(error.clone()),
        };
        let remote_source_receipt = if command == "rch" {
            match read_remote_source_receipt(&stderr, args) {
                Ok(receipt) => Some(receipt),
                Err(error) => {
                    binding_error = Some(error);
                    None
                }
            }
        } else {
            None
        };
        Self {
            execution,
            source: before.ok(),
            results,
            binding_error,
            remote_source_receipt,
            build_environment: [
                "RUSTUP_TOOLCHAIN",
                "RUSTFLAGS",
                "CARGO_ENCODED_RUSTFLAGS",
                "CARGO_BUILD_TARGET",
                "RCH_WORKER",
                "RCH_ENV_ALLOWLIST",
            ]
            .into_iter()
            .map(|key| (key.to_owned(), std::env::var(key).ok()))
            .collect(),
        }
    }

    #[must_use]
    pub fn results(&self) -> &TestResults {
        &self.results
    }

    /// All selected tests must actually pass. Ignored tests and soft skips do
    /// not satisfy this gate, even when Cargo itself exits successfully.
    pub fn require_pass(&self, source: &SourceIdentity) -> Result<(), String> {
        if let Some(error) = self.binding_error.as_ref().or(self.results.error.as_ref()) {
            return Err(error.clone());
        }
        if self.source.as_ref() != Some(source)
            || !self
                .execution
                .is_fresh_against(&source.git_sha, Duration::from_secs(3600))
        {
            return Err("test evidence is stale or belongs to different source bytes".to_owned());
        }
        if !self.execution.outcome().is_success()
            || self.results.failed != 0
            || self.results.skipped != 0
            || self.results.passed == 0
        {
            return Err(format!(
                "test execution did not pass: {:?}; passed={} failed={} skipped={}",
                self.execution.outcome(),
                self.results.passed,
                self.results.failed,
                self.results.skipped
            ));
        }
        Ok(())
    }
}

// RCH proves the transferred Cargo source closure before and after execution.
// Retain its receipt from this process's stderr; never accept a saved receipt.
fn read_remote_source_receipt(stderr: &[u8], args: &[&str]) -> Result<serde_json::Value, String> {
    if !args.contains(&"--source-content-receipt") {
        return Err("remote test execution lacks source-content verification".to_owned());
    }
    let separator = args
        .iter()
        .position(|&arg| arg == "--")
        .ok_or("remote test execution lacks a command separator")?;
    let command = args[separator + 1..].join(" ");
    let expected_command = ExecutedEvidence::hash_bytes(command.as_bytes());
    let stderr = std::str::from_utf8(stderr).map_err(|e| e.to_string())?;
    let mut receipts = stderr
        .lines()
        .filter_map(|line| line.strip_prefix("[RCH] source content receipt: "));
    let receipt: serde_json::Value = serde_json::from_str(
        receipts
            .next()
            .ok_or("remote source-content receipt missing")?,
    )
    .map_err(|e| e.to_string())?;
    if receipts.next().is_some()
        || receipt["schema"] != "rch.source_content_receipt.v1"
        || receipt["command_sha256"] != expected_command
        || receipt["command_exit_code"] != 0
        || receipt["root_count"].as_u64().unwrap_or(0) == 0
        || receipt["roots"].as_array().map(Vec::len)
            != receipt["root_count"]
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
    {
        return Err(
            "remote source-content receipt does not bind this successful command".to_owned(),
        );
    }
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_receipt_rejects_missing_failed_duplicate_or_wrong_commands() {
        // Protocol fixture only; the real RCH integration supplies source proof.
        let args = ["exec", "--source-content-receipt", "--", "cargo", "test"];
        let receipt = serde_json::json!({
            "schema": "rch.source_content_receipt.v1",
            "command_sha256": ExecutedEvidence::hash_bytes(b"cargo test"),
            "command_exit_code": 0,
            "root_count": 1,
            "roots": [{"content_root": "protocol fixture"}]
        });
        let line = format!("[RCH] source content receipt: {receipt}\n");
        assert!(read_remote_source_receipt(line.as_bytes(), &args).is_ok());
        assert!(read_remote_source_receipt(b"", &args).is_err());
        assert!(read_remote_source_receipt(line.repeat(2).as_bytes(), &args).is_err());
        assert!(read_remote_source_receipt(line.as_bytes(), &["exec", "--", "cargo"]).is_err());
        for (field, value) in [
            ("command_sha256", serde_json::json!("another command")),
            ("command_exit_code", serde_json::json!(101)),
            ("root_count", serde_json::json!(0)),
            ("root_count", serde_json::json!(2)),
        ] {
            let mut corrupted = receipt.clone();
            corrupted[field] = value;
            let line = format!("[RCH] source content receipt: {corrupted}\n");
            assert!(read_remote_source_receipt(line.as_bytes(), &args).is_err());
        }
    }

    // A child-only protocol fixture: these outcomes exercise the real libtest
    // process, and are never capability evidence for filesystem behavior.
    #[test]
    fn test_evidence_child_probe() {
        match std::env::var("FFS_TEST_EVIDENCE_CHILD").as_deref() {
            Ok("fail") => panic!("planted child failure"),
            Ok("skip") => eprintln!("SKIPPED: planted missing prerequisite"),
            Ok("scenario-skip") => {
                eprintln!("SCENARIO_RESULT|scenario_id=child|outcome=SKIP|detail=missing tool");
            }
            _ => assert_ne!(
                ExecutedEvidence::hash_bytes(b"a"),
                ExecutedEvidence::hash_bytes(b"b")
            ),
        }
    }

    // Intentionally ignored protocol fixture: the parent verifies that libtest
    // reports an ignored result instead of crediting it as an executed test.
    #[test]
    #[ignore = "child-only evidence protocol probe"]
    fn ignored_evidence_child_probe() {
        // An explicit --include-ignored run should remain valid. The parent
        // checks libtest's ignored counts, not a planted failure in this body.
        test_evidence_child_probe();
    }

    fn child_test_evidence(case: &str, name: &str) -> TestRunEvidence {
        let executable = std::env::current_exe().unwrap();
        TestRunEvidence::run(
            "env",
            &[
                &format!("FFS_TEST_EVIDENCE_CHILD={case}"),
                executable.to_str().unwrap(),
                "--exact",
                name,
                "-Z",
                "unstable-options",
                "--format=json",
                "--show-output",
            ],
        )
    }

    #[test]
    fn test_evidence_requires_real_nonempty_passing_tests() {
        let name = "executed_evidence::tests::test_evidence_child_probe";
        let source = SourceIdentity::capture().unwrap();
        let passed = child_test_evidence("pass", name);
        assert_eq!(passed.results.selected, 1);
        assert_eq!(passed.results.executed, 1);
        assert_eq!(passed.results.tests.get(name), Some(&TestOutcome::Passed));
        assert_eq!(passed.require_pass(&source), Ok(()));

        let failed = child_test_evidence("fail", name);
        assert_eq!(failed.results.failed, 1);
        assert!(failed.require_pass(&source).is_err());
        for case in ["skip", "scenario-skip"] {
            let skipped = child_test_evidence(case, name);
            assert_eq!(skipped.results.skipped, 1);
            assert_eq!(skipped.results.passed, 0);
            assert!(skipped.require_pass(&source).is_err());
        }
        let empty = child_test_evidence("pass", "nonexistent_exact_test");
        assert_eq!(empty.execution.exit_code(), Some(0));
        assert_eq!(empty.results.selected, 0);
        assert!(empty.require_pass(&source).is_err());

        let ignored = child_test_evidence(
            "pass",
            "executed_evidence::tests::ignored_evidence_child_probe",
        );
        assert_eq!(ignored.execution.exit_code(), Some(0));
        assert_eq!(ignored.results.selected, 1);
        assert_eq!(ignored.results.executed, 0);
        assert_eq!(ignored.results.skipped, 1);
        assert!(ignored.require_pass(&source).is_err());

        let mut other_source = source.clone();
        other_source.dirty_source_sha256.push('0');
        assert!(passed.require_pass(&other_source).is_err());
        let mut stale = passed;
        stale.execution.ran_at = 0;
        assert!(stale.require_pass(&source).is_err());
        stale.execution.ran_at = u64::MAX;
        assert!(stale.require_pass(&source).is_err());
    }

    #[test]
    fn test_evidence_reads_rch_stderr_without_discarding_bad_events() {
        let executable = std::env::current_exe().unwrap();
        let output = Command::new(executable)
            .args([
                "--exact",
                "executed_evidence::tests::test_evidence_child_probe",
                "-Z",
                "unstable-options",
                "--format=json",
                "--show-output",
            ])
            .output()
            .unwrap();
        assert!(output.status.success());
        let events = String::from_utf8(output.stdout).unwrap();
        let transcript = format!(
            "[RCH] remote worker\n    Finished test profile\n{events}[RCH] remote worker completed\n"
        );
        let results = TestResults::parse_rch(transcript.as_bytes());
        assert!(results.error.is_none(), "{:?}", results.error);
        assert_eq!(results.selected, 1);
        assert_eq!(results.executed, 1);
        assert_eq!(results.passed, 1);
        assert!(TestResults::parse(b"").error.is_some());

        for corrupt in [
            format!("{transcript}{events}"),
            transcript.replace("\"passed\": 1", "\"passed\": 2"),
            format!("{transcript}{{broken JSON\n"),
            events.lines().take(2).collect::<Vec<_>>().join("\n"),
            events.replacen('\n', "\nunexpected output\n", 1),
            "[RCH] no test output\n".to_owned(),
        ] {
            assert!(
                TestResults::parse_rch(corrupt.as_bytes()).error.is_some(),
                "accepted corrupt RCH transcript: {corrupt}"
            );
        }
    }

    #[test]
    fn test_evidence_rejects_malformed_duplicate_and_incomplete_streams() {
        let valid = concat!(
            "{\"type\":\"suite\",\"event\":\"started\",\"test_count\":1}\n",
            "{\"type\":\"test\",\"event\":\"started\",\"name\":\"real_test\"}\n",
            "{\"type\":\"test\",\"event\":\"ok\",\"name\":\"real_test\"}\n",
            "{\"type\":\"suite\",\"event\":\"ok\",\"passed\":1,\"failed\":0,\"ignored\":0,\"filtered_out\":0}\n",
        );
        assert!(TestResults::parse(valid.as_bytes()).error.is_none());
        for corrupt in [
            valid.replace("\"passed\":1", "\"passed\":2"),
            valid.replace("\"test_count\":1", "\"test_count\":2"),
            valid.lines().take(3).collect::<Vec<_>>().join("\n"),
            format!("{valid}{valid}"),
            format!("{valid}unexpected output"),
            valid.replace(
                "\"event\":\"started\",\"name\"",
                "\"event\":\"ok\",\"name\"",
            ),
        ] {
            assert!(
                TestResults::parse(corrupt.as_bytes()).error.is_some(),
                "{corrupt}"
            );
        }
    }

    #[test]
    fn source_identity_tracks_real_dirty_bytes_from_any_workspace_directory() {
        let repo = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| {
            let output = Command::new("git")
                .current_dir(repo.path())
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        };
        git(&["init", "-b", "main"]);
        std::fs::create_dir(repo.path().join("src")).unwrap();
        let input = repo.path().join("src/input.txt");
        std::fs::write(&input, b"original").unwrap();
        git(&["add", "src/input.txt"]);
        git(&[
            "-c",
            "user.name=Evidence Test",
            "-c",
            "user.email=evidence@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            "fixture",
        ]);
        let clean = SourceIdentity::capture_at(repo.path()).unwrap();
        // A display-only text converter must not hide changes from the digest.
        std::fs::write(
            repo.path().join(".git/info/attributes"),
            "src/input.txt diff=hide\n",
        )
        .unwrap();
        git(&["config", "diff.hide.textconv", "true"]);
        assert_eq!(
            clean,
            SourceIdentity::capture_at(&repo.path().join("src")).unwrap()
        );
        std::fs::write(&input, b"changed").unwrap();
        let changed = SourceIdentity::capture_at(repo.path()).unwrap();
        assert_eq!(clean.git_sha, changed.git_sha);
        assert_ne!(clean.dirty_source_sha256, changed.dirty_source_sha256);
        assert_eq!(
            changed,
            SourceIdentity::capture_at(&repo.path().join("src")).unwrap()
        );
        std::fs::write(&input, b"original").unwrap();
        assert_eq!(clean, SourceIdentity::capture_at(repo.path()).unwrap());
        std::fs::write(repo.path().join("new-input.txt"), b"new").unwrap();
        let added = SourceIdentity::capture_at(repo.path()).unwrap();
        assert_ne!(clean.dirty_source_sha256, added.dirty_source_sha256);
        std::fs::write(repo.path().join("new-input.txt"), b"edited").unwrap();
        assert_ne!(added, SourceIdentity::capture_at(repo.path()).unwrap());
    }

    #[test]
    fn run_captures_successful_execution() {
        let evidence = ExecutedEvidence::run("echo", &["hello"]);

        assert_eq!(evidence.command, "echo");
        assert_eq!(evidence.args, vec!["hello"]);
        assert_eq!(evidence.exit_code, Some(0));
        assert!(evidence.outcome.is_success());
        assert!(!evidence.outcome.is_skipped());
        assert!(!evidence.outcome.is_failure());
        assert!(evidence.duration_ms < 5000);
        assert_ne!(evidence.stdout_sha256, "");
        assert_ne!(evidence.git_sha, "");
    }

    #[test]
    fn run_captures_failed_execution() {
        let evidence = ExecutedEvidence::run("false", &[]);

        assert_eq!(evidence.command, "false");
        assert_eq!(evidence.exit_code, Some(1));
        assert!(!evidence.outcome.is_success());
        assert!(evidence.outcome.is_failure());
        assert!(!evidence.outcome.is_skipped());
    }

    #[test]
    fn run_captures_launch_failure() {
        let evidence = ExecutedEvidence::run("nonexistent_command_xyz_123", &[]);

        assert!(matches!(
            evidence.outcome,
            ExecutionOutcome::LaunchFailed { .. }
        ));
        assert!(!evidence.outcome.is_success());
        assert!(!evidence.outcome.is_skipped());
    }

    #[test]
    fn run_with_prerequisite_skips_on_failure() {
        let evidence = ExecutedEvidence::run_with_prerequisite("echo", &["should not run"], || {
            Err("missing FUSE capability".to_string())
        });

        assert!(evidence.outcome().is_skipped());
        assert!(!evidence.outcome().is_success());
        assert!(!evidence.outcome().is_failure());
        assert_eq!(evidence.duration_ms(), 0);
        assert!(matches!(
            evidence.outcome(),
            ExecutionOutcome::Skipped { reason } if reason == "missing FUSE capability"
        ));
    }

    #[test]
    fn run_with_prerequisite_executes_on_success() {
        let evidence = ExecutedEvidence::run_with_prerequisite("echo", &["runs"], || Ok(()));

        assert!(evidence.outcome.is_success());
        assert!(!evidence.outcome.is_skipped());
    }

    #[test]
    fn is_fresh_requires_matching_git_sha() {
        let evidence = ExecutedEvidence::run("true", &[]);

        assert!(evidence.is_fresh(Duration::from_secs(60)));
        assert!(!evidence.is_fresh_against("fake_sha_12345", Duration::from_secs(60)));
    }

    #[test]
    fn is_fresh_respects_age_window() {
        let mut evidence = ExecutedEvidence::run("true", &[]);

        evidence.ran_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 120;

        assert!(!evidence.is_fresh(Duration::from_secs(60)));
        assert!(evidence.is_fresh(Duration::from_secs(300)));
    }

    #[test]
    fn outcome_classification_is_exhaustive() {
        assert!(ExecutionOutcome::Success.is_success());
        assert!(!ExecutionOutcome::Success.is_failure());
        assert!(!ExecutionOutcome::Success.is_skipped());

        assert!(!ExecutionOutcome::Failed { exit_code: 1 }.is_success());
        assert!(ExecutionOutcome::Failed { exit_code: 1 }.is_failure());
        assert!(!ExecutionOutcome::Failed { exit_code: 1 }.is_skipped());

        assert!(!ExecutionOutcome::Signaled.is_success());
        assert!(ExecutionOutcome::Signaled.is_failure());
        assert!(!ExecutionOutcome::Signaled.is_skipped());

        let skipped = ExecutionOutcome::Skipped {
            reason: "test".into(),
        };
        assert!(!skipped.is_success());
        assert!(!skipped.is_failure());
        assert!(skipped.is_skipped());

        let launch_failed = ExecutionOutcome::LaunchFailed {
            error: "test".into(),
        };
        assert!(!launch_failed.is_success());
        assert!(!launch_failed.is_failure());
        assert!(!launch_failed.is_skipped());
    }

    #[test]
    fn evidence_is_serializable() {
        let evidence = ExecutedEvidence::run("echo", &["test"]);
        let json = serde_json::to_string(&evidence).unwrap();

        assert!(json.contains("\"command\":\"echo\""));
        assert!(json.contains("\"outcome\":"));
        assert!(json.contains("\"git_sha\":"));
    }

    #[test]
    fn different_outputs_produce_different_hashes() {
        let e1 = ExecutedEvidence::run("echo", &["hello"]);
        let e2 = ExecutedEvidence::run("echo", &["world"]);

        assert_ne!(e1.stdout_sha256, e2.stdout_sha256);
    }
}
