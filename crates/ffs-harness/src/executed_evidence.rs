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
        let result = Command::new(command)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();

        let duration = start.elapsed();
        let duration_ms = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);

        match result {
            Ok(output) => Self::from_output(
                command,
                args,
                &output,
                duration_ms,
                ran_at,
                git_sha,
                host_class,
            ),
            Err(e) => {
                warn!(
                    target: "ffs::harness::evidence",
                    command,
                    error = %e,
                    "execution_launch_failed"
                );
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
                }
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
        let fresh = age_secs <= max_age.as_secs();

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

        now.saturating_sub(self.ran_at) <= max_age.as_secs()
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

#[cfg(test)]
mod tests {
    use super::*;

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
