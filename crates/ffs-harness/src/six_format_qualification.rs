#![forbid(unsafe_code)]
//! Source-bound six-format native qualification, persistence-prefix partial-order
//! cut modeling, streaming error-artifact preservation, and workflow-cost receipts
//! (`bd-mizd2`).
//!
//! This module provides the conformance oracle and non-forgeable receipt validator
//! across all seven normative filesystem profiles:
//! - `ext4` (journaled JBD2 + metadata_csum)
//! - `btrfs` (COW B-tree + tree-log + subvolumes)
//! - `fat16` (LFN + OEM code page)
//! - `fat32` (LFN + FSInfo + backup boot sector)
//! - `ntfs_3_1` (MFT USA fixups + ADS + `$LogFile` ARIES)
//! - `zfs_v5000_single` (SPA v5000 single-vdev + ZPL + ZIL + snapshots)
//! - `zfs_v5000_mirror` (SPA v5000 2-way mirror + degraded read + TXG sync)

use crate::artifact_manifest::CleanupStatus;
use crate::executed_evidence::{ExecutedEvidence, SourceIdentity, TestResults};
use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_error::{FfsError, Result as FfsResult};
use ffs_types::ByteOffset;
use parking_lot::Mutex;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Normative filesystem profiles covered by the six-format qualification matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationProfileId {
    Ext4,
    Btrfs,
    Fat16,
    Fat32,
    Ntfs31,
    ZfsV5000Single,
    ZfsV5000Mirror,
}

impl QualificationProfileId {
    pub const ALL: [Self; 7] = [
        Self::Ext4,
        Self::Btrfs,
        Self::Fat16,
        Self::Fat32,
        Self::Ntfs31,
        Self::ZfsV5000Single,
        Self::ZfsV5000Mirror,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ext4 => "ext4",
            Self::Btrfs => "btrfs",
            Self::Fat16 => "fat16",
            Self::Fat32 => "fat32",
            Self::Ntfs31 => "ntfs_3_1",
            Self::ZfsV5000Single => "zfs_v5000_single",
            Self::ZfsV5000Mirror => "zfs_v5000_mirror",
        }
    }

    #[must_use]
    pub const fn required_oracles(self) -> &'static [&'static str] {
        match self {
            Self::Ext4 => &["mkfs.ext4", "debugfs", "dumpe2fs", "e2fsck"],
            Self::Btrfs => &["mkfs.btrfs", "btrfs"],
            Self::Fat16 | Self::Fat32 => &["mkfs.fat", "fsck.fat", "mmd", "mcopy", "mdir"],
            Self::Ntfs31 => &[
                "mkntfs", "ntfscp", "ntfscat", "ntfsls", "ntfsinfo", "ntfsfix",
            ],
            Self::ZfsV5000Single | Self::ZfsV5000Mirror => &["zpool", "zfs", "zdb"],
        }
    }

    #[must_use]
    pub const fn default_policy(self) -> ProfilePolicySpec {
        match self {
            Self::Ext4 => ProfilePolicySpec {
                revision: "rev1_dynamic",
                features: "ext_attr,sparse_super,filetype,extent,64bit,metadata_csum,has_journal",
                geometry: "4096B_block_256B_inode",
                topology: "single_member_internal_jbd2",
                view_selection: "default_root",
                recovery_mode: "jbd2_simulate_ro_apply_rw",
                write_authority: "explicit_rw_jbd2_committed",
                protection_policy: "FFSRQSM3_trusted_root_ext4_commit_seq",
            },
            Self::Btrfs => ProfilePolicySpec {
                revision: "superblock_v1_csum_crc32c",
                features: "extref,skinny_metadata,no_holes,tree_log",
                geometry: "4096B_sectorsize_16384B_nodesize",
                topology: "single_device_cow",
                view_selection: "fs_tree_and_named_subvolume",
                recovery_mode: "ro_overlay_tree_log_rw_generation_commit",
                write_authority: "explicit_rw_cow_transaction",
                protection_policy: "FFSRQSM3_trusted_root_btrfs_generation",
            },
            Self::Fat16 => ProfilePolicySpec {
                revision: "fat16_vfat_lfn",
                features: "vfat_lfn,oem_cp437_ascii",
                geometry: "512B_sector_2_fats",
                topology: "single_volume",
                view_selection: "root_directory",
                recovery_mode: "dual_fat_mirror_ordered_write",
                write_authority: "explicit_rw_ordered_cluster_fat_dirent",
                protection_policy: "FFSRQSM3_trusted_root_fat_write_state",
            },
            Self::Fat32 => ProfilePolicySpec {
                revision: "fat32_fsinfo_backup_boot",
                features: "vfat_lfn,fsinfo,backup_bpb",
                geometry: "512B_sector_2_fats_cluster_root",
                topology: "single_volume",
                view_selection: "root_cluster_chain",
                recovery_mode: "fsinfo_dual_fat_ordered_write",
                write_authority: "explicit_rw_ordered_cluster_fat_dirent",
                protection_policy: "FFSRQSM3_trusted_root_fat_write_state",
            },
            Self::Ntfs31 => ProfilePolicySpec {
                revision: "ntfs_3_1",
                features: "usa_fixups,ads_streams,indx_b_tree,logfile_aries",
                geometry: "512B_sector_4096B_cluster_1024B_mft",
                topology: "single_volume",
                view_selection: "default_data_and_named_ads",
                recovery_mode: "volatile_ro_logfile_persistent_rw_aries",
                write_authority: "explicit_rw_ntfs_transaction_engine",
                protection_policy: "FFSRQSM3_trusted_root_ntfs_logfile_lsn",
            },
            Self::ZfsV5000Single => ProfilePolicySpec {
                revision: "spa_v5000_zpl_v5",
                features: "lzjb_lz4,sha256_fletcher4,zil,snapshots,sa_znode",
                geometry: "ashift_12_4096B_sector",
                topology: "single_leaf_vdev",
                view_selection: "root_dataset_child_dataset_and_snapshot",
                recovery_mode: "volatile_ro_zil_persistent_rw_txg",
                write_authority: "explicit_rw_txg_cow_uberblock_ring",
                protection_policy: "FFSRQSM3_trusted_root_zfs_uberblock_txg",
            },
            Self::ZfsV5000Mirror => ProfilePolicySpec {
                revision: "spa_v5000_zpl_v5",
                features: "mirror_2way,degraded_survivor_read,zil,snapshots,txg_sync",
                geometry: "ashift_12_4096B_sector_2_leaves",
                topology: "two_way_mirror_vdev",
                view_selection: "complete_mirror_and_degraded_survivor_candidate",
                recovery_mode: "volatile_ro_zil_persistent_rw_dual_leaf_txg",
                write_authority: "explicit_rw_txg_all_mirror_leaves",
                protection_policy: "FFSRQSM3_whole_set_2_member_zfs_txg",
            },
        }
    }
}

/// Explicit proof hierarchy separating in-memory models, offline native images,
/// live FUSE mounts, daemon `SIGKILL` crashes, and modeled device flush-prefix cuts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofRegime {
    Static,
    UnitStorageModel,
    NativeImage,
    LiveMountedFuse,
    ProcessSigkillCrash,
    ModeledDeviceFlushPrefixCut,
}

/// Normative policy dimensions recorded for each profile in the qualification matrix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProfilePolicySpec {
    pub revision: &'static str,
    pub features: &'static str,
    pub geometry: &'static str,
    pub topology: &'static str,
    pub view_selection: &'static str,
    pub recovery_mode: &'static str,
    pub write_authority: &'static str,
    pub protection_policy: &'static str,
}

/// Qualification verdict for a profile. Missing oracles/mounts produce `Unqualified`,
/// never silent `Qualified` credit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum QualificationVerdict {
    Qualified,
    Unqualified { missing_prerequisites: Vec<String> },
    Failed { reasons: Vec<String> },
}

impl QualificationVerdict {
    #[must_use]
    pub const fn is_qualified(&self) -> bool {
        matches!(self, Self::Qualified)
    }
}

/// Identity of an executed FrankenFS ELF binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BinaryArtifactIdentity {
    pub role: String,
    pub path: String,
    pub elf_sha256: String,
    pub byte_len: u64,
}

/// Identity and version of an external filesystem producer/checker oracle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OracleToolIdentity {
    pub name: String,
    pub required: bool,
    pub resolved_path: Option<String>,
    pub binary_sha256: Option<String>,
    pub version_line: Option<String>,
}

/// Source, toolchain, lockfile, ELF binary, and external oracle provenance bound to a run.
#[derive(Debug, Clone, Serialize)]
pub struct BuildProvenance {
    pub source: SourceIdentity,
    pub rustc_version_line: String,
    pub rustc_vv_sha256: String,
    pub cargo_lock_sha256: String,
    pub binaries: Vec<BinaryArtifactIdentity>,
    pub oracles: Vec<OracleToolIdentity>,
}

/// SHA-256 digests of one backing member image across every phase of interchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImageTransitionDigest {
    pub member_label: String,
    pub initial_sha256: String,
    pub post_ro_sha256: String,
    pub post_native_rw_sha256: Option<String>,
    pub post_protected_heal_sha256: Option<String>,
    pub post_external_rw_sha256: Option<String>,
}

/// Preserved partial stdout and stderr when a streaming command fails mid-stream or
/// fails post-stream validation (e.g., on the final `N`-th element).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorArtifactRecord {
    pub step: String,
    pub exit_code: Option<i32>,
    pub partial_stdout_bytes: usize,
    pub partial_stdout_sha256: String,
    pub partial_stdout_path: String,
    pub stderr_sha256: String,
    pub stderr_path: String,
    pub reason: String,
}

/// Checked output of a streaming command after status and payload validation succeed.
#[derive(Debug, Clone)]
pub struct CheckedCommandOutput {
    pub evidence: ExecutedEvidence,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Latency, I/O, and memory telemetry for cold/warm read, metadata, sync, and recovery/repair workflows.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct WorkflowCostTelemetry {
    pub cold_seq_read_ns: u64,
    pub warm_seq_read_ns: u64,
    pub rand_read_4k_ns: u64,
    pub metadata_stat_readdir_ns: u64,
    pub sync_4k_ns: u64,
    pub recovery_replay_ns: u64,
    pub degraded_read_ns: Option<u64>,
    pub protected_heal_reseal_ns: u64,
    pub physical_io_bytes: u64,
    pub decoded_bytes: u64,
    pub peak_rss_kib: u64,
}

/// Two-regime crash/restart evidence keeping daemon `SIGKILL` strictly separate from
/// modeled device flush-prefix cuts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RestartRegimeEvidence {
    pub regime: ProofRegime,
    pub acknowledged_prefix: Vec<String>,
    pub uncommitted_suffix: Vec<String>,
    pub surviving_operations: Vec<String>,
    pub sync_failure_injected: bool,
    pub post_commit_cancel_retried_without_duplicate: bool,
    pub checker_passed: bool,
}

/// Complete source-bound qualification receipt for one filesystem profile.
#[derive(Debug, Clone, Serialize)]
pub struct ProfileQualificationReceipt {
    pub profile: QualificationProfileId,
    pub policy: ProfilePolicySpec,
    pub provenance: BuildProvenance,
    pub proof_regimes_exercised: BTreeSet<ProofRegime>,
    pub mount_available: bool,
    pub operations_executed: Vec<String>,
    pub command_evidence: Vec<ExecutedEvidence>,
    pub test_results: TestResults,
    pub image_digests: Vec<ImageTransitionDigest>,
    pub strict_ro_zero_writes_verified: bool,
    pub sidecar_resealed_to_native_commit: bool,
    pub final_element_verified: bool,
    pub restart_evidence: Vec<RestartRegimeEvidence>,
    pub workflow_cost: Option<WorkflowCostTelemetry>,
    pub error_artifacts: Vec<ErrorArtifactRecord>,
    pub cleanup: CleanupStatus,
    pub verdict: QualificationVerdict,
}

/// Compute SHA-256 hex digest of a byte slice.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Compute SHA-256 hex digest and byte length of a file on disk.
pub fn hash_file_sha256(path: &Path) -> std::io::Result<(String, u64)> {
    let bytes = fs::read(path)?;
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    Ok((sha256_hex(&bytes), len))
}

/// Resolve an external executable in `PATH` or `/sbin` / `/usr/sbin` and capture its
/// binary SHA-256 and first `--version` / `-V` line.
#[must_use]
pub fn probe_oracle_tool(name: &str, required: bool) -> OracleToolIdentity {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(paths) = std::env::var_os("PATH") {
        for mut dir in std::env::split_paths(&paths) {
            dir.push(name);
            candidates.push(dir);
        }
    }
    for sys_dir in ["/sbin", "/usr/sbin"] {
        candidates.push(Path::new(sys_dir).join(name));
    }

    let resolved = candidates.into_iter().find(|p| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::metadata(p).is_ok_and(|m| m.is_file() && (m.permissions().mode() & 0o111) != 0)
        }
        #[cfg(not(unix))]
        {
            p.is_file()
        }
    });

    let Some(bin_path) = resolved else {
        return OracleToolIdentity {
            name: name.to_owned(),
            required,
            resolved_path: None,
            binary_sha256: None,
            version_line: None,
        };
    };

    let binary_sha256 = hash_file_sha256(&bin_path).ok().map(|(h, _)| h);
    let version_line = ["--version", "-V"]
        .iter()
        .find_map(|flag| {
            Command::new(&bin_path)
                .arg(flag)
                .output()
                .ok()
                .and_then(|out| {
                    let combined = if out.stdout.is_empty() {
                        out.stderr
                    } else {
                        out.stdout
                    };
                    String::from_utf8_lossy(&combined)
                        .lines()
                        .find(|l| !l.trim().is_empty())
                        .map(|l| l.trim().to_owned())
                })
        })
        .or_else(|| Some("present".to_owned()));

    OracleToolIdentity {
        name: name.to_owned(),
        required,
        resolved_path: Some(bin_path.display().to_string()),
        binary_sha256,
        version_line,
    }
}

/// Capture workspace build provenance (`git_sha`, `dirty_source_sha256`, `rustc -Vv`,
/// `Cargo.lock` SHA-256, executed FrankenFS ELF hashes, and external oracle hashes).
pub fn capture_build_provenance(
    workspace_root: &Path,
    binaries: &[(&str, &Path)],
    oracle_names: &[&str],
) -> Result<BuildProvenance, String> {
    let source = SourceIdentity::capture()?;
    let rustc_out = Command::new("rustc")
        .arg("-Vv")
        .output()
        .map_err(|e| format!("failed to run rustc -Vv: {e}"))?;
    if !rustc_out.status.success() {
        return Err("rustc -Vv exited non-zero".to_owned());
    }
    let rustc_text = String::from_utf8_lossy(&rustc_out.stdout);
    let rustc_version_line = rustc_text
        .lines()
        .next()
        .unwrap_or("rustc unknown")
        .trim()
        .to_owned();
    let rustc_vv_sha256 = sha256_hex(&rustc_out.stdout);

    let lock_path = workspace_root.join("Cargo.lock");
    let (cargo_lock_sha256, _) =
        hash_file_sha256(&lock_path).map_err(|e| format!("failed to hash Cargo.lock: {e}"))?;

    let mut binary_records = Vec::with_capacity(binaries.len());
    for &(role, bin_path) in binaries {
        let (elf_sha256, byte_len) = hash_file_sha256(bin_path)
            .map_err(|e| format!("failed to hash binary {role} ({}): {e}", bin_path.display()))?;
        binary_records.push(BinaryArtifactIdentity {
            role: role.to_owned(),
            path: bin_path.display().to_string(),
            elf_sha256,
            byte_len,
        });
    }

    let oracles = oracle_names
        .iter()
        .map(|name| probe_oracle_tool(name, true))
        .collect();

    Ok(BuildProvenance {
        source,
        rustc_version_line,
        rustc_vv_sha256,
        cargo_lock_sha256,
        binaries: binary_records,
        oracles,
    })
}

/// Read current process peak RSS (`VmHWM`, falling back to `VmRSS`) in KiB on Linux.
#[must_use]
pub fn current_peak_rss_kib() -> u64 {
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    let mut vm_rss = 0_u64;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            if let Some(val) = rest
                .split_whitespace()
                .next()
                .and_then(|t| t.parse::<u64>().ok())
            {
                return val;
            }
        } else if let Some(rest) = line.strip_prefix("VmRSS:")
            && let Some(val) = rest
                .split_whitespace()
                .next()
                .and_then(|t| t.parse::<u64>().ok())
        {
            vm_rss = val;
        }
    }
    vm_rss
}

/// Execute a command, capturing `ExecutedEvidence` plus raw stdout/stderr, and
/// fail closed if either the exit code is non-zero or `validate_stdout` rejects the
/// output. Whenever the command fails, any partial streamed `stdout` and `stderr`
/// are persisted to `artifact_dir` as an [`ErrorArtifactRecord`] so streamed output
/// before a late error is never mistaken for valid data.
pub fn run_checked_streaming_cmd<F>(
    step: &str,
    command: &str,
    args: &[&str],
    extra_env: &[(&str, &str)],
    artifact_dir: &Path,
    error_sink: &mut Vec<ErrorArtifactRecord>,
    validate_stdout: F,
) -> Result<CheckedCommandOutput, String>
where
    F: FnOnce(&[u8]) -> Result<(), String>,
{
    let (evidence, stdout, stderr) =
        ExecutedEvidence::run_captured_with_env(command, args, extra_env);
    let exit_code = evidence.exit_code();
    let failure_reason = if !evidence.outcome().is_success() {
        Some(format!(
            "{step}: command `{command}` failed ({:?}): {}",
            evidence.outcome(),
            String::from_utf8_lossy(&stderr).trim()
        ))
    } else {
        validate_stdout(&stdout)
            .err()
            .map(|reason| format!("{step}: output validation failed: {reason}"))
    };

    if let Some(reason) = failure_reason {
        let _ = fs::create_dir_all(artifact_dir);
        let safe_step: String = step
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let stdout_path = artifact_dir.join(format!("{safe_step}_partial_stdout.bin"));
        let stderr_path = artifact_dir.join(format!("{safe_step}_stderr.txt"));
        let _ = fs::write(&stdout_path, &stdout);
        let _ = fs::write(&stderr_path, &stderr);
        error_sink.push(ErrorArtifactRecord {
            step: step.to_owned(),
            exit_code,
            partial_stdout_bytes: stdout.len(),
            partial_stdout_sha256: sha256_hex(&stdout),
            partial_stdout_path: stdout_path.display().to_string(),
            stderr_sha256: sha256_hex(&stderr),
            stderr_path: stderr_path.display().to_string(),
            reason: reason.clone(),
        });
        return Err(reason);
    }

    Ok(CheckedCommandOutput {
        evidence,
        stdout,
        stderr,
    })
}

/// Validate a [`ProfileQualificationReceipt`] fail-closed.
///
/// Enforces provenance completeness, strict-RO immutability, zero error artifacts,
/// non-empty `TestResults` selection, `NativeCommitBinding` sidecar re-sealing,
/// final-element verification, two-regime restart separation (`ProcessSigkillCrash`
/// vs `ModeledDeviceFlushPrefixCut`), acknowledged-prefix preservation, and clean
/// teardown.
pub fn validate_qualification_receipt(
    receipt: &ProfileQualificationReceipt,
    require_oracles: bool,
    require_fuse: bool,
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    if receipt.provenance.source.git_sha.trim().is_empty() {
        errors.push("missing source git_sha".to_owned());
    }
    if receipt.provenance.cargo_lock_sha256.trim().is_empty() {
        errors.push("missing Cargo.lock SHA-256".to_owned());
    }
    if receipt.provenance.binaries.is_empty() {
        errors.push("no FrankenFS binary ELF SHA-256 recorded".to_owned());
    }

    // Missing required external oracles or skipped FUSE mounts can NEVER be Qualified,
    // and fail closed when `require_oracles` / `require_fuse` is enabled.
    let missing_oracles: Vec<&str> = receipt
        .provenance
        .oracles
        .iter()
        .filter(|o| o.required && (o.resolved_path.is_none() || o.binary_sha256.is_none()))
        .map(|o| o.name.as_str())
        .collect();
    if !missing_oracles.is_empty() {
        if receipt.verdict.is_qualified() {
            errors.push(format!(
                "profile {} marked Qualified despite missing required oracle(s): {}",
                receipt.profile.as_str(),
                missing_oracles.join(", ")
            ));
        }
        if require_oracles {
            errors.push(format!(
                "FFS_REQUIRE_ORACLES=1: missing required oracle(s) for {}: {}",
                receipt.profile.as_str(),
                missing_oracles.join(", ")
            ));
        }
    }

    if !receipt.mount_available {
        if receipt.verdict.is_qualified() {
            errors.push(format!(
                "profile {} marked Qualified without live FUSE mount execution",
                receipt.profile.as_str()
            ));
        }
        if require_fuse {
            errors.push(format!(
                "FFS_REQUIRE_FUSE=1: FUSE mount unavailable or skipped for {}",
                receipt.profile.as_str()
            ));
        }
    }

    // Planted Control #3 guard: zero selected tests, all-ignored streams, or any failed test.
    if let Some(err) = &receipt.test_results.error {
        errors.push(format!("test_results stream error: {err}"));
    }
    if receipt.test_results.empty_selection || receipt.test_results.selected == 0 {
        errors.push("zero selected tests (empty_selection) cannot award qualification".to_owned());
    }
    if receipt.test_results.passed == 0 {
        errors.push("zero passed tests cannot award qualification".to_owned());
    }
    if receipt.test_results.failed > 0 {
        errors.push(format!(
            "{} test(s) failed in test_results",
            receipt.test_results.failed
        ));
    }

    // Planted Control #1 guard: partial stdout / command error artifacts or RO write drift
    // or unsealed sidecar after native RW commit.
    if !receipt.error_artifacts.is_empty() {
        errors.push(format!(
            "{} streaming/command error artifact(s) recorded (first: {})",
            receipt.error_artifacts.len(),
            receipt.error_artifacts[0].reason
        ));
    }
    if !receipt.strict_ro_zero_writes_verified {
        errors.push("strict read-only zero-write/zero-sync check not verified".to_owned());
    }
    for digest in &receipt.image_digests {
        if digest.initial_sha256 != digest.post_ro_sha256 {
            errors.push(format!(
                "read-only inspection mutated member {}: initial={} post_ro={}",
                digest.member_label, digest.initial_sha256, digest.post_ro_sha256
            ));
        }
    }

    if receipt.verdict.is_qualified() {
        if !receipt.sidecar_resealed_to_native_commit {
            errors.push(
                "sidecar protection was not re-sealed to the updated NativeCommitBinding"
                    .to_owned(),
            );
        }
        if !receipt.final_element_verified {
            errors.push("final (N-th) element verification did not complete".to_owned());
        }
        if receipt
            .proof_regimes_exercised
            .contains(&ProofRegime::UnitStorageModel)
            && !receipt
                .proof_regimes_exercised
                .contains(&ProofRegime::NativeImage)
        {
            errors.push(
                "unit/storage-model evidence alone cannot award native-image qualification"
                    .to_owned(),
            );
        }
        if !receipt
            .proof_regimes_exercised
            .contains(&ProofRegime::LiveMountedFuse)
        {
            errors.push("Qualified verdict requires LiveMountedFuse evidence".to_owned());
        }
    }

    // Validate every restart evidence record: acknowledged prefix must be a subset of
    // surviving operations, checker must pass, and ProcessSigkillCrash vs
    // ModeledDeviceFlushPrefixCut must only appear with matching ProofRegime tags.
    let mut saw_sigkill = false;
    let mut saw_flush_cut = false;
    for restart in &receipt.restart_evidence {
        match restart.regime {
            ProofRegime::ProcessSigkillCrash => {
                saw_sigkill = true;
                if restart.sync_failure_injected {
                    errors.push(
                        "ProcessSigkillCrash record conflated with modeled device sync failure"
                            .to_owned(),
                    );
                }
            }
            ProofRegime::ModeledDeviceFlushPrefixCut => {
                saw_flush_cut = true;
            }
            other => {
                errors.push(format!(
                    "invalid proof regime {other:?} in restart_evidence (expected ProcessSigkillCrash or ModeledDeviceFlushPrefixCut)"
                ));
            }
        }
        if !restart.checker_passed {
            errors.push(format!(
                "post-restart filesystem checker failed under {:?}",
                restart.regime
            ));
        }
        let surviving: BTreeSet<&str> = restart
            .surviving_operations
            .iter()
            .map(String::as_str)
            .collect();
        for acked in &restart.acknowledged_prefix {
            if !surviving.contains(acked.as_str()) {
                errors.push(format!(
                    "acknowledged operation `{acked}` lost after {:?} restart",
                    restart.regime
                ));
            }
        }
        if !restart.post_commit_cancel_retried_without_duplicate {
            errors.push(format!(
                "post-commit cancelled rename duplicated or corrupted target under {:?}",
                restart.regime
            ));
        }
    }
    if receipt.verdict.is_qualified()
        && !receipt.restart_evidence.is_empty()
        && (!saw_sigkill || !saw_flush_cut)
    {
        errors.push(
            "restart qualification requires both ProcessSigkillCrash and ModeledDeviceFlushPrefixCut regimes separately".to_owned(),
        );
    }

    if !matches!(
        receipt.cleanup,
        CleanupStatus::Clean | CleanupStatus::PreservedArtifacts
    ) {
        errors.push(format!("unclean teardown status: {:?}", receipt.cleanup));
    }

    if let QualificationVerdict::Failed { reasons } = &receipt.verdict {
        errors.extend(reasons.iter().cloned());
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

// ── Persistence-Prefix Partial-Order Cut Device ─────────────────────────────

/// Persistence partial-order stage for an operation write or barrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceStage {
    Initialization,
    Allocation,
    Namespace,
    NativeLogOrJournal,
    RootOrUberblockPublication,
    Reclamation,
    SidecarFence,
    ClientAcknowledgment,
}

/// One uncommitted write recorded between device `sync()` barriers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PendingWriteOp {
    pub seq: usize,
    pub stage: PersistenceStage,
    pub offset: u64,
    pub data: Vec<u8>,
}

impl PendingWriteOp {
    /// Two writes are independent (and therefore reorderable by a block device
    /// between `sync()` barriers) iff their byte intervals do not overlap.
    #[must_use]
    pub fn is_independent_of(&self, other: &Self) -> bool {
        let self_end = self.offset.saturating_add(self.data.len() as u64);
        let other_end = other.offset.saturating_add(other.data.len() as u64);
        self_end <= other.offset || other_end <= self.offset
    }
}

/// Epoch snapshot between two `sync()` barriers, enabling deterministic exploration
/// of prefix, reordered-independent, and torn-sector cuts without mutating live handles.
#[derive(Debug, Clone)]
pub struct FlushEpochRecord {
    pub epoch_index: usize,
    pub durable_before_epoch: Vec<u8>,
    pub writes: Vec<PendingWriteOp>,
    pub durable_after_sync: Option<Vec<u8>>,
    pub acknowledged_after_sync: Vec<String>,
}

/// Cut schedule applied to an uncommitted [`FlushEpochRecord`] to produce a crash image
/// for restarting a fresh filesystem engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CutSchedule {
    /// Drop all writes after `keep_count` writes in the uncommitted epoch.
    Prefix { keep_count: usize },
    /// Apply only the later write of an independent non-overlapping pair `(first_idx, second_idx)`
    /// while dropping `first_idx` (permitted by block-cache write reordering before `sync()`).
    ReorderIndependentPair {
        dropped_idx: usize,
        persisted_idx: usize,
    },
    /// Persist only the first `sector_bytes` (`512`) of write `write_idx`, simulating a torn
    /// multi-sector write on power loss before `sync()`.
    TornSector {
        write_idx: usize,
        sector_bytes: usize,
    },
}

#[derive(Debug)]
struct FlushCutState {
    volatile_bytes: Vec<u8>,
    durable_bytes: Vec<u8>,
    current_stage: PersistenceStage,
    pending_writes: Vec<PendingWriteOp>,
    epochs: Vec<FlushEpochRecord>,
    acknowledged_ops: Vec<String>,
    next_seq: usize,
}

/// Independent block/byte device model separating volatile OS/device write cache from
/// durable post-`sync()` media bytes (`ModeledDeviceFlushPrefixCut`).
#[derive(Debug, Clone)]
pub struct FlushPrefixCutDevice {
    state: Arc<Mutex<FlushCutState>>,
    fail_next_sync: Arc<AtomicBool>,
    sync_calls: Arc<AtomicUsize>,
    write_calls: Arc<AtomicUsize>,
}

impl FlushPrefixCutDevice {
    #[must_use]
    pub fn from_initial_bytes(initial: Vec<u8>) -> Self {
        Self {
            state: Arc::new(Mutex::new(FlushCutState {
                volatile_bytes: initial.clone(),
                durable_bytes: initial,
                current_stage: PersistenceStage::Initialization,
                pending_writes: Vec::new(),
                epochs: Vec::new(),
                acknowledged_ops: Vec::new(),
                next_seq: 0,
            })),
            fail_next_sync: Arc::new(AtomicBool::new(false)),
            sync_calls: Arc::new(AtomicUsize::new(0)),
            write_calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn set_stage(&self, stage: PersistenceStage) {
        self.state.lock().current_stage = stage;
    }

    /// Arm a deterministic `EIO` failure on the next `sync()` call. Durable media
    /// bytes stay at the previous barrier (writes remain uncommitted in volatile cache).
    pub fn inject_next_sync_failure(&self) {
        self.fail_next_sync.store(true, Ordering::SeqCst);
    }

    /// Record that the caller acknowledged `op_name` AFTER a successful durability barrier.
    pub fn record_acknowledgment(&self, op_name: impl Into<String>) {
        let op = op_name.into();
        let mut guard = self.state.lock();
        guard.acknowledged_ops.push(op.clone());
        if let Some(last_epoch) = guard.epochs.last_mut() {
            last_epoch.acknowledged_after_sync.push(op);
        }
    }

    #[must_use]
    pub fn durable_snapshot(&self) -> Vec<u8> {
        self.state.lock().durable_bytes.clone()
    }

    #[must_use]
    pub fn volatile_snapshot(&self) -> Vec<u8> {
        self.state.lock().volatile_bytes.clone()
    }

    #[must_use]
    pub fn acknowledged_prefix(&self) -> Vec<String> {
        self.state.lock().acknowledged_ops.clone()
    }

    #[must_use]
    pub fn sync_count(&self) -> usize {
        self.sync_calls.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn write_count(&self) -> usize {
        self.write_calls.load(Ordering::SeqCst)
    }

    /// Snapshot all recorded epochs (plus any currently pending unsynced writes as a
    /// trailing unsynced epoch) for deterministic cut-schedule exploration.
    #[must_use]
    pub fn recorded_epochs(&self) -> Vec<FlushEpochRecord> {
        let guard = self.state.lock();
        let mut out = guard.epochs.clone();
        if !guard.pending_writes.is_empty() {
            out.push(FlushEpochRecord {
                epoch_index: out.len(),
                durable_before_epoch: guard.durable_bytes.clone(),
                writes: guard.pending_writes.clone(),
                durable_after_sync: None,
                acknowledged_after_sync: Vec::new(),
            });
        }
        out
    }

    /// Materialize the durable media image produced by applying `schedule` to `epoch`,
    /// ready to be opened by a brand-new filesystem engine instance.
    pub fn materialize_cut_image(
        epoch: &FlushEpochRecord,
        schedule: &CutSchedule,
    ) -> Result<Vec<u8>, String> {
        let mut img = epoch.durable_before_epoch.clone();
        match *schedule {
            CutSchedule::Prefix { keep_count } => {
                if keep_count > epoch.writes.len() {
                    return Err(format!(
                        "keep_count {keep_count} exceeds epoch write count {}",
                        epoch.writes.len()
                    ));
                }
                for w in &epoch.writes[..keep_count] {
                    apply_slice(&mut img, w.offset, &w.data)?;
                }
            }
            CutSchedule::ReorderIndependentPair {
                dropped_idx,
                persisted_idx,
            } => {
                if dropped_idx >= persisted_idx || persisted_idx >= epoch.writes.len() {
                    return Err("invalid reorder pair indices".to_owned());
                }
                let dropped = &epoch.writes[dropped_idx];
                let persisted = &epoch.writes[persisted_idx];
                if !dropped.is_independent_of(persisted) {
                    return Err(format!(
                        "cannot reorder overlapping writes #{dropped_idx} (@{}) and #{persisted_idx} (@{})",
                        dropped.offset, persisted.offset
                    ));
                }
                for (idx, w) in epoch.writes[..=persisted_idx].iter().enumerate() {
                    if idx != dropped_idx {
                        apply_slice(&mut img, w.offset, &w.data)?;
                    }
                }
            }
            CutSchedule::TornSector {
                write_idx,
                sector_bytes,
            } => {
                if write_idx >= epoch.writes.len() || sector_bytes == 0 {
                    return Err("invalid torn-sector parameters".to_owned());
                }
                for w in &epoch.writes[..write_idx] {
                    apply_slice(&mut img, w.offset, &w.data)?;
                }
                let target = &epoch.writes[write_idx];
                let prefix_len = sector_bytes.min(target.data.len());
                apply_slice(&mut img, target.offset, &target.data[..prefix_len])?;
            }
        }
        Ok(img)
    }
}

fn apply_slice(buf: &mut [u8], offset: u64, data: &[u8]) -> Result<(), String> {
    let start = usize::try_from(offset).map_err(|_| "offset overflow".to_owned())?;
    let end = start
        .checked_add(data.len())
        .ok_or_else(|| "write end overflow".to_owned())?;
    let dst = buf
        .get_mut(start..end)
        .ok_or_else(|| format!("write {start}..{end} out of bounds {}", buf.len()))?;
    dst.copy_from_slice(data);
    Ok(())
}

impl ByteDevice for FlushPrefixCutDevice {
    fn len_bytes(&self) -> u64 {
        self.state.lock().volatile_bytes.len() as u64
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> FfsResult<()> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let guard = self.state.lock();
        let start = usize::try_from(offset.0)
            .map_err(|_| FfsError::InvalidGeometry("offset overflow".to_owned()))?;
        let end = start
            .checked_add(buf.len())
            .ok_or_else(|| FfsError::InvalidGeometry("read length overflow".to_owned()))?;
        let src = guard
            .volatile_bytes
            .get(start..end)
            .ok_or_else(|| FfsError::InvalidGeometry("read past end of cut device".to_owned()))?;
        buf.copy_from_slice(src);
        Ok(())
    }

    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, buf: &[u8]) -> FfsResult<()> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        self.write_calls.fetch_add(1, Ordering::SeqCst);
        let mut guard = self.state.lock();
        apply_slice(&mut guard.volatile_bytes, offset.0, buf).map_err(FfsError::InvalidGeometry)?;
        let seq = guard.next_seq;
        guard.next_seq += 1;
        let stage = guard.current_stage;
        guard.pending_writes.push(PendingWriteOp {
            seq,
            stage,
            offset: offset.0,
            data: buf.to_vec(),
        });
        Ok(())
    }

    fn sync(&self, cx: &Cx) -> FfsResult<()> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        self.sync_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_next_sync.swap(false, Ordering::SeqCst) {
            return Err(FfsError::Io(std::io::Error::other(
                "injected FlushPrefixCutDevice sync failure (volatile writes remain undurable)",
            )));
        }
        let mut guard = self.state.lock();
        let epoch_idx = guard.epochs.len();
        let before = guard.durable_bytes.clone();
        let after = guard.volatile_bytes.clone();
        let writes = std::mem::take(&mut guard.pending_writes);
        guard.durable_bytes.clone_from(&after);
        guard.epochs.push(FlushEpochRecord {
            epoch_index: epoch_idx,
            durable_before_epoch: before,
            writes,
            durable_after_sync: Some(after),
            acknowledged_after_sync: Vec::new(),
        });
        Ok(())
    }
}

/// Enumerate independent reorderable write pairs inside one epoch (avoiding combinatorial
/// blow-up on dependent overlapping writes while retaining true non-overlapping schedules).
#[must_use]
pub fn independent_reorder_schedules(
    epoch: &FlushEpochRecord,
    max_pairs: usize,
) -> Vec<CutSchedule> {
    let mut out = Vec::new();
    for i in 0..epoch.writes.len() {
        for j in (i + 1)..epoch.writes.len() {
            if epoch.writes[i].is_independent_of(&epoch.writes[j]) {
                out.push(CutSchedule::ReorderIndependentPair {
                    dropped_idx: i,
                    persisted_idx: j,
                });
                if out.len() >= max_pairs {
                    return out;
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executed_evidence::TestOutcome;

    fn sample_valid_receipt() -> ProfileQualificationReceipt {
        let mut regimes = BTreeSet::new();
        regimes.insert(ProofRegime::NativeImage);
        regimes.insert(ProofRegime::LiveMountedFuse);
        regimes.insert(ProofRegime::ProcessSigkillCrash);
        regimes.insert(ProofRegime::ModeledDeviceFlushPrefixCut);

        let mut tests_map = BTreeMap::new();
        tests_map.insert("ext4_interchange_roundtrip".to_owned(), TestOutcome::Passed);

        ProfileQualificationReceipt {
            profile: QualificationProfileId::Ext4,
            policy: QualificationProfileId::Ext4.default_policy(),
            provenance: BuildProvenance {
                source: SourceIdentity {
                    git_sha: "0123456789abcdef0123456789abcdef01234567".to_owned(),
                    dirty_source_sha256: SourceIdentity::EMPTY_DIRTY_SHA256.to_owned(),
                },
                rustc_version_line: "rustc 1.99.0-nightly".to_owned(),
                rustc_vv_sha256: "aaaa".to_owned(),
                cargo_lock_sha256: "bbbb".to_owned(),
                binaries: vec![BinaryArtifactIdentity {
                    role: "ffs-cli".to_owned(),
                    path: "/tmp/ffs-cli".to_owned(),
                    elf_sha256: "cccc".to_owned(),
                    byte_len: 1024,
                }],
                oracles: vec![OracleToolIdentity {
                    name: "e2fsck".to_owned(),
                    required: true,
                    resolved_path: Some("/sbin/e2fsck".to_owned()),
                    binary_sha256: Some("dddd".to_owned()),
                    version_line: Some("e2fsck 1.47.2".to_owned()),
                }],
            },
            proof_regimes_exercised: regimes,
            mount_available: true,
            operations_executed: vec![
                "format".to_owned(),
                "ro_read".to_owned(),
                "rw_mutate".to_owned(),
            ],
            command_evidence: Vec::new(),
            test_results: TestResults {
                selected: 1,
                executed: 1,
                passed: 1,
                failed: 0,
                skipped: 0,
                filtered_out: 0,
                tests: tests_map,
                empty_selection: false,
                error: None,
            },
            image_digests: vec![ImageTransitionDigest {
                member_label: "primary".to_owned(),
                initial_sha256: "1111".to_owned(),
                post_ro_sha256: "1111".to_owned(),
                post_native_rw_sha256: Some("2222".to_owned()),
                post_protected_heal_sha256: Some("2222".to_owned()),
                post_external_rw_sha256: Some("3333".to_owned()),
            }],
            strict_ro_zero_writes_verified: true,
            sidecar_resealed_to_native_commit: true,
            final_element_verified: true,
            restart_evidence: vec![
                RestartRegimeEvidence {
                    regime: ProofRegime::ProcessSigkillCrash,
                    acknowledged_prefix: vec!["op1_create".to_owned()],
                    uncommitted_suffix: vec!["op2_unsynced".to_owned()],
                    surviving_operations: vec!["op1_create".to_owned()],
                    sync_failure_injected: false,
                    post_commit_cancel_retried_without_duplicate: true,
                    checker_passed: true,
                },
                RestartRegimeEvidence {
                    regime: ProofRegime::ModeledDeviceFlushPrefixCut,
                    acknowledged_prefix: vec!["op1_create".to_owned()],
                    uncommitted_suffix: vec!["op2_unsynced".to_owned()],
                    surviving_operations: vec!["op1_create".to_owned()],
                    sync_failure_injected: true,
                    post_commit_cancel_retried_without_duplicate: true,
                    checker_passed: true,
                },
            ],
            workflow_cost: Some(WorkflowCostTelemetry {
                cold_seq_read_ns: 100_000,
                warm_seq_read_ns: 40_000,
                rand_read_4k_ns: 12_000,
                metadata_stat_readdir_ns: 25_000,
                sync_4k_ns: 180_000,
                recovery_replay_ns: 95_000,
                degraded_read_ns: None,
                protected_heal_reseal_ns: 310_000,
                physical_io_bytes: 65_536,
                decoded_bytes: 65_536,
                peak_rss_kib: 16_384,
            }),
            error_artifacts: Vec::new(),
            cleanup: CleanupStatus::Clean,
            verdict: QualificationVerdict::Qualified,
        }
    }

    #[test]
    fn planted_negative_controls_fail_closed_on_all_four_required_defect_classes() {
        let valid = sample_valid_receipt();
        assert!(validate_qualification_receipt(&valid, true, true).is_ok());

        // Control 1: Historical defect — partial streamed stdout error artifact OR unsealed sidecar.
        let mut c1_partial = valid.clone();
        c1_partial.error_artifacts.push(ErrorArtifactRecord {
            step: "stream_read_nth_chunk".to_owned(),
            exit_code: Some(1),
            partial_stdout_bytes: 4096,
            partial_stdout_sha256: "abcd".to_owned(),
            partial_stdout_path: "/tmp/partial.bin".to_owned(),
            stderr_sha256: "ef01".to_owned(),
            stderr_path: "/tmp/stderr.txt".to_owned(),
            reason: "corrupt chunk #4 after 4096 bytes streamed".to_owned(),
        });
        assert!(validate_qualification_receipt(&c1_partial, true, true).is_err());

        let mut c1_unsealed = valid.clone();
        c1_unsealed.sidecar_resealed_to_native_commit = false;
        assert!(validate_qualification_receipt(&c1_unsealed, true, true).is_err());

        // Control 2: Missing required external oracle under FFS_REQUIRE_ORACLES=1 (or Qualified claim).
        let mut c2_missing_oracle = valid.clone();
        c2_missing_oracle.provenance.oracles[0].resolved_path = None;
        c2_missing_oracle.provenance.oracles[0].binary_sha256 = None;
        assert!(validate_qualification_receipt(&c2_missing_oracle, false, false).is_err());
        c2_missing_oracle.verdict = QualificationVerdict::Unqualified {
            missing_prerequisites: vec!["e2fsck".to_owned()],
        };
        assert!(
            validate_qualification_receipt(&c2_missing_oracle, false, false).is_ok(),
            "Unqualified verdict is honest when require_oracles=false"
        );
        assert!(
            validate_qualification_receipt(&c2_missing_oracle, true, false).is_err(),
            "require_oracles=true must fail closed even when marked Unqualified"
        );

        // Control 3: Zero selected tests / empty_selection stream.
        let mut c3_empty = valid.clone();
        c3_empty.test_results.selected = 0;
        c3_empty.test_results.executed = 0;
        c3_empty.test_results.passed = 0;
        c3_empty.test_results.empty_selection = true;
        assert!(validate_qualification_receipt(&c3_empty, true, true).is_err());

        // Control 4: Final-element failure OR acknowledged-prefix loss OR regime conflation.
        let mut c4_final = valid.clone();
        c4_final.final_element_verified = false;
        assert!(validate_qualification_receipt(&c4_final, true, true).is_err());

        let mut c4_lost_ack = valid.clone();
        c4_lost_ack.restart_evidence[1].surviving_operations.clear();
        assert!(validate_qualification_receipt(&c4_lost_ack, true, true).is_err());

        let mut c4_conflated = valid;
        c4_conflated.restart_evidence.pop(); // Remove ModeledDeviceFlushPrefixCut, leaving only SIGKILL!
        assert!(
            validate_qualification_receipt(&c4_conflated, true, true).is_err(),
            "SIGKILL alone must never satisfy two-regime restart qualification"
        );
    }

    #[test]
    fn flush_prefix_cut_device_separates_volatile_from_durable_and_explores_cuts() {
        let cx = Cx::for_testing();
        let dev = FlushPrefixCutDevice::from_initial_bytes(vec![0_u8; 4096]);

        dev.set_stage(PersistenceStage::Allocation);
        dev.write_all_at(&cx, ByteOffset(0), &[0xAA; 1024]).unwrap();
        dev.set_stage(PersistenceStage::Namespace);
        dev.write_all_at(&cx, ByteOffset(2048), &[0xBB; 1024])
            .unwrap();

        // Before sync(), durable media is still all zeros!
        assert_eq!(&dev.durable_snapshot()[..8], &[0_u8; 8]);
        assert_eq!(&dev.volatile_snapshot()[..8], &[0xAA; 8]);

        // Injected sync() failure leaves durable media untouched and returns an error.
        dev.inject_next_sync_failure();
        assert!(dev.sync(&cx).is_err());
        assert_eq!(&dev.durable_snapshot()[..8], &[0_u8; 8]);

        // Subsequent sync() commits the epoch and records acknowledgment.
        dev.sync(&cx).unwrap();
        dev.record_acknowledgment("tx1_commit");
        assert_eq!(&dev.durable_snapshot()[..8], &[0xAA; 8]);
        assert_eq!(dev.acknowledged_prefix(), vec!["tx1_commit".to_owned()]);

        let epochs = dev.recorded_epochs();
        assert_eq!(epochs.len(), 1);
        let reorders = independent_reorder_schedules(&epochs[0], 8);
        assert_eq!(reorders.len(), 1);

        // Reordered cut persists write #1 (@2048) while dropping independent write #0 (@0).
        let reordered_img =
            FlushPrefixCutDevice::materialize_cut_image(&epochs[0], &reorders[0]).unwrap();
        assert_eq!(&reordered_img[0..8], &[0_u8; 8]);
        assert_eq!(&reordered_img[2048..2056], &[0xBB; 8]);

        // Torn-sector cut persists only the first 512 bytes of write #0 (@0..1024).
        let torn_img = FlushPrefixCutDevice::materialize_cut_image(
            &epochs[0],
            &CutSchedule::TornSector {
                write_idx: 0,
                sector_bytes: 512,
            },
        )
        .unwrap();
        assert_eq!(&torn_img[0..512], &[0xAA; 512]);
        assert_eq!(&torn_img[512..1024], &[0_u8; 512]);
    }
}
