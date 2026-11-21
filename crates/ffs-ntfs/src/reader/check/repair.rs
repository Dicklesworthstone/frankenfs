//! Optional, strictly explicit-authority bounded NTFS repairs.
//!
//! Never invoked during `check`. Only unambiguous, provenance-verified actions
//! are ever planned or executed:
//! 1. Restoring a missing/mismatched trailing backup boot sector from a clean
//!    primary VBR (`SyncBackupBootSector`).
//! 2. Synchronizing `$MFTMirr` prefix records `0..4` from a verified clean `$MFT`
//!    (`SyncMftMirrorPrefix`).
//! 3. Running persistent ARIES `$LogFile` recovery via `NtfsTransactionEngine`
//!    (`RecoverCleanableJournal`).
//!
//! Cross-links, hibernated volumes, missing/corrupt files, namespace cycles,
//! security descriptor damage, and unsupported volume flags are strictly refused.

use std::fs::OpenOptions;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::Arc;

use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_error::{FfsError, Result};
use ffs_ondisk::ntfs::NtfsGeometry;
use serde::Serialize;

use super::{
    NtfsCheckCategory, NtfsCheckLimits, NtfsCheckReport, NtfsCheckStatus, check_volume_device,
};
use crate::reader::{NtfsVolume, checkpoint};
use crate::transaction::{NtfsTransactionEngine, NtfsWriteOptions};

/// One bounded, unambiguous offline NTFS repair action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum NtfsRepairAction {
    /// Copy the verified primary VBR to the trailing backup boot sector.
    SyncBackupBootSector {
        backup_offset: u64,
        sector_bytes: u32,
    },
    /// Synchronize `$MFTMirr` records `0..4` from the verified primary `$MFT`.
    SyncMftMirrorPrefix { records: u64 },
    /// Replay a dirty `$LogFile` through `NtfsTransactionEngine::recover_and_open`.
    RecoverCleanableJournal {
        current_lsn: u64,
        torn_rstr_slot: Option<usize>,
    },
}

/// Deterministic, reviewable repair plan generated from an [`NtfsCheckReport`].
#[derive(Debug, Clone, Serialize)]
pub struct NtfsRepairPlan {
    pub eligible: bool,
    pub actions: Vec<NtfsRepairAction>,
    pub refusal_reasons: Vec<String>,
}

/// Inspect a completed [`NtfsCheckReport`] and build a bounded repair plan.
///
/// Any ambiguity (cross-links, namespace corruption, ownership defects,
/// hibernated state, unsupported volume flags, or incomplete coverage) causes
/// `eligible = false` with explicit `refusal_reasons`.
#[must_use]
pub fn plan_bounded_repair(report: &NtfsCheckReport) -> NtfsRepairPlan {
    let mut actions = Vec::new();
    let mut refusal_reasons = Vec::new();

    if report.status == NtfsCheckStatus::Clean && report.clean {
        return NtfsRepairPlan {
            eligible: true,
            actions,
            refusal_reasons,
        };
    }

    if !report.complete {
        refusal_reasons.push("check did not complete full volume coverage".into());
    }
    if report.hibernated {
        refusal_reasons.push(
            "hiberfil.sys is present; refusing repair on potentially hibernated volume".into(),
        );
    }
    if report.volume_flags & !0x0001 != 0 {
        refusal_reasons.push(format!(
            "volume flags {:#06x} require full native chkdsk/resize handling beyond bounded repair",
            report.volume_flags
        ));
    }

    let mut needs_backup_boot = false;
    let mut needs_mirror_sync = false;
    let mut needs_journal_recovery = false;

    for issue in &report.issues {
        match (issue.category, issue.code.as_str()) {
            (NtfsCheckCategory::Boot, "backup_boot_mismatch") => {
                needs_backup_boot = true;
            }
            (NtfsCheckCategory::MftMirror, "required_mirror_difference") => {
                needs_mirror_sync = true;
            }
            (
                NtfsCheckCategory::Journal,
                "logfile_dirty" | "logfile_torn_rstr" | "volume_dirty_flag",
            ) => {
                needs_journal_recovery = true;
            }
            _ => {
                refusal_reasons.push(format!(
                    "unrepairable or ambiguous issue [{:?}/{}]: {}",
                    issue.category, issue.code, issue.detail
                ));
            }
        }
    }

    if report.volume_flags & 0x0001 != 0 {
        needs_journal_recovery = true;
    }

    if !refusal_reasons.is_empty() {
        return NtfsRepairPlan {
            eligible: false,
            actions: Vec::new(),
            refusal_reasons,
        };
    }

    if needs_journal_recovery {
        if let Some(j) = &report.journal {
            actions.push(NtfsRepairAction::RecoverCleanableJournal {
                current_lsn: j.current_lsn,
                torn_rstr_slot: j.torn_rstr_slot,
            });
        } else {
            refusal_reasons.push("$LogFile could not be parsed cleanly for replay".into());
            return NtfsRepairPlan {
                eligible: false,
                actions: Vec::new(),
                refusal_reasons,
            };
        }
    }
    if needs_mirror_sync {
        actions.push(NtfsRepairAction::SyncMftMirrorPrefix { records: 4 });
    }
    if needs_backup_boot {
        if let Some(backup_offset) = report.backup_boot_offset {
            actions.push(NtfsRepairAction::SyncBackupBootSector {
                backup_offset,
                sector_bytes: report.sector_bytes,
            });
        } else {
            refusal_reasons.push(
                "container lacks trailing space for a backup boot sector; cannot synthesize in place"
                    .into(),
            );
            return NtfsRepairPlan {
                eligible: false,
                actions: Vec::new(),
                refusal_reasons,
            };
        }
    }

    NtfsRepairPlan {
        eligible: true,
        actions,
        refusal_reasons,
    }
}

struct ReadOnlySliceFile {
    file: std::fs::File,
    len: u64,
}

impl ByteDevice for ReadOnlySliceFile {
    fn len_bytes(&self) -> u64 {
        self.len
    }

    fn read_exact_at(&self, cx: &Cx, offset: ffs_types::ByteOffset, data: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        self.file.read_exact_at(data, offset.0)?;
        checkpoint(cx)
    }

    fn write_all_at(&self, _cx: &Cx, _offset: ffs_types::ByteOffset, _data: &[u8]) -> Result<()> {
        Err(FfsError::ReadOnly)
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        checkpoint(cx)
    }
}

/// Apply a bounded repair plan to an explicit offline regular image file.
///
/// # Errors
/// Fails closed if `offline_image` or `allow_write` is false, if the target is
/// not an offline regular file, if the check report is ineligible for bounded
/// repair, or if post-repair verification does not produce a clean volume.
pub fn apply_bounded_repair(
    cx: &Cx,
    path: &Path,
    offset: u64,
    length: Option<u64>,
    offline_image: bool,
    allow_write: bool,
    limits: NtfsCheckLimits,
) -> Result<(NtfsRepairPlan, NtfsCheckReport)> {
    checkpoint(cx)?;
    if !offline_image || !allow_write {
        return Err(FfsError::UnsupportedFeature(
            "bounded NTFS repair requires explicit --offline-image and --allow-write authority"
                .into(),
        ));
    }
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(FfsError::UnsupportedFeature(
            "bounded NTFS repair accepts regular offline image files only".into(),
        ));
    }
    let slice_len = length.unwrap_or_else(|| meta.len().saturating_sub(offset));

    // Phase 1: Pure read-only check before opening write handle.
    let ro_file = std::fs::File::open(path)?;
    ro_file
        .try_lock_shared()
        .map_err(|e| FfsError::Io(std::io::Error::other(e)))?;
    let ro_dev: Arc<dyn ByteDevice> = Arc::new(ReadOnlySliceFile {
        file: ro_file,
        len: meta.len(),
    });
    let initial = check_volume_device(cx, ro_dev, offset, slice_len, limits)?;
    let plan = plan_bounded_repair(&initial);
    if !plan.eligible {
        return Err(FfsError::UnsupportedFeature(format!(
            "bounded NTFS repair refused: {}",
            plan.refusal_reasons.join("; ")
        )));
    }
    if plan.actions.is_empty() {
        return Ok((plan, initial));
    }

    // Phase 2: Execute only the planned bounded actions.
    for action in &plan.actions {
        checkpoint(cx)?;
        match action {
            NtfsRepairAction::RecoverCleanableJournal { .. } => {
                let opts = NtfsWriteOptions {
                    offline_image: true,
                    allow_write: true,
                    recover_dirty: true,
                };
                let engine = NtfsTransactionEngine::open(cx, path, offset, length, opts)?;
                drop(engine);
            }
            NtfsRepairAction::SyncMftMirrorPrefix { records } => {
                sync_mft_mirror_prefix(cx, path, offset, slice_len, *records)?;
            }
            NtfsRepairAction::SyncBackupBootSector {
                backup_offset,
                sector_bytes,
            } => {
                sync_backup_boot_sector(cx, path, offset, *backup_offset, *sector_bytes)?;
            }
        }
    }

    // Phase 3: Re-check completely from scratch in pure read-only mode.
    let verify_file = std::fs::File::open(path)?;
    verify_file
        .try_lock_shared()
        .map_err(|e| FfsError::Io(std::io::Error::other(e)))?;
    let verify_dev: Arc<dyn ByteDevice> = Arc::new(ReadOnlySliceFile {
        file: verify_file,
        len: meta.len(),
    });
    let after = check_volume_device(cx, verify_dev, offset, slice_len, limits)?;
    Ok((plan, after))
}

fn sync_backup_boot_sector(
    cx: &Cx,
    path: &Path,
    base: u64,
    backup_rel_offset: u64,
    sector_bytes: u32,
) -> Result<()> {
    checkpoint(cx)?;
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    file.try_lock()
        .map_err(|e| FfsError::Io(std::io::Error::other(e)))?;
    let sec_len = usize::try_from(sector_bytes)
        .map_err(|_| FfsError::Format("sector size overflow".into()))?;
    let mut primary = vec![0_u8; sec_len];
    file.read_exact_at(&mut primary, base)?;
    // Verify primary VBR parses cleanly before copying it.
    let _ = NtfsGeometry::parse(&primary, backup_rel_offset)
        .map_err(|e| FfsError::Format(e.to_string()))?;
    let dst = base
        .checked_add(backup_rel_offset)
        .ok_or_else(|| FfsError::Format("backup boot offset overflow".into()))?;
    file.write_all_at(&primary, dst)?;
    file.sync_all()?;
    checkpoint(cx)
}

fn sync_mft_mirror_prefix(
    cx: &Cx,
    path: &Path,
    base: u64,
    slice_len: u64,
    records: u64,
) -> Result<()> {
    checkpoint(cx)?;
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    file.try_lock()
        .map_err(|e| FfsError::Io(std::io::Error::other(e)))?;
    let ro_clone = file.try_clone()?;
    let total_len = file.metadata()?.len();
    let ro_dev = Box::new(ReadOnlySliceFile {
        file: ro_clone,
        len: total_len,
    });
    let vol = NtfsVolume::from_device_for_check(cx, ro_dev, base, slice_len)?;
    let rec_bytes = u64::from(vol.geometry.record_bytes());
    let mirror_off = base
        .checked_add(
            vol.geometry
                .cluster_offset(vol.geometry.mirror_cluster())
                .map_err(|e| FfsError::Format(e.to_string()))?,
        )
        .ok_or_else(|| FfsError::Format("mirror offset overflow".into()))?;
    let mft_off = base
        .checked_add(
            vol.geometry
                .cluster_offset(vol.geometry.mft_cluster())
                .map_err(|e| FfsError::Format(e.to_string()))?,
        )
        .ok_or_else(|| FfsError::Format("mft offset overflow".into()))?;
    let byte_len = usize::try_from(records.saturating_mul(rec_bytes))
        .map_err(|_| FfsError::Format("mirror prefix size overflow".into()))?;
    let mut prefix = vec![0_u8; byte_len];
    file.read_exact_at(&mut prefix, mft_off)?;
    file.write_all_at(&prefix, mirror_off)?;
    file.sync_all()?;
    checkpoint(cx)
}
