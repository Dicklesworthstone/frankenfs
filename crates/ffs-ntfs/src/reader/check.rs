//! Unified, strictly non-mutating native NTFS 3.0 / 3.1 structural consistency checker.
//!
//! Combines:
//! - Primary VBR & trailing backup boot sector verification
//! - System metadata file invariants (`records 0..15`, `$AttrDef`, `$Boot`, `$BadClus`, `$UpCase`, `$Extend`)
//! - Unallocated MFT slot hygiene (`free_slot_marked_in_use`)
//! - Cluster allocation & `$Bitmap` reconciliation (`check_allocations`)
//! - Base/extension `$ATTRIBUTE_LIST` ownership audit (`check_record_ownership`)
//! - `$MFT` <-> `$MFTMirr` comparison (`check_mft_mirror`)
//! - `$I30` directory B-tree, `FILE_NAME` link-count, DOS/Win32 pairing & reachability (`check_namespace`)
//! - `$Secure` (`$SII`/`$SDH`/`$SDS`) store & per-file security reference audit (`check_security_references`)
//! - Non-resident stream bounds, EA (`0xD0`/`0xE0`) and `REPARSE_POINT` consistency
//! - `$LogFile` ARIES state inspection & `hiberfil.sys` detection
//!
//! Zero writes and zero syncs are issued during checking (enforced by a
//! read-only counting wrapper on [`ByteDevice`]).

pub mod repair;
mod system_files;

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_error::{FfsError, Result};
use ffs_ondisk::ntfs::NtfsGeometry;
use ffs_types::ByteOffset;
use serde::Serialize;

use super::allocation::{AllocationLimits, NamespaceLimits, RecordOwnershipLimits};
use super::security::SecurityCheckLimits;
use super::{NtfsVolume, checkpoint};
use crate::transaction::NtfsLogStateSummary;

const MAX_CHECK_ISSUES: usize = 256;

/// Overall classification of an NTFS volume after unified non-mutating inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NtfsCheckStatus {
    /// Every check completed with zero structural errors, zero unsupported
    /// gaps, a clean `$LogFile`, and zero volume dirty flags.
    Clean,
    /// Structural invariants passed, but the volume has a dirty `$LogFile`
    /// or `VOLUME_IS_DIRTY` flag requiring recovery before writable mount.
    DirtyJournal,
    /// One or more structural, boot, allocation, mirror, namespace, security,
    /// or metadata corruptions were detected.
    Corrupt,
    /// Inspection did not complete full coverage (budget limit or unsupported
    /// on-disk feature) and therefore cannot certify consistency.
    IncompleteUnsupported,
}

/// Functional domain of one structural finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NtfsCheckCategory {
    Boot,
    SystemMetadata,
    MftSlot,
    Allocation,
    RecordOwnership,
    MftMirror,
    Namespace,
    Security,
    Journal,
    StreamBounds,
    SecondaryIndex,
    UnsupportedFeature,
}

/// One deterministic structural diagnostic finding.
#[derive(Debug, Clone, Serialize)]
pub struct NtfsCheckIssue {
    pub category: NtfsCheckCategory,
    pub code: String,
    pub record: Option<u64>,
    pub cluster: Option<u64>,
    pub detail: String,
}

/// Configurable bounds for the unified structural checker.
#[derive(Debug, Clone, Copy)]
pub struct NtfsCheckLimits {
    pub records: u64,
    pub clusters: u64,
    pub runs: usize,
    pub metadata_bytes: u64,
    pub namespace_entries: u64,
    pub security_entries: usize,
}

impl Default for NtfsCheckLimits {
    fn default() -> Self {
        let alloc = AllocationLimits::default();
        let ns = NamespaceLimits::default();
        let sec = SecurityCheckLimits::default();
        Self {
            records: alloc.records,
            clusters: alloc.clusters,
            runs: alloc.runs,
            metadata_bytes: ns.metadata_bytes,
            namespace_entries: ns.entries,
            security_entries: sec.entries,
        }
    }
}

/// Summary metrics for one sub-pass inside [`NtfsCheckReport`].
#[derive(Debug, Clone, Default, Serialize)]
pub struct NtfsSubcheckSummary {
    pub consistent: bool,
    pub complete: bool,
    pub errors: u64,
    pub unsupported: u64,
    pub limit_reached: Option<String>,
}

/// Complete, non-mutating structural inspection report for an NTFS 3.0/3.1 image.
#[derive(Debug, Clone, Serialize)]
pub struct NtfsCheckReport {
    pub format: &'static str,
    pub ntfs_version: [u8; 2],
    pub read_only: bool,
    pub write_calls: u64,
    pub sync_calls: u64,
    pub status: NtfsCheckStatus,
    pub clean: bool,
    pub complete: bool,
    pub volume_flags: u16,
    pub hibernated: bool,
    pub sector_bytes: u32,
    pub cluster_bytes: u32,
    pub volume_bytes: u64,
    pub backing_bytes: u64,
    pub cluster_count: u64,
    pub mft_cluster: u64,
    pub mirror_cluster: u64,
    pub backup_boot_present: bool,
    pub backup_boot_matches: Option<bool>,
    pub backup_boot_offset: Option<u64>,
    pub bad_clusters: u64,
    pub free_slots_examined: u64,
    pub free_slots_marked_in_use: u64,
    pub allocation: NtfsSubcheckSummary,
    pub ownership: NtfsSubcheckSummary,
    pub mirror: NtfsSubcheckSummary,
    pub namespace: NtfsSubcheckSummary,
    pub security: NtfsSubcheckSummary,
    pub journal: Option<NtfsLogStateSummary>,
    pub issues: Vec<NtfsCheckIssue>,
    pub omitted_issues: u64,
    pub scope_note: &'static str,
}

impl NtfsCheckReport {
    pub(super) fn push_issue(
        &mut self,
        category: NtfsCheckCategory,
        code: impl Into<String>,
        record: Option<u64>,
        cluster: Option<u64>,
        detail: String,
    ) {
        if self.issues.len() < MAX_CHECK_ISSUES {
            let truncated = if detail.chars().count() <= 512 {
                detail
            } else {
                detail.chars().take(512).collect()
            };
            self.issues.push(NtfsCheckIssue {
                category,
                code: code.into(),
                record,
                cluster,
                detail: truncated,
            });
        } else {
            self.omitted_issues += 1;
        }
    }

    fn finalize_status(&mut self) {
        let mut has_corrupt = false;
        let mut has_dirty = self.volume_flags & 0x0001 != 0;
        let mut has_unsupported = !self.complete || (self.volume_flags & !0x0001 != 0);

        if let Some(j) = &self.journal
            && !j.clean
        {
            has_dirty = true;
        }

        for issue in &self.issues {
            match (issue.category, issue.code.as_str()) {
                (NtfsCheckCategory::UnsupportedFeature, _) => has_unsupported = true,
                (
                    NtfsCheckCategory::Journal,
                    "logfile_dirty" | "logfile_torn_rstr" | "volume_dirty_flag",
                ) => has_dirty = true,
                _ => has_corrupt = true,
            }
        }

        if self.hibernated {
            has_corrupt = true;
        }

        self.status = if has_corrupt {
            NtfsCheckStatus::Corrupt
        } else if has_unsupported {
            NtfsCheckStatus::IncompleteUnsupported
        } else if has_dirty {
            NtfsCheckStatus::DirtyJournal
        } else {
            NtfsCheckStatus::Clean
        };
        self.clean = self.status == NtfsCheckStatus::Clean
            && self.complete
            && self.issues.is_empty()
            && self.omitted_issues == 0;
    }
}

/// Strictly non-mutating wrapper that refuses and counts any write or sync call.
struct ReadOnlyAssertDevice {
    inner: Arc<dyn ByteDevice>,
    writes: Arc<AtomicU64>,
    syncs: Arc<AtomicU64>,
}

impl ByteDevice for ReadOnlyAssertDevice {
    fn len_bytes(&self) -> u64 {
        self.inner.len_bytes()
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, data: &mut [u8]) -> Result<()> {
        self.inner.read_exact_at(cx, offset, data)
    }

    fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _data: &[u8]) -> Result<()> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        Err(FfsError::ReadOnly)
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        self.syncs.fetch_add(1, Ordering::Relaxed);
        Err(FfsError::ReadOnly)
    }
}

struct ReadOnlyCheckFile {
    file: File,
    length: u64,
}

impl ByteDevice for ReadOnlyCheckFile {
    fn len_bytes(&self) -> u64 {
        self.length
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, data: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        self.file.read_exact_at(data, offset.0)?;
        checkpoint(cx)
    }

    fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _data: &[u8]) -> Result<()> {
        Err(FfsError::ReadOnly)
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        Err(FfsError::ReadOnly)
    }
}

/// Run the full non-mutating structural checker on an offline regular image file.
///
/// # Errors
/// Returns an error only on I/O, cancellation, invalid path/slice arguments, or
/// unparseable primary boot sector; structural findings on parseable volumes are
/// returned inside [`NtfsCheckReport`].
pub fn check_image_file(
    cx: &Cx,
    path: &Path,
    offset: u64,
    length: Option<u64>,
    limits: NtfsCheckLimits,
) -> Result<NtfsCheckReport> {
    checkpoint(cx)?;
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(FfsError::UnsupportedFeature(
            "NTFS checker accepts regular offline image files only".into(),
        ));
    }
    let file = File::open(path)?;
    file.try_lock_shared()
        .map_err(|e| FfsError::Io(std::io::Error::other(e)))?;
    let total_len = meta.len();
    let slice_len = length.unwrap_or_else(|| total_len.saturating_sub(offset));
    let dev: Arc<dyn ByteDevice> = Arc::new(ReadOnlyCheckFile {
        file,
        length: total_len,
    });
    check_volume_device(cx, dev, offset, slice_len, limits)
}

/// Run the full non-mutating structural checker on a caller-supplied [`ByteDevice`].
///
/// Guarantees zero writes and zero syncs to `device`.
///
/// # Errors
/// Returns an error on cancellation, out-of-range `[base, base + length)`, or
/// unrecoverable I/O failure.
#[allow(clippy::too_many_lines)]
pub fn check_volume_device(
    cx: &Cx,
    device: Arc<dyn ByteDevice>,
    base: u64,
    length: u64,
    limits: NtfsCheckLimits,
) -> Result<NtfsCheckReport> {
    checkpoint(cx)?;
    if length < 512
        || base
            .checked_add(length)
            .is_none_or(|end| end > device.len_bytes())
    {
        return Err(FfsError::InvalidGeometry(
            "NTFS check slice exceeds backing device length".into(),
        ));
    }

    let writes = Arc::new(AtomicU64::new(0));
    let syncs = Arc::new(AtomicU64::new(0));
    let guarded: Arc<dyn ByteDevice> = Arc::new(ReadOnlyAssertDevice {
        inner: device,
        writes: Arc::clone(&writes),
        syncs: Arc::clone(&syncs),
    });

    // Read primary boot sector (512B minimum to discover actual sector_bytes).
    let mut boot512 = [0_u8; 512];
    guarded.read_exact_at(cx, ByteOffset(base), &mut boot512)?;
    let geometry = match NtfsGeometry::parse(&boot512, length) {
        Ok(g) => g,
        Err(err) => {
            let mut report = empty_report(length, &writes, &syncs);
            report.push_issue(
                NtfsCheckCategory::Boot,
                "boot_sector_invalid",
                None,
                None,
                format!("primary NTFS VBR failed parse: {err}"),
            );
            report.finalize_status();
            return Ok(report);
        }
    };

    let sector_len = usize::try_from(geometry.sector_bytes())
        .map_err(|_| FfsError::Format("sector_bytes overflow".into()))?;
    let mut vbr_sector = vec![0_u8; sector_len];
    if u64::from(geometry.sector_bytes()) <= length {
        guarded.read_exact_at(cx, ByteOffset(base), &mut vbr_sector)?;
    } else {
        vbr_sector[..512].copy_from_slice(&boot512);
    }

    let mut report = NtfsCheckReport {
        format: "NTFS",
        ntfs_version: [0, 0],
        read_only: true,
        write_calls: 0,
        sync_calls: 0,
        status: NtfsCheckStatus::Clean,
        clean: false,
        complete: true,
        volume_flags: 0,
        hibernated: false,
        sector_bytes: geometry.sector_bytes(),
        cluster_bytes: geometry.cluster_bytes(),
        volume_bytes: geometry.volume_bytes(),
        backing_bytes: length,
        cluster_count: geometry.cluster_count(),
        mft_cluster: geometry.mft_cluster(),
        mirror_cluster: geometry.mirror_cluster(),
        backup_boot_present: false,
        backup_boot_matches: None,
        backup_boot_offset: None,
        bad_clusters: 0,
        free_slots_examined: 0,
        free_slots_marked_in_use: 0,
        allocation: NtfsSubcheckSummary::default(),
        ownership: NtfsSubcheckSummary::default(),
        mirror: NtfsSubcheckSummary::default(),
        namespace: NtfsSubcheckSummary::default(),
        security: NtfsSubcheckSummary::default(),
        journal: None,
        issues: Vec::new(),
        omitted_issues: 0,
        scope_note: "Native non-mutating NTFS 3.0/3.1 structural checker (not Windows chkdsk; zero writes/syncs issued)",
    };

    check_backup_boot(
        cx,
        guarded.as_ref(),
        base,
        &vbr_sector,
        &geometry,
        &mut report,
    )?;

    // Open NtfsVolume in read-only check mode (permits reading dirty flags without overlay).
    let boxed_guard: Box<dyn ByteDevice> = Box::new(ReadOnlyAssertDevice {
        inner: Arc::clone(&guarded),
        writes: Arc::clone(&writes),
        syncs: Arc::clone(&syncs),
    });
    let volume = match NtfsVolume::from_device_for_check(cx, boxed_guard, base, length) {
        Ok(v) => v,
        Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
        Err(FfsError::UnsupportedFeature(msg)) => {
            report.complete = false;
            report.push_issue(
                NtfsCheckCategory::UnsupportedFeature,
                "volume_bootstrap_unsupported",
                None,
                None,
                msg,
            );
            report.write_calls = writes.load(Ordering::Relaxed);
            report.sync_calls = syncs.load(Ordering::Relaxed);
            report.finalize_status();
            return Ok(report);
        }
        Err(err) => {
            report.push_issue(
                NtfsCheckCategory::SystemMetadata,
                "volume_bootstrap_corrupt",
                None,
                None,
                format!("NTFS volume bootstrap failed: {err}"),
            );
            report.write_calls = writes.load(Ordering::Relaxed);
            report.sync_calls = syncs.load(Ordering::Relaxed);
            report.finalize_status();
            return Ok(report);
        }
    };

    run_volume_subchecks(cx, &volume, &vbr_sector, limits, &mut report)?;
    report.write_calls = writes.load(Ordering::Relaxed);
    report.sync_calls = syncs.load(Ordering::Relaxed);
    report.finalize_status();
    Ok(report)
}

fn check_backup_boot(
    cx: &Cx,
    device: &dyn ByteDevice,
    base: u64,
    primary: &[u8],
    geometry: &NtfsGeometry,
    report: &mut NtfsCheckReport,
) -> Result<()> {
    let sector = u64::from(geometry.sector_bytes());
    let cluster = u64::from(geometry.cluster_bytes());
    let first = geometry.volume_bytes();
    let available = (report.backing_bytes - first) / sector;
    if available == 0 {
        report.push_issue(
            NtfsCheckCategory::Boot,
            "backup_boot_missing",
            None,
            None,
            format!("no complete backup boot sector after volume_bytes ({first})"),
        );
        return Ok(());
    }

    // mkntfs places the copy immediately after the declared sectors. ntfsresize
    // can round the declared size down to a cluster while writing the copy to
    // the actual partition end. Never treat an arbitrary container end as NTFS.
    let candidates = if first.is_multiple_of(cluster) {
        available.min(cluster / sector)
    } else {
        1
    };
    let mut backup = vec![0_u8; primary.len()];
    for i in 0..candidates {
        let offset = first + i * sector;
        device.read_exact_at(cx, ByteOffset(base + offset), &mut backup)?;
        if backup == primary {
            report.backup_boot_present = true;
            report.backup_boot_matches = Some(true);
            report.backup_boot_offset = Some(offset);
            return Ok(());
        }
    }
    report.backup_boot_matches = Some(false);
    if candidates == 1 {
        report.backup_boot_present = true;
        report.backup_boot_offset = Some(first);
        report.push_issue(
            NtfsCheckCategory::Boot,
            "backup_boot_mismatch",
            None,
            None,
            format!("backup boot sector at relative offset {first} disagrees with primary VBR"),
        );
    } else {
        report.push_issue(
            NtfsCheckCategory::Boot,
            "backup_boot_location_ambiguous",
            None,
            None,
            "no matching backup in the final partial cluster; cannot identify a repair target"
                .into(),
        );
    }
    Ok(())
}

fn empty_report(length: u64, writes: &AtomicU64, syncs: &AtomicU64) -> NtfsCheckReport {
    NtfsCheckReport {
        format: "NTFS",
        ntfs_version: [0, 0],
        read_only: true,
        write_calls: writes.load(Ordering::Relaxed),
        sync_calls: syncs.load(Ordering::Relaxed),
        status: NtfsCheckStatus::Corrupt,
        clean: false,
        complete: false,
        volume_flags: 0,
        hibernated: false,
        sector_bytes: 0,
        cluster_bytes: 0,
        volume_bytes: 0,
        backing_bytes: length,
        cluster_count: 0,
        mft_cluster: 0,
        mirror_cluster: 0,
        backup_boot_present: false,
        backup_boot_matches: None,
        backup_boot_offset: None,
        bad_clusters: 0,
        free_slots_examined: 0,
        free_slots_marked_in_use: 0,
        allocation: NtfsSubcheckSummary::default(),
        ownership: NtfsSubcheckSummary::default(),
        mirror: NtfsSubcheckSummary::default(),
        namespace: NtfsSubcheckSummary::default(),
        security: NtfsSubcheckSummary::default(),
        journal: None,
        issues: Vec::new(),
        omitted_issues: 0,
        scope_note: "Native non-mutating NTFS 3.0/3.1 structural checker (not Windows chkdsk; zero writes/syncs issued)",
    }
}

#[allow(clippy::too_many_lines)]
fn run_volume_subchecks(
    cx: &Cx,
    volume: &NtfsVolume,
    vbr_sector: &[u8],
    limits: NtfsCheckLimits,
    report: &mut NtfsCheckReport,
) -> Result<()> {
    report.ntfs_version = volume.version();
    report.volume_flags = volume.volume_flags;
    if volume.volume_flags & 0x0001 != 0 {
        report.push_issue(
            NtfsCheckCategory::Journal,
            "volume_dirty_flag",
            Some(3),
            None,
            format!(
                "$Volume has VOLUME_IS_DIRTY set ({:#06x})",
                volume.volume_flags
            ),
        );
    }
    if volume.volume_flags & !0x0001 != 0 {
        report.push_issue(
            NtfsCheckCategory::UnsupportedFeature,
            "volume_unsupported_flags",
            Some(3),
            None,
            format!(
                "$Volume carries flags beyond VOLUME_IS_DIRTY ({:#06x})",
                volume.volume_flags
            ),
        );
    }

    // 1. System metadata, unallocated slots, stream bounds, DOS/Win32, EA, reparse, hiberfil, $LogFile
    let deep = system_files::audit_system_and_records(cx, volume, vbr_sector, limits, report)?;
    report.hibernated = deep.hibernated;
    report.journal = deep.journal;
    report.free_slots_examined = deep.free_slots_examined;
    report.free_slots_marked_in_use = deep.free_slots_marked_in_use;

    // 2. Cluster allocation & $Bitmap reconciliation
    let alloc_limits = AllocationLimits {
        records: limits.records,
        clusters: limits.clusters,
        runs: limits.runs,
    };
    match volume.check_allocations_internal(cx, alloc_limits, true) {
        Ok(r) => {
            report.bad_clusters = r.bad_clusters;
            report.allocation = NtfsSubcheckSummary {
                consistent: r.is_consistent(),
                complete: r.complete,
                errors: r.errors,
                unsupported: r.unsupported,
                limit_reached: r.limit_reached.map(str::to_owned),
            };
            if !r.complete {
                report.complete = false;
            }
            for issue in r.issues {
                let cat = if issue.category == "unsupported" {
                    NtfsCheckCategory::UnsupportedFeature
                } else {
                    NtfsCheckCategory::Allocation
                };
                report.push_issue(
                    cat,
                    issue.category,
                    issue.record,
                    issue.first_cluster,
                    issue.detail,
                );
            }
        }
        Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
        Err(err) => {
            report.complete = false;
            report.push_issue(
                NtfsCheckCategory::Allocation,
                "allocation_check_failed",
                None,
                None,
                err.to_string(),
            );
        }
    }

    // 3. Base/extension record ownership
    let own_limits = RecordOwnershipLimits {
        records: limits.records,
        metadata_bytes: limits.metadata_bytes,
    };
    match volume.check_record_ownership_internal(cx, own_limits, true) {
        Ok(r) => {
            report.ownership = NtfsSubcheckSummary {
                consistent: r.is_consistent(),
                complete: r.complete,
                errors: r.errors,
                unsupported: r.unsupported,
                limit_reached: r.limit_reached.map(str::to_owned),
            };
            if !r.complete {
                report.complete = false;
            }
            for issue in r.issues {
                let cat = if issue.category == "unsupported" {
                    NtfsCheckCategory::UnsupportedFeature
                } else {
                    NtfsCheckCategory::RecordOwnership
                };
                report.push_issue(cat, issue.category, issue.record, None, issue.detail);
            }
        }
        Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
        Err(err) => {
            report.complete = false;
            report.push_issue(
                NtfsCheckCategory::RecordOwnership,
                "ownership_check_failed",
                None,
                None,
                err.to_string(),
            );
        }
    }

    // 4. $MFTMirr check
    match volume.check_mft_mirror_internal(cx, own_limits, true) {
        Ok(r) => {
            report.mirror = NtfsSubcheckSummary {
                consistent: r.is_consistent(),
                complete: r.complete,
                errors: r.errors,
                unsupported: r.unsupported,
                limit_reached: r.limit_reached.map(str::to_owned),
            };
            if !r.complete {
                report.complete = false;
            }
            for issue in r.issues {
                // Extended mirror tail differences (> record 3) are informational on Windows
                // large-cluster volumes unless they failed metadata parsing.
                if issue.category == "extended_mirror_difference" {
                    continue;
                }
                let cat = if issue.category == "unsupported" {
                    NtfsCheckCategory::UnsupportedFeature
                } else {
                    NtfsCheckCategory::MftMirror
                };
                report.push_issue(cat, issue.category, issue.record, None, issue.detail);
            }
        }
        Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
        Err(err) => {
            report.complete = false;
            report.push_issue(
                NtfsCheckCategory::MftMirror,
                "mirror_check_failed",
                Some(1),
                None,
                err.to_string(),
            );
        }
    }

    // 5. Namespace ($I30 <-> FILE_NAME & reachability)
    let ns_limits = NamespaceLimits {
        records: limits.records,
        metadata_bytes: limits.metadata_bytes,
        entries: limits.namespace_entries,
    };
    match volume.check_namespace_internal(cx, ns_limits, true) {
        Ok(r) => {
            report.namespace = NtfsSubcheckSummary {
                consistent: r.is_consistent(),
                complete: r.complete,
                errors: r.errors,
                unsupported: r.unsupported,
                limit_reached: r.limit_reached.map(str::to_owned),
            };
            if !r.complete {
                report.complete = false;
            }
            for issue in r.issues {
                let cat = if issue.category == "unsupported" {
                    NtfsCheckCategory::UnsupportedFeature
                } else {
                    NtfsCheckCategory::Namespace
                };
                report.push_issue(cat, issue.category, issue.record, None, issue.detail);
            }
        }
        Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
        Err(err) => {
            report.complete = false;
            report.push_issue(
                NtfsCheckCategory::Namespace,
                "namespace_check_failed",
                None,
                None,
                err.to_string(),
            );
        }
    }

    // 6. $Secure & security references
    let sec_limits = SecurityCheckLimits {
        entries: limits.security_entries,
        metadata_bytes: limits.metadata_bytes,
    };
    match volume.check_security_references_internal(cx, sec_limits, limits.records, true) {
        Ok(r) => {
            report.security = NtfsSubcheckSummary {
                consistent: r.is_consistent(),
                complete: r.complete,
                errors: r.errors,
                unsupported: r.unsupported,
                limit_reached: r.limit_reached.map(str::to_owned),
            };
            if !r.complete {
                report.complete = false;
            }
            for issue in r.issues {
                let cat = if issue.category == "unsupported" {
                    NtfsCheckCategory::UnsupportedFeature
                } else {
                    NtfsCheckCategory::Security
                };
                report.push_issue(cat, issue.category, Some(issue.record), None, issue.detail);
            }
        }
        Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
        Err(err) => {
            report.complete = false;
            report.push_issue(
                NtfsCheckCategory::Security,
                "security_check_failed",
                Some(9),
                None,
                err.to_string(),
            );
        }
    }

    Ok(())
}

impl NtfsVolume {
    /// Run the unified non-mutating structural checker on this already-opened
    /// read-only [`NtfsVolume`].
    ///
    /// Note: Because `NtfsVolume` bounds its view to `volume_bytes` (excluding
    /// the container's trailing backup boot sector), callers that have access
    /// to the full backing image or slice should prefer [`check_volume_device`]
    /// or [`check_image_file`] so the trailing backup boot sector is verified too.
    ///
    /// # Errors
    /// Returns an error on cancellation or unexpected device I/O error.
    pub fn check(&self, cx: &Cx, limits: NtfsCheckLimits) -> Result<NtfsCheckReport> {
        checkpoint(cx)?;
        let sector_len = usize::try_from(self.geometry.sector_bytes())
            .map_err(|_| FfsError::Format("sector_bytes overflow".into()))?;
        let mut vbr = vec![0_u8; sector_len];
        self.read_raw_volume_bytes(cx, 0, &mut vbr)?;
        let mut report = NtfsCheckReport {
            format: "NTFS",
            ntfs_version: self.version(),
            read_only: true,
            write_calls: 0,
            sync_calls: 0,
            status: NtfsCheckStatus::Clean,
            clean: false,
            complete: true,
            volume_flags: self.volume_flags,
            hibernated: false,
            sector_bytes: self.geometry.sector_bytes(),
            cluster_bytes: self.geometry.cluster_bytes(),
            volume_bytes: self.geometry.volume_bytes(),
            backing_bytes: self.geometry.volume_bytes(),
            cluster_count: self.geometry.cluster_count(),
            mft_cluster: self.geometry.mft_cluster(),
            mirror_cluster: self.geometry.mirror_cluster(),
            backup_boot_present: false,
            backup_boot_matches: None,
            backup_boot_offset: None,
            bad_clusters: 0,
            free_slots_examined: 0,
            free_slots_marked_in_use: 0,
            allocation: NtfsSubcheckSummary::default(),
            ownership: NtfsSubcheckSummary::default(),
            mirror: NtfsSubcheckSummary::default(),
            namespace: NtfsSubcheckSummary::default(),
            security: NtfsSubcheckSummary::default(),
            journal: None,
            issues: Vec::new(),
            omitted_issues: 0,
            scope_note: "Native non-mutating NTFS 3.0/3.1 structural checker on bounded NtfsVolume (backup boot sector lies outside volume_bytes; use check_volume_device for full container check)",
        };
        run_volume_subchecks(cx, self, &vbr, limits, &mut report)?;
        report.finalize_status();
        Ok(report)
    }
}
