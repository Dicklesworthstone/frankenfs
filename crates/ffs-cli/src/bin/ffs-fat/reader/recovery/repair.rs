//! Explicit, bounded structural recovery, not journal replay or payload repair.
//! Reclaim only allocation proven unreachable by complete independent namespace
//! walks. Never choose a conflicting FAT or guess an owner for a cross-link.

mod boot;
mod long_names;
mod mirrors;
mod salvage;

use super::{DiagnosticVolume, FatCheckReport, FatKind, FatVolume, ImageArgs, Stamp,
    checkpoint, corrupt, open_read_only, reject_sidecar, stable};
use super::super::{Directory, FatEntry, FatTable, MAX_CHAIN_CLUSTERS, MAX_DIRECTORY_SLOTS, allocate};
use anyhow::{Context, Result, bail};
use asupersync::{Cx, types::CancelKind};
use clap::Args;
use ffs_block::ByteDevice;
use ffs_error::FfsError;
use ffs_types::ByteOffset;
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Args)]
pub struct RecoverArgs {
    #[command(flatten)]
    image: ImageArgs,
    /// Confirm exclusive offline ownership; no kernel mount or unrelated writer.
    #[arg(long, required = true)]
    offline_image: bool,
    /// Discard clusters proven unreachable. Their former contents may be lost.
    /// Never repairs ambiguous ownership; use --salvage-to to preserve raw data.
    #[arg(long, conflicts_with = "salvage_to")]
    reclaim_lost: bool,
    /// Retire only long-name records proved to have no live short entry.
    /// Does not repair names attached to live files or authorize cluster loss.
    #[arg(long, conflicts_with = "salvage_to")]
    discard_orphan_lfn: bool,
    /// Reconcile mirrored allocation tables using this zero-based copy only.
    /// Conflicting allocation in other copies is discarded; payload integrity
    /// is not established. Inactive FAT32 tables are never repair candidates.
    #[arg(long, value_name = "COPY", conflicts_with_all = ["reclaim_lost", "discard_orphan_lfn", "salvage_to"])]
    repair_mirrors_from: Option<u8>,
    /// Restore one FAT32 boot sector from an explicitly selected native copy.
    /// Zero selects primary -> backup; otherwise supply the volume-relative
    /// BYTE offset of the backup -> primary. Changed images remain dirty.
    #[arg(long, value_name = "BYTE_OFFSET", conflicts_with_all = ["reclaim_lost", "discard_orphan_lfn", "repair_mirrors_from", "salvage_to"])]
    repair_boot_from: Option<u64>,
    /// Export unambiguous lost chains into a NEW private host directory.
    /// Leaves the image unchanged. Files include slack and may contain sensitive
    /// deleted data; original names and logical lengths cannot be inferred.
    #[arg(long, value_name = "DIRECTORY", conflicts_with = "reclaim_lost")]
    salvage_to: Option<PathBuf>,
    /// Perform every diagnosis and ownership preflight without writes or syncs.
    #[arg(long)]
    dry_run: bool,
}

struct Image {
    file: Arc<File>,
    length: u64,
    writable: bool,
}

impl Image {
    fn range(&self, offset: u64, len: usize) -> ffs_error::Result<()> {
        if offset.checked_add(len as u64).is_none_or(|end| end > self.length)
            || self.file.metadata()?.len() != self.length
        {
            return Err(corrupt(offset, "recovery image length or access range changed"));
        }
        Ok(())
    }
}

impl ByteDevice for Image {
    fn len_bytes(&self) -> u64 { self.length }
    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        self.range(offset.0, bytes.len())?;
        self.file.read_exact_at(bytes, offset.0)?;
        checkpoint(cx)
    }
    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, bytes: &[u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        if !self.writable { return Err(FfsError::ReadOnly); }
        self.range(offset.0, bytes.len())?;
        self.file.write_all_at(bytes, offset.0)?;
        checkpoint(cx)
    }
    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        if !self.writable { return Err(FfsError::ReadOnly); }
        self.file.sync_all()?;
        checkpoint(cx)
    }
}

fn open(args: &RecoverArgs) -> Result<(Arc<File>, Stamp)> {
    if args.dry_run || args.salvage_to.is_some() {
        let (file, stamp) = open_read_only(&args.image.image)?;
        return Ok((Arc::new(file), stamp));
    }
    let path = &args.image.image;
    let named = fs::symlink_metadata(path)?;
    if !named.is_file() || named.file_type().is_symlink() {
        bail!("FAT recovery requires an existing regular image, not a symlink or device");
    }
    let file = OpenOptions::new().read(true).write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || Stamp::of(&named) != Stamp::of(&metadata) {
        bail!("FAT recovery image changed while opening");
    }
    file.try_lock().map_err(|error| anyhow::anyhow!("cannot exclusively lock recovery image: {error}"))?;
    let stamp = Stamp::of(&metadata);
    stable(&file, path, stamp)?;
    Ok((Arc::new(file), stamp))
}

struct Plan {
    before: FatCheckReport,
    /// Ascending cluster ID and exact masked successor, never truncated findings.
    lost: Vec<(u32, u32)>,
    orphan_names: long_names::Names,
}

impl Plan {
    fn prepare(cx: &Cx, diagnostic: &DiagnosticVolume, allow_lost: bool, discard_orphan_lfn: bool) -> Result<Self> {
        let before = diagnostic.report(cx)?;
        if !before.complete || !before.namespace_complete || before.omitted_issues != 0 {
            bail!("recovery requires complete, untruncated allocation and namespace evidence");
        }
        for issue in &before.issues {
            if !matches!(issue.kind,
                "native_boot_dirty" | "native_fat_dirty" | "lost_allocation"
                | "fs_info_free_count" | "fs_info_next_free")
                && !(discard_orphan_lfn && issue.kind == "invalid_long_name")
            {
                bail!("recovery refuses {}: {}; no changes were made", issue.kind, issue.detail);
            }
        }
        let count = before.lost_clusters.context("lost-allocation evidence is unavailable")?;
        if count != 0 && !allow_lost {
            bail!("{count} unreachable clusters require --salvage-to to export raw data or explicit --reclaim-lost to discard allocation; retain a separate copy first");
        }
        // An aggregate invalid_long_name finding is NOT repair authority.
        // Independently classify every record set and preserve a fingerprint
        // of the complete retained namespace before accepting this exception.
        let orphan_names = if discard_orphan_lfn
            && before.issues.iter().any(|issue| issue.kind == "invalid_long_name")
        {
            long_names::Names::prepare(cx, &diagnostic.volume, &before)?
        } else {
            long_names::Names::default()
        };
        let lost = collect_lost(cx, &diagnostic.volume, &before)?;
        Ok(Self { before, lost, orphan_names })
    }

    fn report(&self, dry_run: bool) -> serde_json::Value {
        serde_json::json!({
            "operation": "recover_native_structure", "dry_run": dry_run,
            "format": self.before.format, "volume_offset": self.before.volume_offset,
            "volume_bytes": self.before.volume_bytes,
            "planned_reclaimed_clusters": self.lost.len(),
            "planned_retired_lfn_records": self.orphan_names.count(),
            "free_clusters_after": self.before.free_clusters + self.lost.len() as u64,
            "before": self.before,
            "file_contents_verified": false,
            "contract": "offline structural repair only; no payload restoration, transaction replay, atomicity or recovery of lost filenames"
        })
    }

    fn execute(&self, cx: &Cx, diagnostic: &DiagnosticVolume) -> Result<serde_json::Value> {
        checkpoint(cx)?;
        if self.before.clean {
            let mut report = self.report(false);
            report["changed"] = false.into();
            return Ok(report);
        }
        let volume = &diagnostic.volume;
        // Repeat the entire namespace proof before even setting a dirty bit.
        self.orphan_names.validate(cx, volume)?;
        let mut phase = "persisting native dirty state";
        let result = (|| -> Result<serde_json::Value> {
            set_state(cx, diagnostic, true)?;
            set_hints(cx, volume, u32::MAX)?;
            volume.device.sync(cx)?;
            phase = "retiring verified unbound long-name records";
            self.orphan_names.retire(cx, volume)?;
            phase = "reclaiming verified unreachable allocation";
            free_lost(cx, volume, &self.lost)?;
            let free_after = self.before.free_clusters + self.lost.len() as u64;
            set_hints(cx, volume, u32::try_from(free_after)?)?;
            volume.device.sync(cx)?;
            phase = "verifying repaired allocation and namespace";
            self.orphan_names.verify(cx, volume)?;
            let mut table = FatTable::new(volume);
            for &(cluster, _) in &self.lost {
                if table.entry(cx, cluster)? != FatEntry::Free {
                    bail!("reclaimed cluster {cluster} failed readback");
                }
            }
            let verification = volume.check(cx)?;
            if !verification.clean || !verification.complete || !verification.namespace_complete
                || verification.free_clusters != free_after
                || verification.allocated_clusters + self.lost.len() as u64 != self.before.allocated_clusters
                || verification.referenced_clusters != self.before.referenced_clusters
                || verification.files != self.before.files
                || verification.directories != self.before.directories
            {
                bail!("recovery readback changed reachable ownership or did not repair every finding");
            }
            // Structural success is not permission to erase a newly observed
            // hard error, surface-test request or unsupported native state.
            for issue in diagnostic.native_state(cx)? {
                if !matches!(issue.kind, "native_boot_dirty" | "native_fat_dirty") {
                    bail!("recovery cannot clear unexpected native state: {}", issue.kind);
                }
            }
            phase = "synchronizing final clean state";
            set_state(cx, diagnostic, false)?;
            volume.device.sync(cx)?;
            phase = "verifying clean reader admission";
            let mut boot = [0; 512];
            volume.read_exact(cx, 0, &mut boot)?;
            volume.validate_admission(cx, &boot)?;
            let verification = diagnostic.report(cx)?;
            if !verification.clean { bail!("recovery did not finish with a clean diagnostic report"); }
            let mut report = self.report(false);
            report["changed"] = true.into();
            report["reclaimed_clusters"] = self.lost.len().into();
            report["retired_lfn_records"] = self.orphan_names.count().into();
            report["durability"] = "repaired_metadata_and_clean_state_synced".into();
            report["verification"] = serde_json::to_value(verification)?;
            Ok(report)
        })();
        result.with_context(|| format!(
            "FAT recovery failed while {phase}; image retained and may be dirty or partially changed; no rollback is claimed"
        ))
    }
}

/// Reconstruct complete ownership instead of inferring freeable storage from
/// bounded diagnostic examples. The existing checker must already have ruled
/// out cross-links and incomplete reachability; recheck those invariants here.
fn collect_lost(cx: &Cx, volume: &FatVolume, before: &FatCheckReport) -> Result<Vec<(u32, u32)>> {
    let count = volume.geometry.cluster_count() as usize;
    if count > MAX_CHAIN_CLUSTERS { bail!("recovery allocation budget exceeded"); }
    let mut owners = allocate(count + 2)?;
    let mut pending = VecDeque::from([(Directory::Root, 0_u16)]);
    let mut objects = 1_u64;
    let mut files = 0_u64;
    let mut directories = 0_u64;
    let mut directory_slots = 0_u64;
    let mut referenced = 0_u64;
    while let Some((directory, depth)) = pending.pop_front() {
        checkpoint(cx)?;
        if depth > 256 { bail!("recovery directory-depth budget exceeded"); }
        directories += 1;
        let size = volume.directory_size(cx, directory)?;
        directory_slots = directory_slots.checked_add(size / 32).context("directory budget overflow")?;
        if directory_slots > 4_194_304 { bail!("recovery directory-slot budget exceeded"); }
        let first = match directory {
            Directory::Root if volume.geometry.kind() == FatKind::Fat16 => None,
            Directory::Root => Some(volume.geometry.root_cluster()),
            Directory::Cluster(cluster) => Some(cluster),
        };
        if let Some(first) = first {
            let chain = volume.allocation_chain(cx, first, 1, volume.cluster_offset(first)?,
                (MAX_DIRECTORY_SLOTS * 32).div_ceil(volume.geometry.cluster_bytes() as usize))?;
            referenced += mark_owned(cx, &mut owners, &chain)?;
        }
        for entry in volume.list(cx, directory)? {
            checkpoint(cx)?;
            objects += 1;
            if objects > 131_072 { bail!("recovery object budget exceeded"); }
            if entry.native.is_directory() {
                pending.try_reserve(1).context("reserving bounded recovery directory queue")?;
                pending.push_back((entry.directory()?, depth + 1));
            } else {
                files += 1;
                referenced += mark_owned(cx, &mut owners, &volume.file_chain(cx, &entry)?.clusters)?;
            }
        }
    }
    if files != before.files || directories != before.directories || referenced != before.referenced_clusters {
        bail!("namespace ownership changed during recovery preflight");
    }
    let mut lost = Vec::new();
    let expected = usize::try_from(before.lost_clusters.context("incomplete lost count")?)?;
    if expected > count { bail!("lost count exceeds geometry"); }
    lost.try_reserve_exact(expected).context("reserving bounded lost-allocation plan")?;
    let mut table = FatTable::new(volume);
    let mut free = 0_u64;
    for cluster in 2..=volume.geometry.cluster_count() + 1 {
        checkpoint(cx)?;
        let value = table.entry(cx, cluster)?;
        if value == FatEntry::Free { free += 1; }
        if owners[cluster as usize] == 0 && matches!(value, FatEntry::Next(_) | FatEntry::End) {
            if lost.len() == expected { bail!("lost allocation changed during recovery preflight"); }
            let copy = volume.copies().next().context("no selected FAT")?;
            lost.push((cluster, table.raw_entry(cx, copy, cluster)?));
        }
    }
    if lost.len() != expected || free != before.free_clusters {
        bail!("allocation changed during recovery preflight");
    }
    Ok(lost)
}

fn mark_owned(cx: &Cx, owners: &mut [u8], chain: &[u32]) -> Result<u64> {
    for &cluster in chain {
        checkpoint(cx)?;
        let owner = owners.get_mut(cluster as usize).context("owner lies outside recovery bitmap")?;
        if *owner != 0 { bail!("cross-linked ownership appeared during recovery preflight"); }
        *owner = 1;
    }
    Ok(chain.len() as u64)
}

/// Lowercase hex for a SHA-256 digest recorded in recovery reports.
fn hex_digest(digest: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(64);
    for byte in digest { write!(&mut text, "{byte:02x}").expect("format digest into String"); }
    text
}

fn write_patch(cx: &Cx, volume: &FatVolume, offset: u64, original: &[u8], updated: &[u8]) -> Result<()> {
    checkpoint(cx)?;
    let size = volume.geometry.sector_bytes() as usize;
    if original.len() != size || updated.len() != size || !offset.is_multiple_of(size as u64)
        || offset.checked_add(size as u64).is_none_or(|end| end > volume.geometry.volume_bytes())
    {
        bail!("recovery sector patch exceeds selected volume");
    }
    let mut actual = allocate(size)?;
    volume.read_exact(cx, offset, &mut actual)?;
    if actual != original { bail!("recovery metadata changed before publication at {offset}"); }
    if original == updated { return Ok(()); }
    let physical = volume.base.checked_add(offset).context("recovery physical offset overflow")?;
    volume.device.write_all_at(cx, ByteOffset(physical), updated)?;
    volume.read_exact(cx, offset, &mut actual)?;
    if actual != updated { bail!("recovery sector failed exact readback at {offset}"); }
    Ok(())
}

fn set_state(cx: &Cx, diagnostic: &DiagnosticVolume, dirty: bool) -> Result<()> {
    let volume = &diagnostic.volume;
    let geometry = &volume.geometry;
    let size = geometry.sector_bytes() as usize;
    let (at, mask, clean) = match geometry.kind() {
        FatKind::Fat16 => (37, 0xFFFF_u32, 0x8000_u32),
        FatKind::Fat32 => (65, 0x0FFF_FFFF, 0x0800_0000),
    };
    for sector in std::iter::once(0_u16).chain(geometry.backup_boot_sector()) {
        let offset = u64::from(sector) * size as u64;
        let mut original = allocate(size)?;
        volume.read_exact(cx, offset, &mut original)?;
        if original[at] & !1 != 0 { bail!("unsupported boot state appeared during recovery"); }
        let mut updated = original.clone();
        updated[at] = (updated[at] & !1) | u8::from(dirty);
        write_patch(cx, volume, offset, &original, &updated)?;
    }
    let width = geometry.kind().entry_bytes() as usize;
    for copy in volume.copies() {
        let offset = geometry.entry_offset(copy, 2)
            .map_err(|error| corrupt(0, error.to_string()))? - 2 * width as u64;
        let mut original = allocate(size)?;
        volume.read_exact(cx, offset, &mut original)?;
        let mut bytes = [0; 4];
        bytes[..width].copy_from_slice(&original[width..2 * width]);
        let raw = u32::from_le_bytes(bytes);
        if raw & mask & !clean != mask & !clean { bail!("reserved FAT error state appeared during recovery"); }
        let value = if dirty { raw & !clean } else { raw | clean };
        let mut updated = original.clone();
        updated[width..2 * width].copy_from_slice(&value.to_le_bytes()[..width]);
        write_patch(cx, volume, offset, &original, &updated)?;
    }
    Ok(())
}

fn set_hints(cx: &Cx, volume: &FatVolume, free: u32) -> Result<()> {
    let Some(sector) = volume.geometry.fs_info_sector() else { return Ok(()); };
    let size = volume.geometry.sector_bytes() as usize;
    let offset = u64::from(sector) * size as u64;
    let mut original = allocate(size)?;
    volume.read_exact(cx, offset, &mut original)?;
    if original[..4] != 0x4161_5252_u32.to_le_bytes()
        || original[484..488] != 0x6141_7272_u32.to_le_bytes()
        || original[508..512] != 0xAA55_0000_u32.to_le_bytes()
    { bail!("recovery refuses invalid FSInfo signatures"); }
    let mut updated = original.clone();
    updated[488..492].copy_from_slice(&free.to_le_bytes());
    updated[492..496].copy_from_slice(&u32::MAX.to_le_bytes());
    write_patch(cx, volume, offset, &original, &updated)
}

fn free_lost(cx: &Cx, volume: &FatVolume, lost: &[(u32, u32)]) -> Result<()> {
    let geometry = &volume.geometry;
    let size = geometry.sector_bytes() as usize;
    let width = geometry.kind().entry_bytes() as usize;
    let mask = if width == 2 { 0xFFFF_u32 } else { 0x0FFF_FFFF };
    for copy in volume.copies() {
        let mut position = None;
        let mut original = allocate(size)?;
        let mut updated = allocate(size)?;
        for &(cluster, expected) in lost {
            checkpoint(cx)?;
            let offset = geometry.entry_offset(copy, cluster)
                .map_err(|error| corrupt(0, error.to_string()))?;
            let start = offset / size as u64 * size as u64;
            if position != Some(start) {
                if let Some(previous) = position { write_patch(cx, volume, previous, &original, &updated)?; }
                volume.read_exact(cx, start, &mut original)?;
                updated.copy_from_slice(&original);
                position = Some(start);
            }
            let within = (offset - start) as usize;
            let mut bytes = [0; 4];
            bytes[..width].copy_from_slice(&original[within..within + width]);
            let raw = u32::from_le_bytes(bytes);
            if raw & mask != expected { bail!("lost allocation changed in FAT copy {copy} at cluster {cluster}"); }
            updated[within..within + width].copy_from_slice(&(raw & !mask).to_le_bytes()[..width]);
        }
        if let Some(last) = position { write_patch(cx, volume, last, &original, &updated)?; }
    }
    Ok(())
}

fn recover(cx: &Cx, args: &RecoverArgs) -> Result<serde_json::Value> {
    checkpoint(cx)?;
    if !args.offline_image { bail!("--offline-image is required for structural recovery"); }
    if args.repair_boot_from.is_some()
        && (args.reclaim_lost || args.discard_orphan_lfn || args.repair_mirrors_from.is_some()
            || args.salvage_to.is_some())
    {
        bail!("boot restoration is a separate operation; do not combine repair authorities");
    }
    if args.repair_mirrors_from.is_some()
        && (args.reclaim_lost || args.discard_orphan_lfn || args.salvage_to.is_some())
    {
        bail!("mirror reconciliation is a separate operation; do not combine it with allocation/name cleanup or salvage");
    }
    if args.reclaim_lost && args.salvage_to.is_some() {
        bail!("--salvage-to never modifies the image and cannot be combined with --reclaim-lost");
    }
    if args.discard_orphan_lfn && args.salvage_to.is_some() {
        bail!("--salvage-to is read-only and cannot be combined with --discard-orphan-lfn");
    }
    reject_sidecar(&args.image)?;
    let (file, stamp) = open(args)?;
    let device = Box::new(Image {
        file: Arc::clone(&file), length: stamp.length,
        writable: !args.dry_run && args.salvage_to.is_none(),
    });
    // A damaged primary cannot enter DiagnosticVolume::from_device until a
    // separately validated backup has supplied the private boot projection.
    if let Some(source) = args.repair_boot_from {
        let plan = boot::BootPlan::prepare(cx, device, &args.image, source)?;
        stable(&file, &args.image.image, stamp)?;
        checkpoint(cx)?;
        return if args.dry_run { Ok(plan.report(true)) } else { plan.execute(cx) };
    }
    let diagnostic = DiagnosticVolume::from_device(cx, device, &args.image)?;
    if let Some(copy) = args.repair_mirrors_from {
        let plan = mirrors::MirrorPlan::prepare(cx, diagnostic, copy, &args.image)?;
        stable(&file, &args.image.image, stamp)?;
        checkpoint(cx)?;
        return if args.dry_run { Ok(plan.report(true)) } else { plan.execute(cx) };
    }
    let plan = Plan::prepare(cx, &diagnostic,
        args.reclaim_lost || args.salvage_to.is_some(), args.discard_orphan_lfn)?;
    stable(&file, &args.image.image, stamp)?;
    checkpoint(cx)?;
    if let Some(output) = &args.salvage_to {
        let export = salvage::Salvage::prepare(cx, &diagnostic.volume, plan, output)?;
        stable(&file, &args.image.image, stamp)?;
        if args.dry_run { return Ok(export.report(true)); }
        return export.execute(cx, &diagnostic.volume, || stable(&file, &args.image.image, stamp));
    }
    if args.dry_run { return Ok(plan.report(true)); }
    plan.execute(cx, &diagnostic)
}

pub fn run(cx: &Cx, args: &RecoverArgs) -> Result<serde_json::Value> {
    let signal = cx.clone();
    ctrlc::set_handler(move || {
        signal.cancel_with(CancelKind::User, Some("FAT recovery interrupted"));
    })
        .context("installing FAT recovery cancellation handler; no mutation started")?;
    recover(cx, args)
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests;
}
