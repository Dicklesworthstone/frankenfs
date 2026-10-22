//! Explicit FAT32 FSInfo reconstruction from complete native ownership evidence.
//! Hints never authorize allocation. Repair only the declared primary and an
//! already recognizable conventional backup; never invent a reserved-sector use.

use super::{
    DiagnosticVolume, Directory, FatCheckReport, FatEntry, FatKind, FatVolume, Image,
    ImageArgs, MAX_DIRECTORY_SLOTS, RecoverArgs, StateSector, allocate, checkpoint,
    hex_digest, open, reject_sidecar, set_state, stable, write_patch,
};
use anyhow::{Context, Result, bail};
use asupersync::Cx;
use clap::Args;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::Arc;

const TRANSFER: usize = 64 * 1024;
const SIGNATURES: [(usize, u32); 3] = [
    (0, 0x4161_5252),
    (484, 0x6141_7272),
    (508, 0xAA55_0000),
];

#[derive(Debug, Args)]
pub struct RepairFsInfoArgs {
    #[command(flatten)]
    image: ImageArgs,
    /// Confirm exclusive offline ownership. Keep a separate image copy first.
    #[arg(long, required = true)]
    offline_image: bool,
    /// Diagnose and calculate exact replacement hints without writes or syncs.
    #[arg(long)]
    dry_run: bool,
}

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("bounded FSInfo word"))
}

fn recognized(bytes: &[u8]) -> bool {
    bytes.len() >= 512 && SIGNATURES.iter().all(|&(at, value)| word(bytes, at) == value)
}

fn permitted(report: &FatCheckReport, hints: bool) -> Result<()> {
    if !report.complete || !report.namespace_complete || report.omitted_issues != 0
        || report.lost_clusters.is_none()
    {
        bail!("FSInfo repair requires complete, untruncated allocation and namespace evidence");
    }
    for issue in &report.issues {
        let state = matches!(issue.kind, "native_boot_dirty" | "native_fat_dirty" | "lost_allocation");
        let hint = matches!(issue.kind, "fs_info_signature" | "fs_info_free_count" | "fs_info_next_free");
        if !state && !(hints && hint) {
            bail!("FSInfo repair refuses {}: {}", issue.kind, issue.detail);
        }
    }
    Ok(())
}

fn counts(report: &FatCheckReport) -> [u64; 13] {
    [
        report.volume_offset, report.volume_bytes, u64::from(report.data_clusters),
        report.scanned_clusters, report.free_clusters, report.allocated_clusters,
        report.bad_clusters, report.reserved_clusters, report.conflicting_clusters,
        report.referenced_clusters, report.preallocated_clusters, report.files,
        report.directories,
    ]
}

#[derive(Debug, PartialEq, Eq)]
struct Evidence {
    allocation: [u8; 32],
    namespace: [u8; 32],
    state: [u8; 32],
    next_free: u32,
}

impl Evidence {
    fn capture(cx: &Cx, diagnostic: &DiagnosticVolume, report: &FatCheckReport) -> Result<Self> {
        let volume = &diagnostic.volume;
        let geometry = &volume.geometry;
        let mut bytes = allocate(TRANSFER)?;
        let mut allocation = Sha256::new();
        let mut next_free = u32::MAX;
        let mut free = 0_u64;
        for (index, copy) in volume.copies().enumerate() {
            allocation.update([copy]);
            let width = geometry.kind().entry_bytes() as usize;
            let mut cluster = 2;
            while cluster < geometry.cluster_count() + 2 {
                checkpoint(cx)?;
                let entries = (geometry.cluster_count() + 2 - cluster).min((TRANSFER / width) as u32);
                let offset = geometry.entry_offset(copy, cluster)
                    .map_err(|error| anyhow::anyhow!("{error}"))?;
                let length = entries as usize * width;
                volume.read_exact(cx, offset, &mut bytes[..length])?;
                allocation.update(&bytes[..length]);
                if index == 0 {
                    for (local, raw) in bytes[..length].chunks_exact(4).enumerate() {
                        if geometry.kind().decode_entry(word(raw, 0)) == FatEntry::Free {
                            free += 1;
                            if next_free == u32::MAX { next_free = cluster + local as u32; }
                        }
                    }
                }
                cluster += entries;
            }
        }
        if free != report.free_clusters { bail!("FSInfo free-space evidence changed during preflight"); }
        // Retain every byte of allocated directory storage, including slack and
        // records after end markers. Raw names never need host conversion.
        let mut namespace = Sha256::new();
        let mut pending = VecDeque::from([(Directory::Root, 0_u16)]);
        let mut objects = 1_u64;
        let mut slots = 0_u64;
        let mut directories = 0_u64;
        let mut files = 0_u64;
        while let Some((directory, depth)) = pending.pop_front() {
            checkpoint(cx)?;
            if depth > 256 { bail!("FSInfo namespace depth budget exceeded"); }
            directories += 1;
            let first = match directory {
                Directory::Root => geometry.root_cluster(),
                Directory::Cluster(first) => first,
            };
            let chain = volume.allocation_chain(cx, first, 1, volume.cluster_offset(first)?,
                (MAX_DIRECTORY_SLOTS * 32).div_ceil(geometry.cluster_bytes() as usize))?;
            let added = chain.len() as u64 * u64::from(geometry.cluster_bytes()) / 32;
            if added > MAX_DIRECTORY_SLOTS as u64 { bail!("FSInfo directory budget exceeded"); }
            slots = slots.checked_add(added).filter(|total| *total <= 4_194_304)
                .context("FSInfo allocated-directory budget exceeded")?;
            namespace.update((chain.len() as u64).to_le_bytes());
            for cluster in chain {
                checkpoint(cx)?;
                let offset = volume.cluster_offset(cluster)?;
                namespace.update(offset.to_le_bytes());
                let length = geometry.cluster_bytes() as usize;
                let target = bytes.get_mut(..length)
                    .context("FSInfo directory cluster exceeds bounded transfer scratch")?;
                volume.read_exact(cx, offset, target)?;
                namespace.update(target);
            }
            for entry in volume.list(cx, directory)? {
                checkpoint(cx)?;
                objects += 1;
                if objects > 131_072 { bail!("FSInfo namespace object budget exceeded"); }
                if entry.native.is_directory() {
                    pending.try_reserve(1).context("reserving FSInfo directory traversal")?;
                    pending.push_back((entry.directory()?, depth + 1));
                } else { files += 1; }
            }
        }
        if files != report.files || directories != report.directories {
            bail!("FSInfo namespace counts changed during preflight");
        }
        let mut state = Sha256::new();
        let sectors = std::iter::once(0_u16).chain(geometry.backup_boot_sector())
            .map(|number| StateSector::boot(cx, diagnostic, number, true))
            .chain(volume.copies().map(|copy| StateSector::fat(cx, diagnostic, copy, true)));
        for sector in sectors {
            let mut sector = sector?;
            // Only native clean bits may legitimately change during this repair.
            sector.bytes[sector.byte] = sector.value;
            state.update(sector.offset.to_le_bytes());
            state.update(&sector.bytes);
        }
        Ok(Self {
            allocation: allocation.finalize().into(), namespace: namespace.finalize().into(),
            state: state.finalize().into(), next_free,
        })
    }
}

struct Sector {
    offset: u64,
    original: Vec<u8>,
    updated: Vec<u8>,
}

impl Sector {
    fn read(cx: &Cx, volume: &FatVolume, number: u16) -> Result<Self> {
        let offset = u64::from(number) * u64::from(volume.geometry.sector_bytes());
        let mut original = allocate(volume.geometry.sector_bytes() as usize)?;
        volume.read_exact(cx, offset, &mut original)?;
        Ok(Self { offset, updated: original.clone(), original })
    }

    fn rebuild(&mut self, free: u32, next: u32) {
        for (at, value) in SIGNATURES.into_iter().chain([(488, free), (492, next)]) {
            self.updated[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
    }

    fn verify(&self, cx: &Cx, volume: &FatVolume, after: bool) -> Result<()> {
        let mut actual = allocate(self.original.len())?;
        volume.read_exact(cx, self.offset, &mut actual)?;
        let expected = if after { &self.updated } else { &self.original };
        if &actual != expected { bail!("FSInfo sector changed or failed readback at {}", self.offset); }
        Ok(())
    }
}

pub(super) struct FsInfoPlan {
    before: FatCheckReport,
    evidence: Evidence,
    sectors: Vec<Sector>,
    backup: &'static str,
}

impl FsInfoPlan {
    pub(super) fn prepare(cx: &Cx, diagnostic: &DiagnosticVolume) -> Result<Self> {
        checkpoint(cx)?;
        let volume = &diagnostic.volume;
        let geometry = &volume.geometry;
        if geometry.kind() != FatKind::Fat32 { bail!("FSInfo reconstruction requires FAT32"); }
        let info = geometry.fs_info_sector().context("FAT32 BPB declares no FSInfo sector; no sector will be invented")?;
        if Some(info) == geometry.backup_boot_sector() {
            bail!("declared FSInfo overlaps the backup boot record");
        }
        let before = diagnostic.report(cx)?;
        permitted(&before, true)?;
        let evidence = Evidence::capture(cx, diagnostic, &before)?;
        let free = u32::try_from(before.free_clusters)?;
        let mut primary = Sector::read(cx, volume, info)?;
        primary.rebuild(free, evidence.next_free);
        let mut sectors = vec![primary];
        let reserved = u16::from_le_bytes([diagnostic.boot[14], diagnostic.boot[15]]);
        let mut backup = "not_declared_or_outside_reserved_region";
        if let Some(number) = geometry.backup_boot_sector().and_then(|boot| boot.checked_add(info))
            && number < reserved && number != info && Some(number) != geometry.backup_boot_sector()
        {
            let mut sector = Sector::read(cx, volume, number)?;
            if recognized(&sector.original) {
                sector.rebuild(free, evidence.next_free);
                backup = "recognized_hint_copy";
            } else {
                // Conventional location alone is not authority to overwrite an
                // unknown reserved sector, even when the primary is damaged.
                backup = "unrecognized_reserved_sector_preserved";
            }
            sectors.push(sector);
        }
        Ok(Self { before, evidence, sectors, backup })
    }

    fn validate(&self, cx: &Cx, diagnostic: &DiagnosticVolume, after: bool) -> Result<FatCheckReport> {
        let actual = diagnostic.report(cx)?;
        permitted(&actual, !after)?;
        if counts(&actual) != counts(&self.before) || actual.lost_clusters != self.before.lost_clusters
            || Evidence::capture(cx, diagnostic, &actual)? != self.evidence
        {
            bail!("FSInfo repair allocation, namespace or native-state evidence changed");
        }
        for sector in &self.sectors { sector.verify(cx, &diagnostic.volume, after)?; }
        checkpoint(cx)?;
        Ok(actual)
    }

    pub(super) fn report(&self, dry_run: bool) -> serde_json::Value {
        let sectors: Vec<_> = self.sectors.iter().map(|sector| {
            let old: [u8; 32] = Sha256::digest(&sector.original).into();
            let new: [u8; 32] = Sha256::digest(&sector.updated).into();
            serde_json::json!({
                "offset": sector.offset, "changed": sector.original != sector.updated,
                "signatures_were_valid": recognized(&sector.original),
                "previous_free_hint": word(&sector.original, 488),
                "previous_next_hint": word(&sector.original, 492),
                "before_sha256": hex_digest(&old), "after_sha256": hex_digest(&new)
            })
        }).collect();
        serde_json::json!({
            "operation": "rebuild_fat32_fsinfo", "dry_run": dry_run, "changed": false,
            "volume_offset": self.before.volume_offset, "volume_bytes": self.before.volume_bytes,
            "free_clusters": self.before.free_clusters, "next_free_cluster": self.evidence.next_free,
            "backup_policy": self.backup, "sectors": sectors, "before": self.before,
            "file_contents_verified": false, "allocation_links_written": false,
            "reclaimed_clusters": 0, "native_recovery_required": !self.before.clean,
            "contract": "advisory FSInfo reconstruction only; changed images remain dirty; no allocation reclamation, payload repair, rollback or atomicity"
        })
    }

    pub(super) fn execute(&self, cx: &Cx, diagnostic: &DiagnosticVolume) -> Result<serde_json::Value> {
        self.validate(cx, diagnostic, false)?;
        let mut report = self.report(false);
        if self.sectors.iter().all(|sector| sector.original == sector.updated) { return Ok(report); }
        let volume = &diagnostic.volume;
        let mut phase = "persisting dirty state";
        let result = (|| -> Result<()> {
            set_state(cx, diagnostic, true)?;
            // Recheck evidence after the state barrier, before modifying a hint.
            self.validate(cx, diagnostic, false)?;
            phase = "rebuilding declared FSInfo and recognized backup hints";
            for sector in self.sectors.iter().filter(|sector| sector.original != sector.updated) {
                write_patch(cx, volume, sector.offset, &sector.original, &sector.updated)?;
                volume.device.sync(cx)?;
                sector.verify(cx, volume, true)?;
            }
            phase = "verifying retained ownership and rebuilt hints";
            let after = self.validate(cx, diagnostic, true)?;
            let state = diagnostic.native_state(cx)?;
            let markers = 1 + usize::from(volume.geometry.backup_boot_sector().is_some()) + volume.copies().count();
            if state.len() != markers || state.iter().any(|issue|
                !matches!(issue.kind, "native_boot_dirty" | "native_fat_dirty"))
            {
                bail!("FSInfo repair did not retain every native dirty marker");
            }
            report["changed"] = true.into();
            report["native_recovery_required"] = true.into();
            report["verification"] = serde_json::to_value(after)?;
            report["durability"] = "fsinfo_sectors_synced_and_verified_image_left_dirty".into();
            Ok(())
        })();
        result.with_context(|| format!("FSInfo repair failed while {phase}; image retained and may be dirty or partially repaired; no rollback or cleanup writes"))?;
        Ok(report)
    }
}

/// Repair advisory metadata only. This command never grants ordinary writer
/// admission, clears dirty state, or chooses an allocation owner for repair.
pub fn repair_fsinfo(cx: &Cx, args: &RepairFsInfoArgs) -> Result<serde_json::Value> {
    checkpoint(cx)?;
    if !args.offline_image { bail!("--offline-image is required for FSInfo repair"); }
    reject_sidecar(&args.image)?;
    let options = RecoverArgs {
        image: ImageArgs {
            image: args.image.image.clone(), offset: args.image.offset, length: args.image.length,
            oem_code_page: args.image.oem_code_page, sidecar: None,
        },
        offline_image: true, reclaim_lost: false, discard_orphan_lfn: false,
        repair_mirrors_from: None, repair_boot_from: None, salvage_to: None,
        dry_run: args.dry_run,
    };
    let (file, stamp) = open(&options)?;
    let diagnostic = DiagnosticVolume::from_device(cx, Box::new(Image {
        file: Arc::clone(&file), length: stamp.length, writable: !args.dry_run,
    }), &args.image)?;
    let plan = FsInfoPlan::prepare(cx, &diagnostic)?;
    stable(&file, &args.image.image, stamp)?;
    checkpoint(cx)?;
    if args.dry_run { return Ok(plan.report(true)); }
    plan.execute(cx, &diagnostic)
}
