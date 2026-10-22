//! Repair recognizable dot records using independently checked rooted ownership.
//!
//! Never infer parentage from the damaged `..` pointer. Do not create missing
//! records, move entries, choose an owner of a cross-link, or reclaim allocation.
//! A changed image stays dirty: ordinary recovery is a separate operation.

use super::{
    DiagnosticVolume, Directory, FatCheckReport, FatKind, FatVolume, Image, ImageArgs,
    MAX_DIRECTORY_SLOTS, RecoverArgs, allocate, checkpoint, collect_lost, hex_digest, open,
    reject_sidecar, set_state, stable, write_patch,
};
use anyhow::{Context, Result, bail};
use asupersync::Cx;
use clap::Args;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;

const MAX_OBJECTS: u64 = 131_072;
const MAX_SLOTS: u64 = 4_194_304;
const TRANSFER: usize = 64 * 1024;

#[derive(Debug, Args)]
pub struct RepairParentsArgs {
    #[command(flatten)]
    image: ImageArgs,
    /// Confirm exclusive offline ownership. Retain a separate copy first.
    #[arg(long, required = true)]
    offline_image: bool,
    /// Check ownership and every proposed pointer correction without writing.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct Patch {
    offset: u64,
    original: [u8; 64],
    updated: [u8; 64],
}

#[derive(Debug, PartialEq, Eq)]
struct Evidence {
    patches: Vec<Patch>,
    namespace: [u8; 32],
    allocation: [u8; 32],
    native_state: [u8; 32],
    files: u64,
    directories: u64,
    storage_slots: u64,
}

/// Change only address bits, retaining the FAT16 EA word and FAT32 high nibble.
fn pointer(record: &mut [u8], kind: FatKind, cluster: u32) {
    if kind == FatKind::Fat32 {
        let reserved = u16::from_le_bytes([record[20], record[21]]) & 0xF000;
        record[20..22].copy_from_slice(&(reserved | (cluster >> 16) as u16).to_le_bytes());
    }
    record[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
}

fn corrected_prefix(bytes: &[u8], kind: FatKind, first: u32, parent: u32) -> Result<[u8; 64]> {
    let mut updated: [u8; 64] = bytes
        .get(..64)
        .context("directory lacks complete dot records")?
        .try_into()
        .expect("checked 64-byte prefix");
    for (index, (name, cluster)) in [(*b".          ", first), (*b"..         ", parent)]
        .into_iter()
        .enumerate()
    {
        let record = &mut updated[index * 32..(index + 1) * 32];
        // Refuse missing, deleted, substituted or malformed dot records. A
        // parent_link finding alone is not permission to overwrite a live file.
        if record[..11] != name || record[11] & 0xD8 != 0x10 || record[28..32] != [0; 4] {
            bail!("parent repair requires recognizable, zero-size native dot records");
        }
        pointer(record, kind, cluster);
    }
    Ok(updated)
}

fn permitted(report: &FatCheckReport, parent_links: bool) -> Result<()> {
    if !report.complete || !report.namespace_complete || report.omitted_issues != 0 {
        bail!("parent repair requires complete, untruncated ownership evidence");
    }
    for issue in &report.issues {
        if !(matches!(
            issue.kind,
            "native_boot_dirty" | "native_fat_dirty" | "lost_allocation"
        ) || (parent_links && issue.kind == "parent_link"))
        {
            bail!("parent repair refuses {}: {}", issue.kind, issue.detail);
        }
    }
    Ok(())
}

fn same_accounting(before: &FatCheckReport, after: &FatCheckReport) -> bool {
    before.volume_offset == after.volume_offset
        && before.volume_bytes == after.volume_bytes
        && before.data_clusters == after.data_clusters
        && before.scanned_clusters == after.scanned_clusters
        && before.free_clusters == after.free_clusters
        && before.allocated_clusters == after.allocated_clusters
        && before.bad_clusters == after.bad_clusters
        && before.reserved_clusters == after.reserved_clusters
        && before.conflicting_clusters == after.conflicting_clusters
        && before.referenced_clusters == after.referenced_clusters
        && before.preallocated_clusters == after.preallocated_clusters
        && before.lost_clusters == after.lost_clusters
        && before.files == after.files
        && before.directories == after.directories
        && before.fs_info_free_hint == after.fs_info_free_hint
}

fn verify_dirty(cx: &Cx, diagnostic: &DiagnosticVolume) -> Result<()> {
    let volume = &diagnostic.volume;
    let state = diagnostic.native_state(cx)?;
    let expected =
        1 + usize::from(volume.geometry.backup_boot_sector().is_some()) + volume.copies().count();
    if state.len() != expected
        || state
            .iter()
            .any(|issue| !matches!(issue.kind, "native_boot_dirty" | "native_fat_dirty"))
    {
        bail!("parent repair could not verify all native dirty markers");
    }
    // Check the actual boot records, not only the geometry retained on open.
    for number in std::iter::once(0_u16).chain(volume.geometry.backup_boot_sector()) {
        let mut bytes = [0; 512];
        volume.read_exact(
            cx,
            u64::from(number) * u64::from(volume.geometry.sector_bytes()),
            &mut bytes,
        )?;
        let geometry = ffs_ondisk::fat::FatGeometry::parse(&bytes, volume.geometry.volume_bytes())
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        if geometry != volume.geometry || bytes[21] != diagnostic.boot[21] {
            bail!("parent repair boot geometry changed");
        }
    }
    Ok(())
}

/// Hash all addressable allocation words in the selected copies, including
/// reserved high bits. Exclude only FAT[0..2], whose dirty state must change.
fn allocation_digest(cx: &Cx, volume: &FatVolume) -> Result<[u8; 32]> {
    let width = volume.geometry.kind().entry_bytes() as usize;
    let mut bytes = allocate(TRANSFER)?;
    let mut digest = Sha256::new();
    for copy in volume.copies() {
        digest.update([copy]);
        let mut cluster = 2_u32;
        let end = volume.geometry.cluster_count() + 2;
        while cluster < end {
            checkpoint(cx)?;
            let entries = (end - cluster).min((TRANSFER / width) as u32);
            let offset = volume
                .geometry
                .entry_offset(copy, cluster)
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            let length = entries as usize * width;
            volume.read_exact(cx, offset, &mut bytes[..length])?;
            digest.update(&bytes[..length]);
            cluster += entries;
        }
    }
    Ok(digest.finalize().into())
}

/// Dirty-state publication may share a sector with labels or FAT allocation.
/// Preserve all boot bytes and raw reserved words, normalizing ONLY clean bits.
fn state_digest(cx: &Cx, volume: &FatVolume) -> Result<[u8; 32]> {
    let size = volume.geometry.sector_bytes() as usize;
    let (state_at, clean) = match volume.geometry.kind() {
        FatKind::Fat16 => (37, 0x8000_u32),
        FatKind::Fat32 => (65, 0x0800_0000),
    };
    let mut bytes = allocate(size)?;
    let mut digest = Sha256::new();
    for number in std::iter::once(0_u16).chain(volume.geometry.backup_boot_sector()) {
        let offset = u64::from(number) * size as u64;
        volume.read_exact(cx, offset, &mut bytes)?;
        bytes[state_at] &= !1;
        digest.update(offset.to_le_bytes());
        digest.update(&bytes);
    }
    let width = volume.geometry.kind().entry_bytes() as usize;
    for copy in volume.copies() {
        let offset = volume
            .geometry
            .entry_offset(copy, 2)
            .map_err(|error| anyhow::anyhow!("{error}"))?
            - 2 * width as u64;
        volume.read_exact(cx, offset, &mut bytes[..2 * width])?;
        let mut word = [0; 4];
        word[..width].copy_from_slice(&bytes[width..2 * width]);
        let value = u32::from_le_bytes(word) | clean;
        bytes[width..2 * width].copy_from_slice(&value.to_le_bytes()[..width]);
        digest.update(offset.to_le_bytes());
        digest.update(&bytes[..2 * width]);
    }
    Ok(digest.finalize().into())
}

/// Fingerprint complete allocated directory storage, not just diagnostic
/// examples or display names. Normalize ONLY the two proposed pointer fields.
/// Include physical mappings so a same-count chain swap cannot pass as intact.
fn scan(cx: &Cx, volume: &FatVolume) -> Result<Evidence> {
    let mut evidence = Evidence {
        patches: Vec::new(),
        namespace: [0; 32],
        allocation: [0; 32],
        native_state: [0; 32],
        files: 0,
        directories: 0,
        storage_slots: 0,
    };
    let mut digest = Sha256::new();
    let mut pending = VecDeque::from([(Directory::Root, 0_u32, 0_u16)]);
    let mut visited = BTreeSet::new();
    if volume.geometry.kind() == FatKind::Fat32 {
        visited.insert(volume.geometry.root_cluster());
    }
    let mut objects = 1_u64;
    while let Some((directory, parent, depth)) = pending.pop_front() {
        checkpoint(cx)?;
        if depth > 256 {
            bail!("parent repair exceeds the directory-depth budget");
        }
        evidence.directories += 1;
        let fixed = if directory == Directory::Root {
            volume.geometry.fixed_root()
        } else {
            None
        };
        let mut offsets = Vec::new();
        let size;
        if let Some((start, length)) = fixed {
            size = volume.geometry.sector_bytes() as usize;
            offsets
                .try_reserve_exact((length / size as u64) as usize)
                .context("reserving fixed-root evidence")?;
            offsets.extend((start..start + length).step_by(size));
        } else {
            let first = match directory {
                Directory::Root => volume.geometry.root_cluster(),
                Directory::Cluster(first) => first,
            };
            size = volume.geometry.cluster_bytes() as usize;
            let chain = volume.allocation_chain(
                cx,
                first,
                1,
                volume.cluster_offset(first)?,
                (MAX_DIRECTORY_SLOTS * 32).div_ceil(size),
            )?;
            offsets
                .try_reserve_exact(chain.len())
                .context("reserving directory evidence")?;
            for cluster in chain {
                checkpoint(cx)?;
                offsets.push(volume.cluster_offset(cluster)?);
            }
        }
        let slots = offsets.len() as u64 * (size as u64 / 32);
        if slots > MAX_DIRECTORY_SLOTS as u64 {
            bail!("parent repair directory is too large");
        }
        evidence.storage_slots = evidence
            .storage_slots
            .checked_add(slots)
            .filter(|total| *total <= MAX_SLOTS)
            .context("parent repair directory budget exceeded")?;
        digest.update(b"directory");
        digest.update((offsets.len() as u64).to_le_bytes());
        let mut bytes = allocate(size)?;
        for (index, offset) in offsets.into_iter().enumerate() {
            checkpoint(cx)?;
            volume.read_exact(cx, offset, &mut bytes)?;
            if index == 0
                && let Directory::Cluster(first) = directory
            {
                let original: [u8; 64] =
                    bytes[..64].try_into().expect("complete directory cluster");
                let updated = corrected_prefix(&bytes, volume.geometry.kind(), first, parent)?;
                if original != updated {
                    if evidence.patches.len() as u64 >= MAX_OBJECTS {
                        bail!("parent repair patch budget exceeded");
                    }
                    evidence
                        .patches
                        .try_reserve(1)
                        .context("reserving parent repair evidence")?;
                    evidence.patches.push(Patch {
                        offset,
                        original,
                        updated,
                    });
                }
                bytes[..64].copy_from_slice(&updated);
            }
            digest.update(offset.to_le_bytes());
            digest.update(&bytes);
        }
        // The ordinary list ignores . and .. instead of following them. A
        // second root-based traversal derives ancestry from live name bindings.
        let expected_parent = match directory {
            Directory::Root => 0,
            Directory::Cluster(first) => first,
        };
        for entry in volume.list(cx, directory)? {
            checkpoint(cx)?;
            objects += 1;
            if objects > MAX_OBJECTS {
                bail!("parent repair object budget exceeded");
            }
            if entry.native.is_directory() {
                if depth == 256 || !visited.insert(entry.native.first_cluster) {
                    bail!("parent repair encountered a cycle or repeated directory owner");
                }
                pending
                    .try_reserve(1)
                    .context("reserving bounded parent traversal")?;
                pending.push_back((entry.directory()?, expected_parent, depth + 1));
            } else {
                evidence.files += 1;
            }
        }
    }
    evidence.namespace = digest.finalize().into();
    evidence.allocation = allocation_digest(cx, volume)?;
    evidence.native_state = state_digest(cx, volume)?;
    checkpoint(cx)?;
    Ok(evidence)
}

pub(super) struct ParentPlan {
    before: FatCheckReport,
    evidence: Evidence,
}

impl ParentPlan {
    pub(super) fn prepare(cx: &Cx, diagnostic: &DiagnosticVolume) -> Result<Self> {
        let before = diagnostic.report(cx)?;
        permitted(&before, true)?;
        // Independently rebuild ownership. The resulting list is evidence only:
        // this operation has NO authority to free or salvage its lost clusters.
        let _lost = collect_lost(cx, &diagnostic.volume, &before)?;
        let evidence = scan(cx, &diagnostic.volume)?;
        if evidence.files != before.files || evidence.directories != before.directories {
            bail!("parent repair namespace changed during preflight");
        }
        Ok(Self { before, evidence })
    }

    pub(super) fn report(&self, dry_run: bool) -> serde_json::Value {
        let repairs: Vec<_> = self
            .evidence
            .patches
            .iter()
            .map(|patch| {
                serde_json::json!({
                    "volume_offset": patch.offset,
                    "before_dot_records": patch.original.as_slice(),
                    "after_dot_records": patch.updated.as_slice(),
                })
            })
            .collect();
        serde_json::json!({
            "operation": "repair_native_parent_links", "dry_run": dry_run,
            "planned_directory_repairs": self.evidence.patches.len(),
            "repairs": repairs,
            "volume_offset": self.before.volume_offset, "volume_bytes": self.before.volume_bytes,
            "normalized_directory_sha256": hex_digest(&self.evidence.namespace),
            "allocation_sha256": hex_digest(&self.evidence.allocation),
            "normalized_native_state_sha256": hex_digest(&self.evidence.native_state),
            "before": self.before, "file_contents_verified": false,
            "contract": "offline pointer repair only; modified images remain dirty; no allocation reclamation, payload recovery, rollback or crash atomicity"
        })
    }

    pub(super) fn execute(
        &self,
        cx: &Cx,
        diagnostic: &DiagnosticVolume,
    ) -> Result<serde_json::Value> {
        checkpoint(cx)?;
        let current = diagnostic.report(cx)?;
        if serde_json::to_value(&current)? != serde_json::to_value(&self.before)?
            || scan(cx, &diagnostic.volume)? != self.evidence
        {
            bail!("parent repair evidence changed; no writes were attempted");
        }
        let mut report = self.report(false);
        if self.evidence.patches.is_empty() {
            report["changed"] = false.into();
            report["verification"] = serde_json::to_value(current)?;
            return Ok(report);
        }
        let volume = &diagnostic.volume;
        let size = volume.geometry.sector_bytes() as usize;
        let mut sector = allocate(size)?;
        let mut updated = allocate(size)?;
        let mut readback = allocate(size)?;
        let mut phase = "persisting dirty state";
        let result = (|| -> Result<()> {
            set_state(cx, diagnostic, true)?;
            volume.device.sync(cx)?;
            // Require every selected marker, not just one dirty finding. Do
            // not proceed after a dropped marker or late hard-error signal.
            verify_dirty(cx, diagnostic)?;
            if scan(cx, volume)? != self.evidence {
                bail!("parent repair evidence changed during dirty-state publication");
            }
            phase = "publishing verified native parent pointers";
            for patch in &self.evidence.patches {
                checkpoint(cx)?;
                volume.read_exact(cx, patch.offset, &mut sector)?;
                if sector[..64] != patch.original {
                    bail!("dot records changed before repair");
                }
                updated.copy_from_slice(&sector);
                updated[..64].copy_from_slice(&patch.updated);
                write_patch(cx, volume, patch.offset, &sector, &updated)?;
                volume.device.sync(cx)?;
                volume.read_exact(cx, patch.offset, &mut readback)?;
                if readback != updated {
                    bail!("parent repair sector failed durable readback");
                }
            }
            phase = "checking retained namespace and allocation";
            verify_dirty(cx, diagnostic)?;
            let after = diagnostic.report(cx)?;
            permitted(&after, false)?;
            let evidence = scan(cx, volume)?;
            if !same_accounting(&self.before, &after)
                || !evidence.patches.is_empty()
                || evidence.namespace != self.evidence.namespace
                || evidence.allocation != self.evidence.allocation
                || evidence.native_state != self.evidence.native_state
                || evidence.storage_slots != self.evidence.storage_slots
            {
                bail!("parent repair changed retained namespace, storage or ownership");
            }
            report["changed"] = true.into();
            report["repaired_directories"] = self.evidence.patches.len().into();
            report["left_dirty"] = true.into();
            report["durability"] =
                "parent_sectors_synced_and_verified_native_state_left_dirty".into();
            report["verification"] = serde_json::to_value(after)?;
            Ok(())
        })();
        result.with_context(|| format!(
            "FAT parent repair failed while {phase}; image retained and may be dirty or partly repaired; no rollback or cleanup writes"
        ))?;
        Ok(report)
    }
}

pub fn repair_parents(cx: &Cx, args: &RepairParentsArgs) -> Result<serde_json::Value> {
    checkpoint(cx)?;
    if !args.offline_image {
        bail!("--offline-image is required for parent repair");
    }
    reject_sidecar(&args.image)?;
    // Reuse the established regular-file, no-follow, identity and advisory-lock
    // policy without granting any other recovery mode. Dry-run opens read-only.
    let options = RecoverArgs {
        image: ImageArgs {
            image: args.image.image.clone(),
            offset: args.image.offset,
            length: args.image.length,
            oem_code_page: args.image.oem_code_page,
            sidecar: None,
        },
        offline_image: true,
        reclaim_lost: false,
        discard_orphan_lfn: false,
        repair_mirrors_from: None,
        repair_boot_from: None,
        salvage_to: None,
        dry_run: args.dry_run,
    };
    let (file, stamp) = open(&options)?;
    let diagnostic = DiagnosticVolume::from_device(
        cx,
        Box::new(Image {
            file: Arc::clone(&file),
            length: stamp.length,
            writable: !args.dry_run,
        }),
        &args.image,
    )?;
    let plan = ParentPlan::prepare(cx, &diagnostic)?;
    stable(&file, &args.image.image, stamp)?;
    checkpoint(cx)?;
    if args.dry_run {
        return Ok(plan.report(true));
    }
    plan.execute(cx, &diagnostic)
}
