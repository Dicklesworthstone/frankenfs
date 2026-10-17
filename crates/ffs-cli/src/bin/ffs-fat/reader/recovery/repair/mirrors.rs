//! Explicit operator-selected FAT mirror reconciliation. No copy is guessed.
//! Preflight the chosen allocation interpretation through a private read-only
//! overlay, then copy only data-entry value bits. Never mount that overlay.

use super::{
    DiagnosticVolume, FatCheckReport, FatEntry, FatKind, FatVolume, ImageArgs, MAX_CHAIN_CLUSTERS,
    allocate, checkpoint, long_names::Names, set_hints, set_state, write_patch,
};
use anyhow::{Context, Result, bail};
use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_error::FfsError;
use ffs_types::ByteOffset;
use sha2::{Digest, Sha256};
use std::sync::Arc;

struct Shared(Arc<dyn ByteDevice>);

impl ByteDevice for Shared {
    fn len_bytes(&self) -> u64 {
        self.0.len_bytes()
    }
    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        self.0.read_exact_at(cx, at, bytes)
    }
    fn write_all_at(&self, cx: &Cx, at: ByteOffset, bytes: &[u8]) -> ffs_error::Result<()> {
        self.0.write_all_at(cx, at, bytes)
    }
    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        self.0.sync(cx)
    }
}

/// Only entries 2..=cluster_count+1 are projected. Reserved entries, BPBs,
/// FSInfo, each FAT32 high nibble and table padding retain their actual bytes.
struct Table {
    bytes: Vec<u8>,
    starts: [u64; 2],
    width: usize,
}

impl Table {
    fn project(&self, cx: &Cx, at: u64, bytes: &mut [u8]) -> ffs_error::Result<()> {
        let end = at
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| FfsError::Format("mirror projection range overflow".into()))?;
        for &start in &self.starts {
            let stop = start
                .checked_add(self.bytes.len() as u64)
                .ok_or_else(|| FfsError::Format("mirror table range overflow".into()))?;
            let begin = start.max(at);
            let stop = stop.min(end);
            if begin >= stop {
                continue;
            }
            for position in begin..stop {
                if (position - begin).is_multiple_of(4096) {
                    checkpoint(cx)?;
                }
                let index = (position - start) as usize;
                let target = &mut bytes[(position - at) as usize];
                let mask = if self.width == 4 && index % 4 == 3 {
                    0x0F
                } else {
                    0xFF
                };
                *target = (*target & !mask) | (self.bytes[index] & mask);
            }
        }
        checkpoint(cx)
    }
}

struct View {
    device: Arc<dyn ByteDevice>,
    table: Arc<Table>,
}

impl ByteDevice for View {
    fn len_bytes(&self) -> u64 {
        self.device.len_bytes()
    }
    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        self.device.read_exact_at(cx, at, bytes)?;
        self.table.project(cx, at.0, bytes)
    }
    fn write_all_at(&self, _: &Cx, _: ByteOffset, _: &[u8]) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }
    fn sync(&self, _: &Cx) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }
}

struct Sector {
    offset: u64,
    first: bool,
    before: [u8; 32],
    after: [u8; 32],
    changed: bool,
}

// Dirty publication legitimately changes FAT[1]'s clean bit. Normalize ONLY
// that bit; do not normalize I/O-error bits, reserved bits, or any data entry.
fn fingerprint(kind: FatKind, first: bool, bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    if first {
        let (index, clean) = if kind == FatKind::Fat16 {
            (3, 0x80)
        } else {
            (7, 0x08)
        };
        digest.update(&bytes[..index]);
        digest.update([bytes[index] & !clean]);
        digest.update(&bytes[index + 1..]);
    } else {
        digest.update(bytes);
    }
    digest.finalize().into()
}

fn raw(bytes: &[u8]) -> u32 {
    let mut value = [0; 4];
    value[..bytes.len()].copy_from_slice(bytes);
    u32::from_le_bytes(value)
}

fn native_state(diagnostic: &DiagnosticVolume, cx: &Cx) -> Result<()> {
    for issue in diagnostic.native_state(cx)? {
        if !matches!(issue.kind, "native_boot_dirty" | "native_fat_dirty") {
            bail!(
                "mirror reconciliation refuses {}: {}",
                issue.kind,
                issue.detail
            );
        }
    }
    Ok(())
}

fn admissible(report: &FatCheckReport) -> Result<()> {
    if !report.complete || !report.namespace_complete || report.omitted_issues != 0 {
        bail!("selected FAT copy lacks complete, untruncated structural evidence");
    }
    for issue in &report.issues {
        if !matches!(
            issue.kind,
            "native_boot_dirty"
                | "native_fat_dirty"
                | "lost_allocation"
                | "fs_info_free_count"
                | "fs_info_next_free"
        ) {
            bail!(
                "selected FAT copy is not an admitted repair source: {}: {}",
                issue.kind,
                issue.detail
            );
        }
    }
    if report.lost_clusters.is_none() {
        bail!("selected FAT reachability is incomplete");
    }
    Ok(())
}

pub(super) struct MirrorPlan {
    diagnostic: DiagnosticVolume,
    device: Arc<dyn ByteDevice>,
    table: Arc<Table>,
    selected: FatCheckReport,
    names: Names,
    sectors: Vec<Sector>,
    copy: u8,
    different_entries: u64,
}

impl MirrorPlan {
    pub(super) fn prepare(
        cx: &Cx,
        diagnostic: DiagnosticVolume,
        copy: u8,
        args: &ImageArgs,
    ) -> Result<Self> {
        checkpoint(cx)?;
        let volume = &diagnostic.volume;
        let geometry = &volume.geometry;
        if !geometry.mirrored() || geometry.fat_count() != 2 || copy >= geometry.fat_count() {
            bail!(
                "mirror reconciliation requires two mirrored FATs and an explicit source copy 0 or 1; inactive FATs are not repair authority"
            );
        }
        if geometry.cluster_count() as usize > MAX_CHAIN_CLUSTERS {
            bail!("mirror reconciliation exceeds the allocation budget");
        }
        // Validate EVERY copy's reserved/error state before the overlay can
        // conceal disagreement. A bad hardware/error marker is not cleared.
        native_state(&diagnostic, cx)?;
        let width = geometry.kind().entry_bytes() as usize;
        let count = (geometry.cluster_count() as usize)
            .checked_mul(width)
            .context("mirror allocation size overflow")?;
        let mut bytes = allocate(count)?;
        let source = geometry
            .entry_offset(copy, 2)
            .map_err(|error| anyhow::anyhow!("invalid source FAT range: {error}"))?;
        volume.read_exact(cx, source, &mut bytes)?;
        let mut starts = [0; 2];
        for (index, start) in starts.iter_mut().enumerate() {
            *start = volume
                .base
                .checked_add(
                    geometry
                        .entry_offset(index as u8, 2)
                        .map_err(|error| anyhow::anyhow!("invalid mirror range: {error}"))?,
                )
                .context("mirror physical offset overflow")?;
        }
        let table = Arc::new(Table {
            bytes,
            starts,
            width,
        });
        let expected_geometry = geometry.clone();
        let expected_boot = diagnostic.boot;
        let device: Arc<dyn ByteDevice> = Arc::from(diagnostic.volume.device);
        let diagnostic =
            DiagnosticVolume::from_device(cx, Box::new(Shared(Arc::clone(&device))), args)?;
        if diagnostic.volume.geometry != expected_geometry || diagnostic.boot != expected_boot {
            bail!("volume geometry or boot record changed during mirror preflight");
        }
        let view = DiagnosticVolume::from_device(
            cx,
            Box::new(View {
                device: Arc::clone(&device),
                table: Arc::clone(&table),
            }),
            args,
        )?;
        let selected = view.report(cx)?;
        admissible(&selected)?;
        let names = Names::capture(cx, &view.volume)?;
        drop(view);

        let volume = &diagnostic.volume;
        let geometry = &volume.geometry;
        let size = geometry.sector_bytes() as usize;
        let per_copy = (count + 2 * width).div_ceil(size);
        let mut sectors = Vec::new();
        sectors
            .try_reserve_exact(
                per_copy
                    .checked_mul(2)
                    .context("mirror sector count overflow")?,
            )
            .context("reserving bounded mirror sector evidence")?;
        let mut original = allocate(size)?;
        let mut updated = allocate(size)?;
        let mut different_entries = 0_u64;
        for fat in 0..2_u8 {
            let start = geometry
                .entry_offset(fat, 2)
                .map_err(|error| anyhow::anyhow!("invalid FAT range: {error}"))?
                - (2 * width) as u64;
            for index in 0..per_copy {
                checkpoint(cx)?;
                let offset = start + (index * size) as u64;
                volume.read_exact(cx, offset, &mut original)?;
                updated.copy_from_slice(&original);
                table.project(cx, volume.base + offset, &mut updated)?;
                if fat == copy && original != updated {
                    bail!("selected FAT changed during mirror preflight");
                }
                for (old, new) in original
                    .chunks_exact(width)
                    .zip(updated.chunks_exact(width))
                {
                    if old != new {
                        if geometry.kind().decode_entry(raw(old)) == FatEntry::Bad {
                            bail!(
                                "selected copy would clear a native bad-cluster marker; refusing to erase media-error evidence"
                            );
                        }
                        different_entries += 1;
                    }
                }
                sectors.push(Sector {
                    offset,
                    first: index == 0,
                    changed: original != updated,
                    before: fingerprint(geometry.kind(), index == 0, &original),
                    after: fingerprint(geometry.kind(), index == 0, &updated),
                });
            }
        }
        let plan = Self {
            diagnostic,
            device,
            table,
            selected,
            names,
            sectors,
            copy,
            different_entries,
        };
        plan.validate(cx)?;
        Ok(plan)
    }

    fn view(&self, cx: &Cx) -> Result<DiagnosticVolume> {
        let volume = &self.diagnostic.volume;
        let (view, boot) = FatVolume::parse_volume(
            cx,
            Box::new(View {
                device: Arc::clone(&self.device),
                table: Arc::clone(&self.table),
            }),
            volume.base,
            volume.geometry.volume_bytes(),
        )?;
        let result = DiagnosticVolume {
            volume: view.with_oem_code_page(volume.oem_code_page()),
            boot,
        };
        result.validate_geometry(cx)?;
        Ok(result)
    }

    fn verify_sectors(&self, cx: &Cx, after: bool) -> Result<()> {
        let volume = &self.diagnostic.volume;
        let mut bytes = allocate(volume.geometry.sector_bytes() as usize)?;
        for sector in &self.sectors {
            checkpoint(cx)?;
            volume.read_exact(cx, sector.offset, &mut bytes)?;
            let expected = if after { sector.after } else { sector.before };
            if fingerprint(volume.geometry.kind(), sector.first, &bytes) != expected {
                bail!(
                    "mirror sector evidence changed at volume byte {}",
                    sector.offset
                );
            }
        }
        Ok(())
    }

    fn validate(&self, cx: &Cx) -> Result<()> {
        checkpoint(cx)?;
        let mut boot = [0; 512];
        self.diagnostic.volume.read_exact(cx, 0, &mut boot)?;
        if boot != self.diagnostic.boot {
            bail!("primary boot record changed after mirror preflight");
        }
        self.diagnostic.validate_geometry(cx)?;
        native_state(&self.diagnostic, cx)?;
        self.verify_sectors(cx, false)?;
        let view = self.view(cx)?;
        if Names::capture(cx, &view.volume)? != self.names {
            bail!("namespace changed after selected-copy preflight");
        }
        checkpoint(cx)?;
        Ok(())
    }

    pub(super) fn report(&self, dry_run: bool) -> serde_json::Value {
        serde_json::json!({
            "operation": "reconcile_fat_mirrors", "dry_run": dry_run,
            "authoritative_copy": self.copy, "changed": false,
            "different_entries": self.different_entries,
            "planned_fat_sector_writes": self.sectors.iter().filter(|sector| sector.changed).count(),
            "format": self.selected.format, "volume_offset": self.selected.volume_offset,
            "volume_bytes": self.selected.volume_bytes, "selected_view": self.selected,
            "file_contents_verified": false, "file_payloads_written": false,
            "contract": "operator-selected allocation interpretation, not automatic authority selection, payload repair, or atomic recovery"
        })
    }

    pub(super) fn execute(&self, cx: &Cx) -> Result<serde_json::Value> {
        self.validate(cx)?;
        let mut report = self.report(false);
        if self.different_entries == 0 {
            report["native_recovery_required"] = (!self.selected.clean).into();
            return Ok(report);
        }
        let volume = &self.diagnostic.volume;
        let size = volume.geometry.sector_bytes() as usize;
        let mut original = allocate(size)?;
        let mut updated = allocate(size)?;
        let mut phase = "persisting dirty state";
        let result = (|| -> Result<serde_json::Value> {
            set_state(cx, &self.diagnostic, true)?;
            volume.device.sync(cx)?;
            phase = "reconciling operator-selected FAT values";
            for sector in self.sectors.iter().filter(|sector| sector.changed) {
                checkpoint(cx)?;
                volume.read_exact(cx, sector.offset, &mut original)?;
                if fingerprint(volume.geometry.kind(), sector.first, &original) != sector.before {
                    bail!("mirror changed before publication at {}", sector.offset);
                }
                updated.copy_from_slice(&original);
                self.table
                    .project(cx, volume.base + sector.offset, &mut updated)?;
                write_patch(cx, volume, sector.offset, &original, &updated)?;
            }
            volume.device.sync(cx)?;
            phase = "verifying reconciled mirrors and retained namespace";
            self.verify_sectors(cx, true)?;
            if Names::capture(cx, volume)? != self.names {
                bail!("mirror reconciliation changed retained namespace evidence");
            }
            set_hints(cx, volume, u32::try_from(self.selected.free_clusters)?)?;
            volume.device.sync(cx)?;
            let after = self.diagnostic.report(cx)?;
            admissible(&after)?;
            if after.conflicting_clusters != 0
                || after.free_clusters != self.selected.free_clusters
                || after.allocated_clusters != self.selected.allocated_clusters
                || after.bad_clusters != self.selected.bad_clusters
                || after.referenced_clusters != self.selected.referenced_clusters
                || after.preallocated_clusters != self.selected.preallocated_clusters
                || after.lost_clusters != self.selected.lost_clusters
                || after.files != self.selected.files
                || after.directories != self.selected.directories
            {
                bail!("reconciled image does not match the selected allocation interpretation");
            }
            let needs_recovery = after.lost_clusters != Some(0);
            if !needs_recovery {
                phase = "synchronizing final clean state";
                set_state(cx, &self.diagnostic, false)?;
                volume.device.sync(cx)?;
            }
            phase = "verifying final native state";
            self.verify_sectors(cx, true)?;
            if Names::capture(cx, volume)? != self.names {
                bail!("retained namespace changed during final mirror synchronization");
            }
            let verification = self.diagnostic.report(cx)?;
            admissible(&verification)?;
            if !needs_recovery && !verification.clean {
                bail!("mirror reconciliation did not finish cleanly");
            }
            if needs_recovery {
                let state = self.diagnostic.native_state(cx)?;
                let boots = 1 + usize::from(volume.geometry.backup_boot_sector().is_some());
                if state
                    .iter()
                    .filter(|issue| issue.kind == "native_boot_dirty")
                    .count()
                    != boots
                    || state
                        .iter()
                        .filter(|issue| issue.kind == "native_fat_dirty")
                        .count()
                        != 2
                {
                    bail!(
                        "unresolved lost allocation requires durable dirty state in every native copy"
                    );
                }
            }
            report["changed"] = true.into();
            report["native_recovery_required"] = needs_recovery.into();
            report["durability"] = "mirrors_and_reported_native_state_synced".into();
            report["verification"] = serde_json::to_value(verification)?;
            Ok(report)
        })();
        result.with_context(|| format!(
            "FAT mirror reconciliation failed while {phase}; image retained and may be dirty or partially changed; no rollback is claimed"
        ))
    }
}

#[cfg(test)]
mod projection_tests {
    use super::*;

    #[test]
    fn byte_windows_match_independent_entry_word_projection() {
        let cx = Cx::for_testing();
        for width in [2, 4] {
            let bytes: Vec<_> = (0..7_u32)
                .flat_map(|value| (0xC000_0000 | (value * 97 + 2)).to_le_bytes()[..width].to_vec())
                .collect();
            let table = Table {
                bytes,
                starts: [16, 80],
                width,
            };
            let original: Vec<u8> = (0_u32..128).map(|index| (index * 13 + 7) as u8).collect();
            let mut expected = original.clone();
            let mask = if width == 2 { 0xFFFF } else { 0x0FFF_FFFF };
            for start in [16, 80] {
                for index in 0..7 {
                    let at = start + index * width;
                    let old = raw(&expected[at..at + width]);
                    let value = raw(&table.bytes[index * width..(index + 1) * width]);
                    expected[at..at + width]
                        .copy_from_slice(&((old & !mask) | (value & mask)).to_le_bytes()[..width]);
                }
            }
            for start in 0..=128 {
                for end in start..=128 {
                    let mut actual = original[start..end].to_vec();
                    table.project(&cx, start as u64, &mut actual).unwrap();
                    assert_eq!(
                        actual,
                        expected[start..end],
                        "width {width}, {start}..{end}"
                    );
                }
            }
        }
    }

    #[test]
    fn projection_rejects_overflow_and_cancellation_before_patching() {
        let cx = Cx::for_testing();
        let table = Table {
            bytes: vec![0; 8],
            starts: [16, 80],
            width: 4,
        };
        let mut bytes = [0xAB; 4];
        assert!(table.project(&cx, u64::MAX - 1, &mut bytes).is_err());
        assert_eq!(bytes, [0xAB; 4]);
        cx.set_cancel_requested(true);
        assert!(matches!(
            table.project(&cx, 16, &mut bytes),
            Err(FfsError::Cancelled)
        ));
        assert_eq!(bytes, [0xAB; 4]);
    }
}
