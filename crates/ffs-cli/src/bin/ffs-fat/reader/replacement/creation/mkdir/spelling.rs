//! Native case-only renames, including transitions between SFN and LFN storage.
//!
//! A same-entry lookup is not always a no-op on a case-preserving filesystem.
//! Keep the native alias and payload allocation; reuse existing name slots when
//! possible and reserve complete new storage before retiring any old record.
//! Intermediate native states are dirty, not crash-atomic rename transactions.

use super::super::names::NativeName;
use super::super::super::super::{Directory, Entry, FatVolume};
use super::{
    Extension, Namespace, Slot, checkpoint, delete_entry_slots, deleted_slot,
    find_entry_slots, parent, patch_slot, read_slot, rename_chain, reserve_clusters,
    reserve_slots, retired_slot, set_dirty, set_hints, validate_boot_state,
    validate_entry_slots,
};
use anyhow::{Context, Result, bail};
use asupersync::Cx;
use ffs_ondisk::fat::{FatDirectoryDecoder, FatKind};

// Refuse a previously failed native operation before touching either BPB.
// The general checker intentionally ignores these bits during transactions.
fn clean_state(cx: &Cx, volume: &FatVolume) -> Result<()> {
    validate_boot_state(cx, volume)?;
    let (state_at, mask) = match volume.geometry.kind() {
        FatKind::Fat16 => (37, 0xFFFF_u32),
        FatKind::Fat32 => (65, 0x0FFF_FFFF),
    };
    for sector in std::iter::once(0_u16).chain(volume.geometry.backup_boot_sector()) {
        let offset = u64::from(sector) * u64::from(volume.geometry.sector_bytes());
        let mut boot = [0; 512];
        volume.read_exact(cx, offset, &mut boot)?;
        if boot[state_at] != 0 {
            bail!("case-only rename requires clean, understood native boot state");
        }
    }
    let width = volume.geometry.kind().entry_bytes() as usize;
    for copy in volume.copies() {
        let at = volume.geometry.entry_offset(copy, 2)
            .map_err(|error| anyhow::anyhow!("{error}"))? - width as u64;
        let mut bytes = [0; 4];
        volume.read_exact(cx, at, &mut bytes[..width])?;
        if u32::from_le_bytes(bytes) & mask != mask {
            bail!("case-only rename requires clean reserved FAT state in copy {copy}");
        }
    }
    Ok(())
}

enum Placement {
    Reuse(NativeName),
    Relocate(Namespace),
}

impl Placement {
    fn name(&self) -> &NativeName {
        match self {
            Self::Reuse(name) => name,
            Self::Relocate(namespace) => &namespace.name,
        }
    }

    fn offset(&self, original: &Slot) -> u64 {
        match self {
            Self::Reuse(_) => original.offset,
            Self::Relocate(namespace) => namespace.entry.offset,
        }
    }

    fn extra_clusters(&self) -> usize {
        match self {
            Self::Reuse(_) => 0,
            Self::Relocate(namespace) => namespace.directory_clusters(),
        }
    }
}

fn reserve_destination(
    cx: &Cx,
    volume: &FatVolume,
    directory: Directory,
    name: NativeName,
    free: u64,
) -> Result<Namespace> {
    let needed = name.long_slots() + 1;
    let mut reservation = reserve_slots(cx, volume, directory, needed)?;
    let clusters = reserve_clusters(cx, volume, reservation.extra, free)?;
    let extension = if let Some(tail) = reservation.tail {
        let cluster = *clusters.first().context("missing case-rename directory reservation")?;
        for &cluster in &clusters {
            let start = volume.cluster_offset(cluster)?;
            for offset in (start..start + u64::from(volume.geometry.cluster_bytes())).step_by(32) {
                if reservation.slots.len() < needed {
                    reservation.slots.push(read_slot(cx, volume, offset, true)?);
                } else if reservation.successor.is_none() {
                    reservation.successor = Some(read_slot(cx, volume, offset, true)?);
                    break;
                }
            }
        }
        Some(Extension { tail, cluster, additional: clusters.get(1).copied() })
    } else {
        None
    };
    let entry = reservation.slots.pop().context("missing case-rename short-entry slot")?;
    Ok(Namespace {
        successor: reservation.successor,
        extension,
        entry,
        long_slots: reservation.slots,
        name,
    })
}

pub(super) fn rename(
    cx: &Cx,
    volume: &FatVolume,
    from: &str,
    to: &str,
    source: &Entry,
    dry_run: bool,
) -> Result<serde_json::Value> {
    checkpoint(cx)?;
    clean_state(cx, volume)?;
    let (directory, leaf) = parent(cx, volume, to)?;
    let name = NativeName::case_change(volume, source, &leaf)?;
    let before = volume.check(cx)?;
    if !before.clean || !before.complete || !before.namespace_complete {
        bail!("case-only rename requires a complete clean allocation/namespace check");
    }
    let source_chain = rename_chain(cx, volume, source)?;
    let (short, mut long) = find_entry_slots(cx, volume, directory, source.offset)?;
    let expected_long = source.native.long_name.as_ref().map_or(0, |units| units.len().div_ceil(13));
    if long.len() != expected_long {
        bail!("case-only rename captured an inconsistent native long-name set");
    }
    let mut decoded = FatDirectoryDecoder::default()
        .push(&short.bytes, volume.geometry.kind())
        .map_err(|error| anyhow::anyhow!("{error}"))?
        .context("case-only rename target is not a native short entry")?;
    decoded.long_name.clone_from(&source.native.long_name);
    if decoded != source.native {
        bail!("case-only rename target changed after native lookup");
    }
    let placement = if let Some(slots) = super::rename_in_place::reserve_before(
        cx, volume, directory, &short, &long, name.long_slots(),
    )? {
        long = slots;
        Placement::Reuse(name)
    } else {
        Placement::Relocate(reserve_destination(cx, volume, directory, name, before.free_clusters)?)
    };
    let mut updated = short.bytes;
    // Keep the alias, timestamps, DOS attributes, EA index and all cluster bits.
    updated[12] = (updated[12] & !0x18) | placement.name().flags;
    let free_after = before.free_clusters.checked_sub(placement.extra_clusters() as u64)
        .context("case-only rename free-cluster accounting underflow")?;
    validate_entry_slots(cx, volume, &short, &long)?;
    if let Placement::Relocate(namespace) = &placement {
        namespace.validate(cx, volume)?;
    }
    checkpoint(cx)?;
    let mut report = serde_json::json!({
        "operation": "rename", "dry_run": dry_run, "renamed": !dry_run,
        "unchanged": false, "case_only": true, "replaced_existing": false,
        "from": from, "to": to,
        "format": format!("{:?}", volume.geometry.kind()),
        "volume_offset": volume.base, "volume_bytes": volume.geometry.volume_bytes(),
        "old_entry_offset": short.offset, "new_entry_offset": placement.offset(&short),
        "released_clusters": 0, "new_directory_clusters": placement.extra_clusters(),
        "free_clusters_after": free_after,
        "contract": "ordered native case-only rename; interruption may require recovery; not atomic"
    });
    if dry_run {
        return Ok(report);
    }
    let mut phase = "publishing dirty state";
    let result = (|| -> Result<serde_json::Value> {
        set_dirty(cx, volume, true)?;
        set_hints(cx, volume, u32::MAX)?;
        volume.device.sync(cx)?;
        match &placement {
            Placement::Reuse(_) if long.is_empty() => {
                // Pure SFN case flags fit the existing record, even on a full
                // FAT16 root. No transient unlink or new directory slot needed.
                phase = "publishing short-name case flags";
                patch_slot(cx, volume, short.offset, &short.bytes, &updated)?;
            }
            Placement::Reuse(name) => {
                phase = "retiring the old long-name set";
                delete_entry_slots(cx, volume, &short, &long)?;
                phase = "publishing the new long-name set";
                // Captured slots are ordered nearest to the short entry first.
                // Surplus old slots remain deleted, not attached to a neighbor.
                for (index, slot) in long.iter().take(name.long_slots()).enumerate() {
                    patch_slot(cx, volume, slot.offset, &retired_slot(slot), &name.slot(index + 1))?;
                }
                volume.device.sync(cx)?;
                for (index, slot) in long.iter().take(name.long_slots()).enumerate() {
                    if read_slot(cx, volume, slot.offset, false)?.bytes != name.slot(index + 1) {
                        bail!("case-only rename long-name readback differs from the requested spelling");
                    }
                }
                phase = "publishing the renamed short entry";
                patch_slot(cx, volume, short.offset, &retired_slot(&short), &updated)?;
            }
            Placement::Relocate(namespace) => {
                phase = "preparing complete new directory storage";
                namespace.stage(cx, volume)?;
                phase = "retiring the original spelling";
                // Both spellings have the SAME lookup key and alias. Do not
                // publish duplicate live owners and then try to resolve them.
                // Allocation remains owned until the new entry is published.
                delete_entry_slots(cx, volume, &short, &long)?;
                phase = "publishing the relocated name";
                let expected = if namespace.long_slots.is_empty() {
                    namespace.entry.initialized()
                } else {
                    deleted_slot()
                };
                patch_slot(cx, volume, namespace.entry.offset, &expected, &updated)?;
            }
        }
        volume.device.sync(cx)?;
        phase = "verifying native spelling and identity";
        let published = volume.resolve(cx, to)?.context("case-renamed native entry is missing")?;
        if published.offset != placement.offset(&short)
            || published.name()? != leaf
            || published.native.short_name != source.native.short_name
            || read_slot(cx, volume, published.offset, false)?.bytes != updated
            || rename_chain(cx, volume, &published)? != source_chain
        {
            bail!("case-only rename did not preserve its native alias, metadata and allocation");
        }
        phase = "checking completed namespace and allocation";
        set_hints(cx, volume, u32::try_from(free_after)?)?;
        volume.device.sync(cx)?;
        let verification = volume.check(cx)?;
        if !verification.clean || !verification.complete || !verification.namespace_complete
            || verification.free_clusters != free_after
            || verification.files != before.files
            || verification.directories != before.directories
            || verification.allocated_clusters != before.allocated_clusters + placement.extra_clusters() as u64
        {
            bail!("case-only rename verification failed: {}", serde_json::to_string(&verification)?);
        }
        phase = "synchronizing final clean state";
        set_dirty(cx, volume, false)?;
        volume.device.sync(cx)?;
        report["durability"] = "namespace_allocation_and_clean_state_synced".into();
        report["verification"] = serde_json::to_value(verification)?;
        Ok(report)
    })();
    result.with_context(|| format!(
        "FAT case-only rename failed while {phase}; image retained and may be dirty or partially changed; no rollback or atomicity is claimed"
    ))
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests;
}
