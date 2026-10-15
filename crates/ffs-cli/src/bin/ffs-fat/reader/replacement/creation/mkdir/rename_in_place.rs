//! Rename in an existing name-set footprint without allocating directory slots.
//!
//! FAT16's fixed root cannot grow. Retire the source short entry durably before
//! changing its LFN checksum binding, then publish the new short entry last.
//! No data or directory cluster is allocated or released. Interrupted mutation
//! may leave an unreachable chain and require native recovery; this is not an
//! atomic rename or a persistent orphan protocol.

use super::super::super::super::{Directory, FatVolume, check::FatCheckReport};
use super::super::names::NativeName;
use super::{
    Slot, checkpoint, delete_entry_slots, directory_offsets, patch_slot, read_slot, rename_chain,
    retired_slot, set_dirty, validate_boot_state, validate_entry_slots, verify_retired_slot,
};
use anyhow::{Context, Result, bail};
use asupersync::Cx;
use ffs_error::FfsError;
use ffs_ondisk::fat::FatGeometry;
use serde_json::json;

/// Reserve the old name set plus immediately preceding deleted slots, in
/// logical directory order. Never consume an end marker or a live neighbor.
/// A failed partial reservation must not modify the source's retirement set.
pub(super) fn reserve_before(
    cx: &Cx,
    volume: &FatVolume,
    directory: Directory,
    short: &Slot,
    long: &[Slot],
    needed: usize,
) -> Result<Option<Vec<Slot>>> {
    checkpoint(cx)?;
    if needed > 20 || long.len() > 20 {
        bail!("rename exceeds the native long-name slot limit");
    }
    let mut reserved = Vec::new();
    reserved.try_reserve_exact(needed.max(long.len()))
        .context("reserving bounded rename name slots")?;
    for slot in long {
        reserved.push(Slot { offset: slot.offset, bytes: slot.bytes, fresh: slot.fresh });
    }
    if needed <= reserved.len() {
        return Ok(Some(reserved));
    }
    let (offsets, _) = directory_offsets(cx, volume, directory)?;
    let short_index = offsets.iter().position(|&offset| offset == short.offset)
        .context("rename source is not in its parent directory")?;
    let Some(mut index) = short_index.checked_sub(long.len()) else {
        bail!("rename long-name set extends before the parent directory");
    };
    for (ordinal, slot) in long.iter().enumerate() {
        if slot.offset != offsets[short_index - 1 - ordinal] {
            bail!("rename source name slots are not logically adjacent");
        }
    }
    while reserved.len() < needed {
        checkpoint(cx)?;
        let Some(previous) = index.checked_sub(1) else { return Ok(None); };
        let slot = read_slot(cx, volume, offsets[previous], false)?;
        if slot.bytes[0] != 0xE5 {
            return Ok(None);
        }
        reserved.push(slot);
        index = previous;
    }
    checkpoint(cx)?;
    Ok(Some(reserved))
}

/// Prepared by the ordinary rename preflight under the caller's operation gate.
/// `long` is ordered from the short entry backwards, not by physical address:
/// a fragmented directory can put a preceding logical slot at a higher address.
pub(super) struct Rename<'a> {
    pub from: &'a str,
    pub to: &'a str,
    pub leaf: &'a str,
    pub short: &'a Slot,
    pub long: &'a [Slot],
    pub name: &'a NativeName,
    pub chain: &'a [u32],
    pub before: &'a FatCheckReport,
}

impl Rename<'_> {
    fn verify_names(&self, cx: &Cx, volume: &FatVolume, encoded: &[[u8; 32]]) -> Result<()> {
        for (index, slot) in self.long.iter().enumerate() {
            checkpoint(cx)?;
            let expected = encoded.get(index).copied().unwrap_or_else(|| retired_slot(slot));
            if read_slot(cx, volume, slot.offset, false)?.bytes != expected {
                bail!("in-place rename LFN readback failed at {}", slot.offset);
            }
        }
        Ok(())
    }

    pub(super) fn execute(
        &self,
        cx: &Cx,
        volume: &FatVolume,
        dry_run: bool,
    ) -> Result<serde_json::Value> {
        checkpoint(cx)?;
        if self.name.long_slots() > self.long.len() {
            bail!("new FAT name does not fit the captured source slot set");
        }
        // Allocation checks intentionally permit dirty state inside a mutation.
        // Revalidate admission separately before writing even the dirty marker.
        let mut boot = [0; 512];
        volume.read_exact(cx, 0, &mut boot)?;
        let geometry = FatGeometry::parse(&boot, volume.geometry.volume_bytes())
            .map_err(|error| anyhow::anyhow!("invalid FAT rename geometry: {error}"))?;
        if geometry != volume.geometry {
            bail!("FAT geometry changed since the rename volume was opened");
        }
        volume.validate_admission(cx, &boot)?;
        validate_boot_state(cx, volume)?;
        validate_entry_slots(cx, volume, self.short, self.long)?;

        // Allocate all name staging memory before retirement. This is at most
        // twenty native LFN records, independent of file or directory size.
        let encoded: Vec<[u8; 32]> = (1..=self.name.long_slots())
            .map(|ordinal| self.name.slot(ordinal))
            .collect();
        let mut updated = self.short.bytes;
        updated[..11].copy_from_slice(&self.name.short);
        updated[12] = (updated[12] & !0x18) | self.name.flags;
        let mut report = json!({
            "operation": "rename",
            "dry_run": dry_run,
            "renamed": !dry_run,
            "replaced_existing": false,
            "reused_source_slots": true,
            "format": format!("{:?}", volume.geometry.kind()),
            "volume_offset": volume.base,
            "volume_bytes": volume.geometry.volume_bytes(),
            "from": self.from,
            "to": self.to,
            "old_entry_offset": self.short.offset,
            "new_entry_offset": self.short.offset,
            "released_clusters": 0,
            "new_parent_directory_clusters": 0,
            "free_clusters_after": self.before.free_clusters,
            "contract": "ordered native rename; interrupted mutation may require recovery; not atomic",
        });
        checkpoint(cx)?;
        if dry_run {
            return Ok(report);
        }

        let mut phase = "publishing dirty state";
        let result = (|| -> Result<serde_json::Value> {
            set_dirty(cx, volume, true)?;
            volume.device.sync(cx)?;

            phase = "retiring the old checksum-bound name set";
            delete_entry_slots(cx, volume, self.short, self.long)?;

            phase = "staging the new long name in retired source slots";
            // The closest old LFN slot is ordinal one. Retain that adjacency;
            // do not put the replacement at the far end of a larger old set.
            for (slot, bytes) in self.long.iter().zip(&encoded) {
                patch_slot(cx, volume, slot.offset, &retired_slot(slot), bytes)?;
            }
            if !encoded.is_empty() {
                volume.device.sync(cx)?;
            }
            self.verify_names(cx, volume, &encoded)?;
            // SFN/LFN writes can share a sector. A lost or misdirected staging
            // write must not resurrect the old alias before final publication.
            verify_retired_slot(cx, volume, self.short)?;

            phase = "publishing the renamed short entry";
            patch_slot(
                cx,
                volume,
                self.short.offset,
                &retired_slot(self.short),
                &updated,
            )?;
            volume.device.sync(cx)?;
            if read_slot(cx, volume, self.short.offset, false)?.bytes != updated {
                bail!("in-place rename short-entry publication failed readback");
            }
            self.verify_names(cx, volume, &encoded)?;

            phase = "verifying native name and unchanged allocation";
            let published = volume.resolve(cx, self.to)?.context("renamed destination is missing")?;
            if published.offset != self.short.offset
                || published.name()? != self.leaf
                || rename_chain(cx, volume, &published)?.as_slice() != self.chain
            {
                bail!("in-place rename changed the prepared name, slot or cluster chain");
            }
            match volume.resolve(cx, self.from) {
                Err(FfsError::NotFound(_)) => {}
                Err(error) => return Err(error.into()),
                Ok(_) => bail!("old name remains reachable after in-place rename"),
            }
            let verification = volume.check(cx)?;
            if !verification.clean
                || !verification.complete
                || !verification.namespace_complete
                || verification.free_clusters != self.before.free_clusters
                || verification.allocated_clusters != self.before.allocated_clusters
                || verification.files != self.before.files
                || verification.directories != self.before.directories
            {
                bail!("in-place rename verification failed: {}", serde_json::to_string(&verification)?);
            }
            // FSInfo is untouched: neither free allocation nor search hints
            // change. Directory contents (including . and ..) are also untouched.
            phase = "synchronizing final clean state";
            set_dirty(cx, volume, false)?;
            volume.device.sync(cx)?;
            report["durability"] = "namespace_allocation_and_clean_state_synced".into();
            report["verification"] = serde_json::to_value(verification)?;
            Ok(report)
        })();
        result.with_context(|| format!(
            "FAT in-place rename failed while {phase}; image retained and may be dirty or partially changed; no rollback or atomicity is claimed"
        ))
    }
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests;
    #[cfg(test)]
    mod slot_growth_tests;
}
