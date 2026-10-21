//! Exchange two existing native name bindings without temporary names or allocation.
//!
//! The caller holds the offline/mount writer gate through cache publication.
//! Runtime namespace exchange is serialized; native FAT has no crash-atomic
//! multi-sector exchange. Interrupted metadata can require explicit recovery,
//! but this operation never frees allocation or writes either object's payload.

use super::super::super::super::{Directory, Entry, FatVolume};
use super::{parent, raw_cluster, read_slot, rename_chain, set_dirty, write_volume};
use anyhow::{Context, Result, bail};
use asupersync::Cx;
use ffs_error::FfsError;
use ffs_ondisk::fat::{FatGeometry, FatKind};
use std::collections::BTreeMap;

struct Sector {
    original: Vec<u8>,
    updated: Vec<u8>,
}

/// At most two short entries and two native parent entries. Coalescing is
/// essential when both names share a sector: never overwrite the first update
/// with a stale read-modify-write for the second one.
#[derive(Default)]
struct Publication(BTreeMap<u64, Sector>);

impl Publication {
    fn add(
        &mut self,
        cx: &Cx,
        volume: &FatVolume,
        offset: u64,
        original: &[u8; 32],
        updated: &[u8; 32],
    ) -> Result<()> {
        let size = u64::from(volume.geometry.sector_bytes());
        let start = offset / size * size;
        let within = (offset - start) as usize;
        if !offset.is_multiple_of(32) || within + 32 > size as usize {
            bail!("unaligned native exchange directory record");
        }
        if let std::collections::btree_map::Entry::Vacant(slot) = self.0.entry(start) {
            let mut bytes = vec![0; size as usize];
            volume.read_exact(cx, start, &mut bytes)?;
            slot.insert(Sector {
                updated: bytes.clone(),
                original: bytes,
            });
        }
        let sector = self.0.get_mut(&start).context("missing exchange sector")?;
        if sector.original[within..within + 32] != *original
            || sector.updated[within..within + 32] != *original
        {
            bail!("exchange record changed or overlaps another prepared update");
        }
        sector.updated[within..within + 32].copy_from_slice(updated);
        Ok(())
    }

    fn verify(&self, cx: &Cx, volume: &FatVolume, published: bool) -> Result<()> {
        let mut bytes = vec![0; volume.geometry.sector_bytes() as usize];
        for (&offset, sector) in &self.0 {
            super::checkpoint(cx)?;
            volume.read_exact(cx, offset, &mut bytes)?;
            let expected = if published {
                &sector.updated
            } else {
                &sector.original
            };
            if &bytes != expected {
                bail!("exchange sector failed exact readback at {offset}");
            }
        }
        Ok(())
    }
}

fn moved_record(object: &[u8; 32], name: &[u8; 32]) -> [u8; 32] {
    let mut updated = *object;
    // Name, alias checksum binding and case flags belong to the destination.
    // Attributes, creation/access/modification times, EA index and data address
    // belong to the object. In particular, do not conflate bytes 11 and 12.
    updated[..11].copy_from_slice(&name[..11]);
    updated[12] = name[12];
    updated
}

fn invalid_ancestry() -> anyhow::Error {
    FfsError::Io(std::io::Error::from_raw_os_error(libc::EINVAL)).into()
}

fn check_ancestry(cx: &Cx, volume: &FatVolume, entry: &Entry, destination: &str) -> Result<()> {
    if !entry.native.is_directory() {
        return Ok(());
    }
    let path = destination
        .rsplit_once('/')
        .map_or("", |(parent, _)| parent);
    let mut directory = Directory::Root;
    for part in path
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
    {
        super::checkpoint(cx)?;
        let ancestor = volume.lookup(cx, directory, part)?;
        directory = ancestor.directory()?;
        if ancestor.native.first_cluster == entry.native.first_cluster {
            return Err(invalid_ancestry());
        }
    }
    Ok(())
}

fn parent_cluster(directory: Directory) -> u32 {
    match directory {
        Directory::Root => 0,
        Directory::Cluster(cluster) => cluster,
    }
}

fn stage_parent(
    cx: &Cx,
    volume: &FatVolume,
    publication: &mut Publication,
    entry: &Entry,
    old_parent: Directory,
    new_parent: Directory,
) -> Result<()> {
    if !entry.native.is_directory() || old_parent == new_parent {
        return Ok(());
    }
    let offset = volume.cluster_offset(entry.native.first_cluster)? + 32;
    let old = read_slot(cx, volume, offset, false)?;
    if old.bytes[..11] != *b"..         "
        || old.bytes[11] != 0x10
        || old.bytes[28..32] != [0; 4]
        || raw_cluster(volume.geometry.kind(), &old.bytes) != parent_cluster(old_parent)
    {
        bail!("exchange directory parent does not match its native ancestry");
    }
    let cluster = parent_cluster(new_parent);
    let mut updated = old.bytes;
    if volume.geometry.kind() == FatKind::Fat32 {
        let reserved = u16::from_le_bytes([updated[20], updated[21]]) & 0xF000;
        updated[20..22].copy_from_slice(&(reserved | (cluster >> 16) as u16).to_le_bytes());
    }
    updated[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
    publication.add(cx, volume, offset, &old.bytes, &updated)
}

/// Inspect raw state rather than assuming an acknowledged dirty-marker write
/// was stored. A failed final clean-state sync/readback is never success.
fn verify_state(cx: &Cx, volume: &FatVolume, dirty: bool) -> Result<()> {
    let geometry = &volume.geometry;
    let (state_at, mask, clean) = match geometry.kind() {
        FatKind::Fat16 => (37, 0xFFFF_u32, 0x8000_u32),
        FatKind::Fat32 => (65, 0x0FFF_FFFF, 0x0800_0000),
    };
    for number in std::iter::once(0_u16).chain(geometry.backup_boot_sector()) {
        let mut boot = [0; 512];
        volume.read_exact(
            cx,
            u64::from(number) * u64::from(geometry.sector_bytes()),
            &mut boot,
        )?;
        if boot[state_at] != u8::from(dirty) {
            bail!("native exchange boot state failed verification");
        }
    }
    let width = geometry.kind().entry_bytes() as usize;
    let expected = if dirty { mask & !clean } else { mask };
    for copy in volume.copies() {
        let at = geometry
            .entry_offset(copy, 2)
            .map_err(|e| anyhow::anyhow!("{e}"))?
            - width as u64;
        let mut bytes = [0; 4];
        volume.read_exact(cx, at, &mut bytes[..width])?;
        if u32::from_le_bytes(bytes) & mask != expected {
            bail!("native exchange reserved FAT state failed verification in copy {copy}");
        }
    }
    super::checkpoint(cx)?;
    Ok(())
}

impl FatVolume {
    /// Swap existing objects, including nonempty directories and different
    /// types, under the caller's writer gate. Names/aliases remain in place.
    /// No allocation, reclamation, payload writes or crash atomicity is implied.
    pub fn rename_exchange(
        &self,
        cx: &Cx,
        from: &str,
        to: &str,
        dry_run: bool,
    ) -> Result<serde_json::Value> {
        super::checkpoint(cx)?;
        let (from_dir, from_leaf) = parent(cx, self, from)?;
        let (to_dir, to_leaf) = parent(cx, self, to)?;
        let mut boot = [0; 512];
        self.read_exact(cx, 0, &mut boot)?;
        let geometry = FatGeometry::parse(&boot, self.geometry.volume_bytes())
            .map_err(|error| anyhow::anyhow!("invalid FAT exchange geometry: {error}"))?;
        if geometry != self.geometry {
            bail!("FAT exchange geometry changed since open");
        }
        self.validate_admission(cx, &boot)?;
        verify_state(cx, self, false)?;
        let from_entry = self.lookup(cx, from_dir, &from_leaf)?;
        let to_entry = self.lookup(cx, to_dir, &to_leaf)?;
        let mut report = serde_json::json!({
            "operation": "exchange", "dry_run": dry_run,
            "from": from, "to": to,
            "format": format!("{:?}", geometry.kind()),
            "volume_offset": self.base, "volume_bytes": geometry.volume_bytes(),
            "from_entry_offset": from_entry.offset, "to_entry_offset": to_entry.offset,
            "allocated_clusters": 0, "released_clusters": 0,
            "contract": "serialized native namespace exchange; interrupted metadata may require recovery; not crash-atomic"
        });
        if from_entry.offset == to_entry.offset {
            if from_dir != to_dir {
                bail!("exchange aliases have conflicting parent identities");
            }
            report["unchanged"] = true.into();
            super::checkpoint(cx)?;
            return Ok(report);
        }
        for entry in [&from_entry, &to_entry] {
            if entry.native.attributes & 1 != 0 {
                return Err(FfsError::PermissionDenied.into());
            }
            if entry.native.attributes & 0xC8 != 0 {
                return Err(FfsError::UnsupportedFeature(
                    "unsupported native exchange attributes".into(),
                )
                .into());
            }
        }
        check_ancestry(cx, self, &from_entry, to)?;
        check_ancestry(cx, self, &to_entry, from)?;
        let before = self.check(cx)?;
        if !before.clean || !before.complete || !before.namespace_complete {
            bail!("exchange requires complete clean allocation and namespace evidence");
        }
        let from_chain = rename_chain(cx, self, &from_entry)?;
        let to_chain = rename_chain(cx, self, &to_entry)?;
        let from_slot = read_slot(cx, self, from_entry.offset, false)?;
        let to_slot = read_slot(cx, self, to_entry.offset, false)?;
        let from_updated = moved_record(&to_slot.bytes, &from_slot.bytes);
        let to_updated = moved_record(&from_slot.bytes, &to_slot.bytes);
        let mut publication = Publication::default();
        publication.add(cx, self, from_slot.offset, &from_slot.bytes, &from_updated)?;
        publication.add(cx, self, to_slot.offset, &to_slot.bytes, &to_updated)?;
        stage_parent(cx, self, &mut publication, &from_entry, from_dir, to_dir)?;
        stage_parent(cx, self, &mut publication, &to_entry, to_dir, from_dir)?;
        publication.verify(cx, self, false)?;
        super::checkpoint(cx)?;
        report["unchanged"] = false.into();
        report["metadata_sectors"] = publication.0.len().into();
        if dry_run {
            return Ok(report);
        }

        let mut phase = "persisting dirty state";
        let result = (|| -> Result<serde_json::Value> {
            set_dirty(cx, self, true)?;
            self.device.sync(cx)?;
            verify_state(cx, self, true)?;
            publication.verify(cx, self, false)?;
            phase = "publishing exchanged bindings and native parents";
            for (&offset, sector) in &publication.0 {
                write_volume(cx, self, offset, &sector.updated)?;
            }
            self.device.sync(cx)?;
            publication.verify(cx, self, true)?;
            phase = "verifying exchanged objects and allocation";
            let at_from = self.lookup(cx, from_dir, &from_leaf)?;
            let at_to = self.lookup(cx, to_dir, &to_leaf)?;
            if at_from.offset != from_slot.offset
                || at_to.offset != to_slot.offset
                || at_from.name()? != from_entry.name()?
                || at_to.name()? != to_entry.name()?
                || at_from.native.short_name != from_entry.native.short_name
                || at_to.native.short_name != to_entry.native.short_name
                || rename_chain(cx, self, &at_from)? != to_chain
                || rename_chain(cx, self, &at_to)? != from_chain
            {
                bail!("exchange changed name bindings or prepared object allocation");
            }
            let after = self.check(cx)?;
            if !after.clean
                || !after.complete
                || !after.namespace_complete
                || after.free_clusters != before.free_clusters
                || after.allocated_clusters != before.allocated_clusters
                || after.referenced_clusters != before.referenced_clusters
                || after.preallocated_clusters != before.preallocated_clusters
                || after.files != before.files
                || after.directories != before.directories
            {
                bail!("exchange changed allocation or namespace consistency");
            }
            phase = "synchronizing and verifying clean state";
            set_dirty(cx, self, false)?;
            self.device.sync(cx)?;
            verify_state(cx, self, false)?;
            report["durability"] = "metadata_and_clean_state_synced".into();
            report["verification"] = serde_json::to_value(after)?;
            Ok(report)
        })();
        result.with_context(|| format!(
            "FAT exchange failed while {phase}; image retained and may be dirty or partially changed; no rollback or crash atomicity is claimed"
        ))
    }
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests;
}
