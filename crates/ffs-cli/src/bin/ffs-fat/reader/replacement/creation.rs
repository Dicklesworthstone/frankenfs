//! Create-only namespace publication for the ordered offline FAT writer.
//!
//! Reserve the entire LFN/short-entry set before mutation. New directory
//! storage and the successor terminator become durable before any old end
//! marker is consumed. LFN slots precede a separately published short entry.
//! This is ordered native mutation, not an atomic namespace transaction.

mod mkdir;
mod names;
pub use mkdir::{
    MkdirArgs, RenameArgs, RmdirArgs, UnlinkArgs, mkdir_in_volume, rename_in_volume,
    rmdir_in_volume, run_mkdir, run_rename, run_rmdir, run_unlink, unlink_in_volume,
};

use super::super::{Directory, FatVolume, MAX_DIRECTORY_SLOTS};
use super::{
    EXPECT_END, Replacement, allocate, change_fat, checkpoint, hash_device, modified_timestamp,
    reserve_clusters, validate_boot_state, write_volume,
};
use anyhow::{Context, Result, bail};
use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_ondisk::fat::{FatEntry, FatKind};
use names::NativeName;

#[derive(Debug)]
struct Slot {
    offset: u64,
    bytes: [u8; 32],
    /// The extension initializer replaces these free-space bytes with zeroes.
    fresh: bool,
}

impl Slot {
    fn initialized(&self) -> [u8; 32] {
        if self.fresh { [0; 32] } else { self.bytes }
    }
}

#[derive(Debug)]
struct Extension {
    tail: u32,
    cluster: u32,
    additional: Option<u32>,
}

impl Extension {
    fn clusters(&self) -> impl Iterator<Item = u32> + Clone {
        std::iter::once(self.cluster).chain(self.additional)
    }
}

/// Extra native state required when free slots become a namespace entry set.
#[derive(Debug)]
pub(super) struct Namespace {
    successor: Option<Slot>,
    extension: Option<Extension>,
    entry: Slot,
    long_slots: Vec<Slot>,
    name: NativeName,
}

fn deleted_slot() -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[0] = 0xE5;
    bytes
}

fn patch_slot(
    cx: &Cx,
    volume: &FatVolume,
    offset: u64,
    expected: &[u8; 32],
    updated: &[u8; 32],
) -> Result<()> {
    let sector_bytes = u64::from(volume.geometry.sector_bytes());
    let start = offset / sector_bytes * sector_bytes;
    let within = (offset - start) as usize;
    let mut sector = allocate(sector_bytes as usize)?;
    volume.read_exact(cx, start, &mut sector)?;
    if &sector[within..within + 32] != expected {
        bail!("reserved directory slot changed before creation publication at {offset}");
    }
    sector[within..within + 32].copy_from_slice(updated);
    write_volume(cx, volume, start, &sector)
}

impl Namespace {
    pub(super) fn initial_entry(&self, _existing: [u8; 32]) -> [u8; 32] {
        self.entry.bytes
    }

    pub(super) fn directory_clusters(&self) -> usize {
        self.extension
            .as_ref()
            .map_or(0, |extension| extension.clusters().count())
    }

    pub(super) fn validate(&self, cx: &Cx, volume: &FatVolume) -> Result<()> {
        if let Some(extension) = &self.extension {
            let mut table = super::super::FatTable::new(volume);
            if table.entry(cx, extension.tail)? != FatEntry::End {
                bail!("directory extension tail changed after creation preflight");
            }
            for cluster in extension.clusters() {
                if table.entry(cx, cluster)? != FatEntry::Free {
                    bail!("directory extension allocation changed after creation preflight");
                }
            }
        }
        for slot in self
            .long_slots
            .iter()
            .chain(std::iter::once(&self.entry))
            .chain(self.successor.iter())
        {
            checkpoint(cx)?;
            let mut current = [0; 32];
            volume.read_exact(cx, slot.offset, &mut current)?;
            if current != slot.bytes {
                bail!(
                    "reserved directory slot changed after creation preflight at {}",
                    slot.offset
                );
            }
        }
        checkpoint(cx)?;
        Ok(())
    }

    pub(super) fn stage(&self, cx: &Cx, volume: &FatVolume) -> Result<()> {
        if let Some(extension) = &self.extension {
            let bytes = allocate(volume.geometry.cluster_bytes() as usize)?;
            for cluster in extension.clusters() {
                write_volume(cx, volume, volume.cluster_offset(cluster)?, &bytes)?;
            }
            volume.device.sync(cx)?;
            let end = match volume.geometry.kind() {
                FatKind::Fat16 => 0xFFFF,
                FatKind::Fat32 => 0x0FFF_FFFF,
            };
            let changes = extension.clusters().enumerate().map(|(index, cluster)| {
                let next = if index == 0 {
                    extension.additional.unwrap_or(end)
                } else {
                    end
                };
                (cluster, 0, next)
            });
            change_fat(cx, volume, &changes)?;
            volume.device.sync(cx)?;
            // All new directory links are durable before an existing parent
            // can reach any of them. No data/namespace slot moves are needed.
            change_fat(
                cx,
                volume,
                &std::iter::once((extension.tail, EXPECT_END, extension.cluster)),
            )?;
            volume.device.sync(cx)?;
        }
        if let Some(slot) = &self.successor {
            patch_slot(cx, volume, slot.offset, &slot.initialized(), &[0; 32])?;
            volume.device.sync(cx)?;
        }
        if self.long_slots.is_empty() {
            checkpoint(cx)?;
            return Ok(());
        }

        // A reusable run can start in deleted entries BEFORE the old end
        // marker. Preserve that actual marker too, not merely the first slot,
        // until all hidden slots are durably harmless. New directory clusters
        // have zero end markers after initialization, regardless of old bytes.
        let end_marker = self
            .long_slots
            .iter()
            .position(|slot| slot.initialized()[0] == 0);
        let deleted = deleted_slot();
        patch_slot(
            cx,
            volume,
            self.entry.offset,
            &self.entry.initialized(),
            &deleted,
        )?;
        for (index, slot) in self.long_slots.iter().enumerate().skip(1).rev() {
            if Some(index) != end_marker {
                patch_slot(cx, volume, slot.offset, &slot.initialized(), &deleted)?;
            }
        }
        volume.device.sync(cx)?;

        // Ordinal one is physically closest to the short entry. No old end
        // marker is consumed before the short/hidden-slot barrier above.
        for (index, slot) in self.long_slots.iter().enumerate().rev() {
            let expected = if index == 0 || Some(index) == end_marker {
                slot.initialized()
            } else {
                deleted
            };
            let bytes = self.name.slot(self.long_slots.len() - index);
            patch_slot(cx, volume, slot.offset, &expected, &bytes)?;
        }
        volume.device.sync(cx)?;
        for (index, slot) in self.long_slots.iter().enumerate() {
            let mut actual = [0; 32];
            volume.read_exact(cx, slot.offset, &mut actual)?;
            if actual != self.name.slot(self.long_slots.len() - index) {
                bail!("native long-name readback differs from the reserved name");
            }
        }
        checkpoint(cx)?;
        Ok(())
    }
}

fn parent(cx: &Cx, volume: &FatVolume, path: &str) -> Result<(Directory, String)> {
    if path.len() > 65_536
        || path.ends_with('/')
        || path.is_empty()
        || path
            .split('/')
            .filter(|part| !part.is_empty() && *part != ".")
            .take(257)
            .count()
            > 256
    {
        bail!("creation requires a bounded non-root native file path");
    }
    let (parent_path, name) = path.rsplit_once('/').unwrap_or(("", path));
    let directory = match volume.resolve(cx, parent_path)? {
        None => Directory::Root,
        Some(entry) => {
            let directory = entry.directory()?;
            if entry.native.attributes & 0xC9 != 0 {
                bail!("creation parent has read-only or unsupported native attributes");
            }
            directory
        }
    };
    Ok((directory, name.to_owned()))
}

pub(super) fn directory_offsets(
    cx: &Cx,
    volume: &FatVolume,
    directory: Directory,
) -> Result<(Vec<u64>, Option<u32>)> {
    let mut offsets = Vec::new();
    let tail;
    if directory == Directory::Root
        && let Some((start, length)) = volume.geometry.fixed_root()
    {
        let count = usize::try_from(length / 32).context("FAT root slot count overflow")?;
        if count > MAX_DIRECTORY_SLOTS {
            bail!("creation parent exceeds the directory-slot budget");
        }
        offsets
            .try_reserve_exact(count)
            .context("reserving bounded root slots")?;
        offsets.extend((start..start + length).step_by(32));
        tail = None;
    } else {
        let first = match directory {
            Directory::Root => volume.geometry.root_cluster(),
            Directory::Cluster(first) => first,
        };
        let bytes = volume.geometry.cluster_bytes() as usize;
        let chain = volume.allocation_chain(
            cx,
            first,
            1,
            volume.cluster_offset(first)?,
            (MAX_DIRECTORY_SLOTS * 32).div_ceil(bytes),
        )?;
        let count = chain
            .len()
            .checked_mul(bytes / 32)
            .context("FAT directory slot overflow")?;
        if count > MAX_DIRECTORY_SLOTS {
            bail!("creation parent exceeds the directory-slot budget");
        }
        offsets
            .try_reserve_exact(count)
            .context("reserving bounded directory slots")?;
        tail = chain.last().copied();
        for cluster in chain {
            checkpoint(cx)?;
            let start = volume.cluster_offset(cluster)?;
            offsets.extend((start..start + bytes as u64).step_by(32));
        }
    }
    checkpoint(cx)?;
    Ok((offsets, tail))
}

struct Reservation {
    slots: Vec<Slot>,
    successor: Option<Slot>,
    tail: Option<u32>,
    extra: usize,
}

fn read_slot(cx: &Cx, volume: &FatVolume, offset: u64, fresh: bool) -> Result<Slot> {
    let mut bytes = [0; 32];
    volume.read_exact(cx, offset, &mut bytes)?;
    Ok(Slot {
        offset,
        bytes,
        fresh,
    })
}

fn reserve_slots(
    cx: &Cx,
    volume: &FatVolume,
    directory: Directory,
    needed: usize,
) -> Result<Reservation> {
    let (offsets, tail) = directory_offsets(cx, volume, directory)?;
    let mut slots = Vec::with_capacity(needed);
    let mut after_end = false;
    let mut preceding_lfn = false;
    for (index, offset) in offsets.iter().copied().enumerate() {
        checkpoint(cx)?;
        let slot = read_slot(cx, volume, offset, false)?;
        after_end |= slot.bytes[0] == 0;
        if after_end || slot.bytes[0] == 0xE5 {
            if preceding_lfn {
                if after_end {
                    bail!(
                        "orphan long-name records precede the directory end; native checking is required"
                    );
                }
                preceding_lfn = false;
                slots.clear();
                continue;
            }
            slots.push(slot);
            if slots.len() == needed {
                let successor = if after_end {
                    offsets
                        .get(index + 1)
                        .map(|&offset| read_slot(cx, volume, offset, false))
                        .transpose()?
                } else {
                    None
                };
                return Ok(Reservation {
                    slots,
                    successor,
                    tail: None,
                    extra: 0,
                });
            }
        } else {
            slots.clear();
            preceding_lfn = slot.bytes[11] == 0x0F;
        }
    }
    if preceding_lfn {
        bail!("orphan long-name records at the directory tail forbid creation growth");
    }
    let tail =
        tail.context("full FAT16 fixed root cannot grow; no contiguous directory slot set")?;
    let per_cluster = volume.geometry.cluster_bytes() as usize / 32;
    let extra = (needed - slots.len()).div_ceil(per_cluster);
    if extra > 2
        || offsets
            .len()
            .checked_add(extra * per_cluster)
            .is_none_or(|count| count > MAX_DIRECTORY_SLOTS)
    {
        bail!("directory growth would exceed the admitted slot budget");
    }
    Ok(Reservation {
        slots,
        successor: None,
        tail: Some(tail),
        extra,
    })
}

pub(super) fn prepare(
    cx: &Cx,
    volume: &FatVolume,
    path: &str,
    source: &dyn ByteDevice,
    now: u64,
) -> Result<Replacement> {
    checkpoint(cx)?;
    let size = u32::try_from(source.len_bytes()).context("FAT file size exceeds 2^32 - 1 bytes")?;
    let (date, time) = modified_timestamp(now)?;
    let (directory, name) = parent(cx, volume, path)?;
    let name = NativeName::plan(cx, volume, directory, &name)?;
    validate_boot_state(cx, volume)?;
    let before = volume.check(cx)?;
    if !before.clean || !before.complete || !before.namespace_complete {
        bail!(
            "creation requires a complete clean allocation/namespace check: {}",
            serde_json::to_string(&before)?
        );
    }
    let needed_slots = name.long_slots() + 1;
    let mut reservation = reserve_slots(cx, volume, directory, needed_slots)?;
    let needed = u64::from(size).div_ceil(u64::from(volume.geometry.cluster_bytes())) as usize;
    let total = needed
        .checked_add(reservation.extra)
        .context("creation allocation overflow")?;
    let mut clusters = reserve_clusters(cx, volume, total, before.free_clusters)?;
    let extension = if let Some(tail) = reservation.tail {
        let extra = clusters.split_off(needed);
        let cluster = *extra
            .first()
            .context("missing reserved directory cluster")?;
        for &cluster in &extra {
            let start = volume.cluster_offset(cluster)?;
            for offset in (start..start + u64::from(volume.geometry.cluster_bytes())).step_by(32) {
                if reservation.slots.len() < needed_slots {
                    reservation.slots.push(read_slot(cx, volume, offset, true)?);
                } else if reservation.successor.is_none() {
                    reservation.successor = Some(read_slot(cx, volume, offset, true)?);
                    break;
                }
            }
        }
        Some(Extension {
            tail,
            cluster,
            additional: extra.get(1).copied(),
        })
    } else {
        None
    };
    let entry = reservation
        .slots
        .pop()
        .context("missing reserved short-entry slot")?;
    let original = if name.long.is_empty() {
        entry.initialized()
    } else {
        deleted_slot()
    };
    let mut updated = [0; 32];
    updated[..11].copy_from_slice(&name.short);
    updated[11] = 0x20;
    updated[12] = name.flags;
    updated[13] = ((now % 2) * 100) as u8;
    updated[14..16].copy_from_slice(&time.to_le_bytes());
    updated[16..18].copy_from_slice(&date.to_le_bytes());
    updated[18..20].copy_from_slice(&date.to_le_bytes());
    updated[22..24].copy_from_slice(&time.to_le_bytes());
    updated[24..26].copy_from_slice(&date.to_le_bytes());
    let first = clusters.first().copied().unwrap_or(0);
    if volume.geometry.kind() == FatKind::Fat32 {
        updated[20..22].copy_from_slice(&((first >> 16) as u16).to_le_bytes());
    }
    updated[26..28].copy_from_slice(&(first as u16).to_le_bytes());
    updated[28..32].copy_from_slice(&size.to_le_bytes());
    let digest = hash_device(cx, source)?;
    checkpoint(cx)?;
    Ok(Replacement {
        path: path.to_owned(),
        entry_offset: entry.offset,
        old_size: 0,
        size,
        original,
        updated,
        clusters,
        release: Vec::new(),
        digest,
        free_after: before.free_clusters - total as u64,
        files: before
            .files
            .checked_add(1)
            .context("FAT file count overflow")?,
        directories: before.directories,
        creation: Some(Namespace {
            successor: reservation.successor,
            extension,
            entry,
            long_slots: reservation.slots,
            name,
        }),
    })
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests;
}
