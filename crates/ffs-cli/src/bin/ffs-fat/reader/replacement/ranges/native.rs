//! Incremental native overwrites and growth. Retain the old chain and reserve
//! only missing clusters. Shrink uses the parent's verified reclamation path.
//!
//! Unlike the explicit offline replacement command, an overwrite changes live
//! data in place. A failed or interrupted operation can leave a partial overwrite
//! or leaked allocation and requires checking/recovery; it is not crash-atomic.

use super::super::super::{Entry, FatTable, FatVolume, FileChain, MAX_CHAIN_CLUSTERS};
use super::super::{
    EXPECT_END, HASH_BYTES, allocate, change_fat, checkpoint, modified_timestamp,
    reserve_clusters, set_dirty, set_hints, validate_boot_state, write_volume,
};
use super::EditSource;
use anyhow::{Context, Result, bail};
use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_error::FfsError;
use ffs_ondisk::fat::{FatEntry, FatKind};
use ffs_types::ByteOffset;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Observe attempts, not successes: a failing write can have changed a prefix,
/// and a failed sync leaves durability uncertain. Reads remain unchanged.
struct ObservedDevice {
    inner: Box<dyn ByteDevice>,
    epoch: Arc<AtomicU64>,
}

impl ByteDevice for ObservedDevice {
    fn len_bytes(&self) -> u64 {
        self.inner.len_bytes()
    }

    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        self.inner.read_exact_at(cx, at, bytes)
    }

    fn write_all_at(&self, cx: &Cx, at: ByteOffset, bytes: &[u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        self.epoch.fetch_add(1, Ordering::AcqRel);
        self.inner.write_all_at(cx, at, bytes)
    }

    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        self.epoch.fetch_add(1, Ordering::AcqRel);
        self.inner.sync(cx)
    }
}

impl FatVolume {
    /// Install once before exposing a mount. The adapter holds an exclusive
    /// operation gate across every mutation and its cache publication; the
    /// epoch lets it distinguish preflight refusal from uncertain publication.
    /// This retains the existing device/locks and introduces no backing I/O.
    pub fn with_mutation_observer(mut self) -> (Self, Arc<AtomicU64>) {
        let epoch = Arc::new(AtomicU64::new(0));
        self.device = Box::new(ObservedDevice {
            inner: self.device,
            epoch: Arc::clone(&epoch),
        });
        (self, epoch)
    }
}

struct Allocation {
    chain: Vec<u32>,
    added: Vec<u32>,
}

impl Allocation {
    fn prepare(cx: &Cx, volume: &FatVolume, old: &FileChain, size: u32, free: u64) -> Result<Self> {
        let needed = u64::from(size).div_ceil(u64::from(volume.geometry.cluster_bytes())) as usize;
        // Existing allocation and native preallocation are never relocated.
        let target = needed.max(old.clusters.len());
        if target > MAX_CHAIN_CLUSTERS {
            return Err(FfsError::NoSpace.into());
        }
        let extra = target - old.clusters.len();
        if extra as u64 > free {
            return Err(FfsError::NoSpace.into());
        }
        let added = reserve_clusters(cx, volume, extra, free)?;
        let mut chain = Vec::new();
        chain
            .try_reserve_exact(target)
            .context("reserving native range allocation")?;
        chain.extend_from_slice(&old.clusters);
        chain.extend_from_slice(&added);
        // Revalidate all retained links and reservations before any data
        // write. The mount's operation gate keeps this plan exclusive afterward.
        let mut table = FatTable::new(volume);
        for (index, &cluster) in old.clusters.iter().enumerate() {
            checkpoint(cx)?;
            let expected = old
                .clusters
                .get(index + 1)
                .map_or(FatEntry::End, |&next| FatEntry::Next(next));
            if table.entry(cx, cluster)? != expected {
                bail!("native range source allocation changed before mutation");
            }
        }
        for &cluster in &added {
            checkpoint(cx)?;
            if table.entry(cx, cluster)? != FatEntry::Free {
                bail!("native range reservation is no longer free");
            }
        }
        Ok(Self {
            chain,
            added,
        })
    }
}

/// Return the only logical interval that must be initialized or overwritten.
/// It contains patch bytes and/or bytes beyond the OLD EOF, never an unchanged
/// old prefix/suffix. Thus readback does not use already overwritten old data as
/// its own oracle, even though EditSource retains a view of the same device.
fn changed_range(old_size: u64, source: &EditSource<'_>) -> std::ops::Range<u64> {
    if source.patch.is_empty() {
        old_size..source.size.max(old_size)
    } else {
        source.patch_offset.min(old_size)..source.patch_end
    }
}

fn span(volume: &FatVolume, chain: &[u32], at: u64, remaining: u64) -> Result<(u64, usize)> {
    let cluster_bytes = u64::from(volume.geometry.cluster_bytes());
    let index = usize::try_from(at / cluster_bytes).context("native range cluster index overflow")?;
    let cluster = chain
        .get(index)
        .context("native range exceeds its prepared chain")?;
    let within = at % cluster_bytes;
    let offset = volume
        .cluster_offset(*cluster)?
        .checked_add(within)
        .context("native range physical offset overflow")?;
    let count = remaining.min(cluster_bytes - within).min(HASH_BYTES as u64) as usize;
    Ok((offset, count))
}

pub(super) fn apply(
    cx: &Cx,
    volume: &FatVolume,
    path: &str,
    entry: &Entry,
    old: &FileChain,
    source: &EditSource<'_>,
    now: u64,
) -> Result<()> {
    checkpoint(cx)?;
    if entry.native.is_directory() {
        return Err(FfsError::IsDirectory.into());
    }
    if entry.native.attributes & 1 != 0 {
        return Err(FfsError::PermissionDenied.into());
    }
    if entry.native.attributes & 0xC8 != 0 || old.size != entry.native.size {
        bail!("unsupported or stale native range target");
    }
    let size = u32::try_from(source.size).context("FAT range exceeds 4 GiB - 1")?;
    if size < old.size {
        bail!("native growth must not replace the verified shrink path");
    }
    let (date, time) = modified_timestamp(now)?;
    // The checker also runs inside dirty transactions, so clean allocation is
    // not clean-state admission. Recheck BPBs AND selected FAT reserved entries.
    let mut boot = [0; 512];
    volume.read_exact(cx, 0, &mut boot)?;
    volume.validate_admission(cx, &boot)?;
    validate_boot_state(cx, volume)?;
    let before = volume.check(cx)?;
    if !before.clean || !before.complete || !before.namespace_complete {
        bail!("native range update requires complete clean allocation and namespace: {}", serde_json::to_string(&before)?);
    }
    let allocation = Allocation::prepare(cx, volume, old, size, before.free_clusters)?;
    let free_after = before.free_clusters - allocation.added.len() as u64;
    let free_hint = u32::try_from(free_after).context("native range free count overflow")?;
    let end_marker = match volume.geometry.kind() {
        FatKind::Fat16 => 0xFFFF,
        FatKind::Fat32 => 0x0FFF_FFFF,
    };
    let mut original = [0; 32];
    volume.read_exact(cx, entry.offset, &mut original)?;
    let mut updated = original;
    let first = allocation.chain.first().copied().unwrap_or(0);
    if volume.geometry.kind() == FatKind::Fat32 {
        let high = u16::from_le_bytes([original[20], original[21]]) & 0xF000;
        updated[20..22].copy_from_slice(&(high | (first >> 16) as u16).to_le_bytes());
    }
    updated[26..28].copy_from_slice(&(first as u16).to_le_bytes());
    updated[28..32].copy_from_slice(&size.to_le_bytes());
    updated[22..24].copy_from_slice(&time.to_le_bytes());
    updated[24..26].copy_from_slice(&date.to_le_bytes());
    updated[11] |= 0x20;
    let sector_bytes = u64::from(volume.geometry.sector_bytes());
    let sector_start = entry.offset / sector_bytes * sector_bytes;
    let within = (entry.offset - sector_start) as usize;
    // Reserve scratch before dirty publication; neither payload nor gap size
    // affects memory use. Allocation/checker storage remains explicitly bounded.
    let mut sector = allocate(sector_bytes as usize)?;
    let mut sector_readback = allocate(sector_bytes as usize)?;
    let mut bytes = allocate(HASH_BYTES)?;
    let mut readback = allocate(HASH_BYTES)?;
    volume.read_exact(cx, sector_start, &mut sector)?;
    if sector[within..within + 32] != original {
        bail!("native range directory entry changed before mutation");
    }
    let changed = changed_range(u64::from(old.size), source);
    let mut phase = "publishing dirty state";
    let result = (|| -> Result<()> {
        set_dirty(cx, volume, true)?;
        set_hints(cx, volume, u32::MAX)?;
        volume.device.sync(cx)?;

        phase = "initializing growth and writing the requested range";
        // Newly allocated clusters, including their slack, must contain no bytes
        // from the previous owner before any live chain can reach them.
        bytes.fill(0);
        for &cluster in &allocation.added {
            let base = volume.cluster_offset(cluster)?;
            let mut at = 0_u64;
            let length = u64::from(volume.geometry.cluster_bytes());
            while at < length {
                let count = (length - at).min(HASH_BYTES as u64) as usize;
                write_volume(cx, volume, base + at, &bytes[..count])?;
                at += count as u64;
            }
        }
        let mut at = changed.start;
        while at < changed.end {
            let (physical, count) = span(volume, &allocation.chain, at, changed.end - at)?;
            source.read_exact_at(cx, ByteOffset(at), &mut bytes[..count])?;
            write_volume(cx, volume, physical, &bytes[..count])?;
            at += count as u64;
        }
        if !changed.is_empty() || !allocation.added.is_empty() {
            volume.device.sync(cx)?;
            phase = "verifying initialized range before allocation publication";
            at = changed.start;
            while at < changed.end {
                let (physical, count) = span(volume, &allocation.chain, at, changed.end - at)?;
                source.read_exact_at(cx, ByteOffset(at), &mut bytes[..count])?;
                volume.read_exact(cx, physical, &mut readback[..count])?;
                if bytes[..count] != readback[..count] {
                    bail!("native range data readback differs from the requested bytes");
                }
                at += count as u64;
            }
        }

        if !allocation.added.is_empty() {
            phase = "publishing initialized growth allocation";
            change_fat(
                cx,
                volume,
                &allocation.added.iter().copied().enumerate().map(|(index, cluster)| {
                    (cluster, 0, allocation.added.get(index + 1).copied().unwrap_or(end_marker))
                }),
            )?;
            volume.device.sync(cx)?;
            if let Some(&tail) = old.clusters.last() {
                change_fat(
                    cx,
                    volume,
                    &std::iter::once((tail, EXPECT_END, allocation.added[0])),
                )?;
                volume.device.sync(cx)?;
            }
        }

        phase = "publishing native length and metadata";
        volume.read_exact(cx, sector_start, &mut sector)?;
        if sector[within..within + 32] != original {
            bail!("native range directory entry changed before publication");
        }
        sector[within..within + 32].copy_from_slice(&updated);
        write_volume(cx, volume, sector_start, &sector)?;
        volume.device.sync(cx)?;
        volume.read_exact(cx, sector_start, &mut sector_readback)?;
        if sector_readback != sector {
            bail!("native range directory sector failed readback");
        }

        set_hints(cx, volume, free_hint)?;
        volume.device.sync(cx)?;

        phase = "verifying native range and namespace";
        let actual = volume
            .resolve(cx, path)?
            .context("native range target disappeared")?;
        let mut raw = [0; 32];
        volume.read_exact(cx, actual.offset, &mut raw)?;
        if actual.offset != entry.offset || raw != updated || actual.native.size != size {
            bail!("native range readback changed the file identity or metadata");
        }
        let actual_chain = volume.file_chain(cx, &actual)?;
        if actual_chain.clusters != allocation.chain {
            bail!("native range readback changed the prepared chain");
        }
        let after = volume.check(cx)?;
        if !after.clean
            || !after.complete
            || !after.namespace_complete
            || after.free_clusters != free_after
            || after.files != before.files
            || after.directories != before.directories
        {
            bail!("native range verification failed: {}", serde_json::to_string(&after)?);
        }
        phase = "synchronizing final clean state";
        set_dirty(cx, volume, false)?;
        volume.device.sync(cx)?;
        Ok(())
    })();
    result.with_context(|| format!("FAT range update failed while {phase}; image retained and may be dirty, partially overwritten or partially changed; no rollback or atomicity is claimed"))
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests;
}
