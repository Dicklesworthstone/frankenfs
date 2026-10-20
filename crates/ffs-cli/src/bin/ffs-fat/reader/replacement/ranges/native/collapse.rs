//! Remove whole logical clusters without copying any retained file payload.
//!
//! Hide EOF before splicing the chain: doing the splice first could expose
//! previously invisible preallocation through the old, larger size. Verify the
//! retained chain, publish its new EOF, then reclaim only removed clusters. The
//! caller owns the writer gate through cache publication. This is ordered FAT
//! mutation, not a crash-atomic collapse or a sparse-file implementation.

use super::{
    FatEntry, FatKind, FatTable, FatVolume, FfsError, allocate, change_fat, checkpoint,
    modified_timestamp, set_dirty, set_hints, validate_edit_state, write_volume,
};
use anyhow::{Context, Result, bail};
use asupersync::Cx;

fn invalid_range() -> FfsError {
    FfsError::Io(std::io::Error::from_raw_os_error(libc::EINVAL))
}

/// Always construct a fresh table after a write/sync; no pre-mutation FAT cache
/// can certify that the retained links are now durable and mutually consistent.
fn verify_chain(cx: &Cx, volume: &FatVolume, clusters: &[u32]) -> Result<()> {
    let mut table = FatTable::new(volume);
    for (index, &cluster) in clusters.iter().enumerate() {
        checkpoint(cx)?;
        let expected = clusters
            .get(index + 1)
            .map_or(FatEntry::End, |&next| FatEntry::Next(next));
        if table.entry(cx, cluster)? != expected {
            bail!("native collapse chain verification failed at cluster {cluster}");
        }
    }
    Ok(())
}

fn verify_target(
    cx: &Cx,
    volume: &FatVolume,
    path: &str,
    offset: u64,
    expected: &[u8; 32],
    clusters: &[u32],
) -> Result<()> {
    let entry = volume.resolve(cx, path)?.context("collapsed file disappeared")?;
    let mut record = [0; 32];
    volume.read_exact(cx, entry.offset, &mut record)?;
    if entry.offset != offset || record != *expected
        || clusters.first().copied() != Some(entry.native.first_cluster)
    {
        bail!("native collapse changed file identity or prepared metadata");
    }
    verify_chain(cx, volume, clusters)
}

pub(super) fn apply(
    cx: &Cx,
    volume: &FatVolume,
    path: &str,
    offset: u64,
    length: u64,
    now: u64,
) -> Result<()> {
    checkpoint(cx)?;
    let cluster_bytes = u64::from(volume.geometry.cluster_bytes());
    if length == 0 || !offset.is_multiple_of(cluster_bytes)
        || !length.is_multiple_of(cluster_bytes)
    {
        return Err(invalid_range().into());
    }
    let end = offset.checked_add(length).ok_or_else(invalid_range)?;
    let entry = volume.resolve(cx, path)?.ok_or(FfsError::IsDirectory)?;
    if entry.native.is_directory() {
        return Err(FfsError::IsDirectory.into());
    }
    if entry.native.attributes & 1 != 0 {
        return Err(FfsError::PermissionDenied.into());
    }
    if entry.native.attributes & 0xC8 != 0 {
        bail!("unsupported native attributes on collapse target");
    }
    // Removing the tail (or all bytes) is truncate, not COLLAPSE_RANGE. Requiring
    // a visible suffix also ensures the new first cluster is always defined.
    if end >= u64::from(entry.native.size) {
        return Err(invalid_range().into());
    }
    let (date, time) = modified_timestamp(now)?;
    validate_edit_state(cx, volume)?;
    let before = volume.check(cx)?;
    if !before.clean || !before.complete || !before.namespace_complete {
        bail!("collapse requires complete clean allocation and namespace ownership");
    }
    let old = volume.file_chain(cx, &entry)?;
    let first = usize::try_from(offset / cluster_bytes).context("collapse start overflow")?;
    let last = usize::try_from(end / cluster_bytes).context("collapse end overflow")?;
    if first >= last || last >= old.clusters.len() {
        bail!("collapse range exceeds the validated native chain");
    }
    let removed = last - first;
    let size = u32::try_from(u64::from(old.size) - length).context("collapse size overflow")?;
    let free_after = before.free_clusters.checked_add(removed as u64)
        .filter(|free| *free <= u64::from(volume.geometry.cluster_count()))
        .context("collapse free-space accounting overflow")?;
    let free_hint = u32::try_from(free_after).context("collapse free-space hint overflow")?;
    let mut retained = Vec::new();
    retained.try_reserve_exact(old.clusters.len() - removed)
        .context("reserving bounded collapse chain")?;
    retained.extend_from_slice(&old.clusters[..first]);
    retained.extend_from_slice(&old.clusters[last..]);
    let mut release = Vec::new();
    release.try_reserve_exact(removed).context("reserving bounded collapse release map")?;
    for index in first..last {
        // last is strictly inside the old chain, so every removed link has an
        // exact successor. Never release an inferred or merely example cluster.
        release.push((old.clusters[index], old.clusters[index + 1]));
    }
    release.sort_unstable_by_key(|&(cluster, _)| cluster);

    let mut original = [0; 32];
    volume.read_exact(cx, entry.offset, &mut original)?;
    let mut updated = original;
    let head = retained[0];
    if volume.geometry.kind() == FatKind::Fat32 {
        let high = u16::from_le_bytes([original[20], original[21]]) & 0xF000;
        updated[20..22].copy_from_slice(&(high | (head >> 16) as u16).to_le_bytes());
    }
    // FAT16's high cluster field may be an EA index; leave it unchanged.
    updated[26..28].copy_from_slice(&(head as u16).to_le_bytes());
    updated[28..32].copy_from_slice(&size.to_le_bytes());
    updated[22..24].copy_from_slice(&time.to_le_bytes());
    updated[24..26].copy_from_slice(&date.to_le_bytes());
    updated[11] |= 0x20;
    // Zero EOF before changing a head/link. A torn little-endian size update
    // to an arbitrary SMALLER value can transiently INCREASE the value when
    // a byte borrows; old -> zero and zero -> final avoid that particular risk.
    // A failure may therefore leave an empty file with retained allocation.
    // Dirty admission and the mount health guard remain essential: this is not
    // protection against arbitrary sector corruption or crash-atomic metadata.
    let mut hidden = updated;
    hidden[28..32].fill(0);
    let mut empty_old_head = hidden;
    empty_old_head[20..22].copy_from_slice(&original[20..22]);
    empty_old_head[26..28].copy_from_slice(&original[26..28]);
    let sector_bytes = u64::from(volume.geometry.sector_bytes());
    let start = entry.offset / sector_bytes * sector_bytes;
    let within = (entry.offset - start) as usize;
    let mut sector = allocate(sector_bytes as usize)?;
    let mut readback = allocate(sector_bytes as usize)?;
    verify_chain(cx, volume, &old.clusters)?;
    volume.read_exact(cx, start, &mut sector)?;
    if sector[within..within + 32] != original {
        bail!("collapse directory record changed before mutation");
    }

    let mut phase = "publishing dirty state";
    let result = (|| -> Result<()> {
        set_dirty(cx, volume, true)?;
        set_hints(cx, volume, u32::MAX)?;
        volume.device.sync(cx)?;

        phase = "hiding logical EOF before changing native links";
        volume.read_exact(cx, start, &mut sector)?;
        if sector[within..within + 32] != original {
            bail!("collapse directory record changed before publication");
        }
        sector[within..within + 32].copy_from_slice(&empty_old_head);
        write_volume(cx, volume, start, &sector)?;
        volume.device.sync(cx)?;
        volume.read_exact(cx, start, &mut readback)?;
        if readback != sector {
            bail!("collapse directory sector failed readback; allocation retained");
        }

        phase = "splicing the retained native chain";
        if first == 0 {
            // Head and length occupy distinct bytes even in one native entry.
            // The preceding verified barrier must not be folded into this one.
            volume.read_exact(cx, start, &mut sector)?;
            if sector[within..within + 32] != empty_old_head {
                bail!("shortened collapse record changed before head publication");
            }
            sector[within..within + 32].copy_from_slice(&hidden);
            write_volume(cx, volume, start, &sector)?;
            volume.device.sync(cx)?;
            volume.read_exact(cx, start, &mut readback)?;
            if readback != sector {
                bail!("collapse head sector failed readback; allocation retained");
            }
        } else {
            change_fat(cx, volume, &std::iter::once((
                old.clusters[first - 1], old.clusters[first], old.clusters[last],
            )))?;
            volume.device.sync(cx)?;
        }
        // Prefix removal changed the directory head instead of a FAT link.
        // Both paths must prove that NO removed cluster remains reachable.
        verify_target(cx, volume, path, entry.offset, &hidden, &retained)?;

        phase = "publishing the verified collapsed file length";
        volume.read_exact(cx, start, &mut sector)?;
        if sector[within..within + 32] != hidden {
            bail!("hidden collapse record changed before final length publication");
        }
        sector[within..within + 32].copy_from_slice(&updated);
        write_volume(cx, volume, start, &sector)?;
        volume.device.sync(cx)?;
        volume.read_exact(cx, start, &mut readback)?;
        if readback != sector {
            bail!("collapsed length sector failed readback; allocation retained");
        }
        verify_target(cx, volume, path, entry.offset, &updated, &retained)?;

        phase = "releasing detached collapse allocation";
        change_fat(cx, volume, &release.iter().map(|&(cluster, next)| (cluster, next, 0)))?;
        volume.device.sync(cx)?;
        let mut table = FatTable::new(volume);
        for &(cluster, _) in &release {
            if table.entry(cx, cluster)? != FatEntry::Free {
                bail!("collapse reclamation failed readback at cluster {cluster}");
            }
        }
        // Released entries can share a sector with retained links. Check those
        // links again, not only the now-free entries, before marking clean.
        verify_target(cx, volume, path, entry.offset, &updated, &retained)?;
        set_hints(cx, volume, free_hint)?;
        volume.device.sync(cx)?;

        phase = "verifying collapsed namespace and allocation";
        let after = volume.check(cx)?;
        if !after.clean || !after.complete || !after.namespace_complete
            || after.free_clusters != free_after || after.files != before.files
            || after.directories != before.directories
            || after.preallocated_clusters != before.preallocated_clusters
            || after.referenced_clusters.checked_add(removed as u64) != Some(before.referenced_clusters)
        {
            bail!("collapse verification failed: {}", serde_json::to_string(&after)?);
        }
        phase = "synchronizing final clean state";
        set_dirty(cx, volume, false)?;
        volume.device.sync(cx)?;
        Ok(())
    })();
    result.with_context(|| format!(
        "FAT collapse failed while {phase}; image retained and may contain a shorter or partially changed file and detached allocation; no rollback or atomicity is claimed"
    ))
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests;
}
