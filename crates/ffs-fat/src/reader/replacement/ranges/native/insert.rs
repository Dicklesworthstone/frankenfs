//! Insert allocated zero clusters without copying the existing file payload.
//!
//! The caller holds the native/mounted writer gate through cache publication.
//! Initialize a detached run, hide EOF, connect the retained suffix, then expose
//! the verified new chain and length. No source cluster is freed or overwritten.
//! Native FAT has no sparse-hole representation or crash-atomic chain splice.

use super::{
    EXPECT_END, FatEntry, FatKind, FatTable, FatVolume, FfsError, MAX_CHAIN_CLUSTERS, allocate,
    change_fat, checkpoint, modified_timestamp, reserve_clusters, set_dirty, set_hints,
    validate_edit_state, write_volume,
};
use anyhow::{Context, Result, bail};
use asupersync::Cx;

fn errno(code: i32) -> FfsError {
    FfsError::Io(std::io::Error::from_raw_os_error(code))
}

/// Use a new table at each publication boundary, never a pre-write FAT cache.
fn verify_chain(cx: &Cx, volume: &FatVolume, chain: &[u32]) -> Result<()> {
    let mut table = FatTable::new(volume);
    for (index, &cluster) in chain.iter().enumerate() {
        checkpoint(cx)?;
        let expected = chain
            .get(index + 1)
            .map_or(FatEntry::End, |&next| FatEntry::Next(next));
        if table.entry(cx, cluster)? != expected {
            bail!("native insertion chain failed readback at cluster {cluster}");
        }
    }
    Ok(())
}

fn verify_zeroes(cx: &Cx, volume: &FatVolume, added: &[u32], scratch: &mut [u8]) -> Result<()> {
    for &cluster in added {
        volume.read_exact(cx, volume.cluster_offset(cluster)?, scratch)?;
        if scratch.iter().any(|&byte| byte != 0) {
            bail!("native insertion initialization failed readback at cluster {cluster}");
        }
    }
    checkpoint(cx)?;
    Ok(())
}

/// Reuse preallocated scratch and preserve every neighboring directory record.
struct Record {
    offset: u64,
    start: u64,
    within: usize,
    sector: Vec<u8>,
    readback: Vec<u8>,
}

impl Record {
    fn prepare(cx: &Cx, volume: &FatVolume, offset: u64, original: &[u8; 32]) -> Result<Self> {
        let bytes = u64::from(volume.geometry.sector_bytes());
        let start = offset / bytes * bytes;
        let within = (offset - start) as usize;
        if !offset.is_multiple_of(32) || within + 32 > bytes as usize {
            bail!("unaligned native insertion directory record");
        }
        let mut sector = allocate(bytes as usize)?;
        let readback = allocate(bytes as usize)?;
        volume.read_exact(cx, start, &mut sector)?;
        if sector[within..within + 32] != *original {
            bail!("insertion directory record changed before mutation");
        }
        Ok(Self {
            offset,
            start,
            within,
            sector,
            readback,
        })
    }

    fn publish(
        &mut self,
        cx: &Cx,
        volume: &FatVolume,
        expected: &[u8; 32],
        updated: &[u8; 32],
    ) -> Result<()> {
        volume.read_exact(cx, self.start, &mut self.sector)?;
        if self.sector[self.within..self.within + 32] != *expected {
            bail!("insertion directory record changed before publication");
        }
        self.sector[self.within..self.within + 32].copy_from_slice(updated);
        write_volume(cx, volume, self.start, &self.sector)?;
        volume.device.sync(cx)?;
        volume.read_exact(cx, self.start, &mut self.readback)?;
        if self.readback != self.sector {
            bail!("insertion directory sector failed readback; allocation retained");
        }
        Ok(())
    }

    fn verify(
        &self,
        cx: &Cx,
        volume: &FatVolume,
        path: &str,
        expected: &[u8; 32],
        chain: &[u32],
    ) -> Result<()> {
        let entry = volume
            .resolve(cx, path)?
            .context("inserted file disappeared")?;
        let mut raw = [0; 32];
        volume.read_exact(cx, entry.offset, &mut raw)?;
        if entry.offset != self.offset
            || raw != *expected
            || chain.first().copied() != Some(entry.native.first_cluster)
        {
            bail!("insertion changed native file identity or prepared metadata");
        }
        verify_chain(cx, volume, chain)
    }
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
    if length == 0 || !offset.is_multiple_of(cluster_bytes) || !length.is_multiple_of(cluster_bytes)
    {
        return Err(errno(libc::EINVAL).into());
    }
    let entry = volume.resolve(cx, path)?.ok_or(FfsError::IsDirectory)?;
    if entry.native.is_directory() {
        return Err(FfsError::IsDirectory.into());
    }
    if entry.native.attributes & 1 != 0 {
        return Err(FfsError::PermissionDenied.into());
    }
    if entry.native.attributes & 0xC8 != 0 {
        bail!("unsupported native attributes on insertion target");
    }
    // Inserting at/past EOF is not INSERT_RANGE. Preserve a nonempty suffix.
    if offset >= u64::from(entry.native.size) {
        return Err(errno(libc::EINVAL).into());
    }
    let size = u64::from(entry.native.size)
        .checked_add(length)
        .and_then(|size| u32::try_from(size).ok())
        .ok_or_else(|| errno(libc::EFBIG))?;
    let (date, time) = modified_timestamp(now)?;
    validate_edit_state(cx, volume)?;
    let before = volume.check(cx)?;
    if !before.clean || !before.complete || !before.namespace_complete {
        bail!("insertion requires complete clean allocation and namespace ownership");
    }
    let old = volume.file_chain(cx, &entry)?;
    let split = usize::try_from(offset / cluster_bytes).context("insertion offset overflow")?;
    let count = usize::try_from(length / cluster_bytes).context("insertion capacity overflow")?;
    let total = old
        .clusters
        .len()
        .checked_add(count)
        .filter(|total| *total <= MAX_CHAIN_CLUSTERS)
        .ok_or(FfsError::NoSpace)?;
    if count as u64 > before.free_clusters {
        return Err(FfsError::NoSpace.into());
    }
    if split >= old.clusters.len() {
        bail!("insertion exceeds validated native chain");
    }
    // Do not consume existing beyond-EOF allocation: it shifts with the suffix.
    // Capture ALL space requirements before publishing even a dirty marker.
    let added = reserve_clusters(cx, volume, count, before.free_clusters)?;
    let mut chain = Vec::new();
    chain
        .try_reserve_exact(total)
        .context("reserving bounded insertion chain")?;
    chain.extend_from_slice(&old.clusters[..split]);
    chain.extend_from_slice(&added);
    chain.extend_from_slice(&old.clusters[split..]);
    let free_after = before.free_clusters - count as u64;
    let free_hint = u32::try_from(free_after).context("insertion free-space hint overflow")?;
    let mut original = [0; 32];
    volume.read_exact(cx, entry.offset, &mut original)?;
    let mut updated = original;
    let head = chain[0];
    if volume.geometry.kind() == FatKind::Fat32 {
        let high = u16::from_le_bytes([original[20], original[21]]) & 0xF000;
        updated[20..22].copy_from_slice(&(high | (head >> 16) as u16).to_le_bytes());
    }
    updated[26..28].copy_from_slice(&(head as u16).to_le_bytes());
    updated[28..32].copy_from_slice(&size.to_le_bytes());
    updated[22..24].copy_from_slice(&time.to_le_bytes());
    updated[24..26].copy_from_slice(&date.to_le_bytes());
    updated[11] |= 0x20;
    let mut hidden = original;
    hidden[28..32].fill(0);
    let mut hidden_new_head = hidden;
    hidden_new_head[20..22].copy_from_slice(&updated[20..22]);
    hidden_new_head[26..28].copy_from_slice(&updated[26..28]);
    let mut record = Record::prepare(cx, volume, entry.offset, &original)?;
    // Geometry caps a cluster at 64 KiB. Reserve scratch before mutation.
    let zeroes = allocate(cluster_bytes as usize)?;
    let mut readback = allocate(cluster_bytes as usize)?;
    verify_chain(cx, volume, &old.clusters)?;
    let mut table = FatTable::new(volume);
    for &cluster in &added {
        if table.entry(cx, cluster)? != FatEntry::Free {
            bail!("insertion reservation changed before mutation");
        }
    }
    let end = if volume.geometry.kind() == FatKind::Fat16 {
        0xFFFF
    } else {
        0x0FFF_FFFF
    };
    let mut phase = "publishing dirty state";
    let result = (|| -> Result<()> {
        set_dirty(cx, volume, true)?;
        set_hints(cx, volume, u32::MAX)?;
        volume.device.sync(cx)?;

        phase = "initializing detached insertion storage";
        for &cluster in &added {
            write_volume(cx, volume, volume.cluster_offset(cluster)?, &zeroes)?;
        }
        volume.device.sync(cx)?;
        verify_zeroes(cx, volume, &added, &mut readback)?;
        phase = "publishing detached initialized allocation";
        change_fat(
            cx,
            volume,
            &added
                .iter()
                .copied()
                .enumerate()
                .map(|(index, cluster)| (cluster, 0, added.get(index + 1).copied().unwrap_or(end))),
        )?;
        volume.device.sync(cx)?;
        verify_chain(cx, volume, &added)?;
        verify_chain(cx, volume, &old.clusters)?;

        // The head and size can tear independently inside one directory record.
        // Keep EOF zero through both link/head changes, then publish 0 -> size.
        // Failure may leave an empty file, but never frees its original payload.
        phase = "hiding EOF before chain insertion";
        record.publish(cx, volume, &original, &hidden)?;
        phase = "connecting the retained suffix";
        change_fat(
            cx,
            volume,
            &std::iter::once((added[count - 1], EXPECT_END, old.clusters[split])),
        )?;
        volume.device.sync(cx)?;
        verify_chain(cx, volume, &chain[split..])?;
        verify_chain(cx, volume, &old.clusters)?;
        phase = "publishing the inserted chain head or predecessor";
        if split == 0 {
            record.publish(cx, volume, &hidden, &hidden_new_head)?;
        } else {
            change_fat(
                cx,
                volume,
                &std::iter::once((old.clusters[split - 1], old.clusters[split], added[0])),
            )?;
            volume.device.sync(cx)?;
        }
        record.verify(cx, volume, path, &hidden_new_head, &chain)?;
        verify_zeroes(cx, volume, &added, &mut readback)?;
        phase = "publishing the verified inserted file length";
        record.publish(cx, volume, &hidden_new_head, &updated)?;
        record.verify(cx, volume, path, &updated, &chain)?;
        set_hints(cx, volume, free_hint)?;
        volume.device.sync(cx)?;
        phase = "verifying insertion ownership and accounting";
        let after = volume.check(cx)?;
        if !after.clean
            || !after.complete
            || !after.namespace_complete
            || after.free_clusters != free_after
            || after.files != before.files
            || after.directories != before.directories
            || after.preallocated_clusters != before.preallocated_clusters
            || before.referenced_clusters.checked_add(count as u64)
                != Some(after.referenced_clusters)
            || before.allocated_clusters.checked_add(count as u64) != Some(after.allocated_clusters)
        {
            bail!(
                "insertion verification failed: {}",
                serde_json::to_string(&after)?
            );
        }
        phase = "synchronizing final clean state";
        set_dirty(cx, volume, false)?;
        volume.device.sync(cx)?;
        checkpoint(cx)?;
        Ok(())
    })();
    result.with_context(|| format!(
        "FAT insertion failed while {phase}; image retained and may contain an empty or partially changed file and detached allocation; no rollback or atomicity is claimed"
    ))
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests;
}
