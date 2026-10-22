//! Expand a FAT16 fixed root in a private, read-only native view.
//!
//! Insert zeroed directory storage before the data area and increase the virtual
//! volume length by exactly that amount. Cluster numbers, FATs, old root records
//! and payload do not change. The existing resize/relocation engine then maps
//! this view to the requested output size and verifies it before publication.
//! No source writes, name reconstruction, or new recovery authority is involved.

use super::{
    ByteDevice, ByteOffset, Cx, FatGeometry, FatKind, FatOemCodePage, FatVolume, FfsError, Slice,
    TRANSFER, buffer, checked, checkpoint, invalid,
};
use anyhow::{Context, Result, bail};
use std::sync::Arc;

pub(super) struct Change {
    pub(super) source_bytes: u64,
    pub(super) before: u16,
    pub(super) after: u16,
}

struct ExpandedRoot {
    source: Slice,
    boot: Vec<u8>,
    old_end: u64,
    new_end: u64,
    length: u64,
}

impl ByteDevice for ExpandedRoot {
    fn len_bytes(&self) -> u64 {
        self.length
    }

    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        let end =
            at.0.checked_add(bytes.len() as u64)
                .filter(|end| *end <= self.length)
                .ok_or_else(|| invalid("expanded root read exceeds the private volume"))?;
        let mut done = 0;
        while done < bytes.len() {
            checkpoint(cx)?;
            let position = at.0 + done as u64;
            let maximum = (bytes.len() - done).min(TRANSFER) as u64;
            let (source, count) = if position < self.old_end {
                (Some(position), maximum.min(self.old_end - position))
            } else if position < self.new_end {
                (None, maximum.min(self.new_end - position))
            } else {
                (Some(position - (self.new_end - self.old_end)), maximum)
            };
            let count = count as usize;
            if let Some(source) = source {
                self.source.read_exact_at(
                    cx,
                    ByteOffset(source),
                    &mut bytes[done..done + count],
                )?;
            } else {
                bytes[done..done + count].fill(0);
            }
            done += count;
        }
        // Overlay only the captured primary sector. Actual source read failures
        // remain errors, even when the prepared BPB covers the failing bytes.
        let right = end.min(self.boot.len() as u64);
        if at.0 < right {
            bytes[..(right - at.0) as usize]
                .copy_from_slice(&self.boot[at.0 as usize..right as usize]);
        }
        checkpoint(cx)
    }

    fn write_all_at(&self, _: &Cx, _: ByteOffset, _: &[u8]) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }

    fn sync(&self, _: &Cx) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }
}

pub(super) fn prepare(
    cx: &Cx,
    mut source: Slice,
    entries: u16,
    page: FatOemCodePage,
) -> Result<(Slice, Change)> {
    checkpoint(cx)?;
    let volume = FatVolume::from_device(cx, Box::new(source.clone()), 0, source.length)?
        .with_oem_code_page(page);
    let old = &volume.geometry;
    if old.kind() != FatKind::Fat16 {
        bail!("--root-entries applies only to FAT16; FAT32 roots already use cluster chains");
    }
    let sector = u64::from(old.sector_bytes());
    let (start, bytes) = old.fixed_root().context("FAT16 fixed root is absent")?;
    let requested = u64::from(entries) * 32;
    if entries == 0 || requested < bytes || !requested.is_multiple_of(sector) {
        bail!(
            "--root-entries must preserve or grow the FAT16 root and occupy whole logical sectors"
        );
    }
    // Validate the ORIGINAL namespace first. Appended end markers must never
    // conceal malformed records or an incomplete ownership scan in the source.
    let expected = checked(cx, &volume)?;
    let change = Change {
        source_bytes: old.volume_bytes(),
        before: u16::try_from(bytes / 32).context("native root-entry count overflow")?,
        after: entries,
    };
    // A selected range may include trailing bytes outside the native volume.
    // They are not part of the projection and must not enter the output image.
    source.length = old.volume_bytes();
    if requested == bytes {
        checkpoint(cx)?;
        return Ok((source, change));
    }
    let delta = requested - bytes;
    let length = source
        .length
        .checked_add(delta)
        .context("expanded root length overflow")?;
    let sectors =
        u32::try_from(length / sector).context("expanded root exceeds native sector count")?;
    let old_end = start
        .checked_add(bytes)
        .context("old root boundary overflow")?;
    let new_end = start
        .checked_add(requested)
        .context("expanded root boundary overflow")?;
    let mut boot = buffer(sector as usize)?;
    source.read_exact_at(cx, ByteOffset(0), &mut boot)?;
    // Retained geometry must still describe the same original file before we
    // replace fields. Unknown state is never normalized into an admitted view.
    let original = FatGeometry::parse(&boot, source.length).map_err(|e| invalid(e.to_string()))?;
    if original != *old || boot[37] != 0 {
        bail!("source geometry or native boot state changed during root expansion");
    }
    boot[17..19].copy_from_slice(&entries.to_le_bytes());
    boot[19..21].fill(0);
    boot[32..36].fill(0);
    if let Ok(small) = u16::try_from(sectors) {
        boot[19..21].copy_from_slice(&small.to_le_bytes());
    } else {
        boot[32..36].copy_from_slice(&sectors.to_le_bytes());
    }
    let geometry = FatGeometry::parse(&boot, length).map_err(|e| invalid(e.to_string()))?;
    if geometry.kind() != FatKind::Fat16
        || geometry.cluster_bytes() != old.cluster_bytes()
        || geometry.cluster_count() != old.cluster_count()
        || geometry.fixed_root() != Some((start, requested))
        || old.cluster_offset(2).map_err(|e| invalid(e.to_string()))? != old_end
        || geometry
            .cluster_offset(2)
            .map_err(|e| invalid(e.to_string()))?
            != new_end
    {
        bail!("expanded root changed native cluster identity or geometry");
    }
    let view = Slice {
        inner: Arc::new(ExpandedRoot {
            source,
            boot,
            old_end,
            new_end,
            length,
        }),
        base: 0,
        length,
    };
    let candidate =
        FatVolume::from_device(cx, Box::new(view.clone()), 0, length)?.with_oem_code_page(page);
    if candidate.geometry != geometry || checked(cx, &candidate)? != expected {
        bail!("expanded root changed native ownership or free-space accounting");
    }
    checkpoint(cx)?;
    Ok((view, change))
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests;
}
