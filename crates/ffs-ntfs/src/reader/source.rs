//! The native reader's selected-volume and volatile recovery view.
//!
//! Overlay sectors are authoritative in memory. Covered reads never consult
//! replaced backing bytes, while uncovered runs retain ordinary device errors.
//! A patch is staged completely before publication: any returned error leaves
//! the previous overlay unchanged. No operation writes or synchronizes backing.

use super::{MAX_READ, Source, checkpoint, corrupt, unsupported};
use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_block::io_engine::{VolumeAccess, VolumeDevice};
use ffs_error::{FfsError, Result};
use ffs_types::ByteOffset;
use std::collections::BTreeMap;
use std::sync::Arc;

const SECTOR_BYTES: u64 = 512;
// Payload retention only; map nodes and an in-flight patch are additional.
const MAX_OVERLAY_SECTORS: usize = 64 * 1024 * 1024 / 512;

impl Source {
    pub(super) fn bounded(
        cx: &Cx,
        device: Box<dyn ByteDevice>,
        base: u64,
        length: u64,
    ) -> Result<Self> {
        checkpoint(cx)?;
        let selected = VolumeDevice::new(
            Arc::from(device),
            ByteOffset(base),
            length,
            VolumeAccess::ReadOnly,
        )?;
        checkpoint(cx)?;
        Ok(Self {
            device: Box::new(selected),
            // The adapter already translated the containing image's base.
            base: 0,
            length,
            overlay: BTreeMap::new(),
        })
    }

    fn request_end(&self, offset: u64, length: usize) -> Result<u64> {
        if length > MAX_READ {
            return Err(unsupported("NTFS source request exceeds 16 MiB"));
        }
        let length =
            u64::try_from(length).map_err(|_| corrupt(offset, "NTFS source length overflow"))?;
        offset
            .checked_add(length)
            .filter(|end| *end <= self.length)
            .ok_or_else(|| {
                corrupt(
                    offset,
                    "NTFS request outside the selected addressable volume",
                )
            })
    }

    fn read_backing(&self, cx: &Cx, offset: u64, data: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        self.request_end(offset, data.len())?;
        let physical = self
            .base
            .checked_add(offset)
            .ok_or_else(|| corrupt(offset, "NTFS physical offset overflow"))?;
        self.device.read_exact_at(cx, ByteOffset(physical), data)?;
        checkpoint(cx)
    }

    pub(super) fn read(&self, cx: &Cx, offset: u64, data: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        let end = self.request_end(offset, data.len())?;
        if data.is_empty() {
            return Ok(());
        }
        let first_sector = offset / SECTOR_BYTES;
        let last_sector = (end - 1) / SECTOR_BYTES;
        let mut cursor = offset;
        // Iterate patches, not every sector of an unmodified long read. Gaps
        // are forwarded as contiguous runs, preserving the existing bulk path.
        for (&sector, patch) in self.overlay.range(first_sector..=last_sector) {
            checkpoint(cx)?;
            let sector_start = sector * SECTOR_BYTES;
            let start = offset.max(sector_start);
            let stop = end.min(sector_start.saturating_add(SECTOR_BYTES));
            if cursor < start {
                let destination = &mut data[(cursor - offset) as usize..(start - offset) as usize];
                self.read_backing(cx, cursor, destination)?;
            }
            let destination = &mut data[(start - offset) as usize..(stop - offset) as usize];
            let within = (start - sector_start) as usize;
            destination.copy_from_slice(&patch[within..within + destination.len()]);
            cursor = stop;
        }
        if cursor < end {
            self.read_backing(cx, cursor, &mut data[(cursor - offset) as usize..])?;
        }
        // Source is private and its callers discard their staging buffer on
        // error. It does not advertise ByteDevice destination preservation.
        checkpoint(cx)
    }

    pub(super) fn write_overlay(&mut self, cx: &Cx, offset: u64, data: &[u8]) -> Result<()> {
        checkpoint(cx)?;
        let end = self.request_end(offset, data.len())?;
        if data.is_empty() {
            return Ok(());
        }
        let first_sector = offset / SECTOR_BYTES;
        let last_sector = (end - 1) / SECTOR_BYTES;
        let count = usize::try_from(last_sector - first_sector + 1)
            .map_err(|_| corrupt(offset, "NTFS overlay sector count overflow"))?;
        let mut existing = 0_usize;
        for _ in self.overlay.range(first_sector..=last_sector) {
            checkpoint(cx)?;
            existing += 1;
        }
        overlay_capacity(self.overlay.len(), count, existing)?;
        let mut staged = Vec::new();
        staged
            .try_reserve_exact(count)
            .map_err(|error| FfsError::Io(std::io::Error::other(error)))?;
        for sector in first_sector..=last_sector {
            checkpoint(cx)?;
            let sector_start = sector * SECTOR_BYTES;
            let sector_end = self.length.min(sector_start.saturating_add(SECTOR_BYTES));
            let start = offset.max(sector_start);
            let stop = end.min(sector_end);
            let mut patch = [0_u8; 512];
            if start != sector_start || stop != sector_end {
                if let Some(previous) = self.overlay.get(&sector) {
                    patch.copy_from_slice(previous);
                } else {
                    let valid = (sector_end - sector_start) as usize;
                    self.read_backing(cx, sector_start, &mut patch[..valid])?;
                }
            }
            // A full replacement needs no previous bytes. For a final partial
            // sector, only bytes inside the selected volume are ever read.
            let within = (start - sector_start) as usize;
            let length = (stop - start) as usize;
            let source = (start - offset) as usize;
            patch[within..within + length].copy_from_slice(&data[source..source + length]);
            staged.push((sector, patch));
        }
        checkpoint(cx)?;
        // No fallible checkpoint after this publication boundary. A returned
        // error must not leave a partly applied multi-sector recovery action.
        self.overlay.extend(staged);
        Ok(())
    }
}

fn overlay_capacity(retained: usize, touched: usize, existing: usize) -> Result<()> {
    let new = touched
        .checked_sub(existing)
        .ok_or_else(|| corrupt(0, "NTFS overlay accounting is inconsistent"))?;
    if retained
        .checked_add(new)
        .is_none_or(|total| total > MAX_OVERLAY_SECTORS)
    {
        return Err(unsupported(
            "NTFS recovery overlay exceeds 64 MiB of sector payloads",
        ));
    }
    Ok(())
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests;
}
