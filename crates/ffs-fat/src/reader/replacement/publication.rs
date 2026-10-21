//! Verify disjoint file staging before exposing native namespace references.
//!
//! These checks read actual backing bytes, not the immutable input or an old
//! FAT cache. The caller retains exclusive writer ownership through publication.

use super::{
    EXPECT_END, FatEntry, FatTable, FatVolume, Replacement, allocate, checkpoint, write_volume,
};
use anyhow::{Result, bail};
use asupersync::Cx;
use sha2::{Digest, Sha256};

impl Replacement {
    /// Before data writes, every reservation must still be free. Before name
    /// publication, every new link and every retained old link must agree in
    /// all selected copies. Freeing old allocation remains a later phase.
    pub(super) fn verify_disjoint_links(
        &self,
        cx: &Cx,
        volume: &FatVolume,
        installed: bool,
    ) -> Result<()> {
        checkpoint(cx)?;
        let required = u64::from(self.size).div_ceil(u64::from(volume.geometry.cluster_bytes()));
        if self.clusters.len() as u64 != required {
            bail!("replacement reservation does not match the prepared length");
        }
        let mut table = FatTable::new(volume);
        for (index, &cluster) in self.clusters.iter().enumerate() {
            checkpoint(cx)?;
            // The disjoint allocator returns increasing cluster IDs. Reject
            // repeated or reordered private plans before data could alias.
            if index != 0 && self.clusters[index - 1] >= cluster {
                bail!("replacement reservation is not strictly increasing");
            }
            let expected = if installed {
                self.clusters
                    .get(index + 1)
                    .map_or(FatEntry::End, |&next| FatEntry::Next(next))
            } else {
                FatEntry::Free
            };
            if table.entry(cx, cluster)? != expected {
                bail!("replacement reservation or staged link changed at cluster {cluster}");
            }
        }
        for &(cluster, successor) in &self.release {
            checkpoint(cx)?;
            if self.clusters.binary_search(&cluster).is_ok() {
                bail!("replacement reservation overlaps retained allocation");
            }
            let expected = if successor == EXPECT_END {
                FatEntry::End
            } else {
                FatEntry::Next(successor)
            };
            if table.entry(cx, cluster)? != expected {
                bail!("replacement retained allocation changed at cluster {cluster}");
            }
        }
        checkpoint(cx)?;
        Ok(())
    }

    /// Hash the initialized, still-unreachable clusters and separately verify
    /// all slack. Hashing the input twice does not detect a dropped output write.
    pub(super) fn verify_staged_data(
        &self,
        cx: &Cx,
        volume: &FatVolume,
        bytes: &mut [u8],
    ) -> Result<()> {
        checkpoint(cx)?;
        if bytes.len() != volume.geometry.cluster_bytes() as usize {
            bail!("replacement readback scratch must cover one complete cluster");
        }
        let mut digest = Sha256::new();
        let mut remaining = u64::from(self.size);
        for &cluster in &self.clusters {
            checkpoint(cx)?;
            volume.read_exact(cx, volume.cluster_offset(cluster)?, bytes)?;
            let count = remaining.min(bytes.len() as u64) as usize;
            digest.update(&bytes[..count]);
            if bytes[count..].iter().any(|&byte| byte != 0) {
                bail!("staged replacement slack is not initialized at cluster {cluster}");
            }
            remaining -= count as u64;
        }
        let actual: [u8; 32] = digest.finalize().into();
        if remaining != 0 || actual != self.digest {
            bail!("staged replacement payload differs from the immutable source");
        }
        checkpoint(cx)?;
        Ok(())
    }
}

/// Whole-sector read-modify-write with exact readback. Allocate its scratch
/// before any dirty marker; a neighboring record is part of the expected sector.
pub(super) struct EntryPublication {
    start: u64,
    within: usize,
    sector: Vec<u8>,
    readback: Vec<u8>,
}

impl EntryPublication {
    pub(super) fn new(volume: &FatVolume, offset: u64) -> Result<Self> {
        let size = u64::from(volume.geometry.sector_bytes());
        let start = offset / size * size;
        let within = (offset - start) as usize;
        if !offset.is_multiple_of(32) || within + 32 > size as usize {
            bail!("replacement entry is not an aligned native directory record");
        }
        Ok(Self {
            start,
            within,
            sector: allocate(size as usize)?,
            readback: allocate(size as usize)?,
        })
    }

    fn publish(
        &mut self,
        cx: &Cx,
        volume: &FatVolume,
        expected: &[u8; 32],
        updated: &[u8; 32],
    ) -> Result<()> {
        checkpoint(cx)?;
        volume.read_exact(cx, self.start, &mut self.sector)?;
        if self.sector[self.within..self.within + 32] != *expected {
            bail!("directory entry changed before replacement publication");
        }
        self.sector[self.within..self.within + 32].copy_from_slice(updated);
        write_volume(cx, volume, self.start, &self.sector)?;
        volume.device.sync(cx)?;
        volume.read_exact(cx, self.start, &mut self.readback)?;
        if self.readback != self.sector {
            bail!("replacement directory sector failed readback; old allocation retained");
        }
        checkpoint(cx)?;
        Ok(())
    }

    pub(super) fn publish_file(
        &mut self,
        cx: &Cx,
        volume: &FatVolume,
        plan: &Replacement,
    ) -> Result<()> {
        if plan.creation.is_some() {
            // A reused deleted slot can still contain another object's old
            // cluster/length fields. Do not make its first name byte live
            // before the COMPLETE new record is durable and verified.
            let mut hidden = plan.updated;
            hidden[0] = 0xE5;
            self.publish(cx, volume, &plan.original, &hidden)?;
            return self.publish(cx, volume, &hidden, &plan.updated);
        }

        // FAT32's high head word precedes its low word and logical EOF. A torn
        // one-step replacement can combine heads, or expose the old length
        // through the new chain. Keep the old head while hiding EOF first.
        // Old -> zero and zero -> final also bound any mixed size bytes without
        // requiring atomic 32-bit writes. This is NOT a rollback protocol.
        let mut previous = plan.original;
        let mut empty = previous;
        empty[28..32].fill(0);
        if empty != previous {
            self.publish(cx, volume, &previous, &empty)?;
            previous = empty;
        }
        let mut ready = plan.updated;
        ready[28..32].fill(0);
        if ready != previous {
            self.publish(cx, volume, &previous, &ready)?;
            previous = ready;
        }
        if plan.updated != previous {
            self.publish(cx, volume, &previous, &plan.updated)?;
        }
        checkpoint(cx)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
