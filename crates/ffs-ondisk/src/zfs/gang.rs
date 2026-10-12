//! Native, self-checksummed gang headers (OpenZFS zfs-2.3.0).
//!
//! A gang DVA's ASIZE accounts for an entire fragmented tree, NOT a contiguous
//! extent beginning at the header. Only the 512-byte header is read there.
//! Its checksum verifier always uses DVA[0] and the physical birth of the
//! owning pointer, including when the bytes came from another header replica.
//! Fragment bytes must also pass their own and the leader's data checksums.
//!
//! Layout and contracts: include/sys/{spa,zio}.h and module/zfs/{zio,
//! zio_checksum}.c. This parser neither reads devices nor authorizes writes.

use super::{BlockPointer, Dva, ECK_MAGIC, Endian, checksum, invalid};
use ffs_types::ParseError;

pub const HEADER_BYTES: usize = 512;
pub const HEADER_POINTERS: usize = 3;
const POINTER_BYTES: usize = 128;
const FILLER_START: usize = HEADER_POINTERS * POINTER_BYTES;
const CHECKSUM_MAGIC_OFFSET: usize = HEADER_BYTES - 40;
const CHECKSUM_OFFSET: usize = HEADER_BYTES - 32;

impl BlockPointer {
    /// Native BP_IS_GANG. Admission must still validate every DVA, not just
    /// this identity slot, before trusting a physical address.
    #[must_use]
    pub const fn gang(&self) -> bool {
        !self.embedded() && self.words[1] >> 63 != 0
    }

    /// Native BP_GET_BIRTH, distinct from the logical birth exposed by birth().
    /// Reused blocks can retain an older physical birth in word nine.
    #[must_use]
    pub const fn physical_birth(&self) -> u64 {
        if self.embedded() {
            0
        } else if self.words[9] != 0 {
            self.words[9]
        } else {
            self.birth()
        }
    }

    /// Validate header identities before I/O. DVA zero accounts for every
    /// member's first copy, so it must cover at least PSIZE plus the header.
    /// Additional header replicas may contain no corresponding member copy.
    pub fn gang_dvas(&self, header_allocation: u64) -> Result<Vec<Dva>, ParseError> {
        let dvas = self.regular_dvas()?;
        if !self.gang()
            || dvas.iter().any(|dva| !dva.gang)
            || self.physical_birth() == 0
            || self.physical_birth() > self.birth()
        {
            return Err(invalid("invalid gang identity, DVA flags or physical birth"));
        }
        if header_allocation < HEADER_BYTES as u64
            || !header_allocation.is_multiple_of(HEADER_BYTES as u64)
            || dvas.iter().any(|dva| dva.allocated_bytes < header_allocation)
            || header_allocation
                .checked_add(self.physical_bytes() as u64)
                .is_none_or(|minimum| dvas[0].allocated_bytes < minimum)
        {
            return Err(invalid("invalid native gang-header allocation"));
        }
        Ok(dvas)
    }

    /// Verify a complete physical stream without allocating a logical result
    /// or decompressing it. Gang-tree interior checks use this same boundary.
    pub fn verify_physical(&self, physical: &[u8]) -> Result<(), ParseError> {
        self.regular_dvas()?;
        if physical.len() != self.physical_bytes() {
            return Err(invalid("short physical block"));
        }
        let expected = [
            self.words[12],
            self.words[13],
            self.words[14],
            self.words[15],
        ];
        if checksum(physical, self.checksum_type(), self.payload_order())? != expected {
            return Err(invalid("physical block checksum mismatch"));
        }
        Ok(())
    }
}

/// Fully checked immediate children of one gang node. Device bounds, native
/// topology mapping and the entire recursive tree remain the reader's job.
#[derive(Debug, Clone)]
pub struct GangHeader {
    children: Vec<BlockPointer>,
}

impl GangHeader {
    /// `header_allocation` is the native ASIZE of a 512-byte header on the
    /// admitted top-level vdev, not the parent's aggregate DVA ASIZE. It is one
    /// sector for a leaf/mirror and parity+1 sectors for ordinary RAIDZ.
    pub fn parse(
        raw: &[u8],
        parent: &BlockPointer,
        header_allocation: u64,
    ) -> Result<Self, ParseError> {
        let parent_dvas = parent.gang_dvas(header_allocation)?;
        verify_header(raw, parent, parent_dvas[0])?;
        if raw[FILLER_START..CHECKSUM_MAGIC_OFFSET]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(invalid("nonzero gang-header reserved filler"));
        }

        let mut children = Vec::with_capacity(HEADER_POINTERS);
        let mut total_bytes = 0_usize;
        let mut totals = [header_allocation; HEADER_POINTERS];
        let mut ended = false;
        for bytes in raw[..FILLER_START].as_chunks::<POINTER_BYTES>().0 {
            if bytes.iter().all(|byte| *byte == 0) {
                ended = true;
                continue;
            }
            if ended {
                return Err(invalid("noncontiguous gang-header child slots"));
            }
            let child = BlockPointer::parse(bytes, parent.payload_order())?;
            // Native gang members are uncompressed DMU_OT_NONE, level zero,
            // with the leader's byte order and checksum algorithm. They hold
            // pieces of an already transformed physical stream, not DMU nodes.
            if child.embedded()
                || child.protected()
                || child.hole()
                || child.words[6] & (1_u64 << 62) != 0
                || child.object_type() != 0
                || child.level() != 0
                || child.compression() != 2
                || child.logical_bytes() != child.physical_bytes()
                || child.payload_order() != parent.payload_order()
                || child.checksum_type() != parent.checksum_type()
                || child.birth() == 0
                || child.birth() > parent.physical_birth()
                || child.physical_birth() == 0
                || child.physical_birth() > child.birth()
            {
                return Err(invalid("invalid native gang-member properties or birth"));
            }
            let dvas = child.regular_dvas()?;
            if dvas.len() > parent_dvas.len()
                || dvas.iter().any(|dva| dva.gang != child.gang())
            {
                return Err(invalid("gang child has invalid copies or mixed DVA flags"));
            }
            total_bytes = total_bytes
                .checked_add(child.physical_bytes())
                .filter(|total| *total <= parent.physical_bytes())
                .ok_or_else(|| invalid("gang children exceed parent physical size"))?;
            // zio_write_gang_member_ready accumulates by copy index. A second
            // header copy may have no corresponding ordinary child copy; its
            // ASIZE then accounts only for that header, not for the data tree.
            for (index, dva) in dvas.iter().enumerate() {
                totals[index] = totals[index]
                    .checked_add(dva.allocated_bytes)
                    .ok_or_else(|| invalid("gang allocation accounting overflow"))?;
            }
            children.push(child);
        }
        if children.len() < 2 || total_bytes != parent.physical_bytes() {
            return Err(invalid("gang header must partition its complete physical stream"));
        }
        for (index, dva) in parent_dvas.iter().enumerate() {
            if totals[index] != dva.allocated_bytes {
                return Err(invalid("gang DVA aggregate allocation disagrees with children"));
            }
        }
        Ok(Self { children })
    }

    #[must_use]
    pub fn children(&self) -> &[BlockPointer] {
        &self.children
    }
}

fn verify_header(raw: &[u8], parent: &BlockPointer, identity: Dva) -> Result<(), ParseError> {
    if raw.len() != HEADER_BYTES {
        return Err(invalid("gang header must contain exactly 512 bytes"));
    }
    let order = parent.payload_order();
    if order.u64(raw, CHECKSUM_MAGIC_OFFSET)? != ECK_MAGIC {
        return Err(invalid("gang-header checksum magic or byte order mismatch"));
    }
    let mut expected = [0; 4];
    for (index, value) in expected.iter_mut().enumerate() {
        *value = order.u64(raw, CHECKSUM_OFFSET + index * 8)?;
    }
    // Fixed stack copy: never mutate bytes supplied by a device or its cache.
    let mut verified = [0; HEADER_BYTES];
    verified.copy_from_slice(raw);
    let verifier = [
        u64::from(identity.vdev),
        identity.offset,
        parent.physical_birth(),
        0,
    ];
    for (index, value) in verifier.iter().enumerate() {
        let start = CHECKSUM_OFFSET + index * 8;
        verified[start..start + 8].copy_from_slice(&order.encode(*value));
    }
    // SHA256's numeric words are big-endian regardless of the header's order.
    if checksum(&verified, 8, Endian::Big)? != expected {
        return Err(invalid("gang-header checksum or identity verifier mismatch"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
