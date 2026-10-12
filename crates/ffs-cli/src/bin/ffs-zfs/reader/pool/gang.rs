//! Bounded, immutable gang-tree expansion through the admitted pool owner.
//!
//! Header replicas and ordinary fragments use native checksums. Interior data
//! checksums and the leader's physical checksum are checked before the assembled
//! stream is decoded. Partial traversal never publishes bytes or cache entries.

use super::Pool;
use crate::reader::{
    BlockPointer, BlockRead, Cx, DATA_OFFSET, Dva, FfsError, LABEL_BYTES, Result, VdevConfig,
    checkpoint, corrupt, parse, unsupported,
};
use ffs_ondisk::zfs::MAX_BLOCK_BYTES;
use ffs_ondisk::zfs::gang::{GangHeader, HEADER_BYTES};
use std::collections::{BTreeMap, BTreeSet};

const MAX_GANG_DEPTH: usize = 32;
const MAX_GANG_NODES: usize = 65_536;
const MAX_GANG_WORK_BYTES: usize = MAX_BLOCK_BYTES * MAX_GANG_DEPTH;
/// Count all declared native allocations, including ditto copies and mirrors.
/// PSIZE alone does not bound attempts on small fragments at a large ashift.
const MAX_GANG_ALLOCATED_BYTES: u64 = 256 * 1024 * 1024;

type HeaderIdentity = (u32, u64);

#[derive(Default)]
struct Budget {
    nodes: usize,
    work_bytes: usize,
    active: BTreeSet<HeaderIdentity>,
    headers: Option<BTreeMap<HeaderIdentity, BlockRead>>,
}

impl Budget {
    fn visit(&mut self, bytes: usize) -> Result<()> {
        self.nodes = self
            .nodes
            .checked_add(1)
            .filter(|count| *count <= MAX_GANG_NODES)
            .ok_or_else(|| unsupported("ZFS gang tree exceeds the node budget"))?;
        self.work_bytes = self
            .work_bytes
            .checked_add(bytes)
            .filter(|count| *count <= MAX_GANG_WORK_BYTES)
            .ok_or_else(|| unsupported("ZFS gang tree exceeds the physical-stream work budget"))?;
        Ok(())
    }
}

#[derive(Default)]
struct Admission {
    budget: Budget,
    headers: BTreeMap<HeaderIdentity, BlockRead>,
    // All admitted pointers use one native top-level vdev address space.
    // Header extents use their own allocation, never aggregate tree ASIZE.
    allocations: BTreeMap<u64, u64>,
}

impl Admission {
    fn claim(&mut self, dva: &Dva, bytes: u64) -> Result<()> {
        let end = dva
            .offset
            .checked_add(bytes)
            .ok_or_else(|| corrupt("gang allocation extent overflow"))?;
        if self
            .allocations
            .range(..=dva.offset)
            .next_back()
            .is_some_and(|(_, previous_end)| *previous_end > dva.offset)
            || self
                .allocations
                .range(dva.offset..)
                .next()
                .is_some_and(|(next_start, _)| *next_start < end)
        {
            return Err(corrupt("gang tree repeats or overlaps an allocation"));
        }
        self.allocations.insert(dva.offset, end);
        Ok(())
    }
}

/// Every admitted ashift is at least nine, so a 512-byte header occupies one
/// data sector. Ordinary RAIDZ adds one sector for each native parity column.
pub(super) fn header_allocation(config: &VdevConfig) -> Result<u64> {
    if !(9..=16).contains(&config.ashift) {
        return Err(corrupt("invalid gang-header sector geometry"));
    }
    let sectors = if let Some(group) = &config.raidz_members {
        if !(1..=3).contains(&group.parity)
            || !(group.parity + 1..=8).contains(&group.members.len())
        {
            return Err(corrupt("invalid gang-header RAIDZ geometry"));
        }
        (group.parity + 1) as u64
    } else {
        1
    };
    Ok((1_u64 << config.ashift) * sectors)
}

impl Pool {
    pub(in crate::reader) fn read_gang_block(
        &self,
        cx: &Cx,
        config: &VdevConfig,
        pointer: &BlockPointer,
    ) -> Result<BlockRead> {
        checkpoint(cx)?;
        let dvas = pointer
            .gang_dvas(header_allocation(config)?)
            .map_err(|error| parse(&error))?;
        let replicas = if config.raidz_members.is_some() {
            1
        } else {
            self.members.len() as u64
        };
        let allocated = dvas
            .iter()
            .try_fold(0_u64, |sum, dva| sum.checked_add(dva.allocated_bytes));
        if allocated
            .and_then(|sum| sum.checked_mul(replicas))
            .is_none_or(|bytes| bytes > MAX_GANG_ALLOCATED_BYTES)
        {
            return Err(unsupported(
                "ZFS gang tree exceeds the allocated read budget",
            ));
        }
        let mut admission = Admission::default();
        self.admit_gang(cx, config, pointer, 0, &mut admission)?;
        // Read no fragment until the complete header graph, every declared
        // replica and every native allocation have passed admission. Preserve
        // the verified headers so expansion cannot switch to a different graph.
        let mut budget = Budget {
            headers: Some(admission.headers),
            ..Budget::default()
        };
        let mut physical = Vec::new();
        physical
            .try_reserve_exact(pointer.physical_bytes())
            .map_err(|error| FfsError::Io(std::io::Error::other(error)))?;
        physical.resize(pointer.physical_bytes(), 0);
        let mut result = self.expand_gang(cx, config, pointer, &mut physical, 0, &mut budget)?;
        checkpoint(cx)?;
        if budget
            .headers
            .as_ref()
            .is_some_and(|headers| !headers.is_empty())
        {
            return Err(corrupt("gang expansion did not consume its admitted graph"));
        }
        // Compression belongs to the leader, not to its fragments. Even if
        // every individual fragment verified, the complete leader must match.
        result.bytes = pointer.decode(&physical).map_err(|error| parse(&error))?;
        checkpoint(cx)?;
        Ok(result)
    }

    fn admit_gang(
        &self,
        cx: &Cx,
        config: &VdevConfig,
        pointer: &BlockPointer,
        depth: usize,
        admission: &mut Admission,
    ) -> Result<()> {
        checkpoint(cx)?;
        if pointer.gang() && depth >= MAX_GANG_DEPTH {
            return Err(unsupported("ZFS gang tree exceeds the depth budget"));
        }
        admission.budget.visit(pointer.physical_bytes())?;
        let allocations = self.gang_allocations(cx, config, pointer)?;
        for (dva, bytes) in &allocations {
            checkpoint(cx)?;
            admission.claim(dva, *bytes)?;
        }
        if !pointer.gang() {
            return Ok(());
        }
        let identity = allocations
            .first()
            .map(|(dva, _)| (dva.vdev, dva.offset))
            .ok_or_else(|| corrupt("gang header has no native allocation"))?;
        let block = self.read_gang_header(cx, config, pointer)?;
        let header = GangHeader::parse(&block.bytes, pointer, header_allocation(config)?)
            .map_err(|error| parse(&error))?;
        for child in header.children() {
            self.admit_gang(cx, config, child, depth + 1, admission)?;
        }
        admission.headers.insert(identity, block);
        Ok(())
    }

    /// Reuse physical mapping checks without issuing payload I/O. Both header
    /// and ordinary fragment copies participate in the same overlap check.
    fn gang_allocations(
        &self,
        cx: &Cx,
        config: &VdevConfig,
        pointer: &BlockPointer,
    ) -> Result<Vec<(Dva, u64)>> {
        checkpoint(cx)?;
        if let Some(group) = &config.raidz_members {
            return self.raidz_maps(cx, config, pointer, group).map(|maps| {
                maps.into_iter()
                    .map(|(dva, map)| (dva, map.allocated_bytes()))
                    .collect()
            });
        }
        if pointer.gang() {
            let allocated = header_allocation(config)?;
            return self
                .gang_header_dvas(cx, config, pointer)
                .map(|dvas| dvas.into_iter().map(|dva| (dva, allocated)).collect());
        }
        let dvas = self.members[0].block_dvas(config, pointer)?;
        for member in &self.members[1..] {
            checkpoint(cx)?;
            member.block_dvas(config, pointer)?;
        }
        Ok(dvas
            .into_iter()
            .map(|dva| {
                let allocated = dva.allocated_bytes;
                (dva, allocated)
            })
            .collect())
    }

    fn expand_gang(
        &self,
        cx: &Cx,
        config: &VdevConfig,
        pointer: &BlockPointer,
        destination: &mut [u8],
        depth: usize,
        budget: &mut Budget,
    ) -> Result<BlockRead> {
        checkpoint(cx)?;
        if depth >= MAX_GANG_DEPTH {
            return Err(unsupported("ZFS gang tree exceeds the depth budget"));
        }
        if destination.len() != pointer.physical_bytes() {
            return Err(corrupt(
                "gang traversal destination size disagrees with pointer",
            ));
        }
        budget.visit(destination.len())?;
        let dvas = pointer
            .gang_dvas(header_allocation(config)?)
            .map_err(|error| parse(&error))?;
        let identities: BTreeSet<_> = dvas.iter().map(|dva| (dva.vdev, dva.offset)).collect();
        if identities.len() != dvas.len()
            || identities
                .iter()
                .any(|identity| budget.active.contains(identity))
        {
            return Err(corrupt("repeated or cyclic ZFS gang-header address"));
        }
        budget.active.extend(identities.iter().copied());
        let result = (|| {
            let header_block = if let Some(headers) = &mut budget.headers {
                headers
                    .remove(&(dvas[0].vdev, dvas[0].offset))
                    .ok_or_else(|| corrupt("gang expansion encountered an unadmitted header"))?
            } else {
                self.read_gang_header(cx, config, pointer)?
            };
            let header =
                GangHeader::parse(&header_block.bytes, pointer, header_allocation(config)?)
                    .map_err(|error| parse(&error))?;
            let mut at = 0_usize;
            for child in header.children() {
                checkpoint(cx)?;
                let end = at
                    .checked_add(child.physical_bytes())
                    .ok_or_else(|| corrupt("gang child range overflow"))?;
                let output = destination
                    .get_mut(at..end)
                    .ok_or_else(|| corrupt("gang child exceeds its parent stream"))?;
                if child.gang() {
                    self.expand_gang(cx, config, child, output, depth + 1, budget)?;
                } else {
                    budget.visit(child.physical_bytes())?;
                    // This is the existing verified leaf/mirror/RAIDZ path.
                    // Gang children never enter the DMU cache independently.
                    let block = self.read_block(cx, config, child)?;
                    if block.bytes.len() != output.len() {
                        return Err(corrupt("gang member returned an incorrect physical length"));
                    }
                    output.copy_from_slice(&block.bytes);
                }
                at = end;
            }
            if at != destination.len() {
                return Err(corrupt("gang tree left an incomplete physical stream"));
            }
            checkpoint(cx)?;
            if depth != 0 {
                pointer
                    .verify_physical(destination)
                    .map_err(|error| parse(&error))?;
            }
            checkpoint(cx)?;
            Ok(header_block)
        })();
        // Unwind path state on cancellation and every other failure as well.
        for identity in &identities {
            budget.active.remove(identity);
        }
        result
    }

    fn gang_header_dvas(
        &self,
        cx: &Cx,
        config: &VdevConfig,
        pointer: &BlockPointer,
    ) -> Result<Vec<Dva>> {
        checkpoint(cx)?;
        let allocated = header_allocation(config)?;
        let dvas = pointer
            .gang_dvas(allocated)
            .map_err(|error| parse(&error))?;
        // All copies and all supplied members are bounded before a usable
        // first replica can conceal an invalid later DVA or undersized member.
        for member in &self.members {
            checkpoint(cx)?;
            let end = member.length / LABEL_BYTES * LABEL_BYTES - 2 * LABEL_BYTES;
            if config.allocated_bytes == 0
                || !config.allocated_bytes.is_multiple_of(allocated)
                || config.allocated_bytes > end - DATA_OFFSET
            {
                return Err(corrupt(
                    "configured gang allocation region exceeds a selected member",
                ));
            }
            for dva in &dvas {
                if dva.vdev != config.id {
                    return Err(unsupported(
                        "foreign-vdev gang header requires another topology",
                    ));
                }
                if !dva.offset.is_multiple_of(allocated)
                    || !dva.allocated_bytes.is_multiple_of(allocated)
                    || dva.allocated_bytes < allocated
                    || dva.allocated_bytes > config.allocated_bytes
                    || dva
                        .offset
                        .checked_add(allocated)
                        .is_none_or(|limit| limit > config.allocated_bytes)
                {
                    return Err(corrupt("unaligned or out-of-range gang-header DVA"));
                }
            }
        }
        Ok(dvas)
    }

    fn read_gang_header(
        &self,
        cx: &Cx,
        config: &VdevConfig,
        pointer: &BlockPointer,
    ) -> Result<BlockRead> {
        checkpoint(cx)?;
        if let Some(group) = &config.raidz_members {
            // The stripe verifier recognizes gang headers and uses their
            // embedded identity checksum, not the leader's payload checksum.
            return self.read_raidz_block(cx, config, pointer, group);
        }
        let allocated = header_allocation(config)?;
        let dvas = self.gang_header_dvas(cx, config, pointer)?;
        let mut failures = Vec::new();
        for (copy_index, dva) in dvas.iter().enumerate() {
            let offset = DATA_OFFSET + dva.offset;
            for (member_index, member) in self.members.iter().enumerate() {
                checkpoint(cx)?;
                let result = member.read(cx, offset, HEADER_BYTES).and_then(|bytes| {
                    GangHeader::parse(&bytes, pointer, allocated).map_err(|error| parse(&error))?;
                    Ok(bytes)
                });
                match result {
                    Ok(bytes) => {
                        checkpoint(cx)?;
                        return Ok(BlockRead {
                            bytes,
                            physical_offset: offset,
                            copy_index,
                            member_index,
                            raidz: None,
                        });
                    }
                    Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
                    Err(error) => failures.push(format!(
                        "header DVA {copy_index}, supplied member {member_index}: {error}"
                    )),
                }
            }
        }
        Err(corrupt(format!(
            "all ZFS gang-header copies failed: {}",
            failures.join("; ")
        )))
    }
}

#[cfg(test)]
mod tests;
