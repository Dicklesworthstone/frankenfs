//! Bounded, immutable gang-tree expansion through the admitted pool owner.
//!
//! Header replicas and ordinary fragments use native checksums. Interior data
//! checksums and the leader's physical checksum are checked before the assembled
//! stream is decoded. Partial traversal never publishes bytes or cache entries.

use super::super::{
    BlockPointer, BlockRead, Cx, DATA_OFFSET, Dva, FfsError, LABEL_BYTES, Result, VdevConfig,
    checkpoint, corrupt, parse, unsupported,
};
use super::Pool;
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
    // Track gang allocations per native top-level vdev ID.
    // Header extents use their own allocation, never aggregate tree ASIZE.
    allocations: BTreeMap<u32, BTreeMap<u64, u64>>,
    // Requested only by the physical-copy auditor. Ordinary reads retain the
    // existing header map without allocating this second, bounded manifest.
    audit_nodes: Option<Vec<AuditNode>>,
}

struct AuditNode {
    pointer: BlockPointer,
    header: Option<GangHeader>,
    header_allocations: Vec<u64>,
}

impl Admission {
    fn audit_node(
        &mut self,
        pointer: &BlockPointer,
        header: Option<GangHeader>,
        header_allocations: Vec<u64>,
    ) -> Result<()> {
        if let Some(nodes) = &mut self.audit_nodes {
            nodes
                .try_reserve(1)
                .map_err(|error| FfsError::Io(std::io::Error::other(error)))?;
            nodes.push(AuditNode {
                pointer: pointer.clone(),
                header,
                header_allocations,
            });
        }
        Ok(())
    }

    fn claim(&mut self, dva: &Dva, bytes: u64) -> Result<()> {
        let end = dva
            .offset
            .checked_add(bytes)
            .ok_or_else(|| corrupt("gang allocation extent overflow"))?;
        let vdev_map = self.allocations.entry(dva.vdev).or_default();
        if vdev_map
            .range(..=dva.offset)
            .next_back()
            .is_some_and(|(_, previous_end)| *previous_end > dva.offset)
            || vdev_map
                .range(dva.offset..)
                .next()
                .is_some_and(|(next_start, _)| *next_start < end)
        {
            return Err(corrupt("gang tree repeats or overlaps an allocation"));
        }
        vdev_map.insert(dva.offset, end);
        Ok(())
    }
}

/// Every admitted ashift is at least nine, so a 512-byte header occupies one
/// data sector. Ordinary RAIDZ adds one sector for each native parity column.
pub(super) fn header_allocation(config: &VdevConfig) -> Result<u64> {
    if !(9..=16).contains(&config.ashift) {
        return Err(corrupt("invalid gang-header sector geometry"));
    }
    let sectors = if let Some(group) = &config.raidz_members
        && group.parity != 0
    {
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

/// Keep one header allocation per actual DVA, in copy order.
pub(super) fn header_allocations(config: &VdevConfig, pointer: &BlockPointer) -> Result<Vec<u64>> {
    let dvas = pointer.regular_dvas().map_err(|error| parse(&error))?;
    if let Some(group) = &config.raidz_members
        && group.parity == 0
    {
        let mut allocs = Vec::with_capacity(dvas.len());
        for dva in &dvas {
            let vdev = group
                .members
                .get(dva.vdev as usize)
                .ok_or_else(|| unsupported("foreign-vdev gang header requires another topology"))?;
            if !(9..=16).contains(&vdev.ashift) {
                return Err(corrupt("invalid gang-header sector geometry"));
            }
            allocs.push(1_u64 << vdev.ashift);
        }
        return Ok(allocs);
    }
    if dvas.iter().any(|dva| dva.vdev != config.id) {
        return Err(unsupported(
            "foreign-vdev gang header requires another topology",
        ));
    }
    Ok(vec![header_allocation(config)?; dvas.len()])
}

impl Pool {
    fn gang_allocated_work(&self, config: &VdevConfig, pointer: &BlockPointer) -> Result<u64> {
        let dvas = pointer
            .gang_dvas(&header_allocations(config, pointer)?)
            .map_err(|error| parse(&error))?;
        let replicas = if config.raidz_members.is_some() {
            1
        } else {
            self.members.len() as u64
        };
        let allocated = dvas
            .iter()
            .try_fold(0_u64, |sum, dva| sum.checked_add(dva.allocated_bytes));
        let allocated = allocated
            .and_then(|sum| sum.checked_mul(replicas))
            .filter(|bytes| *bytes <= MAX_GANG_ALLOCATED_BYTES)
            .ok_or_else(|| unsupported("ZFS gang tree exceeds the allocated read budget"))?;
        Ok(allocated)
    }

    /// Reserve conservative byte-work for a complete gang-copy audit BEFORE
    /// reading its manifest. Native aggregate ASIZE includes every header and
    /// fragment copy. Mirror multiplicity is included by gang_allocated_work.
    /// The multipliers cover manifest rereads, header recovery, copy decoding
    /// and parity equations, not wall-clock time or unique physical I/O bytes.
    pub(in super::super) fn gang_audit_work(
        &self,
        config: &VdevConfig,
        pointer: &BlockPointer,
    ) -> Result<u64> {
        let allocated = self.gang_allocated_work(config, pointer)?;
        // One 512-byte header has one data column at every admitted ashift.
        // RAIDZ3 therefore has at most seven recovery hypotheses, not the
        // 92 possible for an ordinary eight-column data block. The larger
        // factor also covers padded-sector reconstruction and P/Q/R auditing.
        let factor = if config
            .raidz_members
            .as_ref()
            .is_some_and(|group| group.parity != 0)
        {
            256
        } else {
            8
        };
        allocated
            .checked_mul(factor)
            .ok_or_else(|| corrupt("gang audit work overflows"))
    }

    /// Visit copies only after the COMPLETE native header graph has passed
    /// the same geometry, aggregate-size, overlap and depth checks as reads.
    /// The caller first reserves gang_audit_work, and never uses this callback
    /// to supply traversal data. Returning false records explicit incomplete
    /// audit coverage at the caller; it does not change ordinary read admission.
    pub(in super::super) fn visit_gang_audit(
        &self,
        cx: &Cx,
        config: &VdevConfig,
        pointer: &BlockPointer,
        mut visit: impl FnMut(&BlockPointer, Option<&GangHeader>, &[u64]) -> Result<bool>,
    ) -> Result<()> {
        checkpoint(cx)?;
        self.gang_allocated_work(config, pointer)?;
        let mut admission = Admission {
            audit_nodes: Some(Vec::new()),
            ..Admission::default()
        };
        self.admit_gang(cx, config, pointer, 0, &mut admission)?;
        let nodes = admission
            .audit_nodes
            .take()
            .ok_or_else(|| corrupt("gang audit lost its native manifest"))?;
        // Raw header buffers have served admission; only parsed identities
        // need to survive the physical audit. No fragment has been read here.
        drop(admission);
        for node in nodes {
            checkpoint(cx)?;
            if !visit(
                &node.pointer,
                node.header.as_ref(),
                &node.header_allocations,
            )? {
                break;
            }
        }
        checkpoint(cx)
    }

    pub(in super::super) fn read_gang_block(
        &self,
        cx: &Cx,
        config: &VdevConfig,
        pointer: &BlockPointer,
    ) -> Result<BlockRead> {
        checkpoint(cx)?;
        self.gang_allocated_work(config, pointer)?;
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
            admission.audit_node(pointer, None, Vec::new())?;
            return Ok(());
        }
        let identity = allocations
            .first()
            .map(|(dva, _)| (dva.vdev, dva.offset))
            .ok_or_else(|| corrupt("gang header has no native allocation"))?;
        let block = self.read_gang_header(cx, config, pointer)?;
        let header_allocations: Vec<_> = allocations.iter().map(|(_, bytes)| *bytes).collect();
        let header = GangHeader::parse(&block.bytes, pointer, &header_allocations)
            .map_err(|error| parse(&error))?;
        if admission.audit_nodes.is_some() {
            admission.audit_node(pointer, Some(header.clone()), header_allocations)?;
        }
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
            if group.parity != 0 {
                return self.raidz_maps(cx, config, pointer, group).map(|maps| {
                    maps.into_iter()
                        .map(|(dva, map)| (dva, map.allocated_bytes()))
                        .collect()
                });
            }
            if pointer.gang() {
                let header_allocs = header_allocations(config, pointer)?;
                let dvas = self.gang_header_dvas(cx, config, pointer)?;
                return Ok(dvas.into_iter().zip(header_allocs).collect());
            }
            let dvas = pointer.regular_dvas().map_err(|error| parse(&error))?;
            for dva in &dvas {
                checkpoint(cx)?;
                let vdev = group
                    .members
                    .get(dva.vdev as usize)
                    .ok_or_else(|| unsupported("DVA references an unconfigured top-level vdev"))?;
                self.members[vdev.supplied_index].validate_dva_for_vdev(
                    vdev.ashift,
                    vdev.allocated_bytes,
                    dva.vdev,
                    pointer,
                    dva,
                )?;
            }
            return Ok(dvas
                .into_iter()
                .map(|dva| {
                    let allocated = dva.allocated_bytes;
                    (dva, allocated)
                })
                .collect());
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
        let header_allocations = header_allocations(config, pointer)?;
        let dvas = pointer
            .gang_dvas(&header_allocations)
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
            let header = GangHeader::parse(&header_block.bytes, pointer, &header_allocations)
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
        let header_allocs = header_allocations(config, pointer)?;
        let dvas = pointer
            .gang_dvas(&header_allocs)
            .map_err(|error| parse(&error))?;
        if let Some(group) = &config.raidz_members
            && group.parity == 0
        {
            for (dva, &allocated) in dvas.iter().zip(&header_allocs) {
                checkpoint(cx)?;
                let vdev = group.members.get(dva.vdev as usize).ok_or_else(|| {
                    unsupported("foreign-vdev gang header requires another topology")
                })?;
                let member = &self.members[vdev.supplied_index];
                let end = member.length / LABEL_BYTES * LABEL_BYTES - 2 * LABEL_BYTES;
                if vdev.allocated_bytes == 0
                    || !vdev.allocated_bytes.is_multiple_of(allocated)
                    || vdev.allocated_bytes > end - DATA_OFFSET
                {
                    return Err(corrupt(
                        "configured gang allocation region exceeds a selected member",
                    ));
                }
                if !dva.offset.is_multiple_of(allocated)
                    || !dva.allocated_bytes.is_multiple_of(allocated)
                    || dva.allocated_bytes < allocated
                    || dva.allocated_bytes > vdev.allocated_bytes
                    || dva
                        .offset
                        .checked_add(allocated)
                        .is_none_or(|limit| limit > vdev.allocated_bytes)
                {
                    return Err(corrupt("unaligned or out-of-range gang-header DVA"));
                }
            }
            return Ok(dvas);
        }
        let allocated = header_allocation(config)?;
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
            if group.parity != 0 {
                // The stripe verifier recognizes gang headers and uses their
                // embedded identity checksum, not the leader's payload checksum.
                return self.read_raidz_block(cx, config, pointer, group);
            }
            let header_allocations = header_allocations(config, pointer)?;
            let dvas = self.gang_header_dvas(cx, config, pointer)?;
            let mut failures = Vec::new();
            for (copy_index, dva) in dvas.iter().enumerate() {
                checkpoint(cx)?;
                let vdev = &group.members[dva.vdev as usize];
                let member_index = vdev.supplied_index;
                let offset = DATA_OFFSET + dva.offset;
                let result = self.members[member_index]
                    .read(cx, offset, HEADER_BYTES)
                    .and_then(|bytes| {
                        GangHeader::parse(&bytes, pointer, &header_allocations)
                            .map_err(|error| parse(&error))?;
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
                        "header DVA {copy_index} (vdev {}): {error}",
                        dva.vdev
                    )),
                }
            }
            return Err(corrupt(format!(
                "all ZFS striped gang-header copies failed: {}",
                failures.join("; ")
            )));
        }
        let allocated = header_allocation(config)?;
        let dvas = self.gang_header_dvas(cx, config, pointer)?;
        let header_allocations = vec![allocated; dvas.len()];
        let mut failures = Vec::new();
        for (copy_index, dva) in dvas.iter().enumerate() {
            let offset = DATA_OFFSET + dva.offset;
            for (member_index, member) in self.members.iter().enumerate() {
                checkpoint(cx)?;
                let result = member.read(cx, offset, HEADER_BYTES).and_then(|bytes| {
                    GangHeader::parse(&bytes, pointer, &header_allocations)
                        .map_err(|error| parse(&error))?;
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

companion_bin_tests! {
    #[cfg(test)]
    mod tests;
}
