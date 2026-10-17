//! Native ZIL I/O over the already admitted immutable storage set.
//!
//! The embedded log verifier, not an ordinary BP checksum, decides whether a
//! replica or reconstructed stripe is usable. No claim, repair or write occurs.

use super::super::super::pool::raidz::NativeMap;
use super::super::super::{Pool, RaidzGroup};
use super::{
    Cx, FfsError, MAX_LOG_BYTES, Pointer, Result, VdevConfig, checkpoint, corrupt, unsupported,
};
use ffs_ondisk::zfs::{DATA_OFFSET, Dva, LABEL_BYTES};
use std::collections::{BTreeMap, BTreeSet};

const MAX_RECONSTRUCTION_BYTES: usize = 256 * 1024 * 1024;

#[derive(Default)]
pub(super) struct ReadState {
    pub(super) physical_bytes: usize,
    pub(super) reconstruction_bytes: usize,
    allocations: BTreeMap<(usize, u64), u64>,
}

struct Extent {
    member: usize,
    offset: u64,
    allocated: u64,
    bytes: usize,
}

enum CopyPlan {
    Replica(Extent),
    Stripe {
        map: NativeMap,
        columns: Vec<Extent>,
    },
}

impl ReadState {
    fn claim(&mut self, extent: &Extent) -> Result<()> {
        self.physical_bytes = self
            .physical_bytes
            .checked_add(extent.bytes)
            .filter(|bytes| *bytes <= MAX_LOG_BYTES)
            .ok_or_else(|| {
                unsupported("ZIL scan exceeds 64 MiB physical work including replicas and parity")
            })?;
        if extent.allocated == 0 {
            return Ok(());
        }
        let end = extent
            .offset
            .checked_add(extent.allocated)
            .ok_or_else(|| corrupt("ZIL extent overflow"))?;
        if self
            .allocations
            .range((extent.member, 0)..(extent.member, end))
            .next_back()
            .is_some_and(|(_, old_end)| *old_end > extent.offset)
        {
            return Err(corrupt(
                "ZIL blocks or replicas alias an allocation interval",
            ));
        }
        self.allocations.insert((extent.member, extent.offset), end);
        Ok(())
    }

    fn assemble(
        &mut self,
        cx: &Cx,
        map: &NativeMap,
        columns: &[Option<Vec<u8>>],
        erased: &[usize],
    ) -> Result<Vec<u8>> {
        checkpoint(cx)?;
        // Charge native padded column bytes, including parity. PSIZE alone
        // understates work when a log block is smaller than the vdev sector.
        let bytes = map.columns().iter().try_fold(0_usize, |sum, column| {
            sum.checked_add(column.bytes)
                .ok_or_else(|| corrupt("ZIL column work overflow"))
        })?;
        self.reconstruction_bytes = self
            .reconstruction_bytes
            .checked_add(bytes)
            .filter(|work| *work <= MAX_RECONSTRUCTION_BYTES)
            .ok_or_else(|| unsupported("ZIL scan exceeds 256 MiB RAIDZ assembly work"))?;
        let slices: Vec<_> = columns.iter().map(Option::as_deref).collect();
        let raw = map.assemble(&slices, erased)?;
        checkpoint(cx)?;
        Ok(raw)
    }
}

fn raidz_plan(
    pool: &Pool,
    config: &VdevConfig,
    pointer: &Pointer,
    group: &RaidzGroup,
    dva: &Dva,
) -> Result<CopyPlan> {
    let width = group.members.len();
    if !(1..=3).contains(&group.parity)
        || !(group.parity + 1..=8).contains(&width)
        || width != pool.leaves().len()
        || !(9..=16).contains(&config.ashift)
    {
        return Err(corrupt("invalid admitted ZIL RAIDZ geometry"));
    }
    let sector = 1_u64 << config.ashift;
    if config.allocated_bytes == 0 || !config.allocated_bytes.is_multiple_of(width as u64 * sector)
    {
        return Err(corrupt("ZIL RAIDZ capacity is not a whole member stripe"));
    }
    let capacity = config.allocated_bytes / width as u64;
    let mut indices = BTreeSet::new();
    let mut guids = BTreeSet::new();
    for member in &group.members {
        let leaf = pool
            .leaves()
            .get(member.supplied_index)
            .ok_or_else(|| corrupt("ZIL RAIDZ child has no supplied member"))?;
        if !indices.insert(member.supplied_index) || member.guid == 0 || !guids.insert(member.guid)
        {
            return Err(corrupt("ZIL RAIDZ mapping repeats a member"));
        }
        let end = leaf.length / LABEL_BYTES * LABEL_BYTES - 2 * LABEL_BYTES;
        if capacity > end - DATA_OFFSET {
            return Err(corrupt("ZIL RAIDZ capacity exceeds a selected member"));
        }
    }
    if dva.vdev != config.id || dva.gang {
        return Err(unsupported(
            "ZIL pointer references an unconfigured or gang vdev",
        ));
    }
    let map = NativeMap::new(
        dva.offset,
        pointer.bp.physical_bytes(),
        config.ashift,
        width,
        group.parity,
    )?;
    if dva.allocated_bytes != map.allocated_bytes()
        || dva
            .offset
            .checked_add(map.allocated_bytes())
            .is_none_or(|end| end > config.allocated_bytes)
    {
        return Err(corrupt("ZIL RAIDZ DVA allocation size or bounds disagree"));
    }
    let mut columns = Vec::with_capacity(map.columns().len());
    for column in map.columns() {
        if column
            .offset
            .checked_add(column.allocated_bytes as u64)
            .is_none_or(|end| end > capacity)
        {
            return Err(corrupt(
                "ZIL RAIDZ column exceeds its native member allocation",
            ));
        }
        let member = group
            .members
            .get(column.child_id)
            .ok_or_else(|| corrupt("ZIL RAIDZ column has no native child"))?;
        columns.push(Extent {
            member: member.supplied_index,
            offset: column.offset,
            allocated: column.allocated_bytes as u64,
            bytes: column.bytes,
        });
    }
    Ok(CopyPlan::Stripe { map, columns })
}

fn plans(
    cx: &Cx,
    pool: &Pool,
    config: &VdevConfig,
    pointer: &Pointer,
    state: &mut ReadState,
) -> Result<Vec<CopyPlan>> {
    if pool.leaves().is_empty() || pool.leaves().len() > 8 {
        return Err(corrupt("invalid ZIL storage set"));
    }
    let mut plans = Vec::new();
    for dva in &pointer.dvas {
        checkpoint(cx)?;
        if let Some(group) = &config.raidz_members {
            if group.parity != 0 {
                plans.push(raidz_plan(pool, config, pointer, group, dva)?);
                continue;
            }
            let member = group
                .members
                .get(dva.vdev as usize)
                .ok_or_else(|| unsupported("ZIL DVA references an unconfigured top-level vdev"))?;
            let leaf = pool
                .leaves()
                .get(member.supplied_index)
                .ok_or_else(|| corrupt("ZIL top-level vdev has no supplied member"))?;
            if !(9..=16).contains(&member.ashift) {
                return Err(corrupt("invalid ZIL top-level ashift"));
            }
            leaf.validate_dva_for_vdev(
                member.ashift,
                member.allocated_bytes,
                dva.vdev,
                &pointer.bp,
                dva,
            )?;
            plans.push(CopyPlan::Replica(Extent {
                member: member.supplied_index,
                offset: dva.offset,
                allocated: dva.allocated_bytes,
                bytes: pointer.bp.physical_bytes(),
            }));
        } else {
            if !(9..=16).contains(&config.ashift) {
                return Err(corrupt("invalid ZIL leaf/mirror ashift"));
            }
            for (member, leaf) in pool.leaves().iter().enumerate() {
                checkpoint(cx)?;
                leaf.validate_dva_for_vdev(
                    config.ashift,
                    config.allocated_bytes,
                    config.id,
                    &pointer.bp,
                    dva,
                )?;
                plans.push(CopyPlan::Replica(Extent {
                    member,
                    offset: dva.offset,
                    allocated: dva.allocated_bytes,
                    bytes: pointer.bp.physical_bytes(),
                }));
            }
        }
    }
    // Admit every copy, including skip-sector allocations, before a good first
    // replica can conceal a bad address, alias or exhausted work budget.
    for plan in &plans {
        match plan {
            CopyPlan::Replica(extent) => state.claim(extent)?,
            CopyPlan::Stripe { columns, .. } => {
                for extent in columns {
                    state.claim(extent)?;
                }
            }
        }
    }
    Ok(plans)
}

fn read_extent(cx: &Cx, pool: &Pool, extent: &Extent) -> Result<Vec<u8>> {
    checkpoint(cx)?;
    pool.leaves()[extent.member].read(cx, DATA_OFFSET + extent.offset, extent.bytes)
}

fn read_stripe(
    cx: &Cx,
    pool: &Pool,
    pointer: &Pointer,
    map: &NativeMap,
    extents: &[Extent],
    state: &mut ReadState,
) -> Result<Option<Vec<u8>>> {
    let mut columns: Vec<Option<Vec<u8>>> = (0..extents.len()).map(|_| None).collect();
    let mut missing = 0_u16;
    let mut io_error = None;
    for (index, extent) in extents.iter().enumerate().skip(map.parity()) {
        if extent.bytes == 0 {
            continue;
        }
        match read_extent(cx, pool, extent) {
            Ok(bytes) => columns[index] = Some(bytes),
            Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
            Err(error) => {
                missing |= 1_u16 << index;
                io_error = Some(error);
            }
        }
    }
    if missing == 0 {
        let raw = state.assemble(cx, map, &columns, &[])?;
        if pointer.checksum_valid(&raw)? {
            return Ok(Some(raw));
        }
    }
    // A checksum failure can be an unwritten tail, but only after all available
    // equations have failed. I/O failure is never successful end-of-log.
    for (index, extent) in extents.iter().enumerate().take(map.parity()) {
        if extent.bytes == 0 {
            continue;
        }
        match read_extent(cx, pool, extent) {
            Ok(bytes) => columns[index] = Some(bytes),
            Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
            Err(error) => {
                missing |= 1_u16 << index;
                io_error = Some(error);
            }
        }
    }
    let active = extents
        .iter()
        .take_while(|extent| extent.bytes != 0)
        .count();
    let parity_mask = (1_u16 << map.parity()) - 1;
    for count in 1..=map.parity() {
        for mask in 1_u16..1_u16 << active {
            if mask.count_ones() as usize != count
                || mask & missing != missing
                || mask & !parity_mask == 0
            {
                continue;
            }
            let erased: Vec<_> = (0..active)
                .filter(|&index| mask & (1_u16 << index) != 0)
                .collect();
            let raw = match state.assemble(cx, map, &columns, &erased) {
                Ok(raw) => raw,
                Err(FfsError::Corruption { .. }) => continue,
                Err(error) => return Err(error),
            };
            if pointer.checksum_valid(&raw)? {
                return Ok(Some(raw));
            }
        }
    }
    match io_error {
        Some(error) => Err(error),
        None => Ok(None),
    }
}
pub(super) fn read_block(
    cx: &Cx,
    pool: &Pool,
    config: &VdevConfig,
    pointer: &Pointer,
    state: &mut ReadState,
) -> Result<Option<Vec<u8>>> {
    let plans = plans(cx, pool, config, pointer, state)?;
    let mut last_error = None;
    for plan in &plans {
        checkpoint(cx)?;
        let result = match plan {
            CopyPlan::Replica(extent) => read_extent(cx, pool, extent)
                .and_then(|raw| Ok(pointer.checksum_valid(&raw)?.then_some(raw))),
            CopyPlan::Stripe { map, columns } => {
                read_stripe(cx, pool, pointer, map, columns, state)
            }
        };
        match result {
            Ok(Some(raw)) => {
                checkpoint(cx)?;
                return Ok(Some(raw));
            }
            Ok(None) => {}
            Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
            Err(error @ FfsError::UnsupportedFeature(_)) => return Err(error),
            Err(error) => last_error = Some(error),
        }
    }
    checkpoint(cx)?;
    match last_error {
        Some(error) => Err(error),
        None => Ok(None),
    }
}
