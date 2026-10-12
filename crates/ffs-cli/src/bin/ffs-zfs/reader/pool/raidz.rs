//! Verified reads through an admitted ordinary RAIDZ1, RAIDZ2 or RAIDZ3 group.
//!
//! Validate every declared DVA and member extent before any data I/O. Intact
//! data needs no parity. Recovery considers at most three erased columns among
//! eight members, including corrupt-but-readable parity, and only publishes a
//! candidate after the original physical checksum and transform both succeed.

use super::Pool;
use crate::reader::{
    BlockPointer, BlockRead, Cx, DATA_OFFSET, Dva, FfsError, LABEL_BYTES, RaidzColumnInfo,
    RaidzGroup, RaidzMember, RaidzReadInfo, Result, VdevConfig, checkpoint, corrupt, parse,
    unsupported,
};
use ffs_ondisk::zfs::gang::{GangHeader, HEADER_BYTES};
use ffs_ondisk::zfs::raidz::parity::RaidzParityMap;
use ffs_ondisk::zfs::raidz::{Raidz1Map, RaidzColumn};
use std::collections::BTreeSet;

/// Keep the existing RAIDZ1 XOR path; only multi-parity uses field inversion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::reader) enum NativeMap {
    Single(Raidz1Map),
    Multiple(RaidzParityMap),
}

impl NativeMap {
    pub(in crate::reader) fn new(
        offset: u64,
        bytes: usize,
        ashift: u8,
        width: usize,
        parity: usize,
    ) -> Result<Self> {
        match parity {
            1 => Raidz1Map::new(offset, bytes, ashift, width)
                .map(Self::Single)
                .map_err(|error| parse(&error)),
            2 | 3 => RaidzParityMap::new(offset, bytes, ashift, width, parity)
                .map(Self::Multiple)
                .map_err(|error| parse(&error)),
            _ => Err(unsupported(
                "ordinary RAIDZ requires one through three parity columns",
            )),
        }
    }

    pub(in crate::reader) fn parity(&self) -> usize {
        match self {
            Self::Single(_) => 1,
            Self::Multiple(map) => map.parity(),
        }
    }

    #[cfg(test)]
    pub(in crate::reader) fn aligned_bytes(&self) -> usize {
        match self {
            Self::Single(map) => map.aligned_bytes(),
            Self::Multiple(map) => map.aligned_bytes(),
        }
    }

    pub(in crate::reader) fn allocated_bytes(&self) -> u64 {
        match self {
            Self::Single(map) => map.allocated_bytes(),
            Self::Multiple(map) => map.allocated_bytes(),
        }
    }

    pub(in crate::reader) fn columns(&self) -> &[RaidzColumn] {
        match self {
            Self::Single(map) => map.columns(),
            Self::Multiple(map) => map.columns(),
        }
    }

    pub(in crate::reader) fn assemble(
        &self,
        columns: &[Option<&[u8]>],
        erased: &[usize],
    ) -> Result<Vec<u8>> {
        match self {
            Self::Single(map) => {
                let erased = match erased {
                    [] => None,
                    [index] => Some(*index),
                    _ => return Err(corrupt("RAIDZ1 cannot reconstruct multiple data columns")),
                };
                map.assemble(columns, erased).map_err(|error| parse(&error))
            }
            Self::Multiple(map) => map.assemble(columns, erased).map_err(|error| parse(&error)),
        }
    }
}

struct Stripe<'a> {
    map: &'a NativeMap,
    members: &'a [RaidzMember],
    pointer: &'a BlockPointer,
    header_allocations: &'a [u64],
    dva_offset: u64,
    copy_index: usize,
}

struct Columns {
    bytes: Vec<Option<Vec<u8>>>,
    missing: Vec<usize>,
    failures: Vec<String>,
}

impl Pool {
    pub(super) fn raidz_maps(
        &self,
        cx: &Cx,
        config: &VdevConfig,
        bp: &BlockPointer,
        group: &RaidzGroup,
    ) -> Result<Vec<(Dva, NativeMap)>> {
        checkpoint(cx)?;
        let members = &group.members;
        let dvas = if bp.gang() {
            bp.gang_dvas(&super::gang::header_allocations(config, bp)?)
        } else {
            bp.regular_dvas()
        }
        .map_err(|error| parse(&error))?;
        if !(1..=3).contains(&group.parity)
            || !(group.parity + 1..=8).contains(&members.len())
            || members.len() != self.members.len()
            || !(9..=16).contains(&config.ashift)
        {
            return Err(corrupt("invalid admitted RAIDZ member or parity geometry"));
        }
        let sector = 1_u64 << config.ashift;
        let width = members.len() as u64;
        if config.allocated_bytes == 0 || !config.allocated_bytes.is_multiple_of(width * sector) {
            return Err(corrupt(
                "RAIDZ allocation region is not a whole member stripe",
            ));
        }
        let member_capacity = config.allocated_bytes / width;
        let mut indices = BTreeSet::new();
        let mut guids = BTreeSet::new();
        for member in members {
            checkpoint(cx)?;
            let leaf = self
                .members
                .get(member.supplied_index)
                .ok_or_else(|| corrupt("RAIDZ child maps outside supplied members"))?;
            if !indices.insert(member.supplied_index)
                || member.guid == 0
                || !guids.insert(member.guid)
            {
                return Err(corrupt("RAIDZ child mapping repeats a supplied identity"));
            }
            let end = leaf.length / LABEL_BYTES * LABEL_BYTES - 2 * LABEL_BYTES;
            if member_capacity > end - DATA_OFFSET {
                return Err(corrupt(
                    "configured RAIDZ capacity exceeds a selected member",
                ));
            }
        }
        let mut maps = Vec::with_capacity(dvas.len());
        for dva in dvas {
            checkpoint(cx)?;
            if dva.vdev != config.id {
                return Err(unsupported(
                    "foreign-vdev DVA needs a different native mapping",
                ));
            }
            if dva.gang != bp.gang() {
                return Err(corrupt("mixed gang and ordinary RAIDZ DVA flags"));
            }
            let map = NativeMap::new(
                dva.offset,
                if bp.gang() {
                    HEADER_BYTES
                } else {
                    bp.physical_bytes()
                },
                config.ashift,
                members.len(),
                group.parity,
            )?;
            // Gang ASIZE accounts for scattered descendants. Only the header
            // map is contiguous here; every child's map is bounded separately.
            let valid_allocation = if bp.gang() {
                dva.allocated_bytes >= map.allocated_bytes()
                    && dva.allocated_bytes.is_multiple_of(sector)
                    && dva.allocated_bytes <= config.allocated_bytes
            } else {
                dva.allocated_bytes == map.allocated_bytes()
            };
            if !valid_allocation
                || dva
                    .offset
                    .checked_add(map.allocated_bytes())
                    .is_none_or(|end| end > config.allocated_bytes)
            {
                return Err(corrupt("RAIDZ DVA allocation size or bounds disagree"));
            }
            for column in map.columns() {
                if column
                    .offset
                    .checked_add(column.allocated_bytes as u64)
                    .is_none_or(|end| end > member_capacity)
                {
                    return Err(corrupt(
                        "RAIDZ column allocation exceeds its configured member",
                    ));
                }
            }
            maps.push((dva, map));
        }
        Ok(maps)
    }

    pub(super) fn read_raidz_block(
        &self,
        cx: &Cx,
        config: &VdevConfig,
        bp: &BlockPointer,
        group: &RaidzGroup,
    ) -> Result<BlockRead> {
        // Complete every map before a usable first DVA can conceal another
        // foreign, unsupported or out-of-range declared copy.
        let maps = self.raidz_maps(cx, config, bp, group)?;
        let header_allocations: Vec<_> = if bp.gang() {
            maps.iter().map(|(_, map)| map.allocated_bytes()).collect()
        } else {
            Vec::new()
        };
        let mut failures = Vec::new();
        for (copy_index, (dva, map)) in maps.iter().enumerate() {
            checkpoint(cx)?;
            let stripe = Stripe {
                map,
                members: &group.members,
                pointer: bp,
                header_allocations: &header_allocations,
                dva_offset: dva.offset,
                copy_index,
            };
            match self.read_raidz_stripe(cx, &stripe) {
                Ok(block) => {
                    checkpoint(cx)?;
                    return Ok(block);
                }
                Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
                Err(error) => failures.push(format!("DVA {copy_index}: {error}")),
            }
        }
        Err(corrupt(format!(
            "all ZFS RAIDZ block copies failed: {}",
            failures.join("; ")
        )))
    }

    fn read_raidz_data(&self, cx: &Cx, stripe: &Stripe<'_>) -> Result<Columns> {
        let mut result = Columns {
            bytes: (0..stripe.map.columns().len()).map(|_| None).collect(),
            missing: Vec::new(),
            failures: Vec::new(),
        };
        for (index, column) in stripe.map.columns().iter().enumerate() {
            if column.data_offset.is_none() {
                continue;
            }
            checkpoint(cx)?;
            let member = &stripe.members[column.child_id];
            match self.members[member.supplied_index].read(
                cx,
                DATA_OFFSET + column.offset,
                column.bytes,
            ) {
                Ok(bytes) => result.bytes[index] = Some(bytes),
                Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
                Err(error) => {
                    result.missing.push(index);
                    result
                        .failures
                        .push(format!("child {}: {error}", column.child_id));
                }
            }
        }
        Ok(result)
    }

    fn read_raidz_stripe(&self, cx: &Cx, stripe: &Stripe<'_>) -> Result<BlockRead> {
        let mut columns = self.read_raidz_data(cx, stripe)?;
        if columns.missing.is_empty() {
            match verify_candidate(cx, stripe, &columns.bytes, &[]) {
                Ok(bytes) => return Ok(stripe.complete(bytes, false, &[])),
                Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
                Err(error) => columns
                    .failures
                    .push(format!("unreconstructed data: {error}")),
            }
        } else if columns.missing.len() > stripe.map.parity() {
            return Err(corrupt(format!(
                "RAIDZ data erasures exceed native parity: {}",
                columns.failures.join("; ")
            )));
        }

        // Read each parity at most once. An unavailable P does not preclude Q
        // or R recovery, and a readable but corrupt parity is not authoritative.
        for index in 0..stripe.map.parity() {
            checkpoint(cx)?;
            let parity = &stripe.map.columns()[index];
            let member = &stripe.members[parity.child_id];
            match self.members[member.supplied_index].read(
                cx,
                DATA_OFFSET + parity.offset,
                parity.bytes,
            ) {
                Ok(bytes) => columns.bytes[index] = Some(bytes),
                Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
                Err(error) => {
                    columns.missing.push(index);
                    columns
                        .failures
                        .push(format!("parity child {}: {error}", parity.child_id));
                }
            }
        }
        for erased in recovery_hypotheses(stripe.map, &columns.missing) {
            checkpoint(cx)?;
            match verify_candidate(cx, stripe, &columns.bytes, &erased) {
                Ok(bytes) => return Ok(stripe.complete(bytes, true, &erased)),
                Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
                Err(error) => columns
                    .failures
                    .push(format!("erased columns {erased:?}: {error}")),
            }
        }
        Err(corrupt(format!(
            "RAIDZ data cannot be verified within {}-column recovery: {}",
            stripe.map.parity(),
            columns.failures.join("; ")
        )))
    }
}

/// At most 92 hypotheses (eight choose one, two or three), independent of file
/// size. Known I/O failures are mandatory exclusions; skip-only columns are
/// never candidates. Excluding parity lets later Q/R equations reject a bad P.
fn recovery_hypotheses(map: &NativeMap, missing: &[usize]) -> Vec<Vec<usize>> {
    let active = map
        .columns()
        .iter()
        .take_while(|column| column.bytes != 0)
        .count();
    if missing.len() > map.parity() || missing.iter().any(|&index| index >= active) {
        return Vec::new();
    }
    let required = missing
        .iter()
        .fold(0_u16, |mask, &index| mask | (1_u16 << index));
    let parity_mask = (1_u16 << map.parity()) - 1;
    let mut candidates = Vec::new();
    for count in missing.len().max(1)..=map.parity() {
        for mask in 1_u16..1_u16 << active {
            if mask.count_ones() as usize != count
                || mask & required != required
                || mask & !parity_mask == 0
            {
                continue;
            }
            candidates.push(
                (0..active)
                    .filter(|&index| mask & (1_u16 << index) != 0)
                    .collect(),
            );
        }
    }
    candidates
}

fn verify_candidate(
    cx: &Cx,
    stripe: &Stripe<'_>,
    columns: &[Option<Vec<u8>>],
    erased: &[usize],
) -> Result<Vec<u8>> {
    checkpoint(cx)?;
    let slices: Vec<_> = columns.iter().map(Option::as_deref).collect();
    let physical = stripe.map.assemble(&slices, erased)?;
    checkpoint(cx)?;
    let bytes = if stripe.pointer.gang() {
        GangHeader::parse(&physical, stripe.pointer, stripe.header_allocations)
            .map_err(|error| parse(&error))?;
        physical
    } else {
        stripe
            .pointer
            .decode(&physical)
            .map_err(|error| parse(&error))?
    };
    checkpoint(cx)?;
    Ok(bytes)
}

impl Stripe<'_> {
    fn complete(&self, bytes: Vec<u8>, parity_read: bool, erased: &[usize]) -> BlockRead {
        let first = &self.map.columns()[self.map.parity()];
        let columns = self
            .map
            .columns()
            .iter()
            .enumerate()
            .map(|(index, column)| RaidzColumnInfo {
                child_id: column.child_id,
                member_guid: self.members[column.child_id].guid,
                physical_offset: DATA_OFFSET + column.offset,
                bytes: column.bytes,
                parity: index < self.map.parity(),
            })
            .collect();
        BlockRead {
            bytes,
            physical_offset: DATA_OFFSET + first.offset,
            copy_index: self.copy_index,
            member_index: self.members[first.child_id].supplied_index,
            raidz: Some(RaidzReadInfo {
                dva_offset: self.dva_offset,
                allocated_bytes: self.map.allocated_bytes(),
                columns,
                parity_read,
                reconstructed_children: erased
                    .iter()
                    .filter_map(|&index| {
                        let column = &self.map.columns()[index];
                        column.data_offset.map(|_| column.child_id)
                    })
                    .collect(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hypotheses_include_every_recoverable_failure_set_without_skip_columns() {
        for parity in 1..=3 {
            for width in parity + 1..=8 {
                for size in [512, 1024, 16_384] {
                    let map = NativeMap::new(0, size, 9, width, parity).unwrap();
                    let active = map
                        .columns()
                        .iter()
                        .filter(|column| column.bytes != 0)
                        .count();
                    for known in 0_u16..1_u16 << active {
                        let missing: Vec<_> = (0..active)
                            .filter(|&index| known & (1 << index) != 0)
                            .collect();
                        let candidates = recovery_hypotheses(&map, &missing);
                        assert!(candidates.len() <= 92);
                        for lost in 1_u16..1_u16 << active {
                            let actual: Vec<_> = (0..active)
                                .filter(|&index| lost & (1 << index) != 0)
                                .collect();
                            let expected = lost.count_ones() as usize <= parity
                                && lost & known == known
                                && actual.iter().any(|&index| index >= parity);
                            assert_eq!(candidates.contains(&actual), expected);
                        }
                    }
                }
            }
        }
    }
}
