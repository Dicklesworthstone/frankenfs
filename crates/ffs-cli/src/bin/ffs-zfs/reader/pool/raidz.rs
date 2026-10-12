//! Verified reads through one admitted ordinary RAIDZ1 group.
//!
//! All member/DVA allocation extents are checked before I/O. Data is tried
//! without parity first; parity is needed only for an erasure or a failed
//! checksum. Each recovery hypothesis is bounded to one native data column.

use super::Pool;
use crate::reader::{
    BlockPointer, BlockRead, Cx, DATA_OFFSET, Dva, FfsError, LABEL_BYTES, RaidzColumnInfo,
    RaidzMember, RaidzReadInfo, Result, VdevConfig, checkpoint, corrupt, parse, unsupported,
};
use ffs_ondisk::zfs::raidz::Raidz1Map;
use std::collections::BTreeSet;

struct Stripe<'a> {
    map: &'a Raidz1Map,
    members: &'a [RaidzMember],
    pointer: &'a BlockPointer,
    dva_offset: u64,
    copy_index: usize,
}

struct Columns {
    bytes: Vec<Option<Vec<u8>>>,
    missing: Vec<usize>,
    failures: Vec<String>,
}

impl Pool {
    fn raidz_maps(
        &self,
        cx: &Cx,
        config: &VdevConfig,
        bp: &BlockPointer,
        members: &[RaidzMember],
    ) -> Result<Vec<(Dva, Raidz1Map)>> {
        checkpoint(cx)?;
        let dvas = bp.regular_dvas().map_err(|error| parse(&error))?;
        if !(2..=8).contains(&members.len())
            || members.len() != self.members.len()
            || !(9..=16).contains(&config.ashift)
        {
            return Err(corrupt("invalid admitted RAIDZ1 member geometry"));
        }
        let sector = 1_u64 << config.ashift;
        let width = members.len() as u64;
        if config.allocated_bytes == 0 || !config.allocated_bytes.is_multiple_of(width * sector) {
            return Err(corrupt(
                "RAIDZ1 allocation region is not a whole member stripe",
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
                .ok_or_else(|| corrupt("RAIDZ1 child maps outside supplied members"))?;
            if !indices.insert(member.supplied_index)
                || member.guid == 0
                || !guids.insert(member.guid)
            {
                return Err(corrupt("RAIDZ1 child mapping repeats a supplied identity"));
            }
            let end = leaf.length / LABEL_BYTES * LABEL_BYTES - 2 * LABEL_BYTES;
            if member_capacity > end - DATA_OFFSET {
                return Err(corrupt(
                    "configured RAIDZ1 capacity exceeds a selected member",
                ));
            }
        }
        let mut maps = Vec::with_capacity(dvas.len());
        for dva in dvas {
            checkpoint(cx)?;
            if dva.vdev != config.id || dva.gang {
                return Err(unsupported(
                    "foreign-vdev or gang DVA needs a different native mapping",
                ));
            }
            let map = Raidz1Map::new(
                dva.offset,
                bp.physical_bytes(),
                config.ashift,
                members.len(),
            )
            .map_err(|error| parse(&error))?;
            if dva.allocated_bytes != map.allocated_bytes()
                || dva
                    .offset
                    .checked_add(dva.allocated_bytes)
                    .is_none_or(|end| end > config.allocated_bytes)
            {
                return Err(corrupt("RAIDZ1 DVA allocation size or bounds disagree"));
            }
            for column in map.columns() {
                if column
                    .offset
                    .checked_add(column.allocated_bytes as u64)
                    .is_none_or(|end| end > member_capacity)
                {
                    return Err(corrupt(
                        "RAIDZ1 column allocation exceeds its configured member",
                    ));
                }
            }
            maps.push((dva, map));
        }
        Ok(maps)
    }

    pub(super) fn read_raidz1_block(
        &self,
        cx: &Cx,
        config: &VdevConfig,
        bp: &BlockPointer,
        members: &[RaidzMember],
    ) -> Result<BlockRead> {
        // Finish the complete map set before any usable first DVA can conceal
        // an out-of-range, foreign or unsupported later DVA.
        let maps = self.raidz_maps(cx, config, bp, members)?;
        let mut failures = Vec::new();
        for (copy_index, (dva, map)) in maps.iter().enumerate() {
            checkpoint(cx)?;
            let stripe = Stripe {
                map,
                members,
                pointer: bp,
                dva_offset: dva.offset,
                copy_index,
            };
            match self.read_raidz1_stripe(cx, &stripe) {
                Ok(block) => {
                    checkpoint(cx)?;
                    return Ok(block);
                }
                Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
                Err(error) => failures.push(format!("DVA {copy_index}: {error}")),
            }
        }
        Err(corrupt(format!(
            "all ZFS RAIDZ1 block copies failed: {}",
            failures.join("; ")
        )))
    }

    fn read_raidz1_data(&self, cx: &Cx, stripe: &Stripe<'_>) -> Result<Columns> {
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

    fn read_raidz1_stripe(&self, cx: &Cx, stripe: &Stripe<'_>) -> Result<BlockRead> {
        let mut columns = self.read_raidz1_data(cx, stripe)?;
        if columns.missing.is_empty() {
            match verify_candidate(cx, stripe, &columns.bytes, None) {
                Ok(bytes) => return Ok(stripe.complete(bytes, false, None)),
                Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
                Err(error) => columns
                    .failures
                    .push(format!("unreconstructed data: {error}")),
            }
        } else if columns.missing.len() > 1 {
            return Err(corrupt(format!(
                "multiple RAIDZ1 data columns are unavailable: {}",
                columns.failures.join("; ")
            )));
        }

        checkpoint(cx)?;
        let parity = &stripe.map.columns()[0];
        let member = &stripe.members[parity.child_id];
        columns.bytes[0] = Some(
            self.members[member.supplied_index]
                .read(cx, DATA_OFFSET + parity.offset, parity.bytes)
                .map_err(|error| match error {
                    FfsError::Cancelled => FfsError::Cancelled,
                    other => corrupt(format!(
                        "RAIDZ1 parity child {} is unavailable: {other}",
                        parity.child_id
                    )),
                })?,
        );
        let candidates = if columns.missing.is_empty() {
            stripe
                .map
                .columns()
                .iter()
                .enumerate()
                .filter_map(|(index, column)| column.data_offset.map(|_| index))
                .collect()
        } else {
            columns.missing
        };
        for index in candidates {
            checkpoint(cx)?;
            match verify_candidate(cx, stripe, &columns.bytes, Some(index)) {
                Ok(bytes) => return Ok(stripe.complete(bytes, true, Some(index))),
                Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
                Err(error) => columns.failures.push(format!(
                    "erased child {}: {error}",
                    stripe.map.columns()[index].child_id
                )),
            }
        }
        Err(corrupt(format!(
            "RAIDZ1 data cannot be verified within one-column recovery: {}",
            columns.failures.join("; ")
        )))
    }
}

fn verify_candidate(
    cx: &Cx,
    stripe: &Stripe<'_>,
    columns: &[Option<Vec<u8>>],
    erased: Option<usize>,
) -> Result<Vec<u8>> {
    checkpoint(cx)?;
    let slices: Vec<_> = columns.iter().map(Option::as_deref).collect();
    let physical = stripe
        .map
        .assemble(&slices, erased)
        .map_err(|error| parse(&error))?;
    checkpoint(cx)?;
    let bytes = stripe
        .pointer
        .decode(&physical)
        .map_err(|error| parse(&error))?;
    checkpoint(cx)?;
    Ok(bytes)
}

impl Stripe<'_> {
    fn complete(&self, bytes: Vec<u8>, parity_read: bool, erased: Option<usize>) -> BlockRead {
        let first = &self.map.columns()[1];
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
                parity: index == 0,
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
                reconstructed_child: erased.map(|index| self.map.columns()[index].child_id),
            }),
        }
    }
}
