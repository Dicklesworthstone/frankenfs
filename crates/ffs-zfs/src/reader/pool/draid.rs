//! Verified reads and bounded P/Q/R recovery for OpenZFS `zfs-2.4.0` dRAID
//! (`org.openzfs:draid`) groups, including 1-row and 2-row cross-group blocks
//! and explicitly declared absent members (`Pool::from_draid_survivors`).

use super::super::{
    BlockPointer, BlockRead, Cx, DATA_OFFSET, Dva, FfsError, LABEL_BYTES, Leaf, RaidzColumnInfo,
    RaidzMember, RaidzReadInfo, Result, VdevConfig, checkpoint, corrupt, decode_or_verify, integer,
    parse, unsupported,
};
use super::Pool;
use super::missing_raidz::ABSENT_RAIDZ_INDEX;
use ffs_ondisk::zfs::draid::{DraidConfig, DraidMap};
use ffs_ondisk::zfs::gang::{GangHeader, HEADER_BYTES};
use std::collections::BTreeSet;

/// Bound on dRAID erasure hypothesis search per row so wide groups (`<= 255`)
/// never trigger unbounded combinatorial explosions during read recovery.
const MAX_DRAID_HYPOTHESES_PER_ROW: usize = 4096;

/// Admitted dRAID group configuration plus native child-ID -> leaf routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraidGroup {
    pub(crate) config: DraidConfig,
    pub(crate) members: Vec<RaidzMember>,
}

/// Generate all erasure subsets of `0..groupwidth` of size `missing.len()..=parity`
/// that include every known-missing column in `missing` and at least one data
/// column (`>= parity`). Works for any `groupwidth <= 255` (no `u16` bitmask limit).
pub(super) fn draid_column_hypotheses(
    groupwidth: usize,
    parity: usize,
    missing: &[usize],
) -> Vec<Vec<usize>> {
    if missing.len() > parity || missing.iter().any(|&idx| idx >= groupwidth) {
        return Vec::new();
    }
    let mut base: Vec<usize> = missing.to_vec();
    base.sort_unstable();
    base.dedup();
    if base.len() > parity {
        return Vec::new();
    }
    let available: Vec<usize> = (0..groupwidth).filter(|idx| !base.contains(idx)).collect();
    let mut out = Vec::new();

    for target_len in base.len().max(1)..=parity {
        let extra = target_len - base.len();
        if extra == 0 {
            if base.iter().any(|&idx| idx >= parity) {
                out.push(base.clone());
            }
            continue;
        }
        let mut chosen = Vec::with_capacity(extra);
        collect_combinations(
            &available,
            0,
            extra,
            &mut chosen,
            &base,
            parity,
            &mut out,
            MAX_DRAID_HYPOTHESES_PER_ROW,
        );
        if out.len() >= MAX_DRAID_HYPOTHESES_PER_ROW {
            break;
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn collect_combinations(
    pool: &[usize],
    start: usize,
    need: usize,
    chosen: &mut Vec<usize>,
    base: &[usize],
    parity: usize,
    out: &mut Vec<Vec<usize>>,
    cap: usize,
) {
    if out.len() >= cap {
        return;
    }
    if need == 0 {
        let mut set = Vec::with_capacity(base.len() + chosen.len());
        set.extend_from_slice(base);
        set.extend_from_slice(chosen);
        set.sort_unstable();
        if set.iter().any(|&idx| idx >= parity) {
            out.push(set);
        }
        return;
    }
    if pool.len().saturating_sub(start) < need {
        return;
    }
    for i in start..=pool.len() - need {
        chosen.push(pool[i]);
        collect_combinations(pool, i + 1, need - 1, chosen, base, parity, out, cap);
        chosen.pop();
        if out.len() >= cap {
            return;
        }
    }
}

impl Pool {
    /// Validate request-shape parameters for read-only dRAID survivor extraction.
    pub fn check_draid_survivors(supplied: usize, missing: &[u64]) -> Result<()> {
        if supplied == 0
            || !(1..=3).contains(&missing.len())
            || supplied
                .checked_add(missing.len())
                .is_none_or(|total| !(2..=255).contains(&total))
        {
            return Err(unsupported(
                "missing dRAID extraction needs survivors, 1..=3 missing GUIDs, and 2..=255 total children",
            ));
        }
        let mut seen = BTreeSet::new();
        for &guid in missing {
            if guid == 0 || !seen.insert(guid) {
                return Err(unsupported(
                    "missing dRAID GUIDs must be nonzero and unique",
                ));
            }
        }
        Ok(())
    }

    /// Explicitly open an exported dRAID group with `1..=nparity` declared
    /// missing children (read-only; never grants writable import authority).
    pub fn from_draid_survivors(cx: &Cx, members: Vec<Leaf>, missing: Vec<u64>) -> Result<Self> {
        checkpoint(cx)?;
        Self::check_draid_survivors(members.len(), &missing)?;
        let first = members[0].label(cx, 0)?;
        let pool_guid = integer(&first.config, "pool_guid")?;
        if pool_guid == 0 {
            return Err(corrupt("dRAID label has zero pool_guid"));
        }
        let tree = first
            .config
            .list("vdev_tree")
            .ok_or_else(|| corrupt("dRAID label missing vdev_tree"))?;
        let draid_cfg = super::vdev::parse_draid_tree_config(tree)?;
        if missing.len() > draid_cfg.nparity {
            return Err(unsupported(
                "missing dRAID member count exceeds group nparity",
            ));
        }
        if members.len() + missing.len() != draid_cfg.children {
            return Err(unsupported(
                "supplied + missing dRAID members must equal configured dRAID child count",
            ));
        }
        let mut pool = Self::from_wide_leaves(members)?;
        pool.missing_raidz_guids = missing;
        Ok(pool)
    }

    /// Map and bounds-check every DVA of `bp` on a dRAID top-level vdev before
    /// issuing any payload I/O.
    pub(super) fn draid_maps(
        &self,
        cx: &Cx,
        config: &VdevConfig,
        bp: &BlockPointer,
        group: &DraidGroup,
    ) -> Result<Vec<(Dva, DraidMap)>> {
        checkpoint(cx)?;
        let physical_bytes = if bp.gang() {
            HEADER_BYTES
        } else {
            bp.physical_bytes()
        };
        let header_alloc = group
            .config
            .psize_to_asize((HEADER_BYTES as u64).next_multiple_of(1_u64 << group.config.ashift))
            .map_err(|e| parse(&e))?;
        let dvas = if bp.gang() {
            let count = bp.data_dvas().map_err(|e| parse(&e))?.len();
            bp.gang_dvas(&vec![header_alloc; count])
        } else {
            bp.data_dvas()
        }
        .map_err(|e| parse(&e))?;

        if group.members.len() != group.config.children
            || group.members.len() != self.members.len() + self.missing_raidz_guids.len()
            || self.missing_raidz_guids.len() > group.config.nparity
        {
            return Err(corrupt(
                "dRAID member partition disagrees with configuration",
            ));
        }
        let mut member_limits = Vec::with_capacity(group.members.len());
        for member in &group.members {
            checkpoint(cx)?;
            if member.supplied_index == ABSENT_RAIDZ_INDEX {
                if !self.missing_raidz_guids.contains(&member.guid) {
                    return Err(corrupt("dRAID route has an undeclared absent child"));
                }
                member_limits.push(u64::MAX);
            } else {
                let leaf = self
                    .members
                    .get(member.supplied_index)
                    .ok_or_else(|| corrupt("dRAID child index out of bounds"))?;
                let end = leaf.length / LABEL_BYTES * LABEL_BYTES - 2 * LABEL_BYTES;
                member_limits.push(end.saturating_sub(DATA_OFFSET));
            }
        }

        let mut maps = Vec::with_capacity(dvas.len());
        for dva in dvas {
            checkpoint(cx)?;
            if dva.vdev != config.id {
                return Err(unsupported("foreign-vdev DVA on dRAID top-level vdev"));
            }
            let map =
                DraidMap::new(&group.config, dva.offset, physical_bytes).map_err(|e| parse(&e))?;
            let valid_alloc = if bp.gang() {
                dva.allocated_bytes >= map.allocated_bytes()
            } else {
                dva.allocated_bytes == map.allocated_bytes()
            };
            if !valid_alloc
                || dva
                    .offset
                    .checked_add(map.allocated_bytes())
                    .is_none_or(|end| end > config.allocated_bytes)
            {
                return Err(corrupt("dRAID DVA allocation size or bounds disagree"));
            }
            for row in map.rows() {
                for col in &row.columns {
                    let limit = member_limits[col.child_id];
                    if col
                        .offset
                        .checked_add(col.full_bytes as u64)
                        .is_none_or(|end| end > limit)
                    {
                        return Err(corrupt(
                            "dRAID column physical offset exceeds member capacity",
                        ));
                    }
                }
            }
            maps.push((dva, map));
        }
        Ok(maps)
    }

    /// Verified read of a regular or gang-header block from a dRAID top-level
    /// vdev, with automatic bounded P/Q/R erasure & corruption reconstruction.
    pub(super) fn read_draid_block_inner(
        &self,
        cx: &Cx,
        config: &VdevConfig,
        bp: &BlockPointer,
        group: &DraidGroup,
        raw_only: bool,
    ) -> Result<BlockRead> {
        let maps = self.draid_maps(cx, config, bp, group)?;
        let header_allocations: Vec<u64> = if bp.gang() {
            maps.iter().map(|(_, m)| m.allocated_bytes()).collect()
        } else {
            Vec::new()
        };
        let mut failures = Vec::new();
        for (copy_index, (dva, map)) in maps.iter().enumerate() {
            checkpoint(cx)?;
            match self.read_draid_copy(
                cx,
                bp,
                group,
                dva,
                map,
                &header_allocations,
                copy_index,
                raw_only,
            ) {
                Ok(block) => return Ok(block),
                Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
                Err(err) => failures.push(format!("dRAID DVA {copy_index}: {err}")),
            }
        }
        Err(corrupt(format!(
            "all ZFS dRAID block copies failed: {}",
            failures.join("; ")
        )))
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn read_draid_copy(
        &self,
        cx: &Cx,
        bp: &BlockPointer,
        group: &DraidGroup,
        dva: &Dva,
        map: &DraidMap,
        header_allocations: &[u64],
        copy_index: usize,
        raw_only: bool,
    ) -> Result<BlockRead> {
        let mut row_bufs: Vec<Vec<Option<Vec<u8>>>> = Vec::with_capacity(map.rows().len());
        let mut row_missing: Vec<Vec<usize>> = Vec::with_capacity(map.rows().len());
        let mut failures = Vec::new();

        // 1. Read active data columns for every row.
        for row in map.rows() {
            let mut cols: Vec<Option<Vec<u8>>> = vec![None; row.columns.len()];
            let mut missing = Vec::new();
            for (idx, col) in row.columns.iter().enumerate().skip(row.parity) {
                if col.bytes == 0 {
                    continue;
                }
                checkpoint(cx)?;
                let member = &group.members[col.child_id];
                match self.read_raidz_member(cx, member, DATA_OFFSET + col.offset, col.bytes) {
                    Ok(bytes) => cols[idx] = Some(bytes),
                    Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
                    Err(err) => {
                        missing.push(idx);
                        failures.push(format!("child {}: {err}", col.child_id));
                    }
                }
            }
            if missing.len() > row.parity {
                return Err(corrupt(format!(
                    "dRAID data erasures exceed nparity ({}): {}",
                    row.parity,
                    failures.join("; ")
                )));
            }
            row_bufs.push(cols);
            row_missing.push(missing);
        }

        // Fast path: no missing data columns -> verify direct assembly first.
        if row_missing.iter().all(Vec::is_empty) {
            let empty: Vec<&[usize]> = vec![&[]; map.rows().len()];
            match verify_draid_candidate(
                cx,
                map,
                bp,
                header_allocations,
                &row_bufs,
                &empty,
                raw_only,
            ) {
                Ok(bytes) => {
                    return Ok(Self::complete_draid_read(
                        group, dva, map, copy_index, bytes, false, &empty,
                    ));
                }
                Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
                Err(err) => failures.push(format!("direct dRAID verify: {err}")),
            }
        }

        // 2. Read parity columns (and full column buffers for short columns) for recovery.
        for (r_idx, row) in map.rows().iter().enumerate() {
            for (idx, col) in row.columns.iter().enumerate().take(row.parity) {
                checkpoint(cx)?;
                let member = &group.members[col.child_id];
                match self.read_raidz_member(cx, member, DATA_OFFSET + col.offset, col.full_bytes) {
                    Ok(bytes) => row_bufs[r_idx][idx] = Some(bytes),
                    Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
                    Err(err) => {
                        row_missing[r_idx].push(idx);
                        failures.push(format!("parity child {}: {err}", col.child_id));
                    }
                }
            }
        }

        // 3. Test bounded recovery hypotheses across the 1 or 2 rows.
        let per_row_hyps: Vec<Vec<Vec<usize>>> = map
            .rows()
            .iter()
            .enumerate()
            .map(|(r_idx, row)| {
                let mut h = Vec::new();
                if row_missing[r_idx].is_empty() {
                    h.push(Vec::new());
                }
                h.extend(draid_column_hypotheses(
                    row.columns.len(),
                    row.parity,
                    &row_missing[r_idx],
                ));
                h
            })
            .collect();

        if per_row_hyps.len() == 1 {
            for erased in &per_row_hyps[0] {
                if erased.is_empty() {
                    continue;
                }
                checkpoint(cx)?;
                let refs = [erased.as_slice()];
                match verify_draid_candidate(
                    cx,
                    map,
                    bp,
                    header_allocations,
                    &row_bufs,
                    &refs,
                    raw_only,
                ) {
                    Ok(bytes) => {
                        return Ok(Self::complete_draid_read(
                            group, dva, map, copy_index, bytes, true, &refs,
                        ));
                    }
                    Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
                    Err(_) => {}
                }
            }
        } else {
            // 2-row cross-group block: test single-row and paired combinations cleanly.
            let mut tested = 0_usize;
            for h0 in &per_row_hyps[0] {
                for h1 in &per_row_hyps[1] {
                    if h0.is_empty() && h1.is_empty() {
                        continue;
                    }
                    tested += 1;
                    if tested > MAX_DRAID_HYPOTHESES_PER_ROW {
                        break;
                    }
                    checkpoint(cx)?;
                    let refs = [h0.as_slice(), h1.as_slice()];
                    match verify_draid_candidate(
                        cx,
                        map,
                        bp,
                        header_allocations,
                        &row_bufs,
                        &refs,
                        raw_only,
                    ) {
                        Ok(bytes) => {
                            return Ok(Self::complete_draid_read(
                                group, dva, map, copy_index, bytes, true, &refs,
                            ));
                        }
                        Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
                        Err(_) => {}
                    }
                }
                if tested > MAX_DRAID_HYPOTHESES_PER_ROW {
                    break;
                }
            }
        }

        Err(corrupt(format!(
            "dRAID data cannot be verified within {}-parity recovery: {}",
            map.parity(),
            failures.join("; ")
        )))
    }

    #[allow(clippy::too_many_arguments)]
    fn complete_draid_read(
        group: &DraidGroup,
        dva: &Dva,
        map: &DraidMap,
        copy_index: usize,
        bytes: Vec<u8>,
        parity_read: bool,
        erased_per_row: &[&[usize]],
    ) -> BlockRead {
        let mut columns = Vec::new();
        let mut reconstructed_children = Vec::new();
        let mut first_data_offset = DATA_OFFSET;
        let mut report_member = 0_usize;
        let mut found_first = false;
        for (r_idx, row) in map.rows().iter().enumerate() {
            for (c_idx, col) in row.columns.iter().enumerate() {
                let member = &group.members[col.child_id];
                if !found_first && col.data_offset.is_some() {
                    first_data_offset = DATA_OFFSET + col.offset;
                    if member.supplied_index != ABSENT_RAIDZ_INDEX {
                        report_member = member.supplied_index;
                    }
                    found_first = true;
                }
                if erased_per_row[r_idx].contains(&c_idx) && col.data_offset.is_some() {
                    reconstructed_children.push(col.child_id);
                }
                columns.push(RaidzColumnInfo {
                    child_id: col.child_id,
                    member_guid: member.guid,
                    physical_offset: DATA_OFFSET + col.offset,
                    bytes: col.bytes,
                    parity: c_idx < row.parity,
                });
            }
        }
        BlockRead {
            bytes,
            physical_offset: first_data_offset,
            copy_index,
            member_index: report_member,
            raidz: Some(RaidzReadInfo {
                dva_offset: dva.offset,
                allocated_bytes: map.allocated_bytes(),
                columns,
                parity_read,
                reconstructed_children,
            }),
        }
    }
}

fn verify_draid_candidate(
    cx: &Cx,
    map: &DraidMap,
    bp: &BlockPointer,
    header_allocations: &[u64],
    row_bufs: &[Vec<Option<Vec<u8>>>],
    erased_per_row: &[&[usize]],
    raw_only: bool,
) -> Result<Vec<u8>> {
    checkpoint(cx)?;
    let slices: Vec<Vec<Option<&[u8]>>> = row_bufs
        .iter()
        .map(|row| row.iter().map(Option::as_deref).collect())
        .collect();
    let physical = map
        .assemble_rows(&slices, erased_per_row)
        .map_err(|e| parse(&e))?;
    checkpoint(cx)?;
    let out = if bp.gang() {
        GangHeader::parse(&physical, bp, header_allocations).map_err(|e| parse(&e))?;
        physical
    } else {
        decode_or_verify(bp, physical, raw_only)?
    };
    checkpoint(cx)?;
    Ok(out)
}
