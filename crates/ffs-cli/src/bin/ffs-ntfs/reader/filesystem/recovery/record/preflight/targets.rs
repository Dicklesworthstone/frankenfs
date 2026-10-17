//! Reconstruct native open-attribute identities and dirty VCN/LCN claims.
//!
//! Layout and operation semantics: Linux v6.17 fs/ntfs3/fslog.c Analysis
//! (OPEN_ATTR_ENRTY, DIR_PAGE_ENTRY, OpenNonresidentAttribute, HotFix and
//! DeleteDirtyClusters). Claims are NOT verified physical allocation ownership.
//! No target-page I/O, writes, or mount authorization is performed here.

use super::{
    Cx, LFS_CLIENT_RECORD, LogRecord, Result, checkpoint, corrupt, table::RestartTable, u16_at,
    u32_at, u64_at, unsupported,
};
use std::collections::{BTreeMap, BTreeSet};

const MAX_ATTRIBUTES: usize = 4096;
const MAX_CLUSTERS: usize = 65_536;
const MAX_WORK: usize = 4 * 1024 * 1024;
const OPEN_ATTRIBUTE: u16 = 0x1C;
const DELETE_CLUSTERS: u16 = 0x0A;
const HOT_FIX: u16 = 0x17;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Attribute {
    pub(super) reference: u64,
    pub(super) kind: u32,
    pub(super) index_bytes: u32,
    pub(super) opened: u64,
    pub(super) name: Vec<u16>,
}

impl Attribute {
    fn parse(data: &[u8], boundary: u64) -> Result<Self> {
        if data.len() != 40 {
            return Err(unsupported(
                "$LogFile target needs a native 40-byte open attribute",
            ));
        }
        let reference = u64_at(data, 16)?;
        let kind = u32_at(data, 8)?;
        let opened = u64_at(data, 24)?;
        if reference == 0 || opened > boundary {
            return Err(corrupt(
                0,
                "invalid $LogFile open-attribute identity or LSN",
            ));
        }
        if !(0x10..=0x100).contains(&kind) || !kind.is_multiple_of(0x10) {
            return Err(unsupported("unknown $LogFile open-attribute type"));
        }
        // The native pointer/allocator/volatile fields are never dereferenced
        // or interpreted as an on-disk attribute name.
        Ok(Self {
            reference,
            kind,
            index_bytes: u32_at(data, 4)?,
            opened,
            name: Vec::new(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Cluster {
    pub(super) oldest: u64,
    // Native zero means no surviving dirty mapping, NOT physical cluster zero.
    pub(super) lcn: Option<u64>,
}

#[derive(Debug, Default)]
pub(super) struct State {
    pub(super) attributes: BTreeMap<u32, Attribute>,
    pub(super) clusters: BTreeMap<(u32, u64), Cluster>,
    last_seen: u64,
    work: usize,
}

fn slot(value: u32) -> Result<u32> {
    if value < 24 || value > u32::from(u16::MAX) || !(value - 24).is_multiple_of(40) {
        return Err(corrupt(
            0,
            "$LogFile target is not an aligned open-attribute slot",
        ));
    }
    Ok(value)
}

fn lcn(value: u64) -> Result<Option<u64>> {
    if value > i64::MAX as u64 {
        return Err(corrupt(0, "negative $LogFile target LCN"));
    }
    Ok((value != 0).then_some(value))
}

fn name(data: &[u8]) -> Result<Vec<u16>> {
    if !data.len().is_multiple_of(2) || data.len() > 510 {
        return Err(corrupt(0, "invalid $LogFile native attribute-name length"));
    }
    Ok(data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|word| u16::from_le_bytes(*word))
        .collect())
}

/// The caller has decoded the LFS record, but semantic payload consumers still
/// validate the complete variable header and their own selected byte range.
pub(super) fn payload(record: &LogRecord, undo: bool) -> Result<&[u8]> {
    let data = &record.data;
    let count = usize::from(u16_at(data, 14)?);
    let minimum = 32 + count.max(1) * 8;
    if minimum > data.len() {
        return Err(corrupt(0, "truncated $LogFile mapping header"));
    }
    let at = if undo { 8 } else { 4 };
    let offset = usize::from(u16_at(data, at)?);
    let size = usize::from(u16_at(data, at + 2)?);
    if size == 0 && offset == 0 {
        return Ok(&data[..0]);
    }
    if offset < minimum || !offset.is_multiple_of(8) {
        return Err(corrupt(0, "$LogFile target payload overlaps its header"));
    }
    data.get(offset..offset + size)
        .ok_or_else(|| corrupt(0, "truncated $LogFile target payload"))
}

pub(super) fn changes_pages(op: u16) -> bool {
    matches!(op, 0x02..=0x09 | 0x0B..=0x16 | 0x21..=0x25)
}

impl State {
    fn charge(&mut self, amount: usize) -> Result<()> {
        self.work = self
            .work
            .checked_add(amount)
            .filter(|work| *work <= MAX_WORK)
            .ok_or_else(|| unsupported("$LogFile target Analysis exceeds its work budget"))?;
        Ok(())
    }

    pub(super) fn seed_attributes(
        &mut self,
        cx: &Cx,
        table: &RestartTable<'_>,
        boundary: u64,
    ) -> Result<()> {
        checkpoint(cx)?;
        if table.entry_size != 40 || table.entries.len() > MAX_ATTRIBUTES {
            return Err(unsupported(
                "$LogFile target attribute table exceeds the native profile",
            ));
        }
        for (&id, bytes) in &table.entries {
            checkpoint(cx)?;
            self.charge(1)?;
            let id = slot(id)?;
            let attribute = Attribute::parse(bytes, boundary)?;
            if self.attributes.insert(id, attribute).is_some() {
                return Err(corrupt(0, "duplicate checkpoint open-attribute slot"));
            }
        }
        checkpoint(cx)
    }

    pub(super) fn seed_names(&mut self, cx: &Cx, data: &[u8]) -> Result<()> {
        let mut at = 0;
        let mut seen = BTreeSet::new();
        loop {
            checkpoint(cx)?;
            self.charge(1)?;
            let id = u32::from(u16_at(data, at)?);
            let size = usize::from(u16_at(data, at + 2)?);
            at += 4;
            if id == 0 {
                if size != 0 || data[at..].iter().any(|byte| *byte != 0) {
                    return Err(corrupt(0, "invalid checkpoint attribute-name terminator"));
                }
                return checkpoint(cx);
            }
            let id = slot(id)?;
            let bytes = data
                .get(at..at + size)
                .ok_or_else(|| corrupt(0, "truncated checkpoint attribute name"))?;
            let decoded = name(bytes)?;
            if !seen.insert(id) {
                return Err(corrupt(0, "duplicate checkpoint attribute name"));
            }
            self.attributes
                .get_mut(&id)
                .ok_or_else(|| corrupt(0, "checkpoint name has no open attribute"))?
                .name = decoded;
            at += size;
        }
    }

    pub(super) fn seed_dirty(&mut self, cx: &Cx, table: &RestartTable<'_>) -> Result<()> {
        checkpoint(cx)?;
        if table.entry_size < 40 {
            return Err(corrupt(0, "short checkpoint dirty-page entries"));
        }
        for entry in table.entries.values() {
            checkpoint(cx)?;
            let id = slot(u32_at(entry, 4)?)?;
            let count = usize::try_from(u32_at(entry, 12)?)
                .map_err(|_| corrupt(0, "dirty-page cluster count overflow"))?;
            let vcn = u64_at(entry, 16)?;
            let oldest = u64_at(entry, 24)?;
            if !self.attributes.contains_key(&id)
                || oldest == 0
                || count == 0
                || count > (entry.len() - 32) / 8
                || vcn.checked_add(count as u64).is_none()
            {
                return Err(corrupt(0, "invalid checkpoint dirty-page mapping"));
            }
            self.charge(count)?;
            for index in 0..count {
                checkpoint(cx)?;
                let key = (id, vcn + index as u64);
                let value = Cluster {
                    oldest,
                    lcn: lcn(u64_at(entry, 32 + index * 8)?)?,
                };
                if let Some(existing) = self.clusters.get_mut(&key) {
                    // Native tables can repeat a VCN for sub-cluster pages.
                    // Agreeing mappings merge; contradictory physical claims do not.
                    if existing.lcn != value.lcn {
                        return Err(corrupt(0, "conflicting checkpoint VCN/LCN claims"));
                    }
                    existing.oldest = existing.oldest.min(oldest);
                } else {
                    if self.clusters.len() == MAX_CLUSTERS {
                        return Err(unsupported(
                            "$LogFile target Analysis exceeds 65536 clusters",
                        ));
                    }
                    self.clusters.insert(key, value);
                }
            }
        }
        checkpoint(cx)
    }

    fn open(&mut self, cx: &Cx, record: &LogRecord) -> Result<()> {
        let id = slot(u32::from(u16_at(&record.data, 12)?))?;
        let mut value = Attribute::parse(payload(record, false)?, record.lsn)?;
        value.name = name(payload(record, true)?)?;
        // The physical OpenNonresidentAttribute record establishes this lifetime,
        // even when the serialized native entry has an initial zero open LSN.
        value.opened = record.lsn;
        if let Some(existing) = self.attributes.get(&id) {
            if value.opened < existing.opened {
                return Ok(()); // Earlier incarnation already superseded by the checkpoint.
            }
            if value.opened == existing.opened {
                if *existing != value {
                    return Err(corrupt(
                        0,
                        "open-attribute record disagrees with its checkpoint identity",
                    ));
                }
                return Ok(());
            }
            if existing.reference == value.reference
                && existing.kind == value.kind
                && existing.index_bytes == value.index_bytes
                && existing.name == value.name
            {
                // Reopening the same stream must not erase its outstanding
                // checkpoint dirty pages or raise their redo low-water mark.
                return Ok(());
            }
        } else if self.attributes.len() == MAX_ATTRIBUTES {
            return Err(unsupported(
                "$LogFile target Analysis exceeds 4096 attributes",
            ));
        }
        // Do not carry another incarnation's mapping into the new file/stream.
        self.charge(self.clusters.len())?;
        if self
            .clusters
            .iter()
            .any(|((target, _), entry)| *target == id && entry.lcn.is_some())
        {
            return Err(unsupported(
                "$LogFile reuses an attribute slot with unresolved dirty ownership",
            ));
        }
        self.clusters.retain(|(target, _), _| *target != id);
        self.attributes.insert(id, value);
        checkpoint(cx)
    }

    fn mapping(&mut self, cx: &Cx, record: &LogRecord, hotfix: bool) -> Result<()> {
        let count = usize::from(u16_at(&record.data, 14)?);
        if count == 0 && !hotfix {
            return Ok(()); // No native page update is described by this record.
        }
        if hotfix && count > 1 {
            return Err(unsupported("$LogFile HotFix has multiple replacement LCNs"));
        }
        // Native LOG_REC_HDR includes one physical word even when lcns_follow
        // is zero. HotFix uses that first word, not a count-sized page update.
        let count = if hotfix { 1 } else { count };
        let id = slot(u32::from(u16_at(&record.data, 12)?))?;
        let vcn = u64_at(&record.data, 24)?;
        if vcn.checked_add(count as u64).is_none() || 32 + count * 8 > record.data.len() {
            return Err(corrupt(0, "invalid $LogFile update VCN/LCN span"));
        }
        self.charge(count)?;
        // Validate the entire array before changing any mappings.
        let mut values = Vec::with_capacity(count);
        for index in 0..count {
            checkpoint(cx)?;
            values.push(lcn(u64_at(&record.data, 32 + index * 8)?)?);
        }
        if self
            .attributes
            .get(&id)
            .is_some_and(|attribute| record.lsn < attribute.opened)
        {
            return Ok(());
        }
        if hotfix {
            if let Some(entry) = self.clusters.get_mut(&(id, vcn))
                && entry.lcn.is_some()
            {
                // HotFix relocates existing dirty data; unlike reuse after
                // deletion, earlier redo must still target the replacement.
                entry.lcn = values[0];
            }
            return checkpoint(cx);
        }
        for (index, value) in values.into_iter().enumerate() {
            checkpoint(cx)?;
            let key = (id, vcn + index as u64);
            if let Some(entry) = self.clusters.get_mut(&key) {
                if entry.lcn.is_none() && value.is_some() {
                    entry.oldest = record.lsn; // New allocation, not an old redo target.
                }
                entry.lcn = value;
            } else {
                if self.clusters.len() == MAX_CLUSTERS {
                    return Err(unsupported(
                        "$LogFile target Analysis exceeds 65536 clusters",
                    ));
                }
                self.clusters.insert(
                    key,
                    Cluster {
                        oldest: record.lsn,
                        lcn: value,
                    },
                );
            }
        }
        checkpoint(cx)
    }

    fn delete(&mut self, cx: &Cx, record: &LogRecord) -> Result<()> {
        let data = payload(record, false)?;
        if !data.len().is_multiple_of(16) {
            return Err(corrupt(0, "partial $LogFile deleted-cluster range"));
        }
        let mut ranges = Vec::with_capacity(data.len() / 16);
        self.charge(data.len() / 16 + self.clusters.len())?;
        for at in (0..data.len()).step_by(16) {
            checkpoint(cx)?;
            let start = u64_at(data, at)?;
            let count = u64_at(data, at + 8)?;
            let end = start
                .checked_add(count)
                .filter(|end| *end <= i64::MAX as u64 + 1)
                .ok_or_else(|| corrupt(0, "overflowing $LogFile deleted-cluster range"))?;
            if count == 0 || start > i64::MAX as u64 {
                return Err(corrupt(
                    0,
                    "empty or negative $LogFile deleted-cluster range",
                ));
            }
            ranges.push((start, end));
        }
        ranges.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::new();
        for (start, end) in ranges {
            if let Some(last) = merged.last_mut()
                && start <= last.1
            {
                last.1 = last.1.max(end);
                continue;
            }
            merged.push((start, end));
        }
        for entry in self.clusters.values_mut() {
            checkpoint(cx)?;
            if let Some(physical) = entry.lcn {
                let index = merged.partition_point(|range| range.0 <= physical);
                if index != 0 && physical < merged[index - 1].1 {
                    entry.lcn = None;
                }
            }
        }
        checkpoint(cx)
    }

    pub(super) fn observe(&mut self, cx: &Cx, record: &LogRecord) -> Result<()> {
        checkpoint(cx)?;
        self.charge(1)?;
        if record.lsn == 0 || record.lsn <= self.last_seen {
            return Err(corrupt(0, "$LogFile target Analysis is not chronological"));
        }
        self.last_seen = record.lsn;
        if record.kind != LFS_CLIENT_RECORD {
            return Ok(());
        }
        match record.summary.redo_op {
            OPEN_ATTRIBUTE => self.open(cx, record)?,
            DELETE_CLUSTERS => self.delete(cx, record)?,
            HOT_FIX => self.mapping(cx, record, true)?,
            opcode if changes_pages(opcode) => self.mapping(cx, record, false)?,
            _ => {}
        }
        checkpoint(cx)
    }

    pub(super) fn finish(&self, cx: &Cx) -> Result<(usize, usize, Option<u64>)> {
        checkpoint(cx)?;
        let mut mapped = 0;
        let mut retired = 0;
        let mut oldest: Option<u64> = None;
        for (&(id, _), entry) in &self.clusters {
            checkpoint(cx)?;
            if entry.lcn.is_some() {
                if !self.attributes.contains_key(&id) {
                    return Err(corrupt(
                        0,
                        "surviving dirty mapping has no native attribute identity",
                    ));
                }
                mapped += 1;
                oldest = Some(oldest.map_or(entry.oldest, |lsn| lsn.min(entry.oldest)));
            } else {
                retired += 1;
            }
        }
        Ok((mapped, retired, oldest))
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::TailRecord;
    use super::*;

    fn record(
        lsn: u64,
        op: u16,
        id: u16,
        vcn: u64,
        lcns: &[u64],
        redo: &[u8],
        undo: &[u8],
    ) -> LogRecord {
        let start = 32 + lcns.len().max(1) * 8;
        let undo_start = (start + redo.len()).next_multiple_of(8);
        let mut data = vec![0; undo_start + undo.len()];
        data[..2].copy_from_slice(&op.to_le_bytes());
        data[4..6].copy_from_slice(&(start as u16).to_le_bytes());
        data[6..8].copy_from_slice(&(redo.len() as u16).to_le_bytes());
        data[8..10].copy_from_slice(&(undo_start as u16).to_le_bytes());
        data[10..12].copy_from_slice(&(undo.len() as u16).to_le_bytes());
        data[12..14].copy_from_slice(&id.to_le_bytes());
        data[14..16].copy_from_slice(&(lcns.len() as u16).to_le_bytes());
        data[24..32].copy_from_slice(&vcn.to_le_bytes());
        for (index, value) in lcns.iter().enumerate() {
            data[32 + index * 8..40 + index * 8].copy_from_slice(&value.to_le_bytes());
        }
        data[start..start + redo.len()].copy_from_slice(redo);
        data[undo_start..].copy_from_slice(undo);
        LogRecord {
            lsn,
            previous: 0,
            undo_next: 0,
            kind: LFS_CLIENT_RECORD,
            summary: TailRecord {
                transaction_id: 24,
                redo_op: op,
                undo_op: 0,
            },
            data,
        }
    }

    fn attribute(reference: u64, opened: u64) -> Vec<u8> {
        let mut bytes = vec![0; 40];
        bytes[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        bytes[8..12].copy_from_slice(&0x80_u32.to_le_bytes());
        bytes[16..24].copy_from_slice(&reference.to_le_bytes());
        bytes[24..32].copy_from_slice(&opened.to_le_bytes());
        bytes
    }

    fn state() -> State {
        let mut state = State::default();
        state
            .observe(
                &Cx::for_testing(),
                &record(
                    10,
                    OPEN_ATTRIBUTE,
                    24,
                    0,
                    &[],
                    &attribute((7 << 48) | 0x002a, 0),
                    &[0, 0xD8, 97, 0],
                ),
            )
            .unwrap();
        state
    }

    fn ranges(values: &[(u64, u64)]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|(start, count)| start.to_le_bytes().into_iter().chain(count.to_le_bytes()))
            .collect()
    }

    #[test]
    fn open_preserves_native_identity_name_and_ignores_serialized_pointers() {
        let mut value = attribute((7 << 48) | 0x002a, 0);
        value[32..40].fill(0xFF);
        let mut state = State::default();
        state
            .observe(
                &Cx::for_testing(),
                &record(10, OPEN_ATTRIBUTE, 24, 0, &[], &value, &[0, 0xD8, 97, 0]),
            )
            .unwrap();
        let target = &state.attributes[&24];
        assert_eq!(target.reference, (7 << 48) | 0x002a);
        assert_eq!(target.name, vec![0xD800, 97]);
        assert_eq!(target.opened, 10);
    }

    #[test]
    fn updates_keep_earliest_redo_lsn_and_hotfix_relocates_earlier_work() {
        let cx = Cx::for_testing();
        let mut state = state();
        state
            .observe(&cx, &record(20, 8, 24, 8, &[100, 200], b"a", &[]))
            .unwrap();
        state
            .observe(&cx, &record(30, 8, 24, 8, &[100], b"b", &[]))
            .unwrap();
        state
            .observe(&cx, &record(40, HOT_FIX, 24, 8, &[300], &[], &[]))
            .unwrap();
        assert_eq!(
            state.clusters[&(24, 8)],
            Cluster {
                oldest: 20,
                lcn: Some(300)
            }
        );
        assert_eq!(
            state.clusters[&(24, 9)],
            Cluster {
                oldest: 20,
                lcn: Some(200)
            }
        );
        assert_eq!(state.finish(&cx).unwrap(), (2, 0, Some(20)));
    }

    #[test]
    fn deletion_uses_half_open_ranges_and_reallocation_resets_redo_age() {
        let cx = Cx::for_testing();
        let mut state = state();
        state
            .observe(&cx, &record(20, 8, 24, 0, &[99, 100, 101, 102], b"a", &[]))
            .unwrap();
        state
            .observe(
                &cx,
                &record(30, DELETE_CLUSTERS, 0, 0, &[], &ranges(&[(100, 2)]), &[]),
            )
            .unwrap();
        state
            .observe(&cx, &record(40, HOT_FIX, 24, 1, &[500], &[], &[]))
            .unwrap();
        assert_eq!(state.clusters[&(24, 1)].lcn, None);
        state
            .observe(&cx, &record(50, 8, 24, 1, &[600], b"b", &[]))
            .unwrap();
        assert_eq!(
            state.clusters[&(24, 1)],
            Cluster {
                oldest: 50,
                lcn: Some(600)
            }
        );
        assert_eq!(state.finish(&cx).unwrap(), (3, 1, Some(20)));
        assert_eq!(state.clusters[&(24, 0)].lcn, Some(99));
        assert_eq!(state.clusters[&(24, 3)].lcn, Some(102));
    }

    #[test]
    fn deletion_does_not_expand_enormous_ranges_or_depend_on_range_order() {
        let cx = Cx::for_testing();
        let mut state = state();
        state
            .observe(&cx, &record(20, 8, 24, 0, &[99, 100, 101], b"x", &[]))
            .unwrap();
        let data = ranges(&[(101, i64::MAX as u64 - 100), (100, 2), (100, 1)]);
        state
            .observe(&cx, &record(30, DELETE_CLUSTERS, 0, 0, &[], &data, &[]))
            .unwrap();
        assert_eq!(state.finish(&cx).unwrap(), (1, 2, Some(20)));
    }

    #[test]
    fn reused_attribute_slot_does_not_inherit_old_file_clusters_or_name() {
        let cx = Cx::for_testing();
        let mut state = state();
        state
            .observe(&cx, &record(20, 8, 24, 0, &[99], b"a", &[]))
            .unwrap();
        state
            .observe(
                &cx,
                &record(25, DELETE_CLUSTERS, 0, 0, &[], &ranges(&[(99, 1)]), &[]),
            )
            .unwrap();
        state
            .observe(
                &cx,
                &record(
                    30,
                    OPEN_ATTRIBUTE,
                    24,
                    0,
                    &[],
                    &attribute((8 << 48) | 0x002b, 0),
                    &[],
                ),
            )
            .unwrap();
        assert!(state.clusters.is_empty());
        assert_eq!(state.attributes[&24].name, [] as [u16; 0]);
        state
            .observe(&cx, &record(40, 8, 24, 0, &[99], b"b", &[]))
            .unwrap();
        assert_eq!(state.clusters[&(24, 0)].oldest, 40);
    }

    #[test]
    fn reopen_preserves_dirty_stream_but_ambiguous_slot_reuse_is_not_authority() {
        let cx = Cx::for_testing();
        let mut state = state();
        state
            .observe(&cx, &record(20, 8, 24, 0, &[99], b"a", &[]))
            .unwrap();
        state
            .observe(
                &cx,
                &record(
                    30,
                    OPEN_ATTRIBUTE,
                    24,
                    0,
                    &[],
                    &attribute((7 << 48) | 0x002a, 0),
                    &[0, 0xD8, 97, 0],
                ),
            )
            .unwrap();
        assert_eq!(state.clusters[&(24, 0)].oldest, 20);
        assert!(
            state
                .observe(
                    &cx,
                    &record(
                        40,
                        OPEN_ATTRIBUTE,
                        24,
                        0,
                        &[],
                        &attribute((8 << 48) | 0x002b, 0),
                        &[]
                    )
                )
                .is_err()
        );
        assert_eq!(state.clusters[&(24, 0)].lcn, Some(99));
    }

    #[test]
    fn malformed_ranges_arrays_and_open_records_fail_before_mapping_changes() {
        let cx = Cx::for_testing();
        let bad = [
            record(20, DELETE_CLUSTERS, 0, 0, &[], &ranges(&[(100, 0)]), &[]),
            record(
                20,
                DELETE_CLUSTERS,
                0,
                0,
                &[],
                &ranges(&[(u64::MAX, 2)]),
                &[],
            ),
            record(20, DELETE_CLUSTERS, 0, 0, &[], &[1; 15], &[]),
            record(20, 8, 24, u64::MAX, &[100], &[], &[]),
            record(20, 8, 24, 0, &[100, u64::MAX], &[], &[]),
            record(20, OPEN_ATTRIBUTE, 25, 0, &[], &attribute(42, 0), &[]),
            record(20, OPEN_ATTRIBUTE, 24, 0, &[], &attribute(42, 0), &[1]),
            record(20, OPEN_ATTRIBUTE, 24, 0, &[], &attribute(42, 21), &[]),
        ];
        for record in bad {
            let mut state = state();
            assert!(state.observe(&cx, &record).is_err());
            assert!(state.clusters.is_empty());
            assert_eq!(state.attributes[&24].reference, (7 << 48) | 0x002a);
        }
    }

    #[test]
    fn zero_lcn_is_not_physical_zero_and_unknown_surviving_targets_fail() {
        let cx = Cx::for_testing();
        let mut state = State::default();
        state
            .observe(&cx, &record(10, 8, 24, 0, &[0], &[], &[]))
            .unwrap();
        assert_eq!(state.finish(&cx).unwrap(), (0, 1, None));
        state
            .observe(&cx, &record(20, 8, 24, 0, &[9], &[], &[]))
            .unwrap();
        assert!(state.finish(&cx).is_err());
    }

    #[test]
    fn target_analysis_is_chronological_and_has_a_cumulative_work_limit() {
        let cx = Cx::for_testing();
        let mut state = state();
        assert!(
            state
                .observe(&cx, &record(10, 0, 0, 0, &[], &[], &[]))
                .is_err()
        );
        state.work = MAX_WORK;
        assert!(
            state
                .observe(&cx, &record(20, 8, 24, 0, &[9], &[], &[]))
                .is_err()
        );
        assert!(state.clusters.is_empty());
    }

    #[test]
    fn checkpoint_dirty_overlap_merges_only_agreeing_native_claims() {
        let cx = Cx::for_testing();
        let mut a = vec![0; 40];
        a[4..8].copy_from_slice(&24_u32.to_le_bytes());
        a[12..16].copy_from_slice(&1_u32.to_le_bytes());
        a[24..32].copy_from_slice(&20_u64.to_le_bytes());
        a[32..40].copy_from_slice(&100_u64.to_le_bytes());
        let mut b = a.clone();
        b[24..32].copy_from_slice(&15_u64.to_le_bytes());
        let table = RestartTable {
            entry_size: 40,
            entries: BTreeMap::from([(24, a.as_slice()), (64, b.as_slice())]),
        };
        let mut state = state();
        state.seed_dirty(&cx, &table).unwrap();
        assert_eq!(
            state.clusters[&(24, 0)],
            Cluster {
                oldest: 15,
                lcn: Some(100)
            }
        );
        b[32..40].copy_from_slice(&200_u64.to_le_bytes());
        let conflicting = RestartTable {
            entry_size: 40,
            entries: BTreeMap::from([(24, a.as_slice()), (64, b.as_slice())]),
        };
        assert!(
            State {
                attributes: state.attributes,
                ..State::default()
            }
            .seed_dirty(&cx, &conflicting)
            .is_err()
        );
    }

    #[test]
    fn checkpoint_incarnation_blocks_older_open_and_mapping_rewind() {
        let cx = Cx::for_testing();
        let value = attribute((9 << 48) | 0x0032, 30);
        let table = RestartTable {
            entry_size: 40,
            entries: BTreeMap::from([(24, value.as_slice())]),
        };
        let mut state = State::default();
        state.seed_attributes(&cx, &table, 40).unwrap();
        state
            .observe(
                &cx,
                &record(10, OPEN_ATTRIBUTE, 24, 0, &[], &attribute(42, 0), &[]),
            )
            .unwrap();
        state
            .observe(&cx, &record(20, 8, 24, 0, &[99], &[], &[]))
            .unwrap();
        assert!(state.clusters.is_empty());
        assert_eq!(state.attributes[&24].reference, (9 << 48) | 0x0032);
    }

    #[test]
    fn serialized_checkpoint_rejects_conflicting_dirty_claims_in_live_preflight() {
        use super::super::super::{LFS_CLIENT_RESTART, PAGE_RECORD_END, Restart};

        const PAGE: usize = 4096;
        const FIRST: u64 = 34 * PAGE as u64;
        let lsns = [FIRST, FIRST + PAGE as u64, FIRST + 2 * PAGE as u64]
            .map(|offset| (1_u64 << 20) | ((offset + 128) / 8));
        for conflict in [false, true] {
            let mut attrs = vec![0; 64];
            attrs[..2].copy_from_slice(&40_u16.to_le_bytes());
            attrs[2..4].copy_from_slice(&1_u16.to_le_bytes());
            attrs[4..6].copy_from_slice(&1_u16.to_le_bytes());
            attrs[24..].copy_from_slice(&attribute((7 << 48) | 0x002a, 0));
            let mut dirty = vec![0; 104];
            dirty[..2].copy_from_slice(&40_u16.to_le_bytes());
            dirty[2..4].copy_from_slice(&2_u16.to_le_bytes());
            dirty[4..6].copy_from_slice(&2_u16.to_le_bytes());
            for at in [24, 64] {
                dirty[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
                dirty[at + 4..at + 8].copy_from_slice(&24_u32.to_le_bytes());
                dirty[at + 8..at + 12].copy_from_slice(&512_u32.to_le_bytes());
                dirty[at + 12..at + 16].copy_from_slice(&1_u32.to_le_bytes());
                dirty[at + 24..at + 32].copy_from_slice(&lsns[0].to_le_bytes());
                let physical = if conflict && at == 64 { 200_u64 } else { 100 };
                dirty[at + 32..at + 40].copy_from_slice(&physical.to_le_bytes());
            }
            let mut checkpoint_data = vec![0; 64];
            checkpoint_data[..4].copy_from_slice(&1_u32.to_le_bytes());
            checkpoint_data[8..16].copy_from_slice(&lsns[2].to_le_bytes());
            checkpoint_data[16..24].copy_from_slice(&lsns[0].to_le_bytes());
            checkpoint_data[32..40].copy_from_slice(&lsns[1].to_le_bytes());
            checkpoint_data[48..52].copy_from_slice(&(attrs.len() as u32).to_le_bytes());
            checkpoint_data[56..60].copy_from_slice(&(dirty.len() as u32).to_le_bytes());
            let mut tail = record(lsns[2], 0, 0, 0, &[], &[], &[]);
            tail.kind = LFS_CLIENT_RESTART;
            tail.data = checkpoint_data;
            let records = [
                record(lsns[0], 0x1D, 0, 0, &[], &attrs, &[]),
                record(lsns[1], 0x1F, 0, 0, &[], &dirty, &[]),
                tail,
            ];
            let mut pages = BTreeMap::new();
            for (index, record) in records.iter().enumerate() {
                let mut page = vec![0; PAGE];
                page[..4].copy_from_slice(b"RCRD");
                page[4..6].copy_from_slice(&40_u16.to_le_bytes());
                page[6..8].copy_from_slice(&9_u16.to_le_bytes());
                page[8..16].copy_from_slice(&record.lsn.to_le_bytes());
                page[16..20].copy_from_slice(&PAGE_RECORD_END.to_le_bytes());
                page[20..22].copy_from_slice(&1_u16.to_le_bytes());
                page[22..24].copy_from_slice(&1_u16.to_le_bytes());
                let end = (176 + record.data.len()).next_multiple_of(8);
                page[24..26].copy_from_slice(&(end as u16).to_le_bytes());
                page[32..40].copy_from_slice(&record.lsn.to_le_bytes());
                page[128..136].copy_from_slice(&record.lsn.to_le_bytes());
                page[152..156].copy_from_slice(&(record.data.len() as u32).to_le_bytes());
                page[156..158].copy_from_slice(&9_u16.to_le_bytes());
                page[160..164].copy_from_slice(&record.kind.to_le_bytes());
                page[164..168].copy_from_slice(&24_u32.to_le_bytes());
                page[176..176 + record.data.len()].copy_from_slice(&record.data);
                page[40..42].copy_from_slice(&0xCAFE_u16.to_le_bytes());
                for sector in 1..=8 {
                    let at = sector * 512;
                    let saved = [page[at - 2], page[at - 1]];
                    page[40 + sector * 2..42 + sector * 2].copy_from_slice(&saved);
                    page[at - 2..at].copy_from_slice(&0xCAFE_u16.to_le_bytes());
                }
                pages.insert(FIRST + index as u64 * PAGE as u64, page);
            }
            let restart = Restart {
                system_page: PAGE as u32,
                log_page: PAGE as u32,
                version: (2, 0),
                clean: false,
                current_lsn: lsns[2],
                seq_num_bits: 44,
                file_size: 4 * 1024 * 1024,
                last_lsn_data_len: 64,
                record_header_len: 48,
                data_off: 128,
                active_client_seq: Some(9),
                active_client_oldest_lsn: Some(lsns[0]),
                active_client_restart_lsn: Some(lsns[2]),
                area: Vec::new(),
            };
            let before = pages.clone();
            let result = super::super::validate(
                &Cx::for_testing(),
                &restart,
                restart.file_size,
                &records[2],
                &mut |offset, size| {
                    assert_eq!(size, PAGE);
                    pages
                        .get(&offset)
                        .cloned()
                        .ok_or_else(|| corrupt(offset, "unexpected fixture read"))
                },
                None,
            );
            assert_eq!(result.is_err(), conflict);
            assert_eq!(pages, before);
        }
    }
}
