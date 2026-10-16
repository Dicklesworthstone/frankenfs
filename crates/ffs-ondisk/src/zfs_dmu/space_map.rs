//! Native space-map records and bounded allocation reconstruction.
//!
//! Format: OpenZFS zfs-2.3.0 space_map.h / space_map.c. Records describe
//! allocation changes, not a bitmap. Zero is a valid one-unit allocation.
//! A caller must authenticate each DMU block and supply its exact used prefix;
//! two-word records may not cross a block boundary. This module performs no I/O.

use crate::zfs::{Endian, MAX_BLOCK_BYTES};
use ffs_types::ParseError;
use std::collections::BTreeMap;
use std::ops::Range;

fn invalid(reason: &'static str) -> ParseError {
    ParseError::InvalidField { field: "zfs.space_map", reason }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Recorded stream length, not the dnode's allocation or logical capacity.
    pub length: u64,
    /// Signed because a log space map can describe a net free operation.
    pub allocated: i64,
    /// Advisory when unflushed log-space-map updates exist; never free authority.
    pub histogram: Option<[u64; 32]>,
}

impl Header {
    pub fn parse(raw: &[u8], order: Endian) -> Result<Self, ParseError> {
        if !matches!(raw.len(), 24 | 320) {
            return Err(invalid("unsupported space-map bonus size"));
        }
        let length = order.u64(raw, 8)?;
        if !length.is_multiple_of(8) {
            return Err(invalid("space-map length is not a whole number of words"));
        }
        let allocated = i64::from_le_bytes(order.u64(raw, 16)?.to_le_bytes());
        let histogram = if raw.len() == 320 {
            if raw[24..64].iter().any(|byte| *byte != 0) {
                return Err(invalid("unknown space-map bonus extension"));
            }
            let mut buckets = [0; 32];
            for (index, bucket) in buckets.iter_mut().enumerate() {
                *bucket = order.u64(raw, 64 + index * 8)?;
            }
            Some(buckets)
        } else {
            None
        };
        // smp_object at offset zero is obsolete, not an identity authority.
        Ok(Self { length, allocated, histogram })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapType {
    Allocate,
    Free,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    pub kind: MapType,
    /// Present only in a two-word record. Metaslab maps encode the native
    /// SM_NO_VDEVID sentinel as zero; log maps carry a real top-level vdev ID.
    pub vdev: Option<u32>,
    pub offset_units: u64,
    pub run_units: u64,
}

impl Extent {
    pub fn byte_range(self, start: u64, size: u64, shift: u8) -> Result<Range<u64>, ParseError> {
        let unit = 1_u64.checked_shl(u32::from(shift))
            .ok_or_else(|| invalid("space-map unit shift overflow"))?;
        let region_end = start.checked_add(size)
            .ok_or_else(|| invalid("space-map region overflow"))?;
        if size == 0 || !start.is_multiple_of(unit) || !size.is_multiple_of(unit) {
            return Err(invalid("unaligned or empty space-map region"));
        }
        let offset = self.offset_units.checked_mul(unit)
            .and_then(|offset| start.checked_add(offset))
            .ok_or_else(|| invalid("space-map entry offset overflow"))?;
        let run = self.run_units.checked_mul(unit)
            .ok_or_else(|| invalid("space-map entry length overflow"))?;
        let end = offset.checked_add(run)
            .ok_or_else(|| invalid("space-map entry end overflow"))?;
        if run == 0 || offset >= region_end || end > region_end {
            return Err(invalid("space-map entry exceeds its selected region"));
        }
        Ok(offset..end)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Record {
    Extent(Extent),
    /// TXG is only its low fifty bits. Debug records are not commit authority.
    Debug { kind: MapType, txg: u64, sync_pass: u16 },
}

/// One authenticated DMU block's used prefix. Errors fuse the iterator; no
/// guessed resynchronization can convert a truncated two-word record into data.
pub struct Records<'a> {
    raw: &'a [u8],
    order: Endian,
    at: usize,
    allow_v2: bool,
}

impl<'a> Records<'a> {
    pub fn new(raw: &'a [u8], order: Endian, allow_v2: bool) -> Result<Self, ParseError> {
        if raw.len() > MAX_BLOCK_BYTES || !raw.len().is_multiple_of(8) {
            return Err(invalid("invalid space-map block prefix length"));
        }
        Ok(Self { raw, order, at: 0, allow_v2 })
    }

    fn record(&mut self) -> Result<Record, ParseError> {
        let first = self.order.u64(self.raw, self.at)?;
        self.at += 8;
        let (kind, vdev, offset_units, run_units) = match first >> 62 {
            2 => {
                let action = (first >> 60) & 3;
                let txg = first & ((1_u64 << 50) - 1);
                let sync_pass = ((first >> 50) & 1023) as u16;
                if action > 1 || (txg == 0 && (action != 0 || sync_pass != 0)) {
                    return Err(invalid("invalid space-map debug or padding record"));
                }
                return Ok(Record::Debug {
                    kind: if action == 0 { MapType::Allocate } else { MapType::Free },
                    txg,
                    sync_pass,
                });
            }
            3 => {
                if !self.allow_v2 {
                    return Err(invalid("two-word space map requires space_map_v2 admission"));
                }
                if first & (3_u64 << 60) != 0 {
                    return Err(invalid("unknown two-word space-map padding"));
                }
                let second = self.order.u64(self.raw, self.at)?;
                self.at += 8;
                (second >> 63, Some((first & 0x00ff_ffff) as u32),
                    second & (u64::MAX >> 1), ((first >> 24) & ((1_u64 << 36) - 1)) + 1)
            }
            _ => ((first >> 15) & 1, None,
                (first >> 16) & ((1_u64 << 47) - 1), (first & 0x7fff) + 1),
        };
        Ok(Record::Extent(Extent {
            kind: if kind == 0 { MapType::Allocate } else { MapType::Free },
            vdev,
            offset_units,
            run_units,
        }))
    }
}

impl Iterator for Records<'_> {
    type Item = Result<Record, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.at >= self.raw.len() {
            return None;
        }
        let result = self.record();
        if result.is_err() {
            self.at = self.raw.len();
        }
        Some(result)
    }
}

impl std::iter::FusedIterator for Records<'_> {}

/// Coalesced allocated byte ranges. Each operation is logarithmic in the
/// number of retained ranges, not proportional to the native region's size.
/// Failed operations leave the map unchanged, including range-budget failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocationMap {
    region: Range<u64>,
    unit: u64,
    allocated: u64,
    max_ranges: usize,
    ranges: BTreeMap<u64, u64>,
}

impl AllocationMap {
    pub fn new(start: u64, size: u64, shift: u8, max_ranges: usize) -> Result<Self, ParseError> {
        let unit = 1_u64.checked_shl(u32::from(shift))
            .ok_or_else(|| invalid("allocation-map shift overflow"))?;
        let end = start.checked_add(size)
            .ok_or_else(|| invalid("allocation-map region overflow"))?;
        if size == 0 || !start.is_multiple_of(unit) || !size.is_multiple_of(unit)
            || !(1..=1_048_576).contains(&max_ranges)
        {
            return Err(invalid("invalid allocation-map geometry or range budget"));
        }
        Ok(Self { region: start..end, unit, allocated: 0, max_ranges, ranges: BTreeMap::new() })
    }

    pub fn apply(&mut self, kind: MapType, range: Range<u64>) -> Result<(), ParseError> {
        let (start, end) = (range.start, range.end);
        if start >= end || start < self.region.start || end > self.region.end
            || !start.is_multiple_of(self.unit) || !end.is_multiple_of(self.unit)
        {
            return Err(invalid("invalid allocation-map change range"));
        }
        let left = self.ranges.range(..=start).next_back().map(|(&a, &b)| (a, b));
        if kind == MapType::Free {
            let (a, b) = left.filter(|&(a, b)| a <= start && b >= end)
                .ok_or_else(|| invalid("space-map free includes unallocated space"))?;
            let new_count = self.ranges.len() - 1 + usize::from(a < start) + usize::from(end < b);
            if new_count > self.max_ranges {
                return Err(invalid("allocation-map range budget exceeded"));
            }
            self.ranges.remove(&a);
            if a < start { self.ranges.insert(a, start); }
            if end < b { self.ranges.insert(end, b); }
            self.allocated -= end - start;
        } else {
            let right = self.ranges.range(start..).next().map(|(&a, &b)| (a, b));
            if left.is_some_and(|(_, b)| b > start) || right.is_some_and(|(a, _)| a < end) {
                return Err(invalid("space-map allocation overlaps allocated space"));
            }
            let left = left.filter(|&(_, b)| b == start);
            let right = right.filter(|&(a, _)| a == end);
            let new_count = self.ranges.len() + 1 - usize::from(left.is_some()) - usize::from(right.is_some());
            if new_count > self.max_ranges {
                return Err(invalid("allocation-map range budget exceeded"));
            }
            let a = left.map_or(start, |(a, _)| a);
            let b = right.map_or(end, |(_, b)| b);
            if let Some((a, _)) = left { self.ranges.remove(&a); }
            if let Some((a, _)) = right { self.ranges.remove(&a); }
            self.ranges.insert(a, b);
            self.allocated += end - start;
        }
        Ok(())
    }

    #[must_use]
    pub const fn allocated_bytes(&self) -> u64 { self.allocated }

    #[must_use]
    pub fn range_count(&self) -> usize { self.ranges.len() }

    pub fn ranges(&self) -> impl Iterator<Item = Range<u64>> + '_ {
        self.ranges.iter().map(|(&start, &end)| start..end)
    }
}

#[cfg(test)]
mod tests;
