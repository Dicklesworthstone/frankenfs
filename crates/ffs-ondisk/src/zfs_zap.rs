//! Native string-keyed fat-ZAP metadata (OpenZFS zfs-2.3.0 zap_impl.h/zap_leaf.h).
//!
//! Pure parsing: the owner supplies checksum-verified blocks in their individual
//! payload byte orders. Header/table/leaf relationships are validated separately
//! from physical I/O. Normalized and binary keys need their own naming contract.

use crate::zfs::Endian;
use ffs_types::ParseError;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

pub const MICRO_TAG: u64 = (1_u64 << 63) + 3;
pub const FAT_TAG: u64 = (1_u64 << 63) + 1;
pub const MAX_TABLE_ENTRIES: usize = 1 << 20;
pub const MAX_LEAVES: usize = 4096;
pub const MAX_ENTRIES: usize = 65_536;
const MAX_NAME_BYTES: usize = 4096;
const MAX_VALUE_BYTES: usize = 65_536;
const CHAIN_END: u16 = u16::MAX;

fn invalid(reason: &'static str) -> ParseError {
    ParseError::InvalidField {
        field: "zfs.zap",
        reason,
    }
}

fn u16_at(raw: &[u8], at: usize, order: Endian) -> Result<u16, ParseError> {
    let bytes: [u8; 2] = raw
        .get(at..at + 2)
        .ok_or_else(|| invalid("truncated 16-bit field"))?
        .try_into()
        .map_err(|_| invalid("truncated 16-bit field"))?;
    Ok(match order {
        Endian::Little => u16::from_le_bytes(bytes),
        Endian::Big => u16::from_be_bytes(bytes),
    })
}

fn u32_at(raw: &[u8], at: usize, order: Endian) -> Result<u32, ParseError> {
    let bytes: [u8; 4] = raw
        .get(at..at + 4)
        .ok_or_else(|| invalid("truncated 32-bit field"))?
        .try_into()
        .map_err(|_| invalid("truncated 32-bit field"))?;
    Ok(match order {
        Endian::Little => u32::from_le_bytes(bytes),
        Endian::Big => u32::from_be_bytes(bytes),
    })
}

/// Typed native integers. Array bytes are always big-endian on disk, independent
/// of the leaf header's byte order. Width is retained, including empty values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: Vec<u8>,
    pub integer_bytes: u8,
    pub values: Vec<u64>,
    pub collision: u32,
}

impl Entry {
    /// Metadata object references require precisely one native uint64 value.
    pub fn scalar(&self) -> Result<u64, ParseError> {
        if self.integer_bytes != 8 || self.values.len() != 1 {
            return Err(invalid("ZAP reference is not one uint64"));
        }
        Ok(self.values[0])
    }
}

#[derive(Debug, Clone)]
pub struct FatHeader {
    block_bytes: usize,
    table_start: u64,
    table_blocks: u64,
    table_shift: u32,
    next_table: u64,
    copied: u64,
    free_block: u64,
    leaves: usize,
    entries: usize,
    salt: u64,
    hash_bits: u32,
}

/// One contiguous, aligned pointer-table interval belonging to a single leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeafRoute {
    pub block: u64,
    pub prefix: u64,
    pub prefix_bits: u32,
}

impl FatHeader {
    pub fn parse(raw: &[u8], order: Endian, max_block: u64) -> Result<Self, ParseError> {
        if !(512..=131_072).contains(&raw.len())
            || !raw.len().is_power_of_two()
            || order.u64(raw, 0)? != FAT_TAG
            || order.u64(raw, 8)? != 0x0002_f52a_b2ab
        {
            return Err(invalid("invalid fat-ZAP header or block size"));
        }
        let flags = order.u64(raw, 96)?;
        if flags & !1 != 0 || order.u64(raw, 88)? != 0 {
            return Err(invalid(
                "normalized, binary or unknown ZAP keys are unsupported",
            ));
        }
        let shift = order.u64(raw, 32)?;
        if shift > u64::from(MAX_TABLE_ENTRIES.ilog2()) {
            return Err(invalid("ZAP pointer table exceeds entry budget"));
        }
        let leaves = order.u64(raw, 64)?;
        let entries = order.u64(raw, 72)?;
        if leaves == 0
            || leaves > MAX_LEAVES as u64
            || leaves > (1_u64 << shift)
            || entries > MAX_ENTRIES as u64
        {
            return Err(invalid("ZAP leaf or entry count exceeds read profile"));
        }
        let header = Self {
            block_bytes: raw.len(),
            table_start: order.u64(raw, 16)?,
            table_blocks: order.u64(raw, 24)?,
            table_shift: shift as u32,
            next_table: order.u64(raw, 40)?,
            copied: order.u64(raw, 48)?,
            free_block: order.u64(raw, 56)?,
            leaves: leaves as usize,
            entries: entries as usize,
            salt: order.u64(raw, 80)?,
            hash_bits: if flags & 1 == 0 { 28 } else { 48 },
        };
        if header.salt == 0 || header.free_block < 2 || header.copied > header.table_blocks {
            return Err(invalid(
                "invalid ZAP salt, allocation or table-growth state",
            ));
        }
        if header.table_blocks == 0 {
            if header.table_start != 0
                || header.next_table != 0
                || header.copied != 0
                || header.table_len() > raw.len() / 16
            {
                return Err(invalid("embedded ZAP table does not fit its header"));
            }
        } else {
            if header.table_blocks.checked_mul((raw.len() / 8) as u64)
                != Some(header.table_len() as u64)
            {
                return Err(invalid("external ZAP table geometry disagrees"));
            }
            let table = header.checked_range(header.table_start, header.table_blocks)?;
            if table.end - 1 > max_block {
                return Err(invalid("ZAP table exceeds the dnode's block range"));
            }
            if header.next_table == 0 {
                if header.copied != 0 {
                    return Err(invalid("copied blocks without a growing ZAP table"));
                }
            } else {
                // Uncopied blocks may not yet be allocated. Reserve their IDs,
                // but require only the copied prefix to be physically readable.
                let growth = header.checked_range(header.next_table, 2 * header.table_blocks)?;
                if table.start < growth.end && growth.start < table.end {
                    return Err(invalid("old and growing ZAP tables overlap"));
                }
                if header.copied != 0 && header.next_table + 2 * header.copied - 1 > max_block {
                    return Err(invalid("copied ZAP table prefix exceeds dnode range"));
                }
            }
        }
        Ok(header)
    }

    fn checked_range(&self, start: u64, blocks: u64) -> Result<Range<u64>, ParseError> {
        let end = start
            .checked_add(blocks)
            .ok_or_else(|| invalid("ZAP table range overflow"))?;
        if start == 0 || blocks == 0 || end > self.free_block {
            return Err(invalid("ZAP table lies outside allocated object IDs"));
        }
        Ok(start..end)
    }

    #[must_use]
    pub fn table_len(&self) -> usize {
        1_usize << self.table_shift
    }
    #[must_use]
    pub const fn entry_count(&self) -> usize {
        self.entries
    }
    #[must_use]
    pub fn table_blocks(&self) -> Range<u64> {
        self.table_start..self.table_start + self.table_blocks
    }
    #[must_use]
    pub fn copied_blocks(&self) -> Range<u64> {
        self.next_table..self.next_table + 2 * self.copied
    }

    pub fn embedded_table(&self, raw: &[u8], order: Endian) -> Result<Vec<u64>, ParseError> {
        if self.table_blocks != 0 || raw.len() != self.block_bytes {
            return Err(invalid("not an embedded ZAP table"));
        }
        (0..self.table_len())
            .map(|i| order.u64(raw, raw.len() / 2 + i * 8))
            .collect()
    }

    pub fn table_block(&self, raw: &[u8], order: Endian) -> Result<Vec<u64>, ParseError> {
        if raw.len() != self.block_bytes {
            return Err(invalid("short ZAP pointer-table block"));
        }
        (0..raw.len())
            .step_by(8)
            .map(|at| order.u64(raw, at))
            .collect()
    }

    /// During incremental growth, the old table remains authoritative. Every
    /// completed source block must have two identical copies of each pointer in
    /// the new table; uncopied allocation is not interpreted as initialized data.
    pub fn check_copied_block(
        &self,
        block: u64,
        values: &[u64],
        table: &[u64],
    ) -> Result<(), ParseError> {
        if !self.copied_blocks().contains(&block)
            || values.len() != self.block_bytes / 8
            || table.len() != self.table_len()
        {
            return Err(invalid("invalid copied ZAP table block"));
        }
        let first = (block - self.next_table) as usize * values.len();
        for (i, value) in values.iter().enumerate() {
            if table.get(usize::midpoint(first, i)) != Some(value) {
                return Err(invalid(
                    "growing ZAP table disagrees with its authoritative copy",
                ));
            }
        }
        Ok(())
    }

    pub fn routes(&self, table: &[u64], max_block: u64) -> Result<Vec<LeafRoute>, ParseError> {
        if table.len() != self.table_len() {
            return Err(invalid("incomplete ZAP pointer table"));
        }
        let mut spans = BTreeMap::<u64, (usize, usize)>::new();
        for (i, &block) in table.iter().enumerate() {
            if block == 0
                || block > max_block
                || block >= self.free_block
                || self.table_blocks().contains(&block)
                || (self.next_table != 0
                    && (self.next_table..self.next_table + 2 * self.table_blocks).contains(&block))
            {
                return Err(invalid(
                    "ZAP leaf pointer is a table, hole or out-of-range block",
                ));
            }
            let (first, count) = spans.entry(block).or_insert((i, 0));
            if *first + *count != i {
                return Err(invalid("ZAP leaf has disjoint pointer-table intervals"));
            }
            *count += 1;
            if spans.len() > self.leaves {
                return Err(invalid("more reachable ZAP leaves than declared"));
            }
        }
        if spans.len() != self.leaves {
            return Err(invalid("ZAP leaf count disagrees with pointer table"));
        }
        let mut routes = Vec::with_capacity(spans.len());
        for (block, (first, count)) in spans {
            if !count.is_power_of_two() || !first.is_multiple_of(count) {
                return Err(invalid("ZAP leaf prefix interval is not aligned"));
            }
            let bits = self.table_shift - count.ilog2();
            routes.push(LeafRoute {
                block,
                prefix: (first / count) as u64,
                prefix_bits: bits,
            });
        }
        Ok(routes)
    }

    pub fn leaf(
        &self,
        raw: &[u8],
        order: Endian,
        route: LeafRoute,
    ) -> Result<Vec<Entry>, ParseError> {
        if raw.len() != self.block_bytes
            || order.u64(raw, 0)? != 1_u64 << 63
            || order.u64(raw, 8)? != 0
            || u32_at(raw, 24, order)? != 0x02ab_1eaf
            || order.u64(raw, 16)? != route.prefix
            || u32::from(u16_at(raw, 32, order)?) != route.prefix_bits
            || route.prefix_bits > self.table_shift
            || raw[36] & !1 != 0
        {
            return Err(invalid(
                "ZAP leaf header or hash prefix disagrees with its route",
            ));
        }
        let buckets = raw.len() / 32;
        let start = 48 + buckets * 2;
        let chunks = (raw.len() - start) / 24;
        let expected_entries = usize::from(u16_at(raw, 30, order)?);
        let expected_free = usize::from(u16_at(raw, 28, order)?);
        if start + chunks * 24 != raw.len()
            || expected_entries > chunks
            || expected_free > chunks
            || route.prefix_bits + buckets.ilog2() > 64
        {
            return Err(invalid("invalid ZAP leaf geometry or counts"));
        }
        let mut leaf = LeafChunks {
            raw: &raw[start..],
            order,
            used: vec![false; chunks],
        };
        let mut entries = Vec::new();
        let mut identities = BTreeSet::new();
        let mut names = BTreeSet::new();
        for bucket in 0..buckets {
            let mut index = u16_at(raw, 48 + bucket * 2, order)?;
            while index != CHAIN_END {
                let chunk = leaf.claim(index, 252)?;
                let hash = order.u64(chunk, 16)?;
                let prefix = if route.prefix_bits == 0 {
                    0
                } else {
                    hash >> (64 - route.prefix_bits)
                };
                let slot =
                    (hash >> (64 - route.prefix_bits - buckets.ilog2())) as usize & (buckets - 1);
                let collision = u32_at(chunk, 12, order)?;
                if prefix != route.prefix
                    || slot != bucket
                    || (self.hash_bits == 48 && collision >= u32::from(u16::MAX))
                    || !identities.insert((hash, collision))
                {
                    return Err(invalid(
                        "ZAP entry hash route or collision identity is invalid",
                    ));
                }
                let width = chunk[1];
                let name_len = usize::from(u16_at(chunk, 6, order)?);
                let value_len = usize::from(u16_at(chunk, 10, order)?);
                if !matches!(width, 1 | 2 | 4 | 8)
                    || name_len == 0
                    || name_len > MAX_NAME_BYTES
                    || value_len * usize::from(width) > MAX_VALUE_BYTES
                {
                    return Err(invalid("ZAP name or value exceeds supported dimensions"));
                }
                let name_first = u16_at(chunk, 4, order)?;
                let value_first = u16_at(chunk, 8, order)?;
                index = u16_at(chunk, 2, order)?;
                let mut name = leaf.array(name_first, name_len)?;
                if name.last() != Some(&0) || name[..name.len() - 1].contains(&0) {
                    return Err(invalid("ZAP string key is not exactly NUL terminated"));
                }
                name.truncate(name.len() - 1);
                if name_hash(&name, self.salt, self.hash_bits) != hash
                    || !names.insert(name.clone())
                {
                    return Err(invalid("ZAP key hash mismatch or duplicate name"));
                }
                let bytes = leaf.array(value_first, value_len * usize::from(width))?;
                let values = bytes
                    .chunks_exact(usize::from(width))
                    .map(|word| {
                        word.iter()
                            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte))
                    })
                    .collect();
                entries.push(Entry {
                    name,
                    integer_bytes: width,
                    values,
                    collision,
                });
                if entries.len() > expected_entries {
                    return Err(invalid("ZAP entry count is too small"));
                }
            }
        }
        let mut next = u16_at(raw, 34, order)?;
        let mut free = 0;
        while next != CHAIN_END {
            let chunk = leaf.claim(next, 253)?;
            next = u16_at(chunk, 22, order)?;
            free += 1;
        }
        if free != expected_free || entries.len() != expected_entries || leaf.used.contains(&false)
        {
            return Err(invalid(
                "unreachable ZAP chunks or inconsistent entry/free counts",
            ));
        }
        Ok(entries)
    }
}

struct LeafChunks<'a> {
    raw: &'a [u8],
    order: Endian,
    used: Vec<bool>,
}
impl<'a> LeafChunks<'a> {
    fn claim(&mut self, index: u16, kind: u8) -> Result<&'a [u8], ParseError> {
        let index = usize::from(index);
        let used = self
            .used
            .get_mut(index)
            .ok_or_else(|| invalid("ZAP chunk index out of bounds"))?;
        if *used {
            return Err(invalid("cyclic or shared ZAP chunk chain"));
        }
        *used = true;
        let chunk = &self.raw[index * 24..index * 24 + 24];
        if chunk[0] != kind {
            return Err(invalid("ZAP chain references the wrong chunk type"));
        }
        Ok(chunk)
    }
    fn array(&mut self, mut next: u16, len: usize) -> Result<Vec<u8>, ParseError> {
        let mut result = Vec::with_capacity(len);
        while result.len() < len {
            let order = self.order;
            let chunk = self.claim(next, 251)?;
            let count = (len - result.len()).min(21);
            result.extend_from_slice(&chunk[1..=count]);
            next = u16_at(chunk, 22, order)?;
        }
        if next != CHAIN_END {
            return Err(invalid("ZAP array extends beyond its declared length"));
        }
        Ok(result)
    }
}

const CRC_TABLE: [u64; 256] = {
    let mut table = [0; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u64;
        let mut bit = 0;
        while bit < 8 {
            crc = (crc >> 1)
                ^ if crc & 1 == 0 {
                    0
                } else {
                    0xc96c_5795_d787_0f42
                };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

fn name_hash(name: &[u8], salt: u64, bits: u32) -> u64 {
    let hash = name.iter().fold(salt, |hash, byte| {
        (hash >> 8) ^ CRC_TABLE[((hash ^ u64::from(*byte)) & 255) as usize]
    });
    hash & (u64::MAX << (64 - bits))
}

#[cfg(test)]
mod tests;
