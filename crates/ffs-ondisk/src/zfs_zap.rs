//! Native string-keyed fat-ZAP metadata (OpenZFS zfs-2.3.0 zap_impl.h/zap_leaf.h).
//!
//! Pure parsing: the owner supplies checksum-verified blocks in their individual
//! payload byte orders. Header/table/leaf relationships are validated separately
//! from physical I/O. Normalized and binary keys need their own naming contract.

pub mod names;

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
    uppercase_names: bool,
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
        Self::parse_with_names(raw, order, max_block, names::NamePolicy::Unnormalized)
    }

    /// Explicitly admit the caller's implemented hash normalization. Returned
    /// names retain their stored spelling; this does not choose lookup semantics.
    pub fn parse_with_names(
        raw: &[u8],
        order: Endian,
        max_block: u64,
        policy: names::NamePolicy,
    ) -> Result<Self, ParseError> {
        if !(512..=131_072).contains(&raw.len())
            || !raw.len().is_power_of_two()
            || order.u64(raw, 0)? != FAT_TAG
            || order.u64(raw, 8)? != 0x0002_f52a_b2ab
        {
            return Err(invalid("invalid fat-ZAP header or block size"));
        }
        let flags = order.u64(raw, 96)?;
        if flags & !1 != 0 {
            return Err(invalid(
                "normalized, binary or unknown ZAP keys are unsupported",
            ));
        }
        let uppercase_names = policy.uppercase(order.u64(raw, 88)?)?;
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
            uppercase_names,
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
    pub const fn block_bytes(&self) -> usize {
        self.block_bytes
    }
    #[must_use]
    pub const fn salt(&self) -> u64 {
        self.salt
    }
    #[must_use]
    pub const fn is_hash64(&self) -> bool {
        self.hash_bits == 48
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
                let expected_hash = if self.uppercase_names {
                    if !name.is_ascii() {
                        return Err(invalid(
                            "non-ASCII normalized ZAP keys need native Unicode tables",
                        ));
                    }
                    name_hash(&name.to_ascii_uppercase(), self.salt, self.hash_bits)
                } else {
                    name_hash(&name, self.salt, self.hash_bits)
                };
                if expected_hash != hash || !names.insert(name.clone()) {
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

pub(crate) fn zap_name_hash(name: &[u8], salt: u64, bits: u32) -> u64 {
    name_hash(name, salt, bits)
}

fn name_hash(name: &[u8], salt: u64, bits: u32) -> u64 {
    let hash = name.iter().fold(salt, |hash, byte| {
        (hash >> 8) ^ CRC_TABLE[((hash ^ u64::from(*byte)) & 255) as usize]
    });
    hash & (u64::MAX << (64 - bits))
}

fn put_u16(raw: &mut [u8], at: usize, value: u16, order: Endian) {
    let bytes = match order {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    };
    raw[at..at + 2].copy_from_slice(&bytes);
}

fn put_u32(raw: &mut [u8], at: usize, value: u32, order: Endian) {
    let bytes = match order {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    };
    raw[at..at + 4].copy_from_slice(&bytes);
}

fn put_u64(raw: &mut [u8], at: usize, value: u64, order: Endian) {
    raw[at..at + 8].copy_from_slice(&order.encode(value));
}

#[derive(Clone)]
struct PreparedZapEntry {
    name_nul: Vec<u8>,
    width: u8,
    value_count: u16,
    value_bytes: Vec<u8>,
    hash: u64,
    collision: u32,
    chunks_needed: usize,
}

fn encode_leaf_block(
    block_bytes: usize,
    prefix: u64,
    prefix_bits: u32,
    items: &[PreparedZapEntry],
    order: Endian,
) -> Result<Vec<u8>, ParseError> {
    let buckets = block_bytes / 32;
    let start = 48 + buckets * 2;
    let total_chunks = (block_bytes - start) / 24;
    let total_needed: usize = items.iter().map(|e| e.chunks_needed).sum();
    if total_needed > total_chunks || items.len() > usize::from(u16::MAX) {
        return Err(invalid("ZAP leaf entries exceed chunk capacity"));
    }

    let mut raw = vec![0_u8; block_bytes];
    put_u64(&mut raw, 0, 1_u64 << 63, order);
    put_u64(&mut raw, 16, prefix, order);
    put_u32(&mut raw, 24, 0x02ab_1eaf, order);
    put_u16(
        &mut raw,
        30,
        u16::try_from(items.len()).map_err(|_| invalid("ZAP leaf entry count overflow"))?,
        order,
    );
    put_u16(
        &mut raw,
        32,
        u16::try_from(prefix_bits).map_err(|_| invalid("ZAP leaf prefix bits overflow"))?,
        order,
    );
    raw[48..start].fill(0xFF);

    // Insert in reverse (hash, collision) order so each bucket chain walks in
    // ascending (hash, collision) order on disk.
    let mut ordered = items.to_vec();
    ordered.sort_by_key(|a| std::cmp::Reverse((a.hash, a.collision)));

    let mut next_chunk = 0_u16;
    let alloc_array = |buf: &mut [u8], payload: &[u8], next: &mut u16| -> u16 {
        if payload.is_empty() {
            return CHAIN_END;
        }
        let first = *next;
        let parts = payload.chunks(21);
        let part_count = parts.len();
        for (idx, part) in parts.enumerate() {
            let at = start + usize::from(*next) * 24;
            buf[at] = 251;
            buf[at + 1..at + 1 + part.len()].copy_from_slice(part);
            let chain_next = if idx + 1 == part_count {
                CHAIN_END
            } else {
                *next + 1
            };
            put_u16(buf, at + 22, chain_next, order);
            *next += 1;
        }
        first
    };

    for item in &ordered {
        let entry_idx = next_chunk;
        next_chunk += 1;
        let name_first = alloc_array(&mut raw, &item.name_nul, &mut next_chunk);
        let value_first = alloc_array(&mut raw, &item.value_bytes, &mut next_chunk);
        let slot = (item.hash >> (64 - prefix_bits - buckets.ilog2())) as usize & (buckets - 1);
        let prev_head = u16_at(&raw, 48 + slot * 2, order)?;
        let at = start + usize::from(entry_idx) * 24;
        raw[at] = 252;
        raw[at + 1] = item.width;
        put_u16(&mut raw, at + 2, prev_head, order);
        put_u16(&mut raw, at + 4, name_first, order);
        put_u16(
            &mut raw,
            at + 6,
            u16::try_from(item.name_nul.len()).map_err(|_| invalid("ZAP name length overflow"))?,
            order,
        );
        put_u16(&mut raw, at + 8, value_first, order);
        put_u16(&mut raw, at + 10, item.value_count, order);
        put_u32(&mut raw, at + 12, item.collision, order);
        put_u64(&mut raw, at + 16, item.hash, order);
        put_u16(&mut raw, 48 + slot * 2, entry_idx, order);
    }

    let free_chunks = total_chunks
        .checked_sub(usize::from(next_chunk))
        .ok_or_else(|| invalid("ZAP leaf chunk allocation overflow"))?;
    put_u16(
        &mut raw,
        28,
        u16::try_from(free_chunks).map_err(|_| invalid("ZAP free chunk count overflow"))?,
        order,
    );
    put_u16(
        &mut raw,
        34,
        if usize::from(next_chunk) == total_chunks {
            CHAIN_END
        } else {
            next_chunk
        },
        order,
    );
    let total_chunks_u16 =
        u16::try_from(total_chunks).map_err(|_| invalid("ZAP chunk limit overflow"))?;
    for free_idx in next_chunk..total_chunks_u16 {
        let at = start + usize::from(free_idx) * 24;
        raw[at] = 253;
        put_u16(
            &mut raw,
            at + 22,
            if free_idx + 1 == total_chunks_u16 {
                CHAIN_END
            } else {
                free_idx + 1
            },
            order,
        );
    }
    Ok(raw)
}

/// Encode a complete string-keyed Fat-ZAP (`ZBT_HEADER` at block 0, leaf blocks,
/// and optional external pointer-table blocks) with automatic leaf splitting and
/// self-verification through `FatHeader::parse`, `routes`, and `leaf`.
pub fn encode_fatzap(
    entries: &[Entry],
    block_bytes: usize,
    salt: u64,
    order: Endian,
) -> Result<Vec<Vec<u8>>, ParseError> {
    encode_fatzap_with_flags(entries, block_bytes, salt, false, order)
}

pub fn encode_fatzap_with_flags(
    entries: &[Entry],
    block_bytes: usize,
    salt: u64,
    hash64: bool,
    order: Endian,
) -> Result<Vec<Vec<u8>>, ParseError> {
    if !(512..=131_072).contains(&block_bytes) || !block_bytes.is_power_of_two() {
        return Err(invalid("invalid fat-ZAP block size"));
    }
    if entries.len() > MAX_ENTRIES {
        return Err(invalid("ZAP entry count exceeds budget"));
    }
    let effective_salt = if salt == 0 {
        0x0123_4567_89ab_cdef
    } else {
        salt
    };
    let hash_bits = if hash64 { 48_u32 } else { 28_u32 };

    let buckets = block_bytes / 32;
    let chunk_area_start = 48 + buckets * 2;
    let leaf_chunk_capacity = (block_bytes - chunk_area_start) / 24;

    let mut seen_names = BTreeSet::new();
    let mut hash_cd = BTreeMap::<u64, u32>::new();
    let mut prepared = Vec::with_capacity(entries.len());
    for entry in entries {
        if entry.name.is_empty() || entry.name.len() + 1 > MAX_NAME_BYTES || entry.name.contains(&0)
        {
            return Err(invalid("invalid fat-ZAP key name"));
        }
        if !seen_names.insert(entry.name.clone()) {
            return Err(invalid("duplicate fat-ZAP key name"));
        }
        if !matches!(entry.integer_bytes, 1 | 2 | 4 | 8) {
            return Err(invalid("unsupported fat-ZAP integer width"));
        }
        let width = usize::from(entry.integer_bytes);
        let val_byte_len = entry
            .values
            .len()
            .checked_mul(width)
            .ok_or_else(|| invalid("fat-ZAP value byte length overflow"))?;
        if val_byte_len > MAX_VALUE_BYTES {
            return Err(invalid("fat-ZAP value exceeds maximum byte length"));
        }
        let value_count = u16::try_from(entry.values.len())
            .map_err(|_| invalid("fat-ZAP value array count overflow"))?;
        let mut value_bytes = Vec::with_capacity(val_byte_len);
        for &v in &entry.values {
            match entry.integer_bytes {
                1 => {
                    let b = u8::try_from(v).map_err(|_| invalid("fat-ZAP u8 value overflow"))?;
                    value_bytes.push(b);
                }
                2 => {
                    let w = u16::try_from(v).map_err(|_| invalid("fat-ZAP u16 value overflow"))?;
                    value_bytes.extend_from_slice(&w.to_be_bytes());
                }
                4 => {
                    let d = u32::try_from(v).map_err(|_| invalid("fat-ZAP u32 value overflow"))?;
                    value_bytes.extend_from_slice(&d.to_be_bytes());
                }
                8 => value_bytes.extend_from_slice(&v.to_be_bytes()),
                _ => unreachable!(),
            }
        }
        let mut name_nul = Vec::with_capacity(entry.name.len() + 1);
        name_nul.extend_from_slice(&entry.name);
        name_nul.push(0);

        let hash = name_hash(&entry.name, effective_salt, hash_bits);
        let cd_slot = hash_cd.entry(hash).or_insert(0);
        let collision = *cd_slot;
        if hash64 && collision >= u32::from(u16::MAX) {
            return Err(invalid("fat-ZAP hash64 collision differentiator overflow"));
        }
        *cd_slot = collision
            .checked_add(1)
            .ok_or_else(|| invalid("fat-ZAP collision differentiator overflow"))?;

        let chunks_needed = 1
            + name_nul.len().div_ceil(21)
            + if value_bytes.is_empty() {
                0
            } else {
                value_bytes.len().div_ceil(21)
            };
        if chunks_needed > leaf_chunk_capacity {
            return Err(invalid("single fat-ZAP entry exceeds leaf block capacity"));
        }
        prepared.push(PreparedZapEntry {
            name_nul,
            width: entry.integer_bytes,
            value_count,
            value_bytes,
            hash,
            collision,
            chunks_needed,
        });
    }

    // Recursively split leaves along hash prefix bits whenever a leaf overflows.
    let max_table_shift = MAX_TABLE_ENTRIES.ilog2().min(hash_bits);
    let mut leaves: Vec<(u64, u32, Vec<PreparedZapEntry>)> = Vec::new();
    let mut work: Vec<(u64, u32, Vec<PreparedZapEntry>)> = vec![(0, 0, prepared)];
    while let Some((prefix, prefix_bits, group)) = work.pop() {
        let needed: usize = group.iter().map(|e| e.chunks_needed).sum();
        if needed <= leaf_chunk_capacity {
            leaves.push((prefix, prefix_bits, group));
            if leaves.len() > MAX_LEAVES {
                return Err(invalid("fat-ZAP leaf count exceeds budget"));
            }
            continue;
        }
        if prefix_bits >= max_table_shift {
            return Err(invalid(
                "fat-ZAP hash collision chain exceeds leaf capacity",
            ));
        }
        let bit_pos = 63 - prefix_bits;
        let mut left = Vec::new();
        let mut right = Vec::new();
        for item in group {
            if (item.hash >> bit_pos) & 1 == 0 {
                left.push(item);
            } else {
                right.push(item);
            }
        }
        // Push right first so pop() visits left (lower prefix) first!
        work.push(((prefix << 1) | 1, prefix_bits + 1, right));
        work.push((prefix << 1, prefix_bits + 1, left));
    }

    leaves.sort_by_key(|&(prefix, prefix_bits, _)| {
        if prefix_bits == 0 {
            0
        } else {
            prefix << (64 - prefix_bits)
        }
    });

    let max_prefix_bits = leaves.iter().map(|&(_, bits, _)| bits).max().unwrap_or(0);
    let embedded_shift = (block_bytes / 16).ilog2();
    let external_min_shift = (block_bytes / 8).ilog2();
    let (table_shift, external_table_blocks) = if max_prefix_bits <= embedded_shift {
        (embedded_shift, 0_u64)
    } else {
        let shift = max_prefix_bits.max(external_min_shift);
        let tbl_len = 1_usize << shift;
        let per_blk = block_bytes / 8;
        (shift, (tbl_len / per_blk) as u64)
    };
    let table_len = 1_usize << table_shift;

    // Block layout:
    // Block 0: Fat-ZAP header (with embedded table when external_table_blocks == 0)
    // Blocks 1..=leaves.len(): Leaf blocks
    // Blocks leaves.len()+1..: External pointer-table blocks (if any)
    let mut blocks = Vec::with_capacity(1 + leaves.len() + external_table_blocks as usize);
    blocks.push(vec![0_u8; block_bytes]);

    let mut ptr_table = vec![0_u64; table_len];
    for (leaf_idx, (prefix, prefix_bits, group)) in leaves.iter().enumerate() {
        let blk_num = (leaf_idx + 1) as u64;
        let leaf_raw = encode_leaf_block(block_bytes, *prefix, *prefix_bits, group, order)?;
        blocks.push(leaf_raw);

        let span = 1_usize << (table_shift - *prefix_bits);
        let first = (*prefix as usize) * span;
        for slot in &mut ptr_table[first..first + span] {
            *slot = blk_num;
        }
    }

    let table_start = if external_table_blocks == 0 {
        0_u64
    } else {
        (leaves.len() + 1) as u64
    };
    if external_table_blocks > 0 {
        let per_blk = block_bytes / 8;
        for chunk in ptr_table.chunks_exact(per_blk) {
            let mut tbl_blk = vec![0_u8; block_bytes];
            for (i, &val) in chunk.iter().enumerate() {
                put_u64(&mut tbl_blk, i * 8, val, order);
            }
            blocks.push(tbl_blk);
        }
    }

    let free_block = blocks.len() as u64;
    let hdr = &mut blocks[0];
    put_u64(hdr, 0, FAT_TAG, order);
    put_u64(hdr, 8, 0x0002_f52a_b2ab, order);
    put_u64(hdr, 16, table_start, order);
    put_u64(hdr, 24, external_table_blocks, order);
    put_u64(hdr, 32, u64::from(table_shift), order);
    put_u64(hdr, 40, 0, order);
    put_u64(hdr, 48, 0, order);
    put_u64(hdr, 56, free_block, order);
    put_u64(hdr, 64, leaves.len() as u64, order);
    put_u64(hdr, 72, entries.len() as u64, order);
    put_u64(hdr, 80, effective_salt, order);
    put_u64(hdr, 88, 0, order);
    put_u64(hdr, 96, u64::from(hash64), order);
    if external_table_blocks == 0 {
        let base = block_bytes / 2;
        for (i, &val) in ptr_table.iter().enumerate() {
            put_u64(hdr, base + i * 8, val, order);
        }
    }

    // Self-verify roundtrip against FatHeader + routes + leaf!
    let max_block = free_block - 1;
    let parsed_hdr = FatHeader::parse(&blocks[0], order, max_block)?;
    let decoded_table = if external_table_blocks == 0 {
        parsed_hdr.embedded_table(&blocks[0], order)?
    } else {
        let mut t = Vec::with_capacity(table_len);
        for blk_id in parsed_hdr.table_blocks() {
            t.extend(parsed_hdr.table_block(&blocks[blk_id as usize], order)?);
        }
        t
    };
    let routes = parsed_hdr.routes(&decoded_table, max_block)?;
    let mut total_decoded = 0_usize;
    for route in routes {
        let leaf_entries = parsed_hdr.leaf(&blocks[route.block as usize], order, route)?;
        total_decoded += leaf_entries.len();
    }
    if total_decoded != entries.len() {
        return Err(invalid("encoded fat-ZAP roundtrip entry count mismatch"));
    }

    Ok(blocks)
}

#[cfg(test)]
mod tests;
