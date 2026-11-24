//! OpenZFS indirect vdev mapping and birth-TXG tables (`com.delphix:device_removal`
//! and `com.delphix:obsolete_counts`).
//!
//! Contract: OpenZFS `zfs-2.4.0` `include/sys/vdev_indirect_mapping.h` and
//! `include/sys/vdev_indirect_births.h`.
//!
//! - `vdev_indirect_mapping_entry_phys_t` is 24 bytes:
//!   - `vimep_src` (8 bytes): low 63 bits are the source offset in **512-byte
//!     sectors** (`DVA_MAPPING_GET_SRC_OFFSET` shifts left by 9); bit 63 is the
//!     GC mark bit.
//!   - `vimep_dst` (16 bytes): destination `dva_t` (`vdev`, `asize`, `offset`,
//!     `gang=0`).
//! - `vdev_indirect_mapping_phys_t` is 32 bytes (or 24 bytes V0 without
//!   `vimp_counts_object`): `max_offset`, `bytes_mapped`, `num_entries`,
//!   `counts_object`.
//! - `vdev_indirect_birth_phys_t` is 8 bytes (`vib_count`), followed by 16-byte
//!   `vdev_indirect_birth_entry_phys_t` entries (`vibe_offset`, `vibe_phys_birth_txg`).

use super::{Dva, Endian, invalid};
use ffs_types::ParseError;
use std::collections::{BTreeMap, BTreeSet};

/// On-disk byte size of `vdev_indirect_mapping_entry_phys_t`.
pub const INDIRECT_MAPPING_ENTRY_BYTES: usize = 24;

/// On-disk byte size of V0 `vdev_indirect_mapping_phys_t` bonus.
pub const INDIRECT_MAPPING_PHYS_V0_BYTES: usize = 24;

/// On-disk byte size of V1 `vdev_indirect_mapping_phys_t` bonus (with `counts_object`).
pub const INDIRECT_MAPPING_PHYS_BYTES: usize = 32;

/// On-disk byte size of `vdev_indirect_birth_phys_t` bonus.
pub const INDIRECT_BIRTH_PHYS_BYTES: usize = 8;

/// On-disk byte size of `vdev_indirect_birth_entry_phys_t`.
pub const INDIRECT_BIRTH_ENTRY_BYTES: usize = 16;

/// Maximum recursion depth when resolving chained removed indirect vdevs.
pub const MAX_INDIRECT_CHAIN_DEPTH: usize = 32;

/// Maximum mapped spans returned for a single DVA translation (bounds adversarial splits).
pub const MAX_INDIRECT_SPLIT_SPANS: usize = 256;

/// Configuration fields stored in an indirect top-level vdev's nvlist
/// (`vdev_indirect_config_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VdevIndirectConfig {
    pub vdev_id: u32,
    pub mapping_object: u64,
    pub births_object: u64,
    pub prev_indirect_vdev: Option<u32>,
}

/// Bonus header of `DMU_OT_VDEV_INDIRECT_MAPPING` (`vdev_indirect_mapping_phys_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndirectMappingPhys {
    pub max_offset: u64,
    pub bytes_mapped: u64,
    pub num_entries: u64,
    pub counts_object: u64,
}

impl IndirectMappingPhys {
    pub fn parse(raw: &[u8], order: Endian) -> Result<Self, ParseError> {
        if raw.len() < INDIRECT_MAPPING_PHYS_V0_BYTES {
            return Err(invalid("indirect mapping bonus shorter than 24 bytes"));
        }
        let max_offset = order.u64(raw, 0)?;
        let bytes_mapped = order.u64(raw, 8)?;
        let num_entries = order.u64(raw, 16)?;
        let counts_object = if raw.len() >= INDIRECT_MAPPING_PHYS_BYTES {
            order.u64(raw, 24)?
        } else {
            0
        };
        Ok(Self {
            max_offset,
            bytes_mapped,
            num_entries,
            counts_object,
        })
    }

    #[must_use]
    pub fn encode(&self, order: Endian) -> [u8; INDIRECT_MAPPING_PHYS_BYTES] {
        let mut out = [0_u8; INDIRECT_MAPPING_PHYS_BYTES];
        out[0..8].copy_from_slice(&order.encode(self.max_offset));
        out[8..16].copy_from_slice(&order.encode(self.bytes_mapped));
        out[16..24].copy_from_slice(&order.encode(self.num_entries));
        out[24..32].copy_from_slice(&order.encode(self.counts_object));
        out
    }
}

/// Single 24-byte `vdev_indirect_mapping_entry_phys_t` mapping a contiguous
/// extent on the removed source vdev onto a destination DVA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndirectMappingEntry {
    /// Byte offset on the removed source vdev (always 512-byte aligned).
    pub src_offset: u64,
    /// GC mark bit (bit 63 of `vimep_src`).
    pub marked: bool,
    /// Destination DVA (`vdev`, `offset`, `allocated_bytes`; `gang` must be `false`).
    pub dst: Dva,
}

impl IndirectMappingEntry {
    pub fn parse(raw: &[u8], order: Endian) -> Result<Self, ParseError> {
        if raw.len() < INDIRECT_MAPPING_ENTRY_BYTES {
            return Err(invalid("truncated indirect mapping entry"));
        }
        let src_word = order.u64(raw, 0)?;
        let marked = (src_word >> 63) != 0;
        let src_sectors = src_word & 0x7fff_ffff_ffff_ffff;
        let src_offset = src_sectors
            .checked_mul(512)
            .ok_or_else(|| invalid("indirect mapping source offset overflow"))?;

        let dva_w0 = order.u64(raw, 8)?;
        let dva_w1 = order.u64(raw, 16)?;
        if dva_w0 & 0xff00_0000_ff00_0000 != 0 || (dva_w1 >> 63) != 0 {
            return Err(invalid(
                "invalid or gang destination DVA in indirect mapping",
            ));
        }
        let allocated_bytes = (dva_w0 & 0x00ff_ffff) * 512;
        if allocated_bytes == 0 {
            return Err(invalid("zero-length indirect mapping entry"));
        }
        let dst_offset = (dva_w1 & 0x7fff_ffff_ffff_ffff)
            .checked_mul(512)
            .ok_or_else(|| invalid("indirect mapping destination offset overflow"))?;
        let dst = Dva {
            vdev: ((dva_w0 >> 32) & 0x00ff_ffff) as u32,
            offset: dst_offset,
            allocated_bytes,
            gang: false,
        };
        src_offset
            .checked_add(allocated_bytes)
            .ok_or_else(|| invalid("indirect mapping source range overflow"))?;
        dst.offset
            .checked_add(allocated_bytes)
            .ok_or_else(|| invalid("indirect mapping destination range overflow"))?;
        Ok(Self {
            src_offset,
            marked,
            dst,
        })
    }

    pub fn encode(&self, order: Endian) -> Result<[u8; INDIRECT_MAPPING_ENTRY_BYTES], ParseError> {
        if self.dst.gang
            || self.dst.allocated_bytes == 0
            || !self.src_offset.is_multiple_of(512)
            || !self.dst.offset.is_multiple_of(512)
            || !self.dst.allocated_bytes.is_multiple_of(512)
            || self.dst.vdev > 0x00ff_ffff
            || (self.dst.allocated_bytes / 512) > 0x00ff_ffff
        {
            return Err(invalid("invalid indirect mapping entry for encoding"));
        }
        let src_sectors = self.src_offset / 512;
        if src_sectors > 0x7fff_ffff_ffff_ffff {
            return Err(invalid(
                "indirect mapping source offset exceeds 63-bit sectors",
            ));
        }
        let src_word = src_sectors | (u64::from(self.marked) << 63);
        let dst_sectors = self.dst.offset / 512;
        if dst_sectors > 0x7fff_ffff_ffff_ffff {
            return Err(invalid(
                "indirect mapping destination offset exceeds 63-bit sectors",
            ));
        }
        let dva_w0 = (u64::from(self.dst.vdev) << 32) | (self.dst.allocated_bytes / 512);
        let dva_w1 = dst_sectors;

        let mut out = [0_u8; INDIRECT_MAPPING_ENTRY_BYTES];
        out[0..8].copy_from_slice(&order.encode(src_word));
        out[8..16].copy_from_slice(&order.encode(dva_w0));
        out[16..24].copy_from_slice(&order.encode(dva_w1));
        Ok(out)
    }

    /// Exclusive ending source offset (`src_offset + dst.allocated_bytes`).
    #[must_use]
    pub const fn src_end(&self) -> u64 {
        self.src_offset + self.dst.allocated_bytes
    }
}

/// Bonus header of `DMU_OT_VDEV_INDIRECT_BIRTHS` (`vdev_indirect_birth_phys_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndirectBirthsPhys {
    pub count: u64,
}

impl IndirectBirthsPhys {
    pub fn parse(raw: &[u8], order: Endian) -> Result<Self, ParseError> {
        if raw.len() < INDIRECT_BIRTH_PHYS_BYTES {
            return Err(invalid("indirect births bonus shorter than 8 bytes"));
        }
        Ok(Self {
            count: order.u64(raw, 0)?,
        })
    }

    #[must_use]
    pub fn encode(&self, order: Endian) -> [u8; INDIRECT_BIRTH_PHYS_BYTES] {
        order.encode(self.count)
    }
}

/// Single 16-byte `vdev_indirect_birth_entry_phys_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndirectBirthEntry {
    /// Exclusive ending source offset covered by `phys_birth_txg`.
    pub offset: u64,
    /// Physical TXG at which the mapping entries up to `offset` were copied.
    pub phys_birth_txg: u64,
}

impl IndirectBirthEntry {
    pub fn parse(raw: &[u8], order: Endian) -> Result<Self, ParseError> {
        if raw.len() < INDIRECT_BIRTH_ENTRY_BYTES {
            return Err(invalid("truncated indirect birth entry"));
        }
        Ok(Self {
            offset: order.u64(raw, 0)?,
            phys_birth_txg: order.u64(raw, 8)?,
        })
    }

    #[must_use]
    pub fn encode(&self, order: Endian) -> [u8; INDIRECT_BIRTH_ENTRY_BYTES] {
        let mut out = [0_u8; INDIRECT_BIRTH_ENTRY_BYTES];
        out[0..8].copy_from_slice(&order.encode(self.offset));
        out[8..16].copy_from_slice(&order.encode(self.phys_birth_txg));
        out
    }
}

/// A translated contiguous physical extent on a destination top-level vdev.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappedSpan {
    /// Destination top-level vdev ID.
    pub vdev: u32,
    /// Destination byte offset on `vdev`.
    pub offset: u64,
    /// Length in bytes of this mapped span.
    pub len: u64,
    /// Starting byte offset within the originally requested source range.
    pub logical_offset: u64,
}

/// Validated sorted indirect mapping table for a single removed top-level vdev.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndirectMappingTable {
    pub vdev_id: u32,
    pub phys: IndirectMappingPhys,
    entries: Vec<IndirectMappingEntry>,
    births: Vec<IndirectBirthEntry>,
}

impl IndirectMappingTable {
    /// Construct and validate a strictly increasing, non-overlapping mapping table.
    pub fn new(
        vdev_id: u32,
        phys: IndirectMappingPhys,
        entries: Vec<IndirectMappingEntry>,
        births: Vec<IndirectBirthEntry>,
    ) -> Result<Self, ParseError> {
        if entries.len() as u64 != phys.num_entries {
            return Err(invalid("indirect mapping entry count disagrees with bonus"));
        }
        let mut prev_end = 0_u64;
        for (idx, entry) in entries.iter().enumerate() {
            if idx > 0 && entry.src_offset < prev_end {
                return Err(invalid(
                    "indirect mapping entries are unsorted or overlapping",
                ));
            }
            if entry.dst.vdev == vdev_id {
                return Err(invalid("indirect mapping entry targets its own vdev"));
            }
            prev_end = entry.src_end();
        }
        if prev_end > phys.max_offset && !entries.is_empty() {
            return Err(invalid("indirect mapping entry exceeds vimp_max_offset"));
        }
        for pair in births.windows(2) {
            if pair[1].offset < pair[0].offset {
                return Err(invalid("indirect birth entries are not monotonic"));
            }
        }
        Ok(Self {
            vdev_id,
            phys,
            entries,
            births,
        })
    }

    /// Parse entries and births from raw object streams.
    pub fn parse(
        vdev_id: u32,
        mapping_bonus: &[u8],
        mapping_bytes: &[u8],
        births_bonus: &[u8],
        births_bytes: &[u8],
        order: Endian,
    ) -> Result<Self, ParseError> {
        let phys = IndirectMappingPhys::parse(mapping_bonus, order)?;
        let count = usize::try_from(phys.num_entries)
            .map_err(|_| invalid("indirect mapping entry count overflow"))?;
        let needed = count
            .checked_mul(INDIRECT_MAPPING_ENTRY_BYTES)
            .ok_or_else(|| invalid("indirect mapping byte length overflow"))?;
        if mapping_bytes.len() < needed {
            return Err(invalid("indirect mapping data shorter than num_entries"));
        }
        let mut entries = Vec::with_capacity(count);
        for chunk in mapping_bytes[..needed]
            .as_chunks::<INDIRECT_MAPPING_ENTRY_BYTES>()
            .0
        {
            entries.push(IndirectMappingEntry::parse(chunk, order)?);
        }

        let births_phys = IndirectBirthsPhys::parse(births_bonus, order)?;
        let birth_count = usize::try_from(births_phys.count)
            .map_err(|_| invalid("indirect birth count overflow"))?;
        let birth_needed = birth_count
            .checked_mul(INDIRECT_BIRTH_ENTRY_BYTES)
            .ok_or_else(|| invalid("indirect birth byte length overflow"))?;
        if births_bytes.len() < birth_needed {
            return Err(invalid("indirect births data shorter than vib_count"));
        }
        let mut births = Vec::with_capacity(birth_count);
        for chunk in births_bytes[..birth_needed]
            .as_chunks::<INDIRECT_BIRTH_ENTRY_BYTES>()
            .0
        {
            births.push(IndirectBirthEntry::parse(chunk, order)?);
        }
        Self::new(vdev_id, phys, entries, births)
    }

    #[must_use]
    pub fn entries(&self) -> &[IndirectMappingEntry] {
        &self.entries
    }

    #[must_use]
    pub fn births(&self) -> &[IndirectBirthEntry] {
        &self.births
    }

    /// Serialize mapping entries in on-disk order.
    pub fn encode_entries(&self, order: Endian) -> Result<Vec<u8>, ParseError> {
        let mut out = Vec::with_capacity(self.entries.len() * INDIRECT_MAPPING_ENTRY_BYTES);
        for entry in &self.entries {
            out.extend_from_slice(&entry.encode(order)?);
        }
        Ok(out)
    }

    /// Serialize birth entries in on-disk order.
    #[must_use]
    pub fn encode_births(&self, order: Endian) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.births.len() * INDIRECT_BIRTH_ENTRY_BYTES);
        for entry in &self.births {
            out.extend_from_slice(&entry.encode(order));
        }
        out
    }

    /// Look up the physical copy birth TXG covering `[offset, offset + len)`.
    #[must_use]
    pub fn phys_birth_txg(&self, offset: u64, len: u64) -> Option<u64> {
        let end = offset.checked_add(len)?;
        let idx = self.births.partition_point(|b| b.offset < end);
        self.births.get(idx).map(|b| b.phys_birth_txg)
    }

    /// Translate a single-hop range `[offset, offset + len)` on this indirect
    /// vdev into one or more destination [`MappedSpan`]s (handling split spans
    /// across adjacent mapping entries).
    pub fn translate_one_hop(&self, offset: u64, len: u64) -> Result<Vec<MappedSpan>, ParseError> {
        if len == 0 {
            return Err(invalid("cannot translate zero-length indirect span"));
        }
        offset
            .checked_add(len)
            .ok_or_else(|| invalid("indirect translation range overflow"))?;

        let mut spans = Vec::new();
        let mut cur_off = offset;
        let mut rem = len;
        let mut logical_off = 0_u64;

        while rem > 0 {
            if spans.len() >= MAX_INDIRECT_SPLIT_SPANS {
                return Err(invalid("indirect span split count exceeds safety bound"));
            }
            // Find the largest index with `entries[idx].src_offset <= cur_off`.
            let pos = self.entries.partition_point(|e| e.src_offset <= cur_off);
            if pos == 0 {
                return Err(invalid("indirect mapping gap before requested offset"));
            }
            let entry = &self.entries[pos - 1];
            if cur_off >= entry.src_end() {
                return Err(invalid("indirect mapping gap at requested offset"));
            }
            let delta = cur_off - entry.src_offset;
            let avail = entry.dst.allocated_bytes - delta;
            let take = rem.min(avail);
            spans.push(MappedSpan {
                vdev: entry.dst.vdev,
                offset: entry
                    .dst
                    .offset
                    .checked_add(delta)
                    .ok_or_else(|| invalid("mapped destination offset overflow"))?,
                len: take,
                logical_offset: logical_off,
            });
            cur_off += take;
            rem -= take;
            logical_off += take;
        }
        Ok(spans)
    }
}

/// Resolve a `(vdev_id, offset, len)` span recursively through any chain of
/// removed indirect vdevs (`MAX_INDIRECT_CHAIN_DEPTH = 32`, cycle-checked)
/// until every returned [`MappedSpan`] targets a concrete surviving vdev.
pub fn resolve_indirect_recursive(
    tables: &BTreeMap<u32, IndirectMappingTable>,
    vdev_id: u32,
    offset: u64,
    len: u64,
) -> Result<Vec<MappedSpan>, ParseError> {
    let mut out = Vec::new();
    let mut visited = BTreeSet::new();
    resolve_recursive_inner(tables, vdev_id, offset, len, 0, 0, &mut visited, &mut out)?;
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn resolve_recursive_inner(
    tables: &BTreeMap<u32, IndirectMappingTable>,
    vdev_id: u32,
    offset: u64,
    len: u64,
    base_logical: u64,
    depth: usize,
    visited: &mut BTreeSet<(u32, u64)>,
    out: &mut Vec<MappedSpan>,
) -> Result<(), ParseError> {
    if depth > MAX_INDIRECT_CHAIN_DEPTH {
        return Err(invalid("indirect vdev resolution depth exceeded"));
    }
    let Some(table) = tables.get(&vdev_id) else {
        if out.len() >= MAX_INDIRECT_SPLIT_SPANS {
            return Err(invalid("resolved indirect spans exceed safety bound"));
        }
        out.push(MappedSpan {
            vdev: vdev_id,
            offset,
            len,
            logical_offset: base_logical,
        });
        return Ok(());
    };
    if !visited.insert((vdev_id, offset)) {
        return Err(invalid("cycle detected in indirect vdev mapping chain"));
    }
    let hops = table.translate_one_hop(offset, len)?;
    for hop in hops {
        resolve_recursive_inner(
            tables,
            hop.vdev,
            hop.offset,
            hop.len,
            base_logical + hop.logical_offset,
            depth + 1,
            visited,
            out,
        )?;
    }
    visited.remove(&(vdev_id, offset));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(
        src_offset: u64,
        dst_vdev: u32,
        dst_offset: u64,
        len: u64,
    ) -> IndirectMappingEntry {
        IndirectMappingEntry {
            src_offset,
            marked: false,
            dst: Dva {
                vdev: dst_vdev,
                offset: dst_offset,
                allocated_bytes: len,
                gang: false,
            },
        }
    }

    #[test]
    fn indirect_mapping_roundtrip_split_spans_and_chained_resolution() {
        for order in [Endian::Little, Endian::Big] {
            // Removed vdev 0 maps [0..4096) -> vdev 1 @ 8192 and [4096..12288) -> vdev 2 @ 16384.
            let t0_entries = vec![
                make_entry(0, 1, 8192, 4096),
                make_entry(4096, 2, 16384, 8192),
            ];
            let t0_phys = IndirectMappingPhys {
                max_offset: 12288,
                bytes_mapped: 12288,
                num_entries: 2,
                counts_object: 77,
            };
            let t0_births = vec![IndirectBirthEntry {
                offset: 12288,
                phys_birth_txg: 55,
            }];
            let t0 = IndirectMappingTable::new(0, t0_phys, t0_entries, t0_births).unwrap();
            let parsed_t0 = IndirectMappingTable::parse(
                0,
                &t0_phys.encode(order),
                &t0.encode_entries(order).unwrap(),
                &IndirectBirthsPhys { count: 1 }.encode(order),
                &t0.encode_births(order),
                order,
            )
            .unwrap();
            assert_eq!(parsed_t0, t0);
            assert_eq!(parsed_t0.phys_birth_txg(1024, 4096), Some(55));

            // Removed vdev 1 subsequently chains [8192..10240) -> vdev 2 @ 65536 and
            // [10240..12288) -> vdev 3 @ 4096.
            let t1_entries = vec![
                make_entry(8192, 2, 65536, 2048),
                make_entry(10240, 3, 4096, 2048),
            ];
            let t1_phys = IndirectMappingPhys {
                max_offset: 12288,
                bytes_mapped: 4096,
                num_entries: 2,
                counts_object: 0,
            };
            let t1 = IndirectMappingTable::new(1, t1_phys, t1_entries, Vec::new()).unwrap();

            let mut tables = BTreeMap::new();
            tables.insert(0, t0);
            tables.insert(1, t1);

            // Request [1024..6144) on vdev 0 (5120 bytes): splits across vdev 0's 2 entries
            // AND splits the first half again across vdev 1's 2 entries -> 3 concrete spans!
            let spans = resolve_indirect_recursive(&tables, 0, 1024, 5120).unwrap();
            assert_eq!(
                spans,
                vec![
                    MappedSpan {
                        vdev: 2,
                        offset: 65536 + 1024,
                        len: 1024,
                        logical_offset: 0,
                    },
                    MappedSpan {
                        vdev: 3,
                        offset: 4096,
                        len: 2048,
                        logical_offset: 1024,
                    },
                    MappedSpan {
                        vdev: 2,
                        offset: 16384,
                        len: 2048,
                        logical_offset: 3072,
                    },
                ]
            );
            assert_eq!(spans.iter().map(|s| s.len).sum::<u64>(), 5120);
        }
    }

    #[test]
    fn indirect_mapping_rejects_gaps_overlaps_self_loops_and_cycles() {
        let phys = IndirectMappingPhys {
            max_offset: 8192,
            bytes_mapped: 4096,
            num_entries: 2,
            counts_object: 0,
        };
        // Overlap
        assert!(
            IndirectMappingTable::new(
                0,
                phys,
                vec![make_entry(0, 1, 0, 4096), make_entry(2048, 1, 4096, 4096)],
                Vec::new()
            )
            .is_err()
        );
        // Self-target
        let phys1 = IndirectMappingPhys {
            max_offset: 4096,
            bytes_mapped: 4096,
            num_entries: 1,
            counts_object: 0,
        };
        assert!(
            IndirectMappingTable::new(0, phys1, vec![make_entry(0, 0, 0, 4096)], Vec::new())
                .is_err()
        );

        // Two-vdev cycle: 0 -> 1 -> 0
        let t0 = IndirectMappingTable::new(0, phys1, vec![make_entry(0, 1, 0, 4096)], Vec::new())
            .unwrap();
        let t1 = IndirectMappingTable::new(1, phys1, vec![make_entry(0, 0, 0, 4096)], Vec::new())
            .unwrap();
        let mut tables = BTreeMap::new();
        tables.insert(0, t0);
        tables.insert(1, t1);
        assert!(resolve_indirect_recursive(&tables, 0, 0, 512).is_err());

        // Gap
        let t_gap =
            IndirectMappingTable::new(2, phys1, vec![make_entry(4096, 3, 0, 4096)], Vec::new());
        assert!(t_gap.is_err()); // 4096 + 4096 > max_offset 4096
        let phys_gap = IndirectMappingPhys {
            max_offset: 8192,
            bytes_mapped: 4096,
            num_entries: 1,
            counts_object: 0,
        };
        let t_gap =
            IndirectMappingTable::new(2, phys_gap, vec![make_entry(4096, 3, 0, 4096)], Vec::new())
                .unwrap();
        assert!(t_gap.translate_one_hop(0, 512).is_err());
    }
}
