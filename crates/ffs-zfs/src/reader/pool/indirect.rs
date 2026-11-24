//! OpenZFS `zfs-2.4.0` indirect vdev (`com.delphix:device_removal`) mapping
//! loader and recursive split-span DVA resolver.
//!
//! Resolves DVAs targeting removed top-level `indirect` vdevs into one or more
//! concrete physical spans on surviving top-level vdevs, handling chained
//! removals (max depth 32, cycle rejection) and split-block reassembly before
//! checksum/decompression verification.

use crate::reader::dmu::Objects;
use crate::reader::{
    BlockPointer, BlockRead, Cx, Dva, FfsError, NvList, Pool, Result, Value, VdevConfig,
    checkpoint, corrupt, decode_or_verify, integer, parse, unsupported,
};
use ffs_ondisk::zfs::indirect::{
    INDIRECT_MAPPING_ENTRY_BYTES, IndirectMappingEntry, IndirectMappingPhys, IndirectMappingTable,
    resolve_indirect_recursive,
};
use std::collections::BTreeMap;

/// Loaded per-vdev indirect mapping tables for a pool's removed top-level vdevs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IndirectVdevMap {
    tables: BTreeMap<u32, IndirectMappingTable>,
}

impl IndirectVdevMap {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tables.is_empty()
    }

    #[must_use]
    pub fn contains_vdev(&self, vdev_id: u32) -> bool {
        self.tables.contains_key(&vdev_id)
    }

    #[must_use]
    pub fn table(&self, vdev_id: u32) -> Option<&IndirectMappingTable> {
        self.tables.get(&vdev_id)
    }

    pub fn insert(&mut self, vdev_id: u32, table: IndirectMappingTable) {
        self.tables.insert(vdev_id, table);
    }

    /// Resolve a DVA (which may reference an `indirect` top-level vdev, even
    /// through multiple chained removals or split across multiple physical
    /// spans) into concrete physical `(vdev, offset, allocated_bytes)` DVAs.
    pub fn resolve_dva(&self, dva: &Dva, length: u64) -> Result<Vec<Dva>> {
        if !self.contains_vdev(dva.vdev) {
            return Ok(vec![*dva]);
        }
        let spans = resolve_indirect_recursive(&self.tables, dva.vdev, dva.offset, length)
            .map_err(|e| parse(&e))?;
        Ok(spans
            .into_iter()
            .map(|span| Dva {
                vdev: span.vdev,
                offset: span.offset,
                allocated_bytes: span.len,
                gang: false,
            })
            .collect())
    }

    /// Load all `indirect` top-level vdev mapping tables declared in MOS `config`.
    pub fn load_from_mos(cx: &Cx, mos: &mut Objects, mos_config: &NvList) -> Result<Self> {
        checkpoint(cx)?;
        let root = mos_config
            .list("vdev_tree")
            .ok_or_else(|| corrupt("MOS config missing vdev_tree"))?;
        let Some(Value::Lists(children)) = root.fields.get("children") else {
            return Ok(Self::default());
        };
        let mut map = Self::default();
        for child in children {
            checkpoint(cx)?;
            if child.text("type") != Some("indirect") {
                continue;
            }
            let vdev_id = u32::try_from(integer(child, "id")?)
                .map_err(|_| corrupt("indirect vdev ID overflow"))?;
            let mapping_obj = integer(child, "indirect_object")?;
            if mapping_obj == 0 {
                return Err(corrupt("indirect vdev has zero indirect_object"));
            }
            let (node, ceiling) = mos.object_with_ceiling(cx, mapping_obj)?;
            let bonus = node.bonus();
            let header = IndirectMappingPhys::parse(bonus, node.order()).map_err(|e| parse(&e))?;
            let max_entries = usize::try_from(header.num_entries)
                .map_err(|_| unsupported("indirect mapping entry count exceeds usize"))?;
            let stream_bytes = max_entries
                .checked_mul(INDIRECT_MAPPING_ENTRY_BYTES)
                .ok_or_else(|| corrupt("indirect mapping byte length overflow"))?;
            if stream_bytes > 64 * 1024 * 1024 {
                return Err(unsupported(
                    "indirect mapping table exceeds 64 MiB read budget",
                ));
            }
            let raw = read_object_prefix(cx, mos, &node, ceiling, stream_bytes)?;
            let mut entries = Vec::with_capacity(max_entries);
            for chunk in raw.as_chunks::<INDIRECT_MAPPING_ENTRY_BYTES>().0 {
                checkpoint(cx)?;
                entries
                    .push(IndirectMappingEntry::parse(chunk, node.order()).map_err(|e| parse(&e))?);
            }
            let table = IndirectMappingTable::new(vdev_id, header, entries, Vec::new())
                .map_err(|e| parse(&e))?;
            map.insert(vdev_id, table);
        }
        Ok(map)
    }
}

fn read_object_prefix(
    cx: &Cx,
    mos: &mut Objects,
    node: &ffs_ondisk::zfs_dmu::Dnode,
    ceiling: u64,
    len: usize,
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(len);
    let bsize = node.data_bytes();
    let blocks = len.div_ceil(bsize);
    for bid in 0..blocks {
        checkpoint(cx)?;
        let need = (len - out.len()).min(bsize);
        if (bid as u64) <= node.max_block()
            && let Some((bytes, _, _)) = mos.object_data_block(cx, node, ceiling, bid as u64)?
        {
            out.extend_from_slice(&bytes[..need]);
            continue;
        }
        out.resize(out.len() + need, 0);
    }
    Ok(out)
}

impl Pool {
    /// Read a block whose DVA(s) may target an indirect (removed) vdev,
    /// resolving split spans and chained indirection transparently and
    /// verifying the reassembled physical payload against `bp`.
    pub(super) fn read_via_indirect(
        &self,
        cx: &Cx,
        config: &VdevConfig,
        bp: &BlockPointer,
        indirect_maps: &IndirectVdevMap,
        raw_only: bool,
    ) -> Result<BlockRead> {
        let dvas = bp.data_dvas().map_err(|e| parse(&e))?;
        let psize = bp.physical_bytes();
        let mut failures = Vec::new();
        for (copy_index, dva) in dvas.iter().enumerate() {
            checkpoint(cx)?;
            let spans = match indirect_maps.resolve_dva(dva, psize as u64) {
                Ok(spans) => spans,
                Err(err) => {
                    failures.push(format!("indirect DVA {copy_index}: {err}"));
                    continue;
                }
            };
            let mut assembled = Vec::with_capacity(psize);
            let mut first_offset = 0_u64;
            let mut first_member = 0_usize;
            let mut ok = true;
            for (span_idx, span_dva) in spans.iter().enumerate() {
                checkpoint(cx)?;
                let span_len = usize::try_from(span_dva.allocated_bytes)
                    .map_err(|_| corrupt("indirect span length overflow"))?;
                match self.read_raw_span_from_concrete_vdev(
                    cx,
                    config,
                    span_dva.vdev,
                    span_dva.offset,
                    span_len,
                ) {
                    Ok((bytes, phys_off, member_idx)) => {
                        if span_idx == 0 {
                            first_offset = phys_off;
                            first_member = member_idx;
                        }
                        assembled.extend_from_slice(&bytes);
                    }
                    Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
                    Err(err) => {
                        failures.push(format!(
                            "indirect DVA {copy_index} span {span_idx} (vdev {}): {err}",
                            span_dva.vdev
                        ));
                        ok = false;
                        break;
                    }
                }
            }
            if !ok || assembled.len() < psize {
                continue;
            }
            assembled.truncate(psize);
            match decode_or_verify(bp, assembled, raw_only) {
                Ok(bytes) => {
                    return Ok(BlockRead {
                        bytes,
                        physical_offset: first_offset,
                        copy_index,
                        member_index: first_member,
                        raidz: None,
                    });
                }
                Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
                Err(err) => failures.push(format!("indirect DVA {copy_index} verify: {err}")),
            }
        }
        Err(corrupt(format!(
            "all ZFS indirect block copies failed: {}",
            failures.join("; ")
        )))
    }
}
