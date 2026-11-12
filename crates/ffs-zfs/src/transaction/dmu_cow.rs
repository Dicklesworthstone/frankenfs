//! Metaslab dual-map space reservation, bottom-up DMU COW tree updates, ZAP/quota
//! helpers, deadlist/bpobj accounting, and iterative MOS + space-map convergence.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_ondisk::zfs::nvlist::{NvList, Value};
use ffs_ondisk::zfs::{
    BlockPointer, Dva, Endian, LABEL_CONFIG_BYTES, RegularBlockSpec,
};
use ffs_ondisk::zfs_dmu::space_map::{
    AllocationMap, Header as SpaceMapHeader, MapType, Record as SpaceMapRecord, Records,
    extent_records_for_range,
};
use ffs_ondisk::zfs_dmu::{
    DMU_OT_DNODE, DNODE_BLOCK_BYTES, DNODE_BYTES, DNODE_FLAG_USED_BYTES,
    DNODE_FLAG_USEROBJUSED_ACCOUNTED, DNODE_FLAG_USERUSED_ACCOUNTED, Dnode, DnodeSpec,
    OBJSET_GROUPUSED_OFFSET, OBJSET_PROJECTUSED_OFFSET, OBJSET_USERUSED_OFFSET, ObjectSet,
    ZapEntry, clear_dnode_at, count_allocated_dnodes, dnode_at, encode_microzap,
    find_free_dnode_slot, microzap, write_dnode_at,
};
use ffs_ondisk::zfs_zap::{Entry as RawZapEntry, FAT_TAG, FatHeader, encode_fatzap_with_flags};

use crate::reader::dmu::Objects;

use super::{checkpoint, corrupt, parse_err, unsupported};

pub(super) const DMU_OT_OBJECT_ARRAY: u8 = 2;
pub(super) const DMU_OT_PACKED_NVLIST: u8 = 3;
pub(super) const DMU_OT_BPOBJ: u8 = 5;
pub(super) const DMU_OT_SPACE_MAP_HEADER: u8 = 7;
pub(super) const DMU_OT_SPACE_MAP: u8 = 8;
pub(super) const DMU_OT_OBJSET: u8 = 11;
pub(super) const DMU_OT_ZNODE: u8 = 17;
pub(super) const DMU_OT_PLAIN_FILE_CONTENTS: u8 = 19;
pub(super) const DMU_OT_DIRECTORY_CONTENTS: u8 = 20;
pub(super) const DMU_OT_BPOBJ_HDR: u8 = 36;
pub(super) const DMU_OT_DEADLIST: u8 = 42;
pub(super) const DMU_OT_DEADLIST_HDR: u8 = 43;
pub(super) const DMU_OT_SA: u8 = 44;

pub(super) const SPACE_MAP_BLOCK_BYTES: usize = 4096;
pub(super) const BPOBJ_MAX_BLOCK_BYTES: usize = 131_072;
pub(super) const FATZAP_BLOCK_BYTES: usize = 16_384;
const MAX_RANGES_PER_METASLAB: usize = 262_144;

/// Persistence barrier bucket for a physical block write inside a TXG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum WriteBucket {
    /// Leaf file/directory/spill/deadlist data & indirect blocks.
    ChildBlocks,
    /// Dataset dnode table blocks and dataset `ObjectSet` root block.
    DatasetMetadata,
    /// MOS space-map stream blocks and MOS dnode/indirect blocks.
    MosSpaceMap,
    /// MOS `ObjectSet` root block (referenced by the Uberblock).
    MosRoot,
}

#[derive(Debug, Clone)]
pub(super) struct StagedBlockWrite {
    pub bucket: WriteBucket,
    pub dva_offset: u64,
    pub bytes: Vec<u8>,
}

/// Exact OpenZFS `dmu_ot[type].ot_metadata` classification (`libzpool.so.7`).
#[must_use]
pub(super) const fn dmu_ot_is_metadata(object_type: u8) -> bool {
    if object_type & 0x80 != 0 {
        object_type & 0x40 != 0
    } else {
        !matches!(object_type, 19 | 23 | 25 | 26 | 49 | 54 | 55)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct SpaceDelta {
    pub dsize: u64,
    pub comp: u64,
    pub uncomp: u64,
}

impl SpaceDelta {
    pub fn from_bp(bp: &BlockPointer) -> Result<Self> {
        if bp.hole() || bp.embedded() {
            return Ok(Self::default());
        }
        let dvas = bp.regular_dvas().map_err(|e| parse_err(&e))?;
        let mut dsize = 0_u64;
        for dva in &dvas {
            dsize = dsize
                .checked_add(dva.allocated_bytes)
                .ok_or_else(|| corrupt("DVA allocated_bytes sum overflow"))?;
        }
        let comp = bp.physical_bytes() as u64;
        let is_meta = bp.level() > 0 || dmu_ot_is_metadata(bp.object_type());
        let uncomp = if is_meta {
            comp
        } else {
            bp.logical_bytes() as u64
        };
        Ok(Self {
            dsize,
            comp,
            uncomp,
        })
    }

    pub fn add_assign(&mut self, rhs: Self) -> Result<()> {
        self.dsize = self
            .dsize
            .checked_add(rhs.dsize)
            .ok_or_else(|| corrupt("space delta dsize overflow"))?;
        self.comp = self
            .comp
            .checked_add(rhs.comp)
            .ok_or_else(|| corrupt("space delta comp overflow"))?;
        self.uncomp = self
            .uncomp
            .checked_add(rhs.uncomp)
            .ok_or_else(|| corrupt("space delta uncomp overflow"))?;
        Ok(())
    }
}

#[derive(Clone)]
pub(super) struct MetaslabState {
    pub id: usize,
    pub object: u64,
    pub start: u64,
    pub size: u64,
    pub allocatable_map: AllocationMap,
    pub final_map: AllocationMap,
    pub txg_allocs: Vec<Range<u64>>,
    pub txg_frees: Vec<Range<u64>>,
    pub bonus_len: usize,
    pub preserved_smp_object: u64,
    pub base_stream: Vec<u8>,
}

impl MetaslabState {
    pub fn is_dirty(&self) -> bool {
        !self.txg_allocs.is_empty() || !self.txg_frees.is_empty()
    }

    pub fn build_full_stream(
        &self,
        new_txg: u64,
        order: Endian,
        allow_v2: bool,
    ) -> Result<Vec<u8>> {
        let mut out = self.base_stream.clone();
        let shift = self.final_map.unit_bytes().trailing_zeros() as u8;
        if !self.txg_allocs.is_empty() {
            let dbg = SpaceMapRecord::Debug {
                kind: MapType::Allocate,
                sync_pass: 1,
                txg: new_txg & ((1_u64 << 50) - 1),
            };
            out.extend_from_slice(&dbg.encode(order, allow_v2).map_err(|e| parse_err(&e))?);
            for range in &self.txg_allocs {
                for rec in extent_records_for_range(
                    MapType::Allocate,
                    range.clone(),
                    self.start,
                    self.size,
                    shift,
                )
                .map_err(|e| parse_err(&e))?
                {
                    out.extend_from_slice(&rec.encode(order, allow_v2).map_err(|e| parse_err(&e))?);
                }
            }
        }
        if !self.txg_frees.is_empty() {
            let dbg = SpaceMapRecord::Debug {
                kind: MapType::Free,
                sync_pass: 1,
                txg: new_txg & ((1_u64 << 50) - 1),
            };
            out.extend_from_slice(&dbg.encode(order, allow_v2).map_err(|e| parse_err(&e))?);
            for range in &self.txg_frees {
                for rec in extent_records_for_range(
                    MapType::Free,
                    range.clone(),
                    self.start,
                    self.size,
                    shift,
                )
                .map_err(|e| parse_err(&e))?
                {
                    out.extend_from_slice(&rec.encode(order, allow_v2).map_err(|e| parse_err(&e))?);
                }
            }
        }
        Ok(out)
    }
}

#[derive(Clone)]
pub(super) struct PoolSpaceAllocator {
    pub ashift: u8,
    pub metaslab_shift: u8,
    pub metaslab_array_obj: u64,
    pub spacemap_v2_present: bool,
    pub spacemap_v2_active: bool,
    pub spacemap_histogram_present: bool,
    pub hole_birth_active: bool,
    pub metaslabs: Vec<MetaslabState>,
}

impl PoolSpaceAllocator {
    pub fn load(
        cx: &Cx,
        mos: &mut Objects,
        write_features: &BTreeMap<String, u64>,
        read_features: &[String],
    ) -> Result<Self> {
        checkpoint(cx)?;
        let directory = mos.zap_values(cx, 1)?;
        let config_id = zap_required_u64(&directory, b"config")?;
        let (cfg_node, cfg_ceiling) = mos.object_with_ceiling(cx, config_id)?;
        if cfg_node.object_type() != DMU_OT_PACKED_NVLIST
            || cfg_node.bonus_type() != 4
            || cfg_node.bonus().len() != 8
            || cfg_node.spill().is_some()
        {
            return Err(corrupt("MOS config object has invalid bonus or type"));
        }
        let cfg_len = cfg_node
            .order()
            .u64(cfg_node.bonus(), 0)
            .map_err(|e| parse_err(&e))?;
        if !(1..=LABEL_CONFIG_BYTES as u64).contains(&cfg_len) {
            return Err(unsupported("MOS config nvlist exceeds reader budget"));
        }
        let cfg_bytes = read_dnode_prefix(cx, mos, &cfg_node, cfg_ceiling, cfg_len as usize)?;
        let cfg_nv = NvList::parse_exact(&cfg_bytes).map_err(|e| parse_err(&e))?;
        let root_tree = cfg_nv
            .list("vdev_tree")
            .ok_or_else(|| corrupt("MOS config missing vdev_tree"))?;
        let Some(Value::Lists(children)) = root_tree.fields.get("children") else {
            return Err(corrupt("MOS config vdev_tree has no children"));
        };
        if children.len() != 1 {
            return Err(unsupported(
                "native ZFS writer requires a single top-level vdev",
            ));
        }
        let top = &children[0];
        let ashift = u8::try_from(
            top.unsigned("ashift")
                .ok_or_else(|| corrupt("missing vdev ashift"))?,
        )
        .map_err(|_| corrupt("vdev ashift overflow"))?;
        let metaslab_shift = u8::try_from(
            top.unsigned("metaslab_shift")
                .ok_or_else(|| corrupt("missing metaslab_shift"))?,
        )
        .map_err(|_| corrupt("metaslab_shift overflow"))?;
        let metaslab_array_obj = top
            .unsigned("metaslab_array")
            .ok_or_else(|| corrupt("missing metaslab_array"))?;
        let asize = top
            .unsigned("asize")
            .ok_or_else(|| corrupt("missing vdev asize"))?;
        let ms_count = usize::try_from(asize >> metaslab_shift)
            .map_err(|_| unsupported("metaslab count overflow"))?;
        if ms_count == 0 || ms_count > 65_536 {
            return Err(unsupported("metaslab count outside admitted writer bounds"));
        }

        let (arr_node, arr_ceiling) = mos.object_with_ceiling(cx, metaslab_array_obj)?;
        if arr_node.object_type() != DMU_OT_OBJECT_ARRAY {
            return Err(corrupt("metaslab_array is not DMU_OT_OBJECT_ARRAY"));
        }
        let per_block = arr_node.data_bytes() / 8;
        let mut sm_objs = Vec::with_capacity(ms_count);
        for block_id in 0..(ms_count.div_ceil(per_block) as u64) {
            checkpoint(cx)?;
            let blk = if block_id <= arr_node.max_block() {
                mos.object_data_block(cx, &arr_node, arr_ceiling, block_id)?
            } else {
                None
            };
            let remain = ms_count - sm_objs.len();
            for slot in 0..remain.min(per_block) {
                let obj = match &blk {
                    Some((bytes, order, _)) => {
                        order.u64(bytes, slot * 8).map_err(|e| parse_err(&e))?
                    }
                    None => 0,
                };
                sm_objs.push(obj);
            }
        }

        let spacemap_v2_present = write_features.contains_key("com.delphix:spacemap_v2");
        let spacemap_v2_active = write_features
            .get("com.delphix:spacemap_v2")
            .copied()
            .unwrap_or(0)
            != 0;
        let spacemap_histogram_present =
            write_features.contains_key("com.delphix:spacemap_histogram");
        let hole_birth_active = read_features.iter().any(|f| f == "com.delphix:hole_birth");
        let ms_size = 1_u64 << metaslab_shift;

        let mut metaslabs = Vec::with_capacity(ms_count);
        for (id, sm_obj) in sm_objs.into_iter().enumerate() {
            checkpoint(cx)?;
            let start = (id as u64) * ms_size;
            let mut map = AllocationMap::new(start, ms_size, ashift, MAX_RANGES_PER_METASLAB)
                .map_err(|e| parse_err(&e))?;
            let mut bonus_len = if spacemap_histogram_present { 320 } else { 24 };
            let mut preserved_smp_object = sm_obj;
            let mut base_stream = Vec::new();
            if sm_obj != 0 {
                let (sm_node, sm_ceiling) = mos.object_with_ceiling(cx, sm_obj)?;
                if sm_node.object_type() != DMU_OT_SPACE_MAP
                    || sm_node.bonus_type() != DMU_OT_SPACE_MAP_HEADER
                    || sm_node.spill().is_some()
                {
                    return Err(corrupt("invalid metaslab space-map dnode"));
                }
                bonus_len = sm_node.bonus().len();
                preserved_smp_object = sm_node
                    .order()
                    .u64(sm_node.bonus(), 0)
                    .map_err(|e| parse_err(&e))?;
                let hdr = SpaceMapHeader::parse(sm_node.bonus(), sm_node.order())
                    .map_err(|e| parse_err(&e))?;
                let stream_len = usize::try_from(hdr.length)
                    .map_err(|_| unsupported("space-map stream exceeds usize"))?;
                base_stream = read_dnode_prefix(cx, mos, &sm_node, sm_ceiling, stream_len)?;
                let bsize = sm_node.data_bytes();
                let blocks = stream_len.div_ceil(bsize);
                for bid in 0..blocks {
                    let start_off = bid * bsize;
                    let end_off = (start_off + bsize).min(stream_len);
                    for rec in Records::new(
                        &base_stream[start_off..end_off],
                        sm_node.order(),
                        spacemap_v2_active,
                    )
                    .map_err(|e| parse_err(&e))?
                    {
                        if let SpaceMapRecord::Extent(ext) = rec.map_err(|e| parse_err(&e))? {
                            if ext.vdev.is_some_and(|v| v != 0) {
                                return Err(corrupt("unexpected log-spacemap vdev in metaslab"));
                            }
                            let range = ext
                                .byte_range(start, ms_size, ashift)
                                .map_err(|e| parse_err(&e))?;
                            map.apply(ext.kind, range).map_err(|e| parse_err(&e))?;
                        }
                    }
                }
                let expected = u64::try_from(hdr.allocated)
                    .map_err(|_| corrupt("negative metaslab allocated bytes"))?;
                if map.allocated_bytes() != expected {
                    return Err(corrupt(
                        "metaslab space-map stream disagrees with header counter",
                    ));
                }
            }
            metaslabs.push(MetaslabState {
                id,
                object: sm_obj,
                start,
                size: ms_size,
                allocatable_map: map.clone(),
                final_map: map,
                txg_allocs: Vec::new(),
                txg_frees: Vec::new(),
                bonus_len,
                preserved_smp_object,
                base_stream,
            });
        }

        Ok(Self {
            ashift,
            metaslab_shift,
            metaslab_array_obj,
            spacemap_v2_present,
            spacemap_v2_active,
            spacemap_histogram_present,
            hole_birth_active,
            metaslabs,
        })
    }

    pub fn total_allocated_bytes(&self) -> u64 {
        self.metaslabs
            .iter()
            .map(|m| m.final_map.allocated_bytes())
            .sum()
    }

    pub fn total_free_bytes(&self) -> u64 {
        self.metaslabs
            .iter()
            .map(|m| m.size - m.final_map.allocated_bytes())
            .sum()
    }

    /// Allocate one physical block extent of `physical_bytes` rounded up to `1 << ashift`.
    /// Prefers already-initialized metaslabs first so uninitialized metaslabs stay untouched
    /// unless all initialized metaslabs lack a contiguous extent.
    pub fn allocate(&mut self, physical_bytes: usize) -> Result<Dva> {
        let sector = 1_u64 << self.ashift;
        let asize = (physical_bytes as u64).div_ceil(sector) * sector;
        if asize == 0 {
            return Err(corrupt("zero-sized ZFS allocation request"));
        }
        for prefer_initialized in [true, false] {
            for ms in &mut self.metaslabs {
                if (ms.object != 0) != prefer_initialized {
                    continue;
                }
                if let Some(range) = ms.allocatable_map.find_free_extent(asize, sector) {
                    ms.allocatable_map
                        .apply(MapType::Allocate, range.clone())
                        .map_err(|e| parse_err(&e))?;
                    ms.final_map
                        .apply(MapType::Allocate, range.clone())
                        .map_err(|e| parse_err(&e))?;
                    push_coalesced_range(&mut ms.txg_allocs, range.clone());
                    return Ok(Dva {
                        vdev: 0,
                        offset: range.start,
                        allocated_bytes: asize,
                        gang: false,
                    });
                }
            }
        }
        Err(FfsError::NoSpace)
    }

    /// Free DVAs of an unshared block (`bp.birth() > ds_prev_snap_txg`).
    /// Blocks born in earlier TXGs are freed ONLY in `final_map` (deferred COW safety:
    /// never reused within `new_txg` before the Uberblock commits).
    pub fn free_block_dvas(&mut self, bp: &BlockPointer, new_txg: u64) -> Result<SpaceDelta> {
        if bp.hole() || bp.embedded() {
            return Ok(SpaceDelta::default());
        }
        let delta = SpaceDelta::from_bp(bp)?;
        let dvas = bp.regular_dvas().map_err(|e| parse_err(&e))?;
        let ms_size = 1_u64 << self.metaslab_shift;
        for dva in dvas {
            if dva.vdev != 0 || dva.gang {
                return Err(unsupported("cannot free foreign-vdev or gang DVA"));
            }
            let ms_id = usize::try_from(dva.offset / ms_size)
                .map_err(|_| corrupt("DVA metaslab index overflow"))?;
            let ms = self
                .metaslabs
                .get_mut(ms_id)
                .ok_or_else(|| corrupt("DVA falls outside metaslab table"))?;
            let range = dva.offset..(dva.offset + dva.allocated_bytes);
            if bp.birth() == new_txg {
                ms.allocatable_map
                    .apply(MapType::Free, range.clone())
                    .map_err(|e| parse_err(&e))?;
                ms.final_map
                    .apply(MapType::Free, range.clone())
                    .map_err(|e| parse_err(&e))?;
                remove_range_from_list(&mut ms.txg_allocs, &range);
            } else {
                ms.final_map
                    .apply(MapType::Free, range.clone())
                    .map_err(|e| parse_err(&e))?;
                push_coalesced_range(&mut ms.txg_frees, range);
            }
        }
        Ok(delta)
    }
}

fn push_coalesced_range(list: &mut Vec<Range<u64>>, range: Range<u64>) {
    if let Some(last) = list.last_mut()
        && last.end == range.start
    {
        last.end = range.end;
        return;
    }
    list.push(range);
}

fn remove_range_from_list(list: &mut Vec<Range<u64>>, target: &Range<u64>) {
    let mut updated = Vec::with_capacity(list.len());
    for r in list.drain(..) {
        if r.end <= target.start || r.start >= target.end {
            updated.push(r);
        } else {
            if r.start < target.start {
                updated.push(r.start..target.start);
            }
            if target.end < r.end {
                updated.push(target.end..r.end);
            }
        }
    }
    *list = updated;
}

pub(super) fn zap_required_u64(rows: &[RawZapEntry], name: &[u8]) -> Result<u64> {
    let row = rows
        .iter()
        .find(|r| r.name == name)
        .ok_or_else(|| corrupt("missing required ZAP entry"))?;
    row.scalar().map_err(|e| parse_err(&e))
}

pub(super) fn zap_optional_u64(rows: &[RawZapEntry], name: &[u8]) -> Result<Option<u64>> {
    let Some(row) = rows.iter().find(|r| r.name == name) else {
        return Ok(None);
    };
    Ok(Some(row.scalar().map_err(|e| parse_err(&e))?))
}

pub(super) fn read_dnode_prefix(
    cx: &Cx,
    view: &mut Objects,
    node: &Dnode,
    ceiling: u64,
    byte_len: usize,
) -> Result<Vec<u8>> {
    if byte_len == 0 {
        return Ok(Vec::new());
    }
    let bsize = node.data_bytes();
    let blocks = byte_len.div_ceil(bsize);
    if (blocks - 1) as u64 > node.max_block() {
        return Err(corrupt("requested dnode prefix exceeds dn_maxblkid"));
    }
    let mut out = Vec::with_capacity(byte_len);
    for bid in 0..(blocks as u64) {
        checkpoint(cx)?;
        let take = (byte_len - out.len()).min(bsize);
        if let Some((bytes, _, _)) = view.object_data_block(cx, node, ceiling, bid)? {
            out.extend_from_slice(&bytes[..take]);
        } else {
            out.resize(out.len() + take, 0);
        }
    }
    Ok(out)
}

/// Parameters for COW-updating or creating a single `Dnode`'s block tree.
pub(super) struct DnodeCowSpec<'a> {
    pub existing: Option<(&'a Dnode, u64)>,
    pub object_type: u8,
    pub bonus_type: u8,
    pub checksum_type: u8,
    pub compress_type: u8,
    pub user_flags: u8,
    pub indirect_shift: u8,
    pub data_bytes: usize,
    pub max_block: u64,
    pub slots: usize,
    pub nblkptr: usize,
    pub bonus: Vec<u8>,
    pub spill: Option<BlockPointer>,
    pub order: Endian,
    pub new_txg: u64,
    pub leaf_bucket: WriteBucket,
    pub indirect_bucket: WriteBucket,
}

pub(super) struct DnodeCowOutput {
    pub dnode: Dnode,
    pub born: SpaceDelta,
    pub retired_bps: Vec<BlockPointer>,
}

fn pointer_fill_contribution(bp: &BlockPointer) -> u64 {
    if bp.embedded() {
        1
    } else if bp.hole() {
        0
    } else {
        bp.fill()
    }
}

fn make_hole_bp(
    logical_bytes: usize,
    object_type: u8,
    level: u8,
    new_txg: u64,
    hole_birth_active: bool,
) -> Result<BlockPointer> {
    if hole_birth_active {
        BlockPointer::born_hole(logical_bytes, object_type, level, new_txg)
            .map_err(|e| parse_err(&e))
    } else {
        Ok(BlockPointer::hole_pointer())
    }
}

/// Enumerate all non-hole leaf and indirect `BlockPointer`s at or after `min_leaf_block`
/// in `node` so shrinking/deleting a dnode accounts for every retired block.
pub(super) fn collect_non_hole_bps_from(
    cx: &Cx,
    view: &mut Objects,
    node: &Dnode,
    ceiling: u64,
    min_leaf_block: u64,
    include_partial_ancestors: bool,
    out: &mut Vec<BlockPointer>,
) -> Result<()> {
    let top_level = node.levels() - 1;
    let fanout = (node.indirect_bytes() / 128) as u128;
    let span = fanout.pow(u32::from(top_level));
    for (slot, bp) in node.pointers().iter().enumerate() {
        let start = (slot as u128) * span;
        let end = start + span;
        if end <= u128::from(min_leaf_block) || bp.hole() {
            continue;
        }
        collect_subtree_bps(
            cx,
            view,
            node,
            bp,
            top_level,
            start,
            span,
            ceiling,
            min_leaf_block,
            include_partial_ancestors,
            out,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn collect_subtree_bps(
    cx: &Cx,
    view: &mut Objects,
    node: &Dnode,
    bp: &BlockPointer,
    level: u8,
    start: u128,
    span: u128,
    ceiling: u64,
    min_leaf_block: u64,
    include_partial_ancestors: bool,
    out: &mut Vec<BlockPointer>,
) -> Result<()> {
    checkpoint(cx)?;
    if bp.hole() {
        return Ok(());
    }
    if level == 0 {
        if start >= u128::from(min_leaf_block) {
            out.push(bp.clone());
        }
        return Ok(());
    }
    let Some((bytes, order, birth)) = view.checked_raw(
        cx,
        bp,
        node.object_type(),
        level,
        node.indirect_bytes(),
        ceiling,
    )?
    else {
        return Ok(());
    };
    let fanout = (bytes.len() / 128) as u128;
    let child_span = span / fanout;
    for (slot, raw) in bytes.as_chunks::<128>().0.iter().enumerate() {
        let child_start = start + (slot as u128) * child_span;
        let child_end = child_start + child_span;
        if child_end <= u128::from(min_leaf_block) {
            continue;
        }
        let child = BlockPointer::parse(raw, order).map_err(|e| parse_err(&e))?;
        if !child.hole() {
            collect_subtree_bps(
                cx,
                view,
                node,
                &child,
                level - 1,
                child_start,
                child_span,
                birth,
                min_leaf_block,
                include_partial_ancestors,
                out,
            )?;
        }
    }
    if start >= u128::from(min_leaf_block) || include_partial_ancestors {
        out.push(bp.clone());
    }
    Ok(())
}

fn lookup_existing_bp_at_level(
    cx: &Cx,
    view: &mut Objects,
    node: &Dnode,
    ceiling: u64,
    target_level: u8,
    index_at_level: u64,
) -> Result<Option<(BlockPointer, u64)>> {
    let old_top = node.levels() - 1;
    if target_level > old_top {
        return Ok(None);
    }
    let fanout = (node.indirect_bytes() / 128) as u128;
    let steps = old_top - target_level;
    let divisor = fanout.pow(u32::from(steps));
    let root_slot = u128::from(index_at_level) / divisor;
    if root_slot >= node.pointers().len() as u128 {
        return Ok(None);
    }
    let mut bp = node.pointers()[root_slot as usize].clone();
    let mut cur_ceiling = ceiling;
    let mut rem = u128::from(index_at_level) % divisor;
    let mut cur_div = divisor;
    for step in 0..steps {
        if bp.hole() {
            return Ok(None);
        }
        let cur_level = old_top - step;
        let Some((bytes, order, birth)) = view.checked_raw(
            cx,
            &bp,
            node.object_type(),
            cur_level,
            node.indirect_bytes(),
            cur_ceiling,
        )?
        else {
            return Ok(None);
        };
        cur_div /= fanout;
        let slot = (rem / cur_div) as usize;
        rem %= cur_div;
        let at = slot * 128;
        bp = BlockPointer::parse(&bytes[at..at + 128], order).map_err(|e| parse_err(&e))?;
        cur_ceiling = birth;
    }
    if bp.hole() {
        Ok(None)
    } else {
        Ok(Some((bp, cur_ceiling)))
    }
}

/// Bottom-up COW update of one dnode's data and indirect blocks.
pub(super) fn cow_update_dnode(
    cx: &Cx,
    view: &mut Objects,
    alloc: &mut PoolSpaceAllocator,
    spec: DnodeCowSpec<'_>,
    dirty_leaves: &BTreeMap<u64, Option<Vec<u8>>>,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<DnodeCowOutput> {
    checkpoint(cx)?;
    let mut retired_bps = Vec::new();
    let mut born = SpaceDelta::default();
    let effective_cksum = if matches!(spec.checksum_type, 6..=8) {
        spec.checksum_type
    } else {
        7
    };

    // 1. If shrinking max_block (or resetting to 0), retire all blocks past spec.max_block.
    if let Some((old_node, old_ceiling)) = spec.existing
        && spec.max_block < old_node.max_block()
    {
        collect_non_hole_bps_from(
            cx,
            view,
            old_node,
            old_ceiling,
            spec.max_block + 1,
            false,
            &mut retired_bps,
        )?;
    }

    // 2. Determine required indirection levels (`1..=7`).
    let indirect_bytes = 1_usize << spec.indirect_shift;
    let fanout = (indirect_bytes / 128) as u64;
    let mut levels = spec.existing.map_or(1_u8, |(n, _)| n.levels());
    if spec.max_block == 0 && levels > 1 {
        // Shrinking back to single-block: retire all old indirect blocks (`level >= 1`).
        if let Some((old_node, old_ceiling)) = spec.existing {
            let mut all_old = Vec::new();
            collect_non_hole_bps_from(cx, view, old_node, old_ceiling, 0, true, &mut all_old)?;
            for bp in all_old {
                if bp.level() > 0 {
                    retired_bps.push(bp);
                }
            }
        }
        levels = 1;
    } else {
        while u128::from(spec.max_block)
            >= (spec.nblkptr as u128) * (u128::from(fanout)).pow(u32::from(levels - 1))
        {
            levels = levels
                .checked_add(1)
                .filter(|&l| l <= 7)
                .ok_or_else(|| unsupported("DMU indirection depth exceeds 7 levels"))?;
        }
    }

    // 3. Build level-0 updated pointers for dirty leaves (`0..=spec.max_block`).
    let mut current_updates: BTreeMap<u64, BlockPointer> = BTreeMap::new();
    for (&block_id, maybe_bytes) in dirty_leaves {
        checkpoint(cx)?;
        if block_id > spec.max_block {
            continue;
        }
        if let Some((old_node, old_ceiling)) = spec.existing
            && let Some((old_bp, _)) =
                lookup_existing_bp_at_level(cx, view, old_node, old_ceiling, 0, block_id)?
        {
            retired_bps.push(old_bp);
        }
        let new_bp = if let Some(payload) = maybe_bytes {
            if payload.len() != spec.data_bytes {
                return Err(corrupt(
                    "dirty DMU leaf block size disagrees with dn_datablkszsec",
                ));
            }
            let fill = if spec.object_type == DMU_OT_DNODE {
                count_allocated_dnodes(payload, spec.order).map_err(|e| parse_err(&e))?
            } else {
                1
            };
            let dva = alloc.allocate(payload.len())?;
            let bp = BlockPointer::new_regular(&RegularBlockSpec {
                dvas: &[dva],
                physical: payload,
                logical_bytes: payload.len(),
                compression: 2,
                checksum_type: effective_cksum,
                object_type: spec.object_type,
                level: 0,
                payload_order: spec.order,
                birth: spec.new_txg,
                fill,
            })
            .map_err(|e| parse_err(&e))?;
            born.add_assign(SpaceDelta::from_bp(&bp)?)?;
            staged_writes.push(StagedBlockWrite {
                bucket: spec.leaf_bucket,
                dva_offset: dva.offset,
                bytes: payload.clone(),
            });
            bp
        } else {
            make_hole_bp(
                spec.data_bytes,
                spec.object_type,
                0,
                spec.new_txg,
                alloc.hole_birth_active,
            )?
        };
        current_updates.insert(block_id, new_bp);
    }

    // If indirection grew (`levels > old_levels`), seed existing root pointers at `old_top`
    // into `level = old_top` updates so they get wrapped into new parent indirects at index 0
    // without losing unmodified subtrees!
    let old_levels = spec.existing.map_or(1_u8, |(n, _)| n.levels());
    let mut promoted_seed: BTreeMap<u8, BTreeMap<u64, BlockPointer>> = BTreeMap::new();
    if let Some((old_node, _)) = spec.existing
        && levels > old_levels
    {
        let old_top = old_levels - 1;
        let map = promoted_seed.entry(old_top).or_default();
        for (slot, bp) in old_node.pointers().iter().enumerate() {
            if !bp.hole() {
                map.insert(slot as u64, bp.clone());
            }
        }
    }

    if let Some(seed) = promoted_seed.remove(&0) {
        for (idx, bp) in seed {
            current_updates.entry(idx).or_insert(bp);
        }
    }

    // 4. Propagate bottom-up through indirect levels `1 .. levels`.
    for parent_level in 1..levels {
        let child_level = parent_level - 1;
        let mut grouped: BTreeMap<u64, Vec<(usize, BlockPointer)>> = BTreeMap::new();
        for (child_idx, child_bp) in current_updates {
            let parent_idx = child_idx / fanout;
            let slot = (child_idx % fanout) as usize;
            grouped
                .entry(parent_idx)
                .or_default()
                .push((slot, child_bp));
        }
        let mut next_updates = BTreeMap::new();
        if let Some(seed) = promoted_seed.remove(&parent_level) {
            for (idx, bp) in seed {
                next_updates.insert(idx, bp);
            }
        }
        for (parent_idx, children) in grouped {
            checkpoint(cx)?;
            let mut raw_block = vec![0_u8; indirect_bytes];
            if let Some((old_node, old_ceiling)) = spec.existing
                && parent_level < old_levels
                && let Some((old_ind_bp, ind_ceiling)) = lookup_existing_bp_at_level(
                    cx,
                    view,
                    old_node,
                    old_ceiling,
                    parent_level,
                    parent_idx,
                )?
            {
                if let Some((old_bytes, old_order, _)) = view.checked_raw(
                    cx,
                    &old_ind_bp,
                    old_node.object_type(),
                    parent_level,
                    indirect_bytes,
                    ind_ceiling,
                )? {
                    if old_order == spec.order {
                        raw_block.copy_from_slice(&old_bytes);
                    } else {
                        for (slot, chunk) in old_bytes.as_chunks::<128>().0.iter().enumerate() {
                            let parsed = BlockPointer::parse(chunk, old_order)
                                .map_err(|e| parse_err(&e))?;
                            raw_block[slot * 128..(slot + 1) * 128]
                                .copy_from_slice(&parsed.encode(spec.order));
                        }
                    }
                }
                retired_bps.push(old_ind_bp);
            }
            // Zero any child slots strictly past `spec.max_block` at `child_level`.
            let child_span = (u128::from(fanout)).pow(u32::from(child_level));
            for slot in 0..(fanout as usize) {
                let child_global = (u128::from(parent_idx) * u128::from(fanout) + slot as u128)
                    * child_span;
                if child_global > u128::from(spec.max_block) {
                    raw_block[slot * 128..(slot + 1) * 128].fill(0);
                }
            }
            for (slot, child_bp) in children {
                raw_block[slot * 128..(slot + 1) * 128]
                    .copy_from_slice(&child_bp.encode(spec.order));
            }
            let mut all_holes = true;
            let mut fill_sum = 0_u64;
            for chunk in raw_block.as_chunks::<128>().0 {
                let parsed = BlockPointer::parse(chunk, spec.order).map_err(|e| parse_err(&e))?;
                if !parsed.hole() {
                    all_holes = false;
                    fill_sum = fill_sum
                        .checked_add(pointer_fill_contribution(&parsed))
                        .ok_or_else(|| corrupt("indirect blk_fill overflow"))?;
                }
            }
            let new_ind_bp = if all_holes {
                make_hole_bp(
                    indirect_bytes,
                    spec.object_type,
                    parent_level,
                    spec.new_txg,
                    alloc.hole_birth_active,
                )?
            } else {
                let dva = alloc.allocate(indirect_bytes)?;
                let bp = BlockPointer::new_regular(&RegularBlockSpec {
                    dvas: &[dva],
                    physical: &raw_block,
                    logical_bytes: indirect_bytes,
                    compression: 2,
                    checksum_type: effective_cksum,
                    object_type: spec.object_type,
                    level: parent_level,
                    payload_order: spec.order,
                    birth: spec.new_txg,
                    fill: fill_sum,
                })
                .map_err(|e| parse_err(&e))?;
                born.add_assign(SpaceDelta::from_bp(&bp)?)?;
                staged_writes.push(StagedBlockWrite {
                    bucket: spec.indirect_bucket,
                    dva_offset: dva.offset,
                    bytes: raw_block,
                });
                bp
            };
            next_updates.insert(parent_idx, new_ind_bp);
        }
        current_updates = next_updates;
    }

    // 5. Assemble root pointers (`0..spec.nblkptr`) and exact `used_bytes`.
    let mut root_pointers = vec![BlockPointer::hole_pointer(); spec.nblkptr];
    if let Some((old_node, _)) = spec.existing
        && levels == old_levels
    {
        for (slot, bp) in old_node.pointers().iter().take(spec.nblkptr).enumerate() {
            let root_span = (u128::from(fanout)).pow(u32::from(levels - 1));
            if (slot as u128) * root_span <= u128::from(spec.max_block) {
                root_pointers[slot] = bp.clone();
            }
        }
    }
    for (slot_u64, bp) in current_updates {
        let slot = usize::try_from(slot_u64).map_err(|_| corrupt("root pointer slot overflow"))?;
        if slot >= spec.nblkptr {
            return Err(corrupt("computed root pointer slot exceeds dn_nblkptr"));
        }
        root_pointers[slot] = bp;
    }

    // Handle spill block delta if spill changed.
    if let Some((old_node, _)) = spec.existing
        && let Some(old_spill) = old_node.spill()
        && spec.spill.as_ref() != Some(old_spill)
    {
        retired_bps.push(old_spill.clone());
    }
    if let Some(new_spill) = &spec.spill {
        let was_same = spec
            .existing
            .and_then(|(n, _)| n.spill())
            .is_some_and(|old_s| old_s == new_spill);
        if !was_same {
            born.add_assign(SpaceDelta::from_bp(new_spill)?)?;
        }
    }

    let mut retired_dsize = 0_u64;
    for rbp in &retired_bps {
        retired_dsize = retired_dsize
            .checked_add(SpaceDelta::from_bp(rbp)?.dsize)
            .ok_or_else(|| corrupt("retired dnode space overflow"))?;
    }
    let old_used = spec.existing.map_or(0_u64, |(n, _)| n.used_bytes());
    let used_bytes = old_used
        .checked_add(born.dsize)
        .and_then(|v| v.checked_sub(retired_dsize))
        .ok_or_else(|| corrupt("dnode used_bytes underflow or overflow"))?;

    let mut flags = DNODE_FLAG_USED_BYTES | (spec.user_flags & 0x0A);
    if spec.spill.is_some() {
        flags |= 0x04;
    }
    let dnode = Dnode::from_spec(DnodeSpec {
        object_type: spec.object_type,
        bonus_type: spec.bonus_type,
        checksum_type: spec.existing.map_or(0, |(n, _)| n.checksum_type()),
        compress_type: spec.compress_type,
        flags,
        order: spec.order,
        levels,
        indirect_shift: spec.indirect_shift,
        data_bytes: spec.data_bytes,
        max_block: spec.max_block,
        used_bytes,
        slots: spec.slots,
        pointers: root_pointers,
        bonus: spec.bonus,
        spill: spec.spill,
    })
    .map_err(|e| parse_err(&e))?;

    Ok(DnodeCowOutput {
        dnode,
        born,
        retired_bps,
    })
}

/// Encode a ZAP entry set (preserving Micro-ZAP while it fits, or upgrading/keeping Fat-ZAP).
pub(super) fn encode_zap_blocks_for_dnode(
    cx: &Cx,
    view: &mut Objects,
    existing: Option<(&Dnode, u64)>,
    entries: &[RawZapEntry],
    order: Endian,
    min_block_bytes: usize,
) -> Result<(usize, Vec<Vec<u8>>)> {
    let mut was_fatzap = false;
    let mut salt = 0x5A46_535F_4646_5331_u64;
    let mut hash64 = false;
    if let Some((node, ceiling)) = existing
        && let Some((blk0, blk_order, _)) = view.object_data_block(cx, node, ceiling, 0)?
        && blk0.len() >= 64
        && blk_order.u64(&blk0, 0).ok() == Some(FAT_TAG)
    {
        was_fatzap = true;
        if let Ok(fh) = FatHeader::parse(&blk0, blk_order, node.max_block()) {
            salt = fh.salt();
            hash64 = fh.is_hash64();
        }
    }

    let can_micro = !was_fatzap
        && !hash64
        && entries.iter().all(|e| {
            e.integer_bytes == 8 && e.values.len() == 1 && !e.name.is_empty() && e.name.len() <= 49
        });
    if can_micro {
        let micro_entries: Vec<ZapEntry> = entries
            .iter()
            .map(|e| ZapEntry {
                name: e.name.clone(),
                value: e.values[0],
                collision: 0,
            })
            .collect();
        let mut bsize = existing
            .map_or(min_block_bytes, |(n, _)| n.data_bytes())
            .max(min_block_bytes)
            .max(512);
        while bsize <= FATZAP_BLOCK_BYTES {
            if let Ok(raw) = encode_microzap(&micro_entries, bsize, salt, order) {
                return Ok((bsize, vec![raw]));
            }
            bsize *= 2;
        }
    }

    let blocks = encode_fatzap_with_flags(entries, FATZAP_BLOCK_BYTES, salt, hash64, order)
        .map_err(|e| parse_err(&e))?;
    Ok((FATZAP_BLOCK_BYTES, blocks))
}

/// Update embedded `ObjectSet` quota ZAPs (`1024`, `1536`, `2048`) if allocated on `os`.
pub(super) struct QuotaDelta {
    pub uid: u64,
    pub gid: u64,
    pub projid: Option<u64>,
    pub bytes_delta: i64,
    pub objs_delta: i64,
}

pub(super) fn objectset_user_accounting_flags(os: &ObjectSet, order: Endian) -> Result<u8> {
    if os
        .embedded_dnode(OBJSET_USERUSED_OFFSET, order)
        .map_err(|e| parse_err(&e))?
        .is_none()
    {
        return Ok(0);
    }
    let mut flags = DNODE_FLAG_USERUSED_ACCOUNTED;
    if os.flags & 0x02 != 0 {
        flags |= DNODE_FLAG_USEROBJUSED_ACCOUNTED;
    }
    Ok(flags)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn apply_objectset_quota_deltas(
    cx: &Cx,
    os_view: &mut Objects,
    os: &mut ObjectSet,
    alloc: &mut PoolSpaceAllocator,
    deltas: &[QuotaDelta],
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
    born_out: &mut SpaceDelta,
    retired_out: &mut Vec<BlockPointer>,
) -> Result<()> {
    if deltas.is_empty()
        || os
            .embedded_dnode(OBJSET_USERUSED_OFFSET, order)
            .map_err(|e| parse_err(&e))?
            .is_none()
    {
        return Ok(());
    }
    let track_objs = os.flags & 0x02 != 0;
    let track_proj = os.flags & 0x04 != 0
        && os
            .embedded_dnode(OBJSET_PROJECTUSED_OFFSET, order)
            .map_err(|e| parse_err(&e))?
            .is_some();

    let mut maps: [(usize, BTreeMap<Vec<u8>, i128>); 3] = [
        (OBJSET_USERUSED_OFFSET, BTreeMap::new()),
        (OBJSET_GROUPUSED_OFFSET, BTreeMap::new()),
        (OBJSET_PROJECTUSED_OFFSET, BTreeMap::new()),
    ];
    for d in deltas {
        if d.bytes_delta != 0 {
            *maps[0]
                .1
                .entry(format!("{:x}", d.uid).into_bytes())
                .or_default() += i128::from(d.bytes_delta);
            *maps[1]
                .1
                .entry(format!("{:x}", d.gid).into_bytes())
                .or_default() += i128::from(d.bytes_delta);
            if track_proj && let Some(proj) = d.projid {
                *maps[2]
                    .1
                    .entry(format!("{proj:x}").into_bytes())
                    .or_default() += i128::from(d.bytes_delta);
            }
        }
        if track_objs && d.objs_delta != 0 {
            *maps[0]
                .1
                .entry(format!("obj-{:x}", d.uid).into_bytes())
                .or_default() += i128::from(d.objs_delta);
            *maps[1]
                .1
                .entry(format!("obj-{:x}", d.gid).into_bytes())
                .or_default() += i128::from(d.objs_delta);
            if track_proj && let Some(proj) = d.projid {
                *maps[2]
                    .1
                    .entry(format!("obj-{proj:x}").into_bytes())
                    .or_default() += i128::from(d.objs_delta);
            }
        }
    }

    let min_blk = (1_usize << alloc.ashift).max(512);
    for (slot_offset, changes) in maps {
        if changes.is_empty() {
            continue;
        }
        let Some(emb_dn) = os
            .embedded_dnode(slot_offset, order)
            .map_err(|e| parse_err(&e))?
        else {
            continue;
        };
        let mut entries = read_embedded_zap_entries(cx, os_view, &emb_dn, os_view.root_birth_txg())?;
        for (key, delta) in changes {
            if delta == 0 {
                continue;
            }
            if let Some(existing) = entries.iter_mut().find(|e| e.name == key) {
                let cur = i128::from(existing.scalar().map_err(|e| parse_err(&e))?);
                let next = u64::try_from((cur + delta).max(0)).unwrap_or(u64::MAX);
                if next == 0 {
                    existing.values.clear();
                } else {
                    existing.values = vec![next];
                }
            } else if delta > 0 {
                entries.push(RawZapEntry {
                    name: key,
                    integer_bytes: 8,
                    values: vec![u64::try_from(delta).unwrap_or(u64::MAX)],
                    collision: 0,
                });
            }
        }
        entries.retain(|e| !e.values.is_empty());
        let (bsize, blocks) = encode_zap_blocks_for_dnode(
            cx,
            os_view,
            Some((&emb_dn, os_view.root_birth_txg())),
            &entries,
            order,
            min_blk,
        )?;
        let mut dirty = BTreeMap::new();
        for (i, blk) in blocks.into_iter().enumerate() {
            dirty.insert(i as u64, Some(blk));
        }
        let out = cow_update_dnode(
            cx,
            os_view,
            alloc,
            DnodeCowSpec {
                existing: Some((&emb_dn, os_view.root_birth_txg())),
                object_type: emb_dn.object_type(),
                bonus_type: emb_dn.bonus_type(),
                checksum_type: 7,
                compress_type: 2,
                user_flags: 0,
                indirect_shift: emb_dn.indirect_shift(),
                data_bytes: bsize,
                max_block: (dirty.len() - 1) as u64,
                slots: 1,
                nblkptr: emb_dn.pointers().len(),
                bonus: emb_dn.bonus().to_vec(),
                spill: None,
                order,
                new_txg,
                leaf_bucket: WriteBucket::DatasetMetadata,
                indirect_bucket: WriteBucket::DatasetMetadata,
            },
            &dirty,
            staged_writes,
        )?;
        born_out.add_assign(out.born)?;
        retired_out.extend(out.retired_bps);
        os.set_embedded_dnode(slot_offset, Some(&out.dnode))
            .map_err(|e| parse_err(&e))?;
    }
    Ok(())
}

fn read_embedded_zap_entries(
    cx: &Cx,
    os_view: &mut Objects,
    emb_dn: &Dnode,
    ceiling: u64,
) -> Result<Vec<RawZapEntry>> {
    let Some((blk0, blk_order, _)) = os_view.object_data_block(cx, emb_dn, ceiling, 0)? else {
        return Ok(Vec::new());
    };
    let tag = blk_order.u64(&blk0, 0).map_err(|e| parse_err(&e))?;
    if tag == ffs_ondisk::zfs_zap::MICRO_TAG {
        let rows = microzap(&blk0, blk_order).map_err(|e| parse_err(&e))?;
        return Ok(rows
            .into_iter()
            .map(|r| RawZapEntry {
                name: r.name,
                integer_bytes: 8,
                values: vec![r.value],
                collision: r.collision,
            })
            .collect());
    }
    if tag != FAT_TAG {
        return Err(corrupt("embedded quota dnode is not a ZAP"));
    }
    let fh = FatHeader::parse(&blk0, blk_order, emb_dn.max_block()).map_err(|e| parse_err(&e))?;
    let table = if fh.table_blocks().is_empty() {
        fh.embedded_table(&blk0, blk_order)
            .map_err(|e| parse_err(&e))?
    } else {
        let mut t = Vec::with_capacity(fh.table_len());
        for bid in fh.table_blocks() {
            let (b, bo, _) = os_view
                .object_data_block(cx, emb_dn, ceiling, bid)?
                .ok_or_else(|| corrupt("missing fatzap table block in embedded dnode"))?;
            t.extend(fh.table_block(&b, bo).map_err(|e| parse_err(&e))?);
        }
        t
    };
    let routes = fh
        .routes(&table, emb_dn.max_block())
        .map_err(|e| parse_err(&e))?;
    let mut out = Vec::with_capacity(fh.entry_count());
    for route in routes {
        let (lb, lo, _) = os_view
            .object_data_block(cx, emb_dn, ceiling, route.block)?
            .ok_or_else(|| corrupt("missing fatzap leaf block in embedded dnode"))?;
        out.extend(fh.leaf(&lb, lo, route).map_err(|e| parse_err(&e))?);
    }
    Ok(out)
}

/// Allocate a free object ID (`>= 1`) in a dnode table (`os_meta_dnode`), loading or
/// extending `meta_dirty_blocks` (`16 KiB` `DMU_OT_DNODE` blocks).
pub(super) fn allocate_object_id(
    cx: &Cx,
    view: &mut Objects,
    meta_dnode: &Dnode,
    meta_ceiling: u64,
    meta_dirty_blocks: &mut BTreeMap<u64, Vec<u8>>,
    slots_needed: usize,
) -> Result<u64> {
    let slots_per_block = DNODE_BLOCK_BYTES / DNODE_BYTES;
    let max_existing = meta_dnode
        .max_block()
        .max(meta_dirty_blocks.keys().copied().max().unwrap_or(0));
    for block_id in 0..=max_existing {
        checkpoint(cx)?;
        ensure_dnode_table_block_loaded(
            cx,
            view,
            meta_dnode,
            meta_ceiling,
            block_id,
            meta_dirty_blocks,
        )?;
        let blk = meta_dirty_blocks
            .get(&block_id)
            .ok_or_else(|| corrupt("missing loaded dnode table block"))?;
        let min_slot = usize::from(block_id == 0);
        if let Some(slot) =
            find_free_dnode_slot(blk, slots_needed, min_slot).map_err(|e| parse_err(&e))?
        {
            return Ok(block_id * (slots_per_block as u64) + (slot as u64));
        }
    }
    let next_block_id = max_existing + 1;
    meta_dirty_blocks.insert(next_block_id, vec![0_u8; DNODE_BLOCK_BYTES]);
    let min_slot = usize::from(next_block_id == 0);
    Ok(next_block_id * (slots_per_block as u64) + (min_slot as u64))
}

pub(super) fn ensure_dnode_table_block_loaded(
    cx: &Cx,
    view: &mut Objects,
    meta_dnode: &Dnode,
    meta_ceiling: u64,
    block_id: u64,
    meta_dirty_blocks: &mut BTreeMap<u64, Vec<u8>>,
) -> Result<()> {
    if meta_dirty_blocks.contains_key(&block_id) {
        return Ok(());
    }
    let raw = if block_id <= meta_dnode.max_block()
        && let Some((bytes, _, _)) =
            view.object_data_block(cx, meta_dnode, meta_ceiling, block_id)?
    {
        bytes.as_ref().clone()
    } else {
        vec![0_u8; DNODE_BLOCK_BYTES]
    };
    meta_dirty_blocks.insert(block_id, raw);
    Ok(())
}

pub(super) fn read_staged_or_committed_dnode(
    cx: &Cx,
    view: &mut Objects,
    _meta_dnode: &Dnode,
    meta_ceiling: u64,
    meta_dirty_blocks: &BTreeMap<u64, Vec<u8>>,
    object_id: u64,
    order: Endian,
) -> Result<(Dnode, u64)> {
    let slots_per_block = (DNODE_BLOCK_BYTES / DNODE_BYTES) as u64;
    let block_id = object_id / slots_per_block;
    let slot = (object_id % slots_per_block) as usize;
    if let Some(blk) = meta_dirty_blocks.get(&block_id) {
        let dn = dnode_at(blk, slot, order)
            .map_err(|e| parse_err(&e))?
            .ok_or_else(|| FfsError::NotFound(format!("ZFS object {object_id} unallocated")))?;
        return Ok((dn, meta_ceiling));
    }
    view.object_with_ceiling(cx, object_id)
}

pub(super) fn put_dnode_in_table(
    cx: &Cx,
    view: &mut Objects,
    meta_dnode: &Dnode,
    meta_ceiling: u64,
    meta_dirty_blocks: &mut BTreeMap<u64, Vec<u8>>,
    object_id: u64,
    dnode: &Dnode,
) -> Result<()> {
    let slots_per_block = (DNODE_BLOCK_BYTES / DNODE_BYTES) as u64;
    let block_id = object_id / slots_per_block;
    let slot = (object_id % slots_per_block) as usize;
    ensure_dnode_table_block_loaded(
        cx,
        view,
        meta_dnode,
        meta_ceiling,
        block_id,
        meta_dirty_blocks,
    )?;
    let blk = meta_dirty_blocks
        .get_mut(&block_id)
        .ok_or_else(|| corrupt("missing dnode table block"))?;
    write_dnode_at(blk, slot, dnode).map_err(|e| parse_err(&e))
}

pub(super) fn remove_dnode_from_table(
    cx: &Cx,
    view: &mut Objects,
    meta_dnode: &Dnode,
    meta_ceiling: u64,
    meta_dirty_blocks: &mut BTreeMap<u64, Vec<u8>>,
    object_id: u64,
    order: Endian,
) -> Result<()> {
    let slots_per_block = (DNODE_BLOCK_BYTES / DNODE_BYTES) as u64;
    let block_id = object_id / slots_per_block;
    let slot = (object_id % slots_per_block) as usize;
    ensure_dnode_table_block_loaded(
        cx,
        view,
        meta_dnode,
        meta_ceiling,
        block_id,
        meta_dirty_blocks,
    )?;
    let blk = meta_dirty_blocks
        .get_mut(&block_id)
        .ok_or_else(|| corrupt("missing dnode table block"))?;
    clear_dnode_at(blk, slot, order).map_err(|e| parse_err(&e))
}

/// Append snapshot-retained `BlockPointer`s (`birth <= ds_prev_snap_txg`) to `ds_deadlist_obj`
/// (`DMU_OT_BPOBJ = 5` old-format deadlist OR `DMU_OT_DEADLIST = 42` modern ZAP deadlist).
#[allow(clippy::too_many_arguments)]
pub(super) fn enqueue_into_dataset_deadlist(
    cx: &Cx,
    mos: &mut Objects,
    mos_dirty_dnode_blocks: &mut BTreeMap<u64, Vec<u8>>,
    write_features: &mut BTreeMap<String, u64>,
    write_features_dirty: &mut bool,
    empty_bpobj_id: Option<u64>,
    deadlist_obj: u64,
    bps: &[BlockPointer],
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<()> {
    if bps.is_empty() {
        return Ok(());
    }
    if deadlist_obj == 0 {
        return Err(corrupt(
            "snapshotted dataset has zero ds_deadlist_obj when retiring shared blocks",
        ));
    }
    let mos_meta = mos.meta_dnode().clone();
    let mos_ceiling = mos.root_birth_txg();
    let (dl_dn, dl_ceiling) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnode_blocks,
        deadlist_obj,
        order,
    )?;
    match dl_dn.object_type() {
        DMU_OT_BPOBJ => {
            append_bps_to_bpobj(
                cx,
                mos,
                &mos_meta,
                mos_ceiling,
                mos_dirty_dnode_blocks,
                deadlist_obj,
                &dl_dn,
                dl_ceiling,
                bps,
                alloc,
                order,
                new_txg,
                staged_writes,
            )?;
            Ok(())
        }
        DMU_OT_DEADLIST => {
            if dl_dn.bonus_type() != DMU_OT_DEADLIST_HDR || dl_dn.bonus().len() < 24 {
                return Err(unsupported("unsupported dsl_deadlist bonus layout"));
            }
            let mut entries = mos.zap_values(cx, deadlist_obj)?;
            // Map mintxg -> index in `entries`
            let mut mintxg_rows: Vec<(u64, usize)> = Vec::with_capacity(entries.len());
            for (idx, row) in entries.iter().enumerate() {
                let s = std::str::from_utf8(&row.name)
                    .map_err(|_| corrupt("non-UTF8 mintxg key in dsl_deadlist"))?;
                let mintxg = u64::from_str_radix(s, 16)
                    .map_err(|_| corrupt("invalid hex mintxg key in dsl_deadlist"))?;
                mintxg_rows.push((mintxg, idx));
            }
            mintxg_rows.sort_unstable_by_key(|(txg, _)| *txg);

            // Group retired bps by greatest `mintxg < bp.birth()`.
            let mut by_row: BTreeMap<usize, Vec<BlockPointer>> = BTreeMap::new();
            let mut total_delta = SpaceDelta::default();
            for bp in bps {
                total_delta.add_assign(SpaceDelta::from_bp(bp)?)?;
                let birth = bp.birth();
                let &(_, row_idx) = mintxg_rows
                    .iter()
                    .rfind(|(mintxg, _)| *mintxg < birth)
                    .ok_or_else(|| corrupt("dsl_deadlist has no mintxg range < killed bp birth"))?;
                by_row.entry(row_idx).or_default().push(bp.clone());
            }

            let mut zap_modified = false;
            let min_blk = (1_usize << alloc.ashift).max(512);
            for (row_idx, group_bps) in by_row {
                let mut bpobj_id = entries[row_idx].scalar().map_err(|e| parse_err(&e))?;
                let (bpobj_dn, bpobj_ceiling, is_new) = if Some(bpobj_id) == empty_bpobj_id {
                    // Materialize a real `DMU_OT_BPOBJ` and decrement `com.delphix:empty_bpobj`.
                    let new_id = allocate_object_id(
                        cx,
                        mos,
                        &mos_meta,
                        mos_ceiling,
                        mos_dirty_dnode_blocks,
                        1,
                    )?;
                    if let Some(cnt) = write_features.get_mut("com.delphix:empty_bpobj") {
                        *cnt = cnt
                            .checked_sub(1)
                            .ok_or_else(|| corrupt("empty_bpobj feature refcount underflow"))?;
                        *write_features_dirty = true;
                    }
                    entries[row_idx].values = vec![new_id];
                    zap_modified = true;
                    bpobj_id = new_id;
                    let empty_dn = Dnode::from_spec(DnodeSpec {
                        object_type: DMU_OT_BPOBJ,
                        bonus_type: DMU_OT_BPOBJ_HDR,
                        checksum_type: 0,
                        compress_type: 0,
                        flags: DNODE_FLAG_USED_BYTES,
                        order,
                        levels: 1,
                        indirect_shift: 17,
                        data_bytes: min_blk,
                        max_block: 0,
                        used_bytes: 0,
                        slots: 1,
                        pointers: vec![
                            BlockPointer::hole_pointer(),
                            BlockPointer::hole_pointer(),
                            BlockPointer::hole_pointer(),
                        ],
                        bonus: vec![0_u8; 48],
                        spill: None,
                    })
                    .map_err(|e| parse_err(&e))?;
                    (empty_dn, new_txg, true)
                } else {
                    let (dn, c) = read_staged_or_committed_dnode(
                        cx,
                        mos,
                        &mos_meta,
                        mos_ceiling,
                        mos_dirty_dnode_blocks,
                        bpobj_id,
                        order,
                    )?;
                    (dn, c, false)
                };
                append_bps_to_bpobj_inner(
                    cx,
                    mos,
                    &mos_meta,
                    mos_ceiling,
                    mos_dirty_dnode_blocks,
                    bpobj_id,
                    if is_new {
                        None
                    } else {
                        Some((&bpobj_dn, bpobj_ceiling))
                    },
                    &bpobj_dn,
                    &group_bps,
                    alloc,
                    order,
                    new_txg,
                    staged_writes,
                )?;
            }

            // Update `dsl_deadlist_phys_t` bonus (`dl_used`, `dl_comp`, `dl_uncomp`) + ZAP if needed.
            let mut dl_bonus = dl_dn.bonus().to_vec();
            let dl_used = order
                .u64(&dl_bonus, 0)
                .map_err(|e| parse_err(&e))?
                .checked_add(total_delta.dsize)
                .ok_or_else(|| corrupt("dl_used overflow"))?;
            let dl_comp = order
                .u64(&dl_bonus, 8)
                .map_err(|e| parse_err(&e))?
                .checked_add(total_delta.comp)
                .ok_or_else(|| corrupt("dl_comp overflow"))?;
            let dl_uncomp = order
                .u64(&dl_bonus, 16)
                .map_err(|e| parse_err(&e))?
                .checked_add(total_delta.uncomp)
                .ok_or_else(|| corrupt("dl_uncomp overflow"))?;
            dl_bonus[0..8].copy_from_slice(&order.encode(dl_used));
            dl_bonus[8..16].copy_from_slice(&order.encode(dl_comp));
            dl_bonus[16..24].copy_from_slice(&order.encode(dl_uncomp));

            let updated_dl_dn = if zap_modified {
                let (bsize, blocks) = encode_zap_blocks_for_dnode(
                    cx,
                    mos,
                    Some((&dl_dn, dl_ceiling)),
                    &entries,
                    order,
                    min_blk,
                )?;
                let mut dirty = BTreeMap::new();
                for (i, blk) in blocks.into_iter().enumerate() {
                    dirty.insert(i as u64, Some(blk));
                }
                let out = cow_update_dnode(
                    cx,
                    mos,
                    alloc,
                    DnodeCowSpec {
                        existing: Some((&dl_dn, dl_ceiling)),
                        object_type: dl_dn.object_type(),
                        bonus_type: dl_dn.bonus_type(),
                        checksum_type: 7,
                        compress_type: 2,
                        user_flags: 0,
                        indirect_shift: dl_dn.indirect_shift(),
                        data_bytes: bsize,
                        max_block: (dirty.len() - 1) as u64,
                        slots: dl_dn.slots(),
                        nblkptr: dl_dn.pointers().len(),
                        bonus: dl_bonus,
                        spill: None,
                        order,
                        new_txg,
                        leaf_bucket: WriteBucket::ChildBlocks,
                        indirect_bucket: WriteBucket::ChildBlocks,
                    },
                    &dirty,
                    staged_writes,
                )?;
                for rbp in &out.retired_bps {
                    alloc.free_block_dvas(rbp, new_txg)?;
                }
                out.dnode
            } else {
                let mut copy = dl_dn.clone();
                let dl_btype = copy.bonus_type();
                copy.set_bonus_and_spill(dl_btype, dl_bonus, None)
                    .map_err(|e| parse_err(&e))?;
                copy
            };
            put_dnode_in_table(
                cx,
                mos,
                &mos_meta,
                mos_ceiling,
                mos_dirty_dnode_blocks,
                deadlist_obj,
                &updated_dl_dn,
            )
        }
        other => Err(unsupported(format!(
            "unsupported ZFS deadlist object type {other}"
        ))),
    }
}

#[allow(clippy::too_many_arguments)]
fn append_bps_to_bpobj(
    cx: &Cx,
    mos: &mut Objects,
    mos_meta: &Dnode,
    mos_ceiling: u64,
    mos_dirty_dnode_blocks: &mut BTreeMap<u64, Vec<u8>>,
    bpobj_id: u64,
    bpobj_dn: &Dnode,
    bpobj_ceiling: u64,
    bps: &[BlockPointer],
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<()> {
    append_bps_to_bpobj_inner(
        cx,
        mos,
        mos_meta,
        mos_ceiling,
        mos_dirty_dnode_blocks,
        bpobj_id,
        Some((bpobj_dn, bpobj_ceiling)),
        bpobj_dn,
        bps,
        alloc,
        order,
        new_txg,
        staged_writes,
    )
}

#[allow(clippy::too_many_arguments)]
fn append_bps_to_bpobj_inner(
    cx: &Cx,
    mos: &mut Objects,
    mos_meta: &Dnode,
    mos_ceiling: u64,
    mos_dirty_dnode_blocks: &mut BTreeMap<u64, Vec<u8>>,
    bpobj_id: u64,
    existing: Option<(&Dnode, u64)>,
    template_dn: &Dnode,
    bps: &[BlockPointer],
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<()> {
    if template_dn.bonus_type() != DMU_OT_BPOBJ_HDR || template_dn.bonus().len() < 16 {
        return Err(corrupt("invalid bpobj header bonus"));
    }
    let old_count = order
        .u64(template_dn.bonus(), 0)
        .map_err(|e| parse_err(&e))?;
    let old_byte_len = usize::try_from(
        old_count
            .checked_mul(128)
            .ok_or_else(|| corrupt("bpobj byte length overflow"))?,
    )
    .map_err(|_| unsupported("bpobj exceeds usize"))?;

    let mut stream = if let Some((dn, c)) = existing {
        read_dnode_prefix(cx, mos, dn, c, old_byte_len)?
    } else {
        Vec::new()
    };
    let mut delta = SpaceDelta::default();
    for bp in bps {
        delta.add_assign(SpaceDelta::from_bp(bp)?)?;
        stream.extend_from_slice(&bp.encode(order));
    }

    let min_blk = (1_usize << alloc.ashift).max(512);
    let data_bytes = if existing.is_some_and(|(dn, _)| dn.max_block() > 0)
        || stream.len() > BPOBJ_MAX_BLOCK_BYTES
    {
        existing
            .filter(|(dn, _)| dn.max_block() > 0)
            .map_or(BPOBJ_MAX_BLOCK_BYTES, |(dn, _)| dn.data_bytes())
    } else {
        stream
            .len()
            .max(min_blk)
            .next_multiple_of(min_blk)
            .min(BPOBJ_MAX_BLOCK_BYTES)
    };
    let num_blocks = stream.len().div_ceil(data_bytes).max(1);
    let first_dirty_block = if existing.is_some_and(|(dn, _)| dn.data_bytes() == data_bytes) {
        old_byte_len / data_bytes
    } else {
        0
    };
    let mut dirty = BTreeMap::new();
    for bid in first_dirty_block..num_blocks {
        let s = bid * data_bytes;
        let e = (s + data_bytes).min(stream.len());
        let mut blk = vec![0_u8; data_bytes];
        if s < e {
            blk[..e - s].copy_from_slice(&stream[s..e]);
        }
        dirty.insert(bid as u64, Some(blk));
    }

    let mut bonus = template_dn.bonus().to_vec();
    let new_count = old_count + (bps.len() as u64);
    let new_bytes = order
        .u64(&bonus, 8)
        .map_err(|e| parse_err(&e))?
        .checked_add(delta.dsize)
        .ok_or_else(|| corrupt("bpo_bytes overflow"))?;
    bonus[0..8].copy_from_slice(&order.encode(new_count));
    bonus[8..16].copy_from_slice(&order.encode(new_bytes));
    if bonus.len() >= 32 {
        let new_comp = order
            .u64(&bonus, 16)
            .map_err(|e| parse_err(&e))?
            .checked_add(delta.comp)
            .ok_or_else(|| corrupt("bpo_comp overflow"))?;
        let new_uncomp = order
            .u64(&bonus, 24)
            .map_err(|e| parse_err(&e))?
            .checked_add(delta.uncomp)
            .ok_or_else(|| corrupt("bpo_uncomp overflow"))?;
        bonus[16..24].copy_from_slice(&order.encode(new_comp));
        bonus[24..32].copy_from_slice(&order.encode(new_uncomp));
    }

    let out = cow_update_dnode(
        cx,
        mos,
        alloc,
        DnodeCowSpec {
            existing,
            object_type: DMU_OT_BPOBJ,
            bonus_type: DMU_OT_BPOBJ_HDR,
            checksum_type: 7,
            compress_type: 2,
            user_flags: 0,
            indirect_shift: template_dn.indirect_shift(),
            data_bytes,
            max_block: (num_blocks - 1) as u64,
            slots: template_dn.slots(),
            nblkptr: template_dn.pointers().len(),
            bonus,
            spill: None,
            order,
            new_txg,
            leaf_bucket: WriteBucket::ChildBlocks,
            indirect_bucket: WriteBucket::ChildBlocks,
        },
        &dirty,
        staged_writes,
    )?;
    for rbp in &out.retired_bps {
        alloc.free_block_dvas(rbp, new_txg)?;
    }
    put_dnode_in_table(
        cx,
        mos,
        mos_meta,
        mos_ceiling,
        mos_dirty_dnode_blocks,
        bpobj_id,
        &out.dnode,
    )
}

/// Converge MOS space-map objects, MOS `features_for_write`, `metaslab_array` (if any
/// uninitialized metaslab was first touched), MOS dnode table, MOS indirects, and the
/// MOS `ObjectSet` root block to an exact fixed point where every physical block in the
/// pool matches the committed space-map streams and 32-bucket histograms to the sector.
#[allow(clippy::too_many_arguments)]
pub(super) fn finalize_mos_and_space_maps_to_convergence(
    cx: &Cx,
    mos: &mut Objects,
    mos_os_template: &ObjectSet,
    old_mos_root_bp: &BlockPointer,
    base_mos_dirty_dnode_blocks: &BTreeMap<u64, Vec<u8>>,
    base_write_features: &BTreeMap<String, u64>,
    base_write_features_dirty: bool,
    write_features_obj: Option<u64>,
    base_alloc: &PoolSpaceAllocator,
    base_staged_writes: &[StagedBlockWrite],
    order: Endian,
    new_txg: u64,
) -> Result<(BlockPointer, PoolSpaceAllocator, Vec<StagedBlockWrite>)> {
    checkpoint(cx)?;
    let mos_meta = mos.meta_dnode().clone();
    let mos_ceiling = mos.root_birth_txg();
    let min_blk = (1_usize << base_alloc.ashift).max(512);

    // Pre-retire the previous MOS ObjectSet root block into `work_base_alloc` once!
    let mut work_base_alloc = base_alloc.clone();
    work_base_alloc.free_block_dvas(old_mos_root_bp, new_txg)?;

    // Track planned `(data_bytes, first_dirty_block, num_blocks)` per metaslab ID across passes.
    let mut planned_sm: BTreeMap<usize, (usize, usize, usize)> = BTreeMap::new();
    for ms in &work_base_alloc.metaslabs {
        if ms.is_dirty() {
            let prelim = ms.build_full_stream(new_txg, order, work_base_alloc.spacemap_v2_active)?;
            let plan = plan_spacemap_blocks(cx, mos, ms.object, &prelim, min_blk)?;
            planned_sm.insert(ms.id, plan);
        }
    }

    for _iter in 0..8 {
        checkpoint(cx)?;
        let mut alloc = work_base_alloc.clone();
        let mut mos_dirty_dnodes = base_mos_dirty_dnode_blocks.clone();
        let mut write_features = base_write_features.clone();
        let mut wf_dirty = base_write_features_dirty;
        let mut staged = base_staged_writes.to_vec();

        // 1. Ensure every dirty metaslab in `planned_sm` has an allocated `sm_obj` ID
        // (and update `metaslab_array` + `spacemap_histogram` refcount if newly initialized).
        let mut ms_array_modified = false;
        let dirty_ms_ids: Vec<usize> = planned_sm.keys().copied().collect();
        for &ms_id in &dirty_ms_ids {
            if alloc.metaslabs[ms_id].object == 0 {
                let new_sm_obj = allocate_object_id(
                    cx,
                    mos,
                    &mos_meta,
                    mos_ceiling,
                    &mut mos_dirty_dnodes,
                    1,
                )?;
                alloc.metaslabs[ms_id].object = new_sm_obj;
                alloc.metaslabs[ms_id].preserved_smp_object = new_sm_obj;
                if alloc.spacemap_histogram_present {
                    alloc.metaslabs[ms_id].bonus_len = 320;
                    if let Some(cnt) = write_features.get_mut("com.delphix:spacemap_histogram") {
                        *cnt = cnt
                            .checked_add(1)
                            .ok_or_else(|| corrupt("spacemap_histogram refcount overflow"))?;
                        wf_dirty = true;
                    }
                } else {
                    alloc.metaslabs[ms_id].bonus_len = 24;
                }
                ms_array_modified = true;
            }
        }
        if alloc.spacemap_v2_present && !alloc.spacemap_v2_active && !dirty_ms_ids.is_empty() {
            // Note: we encode universal 1-word records (`extent_records_for_range` with `None`
            // vdev splits at 32,768 units), so `spacemap_v2` never needs activation unless
            // already active! Preserving `spacemap_v2` refcount untouched avoids needless drift.
        }

        if ms_array_modified {
            let (arr_dn, arr_ceiling) = mos.object_with_ceiling(cx, alloc.metaslab_array_obj)?;
            let total_bytes = alloc.metaslabs.len() * 8;
            let bsize = if arr_dn.max_block() > 0 || total_bytes > FATZAP_BLOCK_BYTES {
                arr_dn.data_bytes()
            } else {
                total_bytes
                    .max(min_blk)
                    .next_multiple_of(min_blk)
                    .min(FATZAP_BLOCK_BYTES)
            };
            let nblocks = total_bytes.div_ceil(bsize).max(1);
            let mut raw = vec![0_u8; nblocks * bsize];
            for (idx, ms) in alloc.metaslabs.iter().enumerate() {
                raw[idx * 8..(idx + 1) * 8].copy_from_slice(&order.encode(ms.object));
            }
            let mut dirty = BTreeMap::new();
            for bid in 0..nblocks {
                dirty.insert(
                    bid as u64,
                    Some(raw[bid * bsize..(bid + 1) * bsize].to_vec()),
                );
            }
            let out = cow_update_dnode(
                cx,
                mos,
                &mut alloc,
                DnodeCowSpec {
                    existing: Some((&arr_dn, arr_ceiling)),
                    object_type: DMU_OT_OBJECT_ARRAY,
                    bonus_type: 0,
                    checksum_type: 7,
                    compress_type: 2,
                    user_flags: 0,
                    indirect_shift: arr_dn.indirect_shift(),
                    data_bytes: bsize,
                    max_block: (nblocks - 1) as u64,
                    slots: 1,
                    nblkptr: arr_dn.pointers().len(),
                    bonus: Vec::new(),
                    spill: None,
                    order,
                    new_txg,
                    leaf_bucket: WriteBucket::MosSpaceMap,
                    indirect_bucket: WriteBucket::MosSpaceMap,
                },
                &dirty,
                &mut staged,
            )?;
            for rbp in &out.retired_bps {
                alloc.free_block_dvas(rbp, new_txg)?;
            }
            put_dnode_in_table(
                cx,
                mos,
                &mos_meta,
                mos_ceiling,
                &mut mos_dirty_dnodes,
                alloc.metaslab_array_obj,
                &out.dnode,
            )?;
        }

        if wf_dirty && let Some(wf_obj) = write_features_obj {
            let (wf_dn, wf_ceiling) = mos.object_with_ceiling(cx, wf_obj)?;
            let wf_entries: Vec<RawZapEntry> = write_features
                .iter()
                .map(|(k, &v)| RawZapEntry {
                    name: k.as_bytes().to_vec(),
                    integer_bytes: 8,
                    values: vec![v],
                    collision: 0,
                })
                .collect();
            let (bsize, blocks) = encode_zap_blocks_for_dnode(
                cx,
                mos,
                Some((&wf_dn, wf_ceiling)),
                &wf_entries,
                order,
                min_blk,
            )?;
            let mut dirty = BTreeMap::new();
            for (i, b) in blocks.into_iter().enumerate() {
                dirty.insert(i as u64, Some(b));
            }
            let out = cow_update_dnode(
                cx,
                mos,
                &mut alloc,
                DnodeCowSpec {
                    existing: Some((&wf_dn, wf_ceiling)),
                    object_type: wf_dn.object_type(),
                    bonus_type: wf_dn.bonus_type(),
                    checksum_type: 7,
                    compress_type: 2,
                    user_flags: 0,
                    indirect_shift: wf_dn.indirect_shift(),
                    data_bytes: bsize,
                    max_block: (dirty.len() - 1) as u64,
                    slots: wf_dn.slots(),
                    nblkptr: wf_dn.pointers().len(),
                    bonus: wf_dn.bonus().to_vec(),
                    spill: None,
                    order,
                    new_txg,
                    leaf_bucket: WriteBucket::MosSpaceMap,
                    indirect_bucket: WriteBucket::MosSpaceMap,
                },
                &dirty,
                &mut staged,
            )?;
            for rbp in &out.retired_bps {
                alloc.free_block_dvas(rbp, new_txg)?;
            }
            put_dnode_in_table(
                cx,
                mos,
                &mos_meta,
                mos_ceiling,
                &mut mos_dirty_dnodes,
                wf_obj,
                &out.dnode,
            )?;
        }

        // 2. Touch dnode table blocks for all `planned_sm` `sm_obj`s so `mos_dirty_dnodes`
        // has the exact set of dirty MOS dnode table blocks before we reserve DVAs!
        for &ms_id in &dirty_ms_ids {
            let sm_obj = alloc.metaslabs[ms_id].object;
            let block_id = sm_obj / ((DNODE_BLOCK_BYTES / DNODE_BYTES) as u64);
            ensure_dnode_table_block_loaded(
                cx,
                mos,
                &mos_meta,
                mos_ceiling,
                block_id,
                &mut mos_dirty_dnodes,
            )?;
        }

        // 3. Reserve DVAs for every planned space-map leaf/indirect block, every dirty MOS
        // dnode table block + MOS indirects, and the MOS `ObjectSet` root block, and retire
        // all replaced committed blocks so `alloc` reaches its COMPLETE end-of-TXG state!
        let mut sm_placeholders: BTreeMap<usize, Vec<(u64, usize)>> = BTreeMap::new();
        for (&ms_id, &(bsize, first_dirty, num_blocks)) in &planned_sm {
            let sm_obj = alloc.metaslabs[ms_id].object;
            let existing = if base_alloc.metaslabs[ms_id].object != 0 {
                Some(mos.object_with_ceiling(cx, sm_obj)?)
            } else {
                None
            };
            let mut dummy_dirty = BTreeMap::new();
            for bid in first_dirty..num_blocks {
                dummy_dirty.insert(bid as u64, Some(vec![0_u8; bsize]));
            }
            let start_idx = staged.len();
            let bonus_len = alloc.metaslabs[ms_id].bonus_len;
            let nblkptr = existing
                .as_ref()
                .map_or(if bonus_len <= 64 { 3 } else { 1 }, |(dn, _)| {
                    dn.pointers().len()
                });
            let ind_shift = existing.as_ref().map_or(14, |(dn, _)| dn.indirect_shift());
            let out = cow_update_dnode(
                cx,
                mos,
                &mut alloc,
                DnodeCowSpec {
                    existing: existing.as_ref().map(|(dn, c)| (dn, *c)),
                    object_type: DMU_OT_SPACE_MAP,
                    bonus_type: DMU_OT_SPACE_MAP_HEADER,
                    checksum_type: 7,
                    compress_type: 2,
                    user_flags: 0,
                    indirect_shift: ind_shift,
                    data_bytes: bsize,
                    max_block: (num_blocks - 1) as u64,
                    slots: 1,
                    nblkptr,
                    bonus: vec![0_u8; bonus_len],
                    spill: None,
                    order,
                    new_txg,
                    leaf_bucket: WriteBucket::MosSpaceMap,
                    indirect_bucket: WriteBucket::MosSpaceMap,
                },
                &dummy_dirty,
                &mut staged,
            )?;
            for rbp in &out.retired_bps {
                alloc.free_block_dvas(rbp, new_txg)?;
            }
            // Record staged indices of leaf blocks `(first_dirty..num_blocks)` so we can
            // rebuild exact bytes + checksums once the space-map stream is finalized!
            let mut leaf_slots = Vec::with_capacity(num_blocks - first_dirty);
            for (offset_idx, bid) in (first_dirty..num_blocks).enumerate() {
                leaf_slots.push((bid as u64, start_idx + offset_idx));
            }
            // Remove any indirect staged writes past leaf_slots; we'll re-encode `sm_obj`
            // using the exact pre-allocated DVAs once stream bytes are built!
            let _ = leaf_slots;
            sm_placeholders.insert(
                ms_id,
                staged[start_idx..]
                    .iter()
                    .map(|w| (w.dva_offset, w.bytes.len()))
                    .collect(),
            );
            staged.truncate(start_idx);
        }

        // Reserve DVAs for MOS `os_meta_dnode` (dirty dnode blocks + indirects) + MOS `ObjectSet`.
        let mos_max_block = mos_meta
            .max_block()
            .max(mos_dirty_dnodes.keys().copied().max().unwrap_or(0));
        let mut dummy_meta_dirty = BTreeMap::new();
        for &bid in mos_dirty_dnodes.keys() {
            dummy_meta_dirty.insert(bid, Some(vec![0_u8; DNODE_BLOCK_BYTES]));
        }
        let meta_start_idx = staged.len();
        let dummy_meta_out = cow_update_dnode(
            cx,
            mos,
            &mut alloc,
            DnodeCowSpec {
                existing: Some((&mos_meta, mos_ceiling)),
                object_type: DMU_OT_DNODE,
                bonus_type: 0,
                checksum_type: 7,
                compress_type: 2,
                user_flags: 0,
                indirect_shift: mos_meta.indirect_shift(),
                data_bytes: DNODE_BLOCK_BYTES,
                max_block: mos_max_block,
                slots: 1,
                nblkptr: 3,
                bonus: Vec::new(),
                spill: None,
                order,
                new_txg,
                leaf_bucket: WriteBucket::MosSpaceMap,
                indirect_bucket: WriteBucket::MosSpaceMap,
            },
            &dummy_meta_dirty,
            &mut staged,
        )?;
        for rbp in &dummy_meta_out.retired_bps {
            alloc.free_block_dvas(rbp, new_txg)?;
        }
        let meta_reserved_dvas: Vec<(u64, usize)> = staged[meta_start_idx..]
            .iter()
            .map(|w| (w.dva_offset, w.bytes.len()))
            .collect();
        staged.truncate(meta_start_idx);

        let mos_root_bytes_len = mos_os_template.physical_bytes();
        let mos_root_dva = alloc.allocate(mos_root_bytes_len)?;

        // 4. Check convergence! Does every dirty metaslab's actual stream plan match `planned_sm`?
        let mut next_planned: BTreeMap<usize, (usize, usize, usize)> = BTreeMap::new();
        for ms in &alloc.metaslabs {
            if ms.is_dirty() {
                let stream = ms.build_full_stream(new_txg, order, alloc.spacemap_v2_active)?;
                let base_obj = base_alloc.metaslabs[ms.id].object;
                let plan = plan_spacemap_blocks(cx, mos, base_obj, &stream, min_blk)?;
                next_planned.insert(ms.id, plan);
            }
        }
        if next_planned != planned_sm {
            planned_sm = next_planned;
            continue;
        }

        // 5. CONVERGED! Replay exact byte encoding into the pre-allocated DVAs (`FixedDvaQueue`)!
        for (&ms_id, &(bsize, first_dirty, num_blocks)) in &planned_sm {
            let sm_obj = alloc.metaslabs[ms_id].object;
            let base_obj = base_alloc.metaslabs[ms_id].object;
            let existing = if base_obj != 0 {
                Some(mos.object_with_ceiling(cx, sm_obj)?)
            } else {
                None
            };
            let stream =
                alloc.metaslabs[ms_id].build_full_stream(new_txg, order, alloc.spacemap_v2_active)?;
            let mut real_dirty = BTreeMap::new();
            for bid in first_dirty..num_blocks {
                let s = bid * bsize;
                let e = (s + bsize).min(stream.len());
                let mut blk = vec![0_u8; bsize];
                if s < e {
                    blk[..e - s].copy_from_slice(&stream[s..e]);
                }
                real_dirty.insert(bid as u64, Some(blk));
            }
            let bonus_len = alloc.metaslabs[ms_id].bonus_len;
            let sm_hdr = SpaceMapHeader {
                length: stream.len() as u64,
                allocated: i64::try_from(alloc.metaslabs[ms_id].final_map.allocated_bytes())
                    .map_err(|_| corrupt("metaslab allocated bytes exceed i64"))?,
                histogram: if bonus_len == 320 {
                    Some(
                        alloc.metaslabs[ms_id]
                            .final_map
                            .free_histogram(alloc.ashift)
                            .map_err(|e| parse_err(&e))?,
                    )
                } else {
                    None
                },
            };
            let sm_bonus = sm_hdr
                .encode(
                    bonus_len,
                    alloc.metaslabs[ms_id].preserved_smp_object,
                    order,
                )
                .map_err(|e| parse_err(&e))?;
            let nblkptr = existing
                .as_ref()
                .map_or(if bonus_len <= 64 { 3 } else { 1 }, |(dn, _)| {
                    dn.pointers().len()
                });
            let ind_shift = existing.as_ref().map_or(14, |(dn, _)| dn.indirect_shift());
            let mut fixed = FixedDvaReplay::new(
                &sm_placeholders[&ms_id],
                alloc.ashift,
                alloc.hole_birth_active,
            );
            let sm_dn = fixed.encode_dnode(
                cx,
                mos,
                DnodeCowSpec {
                    existing: existing.as_ref().map(|(dn, c)| (dn, *c)),
                    object_type: DMU_OT_SPACE_MAP,
                    bonus_type: DMU_OT_SPACE_MAP_HEADER,
                    checksum_type: 7,
                    compress_type: 2,
                    user_flags: 0,
                    indirect_shift: ind_shift,
                    data_bytes: bsize,
                    max_block: (num_blocks - 1) as u64,
                    slots: 1,
                    nblkptr,
                    bonus: sm_bonus,
                    spill: None,
                    order,
                    new_txg,
                    leaf_bucket: WriteBucket::MosSpaceMap,
                    indirect_bucket: WriteBucket::MosSpaceMap,
                },
                &real_dirty,
                &mut staged,
            )?;
            put_dnode_in_table(
                cx,
                mos,
                &mos_meta,
                mos_ceiling,
                &mut mos_dirty_dnodes,
                sm_obj,
                &sm_dn,
            )?;
        }

        // Encode final MOS `os_meta_dnode` into `meta_reserved_dvas`.
        let mut real_meta_dirty = BTreeMap::new();
        for (bid, blk) in mos_dirty_dnodes {
            real_meta_dirty.insert(bid, Some(blk));
        }
        let mut fixed_meta = FixedDvaReplay::new(
            &meta_reserved_dvas,
            alloc.ashift,
            alloc.hole_birth_active,
        );
        let new_mos_meta = fixed_meta.encode_dnode(
            cx,
            mos,
            DnodeCowSpec {
                existing: Some((&mos_meta, mos_ceiling)),
                object_type: DMU_OT_DNODE,
                bonus_type: 0,
                checksum_type: 7,
                compress_type: 2,
                user_flags: 0,
                indirect_shift: mos_meta.indirect_shift(),
                data_bytes: DNODE_BLOCK_BYTES,
                max_block: mos_max_block,
                slots: 1,
                nblkptr: 3,
                bonus: Vec::new(),
                spill: None,
                order,
                new_txg,
                leaf_bucket: WriteBucket::MosSpaceMap,
                indirect_bucket: WriteBucket::MosSpaceMap,
            },
            &real_meta_dirty,
            &mut staged,
        )?;

        let mut new_mos_os = mos_os_template.clone();
        new_mos_os.meta = new_mos_meta;
        let mos_root_bytes = new_mos_os.encode(order).map_err(|e| parse_err(&e))?;
        let mos_fill = new_mos_os.meta_fill();
        let root_cksum = if matches!(old_mos_root_bp.checksum_type(), 6..=8) {
            old_mos_root_bp.checksum_type()
        } else {
            7
        };
        let new_root_bp = BlockPointer::new_regular(&RegularBlockSpec {
            dvas: &[mos_root_dva],
            physical: &mos_root_bytes,
            logical_bytes: mos_root_bytes.len(),
            compression: 2,
            checksum_type: root_cksum,
            object_type: DMU_OT_OBJSET,
            level: 0,
            payload_order: order,
            birth: new_txg,
            fill: mos_fill,
        })
        .map_err(|e| parse_err(&e))?;
        staged.push(StagedBlockWrite {
            bucket: WriteBucket::MosRoot,
            dva_offset: mos_root_dva.offset,
            bytes: mos_root_bytes,
        });

        // Self-audit: verify zero DVA overlap within staged writes!
        verify_disjoint_staged_writes(&staged, alloc.ashift)?;

        return Ok((new_root_bp, alloc, staged));
    }

    Err(corrupt(
        "MOS space-map allocation failed to converge in 8 passes",
    ))
}

fn plan_spacemap_blocks(
    cx: &Cx,
    mos: &mut Objects,
    existing_sm_obj: u64,
    stream: &[u8],
    min_blk: usize,
) -> Result<(usize, usize, usize)> {
    let existing = if existing_sm_obj != 0 {
        Some(mos.object_with_ceiling(cx, existing_sm_obj)?)
    } else {
        None
    };
    let old_len = if let Some((dn, _)) = &existing {
        let hdr = SpaceMapHeader::parse(dn.bonus(), dn.order()).map_err(|e| parse_err(&e))?;
        usize::try_from(hdr.length).map_err(|_| unsupported("space-map stream exceeds usize"))?
    } else {
        0
    };
    let bsize = if existing.as_ref().is_some_and(|(dn, _)| dn.max_block() > 0)
        || stream.len() > SPACE_MAP_BLOCK_BYTES
    {
        existing
            .as_ref()
            .filter(|(dn, _)| dn.max_block() > 0)
            .map_or(SPACE_MAP_BLOCK_BYTES, |(dn, _)| dn.data_bytes())
    } else {
        stream
            .len()
            .max(min_blk)
            .next_multiple_of(min_blk)
            .min(SPACE_MAP_BLOCK_BYTES)
    };
    let num_blocks = stream.len().div_ceil(bsize).max(1);
    let first_dirty = if existing
        .as_ref()
        .is_some_and(|(dn, _)| dn.data_bytes() == bsize)
    {
        (old_len / bsize).min(num_blocks - 1)
    } else {
        0
    };
    Ok((bsize, first_dirty, num_blocks))
}

fn verify_disjoint_staged_writes(staged: &[StagedBlockWrite], ashift: u8) -> Result<()> {
    let sector = 1_u64 << ashift;
    let mut intervals: Vec<(u64, u64)> = staged
        .iter()
        .map(|w| {
            let asize = (w.bytes.len() as u64).div_ceil(sector) * sector;
            (w.dva_offset, w.dva_offset + asize)
        })
        .collect();
    intervals.sort_unstable_by_key(|&(s, _)| s);
    for pair in intervals.windows(2) {
        if pair[0].1 > pair[1].0 {
            return Err(corrupt("internal ZFS TXG staged DVA overlap detected"));
        }
    }
    Ok(())
}

/// Replays pre-reserved DVAs deterministically when encoding finalized space-map and
/// MOS dnode blocks after convergence.
struct FixedDvaReplay<'a> {
    reserved: &'a [(u64, usize)],
    cursor: usize,
    ashift: u8,
    hole_birth_active: bool,
}

impl<'a> FixedDvaReplay<'a> {
    const fn new(reserved: &'a [(u64, usize)], ashift: u8, hole_birth_active: bool) -> Self {
        Self {
            reserved,
            cursor: 0,
            ashift,
            hole_birth_active,
        }
    }

    fn take_dva(&mut self, physical_bytes: usize) -> Result<Dva> {
        let &(offset, expected_len) = self
            .reserved
            .get(self.cursor)
            .ok_or_else(|| corrupt("converged DVA replay exhausted reserved queue"))?;
        self.cursor += 1;
        if expected_len != physical_bytes {
            return Err(corrupt(
                "converged DVA replay physical size disagrees with reservation",
            ));
        }
        let sector = 1_u64 << self.ashift;
        let asize = (physical_bytes as u64).div_ceil(sector) * sector;
        Ok(Dva {
            vdev: 0,
            offset,
            allocated_bytes: asize,
            gang: false,
        })
    }

    fn encode_dnode(
        &mut self,
        cx: &Cx,
        view: &mut Objects,
        spec: DnodeCowSpec<'_>,
        dirty_leaves: &BTreeMap<u64, Option<Vec<u8>>>,
        staged_writes: &mut Vec<StagedBlockWrite>,
    ) -> Result<Dnode> {
        // Build temporary single-metaslab replay wrapper or encode directly using `take_dva`.
        let effective_cksum = if matches!(spec.checksum_type, 6..=8) {
            spec.checksum_type
        } else {
            7
        };
        let indirect_bytes = 1_usize << spec.indirect_shift;
        let fanout = (indirect_bytes / 128) as u64;
        let old_levels = spec.existing.map_or(1_u8, |(n, _)| n.levels());
        let mut levels = old_levels;
        if spec.max_block == 0 && levels > 1 {
            levels = 1;
        } else {
            while u128::from(spec.max_block)
                >= (spec.nblkptr as u128) * (u128::from(fanout)).pow(u32::from(levels - 1))
            {
                levels += 1;
            }
        }

        let mut retired_bps = Vec::new();
        if let Some((old_node, old_ceiling)) = spec.existing
            && spec.max_block < old_node.max_block()
        {
            collect_non_hole_bps_from(
                cx,
                view,
                old_node,
                old_ceiling,
                spec.max_block + 1,
                false,
                &mut retired_bps,
            )?;
        }
        if spec.max_block == 0
            && old_levels > 1
            && let Some((old_node, old_ceiling)) = spec.existing
        {
            let mut all_old = Vec::new();
            collect_non_hole_bps_from(cx, view, old_node, old_ceiling, 0, true, &mut all_old)?;
            for bp in all_old {
                if bp.level() > 0 {
                    retired_bps.push(bp);
                }
            }
        }

        let mut born = SpaceDelta::default();
        let mut current_updates = BTreeMap::new();
        for (&block_id, maybe_bytes) in dirty_leaves {
            if block_id > spec.max_block {
                continue;
            }
            if let Some((old_node, old_ceiling)) = spec.existing
                && let Some((old_bp, _)) =
                    lookup_existing_bp_at_level(cx, view, old_node, old_ceiling, 0, block_id)?
            {
                retired_bps.push(old_bp);
            }
            let new_bp = if let Some(payload) = maybe_bytes {
                let fill = if spec.object_type == DMU_OT_DNODE {
                    count_allocated_dnodes(payload, spec.order).map_err(|e| parse_err(&e))?
                } else {
                    1
                };
                let dva = self.take_dva(payload.len())?;
                let bp = BlockPointer::new_regular(&RegularBlockSpec {
                    dvas: &[dva],
                    physical: payload,
                    logical_bytes: payload.len(),
                    compression: 2,
                    checksum_type: effective_cksum,
                    object_type: spec.object_type,
                    level: 0,
                    payload_order: spec.order,
                    birth: spec.new_txg,
                    fill,
                })
                .map_err(|e| parse_err(&e))?;
                born.add_assign(SpaceDelta::from_bp(&bp)?)?;
                staged_writes.push(StagedBlockWrite {
                    bucket: spec.leaf_bucket,
                    dva_offset: dva.offset,
                    bytes: payload.clone(),
                });
                bp
            } else {
                make_hole_bp(
                    spec.data_bytes,
                    spec.object_type,
                    0,
                    spec.new_txg,
                    self.hole_birth_active,
                )?
            };
            current_updates.insert(block_id, new_bp);
        }

        let mut promoted_seed: BTreeMap<u8, BTreeMap<u64, BlockPointer>> = BTreeMap::new();
        if let Some((old_node, _)) = spec.existing
            && levels > old_levels
        {
            let old_top = old_levels - 1;
            let map = promoted_seed.entry(old_top).or_default();
            for (slot, bp) in old_node.pointers().iter().enumerate() {
                if !bp.hole() {
                    map.insert(slot as u64, bp.clone());
                }
            }
        }
        if let Some(seed) = promoted_seed.remove(&0) {
            for (idx, bp) in seed {
                current_updates.entry(idx).or_insert(bp);
            }
        }

        for parent_level in 1..levels {
            let child_level = parent_level - 1;
            let mut grouped: BTreeMap<u64, Vec<(usize, BlockPointer)>> = BTreeMap::new();
            for (child_idx, child_bp) in current_updates {
                grouped
                    .entry(child_idx / fanout)
                    .or_default()
                    .push(((child_idx % fanout) as usize, child_bp));
            }
            let mut next_updates = BTreeMap::new();
            if let Some(seed) = promoted_seed.remove(&parent_level) {
                for (idx, bp) in seed {
                    next_updates.insert(idx, bp);
                }
            }
            for (parent_idx, children) in grouped {
                let mut raw_block = vec![0_u8; indirect_bytes];
                if let Some((old_node, old_ceiling)) = spec.existing
                    && parent_level < old_levels
                    && let Some((old_ind_bp, ind_ceiling)) = lookup_existing_bp_at_level(
                        cx,
                        view,
                        old_node,
                        old_ceiling,
                        parent_level,
                        parent_idx,
                    )?
                {
                    if let Some((old_bytes, old_order, _)) = view.checked_raw(
                        cx,
                        &old_ind_bp,
                        old_node.object_type(),
                        parent_level,
                        indirect_bytes,
                        ind_ceiling,
                    )? {
                        if old_order == spec.order {
                            raw_block.copy_from_slice(&old_bytes);
                        } else {
                            for (slot, chunk) in old_bytes.as_chunks::<128>().0.iter().enumerate() {
                                let parsed = BlockPointer::parse(chunk, old_order)
                                    .map_err(|e| parse_err(&e))?;
                                raw_block[slot * 128..(slot + 1) * 128]
                                    .copy_from_slice(&parsed.encode(spec.order));
                            }
                        }
                    }
                    retired_bps.push(old_ind_bp);
                }
                let child_span = (u128::from(fanout)).pow(u32::from(child_level));
                for slot in 0..(fanout as usize) {
                    let child_global = (u128::from(parent_idx) * u128::from(fanout) + slot as u128)
                        * child_span;
                    if child_global > u128::from(spec.max_block) {
                        raw_block[slot * 128..(slot + 1) * 128].fill(0);
                    }
                }
                for (slot, child_bp) in children {
                    raw_block[slot * 128..(slot + 1) * 128]
                        .copy_from_slice(&child_bp.encode(spec.order));
                }
                let mut all_holes = true;
                let mut fill_sum = 0_u64;
                for chunk in raw_block.as_chunks::<128>().0 {
                    let parsed =
                        BlockPointer::parse(chunk, spec.order).map_err(|e| parse_err(&e))?;
                    if !parsed.hole() {
                        all_holes = false;
                        fill_sum += pointer_fill_contribution(&parsed);
                    }
                }
                let new_ind_bp = if all_holes {
                    make_hole_bp(
                        indirect_bytes,
                        spec.object_type,
                        parent_level,
                        spec.new_txg,
                        self.hole_birth_active,
                    )?
                } else {
                    let dva = self.take_dva(indirect_bytes)?;
                    let bp = BlockPointer::new_regular(&RegularBlockSpec {
                        dvas: &[dva],
                        physical: &raw_block,
                        logical_bytes: indirect_bytes,
                        compression: 2,
                        checksum_type: effective_cksum,
                        object_type: spec.object_type,
                        level: parent_level,
                        payload_order: spec.order,
                        birth: spec.new_txg,
                        fill: fill_sum,
                    })
                    .map_err(|e| parse_err(&e))?;
                    born.add_assign(SpaceDelta::from_bp(&bp)?)?;
                    staged_writes.push(StagedBlockWrite {
                        bucket: spec.indirect_bucket,
                        dva_offset: dva.offset,
                        bytes: raw_block,
                    });
                    bp
                };
                next_updates.insert(parent_idx, new_ind_bp);
            }
            current_updates = next_updates;
        }

        if self.cursor != self.reserved.len() {
            return Err(corrupt(
                "converged DVA replay did not consume all reserved blocks",
            ));
        }

        let mut root_pointers = vec![BlockPointer::hole_pointer(); spec.nblkptr];
        if let Some((old_node, _)) = spec.existing
            && levels == old_levels
        {
            for (slot, bp) in old_node.pointers().iter().take(spec.nblkptr).enumerate() {
                let root_span = (u128::from(fanout)).pow(u32::from(levels - 1));
                if (slot as u128) * root_span <= u128::from(spec.max_block) {
                    root_pointers[slot] = bp.clone();
                }
            }
        }
        for (slot_u64, bp) in current_updates {
            root_pointers[slot_u64 as usize] = bp;
        }

        let mut retired_dsize = 0_u64;
        for rbp in &retired_bps {
            retired_dsize += SpaceDelta::from_bp(rbp)?.dsize;
        }
        let old_used = spec.existing.map_or(0_u64, |(n, _)| n.used_bytes());
        let used_bytes = old_used
            .checked_add(born.dsize)
            .and_then(|v| v.checked_sub(retired_dsize))
            .ok_or_else(|| corrupt("dnode used_bytes underflow or overflow"))?;

        Dnode::from_spec(DnodeSpec {
            object_type: spec.object_type,
            bonus_type: spec.bonus_type,
            checksum_type: spec.existing.map_or(0, |(n, _)| n.checksum_type()),
            compress_type: spec.compress_type,
            flags: DNODE_FLAG_USED_BYTES,
            order: spec.order,
            levels,
            indirect_shift: spec.indirect_shift,
            data_bytes: spec.data_bytes,
            max_block: spec.max_block,
            used_bytes,
            slots: spec.slots,
            pointers: root_pointers,
            bonus: spec.bonus,
            spill: None,
        })
        .map_err(|e| parse_err(&e))
    }
}

#[allow(dead_code)]
fn _assert_btree_set_used(_: &BTreeSet<u64>) {}
