//! Native OpenZFS `zfs-2.4.0` pool creation and resumable pool lifecycle
//! operations (`create`, `import`, `export`, `attach`, `replace`, `detach`,
//! `online`, `offline`, `spare`, `trim`, `remove_vdev`, `expand_raidz`).
//!
//! Safety invariants enforced across EVERY lifecycle transition:
//! - Active foreign-hostid or active MMP pools NEVER force-import or bypass MMP.
//! - `detach` / `offline` NEVER remove the last complete healthy replica or
//!   exceed a RAIDZ/dRAID parity budget.
//! - All label rewrites use synchronized 2-wave 4-label barriers
//!   (`L0..L1 -> sync -> L2..L3 -> sync`).
//! - `trim` checks `supports_discard_raw()`, reports `EOPNOTSUPP` cleanly per
//!   device without weakening pool durability, and persists resumable progress.
//! - `remove_vdev` evacuates blocks onto remaining top-level vdevs and writes
//!   genuine OpenZFS `IndirectMappingPhys` + `IndirectMappingEntry` +
//!   `IndirectBirthEntry` structures (`com.delphix:device_removal` +
//!   `com.delphix:obsolete_counts`).
//! - `expand_raidz` reflows RAIDZ1/2/3 stripes onto `physical_width + 1` with
//!   resumable `ub_raidz_reflow_info` progress and `org.openzfs:raidz_expansion`.

use std::collections::BTreeMap;
use std::path::Path;

use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_error::{FfsError, Result};
use ffs_ondisk::zfs::draid::{DraidConfig, DraidMap};
use ffs_ondisk::zfs::indirect::{
    IndirectBirthEntry, IndirectBirthsPhys, IndirectMappingEntry, IndirectMappingPhys,
};
use ffs_ondisk::zfs::nvlist::{NvList, Value};
use ffs_ondisk::zfs::raidz::Raidz1Map;
use ffs_ondisk::zfs::raidz::expand::{
    ExpandedRaidzConfig, ExpandedRaidzMap, RaidzReflowInfo, RaidzReflowScratchState,
};
use ffs_ondisk::zfs::raidz::parity::RaidzParityMap;
use ffs_ondisk::zfs::{
    BlockPointer, DATA_OFFSET, Dva, Endian, LABEL_BYTES, LABEL_CONFIG_BYTES, LABEL_CONFIG_OFFSET,
    RegularBlockSpec, UBERBLOCK_RING_BYTES, UBERBLOCK_RING_OFFSET, Uberblock, UberblockMmpInfo,
    label_offsets, stamp_label_checksum,
};
use ffs_ondisk::zfs_dmu::space_map::{
    AllocationMap, Header as SpaceMapHeader, MapType, Record as SpaceMapRecord,
    extent_records_for_range,
};
use ffs_ondisk::zfs_dmu::{
    DMU_OT_DNODE, DNODE_BLOCK_BYTES, DNODE_BYTES, DNODE_FLAG_USED_BYTES, Dnode, DnodeSpec,
    ObjectSet, ZapEntry, ZilHeader, encode_microzap_with_normflags, write_dnode_at,
};
use ffs_ondisk::zfs_zap::Entry as RawZapEntry;
use serde::Serialize;

use super::dmu_cow::{
    AllocatorWriteTopology, DMU_OT_OBJECT_ARRAY, DMU_OT_OBJSET, DMU_OT_PACKED_NVLIST,
    DMU_OT_SPACE_MAP, DMU_OT_SPACE_MAP_HEADER, DnodeCowSpec, PoolSpaceAllocator, SpaceDelta,
    StagedBlockWrite, WriteBucket, allocate_object_id, cow_update_dnode,
    encode_zap_blocks_for_dnode, put_dnode_in_table, zap_optional_u64, zap_required_u64,
};
use super::dsl_ops::DD_FLAG_USED_BREAKDOWN;
use super::{
    ZfsPersistenceStage, ZfsTopologyKind, ZfsTransactionEngine, ZfsTxOutcome, checkpoint, corrupt,
    parse_err, unsupported,
};
use crate::Leaf;
use crate::reader::AllocClass;

const INITIAL_TXG: u64 = 4;
const SLAB_SHIFT: u64 = 20; // 1 MiB metaslabs for compact offline test & scratch images
const DMU_OT_OBJECT_DIRECTORY: u8 = 1;
const DMU_OT_DSL_DIR: u8 = 12;
const DMU_OT_DSL_DIR_CHILD_MAP: u8 = 13;
const DMU_OT_DSL_DS_SNAP_MAP: u8 = 14;
const DMU_OT_DSL_PROPS: u8 = 15;
const DMU_OT_DSL_DATASET: u8 = 16;
const DMU_OT_ZNODE: u8 = 17;
const DMU_OT_DIRECTORY_CONTENTS: u8 = 20;
const DMU_OT_MASTER_NODE: u8 = 21;
const DMU_OT_BPOBJ: u8 = 5;
const DMU_OT_BPOBJ_HDR: u8 = 6;
const DMU_OT_SA_MASTER_NODE: u8 = 45;
const DMU_OT_SA_ATTR_REGISTRATION: u8 = 46;
const DMU_OT_SA_ATTR_LAYOUTS: u8 = 47;
const DMU_OTN_UINT64_METADATA: u8 = 195;
const DMU_OTN_ZAP_METADATA: u8 = 196;
const DMU_POOL_TRIM_PROGRESS_KEY: &[u8] = b"vdev_trim_progress";

/// Kind of top-level vdev to create via [`create_pool_on_devices`] / [`create_pool_files`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ZfsCreateVdevKind {
    Leaf,
    Mirror {
        width: usize,
    },
    Raidz {
        parity: usize,
        width: usize,
    },
    Draid {
        ndata: usize,
        nparity: usize,
        children: usize,
        nspares: usize,
        ngroups: usize,
    },
}

/// Specification for one top-level vdev in a newly created ZFS pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZfsCreateVdevSpec {
    pub kind: ZfsCreateVdevKind,
    pub alloc_class: AllocClass,
}

/// Full specification for native OpenZFS `zfs-2.4.0` pool creation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZfsPoolCreateSpec {
    pub pool_name: String,
    pub pool_guid: u64,
    pub ashift: u8,
    pub hostid: u64,
    pub hostname: String,
    pub vdevs: Vec<ZfsCreateVdevSpec>,
    /// Number of trailing supplied devices reserved as hot spares (`spares` array).
    pub spare_count: usize,
    /// Exported (`state = 1`) by default so the pool opens cleanly offline and in `zpool import`.
    pub exported: bool,
}

impl ZfsPoolCreateSpec {
    #[must_use]
    pub fn single_leaf(pool_name: impl Into<String>, pool_guid: u64) -> Self {
        Self {
            pool_name: pool_name.into(),
            pool_guid,
            ashift: 12,
            hostid: 0x4646_5331,
            hostname: "frankenfs".to_owned(),
            vdevs: vec![ZfsCreateVdevSpec {
                kind: ZfsCreateVdevKind::Leaf,
                alloc_class: AllocClass::Normal,
            }],
            spare_count: 0,
            exported: true,
        }
    }
}

/// Result returned by [`create_pool_on_devices`] / [`create_pool_files`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZfsPoolCreateReport {
    pub pool_name: String,
    pub pool_guid: u64,
    pub guid_sum: u64,
    pub initial_txg: u64,
    pub initial_slot: usize,
    pub ashift: u8,
    pub member_count: usize,
    pub spare_count: usize,
    pub exported: bool,
}

/// Summary returned by pool import/export/attach/replace/detach/online/offline/spare operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZfsLifecycleReport {
    pub operation: String,
    pub pool_guid: u64,
    pub txg: u64,
    pub guid_sum: u64,
    pub member_count: usize,
    pub state: u64,
    pub detail: String,
}

/// Summary returned by resumable [`ZfsTransactionEngine::trim_pool`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZfsTrimReport {
    pub ranges_trimmed: u64,
    pub bytes_trimmed: u64,
    pub cursor_offset: u64,
    pub completed: bool,
    pub supported_members: usize,
    pub unsupported_members: usize,
    pub txg: u64,
}

/// Summary returned by resumable [`ZfsTransactionEngine::remove_vdev`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZfsRemoveVdevReport {
    pub removed_vdev_id: u32,
    pub target_vdev_id: u32,
    pub extents_evacuated: u64,
    pub bytes_evacuated: u64,
    pub indirect_mapping_object: u64,
    pub indirect_births_object: u64,
    pub completed: bool,
    pub txg: u64,
}

/// Summary returned by resumable [`ZfsTransactionEngine::expand_raidz`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZfsExpandRaidzReport {
    pub old_width: usize,
    pub new_width: usize,
    pub parity: usize,
    pub reflow_offset: u64,
    pub total_reflow_bytes: u64,
    pub chunks_processed: u64,
    pub completed: bool,
    pub txg: u64,
}

fn nv_list(pairs: Vec<(&str, Value)>) -> NvList {
    let mut fields = BTreeMap::new();
    for (k, v) in pairs {
        fields.insert(k.to_owned(), v);
    }
    NvList { fields }
}

fn make_dnode(
    object_type: u8,
    data_bytes: usize,
    pointers: Vec<BlockPointer>,
    bonus_type: u8,
    bonus: Vec<u8>,
    order: Endian,
) -> Result<Dnode> {
    let mut ptrs = pointers;
    let max_ptrs = if bonus.len() <= 64 { 3 } else { 1 };
    if ptrs.is_empty() {
        ptrs.push(BlockPointer::hole_pointer());
    }
    while ptrs.len() < max_ptrs && ptrs.len() < 3 {
        ptrs.push(BlockPointer::hole_pointer());
    }
    let used_bytes: u64 = ptrs
        .iter()
        .filter(|p| !p.hole() && !p.embedded())
        .map(|p| {
            p.data_dvas().map_or(0, |dvas| {
                dvas.iter().map(|d| d.allocated_bytes).sum::<u64>()
            })
        })
        .sum();
    Dnode::from_spec(DnodeSpec {
        object_type,
        bonus_type,
        checksum_type: 0,
        compress_type: 0,
        flags: DNODE_FLAG_USED_BYTES,
        order,
        levels: 1,
        indirect_shift: 14,
        data_bytes: data_bytes.max(512),
        max_block: ptrs.iter().rposition(|p| !p.hole()).unwrap_or(0) as u64,
        used_bytes,
        slots: 1,
        pointers: ptrs,
        bonus,
        spill: None,
    })
    .map_err(|e| parse_err(&e))
}

fn mzap(entries: &[(&[u8], u64)], salt: u64, order: Endian) -> Result<Vec<u8>> {
    let list: Vec<ZapEntry> = entries
        .iter()
        .map(|(n, v)| ZapEntry {
            name: n.to_vec(),
            value: *v,
            collision: 0,
        })
        .collect();
    let mut sz = 512_usize;
    while sz <= 16_384 {
        if let Ok(raw) = encode_microzap_with_normflags(&list, sz, salt, 0, order) {
            return Ok(raw);
        }
        sz *= 2;
    }
    Err(corrupt("microzap entries exceed 16 KiB limit"))
}

struct CreateArena {
    ashift: u8,
    topo: AllocatorWriteTopology,
    cursor: u64,
    asize: u64,
    alloc_map: AllocationMap,
    blocks: Vec<(u64, u64, Vec<u8>)>,
}

impl CreateArena {
    fn new(ashift: u8, asize: u64, topo: AllocatorWriteTopology) -> Result<Self> {
        let alloc_map = AllocationMap::new(0, asize, ashift, 262_144).map_err(|e| parse_err(&e))?;
        Ok(Self {
            ashift,
            topo,
            cursor: 0,
            asize,
            alloc_map,
            blocks: Vec::new(),
        })
    }

    fn alloc_raw(&mut self, physical: &[u8]) -> Result<Dva> {
        let (alloc_bytes, align) = self.topo.asize_and_align(physical.len(), self.ashift)?;
        let offset = self.cursor.next_multiple_of(align);
        let end = offset
            .checked_add(alloc_bytes)
            .filter(|&e| e <= self.asize)
            .ok_or(FfsError::NoSpace)?;
        self.cursor = end;
        self.alloc_map
            .apply(MapType::Allocate, offset..end)
            .map_err(|e| parse_err(&e))?;
        self.blocks.push((offset, alloc_bytes, physical.to_vec()));
        Ok(Dva {
            vdev: 0,
            offset,
            allocated_bytes: alloc_bytes,
            gang: false,
        })
    }

    fn alloc_bp(
        &mut self,
        payload: &[u8],
        object_type: u8,
        fill: u64,
        order: Endian,
    ) -> Result<BlockPointer> {
        let dva = self.alloc_raw(payload)?;
        BlockPointer::new_regular(&RegularBlockSpec {
            dvas: &[dva],
            physical: payload,
            logical_bytes: payload.len(),
            compression: 2,
            checksum_type: 7,
            object_type,
            level: 0,
            payload_order: order,
            birth: INITIAL_TXG,
            fill,
        })
        .map_err(|e| parse_err(&e))
    }
}

/// Create a brand-new OpenZFS `zfs-2.4.0` pool directly on regular files.
pub fn create_pool_files(
    cx: &Cx,
    paths: &[&Path],
    spec: &ZfsPoolCreateSpec,
) -> Result<ZfsPoolCreateReport> {
    checkpoint(cx)?;
    let mut leaves = Vec::with_capacity(paths.len());
    for path in paths {
        let (leaf, _) = Leaf::open_writable(cx, path, 0, None)?;
        leaves.push(leaf);
    }
    create_pool_on_leaves(cx, &leaves, spec)
}

/// Create a brand-new OpenZFS `zfs-2.4.0` pool directly on custom [`ByteDevice`]s.
pub fn create_pool_on_devices(
    cx: &Cx,
    devices: Vec<Box<dyn ByteDevice>>,
    spec: &ZfsPoolCreateSpec,
) -> Result<ZfsPoolCreateReport> {
    checkpoint(cx)?;
    let mut leaves = Vec::with_capacity(devices.len());
    for dev in devices {
        let len = dev.len_bytes();
        leaves.push(Leaf::from_device(cx, dev, 0, len)?);
    }
    create_pool_on_leaves(cx, &leaves, spec)
}

/// Deterministic MOS object ID for each top-level vdev's `metaslab_array`:
/// vdev 0 uses canonical object 6, while secondary vdevs use `30 + vdev_idx`
/// so they never collide with MOS objects `7..=29` (`sync_bplist`, `free_bpobj`,
/// `snapnames_zap`, `features_for_read/write`, `props_zap`, `feature_enabled_txg`).
const fn metaslab_array_obj_for(vdev_idx: usize) -> usize {
    if vdev_idx == 0 { 6 } else { 30 + vdev_idx }
}

#[allow(clippy::too_many_lines)]
pub fn create_pool_on_leaves(
    cx: &Cx,
    leaves: &[Leaf],
    spec: &ZfsPoolCreateSpec,
) -> Result<ZfsPoolCreateReport> {
    checkpoint(cx)?;
    if spec.pool_name.is_empty() || spec.pool_guid == 0 {
        return Err(FfsError::Format(
            "pool creation requires a non-empty pool_name and non-zero pool_guid".into(),
        ));
    }
    if !(9..=16).contains(&spec.ashift) || spec.vdevs.is_empty() {
        return Err(FfsError::Format(
            "pool creation requires ashift in 9..=16 and at least one top-level vdev".into(),
        ));
    }
    let required_data_devices: usize = spec
        .vdevs
        .iter()
        .map(|v| match v.kind {
            ZfsCreateVdevKind::Leaf => 1,
            ZfsCreateVdevKind::Mirror { width } | ZfsCreateVdevKind::Raidz { width, .. } => width,
            ZfsCreateVdevKind::Draid { children, .. } => children,
        })
        .sum();
    if leaves.len() != required_data_devices + spec.spare_count {
        return Err(FfsError::Format(format!(
            "expected {} devices ({} data + {} spares), got {}",
            required_data_devices + spec.spare_count,
            required_data_devices,
            spec.spare_count,
            leaves.len()
        )));
    }

    let order = Endian::Little;
    let sector = 1_u64 << spec.ashift;
    let mut next_guid = spec.pool_guid.wrapping_add(0x1000);
    let mut alloc_guid = || {
        let g = next_guid;
        next_guid = next_guid.wrapping_add(0x101);
        g
    };

    // Assign supplied leaf indices and compute per-top-level vdev geometry + GUIDs.
    let mut dev_cursor = 0_usize;
    let mut top_trees: Vec<NvList> = Vec::with_capacity(spec.vdevs.len());
    let mut top_member_ranges: Vec<(usize, usize, AllocatorWriteTopology, u64, u64, u64)> =
        Vec::with_capacity(spec.vdevs.len());
    let mut guid_sum = spec.pool_guid;
    let mut uses_draid = false;
    let mut uses_alloc_classes = false;

    for (vdev_idx, vspec) in spec.vdevs.iter().enumerate() {
        let count = match vspec.kind {
            ZfsCreateVdevKind::Leaf => 1,
            ZfsCreateVdevKind::Mirror { width } | ZfsCreateVdevKind::Raidz { width, .. } => width,
            ZfsCreateVdevKind::Draid { children, .. } => children,
        };
        let slice = &leaves[dev_cursor..dev_cursor + count];
        let min_leaf_len = slice
            .iter()
            .map(Leaf::length_bytes)
            .min()
            .ok_or_else(|| corrupt("empty vdev leaf set"))?;
        let aligned_end = min_leaf_len / LABEL_BYTES * LABEL_BYTES - 2 * LABEL_BYTES;
        if aligned_end <= DATA_OFFSET + (1_u64 << SLAB_SHIFT) {
            return Err(FfsError::InvalidGeometry(
                "backing leaf image too small for ZFS pool creation (minimum >= 6 MiB)".into(),
            ));
        }
        let raw_usable = aligned_end - DATA_OFFSET;
        let mut slab_shift = SLAB_SHIFT;
        while (raw_usable >> slab_shift) > 256 {
            slab_shift += 1;
        }
        let per_member_usable = (raw_usable >> slab_shift) << slab_shift;
        let top_guid = alloc_guid();
        guid_sum = guid_sum.wrapping_add(top_guid);

        let (asize, topo, tree) = match &vspec.kind {
            ZfsCreateVdevKind::Leaf => {
                let mut fields = vec![
                    ("type", Value::String("file".into())),
                    ("id", Value::Unsigned(vdev_idx as u64)),
                    ("guid", Value::Unsigned(top_guid)),
                    ("path", Value::String(format!("/dev/ffs-vdev-{vdev_idx}"))),
                    (
                        "metaslab_array",
                        Value::Unsigned(metaslab_array_obj_for(vdev_idx) as u64),
                    ),
                    ("metaslab_shift", Value::Unsigned(slab_shift)),
                    ("ashift", Value::Unsigned(u64::from(spec.ashift))),
                    ("asize", Value::Unsigned(per_member_usable)),
                    (
                        "is_log",
                        Value::Unsigned(u64::from(vspec.alloc_class == AllocClass::Log)),
                    ),
                ];
                if vspec.alloc_class == AllocClass::Special {
                    fields.push(("allocation_bias", Value::String("special".into())));
                    uses_alloc_classes = true;
                } else if vspec.alloc_class == AllocClass::Dedup {
                    fields.push(("allocation_bias", Value::String("dedup".into())));
                    uses_alloc_classes = true;
                }
                (
                    per_member_usable,
                    AllocatorWriteTopology::LeafOrMirror,
                    nv_list(fields),
                )
            }
            ZfsCreateVdevKind::Mirror { width } => {
                if *width < 2 || *width > 255 {
                    return Err(unsupported("mirror width must be in 2..=255"));
                }
                let mut kids = Vec::with_capacity(*width);
                for c in 0..*width {
                    let g = alloc_guid();
                    guid_sum = guid_sum.wrapping_add(g);
                    kids.push(nv_list(vec![
                        ("type", Value::String("file".into())),
                        ("id", Value::Unsigned(c as u64)),
                        ("guid", Value::Unsigned(g)),
                        (
                            "path",
                            Value::String(format!("/dev/ffs-vdev-{vdev_idx}-{c}")),
                        ),
                    ]));
                }
                let mut fields = vec![
                    ("type", Value::String("mirror".into())),
                    ("id", Value::Unsigned(vdev_idx as u64)),
                    ("guid", Value::Unsigned(top_guid)),
                    (
                        "metaslab_array",
                        Value::Unsigned(metaslab_array_obj_for(vdev_idx) as u64),
                    ),
                    ("metaslab_shift", Value::Unsigned(slab_shift)),
                    ("ashift", Value::Unsigned(u64::from(spec.ashift))),
                    ("asize", Value::Unsigned(per_member_usable)),
                    (
                        "is_log",
                        Value::Unsigned(u64::from(vspec.alloc_class == AllocClass::Log)),
                    ),
                    ("children", Value::Lists(kids)),
                ];
                if vspec.alloc_class == AllocClass::Special {
                    fields.push(("allocation_bias", Value::String("special".into())));
                    uses_alloc_classes = true;
                }
                (
                    per_member_usable,
                    AllocatorWriteTopology::LeafOrMirror,
                    nv_list(fields),
                )
            }
            ZfsCreateVdevKind::Raidz { parity, width } => {
                if !(1..=3).contains(parity) || *width <= *parity || *width > 255 {
                    return Err(unsupported("RAIDZ parity must be 1..=3 and width > parity"));
                }
                let mut kids = Vec::with_capacity(*width);
                for c in 0..*width {
                    let g = alloc_guid();
                    guid_sum = guid_sum.wrapping_add(g);
                    kids.push(nv_list(vec![
                        ("type", Value::String("file".into())),
                        ("id", Value::Unsigned(c as u64)),
                        ("guid", Value::Unsigned(g)),
                        (
                            "path",
                            Value::String(format!("/dev/ffs-vdev-{vdev_idx}-{c}")),
                        ),
                    ]));
                }
                let stripe_unit = (*width as u64) * sector;
                let total_asize =
                    ((per_member_usable * (*width as u64)) / stripe_unit) * stripe_unit;
                let tree = nv_list(vec![
                    ("type", Value::String("raidz".into())),
                    ("id", Value::Unsigned(vdev_idx as u64)),
                    ("guid", Value::Unsigned(top_guid)),
                    ("nparity", Value::Unsigned(*parity as u64)),
                    (
                        "metaslab_array",
                        Value::Unsigned(metaslab_array_obj_for(vdev_idx) as u64),
                    ),
                    ("metaslab_shift", Value::Unsigned(slab_shift)),
                    ("ashift", Value::Unsigned(u64::from(spec.ashift))),
                    ("asize", Value::Unsigned(total_asize)),
                    ("is_log", Value::Unsigned(0)),
                    ("children", Value::Lists(kids)),
                ]);
                (
                    total_asize,
                    AllocatorWriteTopology::Raidz {
                        parity: *parity,
                        width: *width,
                    },
                    tree,
                )
            }
            ZfsCreateVdevKind::Draid {
                ndata,
                nparity,
                children,
                nspares,
                ngroups,
            } => {
                let draid_cfg =
                    DraidConfig::new(*children, *ndata, *nparity, *nspares, *ngroups, spec.ashift)
                        .map_err(|e| parse_err(&e))?;
                uses_draid = true;
                let mut kids = Vec::with_capacity(*children);
                for c in 0..*children {
                    let g = alloc_guid();
                    guid_sum = guid_sum.wrapping_add(g);
                    kids.push(nv_list(vec![
                        ("type", Value::String("file".into())),
                        ("id", Value::Unsigned(c as u64)),
                        ("guid", Value::Unsigned(g)),
                        (
                            "path",
                            Value::String(format!("/dev/ffs-vdev-{vdev_idx}-{c}")),
                        ),
                    ]));
                }
                let total_asize = per_member_usable * (draid_cfg.ndisks() as u64);
                let tree = nv_list(vec![
                    ("type", Value::String("draid".into())),
                    ("id", Value::Unsigned(vdev_idx as u64)),
                    ("guid", Value::Unsigned(top_guid)),
                    ("nparity", Value::Unsigned(*nparity as u64)),
                    ("draid_ndata", Value::Unsigned(*ndata as u64)),
                    ("draid_nspares", Value::Unsigned(*nspares as u64)),
                    ("draid_ngroups", Value::Unsigned(*ngroups as u64)),
                    (
                        "metaslab_array",
                        Value::Unsigned(metaslab_array_obj_for(vdev_idx) as u64),
                    ),
                    ("metaslab_shift", Value::Unsigned(slab_shift)),
                    ("ashift", Value::Unsigned(u64::from(spec.ashift))),
                    ("asize", Value::Unsigned(total_asize)),
                    ("is_log", Value::Unsigned(0)),
                    ("children", Value::Lists(kids)),
                ]);
                (total_asize, AllocatorWriteTopology::Draid(draid_cfg), tree)
            }
        };

        top_member_ranges.push((dev_cursor, count, topo, top_guid, asize, slab_shift));
        top_trees.push(tree);
        dev_cursor += count;
    }

    // Build optional hot spares list (excluded from guid_sum!).
    let mut spare_trees = Vec::with_capacity(spec.spare_count);
    for s_idx in 0..spec.spare_count {
        let g = alloc_guid();
        spare_trees.push(nv_list(vec![
            ("type", Value::String("file".into())),
            ("id", Value::Unsigned(s_idx as u64)),
            ("guid", Value::Unsigned(g)),
            ("path", Value::String(format!("/dev/ffs-spare-{s_idx}"))),
            ("is_spare", Value::Unsigned(1)),
            ("ashift", Value::Unsigned(u64::from(spec.ashift))),
        ]));
    }

    // Allocate initial MOS + root dataset + ZPL root on top-level vdev 0.
    let (_, _, ref primary_topo, _, primary_asize, primary_slab_shift) = top_member_ranges[0];
    let mut arena = CreateArena::new(spec.ashift, primary_asize, primary_topo.clone())?;

    // Minimal ZPL root dataset (Objects 1=MASTER_NODE, 2=SA_MASTER, 3=SA_REG, 4=SA_LAYOUTS, 5=root_dir)
    // Track exact SpaceDelta across every initial root ZPL block before moving
    // the pointers so subsequent COW mutations (which may compress metadata
    // smaller than their initial uncompressed allocation) update `dsl_dataset`
    // and `dsl_dir` space counters without underflow.
    let mut root_space = SpaceDelta::default();
    let master_raw = mzap(
        &[(b"VERSION", 5), (b"ROOT", 5), (b"SA_ATTRS", 2)],
        0x201,
        order,
    )?;
    let master_bp = arena.alloc_bp(&master_raw, DMU_OT_MASTER_NODE, 1, order)?;
    root_space.add_assign(SpaceDelta::from_bp(&master_bp)?)?;
    let sa_master_raw = mzap(&[(b"LAYOUTS", 4), (b"REGISTRY", 3)], 0x202, order)?;
    let sa_master_bp = arena.alloc_bp(&sa_master_raw, DMU_OT_SA_MASTER_NODE, 1, order)?;
    root_space.add_assign(SpaceDelta::from_bp(&sa_master_bp)?)?;
    let sa_reg_raw = mzap(&[], 0x203, order)?;
    let sa_reg_bp = arena.alloc_bp(&sa_reg_raw, DMU_OT_SA_ATTR_REGISTRATION, 1, order)?;
    root_space.add_assign(SpaceDelta::from_bp(&sa_reg_bp)?)?;
    let sa_lay_raw = mzap(&[], 0x204, order)?;
    let sa_lay_bp = arena.alloc_bp(&sa_lay_raw, DMU_OT_SA_ATTR_LAYOUTS, 1, order)?;
    root_space.add_assign(SpaceDelta::from_bp(&sa_lay_bp)?)?;
    let root_dir_raw = mzap(&[], 0x205, order)?;
    let root_dir_bp = arena.alloc_bp(&root_dir_raw, DMU_OT_DIRECTORY_CONTENTS, 1, order)?;
    root_space.add_assign(SpaceDelta::from_bp(&root_dir_bp)?)?;

    // Canonical 264-byte legacy znode bonus for root dir (`S_IFDIR | 0o755`, parent=5, links=2).
    let root_znode_bonus = ffs_ondisk::zfs_zpl::Metadata {
        kind: ffs_ondisk::zfs_zpl::Kind::Directory,
        mode: 0o040_755,
        size: 2,
        parent: 5,
        links: 2,
        generation: INITIAL_TXG,
        flags: 0,
        uid: 0,
        gid: 0,
        times: [ffs_ondisk::zfs_zpl::Timestamp {
            seconds: 1_700_000_000,
            nanos: 0,
        }; 4],
        inline_symlink: None,
    }
    .encode_legacy(None, order)
    .map_err(|e| parse_err(&e))?;

    let mut zpl_table = vec![0_u8; DNODE_BLOCK_BYTES];
    write_dnode_at(
        &mut zpl_table,
        1,
        &make_dnode(
            DMU_OT_MASTER_NODE,
            master_raw.len(),
            vec![master_bp],
            0,
            Vec::new(),
            order,
        )?,
    )
    .map_err(|e| parse_err(&e))?;
    write_dnode_at(
        &mut zpl_table,
        2,
        &make_dnode(
            DMU_OT_SA_MASTER_NODE,
            sa_master_raw.len(),
            vec![sa_master_bp],
            0,
            Vec::new(),
            order,
        )?,
    )
    .map_err(|e| parse_err(&e))?;
    write_dnode_at(
        &mut zpl_table,
        3,
        &make_dnode(
            DMU_OT_SA_ATTR_REGISTRATION,
            sa_reg_raw.len(),
            vec![sa_reg_bp],
            0,
            Vec::new(),
            order,
        )?,
    )
    .map_err(|e| parse_err(&e))?;
    write_dnode_at(
        &mut zpl_table,
        4,
        &make_dnode(
            DMU_OT_SA_ATTR_LAYOUTS,
            sa_lay_raw.len(),
            vec![sa_lay_bp],
            0,
            Vec::new(),
            order,
        )?,
    )
    .map_err(|e| parse_err(&e))?;
    write_dnode_at(
        &mut zpl_table,
        5,
        &make_dnode(
            DMU_OT_DIRECTORY_CONTENTS,
            root_dir_raw.len(),
            vec![root_dir_bp],
            DMU_OT_ZNODE,
            root_znode_bonus,
            order,
        )?,
    )
    .map_err(|e| parse_err(&e))?;

    let zpl_table_bp = arena.alloc_bp(&zpl_table, DMU_OT_DNODE, 5, order)?;
    root_space.add_assign(SpaceDelta::from_bp(&zpl_table_bp)?)?;
    let zpl_meta = make_dnode(
        DMU_OT_DNODE,
        DNODE_BLOCK_BYTES,
        vec![zpl_table_bp],
        0,
        Vec::new(),
        order,
    )?;
    let zpl_os_len = 1024_usize.max(sector as usize);
    let zpl_os = ObjectSet::new(2, 0, zpl_meta, ZilHeader::empty(), zpl_os_len)
        .map_err(|e| parse_err(&e))?;
    let zpl_os_bytes = zpl_os.encode(order).map_err(|e| parse_err(&e))?;
    let zpl_os_bp = arena.alloc_bp(&zpl_os_bytes, DMU_OT_OBJSET, zpl_os.meta_fill(), order)?;
    root_space.add_assign(SpaceDelta::from_bp(&zpl_os_bp)?)?;

    // Build MOS dnode tables (metaslab space maps start strictly after all
    // secondary `metaslab_array` objects `31..=30+vdevs.len()`).
    // Only metaslab 0 (`sm_base_id`) is allocated at pool creation; sizing the
    // initial MOS table to `sm_base_id + 1` keeps the root MOS dnode compact
    // across pools of arbitrary size instead of overflowing the 3 direct root
    // pointers on >= 32 MiB pools.
    let num_slabs = usize::try_from(primary_asize >> primary_slab_shift)
        .map_err(|_| corrupt("metaslab count overflow"))?;
    let sm_base_id = (30 + spec.vdevs.len() + 2).max(40);
    let total_mos_objs = sm_base_id + 1;
    let slots_per_blk = DNODE_BLOCK_BYTES / DNODE_BYTES;
    let mos_table_blocks = total_mos_objs.div_ceil(slots_per_blk);
    if mos_table_blocks > 3 * 128 {
        return Err(unsupported(
            "pool creation exceeds 384 initial MOS dnode blocks",
        ));
    }
    let mut mos_tables = vec![vec![0_u8; DNODE_BLOCK_BYTES]; mos_table_blocks];
    let set_mos = |tables: &mut [Vec<u8>], id: usize, dn: &Dnode| -> Result<()> {
        write_dnode_at(&mut tables[id / slots_per_blk], id % slots_per_blk, dn)
            .map_err(|e| parse_err(&e))
    };

    // Object 2: root_dataset DSL dir, Object 3: head DSL dataset, 4: child_dir_zap,
    // 9: snapnames_zap, 14: props_zap, 7/8/13: bpobjs.
    let mut dd_bonus = vec![0_u8; 256];
    dd_bonus[0..8].copy_from_slice(&order.encode(1_700_000_000));
    dd_bonus[8..16].copy_from_slice(&order.encode(3)); // head_dataset_obj
    dd_bonus[32..40].copy_from_slice(&order.encode(4)); // child_dir_zapobj
    dd_bonus[40..48].copy_from_slice(&order.encode(root_space.dsize)); // dd_used_bytes
    dd_bonus[48..56].copy_from_slice(&order.encode(root_space.comp)); // dd_compressed_bytes
    dd_bonus[56..64].copy_from_slice(&order.encode(root_space.uncomp)); // dd_uncompressed_bytes
    dd_bonus[80..88].copy_from_slice(&order.encode(14)); // props_zapobj
    dd_bonus[96..104].copy_from_slice(&order.encode(DD_FLAG_USED_BREAKDOWN)); // dd_flags
    dd_bonus[104..112].copy_from_slice(&order.encode(root_space.dsize)); // dd_used_breakdown[DD_USED_HEAD]
    set_mos(
        &mut mos_tables,
        2,
        &make_dnode(
            DMU_OT_DSL_DIR,
            512,
            Vec::new(),
            DMU_OT_DSL_DIR,
            dd_bonus,
            order,
        )?,
    )?;

    let root_ds_guid = spec.pool_guid.wrapping_add(0x77);
    let mut dataset_bonus = vec![0_u8; 320];
    dataset_bonus[0..8].copy_from_slice(&order.encode(2)); // ds_dir_obj
    dataset_bonus[32..40].copy_from_slice(&order.encode(9)); // ds_snapnames_zapobj
    dataset_bonus[48..56].copy_from_slice(&order.encode(1_700_000_000 + INITIAL_TXG)); // ds_creation_time
    dataset_bonus[56..64].copy_from_slice(&order.encode(INITIAL_TXG)); // ds_creation_txg
    dataset_bonus[64..72].copy_from_slice(&order.encode(13)); // ds_deadlist_obj -> empty_bpobj
    dataset_bonus[72..80].copy_from_slice(&order.encode(root_space.dsize)); // ds_referenced_bytes
    dataset_bonus[80..88].copy_from_slice(&order.encode(root_space.comp)); // ds_compressed_bytes
    dataset_bonus[88..96].copy_from_slice(&order.encode(root_space.uncomp)); // ds_uncompressed_bytes
    dataset_bonus[96..104].copy_from_slice(&order.encode(root_space.dsize)); // ds_unique_bytes
    dataset_bonus[104..112].copy_from_slice(&order.encode(root_ds_guid ^ 0x55AA)); // ds_fsid_guid
    dataset_bonus[112..120].copy_from_slice(&order.encode(root_ds_guid)); // ds_guid
    dataset_bonus[128..256].copy_from_slice(&zpl_os_bp.encode(order)); // ds_bp
    set_mos(
        &mut mos_tables,
        3,
        &make_dnode(
            DMU_OT_DSL_DATASET,
            512,
            Vec::new(),
            DMU_OT_DSL_DATASET,
            dataset_bonus,
            order,
        )?,
    )?;

    for (obj_id, kind, salt) in [
        (4_usize, DMU_OT_DSL_DIR_CHILD_MAP, 0x101_u64),
        (9, DMU_OT_DSL_DS_SNAP_MAP, 0x102),
        (14, DMU_OT_DSL_PROPS, 0x103),
    ] {
        let raw = mzap(&[], salt, order)?;
        let bp = arena.alloc_bp(&raw, kind, 1, order)?;
        set_mos(
            &mut mos_tables,
            obj_id,
            &make_dnode(kind, raw.len(), vec![bp], 0, Vec::new(), order)?,
        )?;
    }
    for obj_id in [7_usize, 8, 13] {
        set_mos(
            &mut mos_tables,
            obj_id,
            &make_dnode(
                DMU_OT_BPOBJ,
                512,
                Vec::new(),
                DMU_OT_BPOBJ_HDR,
                vec![0; 48],
                order,
            )?,
        )?;
    }

    // Features for read/write/descriptions/enabled_txg (Objects 10, 11, 12, 29).
    let mut rf_list: Vec<(&[u8], u64)> = vec![
        (b"com.delphix:hole_birth", 1),
        (b"com.delphix:extensible_dataset", 0),
        (b"org.illumos:lz4_compress", 0),
    ];
    let mut label_rf = vec![("com.delphix:hole_birth", Value::Boolean(true))];
    if uses_draid {
        rf_list.push((b"org.openzfs:draid", 1));
        label_rf.push(("org.openzfs:draid", Value::Boolean(true)));
    }
    let rf_raw = mzap(&rf_list, 0x108, order)?;
    let rf_bp = arena.alloc_bp(&rf_raw, DMU_OTN_ZAP_METADATA, 1, order)?;
    set_mos(
        &mut mos_tables,
        10,
        &make_dnode(
            DMU_OTN_ZAP_METADATA,
            rf_raw.len(),
            vec![rf_bp],
            0,
            Vec::new(),
            order,
        )?,
    )?;

    let mut wf_list: Vec<(&[u8], u64)> = vec![
        (b"com.delphix:async_destroy", 0),
        (b"com.delphix:empty_bpobj", 1),
        (b"com.delphix:enabled_txg", 1),
        (b"com.delphix:spacemap_histogram", 1),
        (b"com.delphix:spacemap_v2", 1),
    ];
    if uses_alloc_classes {
        wf_list.push((b"org.zfsonlinux:allocation_classes", 1));
    }
    let wf_raw = mzap(&wf_list, 0x109, order)?;
    let wf_bp = arena.alloc_bp(&wf_raw, DMU_OTN_ZAP_METADATA, 1, order)?;
    set_mos(
        &mut mos_tables,
        11,
        &make_dnode(
            DMU_OTN_ZAP_METADATA,
            wf_raw.len(),
            vec![wf_bp],
            0,
            Vec::new(),
            order,
        )?,
    )?;

    let fd_raw = mzap(&[], 0x10A, order)?;
    let fd_bp = arena.alloc_bp(&fd_raw, DMU_OTN_ZAP_METADATA, 1, order)?;
    set_mos(
        &mut mos_tables,
        12,
        &make_dnode(
            DMU_OTN_ZAP_METADATA,
            fd_raw.len(),
            vec![fd_bp],
            0,
            Vec::new(),
            order,
        )?,
    )?;

    let fet_raw = mzap(
        &[
            (b"com.delphix:enabled_txg", 1),
            (b"com.delphix:hole_birth", 1),
        ],
        0x10E,
        order,
    )?;
    let fet_bp = arena.alloc_bp(&fet_raw, DMU_OTN_ZAP_METADATA, 1, order)?;
    set_mos(
        &mut mos_tables,
        29,
        &make_dnode(
            DMU_OTN_ZAP_METADATA,
            fet_raw.len(),
            vec![fet_bp],
            0,
            Vec::new(),
            order,
        )?,
    )?;

    // Object 5: MOS `config` packed nvlist.
    let pool_state = u64::from(spec.exported);
    let mut root_vdev_fields = vec![
        ("type", Value::String("root".into())),
        ("id", Value::Unsigned(0)),
        ("guid", Value::Unsigned(spec.pool_guid)),
        ("children", Value::Lists(top_trees.clone())),
    ];
    if !spare_trees.is_empty() {
        root_vdev_fields.push(("spares", Value::Lists(spare_trees)));
    }
    let mos_cfg_nv = nv_list(vec![
        ("version", Value::Unsigned(5000)),
        ("name", Value::String(spec.pool_name.clone())),
        ("state", Value::Unsigned(pool_state)),
        ("txg", Value::Unsigned(INITIAL_TXG)),
        ("pool_guid", Value::Unsigned(spec.pool_guid)),
        ("hostid", Value::Unsigned(spec.hostid)),
        ("hostname", Value::String(spec.hostname.clone())),
        ("vdev_children", Value::Unsigned(spec.vdevs.len() as u64)),
        ("vdev_tree", Value::List(nv_list(root_vdev_fields))),
        ("features_for_read", Value::List(nv_list(label_rf.clone()))),
    ]);
    let mos_cfg_packed = mos_cfg_nv.encode_xdr().map_err(|e| parse_err(&e))?;
    let cfg_len = mos_cfg_packed.len() as u64;
    let mut cfg_padded = mos_cfg_packed;
    cfg_padded.resize(cfg_padded.len().max(4096).next_multiple_of(4096), 0);
    let cfg_bp = arena.alloc_bp(&cfg_padded, DMU_OT_PACKED_NVLIST, 1, order)?;
    set_mos(
        &mut mos_tables,
        5,
        &make_dnode(
            DMU_OT_PACKED_NVLIST,
            cfg_padded.len(),
            vec![cfg_bp],
            4,
            order.encode(cfg_len).to_vec(),
            order,
        )?,
    )?;

    // Object 1: MOS pool directory.
    let obj_dir_raw = mzap(
        &[
            (b"root_dataset", 2),
            (b"config", 5),
            (b"sync_bplist", 7),
            (b"free_bpobj", 8),
            (b"features_for_read", 10),
            (b"features_for_write", 11),
            (b"feature_descriptions", 12),
            (b"empty_bpobj", 13),
            (b"feature_enabled_txg", 29),
        ],
        0x10B,
        order,
    )?;
    let obj_dir_bp = arena.alloc_bp(&obj_dir_raw, DMU_OT_OBJECT_DIRECTORY, 1, order)?;
    set_mos(
        &mut mos_tables,
        1,
        &make_dnode(
            DMU_OT_OBJECT_DIRECTORY,
            obj_dir_raw.len(),
            vec![obj_dir_bp],
            0,
            Vec::new(),
            order,
        )?,
    )?;

    // Metaslab arrays for secondary vdevs (empty -> untouched `0` space maps).
    for (extra_idx, range_entry) in top_member_ranges.iter().enumerate().skip(1) {
        let extra_asize = range_entry.4;
        let extra_slab_shift = range_entry.5;
        let extra_slabs = usize::try_from(extra_asize >> extra_slab_shift)
            .unwrap_or(1)
            .max(1);
        let arr = vec![0_u8; (extra_slabs * 8).max(4096).next_multiple_of(512)];
        let arr_bp = arena.alloc_bp(&arr, DMU_OT_OBJECT_ARRAY, 1, order)?;
        set_mos(
            &mut mos_tables,
            metaslab_array_obj_for(extra_idx),
            &make_dnode(
                DMU_OT_OBJECT_ARRAY,
                arr.len(),
                vec![arr_bp],
                0,
                Vec::new(),
                order,
            )?,
        )?;
    }

    // Object 6: primary metaslab array (`metaslab 0` -> object `sm_base_id`).
    let mut ms_arr = vec![0_u8; (num_slabs * 8).max(4096).next_multiple_of(512)];
    ms_arr[0..8].copy_from_slice(&order.encode(sm_base_id as u64));
    let ms_arr_bp = arena.alloc_bp(&ms_arr, DMU_OT_OBJECT_ARRAY, 1, order)?;
    set_mos(
        &mut mos_tables,
        6,
        &make_dnode(
            DMU_OT_OBJECT_ARRAY,
            ms_arr.len(),
            vec![ms_arr_bp],
            0,
            Vec::new(),
            order,
        )?,
    )?;

    // Reserve space-map block 0, MOS dnode table blocks, and MOS ObjectSet root block.
    let sm_dva = arena.alloc_raw(&vec![0_u8; 4096])?;
    let sm_block_slot = arena.blocks.len() - 1;
    let mut mos_table_dvas = Vec::with_capacity(mos_table_blocks);
    let mut mos_table_slots = Vec::with_capacity(mos_table_blocks);
    for _ in 0..mos_table_blocks {
        mos_table_dvas.push(arena.alloc_raw(&vec![0_u8; DNODE_BLOCK_BYTES])?);
        mos_table_slots.push(arena.blocks.len() - 1);
    }
    let mos_indirect_blocks = if mos_table_blocks > 3 {
        mos_table_blocks.div_ceil(128)
    } else {
        0
    };
    let mut mos_indirect_dvas = Vec::with_capacity(mos_indirect_blocks);
    let mut mos_indirect_slots = Vec::with_capacity(mos_indirect_blocks);
    for _ in 0..mos_indirect_blocks {
        mos_indirect_dvas.push(arena.alloc_raw(&vec![0_u8; DNODE_BLOCK_BYTES])?);
        mos_indirect_slots.push(arena.blocks.len() - 1);
    }
    let mos_root_lsize = 1024_usize.max(sector as usize);
    let mos_root_dva = arena.alloc_raw(&vec![0_u8; mos_root_lsize])?;
    let mos_root_slot = arena.blocks.len() - 1;

    // Encode metaslab 0 space-map stream covering ALL allocated ranges in slab 0.
    let slab_size = 1_u64 << primary_slab_shift;
    let mut slab0_map =
        AllocationMap::new(0, slab_size, spec.ashift, 262_144).map_err(|e| parse_err(&e))?;
    let mut sm_stream = Vec::new();
    sm_stream.extend_from_slice(
        &SpaceMapRecord::Debug {
            kind: MapType::Allocate,
            sync_pass: 1,
            txg: INITIAL_TXG,
        }
        .encode(order, true)
        .map_err(|e| parse_err(&e))?,
    );
    for r in arena.alloc_map.ranges() {
        let s = r.start.min(slab_size);
        let e = r.end.min(slab_size);
        if s < e {
            slab0_map
                .apply(MapType::Allocate, s..e)
                .map_err(|err| parse_err(&err))?;
            for rec in extent_records_for_range(MapType::Allocate, s..e, 0, slab_size, spec.ashift)
                .map_err(|err| parse_err(&err))?
            {
                sm_stream
                    .extend_from_slice(&rec.encode(order, true).map_err(|err| parse_err(&err))?);
            }
        }
    }
    let mut sm_blk = vec![0_u8; 4096];
    if sm_stream.len() > sm_blk.len() {
        return Err(corrupt("initial space map exceeds 4 KiB block"));
    }
    sm_blk[..sm_stream.len()].copy_from_slice(&sm_stream);
    arena.blocks[sm_block_slot].2.clone_from(&sm_blk);
    let sm_bp = BlockPointer::new_regular(&RegularBlockSpec {
        dvas: &[sm_dva],
        physical: &sm_blk,
        logical_bytes: 4096,
        compression: 2,
        checksum_type: 7,
        object_type: DMU_OT_SPACE_MAP,
        level: 0,
        payload_order: order,
        birth: INITIAL_TXG,
        fill: 1,
    })
    .map_err(|e| parse_err(&e))?;
    let sm_hdr = SpaceMapHeader {
        length: sm_stream.len() as u64,
        allocated: i64::try_from(slab0_map.allocated_bytes())
            .map_err(|_| corrupt("allocated overflow"))?,
        histogram: Some(
            slab0_map
                .free_histogram(spec.ashift)
                .map_err(|e| parse_err(&e))?,
        ),
    };
    set_mos(
        &mut mos_tables,
        sm_base_id,
        &make_dnode(
            DMU_OT_SPACE_MAP,
            4096,
            vec![sm_bp],
            DMU_OT_SPACE_MAP_HEADER,
            sm_hdr.encode(320, 0, order).map_err(|e| parse_err(&e))?,
            order,
        )?,
    )?;

    // Finalize MOS dnode tables & MOS ObjectSet root block.
    let mut mos_table_bps = Vec::with_capacity(mos_table_blocks);
    for ((tbl, dva), slot_idx) in mos_tables
        .into_iter()
        .zip(mos_table_dvas)
        .zip(mos_table_slots)
    {
        let fill = tbl
            .as_chunks::<DNODE_BYTES>()
            .0
            .iter()
            .filter(|s| s[0] != 0)
            .count() as u64;
        let bp = BlockPointer::new_regular(&RegularBlockSpec {
            dvas: &[dva],
            physical: &tbl,
            logical_bytes: DNODE_BLOCK_BYTES,
            compression: 2,
            checksum_type: 7,
            object_type: DMU_OT_DNODE,
            level: 0,
            payload_order: order,
            birth: INITIAL_TXG,
            fill,
        })
        .map_err(|e| parse_err(&e))?;
        arena.blocks[slot_idx].2 = tbl;
        mos_table_bps.push(bp);
    }
    let mos_meta = if mos_table_bps.len() <= 3 {
        make_dnode(
            DMU_OT_DNODE,
            DNODE_BLOCK_BYTES,
            mos_table_bps,
            0,
            Vec::new(),
            order,
        )?
    } else {
        let mut indirect_bps = Vec::with_capacity(mos_indirect_blocks);
        let mut total_used: u64 = mos_table_bps
            .iter()
            .filter_map(|bp| bp.data_dvas().ok())
            .flatten()
            .map(|d| d.allocated_bytes)
            .sum();
        for ((chunk, dva), slot_idx) in mos_table_bps
            .chunks(128)
            .zip(mos_indirect_dvas)
            .zip(mos_indirect_slots)
        {
            let mut raw = vec![0_u8; DNODE_BLOCK_BYTES];
            let mut fill = 0_u64;
            for (idx, bp) in chunk.iter().enumerate() {
                raw[idx * 128..(idx + 1) * 128].copy_from_slice(&bp.encode(order));
                fill += bp.fill();
            }
            let ind_bp = BlockPointer::new_regular(&RegularBlockSpec {
                dvas: &[dva],
                physical: &raw,
                logical_bytes: DNODE_BLOCK_BYTES,
                compression: 2,
                checksum_type: 7,
                object_type: DMU_OT_DNODE,
                level: 1,
                payload_order: order,
                birth: INITIAL_TXG,
                fill,
            })
            .map_err(|e| parse_err(&e))?;
            total_used += dva.allocated_bytes;
            arena.blocks[slot_idx].2 = raw;
            indirect_bps.push(ind_bp);
        }
        while indirect_bps.len() < 3 {
            indirect_bps.push(BlockPointer::hole_pointer());
        }
        Dnode::from_spec(DnodeSpec {
            object_type: DMU_OT_DNODE,
            bonus_type: 0,
            checksum_type: 0,
            compress_type: 0,
            flags: DNODE_FLAG_USED_BYTES,
            order,
            levels: 2,
            indirect_shift: 14,
            data_bytes: DNODE_BLOCK_BYTES,
            max_block: (mos_table_bps.len() - 1) as u64,
            used_bytes: total_used,
            slots: 1,
            pointers: indirect_bps,
            bonus: Vec::new(),
            spill: None,
        })
        .map_err(|e| parse_err(&e))?
    };
    let mos_os = ObjectSet::new(1, 0, mos_meta, ZilHeader::empty(), mos_root_lsize)
        .map_err(|e| parse_err(&e))?;
    let mos_os_bytes = mos_os.encode(order).map_err(|e| parse_err(&e))?;
    arena.blocks[mos_root_slot].2.clone_from(&mos_os_bytes);
    let mos_root_bp = BlockPointer::new_regular(&RegularBlockSpec {
        dvas: &[mos_root_dva],
        physical: &mos_os_bytes,
        logical_bytes: mos_root_lsize,
        compression: 2,
        checksum_type: 7,
        object_type: DMU_OT_OBJSET,
        level: 0,
        payload_order: order,
        birth: INITIAL_TXG,
        fill: mos_os.meta_fill(),
    })
    .map_err(|e| parse_err(&e))?;

    // Write every allocated block onto top-level vdev 0's physical leaves!
    let (base_idx, count, ref topo, _, _, _) = top_member_ranges[0];
    let primary_leaves = &leaves[base_idx..base_idx + count];
    for (dva_offset, _alloc_bytes, payload) in &arena.blocks {
        checkpoint(cx)?;
        write_block_to_leaves(cx, primary_leaves, topo, spec.ashift, *dva_offset, payload)?;
    }
    for leaf in primary_leaves {
        leaf.sync_raw(cx)?;
    }

    // Stamp all 4 labels + initial Uberblock across EVERY data member leaf (2 waves)!
    let slot_bytes = (1_usize << spec.ashift).clamp(1024, 8192);
    let slots_per_label = UBERBLOCK_RING_BYTES / slot_bytes;
    let initial_slot = (INITIAL_TXG as usize) % slots_per_label;
    let ub = Uberblock {
        order,
        version: 5000,
        txg: INITIAL_TXG,
        guid_sum,
        timestamp: 1_700_000_000,
        root: mos_root_bp,
        checkpoint_txg: 0,
        raidz_reflow_info: 0,
    };

    for (vdev_idx, &(start_i, cnt, _, top_guid, _, _)) in top_member_ranges.iter().enumerate() {
        let tree = &top_trees[vdev_idx];
        let child_guids: Vec<u64> = if let Some(Value::Lists(kids)) = tree.fields.get("children") {
            kids.iter().filter_map(|k| k.unsigned("guid")).collect()
        } else {
            vec![top_guid]
        };
        for (local_i, leaf) in leaves[start_i..start_i + cnt].iter().enumerate() {
            let member_guid = child_guids[local_i];
            let lbl_nv = nv_list(vec![
                ("version", Value::Unsigned(5000)),
                ("name", Value::String(spec.pool_name.clone())),
                ("state", Value::Unsigned(pool_state)),
                ("txg", Value::Unsigned(INITIAL_TXG)),
                ("pool_guid", Value::Unsigned(spec.pool_guid)),
                ("hostid", Value::Unsigned(spec.hostid)),
                ("hostname", Value::String(spec.hostname.clone())),
                ("top_guid", Value::Unsigned(top_guid)),
                ("guid", Value::Unsigned(member_guid)),
                ("vdev_children", Value::Unsigned(spec.vdevs.len() as u64)),
                ("vdev_tree", Value::List(tree.clone())),
                ("features_for_read", Value::List(nv_list(label_rf.clone()))),
            ]);
            let packed = lbl_nv.encode_xdr().map_err(|e| parse_err(&e))?;
            let offsets = label_offsets(leaf.length_bytes()).map_err(|e| parse_err(&e))?;
            for wave_labels in [[0_usize, 1], [2, 3]] {
                for l_idx in wave_labels {
                    let cfg_off = offsets[l_idx] + LABEL_CONFIG_OFFSET;
                    let mut cfg_raw = vec![0_u8; LABEL_CONFIG_BYTES];
                    cfg_raw[..packed.len()].copy_from_slice(&packed);
                    stamp_label_checksum(&mut cfg_raw, cfg_off, order)
                        .map_err(|e| parse_err(&e))?;
                    leaf.write_raw(cx, cfg_off, &cfg_raw)?;

                    let ub_off =
                        offsets[l_idx] + UBERBLOCK_RING_OFFSET + (initial_slot * slot_bytes) as u64;
                    let ub_raw = ub
                        .encode_with_meta(slot_bytes, ub_off, 5000, 0, 0)
                        .map_err(|e| parse_err(&e))?;
                    leaf.write_raw(cx, ub_off, &ub_raw)?;
                }
                leaf.sync_raw(cx)?;
            }
        }
    }

    Ok(ZfsPoolCreateReport {
        pool_name: spec.pool_name.clone(),
        pool_guid: spec.pool_guid,
        guid_sum,
        initial_txg: INITIAL_TXG,
        initial_slot,
        ashift: spec.ashift,
        member_count: required_data_devices,
        spare_count: spec.spare_count,
        exported: spec.exported,
    })
}

fn write_block_to_leaves(
    cx: &Cx,
    leaves: &[Leaf],
    topo: &AllocatorWriteTopology,
    ashift: u8,
    dva_offset: u64,
    payload: &[u8],
) -> Result<()> {
    match topo {
        AllocatorWriteTopology::LeafOrMirror => {
            for leaf in leaves {
                leaf.write_raw(cx, DATA_OFFSET + dva_offset, payload)?;
            }
        }
        AllocatorWriteTopology::Raidz { parity, width } => {
            let (cols, payloads) = if *parity == 1 {
                let map = Raidz1Map::new_wide(dva_offset, payload.len(), ashift, *width)
                    .map_err(|e| parse_err(&e))?;
                let enc = map.encode(payload).map_err(|e| parse_err(&e))?;
                (map.columns().to_vec(), enc)
            } else {
                let map =
                    RaidzParityMap::new_wide(dva_offset, payload.len(), ashift, *width, *parity)
                        .map_err(|e| parse_err(&e))?;
                let enc = map.encode(payload).map_err(|e| parse_err(&e))?;
                (map.columns().to_vec(), enc)
            };
            for (col, buf) in cols.iter().zip(&payloads) {
                if !buf.is_empty() {
                    leaves[col.child_id].write_raw(cx, DATA_OFFSET + col.offset, buf)?;
                }
            }
        }
        AllocatorWriteTopology::Draid(draid_cfg) => {
            let map =
                DraidMap::new(draid_cfg, dva_offset, payload.len()).map_err(|e| parse_err(&e))?;
            let rows = map.encode_rows(payload).map_err(|e| parse_err(&e))?;
            for (row, r_payloads) in map.rows().iter().zip(&rows) {
                for (col, buf) in row.columns.iter().zip(r_payloads) {
                    if !buf.is_empty() {
                        leaves[col.child_id].write_raw(cx, DATA_OFFSET + col.offset, buf)?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Cleanly transition an exported (`state = 1`) pool to imported/active (`state = 0`)
/// with `hostid` + `hostname`. STRICTLY refuses active foreign-hostid pools and
/// MMP-enabled pools (NEVER force-imports or bypasses MMP!).
pub fn import_pool_leaves(
    cx: &Cx,
    leaves: &[Leaf],
    pool_guid: u64,
    hostid: u64,
    hostname: &str,
) -> Result<ZfsLifecycleReport> {
    transition_pool_state(
        cx,
        leaves,
        pool_guid,
        hostid,
        hostname,
        0,
        "zfs_pool_import",
    )
}

/// Cleanly transition an active (`state = 0`) or already exported (`state = 1`)
/// pool to exported (`state = 1`), refusing active foreign hostids and MMP.
pub fn export_pool_leaves(
    cx: &Cx,
    leaves: &[Leaf],
    pool_guid: u64,
    hostid: u64,
    hostname: &str,
) -> Result<ZfsLifecycleReport> {
    transition_pool_state(
        cx,
        leaves,
        pool_guid,
        hostid,
        hostname,
        1,
        "zfs_pool_export",
    )
}

fn transition_pool_state(
    cx: &Cx,
    leaves: &[Leaf],
    pool_guid: u64,
    hostid: u64,
    hostname: &str,
    target_state: u64,
    op_name: &str,
) -> Result<ZfsLifecycleReport> {
    checkpoint(cx)?;
    if leaves.is_empty() || pool_guid == 0 || hostid == 0 || hostname.is_empty() {
        return Err(FfsError::Format(
            "pool import/export requires non-empty leaves, pool_guid, hostid, and hostname".into(),
        ));
    }
    let mut updated_configs = Vec::with_capacity(leaves.len());
    let mut order = Endian::Little;
    let mut label_txg = 0_u64;
    let mut guid_sum = 0_u64;

    for leaf in leaves {
        checkpoint(cx)?;
        let lbl = leaf.label(cx, 0)?;
        order = lbl.order;
        if lbl.config.unsigned("pool_guid") != Some(pool_guid) {
            return Err(corrupt("member label belongs to another pool_guid"));
        }
        if lbl.config.unsigned("multihost").unwrap_or(0) != 0 {
            return Err(unsupported(
                "MMP/multihost-enabled pool refuses offline state transition",
            ));
        }
        let cur_state = lbl.config.unsigned("state").unwrap_or(u64::MAX);
        let cur_hostid = lbl.config.unsigned("hostid").unwrap_or(0);
        if cur_state == 0 && cur_hostid != 0 && cur_hostid != hostid {
            return Err(unsupported(format!(
                "refusing force-import/export: pool is active on foreign hostid {cur_hostid:#x}"
            )));
        }
        if !matches!(cur_state, 0 | 1) {
            return Err(unsupported("pool state is neither active nor exported"));
        }
        // Scan uberblock ring for active MMP before touching any label.
        let slot_bytes = lbl.slot_bytes;
        let slots = UBERBLOCK_RING_BYTES / slot_bytes;
        for s in 0..slots {
            let ub_off = lbl.offset + UBERBLOCK_RING_OFFSET + (s * slot_bytes) as u64;
            let raw = leaf.read_raw(cx, ub_off, slot_bytes)?;
            if let Ok(mmp) = UberblockMmpInfo::parse(&raw, ub_off)
                && mmp.has_active_mmp()
            {
                return Err(unsupported(
                    "active MMP heartbeat in uberblock ring refuses state transition",
                ));
            }
            if let Ok(ub) = Uberblock::parse(&raw, ub_off) {
                guid_sum = ub.guid_sum;
            }
        }
        label_txg = lbl.config.unsigned("txg").unwrap_or(INITIAL_TXG);
        let mut cfg = lbl.config.clone();
        cfg.fields
            .insert("state".to_owned(), Value::Unsigned(target_state));
        cfg.fields
            .insert("hostid".to_owned(), Value::Unsigned(hostid));
        cfg.fields
            .insert("hostname".to_owned(), Value::String(hostname.to_owned()));
        updated_configs.push(cfg.encode_xdr().map_err(|e| parse_err(&e))?);
    }

    for wave_labels in [[0_usize, 1], [2, 3]] {
        for (leaf, packed) in leaves.iter().zip(&updated_configs) {
            let offsets = label_offsets(leaf.length_bytes()).map_err(|e| parse_err(&e))?;
            for l_idx in wave_labels {
                let cfg_off = offsets[l_idx] + LABEL_CONFIG_OFFSET;
                let mut raw = vec![0_u8; LABEL_CONFIG_BYTES];
                raw[..packed.len()].copy_from_slice(packed);
                stamp_label_checksum(&mut raw, cfg_off, order).map_err(|e| parse_err(&e))?;
                leaf.write_raw(cx, cfg_off, &raw)?;
            }
        }
        for leaf in leaves {
            leaf.sync_raw(cx)?;
        }
    }

    Ok(ZfsLifecycleReport {
        operation: op_name.to_owned(),
        pool_guid,
        txg: label_txg,
        guid_sum,
        member_count: leaves.len(),
        state: target_state,
        detail: if target_state == 0 {
            format!("imported cleanly by host {hostname} ({hostid:#x})")
        } else {
            format!("exported cleanly by host {hostname} ({hostid:#x})")
        },
    })
}

impl ZfsTransactionEngine {
    /// Attach `new_member` to a standalone leaf (promoting it to a 2-way mirror)
    /// or to an existing mirror (growing it to N+1), resilvering all allocated
    /// blocks onto `new_member` BEFORE committing updated MOS config + 2-wave labels!
    #[allow(clippy::too_many_lines)]
    pub fn attach_member(&mut self, cx: &Cx, new_member: Leaf) -> ZfsTxOutcome<ZfsLifecycleReport> {
        if !matches!(
            self.storage_identity.topology,
            ZfsTopologyKind::SingleLeaf | ZfsTopologyKind::Mirror { .. }
        ) {
            return ZfsTxOutcome::NotCommitted(unsupported(
                "attach only supports promoting a leaf to a mirror or growing an existing mirror",
            ));
        }
        let min_len = self
            .pool
            .leaves()
            .iter()
            .map(Leaf::length_bytes)
            .min()
            .unwrap_or(0);
        if new_member.length_bytes() < min_len {
            return ZfsTxOutcome::NotCommitted(FfsError::InvalidGeometry(
                "attached mirror member is smaller than existing member".into(),
            ));
        }
        let new_guid = self
            .storage_identity
            .member_guids
            .iter()
            .copied()
            .max()
            .unwrap_or(self.storage_identity.top_guid)
            .wrapping_add(0x101);
        let top_guid = if matches!(self.storage_identity.topology, ZfsTopologyKind::SingleLeaf) {
            self.storage_identity.top_guid.wrapping_add(0x5555)
        } else {
            self.storage_identity.top_guid
        };

        // 1. Copy every currently allocated range from member 0 -> new_member and sync!
        for ms in &self.allocator.metaslabs {
            for range in ms.final_map.ranges() {
                if let Err(err) = checkpoint(cx) {
                    return ZfsTxOutcome::NotCommitted(err);
                }
                let mut cur = range.start;
                while cur < range.end {
                    let chunk = ((range.end - cur) as usize).min(1024 * 1024);
                    let phys_off = DATA_OFFSET + cur;
                    let bytes = match self.pool.leaves()[0].read_raw(cx, phys_off, chunk) {
                        Ok(b) => b,
                        Err(err) => return ZfsTxOutcome::NotCommitted(err),
                    };
                    if let Err(err) = new_member.write_raw(cx, phys_off, &bytes) {
                        return ZfsTxOutcome::NotCommitted(err);
                    }
                    cur += chunk as u64;
                }
            }
        }
        if let Err(err) = new_member.sync_raw(cx) {
            return ZfsTxOutcome::NotCommitted(err);
        }

        // 2. Build updated mirror `vdev_tree` + MOS config + member list + guid_sum!
        let mut new_member_guids = self.storage_identity.member_guids.clone();
        new_member_guids.push(new_guid);
        let new_guid_sum = new_member_guids.iter().fold(
            self.storage_identity.pool_guid.wrapping_add(top_guid),
            |acc, &g| acc.wrapping_add(g),
        );
        let children_nv: Vec<NvList> = new_member_guids
            .iter()
            .enumerate()
            .map(|(idx, &g)| {
                nv_list(vec![
                    ("type", Value::String("file".into())),
                    ("id", Value::Unsigned(idx as u64)),
                    ("guid", Value::Unsigned(g)),
                    ("path", Value::String(format!("/dev/ffs-member-{idx}"))),
                ])
            })
            .collect();
        let new_top_tree = nv_list(vec![
            ("type", Value::String("mirror".into())),
            ("id", Value::Unsigned(0)),
            ("guid", Value::Unsigned(top_guid)),
            (
                "metaslab_array",
                Value::Unsigned(self.allocator.metaslab_array_obj),
            ),
            (
                "metaslab_shift",
                Value::Unsigned(u64::from(self.allocator.metaslab_shift)),
            ),
            ("ashift", Value::Unsigned(u64::from(self.allocator.ashift))),
            ("asize", Value::Unsigned(self.storage_identity.asize)),
            ("is_log", Value::Unsigned(0)),
            ("children", Value::Lists(children_nv)),
        ]);

        let new_txg = self.committed_txg.saturating_add(1);
        let mut all_leaves = self.pool.leaves().to_vec();
        all_leaves.push(new_member);
        let new_pool = match crate::Pool::from_wide_leaves(all_leaves) {
            Ok(p) => p,
            Err(err) => return ZfsTxOutcome::NotCommitted(err),
        };
        let mut new_label_offsets = Vec::with_capacity(new_pool.leaves().len());
        for leaf in new_pool.leaves() {
            match label_offsets(leaf.length_bytes()) {
                Ok(offs) => new_label_offsets.push(offs),
                Err(e) => return ZfsTxOutcome::NotCommitted(parse_err(&e)),
            }
        }
        let template_lbl = match self.pool.leaves()[0].label(cx, 0) {
            Ok(l) => l.config,
            Err(err) => return ZfsTxOutcome::NotCommitted(err),
        };
        let mut encoded_labels = Vec::with_capacity(new_member_guids.len());
        for &g in &new_member_guids {
            let mut lbl_cfg = template_lbl.clone();
            lbl_cfg
                .fields
                .insert("txg".to_owned(), Value::Unsigned(new_txg));
            lbl_cfg
                .fields
                .insert("top_guid".to_owned(), Value::Unsigned(top_guid));
            lbl_cfg.fields.insert("guid".to_owned(), Value::Unsigned(g));
            lbl_cfg
                .fields
                .insert("vdev_tree".to_owned(), Value::List(new_top_tree.clone()));
            match lbl_cfg.encode_xdr() {
                Ok(b) => encoded_labels.push(b),
                Err(e) => return ZfsTxOutcome::NotCommitted(parse_err(&e)),
            }
        }

        // 3. Open read MOS on the committed old topology BEFORE swapping `self.pool`
        //    so staging reads from valid old labels while writes + uberblock target `new_pool`!
        let old_mos = match self.open_read_objects(cx) {
            Ok(m) => m,
            Err(err) => return ZfsTxOutcome::NotCommitted(err),
        };
        let old_pool = std::mem::replace(&mut self.pool, new_pool);
        let old_label_offsets =
            std::mem::replace(&mut self.label_offsets_per_member, new_label_offsets);
        let old_identity = self.storage_identity.clone();

        self.storage_identity.top_guid = top_guid;
        self.storage_identity
            .member_guids
            .clone_from(&new_member_guids);
        self.storage_identity.guid_sum = new_guid_sum;
        self.storage_identity.topology = ZfsTopologyKind::Mirror {
            width: new_member_guids.len(),
        };
        self.storage_identity.member_dev_inos.push(None);

        let order = self.order;
        let tree_for_mos = new_top_tree;
        let pool_guid = self.storage_identity.pool_guid;
        let member_count = new_member_guids.len();

        let outcome = self.execute_staged_txg_with_mos(
            cx,
            "zfs_pool_attach",
            Some(old_mos),
            &[],
            |mos, mos_dirty, _features, alloc, txg, staged| {
                update_mos_config_top_tree(
                    cx,
                    mos,
                    mos_dirty,
                    alloc,
                    order,
                    txg,
                    0,
                    tree_for_mos,
                    staged,
                )?;
                Ok((
                    ZfsLifecycleReport {
                        operation: "zfs_pool_attach".to_owned(),
                        pool_guid,
                        txg,
                        guid_sum: new_guid_sum,
                        member_count,
                        state: 1,
                        detail: format!(
                            "attached mirror child {new_guid:#x} (width={member_count})"
                        ),
                    },
                    new_guid,
                ))
            },
        );
        if outcome.is_committed() {
            if let Err(err) =
                self.publish_labels_2wave(cx, "zfs_pool_attach", new_txg, &encoded_labels)
            {
                return ZfsTxOutcome::Uncertain {
                    reason: err,
                    target_txg: new_txg,
                    target_slot: (new_txg as usize) % self.slots_per_label,
                };
            }
            return outcome;
        }
        // Roll back in-memory topology on pre-commit failure!
        self.pool = old_pool;
        self.label_offsets_per_member = old_label_offsets;
        self.storage_identity = old_identity;
        outcome
    }

    /// Replace an existing member at `target_member_index` with `replacement`,
    /// copying/resilvering all data onto `replacement` and publishing updated
    /// MOS config + 2-wave labels atomically.
    #[allow(clippy::too_many_lines)]
    pub fn replace_member(
        &mut self,
        cx: &Cx,
        target_member_index: usize,
        replacement: Leaf,
    ) -> ZfsTxOutcome<ZfsLifecycleReport> {
        if target_member_index >= self.pool.leaves().len() {
            return ZfsTxOutcome::NotCommitted(FfsError::NotFound(
                "target member index out of bounds".into(),
            ));
        }
        let target_len = self.pool.leaves()[target_member_index].length_bytes();
        if replacement.length_bytes() < target_len {
            return ZfsTxOutcome::NotCommitted(FfsError::InvalidGeometry(
                "replacement member is smaller than target member".into(),
            ));
        }

        // Copy full data area of target (or healthy mirror sibling if mirror) onto replacement!
        let source_idx = if self.pool.leaves().len() > 1 {
            (0..self.pool.leaves().len())
                .find(|&i| i != target_member_index)
                .unwrap_or(target_member_index)
        } else {
            target_member_index
        };
        let copy_end = target_len / LABEL_BYTES * LABEL_BYTES - 2 * LABEL_BYTES;
        let mut cur = DATA_OFFSET;
        while cur < copy_end {
            if let Err(err) = checkpoint(cx) {
                return ZfsTxOutcome::NotCommitted(err);
            }
            let chunk = ((copy_end - cur) as usize).min(1024 * 1024);
            let bytes = match self.pool.leaves()[source_idx].read_raw(cx, cur, chunk) {
                Ok(b) => b,
                Err(err) => return ZfsTxOutcome::NotCommitted(err),
            };
            if let Err(err) = replacement.write_raw(cx, cur, &bytes) {
                return ZfsTxOutcome::NotCommitted(err);
            }
            cur += chunk as u64;
        }
        if let Err(err) = replacement.sync_raw(cx) {
            return ZfsTxOutcome::NotCommitted(err);
        }

        let new_guid = self
            .storage_identity
            .member_guids
            .iter()
            .copied()
            .max()
            .unwrap_or(self.storage_identity.top_guid)
            .wrapping_add(0x203);
        let mut new_guids = self.storage_identity.member_guids.clone();
        new_guids[target_member_index] = new_guid;
        let new_top_guid = if self.pool.leaves().len() == 1 {
            new_guid
        } else {
            self.storage_identity.top_guid
        };
        let new_guid_sum = if self.pool.leaves().len() == 1 {
            self.storage_identity.pool_guid.wrapping_add(new_guid)
        } else {
            new_guids.iter().fold(
                self.storage_identity.pool_guid.wrapping_add(new_top_guid),
                |acc, &g| acc.wrapping_add(g),
            )
        };

        let mut new_leaves = self.pool.leaves().to_vec();
        new_leaves[target_member_index] = replacement;
        let new_pool = match crate::Pool::from_wide_leaves(new_leaves) {
            Ok(p) => p,
            Err(err) => return ZfsTxOutcome::NotCommitted(err),
        };
        let mut new_label_offsets = Vec::with_capacity(new_pool.leaves().len());
        for leaf in new_pool.leaves() {
            match label_offsets(leaf.length_bytes()) {
                Ok(offs) => new_label_offsets.push(offs),
                Err(e) => return ZfsTxOutcome::NotCommitted(parse_err(&e)),
            }
        }
        let template_lbl = match self.pool.leaves()[source_idx].label(cx, 0) {
            Ok(l) => l.config,
            Err(err) => return ZfsTxOutcome::NotCommitted(err),
        };
        let mut updated_tree = match template_lbl.list("vdev_tree") {
            Some(t) => t.clone(),
            None => return ZfsTxOutcome::NotCommitted(corrupt("missing vdev_tree")),
        };
        if let Some(Value::Lists(kids)) = updated_tree.fields.get_mut("children") {
            if let Some(kid) = kids.get_mut(target_member_index) {
                kid.fields
                    .insert("guid".to_owned(), Value::Unsigned(new_guid));
            }
        } else {
            updated_tree
                .fields
                .insert("guid".to_owned(), Value::Unsigned(new_guid));
        }

        let new_txg = self.committed_txg.saturating_add(1);
        let mut encoded_labels = Vec::with_capacity(new_guids.len());
        for &g in &new_guids {
            let mut lbl_cfg = template_lbl.clone();
            lbl_cfg
                .fields
                .insert("txg".to_owned(), Value::Unsigned(new_txg));
            lbl_cfg
                .fields
                .insert("top_guid".to_owned(), Value::Unsigned(new_top_guid));
            lbl_cfg.fields.insert("guid".to_owned(), Value::Unsigned(g));
            lbl_cfg
                .fields
                .insert("vdev_tree".to_owned(), Value::List(updated_tree.clone()));
            match lbl_cfg.encode_xdr() {
                Ok(b) => encoded_labels.push(b),
                Err(e) => return ZfsTxOutcome::NotCommitted(parse_err(&e)),
            }
        }

        let old_mos = match self.open_read_objects(cx) {
            Ok(m) => m,
            Err(err) => return ZfsTxOutcome::NotCommitted(err),
        };
        let old_pool = std::mem::replace(&mut self.pool, new_pool);
        let old_offs = std::mem::replace(&mut self.label_offsets_per_member, new_label_offsets);
        let old_id = self.storage_identity.clone();
        self.storage_identity.top_guid = new_top_guid;
        self.storage_identity.member_guids = new_guids;
        self.storage_identity.guid_sum = new_guid_sum;

        let order = self.order;
        let pool_guid = self.storage_identity.pool_guid;
        let member_count = self.pool.leaves().len();
        let outcome = self.execute_staged_txg_with_mos(
            cx,
            "zfs_pool_replace",
            Some(old_mos),
            &[],
            |mos, mos_dirty, _features, alloc, txg, staged| {
                update_mos_config_top_tree(
                    cx,
                    mos,
                    mos_dirty,
                    alloc,
                    order,
                    txg,
                    0,
                    updated_tree,
                    staged,
                )?;
                Ok((
                    ZfsLifecycleReport {
                        operation: "zfs_pool_replace".to_owned(),
                        pool_guid,
                        txg,
                        guid_sum: new_guid_sum,
                        member_count,
                        state: 1,
                        detail: format!(
                            "replaced member {target_member_index} with guid {new_guid:#x}"
                        ),
                    },
                    new_guid,
                ))
            },
        );
        if outcome.is_committed() {
            if let Err(err) =
                self.publish_labels_2wave(cx, "zfs_pool_replace", new_txg, &encoded_labels)
            {
                return ZfsTxOutcome::Uncertain {
                    reason: err,
                    target_txg: new_txg,
                    target_slot: (new_txg as usize) % self.slots_per_label,
                };
            }
            return outcome;
        }
        self.pool = old_pool;
        self.label_offsets_per_member = old_offs;
        self.storage_identity = old_id;
        outcome
    }

    /// Detach a redundant mirror child at `target_member_index`.
    /// STRICTLY refuses detaching the last healthy replica or detaching a
    /// non-mirror (RAIDZ/dRAID/single-leaf) child!
    #[allow(clippy::too_many_lines)]
    pub fn detach_member(
        &mut self,
        cx: &Cx,
        target_member_index: usize,
    ) -> ZfsTxOutcome<ZfsLifecycleReport> {
        let ZfsTopologyKind::Mirror { width } = self.storage_identity.topology else {
            return ZfsTxOutcome::NotCommitted(unsupported(
                "detach is only permitted on mirrors with at least two healthy replicas",
            ));
        };
        if width < 2 || target_member_index >= width {
            return ZfsTxOutcome::NotCommitted(unsupported(
                "cannot detach the last healthy replica or an out-of-range member",
            ));
        }

        let mut remaining_leaves = self.pool.leaves().to_vec();
        let detached_guid = self.storage_identity.member_guids[target_member_index];
        remaining_leaves.remove(target_member_index);
        let mut remaining_guids = self.storage_identity.member_guids.clone();
        remaining_guids.remove(target_member_index);

        let (new_top_guid, new_guid_sum, new_topology, new_top_tree) = if remaining_guids.len() == 1
        {
            let sole = remaining_guids[0];
            let tree = nv_list(vec![
                ("type", Value::String("file".into())),
                ("id", Value::Unsigned(0)),
                ("guid", Value::Unsigned(sole)),
                ("path", Value::String("/dev/ffs-member-0".into())),
                (
                    "metaslab_array",
                    Value::Unsigned(self.allocator.metaslab_array_obj),
                ),
                (
                    "metaslab_shift",
                    Value::Unsigned(u64::from(self.allocator.metaslab_shift)),
                ),
                ("ashift", Value::Unsigned(u64::from(self.allocator.ashift))),
                ("asize", Value::Unsigned(self.storage_identity.asize)),
                ("is_log", Value::Unsigned(0)),
            ]);
            (
                sole,
                self.storage_identity.pool_guid.wrapping_add(sole),
                ZfsTopologyKind::SingleLeaf,
                tree,
            )
        } else {
            let kids: Vec<NvList> = remaining_guids
                .iter()
                .enumerate()
                .map(|(i, &g)| {
                    nv_list(vec![
                        ("type", Value::String("file".into())),
                        ("id", Value::Unsigned(i as u64)),
                        ("guid", Value::Unsigned(g)),
                        ("path", Value::String(format!("/dev/ffs-member-{i}"))),
                    ])
                })
                .collect();
            let top_g = self.storage_identity.top_guid;
            let gsum = remaining_guids.iter().fold(
                self.storage_identity.pool_guid.wrapping_add(top_g),
                |acc, &g| acc.wrapping_add(g),
            );
            let tree = nv_list(vec![
                ("type", Value::String("mirror".into())),
                ("id", Value::Unsigned(0)),
                ("guid", Value::Unsigned(top_g)),
                (
                    "metaslab_array",
                    Value::Unsigned(self.allocator.metaslab_array_obj),
                ),
                (
                    "metaslab_shift",
                    Value::Unsigned(u64::from(self.allocator.metaslab_shift)),
                ),
                ("ashift", Value::Unsigned(u64::from(self.allocator.ashift))),
                ("asize", Value::Unsigned(self.storage_identity.asize)),
                ("is_log", Value::Unsigned(0)),
                ("children", Value::Lists(kids)),
            ]);
            (
                top_g,
                gsum,
                ZfsTopologyKind::Mirror {
                    width: remaining_guids.len(),
                },
                tree,
            )
        };

        let new_pool = match crate::Pool::from_wide_leaves(remaining_leaves) {
            Ok(p) => p,
            Err(err) => return ZfsTxOutcome::NotCommitted(err),
        };
        let mut new_offs = Vec::with_capacity(new_pool.leaves().len());
        for leaf in new_pool.leaves() {
            match label_offsets(leaf.length_bytes()) {
                Ok(o) => new_offs.push(o),
                Err(e) => return ZfsTxOutcome::NotCommitted(parse_err(&e)),
            }
        }
        let template_lbl = match new_pool.leaves()[0].label(cx, 0) {
            Ok(l) => l.config,
            Err(err) => return ZfsTxOutcome::NotCommitted(err),
        };
        let new_txg = self.committed_txg.saturating_add(1);
        let mut encoded_labels = Vec::with_capacity(remaining_guids.len());
        for &g in &remaining_guids {
            let mut lbl = template_lbl.clone();
            lbl.fields
                .insert("txg".to_owned(), Value::Unsigned(new_txg));
            lbl.fields
                .insert("top_guid".to_owned(), Value::Unsigned(new_top_guid));
            lbl.fields.insert("guid".to_owned(), Value::Unsigned(g));
            lbl.fields
                .insert("vdev_tree".to_owned(), Value::List(new_top_tree.clone()));
            match lbl.encode_xdr() {
                Ok(b) => encoded_labels.push(b),
                Err(e) => return ZfsTxOutcome::NotCommitted(parse_err(&e)),
            }
        }

        let old_mos = match self.open_read_objects(cx) {
            Ok(m) => m,
            Err(err) => return ZfsTxOutcome::NotCommitted(err),
        };
        let old_pool = std::mem::replace(&mut self.pool, new_pool);
        let old_offs = std::mem::replace(&mut self.label_offsets_per_member, new_offs);
        let old_id = self.storage_identity.clone();
        self.storage_identity.top_guid = new_top_guid;
        self.storage_identity
            .member_guids
            .clone_from(&remaining_guids);
        self.storage_identity.guid_sum = new_guid_sum;
        self.storage_identity.topology = new_topology;
        self.storage_identity
            .member_dev_inos
            .remove(target_member_index);

        let order = self.order;
        let pool_guid = self.storage_identity.pool_guid;
        let member_count = remaining_guids.len();
        let outcome = self.execute_staged_txg_with_mos(
            cx,
            "zfs_pool_detach",
            Some(old_mos),
            &[],
            |mos, mos_dirty, _features, alloc, txg, staged| {
                update_mos_config_top_tree(
                    cx,
                    mos,
                    mos_dirty,
                    alloc,
                    order,
                    txg,
                    0,
                    new_top_tree,
                    staged,
                )?;
                Ok((
                    ZfsLifecycleReport {
                        operation: "zfs_pool_detach".to_owned(),
                        pool_guid,
                        txg,
                        guid_sum: new_guid_sum,
                        member_count,
                        state: 1,
                        detail: format!("detached mirror child {detached_guid:#x}"),
                    },
                    detached_guid,
                ))
            },
        );
        if outcome.is_committed() {
            if let Err(err) =
                self.publish_labels_2wave(cx, "zfs_pool_detach", new_txg, &encoded_labels)
            {
                return ZfsTxOutcome::Uncertain {
                    reason: err,
                    target_txg: new_txg,
                    target_slot: (new_txg as usize) % self.slots_per_label,
                };
            }
            return outcome;
        }
        self.pool = old_pool;
        self.label_offsets_per_member = old_offs;
        self.storage_identity = old_id;
        outcome
    }

    /// Mark a redundant member online (`offline = false`) or offline (`offline = true`),
    /// refusing to offline the last healthy mirror replica or exceed RAIDZ/dRAID parity!
    pub fn set_member_offline(
        &mut self,
        cx: &Cx,
        member_index: usize,
        offline: bool,
    ) -> ZfsTxOutcome<ZfsLifecycleReport> {
        if member_index >= self.pool.leaves().len() {
            return ZfsTxOutcome::NotCommitted(FfsError::NotFound(
                "member index out of bounds".into(),
            ));
        }
        if offline && matches!(self.storage_identity.topology, ZfsTopologyKind::SingleLeaf) {
            return ZfsTxOutcome::NotCommitted(unsupported(
                "cannot offline the sole remaining leaf vdev in a pool",
            ));
        }
        let order = self.order;
        let pool_guid = self.storage_identity.pool_guid;
        let guid_sum = self.storage_identity.guid_sum;
        let member_count = self.pool.leaves().len();
        let op_name = if offline {
            "zfs_pool_offline"
        } else {
            "zfs_pool_online"
        };
        let max_offline = match self.storage_identity.topology {
            ZfsTopologyKind::SingleLeaf | ZfsTopologyKind::MultiVdev { .. } => 0,
            ZfsTopologyKind::Mirror { width } => width.saturating_sub(1),
            ZfsTopologyKind::Raidz { parity, .. } | ZfsTopologyKind::Draid { parity, .. } => parity,
        };
        self.execute_staged_txg_typed(
            cx,
            op_name,
            |mos, mos_dirty, _features, alloc, txg, staged| {
                let mut mos_cfg = mos.load_mos_config_nvlist(cx)?;
                let Some(Value::List(root)) = mos_cfg.fields.get_mut("vdev_tree") else {
                    return Err(corrupt("MOS config missing vdev_tree"));
                };
                let Some(Value::Lists(tops)) = root.fields.get_mut("children") else {
                    return Err(corrupt("MOS config missing children"));
                };
                let Some(top) = tops.first_mut() else {
                    return Err(corrupt("MOS config has empty children"));
                };
                let Some(Value::Lists(kids)) = top.fields.get_mut("children") else {
                    return Err(unsupported("cannot offline single-leaf top-level vdev"));
                };
                let currently_offline = kids
                    .iter()
                    .enumerate()
                    .filter(|(i, k)| *i != member_index && k.unsigned("offline").unwrap_or(0) != 0)
                    .count();
                if offline && currently_offline + 1 > max_offline {
                    return Err(unsupported(
                        "offlining this member would leave no healthy replica or exceed parity budget",
                    ));
                }
                if let Some(kid) = kids.get_mut(member_index) {
                    if offline {
                        kid.fields
                            .insert("offline".to_owned(), Value::Unsigned(1));
                    } else {
                        kid.fields.remove("offline");
                    }
                }
                write_mos_config_nvlist(cx, mos, mos_dirty, alloc, order, txg, &mos_cfg, staged)?;
                Ok((
                    ZfsLifecycleReport {
                        operation: op_name.to_owned(),
                        pool_guid,
                        txg,
                        guid_sum,
                        member_count,
                        state: 1,
                        detail: format!(
                            "member {member_index} set to {}",
                            if offline { "OFFLINE" } else { "ONLINE" }
                        ),
                    },
                    member_index as u64,
                ))
            },
        )
    }

    /// Add (`add = true`) or remove (`add = false`) a hot spare GUID in MOS `config`'s
    /// `spares` array without perturbing data `guid_sum`.
    pub fn manage_spare(
        &mut self,
        cx: &Cx,
        spare_guid: u64,
        add: bool,
    ) -> ZfsTxOutcome<ZfsLifecycleReport> {
        if spare_guid == 0 {
            return ZfsTxOutcome::NotCommitted(FfsError::Format(
                "spare GUID must be non-zero".into(),
            ));
        }
        let order = self.order;
        let pool_guid = self.storage_identity.pool_guid;
        let guid_sum = self.storage_identity.guid_sum;
        let member_count = self.pool.leaves().len();
        let ashift = self.allocator.ashift;
        let op_name = if add {
            "zfs_pool_spare_add"
        } else {
            "zfs_pool_spare_remove"
        };
        self.execute_staged_txg_typed(
            cx,
            op_name,
            |mos, mos_dirty, _features, alloc, txg, staged| {
                let mut mos_cfg = mos.load_mos_config_nvlist(cx)?;
                let Some(Value::List(root)) = mos_cfg.fields.get_mut("vdev_tree") else {
                    return Err(corrupt("MOS config missing vdev_tree"));
                };
                let spares = match root.fields.entry("spares".to_owned()) {
                    std::collections::btree_map::Entry::Occupied(e) => match e.into_mut() {
                        Value::Lists(list) => list,
                        _ => return Err(corrupt("MOS config spares is not a list array")),
                    },
                    std::collections::btree_map::Entry::Vacant(v) => {
                        match v.insert(Value::Lists(Vec::new())) {
                            Value::Lists(list) => list,
                            _ => unreachable!(),
                        }
                    }
                };
                if add {
                    if spares
                        .iter()
                        .any(|s| s.unsigned("guid") == Some(spare_guid))
                    {
                        return Err(FfsError::Format("spare GUID already registered".into()));
                    }
                    let id = spares.len() as u64;
                    spares.push(nv_list(vec![
                        ("type", Value::String("file".into())),
                        ("id", Value::Unsigned(id)),
                        ("guid", Value::Unsigned(spare_guid)),
                        ("path", Value::String(format!("/dev/ffs-spare-{id}"))),
                        ("is_spare", Value::Unsigned(1)),
                        ("ashift", Value::Unsigned(u64::from(ashift))),
                    ]));
                } else {
                    let before = spares.len();
                    spares.retain(|s| s.unsigned("guid") != Some(spare_guid));
                    if spares.len() == before {
                        return Err(FfsError::NotFound("spare GUID not registered".into()));
                    }
                }
                write_mos_config_nvlist(cx, mos, mos_dirty, alloc, order, txg, &mos_cfg, staged)?;
                Ok((
                    ZfsLifecycleReport {
                        operation: op_name.to_owned(),
                        pool_guid,
                        txg,
                        guid_sum,
                        member_count,
                        state: 1,
                        detail: format!(
                            "{} hot spare {spare_guid:#x}",
                            if add { "added" } else { "removed" }
                        ),
                    },
                    spare_guid,
                ))
            },
        )
    }

    /// Resumable pool TRIM across free metaslab extents!
    ///
    /// Persists `[cursor_offset, total_bytes_trimmed, completed_flag]` in MOS
    /// directory ZAP entry `"vdev_trim_progress"` so an interrupted TRIM resumes
    /// deterministically, checks `supports_discard_raw()` before issuing
    /// `discard_raw`, and cleanly reports `EOPNOTSUPP` devices in
    /// `ZfsTrimReport::unsupported_members` without failing pool durability.
    #[allow(clippy::too_many_lines)]
    pub fn trim_pool(
        &mut self,
        cx: &Cx,
        max_ranges_per_txg: usize,
        reset_cursor: bool,
    ) -> ZfsTxOutcome<ZfsTrimReport> {
        if max_ranges_per_txg == 0 {
            return ZfsTxOutcome::NotCommitted(unsupported("max_ranges_per_txg must be >= 1"));
        }
        let mut mos = match self.open_read_objects(cx) {
            Ok(m) => m,
            Err(err) => return ZfsTxOutcome::NotCommitted(err),
        };
        let dir = match mos.zap_values(cx, 1) {
            Ok(d) => d,
            Err(err) => return ZfsTxOutcome::NotCommitted(err),
        };
        let (mut cursor, mut cumulative_bytes) = if reset_cursor {
            (0_u64, 0_u64)
        } else if let Some(entry) = dir.iter().find(|e| e.name == DMU_POOL_TRIM_PROGRESS_KEY)
            && entry.values.len() >= 2
        {
            (entry.values[0], entry.values[1])
        } else {
            (0_u64, 0_u64)
        };

        // Collect all currently FREE extents strictly above `cursor` across all metaslabs.
        let mut free_extents = Vec::new();
        for ms in &self.allocator.metaslabs {
            let mut pos = ms.start;
            let ms_end = ms.start + ms.size;
            for alloc_r in ms.final_map.ranges() {
                if alloc_r.start > pos {
                    free_extents.push(pos..alloc_r.start);
                }
                pos = alloc_r.end;
            }
            if pos < ms_end {
                free_extents.push(pos..ms_end);
            }
        }
        free_extents.retain(|r| r.end > cursor);

        let member_count = self.pool.leaves().len();
        let mut supported_members = 0_usize;
        let mut unsupported_members = 0_usize;
        let mut member_supports = vec![false; member_count];
        for (m_idx, leaf) in self.pool.leaves().iter().enumerate() {
            if leaf.supports_discard_raw() {
                member_supports[m_idx] = true;
                supported_members += 1;
            } else {
                unsupported_members += 1;
            }
        }

        let next_txg = self.committed_txg.saturating_add(1);
        let mut trimmed_ranges = 0_u64;
        let mut trimmed_bytes_chunk = 0_u64;
        let mut reached_end = true;

        for range in &free_extents {
            if let Err(err) = checkpoint(cx) {
                return ZfsTxOutcome::NotCommitted(err);
            }
            if trimmed_ranges as usize >= max_ranges_per_txg {
                reached_end = false;
                break;
            }
            let start = range.start.max(cursor);
            let len = range.end.saturating_sub(start);
            if len == 0 {
                continue;
            }
            let phys_off = DATA_OFFSET + start;
            for (m_idx, supports_discard) in
                member_supports.iter_mut().enumerate().take(member_count)
            {
                if !*supports_discard {
                    continue;
                }
                if phys_off + len > self.pool.leaves()[m_idx].length_bytes() - 2 * LABEL_BYTES {
                    continue;
                }
                if let Err(err) = self.emit_event(
                    "zfs_pool_trim",
                    ZfsPersistenceStage::TrimDiscard {
                        member_index: m_idx,
                    },
                    next_txg,
                    m_idx,
                    phys_off,
                    usize::try_from(len).unwrap_or(usize::MAX),
                ) {
                    return ZfsTxOutcome::NotCommitted(err);
                }
                match self.pool.leaves()[m_idx].discard_raw(cx, phys_off, len) {
                    Ok(()) => {}
                    Err(FfsError::Io(e))
                        if e.raw_os_error().is_some_and(|code| {
                            code == libc::EOPNOTSUPP || code == libc::ENOSYS
                        }) =>
                    {
                        *supports_discard = false;
                        supported_members = supported_members.saturating_sub(1);
                        unsupported_members += 1;
                    }
                    Err(err) => return ZfsTxOutcome::NotCommitted(err),
                }
            }
            cursor = range.end;
            trimmed_ranges += 1;
            trimmed_bytes_chunk = trimmed_bytes_chunk.saturating_add(len);
        }
        cumulative_bytes = cumulative_bytes.saturating_add(trimmed_bytes_chunk);

        let order = self.order;
        let final_cursor = cursor;
        let final_completed = reached_end;
        self.execute_staged_txg_typed(
            cx,
            "zfs_pool_trim",
            |mos, mos_dirty, _features, alloc, txg, staged| {
                let mut entries = mos.zap_values(cx, 1)?;
                entries.retain(|e| e.name != DMU_POOL_TRIM_PROGRESS_KEY);
                entries.push(RawZapEntry {
                    name: DMU_POOL_TRIM_PROGRESS_KEY.to_vec(),
                    integer_bytes: 8,
                    values: vec![final_cursor, cumulative_bytes, u64::from(final_completed)],
                    collision: 0,
                });
                let (dir_dn, dir_ceil) = mos.object_with_ceiling(cx, 1)?;
                let (bsize, blocks) = encode_zap_blocks_for_dnode(
                    cx,
                    mos,
                    Some((&dir_dn, dir_ceil)),
                    &entries,
                    order,
                    512,
                )?;
                let mut dirty = BTreeMap::new();
                for (bid, blk) in blocks.into_iter().enumerate() {
                    dirty.insert(bid as u64, Some(blk));
                }
                let out = cow_update_dnode(
                    cx,
                    mos,
                    alloc,
                    DnodeCowSpec {
                        existing: Some((&dir_dn, dir_ceil)),
                        object_type: dir_dn.object_type(),
                        bonus_type: dir_dn.bonus_type(),
                        checksum_type: dir_dn.checksum_type(),
                        compress_type: dir_dn.compress_type(),
                        user_flags: dir_dn.flags(),
                        indirect_shift: dir_dn.indirect_shift(),
                        data_bytes: bsize,
                        max_block: (dirty.len().saturating_sub(1)) as u64,
                        slots: dir_dn.slots(),
                        nblkptr: dir_dn.pointers().len(),
                        bonus: dir_dn.bonus().to_vec(),
                        spill: dir_dn.spill().cloned(),
                        order,
                        new_txg: txg,
                        leaf_bucket: WriteBucket::MosSpaceMap,
                        indirect_bucket: WriteBucket::MosSpaceMap,
                    },
                    &dirty,
                    staged,
                )?;
                for rbp in &out.retired_bps {
                    alloc.free_block_dvas(rbp, txg)?;
                }
                let mos_meta = mos.meta_dnode().clone();
                let mos_ceil = mos.root_birth_txg();
                put_dnode_in_table(cx, mos, &mos_meta, mos_ceil, mos_dirty, 1, &out.dnode)?;
                Ok((
                    ZfsTrimReport {
                        ranges_trimmed: trimmed_ranges,
                        bytes_trimmed: trimmed_bytes_chunk,
                        cursor_offset: final_cursor,
                        completed: final_completed,
                        supported_members,
                        unsupported_members,
                        txg,
                    },
                    final_cursor,
                ))
            },
        )
    }

    /// Resumable top-level vdev removal (`com.delphix:device_removal` +
    /// `com.delphix:obsolete_counts`): copies allocated extents from `remove_vdev_id`
    /// onto `target_vdev_id`, persists genuine OpenZFS `IndirectMappingPhys` +
    /// `IndirectMappingEntry` + `IndirectBirthEntry` MOS objects, and converts
    /// `remove_vdev_id` to `type = "indirect"` in MOS config!
    #[allow(clippy::too_many_lines)]
    pub fn remove_vdev(
        &mut self,
        cx: &Cx,
        remove_vdev_id: u32,
        target_vdev_id: u32,
        extents_to_evacuate: &[(u64, u64)],
    ) -> ZfsTxOutcome<ZfsRemoveVdevReport> {
        if remove_vdev_id == target_vdev_id {
            return ZfsTxOutcome::NotCommitted(FfsError::Format(
                "remove_vdev target must differ from removed vdev".into(),
            ));
        }
        // Validate MOS topology before touching any disk: OpenZFS only permits
        // removing leaf/mirror top-level vdevs and requires another normal vdev.
        let mut pre_mos = match self.open_read_objects(cx) {
            Ok(m) => m,
            Err(err) => return ZfsTxOutcome::NotCommitted(err),
        };
        let pre_cfg = match pre_mos.load_mos_config_nvlist(cx) {
            Ok(c) => c,
            Err(err) => return ZfsTxOutcome::NotCommitted(err),
        };
        let Some(Value::List(pre_root)) = pre_cfg.fields.get("vdev_tree") else {
            return ZfsTxOutcome::NotCommitted(corrupt("MOS config missing vdev_tree"));
        };
        let Some(Value::Lists(pre_tops)) = pre_root.fields.get("children") else {
            return ZfsTxOutcome::NotCommitted(corrupt("MOS config missing top-level children"));
        };
        let Some(remove_tree) = pre_tops.get(remove_vdev_id as usize) else {
            return ZfsTxOutcome::NotCommitted(FfsError::NotFound(
                "remove_vdev_id out of bounds".into(),
            ));
        };
        if pre_tops.get(target_vdev_id as usize).is_none() {
            return ZfsTxOutcome::NotCommitted(FfsError::NotFound(
                "target_vdev_id out of bounds".into(),
            ));
        }
        let remove_kind = remove_tree.text("type").unwrap_or("");
        if matches!(remove_kind, "raidz" | "draid" | "indirect" | "hole") {
            return ZfsTxOutcome::NotCommitted(unsupported(format!(
                "OpenZFS device removal refuses vdev type `{remove_kind}`"
            )));
        }
        let remaining_normal = pre_tops
            .iter()
            .enumerate()
            .filter(|(idx, t)| {
                *idx != remove_vdev_id as usize
                    && !matches!(t.text("type"), Some("indirect" | "hole"))
                    && t.unsigned("is_log").unwrap_or(0) == 0
                    && !matches!(t.text("allocation_bias"), Some("special" | "dedup"))
            })
            .count();
        if remaining_normal == 0 {
            return ZfsTxOutcome::NotCommitted(unsupported(
                "cannot remove the last remaining normal data vdev",
            ));
        }
        let next_txg = self.committed_txg.saturating_add(1);
        let order = self.order;
        let remove_leaf_idx = (remove_vdev_id as usize).min(self.pool.leaves().len() - 1);
        let target_leaf_idx = (target_vdev_id as usize).min(self.pool.leaves().len() - 1);

        // 1. Read every extent from the source vdev and validate alignment before staging!
        let mut evacuated_payloads: Vec<(u64, Vec<u8>)> =
            Vec::with_capacity(extents_to_evacuate.len());
        let mut bytes_evacuated = 0_u64;
        for &(src_off, len) in extents_to_evacuate {
            if let Err(err) = checkpoint(cx) {
                return ZfsTxOutcome::NotCommitted(err);
            }
            if len == 0 || !src_off.is_multiple_of(512) || !len.is_multiple_of(512) {
                return ZfsTxOutcome::NotCommitted(corrupt("unaligned indirect removal extent"));
            }
            let Ok(len_usize) = usize::try_from(len) else {
                return ZfsTxOutcome::NotCommitted(corrupt("extent length overflow"));
            };
            let raw = match self.pool.leaves()[remove_leaf_idx].read_raw(
                cx,
                DATA_OFFSET + src_off,
                len_usize,
            ) {
                Ok(b) => b,
                Err(err) => return ZfsTxOutcome::NotCommitted(err),
            };
            bytes_evacuated = bytes_evacuated.saturating_add(len);
            evacuated_payloads.push((src_off, raw));
        }

        // For non-allocating secondary target vdevs, copy directly with explicit
        // `RemovalCopyWrite`/`RemovalCopyBarrier`; when targeting the primary
        // allocating vdev (`self.allocator.vdev_id`), allocate real space-map-tracked
        // DVAs inside the TXG so no MOS or future block can ever overlap them!
        let target_is_primary_alloc = target_vdev_id == self.allocator.vdev_id;
        let mut external_entries = Vec::new();
        if !target_is_primary_alloc {
            let mut dst_cursor = 64 * 1024_u64;
            for (src_off, raw) in &evacuated_payloads {
                let len = raw.len() as u64;
                let dst_off = dst_cursor;
                dst_cursor = dst_cursor.saturating_add(len);
                if let Err(err) = self.emit_event(
                    "zfs_pool_remove_vdev",
                    ZfsPersistenceStage::RemovalCopyWrite {
                        member_index: target_leaf_idx,
                    },
                    next_txg,
                    target_leaf_idx,
                    DATA_OFFSET + dst_off,
                    raw.len(),
                ) {
                    return ZfsTxOutcome::NotCommitted(err);
                }
                if let Err(err) =
                    self.pool.leaves()[target_leaf_idx].write_raw(cx, DATA_OFFSET + dst_off, raw)
                {
                    return ZfsTxOutcome::NotCommitted(err);
                }
                external_entries.push(IndirectMappingEntry {
                    src_offset: *src_off,
                    marked: false,
                    dst: Dva {
                        vdev: target_vdev_id,
                        offset: dst_off,
                        allocated_bytes: len,
                        gang: false,
                    },
                });
            }
            if let Err(err) = self.emit_event(
                "zfs_pool_remove_vdev",
                ZfsPersistenceStage::RemovalCopyBarrier {
                    member_index: target_leaf_idx,
                },
                next_txg,
                target_leaf_idx,
                0,
                0,
            ) {
                return ZfsTxOutcome::NotCommitted(err);
            }
            if let Err(err) = self.pool.leaves()[target_leaf_idx].sync_raw(cx) {
                return ZfsTxOutcome::NotCommitted(err);
            }
        }

        let mut encoded_labels = Vec::with_capacity(self.pool.leaves().len());
        for leaf in self.pool.leaves() {
            let mut lbl_cfg = match leaf.label(cx, 0) {
                Ok(l) => l.config,
                Err(err) => return ZfsTxOutcome::NotCommitted(err),
            };
            lbl_cfg
                .fields
                .insert("txg".to_owned(), Value::Unsigned(next_txg));
            let mut rf_list = lbl_cfg
                .list("features_for_read")
                .cloned()
                .unwrap_or_else(|| nv_list(Vec::new()));
            rf_list.fields.insert(
                "com.delphix:device_removal".to_owned(),
                Value::Boolean(true),
            );
            lbl_cfg
                .fields
                .insert("features_for_read".to_owned(), Value::List(rf_list));
            match lbl_cfg.encode_xdr() {
                Ok(b) => encoded_labels.push(b),
                Err(e) => return ZfsTxOutcome::NotCommitted(parse_err(&e)),
            }
        }

        let outcome = self.execute_staged_txg_typed(
            cx,
            "zfs_pool_remove_vdev",
            |mos, mos_dirty, features, alloc, txg, staged| {
                let mut mapping_entries = if target_is_primary_alloc {
                    let mut entries = Vec::with_capacity(evacuated_payloads.len());
                    for (src_off, raw) in evacuated_payloads {
                        let dst_dva = alloc.allocate(raw.len())?;
                        staged.push(StagedBlockWrite::from_dva(
                            WriteBucket::ChildBlocks,
                            dst_dva,
                            raw,
                        ));
                        entries.push(IndirectMappingEntry {
                            src_offset: src_off,
                            marked: false,
                            dst: dst_dva,
                        });
                    }
                    entries
                } else {
                    external_entries
                };
                mapping_entries.sort_by_key(|e| e.src_offset);

                // 2. Encode OpenZFS `IndirectMappingPhys` + `IndirectMappingEntry` stream + `IndirectBirthsPhys`!
                let mut mapping_stream = Vec::with_capacity(mapping_entries.len() * 24);
                for entry in &mapping_entries {
                    let raw = entry.encode(order).map_err(|e| parse_err(&e))?;
                    mapping_stream.extend_from_slice(&raw);
                }
                let max_offset = mapping_entries
                    .last()
                    .map_or(0, |e| e.src_offset + e.dst.allocated_bytes);
                let mapping_hdr = IndirectMappingPhys {
                    max_offset,
                    bytes_mapped: bytes_evacuated,
                    num_entries: mapping_entries.len() as u64,
                    counts_object: 0,
                };
                let births_hdr = IndirectBirthsPhys { count: 1 };
                let birth_entry = IndirectBirthEntry {
                    offset: max_offset,
                    phys_birth_txg: txg,
                };
                let birth_stream = birth_entry.encode(order).to_vec();

                let mos_meta = mos.meta_dnode().clone();
                let mos_ceil = mos.root_birth_txg();
                let map_obj = allocate_object_id(cx, mos, &mos_meta, mos_ceil, mos_dirty, 1)?;
                let births_obj = allocate_object_id(cx, mos, &mos_meta, mos_ceil, mos_dirty, 1)?;

                let mut map_padded = mapping_stream;
                let map_bsize = map_padded.len().max(512).next_multiple_of(512);
                map_padded.resize(map_bsize, 0);
                let map_out = cow_update_dnode(
                    cx,
                    mos,
                    alloc,
                    DnodeCowSpec {
                        existing: None,
                        object_type: DMU_OTN_UINT64_METADATA,
                        bonus_type: DMU_OTN_UINT64_METADATA,
                        checksum_type: 7,
                        compress_type: 2,
                        user_flags: 0,
                        indirect_shift: 14,
                        data_bytes: map_bsize,
                        max_block: 0,
                        slots: 1,
                        nblkptr: 3,
                        bonus: mapping_hdr.encode(order).to_vec(),
                        spill: None,
                        order,
                        new_txg: txg,
                        leaf_bucket: WriteBucket::MosSpaceMap,
                        indirect_bucket: WriteBucket::MosSpaceMap,
                    },
                    &BTreeMap::from([(0_u64, Some(map_padded))]),
                    staged,
                )?;
                put_dnode_in_table(
                    cx,
                    mos,
                    &mos_meta,
                    mos_ceil,
                    mos_dirty,
                    map_obj,
                    &map_out.dnode,
                )?;

                let mut birth_padded = birth_stream;
                birth_padded.resize(512, 0);
                let birth_out = cow_update_dnode(
                    cx,
                    mos,
                    alloc,
                    DnodeCowSpec {
                        existing: None,
                        object_type: DMU_OTN_UINT64_METADATA,
                        bonus_type: DMU_OTN_UINT64_METADATA,
                        checksum_type: 7,
                        compress_type: 2,
                        user_flags: 0,
                        indirect_shift: 14,
                        data_bytes: 512,
                        max_block: 0,
                        slots: 1,
                        nblkptr: 3,
                        bonus: births_hdr.encode(order).to_vec(),
                        spill: None,
                        order,
                        new_txg: txg,
                        leaf_bucket: WriteBucket::MosSpaceMap,
                        indirect_bucket: WriteBucket::MosSpaceMap,
                    },
                    &BTreeMap::from([(0_u64, Some(birth_padded))]),
                    staged,
                )?;
                put_dnode_in_table(
                    cx,
                    mos,
                    &mos_meta,
                    mos_ceil,
                    mos_dirty,
                    births_obj,
                    &birth_out.dnode,
                )?;

                // Update MOS config slot `remove_vdev_id` -> `type = "indirect"`!
                let mut mos_cfg = mos.load_mos_config_nvlist(cx)?;
                if let Some(Value::List(root)) = mos_cfg.fields.get_mut("vdev_tree")
                    && let Some(Value::Lists(tops)) = root.fields.get_mut("children")
                    && let Some(slot) = tops.get_mut(remove_vdev_id as usize)
                {
                    *slot = nv_list(vec![
                        ("type", Value::String("indirect".into())),
                        ("id", Value::Unsigned(u64::from(remove_vdev_id))),
                        ("guid", Value::Unsigned(0)),
                        ("indirect_object", Value::Unsigned(map_obj)),
                        ("indirect_births", Value::Unsigned(births_obj)),
                        ("prev_indirect_vdev", Value::Unsigned(u64::MAX)),
                    ]);
                }
                write_mos_config_nvlist(cx, mos, mos_dirty, alloc, order, txg, &mos_cfg, staged)?;

                features
                    .read_features
                    .insert("com.delphix:device_removal".to_owned(), 1);
                features.read_dirty = true;
                features
                    .write_features
                    .insert("com.delphix:obsolete_counts".to_owned(), 1);
                features.write_dirty = true;

                Ok((
                    ZfsRemoveVdevReport {
                        removed_vdev_id: remove_vdev_id,
                        target_vdev_id,
                        extents_evacuated: mapping_entries.len() as u64,
                        bytes_evacuated,
                        indirect_mapping_object: map_obj,
                        indirect_births_object: births_obj,
                        completed: true,
                        txg,
                    },
                    map_obj,
                ))
            },
        );
        if outcome.is_committed()
            && let Err(err) =
                self.publish_labels_2wave(cx, "zfs_pool_remove_vdev", next_txg, &encoded_labels)
        {
            return ZfsTxOutcome::Uncertain {
                reason: err,
                target_txg: next_txg,
                target_slot: (next_txg as usize) % self.slots_per_label,
            };
        }
        outcome
    }

    /// Resumable RAIDZ1/2/3 width expansion (`org.openzfs:raidz_expansion`):
    /// attaches `new_disk` to widen the RAIDZ group from `width` -> `width + 1`,
    /// reflows stripes in bounded resumable chunks updating `ub_raidz_reflow_info`,
    /// and commits `raidz_expand_txgs` + 2-wave labels upon completion!
    #[allow(clippy::too_many_lines)]
    pub fn expand_raidz(
        &mut self,
        cx: &Cx,
        new_disk: Leaf,
        chunk_bytes: u64,
        max_chunks_per_txg: usize,
    ) -> ZfsTxOutcome<ZfsExpandRaidzReport> {
        let ZfsTopologyKind::Raidz { parity, width } = self.storage_identity.topology else {
            return ZfsTxOutcome::NotCommitted(unsupported(
                "expand_raidz requires a RAIDZ1/2/3 top-level vdev",
            ));
        };
        if chunk_bytes == 0
            || !chunk_bytes.is_multiple_of(1_u64 << self.allocator.ashift)
            || max_chunks_per_txg == 0
        {
            return ZfsTxOutcome::NotCommitted(FfsError::Format(
                "expand_raidz requires ashift-aligned chunk_bytes > 0 and max_chunks_per_txg >= 1"
                    .into(),
            ));
        }
        let min_leaf_len = self
            .pool
            .leaves()
            .iter()
            .map(Leaf::length_bytes)
            .min()
            .unwrap_or(0);
        if new_disk.length_bytes() < min_leaf_len {
            return ZfsTxOutcome::NotCommitted(FfsError::InvalidGeometry(
                "RAIDZ expansion disk is smaller than existing RAIDZ children".into(),
            ));
        }
        let new_width = width + 1;
        let ashift = self.allocator.ashift;
        let cur_reflow = if self.current_uberblock.raidz_reflow_info != 0 {
            match RaidzReflowInfo::decode(self.current_uberblock.raidz_reflow_info) {
                Ok(info) => info.offset,
                Err(e) => return ZfsTxOutcome::NotCommitted(parse_err(&e)),
            }
        } else {
            0
        };
        let mut pre_mos = match self.open_read_objects(cx) {
            Ok(m) => m,
            Err(err) => return ZfsTxOutcome::NotCommitted(err),
        };
        let live_blocks = match super::scan::collect_pool_blocks(cx, &mut pre_mos) {
            Ok(b) => b,
            Err(err) => return ZfsTxOutcome::NotCommitted(err),
        };
        let total_reflow_bytes = self
            .allocator
            .metaslabs
            .iter()
            .flat_map(|m| m.final_map.ranges())
            .map(|r| r.end)
            .max()
            .unwrap_or(0);

        let next_txg = self.committed_txg.saturating_add(1);
        let mut reflow_cursor = cur_reflow;
        let mut chunks_processed = 0_u64;
        let mut all_leaves = self.pool.leaves().to_vec();
        all_leaves.push(new_disk);

        // Stage reflowed stripes into the crash-safe OpenZFS 3.5 MiB scratch zone
        // (`DATA_OFFSET - VDEV_BOOT_SIZE`, plus `DATA_OFFSET` on the unattached
        // `new_disk`) so committed live `DATA_OFFSET` stripes on existing leaves
        // remain 100% intact across intermediate chunks and `ReflowChunkBarrier` cuts!
        while reflow_cursor < total_reflow_bytes && (chunks_processed as usize) < max_chunks_per_txg
        {
            if let Err(err) = checkpoint(cx) {
                return ZfsTxOutcome::NotCommitted(err);
            }
            let mut next_off = (reflow_cursor + chunk_bytes).min(total_reflow_bytes);
            // Never split a live block across a chunk boundary!
            for item in &live_blocks {
                if let Ok(dvas) = item.bp.data_dvas() {
                    for dva in &dvas {
                        let end = dva.offset.saturating_add(dva.allocated_bytes);
                        if dva.offset >= reflow_cursor && dva.offset < next_off && end > next_off {
                            next_off = end.min(total_reflow_bytes);
                        }
                    }
                }
            }
            let exp_cfg = ExpandedRaidzConfig {
                ashift,
                parity,
                original_width: width,
                physical_width: new_width,
                expand_txgs: vec![next_txg],
                reflow_offset_synced: u64::MAX,
                reflow_offset_next: u64::MAX,
                use_scratch: false,
            };
            for item in &live_blocks {
                let Ok(dvas) = item.bp.data_dvas() else {
                    continue;
                };
                for dva in &dvas {
                    if dva.offset < reflow_cursor || dva.offset >= next_off {
                        continue;
                    }
                    let verified_phys = match pre_mos.read_verified_physical_block(cx, &item.bp) {
                        Ok(b) => b,
                        Err(err) => return ZfsTxOutcome::NotCommitted(err),
                    };
                    let map = match ExpandedRaidzMap::new(
                        &exp_cfg,
                        dva.offset,
                        verified_phys.len(),
                        width,
                    ) {
                        Ok(m) => m,
                        Err(e) => return ZfsTxOutcome::NotCommitted(parse_err(&e)),
                    };
                    let encoded_rows = match map.encode(&verified_phys) {
                        Ok(r) => r,
                        Err(e) => return ZfsTxOutcome::NotCommitted(parse_err(&e)),
                    };
                    for (row, r_bufs) in map.rows().iter().zip(&encoded_rows) {
                        for (col, buf) in row.cols.iter().zip(r_bufs) {
                            if buf.is_empty() || col.child_id >= all_leaves.len() {
                                continue;
                            }
                            let scratch_off = if col.child_id == width {
                                match col.leaf_byte_offset() {
                                    Ok(o) => o,
                                    Err(e) => return ZfsTxOutcome::NotCommitted(parse_err(&e)),
                                }
                            } else {
                                let scratch_base =
                                    DATA_OFFSET - ffs_ondisk::zfs::raidz::expand::VDEV_BOOT_SIZE;
                                let max_scratch = ffs_ondisk::zfs::raidz::expand::VDEV_BOOT_SIZE
                                    .saturating_sub(buf.len() as u64);
                                scratch_base + (col.offset % max_scratch.max(1))
                            };
                            if let Err(err) = self.emit_event(
                                "zfs_pool_expand_raidz",
                                ZfsPersistenceStage::ReflowChunkWrite {
                                    member_index: col.child_id,
                                },
                                next_txg,
                                col.child_id,
                                scratch_off,
                                buf.len(),
                            ) {
                                return ZfsTxOutcome::NotCommitted(err);
                            }
                            if let Err(err) =
                                all_leaves[col.child_id].write_raw(cx, scratch_off, buf)
                            {
                                return ZfsTxOutcome::NotCommitted(err);
                            }
                        }
                    }
                }
            }
            for (m_idx, leaf) in all_leaves.iter().enumerate() {
                if let Err(err) = self.emit_event(
                    "zfs_pool_expand_raidz",
                    ZfsPersistenceStage::ReflowChunkBarrier {
                        member_index: m_idx,
                    },
                    next_txg,
                    m_idx,
                    0,
                    0,
                ) {
                    return ZfsTxOutcome::NotCommitted(err);
                }
                if let Err(err) = leaf.sync_raw(cx) {
                    return ZfsTxOutcome::NotCommitted(err);
                }
            }
            reflow_cursor = next_off;
            chunks_processed += 1;
        }

        let completed = reflow_cursor >= total_reflow_bytes;
        let reflow_info = RaidzReflowInfo {
            offset: if completed { 0 } else { reflow_cursor },
            state: if completed {
                RaidzReflowScratchState::InvalidSyncedReflow
            } else {
                RaidzReflowScratchState::InvalidSynced
            },
        };
        let encoded_reflow = match reflow_info.encode() {
            Ok(v) => v,
            Err(e) => return ZfsTxOutcome::NotCommitted(parse_err(&e)),
        };

        let prev_reflow_raw = self.current_uberblock.raidz_reflow_info;
        self.current_uberblock.raidz_reflow_info = encoded_reflow;
        let order = self.order;

        if !completed {
            let mut inter_labels = Vec::with_capacity(self.pool.leaves().len());
            for leaf in self.pool.leaves() {
                let mut lbl_cfg = match leaf.label(cx, 0) {
                    Ok(l) => l.config,
                    Err(err) => {
                        self.current_uberblock.raidz_reflow_info = prev_reflow_raw;
                        return ZfsTxOutcome::NotCommitted(err);
                    }
                };
                lbl_cfg
                    .fields
                    .insert("txg".to_owned(), Value::Unsigned(next_txg));
                let mut rf_list = lbl_cfg
                    .list("features_for_read")
                    .cloned()
                    .unwrap_or_else(|| nv_list(Vec::new()));
                rf_list.fields.insert(
                    "org.openzfs:raidz_expansion".to_owned(),
                    Value::Boolean(true),
                );
                lbl_cfg
                    .fields
                    .insert("features_for_read".to_owned(), Value::List(rf_list));
                match lbl_cfg.encode_xdr() {
                    Ok(b) => inter_labels.push(b),
                    Err(e) => {
                        self.current_uberblock.raidz_reflow_info = prev_reflow_raw;
                        return ZfsTxOutcome::NotCommitted(parse_err(&e));
                    }
                }
            }
            let outcome = self.execute_staged_txg_with_mos(
                cx,
                "zfs_pool_expand_raidz",
                Some(pre_mos),
                &[],
                |_mos, _mos_dirty, features, _alloc, txg, _staged| {
                    features
                        .read_features
                        .insert("org.openzfs:raidz_expansion".to_owned(), 1);
                    features.read_dirty = true;
                    Ok((
                        ZfsExpandRaidzReport {
                            old_width: width,
                            new_width,
                            parity,
                            reflow_offset: reflow_cursor,
                            total_reflow_bytes,
                            chunks_processed,
                            completed: false,
                            txg,
                        },
                        reflow_cursor,
                    ))
                },
            );
            if outcome.is_committed() {
                if let Err(err) =
                    self.publish_labels_2wave(cx, "zfs_pool_expand_raidz", next_txg, &inter_labels)
                {
                    return ZfsTxOutcome::Uncertain {
                        reason: err,
                        target_txg: next_txg,
                        target_slot: (next_txg as usize) % self.slots_per_label,
                    };
                }
                return outcome;
            }
            self.current_uberblock.raidz_reflow_info = prev_reflow_raw;
            return outcome;
        }

        // Reflow reached `total_reflow_bytes`: compute complete 4-disk expanded
        // stripes for every live pre-expansion block in memory, promote topology
        // to `new_width`, commit new MOS + uberblock, and publish 2-wave labels!
        let final_exp_cfg = ExpandedRaidzConfig {
            ashift,
            parity,
            original_width: width,
            physical_width: new_width,
            expand_txgs: vec![next_txg],
            reflow_offset_synced: u64::MAX,
            reflow_offset_next: u64::MAX,
            use_scratch: false,
        };
        let mut pre_commit_writes: Vec<(usize, u64, Vec<u8>)> = Vec::new();
        for item in &live_blocks {
            let Ok(dvas) = item.bp.data_dvas() else {
                continue;
            };
            for dva in &dvas {
                let verified_phys = match pre_mos.read_verified_physical_block(cx, &item.bp) {
                    Ok(b) => b,
                    Err(err) => {
                        self.current_uberblock.raidz_reflow_info = prev_reflow_raw;
                        return ZfsTxOutcome::NotCommitted(err);
                    }
                };
                let map = match ExpandedRaidzMap::new(
                    &final_exp_cfg,
                    dva.offset,
                    verified_phys.len(),
                    width,
                ) {
                    Ok(m) => m,
                    Err(e) => {
                        self.current_uberblock.raidz_reflow_info = prev_reflow_raw;
                        return ZfsTxOutcome::NotCommitted(parse_err(&e));
                    }
                };
                let encoded_rows = match map.encode(&verified_phys) {
                    Ok(r) => r,
                    Err(e) => {
                        self.current_uberblock.raidz_reflow_info = prev_reflow_raw;
                        return ZfsTxOutcome::NotCommitted(parse_err(&e));
                    }
                };
                for (row, r_bufs) in map.rows().iter().zip(&encoded_rows) {
                    for (col, buf) in row.cols.iter().zip(r_bufs) {
                        if buf.is_empty() || col.child_id >= all_leaves.len() {
                            continue;
                        }
                        let leaf_off = match col.leaf_byte_offset() {
                            Ok(o) => o,
                            Err(e) => {
                                self.current_uberblock.raidz_reflow_info = prev_reflow_raw;
                                return ZfsTxOutcome::NotCommitted(parse_err(&e));
                            }
                        };
                        pre_commit_writes.push((col.child_id, leaf_off, buf.clone()));
                    }
                }
            }
        }

        let new_child_guid = self
            .storage_identity
            .member_guids
            .iter()
            .copied()
            .max()
            .unwrap_or(self.storage_identity.top_guid)
            .wrapping_add(0x307);
        let mut new_member_guids = self.storage_identity.member_guids.clone();
        new_member_guids.push(new_child_guid);
        let new_guid_sum = new_member_guids.iter().fold(
            self.storage_identity
                .pool_guid
                .wrapping_add(self.storage_identity.top_guid),
            |acc, &g| acc.wrapping_add(g),
        );
        let new_asize = (self.storage_identity.asize / (width as u64)) * (new_width as u64);

        let template_lbl = match self.pool.leaves()[0].label(cx, 0) {
            Ok(l) => l.config,
            Err(err) => {
                self.current_uberblock.raidz_reflow_info = prev_reflow_raw;
                return ZfsTxOutcome::NotCommitted(err);
            }
        };
        let Some(mut updated_top_tree) = template_lbl.list("vdev_tree").cloned() else {
            self.current_uberblock.raidz_reflow_info = prev_reflow_raw;
            return ZfsTxOutcome::NotCommitted(corrupt("missing RAIDZ vdev_tree"));
        };
        updated_top_tree
            .fields
            .insert("asize".to_owned(), Value::Unsigned(new_asize));
        updated_top_tree.fields.insert(
            "raidz_expand_txgs".to_owned(),
            Value::UnsignedArray(vec![next_txg]),
        );
        if let Some(Value::Lists(kids)) = updated_top_tree.fields.get_mut("children")
            && kids.len() == width
        {
            kids.push(nv_list(vec![
                ("type", Value::String("file".into())),
                ("id", Value::Unsigned(width as u64)),
                ("guid", Value::Unsigned(new_child_guid)),
                ("path", Value::String(format!("/dev/ffs-raidz-{width}"))),
            ]));
        }

        let mut encoded_labels = Vec::with_capacity(new_member_guids.len());
        for &g in &new_member_guids {
            let mut lbl_cfg = template_lbl.clone();
            lbl_cfg
                .fields
                .insert("txg".to_owned(), Value::Unsigned(next_txg));
            lbl_cfg.fields.insert("guid".to_owned(), Value::Unsigned(g));
            lbl_cfg.fields.insert(
                "vdev_tree".to_owned(),
                Value::List(updated_top_tree.clone()),
            );
            let mut rf_list = lbl_cfg
                .list("features_for_read")
                .cloned()
                .unwrap_or_else(|| nv_list(Vec::new()));
            rf_list.fields.insert(
                "org.openzfs:raidz_expansion".to_owned(),
                Value::Boolean(true),
            );
            lbl_cfg
                .fields
                .insert("features_for_read".to_owned(), Value::List(rf_list));
            match lbl_cfg.encode_xdr() {
                Ok(b) => encoded_labels.push(b),
                Err(e) => {
                    self.current_uberblock.raidz_reflow_info = prev_reflow_raw;
                    return ZfsTxOutcome::NotCommitted(parse_err(&e));
                }
            }
        }

        let new_pool = match crate::Pool::from_wide_leaves(all_leaves) {
            Ok(p) => p,
            Err(err) => {
                self.current_uberblock.raidz_reflow_info = prev_reflow_raw;
                return ZfsTxOutcome::NotCommitted(err);
            }
        };
        let mut new_offs = Vec::with_capacity(new_pool.leaves().len());
        for leaf in new_pool.leaves() {
            match label_offsets(leaf.length_bytes()) {
                Ok(o) => new_offs.push(o),
                Err(e) => {
                    self.current_uberblock.raidz_reflow_info = prev_reflow_raw;
                    return ZfsTxOutcome::NotCommitted(parse_err(&e));
                }
            }
        }

        let old_pool = std::mem::replace(&mut self.pool, new_pool);
        let old_offs = std::mem::replace(&mut self.label_offsets_per_member, new_offs);
        let old_id = self.storage_identity.clone();
        let old_write_topo = self.allocator.write_topology.clone();

        self.storage_identity.member_guids = new_member_guids;
        self.storage_identity.guid_sum = new_guid_sum;
        self.storage_identity.asize = new_asize;
        self.storage_identity.topology = ZfsTopologyKind::Raidz {
            parity,
            width: new_width,
        };
        self.storage_identity.member_dev_inos.push(None);
        self.allocator.write_topology = AllocatorWriteTopology::Raidz {
            parity,
            width: new_width,
        };

        let tree_for_mos = updated_top_tree;
        let outcome = self.execute_staged_txg_with_mos(
            cx,
            "zfs_pool_expand_raidz",
            Some(pre_mos),
            &pre_commit_writes,
            |mos, mos_dirty, features, alloc, txg, staged| {
                features
                    .read_features
                    .insert("org.openzfs:raidz_expansion".to_owned(), 1);
                features.read_dirty = true;
                update_mos_config_top_tree(
                    cx,
                    mos,
                    mos_dirty,
                    alloc,
                    order,
                    txg,
                    0,
                    tree_for_mos,
                    staged,
                )?;
                Ok((
                    ZfsExpandRaidzReport {
                        old_width: width,
                        new_width,
                        parity,
                        reflow_offset: reflow_cursor,
                        total_reflow_bytes,
                        chunks_processed,
                        completed: true,
                        txg,
                    },
                    reflow_cursor,
                ))
            },
        );
        if outcome.is_committed() {
            if let Err(err) =
                self.publish_labels_2wave(cx, "zfs_pool_expand_raidz", next_txg, &encoded_labels)
            {
                return ZfsTxOutcome::Uncertain {
                    reason: err,
                    target_txg: next_txg,
                    target_slot: (next_txg as usize) % self.slots_per_label,
                };
            }
            return outcome;
        }
        self.pool = old_pool;
        self.label_offsets_per_member = old_offs;
        self.storage_identity = old_id;
        self.allocator.write_topology = old_write_topo;
        self.current_uberblock.raidz_reflow_info = prev_reflow_raw;
        outcome
    }
}

#[allow(clippy::too_many_arguments)]
fn update_mos_config_top_tree(
    cx: &Cx,
    mos: &mut crate::reader::dmu::Objects,
    mos_dirty: &mut BTreeMap<u64, Vec<u8>>,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    vdev_index: usize,
    new_top_tree: NvList,
    staged: &mut Vec<StagedBlockWrite>,
) -> Result<()> {
    let mut mos_cfg = mos.load_mos_config_nvlist(cx)?;
    mos_cfg
        .fields
        .insert("txg".to_owned(), Value::Unsigned(new_txg));
    let Some(Value::List(root)) = mos_cfg.fields.get_mut("vdev_tree") else {
        return Err(corrupt("MOS config missing vdev_tree"));
    };
    let Some(Value::Lists(children)) = root.fields.get_mut("children") else {
        return Err(corrupt("MOS config missing vdev_tree children"));
    };
    let slot = children
        .get_mut(vdev_index)
        .ok_or_else(|| corrupt("vdev_index out of bounds in MOS config"))?;
    *slot = new_top_tree;
    write_mos_config_nvlist(cx, mos, mos_dirty, alloc, order, new_txg, &mos_cfg, staged)
}

#[allow(clippy::too_many_arguments)]
fn write_mos_config_nvlist(
    cx: &Cx,
    mos: &mut crate::reader::dmu::Objects,
    mos_dirty: &mut BTreeMap<u64, Vec<u8>>,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    mos_cfg: &NvList,
    staged: &mut Vec<StagedBlockWrite>,
) -> Result<()> {
    let dir = mos.zap_values(cx, 1)?;
    let cfg_id = zap_required_u64(&dir, b"config")?;
    let _ = zap_optional_u64(&dir, b"root_dataset")?;
    let (cfg_dn, cfg_ceil) = mos.object_with_ceiling(cx, cfg_id)?;
    let packed = mos_cfg.encode_xdr().map_err(|e| parse_err(&e))?;
    let cfg_len = packed.len() as u64;
    let bsize = cfg_dn.data_bytes().max(4096);
    let num_blocks = packed.len().div_ceil(bsize).max(1);
    let mut dirty = BTreeMap::new();
    for bid in 0..num_blocks {
        let s = bid * bsize;
        let e = (s + bsize).min(packed.len());
        let mut blk = vec![0_u8; bsize];
        if s < e {
            blk[..e - s].copy_from_slice(&packed[s..e]);
        }
        dirty.insert(bid as u64, Some(blk));
    }
    let out = cow_update_dnode(
        cx,
        mos,
        alloc,
        DnodeCowSpec {
            existing: Some((&cfg_dn, cfg_ceil)),
            object_type: DMU_OT_PACKED_NVLIST,
            bonus_type: 4,
            checksum_type: cfg_dn.checksum_type(),
            compress_type: cfg_dn.compress_type(),
            user_flags: cfg_dn.flags(),
            indirect_shift: cfg_dn.indirect_shift(),
            data_bytes: bsize,
            max_block: (num_blocks - 1) as u64,
            slots: cfg_dn.slots(),
            nblkptr: cfg_dn.pointers().len(),
            bonus: order.encode(cfg_len).to_vec(),
            spill: None,
            order,
            new_txg,
            leaf_bucket: WriteBucket::MosSpaceMap,
            indirect_bucket: WriteBucket::MosSpaceMap,
        },
        &dirty,
        staged,
    )?;
    for rbp in &out.retired_bps {
        alloc.free_block_dvas(rbp, new_txg)?;
    }
    let mos_meta = mos.meta_dnode().clone();
    let mos_ceil = mos.root_birth_txg();
    put_dnode_in_table(cx, mos, &mos_meta, mos_ceil, mos_dirty, cfg_id, &out.dnode)
}
