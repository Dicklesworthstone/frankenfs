//! Native writable ZFS ZVOL lifecycle (`zvol_create`, `zvol_destroy`, `zvol_resize`,
//! `zvol_snapshot`, `zvol_info`) and sector-aligned DMU block I/O (`zvol_read_at`,
//! `zvol_write_at`, `zvol_discard`, `zvol_batch_apply`, `zvol_flush`).
//!
//! Pinned to OpenZFS `zfs-2.3.0` (`zvol.h` / `zvol.c`):
//! - `ObjectSet::kind == 3` (`DMU_OST_ZVOL`), `flags == 0`, with **no** embedded
//!   `userused` / `groupused` / `projectused` dnodes.
//! - Object `1` (`ZVOL_OBJ`, `DMU_OT_ZVOL = 23`): logical volume data blocks of
//!   size `volblocksize` (power of two in `512..=1_048_576`).
//! - Object `2` (`ZVOL_ZAP_OBJ`, `DMU_OT_ZVOL_PROP = 24`): micro-ZAP storing
//!   `"size" -> volsize` (`u64`, exact multiple of `volblocksize`).

use std::collections::{BTreeMap, BTreeSet};

use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_ondisk::zfs::{BlockPointer, Endian, RegularBlockSpec};
use ffs_ondisk::zfs_dmu::{
    DMU_OT_DNODE, DNODE_BLOCK_BYTES, DNODE_FLAG_USED_BYTES, Dnode, DnodeSpec, ObjectSet, ZilHeader,
};
use ffs_ondisk::zfs_zap::Entry as RawZapEntry;
use ffs_ondisk::zfs_zpl::Timestamp;
use serde::Serialize;

use crate::reader::dmu::Objects;
use crate::reader::dmu::properties::PropertyValue;

use super::dmu_cow::{
    DMU_OT_OBJSET, DnodeCowSpec, MosFeatureState, PoolSpaceAllocator, SpaceDelta, StagedBlockWrite,
    WriteBucket, allocate_object_id, cow_update_dnode, encode_zap_blocks_for_dnode,
    enqueue_into_dataset_deadlist, put_dnode_in_table, read_staged_or_committed_dnode,
    zap_required_u64,
};
use super::dsl_ops::{
    DD_FLAG_USED_BREAKDOWN, DMU_OT_DSL_DATASET, DMU_OT_DSL_DIR_CHILD_MAP, DMU_OT_DSL_DS_SNAP_MAP,
    DMU_OTN_ZAP_METADATA, DS_FLAG_UNIQUE_ACCURATE, allocate_fresh_deadlist,
    apply_properties_batch_on_ids, bump_filesystem_limits_counter_if_present, derive_fsid_guid,
    derive_unique_guid, effective_local_numeric_prop, enforce_dataset_quotas_for_growth,
    enforce_pool_reservations_for_growth, link_dataset_to_origin_snapshot,
    lookup_pool_origin_snapshot, propagate_dsl_dir_space_delta, put_new_dsl_dir_in_mos,
    reject_einval, require_filesystem_parent, resolve_dataset_ids, stage_create_snapshot,
    stage_destroy_dataset, validate_dsl_component, write_zap_dnode_in_mos,
};
use super::zpl_ops::ZfsDataChecksum;
use super::{
    ZfsDurableToken, ZfsPropertySetValue, ZfsStorageIdentity, checkpoint, corrupt, parse_err,
    unsupported,
};

pub const ZVOL_OBJ: u64 = 1;
pub const ZVOL_ZAP_OBJ: u64 = 2;
pub const DMU_OT_ZVOL: u8 = 23;
pub const DMU_OT_ZVOL_PROP: u8 = 24;
pub const OBJSET_TYPE_ZVOL: u64 = 3;
pub const ZVOL_LOGICAL_SECTOR_BYTES: usize = 512;
pub const DEFAULT_VOLBLOCKSIZE: u32 = 16_384;
pub const MAX_VOLBLOCKSIZE: usize = 1_048_576;
pub const MAX_ZVOL_IO_BYTES: usize = 16 * 1024 * 1024;

/// Creation parameters for [`super::ZfsTransactionEngine::zvol_create`].
#[derive(Debug, Clone)]
pub struct ZfsZvolCreateOptions {
    /// Logical volume capacity in bytes (`> 0`, `<= i64::MAX`, exact multiple of `volblocksize`).
    pub volsize: u64,
    /// Native DMU block size in bytes (power of two in `512..=1_048_576`, default `16_384`).
    pub volblocksize: u32,
    /// When `false` and `initial_props` does not explicitly set `"refreservation"`,
    /// sets `refreservation = volsize` matching OpenZFS thick-provisioned ZVOL creation.
    pub sparse: bool,
    /// Optional local properties applied atomically in the creation TXG.
    pub initial_props: Vec<(String, ZfsPropertySetValue)>,
    /// Creation timestamp recorded on the MOS `dsl_dir` and `dsl_dataset`.
    pub timestamp: Timestamp,
}

impl Default for ZfsZvolCreateOptions {
    fn default() -> Self {
        Self {
            volsize: 1024 * 1024,
            volblocksize: DEFAULT_VOLBLOCKSIZE,
            sparse: true,
            initial_props: Vec::new(),
            timestamp: Timestamp {
                seconds: 1_710_000_000,
                nanos: 0,
            },
        }
    }
}

/// Geometry, dataset identity, and committed TXG metadata of a native ZFS ZVOL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZfsZvolInfo {
    pub pool_guid: u64,
    pub dataset_guid: u64,
    pub head_object: u64,
    pub directory_object: u64,
    pub committed_txg: u64,
    pub root_birth: u64,
    pub volsize: u64,
    pub volblocksize: usize,
    pub dnode_used_bytes: u64,
    pub referenced_bytes: u64,
    pub readonly: bool,
}

/// Durable commit receipt returned by native ZVOL writes, discards, batch commits, and flushes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZfsCommitReceipt {
    pub storage: ZfsStorageIdentity,
    pub committed_txg: u64,
    pub published_slot: usize,
    pub generation: u64,
    /// Present when a new TXG was published by this operation or flush;
    /// `None` only when flushing an already-clean handle after `sync_devices` succeeds.
    pub token: Option<ZfsDurableToken>,
    pub tx_published: bool,
}

struct ZvolContext {
    head_object: u64,
    directory_object: u64,
    prev_snap_txg: u64,
    deadlist_obj: u64,
    old_os_bp: BlockPointer,
    os: ObjectSet,
    data_dnode: Dnode,
    data_ceiling: u64,
    prop_dnode: Dnode,
    prop_ceiling: u64,
    volsize: u64,
    volblocksize: usize,
}

fn validate_sector_span(offset: u64, len: u64, volsize: u64, max_bytes: usize) -> Result<()> {
    if !offset.is_multiple_of(ZVOL_LOGICAL_SECTOR_BYTES as u64)
        || !len.is_multiple_of(ZVOL_LOGICAL_SECTOR_BYTES as u64)
    {
        return Err(reject_einval(
            "ZVOL block I/O offset and length must be 512-byte sector aligned",
        ));
    }
    if len > max_bytes as u64 {
        return Err(reject_einval(
            "ZVOL block I/O request exceeds 16 MiB maximum transfer size",
        ));
    }
    if offset.checked_add(len).is_none_or(|end| end > volsize) {
        return Err(reject_einval(
            "ZVOL block I/O range exceeds volume capacity",
        ));
    }
    Ok(())
}

fn effective_readonly(cx: &Cx, mos: &mut Objects, dataset: &[Vec<u8>]) -> Result<bool> {
    let properties = mos.properties(cx, dataset, None, &["readonly".into()])?;
    match properties
        .values
        .first()
        .and_then(|property| property.value.as_ref())
    {
        Some(PropertyValue::Number(0)) => Ok(false),
        Some(PropertyValue::Number(1)) => Ok(true),
        _ => Err(corrupt(
            "missing or invalid effective ZFS readonly property",
        )),
    }
}

fn open_zvol_head_context(
    cx: &Cx,
    mos: &mut Objects,
    dataset: &[Vec<u8>],
    commit_order: Endian,
) -> Result<(ZvolContext, Objects)> {
    checkpoint(cx)?;
    let ds_row = mos
        .datasets(cx)?
        .into_iter()
        .find(|d| d.components == dataset)
        .ok_or_else(|| FfsError::NotFound("ZFS volume dataset".into()))?;
    if ds_row.objectset_kind != Some(OBJSET_TYPE_ZVOL) {
        return Err(reject_einval("selected ZFS dataset is not a volume (ZVOL)"));
    }
    if ds_row.flags & 0x1_0000 != 0 {
        return Err(unsupported(
            "native ZVOL writes refuse inconsistent datasets",
        ));
    }
    if effective_readonly(cx, mos, dataset)? {
        return Err(FfsError::ReadOnly);
    }

    let (head_dn, head_ceiling) = mos.object_with_ceiling(cx, ds_row.head_object)?;
    let order = head_dn.order();
    let prev_snap_txg = order.u64(head_dn.bonus(), 16).map_err(|e| parse_err(&e))?;
    let deadlist_obj = order.u64(head_dn.bonus(), 64).map_err(|e| parse_err(&e))?;
    let old_os_bp =
        BlockPointer::parse(&head_dn.bonus()[128..256], order).map_err(|e| parse_err(&e))?;
    let (os_raw, os_order, _) = mos
        .checked_raw(
            cx,
            &old_os_bp,
            DMU_OT_OBJSET,
            0,
            old_os_bp.logical_bytes(),
            head_ceiling,
        )?
        .ok_or_else(|| corrupt("ZVOL head object set is a hole"))?;
    let mut os = ObjectSet::parse(&os_raw, os_order).map_err(|e| parse_err(&e))?;
    if os.kind != OBJSET_TYPE_ZVOL {
        return Err(corrupt("selected dataset is not a ZVOL object set"));
    }
    // ObjectSet::encode retains raw tail bytes; native mutation cannot convert
    // their byte order by merely replacing the meta-dnode and outer header.
    if os_order != commit_order {
        return Err(unsupported(
            "rewriting a mixed-order native ZVOL object set",
        ));
    }
    if mos.dataset_has_pending_zil_work(
        cx,
        ds_row.head_object,
        ds_row.guid,
        &head_dn,
        &old_os_bp,
        &os_raw,
        os_order,
        &os,
    )? {
        return Err(unsupported(
            "pending ZIL intent log requires replay before native ZVOL TXG write",
        ));
    }
    if mos.is_inherited_snapshot_zil(cx, &head_dn, &old_os_bp, &os_raw, os_order, &os)?
        && os_order
            .u64(&os_raw[528..656], 112)
            .map_err(|e| parse_err(&e))?
            != ds_row.head_object
    {
        os.zil_header = ZilHeader::empty();
    }

    let mut os_view = mos.open_objectset_view(os.meta.clone(), old_os_bp.birth(), mos.txg);
    let (data_dnode, data_ceiling) = os_view.object_with_ceiling(cx, ZVOL_OBJ)?;
    let (prop_dnode, prop_ceiling) = os_view.object_with_ceiling(cx, ZVOL_ZAP_OBJ)?;
    for (dn, expected_ot) in [(&data_dnode, DMU_OT_ZVOL), (&prop_dnode, DMU_OT_ZVOL_PROP)] {
        if dn.object_type() != expected_ot
            || dn.bonus_type() != 0
            || !dn.bonus().is_empty()
            || dn.spill().is_some()
        {
            return Err(corrupt("invalid native ZVOL data or property dnode"));
        }
    }
    let prop_rows = os_view.zap_values(cx, ZVOL_ZAP_OBJ)?;
    let volsize = zap_required_u64(&prop_rows, b"size")?;
    let volblocksize = data_dnode.data_bytes();
    if !(ZVOL_LOGICAL_SECTOR_BYTES..=MAX_VOLBLOCKSIZE).contains(&volblocksize)
        || !volblocksize.is_power_of_two()
        || volsize == 0
        || !volsize.is_multiple_of(volblocksize as u64)
    {
        return Err(corrupt("invalid native ZVOL capacity or volblocksize"));
    }

    let ctx = ZvolContext {
        head_object: ds_row.head_object,
        directory_object: ds_row.directory_object,
        prev_snap_txg,
        deadlist_obj,
        old_os_bp,
        os,
        data_dnode,
        data_ceiling,
        prop_dnode,
        prop_ceiling,
        volsize,
        volblocksize,
    };
    Ok((ctx, os_view))
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn finalize_zvol_to_mos(
    cx: &Cx,
    mos: &mut Objects,
    ctx: &mut ZvolContext,
    os_view: &mut Objects,
    zvol_meta_base: &Dnode,
    zvol_ceiling: u64,
    zvol_dirty_dnodes: &BTreeMap<u64, Vec<u8>>,
    born_initial: &SpaceDelta,
    retired_initial: &[BlockPointer],
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    features: &mut MosFeatureState,
    empty_bpobj_id: Option<u64>,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
    result_val: u64,
) -> Result<u64> {
    let mut born = *born_initial;
    let mut retired = retired_initial.to_vec();

    // 1. COW `os.meta` (`DMU_OT_DNODE`) and `ObjectSet` root (`DMU_OT_OBJSET`).
    let mut meta_dirty = BTreeMap::new();
    for (&bid, blk) in zvol_dirty_dnodes {
        meta_dirty.insert(bid, Some(blk.clone()));
    }
    let meta_max_block = zvol_meta_base
        .max_block()
        .max(zvol_dirty_dnodes.keys().copied().max().unwrap_or(0));
    let meta_out = cow_update_dnode(
        cx,
        os_view,
        alloc,
        DnodeCowSpec {
            existing: Some((zvol_meta_base, zvol_ceiling)),
            object_type: DMU_OT_DNODE,
            bonus_type: 0,
            checksum_type: 7,
            compress_type: 2,
            user_flags: 0,
            indirect_shift: zvol_meta_base.indirect_shift(),
            data_bytes: DNODE_BLOCK_BYTES,
            max_block: meta_max_block,
            slots: 1,
            nblkptr: 3,
            bonus: Vec::new(),
            spill: None,
            order,
            new_txg,
            leaf_bucket: WriteBucket::DatasetMetadata,
            indirect_bucket: WriteBucket::DatasetMetadata,
        },
        &meta_dirty,
        staged_writes,
    )?;
    born.add_assign(meta_out.born)?;
    retired.extend(meta_out.retired_bps);

    ctx.os.meta = meta_out.dnode;
    let os_bytes = ctx.os.encode(order).map_err(|e| parse_err(&e))?;
    let os_fill = ctx.os.meta_fill();
    let os_dva = alloc.allocate(os_bytes.len())?;
    let os_cksum = if matches!(ctx.old_os_bp.checksum_type(), 6..=8) {
        ctx.old_os_bp.checksum_type()
    } else {
        7
    };
    let new_os_bp = BlockPointer::new_regular(&RegularBlockSpec {
        dvas: &[os_dva],
        physical: &os_bytes,
        logical_bytes: os_bytes.len(),
        compression: 2,
        checksum_type: os_cksum,
        object_type: DMU_OT_OBJSET,
        level: 0,
        payload_order: order,
        birth: new_txg,
        fill: os_fill,
    })
    .map_err(|e| parse_err(&e))?;
    born.add_assign(SpaceDelta::from_bp(&new_os_bp)?)?;
    staged_writes.push(StagedBlockWrite {
        bucket: WriteBucket::DatasetMetadata,
        dva_offset: os_dva.offset,
        bytes: os_bytes,
    });
    retired.push(ctx.old_os_bp.clone());

    // 2. Partition retired BPs at `prev_snap_txg`.
    let mut killed_free = SpaceDelta::default();
    let mut killed_snap = SpaceDelta::default();
    let mut snap_bps = Vec::new();
    for rbp in &retired {
        if rbp.hole() || rbp.embedded() {
            continue;
        }
        if rbp.birth() > ctx.prev_snap_txg {
            let d = alloc.free_block_dvas(rbp, new_txg)?;
            killed_free.add_assign(d)?;
        } else {
            killed_snap.add_assign(SpaceDelta::from_bp(rbp)?)?;
            snap_bps.push(rbp.clone());
        }
    }

    let ref_add = born
        .dsize
        .saturating_sub(killed_free.dsize + killed_snap.dsize);
    let used_add = born.dsize.saturating_sub(killed_free.dsize);
    if ref_add > 0 || used_add > 0 {
        enforce_dataset_quotas_for_growth(
            cx,
            mos,
            mos_dirty_dnodes,
            ctx.head_object,
            ctx.directory_object,
            ref_add,
            used_add,
            order,
        )?;
        if used_add > 0 {
            enforce_pool_reservations_for_growth(
                cx,
                mos,
                mos_dirty_dnodes,
                ctx.head_object,
                ctx.directory_object,
                used_add,
                0,
                alloc.total_free_bytes(),
                order,
            )?;
        }
    }

    if !snap_bps.is_empty() {
        enqueue_into_dataset_deadlist(
            cx,
            mos,
            mos_dirty_dnodes,
            &mut features.write_features,
            &mut features.write_dirty,
            empty_bpobj_id,
            ctx.deadlist_obj,
            &snap_bps,
            alloc,
            order,
            new_txg,
            staged_writes,
        )?;
    }

    // 3. Update MOS `dsl_dataset` (`head_object`) and `dsl_dir` ancestor accounting.
    let mos_meta = mos.meta_dnode().clone();
    let mos_ceiling = mos.root_birth_txg();
    let (head_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        ctx.head_object,
        order,
    )?;
    let mut head_bonus = head_dn.bonus().to_vec();
    let old_unique = order.u64(&head_bonus, 96).map_err(|e| parse_err(&e))?;
    let apply_u64_delta =
        |buf: &mut [u8], at: usize, add: u64, sub: u64, label: &'static str| -> Result<u64> {
            let cur = order.u64(buf, at).map_err(|e| parse_err(&e))?;
            let next = cur
                .checked_add(add)
                .and_then(|v| v.checked_sub(sub))
                .ok_or_else(|| corrupt(format!("{label} accounting underflow/overflow")))?;
            buf[at..at + 8].copy_from_slice(&order.encode(next));
            Ok(next)
        };

    apply_u64_delta(
        &mut head_bonus,
        72,
        born.dsize,
        killed_free.dsize + killed_snap.dsize,
        "ds_referenced_bytes",
    )?;
    apply_u64_delta(
        &mut head_bonus,
        80,
        born.comp,
        killed_free.comp + killed_snap.comp,
        "ds_compressed_bytes",
    )?;
    apply_u64_delta(
        &mut head_bonus,
        88,
        born.uncomp,
        killed_free.uncomp + killed_snap.uncomp,
        "ds_uncompressed_bytes",
    )?;
    let new_unique = apply_u64_delta(
        &mut head_bonus,
        96,
        born.dsize,
        killed_free.dsize,
        "ds_unique_bytes",
    )?;
    head_bonus[128..256].copy_from_slice(&new_os_bp.encode(order));
    let mut updated_head = head_dn;
    let head_btype = updated_head.bonus_type();
    updated_head
        .set_bonus_and_spill(head_btype, head_bonus, None)
        .map_err(|e| parse_err(&e))?;
    put_dnode_in_table(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        ctx.head_object,
        &updated_head,
    )?;

    // Exact signed delta propagation (supporting both growth and shrink/discard with
    // thick `refreservation` consumption AND restoration!).
    let (own_dd_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        ctx.directory_object,
        order,
    )?;
    let own_dd_flags = order
        .u64(own_dd_dn.bonus(), 96)
        .map_err(|e| parse_err(&e))?;
    let own_props_zap = order
        .u64(own_dd_dn.bonus(), 80)
        .map_err(|e| parse_err(&e))?;
    let refreservation = if own_dd_flags & DD_FLAG_USED_BREAKDOWN != 0 && own_props_zap != 0 {
        let rows = mos.zap_values(cx, own_props_zap)?;
        effective_local_numeric_prop(&rows, "refreservation")?.unwrap_or(0)
    } else {
        0
    };
    let refrsrv_delta = if own_dd_flags & DD_FLAG_USED_BREAKDOWN != 0 && refreservation > 0 {
        let old_rr = refreservation.saturating_sub(old_unique);
        let new_rr = refreservation.saturating_sub(new_unique);
        i128::from(new_rr) - i128::from(old_rr)
    } else {
        0
    };

    let head_dsize_delta =
        i128::from(born.dsize) - i128::from(killed_free.dsize) - i128::from(killed_snap.dsize);
    let snap_dsize_delta = i128::from(killed_snap.dsize);
    let comp_delta = i128::from(born.comp) - i128::from(killed_free.comp);
    let uncomp_delta = i128::from(born.uncomp) - i128::from(killed_free.uncomp);

    propagate_dsl_dir_space_delta(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        ctx.directory_object,
        head_dsize_delta,
        snap_dsize_delta,
        0,
        0,
        refrsrv_delta,
        comp_delta,
        uncomp_delta,
        order,
    )?;

    Ok(result_val)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn stage_create_zvol(
    cx: &Cx,
    mos: &mut Objects,
    parent_dataset: &[Vec<u8>],
    child_name: &[u8],
    opts: &ZfsZvolCreateOptions,
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    features: &mut MosFeatureState,
    empty_bpobj_id: Option<u64>,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<(ZfsZvolInfo, u64)> {
    validate_dsl_component(child_name, false)?;
    let volblocksize = opts.volblocksize as usize;
    if !(ZVOL_LOGICAL_SECTOR_BYTES..=MAX_VOLBLOCKSIZE).contains(&volblocksize)
        || !volblocksize.is_power_of_two()
    {
        return Err(reject_einval(
            "ZVOL volblocksize must be a power of two in 512..=1048576",
        ));
    }
    if opts.volsize == 0
        || i64::try_from(opts.volsize).is_err()
        || !opts.volsize.is_multiple_of(u64::from(opts.volblocksize))
    {
        return Err(reject_einval(
            "ZVOL volsize must be non-zero, <= i64::MAX, and a multiple of volblocksize",
        ));
    }

    require_filesystem_parent(cx, mos, parent_dataset)?;
    let (parent_dd_obj, parent_head_obj, pool_guid) = resolve_dataset_ids(cx, mos, parent_dataset)?;
    let parent_readonly = effective_readonly(cx, mos, parent_dataset)?;
    let mos_meta = mos.meta_dnode().clone();
    let mos_ceiling = mos.root_birth_txg();

    let (p_dd_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        parent_dd_obj,
        order,
    )?;
    let p_child_zap = order.u64(p_dd_dn.bonus(), 32).map_err(|e| parse_err(&e))?;
    let mut p_children = mos.zap_values(cx, p_child_zap)?;
    if p_children.iter().any(|e| e.name == child_name) {
        return Err(FfsError::Exists);
    }

    // Match the pool's `ObjectSet` physical block size (`1024 | 2048 | 4096`) from the parent.
    let (p_head_dn, p_head_ceil) = mos.object_with_ceiling(cx, parent_head_obj)?;
    let p_os_bp = BlockPointer::parse(&p_head_dn.bonus()[128..256], p_head_dn.order())
        .map_err(|e| parse_err(&e))?;
    let (p_os_raw, p_os_ord, _) = mos
        .checked_raw(
            cx,
            &p_os_bp,
            DMU_OT_OBJSET,
            0,
            p_os_bp.logical_bytes(),
            p_head_ceil,
        )?
        .ok_or_else(|| corrupt("parent ObjectSet is a hole"))?;
    let p_os = ObjectSet::parse(&p_os_raw, p_os_ord).map_err(|e| parse_err(&e))?;
    let os_phys_bytes = p_os.physical_bytes();

    // 1. Build fresh ZVOL `ObjectSet` (`kind = 3`, `flags = 0`, NO embedded quota dnodes).
    let empty_meta = Dnode::from_spec(DnodeSpec {
        object_type: DMU_OT_DNODE,
        bonus_type: 0,
        checksum_type: 7,
        compress_type: 2,
        flags: DNODE_FLAG_USED_BYTES,
        order,
        levels: 1,
        indirect_shift: 17,
        data_bytes: DNODE_BLOCK_BYTES,
        max_block: 0,
        used_bytes: 0,
        slots: 1,
        pointers: vec![BlockPointer::hole_pointer(); 3],
        bonus: Vec::new(),
        spill: None,
    })
    .map_err(|e| parse_err(&e))?;
    let mut new_view = mos.open_objectset_view(empty_meta.clone(), new_txg, new_txg);
    let mut zvol_dirty_dnodes: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let mut zvol_born = SpaceDelta::default();
    let min_blk = (1_usize << alloc.ashift).max(512);

    // Object 1 (`ZVOL_OBJ`, `DMU_OT_ZVOL = 23`): empty sparse volume data dnode.
    let data_dn = Dnode::from_spec(DnodeSpec {
        object_type: DMU_OT_ZVOL,
        bonus_type: 0,
        checksum_type: 0,
        compress_type: 0,
        flags: DNODE_FLAG_USED_BYTES,
        order,
        levels: 1,
        indirect_shift: 17,
        data_bytes: volblocksize,
        max_block: 0,
        used_bytes: 0,
        slots: 1,
        pointers: vec![BlockPointer::hole_pointer(); 3],
        bonus: Vec::new(),
        spill: None,
    })
    .map_err(|e| parse_err(&e))?;
    put_dnode_in_table(
        cx,
        &mut new_view,
        &empty_meta,
        new_txg,
        &mut zvol_dirty_dnodes,
        ZVOL_OBJ,
        &data_dn,
    )?;

    // Object 2 (`ZVOL_ZAP_OBJ`, `DMU_OT_ZVOL_PROP = 24`): `"size" -> opts.volsize`.
    let prop_entries = [RawZapEntry {
        name: b"size".to_vec(),
        integer_bytes: 8,
        values: vec![opts.volsize],
        collision: 0,
    }];
    let (prop_bsize, prop_blocks) =
        encode_zap_blocks_for_dnode(cx, &mut new_view, None, &prop_entries, order, min_blk)?;
    let mut prop_dirty = BTreeMap::new();
    for (idx, blk) in prop_blocks.into_iter().enumerate() {
        prop_dirty.insert(idx as u64, Some(blk));
    }
    let prop_out = cow_update_dnode(
        cx,
        &mut new_view,
        alloc,
        DnodeCowSpec {
            existing: None,
            object_type: DMU_OT_ZVOL_PROP,
            bonus_type: 0,
            checksum_type: 7,
            compress_type: 2,
            user_flags: 0,
            indirect_shift: 17,
            data_bytes: prop_bsize,
            max_block: (prop_dirty.len() - 1) as u64,
            slots: 1,
            nblkptr: 3,
            bonus: Vec::new(),
            spill: None,
            order,
            new_txg,
            leaf_bucket: WriteBucket::ChildBlocks,
            indirect_bucket: WriteBucket::ChildBlocks,
        },
        &prop_dirty,
        staged_writes,
    )?;
    zvol_born.add_assign(prop_out.born)?;
    put_dnode_in_table(
        cx,
        &mut new_view,
        &empty_meta,
        new_txg,
        &mut zvol_dirty_dnodes,
        ZVOL_ZAP_OBJ,
        &prop_out.dnode,
    )?;

    let mut meta_dirty = BTreeMap::new();
    for (&bid, blk) in &zvol_dirty_dnodes {
        meta_dirty.insert(bid, Some(blk.clone()));
    }
    let max_meta_blk = zvol_dirty_dnodes.keys().copied().max().unwrap_or(0);
    let meta_out = cow_update_dnode(
        cx,
        &mut new_view,
        alloc,
        DnodeCowSpec {
            existing: None,
            object_type: DMU_OT_DNODE,
            bonus_type: 0,
            checksum_type: 7,
            compress_type: 2,
            user_flags: 0,
            indirect_shift: 17,
            data_bytes: DNODE_BLOCK_BYTES,
            max_block: max_meta_blk,
            slots: 1,
            nblkptr: 3,
            bonus: Vec::new(),
            spill: None,
            order,
            new_txg,
            leaf_bucket: WriteBucket::DatasetMetadata,
            indirect_bucket: WriteBucket::DatasetMetadata,
        },
        &meta_dirty,
        staged_writes,
    )?;
    zvol_born.add_assign(meta_out.born)?;

    let new_os = ObjectSet::new(
        OBJSET_TYPE_ZVOL,
        0,
        meta_out.dnode,
        ZilHeader::empty(),
        os_phys_bytes,
    )
    .map_err(|e| parse_err(&e))?;
    let os_bytes = new_os.encode(order).map_err(|e| parse_err(&e))?;
    let os_fill = new_os.meta_fill();
    let os_dva = alloc.allocate(os_bytes.len())?;
    let new_os_bp = BlockPointer::new_regular(&RegularBlockSpec {
        dvas: &[os_dva],
        physical: &os_bytes,
        logical_bytes: os_bytes.len(),
        compression: 2,
        checksum_type: 7,
        object_type: DMU_OT_OBJSET,
        level: 0,
        payload_order: order,
        birth: new_txg,
        fill: os_fill,
    })
    .map_err(|e| parse_err(&e))?;
    zvol_born.add_assign(SpaceDelta::from_bp(&new_os_bp)?)?;
    staged_writes.push(StagedBlockWrite {
        bucket: WriteBucket::DatasetMetadata,
        dva_offset: os_dva.offset,
        bytes: os_bytes,
    });

    // 2. Enforce parent/ancestor quota and pool reservation headroom before linking into MOS.
    enforce_dataset_quotas_for_growth(
        cx,
        mos,
        mos_dirty_dnodes,
        parent_head_obj,
        parent_dd_obj,
        0,
        zvol_born.dsize,
        order,
    )?;
    enforce_pool_reservations_for_growth(
        cx,
        mos,
        mos_dirty_dnodes,
        parent_head_obj,
        parent_dd_obj,
        zvol_born.dsize,
        0,
        alloc.total_free_bytes(),
        order,
    )?;

    let new_dd_obj = allocate_object_id(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
    let new_head_obj = allocate_object_id(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
    let new_child_zap = allocate_object_id(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
    let new_props_zap = allocate_object_id(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
    let new_snapmap_zap = allocate_object_id(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;

    write_zap_dnode_in_mos(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        alloc,
        new_child_zap,
        None,
        DMU_OT_DSL_DIR_CHILD_MAP,
        0,
        Vec::new(),
        &[],
        0,
        false,
        order,
        new_txg,
        staged_writes,
    )?;
    write_zap_dnode_in_mos(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        alloc,
        new_snapmap_zap,
        None,
        DMU_OT_DSL_DS_SNAP_MAP,
        0,
        Vec::new(),
        &[],
        2, // normflags = 2 (U8_TEXTPREP_TOUPPER)
        false,
        order,
        new_txg,
        staged_writes,
    )?;

    let pool_origin =
        lookup_pool_origin_snapshot(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, order)?;
    let (origin_snap_obj, origin_creation_txg, inherited_flags) =
        if let Some((_, _, orig_snap_id)) = pool_origin {
            let (orig_snap_dn, _) = read_staged_or_committed_dnode(
                cx,
                mos,
                &mos_meta,
                mos_ceiling,
                mos_dirty_dnodes,
                orig_snap_id,
                order,
            )?;
            let c_txg = order
                .u64(orig_snap_dn.bonus(), 56)
                .map_err(|e| parse_err(&e))?;
            let o_flags = order
                .u64(orig_snap_dn.bonus(), 120)
                .map_err(|e| parse_err(&e))?;
            (orig_snap_id, c_txg, o_flags & 0x1_0006)
        } else {
            (0, 0, 0)
        };

    let mut dl_keys = BTreeSet::new();
    dl_keys.insert(0);
    let new_deadlist_obj = allocate_fresh_deadlist(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        features,
        alloc,
        empty_bpobj_id,
        &dl_keys,
        &[],
        order,
        new_txg,
        staged_writes,
    )?;

    let ds_guid = derive_unique_guid(pool_guid, new_txg, new_head_obj, 4);
    let ds_fsid = derive_fsid_guid(ds_guid);
    let mut head_bonus = vec![0_u8; 320];
    head_bonus[0..8].copy_from_slice(&order.encode(new_dd_obj));
    head_bonus[8..16].copy_from_slice(&order.encode(origin_snap_obj));
    head_bonus[16..24].copy_from_slice(&order.encode(origin_creation_txg));
    head_bonus[32..40].copy_from_slice(&order.encode(new_snapmap_zap));
    head_bonus[48..56].copy_from_slice(&order.encode(opts.timestamp.seconds.cast_unsigned()));
    head_bonus[56..64].copy_from_slice(&order.encode(new_txg));
    head_bonus[64..72].copy_from_slice(&order.encode(new_deadlist_obj));
    head_bonus[72..80].copy_from_slice(&order.encode(zvol_born.dsize));
    head_bonus[80..88].copy_from_slice(&order.encode(zvol_born.comp));
    head_bonus[88..96].copy_from_slice(&order.encode(zvol_born.uncomp));
    head_bonus[96..104].copy_from_slice(&order.encode(zvol_born.dsize));
    head_bonus[104..112].copy_from_slice(&order.encode(ds_fsid));
    head_bonus[112..120].copy_from_slice(&order.encode(ds_guid));
    head_bonus[120..128].copy_from_slice(&order.encode(inherited_flags | DS_FLAG_UNIQUE_ACCURATE));
    head_bonus[128..256].copy_from_slice(&new_os_bp.encode(order));

    if volblocksize > 131_072 {
        features.increment_read("com.delphix:extensible_dataset", new_txg)?;
        features.increment_read("org.open-zfs:large_blocks", new_txg)?;
        let lb_entries = [RawZapEntry {
            name: b"org.open-zfs:large_blocks".to_vec(),
            integer_bytes: 8,
            values: vec![0],
            collision: 0,
        }];
        write_zap_dnode_in_mos(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            alloc,
            new_head_obj,
            None,
            DMU_OTN_ZAP_METADATA,
            DMU_OT_DSL_DATASET,
            head_bonus,
            &lb_entries,
            0,
            false,
            order,
            new_txg,
            staged_writes,
        )?;
    } else {
        let head_dn = Dnode::from_spec(DnodeSpec {
            object_type: DMU_OT_DSL_DATASET,
            bonus_type: DMU_OT_DSL_DATASET,
            checksum_type: 0,
            compress_type: 0,
            flags: DNODE_FLAG_USED_BYTES,
            order,
            levels: 1,
            indirect_shift: 17,
            data_bytes: 512,
            max_block: 0,
            used_bytes: 0,
            slots: 1,
            pointers: vec![BlockPointer::hole_pointer()],
            bonus: head_bonus,
            spill: None,
        })
        .map_err(|e| parse_err(&e))?;
        put_dnode_in_table(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            new_head_obj,
            &head_dn,
        )?;
    }

    let mut dd_bonus = vec![0_u8; 256];
    dd_bonus[0..8].copy_from_slice(&order.encode(opts.timestamp.seconds.cast_unsigned()));
    dd_bonus[8..16].copy_from_slice(&order.encode(new_head_obj));
    dd_bonus[16..24].copy_from_slice(&order.encode(parent_dd_obj));
    dd_bonus[24..32].copy_from_slice(&order.encode(origin_snap_obj));
    dd_bonus[32..40].copy_from_slice(&order.encode(new_child_zap));
    dd_bonus[40..48].copy_from_slice(&order.encode(zvol_born.dsize));
    dd_bonus[48..56].copy_from_slice(&order.encode(zvol_born.comp));
    dd_bonus[56..64].copy_from_slice(&order.encode(zvol_born.uncomp));
    dd_bonus[80..88].copy_from_slice(&order.encode(new_props_zap));
    dd_bonus[96..104].copy_from_slice(&order.encode(DD_FLAG_USED_BREAKDOWN));
    dd_bonus[104..112].copy_from_slice(&order.encode(zvol_born.dsize)); // DD_USED_HEAD

    put_new_dsl_dir_in_mos(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        features,
        alloc,
        new_dd_obj,
        dd_bonus,
        order,
        new_txg,
        staged_writes,
    )?;

    if let Some((origin_dd_obj, _, orig_snap_id)) = pool_origin {
        link_dataset_to_origin_snapshot(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            alloc,
            origin_dd_obj,
            orig_snap_id,
            new_head_obj,
            order,
            new_txg,
            staged_writes,
        )?;
    }

    let (p_cz_dn, p_cz_ceil) = mos.object_with_ceiling(cx, p_child_zap)?;
    p_children.push(RawZapEntry {
        name: child_name.to_vec(),
        integer_bytes: 8,
        values: vec![new_dd_obj],
        collision: 0,
    });
    write_zap_dnode_in_mos(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        alloc,
        p_child_zap,
        Some((&p_cz_dn, p_cz_ceil)),
        p_cz_dn.object_type(),
        p_cz_dn.bonus_type(),
        p_cz_dn.bonus().to_vec(),
        &p_children,
        0,
        false,
        order,
        new_txg,
        staged_writes,
    )?;

    propagate_dsl_dir_space_delta(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        parent_dd_obj,
        0,
        0,
        i128::from(zvol_born.dsize),
        0,
        0,
        i128::from(zvol_born.comp),
        i128::from(zvol_born.uncomp),
        order,
    )?;
    bump_filesystem_limits_counter_if_present(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        alloc,
        parent_dd_obj,
        b"com.joyent:filesystem_count",
        1,
        order,
        new_txg,
        staged_writes,
    )?;

    let mut effective_props = opts.initial_props.clone();
    if !opts.sparse && !effective_props.iter().any(|(k, _)| k == "refreservation") {
        effective_props.push((
            "refreservation".to_owned(),
            ZfsPropertySetValue::Number(opts.volsize),
        ));
    }
    let prop_updates: Vec<(&str, Option<&ZfsPropertySetValue>)> = effective_props
        .iter()
        .map(|(k, v)| (k.as_str(), Some(v)))
        .collect();
    apply_properties_batch_on_ids(
        cx,
        mos,
        new_dd_obj,
        new_head_obj,
        new_props_zap,
        None,
        true,
        &prop_updates,
        mos_dirty_dnodes,
        features,
        alloc,
        order,
        new_txg,
        staged_writes,
    )?;

    let mut readonly = parent_readonly;
    for (k, v) in &effective_props {
        if k == "readonly"
            && let ZfsPropertySetValue::Number(n) = v
        {
            readonly = *n != 0;
        }
    }

    let info = ZfsZvolInfo {
        pool_guid,
        dataset_guid: ds_guid,
        head_object: new_head_obj,
        directory_object: new_dd_obj,
        committed_txg: new_txg,
        root_birth: new_txg,
        volsize: opts.volsize,
        volblocksize,
        dnode_used_bytes: 0,
        referenced_bytes: zvol_born.dsize,
        readonly,
    };
    Ok((info, new_head_obj))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn stage_destroy_zvol(
    cx: &Cx,
    mos: &mut Objects,
    dataset: &[Vec<u8>],
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    features: &mut MosFeatureState,
    empty_bpobj_id: Option<u64>,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<u64> {
    let ds_row = mos
        .datasets(cx)?
        .into_iter()
        .find(|d| d.components == dataset)
        .ok_or_else(|| FfsError::NotFound("ZFS volume dataset".into()))?;
    if ds_row.objectset_kind != Some(OBJSET_TYPE_ZVOL) {
        return Err(reject_einval(
            "zvol_destroy target must be a ZFS volume dataset",
        ));
    }
    stage_destroy_dataset(
        cx,
        mos,
        dataset,
        mos_dirty_dnodes,
        features,
        empty_bpobj_id,
        alloc,
        order,
        new_txg,
        staged_writes,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn stage_snapshot_zvol(
    cx: &Cx,
    mos: &mut Objects,
    dataset: &[Vec<u8>],
    snap_name: &[u8],
    timestamp: Timestamp,
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    features: &mut MosFeatureState,
    empty_bpobj_id: Option<u64>,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<u64> {
    let ds_row = mos
        .datasets(cx)?
        .into_iter()
        .find(|d| d.components == dataset)
        .ok_or_else(|| FfsError::NotFound("ZFS volume dataset".into()))?;
    if ds_row.objectset_kind != Some(OBJSET_TYPE_ZVOL) {
        return Err(reject_einval(
            "zvol_snapshot target must be a ZFS volume dataset",
        ));
    }
    stage_create_snapshot(
        cx,
        mos,
        dataset,
        snap_name,
        timestamp,
        mos_dirty_dnodes,
        features,
        empty_bpobj_id,
        alloc,
        order,
        new_txg,
        staged_writes,
    )
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn stage_resize_zvol(
    cx: &Cx,
    mos: &mut Objects,
    dataset: &[Vec<u8>],
    new_volsize: u64,
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    features: &mut MosFeatureState,
    empty_bpobj_id: Option<u64>,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<u64> {
    let (mut ctx, mut os_view) = open_zvol_head_context(cx, mos, dataset, order)?;
    let bs = ctx.volblocksize as u64;
    if new_volsize == 0 || i64::try_from(new_volsize).is_err() || !new_volsize.is_multiple_of(bs) {
        return Err(reject_einval(
            "new ZVOL volsize must be non-zero, <= i64::MAX, and a multiple of volblocksize",
        ));
    }

    let zvol_meta_base = ctx.os.meta.clone();
    let zvol_ceiling = ctx.old_os_bp.birth();
    let mut zvol_dirty_dnodes: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let mut born = SpaceDelta::default();
    let mut retired = Vec::new();

    // If shrinking below `data_dnode.max_block()`, truncate Object 1's DMU tree and retire tail blocks.
    if new_volsize < ctx.volsize {
        let new_last_bid = (new_volsize / bs) - 1;
        if ctx.data_dnode.max_block() > new_last_bid {
            let empty_dirty: BTreeMap<u64, Option<Vec<u8>>> = BTreeMap::new();
            let cksum = if matches!(ctx.data_dnode.checksum_type(), 6..=8) {
                ctx.data_dnode.checksum_type()
            } else {
                7
            };
            let data_out = cow_update_dnode(
                cx,
                &mut os_view,
                alloc,
                DnodeCowSpec {
                    existing: Some((&ctx.data_dnode, ctx.data_ceiling)),
                    object_type: DMU_OT_ZVOL,
                    bonus_type: 0,
                    checksum_type: cksum,
                    compress_type: 2,
                    user_flags: 0,
                    indirect_shift: ctx.data_dnode.indirect_shift(),
                    data_bytes: ctx.volblocksize,
                    max_block: new_last_bid,
                    slots: 1,
                    nblkptr: ctx.data_dnode.pointers().len(),
                    bonus: Vec::new(),
                    spill: None,
                    order,
                    new_txg,
                    leaf_bucket: WriteBucket::ChildBlocks,
                    indirect_bucket: WriteBucket::ChildBlocks,
                },
                &empty_dirty,
                staged_writes,
            )?;
            born.add_assign(data_out.born)?;
            retired.extend(data_out.retired_bps);
            put_dnode_in_table(
                cx,
                &mut os_view,
                &zvol_meta_base,
                zvol_ceiling,
                &mut zvol_dirty_dnodes,
                ZVOL_OBJ,
                &data_out.dnode,
            )?;
        }
    }

    // Update Object 2 (`ZVOL_ZAP_OBJ`) `"size"` property while preserving any other ZAP keys.
    let mut prop_entries = os_view.zap_values(cx, ZVOL_ZAP_OBJ)?;
    if let Some(row) = prop_entries.iter_mut().find(|e| e.name == b"size") {
        row.integer_bytes = 8;
        row.values = vec![new_volsize];
    } else {
        prop_entries.push(RawZapEntry {
            name: b"size".to_vec(),
            integer_bytes: 8,
            values: vec![new_volsize],
            collision: 0,
        });
    }
    let min_blk = (1_usize << alloc.ashift).max(512);
    let (prop_bsize, prop_blocks) = encode_zap_blocks_for_dnode(
        cx,
        &mut os_view,
        Some((&ctx.prop_dnode, ctx.prop_ceiling)),
        &prop_entries,
        order,
        min_blk,
    )?;
    let mut prop_dirty = BTreeMap::new();
    for (idx, blk) in prop_blocks.into_iter().enumerate() {
        prop_dirty.insert(idx as u64, Some(blk));
    }
    let prop_out = cow_update_dnode(
        cx,
        &mut os_view,
        alloc,
        DnodeCowSpec {
            existing: Some((&ctx.prop_dnode, ctx.prop_ceiling)),
            object_type: DMU_OT_ZVOL_PROP,
            bonus_type: 0,
            checksum_type: 7,
            compress_type: 2,
            user_flags: 0,
            indirect_shift: ctx.prop_dnode.indirect_shift(),
            data_bytes: prop_bsize,
            max_block: (prop_dirty.len() - 1) as u64,
            slots: 1,
            nblkptr: ctx.prop_dnode.pointers().len(),
            bonus: Vec::new(),
            spill: None,
            order,
            new_txg,
            leaf_bucket: WriteBucket::ChildBlocks,
            indirect_bucket: WriteBucket::ChildBlocks,
        },
        &prop_dirty,
        staged_writes,
    )?;
    born.add_assign(prop_out.born)?;
    retired.extend(prop_out.retired_bps);
    put_dnode_in_table(
        cx,
        &mut os_view,
        &zvol_meta_base,
        zvol_ceiling,
        &mut zvol_dirty_dnodes,
        ZVOL_ZAP_OBJ,
        &prop_out.dnode,
    )?;

    finalize_zvol_to_mos(
        cx,
        mos,
        &mut ctx,
        &mut os_view,
        &zvol_meta_base,
        zvol_ceiling,
        &zvol_dirty_dnodes,
        &born,
        &retired,
        mos_dirty_dnodes,
        features,
        empty_bpobj_id,
        alloc,
        order,
        new_txg,
        staged_writes,
        new_volsize,
    )
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn stage_zvol_write_at(
    cx: &Cx,
    mos: &mut Objects,
    dataset: &[Vec<u8>],
    offset: u64,
    data: &[u8],
    checksum: ZfsDataChecksum,
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    features: &mut MosFeatureState,
    empty_bpobj_id: Option<u64>,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<u64> {
    let (mut ctx, mut os_view) = open_zvol_head_context(cx, mos, dataset, order)?;
    validate_sector_span(offset, data.len() as u64, ctx.volsize, MAX_ZVOL_IO_BYTES)?;

    let zvol_meta_base = ctx.os.meta.clone();
    let zvol_ceiling = ctx.old_os_bp.birth();
    let mut zvol_dirty_dnodes: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let mut born = SpaceDelta::default();
    let mut retired = Vec::new();

    if !data.is_empty() {
        let bs = ctx.volblocksize as u64;
        let end = offset + data.len() as u64;
        let first_bid = offset / bs;
        let last_bid = (end - 1) / bs;
        let mut dirty_leaves: BTreeMap<u64, Option<Vec<u8>>> = BTreeMap::new();

        for bid in first_bid..=last_bid {
            checkpoint(cx)?;
            let block_start = bid * bs;
            let block_end = block_start + bs;
            let write_start = offset.max(block_start);
            let write_end = end.min(block_end);
            let in_block_off = (write_start - block_start) as usize;
            let in_data_off = (write_start - offset) as usize;
            let copy_len = (write_end - write_start) as usize;

            let buf = if copy_len == ctx.volblocksize {
                data[in_data_off..in_data_off + copy_len].to_vec()
            } else {
                let mut existing = if bid <= ctx.data_dnode.max_block()
                    && let Some((blk, _, _)) =
                        os_view.object_data_block(cx, &ctx.data_dnode, ctx.data_ceiling, bid)?
                {
                    blk.as_ref().clone()
                } else {
                    vec![0_u8; ctx.volblocksize]
                };
                existing[in_block_off..in_block_off + copy_len]
                    .copy_from_slice(&data[in_data_off..in_data_off + copy_len]);
                existing
            };
            dirty_leaves.insert(bid, Some(buf));
        }

        let new_max_block = ctx.data_dnode.max_block().max(last_bid);
        let data_out = cow_update_dnode(
            cx,
            &mut os_view,
            alloc,
            DnodeCowSpec {
                existing: Some((&ctx.data_dnode, ctx.data_ceiling)),
                object_type: DMU_OT_ZVOL,
                bonus_type: 0,
                checksum_type: checksum.code(),
                compress_type: 2,
                user_flags: 0,
                indirect_shift: ctx.data_dnode.indirect_shift(),
                data_bytes: ctx.volblocksize,
                max_block: new_max_block,
                slots: 1,
                nblkptr: ctx.data_dnode.pointers().len(),
                bonus: Vec::new(),
                spill: None,
                order,
                new_txg,
                leaf_bucket: WriteBucket::ChildBlocks,
                indirect_bucket: WriteBucket::ChildBlocks,
            },
            &dirty_leaves,
            staged_writes,
        )?;
        born.add_assign(data_out.born)?;
        retired.extend(data_out.retired_bps);
        put_dnode_in_table(
            cx,
            &mut os_view,
            &zvol_meta_base,
            zvol_ceiling,
            &mut zvol_dirty_dnodes,
            ZVOL_OBJ,
            &data_out.dnode,
        )?;
    }

    finalize_zvol_to_mos(
        cx,
        mos,
        &mut ctx,
        &mut os_view,
        &zvol_meta_base,
        zvol_ceiling,
        &zvol_dirty_dnodes,
        &born,
        &retired,
        mos_dirty_dnodes,
        features,
        empty_bpobj_id,
        alloc,
        order,
        new_txg,
        staged_writes,
        data.len() as u64,
    )
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn stage_zvol_discard(
    cx: &Cx,
    mos: &mut Objects,
    dataset: &[Vec<u8>],
    offset: u64,
    len: u64,
    checksum: ZfsDataChecksum,
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    features: &mut MosFeatureState,
    empty_bpobj_id: Option<u64>,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<u64> {
    let (mut ctx, mut os_view) = open_zvol_head_context(cx, mos, dataset, order)?;
    if !offset.is_multiple_of(ZVOL_LOGICAL_SECTOR_BYTES as u64)
        || !len.is_multiple_of(ZVOL_LOGICAL_SECTOR_BYTES as u64)
        || offset.checked_add(len).is_none_or(|end| end > ctx.volsize)
    {
        return Err(reject_einval(
            "ZVOL discard range must be 512-byte sector aligned and within capacity",
        ));
    }

    let zvol_meta_base = ctx.os.meta.clone();
    let zvol_ceiling = ctx.old_os_bp.birth();
    let mut zvol_dirty_dnodes: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let mut born = SpaceDelta::default();
    let mut retired = Vec::new();

    if len > 0 {
        let bs = ctx.volblocksize as u64;
        let end = offset + len;
        let first_bid = offset / bs;
        let last_bid = ((end - 1) / bs).min(ctx.data_dnode.max_block());
        let mut dirty_leaves: BTreeMap<u64, Option<Vec<u8>>> = BTreeMap::new();

        if first_bid <= last_bid {
            for bid in first_bid..=last_bid {
                checkpoint(cx)?;
                let block_start = bid * bs;
                let block_end = block_start + bs;
                let cut_start = offset.max(block_start);
                let cut_end = end.min(block_end);
                let Some((existing, _, _)) =
                    os_view.object_data_block(cx, &ctx.data_dnode, ctx.data_ceiling, bid)?
                else {
                    // Already a native hole: leave unallocated!
                    continue;
                };
                if cut_start == block_start && cut_end == block_end {
                    dirty_leaves.insert(bid, None);
                } else {
                    let mut buf = existing.as_ref().clone();
                    let in_start = (cut_start - block_start) as usize;
                    let in_end = (cut_end - block_start) as usize;
                    buf[in_start..in_end].fill(0);
                    if buf.iter().all(|&b| b == 0) {
                        dirty_leaves.insert(bid, None);
                    } else {
                        dirty_leaves.insert(bid, Some(buf));
                    }
                }
            }
        }

        if !dirty_leaves.is_empty() {
            let data_out = cow_update_dnode(
                cx,
                &mut os_view,
                alloc,
                DnodeCowSpec {
                    existing: Some((&ctx.data_dnode, ctx.data_ceiling)),
                    object_type: DMU_OT_ZVOL,
                    bonus_type: 0,
                    checksum_type: checksum.code(),
                    compress_type: 2,
                    user_flags: 0,
                    indirect_shift: ctx.data_dnode.indirect_shift(),
                    data_bytes: ctx.volblocksize,
                    max_block: ctx.data_dnode.max_block(),
                    slots: 1,
                    nblkptr: ctx.data_dnode.pointers().len(),
                    bonus: Vec::new(),
                    spill: None,
                    order,
                    new_txg,
                    leaf_bucket: WriteBucket::ChildBlocks,
                    indirect_bucket: WriteBucket::ChildBlocks,
                },
                &dirty_leaves,
                staged_writes,
            )?;
            born.add_assign(data_out.born)?;
            retired.extend(data_out.retired_bps);
            put_dnode_in_table(
                cx,
                &mut os_view,
                &zvol_meta_base,
                zvol_ceiling,
                &mut zvol_dirty_dnodes,
                ZVOL_OBJ,
                &data_out.dnode,
            )?;
        }
    }

    finalize_zvol_to_mos(
        cx,
        mos,
        &mut ctx,
        &mut os_view,
        &zvol_meta_base,
        zvol_ceiling,
        &zvol_dirty_dnodes,
        &born,
        &retired,
        mos_dirty_dnodes,
        features,
        empty_bpobj_id,
        alloc,
        order,
        new_txg,
        staged_writes,
        len,
    )
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn stage_zvol_batch_apply(
    cx: &Cx,
    mos: &mut Objects,
    dataset: &[Vec<u8>],
    dirty_blocks: &BTreeMap<u64, Option<Vec<u8>>>,
    checksum: ZfsDataChecksum,
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    features: &mut MosFeatureState,
    empty_bpobj_id: Option<u64>,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<u64> {
    let (mut ctx, mut os_view) = open_zvol_head_context(cx, mos, dataset, order)?;
    let bs = ctx.volblocksize as u64;
    let total_blocks = ctx.volsize / bs;
    let mut filtered: BTreeMap<u64, Option<Vec<u8>>> = BTreeMap::new();
    let mut new_max_block = ctx.data_dnode.max_block();

    for (&bid, maybe_blk) in dirty_blocks {
        checkpoint(cx)?;
        if bid >= total_blocks {
            return Err(reject_einval(
                "ZVOL batch block index exceeds volume capacity",
            ));
        }
        match maybe_blk {
            Some(buf) => {
                if buf.len() != ctx.volblocksize {
                    return Err(reject_einval(
                        "ZVOL batch block size disagrees with volblocksize",
                    ));
                }
                new_max_block = new_max_block.max(bid);
                filtered.insert(bid, Some(buf.clone()));
            }
            None => {
                if bid <= ctx.data_dnode.max_block() {
                    filtered.insert(bid, None);
                }
            }
        }
    }

    let zvol_meta_base = ctx.os.meta.clone();
    let zvol_ceiling = ctx.old_os_bp.birth();
    let mut zvol_dirty_dnodes: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let mut born = SpaceDelta::default();
    let mut retired = Vec::new();

    if !filtered.is_empty() {
        let data_out = cow_update_dnode(
            cx,
            &mut os_view,
            alloc,
            DnodeCowSpec {
                existing: Some((&ctx.data_dnode, ctx.data_ceiling)),
                object_type: DMU_OT_ZVOL,
                bonus_type: 0,
                checksum_type: checksum.code(),
                compress_type: 2,
                user_flags: 0,
                indirect_shift: ctx.data_dnode.indirect_shift(),
                data_bytes: ctx.volblocksize,
                max_block: new_max_block,
                slots: 1,
                nblkptr: ctx.data_dnode.pointers().len(),
                bonus: Vec::new(),
                spill: None,
                order,
                new_txg,
                leaf_bucket: WriteBucket::ChildBlocks,
                indirect_bucket: WriteBucket::ChildBlocks,
            },
            &filtered,
            staged_writes,
        )?;
        born.add_assign(data_out.born)?;
        retired.extend(data_out.retired_bps);
        put_dnode_in_table(
            cx,
            &mut os_view,
            &zvol_meta_base,
            zvol_ceiling,
            &mut zvol_dirty_dnodes,
            ZVOL_OBJ,
            &data_out.dnode,
        )?;
    }

    finalize_zvol_to_mos(
        cx,
        mos,
        &mut ctx,
        &mut os_view,
        &zvol_meta_base,
        zvol_ceiling,
        &zvol_dirty_dnodes,
        &born,
        &retired,
        mos_dirty_dnodes,
        features,
        empty_bpobj_id,
        alloc,
        order,
        new_txg,
        staged_writes,
        filtered.len() as u64,
    )
}

pub(super) fn read_zvol_at(
    cx: &Cx,
    mos: &mut Objects,
    dataset: &[Vec<u8>],
    snapshot: Option<&[u8]>,
    offset: u64,
    out: &mut [u8],
) -> Result<()> {
    checkpoint(cx)?;
    if !offset.is_multiple_of(ZVOL_LOGICAL_SECTOR_BYTES as u64)
        || !out.len().is_multiple_of(ZVOL_LOGICAL_SECTOR_BYTES)
    {
        return Err(reject_einval(
            "ZVOL read offset and length must be 512-byte sector aligned",
        ));
    }
    if out.len() > MAX_ZVOL_IO_BYTES {
        return Err(reject_einval(
            "ZVOL read request exceeds 16 MiB maximum transfer size",
        ));
    }
    let mut zvol = mos.zvol(cx, dataset, snapshot)?;
    let volsize = zvol.info().size_bytes;
    if offset
        .checked_add(out.len() as u64)
        .is_none_or(|end| end > volsize)
    {
        return Err(reject_einval("ZVOL read range exceeds volume capacity"));
    }
    if out.is_empty() {
        return Ok(());
    }
    let bytes = zvol.read(cx, offset, out.len())?;
    checkpoint(cx)?;
    out.copy_from_slice(&bytes);
    Ok(())
}

pub(super) fn inspect_zvol_info(
    cx: &Cx,
    mos: &mut Objects,
    dataset: &[Vec<u8>],
    snapshot: Option<&[u8]>,
) -> Result<ZfsZvolInfo> {
    checkpoint(cx)?;
    let zvol = mos.zvol(cx, dataset, snapshot)?;
    let vinfo = zvol.info().clone();
    let ds_row = mos
        .datasets(cx)?
        .into_iter()
        .find(|d| d.components == dataset)
        .ok_or_else(|| FfsError::NotFound("ZFS volume dataset".into()))?;
    let (head_object, referenced_bytes, readonly) = if let Some(snap_name) = snapshot {
        let selected = mos.named_snapshot_root(cx, dataset, snap_name)?;
        (selected.info.object, selected.info.referenced_bytes, true)
    } else {
        let (head_dn, _) = mos.object_with_ceiling(cx, ds_row.head_object)?;
        let ref_bytes = head_dn
            .order()
            .u64(head_dn.bonus(), 72)
            .map_err(|e| parse_err(&e))?;
        let ro = effective_readonly(cx, mos, dataset)?;
        (ds_row.head_object, ref_bytes, ro)
    };
    Ok(ZfsZvolInfo {
        pool_guid: vinfo.pool_guid,
        dataset_guid: vinfo.dataset_guid,
        head_object,
        directory_object: ds_row.directory_object,
        committed_txg: vinfo.view_txg,
        root_birth: vinfo.root_birth,
        volsize: vinfo.size_bytes,
        volblocksize: vinfo.block_bytes,
        dnode_used_bytes: vinfo.dnode_used_bytes,
        referenced_bytes,
        readonly,
    })
}
