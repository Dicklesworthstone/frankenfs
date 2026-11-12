//! Native ZPL head-dataset mutations (create, mkdir, write, truncate, rename, unlink)
//! lowered into COW DMU object-set, DSL dataset/dir accounting, and deadlist updates.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_ondisk::zfs::{BlockPointer, Endian, RegularBlockSpec};
use ffs_ondisk::zfs_dmu::{DMU_OT_DNODE, DNODE_BLOCK_BYTES, DNODE_BYTES, Dnode, ObjectSet};
use ffs_ondisk::zfs_zap::Entry as RawZapEntry;
use ffs_ondisk::zfs_zpl::{
    Kind, Metadata, SA_BYTES, SaRegistry, Timestamp, directory_reference,
    encode_directory_reference,
};
use serde::Serialize;

use crate::reader::dmu::Objects;

use super::dmu_cow::{
    DMU_OT_DIRECTORY_CONTENTS, DMU_OT_OBJSET, DMU_OT_PLAIN_FILE_CONTENTS, DMU_OT_SA,
    DMU_OT_ZNODE, DnodeCowSpec, PoolSpaceAllocator, QuotaDelta, SpaceDelta, StagedBlockWrite,
    WriteBucket, allocate_object_id, apply_objectset_quota_deltas, collect_non_hole_bps_from,
    cow_update_dnode, encode_zap_blocks_for_dnode, enqueue_into_dataset_deadlist,
    objectset_user_accounting_flags, put_dnode_in_table, read_staged_or_committed_dnode,
    remove_dnode_from_table, zap_optional_u64, zap_required_u64,
};
use super::{checkpoint, corrupt, parse_err, unsupported};

const DEFAULT_RECORDSIZE: usize = 131_072;
const MAX_WRITE_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
const MAX_PATH_DEPTH: usize = 256;

/// Checksum algorithm used for newly written DMU data blocks (`ZIO_CHECKSUM_*`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub enum ZfsDataChecksum {
    #[default]
    Fletcher4,
    Sha256,
}

impl ZfsDataChecksum {
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Fletcher4 => 7,
            Self::Sha256 => 8,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) enum ZplMutation {
    CreateFile {
        parent_dir: u64,
        name: Vec<u8>,
        mode: u16,
        uid: u64,
        gid: u64,
        timestamp: Timestamp,
        checksum: ZfsDataChecksum,
    },
    Mkdir {
        parent_dir: u64,
        name: Vec<u8>,
        mode: u16,
        uid: u64,
        gid: u64,
        timestamp: Timestamp,
    },
    WriteData {
        file_obj: u64,
        offset: u64,
        data: Vec<u8>,
        timestamp: Timestamp,
        checksum: ZfsDataChecksum,
    },
    TruncateFile {
        file_obj: u64,
        new_size: u64,
        timestamp: Timestamp,
        checksum: ZfsDataChecksum,
    },
    RenameEntry {
        src_dir: u64,
        src_name: Vec<u8>,
        dst_dir: u64,
        dst_name: Vec<u8>,
        expected_source_object: Option<u64>,
        timestamp: Timestamp,
    },
    UnlinkEntry {
        parent_dir: u64,
        name: Vec<u8>,
        rmdir: bool,
        timestamp: Timestamp,
    },
}

impl ZplMutation {
    pub fn op_name(&self) -> &'static str {
        match self {
            Self::CreateFile { .. } => "create_file",
            Self::Mkdir { .. } => "mkdir",
            Self::WriteData { .. } => "write_data",
            Self::TruncateFile { .. } => "truncate_file",
            Self::RenameEntry { .. } => "rename_entry",
            Self::UnlinkEntry { .. } => "unlink_entry",
        }
    }
}

struct DatasetContext {
    head_object: u64,
    directory_object: u64,
    prev_snap_txg: u64,
    deadlist_obj: u64,
    old_os_bp: BlockPointer,
    os: ObjectSet,
    root_dir: u64,
    zpl_version: u64,
    utf8_only: bool,
    sa_registry: Option<SaRegistry>,
    recordsize: usize,
}

fn validate_component(name: &[u8], utf8_only: bool) -> Result<()> {
    if name.is_empty()
        || name.len() > 255
        || name == b"."
        || name == b".."
        || name.contains(&0)
        || name.contains(&b'/')
    {
        return Err(FfsError::Format("invalid ZPL directory entry name".into()));
    }
    if utf8_only && std::str::from_utf8(name).is_err() {
        return Err(FfsError::Format(
            "non-UTF8 directory entry name on utf8only ZPL dataset".into(),
        ));
    }
    Ok(())
}

fn open_head_dataset_context(
    cx: &Cx,
    mos: &mut Objects,
    dataset_components: &[Vec<u8>],
) -> Result<(DatasetContext, Objects)> {
    checkpoint(cx)?;
    let ds_row = mos
        .datasets(cx)?
        .into_iter()
        .find(|d| d.components == dataset_components)
        .ok_or_else(|| FfsError::NotFound("ZFS head dataset".into()))?;
    if ds_row.objectset_kind != Some(2) || ds_row.flags & 0x1_0000 != 0 {
        return Err(unsupported(
            "native ZFS ZPL writes require an initialized case-sensitive filesystem head",
        ));
    }
    let (head_dn, head_ceiling) = mos.object_with_ceiling(cx, ds_row.head_object)?;
    let order = head_dn.order();
    let prev_snap_txg = order
        .u64(head_dn.bonus(), 16)
        .map_err(|e| parse_err(&e))?;
    let deadlist_obj = order
        .u64(head_dn.bonus(), 64)
        .map_err(|e| parse_err(&e))?;
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
        .ok_or_else(|| corrupt("ZPL head object set is a hole"))?;
    let os = ObjectSet::parse(&os_raw, os_order).map_err(|e| parse_err(&e))?;
    if os.kind != 2 {
        return Err(corrupt("selected dataset is not a ZPL object set"));
    }
    if os.zil_header.has_work() {
        return Err(unsupported(
            "pending ZIL intent log requires replay before native TXG write",
        ));
    }

    // Read optional `recordsize` property on `dsl_dir` if explicitly set.
    let mut recordsize = DEFAULT_RECORDSIZE;
    let (dir_dn, _) = mos.object_with_ceiling(cx, ds_row.directory_object)?;
    let props_zap = dir_dn
        .order()
        .u64(dir_dn.bonus(), 80)
        .map_err(|e| parse_err(&e))?;
    if props_zap != 0
        && let Ok(props) = mos.zap_values(cx, props_zap)
        && let Ok(Some(rs)) = zap_optional_u64(&props, b"recordsize")
        && (512..=1_048_576).contains(&rs)
        && rs.is_power_of_two()
    {
        recordsize = (rs as usize).min(DEFAULT_RECORDSIZE);
    }

    let mut os_view = mos.open_objectset_view(os.meta.clone(), old_os_bp.birth(), mos.txg);
    let master = os_view.zap_values(cx, 1)?;
    let root_dir = zap_required_u64(&master, b"ROOT")?;
    let zpl_version = zap_required_u64(&master, b"VERSION")?;
    let utf8_only = zap_optional_u64(&master, b"utf8only")?.unwrap_or(0) != 0;
    let norm = zap_optional_u64(&master, b"normalization")?.unwrap_or(0);
    let case = zap_optional_u64(&master, b"casesensitivity")?.unwrap_or(0);
    if !(4..=5).contains(&zpl_version) || norm != 0 || case != 0 {
        return Err(unsupported(
            "native ZPL writer requires ZPL v4/v5 without normalization or case folding",
        ));
    }
    let sa_registry = if let Some(sa_master) = zap_optional_u64(&master, b"SA_ATTRS")?.filter(|&v| v != 0) {
        let sa_rows = os_view.zap_values(cx, sa_master)?;
        let reg_obj = zap_required_u64(&sa_rows, b"REGISTRY")?;
        let lay_obj = zap_required_u64(&sa_rows, b"LAYOUTS")?;
        let reg_entries = os_view.zap_values(cx, reg_obj)?;
        let lay_entries = os_view.zap_values(cx, lay_obj)?;
        Some(SaRegistry::from_zaps(&reg_entries, &lay_entries).map_err(|e| parse_err(&e))?)
    } else {
        None
    };

    Ok((
        DatasetContext {
            head_object: ds_row.head_object,
            directory_object: ds_row.directory_object,
            prev_snap_txg,
            deadlist_obj,
            old_os_bp,
            os,
            root_dir,
            zpl_version,
            utf8_only,
            sa_registry,
            recordsize,
        },
        os_view,
    ))
}

struct LoadedZplNode {
    dnode: Dnode,
    ceiling: u64,
    metadata: Metadata,
    spill_bytes: Option<Vec<u8>>,
}

fn signed_bytes_delta(new_used: u64, old_used: u64) -> Result<i64> {
    i64::try_from(i128::from(new_used) - i128::from(old_used))
        .map_err(|_| corrupt("ZFS quota bytes_delta overflow"))
}

#[allow(clippy::too_many_arguments)]
fn load_zpl_node(
    cx: &Cx,
    os_view: &mut Objects,
    meta_dnode: &Dnode,
    meta_ceiling: u64,
    dirty_dnode_blocks: &BTreeMap<u64, Vec<u8>>,
    sa_registry: Option<&SaRegistry>,
    object_id: u64,
    order: Endian,
) -> Result<LoadedZplNode> {
    if object_id == 0 {
        return Err(FfsError::NotFound("ZPL object 0".into()));
    }
    let (dnode, ceiling) = read_staged_or_committed_dnode(
        cx,
        os_view,
        meta_dnode,
        meta_ceiling,
        dirty_dnode_blocks,
        object_id,
        order,
    )?;
    if !matches!(dnode.object_type(), DMU_OT_PLAIN_FILE_CONTENTS | DMU_OT_DIRECTORY_CONTENTS) {
        return Err(unsupported("target object is not a ZPL file or directory"));
    }
    let mut spill_bytes = None;
    let metadata = match dnode.bonus_type() {
        DMU_OT_ZNODE => {
            Metadata::legacy(dnode.bonus(), dnode.order()).map_err(|e| parse_err(&e))?
        }
        DMU_OT_SA => {
            if let Some(sbp) = dnode.spill() {
                if sbp.logical_bytes() > SA_BYTES {
                    return Err(unsupported("SA spill block exceeds 128 KiB"));
                }
                let (raw, _, _) = os_view
                    .checked_raw(cx, sbp, DMU_OT_SA, 0, sbp.logical_bytes(), ceiling)?
                    .ok_or_else(|| corrupt("SA spill pointer is a hole"))?;
                spill_bytes = Some(raw.as_ref().clone());
            }
            let reg = sa_registry.ok_or_else(|| corrupt("SA object on dataset without SA_ATTRS"))?;
            reg.decode(dnode.bonus(), spill_bytes.as_deref())
                .and_then(|attrs| attrs.metadata())
                .map_err(|e| parse_err(&e))?
        }
        _ => return Err(unsupported("unsupported ZPL bonus representation")),
    };
    if metadata.flags & 1 != 0 {
        return Err(unsupported("cannot directly mutate private ZPL xattr object"));
    }
    Ok(LoadedZplNode {
        dnode,
        ceiling,
        metadata,
        spill_bytes,
    })
}

fn encode_updated_zpl_bonus(
    loaded: &LoadedZplNode,
    new_meta: &Metadata,
    sa_registry: Option<&SaRegistry>,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<(Vec<u8>, Option<BlockPointer>)> {
    match loaded.dnode.bonus_type() {
        DMU_OT_ZNODE => {
            let bonus = new_meta
                .encode_legacy(Some(loaded.dnode.bonus()), order)
                .map_err(|e| parse_err(&e))?;
            Ok((bonus, None))
        }
        DMU_OT_SA => {
            let reg = sa_registry.ok_or_else(|| corrupt("missing SA registry"))?;
            let (new_bonus, maybe_spill) = reg
                .encode_updated_bonus_and_spill(
                    loaded.dnode.bonus(),
                    loaded.spill_bytes.as_deref(),
                    new_meta,
                )
                .map_err(|e| parse_err(&e))?;
            let spill_bp = match (loaded.dnode.spill(), maybe_spill, &loaded.spill_bytes) {
                (Some(old_bp), Some(new_raw), Some(old_raw)) => {
                    let mut padded = vec![0_u8; old_bp.logical_bytes().max(new_raw.len())];
                    padded[..new_raw.len()].copy_from_slice(&new_raw);
                    if padded == *old_raw {
                        Some(old_bp.clone())
                    } else {
                        let dva = alloc.allocate(padded.len())?;
                        let bp = BlockPointer::new_regular(&RegularBlockSpec {
                            dvas: &[dva],
                            physical: &padded,
                            logical_bytes: padded.len(),
                            compression: 2,
                            checksum_type: 7,
                            object_type: DMU_OT_SA,
                            level: 0,
                            payload_order: order,
                            birth: new_txg,
                            fill: 1,
                        })
                        .map_err(|e| parse_err(&e))?;
                        staged_writes.push(StagedBlockWrite {
                            bucket: WriteBucket::ChildBlocks,
                            dva_offset: dva.offset,
                            bytes: padded,
                        });
                        Some(bp)
                    }
                }
                _ => None,
            };
            Ok((new_bonus, spill_bp))
        }
        _ => Err(unsupported("unsupported ZPL bonus type")),
    }
}

fn encode_new_zpl_bonus(
    parent_loaded: &LoadedZplNode,
    new_meta: &Metadata,
    zpl_version: u64,
    sa_registry: Option<&SaRegistry>,
    order: Endian,
) -> Result<(u8, usize, Vec<u8>)> {
    if zpl_version >= 5
        && parent_loaded.dnode.bonus_type() == DMU_OT_SA
        && let Some(reg) = sa_registry
    {
        let bonus = reg
            .encode_new_from_template(parent_loaded.dnode.bonus(), new_meta)
            .map_err(|e| parse_err(&e))?;
        return Ok((DMU_OT_SA, 1, bonus));
    }
    let bonus = new_meta
        .encode_legacy(None, order)
        .map_err(|e| parse_err(&e))?;
    Ok((DMU_OT_ZNODE, 2, bonus))
}

fn read_dir_entries(
    cx: &Cx,
    os_view: &mut Objects,
    dir_obj: u64,
    staged_dirs: &BTreeMap<u64, Vec<RawZapEntry>>,
) -> Result<Vec<RawZapEntry>> {
    if let Some(entries) = staged_dirs.get(&dir_obj) {
        return Ok(entries.clone());
    }
    os_view.zap_values(cx, dir_obj)
}

#[allow(clippy::too_many_arguments)]
fn flush_dir_node(
    cx: &Cx,
    os_view: &mut Objects,
    alloc: &mut PoolSpaceAllocator,
    dir_loaded: &LoadedZplNode,
    new_dir_meta: &Metadata,
    entries: &[RawZapEntry],
    sa_registry: Option<&SaRegistry>,
    acct_flags: u8,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
    zpl_born: &mut SpaceDelta,
    zpl_retired: &mut Vec<BlockPointer>,
    quota_deltas: &mut Vec<QuotaDelta>,
) -> Result<Dnode> {
    let min_blk = (1_usize << alloc.ashift).max(512);
    let (bsize, blocks) = encode_zap_blocks_for_dnode(
        cx,
        os_view,
        Some((&dir_loaded.dnode, dir_loaded.ceiling)),
        entries,
        order,
        min_blk,
    )?;
    let mut dirty = BTreeMap::new();
    for (i, blk) in blocks.into_iter().enumerate() {
        dirty.insert(i as u64, Some(blk));
    }
    let (bonus, spill) = encode_updated_zpl_bonus(
        dir_loaded,
        new_dir_meta,
        sa_registry,
        alloc,
        order,
        new_txg,
        staged_writes,
    )?;
    let old_used = dir_loaded.dnode.used_bytes();
    let out = cow_update_dnode(
        cx,
        os_view,
        alloc,
        DnodeCowSpec {
            existing: Some((&dir_loaded.dnode, dir_loaded.ceiling)),
            object_type: DMU_OT_DIRECTORY_CONTENTS,
            bonus_type: dir_loaded.dnode.bonus_type(),
            checksum_type: 7,
            compress_type: 2,
            user_flags: acct_flags,
            indirect_shift: dir_loaded.dnode.indirect_shift(),
            data_bytes: bsize,
            max_block: (dirty.len() - 1) as u64,
            slots: dir_loaded.dnode.slots(),
            nblkptr: dir_loaded.dnode.pointers().len(),
            bonus,
            spill,
            order,
            new_txg,
            leaf_bucket: WriteBucket::ChildBlocks,
            indirect_bucket: WriteBucket::ChildBlocks,
        },
        &dirty,
        staged_writes,
    )?;
    zpl_born.add_assign(out.born)?;
    zpl_retired.extend(out.retired_bps);
    let bytes_delta = signed_bytes_delta(out.dnode.used_bytes(), old_used)?;
    if bytes_delta != 0 {
        quota_deltas.push(QuotaDelta {
            uid: new_dir_meta.uid,
            gid: new_dir_meta.gid,
            projid: Some(0),
            bytes_delta,
            objs_delta: 0,
        });
    }
    Ok(out.dnode)
}

/// Stage a single ZPL mutation on `dataset_components` in memory, updating `mos_dirty_dnodes`,
/// `write_features`, `alloc`, and `staged_writes`, and returning the operation's `u64` result
/// (`new_object_id`, `new_size`, `moved_object`, or `removed_object`).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn stage_zpl_mutation(
    cx: &Cx,
    mos: &mut Objects,
    dataset_components: &[Vec<u8>],
    mutation: &ZplMutation,
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    write_features: &mut BTreeMap<String, u64>,
    write_features_dirty: &mut bool,
    empty_bpobj_id: Option<u64>,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<u64> {
    checkpoint(cx)?;
    let (mut ds_ctx, mut os_view) = open_head_dataset_context(cx, mos, dataset_components)?;
    let zpl_meta_base = ds_ctx.os.meta.clone();
    let zpl_ceiling = ds_ctx.old_os_bp.birth();
    let acct_flags = objectset_user_accounting_flags(&ds_ctx.os, order)?;
    let min_blk = (1_usize << alloc.ashift).max(512);

    let mut zpl_dirty_dnodes: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let mut staged_dirs: BTreeMap<u64, Vec<RawZapEntry>> = BTreeMap::new();
    let mut zpl_born = SpaceDelta::default();
    let mut zpl_retired: Vec<BlockPointer> = Vec::new();
    let mut quota_deltas: Vec<QuotaDelta> = Vec::new();

    let result_u64 = match mutation {
        ZplMutation::CreateFile {
            parent_dir,
            name,
            mode,
            uid,
            gid,
            timestamp,
            checksum,
        } => {
            validate_component(name, ds_ctx.utf8_only)?;
            let parent_loaded = load_zpl_node(
                cx,
                &mut os_view,
                &zpl_meta_base,
                zpl_ceiling,
                &zpl_dirty_dnodes,
                ds_ctx.sa_registry.as_ref(),
                *parent_dir,
                order,
            )?;
            if parent_loaded.metadata.kind != Kind::Directory {
                return Err(FfsError::NotDirectory);
            }
            let mut entries = read_dir_entries(cx, &mut os_view, *parent_dir, &staged_dirs)?;
            if entries.iter().any(|e| e.name == *name) {
                return Err(FfsError::Exists);
            }
            let new_obj = allocate_object_id(
                cx,
                &mut os_view,
                &zpl_meta_base,
                zpl_ceiling,
                &mut zpl_dirty_dnodes,
                1,
            )?;
            let clean_meta = Metadata {
                mode: (Kind::Regular.to_tag() << 12) | u64::from((*mode) & 0o7777),
                kind: Kind::Regular,
                uid: *uid,
                gid: *gid,
                size: 0,
                links: 1,
                parent: *parent_dir,
                flags: 0,
                generation: new_txg,
                times: [*timestamp; 4],
                inline_symlink: None,
            };
            let (bonus_type, nblkptr, bonus) = encode_new_zpl_bonus(
                &parent_loaded,
                &clean_meta,
                ds_ctx.zpl_version,
                ds_ctx.sa_registry.as_ref(),
                order,
            )?;
            let mut file_dirty = BTreeMap::new();
            file_dirty.insert(0, None);
            let file_out = cow_update_dnode(
                cx,
                &mut os_view,
                alloc,
                DnodeCowSpec {
                    existing: None,
                    object_type: DMU_OT_PLAIN_FILE_CONTENTS,
                    bonus_type,
                    checksum_type: checksum.code(),
                    compress_type: 2,
                    user_flags: acct_flags,
                    indirect_shift: 17,
                    data_bytes: min_blk,
                    max_block: 0,
                    slots: 1,
                    nblkptr,
                    bonus,
                    spill: None,
                    order,
                    new_txg,
                    leaf_bucket: WriteBucket::ChildBlocks,
                    indirect_bucket: WriteBucket::ChildBlocks,
                },
                &file_dirty,
                staged_writes,
            )?;
            let mut file_dn = file_out.dnode;
            if *checksum == ZfsDataChecksum::Sha256 {
                // Record explicit ZIO_CHECKSUM_SHA256 (8) on dnode checksum_type if requested.
                let mut raw = file_dn.encode().map_err(|e| parse_err(&e))?;
                raw[5] = ZfsDataChecksum::Sha256.code();
                file_dn = Dnode::parse(&raw, order).map_err(|e| parse_err(&e))?;
            }
            put_dnode_in_table(
                cx,
                &mut os_view,
                &zpl_meta_base,
                zpl_ceiling,
                &mut zpl_dirty_dnodes,
                new_obj,
                &file_dn,
            )?;
            quota_deltas.push(QuotaDelta {
                uid: *uid,
                gid: *gid,
                projid: Some(0),
                bytes_delta: 0,
                objs_delta: 1,
            });

            let ref_val = encode_directory_reference(new_obj, Kind::Regular)
                .map_err(|e| parse_err(&e))?;
            entries.push(RawZapEntry {
                name: name.clone(),
                integer_bytes: 8,
                values: vec![ref_val],
                collision: 0,
            });
            let mut new_parent_meta = parent_loaded.metadata.clone();
            new_parent_meta.size += 1;
            new_parent_meta.times[1] = *timestamp;
            new_parent_meta.times[2] = *timestamp;
            let parent_dn = flush_dir_node(
                cx,
                &mut os_view,
                alloc,
                &parent_loaded,
                &new_parent_meta,
                &entries,
                ds_ctx.sa_registry.as_ref(),
                acct_flags,
                order,
                new_txg,
                staged_writes,
                &mut zpl_born,
                &mut zpl_retired,
                &mut quota_deltas,
            )?;
            staged_dirs.insert(*parent_dir, entries);
            put_dnode_in_table(
                cx,
                &mut os_view,
                &zpl_meta_base,
                zpl_ceiling,
                &mut zpl_dirty_dnodes,
                *parent_dir,
                &parent_dn,
            )?;
            new_obj
        }

        ZplMutation::Mkdir {
            parent_dir,
            name,
            mode,
            uid,
            gid,
            timestamp,
        } => {
            validate_component(name, ds_ctx.utf8_only)?;
            let parent_loaded = load_zpl_node(
                cx,
                &mut os_view,
                &zpl_meta_base,
                zpl_ceiling,
                &zpl_dirty_dnodes,
                ds_ctx.sa_registry.as_ref(),
                *parent_dir,
                order,
            )?;
            if parent_loaded.metadata.kind != Kind::Directory {
                return Err(FfsError::NotDirectory);
            }
            let mut entries = read_dir_entries(cx, &mut os_view, *parent_dir, &staged_dirs)?;
            if entries.iter().any(|e| e.name == *name) {
                return Err(FfsError::Exists);
            }
            let new_obj = allocate_object_id(
                cx,
                &mut os_view,
                &zpl_meta_base,
                zpl_ceiling,
                &mut zpl_dirty_dnodes,
                1,
            )?;
            let dir_meta = Metadata {
                mode: (Kind::Directory.to_tag() << 12) | u64::from((*mode) & 0o7777),
                kind: Kind::Directory,
                uid: *uid,
                gid: *gid,
                size: 2,
                links: 2,
                parent: *parent_dir,
                flags: 0,
                generation: new_txg,
                times: [*timestamp; 4],
                inline_symlink: None,
            };
            let (bonus_type, nblkptr, bonus) = encode_new_zpl_bonus(
                &parent_loaded,
                &dir_meta,
                ds_ctx.zpl_version,
                ds_ctx.sa_registry.as_ref(),
                order,
            )?;
            let (bsize, blocks) =
                encode_zap_blocks_for_dnode(cx, &mut os_view, None, &[], order, min_blk)?;
            let mut dir_dirty = BTreeMap::new();
            for (i, blk) in blocks.into_iter().enumerate() {
                dir_dirty.insert(i as u64, Some(blk));
            }
            let dir_out = cow_update_dnode(
                cx,
                &mut os_view,
                alloc,
                DnodeCowSpec {
                    existing: None,
                    object_type: DMU_OT_DIRECTORY_CONTENTS,
                    bonus_type,
                    checksum_type: 7,
                    compress_type: 2,
                    user_flags: acct_flags,
                    indirect_shift: 17,
                    data_bytes: bsize,
                    max_block: (dir_dirty.len() - 1) as u64,
                    slots: 1,
                    nblkptr,
                    bonus,
                    spill: None,
                    order,
                    new_txg,
                    leaf_bucket: WriteBucket::ChildBlocks,
                    indirect_bucket: WriteBucket::ChildBlocks,
                },
                &dir_dirty,
                staged_writes,
            )?;
            zpl_born.add_assign(dir_out.born)?;
            quota_deltas.push(QuotaDelta {
                uid: *uid,
                gid: *gid,
                projid: Some(0),
                bytes_delta: i64::try_from(dir_out.dnode.used_bytes())
                    .map_err(|_| corrupt("ZFS quota bytes_delta overflow"))?,
                objs_delta: 1,
            });
            put_dnode_in_table(
                cx,
                &mut os_view,
                &zpl_meta_base,
                zpl_ceiling,
                &mut zpl_dirty_dnodes,
                new_obj,
                &dir_out.dnode,
            )?;

            let ref_val = encode_directory_reference(new_obj, Kind::Directory)
                .map_err(|e| parse_err(&e))?;
            entries.push(RawZapEntry {
                name: name.clone(),
                integer_bytes: 8,
                values: vec![ref_val],
                collision: 0,
            });
            let mut new_parent_meta = parent_loaded.metadata.clone();
            new_parent_meta.size += 1;
            new_parent_meta.links += 1;
            new_parent_meta.times[1] = *timestamp;
            new_parent_meta.times[2] = *timestamp;
            let parent_dn = flush_dir_node(
                cx,
                &mut os_view,
                alloc,
                &parent_loaded,
                &new_parent_meta,
                &entries,
                ds_ctx.sa_registry.as_ref(),
                acct_flags,
                order,
                new_txg,
                staged_writes,
                &mut zpl_born,
                &mut zpl_retired,
                &mut quota_deltas,
            )?;
            staged_dirs.insert(*parent_dir, entries);
            put_dnode_in_table(
                cx,
                &mut os_view,
                &zpl_meta_base,
                zpl_ceiling,
                &mut zpl_dirty_dnodes,
                *parent_dir,
                &parent_dn,
            )?;
            new_obj
        }

        ZplMutation::WriteData {
            file_obj,
            offset,
            data,
            timestamp,
            checksum,
        } => {
            if data.len() > MAX_WRITE_PAYLOAD_BYTES {
                return Err(unsupported("single ZFS TXG write payload exceeds 16 MiB"));
            }
            let end_offset = offset
                .checked_add(data.len() as u64)
                .filter(|&e| i64::try_from(e).is_ok())
                .ok_or_else(|| FfsError::Format("ZFS write offset overflow".into()))?;
            let loaded = load_zpl_node(
                cx,
                &mut os_view,
                &zpl_meta_base,
                zpl_ceiling,
                &zpl_dirty_dnodes,
                ds_ctx.sa_registry.as_ref(),
                *file_obj,
                order,
            )?;
            if loaded.metadata.kind != Kind::Regular {
                return Err(unsupported("ZPL data write requires a regular file"));
            }
            let new_size = loaded.metadata.size.max(end_offset);
            let mut new_meta = loaded.metadata.clone();
            new_meta.size = new_size;
            new_meta.times[1] = *timestamp;
            new_meta.times[2] = *timestamp;

            if data.is_empty() {
                let (bonus, spill) = encode_updated_zpl_bonus(
                    &loaded,
                    &new_meta,
                    ds_ctx.sa_registry.as_ref(),
                    alloc,
                    order,
                    new_txg,
                    staged_writes,
                )?;
                let out = cow_update_dnode(
                    cx,
                    &mut os_view,
                    alloc,
                    DnodeCowSpec {
                        existing: Some((&loaded.dnode, loaded.ceiling)),
                        object_type: DMU_OT_PLAIN_FILE_CONTENTS,
                        bonus_type: loaded.dnode.bonus_type(),
                        checksum_type: checksum.code(),
                        compress_type: 2,
                        user_flags: acct_flags,
                        indirect_shift: loaded.dnode.indirect_shift(),
                        data_bytes: loaded.dnode.data_bytes(),
                        max_block: loaded.dnode.max_block(),
                        slots: loaded.dnode.slots(),
                        nblkptr: loaded.dnode.pointers().len(),
                        bonus,
                        spill,
                        order,
                        new_txg,
                        leaf_bucket: WriteBucket::ChildBlocks,
                        indirect_bucket: WriteBucket::ChildBlocks,
                    },
                    &BTreeMap::new(),
                    staged_writes,
                )?;
                zpl_born.add_assign(out.born)?;
                zpl_retired.extend(out.retired_bps);
                put_dnode_in_table(
                    cx,
                    &mut os_view,
                    &zpl_meta_base,
                    zpl_ceiling,
                    &mut zpl_dirty_dnodes,
                    *file_obj,
                    &out.dnode,
                )?;
                return finalize_dataset_to_mos(
                    cx,
                    mos,
                    &mut ds_ctx,
                    &mut os_view,
                    &zpl_meta_base,
                    zpl_ceiling,
                    &zpl_dirty_dnodes,
                    &zpl_born,
                    &zpl_retired,
                    &quota_deltas,
                    mos_dirty_dnodes,
                    write_features,
                    write_features_dirty,
                    empty_bpobj_id,
                    alloc,
                    order,
                    new_txg,
                    staged_writes,
                    new_size,
                );
            }

            // Choose new `data_bytes` (`dn_datablkszsec`) following OpenZFS variable-block rule:
            // single-block files grow in multiples of `min_blk` (`512`..=`recordsize`), and
            // multi-block files lock to `recordsize` (or keep existing `data_bytes` if already multi-block).
            let old_bsize = loaded.dnode.data_bytes();
            let target_bsize = if loaded.dnode.max_block() > 0 {
                old_bsize
            } else if end_offset as usize > ds_ctx.recordsize
                || loaded.metadata.size as usize > ds_ctx.recordsize
            {
                ds_ctx.recordsize
            } else {
                (new_size as usize)
                    .max(old_bsize)
                    .max(min_blk)
                    .next_multiple_of(min_blk)
                    .min(ds_ctx.recordsize)
            };
            let first_bid = *offset / (target_bsize as u64);
            let last_bid = (end_offset - 1) / (target_bsize as u64);
            let new_max_block = loaded.dnode.max_block().max(last_bid);

            let mut dirty_leaves: BTreeMap<u64, Option<Vec<u8>>> = BTreeMap::new();
            // If block 0 existed at smaller `old_bsize < target_bsize` AND `first_bid > 0`,
            // we MUST also rewrite block 0 zero-extended to `target_bsize`!
            if loaded.dnode.max_block() == 0
                && old_bsize != target_bsize
                && first_bid > 0
                && let Some((old_b0, _, _)) =
                    os_view.object_data_block(cx, &loaded.dnode, loaded.ceiling, 0)?
            {
                let mut grown = vec![0_u8; target_bsize];
                let copy_len = old_b0.len().min(target_bsize);
                grown[..copy_len].copy_from_slice(&old_b0[..copy_len]);
                dirty_leaves.insert(0, Some(grown));
            }

            for bid in first_bid..=last_bid {
                checkpoint(cx)?;
                let blk_start = bid * (target_bsize as u64);
                let blk_end = blk_start + (target_bsize as u64);
                let w_start = (*offset).max(blk_start);
                let w_end = end_offset.min(blk_end);
                let within = (w_start - blk_start) as usize;
                let count = (w_end - w_start) as usize;
                let data_off = (w_start - *offset) as usize;

                let mut blk = vec![0_u8; target_bsize];
                if !(within == 0 && count == target_bsize)
                    && bid <= loaded.dnode.max_block()
                    && (bid == 0 || loaded.dnode.data_bytes() == target_bsize)
                    && let Some((existing_bytes, _, _)) =
                        os_view.object_data_block(cx, &loaded.dnode, loaded.ceiling, bid)?
                {
                    let copy_len = existing_bytes.len().min(target_bsize);
                    blk[..copy_len].copy_from_slice(&existing_bytes[..copy_len]);
                }
                blk[within..within + count].copy_from_slice(&data[data_off..data_off + count]);
                dirty_leaves.insert(bid, Some(blk));
            }

            let cksum_code = if loaded.dnode.checksum_type() == ZfsDataChecksum::Sha256.code() {
                ZfsDataChecksum::Sha256.code()
            } else {
                checksum.code()
            };
            let (bonus, spill) = encode_updated_zpl_bonus(
                &loaded,
                &new_meta,
                ds_ctx.sa_registry.as_ref(),
                alloc,
                order,
                new_txg,
                staged_writes,
            )?;
            let old_used = loaded.dnode.used_bytes();
            let out = cow_update_dnode(
                cx,
                &mut os_view,
                alloc,
                DnodeCowSpec {
                    existing: Some((&loaded.dnode, loaded.ceiling)),
                    object_type: DMU_OT_PLAIN_FILE_CONTENTS,
                    bonus_type: loaded.dnode.bonus_type(),
                    checksum_type: cksum_code,
                    compress_type: 2,
                    user_flags: acct_flags,
                    indirect_shift: loaded.dnode.indirect_shift(),
                    data_bytes: target_bsize,
                    max_block: new_max_block,
                    slots: loaded.dnode.slots(),
                    nblkptr: loaded.dnode.pointers().len(),
                    bonus,
                    spill,
                    order,
                    new_txg,
                    leaf_bucket: WriteBucket::ChildBlocks,
                    indirect_bucket: WriteBucket::ChildBlocks,
                },
                &dirty_leaves,
                staged_writes,
            )?;
            zpl_born.add_assign(out.born)?;
            zpl_retired.extend(out.retired_bps);
            let bytes_delta = signed_bytes_delta(out.dnode.used_bytes(), old_used)?;
            if bytes_delta != 0 {
                quota_deltas.push(QuotaDelta {
                    uid: new_meta.uid,
                    gid: new_meta.gid,
                    projid: Some(0),
                    bytes_delta,
                    objs_delta: 0,
                });
            }
            put_dnode_in_table(
                cx,
                &mut os_view,
                &zpl_meta_base,
                zpl_ceiling,
                &mut zpl_dirty_dnodes,
                *file_obj,
                &out.dnode,
            )?;
            new_size
        }

        ZplMutation::TruncateFile {
            file_obj,
            new_size,
            timestamp,
            checksum,
        } => {
            if i64::try_from(*new_size).is_err() {
                return Err(FfsError::Format("ZFS truncate size exceeds i64::MAX".into()));
            }
            let loaded = load_zpl_node(
                cx,
                &mut os_view,
                &zpl_meta_base,
                zpl_ceiling,
                &zpl_dirty_dnodes,
                ds_ctx.sa_registry.as_ref(),
                *file_obj,
                order,
            )?;
            if loaded.metadata.kind != Kind::Regular {
                return Err(unsupported("ZPL truncate requires a regular file"));
            }
            let old_size = loaded.metadata.size;
            let prev_block_bytes = loaded.dnode.data_bytes();
            let mut dirty_leaves: BTreeMap<u64, Option<Vec<u8>>> = BTreeMap::new();
            let (target_bsize, target_max_block) = if *new_size == 0 {
                dirty_leaves.insert(0, None);
                (min_blk, 0)
            } else if *new_size < old_size {
                let last_bid = (*new_size - 1) / (prev_block_bytes as u64);
                let new_max = loaded.dnode.max_block().min(last_bid);
                let rem = (*new_size as usize) % prev_block_bytes;
                if rem != 0
                    && last_bid <= loaded.dnode.max_block()
                    && let Some((existing_bytes, _, _)) =
                        os_view.object_data_block(cx, &loaded.dnode, loaded.ceiling, last_bid)?
                {
                    let mut tail = existing_bytes.as_ref().clone();
                    tail[rem..].fill(0);
                    dirty_leaves.insert(last_bid, Some(tail));
                }
                (prev_block_bytes, new_max)
            } else {
                (prev_block_bytes, loaded.dnode.max_block())
            };

            let mut new_meta = loaded.metadata.clone();
            new_meta.size = *new_size;
            new_meta.times[1] = *timestamp;
            new_meta.times[2] = *timestamp;
            let (bonus, spill) = encode_updated_zpl_bonus(
                &loaded,
                &new_meta,
                ds_ctx.sa_registry.as_ref(),
                alloc,
                order,
                new_txg,
                staged_writes,
            )?;
            let old_used = loaded.dnode.used_bytes();
            let out = cow_update_dnode(
                cx,
                &mut os_view,
                alloc,
                DnodeCowSpec {
                    existing: Some((&loaded.dnode, loaded.ceiling)),
                    object_type: DMU_OT_PLAIN_FILE_CONTENTS,
                    bonus_type: loaded.dnode.bonus_type(),
                    checksum_type: checksum.code(),
                    compress_type: 2,
                    user_flags: acct_flags,
                    indirect_shift: loaded.dnode.indirect_shift(),
                    data_bytes: target_bsize,
                    max_block: target_max_block,
                    slots: loaded.dnode.slots(),
                    nblkptr: loaded.dnode.pointers().len(),
                    bonus,
                    spill,
                    order,
                    new_txg,
                    leaf_bucket: WriteBucket::ChildBlocks,
                    indirect_bucket: WriteBucket::ChildBlocks,
                },
                &dirty_leaves,
                staged_writes,
            )?;
            zpl_born.add_assign(out.born)?;
            zpl_retired.extend(out.retired_bps);
            let bytes_delta = signed_bytes_delta(out.dnode.used_bytes(), old_used)?;
            if bytes_delta != 0 {
                quota_deltas.push(QuotaDelta {
                    uid: new_meta.uid,
                    gid: new_meta.gid,
                    projid: Some(0),
                    bytes_delta,
                    objs_delta: 0,
                });
            }
            put_dnode_in_table(
                cx,
                &mut os_view,
                &zpl_meta_base,
                zpl_ceiling,
                &mut zpl_dirty_dnodes,
                *file_obj,
                &out.dnode,
            )?;
            *new_size
        }

        ZplMutation::RenameEntry {
            src_dir,
            src_name,
            dst_dir,
            dst_name,
            expected_source_object,
            timestamp,
        } => {
            validate_component(src_name, ds_ctx.utf8_only)?;
            validate_component(dst_name, ds_ctx.utf8_only)?;
            let src_parent = load_zpl_node(
                cx,
                &mut os_view,
                &zpl_meta_base,
                zpl_ceiling,
                &zpl_dirty_dnodes,
                ds_ctx.sa_registry.as_ref(),
                *src_dir,
                order,
            )?;
            if src_parent.metadata.kind != Kind::Directory {
                return Err(FfsError::NotDirectory);
            }
            let dst_parent = load_zpl_node(
                cx,
                &mut os_view,
                &zpl_meta_base,
                zpl_ceiling,
                &zpl_dirty_dnodes,
                ds_ctx.sa_registry.as_ref(),
                *dst_dir,
                order,
            )?;
            if dst_parent.metadata.kind != Kind::Directory {
                return Err(FfsError::NotDirectory);
            }

            let mut src_entries = read_dir_entries(cx, &mut os_view, *src_dir, &staged_dirs)?;
            let Some(src_pos) = src_entries.iter().position(|e| e.name == *src_name) else {
                return Err(FfsError::NotFound(
                    String::from_utf8_lossy(src_name).into_owned(),
                ));
            };
            let src_ref = src_entries[src_pos]
                .scalar()
                .map_err(|e| parse_err(&e))?;
            let (source_obj, _) = directory_reference(src_ref).map_err(|e| parse_err(&e))?;
            if let Some(expected) = expected_source_object
                && source_obj != *expected
            {
                return Err(FfsError::MvccConflict {
                    tx: new_txg,
                    block: source_obj,
                });
            }
            if source_obj == ds_ctx.root_dir {
                return Err(FfsError::PermissionDenied);
            }
            let src_obj_loaded = load_zpl_node(
                cx,
                &mut os_view,
                &zpl_meta_base,
                zpl_ceiling,
                &zpl_dirty_dnodes,
                ds_ctx.sa_registry.as_ref(),
                source_obj,
                order,
            )?;
            let is_dir = src_obj_loaded.metadata.kind == Kind::Directory;

            // Cycle check if moving a directory across parents.
            if is_dir && *src_dir != *dst_dir {
                let mut cur = *dst_dir;
                let mut seen = BTreeSet::new();
                loop {
                    checkpoint(cx)?;
                    if cur == source_obj || !seen.insert(cur) || seen.len() > MAX_PATH_DEPTH {
                        return Err(FfsError::Format(
                            "ZPL directory rename creates a cycle".into(),
                        ));
                    }
                    if cur == ds_ctx.root_dir {
                        break;
                    }
                    let anc = load_zpl_node(
                        cx,
                        &mut os_view,
                        &zpl_meta_base,
                        zpl_ceiling,
                        &zpl_dirty_dnodes,
                        ds_ctx.sa_registry.as_ref(),
                        cur,
                        order,
                    )?;
                    cur = anc.metadata.parent;
                }
            }

            if *src_dir == *dst_dir && src_name == dst_name {
                return Ok(source_obj);
            }

            let mut dst_entries = if *src_dir == *dst_dir {
                src_entries.clone()
            } else {
                read_dir_entries(cx, &mut os_view, *dst_dir, &staged_dirs)?
            };

            let mut replaced_dir = false;
            if let Some(dst_pos) = dst_entries.iter().position(|e| e.name == *dst_name) {
                let dst_ref = dst_entries[dst_pos]
                    .scalar()
                    .map_err(|e| parse_err(&e))?;
                let (target_obj, _) = directory_reference(dst_ref).map_err(|e| parse_err(&e))?;
                if target_obj == source_obj {
                    return Ok(source_obj);
                }
                let target_loaded = load_zpl_node(
                    cx,
                    &mut os_view,
                    &zpl_meta_base,
                    zpl_ceiling,
                    &zpl_dirty_dnodes,
                    ds_ctx.sa_registry.as_ref(),
                    target_obj,
                    order,
                )?;
                let target_is_dir = target_loaded.metadata.kind == Kind::Directory;
                if target_is_dir != is_dir {
                    return Err(if target_is_dir {
                        FfsError::IsDirectory
                    } else {
                        FfsError::NotDirectory
                    });
                }
                if target_is_dir {
                    let target_children =
                        read_dir_entries(cx, &mut os_view, target_obj, &staged_dirs)?;
                    if !target_children.is_empty() {
                        return Err(FfsError::NotEmpty);
                    }
                    replaced_dir = true;
                }
                dst_entries.remove(dst_pos);
                retire_or_decrement_zpl_target(
                    cx,
                    &mut os_view,
                    &zpl_meta_base,
                    zpl_ceiling,
                    &mut zpl_dirty_dnodes,
                    target_obj,
                    &target_loaded,
                    target_is_dir,
                    ds_ctx.sa_registry.as_ref(),
                    acct_flags,
                    alloc,
                    order,
                    new_txg,
                    *timestamp,
                    staged_writes,
                    &mut zpl_born,
                    &mut zpl_retired,
                    &mut quota_deltas,
                )?;
            }

            let encoded_ref = encode_directory_reference(source_obj, src_obj_loaded.metadata.kind)
                .map_err(|e| parse_err(&e))?;

            if *src_dir == *dst_dir {
                let rm_pos = dst_entries
                    .iter()
                    .position(|e| e.name == *src_name)
                    .ok_or_else(|| corrupt("missing source entry in same-dir rename"))?;
                let had_replacement = dst_entries.len() < src_entries.len();
                dst_entries.remove(rm_pos);
                dst_entries.push(RawZapEntry {
                    name: dst_name.clone(),
                    integer_bytes: 8,
                    values: vec![encoded_ref],
                    collision: 0,
                });
                let mut p_meta = src_parent.metadata.clone();
                if had_replacement {
                    p_meta.size -= 1;
                    if replaced_dir {
                        p_meta.links -= 1;
                    }
                }
                p_meta.times[1] = *timestamp;
                p_meta.times[2] = *timestamp;
                let p_dn = flush_dir_node(
                    cx,
                    &mut os_view,
                    alloc,
                    &src_parent,
                    &p_meta,
                    &dst_entries,
                    ds_ctx.sa_registry.as_ref(),
                    acct_flags,
                    order,
                    new_txg,
                    staged_writes,
                    &mut zpl_born,
                    &mut zpl_retired,
                    &mut quota_deltas,
                )?;
                staged_dirs.insert(*src_dir, dst_entries);
                put_dnode_in_table(
                    cx,
                    &mut os_view,
                    &zpl_meta_base,
                    zpl_ceiling,
                    &mut zpl_dirty_dnodes,
                    *src_dir,
                    &p_dn,
                )?;
            } else {
                let had_replacement = dst_entries.len()
                    < read_dir_entries(cx, &mut os_view, *dst_dir, &staged_dirs)?.len();
                src_entries.remove(src_pos);
                let mut sp_meta = src_parent.metadata.clone();
                sp_meta.size -= 1;
                if is_dir {
                    sp_meta.links -= 1;
                }
                sp_meta.times[1] = *timestamp;
                sp_meta.times[2] = *timestamp;
                let sp_dn = flush_dir_node(
                    cx,
                    &mut os_view,
                    alloc,
                    &src_parent,
                    &sp_meta,
                    &src_entries,
                    ds_ctx.sa_registry.as_ref(),
                    acct_flags,
                    order,
                    new_txg,
                    staged_writes,
                    &mut zpl_born,
                    &mut zpl_retired,
                    &mut quota_deltas,
                )?;
                staged_dirs.insert(*src_dir, src_entries);
                put_dnode_in_table(
                    cx,
                    &mut os_view,
                    &zpl_meta_base,
                    zpl_ceiling,
                    &mut zpl_dirty_dnodes,
                    *src_dir,
                    &sp_dn,
                )?;

                dst_entries.push(RawZapEntry {
                    name: dst_name.clone(),
                    integer_bytes: 8,
                    values: vec![encoded_ref],
                    collision: 0,
                });
                let mut dp_meta = dst_parent.metadata.clone();
                if !had_replacement {
                    dp_meta.size += 1;
                    if is_dir {
                        dp_meta.links += 1;
                    }
                } else if is_dir && !replaced_dir {
                    dp_meta.links += 1;
                }
                dp_meta.times[1] = *timestamp;
                dp_meta.times[2] = *timestamp;
                let dp_dn = flush_dir_node(
                    cx,
                    &mut os_view,
                    alloc,
                    &dst_parent,
                    &dp_meta,
                    &dst_entries,
                    ds_ctx.sa_registry.as_ref(),
                    acct_flags,
                    order,
                    new_txg,
                    staged_writes,
                    &mut zpl_born,
                    &mut zpl_retired,
                    &mut quota_deltas,
                )?;
                staged_dirs.insert(*dst_dir, dst_entries);
                put_dnode_in_table(
                    cx,
                    &mut os_view,
                    &zpl_meta_base,
                    zpl_ceiling,
                    &mut zpl_dirty_dnodes,
                    *dst_dir,
                    &dp_dn,
                )?;
            }

            // Update moved object's `parent` and `ctime`.
            let mut moved_meta = src_obj_loaded.metadata.clone();
            moved_meta.parent = *dst_dir;
            moved_meta.times[2] = *timestamp;
            let (m_bonus, m_spill) = encode_updated_zpl_bonus(
                &src_obj_loaded,
                &moved_meta,
                ds_ctx.sa_registry.as_ref(),
                alloc,
                order,
                new_txg,
                staged_writes,
            )?;
            let m_out = cow_update_dnode(
                cx,
                &mut os_view,
                alloc,
                DnodeCowSpec {
                    existing: Some((&src_obj_loaded.dnode, src_obj_loaded.ceiling)),
                    object_type: src_obj_loaded.dnode.object_type(),
                    bonus_type: src_obj_loaded.dnode.bonus_type(),
                    checksum_type: 7,
                    compress_type: 2,
                    user_flags: acct_flags,
                    indirect_shift: src_obj_loaded.dnode.indirect_shift(),
                    data_bytes: src_obj_loaded.dnode.data_bytes(),
                    max_block: src_obj_loaded.dnode.max_block(),
                    slots: src_obj_loaded.dnode.slots(),
                    nblkptr: src_obj_loaded.dnode.pointers().len(),
                    bonus: m_bonus,
                    spill: m_spill,
                    order,
                    new_txg,
                    leaf_bucket: WriteBucket::ChildBlocks,
                    indirect_bucket: WriteBucket::ChildBlocks,
                },
                &BTreeMap::new(),
                staged_writes,
            )?;
            zpl_born.add_assign(m_out.born)?;
            zpl_retired.extend(m_out.retired_bps);
            put_dnode_in_table(
                cx,
                &mut os_view,
                &zpl_meta_base,
                zpl_ceiling,
                &mut zpl_dirty_dnodes,
                source_obj,
                &m_out.dnode,
            )?;
            source_obj
        }

        ZplMutation::UnlinkEntry {
            parent_dir,
            name,
            rmdir,
            timestamp,
        } => {
            validate_component(name, ds_ctx.utf8_only)?;
            let parent_loaded = load_zpl_node(
                cx,
                &mut os_view,
                &zpl_meta_base,
                zpl_ceiling,
                &zpl_dirty_dnodes,
                ds_ctx.sa_registry.as_ref(),
                *parent_dir,
                order,
            )?;
            if parent_loaded.metadata.kind != Kind::Directory {
                return Err(FfsError::NotDirectory);
            }
            let mut entries = read_dir_entries(cx, &mut os_view, *parent_dir, &staged_dirs)?;
            let Some(pos) = entries.iter().position(|e| e.name == *name) else {
                return Err(FfsError::NotFound(
                    String::from_utf8_lossy(name).into_owned(),
                ));
            };
            let ref_val = entries[pos].scalar().map_err(|e| parse_err(&e))?;
            let (target_obj, _) = directory_reference(ref_val).map_err(|e| parse_err(&e))?;
            if target_obj == ds_ctx.root_dir {
                return Err(FfsError::PermissionDenied);
            }
            let target_loaded = load_zpl_node(
                cx,
                &mut os_view,
                &zpl_meta_base,
                zpl_ceiling,
                &zpl_dirty_dnodes,
                ds_ctx.sa_registry.as_ref(),
                target_obj,
                order,
            )?;
            let target_is_dir = target_loaded.metadata.kind == Kind::Directory;
            if target_is_dir != *rmdir {
                return Err(if target_is_dir {
                    FfsError::IsDirectory
                } else {
                    FfsError::NotDirectory
                });
            }
            if target_is_dir {
                let children = read_dir_entries(cx, &mut os_view, target_obj, &staged_dirs)?;
                if !children.is_empty() {
                    return Err(FfsError::NotEmpty);
                }
            }

            entries.remove(pos);
            let mut p_meta = parent_loaded.metadata.clone();
            p_meta.size -= 1;
            if target_is_dir {
                p_meta.links -= 1;
            }
            p_meta.times[1] = *timestamp;
            p_meta.times[2] = *timestamp;
            let p_dn = flush_dir_node(
                cx,
                &mut os_view,
                alloc,
                &parent_loaded,
                &p_meta,
                &entries,
                ds_ctx.sa_registry.as_ref(),
                acct_flags,
                order,
                new_txg,
                staged_writes,
                &mut zpl_born,
                &mut zpl_retired,
                &mut quota_deltas,
            )?;
            staged_dirs.insert(*parent_dir, entries);
            put_dnode_in_table(
                cx,
                &mut os_view,
                &zpl_meta_base,
                zpl_ceiling,
                &mut zpl_dirty_dnodes,
                *parent_dir,
                &p_dn,
            )?;

            retire_or_decrement_zpl_target(
                cx,
                &mut os_view,
                &zpl_meta_base,
                zpl_ceiling,
                &mut zpl_dirty_dnodes,
                target_obj,
                &target_loaded,
                target_is_dir,
                ds_ctx.sa_registry.as_ref(),
                acct_flags,
                alloc,
                order,
                new_txg,
                *timestamp,
                staged_writes,
                &mut zpl_born,
                &mut zpl_retired,
                &mut quota_deltas,
            )?;
            target_obj
        }
    };

    finalize_dataset_to_mos(
        cx,
        mos,
        &mut ds_ctx,
        &mut os_view,
        &zpl_meta_base,
        zpl_ceiling,
        &zpl_dirty_dnodes,
        &zpl_born,
        &zpl_retired,
        &quota_deltas,
        mos_dirty_dnodes,
        write_features,
        write_features_dirty,
        empty_bpobj_id,
        alloc,
        order,
        new_txg,
        staged_writes,
        result_u64,
    )
}

#[allow(clippy::too_many_arguments)]
fn retire_or_decrement_zpl_target(
    cx: &Cx,
    os_view: &mut Objects,
    zpl_meta_base: &Dnode,
    zpl_ceiling: u64,
    zpl_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    target_obj: u64,
    target_loaded: &LoadedZplNode,
    target_is_dir: bool,
    sa_registry: Option<&SaRegistry>,
    acct_flags: u8,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    timestamp: Timestamp,
    staged_writes: &mut Vec<StagedBlockWrite>,
    zpl_born: &mut SpaceDelta,
    zpl_retired: &mut Vec<BlockPointer>,
    quota_deltas: &mut Vec<QuotaDelta>,
) -> Result<()> {
    let rem_links = if target_is_dir {
        0
    } else {
        target_loaded.metadata.links.saturating_sub(1)
    };
    if rem_links > 0 {
        let mut next_meta = target_loaded.metadata.clone();
        next_meta.links = rem_links;
        next_meta.times[2] = timestamp;
        let (bonus, spill) = encode_updated_zpl_bonus(
            target_loaded,
            &next_meta,
            sa_registry,
            alloc,
            order,
            new_txg,
            staged_writes,
        )?;
        let out = cow_update_dnode(
            cx,
            os_view,
            alloc,
            DnodeCowSpec {
                existing: Some((&target_loaded.dnode, target_loaded.ceiling)),
                object_type: target_loaded.dnode.object_type(),
                bonus_type: target_loaded.dnode.bonus_type(),
                checksum_type: 7,
                compress_type: 2,
                user_flags: acct_flags,
                indirect_shift: target_loaded.dnode.indirect_shift(),
                data_bytes: target_loaded.dnode.data_bytes(),
                max_block: target_loaded.dnode.max_block(),
                slots: target_loaded.dnode.slots(),
                nblkptr: target_loaded.dnode.pointers().len(),
                bonus,
                spill,
                order,
                new_txg,
                leaf_bucket: WriteBucket::ChildBlocks,
                indirect_bucket: WriteBucket::ChildBlocks,
            },
            &BTreeMap::new(),
            staged_writes,
        )?;
        zpl_born.add_assign(out.born)?;
        zpl_retired.extend(out.retired_bps);
        return put_dnode_in_table(
            cx,
            os_view,
            zpl_meta_base,
            zpl_ceiling,
            zpl_dirty_dnodes,
            target_obj,
            &out.dnode,
        );
    }

    // Links == 0: retire all leaf, indirect, and spill blocks, update quota, and free dnode slot!
    collect_non_hole_bps_from(
        cx,
        os_view,
        &target_loaded.dnode,
        target_loaded.ceiling,
        0,
        true,
        zpl_retired,
    )?;
    if let Some(sbp) = target_loaded.dnode.spill() {
        zpl_retired.push(sbp.clone());
    }
    quota_deltas.push(QuotaDelta {
        uid: target_loaded.metadata.uid,
        gid: target_loaded.metadata.gid,
        projid: Some(0),
        bytes_delta: -i64::try_from(target_loaded.dnode.used_bytes())
            .map_err(|_| corrupt("ZFS quota bytes_delta overflow"))?,
        objs_delta: -1,
    });
    remove_dnode_from_table(
        cx,
        os_view,
        zpl_meta_base,
        zpl_ceiling,
        zpl_dirty_dnodes,
        target_obj,
        order,
    )
}

#[allow(clippy::too_many_arguments)]
fn finalize_dataset_to_mos(
    cx: &Cx,
    mos: &mut Objects,
    ds_ctx: &mut DatasetContext,
    os_view: &mut Objects,
    zpl_meta_base: &Dnode,
    zpl_ceiling: u64,
    zpl_dirty_dnodes: &BTreeMap<u64, Vec<u8>>,
    zpl_born_initial: &SpaceDelta,
    zpl_retired_initial: &[BlockPointer],
    quota_deltas: &[QuotaDelta],
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    write_features: &mut BTreeMap<String, u64>,
    write_features_dirty: &mut bool,
    empty_bpobj_id: Option<u64>,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
    result_u64: u64,
) -> Result<u64> {
    let mut zpl_born = *zpl_born_initial;
    let mut zpl_retired = zpl_retired_initial.to_vec();

    // 1. Update embedded ObjectSet quota ZAPs (`userused` / `groupused` / `projectused`) if active.
    apply_objectset_quota_deltas(
        cx,
        os_view,
        &mut ds_ctx.os,
        alloc,
        quota_deltas,
        order,
        new_txg,
        staged_writes,
        &mut zpl_born,
        &mut zpl_retired,
    )?;

    // 2. COW the ZPL `os_meta_dnode` (`DMU_OT_DNODE`) and ZPL `ObjectSet` root (`DMU_OT_OBJSET`).
    let mut zpl_meta_dirty = BTreeMap::new();
    for (&bid, blk) in zpl_dirty_dnodes {
        zpl_meta_dirty.insert(bid, Some(blk.clone()));
    }
    let zpl_max_block = zpl_meta_base
        .max_block()
        .max(zpl_dirty_dnodes.keys().copied().max().unwrap_or(0));
    let meta_out = cow_update_dnode(
        cx,
        os_view,
        alloc,
        DnodeCowSpec {
            existing: Some((zpl_meta_base, zpl_ceiling)),
            object_type: DMU_OT_DNODE,
            bonus_type: 0,
            checksum_type: 7,
            compress_type: 2,
            user_flags: 0,
            indirect_shift: zpl_meta_base.indirect_shift(),
            data_bytes: DNODE_BLOCK_BYTES,
            max_block: zpl_max_block,
            slots: 1,
            nblkptr: 3,
            bonus: Vec::new(),
            spill: None,
            order,
            new_txg,
            leaf_bucket: WriteBucket::DatasetMetadata,
            indirect_bucket: WriteBucket::DatasetMetadata,
        },
        &zpl_meta_dirty,
        staged_writes,
    )?;
    zpl_born.add_assign(meta_out.born)?;
    zpl_retired.extend(meta_out.retired_bps);

    ds_ctx.os.meta = meta_out.dnode;
    let zpl_os_bytes = ds_ctx.os.encode(order).map_err(|e| parse_err(&e))?;
    let zpl_os_fill = ds_ctx.os.meta_fill();
    let zpl_os_dva = alloc.allocate(zpl_os_bytes.len())?;
    let zpl_os_cksum = if matches!(ds_ctx.old_os_bp.checksum_type(), 6..=8) {
        ds_ctx.old_os_bp.checksum_type()
    } else {
        7
    };
    let new_os_bp = BlockPointer::new_regular(&RegularBlockSpec {
        dvas: &[zpl_os_dva],
        physical: &zpl_os_bytes,
        logical_bytes: zpl_os_bytes.len(),
        compression: 2,
        checksum_type: zpl_os_cksum,
        object_type: DMU_OT_OBJSET,
        level: 0,
        payload_order: order,
        birth: new_txg,
        fill: zpl_os_fill,
    })
    .map_err(|e| parse_err(&e))?;
    zpl_born.add_assign(SpaceDelta::from_bp(&new_os_bp)?)?;
    staged_writes.push(StagedBlockWrite {
        bucket: WriteBucket::DatasetMetadata,
        dva_offset: zpl_os_dva.offset,
        bytes: zpl_os_bytes,
    });
    zpl_retired.push(ds_ctx.old_os_bp.clone());

    // 3. Classify retired ZPL blocks: `birth > prev_snap_txg` -> free DVAs;
    // `birth <= prev_snap_txg` -> retain DVAs for snapshots and enqueue in `ds_deadlist_obj`!
    let mut killed_free = SpaceDelta::default();
    let mut killed_snap = SpaceDelta::default();
    let mut snap_bps = Vec::new();
    for rbp in &zpl_retired {
        if rbp.hole() || rbp.embedded() {
            continue;
        }
        if rbp.birth() > ds_ctx.prev_snap_txg {
            let d = alloc.free_block_dvas(rbp, new_txg)?;
            killed_free.add_assign(d)?;
        } else {
            killed_snap.add_assign(SpaceDelta::from_bp(rbp)?)?;
            snap_bps.push(rbp.clone());
        }
    }

    if !snap_bps.is_empty() {
        enqueue_into_dataset_deadlist(
            cx,
            mos,
            mos_dirty_dnodes,
            write_features,
            write_features_dirty,
            empty_bpobj_id,
            ds_ctx.deadlist_obj,
            &snap_bps,
            alloc,
            order,
            new_txg,
            staged_writes,
        )?;
    }

    // 4. Update `dsl_dataset_phys_t` (`head_object`) and `dsl_dir_phys_t` ancestor chain!
    let mos_meta = mos.meta_dnode().clone();
    let mos_ceiling = mos.root_birth_txg();
    let (head_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        ds_ctx.head_object,
        order,
    )?;
    let mut head_bonus = head_dn.bonus().to_vec();
    let apply_u64_delta =
        |buf: &mut [u8], at: usize, add: u64, sub: u64, label: &'static str| -> Result<()> {
            let cur = order.u64(buf, at).map_err(|e| parse_err(&e))?;
            let next = cur
                .checked_add(add)
                .and_then(|v| v.checked_sub(sub))
                .ok_or_else(|| corrupt(format!("{label} accounting underflow/overflow")))?;
            buf[at..at + 8].copy_from_slice(&order.encode(next));
            Ok(())
        };

    apply_u64_delta(
        &mut head_bonus,
        72,
        zpl_born.dsize,
        killed_free.dsize + killed_snap.dsize,
        "ds_referenced_bytes",
    )?;
    apply_u64_delta(
        &mut head_bonus,
        80,
        zpl_born.comp,
        killed_free.comp + killed_snap.comp,
        "ds_compressed_bytes",
    )?;
    apply_u64_delta(
        &mut head_bonus,
        88,
        zpl_born.uncomp,
        killed_free.uncomp + killed_snap.uncomp,
        "ds_uncompressed_bytes",
    )?;
    apply_u64_delta(
        &mut head_bonus,
        96,
        zpl_born.dsize,
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
        ds_ctx.head_object,
        &updated_head,
    )?;

    // Walk `dsl_dir` chain from `directory_object` up to root (`dd_parent_obj == 0`).
    let mut cur_dir = ds_ctx.directory_object;
    let mut is_owning_dir = true;
    let mut visited_dirs = BTreeSet::new();
    while cur_dir != 0 {
        checkpoint(cx)?;
        if !visited_dirs.insert(cur_dir) {
            return Err(corrupt("cycle in DSL directory parent chain"));
        }
        let (dir_dn, _) = read_staged_or_committed_dnode(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            cur_dir,
            order,
        )?;
        let mut dir_bonus = dir_dn.bonus().to_vec();
        let parent_dir = order.u64(&dir_bonus, 16).map_err(|e| parse_err(&e))?;
        let dd_flags = order.u64(&dir_bonus, 96).map_err(|e| parse_err(&e))?;

        apply_u64_delta(
            &mut dir_bonus,
            40,
            zpl_born.dsize,
            killed_free.dsize,
            "dd_used_bytes",
        )?;
        apply_u64_delta(
            &mut dir_bonus,
            48,
            zpl_born.comp,
            killed_free.comp,
            "dd_compressed_bytes",
        )?;
        apply_u64_delta(
            &mut dir_bonus,
            56,
            zpl_born.uncomp,
            killed_free.uncomp,
            "dd_uncompressed_bytes",
        )?;
        if dd_flags & 1 != 0 {
            if is_owning_dir {
                // DD_USED_HEAD (`104..112`) loses both `killed_free` and `killed_snap`;
                // DD_USED_SNAP (`112..120`) gains `killed_snap`!
                apply_u64_delta(
                    &mut dir_bonus,
                    104,
                    zpl_born.dsize,
                    killed_free.dsize + killed_snap.dsize,
                    "dd_used_breakdown[HEAD]",
                )?;
                if killed_snap.dsize != 0 {
                    apply_u64_delta(
                        &mut dir_bonus,
                        112,
                        killed_snap.dsize,
                        0,
                        "dd_used_breakdown[SNAP]",
                    )?;
                }
            } else {
                // Ancestor DSL dirs count all descendant space in DD_USED_CHILD (`120..128`).
                apply_u64_delta(
                    &mut dir_bonus,
                    120,
                    zpl_born.dsize,
                    killed_free.dsize,
                    "dd_used_breakdown[CHILD]",
                )?;
            }
        }
        let mut updated_dir = dir_dn;
        let dir_btype = updated_dir.bonus_type();
        updated_dir
            .set_bonus_and_spill(dir_btype, dir_bonus, None)
            .map_err(|e| parse_err(&e))?;
        put_dnode_in_table(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            cur_dir,
            &updated_dir,
        )?;
        is_owning_dir = false;
        cur_dir = parent_dir;
    }

    let _ = DNODE_BYTES;
    Ok(result_u64)
}
