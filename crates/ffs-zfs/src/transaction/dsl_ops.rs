//! Native ZFS DSL lifecycle transactions: snapshots (`create_snapshot`,
//! `destroy_snapshot`, `rename_snapshot`), datasets & clones (`create_dataset`,
//! `create_clone`, `rename_dataset`, `destroy_dataset`), holds (`hold_snapshot`,
//! `release_snapshot`, `list_holds`), bookmarks (`create_bookmark`,
//! `destroy_bookmark`, `list_bookmarks`), and dataset properties / quotas /
//! reservations (`set_property`, `inherit_property`, quota preflight).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_ondisk::zfs::crypto::{
    DSL_CRYPTO_KEY_VERSION_V1, DSL_DATASET_IVSET_GUID, DSL_DIR_CRYPTO_KEY_OBJ, DslCryptoKeyRecord,
    UnwrappedDslKey, ZFS_PBKDF2_DEFAULT_ITERS, ZFS_PBKDF2_MIN_ITERS, ZfsKeyFormat, ZioEncrypt,
};
use ffs_ondisk::zfs::{BlockPointer, Endian};
use ffs_ondisk::zfs_dmu::{
    DMU_OT_DNODE, DNODE_BLOCK_BYTES, DNODE_BYTES, DNODE_FLAG_USED_BYTES, Dnode, DnodeSpec,
    OBJSET_GROUPUSED_OFFSET, OBJSET_PROJECTUSED_OFFSET, OBJSET_USERUSED_OFFSET, ObjectSet,
    dnode_at,
};
use ffs_ondisk::zfs_zap::Entry as RawZapEntry;
use ffs_ondisk::zfs_zap::names::NamePolicy as ZapNamePolicy;
use ffs_ondisk::zfs_zpl::{Kind, Metadata, SaRegistry, Timestamp, encode_directory_reference};
use serde::Serialize;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{
    ZfsDatasetCryptoInfo, ZfsKeyMaterial, ZfsNonceGenerator, encode_dsl_crypto_key_zap,
    generate_new_dataset_keys, parse_dsl_crypto_key_zap,
};
use crate::reader::dmu::properties::PropertyValue;
use crate::reader::dmu::{DatasetCryptoContext, Objects};

use super::dmu_cow::{
    DMU_OT_BPOBJ, DMU_OT_BPOBJ_HDR, DMU_OT_DEADLIST, DMU_OT_DEADLIST_HDR,
    DMU_OT_DIRECTORY_CONTENTS, DatasetCompression, DatasetFeatureUsage, DatasetWriteCrypto,
    DnodeCowSpec, FATZAP_BLOCK_BYTES, MosFeatureState, PoolSpaceAllocator, SpaceDelta,
    StagedBlockWrite, WriteBucket, allocate_object_id, append_bps_to_bpobj_inner,
    collect_non_hole_bps_from, cow_update_dnode, cow_update_dnode_with_crypto,
    encode_zap_blocks_for_dnode, encode_zap_blocks_for_dnode_with_normflags,
    objectset_user_accounting_flags, put_dnode_in_table, read_dnode_prefix,
    read_staged_or_committed_dnode, remove_dnode_from_table, write_dataset_objset_block,
    zap_optional_u64, zap_required_u64,
};
use super::{checkpoint, corrupt, parse_err, unsupported};

pub(super) const DMU_OT_DSL_DIR: u8 = 12;
pub(super) const DMU_OT_DSL_DIR_CHILD_MAP: u8 = 13;
pub(super) const DMU_OT_DSL_DS_SNAP_MAP: u8 = 14;
pub(super) const DMU_OT_DSL_PROPS: u8 = 15;
pub(super) const DMU_OT_DSL_DATASET: u8 = 16;
const DMU_OT_MASTER_NODE: u8 = 21;
const DMU_OT_UNLINKED_SET: u8 = 22;
const DMU_OT_NEXT_CLONES: u8 = 37;
const DMU_OT_USERREFS: u8 = 41;
const DMU_OT_SA: u8 = 44;
const DMU_OT_SA_MASTER_NODE: u8 = 45;
const DMU_OT_SA_ATTR_REGISTRATION: u8 = 46;
const DMU_OT_SA_ATTR_LAYOUTS: u8 = 47;
const DMU_OT_DSL_CLONES: u8 = 52;
const DMU_OT_BPOBJ_SUBOBJ: u8 = 53;
pub(super) const DMU_OTN_ZAP_METADATA: u8 = 196;

pub(super) const DS_FLAG_UNIQUE_ACCURATE: u64 = 0x4;
const DS_FLAG_DEFER_DESTROY: u64 = 0x8;
pub(super) const DD_FLAG_USED_BREAKDOWN: u64 = 0x1;

const ZFS_ACL_TRIVIAL: u64 = 0x4;
const ZFS_NO_EXECS_DENIED: u64 = 0x100;

/// One active user hold on a ZFS snapshot (`ds_userrefs_obj`, `DMU_OT_USERREFS = 41`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZfsHoldInfo {
    pub tag: String,
    pub timestamp_seconds: u64,
}

/// One native ZFS bookmark (`com.delphix:bookmarks` on zapified head `dsl_dataset`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZfsBookmarkInfo {
    pub name: String,
    pub creation_txg: u64,
    pub creation_time: u64,
    pub guid: u64,
}

/// Property value supplied to [`super::ZfsTransactionEngine::set_property`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZfsPropertySetValue {
    Number(u64),
    Text(Vec<u8>),
}

/// Native encryption creation parameters for [`super::ZfsTransactionEngine::create_encrypted_dataset`].
#[derive(Debug, Clone)]
pub struct ZfsEncryptionCreateOptions {
    /// Requested OpenZFS cipher suite (`On`, `Off`, `Inherit`, or concrete AES-128/192/256 GCM/CCM).
    pub suite: ZioEncrypt,
    /// Required wrapping key input when creating a new encryption root (`suite.is_active()`).
    pub key_material: Option<ZfsKeyMaterial>,
    /// Optional `keylocation` property text (defaults to `"prompt"` for new encryption roots).
    pub keylocation: Option<Vec<u8>>,
    /// Optional PBKDF2-HMAC-SHA1 iteration count for `keyformat=passphrase` (`>= 100_000`, default `350_000`).
    pub pbkdf2_iters: Option<u64>,
    /// Optional caller input mixed with mandatory OS entropy for key/IV generation.
    pub extra_entropy: Vec<u8>,
}

/// DSL-level pool/dataset mutation staged in one atomic TXG.
#[derive(Debug, Clone)]
pub(super) enum DslMutation {
    CreateSnapshot {
        dataset: Vec<Vec<u8>>,
        snap_name: Vec<u8>,
        timestamp: Timestamp,
    },
    DestroySnapshot {
        dataset: Vec<Vec<u8>>,
        snap_name: Vec<u8>,
        defer: bool,
    },
    RenameSnapshot {
        dataset: Vec<Vec<u8>>,
        old_snap_name: Vec<u8>,
        new_snap_name: Vec<u8>,
    },
    HoldSnapshot {
        dataset: Vec<Vec<u8>>,
        snap_name: Vec<u8>,
        tag: Vec<u8>,
        timestamp: Timestamp,
    },
    ReleaseSnapshot {
        dataset: Vec<Vec<u8>>,
        snap_name: Vec<u8>,
        tag: Vec<u8>,
    },
    CreateBookmark {
        dataset: Vec<Vec<u8>>,
        bookmark_name: Vec<u8>,
        source_name: Vec<u8>,
        source_is_bookmark: bool,
    },
    DestroyBookmark {
        dataset: Vec<Vec<u8>>,
        bookmark_name: Vec<u8>,
    },
    CreateDataset {
        parent_dataset: Vec<Vec<u8>>,
        child_name: Vec<u8>,
        initial_props: Vec<(String, ZfsPropertySetValue)>,
        encryption: Option<ZfsEncryptionCreateOptions>,
        timestamp: Timestamp,
    },
    CreateClone {
        origin_dataset: Vec<Vec<u8>>,
        origin_snap: Vec<u8>,
        target_parent: Vec<Vec<u8>>,
        target_name: Vec<u8>,
        initial_props: Vec<(String, ZfsPropertySetValue)>,
        timestamp: Timestamp,
    },
    RenameDataset {
        old_dataset: Vec<Vec<u8>>,
        new_dataset: Vec<Vec<u8>>,
    },
    DestroyDataset {
        dataset: Vec<Vec<u8>>,
    },
    SetProperty {
        dataset: Vec<Vec<u8>>,
        name: String,
        value: ZfsPropertySetValue,
    },
    InheritProperty {
        dataset: Vec<Vec<u8>>,
        name: String,
    },
    ChangeKey {
        dataset: Vec<Vec<u8>>,
        new_material: ZfsKeyMaterial,
        new_keylocation: Option<Vec<u8>>,
        pbkdf2_iters: Option<u64>,
        extra_entropy: Vec<u8>,
    },
}

impl DslMutation {
    pub const fn op_name(&self) -> &'static str {
        match self {
            Self::CreateSnapshot { .. } => "create_snapshot",
            Self::DestroySnapshot { .. } => "destroy_snapshot",
            Self::RenameSnapshot { .. } => "rename_snapshot",
            Self::HoldSnapshot { .. } => "hold_snapshot",
            Self::ReleaseSnapshot { .. } => "release_snapshot",
            Self::CreateBookmark { .. } => "create_bookmark",
            Self::DestroyBookmark { .. } => "destroy_bookmark",
            Self::CreateDataset { .. } => "create_dataset",
            Self::CreateClone { .. } => "create_clone",
            Self::RenameDataset { .. } => "rename_dataset",
            Self::DestroyDataset { .. } => "destroy_dataset",
            Self::SetProperty { .. } => "set_property",
            Self::InheritProperty { .. } => "inherit_property",
            Self::ChangeKey { .. } => "change_key",
        }
    }
}

/// Staged DSL mutation result carrying any freshly created encryption-root key
/// to be inserted into the engine keyring ONLY after durable TXG commit.
pub(super) struct DslStageResult {
    pub value: u64,
    pub new_root_key: Option<(u64, UnwrappedDslKey)>,
}

pub(super) fn reject_busy(detail: impl Into<String>) -> FfsError {
    FfsError::RequestRejected {
        errno: libc::EBUSY,
        detail: detail.into(),
    }
}

pub(super) fn reject_einval(detail: impl Into<String>) -> FfsError {
    FfsError::RequestRejected {
        errno: libc::EINVAL,
        detail: detail.into(),
    }
}

pub(super) fn reject_edquot(detail: impl Into<String>) -> FfsError {
    FfsError::RequestRejected {
        errno: libc::EDQUOT,
        detail: detail.into(),
    }
}

pub(super) fn validate_dsl_component(name: &[u8], ascii_only: bool) -> Result<()> {
    if name.is_empty()
        || name.len() > 255
        || matches!(name, b"." | b"..")
        || name.starts_with(b"$")
        || name.iter().any(|b| matches!(*b, 0 | b'/' | b'@' | b'#'))
    {
        return Err(reject_einval("invalid ZFS dataset/snapshot/bookmark name"));
    }
    if ascii_only && !name.is_ascii() {
        return Err(reject_einval(
            "ZFS snapshot/bookmark name must be ASCII for normalized catalog",
        ));
    }
    Ok(())
}

fn validate_hold_tag(tag: &[u8]) -> Result<()> {
    if tag.is_empty() || tag.len() > 255 || tag.contains(&0) {
        return Err(reject_einval("invalid ZFS snapshot hold tag"));
    }
    Ok(())
}

pub(super) fn derive_unique_guid(pool_guid: u64, new_txg: u64, obj_id: u64, salt: u64) -> u64 {
    let mut h = blake3::Hasher::new();
    h.update(b"ffs.zfs.dsl.guid.v1:");
    h.update(&pool_guid.to_le_bytes());
    h.update(&new_txg.to_le_bytes());
    h.update(&obj_id.to_le_bytes());
    h.update(&salt.to_le_bytes());
    let bytes = h.finalize();
    let v = u64::from_le_bytes(bytes.as_bytes()[0..8].try_into().unwrap_or([1; 8]));
    if v == 0 { 1 } else { v }
}

pub(super) fn derive_fsid_guid(guid: u64) -> u64 {
    let masked = guid & 0x00FF_FFFF_FFFF_FFFF;
    if masked == 0 { 1 } else { masked }
}

/// Check `refquota` (against `head.ds_referenced_bytes + ref_delta`) and `dd_quota`
/// (against `dir.dd_used_bytes + used_delta` across `directory_object` and all ancestors)
/// before publishing a ZPL or DSL space increase.
#[allow(clippy::too_many_arguments)]
pub(super) fn enforce_dataset_quotas_for_growth(
    cx: &Cx,
    mos: &mut Objects,
    mos_dirty_dnodes: &BTreeMap<u64, Vec<u8>>,
    head_object: u64,
    directory_object: u64,
    ref_add: u64,
    used_add: u64,
    order: Endian,
) -> Result<()> {
    if ref_add == 0 && used_add == 0 {
        return Ok(());
    }
    let mos_meta = mos.meta_dnode().clone();
    let mos_ceiling = mos.root_birth_txg();
    let (head_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        head_object,
        order,
    )?;
    let cur_ref = order.u64(head_dn.bonus(), 72).map_err(|e| parse_err(&e))?;
    let (own_dir_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        directory_object,
        order,
    )?;
    let props_zap = order
        .u64(own_dir_dn.bonus(), 80)
        .map_err(|e| parse_err(&e))?;
    if ref_add > 0
        && props_zap != 0
        && let Some(rq) = effective_local_numeric_prop(&mos.zap_values(cx, props_zap)?, "refquota")?
        && rq > 0
        && ref_add > rq.saturating_sub(cur_ref)
    {
        return Err(reject_edquot("ZFS dataset refquota exceeded"));
    }

    if used_add > 0 {
        let mut cur_dir = directory_object;
        let mut seen = BTreeSet::new();
        let mut growth = used_add;
        while cur_dir != 0 && growth > 0 {
            checkpoint(cx)?;
            if !seen.insert(cur_dir) {
                return Err(corrupt("cycle in DSL directory ancestry"));
            }
            let (dd_dn, _) = read_staged_or_committed_dnode(
                cx,
                mos,
                &mos_meta,
                mos_ceiling,
                mos_dirty_dnodes,
                cur_dir,
                order,
            )?;
            let parent = order.u64(dd_dn.bonus(), 16).map_err(|e| parse_err(&e))?;
            let dd_used = order.u64(dd_dn.bonus(), 40).map_err(|e| parse_err(&e))?;
            let dd_quota = order.u64(dd_dn.bonus(), 64).map_err(|e| parse_err(&e))?;
            if dd_quota > 0 && growth > dd_quota.saturating_sub(dd_used) {
                return Err(reject_edquot("ZFS dataset or ancestor quota exceeded"));
            }
            // The parent already carries max(dd_used, dd_reserved) for this
            // child. Only growth beyond that commitment reaches the next quota.
            let dd_reserved = order.u64(dd_dn.bonus(), 72).map_err(|e| parse_err(&e))?;
            growth = growth.saturating_sub(dd_reserved.saturating_sub(dd_used));
            cur_dir = parent;
        }
    }
    Ok(())
}

/// Ensure physical pool free bytes (`post_alloc_free_bytes`) cover all unconsumed
/// `reservation` and `refreservation` commitments across every dataset in the pool.
#[allow(clippy::too_many_arguments)]
pub(super) fn enforce_pool_reservations_for_growth(
    cx: &Cx,
    mos: &mut Objects,
    mos_dirty_dnodes: &BTreeMap<u64, Vec<u8>>,
    target_head_object: u64,
    target_directory_object: u64,
    target_used_add: u64,
    extra_reserved_demand: u64,
    post_alloc_free_bytes: u64,
    order: Endian,
) -> Result<()> {
    let mos_meta = mos.meta_dnode().clone();
    let mos_ceiling = mos.root_birth_txg();

    let mut consumed_target_refrsrv = 0_u64;
    if target_head_object != 0 && target_directory_object != 0 && target_used_add > 0 {
        let (th_dn, _) = read_staged_or_committed_dnode(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            target_head_object,
            order,
        )?;
        let (tdd_dn, _) = read_staged_or_committed_dnode(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            target_directory_object,
            order,
        )?;
        let cur_u = order.u64(th_dn.bonus(), 96).map_err(|e| parse_err(&e))?;
        let p_zap = order.u64(tdd_dn.bonus(), 80).map_err(|e| parse_err(&e))?;
        if p_zap != 0
            && let Some(refrsrv) =
                effective_local_numeric_prop(&mos.zap_values(cx, p_zap)?, "refreservation")?
            && refrsrv > cur_u
        {
            consumed_target_refrsrv = (refrsrv - cur_u).min(target_used_add);
        }
    }
    let net_used_add = target_used_add.saturating_sub(consumed_target_refrsrv);

    let mut ancestors = BTreeSet::new();
    let mut walk = target_directory_object;
    while walk != 0 && ancestors.insert(walk) {
        let (dd_dn, _) = read_staged_or_committed_dnode(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            walk,
            order,
        )?;
        walk = order.u64(dd_dn.bonus(), 16).map_err(|e| parse_err(&e))?;
    }

    let mut total_reserved_slack = extra_reserved_demand;
    for ds in mos.datasets(cx)? {
        if ds.objectset_kind.is_none() {
            continue;
        }
        let (h_dn, _) = read_staged_or_committed_dnode(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            ds.head_object,
            order,
        )?;
        let (dd_dn, _) = read_staged_or_committed_dnode(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            ds.directory_object,
            order,
        )?;
        let cur_unique = order.u64(h_dn.bonus(), 96).map_err(|e| parse_err(&e))?;
        let post_unique = if ds.head_object == target_head_object {
            cur_unique.saturating_add(target_used_add)
        } else {
            cur_unique
        };
        let props_zap = order.u64(dd_dn.bonus(), 80).map_err(|e| parse_err(&e))?;
        let refrsrv_slack = if props_zap != 0
            && let Some(refrsrv) =
                effective_local_numeric_prop(&mos.zap_values(cx, props_zap)?, "refreservation")?
        {
            refrsrv.saturating_sub(post_unique)
        } else {
            0_u64
        };
        let cur_dd_used = order.u64(dd_dn.bonus(), 40).map_err(|e| parse_err(&e))?;
        let dd_reserved = order.u64(dd_dn.bonus(), 72).map_err(|e| parse_err(&e))?;
        let post_dd_used = if ancestors.contains(&ds.directory_object) {
            cur_dd_used.saturating_add(net_used_add)
        } else {
            cur_dd_used
        };
        let rsrv_slack = dd_reserved.saturating_sub(post_dd_used);
        total_reserved_slack = total_reserved_slack
            .saturating_add(refrsrv_slack)
            .saturating_add(rsrv_slack);
    }

    if total_reserved_slack > post_alloc_free_bytes {
        return Err(FfsError::NoSpace);
    }
    Ok(())
}

pub(super) fn effective_local_numeric_prop(
    rows: &[RawZapEntry],
    name: &str,
) -> Result<Option<u64>> {
    if let Some(v) = zap_optional_u64(rows, name.as_bytes())? {
        return Ok(Some(v));
    }
    let inherit_key = format!("{name}$inherit");
    if rows.iter().any(|r| r.name == inherit_key.as_bytes()) {
        return Ok(None);
    }
    let recvd_key = format!("{name}$recvd");
    zap_optional_u64(rows, recvd_key.as_bytes())
}

const EXTENSIBLE_DATASET_FEATURE: &str = "com.delphix:extensible_dataset";
const DATASET_BLOCK_FEATURES: [&str; 3] = [
    "org.open-zfs:large_blocks",
    "org.illumos:sha512",
    "org.freebsd:zstd_compress",
];

fn require_dataset_block_feature(features: &MosFeatureState, feature: &str) -> Result<()> {
    for required in [feature, EXTENSIBLE_DATASET_FEATURE] {
        if !features.read_features.contains_key(required) {
            return Err(unsupported(format!(
                "ZFS dataset block feature requires enabled pool feature {required}"
            )));
        }
    }
    Ok(())
}

pub(super) fn dataset_block_feature_owners(
    rows: &[RawZapEntry],
    features: &MosFeatureState,
) -> Result<Vec<&'static str>> {
    let mut owners = Vec::new();
    for feature in DATASET_BLOCK_FEATURES {
        if let Some(value) = zap_optional_u64(rows, feature.as_bytes())? {
            if value != 0 {
                return Err(corrupt(format!(
                    "native dataset feature {feature} requires a zero-valued ownership marker"
                )));
            }
            if features
                .read_features
                .get(feature)
                .is_none_or(|count| *count == 0)
            {
                return Err(corrupt(format!(
                    "native dataset owns {feature} without an active pool feature"
                )));
            }
            owners.push(feature);
        }
    }
    Ok(owners)
}

pub(super) fn dataset_feature_entries(
    cx: &Cx,
    mos: &mut Objects,
    object: u64,
    node: &Dnode,
    features: &MosFeatureState,
) -> Result<Vec<RawZapEntry>> {
    if node.bonus_type() != DMU_OT_DSL_DATASET || node.spill().is_some() {
        return Err(unsupported(
            "unsupported native dataset bonus or spill layout",
        ));
    }
    if node.object_type() == DMU_OT_DSL_DATASET {
        if node.pointers().iter().any(|pointer| !pointer.hole()) {
            return Err(corrupt("non-extensible native dataset has allocated data"));
        }
        return Ok(Vec::new());
    }
    if node.object_type() != DMU_OTN_ZAP_METADATA {
        return Err(corrupt("native dataset has an invalid object type"));
    }
    if features
        .read_features
        .get(EXTENSIBLE_DATASET_FEATURE)
        .is_none_or(|count| *count == 0)
    {
        return Err(corrupt(
            "zapified native dataset requires an active extensible-dataset feature",
        ));
    }
    let rows = mos.zap_values(cx, object)?;
    dataset_block_feature_owners(&rows, features)?;
    Ok(rows)
}

/// Add missing native ownership markers to an existing or newly created ZAP.
/// The caller accounts for the ZAP object's extensible-dataset ownership.
pub(super) fn activate_dataset_block_features(
    rows: &mut Vec<RawZapEntry>,
    required_features: &[&str],
    features: &mut MosFeatureState,
    new_txg: u64,
) -> Result<bool> {
    let owners = dataset_block_feature_owners(rows, features)?;
    let mut missing = BTreeSet::new();
    for requested in required_features {
        let feature = DATASET_BLOCK_FEATURES
            .into_iter()
            .find(|feature| feature == requested)
            .ok_or_else(|| unsupported("unsupported native dataset block feature"))?;
        require_dataset_block_feature(features, feature)?;
        if !owners.contains(&feature) {
            missing.insert(feature);
        }
    }
    let changed = !missing.is_empty();
    for feature in missing {
        features.increment_read(feature, new_txg)?;
        rows.push(RawZapEntry {
            name: feature.as_bytes().to_vec(),
            integer_bytes: 8,
            values: vec![0],
            collision: 0,
        });
    }
    Ok(changed)
}

/// OpenZFS activates ZSTD when its property is explicitly set, even before a
/// compressed block is born. Inherited compression activates on block birth.
pub(super) fn activate_initial_compression_feature(
    rows: &mut Vec<RawZapEntry>,
    initial_props: &[(String, ZfsPropertySetValue)],
    features: &mut MosFeatureState,
    new_txg: u64,
) -> Result<()> {
    let mut requires_zstd = false;
    for (name, value) in initial_props {
        if name != "compression" {
            continue;
        }
        let ZfsPropertySetValue::Number(raw) = value else {
            return Err(reject_einval(
                "ZFS compression requires a numeric property value",
            ));
        };
        DatasetCompression::from_property(*raw, features)?;
        requires_zstd |= raw & 127 == 16;
    }
    if requires_zstd {
        activate_dataset_block_features(rows, &["org.freebsd:zstd_compress"], features, new_txg)?;
    }
    Ok(())
}

/// Release exactly one dataset's ownership of each feature it actually stores.
pub(super) fn release_dataset_block_features(
    rows: &[RawZapEntry],
    features: &mut MosFeatureState,
) -> Result<()> {
    for feature in dataset_block_feature_owners(rows, features)? {
        features.decrement_read(feature)?;
    }
    Ok(())
}

/// Activate features required by newly born dataset blocks in this same TXG.
/// The native boolean ownership marker lives on each head/snapshot/clone, and
/// survives property changes and block retirement until that owner is destroyed.
/// Call once after the head bonus update, with the complete required feature set.
#[allow(clippy::too_many_arguments)]
pub(super) fn stage_activate_dataset_features(
    cx: &Cx,
    mos: &mut Objects,
    head_object: u64,
    required_features: &[&str],
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    features: &mut MosFeatureState,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<()> {
    checkpoint(cx)?;
    let mos_meta = mos.meta_dnode().clone();
    let mos_ceiling = mos.root_birth_txg();
    let (committed, _) = mos.object_with_ceiling(cx, head_object)?;
    let (head, ceiling) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        head_object,
        order,
    )?;
    // The staged bonus contains the just-staged data/accounting roots, but
    // ZAP reads still resolve committed blocks. Never discard an earlier staged
    // ZAP rewrite by accidentally reloading its old entries from the MOS.
    if head.object_type() != committed.object_type()
        || head.pointers() != committed.pointers()
        || head.levels() != committed.levels()
        || head.data_bytes() != committed.data_bytes()
        || head.max_block() != committed.max_block()
    {
        return Err(unsupported(
            "dataset feature activation requires unchanged head ZAP data in this TXG",
        ));
    }
    let mut rows = dataset_feature_entries(cx, mos, head_object, &head, features)?;
    if !activate_dataset_block_features(&mut rows, required_features, features, new_txg)? {
        return Ok(());
    }
    if head.object_type() != DMU_OTN_ZAP_METADATA {
        features.increment_read(EXTENSIBLE_DATASET_FEATURE, new_txg)?;
    }
    write_zap_dnode_in_mos(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        alloc,
        head_object,
        Some((&head, ceiling)),
        DMU_OTN_ZAP_METADATA,
        DMU_OT_DSL_DATASET,
        head.bonus().to_vec(),
        &rows,
        0,
        false,
        order,
        new_txg,
        staged_writes,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn write_zap_dnode_in_mos(
    cx: &Cx,
    mos: &mut Objects,
    mos_meta: &Dnode,
    mos_ceiling: u64,
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    alloc: &mut PoolSpaceAllocator,
    object_id: u64,
    existing: Option<(&Dnode, u64)>,
    object_type: u8,
    bonus_type: u8,
    bonus: Vec<u8>,
    entries: &[RawZapEntry],
    default_normflags: u64,
    force_fatzap: bool,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<()> {
    let min_blk = (1_usize << alloc.ashift).max(512);
    let (bsize, blocks) = if force_fatzap {
        let blks = ffs_ondisk::zfs_zap::encode_fatzap_with_normflags(
            entries,
            FATZAP_BLOCK_BYTES,
            0x5A46_535F_4646_5331,
            false,
            default_normflags,
            order,
        )
        .map_err(|e| parse_err(&e))?;
        (FATZAP_BLOCK_BYTES, blks)
    } else {
        encode_zap_blocks_for_dnode_with_normflags(
            cx,
            mos,
            existing,
            entries,
            default_normflags,
            order,
            min_blk,
        )?
    };
    let mut dirty = BTreeMap::new();
    for (idx, blk) in blocks.into_iter().enumerate() {
        dirty.insert(idx as u64, Some(blk));
    }
    let nblkptr = existing.map_or_else(
        || if bonus.is_empty() { 3 } else { 1 },
        |(dn, _)| dn.pointers().len(),
    );
    let ind_shift = existing.map_or(17, |(dn, _)| dn.indirect_shift());
    let slots = existing.map_or(1, |(dn, _)| dn.slots());
    let out = cow_update_dnode(
        cx,
        mos,
        alloc,
        DnodeCowSpec {
            existing,
            object_type,
            bonus_type,
            checksum_type: 7,
            compress_type: 2,
            user_flags: 0,
            indirect_shift: ind_shift,
            data_bytes: bsize,
            max_block: (dirty.len() - 1) as u64,
            slots,
            nblkptr,
            bonus,
            spill: None,
            order,
            new_txg,
            leaf_bucket: WriteBucket::DatasetMetadata,
            indirect_bucket: WriteBucket::DatasetMetadata,
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
        mos_dirty_dnodes,
        object_id,
        &out.dnode,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn free_mos_object_completely(
    cx: &Cx,
    mos: &mut Objects,
    mos_meta: &Dnode,
    mos_ceiling: u64,
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    alloc: &mut PoolSpaceAllocator,
    object_id: u64,
    order: Endian,
    new_txg: u64,
) -> Result<()> {
    if object_id == 0 {
        return Ok(());
    }
    let (dn, ceiling) = read_staged_or_committed_dnode(
        cx,
        mos,
        mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        object_id,
        order,
    )?;
    let mut bps = Vec::new();
    collect_non_hole_bps_from(cx, mos, &dn, ceiling, 0, true, &mut bps)?;
    if let Some(sbp) = dn.spill() {
        bps.push(sbp.clone());
    }
    for bp in &bps {
        alloc.free_block_dvas(bp, new_txg)?;
    }
    remove_dnode_from_table(
        cx,
        mos,
        mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        object_id,
        order,
    )
}

#[allow(clippy::too_many_arguments)]
fn flatten_bpobj_recursive(
    cx: &Cx,
    mos: &mut Objects,
    mos_meta: &Dnode,
    mos_ceiling: u64,
    mos_dirty_dnodes: &BTreeMap<u64, Vec<u8>>,
    bpobj_id: u64,
    empty_bpobj_id: Option<u64>,
    visited: &mut BTreeSet<u64>,
    order: Endian,
    out_bps: &mut Vec<BlockPointer>,
) -> Result<()> {
    checkpoint(cx)?;
    if bpobj_id == 0 || Some(bpobj_id) == empty_bpobj_id {
        return Ok(());
    }
    if !visited.insert(bpobj_id) {
        return Err(corrupt("cycle in ZFS bpobj subobjects"));
    }
    let (dn, ceiling) = read_staged_or_committed_dnode(
        cx,
        mos,
        mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        bpobj_id,
        order,
    )?;
    if dn.object_type() != DMU_OT_BPOBJ
        || dn.bonus_type() != DMU_OT_BPOBJ_HDR
        || dn.bonus().len() < 16
    {
        return Err(corrupt("invalid DMU_OT_BPOBJ dnode"));
    }
    let count = order.u64(dn.bonus(), 0).map_err(|e| parse_err(&e))?;
    let byte_len = usize::try_from(
        count
            .checked_mul(128)
            .ok_or_else(|| corrupt("bpobj count overflow"))?,
    )
    .map_err(|_| unsupported("bpobj exceeds usize"))?;
    if byte_len > 0 {
        let raw = read_dnode_prefix(cx, mos, &dn, ceiling, byte_len)?;
        for chunk in raw.as_chunks::<128>().0 {
            let bp = BlockPointer::parse(chunk, dn.order()).map_err(|e| parse_err(&e))?;
            if !bp.hole() && !bp.embedded() {
                out_bps.push(bp);
            }
        }
    }
    if dn.bonus().len() >= 48 {
        let subobjs_id = order.u64(dn.bonus(), 32).map_err(|e| parse_err(&e))?;
        let num_subobjs = order.u64(dn.bonus(), 40).map_err(|e| parse_err(&e))?;
        if subobjs_id != 0 && num_subobjs > 0 {
            let (sub_dn, sub_ceil) = read_staged_or_committed_dnode(
                cx,
                mos,
                mos_meta,
                mos_ceiling,
                mos_dirty_dnodes,
                subobjs_id,
                order,
            )?;
            if sub_dn.object_type() != DMU_OT_BPOBJ_SUBOBJ {
                return Err(corrupt("bpo_subobjs is not DMU_OT_BPOBJ_SUBOBJ"));
            }
            let sub_bytes = usize::try_from(
                num_subobjs
                    .checked_mul(8)
                    .ok_or_else(|| corrupt("bpo_num_subobjs overflow"))?,
            )
            .map_err(|_| unsupported("bpo_num_subobjs exceeds usize"))?;
            let sub_raw = read_dnode_prefix(cx, mos, &sub_dn, sub_ceil, sub_bytes)?;
            for chunk in sub_raw.as_chunks::<8>().0 {
                let child_id = sub_dn.order().u64(chunk, 0).map_err(|e| parse_err(&e))?;
                flatten_bpobj_recursive(
                    cx,
                    mos,
                    mos_meta,
                    mos_ceiling,
                    mos_dirty_dnodes,
                    child_id,
                    empty_bpobj_id,
                    visited,
                    order,
                    out_bps,
                )?;
            }
        }
    }
    Ok(())
}

/// Extract `(mintxg_keys, all_bps)` from a dataset/snapshot `ds_deadlist_obj`.
#[allow(clippy::too_many_arguments)]
fn flatten_deadlist_bps(
    cx: &Cx,
    mos: &mut Objects,
    mos_meta: &Dnode,
    mos_ceiling: u64,
    mos_dirty_dnodes: &BTreeMap<u64, Vec<u8>>,
    deadlist_obj: u64,
    empty_bpobj_id: Option<u64>,
    order: Endian,
) -> Result<(BTreeSet<u64>, Vec<BlockPointer>)> {
    let mut keys = BTreeSet::new();
    keys.insert(0);
    let mut bps = Vec::new();
    if deadlist_obj == 0 || Some(deadlist_obj) == empty_bpobj_id {
        return Ok((keys, bps));
    }
    let (dl_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        deadlist_obj,
        order,
    )?;
    let mut visited = BTreeSet::new();
    match dl_dn.object_type() {
        DMU_OT_BPOBJ => {
            flatten_bpobj_recursive(
                cx,
                mos,
                mos_meta,
                mos_ceiling,
                mos_dirty_dnodes,
                deadlist_obj,
                empty_bpobj_id,
                &mut visited,
                order,
                &mut bps,
            )?;
        }
        DMU_OT_DEADLIST => {
            for row in mos.zap_values(cx, deadlist_obj)? {
                let text = std::str::from_utf8(&row.name)
                    .map_err(|_| corrupt("non-UTF8 mintxg key in dsl_deadlist"))?;
                let mintxg = u64::from_str_radix(text, 16)
                    .map_err(|_| corrupt("invalid hex mintxg key in dsl_deadlist"))?;
                keys.insert(mintxg);
                let bpobj_id = row.scalar().map_err(|e| parse_err(&e))?;
                flatten_bpobj_recursive(
                    cx,
                    mos,
                    mos_meta,
                    mos_ceiling,
                    mos_dirty_dnodes,
                    bpobj_id,
                    empty_bpobj_id,
                    &mut visited,
                    order,
                    &mut bps,
                )?;
            }
        }
        other => {
            return Err(unsupported(format!(
                "unsupported deadlist object type {other}"
            )));
        }
    }
    Ok((keys, bps))
}

#[allow(clippy::too_many_arguments)]
fn free_bpobj_containers_recursive(
    cx: &Cx,
    mos: &mut Objects,
    mos_meta: &Dnode,
    mos_ceiling: u64,
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    features: &mut MosFeatureState,
    alloc: &mut PoolSpaceAllocator,
    bpobj_id: u64,
    empty_bpobj_id: Option<u64>,
    visited: &mut BTreeSet<u64>,
    order: Endian,
    new_txg: u64,
) -> Result<()> {
    if bpobj_id == 0 {
        return Ok(());
    }
    if Some(bpobj_id) == empty_bpobj_id {
        if features
            .write_features
            .contains_key("com.delphix:empty_bpobj")
        {
            features.decrement_write("com.delphix:empty_bpobj")?;
        }
        return Ok(());
    }
    if !visited.insert(bpobj_id) {
        return Ok(());
    }
    let (dn, ceiling) = read_staged_or_committed_dnode(
        cx,
        mos,
        mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        bpobj_id,
        order,
    )?;
    if dn.bonus().len() >= 48 {
        let subobjs_id = order.u64(dn.bonus(), 32).map_err(|e| parse_err(&e))?;
        let num_subobjs = order.u64(dn.bonus(), 40).map_err(|e| parse_err(&e))?;
        if subobjs_id != 0 {
            if num_subobjs > 0 {
                let (sub_dn, sub_ceil) = read_staged_or_committed_dnode(
                    cx,
                    mos,
                    mos_meta,
                    mos_ceiling,
                    mos_dirty_dnodes,
                    subobjs_id,
                    order,
                )?;
                let sub_bytes = usize::try_from(num_subobjs * 8)
                    .map_err(|_| unsupported("bpo_num_subobjs exceeds usize"))?;
                let sub_raw = read_dnode_prefix(cx, mos, &sub_dn, sub_ceil, sub_bytes)?;
                for chunk in sub_raw.as_chunks::<8>().0 {
                    let child_id = sub_dn.order().u64(chunk, 0).map_err(|e| parse_err(&e))?;
                    free_bpobj_containers_recursive(
                        cx,
                        mos,
                        mos_meta,
                        mos_ceiling,
                        mos_dirty_dnodes,
                        features,
                        alloc,
                        child_id,
                        empty_bpobj_id,
                        visited,
                        order,
                        new_txg,
                    )?;
                }
            }
            free_mos_object_completely(
                cx,
                mos,
                mos_meta,
                mos_ceiling,
                mos_dirty_dnodes,
                alloc,
                subobjs_id,
                order,
                new_txg,
            )?;
        }
    }
    let _ = ceiling;
    free_mos_object_completely(
        cx,
        mos,
        mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        alloc,
        bpobj_id,
        order,
        new_txg,
    )
}

/// Free ONLY the MOS deadlist/bpobj container metadata (maintaining `com.delphix:empty_bpobj`
/// refcounts) without freeing the ZPL DVAs listed inside the deadlist.
#[allow(clippy::too_many_arguments)]
pub(super) fn free_deadlist_containers(
    cx: &Cx,
    mos: &mut Objects,
    mos_meta: &Dnode,
    mos_ceiling: u64,
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    features: &mut MosFeatureState,
    alloc: &mut PoolSpaceAllocator,
    deadlist_obj: u64,
    empty_bpobj_id: Option<u64>,
    order: Endian,
    new_txg: u64,
) -> Result<()> {
    if deadlist_obj == 0 {
        return Ok(());
    }
    if Some(deadlist_obj) == empty_bpobj_id {
        if features
            .write_features
            .contains_key("com.delphix:empty_bpobj")
        {
            features.decrement_write("com.delphix:empty_bpobj")?;
        }
        return Ok(());
    }
    let (dl_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        deadlist_obj,
        order,
    )?;
    let mut visited = BTreeSet::new();
    match dl_dn.object_type() {
        DMU_OT_BPOBJ => {
            free_bpobj_containers_recursive(
                cx,
                mos,
                mos_meta,
                mos_ceiling,
                mos_dirty_dnodes,
                features,
                alloc,
                deadlist_obj,
                empty_bpobj_id,
                &mut visited,
                order,
                new_txg,
            )?;
        }
        DMU_OT_DEADLIST => {
            for row in mos.zap_values(cx, deadlist_obj)? {
                let bpobj_id = row.scalar().map_err(|e| parse_err(&e))?;
                free_bpobj_containers_recursive(
                    cx,
                    mos,
                    mos_meta,
                    mos_ceiling,
                    mos_dirty_dnodes,
                    features,
                    alloc,
                    bpobj_id,
                    empty_bpobj_id,
                    &mut visited,
                    order,
                    new_txg,
                )?;
            }
            free_mos_object_completely(
                cx,
                mos,
                mos_meta,
                mos_ceiling,
                mos_dirty_dnodes,
                alloc,
                deadlist_obj,
                order,
                new_txg,
            )?;
        }
        other => {
            return Err(unsupported(format!(
                "cannot free unsupported deadlist type {other}"
            )));
        }
    }
    Ok(())
}

/// Allocate and populate a fresh `DMU_OT_DEADLIST (50)` (with sorted `mintxg` keys and
/// `bps` grouped by greatest `mintxg < bp.birth()`), returning the new MOS object ID.
#[allow(clippy::too_many_arguments)]
pub(super) fn allocate_fresh_deadlist(
    cx: &Cx,
    mos: &mut Objects,
    mos_meta: &Dnode,
    mos_ceiling: u64,
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    features: &mut MosFeatureState,
    alloc: &mut PoolSpaceAllocator,
    empty_bpobj_id: Option<u64>,
    mintxg_set: &BTreeSet<u64>,
    bps: &[BlockPointer],
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<u64> {
    let mut keys: Vec<u64> = mintxg_set.iter().copied().collect();
    if !keys.contains(&0) {
        keys.insert(0, 0);
    }
    keys.sort_unstable();
    keys.dedup();

    let mut buckets: BTreeMap<u64, Vec<BlockPointer>> = BTreeMap::new();
    let mut total_delta = SpaceDelta::default();
    for bp in bps {
        total_delta.add_assign(SpaceDelta::from_bp(bp)?)?;
        let birth = bp.birth();
        let &chosen = keys
            .iter()
            .rfind(|&&m| m < birth)
            .ok_or_else(|| corrupt("deadlist lacks mintxg < retired block birth"))?;
        buckets.entry(chosen).or_default().push(bp.clone());
    }

    let min_blk = (1_usize << alloc.ashift).max(512);
    let mut zap_entries = Vec::with_capacity(keys.len());
    for &mintxg in &keys {
        let group = buckets.remove(&mintxg).unwrap_or_default();
        let bpobj_id = if group.is_empty() {
            if let Some(empty_id) = empty_bpobj_id {
                if features
                    .write_features
                    .contains_key("com.delphix:empty_bpobj")
                {
                    features.increment_write("com.delphix:empty_bpobj", new_txg)?;
                }
                empty_id
            } else {
                let id = allocate_object_id(cx, mos, mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
                let empty_blk = vec![0_u8; min_blk];
                let mut dirty = BTreeMap::new();
                dirty.insert(0_u64, Some(empty_blk));
                let out = cow_update_dnode(
                    cx,
                    mos,
                    alloc,
                    DnodeCowSpec {
                        existing: None,
                        object_type: DMU_OT_BPOBJ,
                        bonus_type: DMU_OT_BPOBJ_HDR,
                        checksum_type: 7,
                        compress_type: 2,
                        user_flags: 0,
                        indirect_shift: 17,
                        data_bytes: min_blk,
                        max_block: 0,
                        slots: 1,
                        nblkptr: 2,
                        bonus: vec![0_u8; 48],
                        spill: None,
                        order,
                        new_txg,
                        leaf_bucket: WriteBucket::ChildBlocks,
                        indirect_bucket: WriteBucket::ChildBlocks,
                    },
                    &dirty,
                    staged_writes,
                )?;
                put_dnode_in_table(
                    cx,
                    mos,
                    mos_meta,
                    mos_ceiling,
                    mos_dirty_dnodes,
                    id,
                    &out.dnode,
                )?;
                id
            }
        } else {
            let id = allocate_object_id(cx, mos, mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
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
            append_bps_to_bpobj_inner(
                cx,
                mos,
                mos_meta,
                mos_ceiling,
                mos_dirty_dnodes,
                id,
                None,
                &empty_dn,
                &group,
                alloc,
                order,
                new_txg,
                staged_writes,
            )?;
            id
        };
        zap_entries.push(RawZapEntry {
            name: format!("{mintxg:x}").into_bytes(),
            integer_bytes: 8,
            values: vec![bpobj_id],
            collision: 0,
        });
    }

    let dl_id = allocate_object_id(cx, mos, mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
    let mut dl_bonus = vec![0_u8; 320];
    dl_bonus[0..8].copy_from_slice(&order.encode(total_delta.dsize));
    dl_bonus[8..16].copy_from_slice(&order.encode(total_delta.comp));
    dl_bonus[16..24].copy_from_slice(&order.encode(total_delta.uncomp));
    write_zap_dnode_in_mos(
        cx,
        mos,
        mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        alloc,
        dl_id,
        None,
        DMU_OT_DEADLIST,
        DMU_OT_DEADLIST_HDR,
        dl_bonus,
        &zap_entries,
        0,
        false,
        order,
        new_txg,
        staged_writes,
    )?;
    Ok(dl_id)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ObjectSetWalkMode {
    MeasureOnly,
    FreeToAllocator,
}

/// Walk all blocks reachable from `os_bp` with `bp.birth() > min_exclusive_birth`,
/// pruning any subtree born at or before `min_exclusive_birth`.
/// Supports encrypted datasets keylessly (using physical checksums + indirect SHA-512 MACs
/// + plaintext dnode core/BP layout) so locked destroy works natively.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn walk_objectset_above_txg(
    cx: &Cx,
    mos: &mut Objects,
    os_bp: &BlockPointer,
    os_ceiling: u64,
    crypto_info: Option<&ZfsDatasetCryptoInfo>,
    min_exclusive_birth: u64,
    mode: ObjectSetWalkMode,
    alloc: &mut PoolSpaceAllocator,
    new_txg: u64,
) -> Result<(SpaceDelta, bool)> {
    checkpoint(cx)?;
    if os_bp.hole() || os_bp.birth() <= min_exclusive_birth {
        return Ok((SpaceDelta::default(), false));
    }
    let (os_raw, os_ord, _) =
        mos.read_dataset_objset_block_raw(cx, os_bp, os_ceiling, None, true)?;
    let os = ObjectSet::parse(&os_raw, os_ord).map_err(|e| parse_err(&e))?;
    let has_projectused = os
        .embedded_dnode(OBJSET_PROJECTUSED_OFFSET, os_ord)
        .map_err(|e| parse_err(&e))?
        .is_some();

    let view_crypto = if os_bp.protected() {
        let info = crypto_info.cloned().ok_or_else(|| {
            corrupt("protected dataset ObjectSet missing dsl_crypto_key metadata during walk")
        })?;
        Some(Arc::new(DatasetCryptoContext {
            info,
            raw_scrub_only: true,
        }))
    } else {
        None
    };
    let mut os_view =
        mos.open_objectset_view_with_crypto(os.meta.clone(), os_bp.birth(), mos.txg, view_crypto);
    let mut total = SpaceDelta::from_bp(os_bp)?;
    if mode == ObjectSetWalkMode::FreeToAllocator {
        alloc.free_block_dvas(os_bp, new_txg)?;
    }

    // 1. Embedded quota dnodes (`1024`, `1536`, `2048`).
    for emb_off in [
        OBJSET_USERUSED_OFFSET,
        OBJSET_GROUPUSED_OFFSET,
        OBJSET_PROJECTUSED_OFFSET,
    ] {
        if let Some(emb_dn) = os
            .embedded_dnode(emb_off, os_ord)
            .map_err(|e| parse_err(&e))?
        {
            walk_dnode_bps_above_txg(
                cx,
                &mut os_view,
                &emb_dn,
                os_bp.birth(),
                min_exclusive_birth,
                mode,
                alloc,
                new_txg,
                &mut total,
            )?;
        }
    }

    // 2. Meta-dnode indirects + level-0 dnode table blocks (`bp.birth() > min_exclusive_birth`).
    // Any user dnode block with `blk_bp.birth() <= min_exclusive_birth` cannot contain any
    // user block with `birth > min_exclusive_birth` (DMU parent-birth >= child-birth invariant!).
    let mut meta_table_blocks: Vec<(u64, u64)> = Vec::new();
    walk_meta_dnode_above_txg(
        cx,
        &mut os_view,
        &os.meta,
        os_bp.birth(),
        min_exclusive_birth,
        mode,
        alloc,
        new_txg,
        &mut total,
        &mut meta_table_blocks,
    )?;

    let slots_per_blk = DNODE_BLOCK_BYTES / DNODE_BYTES;
    for (blk_id, blk_birth) in meta_table_blocks {
        checkpoint(cx)?;
        let Some((blk_bytes, blk_ord, _)) =
            os_view.object_data_block(cx, &os.meta, os_bp.birth(), blk_id)?
        else {
            continue;
        };
        let mut slot = 0_usize;
        while slot < slots_per_blk {
            let at = slot * DNODE_BYTES;
            if blk_bytes[at] == 0 {
                slot += 1;
                continue;
            }
            let nslots = usize::from(blk_bytes[at + 12]) + 1;
            if let Some(user_dn) = dnode_at(&blk_bytes, slot, blk_ord).map_err(|e| parse_err(&e))? {
                walk_dnode_bps_above_txg(
                    cx,
                    &mut os_view,
                    &user_dn,
                    blk_birth,
                    min_exclusive_birth,
                    mode,
                    alloc,
                    new_txg,
                    &mut total,
                )?;
            }
            slot += nslots;
        }
    }

    Ok((total, has_projectused))
}

#[allow(clippy::too_many_arguments)]
fn walk_dnode_bps_above_txg(
    cx: &Cx,
    view: &mut Objects,
    dnode: &Dnode,
    ceiling: u64,
    min_exclusive_birth: u64,
    mode: ObjectSetWalkMode,
    alloc: &mut PoolSpaceAllocator,
    new_txg: u64,
    total: &mut SpaceDelta,
) -> Result<()> {
    if let Some(sbp) = dnode.spill()
        && !sbp.hole()
        && !sbp.embedded()
        && sbp.birth() > min_exclusive_birth
    {
        total.add_assign(SpaceDelta::from_bp(sbp)?)?;
        if mode == ObjectSetWalkMode::FreeToAllocator {
            alloc.free_block_dvas(sbp, new_txg)?;
        }
    }
    let root_level = dnode.levels().saturating_sub(1);
    for bp in dnode.pointers() {
        walk_bp_subtree_above_txg(
            cx,
            view,
            bp,
            root_level,
            dnode.object_type(),
            dnode.indirect_shift(),
            ceiling,
            min_exclusive_birth,
            mode,
            alloc,
            new_txg,
            total,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn walk_bp_subtree_above_txg(
    cx: &Cx,
    view: &mut Objects,
    bp: &BlockPointer,
    level: u8,
    obj_type: u8,
    ind_shift: u8,
    ceiling: u64,
    min_exclusive_birth: u64,
    mode: ObjectSetWalkMode,
    alloc: &mut PoolSpaceAllocator,
    new_txg: u64,
    total: &mut SpaceDelta,
) -> Result<()> {
    checkpoint(cx)?;
    if bp.hole() || bp.birth() <= min_exclusive_birth {
        return Ok(());
    }
    if level > 0 {
        let ind_bytes = 1_usize << ind_shift;
        if let Some((raw, ord, birth)) =
            view.checked_raw(cx, bp, obj_type, level, ind_bytes, ceiling)?
        {
            for chunk in raw.as_chunks::<128>().0 {
                let child = BlockPointer::parse(chunk, ord).map_err(|e| parse_err(&e))?;
                walk_bp_subtree_above_txg(
                    cx,
                    view,
                    &child,
                    level - 1,
                    obj_type,
                    ind_shift,
                    birth,
                    min_exclusive_birth,
                    mode,
                    alloc,
                    new_txg,
                    total,
                )?;
            }
        }
    }
    if !bp.embedded() {
        total.add_assign(SpaceDelta::from_bp(bp)?)?;
        if mode == ObjectSetWalkMode::FreeToAllocator {
            alloc.free_block_dvas(bp, new_txg)?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn walk_meta_dnode_above_txg(
    cx: &Cx,
    view: &mut Objects,
    meta_dn: &Dnode,
    ceiling: u64,
    min_exclusive_birth: u64,
    mode: ObjectSetWalkMode,
    alloc: &mut PoolSpaceAllocator,
    new_txg: u64,
    total: &mut SpaceDelta,
    out_l0_blocks: &mut Vec<(u64, u64)>,
) -> Result<()> {
    let root_level = meta_dn.levels().saturating_sub(1);
    let span = 1_u64 << ((u32::from(meta_dn.indirect_shift()) - 7) * u32::from(root_level));
    for (idx, bp) in meta_dn.pointers().iter().enumerate() {
        walk_meta_bp_above_txg(
            cx,
            view,
            bp,
            root_level,
            (idx as u64) * span,
            meta_dn.indirect_shift(),
            ceiling,
            min_exclusive_birth,
            mode,
            alloc,
            new_txg,
            total,
            out_l0_blocks,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn walk_meta_bp_above_txg(
    cx: &Cx,
    view: &mut Objects,
    bp: &BlockPointer,
    level: u8,
    base_l0_id: u64,
    ind_shift: u8,
    ceiling: u64,
    min_exclusive_birth: u64,
    mode: ObjectSetWalkMode,
    alloc: &mut PoolSpaceAllocator,
    new_txg: u64,
    total: &mut SpaceDelta,
    out_l0_blocks: &mut Vec<(u64, u64)>,
) -> Result<()> {
    checkpoint(cx)?;
    if bp.hole() || bp.birth() <= min_exclusive_birth {
        return Ok(());
    }
    if level == 0 {
        // Read user dnode table BEFORE freeing DVA (note: free_block_dvas only mutates in-memory maps,
        // never physical device bytes, so reading via `view` remains safe, and recording `(id, birth)`
        // lets caller inspect every user dnode in this table block).
        out_l0_blocks.push((base_l0_id, bp.birth()));
    } else {
        let ind_bytes = 1_usize << ind_shift;
        let child_span = 1_u64 << ((u32::from(ind_shift) - 7) * u32::from(level - 1));
        if let Some((raw, ord, birth)) =
            view.checked_raw(cx, bp, DMU_OT_DNODE, level, ind_bytes, ceiling)?
        {
            for (idx, chunk) in raw.as_chunks::<128>().0.iter().enumerate() {
                let child = BlockPointer::parse(chunk, ord).map_err(|e| parse_err(&e))?;
                walk_meta_bp_above_txg(
                    cx,
                    view,
                    &child,
                    level - 1,
                    base_l0_id + (idx as u64) * child_span,
                    ind_shift,
                    birth,
                    min_exclusive_birth,
                    mode,
                    alloc,
                    new_txg,
                    total,
                    out_l0_blocks,
                )?;
            }
        }
    }
    if !bp.embedded() {
        total.add_assign(SpaceDelta::from_bp(bp)?)?;
        if mode == ObjectSetWalkMode::FreeToAllocator {
            alloc.free_block_dvas(bp, new_txg)?;
        }
    }
    Ok(())
}

/// Publish the same space charges for filesystem and volume COW. A snapshot
/// retains its retired blocks. A refreservation charges only the portion not
/// already occupied by unique data, both when the head grows and when it shrinks.
#[allow(clippy::too_many_arguments)]
pub(super) fn stage_head_space(
    cx: &Cx,
    mos: &mut Objects,
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    head_object: u64,
    directory_object: u64,
    new_root: &BlockPointer,
    born: SpaceDelta,
    freed: SpaceDelta,
    retained: SpaceDelta,
    retired_snap_bps: &[BlockPointer],
    pool_free_bytes: u64,
    order: Endian,
) -> Result<()> {
    let meta = mos.meta_dnode().clone();
    let ceiling = mos.root_birth_txg();
    let (mut head, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        &meta,
        ceiling,
        mos_dirty_dnodes,
        head_object,
        order,
    )?;
    let (dir, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        &meta,
        ceiling,
        mos_dirty_dnodes,
        directory_object,
        order,
    )?;
    let dd_origin_obj = order.u64(dir.bonus(), 24).map_err(|e| parse_err(&e))?;
    let props = order.u64(dir.bonus(), 80).map_err(|e| parse_err(&e))?;
    let refreservation = if props == 0 {
        0
    } else {
        effective_local_numeric_prop(&mos.zap_values(cx, props)?, "refreservation")?.unwrap_or(0)
    };
    let mut bonus = head.bonus().to_vec();
    let prev_snap_obj = order.u64(&bonus, 8).map_err(|e| parse_err(&e))?;
    let old_unique = order.u64(&bonus, 96).map_err(|e| parse_err(&e))?;
    let unique_delta = i128::from(born.dsize) - i128::from(freed.dsize);
    let ref_delta = unique_delta - i128::from(retained.dsize);
    // On a clone, blocks born `<= origin_txg` belong to the origin dataset, not
    // this clone's `DD_USED_HEAD` or `DD_USED_SNAP`. Retiring an origin block
    // during COW must not debit `DD_USED_HEAD` (which would underflow) or
    // credit `DD_USED_SNAP` — both before and after the clone takes snapshots
    // of its own. Only retired blocks born strictly after `origin_txg` belonged
    // to this clone's HEAD and shift into `DD_USED_SNAP`.
    let (dir_head_delta, dir_snap_delta) = if dd_origin_obj == 0 {
        (ref_delta, i128::from(retained.dsize))
    } else if prev_snap_obj == dd_origin_obj {
        (unique_delta, 0_i128)
    } else {
        let (origin_dn, _) = read_staged_or_committed_dnode(
            cx,
            mos,
            &meta,
            ceiling,
            mos_dirty_dnodes,
            dd_origin_obj,
            order,
        )?;
        let origin_txg = order
            .u64(origin_dn.bonus(), 56)
            .map_err(|e| parse_err(&e))?;
        let mut own_snap_retained_dsize = 0_u64;
        for bp in retired_snap_bps {
            if bp.birth() > origin_txg {
                own_snap_retained_dsize = own_snap_retained_dsize
                    .checked_add(SpaceDelta::from_bp(bp)?.dsize)
                    .ok_or_else(|| corrupt("clone own snapshot retained dsize overflow"))?;
            }
        }
        let own_snap_retained = i128::from(own_snap_retained_dsize);
        (unique_delta - own_snap_retained, own_snap_retained)
    };
    let comp_delta = i128::from(born.comp) - i128::from(freed.comp);
    let uncomp_delta = i128::from(born.uncomp) - i128::from(freed.uncomp);
    for (offset, delta) in [
        (72, ref_delta),
        (80, comp_delta - i128::from(retained.comp)),
        (88, uncomp_delta - i128::from(retained.uncomp)),
        (96, unique_delta),
    ] {
        let old = order.u64(&bonus, offset).map_err(|e| parse_err(&e))?;
        let new = u64::try_from(i128::from(old) + delta)
            .map_err(|_| corrupt("DSL dataset space counter underflow/overflow"))?;
        bonus[offset..offset + 8].copy_from_slice(&order.encode(new));
    }
    let new_unique = order.u64(&bonus, 96).map_err(|e| parse_err(&e))?;
    let reservation_delta = i128::from(refreservation.saturating_sub(new_unique))
        - i128::from(refreservation.saturating_sub(old_unique));
    let dir_delta = unique_delta + reservation_delta;
    enforce_dataset_quotas_for_growth(
        cx,
        mos,
        mos_dirty_dnodes,
        head_object,
        directory_object,
        u64::try_from(ref_delta.max(0)).map_err(|_| corrupt("DSL referenced growth overflow"))?,
        u64::try_from(dir_delta.max(0)).map_err(|_| corrupt("DSL directory growth overflow"))?,
        order,
    )?;
    bonus[128..256].copy_from_slice(&new_root.encode(order));
    head.set_bonus_and_spill(head.bonus_type(), bonus, None)
        .map_err(|e| parse_err(&e))?;
    put_dnode_in_table(
        cx,
        mos,
        &meta,
        ceiling,
        mos_dirty_dnodes,
        head_object,
        &head,
    )?;
    propagate_dsl_dir_space_delta(
        cx,
        mos,
        &meta,
        ceiling,
        mos_dirty_dnodes,
        directory_object,
        dir_head_delta,
        dir_snap_delta,
        0,
        0,
        reservation_delta,
        comp_delta,
        uncomp_delta,
        order,
    )?;
    if unique_delta > 0 {
        // Use the staged counters. The same physical bytes can satisfy a head
        // refreservation and several nested directory reservations.
        enforce_pool_reservations_for_growth(
            cx,
            mos,
            mos_dirty_dnodes,
            0,
            0,
            0,
            0,
            pool_free_bytes,
            order,
        )?;
    }
    Ok(())
}

/// Propagate signed `(dsize, comp, uncomp)` + breakdown deltas up `dsl_dir` and its ancestors.
#[allow(clippy::too_many_arguments)]
pub(super) fn propagate_dsl_dir_space_delta(
    cx: &Cx,
    mos: &mut Objects,
    mos_meta: &Dnode,
    mos_ceiling: u64,
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    start_dir_obj: u64,
    head_dsize_delta: i128,
    snap_dsize_delta: i128,
    child_dsize_delta: i128,
    child_rsrv_delta: i128,
    refrsrv_delta: i128,
    comp_delta: i128,
    uncomp_delta: i128,
    order: Endian,
) -> Result<()> {
    let apply_i128 = |buf: &mut [u8], at: usize, delta: i128, label: &'static str| -> Result<u64> {
        let cur = i128::from(order.u64(buf, at).map_err(|e| parse_err(&e))?);
        let next = u64::try_from(
            cur.checked_add(delta)
                .filter(|&v| v >= 0)
                .ok_or_else(|| corrupt(format!("{label} underflow/overflow")))?,
        )
        .map_err(|_| corrupt(format!("{label} u64 overflow")))?;
        buf[at..at + 8].copy_from_slice(&order.encode(next));
        Ok(next)
    };

    let own_used_delta =
        head_dsize_delta + snap_dsize_delta + child_dsize_delta + child_rsrv_delta + refrsrv_delta;
    if own_used_delta == 0
        && head_dsize_delta == 0
        && snap_dsize_delta == 0
        && child_dsize_delta == 0
        && child_rsrv_delta == 0
        && refrsrv_delta == 0
        && comp_delta == 0
        && uncomp_delta == 0
    {
        return Ok(());
    }

    let mut cur_dir = start_dir_obj;
    let mut is_start = true;
    let mut carry_child_used_delta = 0_i128;
    let mut carry_child_rsrv_delta = 0_i128;
    let mut seen = BTreeSet::new();

    while cur_dir != 0 {
        checkpoint(cx)?;
        if !seen.insert(cur_dir) {
            return Err(corrupt("cycle in DSL directory chain"));
        }
        let (dd_dn, _) = read_staged_or_committed_dnode(
            cx,
            mos,
            mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            cur_dir,
            order,
        )?;
        let mut bonus = dd_dn.bonus().to_vec();
        let parent_dir = order.u64(&bonus, 16).map_err(|e| parse_err(&e))?;
        let old_used = order.u64(&bonus, 40).map_err(|e| parse_err(&e))?;
        let dd_reserved = order.u64(&bonus, 72).map_err(|e| parse_err(&e))?;
        let dd_flags = order.u64(&bonus, 96).map_err(|e| parse_err(&e))?;

        let this_used_delta = if is_start {
            own_used_delta
        } else {
            carry_child_used_delta + carry_child_rsrv_delta
        };

        let new_used = apply_i128(&mut bonus, 40, this_used_delta, "dd_used_bytes")?;
        let _ = apply_i128(&mut bonus, 48, comp_delta, "dd_compressed_bytes")?;
        let _ = apply_i128(&mut bonus, 56, uncomp_delta, "dd_uncompressed_bytes")?;

        if dd_flags & DD_FLAG_USED_BREAKDOWN != 0 {
            if is_start {
                let _ = apply_i128(&mut bonus, 104, head_dsize_delta, "dd_used_breakdown[HEAD]")?;
                let _ = apply_i128(&mut bonus, 112, snap_dsize_delta, "dd_used_breakdown[SNAP]")?;
                let _ = apply_i128(
                    &mut bonus,
                    120,
                    child_dsize_delta,
                    "dd_used_breakdown[CHILD]",
                )?;
                let _ = apply_i128(
                    &mut bonus,
                    128,
                    child_rsrv_delta,
                    "dd_used_breakdown[CHILD_RSRV]",
                )?;
                let _ = apply_i128(&mut bonus, 136, refrsrv_delta, "dd_used_breakdown[REFRSRV]")?;
            } else {
                let _ = apply_i128(
                    &mut bonus,
                    120,
                    carry_child_used_delta,
                    "dd_used_breakdown[CHILD]",
                )?;
                let _ = apply_i128(
                    &mut bonus,
                    128,
                    carry_child_rsrv_delta,
                    "dd_used_breakdown[CHILD_RSRV]",
                )?;
            }
        }

        let mut updated = dd_dn;
        let btype = updated.bonus_type();
        updated
            .set_bonus_and_spill(btype, bonus, None)
            .map_err(|e| parse_err(&e))?;
        put_dnode_in_table(
            cx,
            mos,
            mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            cur_dir,
            &updated,
        )?;

        let old_excess = dd_reserved.saturating_sub(old_used);
        let new_excess = dd_reserved.saturating_sub(new_used);
        carry_child_used_delta = i128::from(new_used) - i128::from(old_used);
        carry_child_rsrv_delta = i128::from(new_excess) - i128::from(old_excess);
        is_start = false;
        cur_dir = parent_dir;
    }
    Ok(())
}

/// Resolve a committed dataset path (`components`) to `(directory_object, head_object, pool_guid)`.
pub(super) fn resolve_dataset_ids(
    cx: &Cx,
    mos: &mut Objects,
    components: &[Vec<u8>],
) -> Result<(u64, u64, u64)> {
    let row = mos
        .datasets(cx)?
        .into_iter()
        .find(|d| d.components == components)
        .ok_or_else(|| FfsError::NotFound("ZFS dataset".into()))?;
    Ok((row.directory_object, row.head_object, mos.pool_guid()))
}

/// Verify that `parent_dataset` is an initialized ZPL filesystem (`objectset_kind == Some(2)`),
/// rejecting volumes (`OBJSET_TYPE_ZVOL = 3`) and inconsistent datasets with `EINVAL`.
pub(super) fn require_filesystem_parent(
    cx: &Cx,
    mos: &mut Objects,
    parent_dataset: &[Vec<u8>],
) -> Result<()> {
    let row = mos
        .datasets(cx)?
        .into_iter()
        .find(|d| d.components == parent_dataset)
        .ok_or_else(|| FfsError::NotFound("ZFS parent dataset".into()))?;
    if row.objectset_kind != Some(2) || row.flags & 0x1_0000 != 0 {
        return Err(reject_einval(
            "ZFS parent dataset must be an initialized filesystem (cannot nest under a volume)",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn stage_dsl_mutation(
    cx: &Cx,
    mos: &mut Objects,
    mutation: &DslMutation,
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    features: &mut MosFeatureState,
    empty_bpobj_id: Option<u64>,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<DslStageResult> {
    checkpoint(cx)?;
    match mutation {
        DslMutation::CreateSnapshot {
            dataset,
            snap_name,
            timestamp,
        } => Ok(DslStageResult {
            value: stage_create_snapshot(
                cx,
                mos,
                dataset,
                snap_name,
                *timestamp,
                mos_dirty_dnodes,
                features,
                empty_bpobj_id,
                alloc,
                order,
                new_txg,
                staged_writes,
            )?,
            new_root_key: None,
        }),
        DslMutation::DestroySnapshot {
            dataset,
            snap_name,
            defer,
        } => Ok(DslStageResult {
            value: stage_destroy_snapshot(
                cx,
                mos,
                dataset,
                snap_name,
                *defer,
                mos_dirty_dnodes,
                features,
                empty_bpobj_id,
                alloc,
                order,
                new_txg,
                staged_writes,
            )?,
            new_root_key: None,
        }),
        DslMutation::RenameSnapshot {
            dataset,
            old_snap_name,
            new_snap_name,
        } => Ok(DslStageResult {
            value: stage_rename_snapshot(
                cx,
                mos,
                dataset,
                old_snap_name,
                new_snap_name,
                mos_dirty_dnodes,
                alloc,
                order,
                new_txg,
                staged_writes,
            )?,
            new_root_key: None,
        }),
        DslMutation::HoldSnapshot {
            dataset,
            snap_name,
            tag,
            timestamp,
        } => Ok(DslStageResult {
            value: stage_hold_snapshot(
                cx,
                mos,
                dataset,
                snap_name,
                tag,
                *timestamp,
                mos_dirty_dnodes,
                alloc,
                order,
                new_txg,
                staged_writes,
            )?,
            new_root_key: None,
        }),
        DslMutation::ReleaseSnapshot {
            dataset,
            snap_name,
            tag,
        } => Ok(DslStageResult {
            value: stage_release_snapshot(
                cx,
                mos,
                dataset,
                snap_name,
                tag,
                mos_dirty_dnodes,
                features,
                empty_bpobj_id,
                alloc,
                order,
                new_txg,
                staged_writes,
            )?,
            new_root_key: None,
        }),
        DslMutation::CreateBookmark {
            dataset,
            bookmark_name,
            source_name,
            source_is_bookmark,
        } => Ok(DslStageResult {
            value: stage_create_bookmark(
                cx,
                mos,
                dataset,
                bookmark_name,
                source_name,
                *source_is_bookmark,
                mos_dirty_dnodes,
                features,
                alloc,
                order,
                new_txg,
                staged_writes,
            )?,
            new_root_key: None,
        }),
        DslMutation::DestroyBookmark {
            dataset,
            bookmark_name,
        } => Ok(DslStageResult {
            value: stage_destroy_bookmark(
                cx,
                mos,
                dataset,
                bookmark_name,
                mos_dirty_dnodes,
                features,
                alloc,
                order,
                new_txg,
                staged_writes,
            )?,
            new_root_key: None,
        }),
        DslMutation::CreateDataset {
            parent_dataset,
            child_name,
            initial_props,
            encryption,
            timestamp,
        } => stage_create_dataset(
            cx,
            mos,
            parent_dataset,
            child_name,
            initial_props,
            encryption.as_ref(),
            *timestamp,
            mos_dirty_dnodes,
            features,
            empty_bpobj_id,
            alloc,
            order,
            new_txg,
            staged_writes,
        ),
        DslMutation::CreateClone {
            origin_dataset,
            origin_snap,
            target_parent,
            target_name,
            initial_props,
            timestamp,
        } => Ok(DslStageResult {
            value: stage_create_clone(
                cx,
                mos,
                origin_dataset,
                origin_snap,
                target_parent,
                target_name,
                initial_props,
                *timestamp,
                mos_dirty_dnodes,
                features,
                empty_bpobj_id,
                alloc,
                order,
                new_txg,
                staged_writes,
            )?,
            new_root_key: None,
        }),
        DslMutation::RenameDataset {
            old_dataset,
            new_dataset,
        } => Ok(DslStageResult {
            value: stage_rename_dataset(
                cx,
                mos,
                old_dataset,
                new_dataset,
                mos_dirty_dnodes,
                alloc,
                order,
                new_txg,
                staged_writes,
            )?,
            new_root_key: None,
        }),
        DslMutation::DestroyDataset { dataset } => Ok(DslStageResult {
            value: stage_destroy_dataset(
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
            )?,
            new_root_key: None,
        }),
        DslMutation::SetProperty {
            dataset,
            name,
            value,
        } => Ok(DslStageResult {
            value: stage_set_property(
                cx,
                mos,
                dataset,
                name,
                Some(value),
                mos_dirty_dnodes,
                features,
                alloc,
                order,
                new_txg,
                staged_writes,
            )?,
            new_root_key: None,
        }),
        DslMutation::InheritProperty { dataset, name } => Ok(DslStageResult {
            value: stage_set_property(
                cx,
                mos,
                dataset,
                name,
                None,
                mos_dirty_dnodes,
                features,
                alloc,
                order,
                new_txg,
                staged_writes,
            )?,
            new_root_key: None,
        }),
        DslMutation::ChangeKey {
            dataset,
            new_material,
            new_keylocation,
            pbkdf2_iters,
            extra_entropy,
        } => Ok(DslStageResult {
            value: stage_change_key(
                cx,
                mos,
                dataset,
                new_material,
                new_keylocation.as_deref(),
                *pbkdf2_iters,
                extra_entropy,
                mos_dirty_dnodes,
                features,
                alloc,
                order,
                new_txg,
                staged_writes,
            )?,
            new_root_key: None,
        }),
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn stage_create_snapshot(
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
    validate_dsl_component(snap_name, true)?;
    let (dir_obj, head_obj, pool_guid) = resolve_dataset_ids(cx, mos, dataset)?;
    let mos_meta = mos.meta_dnode().clone();
    let mos_ceiling = mos.root_birth_txg();
    let (head_dn, head_ceil) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        head_obj,
        order,
    )?;
    let snapmap_obj = order.u64(head_dn.bonus(), 32).map_err(|e| parse_err(&e))?;
    if snapmap_obj == 0 {
        return Err(corrupt("head dataset has zero ds_snapnames_zapobj"));
    }
    let mut snap_entries =
        mos.zap_values_with_names(cx, snapmap_obj, ZapNamePolicy::AsciiUppercase)?;
    if snap_entries
        .iter()
        .any(|e| e.name.eq_ignore_ascii_case(snap_name))
    {
        return Err(FfsError::Exists);
    }

    let (dir_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        dir_obj,
        order,
    )?;
    let props_zap = order.u64(dir_dn.bonus(), 80).map_err(|e| parse_err(&e))?;
    let prop_rows = if props_zap != 0 {
        mos.zap_values(cx, props_zap)?
    } else {
        Vec::new()
    };
    let refreservation = effective_local_numeric_prop(&prop_rows, "refreservation")?.unwrap_or(0);

    let old_prev_snap_obj = order.u64(head_dn.bonus(), 8).map_err(|e| parse_err(&e))?;
    let old_prev_snap_txg = order.u64(head_dn.bonus(), 16).map_err(|e| parse_err(&e))?;
    let old_deadlist_obj = order.u64(head_dn.bonus(), 64).map_err(|e| parse_err(&e))?;
    let head_ref_bytes = order.u64(head_dn.bonus(), 72).map_err(|e| parse_err(&e))?;
    let head_comp_bytes = order.u64(head_dn.bonus(), 80).map_err(|e| parse_err(&e))?;
    let head_uncomp_bytes = order.u64(head_dn.bonus(), 88).map_err(|e| parse_err(&e))?;
    let old_head_unique = order.u64(head_dn.bonus(), 96).map_err(|e| parse_err(&e))?;
    let head_flags = order.u64(head_dn.bonus(), 120).map_err(|e| parse_err(&e))?;

    // Check refreservation jump when `head.ds_unique_bytes` resets from `old_head_unique` -> `0`.
    let old_refrsrv_charge = refreservation.saturating_sub(old_head_unique);
    let new_refrsrv_charge = refreservation;
    let refrsrv_add = new_refrsrv_charge.saturating_sub(old_refrsrv_charge);
    if refrsrv_add > 0 {
        if refrsrv_add > alloc.total_free_bytes() {
            return Err(FfsError::NoSpace);
        }
        enforce_dataset_quotas_for_growth(
            cx,
            mos,
            mos_dirty_dnodes,
            head_obj,
            dir_obj,
            0,
            refrsrv_add,
            order,
        )?;
    }

    // 1. Allocate `snap_ds_obj` (`DMU_OT_DSL_DATASET = 16`, 320B bonus), transferring `old_deadlist_obj`.
    let snap_ds_obj = allocate_object_id(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
    let snap_guid = derive_unique_guid(pool_guid, new_txg, snap_ds_obj, 1);
    let snap_fsid = derive_fsid_guid(snap_guid);
    let mut snap_bonus = vec![0_u8; 320];
    snap_bonus[0..8].copy_from_slice(&order.encode(dir_obj));
    snap_bonus[8..16].copy_from_slice(&order.encode(old_prev_snap_obj));
    snap_bonus[16..24].copy_from_slice(&order.encode(old_prev_snap_txg));
    snap_bonus[24..32].copy_from_slice(&order.encode(head_obj));
    snap_bonus[40..48].copy_from_slice(&order.encode(1)); // ds_num_children = 1
    snap_bonus[48..56].copy_from_slice(&order.encode(timestamp.seconds.cast_unsigned()));
    snap_bonus[56..64].copy_from_slice(&order.encode(new_txg));
    snap_bonus[64..72].copy_from_slice(&order.encode(old_deadlist_obj));
    snap_bonus[72..80].copy_from_slice(&order.encode(head_ref_bytes));
    snap_bonus[80..88].copy_from_slice(&order.encode(head_comp_bytes));
    snap_bonus[88..96].copy_from_slice(&order.encode(head_uncomp_bytes));
    snap_bonus[96..104].copy_from_slice(&order.encode(0)); // ds_unique_bytes = 0 at creation
    snap_bonus[104..112].copy_from_slice(&order.encode(snap_fsid));
    snap_bonus[112..120].copy_from_slice(&order.encode(snap_guid));
    snap_bonus[120..128]
        .copy_from_slice(&order.encode((head_flags & 0x1_0006) | DS_FLAG_UNIQUE_ACCURATE));
    snap_bonus[128..256].copy_from_slice(&head_dn.bonus()[128..256]); // identical ObjectSet BP!

    let mut head_zap_entries = dataset_feature_entries(cx, mos, head_obj, &head_dn, features)?;
    let head_features = dataset_block_feature_owners(&head_zap_entries, features)?;
    let old_head_ivset_guid = zap_optional_u64(&head_zap_entries, DSL_DATASET_IVSET_GUID)?;
    // Native IV-set identities belong to snapshots. A received head may retain
    // an older snapshot's GUID, and imported native heads need not have one.
    // Derive this snapshot's identity independently of that writable-head state.
    let snapshot_ivset_guid = mos
        .dataset_crypto_info(cx, dataset)?
        .map(|_| derive_unique_guid(pool_guid, new_txg, snap_ds_obj, 14));
    let mut snap_zap_entries = Vec::new();
    for feature in head_features {
        features.increment_read(feature, new_txg)?;
        snap_zap_entries.push(RawZapEntry {
            name: feature.as_bytes().to_vec(),
            integer_bytes: 8,
            values: vec![0],
            collision: 0,
        });
    }
    if let Some(ivset_guid) = snapshot_ivset_guid {
        snap_zap_entries.push(RawZapEntry {
            name: DSL_DATASET_IVSET_GUID.to_vec(),
            integer_bytes: 8,
            values: vec![ivset_guid],
            collision: 0,
        });
    }
    if snap_zap_entries.is_empty() {
        let snap_dn = Dnode::from_spec(DnodeSpec {
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
            bonus: snap_bonus,
            spill: None,
        })
        .map_err(|e| parse_err(&e))?;
        put_dnode_in_table(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            snap_ds_obj,
            &snap_dn,
        )?;
    } else {
        features.increment_read("com.delphix:extensible_dataset", new_txg)?;
        write_zap_dnode_in_mos(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            alloc,
            snap_ds_obj,
            None,
            DMU_OTN_ZAP_METADATA,
            DMU_OT_DSL_DATASET,
            snap_bonus,
            &snap_zap_entries,
            0,
            false,
            order,
            new_txg,
            staged_writes,
        )?;
    }

    // 2. Relink predecessor snapshot (`ds_next_snap_obj` or clone branch in `ds_next_clones_obj`).
    if old_prev_snap_obj != 0 {
        let (prev_dn, _) = read_staged_or_committed_dnode(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            old_prev_snap_obj,
            order,
        )?;
        let prev_next = order.u64(prev_dn.bonus(), 24).map_err(|e| parse_err(&e))?;
        if prev_next == head_obj {
            let mut prev_bonus = prev_dn.bonus().to_vec();
            prev_bonus[24..32].copy_from_slice(&order.encode(snap_ds_obj));
            let mut updated_prev = prev_dn;
            let btype = updated_prev.bonus_type();
            updated_prev
                .set_bonus_and_spill(btype, prev_bonus, None)
                .map_err(|e| parse_err(&e))?;
            put_dnode_in_table(
                cx,
                mos,
                &mos_meta,
                mos_ceiling,
                mos_dirty_dnodes,
                old_prev_snap_obj,
                &updated_prev,
            )?;
        } else {
            let clones_zap = order.u64(prev_dn.bonus(), 256).map_err(|e| parse_err(&e))?;
            if clones_zap == 0 {
                return Err(corrupt("clone predecessor lacks ds_next_clones_obj"));
            }
            let (cz_dn, cz_ceil) = mos.object_with_ceiling(cx, clones_zap)?;
            let mut cz_entries = mos.zap_values(cx, clones_zap)?;
            let old_key = format!("{head_obj:x}").into_bytes();
            cz_entries.retain(|e| e.name != old_key);
            cz_entries.push(RawZapEntry {
                name: format!("{snap_ds_obj:x}").into_bytes(),
                integer_bytes: 8,
                values: vec![snap_ds_obj],
                collision: 0,
            });
            write_zap_dnode_in_mos(
                cx,
                mos,
                &mos_meta,
                mos_ceiling,
                mos_dirty_dnodes,
                alloc,
                clones_zap,
                Some((&cz_dn, cz_ceil)),
                cz_dn.object_type(),
                cz_dn.bonus_type(),
                cz_dn.bonus().to_vec(),
                &cz_entries,
                0,
                false,
                order,
                new_txg,
                staged_writes,
            )?;
        }
    }

    // 3. Allocate fresh `head.ds_deadlist_obj` inheriting `mintxg` keys + `old_prev_snap_txg`.
    let (mut mintxgs, _) = flatten_deadlist_bps(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        old_deadlist_obj,
        empty_bpobj_id,
        order,
    )?;
    mintxgs.insert(old_prev_snap_txg);
    let new_head_dl = allocate_fresh_deadlist(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        features,
        alloc,
        empty_bpobj_id,
        &mintxgs,
        &[],
        order,
        new_txg,
        staged_writes,
    )?;

    // 4. Update `head` (`ds_prev_snap_obj`, `ds_prev_snap_txg`, `ds_deadlist_obj`, `ds_unique_bytes = 0`).
    // Our encrypted writers also use the head's GUID as a nonce domain. Rotate
    // that domain independently of the new snapshot's native IV-set identity.
    let mut head_bonus = head_dn.bonus().to_vec();
    head_bonus[8..16].copy_from_slice(&order.encode(snap_ds_obj));
    head_bonus[16..24].copy_from_slice(&order.encode(new_txg));
    head_bonus[64..72].copy_from_slice(&order.encode(new_head_dl));
    head_bonus[96..104].copy_from_slice(&order.encode(0));
    if let Some(snapshot_ivset) = snapshot_ivset_guid {
        let mut next_ivset = derive_unique_guid(pool_guid, new_txg, head_obj, 11);
        while Some(next_ivset) == old_head_ivset_guid || next_ivset == snapshot_ivset {
            next_ivset = next_ivset.wrapping_add(1).max(1);
        }
        head_zap_entries.retain(|e| e.name != DSL_DATASET_IVSET_GUID);
        head_zap_entries.push(RawZapEntry {
            name: DSL_DATASET_IVSET_GUID.to_vec(),
            integer_bytes: 8,
            values: vec![next_ivset],
            collision: 0,
        });
        if head_dn.object_type() != DMU_OTN_ZAP_METADATA {
            features.increment_read("com.delphix:extensible_dataset", new_txg)?;
        }
        write_zap_dnode_in_mos(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            alloc,
            head_obj,
            Some((&head_dn, head_ceil)),
            DMU_OTN_ZAP_METADATA,
            DMU_OT_DSL_DATASET,
            head_bonus,
            &head_zap_entries,
            0,
            false,
            order,
            new_txg,
            staged_writes,
        )?;
    } else {
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
            head_obj,
            &updated_head,
        )?;
    }

    // 5. Insert `snap_name -> snap_ds_obj` into `head.ds_snapnames_zapobj` (preserving `normflags = 2`).
    let (sm_dn, sm_ceil) = mos.object_with_ceiling(cx, snapmap_obj)?;
    snap_entries.push(RawZapEntry {
        name: snap_name.to_vec(),
        integer_bytes: 8,
        values: vec![snap_ds_obj],
        collision: 0,
    });
    write_zap_dnode_in_mos(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        alloc,
        snapmap_obj,
        Some((&sm_dn, sm_ceil)),
        sm_dn.object_type(),
        sm_dn.bonus_type(),
        sm_dn.bonus().to_vec(),
        &snap_entries,
        2,
        false,
        order,
        new_txg,
        staged_writes,
    )?;

    // 6. Update `owning_dir` (`DD_USED_REFRSRV` delta if `refreservation > 0`, plus `snapshot_count` if zapified).
    if refrsrv_add > 0 {
        propagate_dsl_dir_space_delta(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            dir_obj,
            0,
            0,
            0,
            0,
            i128::from(refrsrv_add),
            0,
            0,
            order,
        )?;
    }
    bump_filesystem_limits_counter_if_present(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        alloc,
        dir_obj,
        b"com.joyent:snapshot_count",
        1,
        order,
        new_txg,
        staged_writes,
    )?;

    if refrsrv_add > 0 {
        // The snapshot made all previously unique head blocks shared. Its
        // newly unconsumed refreservation must fit alongside the commitments
        // of other heads, including after this directory consumed any slack
        // it had already reserved from its parent.
        enforce_pool_reservations_for_growth(
            cx,
            mos,
            mos_dirty_dnodes,
            0,
            0,
            0,
            0,
            alloc.total_free_bytes(),
            order,
        )?;
    }
    Ok(snap_ds_obj)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn bump_filesystem_limits_counter_if_present(
    cx: &Cx,
    mos: &mut Objects,
    mos_meta: &Dnode,
    mos_ceiling: u64,
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    alloc: &mut PoolSpaceAllocator,
    start_dir_obj: u64,
    counter_key: &[u8],
    delta: i64,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<()> {
    let deltas = match counter_key {
        b"com.joyent:filesystem_count" => [i128::from(delta), 0],
        b"com.joyent:snapshot_count" => [0, i128::from(delta)],
        _ => return Err(corrupt("unknown native filesystem limit counter")),
    };
    adjust_filesystem_limits_counters(
        cx,
        mos,
        mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        alloc,
        &[(start_dir_obj, deltas)],
        true,
        order,
        new_txg,
        staged_writes,
    )
}

/// Apply the net change once per ancestor and once per DSL directory ZAP.
///
/// Native count fields are namespaced, while their non-inheritable properties
/// are `filesystem_limit` and `snapshot_limit` (OpenZFS zfs-2.3.0 dsl_dir.c).
/// Combining both dimensions and both sides of a move before COW also prevents
/// a second update from rereading committed counts or discarding the first
/// staged update. Common ancestors of a rename have no growth to admit, even
/// when an administrator has lowered their limit below existing usage.
///
/// OpenZFS's private receive clone increments the persisted filesystem count,
/// but bypasses filesystem limit admission. Only that internal creation passes
/// `enforce_limits = false`; arithmetic and native metadata are still checked.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn adjust_filesystem_limits_counters(
    cx: &Cx,
    mos: &mut Objects,
    mos_meta: &Dnode,
    mos_ceiling: u64,
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    alloc: &mut PoolSpaceAllocator,
    changes: &[(u64, [i128; 2])],
    enforce_limits: bool,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<()> {
    let mut ancestors: BTreeMap<u64, [i128; 2]> = BTreeMap::new();
    for &(start_dir, delta) in changes {
        if delta == [0, 0] {
            continue;
        }
        let mut cur_dir = start_dir;
        let mut seen = BTreeSet::new();
        let mut untracked_below = [false; 2];
        while cur_dir != 0 {
            checkpoint(cx)?;
            if !seen.insert(cur_dir) {
                return Err(corrupt("cycle in filesystem limit ancestry"));
            }
            let (dd_dn, _) = read_staged_or_committed_dnode(
                cx,
                mos,
                mos_meta,
                mos_ceiling,
                mos_dirty_dnodes,
                cur_dir,
                order,
            )?;
            if !matches!(dd_dn.object_type(), DMU_OT_DSL_DIR | DMU_OTN_ZAP_METADATA)
                || dd_dn.bonus_type() != DMU_OT_DSL_DIR
                || dd_dn.bonus().len() != 256
            {
                return Err(corrupt("filesystem limit ancestor is not a DSL directory"));
            }
            let entries = if dd_dn.object_type() == DMU_OTN_ZAP_METADATA {
                mos.zap_values(cx, cur_dir)?
            } else {
                Vec::new()
            };
            let counts = [
                zap_optional_u64(&entries, b"com.joyent:filesystem_count")?,
                zap_optional_u64(&entries, b"com.joyent:snapshot_count")?,
            ];
            if counts[0].is_some() != counts[1].is_some() {
                return Err(corrupt(
                    "partially initialized native filesystem limit counters",
                ));
            }
            for index in 0..2 {
                if delta[index] == 0 {
                    continue;
                }
                if counts[index].is_none() {
                    untracked_below[index] = true;
                } else if untracked_below[index] {
                    return Err(corrupt("uninitialized directory below a counted ancestor"));
                }
            }
            let totals = ancestors.entry(cur_dir).or_default();
            for (total, change) in totals.iter_mut().zip(delta) {
                *total = total
                    .checked_add(change)
                    .ok_or_else(|| corrupt("filesystem limit delta overflow"))?;
            }
            cur_dir = order.u64(dd_dn.bonus(), 16).map_err(|e| parse_err(&e))?;
        }
    }

    // Resolve and validate every affected native limit before allocating any
    // replacement counter ZAP. A failed/corrupt property read is not unlimited.
    let mut updates = Vec::new();
    for (directory, deltas) in ancestors {
        if deltas == [0, 0] {
            continue;
        }
        let (dd_dn, dd_ceil) = read_staged_or_committed_dnode(
            cx,
            mos,
            mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            directory,
            order,
        )?;
        let props_zap = order.u64(dd_dn.bonus(), 80).map_err(|e| parse_err(&e))?;
        let properties = if props_zap == 0 {
            Vec::new()
        } else {
            mos.zap_values(cx, props_zap)?
        };
        let mut entries = if dd_dn.object_type() == DMU_OTN_ZAP_METADATA {
            mos.zap_values(cx, directory)?
        } else {
            Vec::new()
        };
        let mut changed = false;
        for ((counter_key, property), delta) in [
            (
                b"com.joyent:filesystem_count".as_slice(),
                "filesystem_limit",
            ),
            (b"com.joyent:snapshot_count".as_slice(), "snapshot_limit"),
        ]
        .into_iter()
        .zip(deltas)
        {
            if delta == 0 {
                continue;
            }
            let limit = effective_local_numeric_prop(&properties, property)?
                .filter(|&value| value != u64::MAX);
            let Some(pos) = entries.iter().position(|entry| entry.name == counter_key) else {
                if limit.is_some() {
                    return Err(corrupt(
                        "native filesystem limit has no initialized counter",
                    ));
                }
                continue;
            };
            let current = entries[pos].scalar().map_err(|e| parse_err(&e))?;
            let next = i128::from(current)
                .checked_add(delta)
                .and_then(|value| u64::try_from(value).ok())
                .ok_or_else(|| corrupt("native filesystem limit counter underflow or overflow"))?;
            if enforce_limits && delta > 0 && limit.is_some_and(|limit| next > limit) {
                return Err(reject_edquot("ZFS filesystem/snapshot limit exceeded"));
            }
            entries[pos].values = vec![next];
            changed = true;
        }
        if changed {
            updates.push((directory, dd_dn, dd_ceil, entries));
        }
    }
    for (directory, dd_dn, dd_ceil, entries) in updates {
        write_zap_dnode_in_mos(
            cx,
            mos,
            mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            alloc,
            directory,
            Some((&dd_dn, dd_ceil)),
            dd_dn.object_type(),
            dd_dn.bonus_type(),
            dd_dn.bonus().to_vec(),
            &entries,
            0,
            false,
            order,
            new_txg,
            staged_writes,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn stage_destroy_snapshot(
    cx: &Cx,
    mos: &mut Objects,
    dataset: &[Vec<u8>],
    snap_name: &[u8],
    defer: bool,
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    features: &mut MosFeatureState,
    empty_bpobj_id: Option<u64>,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<u64> {
    validate_dsl_component(snap_name, true)?;
    let (dir_obj, head_obj, _) = resolve_dataset_ids(cx, mos, dataset)?;
    let mos_meta = mos.meta_dnode().clone();
    let mos_ceiling = mos.root_birth_txg();
    let (head_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        head_obj,
        order,
    )?;
    let snapmap_obj = order.u64(head_dn.bonus(), 32).map_err(|e| parse_err(&e))?;
    let snap_entries = mos.zap_values_with_names(cx, snapmap_obj, ZapNamePolicy::AsciiUppercase)?;
    let snap_row = snap_entries
        .iter()
        .find(|e| e.name == snap_name)
        .ok_or_else(|| FfsError::NotFound("ZFS snapshot".into()))?;
    let snap_ds_obj = snap_row.scalar().map_err(|e| parse_err(&e))?;

    stage_destroy_snapshot_by_id(
        cx,
        mos,
        dir_obj,
        head_obj,
        snap_ds_obj,
        defer,
        &[],
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
fn stage_destroy_snapshot_by_id(
    cx: &Cx,
    mos: &mut Objects,
    dir_obj: u64,
    head_obj: u64,
    snap_ds_obj: u64,
    defer: bool,
    additional_limit_changes: &[(u64, [i128; 2])],
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    features: &mut MosFeatureState,
    empty_bpobj_id: Option<u64>,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<u64> {
    let mos_meta = mos.meta_dnode().clone();
    let mos_ceiling = mos.root_birth_txg();
    let (snap_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        snap_ds_obj,
        order,
    )?;
    let prev_obj = order.u64(snap_dn.bonus(), 8).map_err(|e| parse_err(&e))?;
    let prev_txg = order.u64(snap_dn.bonus(), 16).map_err(|e| parse_err(&e))?;
    let next_obj = order.u64(snap_dn.bonus(), 24).map_err(|e| parse_err(&e))?;
    let num_children = order.u64(snap_dn.bonus(), 40).map_err(|e| parse_err(&e))?;
    let snap_deadlist_obj = order.u64(snap_dn.bonus(), 64).map_err(|e| parse_err(&e))?;
    let snap_flags = order.u64(snap_dn.bonus(), 120).map_err(|e| parse_err(&e))?;
    let snap_props_obj = order.u64(snap_dn.bonus(), 264).map_err(|e| parse_err(&e))?;
    let snap_userrefs_obj = order.u64(snap_dn.bonus(), 272).map_err(|e| parse_err(&e))?;

    let held = snap_userrefs_obj != 0 && !mos.zap_values(cx, snap_userrefs_obj)?.is_empty();
    let has_clones = num_children > 1;
    if has_clones || held {
        if !defer {
            return Err(reject_busy(
                "ZFS snapshot has dependent clones or user holds",
            ));
        }
        let mut bonus = snap_dn.bonus().to_vec();
        bonus[120..128].copy_from_slice(&order.encode(snap_flags | DS_FLAG_DEFER_DESTROY));
        let mut updated = snap_dn;
        let btype = updated.bonus_type();
        updated
            .set_bonus_and_spill(btype, bonus, None)
            .map_err(|e| parse_err(&e))?;
        put_dnode_in_table(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            snap_ds_obj,
            &updated,
        )?;
        return Ok(snap_ds_obj);
    }

    // Full snapshot destruction:
    // Step A: Flatten `next_ds.ds_deadlist_obj` and partition at `prev_txg`.
    let (next_dn_orig, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        next_obj,
        order,
    )?;
    let next_dl_obj = order
        .u64(next_dn_orig.bonus(), 64)
        .map_err(|e| parse_err(&e))?;
    let (next_mintxgs, next_bps) = flatten_deadlist_bps(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        next_dl_obj,
        empty_bpobj_id,
        order,
    )?;
    let mut freed_space = SpaceDelta::default();
    let mut retained_from_next = Vec::new();
    for bp in next_bps {
        if bp.birth() > prev_txg {
            let d = alloc.free_block_dvas(&bp, new_txg)?;
            freed_space.add_assign(d)?;
        } else {
            retained_from_next.push(bp);
        }
    }

    // Step B: Flatten `snap_ds.ds_deadlist_obj` and free BOTH deadlist containers.
    let (snap_mintxgs, mut merged_bps) = flatten_deadlist_bps(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        snap_deadlist_obj,
        empty_bpobj_id,
        order,
    )?;
    merged_bps.extend(retained_from_next);

    free_deadlist_containers(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        features,
        alloc,
        snap_deadlist_obj,
        empty_bpobj_id,
        order,
        new_txg,
    )?;
    free_deadlist_containers(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        features,
        alloc,
        next_dl_obj,
        empty_bpobj_id,
        order,
        new_txg,
    )?;

    // Step C: Rebuild `next_ds.ds_deadlist_obj` keeping only `mintxg < prev_txg` (plus `0`).
    let mut rebuilt_mintxgs = snap_mintxgs;
    for m in next_mintxgs {
        if m < prev_txg || m == 0 {
            rebuilt_mintxgs.insert(m);
        }
    }
    rebuilt_mintxgs.insert(0);
    let rebuilt_dl_obj = allocate_fresh_deadlist(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        features,
        alloc,
        empty_bpobj_id,
        &rebuilt_mintxgs,
        &merged_bps,
        order,
        new_txg,
        staged_writes,
    )?;

    // Step D: Relink `prev_obj <-> next_obj` and recompute `ds_unique_bytes`!
    if prev_obj != 0 {
        let (prev_dn, _) = read_staged_or_committed_dnode(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            prev_obj,
            order,
        )?;
        let prev_dir = order.u64(prev_dn.bonus(), 0).map_err(|e| parse_err(&e))?;
        let prev_prev_txg = order.u64(prev_dn.bonus(), 16).map_err(|e| parse_err(&e))?;
        let prev_next = order.u64(prev_dn.bonus(), 24).map_err(|e| parse_err(&e))?;
        let mut prev_bonus = prev_dn.bonus().to_vec();
        if prev_dir == dir_obj {
            let mut prev_unique = 0_u64;
            for bp in &merged_bps {
                if bp.birth() > prev_prev_txg && bp.birth() <= prev_txg {
                    prev_unique = prev_unique.saturating_add(SpaceDelta::from_bp(bp)?.dsize);
                }
            }
            prev_bonus[96..104].copy_from_slice(&order.encode(prev_unique));
        }
        if prev_next == snap_ds_obj {
            prev_bonus[24..32].copy_from_slice(&order.encode(next_obj));
        } else {
            let clones_zap = order.u64(&prev_bonus, 256).map_err(|e| parse_err(&e))?;
            if clones_zap != 0 {
                let (cz_dn, cz_ceil) = mos.object_with_ceiling(cx, clones_zap)?;
                let mut cz_entries = mos.zap_values(cx, clones_zap)?;
                let old_key = format!("{snap_ds_obj:x}").into_bytes();
                cz_entries.retain(|e| e.name != old_key);
                cz_entries.push(RawZapEntry {
                    name: format!("{next_obj:x}").into_bytes(),
                    integer_bytes: 8,
                    values: vec![next_obj],
                    collision: 0,
                });
                write_zap_dnode_in_mos(
                    cx,
                    mos,
                    &mos_meta,
                    mos_ceiling,
                    mos_dirty_dnodes,
                    alloc,
                    clones_zap,
                    Some((&cz_dn, cz_ceil)),
                    cz_dn.object_type(),
                    cz_dn.bonus_type(),
                    cz_dn.bonus().to_vec(),
                    &cz_entries,
                    0,
                    false,
                    order,
                    new_txg,
                    staged_writes,
                )?;
            }
        }
        let mut updated_prev = prev_dn;
        let btype = updated_prev.bonus_type();
        updated_prev
            .set_bonus_and_spill(btype, prev_bonus, None)
            .map_err(|e| parse_err(&e))?;
        put_dnode_in_table(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            prev_obj,
            &updated_prev,
        )?;
    }

    // Update `next_obj` (`ds_prev_snap_obj`, `ds_prev_snap_txg`, `ds_deadlist_obj`, `ds_unique_bytes`).
    let (next_dn_cur, next_ceil) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        next_obj,
        order,
    )?;
    let old_next_unique = order
        .u64(next_dn_cur.bonus(), 96)
        .map_err(|e| parse_err(&e))?;
    let new_next_unique = if next_obj == head_obj {
        let next_bp = BlockPointer::parse(&next_dn_cur.bonus()[128..256], order)
            .map_err(|e| parse_err(&e))?;
        let dir_crypto = mos.dataset_crypto_info_for_dir(cx, dir_obj)?;
        let (measured, _) = walk_objectset_above_txg(
            cx,
            mos,
            &next_bp,
            next_ceil,
            dir_crypto.as_ref(),
            prev_txg,
            ObjectSetWalkMode::MeasureOnly,
            alloc,
            new_txg,
        )?;
        measured.dsize
    } else {
        let next_next_obj = order
            .u64(next_dn_cur.bonus(), 24)
            .map_err(|e| parse_err(&e))?;
        let next_creation_txg = order
            .u64(next_dn_cur.bonus(), 56)
            .map_err(|e| parse_err(&e))?;
        let (nn_dn, _) = read_staged_or_committed_dnode(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            next_next_obj,
            order,
        )?;
        let successor_deadlist = order.u64(nn_dn.bonus(), 64).map_err(|e| parse_err(&e))?;
        let (_, nn_bps) = flatten_deadlist_bps(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            successor_deadlist,
            empty_bpobj_id,
            order,
        )?;
        let mut u = 0_u64;
        for bp in &nn_bps {
            if bp.birth() > prev_txg && bp.birth() <= next_creation_txg {
                u = u.saturating_add(SpaceDelta::from_bp(bp)?.dsize);
            }
        }
        u
    };

    let mut next_bonus = next_dn_cur.bonus().to_vec();
    next_bonus[8..16].copy_from_slice(&order.encode(prev_obj));
    next_bonus[16..24].copy_from_slice(&order.encode(prev_txg));
    next_bonus[64..72].copy_from_slice(&order.encode(rebuilt_dl_obj));
    next_bonus[96..104].copy_from_slice(&order.encode(new_next_unique));
    let mut updated_next = next_dn_cur;
    let next_btype = updated_next.bonus_type();
    updated_next
        .set_bonus_and_spill(next_btype, next_bonus, None)
        .map_err(|e| parse_err(&e))?;
    put_dnode_in_table(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        next_obj,
        &updated_next,
    )?;

    // Step E: Remove from `head.ds_snapnames_zapobj` and free `snap_ds_obj` (+ props/userrefs/extensible).
    let (head_cur, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        head_obj,
        order,
    )?;
    let snapmap_obj = order.u64(head_cur.bonus(), 32).map_err(|e| parse_err(&e))?;
    let (sm_dn, sm_ceil) = mos.object_with_ceiling(cx, snapmap_obj)?;
    let mut sm_entries =
        mos.zap_values_with_names(cx, snapmap_obj, ZapNamePolicy::AsciiUppercase)?;
    sm_entries.retain(|e| e.scalar().ok() != Some(snap_ds_obj));
    write_zap_dnode_in_mos(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        alloc,
        snapmap_obj,
        Some((&sm_dn, sm_ceil)),
        sm_dn.object_type(),
        sm_dn.bonus_type(),
        sm_dn.bonus().to_vec(),
        &sm_entries,
        2,
        false,
        order,
        new_txg,
        staged_writes,
    )?;

    if snap_props_obj != 0 {
        free_mos_object_completely(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            alloc,
            snap_props_obj,
            order,
            new_txg,
        )?;
    }
    if snap_userrefs_obj != 0 {
        free_mos_object_completely(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            alloc,
            snap_userrefs_obj,
            order,
            new_txg,
        )?;
    }
    if snap_dn.object_type() == DMU_OTN_ZAP_METADATA {
        let snap_entries = dataset_feature_entries(cx, mos, snap_ds_obj, &snap_dn, features)?;
        release_dataset_block_features(&snap_entries, features)?;
        features.decrement_read(EXTENSIBLE_DATASET_FEATURE)?;
    }
    free_mos_object_completely(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        alloc,
        snap_ds_obj,
        order,
        new_txg,
    )?;

    // Step F: Update `owning_dir` (`DD_USED_SNAP` loses `freed_space.dsize`, and if `next_obj == head_obj`,
    // `DD_USED_REFRSRV` adjusts for `old_next_unique -> new_next_unique`)!
    let (dir_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        dir_obj,
        order,
    )?;
    let props_zap = order.u64(dir_dn.bonus(), 80).map_err(|e| parse_err(&e))?;
    let refreservation = if props_zap != 0
        && let Ok(rows) = mos.zap_values(cx, props_zap)
    {
        effective_local_numeric_prop(&rows, "refreservation")?.unwrap_or(0)
    } else {
        0
    };
    let refrsrv_delta = if next_obj == head_obj && refreservation > 0 {
        i128::from(refreservation.saturating_sub(new_next_unique))
            - i128::from(refreservation.saturating_sub(old_next_unique))
    } else {
        0
    };

    propagate_dsl_dir_space_delta(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        dir_obj,
        0,
        -i128::from(freed_space.dsize),
        0,
        0,
        refrsrv_delta,
        -i128::from(freed_space.comp),
        -i128::from(freed_space.uncomp),
        order,
    )?;
    let mut limit_changes = vec![(dir_obj, [0, -1])];
    limit_changes.extend_from_slice(additional_limit_changes);
    adjust_filesystem_limits_counters(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        alloc,
        &limit_changes,
        true,
        order,
        new_txg,
        staged_writes,
    )?;

    Ok(snap_ds_obj)
}

#[allow(clippy::too_many_arguments)]
fn stage_rename_snapshot(
    cx: &Cx,
    mos: &mut Objects,
    dataset: &[Vec<u8>],
    old_snap_name: &[u8],
    new_snap_name: &[u8],
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<u64> {
    validate_dsl_component(old_snap_name, true)?;
    validate_dsl_component(new_snap_name, true)?;
    let (_, head_obj, _) = resolve_dataset_ids(cx, mos, dataset)?;
    let mos_meta = mos.meta_dnode().clone();
    let mos_ceiling = mos.root_birth_txg();
    let (head_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        head_obj,
        order,
    )?;
    let snapmap_obj = order.u64(head_dn.bonus(), 32).map_err(|e| parse_err(&e))?;
    let (sm_dn, sm_ceil) = mos.object_with_ceiling(cx, snapmap_obj)?;
    let mut entries = mos.zap_values_with_names(cx, snapmap_obj, ZapNamePolicy::AsciiUppercase)?;
    let pos = entries
        .iter()
        .position(|e| e.name == old_snap_name)
        .ok_or_else(|| FfsError::NotFound("ZFS snapshot".into()))?;
    let snap_ds_obj = entries[pos].scalar().map_err(|e| parse_err(&e))?;
    if entries
        .iter()
        .enumerate()
        .any(|(i, e)| i != pos && e.name.eq_ignore_ascii_case(new_snap_name))
    {
        return Err(FfsError::Exists);
    }
    entries[pos].name = new_snap_name.to_vec();
    write_zap_dnode_in_mos(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        alloc,
        snapmap_obj,
        Some((&sm_dn, sm_ceil)),
        sm_dn.object_type(),
        sm_dn.bonus_type(),
        sm_dn.bonus().to_vec(),
        &entries,
        2,
        false,
        order,
        new_txg,
        staged_writes,
    )?;
    Ok(snap_ds_obj)
}

#[allow(clippy::too_many_arguments)]
fn stage_hold_snapshot(
    cx: &Cx,
    mos: &mut Objects,
    dataset: &[Vec<u8>],
    snap_name: &[u8],
    tag: &[u8],
    timestamp: Timestamp,
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<u64> {
    validate_dsl_component(snap_name, true)?;
    validate_hold_tag(tag)?;
    let (_, head_obj, _) = resolve_dataset_ids(cx, mos, dataset)?;
    let mos_meta = mos.meta_dnode().clone();
    let mos_ceiling = mos.root_birth_txg();
    let (head_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        head_obj,
        order,
    )?;
    let snapmap_obj = order.u64(head_dn.bonus(), 32).map_err(|e| parse_err(&e))?;
    let snap_entries = mos.zap_values_with_names(cx, snapmap_obj, ZapNamePolicy::AsciiUppercase)?;
    let snap_ds_obj = snap_entries
        .iter()
        .find(|e| e.name == snap_name)
        .ok_or_else(|| FfsError::NotFound("ZFS snapshot".into()))?
        .scalar()
        .map_err(|e| parse_err(&e))?;

    let (snap_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        snap_ds_obj,
        order,
    )?;
    let snap_flags = order.u64(snap_dn.bonus(), 120).map_err(|e| parse_err(&e))?;
    if snap_flags & DS_FLAG_DEFER_DESTROY != 0 {
        return Err(reject_busy(
            "cannot place user hold on snapshot marked for deferred destroy",
        ));
    }
    let cur_userrefs = order.u64(snap_dn.bonus(), 272).map_err(|e| parse_err(&e))?;
    let (userrefs_obj, existing_ur, mut entries) = if cur_userrefs == 0 {
        let id = allocate_object_id(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
        (id, None, Vec::new())
    } else {
        let (dn, c) = mos.object_with_ceiling(cx, cur_userrefs)?;
        let rows = mos.zap_values(cx, cur_userrefs)?;
        (cur_userrefs, Some((dn, c)), rows)
    };
    if entries.iter().any(|e| e.name == tag) {
        return Err(FfsError::Exists);
    }
    entries.push(RawZapEntry {
        name: tag.to_vec(),
        integer_bytes: 8,
        values: vec![timestamp.seconds.cast_unsigned()],
        collision: 0,
    });
    write_zap_dnode_in_mos(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        alloc,
        userrefs_obj,
        existing_ur.as_ref().map(|(d, c)| (d, *c)),
        DMU_OT_USERREFS,
        0,
        Vec::new(),
        &entries,
        0,
        false,
        order,
        new_txg,
        staged_writes,
    )?;
    if cur_userrefs == 0 {
        let mut bonus = snap_dn.bonus().to_vec();
        bonus[272..280].copy_from_slice(&order.encode(userrefs_obj));
        let mut updated = snap_dn;
        let btype = updated.bonus_type();
        updated
            .set_bonus_and_spill(btype, bonus, None)
            .map_err(|e| parse_err(&e))?;
        put_dnode_in_table(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            snap_ds_obj,
            &updated,
        )?;
    }
    Ok(snap_ds_obj)
}

#[allow(clippy::too_many_arguments)]
fn stage_release_snapshot(
    cx: &Cx,
    mos: &mut Objects,
    dataset: &[Vec<u8>],
    snap_name: &[u8],
    tag: &[u8],
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    features: &mut MosFeatureState,
    empty_bpobj_id: Option<u64>,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<u64> {
    validate_dsl_component(snap_name, true)?;
    validate_hold_tag(tag)?;
    let (dir_obj, head_obj, _) = resolve_dataset_ids(cx, mos, dataset)?;
    let mos_meta = mos.meta_dnode().clone();
    let mos_ceiling = mos.root_birth_txg();
    let (head_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        head_obj,
        order,
    )?;
    let snapmap_obj = order.u64(head_dn.bonus(), 32).map_err(|e| parse_err(&e))?;
    let snap_entries = mos.zap_values_with_names(cx, snapmap_obj, ZapNamePolicy::AsciiUppercase)?;
    let snap_ds_obj = snap_entries
        .iter()
        .find(|e| e.name == snap_name)
        .ok_or_else(|| FfsError::NotFound("ZFS snapshot".into()))?
        .scalar()
        .map_err(|e| parse_err(&e))?;

    let (snap_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        snap_ds_obj,
        order,
    )?;
    let num_children = order.u64(snap_dn.bonus(), 40).map_err(|e| parse_err(&e))?;
    let snap_flags = order.u64(snap_dn.bonus(), 120).map_err(|e| parse_err(&e))?;
    let cur_userrefs = order.u64(snap_dn.bonus(), 272).map_err(|e| parse_err(&e))?;
    if cur_userrefs == 0 {
        return Err(FfsError::NotFound("ZFS snapshot hold tag".into()));
    }
    let (ur_dn, ur_ceil) = mos.object_with_ceiling(cx, cur_userrefs)?;
    let mut entries = mos.zap_values(cx, cur_userrefs)?;
    let before = entries.len();
    entries.retain(|e| e.name != tag);
    if entries.len() == before {
        return Err(FfsError::NotFound("ZFS snapshot hold tag".into()));
    }
    if entries.is_empty() {
        free_mos_object_completely(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            alloc,
            cur_userrefs,
            order,
            new_txg,
        )?;
        let mut bonus = snap_dn.bonus().to_vec();
        bonus[272..280].copy_from_slice(&order.encode(0));
        let mut updated = snap_dn;
        let btype = updated.bonus_type();
        updated
            .set_bonus_and_spill(btype, bonus, None)
            .map_err(|e| parse_err(&e))?;
        put_dnode_in_table(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            snap_ds_obj,
            &updated,
        )?;
        if snap_flags & DS_FLAG_DEFER_DESTROY != 0 && num_children == 1 {
            return stage_destroy_snapshot_by_id(
                cx,
                mos,
                dir_obj,
                head_obj,
                snap_ds_obj,
                false,
                &[],
                mos_dirty_dnodes,
                features,
                empty_bpobj_id,
                alloc,
                order,
                new_txg,
                staged_writes,
            );
        }
    } else {
        write_zap_dnode_in_mos(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            alloc,
            cur_userrefs,
            Some((&ur_dn, ur_ceil)),
            ur_dn.object_type(),
            ur_dn.bonus_type(),
            ur_dn.bonus().to_vec(),
            &entries,
            0,
            false,
            order,
            new_txg,
            staged_writes,
        )?;
    }
    Ok(snap_ds_obj)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn stage_create_bookmark(
    cx: &Cx,
    mos: &mut Objects,
    dataset: &[Vec<u8>],
    bookmark_name: &[u8],
    source_name: &[u8],
    source_is_bookmark: bool,
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    features: &mut MosFeatureState,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<u64> {
    validate_dsl_component(bookmark_name, true)?;
    validate_dsl_component(source_name, true)?;
    if !features
        .write_features
        .contains_key("com.delphix:bookmarks")
        || !features
            .read_features
            .contains_key("com.delphix:extensible_dataset")
    {
        return Err(unsupported(
            "ZFS bookmarks require com.delphix:bookmarks and com.delphix:extensible_dataset",
        ));
    }
    let (_, head_obj, _) = resolve_dataset_ids(cx, mos, dataset)?;
    let mos_meta = mos.meta_dnode().clone();
    let mos_ceiling = mos.root_birth_txg();
    let (head_dn, head_ceil) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        head_obj,
        order,
    )?;

    let (src_txg, src_time, src_guid) = if source_is_bookmark {
        let existing_bmarks = read_bookmarks_on_head(cx, mos, head_obj, &head_dn)?;
        let found = existing_bmarks
            .into_iter()
            .find(|b| b.name.as_bytes() == source_name)
            .ok_or_else(|| FfsError::NotFound("ZFS source bookmark".into()))?;
        (found.creation_txg, found.creation_time, found.guid)
    } else {
        let snapmap_obj = order.u64(head_dn.bonus(), 32).map_err(|e| parse_err(&e))?;
        let snap_entries =
            mos.zap_values_with_names(cx, snapmap_obj, ZapNamePolicy::AsciiUppercase)?;
        let snap_ds_obj = snap_entries
            .iter()
            .find(|e| e.name == source_name)
            .ok_or_else(|| FfsError::NotFound("ZFS source snapshot".into()))?
            .scalar()
            .map_err(|e| parse_err(&e))?;
        let (s_dn, _) = mos.object_with_ceiling(cx, snap_ds_obj)?;
        let c_time = order.u64(s_dn.bonus(), 48).map_err(|e| parse_err(&e))?;
        let c_txg = order.u64(s_dn.bonus(), 56).map_err(|e| parse_err(&e))?;
        let guid = order.u64(s_dn.bonus(), 112).map_err(|e| parse_err(&e))?;
        (c_txg, c_time, guid)
    };

    // Zapify `head_dn` (`DMU_OT_DSL_DATASET = 16 -> DMU_OTN_ZAP_METADATA = 196`) if needed.
    let was_zapified = head_dn.object_type() == DMU_OTN_ZAP_METADATA;
    let mut head_zap_entries = if was_zapified {
        mos.zap_values(cx, head_obj)?
    } else {
        features.increment_read("com.delphix:extensible_dataset", new_txg)?;
        Vec::new()
    };

    let existing_bm_obj = zap_optional_u64(&head_zap_entries, b"com.delphix:bookmarks")?;
    let (bmark_zapobj, existing_bm_dn, mut bm_entries) = match existing_bm_obj {
        Some(id) if id != 0 => {
            let (dn, c) = mos.object_with_ceiling(cx, id)?;
            let rows = mos.zap_values_with_names(cx, id, ZapNamePolicy::AsciiUppercase)?;
            (id, Some((dn, c)), rows)
        }
        _ => {
            let id = allocate_object_id(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
            head_zap_entries.retain(|e| e.name != b"com.delphix:bookmarks");
            head_zap_entries.push(RawZapEntry {
                name: b"com.delphix:bookmarks".to_vec(),
                integer_bytes: 8,
                values: vec![id],
                collision: 0,
            });
            (id, None, Vec::new())
        }
    };

    if bm_entries
        .iter()
        .any(|e| e.name.eq_ignore_ascii_case(bookmark_name))
    {
        return Err(FfsError::Exists);
    }
    bm_entries.push(RawZapEntry {
        name: bookmark_name.to_vec(),
        integer_bytes: 8,
        values: vec![src_txg, src_time, src_guid],
        collision: 0,
    });
    if existing_bm_dn.is_none() {
        features.increment_write("com.delphix:bookmarks", new_txg)?;
    }

    write_zap_dnode_in_mos(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        alloc,
        bmark_zapobj,
        existing_bm_dn.as_ref().map(|(d, c)| (d, *c)),
        DMU_OTN_ZAP_METADATA,
        0,
        Vec::new(),
        &bm_entries,
        2,
        true, // multi-u64 array requires Fat-ZAP!
        order,
        new_txg,
        staged_writes,
    )?;

    if !was_zapified || existing_bm_obj.is_none() {
        write_zap_dnode_in_mos(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            alloc,
            head_obj,
            if was_zapified {
                Some((&head_dn, head_ceil))
            } else {
                None
            },
            DMU_OTN_ZAP_METADATA,
            DMU_OT_DSL_DATASET,
            head_dn.bonus().to_vec(),
            &head_zap_entries,
            0,
            false,
            order,
            new_txg,
            staged_writes,
        )?;
    }

    Ok(bmark_zapobj)
}

#[allow(clippy::too_many_arguments)]
fn stage_destroy_bookmark(
    cx: &Cx,
    mos: &mut Objects,
    dataset: &[Vec<u8>],
    bookmark_name: &[u8],
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    features: &mut MosFeatureState,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<u64> {
    validate_dsl_component(bookmark_name, true)?;
    let (_, head_obj, _) = resolve_dataset_ids(cx, mos, dataset)?;
    let mos_meta = mos.meta_dnode().clone();
    let mos_ceiling = mos.root_birth_txg();
    let (head_dn, head_ceil) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        head_obj,
        order,
    )?;
    if head_dn.object_type() != DMU_OTN_ZAP_METADATA {
        return Err(FfsError::NotFound("ZFS bookmark".into()));
    }
    let mut head_entries = mos.zap_values(cx, head_obj)?;
    let bmark_zapobj = zap_optional_u64(&head_entries, b"com.delphix:bookmarks")?
        .filter(|&id| id != 0)
        .ok_or_else(|| FfsError::NotFound("ZFS bookmark".into()))?;
    let (bm_dn, bm_ceil) = mos.object_with_ceiling(cx, bmark_zapobj)?;
    let mut bm_entries =
        mos.zap_values_with_names(cx, bmark_zapobj, ZapNamePolicy::AsciiUppercase)?;
    let before = bm_entries.len();
    bm_entries.retain(|e| e.name != bookmark_name);
    if bm_entries.len() == before {
        return Err(FfsError::NotFound("ZFS bookmark".into()));
    }

    if bm_entries.is_empty() {
        features.decrement_write("com.delphix:bookmarks")?;
        free_mos_object_completely(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            alloc,
            bmark_zapobj,
            order,
            new_txg,
        )?;
        head_entries.retain(|e| e.name != b"com.delphix:bookmarks");
        write_zap_dnode_in_mos(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            alloc,
            head_obj,
            Some((&head_dn, head_ceil)),
            DMU_OTN_ZAP_METADATA,
            DMU_OT_DSL_DATASET,
            head_dn.bonus().to_vec(),
            &head_entries,
            0,
            false,
            order,
            new_txg,
            staged_writes,
        )?;
    } else {
        write_zap_dnode_in_mos(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            alloc,
            bmark_zapobj,
            Some((&bm_dn, bm_ceil)),
            DMU_OTN_ZAP_METADATA,
            0,
            Vec::new(),
            &bm_entries,
            2,
            true,
            order,
            new_txg,
            staged_writes,
        )?;
    }
    Ok(bmark_zapobj)
}

pub fn list_holds_in_mos(
    cx: &Cx,
    mos: &mut Objects,
    dataset: &[Vec<u8>],
    snap_name: &[u8],
) -> Result<Vec<ZfsHoldInfo>> {
    validate_dsl_component(snap_name, true)?;
    let (_, head_obj, _) = resolve_dataset_ids(cx, mos, dataset)?;
    let (head_dn, _) = mos.object_with_ceiling(cx, head_obj)?;
    let snapmap_obj = head_dn
        .order()
        .u64(head_dn.bonus(), 32)
        .map_err(|e| parse_err(&e))?;
    let snap_entries = mos.zap_values_with_names(cx, snapmap_obj, ZapNamePolicy::AsciiUppercase)?;
    let snap_ds_obj = snap_entries
        .iter()
        .find(|e| e.name == snap_name)
        .ok_or_else(|| FfsError::NotFound("ZFS snapshot".into()))?
        .scalar()
        .map_err(|e| parse_err(&e))?;
    let (snap_dn, _) = mos.object_with_ceiling(cx, snap_ds_obj)?;
    let ur_obj = snap_dn
        .order()
        .u64(snap_dn.bonus(), 272)
        .map_err(|e| parse_err(&e))?;
    if ur_obj == 0 {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for row in mos.zap_values(cx, ur_obj)? {
        out.push(ZfsHoldInfo {
            tag: String::from_utf8_lossy(&row.name).into_owned(),
            timestamp_seconds: row.scalar().map_err(|e| parse_err(&e))?,
        });
    }
    out.sort_by(|a, b| a.tag.cmp(&b.tag));
    Ok(out)
}

pub fn list_bookmarks_in_mos(
    cx: &Cx,
    mos: &mut Objects,
    dataset: &[Vec<u8>],
) -> Result<Vec<ZfsBookmarkInfo>> {
    let (_, head_obj, _) = resolve_dataset_ids(cx, mos, dataset)?;
    let (head_dn, _) = mos.object_with_ceiling(cx, head_obj)?;
    read_bookmarks_on_head(cx, mos, head_obj, &head_dn)
}

fn read_bookmarks_on_head(
    cx: &Cx,
    mos: &mut Objects,
    head_obj: u64,
    head_dn: &Dnode,
) -> Result<Vec<ZfsBookmarkInfo>> {
    if head_dn.object_type() != DMU_OTN_ZAP_METADATA {
        return Ok(Vec::new());
    }
    let head_entries = mos.zap_values(cx, head_obj)?;
    let Some(bm_obj) =
        zap_optional_u64(&head_entries, b"com.delphix:bookmarks")?.filter(|&id| id != 0)
    else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for row in mos.zap_values_with_names(cx, bm_obj, ZapNamePolicy::AsciiUppercase)? {
        if row.integer_bytes != 8 || row.values.len() < 3 {
            return Err(corrupt("invalid ZFS bookmark entry width"));
        }
        out.push(ZfsBookmarkInfo {
            name: String::from_utf8_lossy(&row.name).into_owned(),
            creation_txg: row.values[0],
            creation_time: row.values[1],
            guid: row.values[2],
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Adjust `DSL_CRYPTO_REFCOUNT` on a MOS `dsl_crypto_key` ZAP object by `delta` (`+1` or `-1`).
/// Returns the updated refcount (`0` means the caller must free `crypto_key_obj` and decrement
/// `com.datto:encryption` in `features_for_read`).
#[allow(clippy::too_many_arguments)]
pub(super) fn adjust_dsl_crypto_key_refcount(
    cx: &Cx,
    mos: &mut Objects,
    mos_meta: &Dnode,
    mos_ceiling: u64,
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    alloc: &mut PoolSpaceAllocator,
    crypto_key_obj: u64,
    delta: i64,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<u64> {
    let (key_dn, key_ceil) = mos.object_with_ceiling(cx, crypto_key_obj)?;
    let key_entries = mos.zap_values(cx, crypto_key_obj)?;
    let mut record = parse_dsl_crypto_key_zap(&key_entries)?;
    let next = u64::try_from(
        i128::from(record.refcount)
            .checked_add(i128::from(delta))
            .filter(|&v| v >= 0)
            .ok_or_else(|| corrupt("DSL_CRYPTO_REFCOUNT underflow/overflow"))?,
    )
    .map_err(|_| corrupt("DSL_CRYPTO_REFCOUNT u64 overflow"))?;
    if next == 0 {
        return Ok(0);
    }
    record.refcount = next;
    let updated_entries = encode_dsl_crypto_key_zap(&record);
    write_zap_dnode_in_mos(
        cx,
        mos,
        mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        alloc,
        crypto_key_obj,
        Some((&key_dn, key_ceil)),
        DMU_OTN_ZAP_METADATA,
        0,
        Vec::new(),
        &updated_entries,
        0,
        true,
        order,
        new_txg,
        staged_writes,
    )?;
    Ok(next)
}

/// Resolve effective compression for a newly created child dataset from
/// `initial_props` (falling back to inherited `parent_dataset` `compression` property).
pub(super) fn effective_compression_for_new_dataset(
    cx: &Cx,
    mos: &mut Objects,
    parent_dataset: &[Vec<u8>],
    initial_props: &[(String, ZfsPropertySetValue)],
    features: &MosFeatureState,
) -> Result<DatasetCompression> {
    for (k, v) in initial_props {
        if k == "compression"
            && let ZfsPropertySetValue::Number(raw) = v
        {
            return DatasetCompression::from_property(*raw, features);
        }
    }
    let props = mos.properties(cx, parent_dataset, None, &["compression".into()])?;
    let raw = match props.values.first().and_then(|p| p.value.as_ref()) {
        Some(PropertyValue::Number(n)) => *n,
        _ => 2,
    };
    DatasetCompression::from_property(raw, features)
}

/// Build a fresh ZPL v4/v5 `ObjectSet` mirroring the SA schema and embedded quota
/// schema of `parent_head_obj`.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn build_fresh_zpl_objectset(
    cx: &Cx,
    mos: &mut Objects,
    parent_head_obj: u64,
    parent_crypto: Option<&ZfsDatasetCryptoInfo>,
    compression: DatasetCompression,
    mut write_crypto: Option<&mut DatasetWriteCrypto>,
    features: &mut MosFeatureState,
    alloc: &mut PoolSpaceAllocator,
    timestamp: Timestamp,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<(BlockPointer, SpaceDelta, DatasetFeatureUsage)> {
    let (p_dn, p_ceil) = mos.object_with_ceiling(cx, parent_head_obj)?;
    let p_os_bp =
        BlockPointer::parse(&p_dn.bonus()[128..256], p_dn.order()).map_err(|e| parse_err(&e))?;
    let (p_verify_key, p_view_crypto) = if let Some(p_info) = parent_crypto {
        let key = mos
            .keyring()
            .get(p_info.encryption_root_ddobj)
            .ok_or(FfsError::PermissionDenied)?;
        let vc = Arc::new(DatasetCryptoContext {
            info: p_info.clone(),
            raw_scrub_only: false,
        });
        (Some(key), Some(vc))
    } else {
        (None, None)
    };
    let (p_os_raw, p_os_ord, _) =
        mos.read_dataset_objset_block_raw(cx, &p_os_bp, p_ceil, p_verify_key.as_deref(), false)?;
    let p_os = ObjectSet::parse(&p_os_raw, p_os_ord).map_err(|e| parse_err(&e))?;
    let mut p_view = mos.open_objectset_view_with_crypto(
        p_os.meta.clone(),
        p_os_bp.birth(),
        mos.txg,
        p_view_crypto,
    );
    let p_master = p_view.zap_values(cx, 1)?;
    let p_root_id = zap_required_u64(&p_master, b"ROOT")?;
    let zpl_version = zap_required_u64(&p_master, b"VERSION")?;
    let (p_root_dn, _) = p_view.object_with_ceiling(cx, p_root_id)?;

    let min_blk = (1_usize << alloc.ashift).max(512);
    let mut zpl_born = SpaceDelta::default();
    let mut feature_usage = DatasetFeatureUsage::default();
    let mut zpl_dirty_dnodes: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let empty_meta = Dnode::from_spec(DnodeSpec {
        object_type: DMU_OT_DNODE,
        bonus_type: 0,
        checksum_type: 0,
        compress_type: 0,
        flags: DNODE_FLAG_USED_BYTES,
        order,
        levels: 1,
        indirect_shift: 17,
        data_bytes: DNODE_BLOCK_BYTES,
        max_block: 0,
        used_bytes: 0,
        slots: 1,
        pointers: vec![
            BlockPointer::hole_pointer(),
            BlockPointer::hole_pointer(),
            BlockPointer::hole_pointer(),
        ],
        bonus: Vec::new(),
        spill: None,
    })
    .map_err(|e| parse_err(&e))?;
    let mut new_view = mos.open_objectset_view(empty_meta.clone(), new_txg, new_txg);
    let acct_flags = objectset_user_accounting_flags(&p_os, p_os_ord)?;

    // Helper to allocate & insert a ZPL ZAP object into `zpl_dirty_dnodes`.
    let mut write_zpl_zap = |obj_id: u64,
                             obj_type: u8,
                             btype: u8,
                             bonus: Vec<u8>,
                             user_flags: u8,
                             entries: &[RawZapEntry],
                             force_fat: bool,
                             wc: Option<&mut DatasetWriteCrypto>|
     -> Result<u64> {
        let (bsize, blocks) = if force_fat {
            let blks = ffs_ondisk::zfs_zap::encode_fatzap_with_normflags(
                entries,
                FATZAP_BLOCK_BYTES,
                0x5A46_535F_4646_5331,
                false,
                0,
                order,
            )
            .map_err(|e| parse_err(&e))?;
            (FATZAP_BLOCK_BYTES, blks)
        } else {
            encode_zap_blocks_for_dnode(cx, &mut new_view, None, entries, order, min_blk)?
        };
        let mut dirty = BTreeMap::new();
        for (i, b) in blocks.into_iter().enumerate() {
            dirty.insert(i as u64, Some(b));
        }
        let nblkptr = if bonus.is_empty() { 3 } else { 1 };
        let out = cow_update_dnode_with_crypto(
            cx,
            &mut new_view,
            alloc,
            DnodeCowSpec {
                existing: None,
                object_type: obj_type,
                bonus_type: btype,
                checksum_type: 7,
                compress_type: 2,
                user_flags,
                indirect_shift: 17,
                data_bytes: bsize,
                max_block: (dirty.len() - 1) as u64,
                slots: 1,
                nblkptr,
                bonus,
                spill: None,
                order,
                new_txg,
                leaf_bucket: WriteBucket::ChildBlocks,
                indirect_bucket: WriteBucket::ChildBlocks,
            },
            &dirty,
            obj_id,
            compression,
            wc,
            staged_writes,
        )?;
        zpl_born.add_assign(out.born)?;
        feature_usage.extend(out.feature_usage);
        let used = out.dnode.used_bytes();
        put_dnode_in_table(
            cx,
            &mut new_view,
            &empty_meta,
            new_txg,
            &mut zpl_dirty_dnodes,
            obj_id,
            &out.dnode,
        )?;
        Ok(used)
    };

    // 2. Copy SA schema (`SA_MASTER = 8`, `REGISTRY = 9`, `LAYOUTS = 10`) if ZPL v5.
    let mut sa_registry = None;
    let mut master_entries = vec![
        RawZapEntry {
            name: b"VERSION".to_vec(),
            integer_bytes: 8,
            values: vec![zpl_version],
            collision: 0,
        },
        RawZapEntry {
            name: b"DELETE_QUEUE".to_vec(),
            integer_bytes: 8,
            values: vec![2],
            collision: 0,
        },
        RawZapEntry {
            name: b"ROOT".to_vec(),
            integer_bytes: 8,
            values: vec![3],
            collision: 0,
        },
        RawZapEntry {
            name: b"casesensitivity".to_vec(),
            integer_bytes: 8,
            values: vec![0],
            collision: 0,
        },
        RawZapEntry {
            name: b"normalization".to_vec(),
            integer_bytes: 8,
            values: vec![0],
            collision: 0,
        },
        RawZapEntry {
            name: b"utf8only".to_vec(),
            integer_bytes: 8,
            values: vec![0],
            collision: 0,
        },
    ];

    if let Some(p_sa_master) = zap_optional_u64(&p_master, b"SA_ATTRS")?.filter(|&v| v != 0) {
        let sa_rows = p_view.zap_values(cx, p_sa_master)?;
        let reg_obj = zap_required_u64(&sa_rows, b"REGISTRY")?;
        let lay_obj = zap_required_u64(&sa_rows, b"LAYOUTS")?;
        let reg_entries = p_view.zap_values(cx, reg_obj)?;
        let lay_entries = p_view.zap_values(cx, lay_obj)?;
        sa_registry =
            Some(SaRegistry::from_zaps(&reg_entries, &lay_entries).map_err(|e| parse_err(&e))?);

        let _ = write_zpl_zap(
            8,
            DMU_OT_SA_MASTER_NODE,
            0,
            Vec::new(),
            0,
            &[
                RawZapEntry {
                    name: b"REGISTRY".to_vec(),
                    integer_bytes: 8,
                    values: vec![9],
                    collision: 0,
                },
                RawZapEntry {
                    name: b"LAYOUTS".to_vec(),
                    integer_bytes: 8,
                    values: vec![10],
                    collision: 0,
                },
            ],
            false,
            write_crypto.as_deref_mut(),
        )?;
        let _ = write_zpl_zap(
            9,
            DMU_OT_SA_ATTR_REGISTRATION,
            0,
            Vec::new(),
            0,
            &reg_entries,
            false,
            write_crypto.as_deref_mut(),
        )?;
        let _ = write_zpl_zap(
            10,
            DMU_OT_SA_ATTR_LAYOUTS,
            0,
            Vec::new(),
            0,
            &lay_entries,
            true, // uint16 array values require Fat-ZAP!
            write_crypto.as_deref_mut(),
        )?;
        master_entries.push(RawZapEntry {
            name: b"SA_ATTRS".to_vec(),
            integer_bytes: 8,
            values: vec![8],
            collision: 0,
        });
    }

    // 3. Object 1 (`MASTER_NODE`) and Object 2 (`DELETE_QUEUE`).
    let _ = write_zpl_zap(
        1,
        DMU_OT_MASTER_NODE,
        0,
        Vec::new(),
        0,
        &master_entries,
        false,
        write_crypto.as_deref_mut(),
    )?;
    let _ = write_zpl_zap(
        2,
        DMU_OT_UNLINKED_SET,
        0,
        Vec::new(),
        0,
        &[],
        false,
        write_crypto.as_deref_mut(),
    )?;

    // 4. Object 3 (`ROOT` directory, mode `0o40755`, self-parented `parent = 3`).
    let root_meta = Metadata {
        kind: Kind::Directory,
        mode: 0o040_755,
        size: 2,
        parent: 3,
        links: 2,
        generation: new_txg.max(1),
        flags: ZFS_ACL_TRIVIAL | ZFS_NO_EXECS_DENIED,
        uid: 0,
        gid: 0,
        times: [timestamp; 4],
        inline_symlink: None,
    };
    let (root_btype, root_bonus) = if let Some(ref reg) = sa_registry {
        (
            DMU_OT_SA,
            reg.encode_new_from_template(p_root_dn.bonus(), &root_meta)
                .map_err(|e| parse_err(&e))?,
        )
    } else {
        let _ = encode_directory_reference(3, Kind::Directory).map_err(|e| parse_err(&e))?;
        (
            super::dmu_cow::DMU_OT_ZNODE,
            root_meta
                .encode_legacy(None, order)
                .map_err(|e| parse_err(&e))?,
        )
    };
    let root_used = write_zpl_zap(
        3,
        DMU_OT_DIRECTORY_CONTENTS,
        root_btype,
        root_bonus,
        acct_flags,
        &[],
        false,
        write_crypto.as_deref_mut(),
    )?;

    // Build `ObjectSet` and write initial embedded quota ZAPs directly with Object 3's accounting
    // (avoiding reading uncommitted staged blocks back from disk).
    let mut initial_quota_entries = Vec::new();
    if root_used > 0 {
        initial_quota_entries.push(RawZapEntry {
            name: b"0".to_vec(),
            integer_bytes: 8,
            values: vec![root_used],
            collision: 0,
        });
    }
    if p_os.flags & 0x02 != 0 {
        initial_quota_entries.push(RawZapEntry {
            name: b"obj-0".to_vec(),
            integer_bytes: 8,
            values: vec![1],
            collision: 0,
        });
    }
    let os_phys_bytes = if write_crypto.is_some() {
        p_os.physical_bytes().max(2048)
    } else {
        p_os.physical_bytes()
    };
    let mut new_os = ObjectSet::new(
        2,
        p_os.flags,
        empty_meta.clone(),
        ffs_ondisk::zfs_dmu::ZilHeader::empty(),
        os_phys_bytes,
    )
    .map_err(|e| parse_err(&e))?;
    for emb_off in [
        OBJSET_USERUSED_OFFSET,
        OBJSET_GROUPUSED_OFFSET,
        OBJSET_PROJECTUSED_OFFSET,
    ] {
        if let Some(p_emb) = p_os
            .embedded_dnode(emb_off, p_os_ord)
            .map_err(|e| parse_err(&e))?
        {
            if emb_off == OBJSET_PROJECTUSED_OFFSET
                && features
                    .write_features
                    .contains_key("org.zfsonlinux:project_quota")
            {
                features.increment_write("org.zfsonlinux:project_quota", new_txg)?;
            }
            let emb_entries: &[RawZapEntry] =
                if emb_off == OBJSET_PROJECTUSED_OFFSET && p_os.flags & 0x04 == 0 {
                    &[]
                } else {
                    &initial_quota_entries
                };
            let (ebsize, eblocks) =
                encode_zap_blocks_for_dnode(cx, &mut new_view, None, emb_entries, order, min_blk)?;
            let mut edirty = BTreeMap::new();
            for (i, b) in eblocks.into_iter().enumerate() {
                edirty.insert(i as u64, Some(b));
            }
            let eout = cow_update_dnode_with_crypto(
                cx,
                &mut new_view,
                alloc,
                DnodeCowSpec {
                    existing: None,
                    object_type: p_emb.object_type(),
                    bonus_type: 0,
                    checksum_type: 7,
                    compress_type: 2,
                    user_flags: 0,
                    indirect_shift: p_emb.indirect_shift(),
                    data_bytes: ebsize,
                    max_block: (edirty.len() - 1) as u64,
                    slots: 1,
                    nblkptr: 3,
                    bonus: Vec::new(),
                    spill: None,
                    order,
                    new_txg,
                    leaf_bucket: WriteBucket::ChildBlocks,
                    indirect_bucket: WriteBucket::ChildBlocks,
                },
                &edirty,
                emb_off as u64,
                compression,
                write_crypto.as_deref_mut(),
                staged_writes,
            )?;
            zpl_born.add_assign(eout.born)?;
            feature_usage.extend(eout.feature_usage);
            new_os
                .set_embedded_dnode(emb_off, Some(&eout.dnode))
                .map_err(|e| parse_err(&e))?;
        }
    }

    // 5. Write `os_meta_dnode` + 4096B `ObjectSet` root block.
    let mut meta_dirty = BTreeMap::new();
    for (&bid, blk) in &zpl_dirty_dnodes {
        meta_dirty.insert(bid, Some(blk.clone()));
    }
    let max_blk = zpl_dirty_dnodes.keys().copied().max().unwrap_or(0);
    let meta_out = cow_update_dnode_with_crypto(
        cx,
        &mut new_view,
        alloc,
        DnodeCowSpec {
            existing: None,
            object_type: DMU_OT_DNODE,
            bonus_type: 0,
            checksum_type: 7,
            compress_type: 0,
            user_flags: 0,
            indirect_shift: 17,
            data_bytes: DNODE_BLOCK_BYTES,
            max_block: max_blk,
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
        0,
        compression,
        write_crypto.as_deref_mut(),
        staged_writes,
    )?;
    zpl_born.add_assign(meta_out.born)?;
    feature_usage.extend(meta_out.feature_usage);
    new_os.meta = meta_out.dnode;

    let os_bp = write_dataset_objset_block(
        &mut new_os,
        alloc,
        7,
        order,
        new_txg,
        compression,
        write_crypto.as_deref(),
        staged_writes,
    )?;
    zpl_born.add_assign(SpaceDelta::from_bp(&os_bp)?)?;
    feature_usage.observe(&os_bp);
    Ok((os_bp, zpl_born, feature_usage))
}

/// Resolve OpenZFS `dp->dp_origin_snap` (`$ORIGIN@$ORIGIN`) as `(origin_dd_obj, origin_head_obj, origin_snap_obj)`
/// if the pool contains the special `$ORIGIN` directory under MOS Object 1 `"root_dataset"`.
pub(super) fn lookup_pool_origin_snapshot(
    cx: &Cx,
    mos: &mut Objects,
    mos_meta: &Dnode,
    mos_ceiling: u64,
    mos_dirty_dnodes: &BTreeMap<u64, Vec<u8>>,
    order: Endian,
) -> Result<Option<(u64, u64, u64)>> {
    let dir_entries = mos.zap_values(cx, 1)?;
    let Some(root_dd_obj) = zap_optional_u64(&dir_entries, b"root_dataset")?.filter(|&id| id != 0)
    else {
        return Ok(None);
    };
    let (root_dd_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        root_dd_obj,
        order,
    )?;
    let root_child_zap = order
        .u64(root_dd_dn.bonus(), 32)
        .map_err(|e| parse_err(&e))?;
    if root_child_zap == 0 {
        return Ok(None);
    }
    let root_children = mos.zap_values(cx, root_child_zap)?;
    let Some(origin_dd_obj) = zap_optional_u64(&root_children, b"$ORIGIN")?.filter(|&id| id != 0)
    else {
        return Ok(None);
    };
    let (origin_dd_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        origin_dd_obj,
        order,
    )?;
    let origin_head_obj = order
        .u64(origin_dd_dn.bonus(), 8)
        .map_err(|e| parse_err(&e))?;
    if origin_head_obj == 0 {
        return Ok(None);
    }
    let (origin_head_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        origin_head_obj,
        order,
    )?;
    let origin_snap_obj = order
        .u64(origin_head_dn.bonus(), 8)
        .map_err(|e| parse_err(&e))?;
    if origin_snap_obj == 0 {
        return Ok(None);
    }
    Ok(Some((origin_dd_obj, origin_head_obj, origin_snap_obj)))
}

/// Write a newly created `dsl_dir` (`DMU_OT_DSL_DIR`), automatically zapifying with
/// `filesystem_count = 0` and `snapshot_count = 0` when `com.joyent:filesystem_limits` is active
/// and/or attaching any `extra_zap_entries` (such as `com.datto:crypto_key_obj`).
#[allow(clippy::too_many_arguments)]
pub(super) fn put_new_dsl_dir_in_mos(
    cx: &Cx,
    mos: &mut Objects,
    mos_meta: &Dnode,
    mos_ceiling: u64,
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    features: &mut MosFeatureState,
    alloc: &mut PoolSpaceAllocator,
    dd_obj: u64,
    dd_bonus: Vec<u8>,
    extra_zap_entries: &[RawZapEntry],
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<()> {
    let fs_ss_limit_active = features
        .write_features
        .get("com.joyent:filesystem_limits")
        .copied()
        .unwrap_or(0)
        > 0;
    if fs_ss_limit_active || !extra_zap_entries.is_empty() {
        features.increment_read("com.delphix:extensible_dataset", new_txg)?;
        let mut entries = Vec::with_capacity(2 + extra_zap_entries.len());
        if fs_ss_limit_active {
            entries.push(RawZapEntry {
                name: b"com.joyent:filesystem_count".to_vec(),
                integer_bytes: 8,
                values: vec![0],
                collision: 0,
            });
            entries.push(RawZapEntry {
                name: b"com.joyent:snapshot_count".to_vec(),
                integer_bytes: 8,
                values: vec![0],
                collision: 0,
            });
        }
        entries.extend_from_slice(extra_zap_entries);
        write_zap_dnode_in_mos(
            cx,
            mos,
            mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            alloc,
            dd_obj,
            None,
            DMU_OTN_ZAP_METADATA,
            DMU_OT_DSL_DIR,
            dd_bonus,
            &entries,
            0,
            false,
            order,
            new_txg,
            staged_writes,
        )
    } else {
        let dd_dn = Dnode::from_spec(DnodeSpec {
            object_type: DMU_OT_DSL_DIR,
            bonus_type: DMU_OT_DSL_DIR,
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
            bonus: dd_bonus,
            spill: None,
        })
        .map_err(|e| parse_err(&e))?;
        put_dnode_in_table(
            cx,
            mos,
            mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            dd_obj,
            &dd_dn,
        )
    }
}

/// Link a newly created head dataset (`child_head_obj`) as a clone/branch of `origin_snap_obj`
/// (`ds_num_children += 1`, `ds_next_clones_obj` with `DMU_OT_NEXT_CLONES`, and `origin_dd.dd_clones`
/// with `DMU_OT_DSL_CLONES`, matching OpenZFS `dsl_dataset_create_sync_dd`).
#[allow(clippy::too_many_arguments)]
pub(super) fn link_dataset_to_origin_snapshot(
    cx: &Cx,
    mos: &mut Objects,
    mos_meta: &Dnode,
    mos_ceiling: u64,
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    alloc: &mut PoolSpaceAllocator,
    origin_dd_obj: u64,
    origin_snap_obj: u64,
    child_head_obj: u64,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<()> {
    let (o_snap_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        origin_snap_obj,
        order,
    )?;
    let o_num_children = order
        .u64(o_snap_dn.bonus(), 40)
        .map_err(|e| parse_err(&e))?;
    let o_next_clones = order
        .u64(o_snap_dn.bonus(), 256)
        .map_err(|e| parse_err(&e))?;

    let (nc_obj, nc_existing, mut nc_entries) = if o_next_clones == 0 {
        let id = allocate_object_id(cx, mos, mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
        (id, None, Vec::new())
    } else {
        let (dn, c) = mos.object_with_ceiling(cx, o_next_clones)?;
        let rows = mos.zap_values(cx, o_next_clones)?;
        (o_next_clones, Some((dn, c)), rows)
    };
    nc_entries.push(RawZapEntry {
        name: format!("{child_head_obj:x}").into_bytes(),
        integer_bytes: 8,
        values: vec![child_head_obj],
        collision: 0,
    });
    write_zap_dnode_in_mos(
        cx,
        mos,
        mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        alloc,
        nc_obj,
        nc_existing.as_ref().map(|(d, c)| (d, *c)),
        DMU_OT_NEXT_CLONES,
        0,
        Vec::new(),
        &nc_entries,
        0,
        false,
        order,
        new_txg,
        staged_writes,
    )?;
    let mut o_snap_bonus = o_snap_dn.bonus().to_vec();
    o_snap_bonus[40..48].copy_from_slice(&order.encode(o_num_children + 1));
    o_snap_bonus[256..264].copy_from_slice(&order.encode(nc_obj));
    let mut updated_o_snap = o_snap_dn;
    let os_btype = updated_o_snap.bonus_type();
    updated_o_snap
        .set_bonus_and_spill(os_btype, o_snap_bonus, None)
        .map_err(|e| parse_err(&e))?;
    put_dnode_in_table(
        cx,
        mos,
        mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        origin_snap_obj,
        &updated_o_snap,
    )?;

    let (o_dd_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        origin_dd_obj,
        order,
    )?;
    let cur_dd_clones = order.u64(o_dd_dn.bonus(), 144).map_err(|e| parse_err(&e))?;
    let (ddc_obj, ddc_existing, mut ddc_entries) = if cur_dd_clones == 0 {
        let id = allocate_object_id(cx, mos, mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
        (id, None, Vec::new())
    } else {
        let (dn, c) = mos.object_with_ceiling(cx, cur_dd_clones)?;
        let rows = mos.zap_values(cx, cur_dd_clones)?;
        (cur_dd_clones, Some((dn, c)), rows)
    };
    ddc_entries.push(RawZapEntry {
        name: format!("{child_head_obj:x}").into_bytes(),
        integer_bytes: 8,
        values: vec![child_head_obj],
        collision: 0,
    });
    write_zap_dnode_in_mos(
        cx,
        mos,
        mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        alloc,
        ddc_obj,
        ddc_existing.as_ref().map(|(d, c)| (d, *c)),
        DMU_OT_DSL_CLONES,
        0,
        Vec::new(),
        &ddc_entries,
        0,
        false,
        order,
        new_txg,
        staged_writes,
    )?;
    if cur_dd_clones == 0 {
        let mut o_dd_bonus = o_dd_dn.bonus().to_vec();
        o_dd_bonus[144..152].copy_from_slice(&order.encode(ddc_obj));
        let mut updated_o_dd = o_dd_dn;
        let btype = updated_o_dd.bonus_type();
        updated_o_dd
            .set_bonus_and_spill(btype, o_dd_bonus, None)
            .map_err(|e| parse_err(&e))?;
        put_dnode_in_table(
            cx,
            mos,
            mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            origin_dd_obj,
            &updated_o_dd,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn stage_create_dataset(
    cx: &Cx,
    mos: &mut Objects,
    parent_dataset: &[Vec<u8>],
    child_name: &[u8],
    initial_props: &[(String, ZfsPropertySetValue)],
    encryption: Option<&ZfsEncryptionCreateOptions>,
    timestamp: Timestamp,
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    features: &mut MosFeatureState,
    empty_bpobj_id: Option<u64>,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<DslStageResult> {
    validate_dsl_component(child_name, false)?;
    require_filesystem_parent(cx, mos, parent_dataset)?;
    let (parent_dd_obj, parent_head_obj, pool_guid) = resolve_dataset_ids(cx, mos, parent_dataset)?;
    let parent_crypto = mos.dataset_crypto_info(cx, parent_dataset)?;
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

    // Allocate core MOS object IDs upfront so new encryption roots can bind `DSL_CRYPTO_ROOT_DDOBJ`
    // and `com.datto:ivset_guid` before writing the dataset's initial ObjectSet blocks.
    let new_dd_obj = allocate_object_id(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
    let new_head_obj = allocate_object_id(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
    let new_child_zap = allocate_object_id(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
    let new_props_zap = allocate_object_id(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
    let new_snapmap_zap = allocate_object_id(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;

    let ds_guid = derive_unique_guid(pool_guid, new_txg, new_head_obj, 2);
    let ds_fsid = derive_fsid_guid(ds_guid);
    let compression =
        effective_compression_for_new_dataset(cx, mos, parent_dataset, initial_props, features)?;

    // Resolve encryption creation mode:
    // - Explicit `Off`: forbidden under encrypted parent; unencrypted otherwise.
    // - Explicit active suite (`On` / `Aes*`): new encryption root with fresh `dsl_crypto_key`.
    // - `None` or `Inherit`: inherit parent's `dsl_crypto_key` if parent is encrypted.
    let mut crypto_key_obj_for_dir: Option<u64> = None;
    let mut ivset_guid_for_head: Option<u64> = None;
    let mut new_root_key: Option<(u64, UnwrappedDslKey)> = None;
    let mut root_keylocation_prop: Option<Vec<u8>> = None;
    let mut is_new_encryption_root = false;

    let mut write_crypto: Option<DatasetWriteCrypto> = match encryption {
        Some(opts) if opts.suite == ZioEncrypt::Off => {
            if parent_crypto.is_some() {
                return Err(reject_einval(
                    "cannot create unencrypted ZFS dataset under an encrypted parent",
                ));
            }
            None
        }
        Some(opts) if opts.suite.is_active() => {
            if !features.read_features.contains_key("com.datto:encryption")
                || !features
                    .read_features
                    .contains_key("com.delphix:extensible_dataset")
                || !features.read_features.contains_key("com.datto:bookmark_v2")
                || !features
                    .write_features
                    .contains_key("com.delphix:bookmarks")
            {
                return Err(unsupported(
                    "ZFS native encryption requires com.datto:encryption, com.datto:bookmark_v2, com.delphix:bookmarks, and com.delphix:extensible_dataset enabled on pool",
                ));
            }
            let key_material = opts.key_material.as_ref().ok_or_else(|| {
                reject_einval("creating a new ZFS encryption root requires key_material")
            })?;
            let keyformat = key_material.format();
            let crypto_key_obj =
                allocate_object_id(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
            let (pbkdf2_salt, pbkdf2_iters) = if keyformat == ZfsKeyFormat::Passphrase {
                let iters = opts.pbkdf2_iters.unwrap_or(ZFS_PBKDF2_DEFAULT_ITERS);
                if iters < ZFS_PBKDF2_MIN_ITERS {
                    return Err(reject_einval(
                        "ZFS passphrase pbkdf2iters must be at least 100000",
                    ));
                }
                let salt = derive_unique_guid(pool_guid, new_txg, crypto_key_obj, 99);
                (salt, iters)
            } else {
                (0, 0)
            };
            let wrapping =
                key_material.resolve_wrapping_key(keyformat, pbkdf2_salt, pbkdf2_iters)?;
            let (master, hmac, wrap_iv, key_guid) =
                generate_new_dataset_keys(cx, pool_guid, ds_guid, new_txg, &opts.extra_entropy)?;
            let master = Zeroizing::new(master);
            let hmac = Zeroizing::new(hmac);
            let record = DslCryptoKeyRecord::wrap(
                opts.suite.effective(),
                key_guid,
                DSL_CRYPTO_KEY_VERSION_V1,
                new_dd_obj,
                1,
                keyformat,
                pbkdf2_salt,
                pbkdf2_iters,
                wrap_iv,
                wrapping.as_bytes(),
                master.as_slice(),
                &hmac,
            )
            .map_err(|e| parse_err(&e))?;
            let unwrapped = record
                .unwrap(wrapping.as_bytes())
                .map_err(|e| parse_err(&e))?;
            let key_entries = encode_dsl_crypto_key_zap(&record);
            write_zap_dnode_in_mos(
                cx,
                mos,
                &mos_meta,
                mos_ceiling,
                mos_dirty_dnodes,
                alloc,
                crypto_key_obj,
                None,
                DMU_OTN_ZAP_METADATA,
                0,
                Vec::new(),
                &key_entries,
                0,
                true, // Fat-ZAP required for uint8 key/IV/MAC arrays!
                order,
                new_txg,
                staged_writes,
            )?;
            features.increment_read("com.datto:encryption", new_txg)?;
            let ivset_guid = derive_unique_guid(pool_guid, new_txg, new_head_obj, 7);
            let key_arc = Arc::new(unwrapped.clone());
            crypto_key_obj_for_dir = Some(crypto_key_obj);
            ivset_guid_for_head = Some(ivset_guid);
            new_root_key = Some((new_dd_obj, unwrapped));
            is_new_encryption_root = true;
            root_keylocation_prop = Some(
                opts.keylocation
                    .clone()
                    .unwrap_or_else(|| b"prompt".to_vec()),
            );
            Some(DatasetWriteCrypto {
                nonces: ZfsNonceGenerator::new(
                    cx,
                    ivset_guid,
                    key_guid,
                    new_txg,
                    &opts.extra_entropy,
                )?,
                key: key_arc,
            })
        }
        _ => {
            if let Some(ref p_info) = parent_crypto {
                let key = mos
                    .keyring()
                    .get(p_info.encryption_root_ddobj)
                    .ok_or(FfsError::PermissionDenied)?;
                let _ = adjust_dsl_crypto_key_refcount(
                    cx,
                    mos,
                    &mos_meta,
                    mos_ceiling,
                    mos_dirty_dnodes,
                    alloc,
                    p_info.crypto_key_obj,
                    1,
                    order,
                    new_txg,
                    staged_writes,
                )?;
                let ivset_guid = derive_unique_guid(pool_guid, new_txg, new_head_obj, 7);
                crypto_key_obj_for_dir = Some(p_info.crypto_key_obj);
                ivset_guid_for_head = Some(ivset_guid);
                Some(DatasetWriteCrypto {
                    nonces: ZfsNonceGenerator::new(
                        cx,
                        ivset_guid,
                        p_info.record.guid,
                        new_txg,
                        &[],
                    )?,
                    key,
                })
            } else {
                None
            }
        }
    };

    // Build fresh ZPL `ObjectSet` (`new_os_bp`, `os_space`).
    let (new_os_bp, os_space, feature_usage) = build_fresh_zpl_objectset(
        cx,
        mos,
        parent_head_obj,
        parent_crypto.as_ref(),
        compression,
        write_crypto.as_mut(),
        features,
        alloc,
        timestamp,
        order,
        new_txg,
        staged_writes,
    )?;

    // Check parent/ancestor quota headroom before linking.
    enforce_dataset_quotas_for_growth(
        cx,
        mos,
        mos_dirty_dnodes,
        parent_head_obj,
        parent_dd_obj,
        0,
        os_space.dsize,
        order,
    )?;

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
        2, // normflags = 2 (U8_TEXTPREP_TOUPPER)!
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

    let mut head_bonus = vec![0_u8; 320];
    head_bonus[0..8].copy_from_slice(&order.encode(new_dd_obj));
    head_bonus[8..16].copy_from_slice(&order.encode(origin_snap_obj));
    head_bonus[16..24].copy_from_slice(&order.encode(origin_creation_txg));
    head_bonus[32..40].copy_from_slice(&order.encode(new_snapmap_zap));
    head_bonus[48..56].copy_from_slice(&order.encode(timestamp.seconds.cast_unsigned()));
    head_bonus[56..64].copy_from_slice(&order.encode(new_txg));
    head_bonus[64..72].copy_from_slice(&order.encode(new_deadlist_obj));
    head_bonus[72..80].copy_from_slice(&order.encode(os_space.dsize));
    head_bonus[80..88].copy_from_slice(&order.encode(os_space.comp));
    head_bonus[88..96].copy_from_slice(&order.encode(os_space.uncomp));
    head_bonus[96..104].copy_from_slice(&order.encode(os_space.dsize));
    head_bonus[104..112].copy_from_slice(&order.encode(ds_fsid));
    head_bonus[112..120].copy_from_slice(&order.encode(ds_guid));
    head_bonus[120..128].copy_from_slice(&order.encode(inherited_flags | DS_FLAG_UNIQUE_ACCURATE));
    head_bonus[128..256].copy_from_slice(&new_os_bp.encode(order));

    let mut head_zap = Vec::new();
    activate_dataset_block_features(
        &mut head_zap,
        &feature_usage.required_features(),
        features,
        new_txg,
    )?;
    activate_initial_compression_feature(&mut head_zap, initial_props, features, new_txg)?;
    if let Some(ivset_guid) = ivset_guid_for_head {
        head_zap.push(RawZapEntry {
            name: DSL_DATASET_IVSET_GUID.to_vec(),
            integer_bytes: 8,
            values: vec![ivset_guid],
            collision: 0,
        });
    }
    if head_zap.is_empty() {
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
    } else {
        features.increment_read("com.delphix:extensible_dataset", new_txg)?;
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
            &head_zap,
            0,
            false,
            order,
            new_txg,
            staged_writes,
        )?;
    }

    let mut dd_bonus = vec![0_u8; 256];
    dd_bonus[0..8].copy_from_slice(&order.encode(timestamp.seconds.cast_unsigned()));
    dd_bonus[8..16].copy_from_slice(&order.encode(new_head_obj));
    dd_bonus[16..24].copy_from_slice(&order.encode(parent_dd_obj));
    dd_bonus[24..32].copy_from_slice(&order.encode(origin_snap_obj));
    dd_bonus[32..40].copy_from_slice(&order.encode(new_child_zap));
    dd_bonus[40..48].copy_from_slice(&order.encode(os_space.dsize));
    dd_bonus[48..56].copy_from_slice(&order.encode(os_space.comp));
    dd_bonus[56..64].copy_from_slice(&order.encode(os_space.uncomp));
    dd_bonus[80..88].copy_from_slice(&order.encode(new_props_zap));
    dd_bonus[96..104].copy_from_slice(&order.encode(DD_FLAG_USED_BREAKDOWN));
    dd_bonus[104..112].copy_from_slice(&order.encode(os_space.dsize)); // DD_USED_HEAD

    let mut dd_extra_zap = Vec::new();
    if let Some(ck_obj) = crypto_key_obj_for_dir {
        dd_extra_zap.push(RawZapEntry {
            name: DSL_DIR_CRYPTO_KEY_OBJ.to_vec(),
            integer_bytes: 8,
            values: vec![ck_obj],
            collision: 0,
        });
    }
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
        &dd_extra_zap,
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

    // Link into `parent_dd.dd_child_dir_zapobj` and propagate `os_space` up `parent_dd_obj`!
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
        i128::from(os_space.dsize),
        0,
        0,
        i128::from(os_space.comp),
        i128::from(os_space.uncomp),
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

    let mut effective_props = initial_props.to_vec();
    if let Some(loc) = root_keylocation_prop
        && !effective_props.iter().any(|(k, _)| k == "keylocation")
    {
        effective_props.push(("keylocation".to_owned(), ZfsPropertySetValue::Text(loc)));
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
        false,
        is_new_encryption_root,
        &prop_updates,
        mos_dirty_dnodes,
        features,
        alloc,
        order,
        new_txg,
        staged_writes,
    )?;

    Ok(DslStageResult {
        value: new_head_obj,
        new_root_key,
    })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn stage_create_clone(
    cx: &Cx,
    mos: &mut Objects,
    origin_dataset: &[Vec<u8>],
    origin_snap: &[u8],
    target_parent: &[Vec<u8>],
    target_name: &[u8],
    initial_props: &[(String, ZfsPropertySetValue)],
    timestamp: Timestamp,
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    features: &mut MosFeatureState,
    empty_bpobj_id: Option<u64>,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<u64> {
    validate_dsl_component(origin_snap, true)?;
    validate_dsl_component(target_name, false)?;
    require_filesystem_parent(cx, mos, target_parent)?;
    let origin_is_zvol = mos
        .datasets(cx)?
        .into_iter()
        .find(|d| d.components == origin_dataset)
        .is_some_and(|d| d.objectset_kind == Some(3));
    let (origin_dd_obj, origin_head_obj, pool_guid) = resolve_dataset_ids(cx, mos, origin_dataset)?;
    let (target_parent_dd, _, _) = resolve_dataset_ids(cx, mos, target_parent)?;
    let mos_meta = mos.meta_dnode().clone();
    let mos_ceiling = mos.root_birth_txg();

    let (o_head_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        origin_head_obj,
        order,
    )?;
    let o_snapmap = order
        .u64(o_head_dn.bonus(), 32)
        .map_err(|e| parse_err(&e))?;
    let o_snaps = mos.zap_values_with_names(cx, o_snapmap, ZapNamePolicy::AsciiUppercase)?;
    let origin_snap_obj = o_snaps
        .iter()
        .find(|e| e.name == origin_snap)
        .ok_or_else(|| FfsError::NotFound("ZFS origin snapshot".into()))?
        .scalar()
        .map_err(|e| parse_err(&e))?;

    let (o_snap_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        origin_snap_obj,
        order,
    )?;
    let o_snap_flags = order
        .u64(o_snap_dn.bonus(), 120)
        .map_err(|e| parse_err(&e))?;
    if o_snap_flags & DS_FLAG_DEFER_DESTROY != 0 {
        return Err(reject_busy(
            "cannot clone snapshot marked for deferred destroy",
        ));
    }
    let o_prev_txg = order
        .u64(o_snap_dn.bonus(), 16)
        .map_err(|e| parse_err(&e))?;
    let o_creation_txg = order
        .u64(o_snap_dn.bonus(), 56)
        .map_err(|e| parse_err(&e))?;
    let o_ref_bytes = order
        .u64(o_snap_dn.bonus(), 72)
        .map_err(|e| parse_err(&e))?;
    let o_comp_bytes = order
        .u64(o_snap_dn.bonus(), 80)
        .map_err(|e| parse_err(&e))?;
    let o_uncomp_bytes = order
        .u64(o_snap_dn.bonus(), 88)
        .map_err(|e| parse_err(&e))?;

    let (tp_dd_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        target_parent_dd,
        order,
    )?;
    let tp_child_zap = order.u64(tp_dd_dn.bonus(), 32).map_err(|e| parse_err(&e))?;
    let mut tp_children = mos.zap_values(cx, tp_child_zap)?;
    if tp_children.iter().any(|e| e.name == target_name) {
        return Err(FfsError::Exists);
    }

    let clone_dd_obj = allocate_object_id(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
    let clone_head_obj = allocate_object_id(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
    let clone_child_zap = allocate_object_id(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
    let clone_props_zap = allocate_object_id(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
    let clone_snapmap = allocate_object_id(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;

    write_zap_dnode_in_mos(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        alloc,
        clone_child_zap,
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
        clone_snapmap,
        None,
        DMU_OT_DSL_DS_SNAP_MAP,
        0,
        Vec::new(),
        &[],
        2,
        false,
        order,
        new_txg,
        staged_writes,
    )?;

    let mut dl_keys = BTreeSet::new();
    dl_keys.insert(0);
    dl_keys.insert(o_prev_txg);
    let clone_deadlist_obj = allocate_fresh_deadlist(
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

    let clone_guid = derive_unique_guid(pool_guid, new_txg, clone_head_obj, 3);
    let clone_fsid = derive_fsid_guid(clone_guid);
    let mut head_bonus = vec![0_u8; 320];
    head_bonus[0..8].copy_from_slice(&order.encode(clone_dd_obj));
    head_bonus[8..16].copy_from_slice(&order.encode(origin_snap_obj));
    head_bonus[16..24].copy_from_slice(&order.encode(o_creation_txg));
    head_bonus[32..40].copy_from_slice(&order.encode(clone_snapmap));
    head_bonus[48..56].copy_from_slice(&order.encode(timestamp.seconds.cast_unsigned()));
    head_bonus[56..64].copy_from_slice(&order.encode(new_txg));
    head_bonus[64..72].copy_from_slice(&order.encode(clone_deadlist_obj));
    head_bonus[72..80].copy_from_slice(&order.encode(o_ref_bytes));
    head_bonus[80..88].copy_from_slice(&order.encode(o_comp_bytes));
    head_bonus[88..96].copy_from_slice(&order.encode(o_uncomp_bytes));
    head_bonus[96..104].copy_from_slice(&order.encode(0)); // ds_unique_bytes = 0!
    head_bonus[104..112].copy_from_slice(&order.encode(clone_fsid));
    head_bonus[112..120].copy_from_slice(&order.encode(clone_guid));
    head_bonus[120..128]
        .copy_from_slice(&order.encode((o_snap_flags & 0x1_0006) | DS_FLAG_UNIQUE_ACCURATE));
    head_bonus[128..256].copy_from_slice(&o_snap_dn.bonus()[128..256]); // zero-copy ObjectSet BP!

    let origin_crypto = mos.dataset_crypto_info(cx, origin_dataset)?;
    let origin_features = dataset_feature_entries(cx, mos, origin_snap_obj, &o_snap_dn, features)?;
    let mut clone_head_zap = Vec::new();
    for feature in dataset_block_feature_owners(&origin_features, features)? {
        features.increment_read(feature, new_txg)?;
        clone_head_zap.push(RawZapEntry {
            name: feature.as_bytes().to_vec(),
            integer_bytes: 8,
            values: vec![0],
            collision: 0,
        });
    }
    let mut clone_dd_extra_zap = Vec::new();
    activate_initial_compression_feature(&mut clone_head_zap, initial_props, features, new_txg)?;
    if let Some(ref o_info) = origin_crypto {
        let _ = adjust_dsl_crypto_key_refcount(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            alloc,
            o_info.crypto_key_obj,
            1,
            order,
            new_txg,
            staged_writes,
        )?;
        let clone_ivset_guid = derive_unique_guid(pool_guid, new_txg, clone_head_obj, 13);
        clone_head_zap.push(RawZapEntry {
            name: DSL_DATASET_IVSET_GUID.to_vec(),
            integer_bytes: 8,
            values: vec![clone_ivset_guid],
            collision: 0,
        });
        clone_dd_extra_zap.push(RawZapEntry {
            name: DSL_DIR_CRYPTO_KEY_OBJ.to_vec(),
            integer_bytes: 8,
            values: vec![o_info.crypto_key_obj],
            collision: 0,
        });
    }
    if clone_head_zap.is_empty() {
        let clone_head_dn = Dnode::from_spec(DnodeSpec {
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
            clone_head_obj,
            &clone_head_dn,
        )?;
    } else {
        features.increment_read("com.delphix:extensible_dataset", new_txg)?;
        write_zap_dnode_in_mos(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            alloc,
            clone_head_obj,
            None,
            DMU_OTN_ZAP_METADATA,
            DMU_OT_DSL_DATASET,
            head_bonus,
            &clone_head_zap,
            0,
            false,
            order,
            new_txg,
            staged_writes,
        )?;
    }

    let mut dd_bonus = vec![0_u8; 256];
    dd_bonus[0..8].copy_from_slice(&order.encode(timestamp.seconds.cast_unsigned()));
    dd_bonus[8..16].copy_from_slice(&order.encode(clone_head_obj));
    dd_bonus[16..24].copy_from_slice(&order.encode(target_parent_dd));
    dd_bonus[24..32].copy_from_slice(&order.encode(origin_snap_obj)); // dd_origin_obj!
    dd_bonus[32..40].copy_from_slice(&order.encode(clone_child_zap));
    dd_bonus[80..88].copy_from_slice(&order.encode(clone_props_zap));
    dd_bonus[96..104].copy_from_slice(&order.encode(DD_FLAG_USED_BREAKDOWN));

    put_new_dsl_dir_in_mos(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        features,
        alloc,
        clone_dd_obj,
        dd_bonus,
        &clone_dd_extra_zap,
        order,
        new_txg,
        staged_writes,
    )?;

    link_dataset_to_origin_snapshot(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        alloc,
        origin_dd_obj,
        origin_snap_obj,
        clone_head_obj,
        order,
        new_txg,
        staged_writes,
    )?;

    // Link into `target_parent.dd_child_dir_zapobj`.
    let (tp_cz_dn, tp_cz_ceil) = mos.object_with_ceiling(cx, tp_child_zap)?;
    tp_children.push(RawZapEntry {
        name: target_name.to_vec(),
        integer_bytes: 8,
        values: vec![clone_dd_obj],
        collision: 0,
    });
    write_zap_dnode_in_mos(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        alloc,
        tp_child_zap,
        Some((&tp_cz_dn, tp_cz_ceil)),
        tp_cz_dn.object_type(),
        tp_cz_dn.bonus_type(),
        tp_cz_dn.bonus().to_vec(),
        &tp_children,
        0,
        false,
        order,
        new_txg,
        staged_writes,
    )?;
    bump_filesystem_limits_counter_if_present(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        alloc,
        target_parent_dd,
        b"com.joyent:filesystem_count",
        1,
        order,
        new_txg,
        staged_writes,
    )?;

    let prop_updates: Vec<(&str, Option<&ZfsPropertySetValue>)> = initial_props
        .iter()
        .map(|(k, v)| (k.as_str(), Some(v)))
        .collect();
    apply_properties_batch_on_ids(
        cx,
        mos,
        clone_dd_obj,
        clone_head_obj,
        clone_props_zap,
        None,
        origin_is_zvol,
        false,
        &prop_updates,
        mos_dirty_dnodes,
        features,
        alloc,
        order,
        new_txg,
        staged_writes,
    )?;

    Ok(clone_head_obj)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn stage_rename_dataset(
    cx: &Cx,
    mos: &mut Objects,
    old_dataset: &[Vec<u8>],
    new_dataset: &[Vec<u8>],
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<u64> {
    if old_dataset.is_empty() || new_dataset.is_empty() {
        return Err(reject_einval("cannot rename ZFS pool root dataset"));
    }
    let old_leaf = old_dataset.last().expect("nonempty");
    let new_leaf = new_dataset.last().expect("nonempty");
    validate_dsl_component(new_leaf, false)?;
    require_filesystem_parent(cx, mos, &new_dataset[..new_dataset.len() - 1])?;

    let (target_dd_obj, target_head_obj, _) = resolve_dataset_ids(cx, mos, old_dataset)?;
    let (old_parent_dd, _, _) =
        resolve_dataset_ids(cx, mos, &old_dataset[..old_dataset.len() - 1])?;
    let (new_parent_dd, new_parent_head, _) =
        resolve_dataset_ids(cx, mos, &new_dataset[..new_dataset.len() - 1])?;
    if old_dataset == new_dataset {
        return Ok(target_head_obj);
    }
    if old_parent_dd != new_parent_dd
        && let Some(target_crypto) = mos.dataset_crypto_info(cx, old_dataset)?
        && target_crypto.encryption_root_ddobj != target_dd_obj
    {
        let new_parent_crypto =
            mos.dataset_crypto_info(cx, &new_dataset[..new_dataset.len() - 1])?;
        if new_parent_crypto.as_ref().map(|c| c.encryption_root_ddobj)
            != Some(target_crypto.encryption_root_ddobj)
        {
            return Err(reject_einval(
                "cannot move encrypted non-root ZFS dataset outside its encryption root",
            ));
        }
    }

    let mos_meta = mos.meta_dnode().clone();
    let mos_ceiling = mos.root_birth_txg();

    // Cycle check: `target_dd_obj` MUST NOT appear in `new_parent_dd` ancestry!
    let mut check_dir = new_parent_dd;
    let mut seen = BTreeSet::new();
    while check_dir != 0 {
        if check_dir == target_dd_obj {
            return Err(reject_einval(
                "cannot rename ZFS dataset into its own descendant",
            ));
        }
        if !seen.insert(check_dir) {
            return Err(corrupt("cycle in DSL directory ancestry"));
        }
        let (dn, _) = read_staged_or_committed_dnode(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            check_dir,
            order,
        )?;
        check_dir = order.u64(dn.bonus(), 16).map_err(|e| parse_err(&e))?;
    }

    if old_parent_dd == new_parent_dd {
        let (p_dn, _) = read_staged_or_committed_dnode(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            old_parent_dd,
            order,
        )?;
        let cz = order.u64(p_dn.bonus(), 32).map_err(|e| parse_err(&e))?;
        let (cz_dn, cz_ceil) = mos.object_with_ceiling(cx, cz)?;
        let mut entries = mos.zap_values(cx, cz)?;
        if entries.iter().any(|e| &e.name == new_leaf) {
            return Err(FfsError::Exists);
        }
        let pos = entries
            .iter()
            .position(|e| &e.name == old_leaf)
            .ok_or_else(|| corrupt("missing child entry in parent dsl_dir"))?;
        entries[pos].name.clone_from(new_leaf);
        write_zap_dnode_in_mos(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            alloc,
            cz,
            Some((&cz_dn, cz_ceil)),
            cz_dn.object_type(),
            cz_dn.bonus_type(),
            cz_dn.bonus().to_vec(),
            &entries,
            0,
            false,
            order,
            new_txg,
            staged_writes,
        )?;
        return Ok(target_head_obj);
    }

    // Cross-parent rename!
    let (np_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        new_parent_dd,
        order,
    )?;
    let np_cz = order.u64(np_dn.bonus(), 32).map_err(|e| parse_err(&e))?;
    let mut np_entries = mos.zap_values(cx, np_cz)?;
    if np_entries.iter().any(|e| &e.name == new_leaf) {
        return Err(FfsError::Exists);
    }

    let (t_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        target_dd_obj,
        order,
    )?;
    let t_used = order.u64(t_dn.bonus(), 40).map_err(|e| parse_err(&e))?;
    let t_comp = order.u64(t_dn.bonus(), 48).map_err(|e| parse_err(&e))?;
    let t_uncomp = order.u64(t_dn.bonus(), 56).map_err(|e| parse_err(&e))?;
    let t_reserved = order.u64(t_dn.bonus(), 72).map_err(|e| parse_err(&e))?;
    let t_rsrv_excess = t_reserved.saturating_sub(t_used);
    let transfer_charge = t_used.saturating_add(t_rsrv_excess);

    //Subtract from old_parent first so common ancestors above LCA aren't double-counted during quota check!
    propagate_dsl_dir_space_delta(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        old_parent_dd,
        0,
        0,
        -i128::from(t_used),
        -i128::from(t_rsrv_excess),
        0,
        -i128::from(t_comp),
        -i128::from(t_uncomp),
        order,
    )?;
    enforce_dataset_quotas_for_growth(
        cx,
        mos,
        mos_dirty_dnodes,
        new_parent_head,
        new_parent_dd,
        0,
        transfer_charge,
        order,
    )?;
    propagate_dsl_dir_space_delta(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        new_parent_dd,
        0,
        0,
        i128::from(t_used),
        i128::from(t_rsrv_excess),
        0,
        i128::from(t_comp),
        i128::from(t_uncomp),
        order,
    )?;

    // Update `old_parent` child map, `new_parent` child map, and `target_dd.dd_parent_obj`.
    let (op_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        old_parent_dd,
        order,
    )?;
    let op_cz = order.u64(op_dn.bonus(), 32).map_err(|e| parse_err(&e))?;
    let (op_cz_dn, op_cz_ceil) = mos.object_with_ceiling(cx, op_cz)?;
    let mut op_entries = mos.zap_values(cx, op_cz)?;
    op_entries.retain(|e| &e.name != old_leaf);
    write_zap_dnode_in_mos(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        alloc,
        op_cz,
        Some((&op_cz_dn, op_cz_ceil)),
        op_cz_dn.object_type(),
        op_cz_dn.bonus_type(),
        op_dn.bonus()[..0].to_vec(),
        &op_entries,
        0,
        false,
        order,
        new_txg,
        staged_writes,
    )?;

    let (np_cz_dn, np_cz_ceil) = mos.object_with_ceiling(cx, np_cz)?;
    np_entries.push(RawZapEntry {
        name: new_leaf.clone(),
        integer_bytes: 8,
        values: vec![target_dd_obj],
        collision: 0,
    });
    write_zap_dnode_in_mos(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        alloc,
        np_cz,
        Some((&np_cz_dn, np_cz_ceil)),
        np_cz_dn.object_type(),
        np_cz_dn.bonus_type(),
        Vec::new(),
        &np_entries,
        0,
        false,
        order,
        new_txg,
        staged_writes,
    )?;

    let (t_cur, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        target_dd_obj,
        order,
    )?;
    let t_entries = if t_cur.object_type() == DMU_OTN_ZAP_METADATA {
        mos.zap_values(cx, target_dd_obj)?
    } else {
        Vec::new()
    };
    let moved_counts = (
        zap_optional_u64(&t_entries, b"com.joyent:filesystem_count")?,
        zap_optional_u64(&t_entries, b"com.joyent:snapshot_count")?,
    );
    let (moved_filesystems, moved_snapshots) = match moved_counts {
        (Some(filesystems), Some(snapshots)) => {
            (i128::from(filesystems) + 1, i128::from(snapshots))
        }
        (None, None) => {
            for parent in [old_parent_dd, new_parent_dd] {
                let parent_dn = mos.object(cx, parent)?;
                if parent_dn.object_type() == DMU_OTN_ZAP_METADATA {
                    let rows = mos.zap_values(cx, parent)?;
                    if zap_optional_u64(&rows, b"com.joyent:filesystem_count")?.is_some()
                        || zap_optional_u64(&rows, b"com.joyent:snapshot_count")?.is_some()
                    {
                        return Err(unsupported(
                            "moving an untracked subtree requires native counter initialization",
                        ));
                    }
                }
            }
            (1, 0)
        }
        _ => return Err(corrupt("partially initialized moved dataset counters")),
    };
    let mut t_bonus = t_cur.bonus().to_vec();
    t_bonus[16..24].copy_from_slice(&order.encode(new_parent_dd));
    let mut updated_t = t_cur;
    let btype = updated_t.bonus_type();
    updated_t
        .set_bonus_and_spill(btype, t_bonus, None)
        .map_err(|e| parse_err(&e))?;
    put_dnode_in_table(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        target_dd_obj,
        &updated_t,
    )?;

    adjust_filesystem_limits_counters(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        alloc,
        &[
            (old_parent_dd, [-moved_filesystems, -moved_snapshots]),
            (new_parent_dd, [moved_filesystems, moved_snapshots]),
        ],
        true,
        order,
        new_txg,
        staged_writes,
    )?;
    Ok(target_head_obj)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn stage_destroy_dataset(
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
    if dataset.is_empty() {
        return Err(reject_einval("cannot destroy ZFS pool root dataset"));
    }
    let leaf_name = dataset.last().expect("nonempty");
    let (dd_obj, head_obj, _) = resolve_dataset_ids(cx, mos, dataset)?;
    let dataset_crypto = mos.dataset_crypto_info(cx, dataset)?;
    stage_destroy_dataset_by_ids(
        cx,
        mos,
        dd_obj,
        head_obj,
        leaf_name,
        dataset_crypto.as_ref(),
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
pub(super) fn stage_destroy_dataset_by_ids(
    cx: &Cx,
    mos: &mut Objects,
    dd_obj: u64,
    head_obj: u64,
    leaf_name: &[u8],
    dataset_crypto: Option<&ZfsDatasetCryptoInfo>,
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    features: &mut MosFeatureState,
    empty_bpobj_id: Option<u64>,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<u64> {
    let mos_meta = mos.meta_dnode().clone();
    let mos_ceiling = mos.root_birth_txg();

    let (dd_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        dd_obj,
        order,
    )?;
    let parent_dd_obj = order.u64(dd_dn.bonus(), 16).map_err(|e| parse_err(&e))?;
    let origin_obj = order.u64(dd_dn.bonus(), 24).map_err(|e| parse_err(&e))?;
    let child_zap = order.u64(dd_dn.bonus(), 32).map_err(|e| parse_err(&e))?;
    let dd_used = order.u64(dd_dn.bonus(), 40).map_err(|e| parse_err(&e))?;
    let dd_comp = order.u64(dd_dn.bonus(), 48).map_err(|e| parse_err(&e))?;
    let dd_uncomp = order.u64(dd_dn.bonus(), 56).map_err(|e| parse_err(&e))?;
    let dd_reserved = order.u64(dd_dn.bonus(), 72).map_err(|e| parse_err(&e))?;
    let props_zap = order.u64(dd_dn.bonus(), 80).map_err(|e| parse_err(&e))?;
    let dd_clones = order.u64(dd_dn.bonus(), 144).map_err(|e| parse_err(&e))?;

    if child_zap != 0 && !mos.zap_values(cx, child_zap)?.is_empty() {
        return Err(reject_busy("ZFS dataset has child datasets"));
    }
    if dd_clones != 0 && !mos.zap_values(cx, dd_clones)?.is_empty() {
        return Err(reject_busy("ZFS dataset has dependent clones"));
    }

    let (head_dn, head_ceil) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        head_obj,
        order,
    )?;
    let prev_snap_txg = order.u64(head_dn.bonus(), 16).map_err(|e| parse_err(&e))?;
    let snapmap_obj = order.u64(head_dn.bonus(), 32).map_err(|e| parse_err(&e))?;
    let deadlist_obj = order.u64(head_dn.bonus(), 64).map_err(|e| parse_err(&e))?;
    if snapmap_obj != 0
        && !mos
            .zap_values_with_names(cx, snapmap_obj, ZapNamePolicy::AsciiUppercase)?
            .is_empty()
    {
        return Err(reject_busy("ZFS dataset has snapshots"));
    }

    if let Some(c_info) = dataset_crypto
        && c_info.encryption_root_ddobj == dd_obj
        && c_info.record.refcount > 1
    {
        return Err(reject_busy(
            "cannot destroy ZFS encryption root while dependent datasets or clones share its key",
        ));
    }

    // 1. Free ONLY blocks in `head.ds_bp` born strictly after `origin_txg`, plus any
    // unclaimed head-owned ZIL tail block (`zh_log`) not inherited from an origin/snapshot!
    let origin_txg = if origin_obj == 0 { 0 } else { prev_snap_txg };
    let head_bp =
        BlockPointer::parse(&head_dn.bonus()[128..256], order).map_err(|e| parse_err(&e))?;
    if !head_bp.hole() {
        let (os_raw, os_order, _) =
            mos.read_dataset_objset_block_raw(cx, &head_bp, head_ceil, None, true)?;
        let os = ObjectSet::parse(&os_raw, os_order).map_err(|e| parse_err(&e))?;
        if let Some((zil_bp, zil_dvas)) = crate::reader::dmu::zil::parse_unclaimed_head_zil_dvas(
            &os_raw[512..704],
            os_order,
            head_obj,
            mos.root_birth_txg(),
        )? && !mos.is_inherited_snapshot_zil(cx, &head_dn, &head_bp, &os_raw, os_order, &os)?
            && zil_bp.birth() > origin_txg
        {
            alloc.free_raw_dvas(&zil_dvas, zil_bp.birth(), new_txg)?;
        }
    }
    let (_, had_projectused) = walk_objectset_above_txg(
        cx,
        mos,
        &head_bp,
        head_ceil,
        dataset_crypto,
        origin_txg,
        ObjectSetWalkMode::FreeToAllocator,
        alloc,
        new_txg,
    )?;
    if had_projectused
        && features
            .write_features
            .get("org.zfsonlinux:project_quota")
            .copied()
            .unwrap_or(0)
            > 0
    {
        features.decrement_write("org.zfsonlinux:project_quota")?;
    }

    // 2. Free deadlist container objects ONLY (any ZPL blocks in a snapshotless clone's
    // deadlist have `birth <= origin_txg` and remain owned by `origin_obj`!).
    free_deadlist_containers(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        features,
        alloc,
        deadlist_obj,
        empty_bpobj_id,
        order,
        new_txg,
    )?;

    // 3. Free any extensible dataset ZAP objects (`com.delphix:bookmarks`) on `head_dn`.
    if head_dn.object_type() == DMU_OTN_ZAP_METADATA {
        let head_entries = dataset_feature_entries(cx, mos, head_obj, &head_dn, features)?;
        if let Some(bm_obj) =
            zap_optional_u64(&head_entries, b"com.delphix:bookmarks")?.filter(|&id| id != 0)
        {
            features.decrement_write("com.delphix:bookmarks")?;
            free_mos_object_completely(
                cx,
                mos,
                &mos_meta,
                mos_ceiling,
                mos_dirty_dnodes,
                alloc,
                bm_obj,
                order,
                new_txg,
            )?;
        }
        release_dataset_block_features(&head_entries, features)?;
        features.decrement_read(EXTENSIBLE_DATASET_FEATURE)?;
    }

    // 4. Unlink from `parent_dd.dd_child_dir_zapobj` and subtract space from `parent_dd` chain.
    let (p_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        parent_dd_obj,
        order,
    )?;
    let p_cz = order.u64(p_dn.bonus(), 32).map_err(|e| parse_err(&e))?;
    let (p_cz_dn, p_cz_ceil) = mos.object_with_ceiling(cx, p_cz)?;
    let mut p_entries = mos.zap_values(cx, p_cz)?;
    p_entries.retain(|e| e.name != leaf_name);
    write_zap_dnode_in_mos(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        alloc,
        p_cz,
        Some((&p_cz_dn, p_cz_ceil)),
        p_cz_dn.object_type(),
        p_cz_dn.bonus_type(),
        Vec::new(),
        &p_entries,
        0,
        false,
        order,
        new_txg,
        staged_writes,
    )?;

    let rsrv_excess = dd_reserved.saturating_sub(dd_used);
    propagate_dsl_dir_space_delta(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        parent_dd_obj,
        0,
        0,
        -i128::from(dd_used),
        -i128::from(rsrv_excess),
        0,
        -i128::from(dd_comp),
        -i128::from(dd_uncomp),
        order,
    )?;
    // 5. Free MOS objects of this dataset (`snapmap_obj`, `child_zap`, `props_zap`, `dd_clones`, `head_obj`, `dd_obj`).
    if dd_dn.object_type() == DMU_OTN_ZAP_METADATA
        && features
            .read_features
            .get("com.delphix:extensible_dataset")
            .copied()
            .unwrap_or(0)
            > 0
    {
        features.decrement_read("com.delphix:extensible_dataset")?;
    }
    for mos_id in [
        snapmap_obj,
        child_zap,
        props_zap,
        dd_clones,
        head_obj,
        dd_obj,
    ] {
        if mos_id != 0 {
            free_mos_object_completely(
                cx,
                mos,
                &mos_meta,
                mos_ceiling,
                mos_dirty_dnodes,
                alloc,
                mos_id,
                order,
                new_txg,
            )?;
        }
    }

    // 5b. Decrement `DSL_CRYPTO_REFCOUNT` (or free `dsl_crypto_key` + decrement `com.datto:encryption` at 0).
    if let Some(c_info) = dataset_crypto {
        let remaining = adjust_dsl_crypto_key_refcount(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            alloc,
            c_info.crypto_key_obj,
            -1,
            order,
            new_txg,
            staged_writes,
        )?;
        if remaining == 0 {
            free_mos_object_completely(
                cx,
                mos,
                &mos_meta,
                mos_ceiling,
                mos_dirty_dnodes,
                alloc,
                c_info.crypto_key_obj,
                order,
                new_txg,
            )?;
            if features
                .read_features
                .get("com.datto:encryption")
                .copied()
                .unwrap_or(0)
                > 0
            {
                features.decrement_read("com.datto:encryption")?;
            }
        }
    }

    // 6. If this was a clone (`origin_obj != 0`), unlink from `origin_snap` + `origin_dd.dd_clones`,
    // and auto-destroy `origin_snap` if `DS_FLAG_DEFER_DESTROY` was waiting on this last clone!
    // Combine filesystem and snapshot decrements before rewriting a shared
    // ancestor's counter ZAP; both destructions belong to this same TXG.
    let mut filesystem_count_adjusted = false;
    if origin_obj != 0 {
        let (o_snap_dn, _) = read_staged_or_committed_dnode(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            origin_obj,
            order,
        )?;
        let o_dd_obj = order.u64(o_snap_dn.bonus(), 0).map_err(|e| parse_err(&e))?;
        let o_children = order
            .u64(o_snap_dn.bonus(), 40)
            .map_err(|e| parse_err(&e))?;
        let o_flags = order
            .u64(o_snap_dn.bonus(), 120)
            .map_err(|e| parse_err(&e))?;
        let o_nc_obj = order
            .u64(o_snap_dn.bonus(), 256)
            .map_err(|e| parse_err(&e))?;
        let o_ur_obj = order
            .u64(o_snap_dn.bonus(), 272)
            .map_err(|e| parse_err(&e))?;

        let new_o_children = o_children
            .checked_sub(1)
            .ok_or_else(|| corrupt("origin ds_num_children underflow"))?;
        let mut new_nc_obj = o_nc_obj;
        if o_nc_obj != 0 {
            let (nc_dn, nc_ceil) = mos.object_with_ceiling(cx, o_nc_obj)?;
            let mut nc_entries = mos.zap_values(cx, o_nc_obj)?;
            let key = format!("{head_obj:x}").into_bytes();
            nc_entries.retain(|e| e.name != key);
            if nc_entries.is_empty() {
                free_mos_object_completely(
                    cx,
                    mos,
                    &mos_meta,
                    mos_ceiling,
                    mos_dirty_dnodes,
                    alloc,
                    o_nc_obj,
                    order,
                    new_txg,
                )?;
                new_nc_obj = 0;
            } else {
                write_zap_dnode_in_mos(
                    cx,
                    mos,
                    &mos_meta,
                    mos_ceiling,
                    mos_dirty_dnodes,
                    alloc,
                    o_nc_obj,
                    Some((&nc_dn, nc_ceil)),
                    nc_dn.object_type(),
                    nc_dn.bonus_type(),
                    Vec::new(),
                    &nc_entries,
                    0,
                    false,
                    order,
                    new_txg,
                    staged_writes,
                )?;
            }
        }
        let mut o_snap_bonus = o_snap_dn.bonus().to_vec();
        o_snap_bonus[40..48].copy_from_slice(&order.encode(new_o_children));
        o_snap_bonus[256..264].copy_from_slice(&order.encode(new_nc_obj));
        let mut updated_o_snap = o_snap_dn;
        let os_btype = updated_o_snap.bonus_type();
        updated_o_snap
            .set_bonus_and_spill(os_btype, o_snap_bonus, None)
            .map_err(|e| parse_err(&e))?;
        put_dnode_in_table(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            origin_obj,
            &updated_o_snap,
        )?;

        // Update `origin_dd.dd_clones`.
        let (o_dd_dn, _) = read_staged_or_committed_dnode(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            o_dd_obj,
            order,
        )?;
        let o_dd_head = order.u64(o_dd_dn.bonus(), 8).map_err(|e| parse_err(&e))?;
        let o_dd_clones = order.u64(o_dd_dn.bonus(), 144).map_err(|e| parse_err(&e))?;
        if o_dd_clones != 0 {
            let (clones_zap_dn, clones_zap_ceil) = mos.object_with_ceiling(cx, o_dd_clones)?;
            let mut ddc_entries = mos.zap_values(cx, o_dd_clones)?;
            let key = format!("{head_obj:x}").into_bytes();
            ddc_entries.retain(|e| e.name != key);
            if ddc_entries.is_empty() {
                free_mos_object_completely(
                    cx,
                    mos,
                    &mos_meta,
                    mos_ceiling,
                    mos_dirty_dnodes,
                    alloc,
                    o_dd_clones,
                    order,
                    new_txg,
                )?;
                let mut o_dd_bonus = o_dd_dn.bonus().to_vec();
                o_dd_bonus[144..152].copy_from_slice(&order.encode(0));
                let mut updated_o_dd = o_dd_dn;
                let btype = updated_o_dd.bonus_type();
                updated_o_dd
                    .set_bonus_and_spill(btype, o_dd_bonus, None)
                    .map_err(|e| parse_err(&e))?;
                put_dnode_in_table(
                    cx,
                    mos,
                    &mos_meta,
                    mos_ceiling,
                    mos_dirty_dnodes,
                    o_dd_obj,
                    &updated_o_dd,
                )?;
            } else {
                write_zap_dnode_in_mos(
                    cx,
                    mos,
                    &mos_meta,
                    mos_ceiling,
                    mos_dirty_dnodes,
                    alloc,
                    o_dd_clones,
                    Some((&clones_zap_dn, clones_zap_ceil)),
                    clones_zap_dn.object_type(),
                    clones_zap_dn.bonus_type(),
                    Vec::new(),
                    &ddc_entries,
                    0,
                    false,
                    order,
                    new_txg,
                    staged_writes,
                )?;
            }
        }

        let pool_origin_snap =
            lookup_pool_origin_snapshot(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, order)?
                .map(|(_, _, snap_id)| snap_id);
        let o_held = o_ur_obj != 0 && !mos.zap_values(cx, o_ur_obj)?.is_empty();
        if Some(origin_obj) != pool_origin_snap
            && o_flags & DS_FLAG_DEFER_DESTROY != 0
            && new_o_children == 1
            && !o_held
        {
            stage_destroy_snapshot_by_id(
                cx,
                mos,
                o_dd_obj,
                o_dd_head,
                origin_obj,
                false,
                &[(parent_dd_obj, [-1, 0])],
                mos_dirty_dnodes,
                features,
                empty_bpobj_id,
                alloc,
                order,
                new_txg,
                staged_writes,
            )?;
            filesystem_count_adjusted = true;
        }
    }
    if !filesystem_count_adjusted {
        bump_filesystem_limits_counter_if_present(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            alloc,
            parent_dd_obj,
            b"com.joyent:filesystem_count",
            -1,
            order,
            new_txg,
            staged_writes,
        )?;
    }

    Ok(head_obj)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn stage_change_key(
    cx: &Cx,
    mos: &mut Objects,
    dataset: &[Vec<u8>],
    new_material: &ZfsKeyMaterial,
    new_keylocation: Option<&[u8]>,
    pbkdf2_iters: Option<u64>,
    extra_entropy: &[u8],
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    features: &MosFeatureState,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<u64> {
    let (dd_obj, head_obj, pool_guid) = resolve_dataset_ids(cx, mos, dataset)?;
    let info = mos
        .dataset_crypto_info(cx, dataset)?
        .ok_or_else(|| reject_einval("cannot change key on an unencrypted ZFS dataset"))?;
    if info.encryption_root_ddobj != dd_obj {
        return Err(reject_einval(
            "change_key target must be a ZFS encryption root dataset",
        ));
    }
    let loaded = mos
        .keyring()
        .get(dd_obj)
        .ok_or(FfsError::PermissionDenied)?;

    let new_keyformat = new_material.format();
    let (new_pbkdf2_salt, new_pbkdf2_iters) = if new_keyformat == ZfsKeyFormat::Passphrase {
        let iters = pbkdf2_iters.unwrap_or(ZFS_PBKDF2_DEFAULT_ITERS);
        if iters < ZFS_PBKDF2_MIN_ITERS {
            return Err(reject_einval(
                "ZFS passphrase pbkdf2iters must be at least 100000",
            ));
        }
        let mut salt = derive_unique_guid(pool_guid, new_txg, info.crypto_key_obj, 101);
        if salt == info.record.pbkdf2_salt {
            salt = salt.wrapping_add(1).max(1);
        }
        (salt, iters)
    } else {
        (0, 0)
    };
    let new_wrapping =
        new_material.resolve_wrapping_key(new_keyformat, new_pbkdf2_salt, new_pbkdf2_iters)?;
    let (mut unused_master, mut unused_hmac, mut new_wrap_iv, _) =
        generate_new_dataset_keys(cx, pool_guid, info.record.guid, new_txg, extra_entropy)?;
    unused_master.zeroize();
    unused_hmac.zeroize();
    if new_wrap_iv == info.record.iv {
        new_wrap_iv[0] ^= 0x01;
    }

    let new_record = DslCryptoKeyRecord::wrap(
        info.record.suite,
        info.record.guid,
        info.record.version,
        info.record.root_ddobj,
        info.record.refcount,
        new_keyformat,
        new_pbkdf2_salt,
        new_pbkdf2_iters,
        new_wrap_iv,
        new_wrapping.as_bytes(),
        loaded.active_master_key(),
        &loaded.hmac_key,
    )
    .map_err(|e| parse_err(&e))?;
    let verified = new_record
        .unwrap(new_wrapping.as_bytes())
        .map_err(|e| parse_err(&e))?;
    if verified.active_master_key() != loaded.active_master_key()
        || verified.hmac_key != loaded.hmac_key
    {
        return Err(corrupt(
            "re-wrapped dsl_crypto_key failed roundtrip verification",
        ));
    }

    let mos_meta = mos.meta_dnode().clone();
    let mos_ceiling = mos.root_birth_txg();
    let (key_dn, key_ceil) = mos.object_with_ceiling(cx, info.crypto_key_obj)?;
    let key_entries = encode_dsl_crypto_key_zap(&new_record);
    write_zap_dnode_in_mos(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        alloc,
        info.crypto_key_obj,
        Some((&key_dn, key_ceil)),
        DMU_OTN_ZAP_METADATA,
        0,
        Vec::new(),
        &key_entries,
        0,
        true,
        order,
        new_txg,
        staged_writes,
    )?;

    if let Some(loc) = new_keylocation {
        let (dd_dn, _) = read_staged_or_committed_dnode(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            dd_obj,
            order,
        )?;
        let props_zap = order.u64(dd_dn.bonus(), 80).map_err(|e| parse_err(&e))?;
        let (pz_dn, pz_ceil) = mos.object_with_ceiling(cx, props_zap)?;
        let is_zvol = mos
            .datasets(cx)?
            .into_iter()
            .find(|d| d.head_object == head_obj)
            .is_some_and(|d| d.objectset_kind == Some(3));
        let val = ZfsPropertySetValue::Text(loc.to_vec());
        let updates = [("keylocation", Some(&val))];
        apply_properties_batch_on_ids(
            cx,
            mos,
            dd_obj,
            head_obj,
            props_zap,
            Some((&pz_dn, pz_ceil)),
            is_zvol,
            true,
            &updates,
            mos_dirty_dnodes,
            features,
            alloc,
            order,
            new_txg,
            staged_writes,
        )?;
    }

    Ok(head_obj)
}

#[allow(clippy::too_many_arguments)]
fn stage_set_property(
    cx: &Cx,
    mos: &mut Objects,
    dataset: &[Vec<u8>],
    name: &str,
    value: Option<&ZfsPropertySetValue>,
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    features: &mut MosFeatureState,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<u64> {
    let (dd_obj, head_obj, _) = resolve_dataset_ids(cx, mos, dataset)?;
    let is_encryption_root = mos
        .dataset_crypto_info(cx, dataset)?
        .is_some_and(|c| c.encryption_root_ddobj == dd_obj);
    let mos_meta = mos.meta_dnode().clone();
    let mos_ceiling = mos.root_birth_txg();
    let (dd_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        dd_obj,
        order,
    )?;
    let props_zap = order.u64(dd_dn.bonus(), 80).map_err(|e| parse_err(&e))?;
    let (pz_dn, pz_ceil) = mos.object_with_ceiling(cx, props_zap)?;
    let is_zvol = mos
        .datasets(cx)?
        .into_iter()
        .find(|d| d.head_object == head_obj)
        .is_some_and(|d| d.objectset_kind == Some(3));
    let updates = [(name, value)];
    apply_properties_batch_on_ids(
        cx,
        mos,
        dd_obj,
        head_obj,
        props_zap,
        Some((&pz_dn, pz_ceil)),
        is_zvol,
        is_encryption_root,
        &updates,
        mos_dirty_dnodes,
        features,
        alloc,
        order,
        new_txg,
        staged_writes,
    )?;
    if name == "compression"
        && matches!(value, Some(ZfsPropertySetValue::Number(raw)) if raw & 127 == 16)
    {
        stage_activate_dataset_features(
            cx,
            mos,
            head_obj,
            &["org.freebsd:zstd_compress"],
            mos_dirty_dnodes,
            features,
            alloc,
            order,
            new_txg,
            staged_writes,
        )?;
    }
    Ok(head_obj)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn apply_properties_batch_on_ids(
    cx: &Cx,
    mos: &mut Objects,
    dd_obj: u64,
    head_obj: u64,
    props_zap: u64,
    existing_pz: Option<(&Dnode, u64)>,
    is_zvol: bool,
    is_encryption_root: bool,
    updates: &[(&str, Option<&ZfsPropertySetValue>)],
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    features: &MosFeatureState,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<()> {
    let mos_meta = mos.meta_dnode().clone();
    let mos_ceiling = mos.root_birth_txg();
    let mut rows = if existing_pz.is_some() {
        mos.zap_values(cx, props_zap)?
    } else {
        Vec::new()
    };

    for &(name, value) in updates {
        if name.is_empty()
            || name.len() >= 256
            || name.starts_with('-')
            || name.contains('$')
            || !name.bytes().all(|b| {
                b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || matches!(b, b':' | b'-' | b'_' | b'.')
            })
        {
            return Err(reject_einval(format!("invalid ZFS property name {name}")));
        }

        let (dd_dn, _) = read_staged_or_committed_dnode(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            dd_obj,
            order,
        )?;
        let parent_dd = order.u64(dd_dn.bonus(), 16).map_err(|e| parse_err(&e))?;
        let dd_used = order.u64(dd_dn.bonus(), 40).map_err(|e| parse_err(&e))?;
        let old_dd_quota = order.u64(dd_dn.bonus(), 64).map_err(|e| parse_err(&e))?;
        let old_dd_reserved = order.u64(dd_dn.bonus(), 72).map_err(|e| parse_err(&e))?;

        let (head_dn, _) = read_staged_or_committed_dnode(
            cx,
            mos,
            &mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            head_obj,
            order,
        )?;
        let head_ref_bytes = order.u64(head_dn.bonus(), 72).map_err(|e| parse_err(&e))?;
        let head_unique = order.u64(head_dn.bonus(), 96).map_err(|e| parse_err(&e))?;

        let old_refquota = effective_local_numeric_prop(&rows, "refquota")?.unwrap_or(0);
        let old_refrsrv = effective_local_numeric_prop(&rows, "refreservation")?.unwrap_or(0);

        let is_user_prop = name.contains(':');
        if is_zvol
            && !is_user_prop
            && matches!(
                name,
                "quota"
                    | "refquota"
                    | "filesystem_limit"
                    | "recordsize"
                    | "atime"
                    | "relatime"
                    | "devices"
                    | "exec"
                    | "setuid"
                    | "volblocksize"
            )
        {
            return Err(reject_einval(format!(
                "ZFS property {name} is not mutable on a volume dataset"
            )));
        }
        if !is_zvol && !is_user_prop && matches!(name, "snapdev" | "volthreading" | "volblocksize")
        {
            return Err(reject_einval(format!(
                "ZFS volume property {name} is not valid on a filesystem dataset"
            )));
        }
        let mut next_dd_quota = old_dd_quota;
        let mut next_dd_reserved = old_dd_reserved;
        let mut refrsrv_delta = 0_i128;

        let iuv_key = format!("{name}$iuv").into_bytes();
        let inherit_key = format!("{name}$inherit").into_bytes();
        let recvd_key = format!("{name}$recvd").into_bytes();
        let has_recvd = rows.iter().any(|r| r.name == recvd_key);

        // OpenZFS zfs-2.3.0 dsl_prop_predict treats clearing these
        // non-inheritable properties as restoring their received value (or
        // zero). A restored limit can tighten quotas or consume reserved
        // space, so it needs the same preflight and accounting as a local set.
        // Retain the original request separately so restoration does not
        // accidentally publish a new local override of the received value.
        let is_space_property = matches!(
            name,
            "quota" | "refquota" | "reservation" | "refreservation"
        );
        let is_count_limit = matches!(name, "filesystem_limit" | "snapshot_limit");
        let restored_numeric_value = if value.is_none() && (is_space_property || is_count_limit) {
            Some(ZfsPropertySetValue::Number(
                zap_optional_u64(&rows, &recvd_key)?.unwrap_or(if is_count_limit {
                    u64::MAX
                } else {
                    0
                }),
            ))
        } else {
            None
        };

        if let Some(val) = value.or(restored_numeric_value.as_ref()) {
            if is_user_prop || name == "keylocation" {
                if name == "keylocation" && !is_encryption_root {
                    return Err(reject_einval(
                        "keylocation property may only be set on a ZFS encryption root",
                    ));
                }
                let ZfsPropertySetValue::Text(bytes) = val else {
                    return Err(reject_einval(format!(
                        "ZFS property {name} requires a string value"
                    )));
                };
                if (name == "keylocation" && bytes.is_empty())
                    || bytes.len() >= 8192
                    || bytes.contains(&0)
                {
                    return Err(reject_einval(format!("invalid ZFS property {name} value")));
                }
                let mut vals: Vec<u64> = bytes.iter().map(|&b| u64::from(b)).collect();
                vals.push(0);
                rows.retain(|r| {
                    r.name != name.as_bytes() && r.name != iuv_key && r.name != inherit_key
                });
                rows.push(RawZapEntry {
                    name: name.as_bytes().to_vec(),
                    integer_bytes: 1,
                    values: vals,
                    collision: 0,
                });
            } else {
                let ZfsPropertySetValue::Number(num) = *val else {
                    return Err(reject_einval(format!(
                        "native ZFS property {name} requires a numeric value"
                    )));
                };
                match name {
                    "filesystem_limit" | "snapshot_limit" => {
                        // Native count limits may be lowered below current
                        // usage. They govern subsequent growth, not existence.
                        // Do not activate tracking with invented zero counts:
                        // imported hierarchies must already be initialized.
                        zap_optional_u64(&rows, name.as_bytes())?;
                        zap_optional_u64(&rows, &recvd_key)?;
                        if features
                            .write_features
                            .get("com.joyent:filesystem_limits")
                            .copied()
                            .unwrap_or(0)
                            == 0
                            || dd_dn.object_type() != DMU_OTN_ZAP_METADATA
                        {
                            return Err(unsupported(
                                "native count limits require initialized filesystem limit tracking",
                            ));
                        }
                        let counter_rows = mos.zap_values(cx, dd_obj)?;
                        for counter in [
                            b"com.joyent:filesystem_count".as_slice(),
                            b"com.joyent:snapshot_count".as_slice(),
                        ] {
                            if zap_optional_u64(&counter_rows, counter)?.is_none() {
                                return Err(corrupt(
                                    "native count limit has no initialized counter",
                                ));
                            }
                        }
                    }
                    "quota" => {
                        if num > 0 && num < dd_used.max(old_dd_reserved) {
                            return Err(reject_edquot(
                                "cannot set quota below current dataset used or reservation",
                            ));
                        }
                        next_dd_quota = num;
                    }
                    "refquota" => {
                        if num > 0 && num < head_ref_bytes.max(old_refrsrv) {
                            return Err(reject_edquot(
                                "cannot set refquota below current referenced bytes or refreservation",
                            ));
                        }
                    }
                    "reservation" => {
                        if old_dd_quota > 0 && num > old_dd_quota {
                            return Err(reject_edquot("reservation exceeds dataset quota"));
                        }
                        let old_excess = old_dd_reserved.saturating_sub(dd_used);
                        let new_excess = num.saturating_sub(dd_used);
                        let add = new_excess.saturating_sub(old_excess);
                        if add > 0 {
                            enforce_pool_reservations_for_growth(
                                cx,
                                mos,
                                mos_dirty_dnodes,
                                head_obj,
                                dd_obj,
                                0,
                                add,
                                alloc.total_free_bytes(),
                                order,
                            )?;
                            if parent_dd != 0 {
                                enforce_dataset_quotas_for_growth(
                                    cx,
                                    mos,
                                    mos_dirty_dnodes,
                                    head_obj,
                                    parent_dd,
                                    0,
                                    add,
                                    order,
                                )?;
                            }
                        }
                        next_dd_reserved = num;
                    }
                    "refreservation" => {
                        if old_refquota > 0 && num > old_refquota {
                            return Err(reject_edquot("refreservation exceeds dataset refquota"));
                        }
                        let old_charge = old_refrsrv.saturating_sub(head_unique);
                        let new_charge = num.saturating_sub(head_unique);
                        let add = new_charge.saturating_sub(old_charge);
                        if add > 0 {
                            enforce_pool_reservations_for_growth(
                                cx,
                                mos,
                                mos_dirty_dnodes,
                                head_obj,
                                dd_obj,
                                0,
                                add,
                                alloc.total_free_bytes(),
                                order,
                            )?;
                            enforce_dataset_quotas_for_growth(
                                cx,
                                mos,
                                mos_dirty_dnodes,
                                head_obj,
                                dd_obj,
                                0,
                                add,
                                order,
                            )?;
                        }
                        refrsrv_delta = i128::from(new_charge) - i128::from(old_charge);
                    }
                    "readonly" | "atime" | "relatime" | "devices" | "exec" | "setuid"
                    | "snapdev" | "logbias" | "volthreading" => {
                        if num > 1 {
                            return Err(reject_einval(format!(
                                "boolean ZFS property {name} must be 0 or 1"
                            )));
                        }
                    }
                    "sync" => {
                        if num > 2 {
                            return Err(reject_einval(
                                "ZFS sync property must be 0 (standard), 1 (always), or 2 (disabled)",
                            ));
                        }
                    }
                    "recordsize" => {
                        if !(512..=1_048_576).contains(&num) || !num.is_power_of_two() {
                            return Err(reject_einval(
                                "ZFS recordsize must be a power of two in 512..=1048576",
                            ));
                        }
                        if num > 131_072 {
                            require_dataset_block_feature(features, "org.open-zfs:large_blocks")?;
                        }
                    }
                    "checksum" => {
                        if !matches!(num, 1 | 6 | 7 | 8 | 11) {
                            return Err(unsupported(format!(
                                "unsupported ZFS checksum property index {num}"
                            )));
                        }
                        if num == 11 {
                            require_dataset_block_feature(features, "org.illumos:sha512")?;
                        }
                    }
                    "compression" => {
                        // Pool capability is admission, not dataset ownership.
                        // ZSTD ownership is staged on the head by the caller;
                        // LZ4 must already be active from pool feature enablement.
                        DatasetCompression::from_property(num, features)?;
                    }
                    _ => {
                        return Err(unsupported(format!(
                            "setting ZFS property {name} is not supported"
                        )));
                    }
                }

                rows.retain(|r| {
                    r.name != name.as_bytes() && r.name != iuv_key && r.name != inherit_key
                });
                let clear_zero = is_space_property && num == 0 && !has_recvd;
                if value.is_some() && !clear_zero {
                    rows.push(RawZapEntry {
                        name: name.as_bytes().to_vec(),
                        integer_bytes: 8,
                        values: vec![num],
                        collision: 0,
                    });
                }
            }
        } else {
            // Ordinary inheritable properties suppress received values and
            // resolve their parent/default after the local override is removed.
            rows.retain(|r| {
                r.name != name.as_bytes() && r.name != iuv_key && r.name != inherit_key
            });
            if has_recvd && !is_space_property && !is_count_limit {
                rows.push(RawZapEntry {
                    name: inherit_key,
                    integer_bytes: 8,
                    values: vec![0],
                    collision: 0,
                });
            }
        }

        if next_dd_quota != old_dd_quota || next_dd_reserved != old_dd_reserved {
            let (cur_dd, _) = read_staged_or_committed_dnode(
                cx,
                mos,
                &mos_meta,
                mos_ceiling,
                mos_dirty_dnodes,
                dd_obj,
                order,
            )?;
            let mut dd_bonus = cur_dd.bonus().to_vec();
            dd_bonus[64..72].copy_from_slice(&order.encode(next_dd_quota));
            dd_bonus[72..80].copy_from_slice(&order.encode(next_dd_reserved));
            let mut updated_dd = cur_dd;
            let btype = updated_dd.bonus_type();
            updated_dd
                .set_bonus_and_spill(btype, dd_bonus, None)
                .map_err(|e| parse_err(&e))?;
            put_dnode_in_table(
                cx,
                mos,
                &mos_meta,
                mos_ceiling,
                mos_dirty_dnodes,
                dd_obj,
                &updated_dd,
            )?;
        }

        if refrsrv_delta != 0 {
            propagate_dsl_dir_space_delta(
                cx,
                mos,
                &mos_meta,
                mos_ceiling,
                mos_dirty_dnodes,
                dd_obj,
                0,
                0,
                0,
                0,
                refrsrv_delta,
                0,
                0,
                order,
            )?;
        }

        if next_dd_reserved != old_dd_reserved && parent_dd != 0 {
            let (cur_dd, _) = read_staged_or_committed_dnode(
                cx,
                mos,
                &mos_meta,
                mos_ceiling,
                mos_dirty_dnodes,
                dd_obj,
                order,
            )?;
            let cur_used = order.u64(cur_dd.bonus(), 40).map_err(|e| parse_err(&e))?;
            let old_excess = old_dd_reserved.saturating_sub(cur_used);
            let new_excess = next_dd_reserved.saturating_sub(cur_used);
            let parent_rsrv_delta = i128::from(new_excess) - i128::from(old_excess);
            if parent_rsrv_delta != 0 {
                propagate_dsl_dir_space_delta(
                    cx,
                    mos,
                    &mos_meta,
                    mos_ceiling,
                    mos_dirty_dnodes,
                    parent_dd,
                    0,
                    0,
                    0,
                    parent_rsrv_delta,
                    0,
                    0,
                    0,
                    order,
                )?;
            }
        }
    }

    let force_fat = rows
        .iter()
        .any(|r| r.integer_bytes != 8 || r.values.len() != 1);
    write_zap_dnode_in_mos(
        cx,
        mos,
        &mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        alloc,
        props_zap,
        existing_pz,
        DMU_OT_DSL_PROPS,
        0,
        Vec::new(),
        &rows,
        0,
        force_fat,
        order,
        new_txg,
        staged_writes,
    )?;

    Ok(())
}

/// Compute effective `(referenced_bytes, available_bytes)` when `refquota` or any ancestor
/// `quota` is active on `dataset_components`; returns `Ok(None)` when unconstrained by quotas.
pub fn dataset_statfs_quota_space(
    cx: &Cx,
    mos: &mut Objects,
    dataset_components: &[Vec<u8>],
    pool_free_bytes: u64,
) -> Result<Option<(u64, u64)>> {
    let (dir_obj, head_obj, _) = resolve_dataset_ids(cx, mos, dataset_components)?;
    let (head_dn, _) = mos.object_with_ceiling(cx, head_obj)?;
    let order = head_dn.order();
    let referenced = order.u64(head_dn.bonus(), 72).map_err(|e| parse_err(&e))?;
    let unique = order.u64(head_dn.bonus(), 96).map_err(|e| parse_err(&e))?;

    let mut has_quota = false;
    let mut avail = pool_free_bytes;
    let mut reserved_headroom = 0_u64;

    let mut cur_dir = dir_obj;
    let mut is_self = true;
    let mut visited = BTreeSet::new();
    while cur_dir != 0 {
        checkpoint(cx)?;
        if !visited.insert(cur_dir) {
            return Err(corrupt("cycle in DSL directory parent chain"));
        }
        let (dd_dn, _) = mos.object_with_ceiling(cx, cur_dir)?;
        let order = dd_dn.order();
        let parent_dd = order.u64(dd_dn.bonus(), 16).map_err(|e| parse_err(&e))?;
        let dd_used = order.u64(dd_dn.bonus(), 40).map_err(|e| parse_err(&e))?;
        let dd_quota = order.u64(dd_dn.bonus(), 64).map_err(|e| parse_err(&e))?;
        let dd_reserved = order.u64(dd_dn.bonus(), 72).map_err(|e| parse_err(&e))?;
        if is_self {
            let props_obj = order.u64(dd_dn.bonus(), 80).map_err(|e| parse_err(&e))?;
            if props_obj != 0 {
                let entries = mos.zap_values(cx, props_obj)?;
                if let Some(rq) = effective_local_numeric_prop(&entries, "refquota")?
                    && rq > 0
                {
                    has_quota = true;
                    avail = avail.min(rq.saturating_sub(referenced));
                }
                reserved_headroom = effective_local_numeric_prop(&entries, "refreservation")?
                    .unwrap_or(0)
                    .saturating_sub(unique);
            }
        }
        if dd_quota > 0 {
            has_quota = true;
            avail = avail.min(
                dd_quota
                    .saturating_sub(dd_used)
                    .saturating_add(reserved_headroom),
            );
        }
        // This directory's reservation is charged to its parent, so it can
        // offset a parent quota but cannot enlarge the directory's own quota.
        reserved_headroom = reserved_headroom.saturating_add(dd_reserved.saturating_sub(dd_used));
        is_self = false;
        cur_dir = parent_dd;
    }

    Ok(has_quota.then_some((referenced, avail)))
}
