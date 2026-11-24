//! Native ZPL head-dataset mutations (create, mkdir, symlink, write, setattr, link, rename, unlink)
//! lowered into COW DMU object-set, DSL dataset/dir accounting, and deadlist updates.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_ondisk::zfs::crypto::DSL_DATASET_IVSET_GUID;
use ffs_ondisk::zfs::{BlockPointer, Endian};
use ffs_ondisk::zfs_dmu::{
    DMU_OT_DNODE, DNODE_BLOCK_BYTES, DNODE_BYTES, Dnode, DnodeSpec, OBJSET_GROUPUSED_OFFSET,
    OBJSET_PROJECTUSED_OFFSET, OBJSET_USERUSED_OFFSET, ObjectSet, dnode_at,
};
use ffs_ondisk::zfs_zap::Entry as RawZapEntry;
use ffs_ondisk::zfs_zpl::{
    Kind, Metadata, SA_BYTES, SaRegistry, Timestamp, XATTR_BYTES, XATTR_COUNT, XATTR_NAME_BYTES,
    XattrSources, directory_reference, encode_directory_reference,
};
use serde::Serialize;

use crate::crypto::ZfsNonceGenerator;
use crate::reader::dmu::properties::PropertyValue;
use crate::reader::dmu::{DatasetCryptoContext, Objects};

use super::dmu_cow::{
    DMU_OT_DIRECTORY_CONTENTS, DMU_OT_PLAIN_FILE_CONTENTS, DMU_OT_SA, DMU_OT_ZNODE,
    DatasetWriteCrypto, DnodeCowOutput, DnodeCowSpec, OwnerQuotaLimits, PoolSpaceAllocator,
    QuotaDelta, SpaceDelta, StagedBlockWrite, WriteBucket, allocate_object_id,
    allocated_leaf_blocks_in_range, apply_objectset_quota_deltas, collect_non_hole_bps_from,
    cow_update_dnode_with_crypto, decode_compression_property, encode_zap_blocks_for_dnode,
    enqueue_into_dataset_deadlist, load_owner_quota_limits, objectset_user_accounting_flags,
    put_dnode_in_table, read_staged_or_committed_dnode, remove_dnode_from_table,
    write_dataset_block, write_dataset_objset_block, zap_optional_u64, zap_required_u64,
};
use super::dsl_ops::DMU_OTN_ZAP_METADATA;
use super::{checkpoint, corrupt, parse_err, unsupported};

const DMU_SPILL_BLKID: u64 = u64::MAX - 1;

const DEFAULT_RECORDSIZE: usize = 131_072;
const MAX_WRITE_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
const MAX_PATH_DEPTH: usize = 256;
// One 512-byte dnode, minus its 64-byte header, one 128-byte data pointer,
// and the 264-byte legacy znode. Longer targets use ordinary file data.
const MAX_INLINE_SYMLINK_BYTES: usize = 56;
const DMU_OT_UNLINKED_SET: u8 = 22;
#[allow(dead_code)]
const DMU_OT_ACL: u8 = 33;
const DMU_OT_SA_ATTR_REGISTRATION: u8 = 46;
const DMU_OT_SA_ATTR_LAYOUTS: u8 = 47;
const MAX_PENDING_UNLINKS: usize = 65_536;

/// A generation-bound object retained in the native ZPL unlinked set.
/// The object number alone is insufficient authority to reclaim a reused slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ZfsUnlinkedObject {
    pub object: u64,
    pub generation: u64,
}

/// A dataset-local object and its native birth generation. Namespace operations
/// bind both fields so a retry cannot act on a reused object number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ZfsObjectIdentity {
    pub object: u64,
    pub generation: u64,
}

// Native persistent ZPL flags (OpenZFS zfs-2.3.0, sys/zfs_znode.h).
// Dataset `readonly` is a separate, inherited DSL property.
#[allow(dead_code)]
const ZFS_XATTR: u64 = 0x1;
const ZFS_INHERIT_ACE: u64 = 0x2;
const ZFS_ACL_TRIVIAL: u64 = 0x4;
const ZFS_NO_EXECS_DENIED: u64 = 0x100;
const ZFS_READONLY: u64 = 0x0000_0001_0000_0000;
const ZFS_IMMUTABLE: u64 = 0x0000_0010_0000_0000;
const ZFS_NOUNLINK: u64 = 0x0000_0020_0000_0000;
const ZFS_APPENDONLY: u64 = 0x0000_0040_0000_0000;
const ZFS_PROJINHERIT: u64 = 0x0000_4000_0000_0000;
const ZFS_PROJID: u64 = 0x0000_8000_0000_0000;

fn reject_flags(metadata: &Metadata, prohibited: u64) -> Result<()> {
    if metadata.flags & prohibited != 0 {
        return Err(FfsError::RequestRejected {
            errno: libc::EPERM,
            detail: "native ZPL persistent flags prohibit this mutation".into(),
        });
    }
    Ok(())
}

fn admit_directory_add(
    parent: &LoadedZplNode,
    context: &DatasetContext,
    write_features: &BTreeMap<String, u64>,
) -> Result<()> {
    // Append-only directories may gain new names, but immutable directories
    // cannot. A project tree needs already active native accounting; creating
    // entries must never silently enable a pool feature or incomplete counters.
    reject_flags(&parent.metadata, ZFS_IMMUTABLE)?;
    if parent.metadata.flags & ZFS_PROJINHERIT == 0 {
        return Ok(());
    }
    if context.zpl_version < 5
        || parent.dnode.bonus_type() != DMU_OT_SA
        || parent.metadata.flags & ZFS_PROJID == 0
        || context.os.flags & 0x07 != 0x07
        || write_features
            .get("org.zfsonlinux:project_quota")
            .is_none_or(|&references| references == 0)
    {
        return Err(unsupported(
            "project inheritance requires ZPL v5 SA and active, complete native project accounting",
        ));
    }
    for offset in [
        OBJSET_USERUSED_OFFSET,
        OBJSET_GROUPUSED_OFFSET,
        OBJSET_PROJECTUSED_OFFSET,
    ] {
        if context
            .os
            .embedded_dnode(offset, context.os.meta.order())
            .map_err(|error| parse_err(&error))?
            .is_none()
        {
            return Err(corrupt(
                "project inheritance lacks its native accounting object",
            ));
        }
    }
    Ok(())
}

fn admit_project_entry(parent: &LoadedZplNode, target: &LoadedZplNode) -> Result<()> {
    // OpenZFS zfs-2.3.0 zfs_link/zfs_rename: linking or moving an existing
    // object never changes its project owner to fit the destination tree.
    if parent.metadata.flags & ZFS_PROJINHERIT != 0 && parent.project_id != target.project_id {
        return Err(FfsError::RequestRejected {
            errno: libc::EXDEV,
            detail: "ZPL destination inherits a different native project ID".into(),
        });
    }
    Ok(())
}

fn admit_directory_remove(parent: &Metadata, target: &Metadata) -> Result<()> {
    reject_flags(parent, ZFS_IMMUTABLE | ZFS_APPENDONLY)?;
    reject_flags(target, ZFS_IMMUTABLE | ZFS_APPENDONLY | ZFS_NOUNLINK)
}

fn clear_setid_bits_for_nonroot(mode: u64) -> u64 {
    let mut next = mode & !0o4000;
    // Linux/FUSE baseline: group-executable SGID must be dropped. The frontend
    // additionally removes non-executable SGID for callers outside the file's group.
    if next & 0o0010 != 0 {
        next &= !0o2000;
    }
    next
}

/// Checksum selection for newly written DMU data blocks (`ZIO_CHECKSUM_*`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub enum ZfsDataChecksum {
    /// Resolve the native dnode override and effective dataset property for ZPL writes.
    Inherit,
    #[default]
    Fletcher4,
    Sha256,
}

impl ZfsDataChecksum {
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Inherit => 0,
            Self::Fletcher4 => 7,
            Self::Sha256 => 8,
        }
    }
}

/// Creation / replacement policy for ZPL extended attribute updates.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub enum ZfsXattrSetMode {
    #[default]
    Auto,
    Create,
    Replace,
}

/// Native sparse range edits. Complete blocks become holes; partial blocks are
/// zeroed without changing bytes outside the requested range. No space is reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ZfsFileRangeOperation {
    /// Punch a hole while preserving the logical file size.
    PunchHole,
    /// Zero a range, optionally extending EOF to its end.
    ZeroRange { keep_size: bool },
}

impl ZfsFileRangeOperation {
    pub(crate) const fn keeps_size(self) -> bool {
        matches!(self, Self::PunchHole | Self::ZeroRange { keep_size: true })
    }
}

/// Native size and timestamp updates published together in one head-dataset TXG.
#[derive(Debug, Clone, Default)]
pub struct ZfsSetAttr {
    pub size: Option<u64>,
    pub atime: Option<Timestamp>,
    pub mtime: Option<Timestamp>,
}

/// Native size, permission, ownership, and timestamp updates published together
/// in one head-dataset TXG.
#[derive(Debug, Clone, Default)]
pub struct ZfsPosixSetAttr {
    pub size: Option<u64>,
    pub atime: Option<Timestamp>,
    pub mtime: Option<Timestamp>,
    pub mode: Option<u16>,
    pub uid: Option<u64>,
    pub gid: Option<u64>,
    /// Clear set-user-ID and executable set-group-ID after applying `mode`.
    /// Non-executable set-group-ID and directory permissions are preserved.
    pub clear_suid_sgid: bool,
    /// Remove the exact native `security.capability` SA xattr in this TXG.
    /// Directory-backed capability values refuse the whole mutation.
    pub clear_file_capabilities: bool,
}

impl From<&ZfsSetAttr> for ZfsPosixSetAttr {
    fn from(value: &ZfsSetAttr) -> Self {
        Self {
            size: value.size,
            atime: value.atime,
            mtime: value.mtime,
            ..Self::default()
        }
    }
}

impl ZfsPosixSetAttr {
    pub(super) fn validate(&self, timestamp: Timestamp) -> Result<()> {
        if self.size.is_none()
            && self.atime.is_none()
            && self.mtime.is_none()
            && self.mode.is_none()
            && self.uid.is_none()
            && self.gid.is_none()
            && !self.clear_suid_sgid
            && !self.clear_file_capabilities
        {
            return Err(FfsError::Format("empty native ZPL attribute update".into()));
        }
        if self.mode.is_some_and(|m| m & !0o7777 != 0) {
            return Err(FfsError::Format(
                "ZPL setattr mode contains file-type bits".into(),
            ));
        }
        if self.size.is_some_and(|size| i64::try_from(size).is_err()) {
            return Err(FfsError::Format(
                "ZFS truncate size exceeds i64::MAX".into(),
            ));
        }
        if [Some(timestamp), self.atime, self.mtime]
            .into_iter()
            .flatten()
            .any(|time| time.nanos >= 1_000_000_000)
        {
            return Err(FfsError::Format("invalid ZPL nanoseconds".into()));
        }
        Ok(())
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
        symlink_target: Option<Vec<u8>>,
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
        clear_suid_sgid: bool,
        clear_file_capabilities: bool,
        timestamp: Timestamp,
        checksum: ZfsDataChecksum,
    },
    EditRange {
        file_obj: u64,
        offset: u64,
        length: u64,
        operation: ZfsFileRangeOperation,
        clear_suid_sgid: bool,
        clear_file_capabilities: bool,
        timestamp: Timestamp,
        checksum: ZfsDataChecksum,
    },
    SetAttributes {
        file_obj: u64,
        attrs: ZfsPosixSetAttr,
        timestamp: Timestamp,
        checksum: ZfsDataChecksum,
    },
    SetXattr {
        target_obj: u64,
        name: String,
        value: Vec<u8>,
        mode: ZfsXattrSetMode,
        timestamp: Timestamp,
    },
    RemoveXattr {
        target_obj: u64,
        name: String,
        timestamp: Timestamp,
    },
    LinkEntry {
        source_object: u64,
        parent_dir: u64,
        name: Vec<u8>,
        timestamp: Timestamp,
    },
    RenameEntry {
        src_dir: u64,
        src_name: Vec<u8>,
        dst_dir: u64,
        dst_name: Vec<u8>,
        expected_source_object: Option<u64>,
        retain_replaced: Option<ZfsUnlinkedObject>,
        timestamp: Timestamp,
    },
    ExchangeEntries {
        src_dir: u64,
        src_name: Vec<u8>,
        dst_dir: u64,
        dst_name: Vec<u8>,
        source: ZfsObjectIdentity,
        target: ZfsObjectIdentity,
        timestamp: Timestamp,
    },
    UnlinkEntry {
        parent_dir: u64,
        name: Vec<u8>,
        rmdir: bool,
        retain: Option<ZfsUnlinkedObject>,
        timestamp: Timestamp,
    },
    ReapUnlinked {
        identity: ZfsUnlinkedObject,
    },
}

impl ZplMutation {
    pub fn op_name(&self) -> &'static str {
        match self {
            Self::CreateFile {
                symlink_target: Some(_),
                ..
            } => "create_symlink",
            Self::CreateFile { .. } => "create_file",
            Self::Mkdir { .. } => "mkdir",
            Self::WriteData { .. } => "write_data",
            Self::EditRange {
                operation: ZfsFileRangeOperation::PunchHole,
                ..
            } => "punch_hole",
            Self::EditRange { .. } => "zero_range",
            Self::SetAttributes { .. } => "set_attributes",
            Self::SetXattr { .. } => "set_xattr",
            Self::RemoveXattr { .. } => "remove_xattr",
            Self::LinkEntry { .. } => "link_entry",
            Self::RenameEntry { .. } => "rename_entry",
            Self::ExchangeEntries { .. } => "exchange_entries",
            Self::UnlinkEntry { .. } => "unlink_entry",
            Self::ReapUnlinked { .. } => "reap_unlinked",
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
    owner_quota_limits: OwnerQuotaLimits,
    root_dir: u64,
    zpl_version: u64,
    utf8_only: bool,
    sa_registry: Option<SaRegistry>,
    sa_reg_obj: Option<u64>,
    sa_lay_obj: Option<u64>,
    sa_reg_entries: Vec<RawZapEntry>,
    sa_lay_entries: Vec<RawZapEntry>,
    sa_reg_dirty: bool,
    sa_lay_dirty: bool,
    recordsize: usize,
    checksum: u8,
    unlinked_set: Option<u64>,
    write_crypto: Option<DatasetWriteCrypto>,
}

impl DatasetContext {
    fn data_checksum(&self, requested: ZfsDataChecksum, node: Option<&Dnode>) -> Result<u8> {
        let native = node.map_or(0, Dnode::checksum_type);
        let inherited = match native {
            0 => self.checksum,
            1 => ZfsDataChecksum::Fletcher4.code(),
            6 | 7 => native,
            // Explicit SHA256 retains its integrity policy on every data rewrite.
            // Native dnode overrides contain only legacy checksum selectors;
            // SHA512/256 is selected through the dataset property instead.
            8 => return Ok(native),
            _ => {
                return Err(unsupported(format!(
                    "native ZPL dnode checksum selector {native} is outside the writer profile"
                )));
            }
        };
        Ok(if requested == ZfsDataChecksum::Inherit {
            inherited
        } else {
            requested.code()
        })
    }
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

fn admit_existing_sha512_ownership(
    cx: &Cx,
    mos: &mut Objects,
    head_object: u64,
    head: &Dnode,
) -> Result<()> {
    // First use requires atomic per-dataset feature activation. Until that
    // lifecycle is supported here, only continue an already-owned native use.
    if head.object_type() != DMU_OTN_ZAP_METADATA
        || zap_optional_u64(&mos.zap_values(cx, head_object)?, b"org.illumos:sha512")? != Some(0)
    {
        return Err(unsupported(
            "native SHA512 writes require existing dataset feature ownership",
        ));
    }
    let directory = mos.zap_values(cx, 1)?;
    let features_object = zap_required_u64(&directory, b"features_for_read")?;
    let features = mos.zap_values(cx, features_object)?;
    for feature in [
        b"org.illumos:sha512".as_slice(),
        b"com.delphix:extensible_dataset".as_slice(),
    ] {
        if zap_optional_u64(&features, feature)?.is_none_or(|count| count == 0) {
            return Err(unsupported(
                "native SHA512 writes require active SHA512 and extensible-dataset features",
            ));
        }
    }
    Ok(())
}

fn open_head_dataset_context(
    cx: &Cx,
    mos: &mut Objects,
    dataset_components: &[Vec<u8>],
    new_txg: u64,
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
    // Resolve native local/received/inherited policy from one committed MOS.
    // A raw local property lookup misses both ancestors and $inherit precedence.
    let properties = mos.properties(
        cx,
        dataset_components,
        None,
        &[
            "readonly".into(),
            "compression".into(),
            "recordsize".into(),
            "checksum".into(),
        ],
    )?;
    match properties
        .values
        .first()
        .and_then(|property| property.value.as_ref())
    {
        Some(PropertyValue::Number(0)) => {}
        Some(PropertyValue::Number(1)) => return Err(FfsError::ReadOnly),
        _ => {
            return Err(corrupt(
                "missing or invalid effective ZFS readonly property",
            ));
        }
    }
    let compression_raw = match properties
        .values
        .get(1)
        .and_then(|property| property.value.as_ref())
    {
        Some(PropertyValue::Number(raw)) => *raw,
        _ => 2,
    };
    let (compression, zstd_level) = decode_compression_property(compression_raw);

    let crypto_info = mos.dataset_crypto_info(cx, dataset_components)?;
    let loaded_key = if let Some(ref info) = crypto_info {
        Some(
            mos.keyring()
                .get(info.encryption_root_ddobj)
                .ok_or(FfsError::PermissionDenied)?,
        )
    } else {
        None
    };

    let (head_dn, head_ceiling) = mos.object_with_ceiling(cx, ds_row.head_object)?;
    let order = head_dn.order();
    let prev_snap_txg = order.u64(head_dn.bonus(), 16).map_err(|e| parse_err(&e))?;
    let deadlist_obj = order.u64(head_dn.bonus(), 64).map_err(|e| parse_err(&e))?;
    let old_os_bp =
        BlockPointer::parse(&head_dn.bonus()[128..256], order).map_err(|e| parse_err(&e))?;
    let (os_raw, os_order, _) = mos.read_dataset_objset_block_raw(
        cx,
        &old_os_bp,
        head_ceiling,
        loaded_key.as_deref(),
        false,
    )?;
    let mut os = ObjectSet::parse(&os_raw, os_order).map_err(|e| parse_err(&e))?;
    if os.kind != 2 {
        return Err(corrupt("selected dataset is not a ZPL object set"));
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
            "pending ZIL intent log requires replay before native TXG write",
        ));
    }
    // If this head dataset is COWing an inherited snapshot/origin ObjectSet for
    // the first time (`old_os_bp.birth() <= prev_snap_txg`) and `os_zil_header`
    // belongs to the ancestor dataset (`zc_objset != head_object`), clear
    // `zil_header` on the newly COW'd ObjectSet (`zil_reset` / `dsl_dataset_clone_sync`)
    // so the ancestor keeps exclusive ownership of its pre-allocated `zh_log` block.
    if mos.is_inherited_snapshot_zil(cx, &head_dn, &old_os_bp, &os_raw, os_order, &os)?
        && os_order
            .u64(&os_raw[528..656], 112)
            .map_err(|e| parse_err(&e))?
            != ds_row.head_object
    {
        os.zil_header = ffs_ondisk::zfs_dmu::ZilHeader::empty();
    }

    let recordsize = match properties
        .values
        .get(2)
        .and_then(|property| property.value.as_ref())
    {
        Some(PropertyValue::Number(size))
            if (512..=1_048_576).contains(size) && size.is_power_of_two() =>
        {
            // recordsize is a maximum. Keep the existing 128 KiB writer ceiling
            // until large-block dataset feature ownership is supported.
            (*size as usize).min(DEFAULT_RECORDSIZE)
        }
        _ => {
            return Err(corrupt(
                "missing or invalid effective ZFS recordsize property",
            ));
        }
    };
    let checksum = match properties
        .values
        .get(3)
        .and_then(|property| property.value.as_ref())
    {
        Some(PropertyValue::Number(1 | 7)) => 7,
        Some(PropertyValue::Number(value @ (6 | 8 | 11))) => *value as u8,
        Some(PropertyValue::Number(value)) => {
            return Err(unsupported(format!(
                "effective ZFS checksum selector {value} is outside the native writer profile"
            )));
        }
        _ => {
            return Err(corrupt(
                "missing or invalid effective ZFS checksum property",
            ));
        }
    };
    if checksum == 11 || old_os_bp.checksum_type() == 11 {
        // Finalization also rewrites the object-set root with its old algorithm,
        // even when a caller requests Fletcher4 or changes only metadata.
        admit_existing_sha512_ownership(cx, mos, ds_row.head_object, &head_dn)?;
    }

    let (write_crypto, view_crypto) = if let (Some(info), Some(key)) = (crypto_info, loaded_key) {
        let ivset_guid = if head_dn.object_type() == DMU_OTN_ZAP_METADATA {
            zap_optional_u64(
                &mos.zap_values(cx, ds_row.head_object)?,
                DSL_DATASET_IVSET_GUID,
            )?
            .unwrap_or(ds_row.guid)
        } else {
            ds_row.guid
        };
        let wc = DatasetWriteCrypto {
            nonces: ZfsNonceGenerator::new(ivset_guid, info.record.guid, new_txg, &[]),
            key,
            compression,
            zstd_level,
        };
        let vc = Arc::new(DatasetCryptoContext {
            info,
            raw_scrub_only: false,
        });
        (Some(wc), Some(vc))
    } else {
        (None, None)
    };

    let mut os_view = mos.open_objectset_view_with_crypto(
        os.meta.clone(),
        old_os_bp.birth(),
        mos.txg,
        view_crypto,
    );
    let master = os_view.zap_values(cx, 1)?;
    // Limits are read from the selected committed object set and checked
    // against the same net owner deltas that will be published with this TXG.
    let owner_quota_limits = load_owner_quota_limits(cx, &mut os_view, &os, &master, os_order)?;
    let root_dir = zap_required_u64(&master, b"ROOT")?;
    let unlinked_set = zap_optional_u64(&master, b"DELETE_QUEUE")?.filter(|&object| object != 0);
    let zpl_version = zap_required_u64(&master, b"VERSION")?;
    let utf8_only = zap_optional_u64(&master, b"utf8only")?.unwrap_or(0) != 0;
    let norm = zap_optional_u64(&master, b"normalization")?.unwrap_or(0);
    let case = zap_optional_u64(&master, b"casesensitivity")?.unwrap_or(0);
    if !(4..=5).contains(&zpl_version) || norm != 0 || case != 0 {
        return Err(unsupported(
            "native ZPL writer requires ZPL v4/v5 without normalization or case folding",
        ));
    }
    let (sa_registry, sa_reg_obj, sa_lay_obj, sa_reg_entries, sa_lay_entries) =
        if let Some(sa_master) = zap_optional_u64(&master, b"SA_ATTRS")?.filter(|&v| v != 0) {
            let sa_rows = os_view.zap_values(cx, sa_master)?;
            let reg_obj = zap_required_u64(&sa_rows, b"REGISTRY")?;
            let lay_obj = zap_required_u64(&sa_rows, b"LAYOUTS")?;
            let reg_entries = os_view.zap_values(cx, reg_obj)?;
            let lay_entries = os_view.zap_values(cx, lay_obj)?;
            let reg =
                SaRegistry::from_zaps(&reg_entries, &lay_entries).map_err(|e| parse_err(&e))?;
            (
                Some(reg),
                Some(reg_obj),
                Some(lay_obj),
                reg_entries,
                lay_entries,
            )
        } else {
            (None, None, None, Vec::new(), Vec::new())
        };

    Ok((
        DatasetContext {
            head_object: ds_row.head_object,
            directory_object: ds_row.directory_object,
            prev_snap_txg,
            deadlist_obj,
            old_os_bp,
            os,
            owner_quota_limits,
            root_dir,
            zpl_version,
            utf8_only,
            sa_registry,
            sa_reg_obj,
            sa_lay_obj,
            sa_reg_entries,
            sa_lay_entries,
            sa_reg_dirty: false,
            sa_lay_dirty: false,
            recordsize,
            checksum,
            unlinked_set,
            write_crypto,
        },
        os_view,
    ))
}

struct LoadedZplNode {
    dnode: Dnode,
    ceiling: u64,
    metadata: Metadata,
    project_id: u64,
    spill_bytes: Option<Vec<u8>>,
}

fn signed_bytes_delta(new_used: u64, old_used: u64) -> Result<i64> {
    i64::try_from(i128::from(new_used) - i128::from(old_used))
        .map_err(|_| corrupt("ZFS quota bytes_delta overflow"))
}

/// Initialize only allocated portions of an exposed byte range. Whole blocks
/// become holes; at most two partial boundary blocks require payload reads.
/// The bounded tree walk skips logical holes, including very large sparse gaps.
fn zero_allocated_range(
    cx: &Cx,
    view: &mut Objects,
    loaded: &LoadedZplNode,
    start: u64,
    end: u64,
) -> Result<BTreeMap<u64, Option<Vec<u8>>>> {
    let mut dirty = BTreeMap::new();
    if start >= end {
        return Ok(dirty);
    }
    let block_bytes = loaded.dnode.data_bytes();
    let block_size = block_bytes as u64;
    let blocks = allocated_leaf_blocks_in_range(
        cx,
        view,
        &loaded.dnode,
        loaded.ceiling,
        start / block_size,
        (end - 1) / block_size,
    )?;
    let mut edge_bytes = 0_usize;
    for block in blocks {
        checkpoint(cx)?;
        let block_start = block * block_size;
        let within_start = start.saturating_sub(block_start) as usize;
        let within_end = (end - block_start).min(block_size) as usize;
        if within_start == 0 && within_end == block_bytes {
            dirty.insert(block, None);
            continue;
        }
        edge_bytes = edge_bytes
            .checked_add(block_bytes)
            .filter(|&bytes| bytes <= MAX_WRITE_PAYLOAD_BYTES)
            .ok_or_else(|| unsupported("ZPL range edges exceed 16 MiB of initialized data"))?;
        let Some((existing, _, _)) =
            view.object_data_block(cx, &loaded.dnode, loaded.ceiling, block)?
        else {
            return Err(corrupt("allocated ZPL range block became a hole"));
        };
        let mut bytes = existing.as_ref().clone();
        bytes[within_start..within_end].fill(0);
        dirty.insert(
            block,
            (!bytes.iter().all(|&byte| byte == 0)).then_some(bytes),
        );
    }
    Ok(dirty)
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
    let loaded = decode_zpl_node(cx, os_view, dnode, ceiling, sa_registry)?;
    if loaded.metadata.flags & 1 != 0 {
        return Err(unsupported(
            "cannot directly mutate private ZPL xattr object",
        ));
    }
    Ok(loaded)
}

fn decode_zpl_node(
    cx: &Cx,
    os_view: &mut Objects,
    dnode: Dnode,
    ceiling: u64,
    sa_registry: Option<&SaRegistry>,
) -> Result<LoadedZplNode> {
    if !matches!(
        dnode.object_type(),
        DMU_OT_PLAIN_FILE_CONTENTS | DMU_OT_DIRECTORY_CONTENTS
    ) {
        return Err(unsupported("target object is not a ZPL file or directory"));
    }
    let mut spill_bytes = None;
    let (metadata, project_id) = match dnode.bonus_type() {
        DMU_OT_ZNODE => {
            let metadata =
                Metadata::legacy(dnode.bonus(), dnode.order()).map_err(|e| parse_err(&e))?;
            if metadata.flags & ZFS_PROJID != 0 {
                return Err(corrupt(
                    "legacy ZFS_PROJID flag lacks its project ID attribute",
                ));
            }
            (metadata, 0)
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
            let reg =
                sa_registry.ok_or_else(|| corrupt("SA object on dataset without SA_ATTRS"))?;
            let attrs = reg
                .decode(dnode.bonus(), spill_bytes.as_deref())
                .map_err(|e| parse_err(&e))?;
            let metadata = attrs.metadata().map_err(|e| parse_err(&e))?;
            let stored_project_id = attrs.project_id().map_err(|e| parse_err(&e))?;
            let project_id = if metadata.flags & ZFS_PROJID != 0 {
                stored_project_id
            } else {
                0
            };
            (metadata, project_id)
        }
        _ => return Err(unsupported("unsupported ZPL bonus representation")),
    };
    Ok(LoadedZplNode {
        dnode,
        ceiling,
        metadata,
        project_id,
        spill_bytes,
    })
}

fn file_capability_xattr_update(
    cx: &Cx,
    mos: &mut Objects,
    dataset_components: &[Vec<u8>],
    file_obj: u64,
    loaded: &LoadedZplNode,
    sa_registry: Option<&SaRegistry>,
) -> Result<Option<BTreeMap<String, Vec<u8>>>> {
    checkpoint(cx)?;
    if loaded.metadata.kind != Kind::Regular {
        return Err(unsupported(
            "ZPL file capability removal requires a regular file",
        ));
    }
    let mut source = match loaded.dnode.bonus_type() {
        DMU_OT_ZNODE => XattrSources::legacy(loaded.dnode.bonus(), loaded.dnode.order()),
        DMU_OT_SA => sa_registry
            .ok_or_else(|| corrupt("missing SA registry"))?
            .decode(loaded.dnode.bonus(), loaded.spill_bytes.as_deref())
            .and_then(|attrs| attrs.xattrs()),
        _ => return Err(unsupported("unsupported ZPL bonus representation")),
    }
    .map_err(|error| parse_err(&error))?;
    if source.directory != 0 {
        // Reuse the reader's bounded catalog and private-object ownership
        // checks. A directory shadow cannot survive an SA capability removal.
        return mos
            .zpl(cx, dataset_components)?
            .file_capability_removal_xattrs(cx, file_obj);
    }
    Ok(source
        .inline
        .remove("security.capability")
        .is_some()
        .then_some(source.inline))
}

#[allow(clippy::too_many_arguments)]
fn encode_updated_zpl_bonus_with_options(
    loaded: &LoadedZplNode,
    object_id: u64,
    new_meta: &Metadata,
    ds_ctx: &mut DatasetContext,
    rebuild_trivial_acl: bool,
    inline_xattrs: Option<&BTreeMap<String, Vec<u8>>>,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<(Vec<u8>, Option<BlockPointer>)> {
    let min_blk = (1_usize << alloc.ashift).max(512);
    match loaded.dnode.bonus_type() {
        DMU_OT_ZNODE => {
            if inline_xattrs.is_some() {
                return Err(unsupported(
                    "SA extended attributes require a ZPL v5 SA-formatted object",
                ));
            }
            if rebuild_trivial_acl {
                let ownership = ffs_ondisk::zfs_zpl::ReclamationOwnership::legacy(
                    loaded.dnode.bonus(),
                    loaded.dnode.order(),
                )
                .map_err(|e| parse_err(&e))?;
                if ownership.external_acl_object != 0 {
                    return Err(unsupported(
                        "chmod on a ZPL object with an external ACL object is unavailable",
                    ));
                }
            }
            let bonus = new_meta
                .encode_legacy_with_options(
                    Some(loaded.dnode.bonus()),
                    order,
                    None,
                    rebuild_trivial_acl,
                )
                .map_err(|e| parse_err(&e))?;
            Ok((bonus, None))
        }
        DMU_OT_SA => {
            if rebuild_trivial_acl {
                let reg_ref = ds_ctx
                    .sa_registry
                    .as_ref()
                    .ok_or_else(|| corrupt("missing SA registry"))?;
                let ownership = reg_ref
                    .decode(loaded.dnode.bonus(), loaded.spill_bytes.as_deref())
                    .and_then(|attrs| attrs.reclamation_ownership())
                    .map_err(|e| parse_err(&e))?;
                if ownership.external_acl_object != 0 {
                    return Err(unsupported(
                        "chmod on a ZPL object with an external ACL object is unavailable",
                    ));
                }
            }
            let reg = ds_ctx
                .sa_registry
                .as_mut()
                .ok_or_else(|| corrupt("missing SA registry"))?;
            let prev_reg_len = ds_ctx.sa_reg_entries.len();
            let prev_lay_len = ds_ctx.sa_lay_entries.len();
            let total_dnode_body = loaded.dnode.slots() * DNODE_BYTES - 64;
            let ptr_bytes = loaded.dnode.pointers().len() * 128;
            let max_bonus_no_spill = total_dnode_body.saturating_sub(ptr_bytes);
            let max_bonus_with_spill = max_bonus_no_spill.saturating_sub(128);
            let (new_bonus, maybe_spill) = reg
                .encode_updated_with_options(
                    &mut ds_ctx.sa_reg_entries,
                    &mut ds_ctx.sa_lay_entries,
                    loaded.dnode.bonus(),
                    loaded.spill_bytes.as_deref(),
                    new_meta,
                    rebuild_trivial_acl,
                    inline_xattrs,
                    None,
                    max_bonus_no_spill,
                    max_bonus_with_spill,
                )
                .map_err(|e| parse_err(&e))?;
            if ds_ctx.sa_reg_entries.len() != prev_reg_len {
                ds_ctx.sa_reg_dirty = true;
            }
            if ds_ctx.sa_lay_entries.len() != prev_lay_len {
                ds_ctx.sa_lay_dirty = true;
            }
            let spill_bp = match (loaded.dnode.spill(), maybe_spill, &loaded.spill_bytes) {
                (Some(old_bp), Some(new_raw), Some(old_raw)) => {
                    let target_len = if new_raw.len() <= old_bp.logical_bytes() {
                        old_bp.logical_bytes()
                    } else {
                        new_raw.len().next_power_of_two().max(min_blk).min(SA_BYTES)
                    };
                    let mut padded = vec![0_u8; target_len];
                    padded[..new_raw.len()].copy_from_slice(&new_raw);
                    if padded == *old_raw {
                        Some(old_bp.clone())
                    } else {
                        let bp = write_dataset_block(
                            alloc,
                            &padded,
                            object_id,
                            DMU_SPILL_BLKID,
                            DMU_OT_SA,
                            0,
                            7,
                            order,
                            new_txg,
                            1,
                            WriteBucket::ChildBlocks,
                            ds_ctx.write_crypto.as_mut(),
                            staged_writes,
                        )?;
                        Some(bp)
                    }
                }
                (None, Some(new_raw), _) => {
                    let target_len = new_raw.len().next_power_of_two().max(min_blk).min(SA_BYTES);
                    if target_len < new_raw.len() {
                        return Err(unsupported("SA spill block exceeds 128 KiB"));
                    }
                    let mut padded = vec![0_u8; target_len];
                    padded[..new_raw.len()].copy_from_slice(&new_raw);
                    let bp = write_dataset_block(
                        alloc,
                        &padded,
                        object_id,
                        DMU_SPILL_BLKID,
                        DMU_OT_SA,
                        0,
                        7,
                        order,
                        new_txg,
                        1,
                        WriteBucket::ChildBlocks,
                        ds_ctx.write_crypto.as_mut(),
                        staged_writes,
                    )?;
                    Some(bp)
                }
                _ => None,
            };
            Ok((new_bonus, spill_bp))
        }
        _ => Err(unsupported("unsupported ZPL bonus type")),
    }
}

#[allow(clippy::too_many_arguments)]
fn encode_updated_zpl_bonus(
    loaded: &LoadedZplNode,
    object_id: u64,
    new_meta: &Metadata,
    sa_registry: Option<&SaRegistry>,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    write_crypto: Option<&mut DatasetWriteCrypto>,
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
                        let bp = write_dataset_block(
                            alloc,
                            &padded,
                            object_id,
                            DMU_SPILL_BLKID,
                            DMU_OT_SA,
                            0,
                            7,
                            order,
                            new_txg,
                            1,
                            WriteBucket::ChildBlocks,
                            write_crypto,
                            staged_writes,
                        )?;
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

/// Replace only bonus/spill metadata. Unlike a data-tree COW, this retains the
/// exact indirection and root pointers even when a sparse tree could be collapsed.
/// Changed SA spills still enter the ordinary allocation and deadlist accounting.
fn update_metadata_only_dnode(
    loaded: &LoadedZplNode,
    bonus: Vec<u8>,
    spill: Option<BlockPointer>,
    order: Endian,
) -> Result<DnodeCowOutput> {
    let mut born = SpaceDelta::default();
    let mut retired_bps = Vec::new();
    let mut retired_bytes = 0;
    if loaded.dnode.spill() != spill.as_ref() {
        if let Some(old_spill) = loaded.dnode.spill() {
            retired_bytes = SpaceDelta::from_bp(old_spill)?.dsize;
            retired_bps.push(old_spill.clone());
        }
        if let Some(new_spill) = &spill {
            born = SpaceDelta::from_bp(new_spill)?;
        }
    }
    let used_bytes = loaded
        .dnode
        .used_bytes()
        .checked_add(born.dsize)
        .and_then(|used| used.checked_sub(retired_bytes))
        .ok_or_else(|| corrupt("dnode used_bytes underflow or overflow"))?;
    let dnode = Dnode::from_spec(DnodeSpec {
        object_type: loaded.dnode.object_type(),
        bonus_type: loaded.dnode.bonus_type(),
        checksum_type: loaded.dnode.checksum_type(),
        compress_type: loaded.dnode.compress_type(),
        flags: loaded.dnode.flags(),
        order,
        levels: loaded.dnode.levels(),
        indirect_shift: loaded.dnode.indirect_shift(),
        data_bytes: loaded.dnode.data_bytes(),
        max_block: loaded.dnode.max_block(),
        used_bytes,
        slots: loaded.dnode.slots(),
        pointers: loaded.dnode.pointers().to_vec(),
        bonus,
        spill,
    })
    .map_err(|e| parse_err(&e))?;
    Ok(DnodeCowOutput {
        dnode,
        born,
        retired_bps,
    })
}

/// Encode the compact native FUID ACL for a newly created mode-0777 symlink.
/// OpenZFS skips inherited ACEs for symlinks, then applies chmod-derived masks.
/// These are the three ALLOW ACEs produced by `acl_trivial_access_masks` in
/// OpenZFS zfs-2.3.0 `zfs_acl.c`; no deny ACEs are needed for mode 0777.
fn encode_symlink_acl(bonus: &mut [u8], order: Endian) {
    // znode_phys_t.zp_acl starts at 176; zfs_acl_phys_t has a 16-byte header.
    bonus[176..184].fill(0);
    let (size, version, count) = match order {
        Endian::Little => (
            24_u32.to_le_bytes(),
            1_u16.to_le_bytes(),
            3_u16.to_le_bytes(),
        ),
        Endian::Big => (
            24_u32.to_be_bytes(),
            1_u16.to_be_bytes(),
            3_u16.to_be_bytes(),
        ),
    };
    bonus[184..188].copy_from_slice(&size);
    bonus[188..190].copy_from_slice(&version);
    bonus[190..192].copy_from_slice(&count);
    for (index, (flags, mask)) in [
        (0x1000_u16, 0x001e_01bf_u32), // owner@
        (0x2040_u16, 0x0012_00af_u32), // group@ | ACE_IDENTIFIER_GROUP
        (0x4000_u16, 0x0012_00af_u32), // everyone@
    ]
    .into_iter()
    .enumerate()
    {
        let at = 192 + index * 8;
        let (flags, mask) = match order {
            Endian::Little => (flags.to_le_bytes(), mask.to_le_bytes()),
            Endian::Big => (flags.to_be_bytes(), mask.to_be_bytes()),
        };
        bonus[at..at + 2].fill(0); // ACE_ACCESS_ALLOWED_ACE_TYPE
        bonus[at + 2..at + 4].copy_from_slice(&flags);
        bonus[at + 4..at + 8].copy_from_slice(&mask);
    }
}

fn encode_new_zpl_bonus(
    parent_loaded: &LoadedZplNode,
    new_meta: &Metadata,
    context: &mut DatasetContext,
    order: Endian,
) -> Result<(u8, usize, Vec<u8>, u64)> {
    // zfs_mknode inherits both ID and flag for regular files and directories.
    // Symlinks keep the default project, even inside a project tree.
    if matches!(new_meta.kind, Kind::Regular | Kind::Directory)
        && parent_loaded.metadata.flags & ZFS_PROJINHERIT != 0
    {
        // Native ACL inheritance is independent of project inheritance. Until
        // inherited ACEs are implemented, a fresh mode-only ACL must not replace
        // the parent's inheritable access policy. Native symlinks inherit none.
        if parent_loaded.metadata.flags & ZFS_INHERIT_ACE != 0 {
            return Err(unsupported(
                "project creation with inheritable native ACL entries is unavailable",
            ));
        }
        let mut metadata = new_meta.clone();
        metadata.flags |= ZFS_PROJID | ZFS_PROJINHERIT;
        let registry = context
            .sa_registry
            .as_mut()
            .ok_or_else(|| corrupt("project inheritance lacks an SA registry"))?;
        let registry_len = context.sa_reg_entries.len();
        let layouts_len = context.sa_lay_entries.len();
        let bonus = registry
            .encode_new_with_project(
                &mut context.sa_reg_entries,
                &mut context.sa_lay_entries,
                parent_loaded.dnode.bonus(),
                &metadata,
                Some(parent_loaded.project_id),
            )
            .map_err(|error| parse_err(&error))?;
        context.sa_reg_dirty |= context.sa_reg_entries.len() != registry_len;
        context.sa_lay_dirty |= context.sa_lay_entries.len() != layouts_len;
        return Ok((DMU_OT_SA, 1, bonus, parent_loaded.project_id));
    }
    // Native ZPL v5 also admits legacy znodes. Creating a legacy symlink keeps
    // the target in its native inline/data form without inventing an SA layout
    // or changing the existing parent's SA registry and attributes.
    if new_meta.kind != Kind::Symlink
        && context.zpl_version >= 5
        && parent_loaded.dnode.bonus_type() == DMU_OT_SA
        && let Some(reg) = context.sa_registry.as_ref()
    {
        let bonus = reg
            .encode_new_from_template(parent_loaded.dnode.bonus(), new_meta)
            .map_err(|e| parse_err(&e))?;
        let project_id = reg
            .decode(&bonus, None)
            .and_then(|attrs| attrs.project_id())
            .map_err(|e| parse_err(&e))?;
        return Ok((DMU_OT_SA, 1, bonus, project_id));
    }
    let mut bonus = new_meta
        .encode_legacy(None, order)
        .map_err(|e| parse_err(&e))?;
    if new_meta.kind == Kind::Symlink {
        encode_symlink_acl(&mut bonus, order);
    }
    let nblkptr = super::dmu_cow::max_nblkptr_for_dnode(1, bonus.len(), false)?;
    Ok((DMU_OT_ZNODE, nblkptr, bonus, 0))
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
    dir_obj: u64,
    dir_loaded: &LoadedZplNode,
    new_dir_meta: &Metadata,
    entries: &[RawZapEntry],
    sa_registry: Option<&SaRegistry>,
    acct_flags: u8,
    order: Endian,
    new_txg: u64,
    mut write_crypto: Option<&mut DatasetWriteCrypto>,
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
        dir_obj,
        new_dir_meta,
        sa_registry,
        alloc,
        order,
        new_txg,
        write_crypto.as_deref_mut(),
        staged_writes,
    )?;
    let old_used = dir_loaded.dnode.used_bytes();
    let out = cow_update_dnode_with_crypto(
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
        dir_obj,
        write_crypto,
        staged_writes,
    )?;
    zpl_born.add_assign(out.born)?;
    zpl_retired.extend(out.retired_bps);
    let bytes_delta = signed_bytes_delta(out.dnode.used_bytes(), old_used)?;
    if bytes_delta != 0 {
        quota_deltas.push(QuotaDelta {
            uid: new_dir_meta.uid,
            gid: new_dir_meta.gid,
            projid: Some(dir_loaded.project_id),
            bytes_delta,
            objs_delta: 0,
        });
    }
    Ok(out.dnode)
}

fn read_unlinked_set(
    cx: &Cx,
    view: &mut Objects,
    object: Option<u64>,
) -> Result<(u64, Dnode, u64, Vec<RawZapEntry>)> {
    let object = object.ok_or_else(|| unsupported("ZPL dataset has no native unlinked set"))?;
    let (node, ceiling) = view.object_with_ceiling(cx, object)?;
    if node.object_type() != DMU_OT_UNLINKED_SET || node.bonus_type() != 0 || node.spill().is_some()
    {
        return Err(corrupt("ZPL unlinked set has the wrong native object type"));
    }
    let entries = view.zap_values(cx, object)?;
    if entries.len() > MAX_PENDING_UNLINKS {
        return Err(unsupported(
            "ZPL unlinked set exceeds the reclamation work budget",
        ));
    }
    let mut seen = BTreeSet::new();
    for entry in &entries {
        checkpoint(cx)?;
        let target = entry.scalar().map_err(|e| parse_err(&e))?;
        // OpenZFS zfs-2.3.0 zap_add_int stores an unpadded lowercase hexadecimal
        // name and one uint64 object value, not a directory reference/tag.
        if entry.integer_bytes != 8
            || target == 0
            || target >= (1 << 48) - 1
            || entry.name != format!("{target:x}").as_bytes()
            || !seen.insert(target)
        {
            return Err(corrupt("invalid native ZPL unlinked-set entry"));
        }
    }
    Ok((object, node, ceiling, entries))
}

fn admit_unlinked_file(loaded: &LoadedZplNode, registry: Option<&SaRegistry>) -> Result<()> {
    if loaded.metadata.kind != Kind::Regular {
        return Err(unsupported(
            "native orphan reclamation currently requires a regular file",
        ));
    }
    admit_zpl_reclamation(loaded, registry)
}

fn admit_zpl_reclamation(loaded: &LoadedZplNode, registry: Option<&SaRegistry>) -> Result<()> {
    let ownership = match loaded.dnode.bonus_type() {
        DMU_OT_ZNODE => ffs_ondisk::zfs_zpl::ReclamationOwnership::legacy(
            loaded.dnode.bonus(),
            loaded.dnode.order(),
        )
        .map_err(|e| parse_err(&e))?,
        DMU_OT_SA => registry
            .ok_or_else(|| corrupt("missing SA registry"))?
            .decode(loaded.dnode.bonus(), loaded.spill_bytes.as_deref())
            .and_then(|attrs| attrs.reclamation_ownership())
            .map_err(|e| parse_err(&e))?,
        _ => return Err(unsupported("unsupported orphan bonus representation")),
    };
    if ownership.xattr_directory != 0 {
        return Err(unsupported(
            "ZPL reclamation with a native xattr directory is unavailable",
        ));
    }
    if ownership.external_acl_object != 0 {
        return Err(unsupported(
            "ZPL reclamation with an external ACL object is unavailable",
        ));
    }
    // load_zpl_node validates the native project attribute and its presence
    // flag. Retention and final retirement charge their deltas to that loaded
    // owner, including nonzero project IDs.
    Ok(())
}

fn retain_unlinked_target(
    object: u64,
    loaded: &LoadedZplNode,
    identity: Option<ZfsUnlinkedObject>,
    registry: Option<&SaRegistry>,
) -> Result<bool> {
    let Some(identity) = identity else {
        return Ok(false);
    };
    if identity.object != object || identity.generation != loaded.metadata.generation {
        return Err(FfsError::Io(std::io::Error::from_raw_os_error(
            libc::ESTALE,
        )));
    }
    if loaded.metadata.links == 0 {
        return Err(corrupt(
            "directory entry refers to an already unlinked file",
        ));
    }
    admit_unlinked_file(loaded, registry)?;
    Ok(loaded.metadata.links == 1)
}

/// Inspect the native queue before mount ownership is exposed to callers.
/// This performs no writes and preflights the whole bounded reclamation batch.
pub(super) fn pending_unlinks(
    cx: &Cx,
    mos: &mut Objects,
    dataset_components: &[Vec<u8>],
) -> Result<Vec<ZfsUnlinkedObject>> {
    let mos_txg = mos.txg;
    let (context, mut view) = open_head_dataset_context(cx, mos, dataset_components, mos_txg)?;
    if context.unlinked_set.is_none() {
        return Ok(Vec::new());
    }
    let (_, _, _, entries) = read_unlinked_set(cx, &mut view, context.unlinked_set)?;
    let mut pending = Vec::with_capacity(entries.len());
    for entry in entries {
        let object = entry.values[0];
        let loaded = load_zpl_node(
            cx,
            &mut view,
            &context.os.meta,
            context.old_os_bp.birth(),
            &BTreeMap::new(),
            context.sa_registry.as_ref(),
            object,
            context.os.meta.order(),
        )?;
        if loaded.metadata.links != 0 || object == context.root_dir {
            return Err(corrupt("native unlinked set references a live ZPL object"));
        }
        admit_unlinked_file(&loaded, context.sa_registry.as_ref())?;
        pending.push(ZfsUnlinkedObject {
            object,
            generation: loaded.metadata.generation,
        });
    }
    Ok(pending)
}

#[allow(clippy::too_many_arguments)]
fn stage_unlinked_set_change(
    cx: &Cx,
    view: &mut Objects,
    context: &mut DatasetContext,
    dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    target: u64,
    add: bool,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
    born: &mut SpaceDelta,
    retired: &mut Vec<BlockPointer>,
) -> Result<()> {
    let (object, node, ceiling, mut entries) = read_unlinked_set(cx, view, context.unlinked_set)?;
    let position = entries.iter().position(|entry| entry.values[0] == target);
    if add {
        if position.is_some() {
            return Err(corrupt(
                "linked object is already in the native unlinked set",
            ));
        }
        if entries.len() == MAX_PENDING_UNLINKS {
            return Err(unsupported(
                "native unlinked set is at the reclamation work limit",
            ));
        }
        entries.push(RawZapEntry {
            name: format!("{target:x}").into_bytes(),
            integer_bytes: 8,
            values: vec![target],
            collision: 0,
        });
    } else {
        let position =
            position.ok_or_else(|| FfsError::NotFound("native unlinked object".into()))?;
        entries.remove(position);
    }
    let (block_size, blocks) = encode_zap_blocks_for_dnode(
        cx,
        view,
        Some((&node, ceiling)),
        &entries,
        order,
        (1_usize << alloc.ashift).max(512),
    )?;
    let dirty: BTreeMap<_, _> = blocks
        .into_iter()
        .enumerate()
        .map(|(index, bytes)| (index as u64, Some(bytes)))
        .collect();
    let out = cow_update_dnode_with_crypto(
        cx,
        view,
        alloc,
        DnodeCowSpec {
            existing: Some((&node, ceiling)),
            object_type: DMU_OT_UNLINKED_SET,
            bonus_type: node.bonus_type(),
            checksum_type: 7,
            compress_type: 2,
            user_flags: 0,
            indirect_shift: node.indirect_shift(),
            data_bytes: block_size,
            max_block: (dirty.len() - 1) as u64,
            slots: node.slots(),
            nblkptr: node.pointers().len(),
            bonus: node.bonus().to_vec(),
            spill: None,
            order,
            new_txg,
            leaf_bucket: WriteBucket::ChildBlocks,
            indirect_bucket: WriteBucket::ChildBlocks,
        },
        &dirty,
        object,
        context.write_crypto.as_mut(),
        staged_writes,
    )?;
    born.add_assign(out.born)?;
    retired.extend(out.retired_bps);
    put_dnode_in_table(
        cx,
        view,
        &context.os.meta,
        context.old_os_bp.birth(),
        dirty_dnodes,
        object,
        &out.dnode,
    )
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
    let (mut ds_ctx, mut os_view) =
        open_head_dataset_context(cx, mos, dataset_components, new_txg)?;
    // ObjectSet retains its embedded usage dnodes in the source byte order.
    // Until that tail is converted as a unit, a transaction must not rewrite
    // selected fields and retain the remaining counters in a different order.
    if ds_ctx.os.meta.order() != order {
        return Err(unsupported("rewriting a mixed-order native ZPL object set"));
    }
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
            symlink_target,
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
            admit_directory_add(&parent_loaded, &ds_ctx, write_features)?;
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
            let kind = if symlink_target.is_some() {
                Kind::Symlink
            } else {
                Kind::Regular
            };
            let clean_meta = Metadata {
                mode: (kind.to_tag() << 12) | u64::from((*mode) & 0o7777),
                kind,
                uid: *uid,
                gid: *gid,
                size: symlink_target
                    .as_ref()
                    .map_or(0, |target| target.len() as u64),
                links: 1,
                parent: *parent_dir,
                flags: if kind == Kind::Symlink {
                    ZFS_ACL_TRIVIAL | ZFS_NO_EXECS_DENIED
                } else {
                    0
                },
                generation: new_txg,
                times: [*timestamp; 4],
                inline_symlink: symlink_target
                    .as_ref()
                    .filter(|target| target.len() <= MAX_INLINE_SYMLINK_BYTES)
                    .cloned(),
            };
            let (bonus_type, nblkptr, bonus, project_id) =
                encode_new_zpl_bonus(&parent_loaded, &clean_meta, &mut ds_ctx, order)?;
            let (data_bytes, file_contents) = match symlink_target {
                Some(target) if clean_meta.inline_symlink.is_none() => {
                    let data_bytes = target.len().next_power_of_two().max(min_blk);
                    let mut bytes = vec![0_u8; data_bytes];
                    bytes[..target.len()].copy_from_slice(target);
                    (data_bytes, Some(bytes))
                }
                _ => (min_blk, None),
            };
            let file_dirty = BTreeMap::from([(0, file_contents)]);
            let file_out = cow_update_dnode_with_crypto(
                cx,
                &mut os_view,
                alloc,
                DnodeCowSpec {
                    existing: None,
                    object_type: DMU_OT_PLAIN_FILE_CONTENTS,
                    bonus_type,
                    checksum_type: ds_ctx.data_checksum(*checksum, None)?,
                    compress_type: 2,
                    user_flags: acct_flags,
                    indirect_shift: 17,
                    data_bytes,
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
                new_obj,
                ds_ctx.write_crypto.as_mut(),
                staged_writes,
            )?;
            zpl_born.add_assign(file_out.born)?;
            zpl_retired.extend(file_out.retired_bps);
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
                projid: Some(project_id),
                bytes_delta: signed_bytes_delta(file_dn.used_bytes(), 0)?,
                objs_delta: 1,
            });

            let ref_val = encode_directory_reference(new_obj, kind).map_err(|e| parse_err(&e))?;
            entries.push(RawZapEntry {
                name: name.clone(),
                integer_bytes: 8,
                values: vec![ref_val],
                collision: 0,
            });
            let mut new_parent_meta = parent_loaded.metadata.clone();
            new_parent_meta.size = new_parent_meta
                .size
                .checked_add(1)
                .ok_or_else(|| corrupt("ZPL directory entry count overflow"))?;
            new_parent_meta.times[1] = *timestamp;
            new_parent_meta.times[2] = *timestamp;
            let parent_dn = flush_dir_node(
                cx,
                &mut os_view,
                alloc,
                *parent_dir,
                &parent_loaded,
                &new_parent_meta,
                &entries,
                ds_ctx.sa_registry.as_ref(),
                acct_flags,
                order,
                new_txg,
                ds_ctx.write_crypto.as_mut(),
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
            admit_directory_add(&parent_loaded, &ds_ctx, write_features)?;
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
            let (bonus_type, nblkptr, bonus, project_id) =
                encode_new_zpl_bonus(&parent_loaded, &dir_meta, &mut ds_ctx, order)?;
            let (bsize, blocks) =
                encode_zap_blocks_for_dnode(cx, &mut os_view, None, &[], order, min_blk)?;
            let mut dir_dirty = BTreeMap::new();
            for (i, blk) in blocks.into_iter().enumerate() {
                dir_dirty.insert(i as u64, Some(blk));
            }
            let dir_out = cow_update_dnode_with_crypto(
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
                new_obj,
                ds_ctx.write_crypto.as_mut(),
                staged_writes,
            )?;
            zpl_born.add_assign(dir_out.born)?;
            quota_deltas.push(QuotaDelta {
                uid: *uid,
                gid: *gid,
                projid: Some(project_id),
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

            let ref_val =
                encode_directory_reference(new_obj, Kind::Directory).map_err(|e| parse_err(&e))?;
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
                *parent_dir,
                &parent_loaded,
                &new_parent_meta,
                &entries,
                ds_ctx.sa_registry.as_ref(),
                acct_flags,
                order,
                new_txg,
                ds_ctx.write_crypto.as_mut(),
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

        ZplMutation::LinkEntry {
            source_object,
            parent_dir,
            name,
            timestamp,
        } => {
            validate_component(name, ds_ctx.utf8_only)?;
            let source = load_zpl_node(
                cx,
                &mut os_view,
                &zpl_meta_base,
                zpl_ceiling,
                &zpl_dirty_dnodes,
                ds_ctx.sa_registry.as_ref(),
                *source_object,
                order,
            )?;
            if source.metadata.kind == Kind::Directory {
                return Err(FfsError::RequestRejected {
                    errno: libc::EPERM,
                    detail: "ZPL directories cannot have user-created hard links".into(),
                });
            }
            if source.metadata.kind != Kind::Regular {
                return Err(unsupported(
                    "native hard links currently require a regular file",
                ));
            }
            if source.metadata.links == 0 {
                return Err(FfsError::NotFound("unlinked ZPL source object".into()));
            }
            let new_links =
                source
                    .metadata
                    .links
                    .checked_add(1)
                    .ok_or_else(|| FfsError::RequestRejected {
                        errno: libc::EMLINK,
                        detail: "ZPL native link count is exhausted".into(),
                    })?;
            let parent = load_zpl_node(
                cx,
                &mut os_view,
                &zpl_meta_base,
                zpl_ceiling,
                &zpl_dirty_dnodes,
                ds_ctx.sa_registry.as_ref(),
                *parent_dir,
                order,
            )?;
            if parent.metadata.kind != Kind::Directory {
                return Err(FfsError::NotDirectory);
            }
            reject_flags(&source.metadata, ZFS_IMMUTABLE | ZFS_APPENDONLY)?;
            admit_directory_add(&parent, &ds_ctx, write_features)?;
            admit_project_entry(&parent, &source)?;
            let mut entries = read_dir_entries(cx, &mut os_view, *parent_dir, &staged_dirs)?;
            if entries.iter().any(|entry| entry.name == *name) {
                return Err(FfsError::Exists);
            }
            let mut parent_meta = parent.metadata.clone();
            parent_meta.size = parent_meta
                .size
                .checked_add(1)
                .ok_or_else(|| corrupt("ZPL directory entry count overflow"))?;
            parent_meta.times[1] = *timestamp;
            parent_meta.times[2] = *timestamp;

            // Native ZPL_PARENT is a hint for multiply linked files. OpenZFS
            // updates it to the directory receiving the newest link; it is not
            // an exclusive ownership edge. Preserve data, generation and mtime.
            let mut source_meta = source.metadata.clone();
            source_meta.links = new_links;
            source_meta.parent = *parent_dir;
            source_meta.times[2] = *timestamp;
            let (bonus, spill) = encode_updated_zpl_bonus(
                &source,
                *source_object,
                &source_meta,
                ds_ctx.sa_registry.as_ref(),
                alloc,
                order,
                new_txg,
                ds_ctx.write_crypto.as_mut(),
                staged_writes,
            )?;
            let source_out = cow_update_dnode_with_crypto(
                cx,
                &mut os_view,
                alloc,
                DnodeCowSpec {
                    existing: Some((&source.dnode, source.ceiling)),
                    object_type: source.dnode.object_type(),
                    bonus_type: source.dnode.bonus_type(),
                    checksum_type: source.dnode.checksum_type(),
                    compress_type: source.dnode.compress_type(),
                    user_flags: acct_flags,
                    indirect_shift: source.dnode.indirect_shift(),
                    data_bytes: source.dnode.data_bytes(),
                    max_block: source.dnode.max_block(),
                    slots: source.dnode.slots(),
                    nblkptr: source.dnode.pointers().len(),
                    bonus,
                    spill,
                    order,
                    new_txg,
                    leaf_bucket: WriteBucket::ChildBlocks,
                    indirect_bucket: WriteBucket::ChildBlocks,
                },
                &BTreeMap::new(),
                *source_object,
                ds_ctx.write_crypto.as_mut(),
                staged_writes,
            )?;
            zpl_born.add_assign(source_out.born)?;
            zpl_retired.extend(source_out.retired_bps);
            let bytes_delta =
                signed_bytes_delta(source_out.dnode.used_bytes(), source.dnode.used_bytes())?;
            if bytes_delta != 0 {
                quota_deltas.push(QuotaDelta {
                    uid: source_meta.uid,
                    gid: source_meta.gid,
                    projid: Some(source.project_id),
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
                *source_object,
                &source_out.dnode,
            )?;
            entries.push(RawZapEntry {
                name: name.clone(),
                integer_bytes: 8,
                values: vec![
                    encode_directory_reference(*source_object, Kind::Regular)
                        .map_err(|error| parse_err(&error))?,
                ],
                collision: 0,
            });
            let parent_node = flush_dir_node(
                cx,
                &mut os_view,
                alloc,
                *parent_dir,
                &parent,
                &parent_meta,
                &entries,
                ds_ctx.sa_registry.as_ref(),
                acct_flags,
                order,
                new_txg,
                ds_ctx.write_crypto.as_mut(),
                staged_writes,
                &mut zpl_born,
                &mut zpl_retired,
                &mut quota_deltas,
            )?;
            put_dnode_in_table(
                cx,
                &mut os_view,
                &zpl_meta_base,
                zpl_ceiling,
                &mut zpl_dirty_dnodes,
                *parent_dir,
                &parent_node,
            )?;
            *source_object
        }

        ZplMutation::WriteData {
            file_obj,
            offset,
            data,
            clear_suid_sgid,
            clear_file_capabilities,
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
            // Like native zfs_write, positioned writes to append-only files
            // may start at or beyond EOF but cannot overwrite existing bytes.
            // DOS ZFS_READONLY is an open/access policy, not revocation of an
            // already authorized data-write capability.
            let prohibited = if *offset < loaded.metadata.size {
                ZFS_IMMUTABLE | ZFS_APPENDONLY
            } else {
                ZFS_IMMUTABLE
            };
            reject_flags(&loaded.metadata, prohibited)?;
            let empty_privilege_write = *clear_file_capabilities && data.is_empty();
            let new_size = if empty_privilege_write {
                loaded.metadata.size
            } else {
                loaded.metadata.size.max(end_offset)
            };
            let mut new_meta = loaded.metadata.clone();
            if *clear_suid_sgid && !data.is_empty() {
                new_meta.mode = clear_setid_bits_for_nonroot(new_meta.mode);
            }
            new_meta.size = new_size;
            if !empty_privilege_write {
                new_meta.times[1] = *timestamp;
                new_meta.times[2] = *timestamp;
            }

            if data.is_empty() {
                let dirty_leaves = zero_allocated_range(
                    cx,
                    &mut os_view,
                    &loaded,
                    loaded.metadata.size,
                    new_size,
                )?;
                let (bonus, spill) = encode_updated_zpl_bonus(
                    &loaded,
                    *file_obj,
                    &new_meta,
                    ds_ctx.sa_registry.as_ref(),
                    alloc,
                    order,
                    new_txg,
                    ds_ctx.write_crypto.as_mut(),
                    staged_writes,
                )?;
                let out = cow_update_dnode_with_crypto(
                    cx,
                    &mut os_view,
                    alloc,
                    DnodeCowSpec {
                        existing: Some((&loaded.dnode, loaded.ceiling)),
                        object_type: DMU_OT_PLAIN_FILE_CONTENTS,
                        bonus_type: loaded.dnode.bonus_type(),
                        checksum_type: ds_ctx.data_checksum(*checksum, Some(&loaded.dnode))?,
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
                    &dirty_leaves,
                    *file_obj,
                    ds_ctx.write_crypto.as_mut(),
                    staged_writes,
                )?;
                zpl_born.add_assign(out.born)?;
                zpl_retired.extend(out.retired_bps);
                let bytes_delta =
                    signed_bytes_delta(out.dnode.used_bytes(), loaded.dnode.used_bytes())?;
                if bytes_delta != 0 {
                    quota_deltas.push(QuotaDelta {
                        uid: new_meta.uid,
                        gid: new_meta.gid,
                        projid: Some(loaded.project_id),
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
            // A later reduction of the dataset's recordsize must never shrink an
            // existing block. Reinterpreting its bytes at the smaller geometry
            // would discard the untouched suffix and turn it into holes.
            let old_bsize = loaded.dnode.data_bytes();
            let target_bsize = if loaded.dnode.max_block() > 0 || old_bsize >= ds_ctx.recordsize {
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

            // Existing allocation beyond EOF is not initialized file data.
            // Clear the gap using the old geometry; the single-block growth
            // case below initializes its replacement under the new geometry.
            let mut dirty_leaves = if old_bsize == target_bsize {
                zero_allocated_range(cx, &mut os_view, &loaded, loaded.metadata.size, *offset)?
            } else {
                BTreeMap::new()
            };
            // If block 0 existed at smaller `old_bsize < target_bsize` AND `first_bid > 0`,
            // we MUST also rewrite block 0 zero-extended to `target_bsize`!
            if loaded.dnode.max_block() == 0
                && old_bsize != target_bsize
                && first_bid > 0
                && let Some((old_b0, _, _)) =
                    os_view.object_data_block(cx, &loaded.dnode, loaded.ceiling, 0)?
            {
                let mut grown = vec![0_u8; target_bsize];
                let copy_len = old_b0
                    .len()
                    .min(target_bsize)
                    .min(usize::try_from(loaded.metadata.size).unwrap_or(usize::MAX));
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
                    let visible = loaded.metadata.size.saturating_sub(blk_start);
                    let copy_len = existing_bytes
                        .len()
                        .min(target_bsize)
                        .min(usize::try_from(visible).unwrap_or(usize::MAX));
                    blk[..copy_len].copy_from_slice(&existing_bytes[..copy_len]);
                }
                blk[within..within + count].copy_from_slice(&data[data_off..data_off + count]);
                dirty_leaves.insert(bid, Some(blk));
            }

            let inline_xattrs = if *clear_file_capabilities {
                file_capability_xattr_update(
                    cx,
                    mos,
                    dataset_components,
                    *file_obj,
                    &loaded,
                    ds_ctx.sa_registry.as_ref(),
                )?
            } else {
                None
            };
            let cksum_code = ds_ctx.data_checksum(*checksum, Some(&loaded.dnode))?;
            let (bonus, spill) = encode_updated_zpl_bonus_with_options(
                &loaded,
                *file_obj,
                &new_meta,
                &mut ds_ctx,
                false,
                inline_xattrs.as_ref(),
                alloc,
                order,
                new_txg,
                staged_writes,
            )?;
            let old_used = loaded.dnode.used_bytes();
            let out = cow_update_dnode_with_crypto(
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
                *file_obj,
                ds_ctx.write_crypto.as_mut(),
                staged_writes,
            )?;
            zpl_born.add_assign(out.born)?;
            zpl_retired.extend(out.retired_bps);
            let bytes_delta = signed_bytes_delta(out.dnode.used_bytes(), old_used)?;
            if bytes_delta != 0 {
                quota_deltas.push(QuotaDelta {
                    uid: new_meta.uid,
                    gid: new_meta.gid,
                    projid: Some(loaded.project_id),
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

        ZplMutation::EditRange {
            file_obj,
            offset,
            length,
            operation,
            clear_suid_sgid,
            clear_file_capabilities,
            timestamp,
            checksum,
        } => {
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
            if loaded.metadata.kind == Kind::Directory {
                return Err(FfsError::IsDirectory);
            }
            if loaded.metadata.kind != Kind::Regular {
                return Err(unsupported("ZPL range mutation requires a regular file"));
            }
            reject_flags(
                &loaded.metadata,
                ZFS_IMMUTABLE | ZFS_APPENDONLY | ZFS_READONLY,
            )?;
            let old_size = loaded.metadata.size;
            // The public entry point validates the signed range before staging.
            let requested_end = offset + length;
            let end = if operation.keeps_size() {
                requested_end.min(old_size)
            } else {
                requested_end
            };
            let new_size = old_size.max(end);
            if *offset < end {
                let inline_xattrs = if *clear_file_capabilities {
                    file_capability_xattr_update(
                        cx,
                        mos,
                        dataset_components,
                        *file_obj,
                        &loaded,
                        ds_ctx.sa_registry.as_ref(),
                    )?
                } else {
                    None
                };
                // Extending EOF also exposes the gap before `offset`; zero any
                // allocated tail there rather than trusting bytes beyond old EOF.
                let start = if new_size > old_size {
                    (*offset).min(old_size)
                } else {
                    *offset
                };
                let block_bytes = loaded.dnode.data_bytes();
                let dirty_leaves = zero_allocated_range(cx, &mut os_view, &loaded, start, end)?;
                let mut new_meta = loaded.metadata.clone();
                if *clear_suid_sgid {
                    new_meta.mode = clear_setid_bits_for_nonroot(new_meta.mode);
                }
                new_meta.size = new_size;
                new_meta.times[1] = *timestamp;
                new_meta.times[2] = *timestamp;
                let (bonus, spill) = encode_updated_zpl_bonus_with_options(
                    &loaded,
                    *file_obj,
                    &new_meta,
                    &mut ds_ctx,
                    false,
                    inline_xattrs.as_ref(),
                    alloc,
                    order,
                    new_txg,
                    staged_writes,
                )?;
                let out = cow_update_dnode_with_crypto(
                    cx,
                    &mut os_view,
                    alloc,
                    DnodeCowSpec {
                        existing: Some((&loaded.dnode, loaded.ceiling)),
                        object_type: DMU_OT_PLAIN_FILE_CONTENTS,
                        bonus_type: loaded.dnode.bonus_type(),
                        checksum_type: ds_ctx.data_checksum(*checksum, Some(&loaded.dnode))?,
                        compress_type: loaded.dnode.compress_type(),
                        user_flags: acct_flags,
                        indirect_shift: loaded.dnode.indirect_shift(),
                        data_bytes: block_bytes,
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
                    &dirty_leaves,
                    *file_obj,
                    ds_ctx.write_crypto.as_mut(),
                    staged_writes,
                )?;
                zpl_born.add_assign(out.born)?;
                zpl_retired.extend(out.retired_bps);
                let bytes_delta =
                    signed_bytes_delta(out.dnode.used_bytes(), loaded.dnode.used_bytes())?;
                if bytes_delta != 0 {
                    quota_deltas.push(QuotaDelta {
                        uid: new_meta.uid,
                        gid: new_meta.gid,
                        projid: Some(loaded.project_id),
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
            }
            new_size
        }

        ZplMutation::SetAttributes {
            file_obj,
            attrs,
            timestamp,
            checksum,
        } => {
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
            if attrs.size.is_some() && loaded.metadata.kind != Kind::Regular {
                return Err(unsupported("ZPL truncate requires a regular file"));
            }
            if attrs.mode.is_some() && loaded.metadata.kind == Kind::Symlink {
                return Err(unsupported("ZPL chmod on a symbolic link is not supported"));
            }
            // Native zfs_setattr permits atime-only updates on immutable nodes.
            // DOS readonly and append-only affect truncation, not timestamps/mode/owner.
            if attrs.size.is_some() {
                reject_flags(
                    &loaded.metadata,
                    ZFS_IMMUTABLE | ZFS_APPENDONLY | ZFS_READONLY,
                )?;
            } else if attrs.mtime.is_some()
                || attrs.mode.is_some()
                || attrs.uid.is_some()
                || attrs.gid.is_some()
                || attrs.clear_suid_sgid
                || attrs.clear_file_capabilities
            {
                reject_flags(&loaded.metadata, ZFS_IMMUTABLE)?;
            }
            let old_size = loaded.metadata.size;
            let new_size = attrs.size.unwrap_or(old_size);
            let prev_block_bytes = loaded.dnode.data_bytes();
            let mut dirty_leaves: BTreeMap<u64, Option<Vec<u8>>> = BTreeMap::new();
            let (target_bsize, target_max_block) = if attrs.size.is_none() {
                (prev_block_bytes, loaded.dnode.max_block())
            } else if new_size == 0 {
                dirty_leaves.insert(0, None);
                (min_blk, 0)
            } else if new_size < old_size {
                let last_bid = (new_size - 1) / (prev_block_bytes as u64);
                let new_max = loaded.dnode.max_block().min(last_bid);
                let rem = (new_size as usize) % prev_block_bytes;
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
            } else if new_size > old_size {
                dirty_leaves = zero_allocated_range(cx, &mut os_view, &loaded, old_size, new_size)?;
                (prev_block_bytes, loaded.dnode.max_block())
            } else {
                (prev_block_bytes, loaded.dnode.max_block())
            };

            let mut new_meta = loaded.metadata.clone();
            new_meta.size = new_size;
            if let Some(uid) = attrs.uid {
                new_meta.uid = uid;
            }
            if let Some(gid) = attrs.gid {
                new_meta.gid = gid;
            }
            let owner_changed =
                (loaded.metadata.uid, loaded.metadata.gid) != (new_meta.uid, new_meta.gid);
            // Set-ID bits do not change NFSv4 access masks. Preserve native ACLs
            // when FUSE requests only privilege removal before a data mutation.
            let clears_only_setid = attrs.mode.is_some_and(|mode| {
                let current = loaded.metadata.mode & 0o7777;
                let requested = u64::from(mode) & 0o7777;
                requested != current
                    && requested & !current == 0
                    && (requested ^ current) & !0o6000 == 0
            });
            let rebuild_trivial_acl = attrs.mode.is_some() && !clears_only_setid;
            if let Some(req_mode) = attrs.mode {
                new_meta.mode = (new_meta.mode & !0o7777) | u64::from(req_mode & 0o7777);
                if rebuild_trivial_acl {
                    // Native zfs_fastaccesschk_execute trusts this flag before
                    // checking mode or ACL. A regenerated trivial ACL permits
                    // that shortcut only when every mode class can execute.
                    new_meta.flags = (new_meta.flags | ZFS_ACL_TRIVIAL) & !ZFS_NO_EXECS_DENIED;
                    if new_meta.mode & 0o111 == 0o111 {
                        new_meta.flags |= ZFS_NO_EXECS_DENIED;
                    }
                }
            }
            // A compound data/mode request must not restore privilege bits
            // after the caller requested that the data mutation clear them.
            if (attrs.clear_suid_sgid || (owner_changed && attrs.mode.is_none()))
                && new_meta.kind != Kind::Directory
            {
                new_meta.mode = clear_setid_bits_for_nonroot(new_meta.mode);
            }
            if let Some(atime) = attrs.atime {
                new_meta.times[0] = atime;
            }
            if let Some(mtime) = attrs.mtime {
                new_meta.times[1] = mtime;
            } else if attrs.size.is_some() {
                new_meta.times[1] = *timestamp;
            }
            new_meta.times[2] = *timestamp;
            let inline_xattrs = if attrs.clear_file_capabilities {
                file_capability_xattr_update(
                    cx,
                    mos,
                    dataset_components,
                    *file_obj,
                    &loaded,
                    ds_ctx.sa_registry.as_ref(),
                )?
            } else {
                None
            };
            let (bonus, spill) = encode_updated_zpl_bonus_with_options(
                &loaded,
                *file_obj,
                &new_meta,
                &mut ds_ctx,
                rebuild_trivial_acl,
                inline_xattrs.as_ref(),
                alloc,
                order,
                new_txg,
                staged_writes,
            )?;
            let old_used = loaded.dnode.used_bytes();
            let out = if attrs.size.is_some() {
                cow_update_dnode_with_crypto(
                    cx,
                    &mut os_view,
                    alloc,
                    DnodeCowSpec {
                        existing: Some((&loaded.dnode, loaded.ceiling)),
                        object_type: DMU_OT_PLAIN_FILE_CONTENTS,
                        bonus_type: loaded.dnode.bonus_type(),
                        checksum_type: ds_ctx.data_checksum(*checksum, Some(&loaded.dnode))?,
                        compress_type: loaded.dnode.compress_type(),
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
                    *file_obj,
                    ds_ctx.write_crypto.as_mut(),
                    staged_writes,
                )?
            } else {
                update_metadata_only_dnode(&loaded, bonus, spill, order)?
            };
            zpl_born.add_assign(out.born)?;
            zpl_retired.extend(out.retired_bps);
            if owner_changed {
                quota_deltas.push(QuotaDelta {
                    uid: loaded.metadata.uid,
                    gid: loaded.metadata.gid,
                    projid: Some(loaded.project_id),
                    bytes_delta: -i64::try_from(old_used)
                        .map_err(|_| corrupt("ZFS quota bytes_delta overflow"))?,
                    objs_delta: -1,
                });
                quota_deltas.push(QuotaDelta {
                    uid: new_meta.uid,
                    gid: new_meta.gid,
                    projid: Some(loaded.project_id),
                    bytes_delta: i64::try_from(out.dnode.used_bytes())
                        .map_err(|_| corrupt("ZFS quota bytes_delta overflow"))?,
                    objs_delta: 1,
                });
            } else {
                let bytes_delta = signed_bytes_delta(out.dnode.used_bytes(), old_used)?;
                if bytes_delta != 0 {
                    quota_deltas.push(QuotaDelta {
                        uid: new_meta.uid,
                        gid: new_meta.gid,
                        projid: Some(loaded.project_id),
                        bytes_delta,
                        objs_delta: 0,
                    });
                }
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

        ZplMutation::SetXattr {
            target_obj,
            name,
            value,
            mode,
            timestamp,
        } => {
            stage_sa_xattr_mutation(
                cx,
                &mut os_view,
                &zpl_meta_base,
                zpl_ceiling,
                &mut zpl_dirty_dnodes,
                &mut ds_ctx,
                *target_obj,
                name,
                Some((value.as_slice(), *mode)),
                *timestamp,
                alloc,
                order,
                new_txg,
                staged_writes,
                &mut zpl_born,
                &mut zpl_retired,
                &mut quota_deltas,
            )?;
            *target_obj
        }

        ZplMutation::RemoveXattr {
            target_obj,
            name,
            timestamp,
        } => {
            stage_sa_xattr_mutation(
                cx,
                &mut os_view,
                &zpl_meta_base,
                zpl_ceiling,
                &mut zpl_dirty_dnodes,
                &mut ds_ctx,
                *target_obj,
                name,
                None,
                *timestamp,
                alloc,
                order,
                new_txg,
                staged_writes,
                &mut zpl_born,
                &mut zpl_retired,
                &mut quota_deltas,
            )?;
            *target_obj
        }

        ZplMutation::RenameEntry {
            src_dir,
            src_name,
            dst_dir,
            dst_name,
            expected_source_object,
            retain_replaced,
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
            let src_ref = src_entries[src_pos].scalar().map_err(|e| parse_err(&e))?;
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
            admit_directory_remove(&src_parent.metadata, &src_obj_loaded.metadata)?;
            admit_directory_add(&dst_parent, &ds_ctx, write_features)?;
            admit_project_entry(&dst_parent, &src_obj_loaded)?;

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
                let dst_ref = dst_entries[dst_pos].scalar().map_err(|e| parse_err(&e))?;
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
                admit_directory_remove(&dst_parent.metadata, &target_loaded.metadata)?;
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
                let retain = retain_unlinked_target(
                    target_obj,
                    &target_loaded,
                    *retain_replaced,
                    ds_ctx.sa_registry.as_ref(),
                )?;
                if retain {
                    stage_unlinked_set_change(
                        cx,
                        &mut os_view,
                        &mut ds_ctx,
                        &mut zpl_dirty_dnodes,
                        target_obj,
                        true,
                        alloc,
                        order,
                        new_txg,
                        staged_writes,
                        &mut zpl_born,
                        &mut zpl_retired,
                    )?;
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
                    retain,
                    ds_ctx.sa_registry.as_ref(),
                    acct_flags,
                    alloc,
                    order,
                    new_txg,
                    *timestamp,
                    ds_ctx.write_crypto.as_mut(),
                    staged_writes,
                    &mut zpl_born,
                    &mut zpl_retired,
                    &mut quota_deltas,
                )?;
            } else if retain_replaced.is_some() {
                return Err(FfsError::NotFound("expected ZPL rename replacement".into()));
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
                    *src_dir,
                    &src_parent,
                    &p_meta,
                    &dst_entries,
                    ds_ctx.sa_registry.as_ref(),
                    acct_flags,
                    order,
                    new_txg,
                    ds_ctx.write_crypto.as_mut(),
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
                    *src_dir,
                    &src_parent,
                    &sp_meta,
                    &src_entries,
                    ds_ctx.sa_registry.as_ref(),
                    acct_flags,
                    order,
                    new_txg,
                    ds_ctx.write_crypto.as_mut(),
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
                    *dst_dir,
                    &dst_parent,
                    &dp_meta,
                    &dst_entries,
                    ds_ctx.sa_registry.as_ref(),
                    acct_flags,
                    order,
                    new_txg,
                    ds_ctx.write_crypto.as_mut(),
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
            moved_meta.flags |= dst_parent.metadata.flags & ZFS_PROJINHERIT;
            let (m_bonus, m_spill) = encode_updated_zpl_bonus(
                &src_obj_loaded,
                source_obj,
                &moved_meta,
                ds_ctx.sa_registry.as_ref(),
                alloc,
                order,
                new_txg,
                ds_ctx.write_crypto.as_mut(),
                staged_writes,
            )?;
            let m_out = cow_update_dnode_with_crypto(
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
                source_obj,
                ds_ctx.write_crypto.as_mut(),
                staged_writes,
            )?;
            zpl_born.add_assign(m_out.born)?;
            zpl_retired.extend(m_out.retired_bps);
            let moved_delta =
                signed_bytes_delta(m_out.dnode.used_bytes(), src_obj_loaded.dnode.used_bytes())?;
            if moved_delta != 0 {
                quota_deltas.push(QuotaDelta {
                    uid: moved_meta.uid,
                    gid: moved_meta.gid,
                    projid: Some(src_obj_loaded.project_id),
                    bytes_delta: moved_delta,
                    objs_delta: 0,
                });
            }
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

        ZplMutation::ExchangeEntries {
            src_dir,
            src_name,
            dst_dir,
            dst_name,
            source,
            target,
            timestamp,
        } => {
            validate_component(src_name, ds_ctx.utf8_only)?;
            validate_component(dst_name, ds_ctx.utf8_only)?;
            let mut parents = Vec::with_capacity(2);
            for &parent in &[*src_dir, *dst_dir] {
                let loaded = load_zpl_node(
                    cx,
                    &mut os_view,
                    &zpl_meta_base,
                    zpl_ceiling,
                    &zpl_dirty_dnodes,
                    ds_ctx.sa_registry.as_ref(),
                    parent,
                    order,
                )?;
                if loaded.metadata.kind != Kind::Directory {
                    return Err(FfsError::NotDirectory);
                }
                parents.push(loaded);
            }
            let mut entries = vec![read_dir_entries(cx, &mut os_view, *src_dir, &staged_dirs)?];
            entries.push(if src_dir == dst_dir {
                entries[0].clone()
            } else {
                read_dir_entries(cx, &mut os_view, *dst_dir, &staged_dirs)?
            });
            let mut positions = [0; 2];
            let mut nodes = Vec::with_capacity(2);
            for (index, (name, identity)) in [(src_name, source), (dst_name, target)]
                .into_iter()
                .enumerate()
            {
                let position = entries[index]
                    .iter()
                    .position(|entry| entry.name == *name)
                    .ok_or_else(|| {
                        FfsError::NotFound(String::from_utf8_lossy(name).into_owned())
                    })?;
                let reference = entries[index][position]
                    .scalar()
                    .map_err(|e| parse_err(&e))?;
                let (object, kind) = directory_reference(reference).map_err(|e| parse_err(&e))?;
                if object != identity.object {
                    return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                        libc::ESTALE,
                    )));
                }
                if object == ds_ctx.root_dir {
                    return Err(FfsError::PermissionDenied);
                }
                let loaded = load_zpl_node(
                    cx,
                    &mut os_view,
                    &zpl_meta_base,
                    zpl_ceiling,
                    &zpl_dirty_dnodes,
                    ds_ctx.sa_registry.as_ref(),
                    object,
                    order,
                )?;
                if loaded.metadata.generation != identity.generation {
                    return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                        libc::ESTALE,
                    )));
                }
                if loaded.metadata.links == 0
                    || kind.is_some_and(|kind| kind != loaded.metadata.kind)
                    || (loaded.metadata.kind == Kind::Directory
                        && loaded.metadata.parent != [*src_dir, *dst_dir][index])
                {
                    return Err(corrupt(
                        "ZPL exchange entry disagrees with its native object",
                    ));
                }
                // Both names are removed and replaced. In particular, an
                // append-only parent cannot accept an exchange as an insertion.
                admit_directory_remove(&parents[index].metadata, &loaded.metadata)?;
                admit_directory_add(&parents[1 - index], &ds_ctx, write_features)?;
                // Preserve project-tree membership in both directions. This
                // bounded profile also refuses the reverse mismatch that the
                // pinned native implementation's one-sided check overlooks.
                admit_project_entry(&parents[1 - index], &loaded)?;
                positions[index] = position;
                nodes.push(loaded);
            }
            if source.object == target.object {
                return Ok(source.object);
            }

            // Check BOTH proposed parent edges before staging any COW writes.
            // Swapping an ancestor and descendant must not turn either side
            // into a cycle, even when the other entry is a regular file.
            if src_dir != dst_dir {
                for (node, new_parent, identity) in
                    [(&nodes[0], *dst_dir, source), (&nodes[1], *src_dir, target)]
                {
                    if node.metadata.kind != Kind::Directory {
                        continue;
                    }
                    let mut current = new_parent;
                    let mut seen = BTreeSet::new();
                    loop {
                        checkpoint(cx)?;
                        if current == identity.object {
                            return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                                libc::EINVAL,
                            )));
                        }
                        if !seen.insert(current) || seen.len() > MAX_PATH_DEPTH {
                            return Err(corrupt("invalid ZPL exchange directory ancestry"));
                        }
                        if current == ds_ctx.root_dir {
                            break;
                        }
                        let ancestor = load_zpl_node(
                            cx,
                            &mut os_view,
                            &zpl_meta_base,
                            zpl_ceiling,
                            &zpl_dirty_dnodes,
                            ds_ctx.sa_registry.as_ref(),
                            current,
                            order,
                        )?;
                        if ancestor.metadata.kind != Kind::Directory {
                            return Err(corrupt("ZPL exchange ancestor is not a directory"));
                        }
                        current = ancestor.metadata.parent;
                    }
                }
            }

            let references = [
                encode_directory_reference(source.object, nodes[0].metadata.kind)
                    .map_err(|e| parse_err(&e))?,
                encode_directory_reference(target.object, nodes[1].metadata.kind)
                    .map_err(|e| parse_err(&e))?,
            ];
            // Preserve each name and its ZAP collision identity. Only its
            // native object/type value changes; no object is retired or linked.
            entries[0][positions[0]].values[0] = references[1];
            if src_dir == dst_dir {
                entries[0][positions[1]].values[0] = references[0];
            } else {
                entries[1][positions[1]].values[0] = references[0];
            }
            let parent_count = if src_dir == dst_dir { 1 } else { 2 };
            for index in 0..parent_count {
                let mut metadata = parents[index].metadata.clone();
                if src_dir != dst_dir {
                    let outgoing = u64::from(nodes[index].metadata.kind == Kind::Directory);
                    let incoming = u64::from(nodes[1 - index].metadata.kind == Kind::Directory);
                    metadata.links = metadata
                        .links
                        .checked_sub(outgoing)
                        .and_then(|links| links.checked_add(incoming))
                        .filter(|&links| links >= 2)
                        .ok_or_else(|| corrupt("ZPL exchange parent link count is invalid"))?;
                }
                metadata.times[1] = *timestamp;
                metadata.times[2] = *timestamp;
                let dnode = flush_dir_node(
                    cx,
                    &mut os_view,
                    alloc,
                    [*src_dir, *dst_dir][index],
                    &parents[index],
                    &metadata,
                    &entries[index],
                    ds_ctx.sa_registry.as_ref(),
                    acct_flags,
                    order,
                    new_txg,
                    ds_ctx.write_crypto.as_mut(),
                    staged_writes,
                    &mut zpl_born,
                    &mut zpl_retired,
                    &mut quota_deltas,
                )?;
                put_dnode_in_table(
                    cx,
                    &mut os_view,
                    &zpl_meta_base,
                    zpl_ceiling,
                    &mut zpl_dirty_dnodes,
                    [*src_dir, *dst_dir][index],
                    &dnode,
                )?;
            }
            for (index, loaded) in nodes.iter().enumerate() {
                let obj_id = [source.object, target.object][index];
                let mut metadata = loaded.metadata.clone();
                metadata.parent = [*dst_dir, *src_dir][index];
                metadata.times[2] = *timestamp;
                metadata.flags |= parents[1 - index].metadata.flags & ZFS_PROJINHERIT;
                let (bonus, spill) = encode_updated_zpl_bonus(
                    loaded,
                    obj_id,
                    &metadata,
                    ds_ctx.sa_registry.as_ref(),
                    alloc,
                    order,
                    new_txg,
                    ds_ctx.write_crypto.as_mut(),
                    staged_writes,
                )?;
                let out = cow_update_dnode_with_crypto(
                    cx,
                    &mut os_view,
                    alloc,
                    DnodeCowSpec {
                        existing: Some((&loaded.dnode, loaded.ceiling)),
                        object_type: loaded.dnode.object_type(),
                        bonus_type: loaded.dnode.bonus_type(),
                        checksum_type: 7,
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
                    obj_id,
                    ds_ctx.write_crypto.as_mut(),
                    staged_writes,
                )?;
                zpl_born.add_assign(out.born)?;
                zpl_retired.extend(out.retired_bps);
                let bytes_delta =
                    signed_bytes_delta(out.dnode.used_bytes(), loaded.dnode.used_bytes())?;
                if bytes_delta != 0 {
                    quota_deltas.push(QuotaDelta {
                        uid: metadata.uid,
                        gid: metadata.gid,
                        projid: Some(loaded.project_id),
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
                    [source.object, target.object][index],
                    &out.dnode,
                )?;
            }
            source.object
        }

        ZplMutation::UnlinkEntry {
            parent_dir,
            name,
            rmdir,
            retain,
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
            admit_directory_remove(&parent_loaded.metadata, &target_loaded.metadata)?;
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
            let retain = retain_unlinked_target(
                target_obj,
                &target_loaded,
                *retain,
                ds_ctx.sa_registry.as_ref(),
            )?;
            if retain {
                stage_unlinked_set_change(
                    cx,
                    &mut os_view,
                    &mut ds_ctx,
                    &mut zpl_dirty_dnodes,
                    target_obj,
                    true,
                    alloc,
                    order,
                    new_txg,
                    staged_writes,
                    &mut zpl_born,
                    &mut zpl_retired,
                )?;
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
                *parent_dir,
                &parent_loaded,
                &p_meta,
                &entries,
                ds_ctx.sa_registry.as_ref(),
                acct_flags,
                order,
                new_txg,
                ds_ctx.write_crypto.as_mut(),
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
                retain,
                ds_ctx.sa_registry.as_ref(),
                acct_flags,
                alloc,
                order,
                new_txg,
                *timestamp,
                ds_ctx.write_crypto.as_mut(),
                staged_writes,
                &mut zpl_born,
                &mut zpl_retired,
                &mut quota_deltas,
            )?;
            target_obj
        }
        ZplMutation::ReapUnlinked { identity } => {
            let (_, _, _, entries) = read_unlinked_set(cx, &mut os_view, ds_ctx.unlinked_set)?;
            if !entries
                .iter()
                .any(|entry| entry.values[0] == identity.object)
            {
                return Err(FfsError::NotFound("native unlinked object".into()));
            }
            let loaded = load_zpl_node(
                cx,
                &mut os_view,
                &zpl_meta_base,
                zpl_ceiling,
                &zpl_dirty_dnodes,
                ds_ctx.sa_registry.as_ref(),
                identity.object,
                order,
            )?;
            if loaded.metadata.generation != identity.generation {
                return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                    libc::ESTALE,
                )));
            }
            if loaded.metadata.links != 0 || identity.object == ds_ctx.root_dir {
                return Err(corrupt("native unlinked set references a live ZPL object"));
            }
            admit_unlinked_file(&loaded, ds_ctx.sa_registry.as_ref())?;
            retire_or_decrement_zpl_target(
                cx,
                &mut os_view,
                &zpl_meta_base,
                zpl_ceiling,
                &mut zpl_dirty_dnodes,
                identity.object,
                &loaded,
                false,
                false,
                ds_ctx.sa_registry.as_ref(),
                acct_flags,
                alloc,
                order,
                new_txg,
                loaded.metadata.times[2],
                ds_ctx.write_crypto.as_mut(),
                staged_writes,
                &mut zpl_born,
                &mut zpl_retired,
                &mut quota_deltas,
            )?;
            stage_unlinked_set_change(
                cx,
                &mut os_view,
                &mut ds_ctx,
                &mut zpl_dirty_dnodes,
                identity.object,
                false,
                alloc,
                order,
                new_txg,
                staged_writes,
                &mut zpl_born,
                &mut zpl_retired,
            )?;
            identity.object
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
    retain_unlinked: bool,
    sa_registry: Option<&SaRegistry>,
    acct_flags: u8,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    timestamp: Timestamp,
    mut write_crypto: Option<&mut DatasetWriteCrypto>,
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
    if rem_links > 0 || retain_unlinked {
        let mut next_meta = target_loaded.metadata.clone();
        next_meta.links = rem_links;
        next_meta.times[2] = timestamp;
        let (bonus, spill) = encode_updated_zpl_bonus(
            target_loaded,
            target_obj,
            &next_meta,
            sa_registry,
            alloc,
            order,
            new_txg,
            write_crypto.as_deref_mut(),
            staged_writes,
        )?;
        let out = cow_update_dnode_with_crypto(
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
            target_obj,
            write_crypto,
            staged_writes,
        )?;
        zpl_born.add_assign(out.born)?;
        zpl_retired.extend(out.retired_bps);
        let bytes_delta =
            signed_bytes_delta(out.dnode.used_bytes(), target_loaded.dnode.used_bytes())?;
        if bytes_delta != 0 {
            quota_deltas.push(QuotaDelta {
                uid: next_meta.uid,
                gid: next_meta.gid,
                projid: Some(target_loaded.project_id),
                bytes_delta,
                objs_delta: 0,
            });
        }
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

    // The data tree and SA spill do not own private xattr directories or legacy
    // external ACL objects. Require their cleanup support before final unlink,
    // replacement, or reap. Nonfinal decrements above preserve these owners.
    admit_zpl_reclamation(target_loaded, sa_registry)?;

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
        projid: Some(target_loaded.project_id),
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

fn is_reserved_xattr_prefix(name: &[u8]) -> bool {
    [
        b"freebsd:".as_slice(),
        b"security.",
        b"system.",
        b"trusted.",
        b"user.",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

#[allow(clippy::too_many_arguments)]
fn stage_sa_xattr_mutation(
    cx: &Cx,
    os_view: &mut Objects,
    zpl_meta_base: &Dnode,
    zpl_ceiling: u64,
    zpl_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    ds_ctx: &mut DatasetContext,
    target_obj: u64,
    name: &str,
    set_op: Option<(&[u8], ZfsXattrSetMode)>,
    timestamp: Timestamp,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
    zpl_born: &mut SpaceDelta,
    zpl_retired: &mut Vec<BlockPointer>,
    quota_deltas: &mut Vec<QuotaDelta>,
) -> Result<()> {
    if timestamp.nanos >= 1_000_000_000 {
        return Err(FfsError::Format("invalid ZPL nanoseconds".into()));
    }
    if name.len() > XATTR_NAME_BYTES {
        return Err(FfsError::NameTooLong);
    }
    let Some(suffix) = name.strip_prefix("user.") else {
        return Err(unsupported("only the ZPL user xattr namespace is exposed"));
    };
    if suffix.is_empty()
        || suffix.as_bytes().contains(&0)
        || is_reserved_xattr_prefix(suffix.as_bytes())
    {
        return Err(FfsError::Format("invalid user xattr suffix".into()));
    }
    if let Some((val, _)) = set_op
        && val.len() > XATTR_BYTES
    {
        return Err(FfsError::RequestRejected {
            errno: libc::E2BIG,
            detail: "ZPL user xattr value exceeds 64 KiB".into(),
        });
    }

    let loaded = load_zpl_node(
        cx,
        os_view,
        zpl_meta_base,
        zpl_ceiling,
        zpl_dirty_dnodes,
        ds_ctx.sa_registry.as_ref(),
        target_obj,
        order,
    )?;
    reject_flags(
        &loaded.metadata,
        ZFS_IMMUTABLE | ZFS_APPENDONLY | ZFS_READONLY,
    )?;
    if loaded.dnode.bonus_type() != DMU_OT_SA || ds_ctx.zpl_version < 5 {
        return Err(unsupported(
            "native ZPL xattr writes require a ZPL v5 SA-formatted object",
        ));
    }

    let XattrSources {
        directory: xattr_dir,
        mut inline,
    } = ds_ctx
        .sa_registry
        .as_ref()
        .ok_or_else(|| corrupt("missing SA registry"))?
        .decode(loaded.dnode.bonus(), loaded.spill_bytes.as_deref())
        .and_then(|attrs| attrs.xattrs())
        .map_err(|e| parse_err(&e))?;

    if xattr_dir != 0 {
        let dir_entries = os_view.zap_values(cx, xattr_dir)?;
        if dir_entries
            .iter()
            .any(|e| e.name == name.as_bytes() || e.name == suffix.as_bytes())
        {
            return Err(unsupported(
                "mutating legacy directory-backed xattr entries on an SA object is unavailable",
            ));
        }
    }

    let existed = inline.contains_key(name) || inline.contains_key(suffix);
    if let Some((val, mode)) = set_op {
        match mode {
            ZfsXattrSetMode::Create if existed => return Err(FfsError::Exists),
            ZfsXattrSetMode::Replace if !existed => {
                return Err(FfsError::RequestRejected {
                    errno: libc::ENODATA,
                    detail: "ZPL user xattr not found".into(),
                });
            }
            _ => {}
        }
        inline.remove(suffix);
        inline.insert(name.to_owned(), val.to_vec());
        if inline.len() > XATTR_COUNT {
            return Err(FfsError::NoSpace);
        }
    } else {
        let removed_prefixed = inline.remove(name).is_some();
        let removed_compat = inline.remove(suffix).is_some();
        if !removed_prefixed && !removed_compat {
            return Err(FfsError::RequestRejected {
                errno: libc::ENODATA,
                detail: "ZPL user xattr not found".into(),
            });
        }
    }

    let mut new_meta = loaded.metadata.clone();
    new_meta.times[2] = timestamp;
    let (bonus, spill) = encode_updated_zpl_bonus_with_options(
        &loaded,
        target_obj,
        &new_meta,
        ds_ctx,
        false,
        Some(&inline),
        alloc,
        order,
        new_txg,
        staged_writes,
    )?;
    let old_used = loaded.dnode.used_bytes();
    let out = update_metadata_only_dnode(&loaded, bonus, spill, order)?;
    zpl_born.add_assign(out.born)?;
    zpl_retired.extend(out.retired_bps);
    let bytes_delta = signed_bytes_delta(out.dnode.used_bytes(), old_used)?;
    if bytes_delta != 0 {
        quota_deltas.push(QuotaDelta {
            uid: new_meta.uid,
            gid: new_meta.gid,
            projid: Some(loaded.project_id),
            bytes_delta,
            objs_delta: 0,
        });
    }
    put_dnode_in_table(
        cx,
        os_view,
        zpl_meta_base,
        zpl_ceiling,
        zpl_dirty_dnodes,
        target_obj,
        &out.dnode,
    )
}

#[allow(clippy::too_many_arguments)]
fn flush_sa_table_zap(
    cx: &Cx,
    os_view: &mut Objects,
    zpl_meta_base: &Dnode,
    zpl_ceiling: u64,
    zpl_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    obj_id: u64,
    expected_type: u8,
    entries: &[RawZapEntry],
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    write_crypto: Option<&mut DatasetWriteCrypto>,
    staged_writes: &mut Vec<StagedBlockWrite>,
    zpl_born: &mut SpaceDelta,
    zpl_retired: &mut Vec<BlockPointer>,
) -> Result<()> {
    let (existing_dn, ceiling) = read_staged_or_committed_dnode(
        cx,
        os_view,
        zpl_meta_base,
        zpl_ceiling,
        zpl_dirty_dnodes,
        obj_id,
        order,
    )?;
    if existing_dn.object_type() != expected_type {
        return Err(corrupt("SA registry/layout ZAP has unexpected object type"));
    }
    let min_blk = (1_usize << alloc.ashift).max(512);
    let (bsize, blocks) = encode_zap_blocks_for_dnode(
        cx,
        os_view,
        Some((&existing_dn, ceiling)),
        entries,
        order,
        min_blk,
    )?;
    let dirty: BTreeMap<_, _> = blocks
        .into_iter()
        .enumerate()
        .map(|(i, b)| (i as u64, Some(b)))
        .collect();
    let out = cow_update_dnode_with_crypto(
        cx,
        os_view,
        alloc,
        DnodeCowSpec {
            existing: Some((&existing_dn, ceiling)),
            object_type: expected_type,
            bonus_type: existing_dn.bonus_type(),
            checksum_type: 7,
            compress_type: 2,
            user_flags: 0,
            indirect_shift: existing_dn.indirect_shift(),
            data_bytes: bsize,
            max_block: (dirty.len() - 1) as u64,
            slots: existing_dn.slots(),
            nblkptr: existing_dn.pointers().len(),
            bonus: existing_dn.bonus().to_vec(),
            spill: None,
            order,
            new_txg,
            leaf_bucket: WriteBucket::ChildBlocks,
            indirect_bucket: WriteBucket::ChildBlocks,
        },
        &dirty,
        obj_id,
        write_crypto,
        staged_writes,
    )?;
    zpl_born.add_assign(out.born)?;
    zpl_retired.extend(out.retired_bps);
    put_dnode_in_table(
        cx,
        os_view,
        zpl_meta_base,
        zpl_ceiling,
        zpl_dirty_dnodes,
        obj_id,
        &out.dnode,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_owner_quota_preimages(
    cx: &Cx,
    ds_ctx: &DatasetContext,
    os_view: &mut Objects,
    meta: &Dnode,
    ceiling: u64,
    dirty: &BTreeMap<u64, Vec<u8>>,
    order: Endian,
) -> Result<()> {
    if !ds_ctx.owner_quota_limits.active {
        return Ok(());
    }
    let mut existing = Vec::new();
    for (&block, bytes) in dirty {
        // Inspect each committed object once, including deletions and owners
        // that cancel to zero in the transaction's aggregate usage change.
        if let Some((old, old_order, old_ceiling)) =
            os_view.object_data_block(cx, meta, ceiling, block)?
        {
            ds_ctx
                .owner_quota_limits
                .validate_dnode_table(&ds_ctx.os, &old, old_order)?;
            let mut slot = 0;
            while slot < old.len() / DNODE_BYTES {
                checkpoint(cx)?;
                let Some(node) =
                    dnode_at(&old, slot, old_order).map_err(|error| parse_err(&error))?
                else {
                    slot += 1;
                    continue;
                };
                slot += node.slots();
                if matches!(
                    node.object_type(),
                    DMU_OT_PLAIN_FILE_CONTENTS | DMU_OT_DIRECTORY_CONTENTS
                ) {
                    let loaded = decode_zpl_node(
                        cx,
                        os_view,
                        node,
                        old_ceiling,
                        ds_ctx.sa_registry.as_ref(),
                    )?;
                    existing.push(QuotaDelta {
                        uid: loaded.metadata.uid,
                        gid: loaded.metadata.gid,
                        projid: Some(loaded.project_id),
                        bytes_delta: i64::try_from(loaded.dnode.used_bytes()).map_err(|_| {
                            corrupt("existing native owner usage exceeds supported range")
                        })?,
                        objs_delta: 1,
                    });
                }
            }
        }
        ds_ctx
            .owner_quota_limits
            .validate_dnode_table(&ds_ctx.os, bytes, order)?;
    }
    ds_ctx
        .owner_quota_limits
        .validate_existing_usage(&existing, ds_ctx.os.flags & 2 != 0)
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
    let mut all_zpl_dirty = zpl_dirty_dnodes.clone();

    validate_owner_quota_preimages(
        cx,
        ds_ctx,
        os_view,
        zpl_meta_base,
        zpl_ceiling,
        zpl_dirty_dnodes,
        order,
    )?;

    if ds_ctx.sa_reg_dirty
        && let Some(reg_obj) = ds_ctx.sa_reg_obj
    {
        flush_sa_table_zap(
            cx,
            os_view,
            zpl_meta_base,
            zpl_ceiling,
            &mut all_zpl_dirty,
            reg_obj,
            DMU_OT_SA_ATTR_REGISTRATION,
            &ds_ctx.sa_reg_entries,
            alloc,
            order,
            new_txg,
            ds_ctx.write_crypto.as_mut(),
            staged_writes,
            &mut zpl_born,
            &mut zpl_retired,
        )?;
    }
    if ds_ctx.sa_lay_dirty
        && let Some(lay_obj) = ds_ctx.sa_lay_obj
    {
        flush_sa_table_zap(
            cx,
            os_view,
            zpl_meta_base,
            zpl_ceiling,
            &mut all_zpl_dirty,
            lay_obj,
            DMU_OT_SA_ATTR_LAYOUTS,
            &ds_ctx.sa_lay_entries,
            alloc,
            order,
            new_txg,
            ds_ctx.write_crypto.as_mut(),
            staged_writes,
            &mut zpl_born,
            &mut zpl_retired,
        )?;
    }

    // 1. Update embedded ObjectSet quota ZAPs (`userused` / `groupused` / `projectused`) if active.
    apply_objectset_quota_deltas(
        cx,
        os_view,
        &mut ds_ctx.os,
        alloc,
        quota_deltas,
        &ds_ctx.owner_quota_limits,
        order,
        new_txg,
        ds_ctx.write_crypto.as_mut(),
        staged_writes,
        &mut zpl_born,
        &mut zpl_retired,
    )?;

    // 2. COW the ZPL `os_meta_dnode` (`DMU_OT_DNODE`) and ZPL `ObjectSet` root (`DMU_OT_OBJSET`).
    let mut zpl_meta_dirty = BTreeMap::new();
    for (&bid, blk) in &all_zpl_dirty {
        zpl_meta_dirty.insert(bid, Some(blk.clone()));
    }
    let zpl_max_block = zpl_meta_base
        .max_block()
        .max(all_zpl_dirty.keys().copied().max().unwrap_or(0));
    let meta_out = cow_update_dnode_with_crypto(
        cx,
        os_view,
        alloc,
        DnodeCowSpec {
            existing: Some((zpl_meta_base, zpl_ceiling)),
            object_type: DMU_OT_DNODE,
            bonus_type: 0,
            checksum_type: 7,
            compress_type: zpl_meta_base.compress_type(),
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
        0,
        ds_ctx.write_crypto.as_mut(),
        staged_writes,
    )?;
    zpl_born.add_assign(meta_out.born)?;
    zpl_retired.extend(meta_out.retired_bps);

    ds_ctx.os.meta = meta_out.dnode;
    let zpl_os_cksum = if matches!(ds_ctx.old_os_bp.checksum_type(), 6..=8 | 11) {
        ds_ctx.old_os_bp.checksum_type()
    } else {
        7
    };
    let new_os_bp = write_dataset_objset_block(
        &mut ds_ctx.os,
        alloc,
        zpl_os_cksum,
        order,
        new_txg,
        ds_ctx.write_crypto.as_ref(),
        staged_writes,
    )?;
    zpl_born.add_assign(SpaceDelta::from_bp(&new_os_bp)?)?;
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

    let ref_add = zpl_born
        .dsize
        .saturating_sub(killed_free.dsize + killed_snap.dsize);
    let used_add = zpl_born.dsize.saturating_sub(killed_free.dsize);
    if ref_add > 0 || used_add > 0 {
        super::dsl_ops::enforce_dataset_quotas_for_growth(
            cx,
            mos,
            mos_dirty_dnodes,
            ds_ctx.head_object,
            ds_ctx.directory_object,
            ref_add,
            used_add,
            order,
        )?;
        if used_add > 0 {
            super::dsl_ops::enforce_pool_reservations_for_growth(
                cx,
                mos,
                mos_dirty_dnodes,
                ds_ctx.head_object,
                ds_ctx.directory_object,
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
    let mut consumed_refrsrv = 0_u64;
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

        if is_owning_dir && dd_flags & 1 != 0 && zpl_born.dsize > killed_free.dsize {
            let cur_refrsrv = order.u64(&dir_bonus, 136).map_err(|e| parse_err(&e))?;
            consumed_refrsrv = cur_refrsrv.min(zpl_born.dsize - killed_free.dsize);
        }

        apply_u64_delta(
            &mut dir_bonus,
            40,
            zpl_born.dsize,
            killed_free.dsize + consumed_refrsrv,
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
                if consumed_refrsrv != 0 {
                    apply_u64_delta(
                        &mut dir_bonus,
                        136,
                        0,
                        consumed_refrsrv,
                        "dd_used_breakdown[REFRSRV]",
                    )?;
                }
            } else {
                // Ancestor DSL dirs count all descendant space in DD_USED_CHILD (`120..128`).
                apply_u64_delta(
                    &mut dir_bonus,
                    120,
                    zpl_born.dsize,
                    killed_free.dsize + consumed_refrsrv,
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
