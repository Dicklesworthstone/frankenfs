//! Explicitly admitted native ZFS metaslab allocation, COW DMU/ZPL mutations,
//! child-before-parent persistence barriers, synchronized 4-label Uberblock
//! publication, and storage/topology/TXG-bound durable commit tokens.
//!
//! Preserves read-only admission on [`crate::Leaf`], [`crate::Pool`], [`crate::Objects`],
//! [`crate::Zpl`], and [`crate::ZfsFs`]: native writes require opening a
//! [`ZfsTransactionEngine`] with explicit [`ZfsWriteOptions`] (never `import_active`
//! or force-import).

mod checkpoint;
mod dmu_cow;
mod dsl_ops;
mod lifecycle;
mod recv_ops;
mod scan;
mod zpl_ops;
mod zvol_ops;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_error::{FfsError, Result};
use ffs_ondisk::zfs::{
    BlockPointer, DATA_OFFSET, Endian, LABEL_CONFIG_BYTES, LABEL_CONFIG_OFFSET,
    UBERBLOCK_RING_BYTES, UBERBLOCK_RING_OFFSET, Uberblock, UberblockMmpInfo, stamp_label_checksum,
};
use ffs_ondisk::zfs_dmu::ObjectSet;
use ffs_ondisk::zfs_zpl::Timestamp;
use ffs_types::ParseError;
use serde::Serialize;

use crate::crypto::{ZfsDatasetCryptoInfo, ZfsKeyMaterial, ZfsKeyRing, ZfsKeyStatus};
use crate::reader::dmu::Objects;
use crate::reader::dmu::allocation::AllocationLimits;
use crate::reader::dmu::scrub::ScrubLimits;
use crate::{Leaf, Pool};

pub use self::checkpoint::{ZfsCheckpointInfo, ZfsRewindReport};
use self::dmu_cow::{
    MosFeatureState, PoolSpaceAllocator, StagedBlockWrite, WriteBucket,
    finalize_mos_and_space_maps_to_convergence, zap_optional_u64, zap_required_u64,
};
pub(crate) use self::dmu_cow::{dmu_ot_is_byte_array, dmu_ot_is_metadata};
pub(crate) use self::dsl_ops::dataset_statfs_quota_space;
use self::dsl_ops::{DslMutation, stage_dsl_mutation};
pub use self::dsl_ops::{
    ZfsBookmarkInfo, ZfsEncryptionCreateOptions, ZfsHoldInfo, ZfsPropertySetValue,
    list_bookmarks_in_mos, list_holds_in_mos,
};
pub use self::lifecycle::{
    ZfsCreateVdevKind, ZfsCreateVdevSpec, ZfsExpandRaidzReport, ZfsLifecycleReport,
    ZfsPoolCreateReport, ZfsPoolCreateSpec, ZfsRemoveVdevReport, ZfsTrimReport, create_pool_files,
    create_pool_on_devices, export_pool_leaves, import_pool_leaves,
};
pub use self::recv_ops::{
    ZfsRecvOutcome, ZfsRecvProgress, ZfsRecvReport, ZfsRecvRequest, ZfsRecvStage, ZfsResumeState,
    inspect_receive_resume_state_in_mos,
};
pub use self::scan::{ZfsScanLimits, ZfsScanReport};
pub use self::zpl_ops::{
    ZfsDataChecksum, ZfsFileRangeOperation, ZfsObjectIdentity, ZfsPosixSetAttr, ZfsSetAttr,
    ZfsUnlinkedObject, ZfsXattrSetMode,
};
use self::zpl_ops::{ZplMutation, stage_zpl_mutation};
pub use self::zvol_ops::{
    DEFAULT_VOLBLOCKSIZE, MAX_VOLBLOCKSIZE, MAX_ZVOL_IO_BYTES, ZVOL_LOGICAL_SECTOR_BYTES,
    ZfsCommitReceipt, ZfsZvolCreateOptions, ZfsZvolInfo,
};

type FaultHook = Box<dyn FnMut(&ZfsPersistenceEvent) -> Result<()> + Send + Sync>;

pub(super) fn checkpoint(cx: &Cx) -> Result<()> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)
}

pub(super) fn corrupt(detail: impl Into<String>) -> FfsError {
    FfsError::Corruption {
        block: 0,
        detail: detail.into(),
    }
}

pub(super) fn parse_err(error: &ParseError) -> FfsError {
    corrupt(error.to_string())
}

pub(super) fn unsupported(detail: impl Into<String>) -> FfsError {
    FfsError::UnsupportedFeature(detail.into())
}

fn same_uberblock(left: &Uberblock, right: &Uberblock) -> bool {
    left.order == right.order
        && left.version == right.version
        && left.txg == right.txg
        && left.guid_sum == right.guid_sum
        && left.timestamp == right.timestamp
        && left.root == right.root
        && left.checkpoint_txg == right.checkpoint_txg
        && left.raidz_reflow_info == right.raidz_reflow_info
}

/// Explicit authorization and root-binding required to open a ZFS pool for native TXG writes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ZfsWriteOptions {
    /// Caller confirms all member images are offline and unmounted.
    pub offline_image: bool,
    /// Caller explicitly authorizes native on-disk ZFS mutations.
    pub allow_write: bool,
    /// Expected native pool GUID (`!= 0`).
    pub pool_guid: u64,
    /// Explicit label index (`0..4`) naming the authoritative Uberblock ring candidate.
    pub label: usize,
    /// Explicit Uberblock ring slot naming the current authoritative TXG.
    pub slot: usize,
    /// Explicit authorization to synchronize torn/split Uberblock slots across labels/members
    /// to the verified highest-TXG candidate (`slot`) after an `Uncertain` cut.
    pub reconcile_torn_uberblocks: bool,
}

/// Admitted top-level vdev topology for the synchronous ZFS TXG writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ZfsTopologyKind {
    SingleLeaf,
    Mirror {
        width: usize,
    },
    Raidz {
        parity: usize,
        width: usize,
    },
    Draid {
        parity: usize,
        ndata: usize,
        children: usize,
        nspares: usize,
        ngroups: usize,
    },
    MultiVdev {
        top_levels: usize,
    },
}

/// Storage, topology, and pool identity bound into every [`ZfsDurableToken`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZfsStorageIdentity {
    pub pool_guid: u64,
    pub top_guid: u64,
    pub member_guids: Vec<u64>,
    pub guid_sum: u64,
    pub version: u64,
    pub ashift: u8,
    pub asize: u64,
    pub label_txg: u64,
    pub topology: ZfsTopologyKind,
    pub member_dev_inos: Vec<Option<(u64, u64)>>,
}

fn serialize_root_bp<S: serde::Serializer>(
    bytes: &[u8; 128],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    bytes.as_slice().serialize(serializer)
}

/// Unforgeable native commit token bound to a specific ZFS pool/topology/member set
/// and committed Uberblock TXG + ring slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZfsDurableToken {
    storage: ZfsStorageIdentity,
    committed_txg: u64,
    published_slot: usize,
    #[serde(serialize_with = "serialize_root_bp")]
    root_bp: [u8; 128],
    generation: u64,
    operation_digest: [u8; 32],
}

impl ZfsDurableToken {
    #[must_use]
    pub const fn storage(&self) -> &ZfsStorageIdentity {
        &self.storage
    }

    #[must_use]
    pub const fn committed_txg(&self) -> u64 {
        self.committed_txg
    }

    #[must_use]
    pub const fn published_slot(&self) -> usize {
        self.published_slot
    }

    #[must_use]
    pub const fn root_bp(&self) -> &[u8; 128] {
        &self.root_bp
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn operation_digest(&self) -> &[u8; 32] {
        &self.operation_digest
    }

    /// Verify that this token belongs to `engine`'s exact storage/topology identity
    /// and a monotonically committed TXG.
    #[must_use]
    pub fn matches_engine(&self, engine: &ZfsTransactionEngine) -> bool {
        self.storage == engine.storage_identity
            && self.committed_txg >= engine.storage_identity.label_txg
            && self.committed_txg <= engine.committed_txg
            && self.generation <= engine.generation
    }
}

/// Outcome of a native ZFS TXG publication, distinguishing pre-Uberblock failure,
/// durable 4-label commit, and incomplete Uberblock publication uncertainty.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum ZfsTxOutcome<T> {
    /// All child blocks, MOS root, and all 4 Uberblock labels on every member synced durably.
    /// Cancellation after that boundary preserves this known outcome and its token.
    Committed { value: T, token: ZfsDurableToken },
    /// Rejected or failed strictly before the first `UberblockWrite` (prior TXG stays intact).
    NotCommitted(FfsError),
    /// Failed or cancelled after starting `UberblockWrite`, before every required
    /// publication barrier succeeded. Native label/ring inspection must reconcile
    /// whether `target_txg` or the predecessor TXG is authoritative.
    Uncertain {
        reason: FfsError,
        target_txg: u64,
        target_slot: usize,
    },
}

impl<T> ZfsTxOutcome<T> {
    #[must_use]
    pub const fn is_committed(&self) -> bool {
        matches!(self, Self::Committed { .. })
    }

    #[must_use]
    pub const fn is_not_committed(&self) -> bool {
        matches!(self, Self::NotCommitted(_))
    }

    pub fn into_result(self) -> Result<(T, ZfsDurableToken)> {
        match self {
            Self::Committed { value, token } => Ok((value, token)),
            Self::NotCommitted(err) => Err(err),
            Self::Uncertain { reason, .. } => Err(reason),
        }
    }
}

/// Ordered persistence stages emitted during TXG commit for persistence-prefix verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ZfsPersistenceStage {
    ChildBlocksWrite {
        member_index: usize,
    },
    ChildBlocksBarrier {
        member_index: usize,
    },
    DatasetMetadataWrite {
        member_index: usize,
    },
    DatasetMetadataBarrier {
        member_index: usize,
    },
    MosSpaceMapWrite {
        member_index: usize,
    },
    MosSpaceMapBarrier {
        member_index: usize,
    },
    MosRootWrite {
        member_index: usize,
    },
    MosRootBarrier {
        member_index: usize,
    },
    UberblockWrite {
        member_index: usize,
        label: usize,
        slot: usize,
    },
    UberblockBarrier {
        member_index: usize,
        wave: u8,
    },
    LabelConfigWrite {
        member_index: usize,
        label: usize,
    },
    LabelConfigBarrier {
        member_index: usize,
        wave: u8,
    },
    ScanHealWrite {
        member_index: usize,
    },
    ScanHealBarrier {
        member_index: usize,
    },
    TrimDiscard {
        member_index: usize,
    },
    ReflowChunkWrite {
        member_index: usize,
    },
    ReflowChunkBarrier {
        member_index: usize,
    },
    RemovalCopyWrite {
        member_index: usize,
    },
    RemovalCopyBarrier {
        member_index: usize,
    },
    CheckpointUberblockWrite {
        member_index: usize,
        label: usize,
        slot: usize,
    },
    CheckpointUberblockBarrier {
        member_index: usize,
        wave: u8,
    },
    BeforeAcknowledge,
    AckPublished,
}

/// Structured persistence event emitted by [`ZfsTransactionEngine`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZfsPersistenceEvent {
    pub seq: u64,
    pub operation: String,
    pub stage: ZfsPersistenceStage,
    pub txg: u64,
    pub member_index: usize,
    pub offset: u64,
    pub bytes: usize,
}

/// Diagnostic report produced during clean-only ZFS writer admission.
#[derive(Debug, Clone, Serialize)]
pub struct ZfsAdmissionReport {
    pub admitted_clean_write: bool,
    pub pool_guid: u64,
    pub top_guid: u64,
    pub member_guids: Vec<u64>,
    pub guid_sum: u64,
    pub topology: ZfsTopologyKind,
    pub version: u64,
    pub ashift: u8,
    pub label_txg: u64,
    pub selected_txg: u64,
    pub max_ring_txg: u64,
    pub selected_label: usize,
    pub selected_slot: usize,
    pub slots_per_label: usize,
    pub mmp_active: bool,
    pub dirty_zil_datasets: Vec<String>,
    pub allocated_bytes: u64,
    pub free_bytes: u64,
}

/// Admitted write-only feature GUIDs in `features_for_write` (`count > 0` allowed),
/// delegated to the single pinned OpenZFS 2.4.0 manifest in `ffs-ondisk`.
fn is_admitted_active_write_feature(guid: &str) -> bool {
    ffs_ondisk::zfs::features::is_admitted_active_write_feature(guid)
}

fn is_admitted_active_read_feature_for_write(guid: &str) -> bool {
    ffs_ondisk::zfs::features::is_admitted_active_read_feature_for_write(guid)
}

/// Explicitly admitted synchronous ZFS TXG writer over a single leaf or complete N-way mirror.
pub struct ZfsTransactionEngine {
    pool: Pool,
    storage_identity: ZfsStorageIdentity,
    admission_report: ZfsAdmissionReport,
    order: Endian,
    slot_bytes: usize,
    slots_per_label: usize,
    label_offsets_per_member: Vec<[u64; 4]>,
    committed_txg: u64,
    committed_slot: usize,
    current_uberblock: Uberblock,
    current_software_version: Option<u64>,
    mos_os: ObjectSet,
    mos_features: MosFeatureState,
    empty_bpobj_id: Option<u64>,
    read_features: Vec<String>,
    allocator: PoolSpaceAllocator,
    generation: u64,
    seq: u64,
    events: Vec<ZfsPersistenceEvent>,
    fault_hook: Option<FaultHook>,
    poisoned_uncertain: bool,
    keyring: ZfsKeyRing,
}

impl ZfsTransactionEngine {
    /// Open one regular file image (standalone leaf) or `2..=8` regular file images (mirror)
    /// with exclusive advisory locks (`try_lock`) and strict clean-only ZFS writer admission.
    pub fn open_files(cx: &Cx, paths: &[&Path], options: ZfsWriteOptions) -> Result<Self> {
        Self::open_files_at(cx, paths, 0, None, options)
    }

    /// Open one regular file image (standalone leaf) or `2..=8` regular file images (mirror)
    /// bounded to `[offset, offset + length)` on each member file.
    pub fn open_files_at(
        cx: &Cx,
        paths: &[&Path],
        offset: u64,
        length: Option<u64>,
        options: ZfsWriteOptions,
    ) -> Result<Self> {
        checkpoint(cx)?;
        if !options.offline_image || !options.allow_write {
            return Err(FfsError::PermissionDenied);
        }
        if options.pool_guid == 0 || options.label >= 4 {
            return Err(FfsError::Format(
                "ZFS writer requires a non-zero pool_guid and label in 0..4".into(),
            ));
        }
        if paths.is_empty() || paths.len() > 255 {
            return Err(unsupported(
                "ZFS native writer requires 1..=255 member files",
            ));
        }
        let mut leaves = Vec::with_capacity(paths.len());
        let mut dev_inos = Vec::with_capacity(paths.len());
        for path in paths {
            let (leaf, dev_ino) = Leaf::open_writable(cx, path, offset, length)?;
            leaves.push(leaf);
            dev_inos.push(dev_ino);
        }
        Self::from_leaves_with_dev_inos(cx, leaves, dev_inos, options)
    }

    /// Open a [`ZfsTransactionEngine`] over custom [`ByteDevice`]s (for persistence-prefix
    /// fault-injection schedules on separately faultable devices).
    pub fn from_devices(
        cx: &Cx,
        devices: Vec<Box<dyn ByteDevice>>,
        options: ZfsWriteOptions,
    ) -> Result<Self> {
        checkpoint(cx)?;
        if !options.offline_image || !options.allow_write {
            return Err(FfsError::PermissionDenied);
        }
        if options.pool_guid == 0 || options.label >= 4 {
            return Err(FfsError::Format(
                "ZFS writer requires a non-zero pool_guid and label in 0..4".into(),
            ));
        }
        if devices.is_empty() || devices.len() > 255 {
            return Err(unsupported(
                "ZFS native writer requires 1..=255 member devices",
            ));
        }
        let mut leaves = Vec::with_capacity(devices.len());
        let dev_inos = vec![None; devices.len()];
        for dev in devices {
            let len = dev.len_bytes();
            leaves.push(Leaf::from_device(cx, dev, 0, len)?);
        }
        Self::from_leaves_with_dev_inos(cx, leaves, dev_inos, options)
    }

    /// Run writer admission checks without mutating on-disk bytes.
    pub fn inspect_admission(
        cx: &Cx,
        leaves: Vec<Leaf>,
        options: ZfsWriteOptions,
    ) -> Result<ZfsAdmissionReport> {
        let dev_inos = vec![None; leaves.len()];
        let mut opts = options;
        opts.reconcile_torn_uberblocks = false;
        let engine = Self::from_leaves_with_dev_inos(cx, leaves, dev_inos, opts)?;
        Ok(engine.admission_report)
    }

    #[allow(clippy::too_many_lines)]
    fn from_leaves_with_dev_inos(
        cx: &Cx,
        leaves: Vec<Leaf>,
        member_dev_inos: Vec<Option<(u64, u64)>>,
        options: ZfsWriteOptions,
    ) -> Result<Self> {
        checkpoint(cx)?;
        if !options.offline_image || !options.allow_write {
            return Err(FfsError::PermissionDenied);
        }
        if options.pool_guid == 0 || options.label >= 4 {
            return Err(FfsError::Format(
                "ZFS writer requires a non-zero pool_guid and label in 0..4".into(),
            ));
        }
        let mut pool = Pool::from_wide_leaves(leaves)?;
        if pool.has_missing_members() {
            return Err(unsupported(
                "degraded ZFS pools with missing members are refused for writes",
            ));
        }
        // Select immutable native authority before considering any recovery
        // writes. A retained owner can exclude a merely prepared future child,
        // but never a child required by a committed successor configuration.
        let recovered_root = if options.reconcile_torn_uberblocks {
            Some(pool.import_active(cx, Some(options.pool_guid))?.2)
        } else {
            None
        };
        let mut member_dev_inos = member_dev_inos;
        if let Some(selected) = recovered_root
            .as_ref()
            .and_then(|root| root.imported_pool.as_ref())
        {
            if let Some(configuration) = selected.imported_configuration() {
                member_dev_inos = configuration
                    .source_indices
                    .iter()
                    .map(|&index| {
                        member_dev_inos
                            .get(index)
                            .copied()
                            .ok_or_else(|| corrupt("imported member identity index is absent"))
                    })
                    .collect::<Result<Vec<_>>>()?;
            }
            pool = selected.clone();
        }
        let selected_labels = pool
            .imported_configuration()
            .map(|configuration| configuration.labels.clone());
        let members = pool.leaves();
        if selected_labels
            .as_ref()
            .is_some_and(|labels| labels.len() != members.len())
        {
            return Err(corrupt(
                "imported configuration does not cover every retained member",
            ));
        }
        let physical_labels = if options.reconcile_torn_uberblocks {
            pool.verified_member_labels(cx)?
        } else {
            members
                .iter()
                .map(|member| {
                    (0..4)
                        .map(|index| member.label(cx, index).map(|label| (index, label)))
                        .collect::<Result<Vec<_>>>()
                })
                .collect::<Result<Vec<_>>>()?
        };

        // 1. Every verified physical label must establish the same exported
        // identity and refuse MMP. Reconciliation may repair bad redundant
        // copies only after full native topology, ZIL, and allocation admission.
        let mut member_guids = Vec::with_capacity(members.len());
        let mut label_offsets_per_member = Vec::with_capacity(members.len());
        let first_l0 = if let Some(labels) = &selected_labels {
            labels[0].clone()
        } else {
            let copies = &physical_labels[0];
            copies
                .iter()
                .find(|(index, _)| *index == options.label)
                .or_else(|| copies.first())
                .ok_or_else(|| corrupt("no verified first member configuration"))?
                .1
                .clone()
        };
        let slot_bytes = first_l0.slot_bytes;
        let slots_per_label = UBERBLOCK_RING_BYTES / slot_bytes;
        if options.slot >= slots_per_label {
            return Err(FfsError::Format(
                "selected Uberblock slot exceeds label ring capacity".into(),
            ));
        }

        let vdev_children_count = first_l0.config.unsigned("vdev_children").unwrap_or(1);
        let topology = if vdev_children_count > 1 {
            ZfsTopologyKind::MultiVdev {
                top_levels: usize::try_from(vdev_children_count)
                    .map_err(|_| corrupt("vdev_children overflow"))?,
            }
        } else if members.len() == 1 {
            let tree = first_l0
                .config
                .list("vdev_tree")
                .ok_or_else(|| corrupt("missing vdev_tree"))?;
            if !matches!(tree.text("type"), Some("file" | "disk"))
                || tree.fields.contains_key("children")
            {
                return Err(unsupported(
                    "standalone writer requires a single file or disk vdev",
                ));
            }
            ZfsTopologyKind::SingleLeaf
        } else {
            let tree = first_l0
                .config
                .list("vdev_tree")
                .ok_or_else(|| corrupt("missing vdev_tree"))?;
            match tree.text("type") {
                Some("mirror") => ZfsTopologyKind::Mirror {
                    width: members.len(),
                },
                Some("raidz") => {
                    let parity = usize::try_from(
                        tree.unsigned("nparity")
                            .ok_or_else(|| corrupt("RAIDZ missing nparity"))?,
                    )
                    .map_err(|_| corrupt("RAIDZ nparity overflow"))?;
                    if !(1..=3).contains(&parity) || members.len() <= parity {
                        return Err(unsupported("unsupported RAIDZ parity or width"));
                    }
                    ZfsTopologyKind::Raidz {
                        parity,
                        width: members.len(),
                    }
                }
                Some("draid") => {
                    let cfg = crate::reader::pool::vdev::parse_draid_tree_config(tree)?;
                    ZfsTopologyKind::Draid {
                        parity: cfg.nparity,
                        ndata: cfg.ndata,
                        children: cfg.children,
                        nspares: cfg.nspares,
                        ngroups: cfg.ngroups,
                    }
                }
                _ => {
                    return Err(unsupported(
                        "multi-device ZFS native writer requires complete mirror, RAIDZ, dRAID, or multi-vdev topology",
                    ));
                }
            }
        };

        let top_guid = first_l0
            .config
            .unsigned("top_guid")
            .ok_or_else(|| corrupt("missing top_guid"))?;
        let version = first_l0
            .config
            .unsigned("version")
            .ok_or_else(|| corrupt("missing pool version"))?;
        let label_txg = first_l0
            .config
            .unsigned("txg")
            .ok_or_else(|| corrupt("missing label txg"))?;

        for (member, labels) in members.iter().zip(&physical_labels) {
            checkpoint(cx)?;
            let l_offsets =
                label_offsets(member.length_bytes()).map_err(|error| parse_err(&error))?;
            let mut m_guid = None;
            for (_, lbl) in labels {
                if lbl.config.unsigned("pool_guid") != Some(options.pool_guid) {
                    return Err(corrupt("physical writer label belongs to another pool"));
                }
                if lbl.config.unsigned("state") != Some(1) {
                    return Err(unsupported(
                        "ZFS native writer requires a cleanly exported pool (state == 1); active pools are never force-imported",
                    ));
                }
                if lbl.config.unsigned("vdev_children") != Some(vdev_children_count)
                    || lbl.slot_bytes != slot_bytes
                {
                    return Err(corrupt("member labels disagree on vdev or sector geometry"));
                }
                if lbl.config.unsigned("multihost").unwrap_or(0) != 0 {
                    return Err(unsupported(
                        "ZFS multihost/MMP-enabled label refuses offline writer admission",
                    ));
                }
                let guid = lbl
                    .config
                    .unsigned("guid")
                    .ok_or_else(|| corrupt("missing physical member guid"))?;
                if let Some(prev) = m_guid {
                    if prev != guid {
                        return Err(corrupt("member labels disagree on physical GUID"));
                    }
                } else {
                    m_guid = Some(guid);
                }
            }
            member_guids.push(m_guid.ok_or_else(|| corrupt("missing member guid"))?);
            label_offsets_per_member.push(l_offsets);
        }

        let guid_sum = if vdev_children_count > 1 {
            // For multi-top-vdev pools, read authoritative guid_sum from the selected uberblock
            // and verify against PoolTopology once MOS config is loaded below.
            if let Some(root) = &recovered_root {
                root.uberblock.guid_sum
            } else {
                let sel_lbl = members[0].label(cx, options.label)?;
                let sel_ub = members[0].uberblock(cx, &sel_lbl, options.slot)?;
                sel_ub.guid_sum
            }
        } else if members.len() == 1 {
            options.pool_guid.wrapping_add(top_guid)
        } else {
            member_guids
                .iter()
                .fold(options.pool_guid.wrapping_add(top_guid), |acc, &g| {
                    acc.wrapping_add(g)
                })
        };

        // 2. Scan all 4 labels x `slots_per_label` across all members to check MMP activity
        // and discover `max_ring_txg` (so stale ring slots cannot roll back a newer TXG!).
        let mut max_ring_txg = 0_u64;
        let mut mmp_active = false;
        let mut selected_ub_from_scan: Option<(usize, usize, Uberblock, Endian, Option<u64>)> =
            None;
        for (m_idx, member) in members.iter().enumerate() {
            for l_idx in 0..4 {
                checkpoint(cx)?;
                for s_idx in 0..slots_per_label {
                    let off = label_offsets_per_member[m_idx][l_idx]
                        + UBERBLOCK_RING_OFFSET
                        + (s_idx * slot_bytes) as u64;
                    let raw = member.read_raw(cx, off, slot_bytes)?;
                    let Ok(ub) = Uberblock::parse(&raw, off) else {
                        continue;
                    };
                    if ub.version != version || ub.txg < label_txg || ub.guid_sum != guid_sum {
                        continue;
                    }
                    let ub_order = if Endian::Little.u64(&raw, 0).ok() == Some(0x00ba_b10c) {
                        Endian::Little
                    } else {
                        Endian::Big
                    };
                    let mmp = UberblockMmpInfo::parse(&raw, off).map_err(|e| parse_err(&e))?;
                    if mmp.has_active_mmp() {
                        mmp_active = true;
                    }
                    max_ring_txg = max_ring_txg.max(ub.txg);
                    let matches_slot = s_idx == options.slot
                        && (l_idx == options.label || options.reconcile_torn_uberblocks);
                    if matches_slot {
                        let replace = match &selected_ub_from_scan {
                            None => true,
                            Some((_, _, prev_ub, _, _)) => {
                                ub.txg > prev_ub.txg
                                    || (ub.txg == prev_ub.txg
                                        && (ub.timestamp > prev_ub.timestamp
                                            || (ub.timestamp == prev_ub.timestamp
                                                && l_idx == options.label)))
                            }
                        };
                        if replace {
                            selected_ub_from_scan =
                                Some((m_idx, l_idx, ub, ub_order, Some(mmp.software_version)));
                        }
                    }
                }
            }
        }
        if mmp_active {
            return Err(unsupported(
                "active ZFS Multi-Modifier Protection (MMP) state in Uberblock ring refuses write",
            ));
        }

        // 3. Select and verify the requested root without modifying any member.
        // Reconciliation must not heal labels for a pool that fails later write admission.
        let (selected_member, selected_label, expected_ub, expected_order, current_sw_version) =
            selected_ub_from_scan.as_ref().ok_or_else(|| {
                corrupt("explicitly selected (label, slot) does not contain a valid Uberblock")
            })?;
        if expected_ub.txg != max_ring_txg {
            return Err(corrupt(
                "explicitly selected Uberblock slot is older than a newer committed TXG in the ring",
            ));
        }
        let root_block = if options.reconcile_torn_uberblocks {
            let imported_root = recovered_root
                .ok_or_else(|| corrupt("reconciliation lost its selected native root"))?;
            if !same_uberblock(&imported_root.uberblock, expected_ub) {
                return Err(corrupt(
                    "reconcile_torn_uberblocks candidate disagrees with verified active pool root",
                ));
            }
            imported_root
        } else {
            // Strict unanimity across all 4 labels of every member at the selected slot.
            for member in members {
                for l_idx in 0..4 {
                    let lbl = member.label(cx, l_idx)?;
                    let other = match member.uberblock(cx, &lbl, options.slot) {
                        Ok(ub) => ub,
                        Err(e @ (FfsError::Cancelled | FfsError::Io(_))) => return Err(e),
                        Err(_) => {
                            return Err(corrupt(
                                "Uberblock slots disagree across labels or members; explicit reconciliation required",
                            ));
                        }
                    };
                    if !same_uberblock(&other, expected_ub) {
                        return Err(corrupt(
                            "Uberblock slots disagree across labels or members; explicit reconciliation required",
                        ));
                    }
                }
            }
            pool.root(cx, options.label, options.slot, options.pool_guid)?
        };
        let current_uberblock = root_block.uberblock.clone();
        let vcfg = root_block.vdev_config().clone();
        let order = current_uberblock.root.payload_order();
        let mos_os = ObjectSet::parse(&root_block.data, order).map_err(|e| parse_err(&e))?;
        let current_sw_version = *current_sw_version;

        // 4. Open the exact verified root, admit writes, and inspect ZIL on every head.
        // A split mirror cannot use the strict label reader until reconciliation,
        // but this constructor retains complete read-feature and checksum admission.
        let mut mos = Objects::from_root(cx, pool.clone(), root_block)?;
        let mut mos_features = MosFeatureState::default();
        let dir_entries = mos.zap_values(cx, 1)?;
        for entry in &dir_entries {
            if entry.name.starts_with(b"DDT-") {
                let ddt_obj = entry.scalar().map_err(|e| parse_err(&e))?;
                if ddt_obj != 0 && !mos.zap_values(cx, ddt_obj)?.is_empty() {
                    return Err(unsupported(
                        "ZFS pool contains non-empty legacy DDT deduplication entries; native writes are refused",
                    ));
                }
            }
        }
        let empty_bpobj_id = zap_optional_u64(&dir_entries, b"empty_bpobj")?;
        if version == 5000 {
            let rf_id = zap_required_u64(&dir_entries, b"features_for_read")?;
            mos_features.read_features_obj = Some(rf_id);
            for entry in mos.zap_values(cx, rf_id)? {
                let name = std::str::from_utf8(&entry.name)
                    .map_err(|_| corrupt("non-UTF8 read feature GUID"))?
                    .to_owned();
                let count = entry.scalar().map_err(|e| parse_err(&e))?;
                if count != 0 && !is_admitted_active_read_feature_for_write(&name) {
                    return Err(unsupported(format!(
                        "active ZFS read feature {name} (refcount={count}) is not admitted for native writes"
                    )));
                }
                mos_features.read_features.insert(name, count);
            }
            let wf_id = zap_required_u64(&dir_entries, b"features_for_write")?;
            mos_features.write_features_obj = Some(wf_id);
            for entry in mos.zap_values(cx, wf_id)? {
                let name = std::str::from_utf8(&entry.name)
                    .map_err(|_| corrupt("non-UTF8 write feature GUID"))?
                    .to_owned();
                let count = entry.scalar().map_err(|e| parse_err(&e))?;
                if count != 0 && !is_admitted_active_write_feature(&name) {
                    return Err(unsupported(format!(
                        "active ZFS write feature {name} (refcount={count}) is not admitted for native writes"
                    )));
                }
                mos_features.write_features.insert(name, count);
            }
            if let Some(et_id) = zap_optional_u64(&dir_entries, b"feature_enabled_txg")? {
                mos_features.enabled_txg_obj = Some(et_id);
                for entry in mos.zap_values(cx, et_id)? {
                    let name = std::str::from_utf8(&entry.name)
                        .map_err(|_| corrupt("non-UTF8 enabled_txg feature GUID"))?
                        .to_owned();
                    let txg = entry.scalar().map_err(|e| parse_err(&e))?;
                    mos_features.enabled_txg.insert(name, txg);
                }
            }
        }

        let mut dirty_zil_datasets = Vec::new();
        for ds in mos.datasets(cx)? {
            checkpoint(cx)?;
            if ds.objectset_kind.is_none() {
                continue;
            }
            let (hd_dn, hd_ceil) = mos.object_with_ceiling(cx, ds.head_object)?;
            let ds_bp = BlockPointer::parse(&hd_dn.bonus()[128..256], hd_dn.order())
                .map_err(|e| parse_err(&e))?;
            let (ds_raw, ds_ord, _) =
                mos.read_dataset_objset_block_raw(cx, &ds_bp, hd_ceil, None, true)?;
            let ds_os = ObjectSet::parse(&ds_raw, ds_ord).map_err(|e| parse_err(&e))?;
            if mos.dataset_has_pending_zil_work(
                cx,
                ds.head_object,
                ds.guid,
                &hd_dn,
                &ds_bp,
                &ds_raw,
                ds_ord,
                &ds_os,
            )? {
                let rel = ds
                    .components
                    .iter()
                    .map(|c| String::from_utf8_lossy(c).into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                dirty_zil_datasets.push(if rel.is_empty() {
                    "<root>".to_owned()
                } else {
                    rel
                });
            }
        }
        if !dirty_zil_datasets.is_empty() {
            return Err(unsupported(format!(
                "clean-only ZFS writer refuses pending ZIL on datasets: {}",
                dirty_zil_datasets.join(", ")
            )));
        }

        // 5. Load metaslab space maps and verify accounting before any recovery write.
        let mut allocator = PoolSpaceAllocator::load(
            cx,
            &mut mos,
            &mos_features.write_features,
            &vcfg.read_features,
            &member_guids,
        )?;
        allocator.checkpoint_txg = current_uberblock.checkpoint_txg;
        if allocator.checkpoint_txg != 0 {
            allocator.checkpoint_deferred_frees =
                checkpoint::load_deferred_frees_from_mos(cx, &mut mos)?;
        }

        // The admission view retains imported authority, but a live writer must
        // rediscover later publications from the exact retained physical leaves.
        let writer_pool = Pool::from_wide_leaves(members.to_vec())?;

        // 6. Only a fully admitted writer may reconcile the selected ring copies.
        if options.reconcile_torn_uberblocks {
            let scrub = mos.scrub(
                cx,
                ScrubLimits {
                    copy_bytes: Some(1 << 30),
                    ..ScrubLimits::default()
                },
            )?;
            if !scrub.is_clean() {
                return Err(corrupt(
                    "reconcile_torn_uberblocks refused: MOS scrub detected errors",
                ));
            }
            let _ = mos.allocation(cx, AllocationLimits::default())?;

            // Encode every selected configuration before any recovery write.
            // Ordinary leaf, mirror, dRAID, and stripe imports do not carry a
            // canonical cohort and retain their existing UB-only reconciliation.
            let encoded_configurations = if let Some(labels) = &selected_labels {
                let mut configurations = Vec::with_capacity(members.len());
                for (member_index, label) in labels.iter().enumerate() {
                    checkpoint(cx)?;
                    if label.config.unsigned("pool_guid") != Some(options.pool_guid)
                        || label.config.unsigned("guid") != Some(member_guids[member_index])
                        || label.config.unsigned("top_guid") != Some(top_guid)
                        || label.config.unsigned("txg") != Some(label_txg)
                        || label.config.unsigned("version") != Some(version)
                        || label.config.unsigned("state") != Some(1)
                        || label.config.unsigned("multihost").unwrap_or(0) != 0
                        || label.slot_bytes != slot_bytes
                    {
                        return Err(corrupt(
                            "canonical recovery label disagrees with admitted identity",
                        ));
                    }
                    let packed = label
                        .config
                        .encode_xdr()
                        .map_err(|error| parse_err(&error))?;
                    if packed.len() > LABEL_CONFIG_BYTES - 40 {
                        return Err(corrupt(
                            "canonical recovery label exceeds its configuration span",
                        ));
                    }
                    let mut copies = Vec::with_capacity(4);
                    for label_offset in label_offsets_per_member[member_index] {
                        let offset = label_offset + LABEL_CONFIG_OFFSET;
                        let mut bytes = vec![0_u8; LABEL_CONFIG_BYTES];
                        bytes[..packed.len()].copy_from_slice(&packed);
                        stamp_label_checksum(&mut bytes, offset, label.order)
                            .map_err(|error| parse_err(&error))?;
                        copies.push((offset, bytes));
                    }
                    configurations.push(copies);
                }
                Some(configurations)
            } else {
                None
            };

            // Preserve a verified physical identity on every member, the
            // canonical generation's source, and the selected UB until the
            // first replacement wave is durable. These sources need not be in
            // the same fixed front/back label pair after an interrupted write.
            let mut recovery_waves = Vec::with_capacity(members.len());
            let mut canonical_source_found = selected_labels.is_none();
            for (member_index, labels) in physical_labels.iter().enumerate() {
                let canonical_source = selected_labels.as_ref().and_then(|canonical| {
                    labels
                        .iter()
                        .find(|(_, label)| label.config == canonical[member_index].config)
                });
                canonical_source_found |= canonical_source.is_some();
                let (identity_label, _) = canonical_source
                    .or_else(|| labels.first())
                    .ok_or_else(|| corrupt("recovery member has no verified identity source"))?;
                let mut reserved = [false; 4];
                *reserved
                    .get_mut(*identity_label)
                    .ok_or_else(|| corrupt("recovery identity label index is invalid"))? = true;
                if member_index == *selected_member {
                    reserved[*selected_label] = true;
                }
                let first: Vec<_> = (0..4).filter(|&index| !reserved[index]).take(2).collect();
                if first.len() != 2 {
                    return Err(corrupt(
                        "recovery cannot preserve its native authority sources",
                    ));
                }
                let second: Vec<_> = (0..4).filter(|index| !first.contains(index)).collect();
                recovery_waves.push([[first[0], first[1]], [second[0], second[1]]]);
            }
            if !canonical_source_found {
                return Err(corrupt(
                    "canonical recovery generation has no retained physical source",
                ));
            }

            // Pre-encode the selected UB at every destination as well, so all
            // deterministic encoding errors precede the first physical write.
            let default_sw = if version == 5000 { 5000 } else { version };
            let mut recovery_uberblock = current_uberblock.clone();
            recovery_uberblock.order = *expected_order;
            let mut encoded_uberblocks = Vec::with_capacity(members.len());
            for offsets in &label_offsets_per_member {
                checkpoint(cx)?;
                let mut copies = Vec::with_capacity(4);
                for label_offset in offsets {
                    let offset =
                        label_offset + UBERBLOCK_RING_OFFSET + (options.slot * slot_bytes) as u64;
                    let bytes = recovery_uberblock
                        .encode_with_meta(
                            slot_bytes,
                            offset,
                            current_sw_version.unwrap_or(default_sw),
                            0,
                            0,
                        )
                        .map_err(|error| parse_err(&error))?;
                    copies.push((offset, bytes));
                }
                encoded_uberblocks.push(copies);
            }

            let mut protection = pool.defer_protection(cx)?;
            for wave in 0..2 {
                for (m_idx, member) in members.iter().enumerate() {
                    for l_idx in recovery_waves[m_idx][wave] {
                        checkpoint(cx)?;
                        if let Some(configurations) = &encoded_configurations {
                            let (offset, bytes) = &configurations[m_idx][l_idx];
                            member.write_raw(cx, *offset, bytes)?;
                        }
                        let (offset, bytes) = &encoded_uberblocks[m_idx][l_idx];
                        member.write_raw(cx, *offset, bytes)?;
                    }
                }
                for member in members {
                    member.sync_raw(cx)?;
                }
            }
            for hold in &mut protection {
                hold.complete();
            }
        }

        let storage_identity = ZfsStorageIdentity {
            pool_guid: options.pool_guid,
            top_guid,
            member_guids: member_guids.clone(),
            guid_sum,
            version,
            ashift: vcfg.ashift,
            asize: vcfg.allocated_bytes,
            label_txg,
            topology,
            member_dev_inos,
        };
        let admission_report = ZfsAdmissionReport {
            admitted_clean_write: true,
            pool_guid: options.pool_guid,
            top_guid,
            member_guids,
            guid_sum,
            topology,
            version,
            ashift: vcfg.ashift,
            label_txg,
            selected_txg: current_uberblock.txg,
            max_ring_txg,
            selected_label: options.label,
            selected_slot: options.slot,
            slots_per_label,
            mmp_active: false,
            dirty_zil_datasets,
            allocated_bytes: allocator.total_allocated_bytes(),
            free_bytes: allocator.total_free_bytes(),
        };

        Ok(Self {
            pool: writer_pool,
            storage_identity,
            admission_report,
            order,
            slot_bytes,
            slots_per_label,
            label_offsets_per_member,
            committed_txg: current_uberblock.txg,
            committed_slot: options.slot,
            current_uberblock,
            current_software_version: current_sw_version,
            mos_os,
            mos_features,
            empty_bpobj_id,
            read_features: vcfg.read_features,
            allocator,
            generation: 0,
            seq: 0,
            events: Vec::new(),
            fault_hook: None,
            poisoned_uncertain: false,
            keyring: ZfsKeyRing::new(),
        })
    }

    /// Attach a shared [`ZfsKeyRing`] to this transaction engine.
    #[must_use]
    pub fn with_keyring(mut self, keyring: ZfsKeyRing) -> Self {
        self.keyring = keyring;
        self
    }

    /// Borrow the engine's in-memory [`ZfsKeyRing`].
    #[must_use]
    pub const fn keyring(&self) -> &ZfsKeyRing {
        &self.keyring
    }

    /// Discover native `com.datto:encryption` metadata for `dataset_components`.
    pub fn dataset_crypto_info(
        &self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
    ) -> Result<Option<ZfsDatasetCryptoInfo>> {
        let mut mos = self.open_read_objects(cx)?;
        mos.dataset_crypto_info(cx, dataset_components)
    }

    /// Unwrap and load the dataset encryption key for `dataset_components`.
    pub fn load_key(
        &self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        material: &ZfsKeyMaterial,
    ) -> Result<ZfsDatasetCryptoInfo> {
        let mut mos = self.open_read_objects(cx)?;
        mos.load_key(cx, dataset_components, material)
    }

    /// Unload and scrub the encryption key for `dataset_components`'s encryption root.
    pub fn unload_key(&self, cx: &Cx, dataset_components: &[Vec<u8>]) -> Result<bool> {
        let mut mos = self.open_read_objects(cx)?;
        mos.unload_key(cx, dataset_components)
    }

    /// Report runtime [`ZfsKeyStatus`] for `dataset_components`.
    pub fn key_status(&self, cx: &Cx, dataset_components: &[Vec<u8>]) -> Result<ZfsKeyStatus> {
        let mut mos = self.open_read_objects(cx)?;
        mos.key_status(cx, dataset_components)
    }

    pub fn with_fault_hook(
        &mut self,
        hook: impl FnMut(&ZfsPersistenceEvent) -> Result<()> + Send + Sync + 'static,
    ) {
        self.fault_hook = Some(Box::new(hook));
    }

    pub fn clear_fault_hook(&mut self) {
        self.fault_hook = None;
    }

    #[must_use]
    pub const fn admission_report(&self) -> &ZfsAdmissionReport {
        &self.admission_report
    }

    #[must_use]
    pub const fn storage_identity(&self) -> &ZfsStorageIdentity {
        &self.storage_identity
    }

    #[must_use]
    pub const fn committed_txg(&self) -> u64 {
        self.committed_txg
    }

    #[must_use]
    pub const fn committed_slot(&self) -> usize {
        self.committed_slot
    }

    /// Whether uncertain publication or an interrupted physical repair requires
    /// a fresh native writer before this handle can serve further mutations.
    #[must_use]
    pub const fn requires_recovery(&self) -> bool {
        self.poisoned_uncertain
    }

    /// Allocated bytes in the currently committed native metaslab maps.
    #[must_use]
    pub fn allocated_bytes(&self) -> u64 {
        self.allocator.total_allocated_bytes()
    }

    /// Free bytes in the currently committed native metaslab maps.
    #[must_use]
    pub fn free_bytes(&self) -> u64 {
        self.allocator.total_free_bytes()
    }

    /// Issue a durability barrier on every retained member.
    ///
    /// Mutations already publish synchronously. This additional barrier lets a
    /// filesystem consumer report current device errors from fsync and unmount;
    /// it cannot resolve an uncertain native publication or mint a new token.
    pub fn sync_devices(&self, cx: &Cx) -> Result<()> {
        checkpoint(cx)?;
        if self.requires_recovery() {
            return Err(unsupported(
                "ZFS writer requires explicit recovery before synchronization",
            ));
        }
        for member in self.pool.leaves() {
            member.sync_raw(cx)?;
        }
        Ok(())
    }

    /// Enter deferred-seal mode across every member device in the pool.
    pub fn begin_durability_commit(&self, cx: &Cx) -> Result<()> {
        let leaves = self.pool.leaves();
        for (entered, member) in leaves.iter().enumerate() {
            if let Err(err) = member.begin_durability_commit(cx) {
                for prev in &leaves[..entered] {
                    prev.abort_durability_commit();
                }
                return Err(err);
            }
        }
        Ok(())
    }

    /// Mark a multi-barrier TXG commit complete across every member device.
    pub fn complete_durability_commit(&self) {
        for member in self.pool.leaves() {
            member.complete_durability_commit();
        }
    }

    /// Abort a multi-barrier TXG commit across every member device.
    pub fn abort_durability_commit(&self) {
        for member in self.pool.leaves() {
            member.abort_durability_commit();
        }
    }

    #[must_use]
    pub fn persistence_events(&self) -> &[ZfsPersistenceEvent] {
        &self.events
    }

    pub fn verify_token(&self, token: &ZfsDurableToken) -> Result<()> {
        if !token.matches_engine(self) {
            return Err(FfsError::PermissionDenied);
        }
        Ok(())
    }

    /// Open a fresh read-only [`Objects`] view pinned to the currently committed `(0, slot)`
    /// with this engine's shared [`ZfsKeyRing`] attached.
    pub fn open_read_objects(&self, cx: &Cx) -> Result<Objects> {
        let objects =
            self.pool
                .objects(cx, 0, self.committed_slot, self.storage_identity.pool_guid)?;
        Ok(objects.with_keyring(self.keyring.clone()))
    }

    /// Create a new regular file in `parent_dir` on `dataset_components` (`&[]` = root dataset)
    /// and publish a new TXG.
    #[allow(clippy::too_many_arguments)]
    pub fn create_file(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        parent_dir: u64,
        name: &[u8],
        mode: u16,
        uid: u64,
        gid: u64,
        timestamp: Timestamp,
        checksum: ZfsDataChecksum,
    ) -> ZfsTxOutcome<u64> {
        self.execute_zpl_txg(
            cx,
            dataset_components,
            &ZplMutation::CreateFile {
                parent_dir,
                name: name.to_vec(),
                mode,
                uid,
                gid,
                symlink_target: None,
                timestamp,
                checksum,
            },
        )
    }

    /// Create a native symbolic link and its directory entry in one TXG.
    ///
    /// Targets are uninterpreted bytes, excluding NUL, with the Linux maximum
    /// length of 4095 bytes. Empty targets are rejected. The new symlink has
    /// mode `0777`; callers apply any parent group inheritance before supplying
    /// `gid`. Legacy native znodes support both ZPL v4 and v5 without altering
    /// the dataset's SA registry or the parent's metadata representation.
    #[allow(clippy::too_many_arguments)]
    pub fn create_symlink(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        parent_dir: u64,
        name: &[u8],
        target: &[u8],
        uid: u64,
        gid: u64,
        timestamp: Timestamp,
        checksum: ZfsDataChecksum,
    ) -> ZfsTxOutcome<u64> {
        // Validate the whole request before metadata reads or COW staging.
        // Linux rejects an empty symlink target as an empty pathname (ENOENT).
        if target.is_empty() {
            return ZfsTxOutcome::NotCommitted(FfsError::NotFound(
                "empty ZPL symlink target".into(),
            ));
        }
        if target.contains(&0) {
            return ZfsTxOutcome::NotCommitted(FfsError::Format(
                "ZPL symlink target contains NUL".into(),
            ));
        }
        if target.len() > 4095 {
            return ZfsTxOutcome::NotCommitted(FfsError::NameTooLong);
        }
        if timestamp.nanos >= 1_000_000_000 {
            return ZfsTxOutcome::NotCommitted(FfsError::Format("invalid ZPL nanoseconds".into()));
        }
        self.execute_zpl_txg(
            cx,
            dataset_components,
            &ZplMutation::CreateFile {
                parent_dir,
                name: name.to_vec(),
                mode: 0o777,
                uid,
                gid,
                symlink_target: Some(target.to_vec()),
                timestamp,
                checksum,
            },
        )
    }

    /// Create a new directory in `parent_dir` on `dataset_components` and publish a new TXG.
    #[allow(clippy::too_many_arguments)]
    pub fn mkdir(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        parent_dir: u64,
        name: &[u8],
        mode: u16,
        uid: u64,
        gid: u64,
        timestamp: Timestamp,
    ) -> ZfsTxOutcome<u64> {
        self.execute_zpl_txg(
            cx,
            dataset_components,
            &ZplMutation::Mkdir {
                parent_dir,
                name: name.to_vec(),
                mode,
                uid,
                gid,
                timestamp,
            },
        )
    }

    /// Write `data` at `offset` in `file_obj` on `dataset_components` and publish a new TXG.
    #[allow(clippy::too_many_arguments)]
    pub fn write_file_data(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        file_obj: u64,
        offset: u64,
        data: &[u8],
        timestamp: Timestamp,
        checksum: ZfsDataChecksum,
    ) -> ZfsTxOutcome<u64> {
        self.write_file_data_with_privilege_policy(
            cx,
            dataset_components,
            file_obj,
            offset,
            data,
            timestamp,
            checksum,
            false,
            false,
        )
    }

    /// Write data and clear set-user-ID and executable set-group-ID permissions
    /// in the same TXG. A zero-length write does not clear either bit.
    ///
    /// This is the data-mutation policy for callers without privilege to retain
    /// set-ID permissions. File capabilities require separate admission; this
    /// operation does not remove capability extended attributes.
    #[allow(clippy::too_many_arguments)]
    pub fn write_file_data_clearing_setid(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        file_obj: u64,
        offset: u64,
        data: &[u8],
        timestamp: Timestamp,
        checksum: ZfsDataChecksum,
    ) -> ZfsTxOutcome<u64> {
        self.write_file_data_with_privilege_policy(
            cx,
            dataset_components,
            file_obj,
            offset,
            data,
            timestamp,
            checksum,
            true,
            false,
        )
    }

    /// Write data, clear set-user-ID and executable set-group-ID permissions, and
    /// remove native SA and directory-backed file capabilities in the same TXG.
    /// Empty writes preserve size, timestamps, and privileges. Malformed private
    /// ownership refuses the whole mutation before publication.
    #[allow(clippy::too_many_arguments)]
    pub fn write_file_data_clearing_privileges(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        file_obj: u64,
        offset: u64,
        data: &[u8],
        timestamp: Timestamp,
        checksum: ZfsDataChecksum,
    ) -> ZfsTxOutcome<u64> {
        self.write_file_data_with_privilege_policy(
            cx,
            dataset_components,
            file_obj,
            offset,
            data,
            timestamp,
            checksum,
            true,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn write_file_data_with_privilege_policy(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        file_obj: u64,
        offset: u64,
        data: &[u8],
        timestamp: Timestamp,
        checksum: ZfsDataChecksum,
        clear_suid_sgid: bool,
        clear_file_capabilities: bool,
    ) -> ZfsTxOutcome<u64> {
        self.execute_zpl_txg(
            cx,
            dataset_components,
            &ZplMutation::WriteData {
                file_obj,
                offset,
                data: data.to_vec(),
                clear_suid_sgid,
                clear_file_capabilities,
                timestamp,
                checksum,
            },
        )
    }

    /// Punch or zero a regular-file byte range and publish its new size in one TXG.
    /// Sparse intervals are skipped without allocation. At most 65536 allocated
    /// leaves, 16 MiB of indirect metadata and 16 MiB of edge data are processed;
    /// larger allocated edits must be split by the caller. No space is reserved.
    #[allow(clippy::too_many_arguments)]
    pub fn edit_file_range(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        file_obj: u64,
        offset: u64,
        length: u64,
        operation: ZfsFileRangeOperation,
        timestamp: Timestamp,
        checksum: ZfsDataChecksum,
    ) -> ZfsTxOutcome<u64> {
        self.edit_file_range_with_privilege_policy(
            cx,
            dataset_components,
            file_obj,
            offset,
            length,
            operation,
            timestamp,
            checksum,
            false,
            false,
        )
    }

    /// Edit a sparse range and clear set-user-ID and executable set-group-ID
    /// permissions in the same TXG. A size-preserving range wholly beyond EOF
    /// does not change the inode's permissions or timestamps.
    ///
    /// File capabilities require separate admission; this operation does not
    /// remove capability extended attributes.
    #[allow(clippy::too_many_arguments)]
    pub fn edit_file_range_clearing_setid(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        file_obj: u64,
        offset: u64,
        length: u64,
        operation: ZfsFileRangeOperation,
        timestamp: Timestamp,
        checksum: ZfsDataChecksum,
    ) -> ZfsTxOutcome<u64> {
        self.edit_file_range_with_privilege_policy(
            cx,
            dataset_components,
            file_obj,
            offset,
            length,
            operation,
            timestamp,
            checksum,
            true,
            false,
        )
    }

    /// Edit a sparse range while clearing set-ID permissions and native SA and
    /// directory-backed file capabilities atomically. A size-preserving range
    /// wholly beyond EOF retains all privileges. Malformed private ownership
    /// refuses the whole mutation.
    #[allow(clippy::too_many_arguments)]
    pub fn edit_file_range_clearing_privileges(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        file_obj: u64,
        offset: u64,
        length: u64,
        operation: ZfsFileRangeOperation,
        timestamp: Timestamp,
        checksum: ZfsDataChecksum,
    ) -> ZfsTxOutcome<u64> {
        self.edit_file_range_with_privilege_policy(
            cx,
            dataset_components,
            file_obj,
            offset,
            length,
            operation,
            timestamp,
            checksum,
            true,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn edit_file_range_with_privilege_policy(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        file_obj: u64,
        offset: u64,
        length: u64,
        operation: ZfsFileRangeOperation,
        timestamp: Timestamp,
        checksum: ZfsDataChecksum,
        clear_suid_sgid: bool,
        clear_file_capabilities: bool,
    ) -> ZfsTxOutcome<u64> {
        if length == 0
            || offset
                .checked_add(length)
                .is_none_or(|end| i64::try_from(end).is_err())
        {
            return ZfsTxOutcome::NotCommitted(FfsError::RequestRejected {
                errno: libc::EINVAL,
                detail: "ZPL range must be nonempty and end within i64::MAX".into(),
            });
        }
        if timestamp.nanos >= 1_000_000_000 {
            return ZfsTxOutcome::NotCommitted(FfsError::Format("invalid ZPL nanoseconds".into()));
        }
        self.execute_zpl_txg(
            cx,
            dataset_components,
            &ZplMutation::EditRange {
                file_obj,
                offset,
                length,
                operation,
                clear_suid_sgid,
                clear_file_capabilities,
                timestamp,
                checksum,
            },
        )
    }

    /// Set or replace a ZPL `user.*` extended attribute in SA (`ZPL_DXATTR` inline or spill).
    /// On an SA-formatted ZPL v5 owner, replacement also retires matching private
    /// directory values and unprefixed compatibility aliases in the same TXG.
    /// Snapshots retain their old values and native owner usage is reconciled.
    #[allow(clippy::too_many_arguments)]
    pub fn set_xattr(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        target_obj: u64,
        name: &str,
        value: &[u8],
        mode: ZfsXattrSetMode,
        timestamp: Timestamp,
    ) -> ZfsTxOutcome<u64> {
        self.execute_zpl_txg(
            cx,
            dataset_components,
            &ZplMutation::SetXattr {
                target_obj,
                name: name.to_owned(),
                value: value.to_vec(),
                mode,
                timestamp,
            },
        )
    }

    /// Remove a ZPL `user.*` extended attribute from both native stores of an
    /// SA-formatted ZPL v5 owner, including unprefixed compatibility aliases.
    pub fn remove_xattr(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        target_obj: u64,
        name: &str,
        timestamp: Timestamp,
    ) -> ZfsTxOutcome<u64> {
        self.execute_zpl_txg(
            cx,
            dataset_components,
            &ZplMutation::RemoveXattr {
                target_obj,
                name: name.to_owned(),
                timestamp,
            },
        )
    }

    /// Truncate or extend `file_obj` to `new_size` on `dataset_components` and publish a new TXG.
    pub fn truncate_file(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        file_obj: u64,
        new_size: u64,
        timestamp: Timestamp,
        checksum: ZfsDataChecksum,
    ) -> ZfsTxOutcome<u64> {
        self.set_attributes(
            cx,
            dataset_components,
            file_obj,
            &ZfsSetAttr {
                size: Some(new_size),
                ..ZfsSetAttr::default()
            },
            timestamp,
            checksum,
        )
    }

    /// Publish size and native timestamps atomically in one TXG, returning the
    /// resulting logical size. `timestamp` supplies ctime and, for a size change
    /// without an explicit mtime, the new mtime. Empty requests are rejected.
    /// Native readonly and persistent flag rules apply before publication.
    ///
    /// A metadata-only change preserves the existing data tree and does not use
    /// `checksum`; that algorithm is used only for blocks rewritten by truncation.
    pub fn set_attributes(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        object: u64,
        attrs: &ZfsSetAttr,
        timestamp: Timestamp,
        checksum: ZfsDataChecksum,
    ) -> ZfsTxOutcome<u64> {
        self.set_posix_attributes(
            cx,
            dataset_components,
            object,
            &ZfsPosixSetAttr::from(attrs),
            timestamp,
            checksum,
        )
    }

    /// Publish size, POSIX mode/uid/gid, privilege clearing, and native timestamps
    /// atomically in one TXG, rebuilding trivial NFSv4 DACL on chmod and
    /// transferring embedded `userused`/`groupused` quota accounting on chown.
    pub fn set_posix_attributes(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        object: u64,
        attrs: &ZfsPosixSetAttr,
        timestamp: Timestamp,
        checksum: ZfsDataChecksum,
    ) -> ZfsTxOutcome<u64> {
        // Validate the whole compound request before opening metadata or staging
        // a size change. A bad explicit time cannot leave a truncated file.
        if let Err(error) = attrs.validate(timestamp) {
            return ZfsTxOutcome::NotCommitted(error);
        }
        self.execute_zpl_txg(
            cx,
            dataset_components,
            &ZplMutation::SetAttributes {
                file_obj: object,
                attrs: attrs.clone(),
                timestamp,
                checksum,
            },
        )
    }

    /// Add a name for an existing regular file in the same head dataset.
    /// The source object and destination directory are dataset-local object IDs;
    /// the link count and namespace entry publish together in one native TXG.
    pub fn link_entry(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        source_object: u64,
        parent_dir: u64,
        name: &[u8],
        timestamp: Timestamp,
    ) -> ZfsTxOutcome<u64> {
        self.execute_zpl_txg(
            cx,
            dataset_components,
            &ZplMutation::LinkEntry {
                source_object,
                parent_dir,
                name: name.to_vec(),
                timestamp,
            },
        )
    }

    /// Rename `(src_dir, src_name)` to `(dst_dir, dst_name)` with optional `expected_source_object`
    /// idempotency guard (so retrying after post-commit cancellation refuses duplicate renames).
    #[allow(clippy::too_many_arguments)]
    pub fn rename_entry(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        src_dir: u64,
        src_name: &[u8],
        dst_dir: u64,
        dst_name: &[u8],
        expected_source_object: Option<u64>,
        timestamp: Timestamp,
    ) -> ZfsTxOutcome<u64> {
        self.execute_zpl_txg(
            cx,
            dataset_components,
            &ZplMutation::RenameEntry {
                src_dir,
                src_name: src_name.to_vec(),
                dst_dir,
                dst_name: dst_name.to_vec(),
                expected_source_object,
                retain_replaced: None,
                timestamp,
            },
        )
    }

    /// Atomically exchange two existing names within one head dataset.
    ///
    /// Both entries may be nonempty directories, regular files or symbolic
    /// links, including different kinds. Native object/generation guards are
    /// mandatory: retrying an already committed swap with its original guards
    /// returns `ESTALE` rather than silently exchanging the names back.
    #[allow(clippy::too_many_arguments)]
    pub fn exchange_entries(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        src_dir: u64,
        src_name: &[u8],
        dst_dir: u64,
        dst_name: &[u8],
        source: ZfsObjectIdentity,
        target: ZfsObjectIdentity,
        timestamp: Timestamp,
    ) -> ZfsTxOutcome<u64> {
        self.execute_zpl_txg(
            cx,
            dataset_components,
            &ZplMutation::ExchangeEntries {
                src_dir,
                src_name: src_name.to_vec(),
                dst_dir,
                dst_name: dst_name.to_vec(),
                source,
                target,
                timestamp,
            },
        )
    }

    /// Unlink a regular file (`rmdir == false`) or remove an empty directory (`rmdir == true`).
    pub fn unlink_entry(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        parent_dir: u64,
        name: &[u8],
        rmdir: bool,
        timestamp: Timestamp,
    ) -> ZfsTxOutcome<u64> {
        self.execute_zpl_txg(
            cx,
            dataset_components,
            &ZplMutation::UnlinkEntry {
                parent_dir,
                name: name.to_vec(),
                rmdir,
                retain: None,
                timestamp,
            },
        )
    }

    /// Remove a name while retaining its final-link regular file in the native
    /// `DELETE_QUEUE`. A live handle may keep reading/writing the object until
    /// its owner calls [`Self::reap_unlinked_file`]. With other hard links, only
    /// the requested name is removed. The identity is checked before any writes.
    pub fn unlink_open_file(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        parent_dir: u64,
        name: &[u8],
        identity: ZfsUnlinkedObject,
        timestamp: Timestamp,
    ) -> ZfsTxOutcome<u64> {
        self.execute_zpl_txg(
            cx,
            dataset_components,
            &ZplMutation::UnlinkEntry {
                parent_dir,
                name: name.to_vec(),
                rmdir: false,
                retain: Some(identity),
                timestamp,
            },
        )
    }

    /// Atomically replace a name while preserving its open target in the native
    /// unlinked set. Source publication and target retention share one TXG.
    #[allow(clippy::too_many_arguments)]
    pub fn rename_retaining_open_target(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        src_dir: u64,
        src_name: &[u8],
        dst_dir: u64,
        dst_name: &[u8],
        expected_source_object: Option<u64>,
        target: ZfsUnlinkedObject,
        timestamp: Timestamp,
    ) -> ZfsTxOutcome<u64> {
        self.execute_zpl_txg(
            cx,
            dataset_components,
            &ZplMutation::RenameEntry {
                src_dir,
                src_name: src_name.to_vec(),
                dst_dir,
                dst_name: dst_name.to_vec(),
                expected_source_object,
                retain_replaced: Some(target),
                timestamp,
            },
        )
    }

    /// Inspect pending regular-file reclamation without mutating storage.
    /// Owners may drain this set when opening a fresh mount, before exposing
    /// any handles. Never reap it while another dataset consumer holds pins.
    pub fn pending_unlinks(
        &self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
    ) -> Result<Vec<ZfsUnlinkedObject>> {
        zpl_ops::pending_unlinks(
            cx,
            &mut self.open_read_objects(cx)?,
            dataset_components,
            &self.mos_features,
        )
    }

    /// Reclaim one generation-bound, zero-link regular file and remove its
    /// native queue entry in the same TXG. The caller must ensure no live handles
    /// remain; stale identities, live links, and unsupported ownership are refused.
    pub fn reap_unlinked_file(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        identity: ZfsUnlinkedObject,
    ) -> ZfsTxOutcome<u64> {
        self.execute_zpl_txg(
            cx,
            dataset_components,
            &ZplMutation::ReapUnlinked { identity },
        )
    }

    /// Create an atomic DSL snapshot (`dataset@snap_name`), returning the new snapshot MOS object ID.
    pub fn create_snapshot(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        snap_name: &[u8],
        timestamp: Timestamp,
    ) -> ZfsTxOutcome<u64> {
        self.execute_dsl_txg(
            cx,
            &DslMutation::CreateSnapshot {
                dataset: dataset_components.to_vec(),
                snap_name: snap_name.to_vec(),
                timestamp,
            },
        )
    }

    /// Destroy `dataset@snap_name` (or mark `DS_FLAG_DEFER_DESTROY` when `defer == true`
    /// and holds or clones remain), returning the snapshot MOS object ID.
    pub fn destroy_snapshot(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        snap_name: &[u8],
        defer: bool,
    ) -> ZfsTxOutcome<u64> {
        self.execute_dsl_txg(
            cx,
            &DslMutation::DestroySnapshot {
                dataset: dataset_components.to_vec(),
                snap_name: snap_name.to_vec(),
                defer,
            },
        )
    }

    /// Rename `dataset@old_snap_name` to `dataset@new_snap_name`.
    pub fn rename_snapshot(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        old_snap_name: &[u8],
        new_snap_name: &[u8],
    ) -> ZfsTxOutcome<u64> {
        self.execute_dsl_txg(
            cx,
            &DslMutation::RenameSnapshot {
                dataset: dataset_components.to_vec(),
                old_snap_name: old_snap_name.to_vec(),
                new_snap_name: new_snap_name.to_vec(),
            },
        )
    }

    /// Place a user hold `tag` (`DMU_OT_USERREFS = 41`) on `dataset@snap_name`.
    pub fn hold_snapshot(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        snap_name: &[u8],
        tag: &[u8],
        timestamp: Timestamp,
    ) -> ZfsTxOutcome<u64> {
        self.execute_dsl_txg(
            cx,
            &DslMutation::HoldSnapshot {
                dataset: dataset_components.to_vec(),
                snap_name: snap_name.to_vec(),
                tag: tag.to_vec(),
                timestamp,
            },
        )
    }

    /// Release a user hold `tag` on `dataset@snap_name` (auto-destroying the snapshot
    /// in the same TXG if `DS_FLAG_DEFER_DESTROY` is set and zero holds/clones remain).
    pub fn release_snapshot(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        snap_name: &[u8],
        tag: &[u8],
    ) -> ZfsTxOutcome<u64> {
        self.execute_dsl_txg(
            cx,
            &DslMutation::ReleaseSnapshot {
                dataset: dataset_components.to_vec(),
                snap_name: snap_name.to_vec(),
                tag: tag.to_vec(),
            },
        )
    }

    /// List active user holds on `dataset@snap_name`.
    pub fn list_holds(
        &self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        snap_name: &[u8],
    ) -> Result<Vec<ZfsHoldInfo>> {
        list_holds_in_mos(
            cx,
            &mut self.open_read_objects(cx)?,
            dataset_components,
            snap_name,
        )
    }

    /// Create bookmark `dataset#bookmark_name` from `@source_name` (`source_is_bookmark == false`)
    /// or `#source_name` (`source_is_bookmark == true`).
    pub fn create_bookmark(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        bookmark_name: &[u8],
        source_name: &[u8],
        source_is_bookmark: bool,
    ) -> ZfsTxOutcome<u64> {
        self.execute_dsl_txg(
            cx,
            &DslMutation::CreateBookmark {
                dataset: dataset_components.to_vec(),
                bookmark_name: bookmark_name.to_vec(),
                source_name: source_name.to_vec(),
                source_is_bookmark,
            },
        )
    }

    /// Destroy bookmark `dataset#bookmark_name`.
    pub fn destroy_bookmark(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        bookmark_name: &[u8],
    ) -> ZfsTxOutcome<u64> {
        self.execute_dsl_txg(
            cx,
            &DslMutation::DestroyBookmark {
                dataset: dataset_components.to_vec(),
                bookmark_name: bookmark_name.to_vec(),
            },
        )
    }

    /// List bookmarks on `dataset`.
    pub fn list_bookmarks(
        &self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
    ) -> Result<Vec<ZfsBookmarkInfo>> {
        list_bookmarks_in_mos(cx, &mut self.open_read_objects(cx)?, dataset_components)
    }

    /// Create a fresh child ZPL filesystem dataset under `parent_dataset`, returning its head MOS object ID.
    pub fn create_dataset(
        &mut self,
        cx: &Cx,
        parent_dataset: &[Vec<u8>],
        child_name: &[u8],
        initial_props: &[(String, ZfsPropertySetValue)],
        timestamp: Timestamp,
    ) -> ZfsTxOutcome<u64> {
        self.execute_dsl_txg(
            cx,
            &DslMutation::CreateDataset {
                parent_dataset: parent_dataset.to_vec(),
                child_name: child_name.to_vec(),
                initial_props: initial_props.to_vec(),
                encryption: None,
                timestamp,
            },
        )
    }

    /// Create a fresh child ZPL filesystem dataset with explicit native encryption parameters.
    ///
    /// When creating a new encryption root (`options.suite.is_active()`), the unwrapped key is
    /// inserted into this engine's keyring ONLY after the TXG commits durably across all 4 labels;
    /// pre-Uberblock failures leave the keyring untouched.
    #[allow(clippy::too_many_arguments)]
    pub fn create_encrypted_dataset(
        &mut self,
        cx: &Cx,
        parent_dataset: &[Vec<u8>],
        child_name: &[u8],
        initial_props: &[(String, ZfsPropertySetValue)],
        encryption: &ZfsEncryptionCreateOptions,
        timestamp: Timestamp,
    ) -> ZfsTxOutcome<u64> {
        self.execute_dsl_txg(
            cx,
            &DslMutation::CreateDataset {
                parent_dataset: parent_dataset.to_vec(),
                child_name: child_name.to_vec(),
                initial_props: initial_props.to_vec(),
                encryption: Some(encryption.clone()),
                timestamp,
            },
        )
    }

    /// Atomically rotate the wrapping key (and optional `keylocation`) of an encrypted root dataset
    /// without rewriting any dataset data blocks.
    pub fn change_key(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        new_material: &ZfsKeyMaterial,
        new_keylocation: Option<&[u8]>,
        pbkdf2_iters: Option<u64>,
        extra_entropy: &[u8],
    ) -> ZfsTxOutcome<u64> {
        self.execute_dsl_txg(
            cx,
            &DslMutation::ChangeKey {
                dataset: dataset_components.to_vec(),
                new_material: new_material.clone(),
                new_keylocation: new_keylocation.map(<[u8]>::to_vec),
                pbkdf2_iters,
                extra_entropy: extra_entropy.to_vec(),
            },
        )
    }

    /// Create a writable clone dataset from `origin_dataset@origin_snap` at `target_parent/target_name`,
    /// returning the clone's head MOS object ID.
    #[allow(clippy::too_many_arguments)]
    pub fn create_clone(
        &mut self,
        cx: &Cx,
        origin_dataset: &[Vec<u8>],
        origin_snap: &[u8],
        target_parent: &[Vec<u8>],
        target_name: &[u8],
        initial_props: &[(String, ZfsPropertySetValue)],
        timestamp: Timestamp,
    ) -> ZfsTxOutcome<u64> {
        self.execute_dsl_txg(
            cx,
            &DslMutation::CreateClone {
                origin_dataset: origin_dataset.to_vec(),
                origin_snap: origin_snap.to_vec(),
                target_parent: target_parent.to_vec(),
                target_name: target_name.to_vec(),
                initial_props: initial_props.to_vec(),
                timestamp,
            },
        )
    }

    /// Rename a non-root dataset (`old_dataset` -> `new_dataset`), transferring parent space/reservation accounting.
    pub fn rename_dataset(
        &mut self,
        cx: &Cx,
        old_dataset: &[Vec<u8>],
        new_dataset: &[Vec<u8>],
    ) -> ZfsTxOutcome<u64> {
        self.execute_dsl_txg(
            cx,
            &DslMutation::RenameDataset {
                old_dataset: old_dataset.to_vec(),
                new_dataset: new_dataset.to_vec(),
            },
        )
    }

    /// Destroy a leaf dataset or clone (reclaiming only `birth > origin_txg` blocks and auto-destroying
    /// any deferred-destroy origin snapshot when its last clone and hold are released).
    pub fn destroy_dataset(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
    ) -> ZfsTxOutcome<u64> {
        self.execute_dsl_txg(
            cx,
            &DslMutation::DestroyDataset {
                dataset: dataset_components.to_vec(),
            },
        )
    }

    /// Set a dataset property (`quota`, `refquota`, `reservation`, `refreservation`, `readonly`,
    /// `atime`, `recordsize`, `checksum`, or user property `ns:name`).
    pub fn set_property(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        name: &str,
        value: ZfsPropertySetValue,
    ) -> ZfsTxOutcome<u64> {
        self.execute_dsl_txg(
            cx,
            &DslMutation::SetProperty {
                dataset: dataset_components.to_vec(),
                name: name.to_owned(),
                value,
            },
        )
    }

    /// Inherit (clear local setting + `$iuv` / `$inherit`) a dataset property.
    pub fn inherit_property(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        name: &str,
    ) -> ZfsTxOutcome<u64> {
        self.execute_dsl_txg(
            cx,
            &DslMutation::InheritProperty {
                dataset: dataset_components.to_vec(),
                name: name.to_owned(),
            },
        )
    }

    /// Create a fresh native ZFS volume (`DMU_OST_ZVOL = 3`) under `parent_dataset`.
    pub fn zvol_create(
        &mut self,
        cx: &Cx,
        parent_dataset: &[Vec<u8>],
        name: &[u8],
        opts: &ZfsZvolCreateOptions,
    ) -> ZfsTxOutcome<ZfsZvolInfo> {
        let empty_bpobj_id = self.empty_bpobj_id;
        let order = self.order;
        self.execute_staged_txg_typed(
            cx,
            "zvol_create",
            |mos, mos_dirty_dnodes, draft_features, draft_alloc, new_txg, base_staged| {
                zvol_ops::stage_create_zvol(
                    cx,
                    mos,
                    parent_dataset,
                    name,
                    opts,
                    mos_dirty_dnodes,
                    draft_features,
                    empty_bpobj_id,
                    draft_alloc,
                    order,
                    new_txg,
                    base_staged,
                )
            },
        )
    }

    /// Destroy a native ZFS volume (`DMU_OST_ZVOL = 3`), reclaiming volume blocks,
    /// head-owned unclaimed ZIL tail blocks, and MOS objects.
    pub fn zvol_destroy(&mut self, cx: &Cx, dataset: &[Vec<u8>]) -> ZfsTxOutcome<u64> {
        let empty_bpobj_id = self.empty_bpobj_id;
        let order = self.order;
        self.execute_staged_txg(
            cx,
            "zvol_destroy",
            |mos, mos_dirty_dnodes, draft_features, draft_alloc, new_txg, base_staged| {
                zvol_ops::stage_destroy_zvol(
                    cx,
                    mos,
                    dataset,
                    mos_dirty_dnodes,
                    draft_features,
                    empty_bpobj_id,
                    draft_alloc,
                    order,
                    new_txg,
                    base_staged,
                )
            },
        )
    }

    /// Resize a native ZFS volume (`volsize`), retiring truncated tail leaf and indirect
    /// blocks on shrink and updating Object 2 (`ZVOL_ZAP_OBJ`) `"size"` atomically in one TXG.
    pub fn zvol_resize(
        &mut self,
        cx: &Cx,
        dataset: &[Vec<u8>],
        new_volsize: u64,
    ) -> ZfsTxOutcome<u64> {
        let empty_bpobj_id = self.empty_bpobj_id;
        let order = self.order;
        self.execute_staged_txg(
            cx,
            "zvol_resize",
            |mos, mos_dirty_dnodes, draft_features, draft_alloc, new_txg, base_staged| {
                zvol_ops::stage_resize_zvol(
                    cx,
                    mos,
                    dataset,
                    new_volsize,
                    mos_dirty_dnodes,
                    draft_features,
                    empty_bpobj_id,
                    draft_alloc,
                    order,
                    new_txg,
                    base_staged,
                )
            },
        )
    }

    /// Create an atomic snapshot on a native ZFS volume (`DMU_OST_ZVOL = 3`).
    pub fn zvol_snapshot(
        &mut self,
        cx: &Cx,
        dataset: &[Vec<u8>],
        snap_name: &[u8],
        timestamp: Timestamp,
    ) -> ZfsTxOutcome<u64> {
        let empty_bpobj_id = self.empty_bpobj_id;
        let order = self.order;
        self.execute_staged_txg(
            cx,
            "zvol_snapshot",
            |mos, mos_dirty_dnodes, draft_features, draft_alloc, new_txg, base_staged| {
                zvol_ops::stage_snapshot_zvol(
                    cx,
                    mos,
                    dataset,
                    snap_name,
                    timestamp,
                    mos_dirty_dnodes,
                    draft_features,
                    empty_bpobj_id,
                    draft_alloc,
                    order,
                    new_txg,
                    base_staged,
                )
            },
        )
    }

    /// Inspect geometry, dataset identity, and effective readonly state of a ZVOL head or snapshot.
    pub fn zvol_info(
        &self,
        cx: &Cx,
        dataset: &[Vec<u8>],
        snapshot: Option<&[u8]>,
    ) -> Result<ZfsZvolInfo> {
        let mut mos = self.open_read_objects(cx)?;
        zvol_ops::inspect_zvol_info(cx, &mut mos, dataset, snapshot)
    }

    /// Sector-aligned (`512` B), bounded (`<= 16 MiB`) read from a ZVOL head or snapshot.
    /// Preserves `out` untouched on error and zero-fills sparse holes and unallocated tails.
    pub fn zvol_read_at(
        &self,
        cx: &Cx,
        dataset: &[Vec<u8>],
        snapshot: Option<&[u8]>,
        offset: u64,
        out: &mut [u8],
    ) -> Result<()> {
        let mut mos = self.open_read_objects(cx)?;
        zvol_ops::read_zvol_at(cx, &mut mos, dataset, snapshot, offset, out)
    }

    /// Sector-aligned (`512` B), bounded (`<= 16 MiB`) COW write to a native ZVOL head.
    /// Performs sub-`volblocksize` read-modify-write COW and publishes one durable 4-label TXG.
    pub fn zvol_write_at(
        &mut self,
        cx: &Cx,
        dataset: &[Vec<u8>],
        offset: u64,
        data: &[u8],
        checksum: ZfsDataChecksum,
    ) -> ZfsTxOutcome<ZfsCommitReceipt> {
        if checksum == ZfsDataChecksum::Inherit {
            return ZfsTxOutcome::NotCommitted(unsupported(
                "checksum inheritance is only supported for native ZPL writes",
            ));
        }
        let empty_bpobj_id = self.empty_bpobj_id;
        let order = self.order;
        let outcome = self.execute_staged_txg(
            cx,
            "zvol_write_at",
            |mos, mos_dirty_dnodes, draft_features, draft_alloc, new_txg, base_staged| {
                zvol_ops::stage_zvol_write_at(
                    cx,
                    mos,
                    dataset,
                    offset,
                    data,
                    checksum,
                    mos_dirty_dnodes,
                    draft_features,
                    empty_bpobj_id,
                    draft_alloc,
                    order,
                    new_txg,
                    base_staged,
                )
            },
        );
        self.map_receipt_outcome(outcome)
    }

    /// Sector-aligned (`512` B) discard/TRIM on a native ZVOL head.
    /// Full `volblocksize`-aligned allocated blocks punch native holes; partial sub-block spans
    /// zero covered bytes on allocated blocks without allocating existing holes.
    pub fn zvol_discard(
        &mut self,
        cx: &Cx,
        dataset: &[Vec<u8>],
        offset: u64,
        len: u64,
        checksum: ZfsDataChecksum,
    ) -> ZfsTxOutcome<ZfsCommitReceipt> {
        if checksum == ZfsDataChecksum::Inherit {
            return ZfsTxOutcome::NotCommitted(unsupported(
                "checksum inheritance is only supported for native ZPL writes",
            ));
        }
        let empty_bpobj_id = self.empty_bpobj_id;
        let order = self.order;
        let outcome = self.execute_staged_txg(
            cx,
            "zvol_discard",
            |mos, mos_dirty_dnodes, draft_features, draft_alloc, new_txg, base_staged| {
                zvol_ops::stage_zvol_discard(
                    cx,
                    mos,
                    dataset,
                    offset,
                    len,
                    checksum,
                    mos_dirty_dnodes,
                    draft_features,
                    empty_bpobj_id,
                    draft_alloc,
                    order,
                    new_txg,
                    base_staged,
                )
            },
        );
        self.map_receipt_outcome(outcome)
    }

    /// Commit a coalesced set of full `volblocksize` writes (`Some(block)`) and native hole
    /// punches (`None`) atomically in a single durable 4-label TXG.
    pub fn zvol_batch_apply(
        &mut self,
        cx: &Cx,
        dataset: &[Vec<u8>],
        dirty_blocks: &BTreeMap<u64, Option<Vec<u8>>>,
        checksum: ZfsDataChecksum,
    ) -> ZfsTxOutcome<ZfsCommitReceipt> {
        if checksum == ZfsDataChecksum::Inherit {
            return ZfsTxOutcome::NotCommitted(unsupported(
                "checksum inheritance is only supported for native ZPL writes",
            ));
        }
        let empty_bpobj_id = self.empty_bpobj_id;
        let order = self.order;
        let outcome = self.execute_staged_txg(
            cx,
            "zvol_batch_apply",
            |mos, mos_dirty_dnodes, draft_features, draft_alloc, new_txg, base_staged| {
                zvol_ops::stage_zvol_batch_apply(
                    cx,
                    mos,
                    dataset,
                    dirty_blocks,
                    checksum,
                    mos_dirty_dnodes,
                    draft_features,
                    empty_bpobj_id,
                    draft_alloc,
                    order,
                    new_txg,
                    base_staged,
                )
            },
        );
        self.map_receipt_outcome(outcome)
    }

    /// Issue a member-wide device durability barrier and return a [`ZfsCommitReceipt`]
    /// pinned to the currently committed TXG (`tx_published = false`).
    pub fn zvol_flush(&self, cx: &Cx) -> Result<ZfsCommitReceipt> {
        self.sync_devices(cx)?;
        Ok(ZfsCommitReceipt {
            storage: self.storage_identity.clone(),
            committed_txg: self.committed_txg,
            published_slot: self.committed_slot,
            generation: self.generation,
            token: None,
            tx_published: false,
        })
    }

    fn map_receipt_outcome(&self, outcome: ZfsTxOutcome<u64>) -> ZfsTxOutcome<ZfsCommitReceipt> {
        match outcome {
            ZfsTxOutcome::Committed { token, .. } => {
                let receipt = ZfsCommitReceipt {
                    storage: self.storage_identity.clone(),
                    committed_txg: token.committed_txg(),
                    published_slot: token.published_slot(),
                    generation: token.generation(),
                    token: Some(token.clone()),
                    tx_published: true,
                };
                ZfsTxOutcome::Committed {
                    value: receipt,
                    token,
                }
            }
            ZfsTxOutcome::NotCommitted(err) => ZfsTxOutcome::NotCommitted(err),
            ZfsTxOutcome::Uncertain {
                reason,
                target_txg,
                target_slot,
            } => ZfsTxOutcome::Uncertain {
                reason,
                target_txg,
                target_slot,
            },
        }
    }

    fn emit_event(
        &mut self,
        operation: &str,
        stage: ZfsPersistenceStage,
        txg: u64,
        member_index: usize,
        offset: u64,
        bytes: usize,
    ) -> Result<()> {
        self.seq += 1;
        let event = ZfsPersistenceEvent {
            seq: self.seq,
            operation: operation.to_owned(),
            stage,
            txg,
            member_index,
            offset,
            bytes,
        };
        self.events.push(event.clone());
        if let Some(hook) = self.fault_hook.as_mut() {
            hook(&event)?;
        }
        Ok(())
    }

    fn execute_zpl_txg(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        mutation: &ZplMutation,
    ) -> ZfsTxOutcome<u64> {
        let empty_bpobj_id = self.empty_bpobj_id;
        let order = self.order;
        self.execute_staged_txg(
            cx,
            mutation.op_name(),
            |mos, mos_dirty_dnodes, draft_features, draft_alloc, new_txg, base_staged| {
                stage_zpl_mutation(
                    cx,
                    mos,
                    dataset_components,
                    mutation,
                    mos_dirty_dnodes,
                    draft_features,
                    empty_bpobj_id,
                    draft_alloc,
                    order,
                    new_txg,
                    base_staged,
                )
            },
        )
    }

    fn execute_dsl_txg(&mut self, cx: &Cx, mutation: &DslMutation) -> ZfsTxOutcome<u64> {
        let empty_bpobj_id = self.empty_bpobj_id;
        let order = self.order;
        let outcome = self.execute_staged_txg_typed(
            cx,
            mutation.op_name(),
            |mos, mos_dirty_dnodes, draft_features, draft_alloc, new_txg, base_staged| {
                let staged = stage_dsl_mutation(
                    cx,
                    mos,
                    mutation,
                    mos_dirty_dnodes,
                    draft_features,
                    empty_bpobj_id,
                    draft_alloc,
                    order,
                    new_txg,
                    base_staged,
                )?;
                let value = staged.value;
                Ok((staged, value))
            },
        );
        match outcome {
            ZfsTxOutcome::Committed { value, token } => {
                if let Some((root_ddobj, unwrapped)) = value.new_root_key {
                    let _ = self.keyring.insert_unwrapped(root_ddobj, unwrapped);
                }
                ZfsTxOutcome::Committed {
                    value: value.value,
                    token,
                }
            }
            ZfsTxOutcome::NotCommitted(err) => ZfsTxOutcome::NotCommitted(err),
            ZfsTxOutcome::Uncertain {
                reason,
                target_txg,
                target_slot,
            } => ZfsTxOutcome::Uncertain {
                reason,
                target_txg,
                target_slot,
            },
        }
    }

    fn execute_staged_txg(
        &mut self,
        cx: &Cx,
        op_name: &str,
        stage_fn: impl FnOnce(
            &mut Objects,
            &mut BTreeMap<u64, Vec<u8>>,
            &mut MosFeatureState,
            &mut PoolSpaceAllocator,
            u64,
            &mut Vec<StagedBlockWrite>,
        ) -> Result<u64>,
    ) -> ZfsTxOutcome<u64> {
        self.execute_staged_txg_typed(
            cx,
            op_name,
            |mos, mos_dirty, features, alloc, new_txg, staged| {
                let val = stage_fn(mos, mos_dirty, features, alloc, new_txg, staged)?;
                Ok((val, val))
            },
        )
    }

    #[allow(clippy::too_many_lines)]
    fn execute_staged_txg_typed<T>(
        &mut self,
        cx: &Cx,
        op_name: &str,
        stage_fn: impl FnOnce(
            &mut Objects,
            &mut BTreeMap<u64, Vec<u8>>,
            &mut MosFeatureState,
            &mut PoolSpaceAllocator,
            u64,
            &mut Vec<StagedBlockWrite>,
        ) -> Result<(T, u64)>,
    ) -> ZfsTxOutcome<T> {
        self.execute_staged_txg_with_mos(cx, op_name, None, &[], stage_fn)
    }

    fn execute_staged_txg_with_mos<T>(
        &mut self,
        cx: &Cx,
        op_name: &str,
        pre_opened_mos: Option<Objects>,
        pre_commit_writes: &[(usize, u64, Vec<u8>)],
        stage_fn: impl FnOnce(
            &mut Objects,
            &mut BTreeMap<u64, Vec<u8>>,
            &mut MosFeatureState,
            &mut PoolSpaceAllocator,
            u64,
            &mut Vec<StagedBlockWrite>,
        ) -> Result<(T, u64)>,
    ) -> ZfsTxOutcome<T> {
        self.execute_staged_txg_publication(
            cx,
            op_name,
            pre_opened_mos,
            pre_commit_writes,
            true,
            stage_fn,
        )
    }

    /// Topology changes defer acknowledgement until their label configurations
    /// have also crossed every required durability barrier.
    #[allow(clippy::too_many_lines)]
    fn execute_staged_txg_publication<T>(
        &mut self,
        cx: &Cx,
        op_name: &str,
        pre_opened_mos: Option<Objects>,
        pre_commit_writes: &[(usize, u64, Vec<u8>)],
        acknowledge: bool,
        stage_fn: impl FnOnce(
            &mut Objects,
            &mut BTreeMap<u64, Vec<u8>>,
            &mut MosFeatureState,
            &mut PoolSpaceAllocator,
            u64,
            &mut Vec<StagedBlockWrite>,
        ) -> Result<(T, u64)>,
    ) -> ZfsTxOutcome<T> {
        if self.poisoned_uncertain {
            return ZfsTxOutcome::NotCommitted(unsupported(
                "ZFS writer requires fresh native recovery after uncertain publication or interrupted repair",
            ));
        }
        if self.allocator.raidz_expanding && op_name != "zfs_pool_expand_raidz_complete" {
            return ZfsTxOutcome::NotCommitted(unsupported(
                "ZFS RAIDZ expansion must complete before foreground transactions resume",
            ));
        }
        if let Err(err) = checkpoint(cx) {
            return ZfsTxOutcome::NotCommitted(err);
        }
        let Some(new_txg) = self.committed_txg.checked_add(1) else {
            return ZfsTxOutcome::NotCommitted(corrupt("ZFS TXG counter overflow"));
        };
        let target_slot = (new_txg as usize) % self.slots_per_label;

        // 1. Stage the entire COW DMU + space-map convergence in memory BEFORE any device write!
        let mut mos = match pre_opened_mos {
            Some(m) => m,
            None => match self.open_read_objects(cx) {
                Ok(m) => m,
                Err(err) => return ZfsTxOutcome::NotCommitted(err),
            },
        };
        let mut draft_alloc = self.allocator.clone();
        let mut draft_features = self.mos_features.clone();
        let mut mos_dirty_dnodes = BTreeMap::new();
        let mut base_staged = Vec::new();

        let (result_typed, result_val) = match stage_fn(
            &mut mos,
            &mut mos_dirty_dnodes,
            &mut draft_features,
            &mut draft_alloc,
            new_txg,
            &mut base_staged,
        ) {
            Ok(val) => val,
            Err(err) => return ZfsTxOutcome::NotCommitted(err),
        };

        let (new_root_bp, mut converged_alloc, converged_features, staged_writes) =
            match finalize_mos_and_space_maps_to_convergence(
                cx,
                &mut mos,
                &self.mos_os,
                &self.current_uberblock.root,
                &mos_dirty_dnodes,
                &draft_features,
                &draft_alloc,
                &base_staged,
                self.order,
                new_txg,
            ) {
                Ok(res) => res,
                Err(err) => return ZfsTxOutcome::NotCommitted(err),
            };

        // Extract the new MOS ObjectSet from the last staged `MosRoot` write for state advance.
        let Some(mos_root_write) = staged_writes
            .iter()
            .rfind(|w| w.bucket == WriteBucket::MosRoot)
        else {
            return ZfsTxOutcome::NotCommitted(corrupt("missing staged MOS root write"));
        };
        let next_mos_os = match ObjectSet::parse(&mos_root_write.bytes, self.order) {
            Ok(os) => os,
            Err(e) => return ZfsTxOutcome::NotCommitted(parse_err(&e)),
        };

        // Bind every native child to its admitted physical device before any write.
        // Argument order is unrelated to native vdev or parity-column IDs.
        let write_members = match self.staged_write_members(&converged_alloc, &staged_writes) {
            Ok(members) => members,
            Err(err) => return ZfsTxOutcome::NotCommitted(err),
        };

        // 2. Persist any pre-commit topology reflow writes + strictly child-before-parent
        //    blocks across all members BEFORE touching Uberblocks!
        // Retain independent handles to the same admitted devices while updating
        // engine state. Every early return drops all guards and aborts the epoch.
        let pool = self.pool.clone();
        let mut protection = match pool.defer_protection(cx) {
            Ok(holds) => holds,
            Err(error) => return ZfsTxOutcome::NotCommitted(error),
        };
        let member_count = pool.leaves().len();
        if !pre_commit_writes.is_empty() {
            for (m_idx, phys_off, bytes) in pre_commit_writes {
                if *m_idx >= member_count {
                    return ZfsTxOutcome::NotCommitted(corrupt(
                        "pre-commit write member index out of bounds",
                    ));
                }
                if let Err(err) = pool.leaves()[*m_idx].write_raw(cx, *phys_off, bytes) {
                    return ZfsTxOutcome::NotCommitted(err);
                }
            }
            for m_idx in 0..member_count {
                if let Err(err) = pool.leaves()[m_idx].sync_raw(cx) {
                    return ZfsTxOutcome::NotCommitted(err);
                }
            }
        }
        for bucket in [
            WriteBucket::ChildBlocks,
            WriteBucket::DatasetMetadata,
            WriteBucket::MosSpaceMap,
            WriteBucket::MosRoot,
        ] {
            let bucket_writes: Vec<_> = staged_writes
                .iter()
                .filter(|w| w.bucket == bucket)
                .collect();
            if bucket_writes.is_empty() {
                continue;
            }
            for w in &bucket_writes {
                if let Err(err) = self.write_staged_block_to_topology(
                    cx,
                    op_name,
                    new_txg,
                    w,
                    &converged_alloc,
                    &write_members,
                ) {
                    return ZfsTxOutcome::NotCommitted(err);
                }
            }
            for m_idx in 0..member_count {
                let barrier_stage = match bucket {
                    WriteBucket::ChildBlocks => ZfsPersistenceStage::ChildBlocksBarrier {
                        member_index: m_idx,
                    },
                    WriteBucket::DatasetMetadata => ZfsPersistenceStage::DatasetMetadataBarrier {
                        member_index: m_idx,
                    },
                    WriteBucket::MosSpaceMap => ZfsPersistenceStage::MosSpaceMapBarrier {
                        member_index: m_idx,
                    },
                    WriteBucket::MosRoot => ZfsPersistenceStage::MosRootBarrier {
                        member_index: m_idx,
                    },
                };
                if let Err(err) = self.emit_event(op_name, barrier_stage, new_txg, m_idx, 0, 0) {
                    return ZfsTxOutcome::NotCommitted(err);
                }
                if let Err(err) = self.pool.leaves()[m_idx].sync_raw(cx) {
                    return ZfsTxOutcome::NotCommitted(err);
                }
            }
        }

        // Cancellation after staged barriers still precedes native root publication.
        // Preserve NotCommitted while no uberblock has been touched.
        if let Err(err) = checkpoint(cx) {
            return ZfsTxOutcome::NotCommitted(err);
        }

        // 3. Synchronized 2-wave 4-label Uberblock publication (`L0..L1` -> sync -> `L2..L3` -> sync).
        // Errors after starting a write and before all publication barriers succeed
        // are `Uncertain`. After the final barrier, the commit is known durable.
        let next_ts = self.current_uberblock.timestamp.saturating_add(1);
        let new_ub = Uberblock {
            order: self.order,
            version: self.storage_identity.version,
            txg: new_txg,
            guid_sum: self.storage_identity.guid_sum,
            timestamp: next_ts,
            root: new_root_bp,
            checkpoint_txg: self.current_uberblock.checkpoint_txg,
            raidz_reflow_info: self.current_uberblock.raidz_reflow_info,
        };
        let sw_version =
            self.current_software_version
                .unwrap_or(if self.storage_identity.version == 5000 {
                    5000
                } else {
                    self.storage_identity.version
                });

        let mut first_ub_written = false;
        for (wave_idx, labels) in [(1_u8, [0_usize, 1]), (2_u8, [2_usize, 3])] {
            for m_idx in 0..member_count {
                for l_idx in labels {
                    let ub_off = self.label_offsets_per_member[m_idx][l_idx]
                        + UBERBLOCK_RING_OFFSET
                        + (target_slot * self.slot_bytes) as u64;
                    let encoded =
                        match new_ub.encode_with_meta(self.slot_bytes, ub_off, sw_version, 0, 0) {
                            Ok(b) => b,
                            Err(e) => {
                                let err = parse_err(&e);
                                if first_ub_written {
                                    self.poisoned_uncertain = true;
                                    return ZfsTxOutcome::Uncertain {
                                        reason: err,
                                        target_txg: new_txg,
                                        target_slot,
                                    };
                                }
                                return ZfsTxOutcome::NotCommitted(err);
                            }
                        };
                    if let Err(err) = self.emit_event(
                        op_name,
                        ZfsPersistenceStage::UberblockWrite {
                            member_index: m_idx,
                            label: l_idx,
                            slot: target_slot,
                        },
                        new_txg,
                        m_idx,
                        ub_off,
                        encoded.len(),
                    ) {
                        if first_ub_written {
                            self.poisoned_uncertain = true;
                            return ZfsTxOutcome::Uncertain {
                                reason: err,
                                target_txg: new_txg,
                                target_slot,
                            };
                        }
                        return ZfsTxOutcome::NotCommitted(err);
                    }
                    first_ub_written = true;
                    if let Err(err) = self.pool.leaves()[m_idx].write_raw(cx, ub_off, &encoded) {
                        self.poisoned_uncertain = true;
                        return ZfsTxOutcome::Uncertain {
                            reason: err,
                            target_txg: new_txg,
                            target_slot,
                        };
                    }
                }
            }
            for m_idx in 0..member_count {
                if let Err(err) = self.emit_event(
                    op_name,
                    ZfsPersistenceStage::UberblockBarrier {
                        member_index: m_idx,
                        wave: wave_idx,
                    },
                    new_txg,
                    m_idx,
                    0,
                    0,
                ) {
                    self.poisoned_uncertain = true;
                    return ZfsTxOutcome::Uncertain {
                        reason: err,
                        target_txg: new_txg,
                        target_slot,
                    };
                }
                if let Err(err) = self.pool.leaves()[m_idx].sync_raw(cx) {
                    self.poisoned_uncertain = true;
                    return ZfsTxOutcome::Uncertain {
                        reason: err,
                        target_txg: new_txg,
                        target_slot,
                    };
                }
            }
        }

        // 4. Every required device barrier succeeded. Advance the in-memory root
        // and allocator before observing any further cancellation or reply fault.
        // A cancelled reply cannot make this durable TXG uncertain, poison the
        // owner, or leave subsequent requests using the predecessor allocator.
        for hold in &mut protection {
            hold.complete();
        }
        let allow_v2 = converged_alloc.spacemap_v2_active;
        for ms in &mut converged_alloc.metaslabs {
            if ms.is_dirty() {
                if let Ok(new_stream) = ms.build_full_stream(new_txg, self.order, allow_v2) {
                    ms.base_stream = new_stream;
                }
                ms.allocatable_map = ms.final_map.clone();
                ms.txg_allocs.clear();
                ms.txg_frees.clear();
            }
        }
        self.allocator = converged_alloc;
        self.mos_features = converged_features;
        let _ = &self.read_features;
        self.mos_os = next_mos_os;
        self.committed_txg = new_txg;
        self.committed_slot = target_slot;
        self.current_uberblock = new_ub;
        self.generation += 1;

        let root_bp_bytes = self.current_uberblock.root.encode(self.order);
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.storage_identity.pool_guid.to_le_bytes());
        hasher.update(&self.storage_identity.guid_sum.to_le_bytes());
        hasher.update(&new_txg.to_le_bytes());
        hasher.update(&(target_slot as u64).to_le_bytes());
        hasher.update(&root_bp_bytes);
        hasher.update(op_name.as_bytes());
        hasher.update(&result_val.to_le_bytes());
        let operation_digest = *hasher.finalize().as_bytes();

        let token = ZfsDurableToken {
            storage: self.storage_identity.clone(),
            committed_txg: new_txg,
            published_slot: target_slot,
            root_bp: root_bp_bytes,
            generation: self.generation,
            operation_digest,
        };
        // These events concern delivery of a known result, not native durability.
        // Preserve the token even if the request is cancelled or its reply fails:
        // the caller can reconcile the committed operation without replaying it.
        if acknowledge {
            self.acknowledge_committed_txg(op_name);
        }
        ZfsTxOutcome::Committed {
            value: result_typed,
            token,
        }
    }

    /// Deliver a known durable result after its enclosing lifecycle transition.
    /// A reply fault cannot undo either the native root or its completed labels.
    fn acknowledge_committed_txg(&mut self, op_name: &str) {
        let _ = self.emit_event(
            op_name,
            ZfsPersistenceStage::BeforeAcknowledge,
            self.committed_txg,
            0,
            0,
            0,
        );
        let _ = self.emit_event(
            op_name,
            ZfsPersistenceStage::AckPublished,
            self.committed_txg,
            0,
            0,
            0,
        );
    }

    /// Resolve the selected allocator's native child order once for the whole TXG.
    /// A missing, duplicated, or foreign route must fail before any physical write.
    fn staged_write_members(
        &self,
        allocation: &PoolSpaceAllocator,
        staged: &[StagedBlockWrite],
    ) -> Result<Vec<usize>> {
        let supplied = &self.storage_identity.member_guids;
        if supplied.len() != self.pool.leaves().len() {
            return Err(corrupt(
                "ZFS member GUID count disagrees with supplied devices",
            ));
        }
        let supplied_indices: BTreeMap<_, _> = supplied
            .iter()
            .copied()
            .enumerate()
            .map(|(index, guid)| (guid, index))
            .collect();
        if supplied_indices.len() != supplied.len() || supplied_indices.contains_key(&0) {
            return Err(corrupt("duplicate or zero supplied ZFS member GUID"));
        }
        let expected_count = match &allocation.write_topology {
            dmu_cow::AllocatorWriteTopology::LeafOrMirror => allocation.write_member_guids.len(),
            dmu_cow::AllocatorWriteTopology::Raidz { width, .. } => *width,
            dmu_cow::AllocatorWriteTopology::Draid(config) => config.children,
        };
        if expected_count == 0 || allocation.write_member_guids.len() != expected_count {
            return Err(corrupt(
                "ZFS write geometry disagrees with native child GUIDs",
            ));
        }
        if staged
            .iter()
            .any(|write| write.vdev_id != allocation.vdev_id)
        {
            return Err(corrupt("staged ZFS write targets a foreign allocator vdev"));
        }
        let mut seen = BTreeSet::new();
        allocation
            .write_member_guids
            .iter()
            .map(|guid| {
                if *guid == 0 || !seen.insert(*guid) {
                    return Err(corrupt("duplicate or zero native ZFS child GUID"));
                }
                supplied_indices.get(guid).copied().ok_or_else(|| {
                    unsupported("native ZFS write child has no supplied physical device")
                })
            })
            .collect()
    }

    /// Fan out a single staged block using the preflighted native-child mapping.
    fn write_staged_block_to_topology(
        &mut self,
        cx: &Cx,
        op_name: &str,
        new_txg: u64,
        w: &StagedBlockWrite,
        allocation: &PoolSpaceAllocator,
        members: &[usize],
    ) -> Result<()> {
        let stage_for = |member_index: usize| match w.bucket {
            WriteBucket::ChildBlocks => ZfsPersistenceStage::ChildBlocksWrite { member_index },
            WriteBucket::DatasetMetadata => {
                ZfsPersistenceStage::DatasetMetadataWrite { member_index }
            }
            WriteBucket::MosSpaceMap => ZfsPersistenceStage::MosSpaceMapWrite { member_index },
            WriteBucket::MosRoot => ZfsPersistenceStage::MosRootWrite { member_index },
        };
        match &allocation.write_topology {
            dmu_cow::AllocatorWriteTopology::LeafOrMirror => {
                let phys_off = DATA_OFFSET + w.dva_offset;
                for &m_idx in members {
                    self.emit_event(
                        op_name,
                        stage_for(m_idx),
                        new_txg,
                        m_idx,
                        phys_off,
                        w.bytes.len(),
                    )?;
                    self.pool.leaves()[m_idx].write_raw(cx, phys_off, &w.bytes)?;
                }
            }
            dmu_cow::AllocatorWriteTopology::Raidz { parity, width } => {
                let ashift = allocation.ashift;
                let (columns, payloads) = if *parity == 1 {
                    let map = ffs_ondisk::zfs::raidz::Raidz1Map::new_wide(
                        w.dva_offset,
                        w.bytes.len(),
                        ashift,
                        *width,
                    )
                    .map_err(|e| parse_err(&e))?;
                    let payloads = map.encode(&w.bytes).map_err(|e| parse_err(&e))?;
                    (map.columns().to_vec(), payloads)
                } else {
                    let map = ffs_ondisk::zfs::raidz::parity::RaidzParityMap::new_wide(
                        w.dva_offset,
                        w.bytes.len(),
                        ashift,
                        *width,
                        *parity,
                    )
                    .map_err(|e| parse_err(&e))?;
                    let payloads = map.encode(&w.bytes).map_err(|e| parse_err(&e))?;
                    (map.columns().to_vec(), payloads)
                };
                for (col, payload) in columns.iter().zip(&payloads) {
                    if payload.is_empty() {
                        continue;
                    }
                    let phys_off = DATA_OFFSET + col.offset;
                    let m_idx = members[col.child_id];
                    self.emit_event(
                        op_name,
                        stage_for(m_idx),
                        new_txg,
                        m_idx,
                        phys_off,
                        payload.len(),
                    )?;
                    self.pool.leaves()[m_idx].write_raw(cx, phys_off, payload)?;
                }
            }
            dmu_cow::AllocatorWriteTopology::Draid(draid_cfg) => {
                let map =
                    ffs_ondisk::zfs::draid::DraidMap::new(draid_cfg, w.dva_offset, w.bytes.len())
                        .map_err(|e| parse_err(&e))?;
                let encoded_rows = map.encode_rows(&w.bytes).map_err(|e| parse_err(&e))?;
                for (row, row_payloads) in map.rows().iter().zip(&encoded_rows) {
                    for (col, payload) in row.columns.iter().zip(row_payloads) {
                        if payload.is_empty() {
                            continue;
                        }
                        let phys_off = DATA_OFFSET + col.offset;
                        let m_idx = members[col.child_id];
                        self.emit_event(
                            op_name,
                            stage_for(m_idx),
                            new_txg,
                            m_idx,
                            phys_off,
                            payload.len(),
                        )?;
                        self.pool.leaves()[m_idx].write_raw(cx, phys_off, payload)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Rewrite all 4 vdev label configuration blocks (`112 KiB` XDR nvlist +
    /// offset-salted SHA-256 `zio_eck_t`) across all members in 2 synchronized
    /// waves (`L0..L1 -> sync -> L2..L3 -> sync`).
    pub(super) fn publish_labels_2wave(
        &mut self,
        cx: &Cx,
        op_name: &str,
        txg: u64,
        encoded_nvlists_per_member: &[Vec<u8>],
    ) -> Result<()> {
        let member_count = self.pool.leaves().len();
        if encoded_nvlists_per_member.len() != member_count {
            return Err(corrupt("label payload count disagrees with member count"));
        }
        for (wave, labels) in [(1_u8, [0_usize, 1]), (2_u8, [2_usize, 3])] {
            for (m_idx, packed) in encoded_nvlists_per_member.iter().enumerate() {
                if packed.len() > LABEL_CONFIG_BYTES - 40 {
                    return Err(corrupt("encoded label nvlist exceeds 112 KiB label area"));
                }
                for l_idx in labels {
                    let cfg_off = self.label_offsets_per_member[m_idx][l_idx] + LABEL_CONFIG_OFFSET;
                    let mut raw = vec![0_u8; LABEL_CONFIG_BYTES];
                    raw[..packed.len()].copy_from_slice(packed);
                    stamp_label_checksum(&mut raw, cfg_off, self.order)
                        .map_err(|e| parse_err(&e))?;
                    self.emit_event(
                        op_name,
                        ZfsPersistenceStage::LabelConfigWrite {
                            member_index: m_idx,
                            label: l_idx,
                        },
                        txg,
                        m_idx,
                        cfg_off,
                        raw.len(),
                    )?;
                    self.pool.leaves()[m_idx].write_raw(cx, cfg_off, &raw)?;
                }
            }
            for m_idx in 0..member_count {
                self.emit_event(
                    op_name,
                    ZfsPersistenceStage::LabelConfigBarrier {
                        member_index: m_idx,
                        wave,
                    },
                    txg,
                    m_idx,
                    0,
                    0,
                )?;
                self.pool.leaves()[m_idx].sync_raw(cx)?;
            }
        }
        Ok(())
    }
}
