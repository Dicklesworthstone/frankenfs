//! Explicitly admitted native ZFS metaslab allocation, COW DMU/ZPL mutations,
//! child-before-parent persistence barriers, synchronized 4-label Uberblock
//! publication, and storage/topology/TXG-bound durable commit tokens.
//!
//! Preserves read-only admission on [`crate::Leaf`], [`crate::Pool`], [`crate::Objects`],
//! [`crate::Zpl`], and [`crate::ZfsFs`]: native writes require opening a
//! [`ZfsTransactionEngine`] with explicit [`ZfsWriteOptions`] (never `import_active`
//! or force-import).

mod dmu_cow;
mod zpl_ops;

use std::collections::BTreeMap;
use std::path::Path;

use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_error::{FfsError, Result};
use ffs_ondisk::zfs::{
    BlockPointer, DATA_OFFSET, Endian, UBERBLOCK_RING_BYTES, UBERBLOCK_RING_OFFSET, Uberblock,
    UberblockMmpInfo,
};
use ffs_ondisk::zfs_dmu::ObjectSet;
use ffs_ondisk::zfs_zpl::Timestamp;
use ffs_types::ParseError;
use serde::Serialize;

use crate::reader::dmu::Objects;
use crate::reader::dmu::allocation::AllocationLimits;
use crate::reader::dmu::scrub::ScrubLimits;
use crate::{Leaf, Pool};

use self::dmu_cow::{
    DMU_OT_OBJSET, PoolSpaceAllocator, WriteBucket, finalize_mos_and_space_maps_to_convergence,
    zap_optional_u64, zap_required_u64,
};
pub use self::zpl_ops::ZfsDataChecksum;
use self::zpl_ops::{ZplMutation, stage_zpl_mutation};

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
    Mirror { width: usize },
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

/// Admitted write-only feature GUIDs in `features_for_write` (`count > 0` allowed).
fn is_admitted_active_write_feature(guid: &str) -> bool {
    matches!(
        guid,
        "com.delphix:async_destroy"
            | "com.delphix:empty_bpobj"
            | "com.delphix:spacemap_histogram"
            | "com.delphix:enabled_txg"
            | "com.delphix:spacemap_v2"
            | "com.delphix:bookmarks"
            | "com.joyent:filesystem_limits"
            | "org.zfsonlinux:userobj_accounting"
            | "org.zfsonlinux:project_quota"
    )
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
    write_features: BTreeMap<String, u64>,
    write_features_obj: Option<u64>,
    empty_bpobj_id: Option<u64>,
    read_features: Vec<String>,
    allocator: PoolSpaceAllocator,
    generation: u64,
    seq: u64,
    events: Vec<ZfsPersistenceEvent>,
    fault_hook: Option<FaultHook>,
    poisoned_uncertain: bool,
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
        if paths.is_empty() || paths.len() > 8 {
            return Err(unsupported(
                "ZFS native writer requires 1 leaf or 2..=8 mirror member files",
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
        if devices.is_empty() || devices.len() > 8 {
            return Err(unsupported(
                "ZFS native writer requires 1 leaf or 2..=8 mirror devices",
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
        let pool = Pool::from_leaves(leaves)?;
        if pool.has_missing_members() {
            return Err(unsupported(
                "degraded ZFS pools with missing members are refused for writes",
            ));
        }
        let members = pool.leaves();

        // 1. Validate all 4 labels across all members: require `state == 1` (EXPORTED),
        // `vdev_children == 1`, `multihost == 0`, and standalone leaf or mirror topology.
        let mut member_guids = Vec::with_capacity(members.len());
        let mut label_offsets_per_member = Vec::with_capacity(members.len());
        let first_l0 = members[0].label(cx, options.label)?;
        let slot_bytes = first_l0.slot_bytes;
        let slots_per_label = UBERBLOCK_RING_BYTES / slot_bytes;
        if options.slot >= slots_per_label {
            return Err(FfsError::Format(
                "selected Uberblock slot exceeds label ring capacity".into(),
            ));
        }

        let topology = if members.len() == 1 {
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
            if tree.text("type") != Some("mirror") {
                return Err(unsupported(
                    "multi-device ZFS native writer only admits complete mirrors (RAIDZ/striped refused)",
                ));
            }
            ZfsTopologyKind::Mirror {
                width: members.len(),
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

        for member in members {
            checkpoint(cx)?;
            let mut l_offsets = [0_u64; 4];
            let mut m_guid = None;
            for (l_idx, slot_off) in l_offsets.iter_mut().enumerate() {
                let lbl = member.label(cx, l_idx)?;
                *slot_off = lbl.offset;
                if lbl.config.unsigned("state") != Some(1) {
                    return Err(unsupported(
                        "ZFS native writer requires an cleanly exported pool (state == 1); active pools are never force-imported",
                    ));
                }
                if lbl.config.unsigned("vdev_children") != Some(1) {
                    return Err(unsupported(
                        "striped multi-top-vdev pools are outside initial synchronous writer admission",
                    ));
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

        let guid_sum = if members.len() == 1 {
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
        let mut selected_ub_from_scan: Option<(usize, Uberblock, Endian, Option<u64>)> = None;
        for (m_idx, member) in members.iter().enumerate() {
            for l_idx in 0..4 {
                checkpoint(cx)?;
                let lbl = member.label(cx, l_idx)?;
                for s_idx in 0..slots_per_label {
                    let off = lbl.offset + UBERBLOCK_RING_OFFSET + (s_idx * slot_bytes) as u64;
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
                    if l_idx == options.label
                        && s_idx == options.slot
                        && selected_ub_from_scan.is_none()
                    {
                        selected_ub_from_scan =
                            Some((m_idx, ub, ub_order, Some(mmp.software_version)));
                    }
                }
            }
        }
        if mmp_active {
            return Err(unsupported(
                "active ZFS Multi-Modifier Protection (MMP) state in Uberblock ring refuses write",
            ));
        }

        // 3. Reconcile torn Uberblocks ONLY if explicitly requested; otherwise require unanimous
        // 4-label agreement across all members on `(options.label, options.slot)`!
        if options.reconcile_torn_uberblocks {
            let Some((_, ref cand_ub, cand_order, sw_ver)) = selected_ub_from_scan else {
                return Err(corrupt(
                    "reconcile_torn_uberblocks target (label, slot) has no valid Uberblock on any member",
                ));
            };
            if cand_ub.txg != max_ring_txg {
                return Err(corrupt(
                    "reconcile_torn_uberblocks refuses non-maximal Uberblock TXG",
                ));
            }
            // Verify full pool scrub & allocation via `import_objects` before writing any label!
            let imported = pool.import_objects(cx, Some(options.pool_guid))?;
            if imported.txg != cand_ub.txg {
                return Err(corrupt(
                    "reconcile_torn_uberblocks candidate disagrees with verified active pool root",
                ));
            }
            let scrub = imported.scrub(
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
            let _ = imported.allocation(cx, AllocationLimits::default())?;

            // Synchronize `(0..4, options.slot)` across all members in 2 waves (`L0..L1`, `L2..L3`).
            let default_sw = if version == 5000 { 5000 } else { version };
            let mut synced_ub = cand_ub.clone();
            synced_ub.order = cand_order;
            for wave_labels in [[0_usize, 1], [2, 3]] {
                for (m_idx, member) in members.iter().enumerate() {
                    for l_idx in wave_labels {
                        let off = label_offsets_per_member[m_idx][l_idx]
                            + UBERBLOCK_RING_OFFSET
                            + (options.slot * slot_bytes) as u64;
                        let encoded = synced_ub
                            .encode_with_meta(slot_bytes, off, sw_ver.unwrap_or(default_sw), 0, 0)
                            .map_err(|e| parse_err(&e))?;
                        member.write_raw(cx, off, &encoded)?;
                    }
                }
                for member in members {
                    member.sync_raw(cx)?;
                }
            }
        } else {
            // Strict unanimity across all 4 labels of every member at `options.slot`!
            let (_, expected_ub, _, _) = selected_ub_from_scan.as_ref().ok_or_else(|| {
                corrupt("explicitly selected (label, slot) does not contain a valid Uberblock")
            })?;
            for member in members {
                for l_idx in 0..4 {
                    let lbl = member.label(cx, l_idx)?;
                    let other = member.uberblock(cx, &lbl, options.slot)?;
                    if other.version != expected_ub.version
                        || other.txg != expected_ub.txg
                        || other.guid_sum != expected_ub.guid_sum
                        || other.timestamp != expected_ub.timestamp
                        || other.root != expected_ub.root
                    {
                        return Err(corrupt(
                            "Uberblock slots disagree across labels or members; explicit reconciliation required",
                        ));
                    }
                }
            }
        }

        let root_block = pool.root(cx, options.label, options.slot, options.pool_guid)?;
        if root_block.uberblock.txg != max_ring_txg {
            return Err(corrupt(
                "explicitly selected Uberblock slot is older than a newer committed TXG in the ring",
            ));
        }
        let vcfg = root_block.vdev_config().clone();
        let order = root_block.uberblock.root.payload_order();
        let mos_os = ObjectSet::parse(&root_block.data, order).map_err(|e| parse_err(&e))?;
        let current_sw_version = selected_ub_from_scan.and_then(|(_, _, _, sw)| sw);

        // 4. Open `Objects`, validate MOS feature catalogs for WRITES, and inspect ZIL on all heads.
        let mut mos = pool.objects(cx, options.label, options.slot, options.pool_guid)?;
        let mut write_features = BTreeMap::new();
        let mut write_features_obj = None;
        let dir_entries = mos.zap_values(cx, 1)?;
        let empty_bpobj_id = zap_optional_u64(&dir_entries, b"empty_bpobj")?;
        if version == 5000 {
            let wf_id = zap_required_u64(&dir_entries, b"features_for_write")?;
            write_features_obj = Some(wf_id);
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
                write_features.insert(name, count);
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
            let (ds_raw, ds_ord, _) = mos
                .checked_raw(cx, &ds_bp, DMU_OT_OBJSET, 0, ds_bp.logical_bytes(), hd_ceil)?
                .ok_or_else(|| corrupt("head dataset ObjectSet is a hole"))?;
            let ds_os = ObjectSet::parse(&ds_raw, ds_ord).map_err(|e| parse_err(&e))?;
            if ds_os.zil_header.has_work() {
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

        // 5. Load metaslab space maps and verify accounting.
        let allocator =
            PoolSpaceAllocator::load(cx, &mut mos, &write_features, &vcfg.read_features)?;

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
            selected_txg: root_block.uberblock.txg,
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
            pool,
            storage_identity,
            admission_report,
            order,
            slot_bytes,
            slots_per_label,
            label_offsets_per_member,
            committed_txg: root_block.uberblock.txg,
            committed_slot: options.slot,
            current_uberblock: root_block.uberblock,
            current_software_version: current_sw_version,
            mos_os,
            write_features,
            write_features_obj,
            empty_bpobj_id,
            read_features: vcfg.read_features,
            allocator,
            generation: 0,
            seq: 0,
            events: Vec::new(),
            fault_hook: None,
            poisoned_uncertain: false,
        })
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

    /// Open a fresh read-only [`Objects`] view pinned to the currently committed `(0, slot)`.
    pub fn open_read_objects(&self, cx: &Cx) -> Result<Objects> {
        self.pool
            .objects(cx, 0, self.committed_slot, self.storage_identity.pool_guid)
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
        self.execute_zpl_txg(
            cx,
            dataset_components,
            &ZplMutation::WriteData {
                file_obj,
                offset,
                data: data.to_vec(),
                timestamp,
                checksum,
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
        self.execute_zpl_txg(
            cx,
            dataset_components,
            &ZplMutation::TruncateFile {
                file_obj,
                new_size,
                timestamp,
                checksum,
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
                timestamp,
            },
        )
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

    #[allow(clippy::too_many_lines)]
    fn execute_zpl_txg(
        &mut self,
        cx: &Cx,
        dataset_components: &[Vec<u8>],
        mutation: &ZplMutation,
    ) -> ZfsTxOutcome<u64> {
        if self.poisoned_uncertain {
            return ZfsTxOutcome::NotCommitted(unsupported(
                "ZFS writer handle experienced an Uncertain Uberblock outcome; reopen fresh engine to reconcile",
            ));
        }
        if let Err(err) = checkpoint(cx) {
            return ZfsTxOutcome::NotCommitted(err);
        }
        let Some(new_txg) = self.committed_txg.checked_add(1) else {
            return ZfsTxOutcome::NotCommitted(corrupt("ZFS TXG counter overflow"));
        };
        let target_slot = (new_txg as usize) % self.slots_per_label;
        let op_name = mutation.op_name();

        // 1. Stage the entire COW DMU + space-map convergence in memory BEFORE any device write!
        let mut mos = match self.open_read_objects(cx) {
            Ok(m) => m,
            Err(err) => return ZfsTxOutcome::NotCommitted(err),
        };
        let mut draft_alloc = self.allocator.clone();
        let mut draft_wf = self.write_features.clone();
        let mut wf_dirty = false;
        let mut mos_dirty_dnodes = BTreeMap::new();
        let mut base_staged = Vec::new();

        let result_val = match stage_zpl_mutation(
            cx,
            &mut mos,
            dataset_components,
            mutation,
            &mut mos_dirty_dnodes,
            &mut draft_wf,
            &mut wf_dirty,
            self.empty_bpobj_id,
            &mut draft_alloc,
            self.order,
            new_txg,
            &mut base_staged,
        ) {
            Ok(val) => val,
            Err(err) => return ZfsTxOutcome::NotCommitted(err),
        };

        let (new_root_bp, mut converged_alloc, staged_writes) =
            match finalize_mos_and_space_maps_to_convergence(
                cx,
                &mut mos,
                &self.mos_os,
                &self.current_uberblock.root,
                &mos_dirty_dnodes,
                &draft_wf,
                wf_dirty,
                self.write_features_obj,
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

        // 2. Persist strictly child-before-parent across all members BEFORE touching Uberblocks!
        let member_count = self.pool.leaves().len();
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
                let phys_off = DATA_OFFSET + w.dva_offset;
                for m_idx in 0..member_count {
                    let write_stage = match bucket {
                        WriteBucket::ChildBlocks => ZfsPersistenceStage::ChildBlocksWrite {
                            member_index: m_idx,
                        },
                        WriteBucket::DatasetMetadata => ZfsPersistenceStage::DatasetMetadataWrite {
                            member_index: m_idx,
                        },
                        WriteBucket::MosSpaceMap => ZfsPersistenceStage::MosSpaceMapWrite {
                            member_index: m_idx,
                        },
                        WriteBucket::MosRoot => ZfsPersistenceStage::MosRootWrite {
                            member_index: m_idx,
                        },
                    };
                    if let Err(err) = self.emit_event(
                        op_name,
                        write_stage,
                        new_txg,
                        m_idx,
                        phys_off,
                        w.bytes.len(),
                    ) {
                        return ZfsTxOutcome::NotCommitted(err);
                    }
                    if let Err(err) = self.pool.leaves()[m_idx].write_raw(cx, phys_off, &w.bytes) {
                        return ZfsTxOutcome::NotCommitted(err);
                    }
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
        self.write_features = draft_wf;
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
        let _ = self.emit_event(
            op_name,
            ZfsPersistenceStage::BeforeAcknowledge,
            new_txg,
            0,
            0,
            0,
        );
        let _ = self.emit_event(op_name, ZfsPersistenceStage::AckPublished, new_txg, 0, 0, 0);
        ZfsTxOutcome::Committed {
            value: result_val,
            token,
        }
    }
}
