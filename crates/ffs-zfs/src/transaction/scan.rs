//! Resumable pool-wide scrub and resilver engine persisted in MOS `"scan"`
//! (`dsl_scan_phys_t`, `24 × u64 = 192` bytes, OpenZFS `zfs-2.4.0`).
//!
//! Deterministically walks MOS (`objset = 0`) plus every dataset head and
//! snapshot in ascending `(objset, object, level, blkid)` order, verifies every
//! physical replica / RAIDZ column / dRAID column, heals recoverable damage
//! directly on disk (`ScanHealWrite` + `ScanHealBarrier`), persists exact
//! resumption bookmarks in MOS object 1 `"scan"` at bounded chunk intervals,
//! and cleanly reconciles concurrent foreground writes across pause/resume.
//! As in native `dsl_scan.c`, blocks retained only by a pool checkpoint are
//! excluded. Reports expose that scope; this scanner never clears native DTLs.

use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_ondisk::zfs::draid::DraidMap;
use ffs_ondisk::zfs::nvlist::Value;
use ffs_ondisk::zfs::raidz::Raidz1Map;
use ffs_ondisk::zfs::raidz::parity::RaidzParityMap;
use ffs_ondisk::zfs::scan::{
    DSL_SCAN_PHYS_WORDS, DslScanFunc, DslScanPhys, DslScanState, ZBookmarkPhys,
};
use ffs_ondisk::zfs::{BlockPointer, DATA_OFFSET, Dva, label_offsets};
use ffs_ondisk::zfs_dmu::{
    DNODE_BLOCK_BYTES, DNODE_BYTES, Dnode, OBJSET_GROUPUSED_OFFSET, OBJSET_PROJECTUSED_OFFSET,
    OBJSET_USERUSED_OFFSET, ObjectSet,
};
use ffs_ondisk::zfs_zap::Entry as RawZapEntry;
use serde::Serialize;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Arc;

use super::dmu_cow::{AllocatorWriteTopology, PoolSpaceAllocator};
use super::{
    ZfsPersistenceStage, ZfsTransactionEngine, ZfsTxOutcome, checkpoint, corrupt, parse_err,
    unsupported,
};
use crate::reader::dmu::{DatasetCryptoContext, Objects};
use crate::reader::pool::vdev::{PoolTopology, TopVdevKind, VdevHealth};

const DMU_POOL_SCAN_KEY: &[u8] = b"scan";
// OpenZFS zfs-2.4.0 include/sys/{zio,dmu}.h. Object-set roots must not
// collide with their level-zero meta-dnode block at (object=0, blkid=0).
const ZB_ROOT_LEVEL: i64 = -1;
const DMU_SPILL_BLKID: u64 = u64::MAX - 1;
const DMU_USERUSED_OBJECT: u64 = u64::MAX;
const DMU_GROUPUSED_OBJECT: u64 = u64::MAX - 1;
const DMU_PROJECTUSED_OBJECT: u64 = u64::MAX - 2;
const MAX_SCAN_POINTERS: usize = 1 << 20;
const MAX_SCAN_OBJECTS: usize = 1 << 20;
const MAX_SCAN_OBJECTSETS: usize = 65_536;
const MAX_SCAN_METADATA_BYTES: usize = 64 * 1024 * 1024;
const MAX_DMU_OBJECT: u64 = 1 << 48;

/// Per-invocation work bound for resumable scrub and resilver chunks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ZfsScanLimits {
    /// Maximum non-hole block pointers examined in a single TXG chunk before
    /// checkpointing `DslScanPhys` into MOS `"scan"` and returning.
    pub max_blocks_per_txg: usize,
}

impl Default for ZfsScanLimits {
    fn default() -> Self {
        Self {
            max_blocks_per_txg: usize::MAX,
        }
    }
}

/// Summary report emitted by each scrub or resilver chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZfsScanReport {
    pub func: u64,
    pub state: u64,
    pub examined_blocks: u64,
    pub processed_blocks: u64,
    pub repaired_blocks: u64,
    /// Blocks verified in this chunk whose physical repair layout is not admitted.
    /// Their readable contents are not counted as checksum failures.
    pub repair_unavailable_blocks: u64,
    /// Native scans exclude blocks freed from the live pool but retained only
    /// by an active pool checkpoint. Completion does not certify those blocks.
    pub checkpoint_only_blocks_excluded: bool,
    pub unrecoverable_errors: u64,
    pub completed: bool,
    pub bookmark_objset: u64,
    pub bookmark_object: u64,
    pub bookmark_level: i64,
    pub bookmark_blkid: u64,
    pub txg: u64,
}

#[derive(Debug, Clone)]
pub(super) struct DiscoveredBlock {
    pub(super) bookmark: ZBookmarkPhys,
    pub(super) bp: BlockPointer,
}

struct ScanRepairRoute {
    geometry: AllocatorWriteTopology,
    ashift: u8,
    asize: u64,
    /// Native child order mapped to the caller's supplied physical devices.
    members: Vec<usize>,
}

type ScanRepairRoutes = BTreeMap<u32, Option<ScanRepairRoute>>;

struct ScanRepairWrite<'a> {
    member: usize,
    offset: u64,
    bytes: Cow<'a, [u8]>,
}

enum ScanBlockResult {
    Verified,
    Repaired,
    RepairUnavailable,
}

enum ScanBlockFailure {
    Verification(FfsError),
    Repair(FfsError),
}

impl From<FfsError> for ScanBlockFailure {
    fn from(error: FfsError) -> Self {
        Self::Verification(error)
    }
}

impl ScanRepairRoute {
    /// Construct every physical destination before any copy of this BP is healed.
    fn plan<'a>(&self, dva: &Dva, physical: &'a [u8]) -> Result<Vec<ScanRepairWrite<'a>>> {
        let sector = 1_u64 << self.ashift;
        if dva.gang
            || dva.allocated_bytes < physical.len() as u64
            || !dva.offset.is_multiple_of(sector)
            || !dva.allocated_bytes.is_multiple_of(sector)
            || dva
                .offset
                .checked_add(dva.allocated_bytes)
                .is_none_or(|end| end > self.asize)
        {
            return Err(corrupt("scrub DVA exceeds its native vdev geometry"));
        }
        let mut writes = Vec::new();
        match &self.geometry {
            AllocatorWriteTopology::LeafOrMirror => {
                for child in 0..self.members.len() {
                    self.push_write(&mut writes, child, dva.offset, Cow::Borrowed(physical))?;
                }
            }
            AllocatorWriteTopology::Raidz { parity, width } => {
                let (columns, payloads, asize) = if *parity == 1 {
                    let map = Raidz1Map::new_wide(dva.offset, physical.len(), self.ashift, *width)
                        .map_err(|e| parse_err(&e))?;
                    let payloads = map.encode(physical).map_err(|e| parse_err(&e))?;
                    (map.columns().to_vec(), payloads, map.allocated_bytes())
                } else {
                    let map = RaidzParityMap::new_wide(
                        dva.offset,
                        physical.len(),
                        self.ashift,
                        *width,
                        *parity,
                    )
                    .map_err(|e| parse_err(&e))?;
                    let payloads = map.encode(physical).map_err(|e| parse_err(&e))?;
                    (map.columns().to_vec(), payloads, map.allocated_bytes())
                };
                if asize > dva.allocated_bytes {
                    return Err(corrupt("scrub RAIDZ columns exceed their DVA allocation"));
                }
                for (column, bytes) in columns.iter().zip(payloads) {
                    self.push_write(
                        &mut writes,
                        column.child_id,
                        column.offset,
                        Cow::Owned(bytes),
                    )?;
                }
            }
            AllocatorWriteTopology::Draid(config) => {
                let map =
                    DraidMap::new(config, dva.offset, physical.len()).map_err(|e| parse_err(&e))?;
                if map.allocated_bytes() > dva.allocated_bytes {
                    return Err(corrupt("scrub dRAID columns exceed their DVA allocation"));
                }
                let payloads = map.encode_rows(physical).map_err(|e| parse_err(&e))?;
                for (row, row_payloads) in map.rows().iter().zip(payloads) {
                    for (column, bytes) in row.columns.iter().zip(row_payloads) {
                        self.push_write(
                            &mut writes,
                            column.child_id,
                            column.offset,
                            Cow::Owned(bytes),
                        )?;
                    }
                }
            }
        }
        Ok(writes)
    }

    fn push_write<'a>(
        &self,
        writes: &mut Vec<ScanRepairWrite<'a>>,
        child: usize,
        offset: u64,
        bytes: Cow<'a, [u8]>,
    ) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let member = *self
            .members
            .get(child)
            .ok_or_else(|| corrupt("scrub column has no native physical child"))?;
        writes.push(ScanRepairWrite {
            member,
            offset: DATA_OFFSET
                .checked_add(offset)
                .ok_or_else(|| corrupt("scrub physical offset overflow"))?,
            bytes,
        });
        Ok(())
    }
}

fn bookmark_key(b: &ZBookmarkPhys) -> (u64, u64, i64, u64) {
    (b.objset, b.object, b.level, b.blkid)
}

/// Read persisted `DslScanPhys` from MOS pool directory object 1 (`"scan"`).
pub(super) fn read_scan_phys_from_mos(cx: &Cx, mos: &mut Objects) -> Result<Option<DslScanPhys>> {
    checkpoint(cx)?;
    let dir = mos.zap_values(cx, 1)?;
    let Some(entry) = dir.iter().find(|e| e.name == DMU_POOL_SCAN_KEY) else {
        return Ok(None);
    };
    if entry.integer_bytes != 8 || entry.values.len() != DSL_SCAN_PHYS_WORDS {
        return Err(corrupt("MOS scan entry is not a 24-word dsl_scan_phys_t"));
    }
    let words: [u64; DSL_SCAN_PHYS_WORDS] = entry
        .values
        .as_slice()
        .try_into()
        .map_err(|_| corrupt("MOS scan entry length mismatch"))?;
    let phys = DslScanPhys::from_words(&words).map_err(|e| parse_err(&e))?;
    Ok(Some(phys))
}

/// Stage an updated `"scan"` 24-word ZAP entry inside MOS object 1.
pub(super) fn stage_scan_phys_in_mos(
    cx: &Cx,
    mos: &mut Objects,
    alloc: &mut PoolSpaceAllocator,
    scan: &DslScanPhys,
) -> Result<()> {
    let mut dir_entries = match &alloc.pending_mos_directory {
        Some(entries) => entries.clone(),
        None => mos.zap_values(cx, 1)?,
    };
    dir_entries.retain(|e| e.name != DMU_POOL_SCAN_KEY);
    dir_entries.push(RawZapEntry {
        name: DMU_POOL_SCAN_KEY.to_vec(),
        integer_bytes: 8,
        values: scan.to_words().to_vec(),
        collision: 0,
    });
    alloc.pending_mos_directory = Some(dir_entries);
    Ok(())
}

struct ScanTree<'a> {
    objset: u64,
    object: u64,
    node: &'a Dnode,
    dnodes: bool,
}

/// The complete discovery pass precedes repair. Running out of a discovery
/// budget is an error, never an apparently complete prefix of the pool.
struct ScanInventory {
    blocks: Vec<DiscoveredBlock>,
    datasets: Vec<(u64, Dnode, u64)>,
    pointers_left: usize,
    objects_left: usize,
    metadata_left: usize,
}

impl ScanInventory {
    fn new() -> Self {
        Self {
            blocks: Vec::new(),
            datasets: Vec::new(),
            pointers_left: MAX_SCAN_POINTERS,
            objects_left: MAX_SCAN_OBJECTS,
            metadata_left: MAX_SCAN_METADATA_BYTES,
        }
    }

    fn charge_pointer(&mut self) -> Result<()> {
        self.pointers_left = self
            .pointers_left
            .checked_sub(1)
            .ok_or_else(|| unsupported("pool scan inventory exceeds its block-pointer budget"))?;
        Ok(())
    }

    fn charge_metadata(&mut self, bytes: usize) -> Result<()> {
        self.metadata_left = self
            .metadata_left
            .checked_sub(bytes)
            .ok_or_else(|| unsupported("pool scan inventory exceeds 64 MiB of decoded metadata"))?;
        Ok(())
    }

    fn push(&mut self, bookmark: ZBookmarkPhys, bp: &BlockPointer) {
        if !bp.hole() && !bp.embedded() {
            self.blocks.push(DiscoveredBlock {
                bookmark,
                bp: bp.clone(),
            });
        }
    }

    fn objectset(
        &mut self,
        cx: &Cx,
        view: &mut Objects,
        id: u64,
        root: &BlockPointer,
        os: &ObjectSet,
    ) -> Result<()> {
        checkpoint(cx)?;
        self.charge_pointer()?;
        self.push(
            ZBookmarkPhys {
                objset: id,
                object: 0,
                level: ZB_ROOT_LEVEL,
                blkid: 0,
            },
            root,
        );
        self.tree(
            cx,
            view,
            &ScanTree {
                objset: id,
                object: 0,
                node: &os.meta,
                dnodes: true,
            },
            root.birth(),
        )?;
        for (offset, object) in [
            (OBJSET_USERUSED_OFFSET, DMU_USERUSED_OBJECT),
            (OBJSET_GROUPUSED_OFFSET, DMU_GROUPUSED_OBJECT),
            (OBJSET_PROJECTUSED_OFFSET, DMU_PROJECTUSED_OBJECT),
        ] {
            if let Some(node) = os
                .embedded_dnode(offset, root.payload_order())
                .map_err(|error| parse_err(&error))?
            {
                self.tree(
                    cx,
                    view,
                    &ScanTree {
                        objset: id,
                        object,
                        node: &node,
                        dnodes: false,
                    },
                    root.birth(),
                )?;
            }
        }
        Ok(())
    }

    fn tree(
        &mut self,
        cx: &Cx,
        view: &mut Objects,
        tree: &ScanTree<'_>,
        ceiling: u64,
    ) -> Result<()> {
        let level = tree.node.levels() - 1;
        for (slot, bp) in tree.node.pointers().iter().enumerate() {
            self.visit(cx, view, tree, bp, level, slot as u64, ceiling)?;
        }
        if let Some(spill) = tree.node.spill() {
            checkpoint(cx)?;
            self.charge_pointer()?;
            if !view.validate_pointer(
                spill,
                tree.node.bonus_type(),
                0,
                spill.logical_bytes(),
                ceiling,
            )? || spill.embedded()
            {
                return Err(corrupt("allocated DMU spill has no physical block"));
            }
            self.push(
                ZBookmarkPhys {
                    objset: tree.objset,
                    object: tree.object,
                    level: 0,
                    blkid: DMU_SPILL_BLKID,
                },
                spill,
            );
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn visit(
        &mut self,
        cx: &Cx,
        view: &mut Objects,
        tree: &ScanTree<'_>,
        bp: &BlockPointer,
        level: u8,
        blkid: u64,
        ceiling: u64,
    ) -> Result<()> {
        checkpoint(cx)?;
        self.charge_pointer()?;
        let fanout = (tree.node.indirect_bytes() / 128) as u64;
        let span = u128::from(fanout).pow(u32::from(level));
        let first_leaf = u128::from(blkid)
            .checked_mul(span)
            .ok_or_else(|| corrupt("scan logical block position overflow"))?;
        if !bp.hole() && first_leaf > u128::from(tree.node.max_block()) {
            return Err(corrupt("scan pointer exceeds its dnode's maximum block"));
        }
        let size = if level == 0 {
            tree.node.data_bytes()
        } else {
            tree.node.indirect_bytes()
        };
        if !view.validate_pointer(bp, tree.node.object_type(), level, size, ceiling)? {
            return Ok(());
        }
        self.push(
            ZBookmarkPhys {
                objset: tree.objset,
                object: tree.object,
                level: i64::from(level),
                blkid,
            },
            bp,
        );
        if level == 0 && !tree.dnodes {
            return Ok(());
        }
        self.charge_metadata(size)?;
        let (raw, order, birth) = view
            .checked_raw(cx, bp, tree.node.object_type(), level, size, ceiling)?
            .ok_or_else(|| corrupt("scan metadata pointer became a hole"))?;
        if level == 0 {
            return self.dnodes(cx, view, tree.objset, blkid, &raw, order, birth);
        }
        for (slot, bytes) in raw.as_chunks::<128>().0.iter().enumerate() {
            let child = BlockPointer::parse(bytes, order).map_err(|error| parse_err(&error))?;
            let child_blkid = blkid
                .checked_mul(fanout)
                .and_then(|start| start.checked_add(slot as u64))
                .ok_or_else(|| corrupt("scan indirect block ID overflow"))?;
            self.visit(cx, view, tree, &child, level - 1, child_blkid, birth)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn dnodes(
        &mut self,
        cx: &Cx,
        view: &mut Objects,
        objset: u64,
        block: u64,
        bytes: &[u8],
        order: ffs_ondisk::zfs::Endian,
        birth: u64,
    ) -> Result<()> {
        let slots_per_block = DNODE_BLOCK_BYTES / DNODE_BYTES;
        let first = block
            .checked_mul(slots_per_block as u64)
            .filter(|first| *first <= MAX_DMU_OBJECT - slots_per_block as u64)
            .ok_or_else(|| corrupt("scan meta-dnode exceeds the native object namespace"))?;
        let mut slot = 0;
        while slot < slots_per_block {
            checkpoint(cx)?;
            self.objects_left = self
                .objects_left
                .checked_sub(1)
                .ok_or_else(|| unsupported("pool scan inventory exceeds its dnode-slot budget"))?;
            let start = slot * DNODE_BYTES;
            if bytes[start] == 0 {
                slot += 1;
                continue;
            }
            let count = usize::from(bytes[start + 12]) + 1;
            if slot + count > slots_per_block {
                return Err(corrupt("scan large dnode crosses its metadata block"));
            }
            let object = first + slot as u64;
            if object == 0 {
                return Err(corrupt("scan found an allocated reserved object zero"));
            }
            let node = Dnode::parse(&bytes[start..(slot + count) * DNODE_BYTES], order)
                .map_err(|error| parse_err(&error))?;
            slot += node.slots();
            if objset == 0 && (node.object_type() == 16 || node.bonus_type() == 16) {
                if !matches!(node.object_type(), 16 | 196)
                    || node.bonus_type() != 16
                    || node.bonus().len() != 320
                    || node.spill().is_some()
                {
                    return Err(corrupt("scan found an invalid native DSL dataset dnode"));
                }
                if self.datasets.len() == MAX_SCAN_OBJECTSETS {
                    return Err(unsupported(
                        "pool scan inventory exceeds its object-set budget",
                    ));
                }
                self.datasets.push((object, node.clone(), birth));
            }
            self.tree(
                cx,
                view,
                &ScanTree {
                    objset,
                    object,
                    node: &node,
                    dnodes: false,
                },
                birth,
            )?;
        }
        Ok(())
    }
}

/// Enumerate complete native roots, including snapshots and private receive
/// datasets, from allocated MOS DSL dnodes rather than the visible namespace.
/// A sparse high object ID costs only its real indirect and metadata blocks.
pub(super) fn collect_pool_blocks(
    cx: &Cx,
    mos: &mut Objects,
    mos_root: &BlockPointer,
    mos_os: &ObjectSet,
) -> Result<Vec<DiscoveredBlock>> {
    let mut inventory = ScanInventory::new();
    inventory.charge_metadata(mos_root.logical_bytes())?;
    inventory.objectset(cx, mos, 0, mos_root, mos_os)?;
    for (id, node, ceiling) in std::mem::take(&mut inventory.datasets) {
        checkpoint(cx)?;
        let order = node.order();
        let directory = order
            .u64(node.bonus(), 0)
            .map_err(|error| parse_err(&error))?;
        let next = order
            .u64(node.bonus(), 24)
            .map_err(|error| parse_err(&error))?;
        let created = order
            .u64(node.bonus(), 56)
            .map_err(|error| parse_err(&error))?;
        let guid = order
            .u64(node.bonus(), 112)
            .map_err(|error| parse_err(&error))?;
        if directory == 0 || guid == 0 || created == 0 || created > ceiling || created > mos.txg {
            return Err(corrupt(
                "scan DSL dataset identity or creation TXG is invalid",
            ));
        }
        let root_bytes = &node.bonus()[128..256];
        if root_bytes.iter().all(|byte| *byte == 0) {
            // Native $ORIGIN records can own no initialized object set.
            if node.bonus()[72..104].iter().any(|byte| *byte != 0) {
                return Err(corrupt(
                    "uninitialized scan dataset accounts for live blocks",
                ));
            }
            continue;
        }
        let root = BlockPointer::parse(root_bytes, order).map_err(|error| parse_err(&error))?;
        let ceiling = if next == 0 {
            ceiling
        } else {
            ceiling.min(created)
        };
        inventory.charge_metadata(root.logical_bytes())?;
        let (raw, order, birth) =
            mos.read_dataset_objset_block_raw(cx, &root, ceiling, None, true)?;
        let os = ObjectSet::parse(&raw, order).map_err(|error| parse_err(&error))?;
        if !matches!(os.kind, 2 | 3) {
            return Err(unsupported(
                "scan dataset is not a filesystem or volume object set",
            ));
        }
        // Only a head's ZIL is live; snapshots can retain stale log pointers
        // which native dsl_scan_visitds explicitly ignores. Check every head,
        // including receive staging that visible dataset enumeration hides.
        if next == 0
            && mos.dataset_has_pending_zil_work(cx, id, guid, &node, &root, &raw, order, &os)?
        {
            return Err(unsupported(
                "pool scan requires native replay of a pending head ZIL",
            ));
        }
        let crypto = if root.protected() {
            Some(Arc::new(DatasetCryptoContext {
                info: mos
                    .dataset_crypto_info_for_dir(cx, directory)?
                    .ok_or_else(|| {
                        corrupt("protected scan dataset has no native encryption metadata")
                    })?,
                raw_scrub_only: true,
            }))
        } else {
            None
        };
        let mut view = mos.open_objectset_view_with_crypto(os.meta.clone(), birth, mos.txg, crypto);
        inventory.objectset(cx, &mut view, id, &root, &os)?;
    }
    inventory
        .blocks
        .sort_by_key(|item| bookmark_key(&item.bookmark));
    if inventory
        .blocks
        .windows(2)
        .any(|pair| pair[0].bookmark == pair[1].bookmark)
    {
        return Err(corrupt(
            "scan block inventory contains duplicate resume bookmarks",
        ));
    }
    Ok(inventory.blocks)
}

impl ZfsTransactionEngine {
    /// Read admission does not imply that the ordinary writer's geometry can
    /// repair every vdev. Preserve verification for those layouts, while only
    /// admitting direct, healthy physical destinations for repair writes.
    fn scan_repair_routes(&self, cx: &Cx, mos: &mut Objects) -> Result<ScanRepairRoutes> {
        let config = mos.load_mos_config_nvlist(cx)?;
        if self.storage_identity.member_guids.len() != self.pool.leaves().len() {
            return Err(corrupt(
                "scrub member identity count disagrees with devices",
            ));
        }
        let topology = PoolTopology::from_mos_config(&config, &self.storage_identity.member_guids)?;
        let trees = config
            .list("vdev_tree")
            .and_then(|root| root.fields.get("children"));
        let Some(Value::Lists(trees)) = trees else {
            return Err(corrupt("scrub MOS configuration has no top-level vdevs"));
        };
        let mut routes = BTreeMap::new();
        for top in &topology.top_vdevs {
            checkpoint(cx)?;
            let tree = trees
                .get(top.id as usize)
                .ok_or_else(|| corrupt("scrub vdev ID has no native configuration"))?;
            let direct_children = match tree.fields.get("children") {
                Some(Value::Lists(children)) => children.iter().all(|child| {
                    matches!(child.text("type"), Some("file" | "disk"))
                        && !child.fields.contains_key("children")
                        && VdevHealth::from_vdev_tree(child).is_healthy()
                }),
                None => matches!(top.kind, TopVdevKind::Leaf),
                Some(_) => return Err(corrupt("scrub vdev children are not a native array")),
            };
            if !top.is_complete() || !top.health.is_healthy() || !direct_children {
                routes.insert(top.id, None);
                continue;
            }
            let geometry = match &top.kind {
                TopVdevKind::Leaf | TopVdevKind::Mirror => AllocatorWriteTopology::LeafOrMirror,
                TopVdevKind::Raidz {
                    parity,
                    expanded: None,
                } => AllocatorWriteTopology::Raidz {
                    parity: *parity,
                    width: top.children_guids.len(),
                },
                TopVdevKind::Draid(config) => AllocatorWriteTopology::Draid(config.clone()),
                TopVdevKind::Raidz {
                    expanded: Some(_), ..
                }
                | TopVdevKind::Indirect(_)
                | TopVdevKind::Hole => {
                    routes.insert(top.id, None);
                    continue;
                }
            };
            let members: Vec<_> = top.supplied_indices.iter().flatten().copied().collect();
            if members.is_empty()
                || members.len() != top.children_guids.len()
                || members
                    .iter()
                    .any(|&index| index >= self.pool.leaves().len())
                || !(9..=16).contains(&top.ashift)
            {
                return Err(corrupt("scrub native child routing is incomplete"));
            }
            routes.insert(
                top.id,
                Some(ScanRepairRoute {
                    geometry,
                    ashift: top.ashift,
                    asize: top.asize,
                    members,
                }),
            );
        }
        Ok(routes)
    }

    /// A failed in-place repair has no new committed TXG, but it must not be
    /// followed by more writes through this engine. Reopen from native media.
    fn failed_scan_chunk(
        &mut self,
        error: FfsError,
        repair_started: bool,
    ) -> ZfsTxOutcome<ZfsScanReport> {
        if repair_started {
            self.poisoned_uncertain = true;
        }
        ZfsTxOutcome::NotCommitted(error)
    }

    /// Inspect the current persisted pool scan (`dsl_scan_phys_t`) from MOS `"scan"`.
    pub fn scan_status(&self, cx: &Cx) -> Result<Option<DslScanPhys>> {
        let mut mos = self.open_read_objects(cx)?;
        read_scan_phys_from_mos(cx, &mut mos)
    }

    /// Start a brand-new resumable pool-wide scrub (`DslScanFunc::Scrub`),
    /// processing up to `limits.max_blocks_per_txg` blocks in this TXG chunk.
    pub fn scrub_start(&mut self, cx: &Cx, limits: ZfsScanLimits) -> ZfsTxOutcome<ZfsScanReport> {
        let min_txg = 0;
        let max_txg = self.committed_txg;
        self.run_scan_chunk(
            cx,
            "zfs_scrub_start",
            Some((DslScanFunc::Scrub, min_txg, max_txg)),
            limits,
        )
    }

    /// Resume an active scrub from its persisted MOS `"scan"` bookmark.
    pub fn scrub_resume(&mut self, cx: &Cx, limits: ZfsScanLimits) -> ZfsTxOutcome<ZfsScanReport> {
        self.run_scan_chunk(cx, "zfs_scrub_resume", None, limits)
    }

    /// Cancel an active scrub or resilver and persist `DslScanState::Canceled` in MOS `"scan"`.
    pub fn scrub_cancel(&mut self, cx: &Cx) -> ZfsTxOutcome<ZfsScanReport> {
        let ts = self.current_uberblock.timestamp.saturating_add(1);
        let checkpoint_only_blocks_excluded = self.scan_excludes_checkpoint_blocks();
        self.execute_staged_txg_typed(
            cx,
            "zfs_scrub_cancel",
            |mos, _mos_dirty, _features, alloc, new_txg, _staged| {
                let mut scan = read_scan_phys_from_mos(cx, mos)?
                    .ok_or_else(|| FfsError::Format("no active pool scan to cancel".into()))?;
                if scan.state != DslScanState::Scanning {
                    return Err(FfsError::Format(
                        "pool scan is not currently running".into(),
                    ));
                }
                scan.state = DslScanState::Canceled;
                scan.end_time = ts;
                stage_scan_phys_in_mos(cx, mos, alloc, &scan)?;
                let report =
                    scan_report_from_phys(&scan, 0, 0, checkpoint_only_blocks_excluded, new_txg);
                Ok((report, new_txg))
            },
        )
    }

    /// Start a TXG-filtered resumable pool resilver (`DslScanFunc::Resilver`,
    /// repairing blocks born in `min_txg..=committed_txg`).
    pub fn resilver_start(
        &mut self,
        cx: &Cx,
        min_txg: u64,
        limits: ZfsScanLimits,
    ) -> ZfsTxOutcome<ZfsScanReport> {
        let max_txg = self.committed_txg;
        self.run_scan_chunk(
            cx,
            "zfs_resilver_start",
            Some((DslScanFunc::Resilver, min_txg, max_txg)),
            limits,
        )
    }

    /// Resume an active resilver from its persisted MOS `"scan"` bookmark.
    pub fn resilver_resume(
        &mut self,
        cx: &Cx,
        limits: ZfsScanLimits,
    ) -> ZfsTxOutcome<ZfsScanReport> {
        self.run_scan_chunk(cx, "zfs_resilver_resume", None, limits)
    }

    #[allow(clippy::too_many_lines)]
    fn run_scan_chunk(
        &mut self,
        cx: &Cx,
        op_name: &str,
        start_new: Option<(DslScanFunc, u64, u64)>,
        limits: ZfsScanLimits,
    ) -> ZfsTxOutcome<ZfsScanReport> {
        if self.requires_recovery() {
            return ZfsTxOutcome::NotCommitted(unsupported(
                "ZFS scan repair requires recovery of the uncertain writer",
            ));
        }
        if self.allocator.raidz_expanding {
            return ZfsTxOutcome::NotCommitted(unsupported(
                "pool scan repair requires completed RAIDZ expansion",
            ));
        }
        if limits.max_blocks_per_txg == 0 {
            return ZfsTxOutcome::NotCommitted(unsupported(
                "ZfsScanLimits::max_blocks_per_txg must be >= 1",
            ));
        }
        let mut mos = match self.open_read_objects(cx) {
            Ok(m) => m,
            Err(err) => return ZfsTxOutcome::NotCommitted(err),
        };
        let existing_scan = match read_scan_phys_from_mos(cx, &mut mos) {
            Ok(s) => s,
            Err(err) => return ZfsTxOutcome::NotCommitted(err),
        };

        let mut scan = match start_new {
            Some((func, min_txg, max_txg)) => DslScanPhys {
                func,
                state: DslScanState::Scanning,
                queue_obj: 0,
                min_txg,
                max_txg,
                cur_min_txg: min_txg,
                cur_max_txg: max_txg,
                start_time: self.current_uberblock.timestamp,
                end_time: 0,
                to_examine: 0,
                examined: 0,
                skipped: 0,
                processed: 0,
                errors: 0,
                ddt_class_max: 0,
                ddt_bookmark: [0; 4],
                bookmark: ZBookmarkPhys::default(),
                flags: 0,
            },
            None => match existing_scan {
                Some(s) if s.state == DslScanState::Scanning => s,
                Some(_) => {
                    return ZfsTxOutcome::NotCommitted(FfsError::Format(
                        "pool scan is already finished or canceled".into(),
                    ));
                }
                None => {
                    return ZfsTxOutcome::NotCommitted(FfsError::Format(
                        "no active pool scan to resume".into(),
                    ));
                }
            },
        };
        let resuming = start_new.is_none();

        let all_blocks =
            match collect_pool_blocks(cx, &mut mos, &self.current_uberblock.root, &self.mos_os) {
                Ok(b) => b,
                Err(err) => return ZfsTxOutcome::NotCommitted(err),
            };
        let repair_routes = match self.scan_repair_routes(cx, &mut mos) {
            Ok(routes) => routes,
            Err(err) => return ZfsTxOutcome::NotCommitted(err),
        };
        let pool = self.pool.clone();
        let mut protection = match pool.defer_protection(cx) {
            Ok(holds) => holds,
            Err(err) => return ZfsTxOutcome::NotCommitted(err),
        };
        let current_txg = self.committed_txg;
        let next_txg = current_txg.saturating_add(1);
        let mut examined_this_chunk = 0_u64;
        let mut repaired_this_chunk = 0_u64;
        let mut repair_unavailable_this_chunk = 0_u64;
        let mut repair_started = false;
        let mut reached_end = true;

        for item in &all_blocks {
            if let Err(err) = checkpoint(cx) {
                return self.failed_scan_chunk(err, repair_started);
            }
            if resuming && bookmark_key(&item.bookmark) <= bookmark_key(&scan.bookmark) {
                continue;
            }
            if item.bp.birth() < scan.min_txg || item.bp.birth() > scan.max_txg {
                scan.skipped = scan.skipped.saturating_add(item.bp.physical_bytes() as u64);
                scan.bookmark = item.bookmark;
                continue;
            }
            if examined_this_chunk as usize >= limits.max_blocks_per_txg {
                reached_end = false;
                break;
            }

            // Verify and, if damaged & recoverable, heal physical replicas / parity!
            match self.verify_and_heal_block(
                cx,
                op_name,
                next_txg,
                &mos,
                &item.bp,
                &repair_routes,
                &mut repair_started,
            ) {
                Ok(result) => {
                    match result {
                        ScanBlockResult::Repaired => repaired_this_chunk += 1,
                        ScanBlockResult::RepairUnavailable => repair_unavailable_this_chunk += 1,
                        ScanBlockResult::Verified => {}
                    }
                    scan.processed = scan
                        .processed
                        .saturating_add(item.bp.physical_bytes() as u64);
                }
                Err(ScanBlockFailure::Verification(FfsError::Cancelled)) => {
                    return self.failed_scan_chunk(FfsError::Cancelled, repair_started);
                }
                Err(ScanBlockFailure::Repair(error)) => {
                    return self.failed_scan_chunk(error, repair_started);
                }
                Err(ScanBlockFailure::Verification(_)) => {
                    scan.errors = scan.errors.saturating_add(1);
                }
            }
            scan.examined = scan
                .examined
                .saturating_add(item.bp.physical_bytes() as u64);
            scan.bookmark = item.bookmark;
            examined_this_chunk += 1;
        }

        if reached_end {
            scan.state = DslScanState::Finished;
            scan.end_time = self.current_uberblock.timestamp.saturating_add(1);
        }

        let final_scan = scan;
        let checkpoint_only_blocks_excluded = self.scan_excludes_checkpoint_blocks();
        let outcome = self.execute_staged_txg_typed(
            cx,
            op_name,
            |mos, _mos_dirty, _features, alloc, new_txg, _staged| {
                stage_scan_phys_in_mos(cx, mos, alloc, &final_scan)?;
                let report = scan_report_from_phys(
                    &final_scan,
                    repaired_this_chunk,
                    repair_unavailable_this_chunk,
                    checkpoint_only_blocks_excluded,
                    new_txg,
                );
                Ok((report, new_txg))
            },
        );
        if outcome.is_committed() {
            for hold in &mut protection {
                hold.complete();
            }
        } else if repair_started {
            // Repair may already be durable even when the scan checkpoint
            // fails. Do not let this engine silently continue from that cut.
            self.poisoned_uncertain = true;
        }
        outcome
    }

    fn scan_excludes_checkpoint_blocks(&self) -> bool {
        self.current_uberblock.checkpoint_txg != 0
            || self.allocator.checkpoint_txg != 0
            || !self.allocator.checkpoint_deferred_frees.is_empty()
    }

    /// Verify before planning repair, so readable layouts retain checksum
    /// coverage even when their physical healing algorithm is not admitted.
    #[allow(clippy::too_many_arguments)]
    fn verify_and_heal_block(
        &mut self,
        cx: &Cx,
        op_name: &str,
        txg: u64,
        mos: &Objects,
        bp: &BlockPointer,
        routes: &ScanRepairRoutes,
        repair_started: &mut bool,
    ) -> std::result::Result<ScanBlockResult, ScanBlockFailure> {
        checkpoint(cx)?;
        if bp.hole() || bp.embedded() {
            return Ok(ScanBlockResult::Verified);
        }
        let verified_phys = mos.read_verified_physical_block(cx, bp)?;
        if bp.gang() {
            return Ok(ScanBlockResult::RepairUnavailable);
        }
        let dvas = bp.data_dvas().map_err(|e| parse_err(&e))?;
        let mut unavailable = false;
        for dva in &dvas {
            match routes.get(&dva.vdev) {
                Some(Some(_)) => {}
                Some(None) => unavailable = true,
                None => {
                    return Err(corrupt("scrub DVA targets an unknown native vdev").into());
                }
            }
        }
        if unavailable {
            // One unsupported copy must not allow a partial repair through an
            // unrelated ordinary allocator. Count this verified BP only once.
            return Ok(ScanBlockResult::RepairUnavailable);
        }
        let mut writes = Vec::new();
        for dva in &dvas {
            checkpoint(cx)?;
            let route = routes
                .get(&dva.vdev)
                .and_then(Option::as_ref)
                .ok_or_else(|| corrupt("scrub repair route disappeared"))?;
            writes.extend(route.plan(dva, &verified_phys)?);
        }
        for write in &writes {
            checkpoint(cx)?;
            let leaf = self
                .pool
                .leaves()
                .get(write.member)
                .ok_or_else(|| corrupt("scrub repair member is absent"))?;
            let data_end = label_offsets(leaf.length_bytes()).map_err(|e| parse_err(&e))?[2];
            if write.offset < DATA_OFFSET
                || write
                    .offset
                    .checked_add(write.bytes.len() as u64)
                    .is_none_or(|end| end > data_end)
            {
                return Err(corrupt("scrub repair overlaps labels or exceeds its member").into());
            }
        }
        let healed = self
            .apply_scan_repairs(cx, op_name, txg, writes, repair_started)
            .map_err(ScanBlockFailure::Repair)?;
        Ok(if healed {
            ScanBlockResult::Repaired
        } else {
            ScanBlockResult::Verified
        })
    }

    fn apply_scan_repairs(
        &mut self,
        cx: &Cx,
        op_name: &str,
        txg: u64,
        writes: Vec<ScanRepairWrite<'_>>,
        repair_started: &mut bool,
    ) -> Result<bool> {
        let mut healed_any = false;
        let mut synced_members = vec![false; self.pool.leaves().len()];
        for write in writes {
            checkpoint(cx)?;
            let current = match self.pool.leaves()[write.member].read_raw(
                cx,
                write.offset,
                write.bytes.len(),
            ) {
                Ok(bytes) => Some(bytes),
                Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
                Err(_) => None,
            };
            if current.as_deref() != Some(write.bytes.as_ref()) {
                self.emit_event(
                    op_name,
                    ZfsPersistenceStage::ScanHealWrite {
                        member_index: write.member,
                    },
                    txg,
                    write.member,
                    write.offset,
                    write.bytes.len(),
                )?;
                // An I/O error may still leave a torn physical write. From
                // this point any failed scan chunk requires a fresh writer.
                *repair_started = true;
                self.pool.leaves()[write.member].write_raw(cx, write.offset, &write.bytes)?;
                synced_members[write.member] = true;
                healed_any = true;
            }
        }
        for (member, dirty) in synced_members.into_iter().enumerate() {
            if dirty {
                self.emit_event(
                    op_name,
                    ZfsPersistenceStage::ScanHealBarrier {
                        member_index: member,
                    },
                    txg,
                    member,
                    0,
                    0,
                )?;
                self.pool.leaves()[member].sync_raw(cx)?;
            }
        }
        Ok(healed_any)
    }
}

fn scan_report_from_phys(
    phys: &DslScanPhys,
    repaired_blocks: u64,
    repair_unavailable_blocks: u64,
    checkpoint_only_blocks_excluded: bool,
    txg: u64,
) -> ZfsScanReport {
    ZfsScanReport {
        func: phys.func as u64,
        state: phys.state as u64,
        examined_blocks: phys.examined,
        processed_blocks: phys.processed,
        repaired_blocks,
        repair_unavailable_blocks,
        checkpoint_only_blocks_excluded,
        unrecoverable_errors: phys.errors,
        completed: phys.state == DslScanState::Finished,
        bookmark_objset: phys.bookmark.objset,
        bookmark_object: phys.bookmark.object,
        bookmark_level: phys.bookmark.level,
        bookmark_blkid: phys.bookmark.blkid,
        txg,
    }
}

companion_bin_tests! {
#[cfg(test)]
mod inventory_tests {
    use super::*;
    use crate::{ZfsPoolCreateSpec, ZfsWriteOptions, create_pool_on_devices};
    use ffs_block::ByteDevice;
    use ffs_ondisk::zfs::{Endian, RegularBlockSpec};
    use ffs_ondisk::zfs_dmu::{DMU_OT_DNODE, DMU_OT_OBJSET, DnodeSpec, ZilHeader, write_dnode_at};
    use ffs_types::ByteOffset;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Media {
        bytes: Vec<u8>,
        reads: Vec<(u64, usize)>,
        writes: usize,
    }

    #[derive(Clone)]
    struct MemoryDevice(Arc<Mutex<Media>>);

    impl ByteDevice for MemoryDevice {
        fn len_bytes(&self) -> u64 { self.0.lock().unwrap().bytes.len() as u64 }

        fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
            checkpoint(cx)?;
            let mut media = self.0.lock().unwrap();
            let start = offset.0 as usize;
            out.copy_from_slice(media.bytes.get(start..start + out.len())
                .ok_or_else(|| corrupt("scan test read outside media"))?);
            media.reads.push((offset.0, out.len()));
            Ok(())
        }

        fn write_all_at(&self, cx: &Cx, offset: ByteOffset, bytes: &[u8]) -> Result<()> {
            checkpoint(cx)?;
            let mut media = self.0.lock().unwrap();
            let start = offset.0 as usize;
            media.bytes.get_mut(start..start + bytes.len())
                .ok_or_else(|| corrupt("scan test write outside media"))?
                .copy_from_slice(bytes);
            media.writes += 1;
            Ok(())
        }

        fn sync(&self, cx: &Cx) -> Result<()> { checkpoint(cx) }
    }

    struct SparseFixture {
        device: MemoryDevice,
        view: Objects,
        root: BlockPointer,
        os: ObjectSet,
        payload: BlockPointer,
        interior: BlockPointer,
    }

    fn store_block(
        device: &MemoryDevice,
        cursor: &mut u64,
        bytes: &[u8],
        kind: u8,
        level: u8,
        order: Endian,
    ) -> BlockPointer {
        let offset = *cursor;
        *cursor += bytes.len() as u64;
        let mut media = device.0.lock().unwrap();
        let start = (DATA_OFFSET + offset) as usize;
        media.bytes[start..start + bytes.len()].copy_from_slice(bytes);
        BlockPointer::new_regular(&RegularBlockSpec {
            dvas: &[Dva { vdev: 0, offset, allocated_bytes: bytes.len() as u64, gang: false }],
            logical_bytes: bytes.len(), physical: bytes, compression: 2,
            checksum_type: 7, object_type: kind, level, payload_order: order, birth: 1, fill: 1,
        }).unwrap()
    }

    fn sparse_fixture(cx: &Cx, order: Endian, malformed: bool) -> SparseFixture {
        let device = MemoryDevice(Arc::new(Mutex::new(Media {
            bytes: vec![0; 12 * 1024 * 1024], ..Media::default()
        })));
        let pool_guid = 0x5CA1_1A7E_0000_0001;
        let created = create_pool_on_devices(
            cx, vec![Box::new(device.clone())],
            &ZfsPoolCreateSpec::single_leaf("scan_sparse", pool_guid),
        ).unwrap();
        let engine = ZfsTransactionEngine::from_devices(
            cx, vec![Box::new(device.clone())],
            ZfsWriteOptions {
                offline_image: true, allow_write: true, pool_guid,
                label: 0, slot: created.initial_slot, reconcile_torn_uberblocks: false,
            },
        ).unwrap();
        let mos = engine.open_read_objects(cx).unwrap();

        // A standalone native object set on this reader's real leaf. Its one
        // dnode block is above the previous 4096-block cutoff, with large holes
        // represented by zero BPs instead of millions of synthetic reads.
        let mut cursor = 2 * 1024 * 1024;
        let payload = store_block(&device, &mut cursor, &vec![0x63; 4096], 19, 0, order);
        let interior = store_block(&device, &mut cursor, &vec![0xA4; 4096], 19, 0, order);
        let small = DnodeSpec {
            object_type: 19, bonus_type: 17, checksum_type: 7, compress_type: 2,
            flags: 1, order, levels: 1, indirect_shift: 12, data_bytes: 4096,
            max_block: 0, used_bytes: 4096, slots: 1, pointers: vec![interior.clone()],
            bonus: Vec::new(), spill: None,
        };
        let fake = Dnode::from_spec(small.clone()).unwrap().encode().unwrap();
        let mut bonus = vec![0; 832];
        // This valid-looking dnode begins inside the first object's second
        // slot. Its BP is payload bytes, not another allocation owner.
        bonus[320..].copy_from_slice(&fake);
        let large = Dnode::from_spec(DnodeSpec {
            slots: 2, pointers: vec![payload.clone()], bonus, ..small.clone()
        }).unwrap();
        let trailing = Dnode::from_spec(DnodeSpec {
            pointers: vec![payload.clone()], ..small
        }).unwrap();
        let mut table = vec![0; DNODE_BLOCK_BYTES];
        write_dnode_at(&mut table, 5, &large).unwrap();
        write_dnode_at(&mut table, 7, &trailing).unwrap();
        if malformed { table[7 * DNODE_BYTES + 2] = 0; }
        let table_bp = store_block(&device, &mut cursor, &table, DMU_OT_DNODE, 0, order);
        let mut indirect = vec![0; 4096];
        indirect[128..256].copy_from_slice(&table_bp.encode(order));
        let first = store_block(&device, &mut cursor, &indirect, DMU_OT_DNODE, 1, order);
        indirect.fill(0);
        indirect[..128].copy_from_slice(&first.encode(order));
        let second = store_block(&device, &mut cursor, &indirect, DMU_OT_DNODE, 2, order);
        indirect.fill(0);
        indirect[4 * 128..5 * 128].copy_from_slice(&second.encode(order));
        let third = store_block(&device, &mut cursor, &indirect, DMU_OT_DNODE, 3, order);
        let meta = Dnode::from_spec(DnodeSpec {
            object_type: DMU_OT_DNODE, bonus_type: 0, checksum_type: 7,
            compress_type: 2, flags: 1, order, levels: 4, indirect_shift: 12,
            data_bytes: DNODE_BLOCK_BYTES, max_block: 4097, used_bytes: 28_672,
            slots: 1, pointers: vec![third], bonus: Vec::new(), spill: None,
        }).unwrap();
        let os = ObjectSet::new(2, 0, meta, ZilHeader::empty(), 4096).unwrap();
        let root = store_block(&device, &mut cursor, &os.encode(order).unwrap(), DMU_OT_OBJSET, 0, order);
        let view = mos.open_objectset_view(os.meta.clone(), 1, mos.txg);
        device.0.lock().unwrap().reads.clear();
        SparseFixture { device, view, root, os, payload, interior }
    }

    #[test]
    fn scan_inventory_visits_sparse_high_objects_and_skips_large_dnode_interiors() {
        let cx = Cx::for_testing();
        for order in [Endian::Little, Endian::Big] {
            let mut fixture = sparse_fixture(&cx, order, false);
            let writes = fixture.device.0.lock().unwrap().writes;
            let mut inventory = ScanInventory::new();
            inventory.objectset(&cx, &mut fixture.view, 99, &fixture.root, &fixture.os).unwrap();
            let objects: Vec<_> = inventory.blocks.iter()
                .filter(|block| block.bp == fixture.payload)
                .map(|block| block.bookmark.object).collect();
            assert_eq!(objects, vec![4097 * 32 + 5, 4097 * 32 + 7]);
            assert!(!inventory.blocks.iter().any(|block| block.bp == fixture.interior));
            assert_eq!(inventory.blocks.len(), 7, "root, three indirects, table and two real objects");
            let media = fixture.device.0.lock().unwrap();
            assert_eq!(media.reads.len(), 4, "holes must not expand into linear metadata reads");
            assert_eq!(media.writes, writes, "inventory is read-only");
        }
    }

    #[test]
    fn scan_inventory_metadata_budget_and_last_allocated_dnode_errors_are_terminal() {
        let cx = Cx::for_testing();
        for order in [Endian::Little, Endian::Big] {
            let mut fixture = sparse_fixture(&cx, order, false);
            let writes = fixture.device.0.lock().unwrap().writes;
            let mut inventory = ScanInventory::new();
            inventory.metadata_left = 3 * 4096 + DNODE_BLOCK_BYTES - 1;
            assert!(matches!(
                inventory.objectset(&cx, &mut fixture.view, 99, &fixture.root, &fixture.os),
                Err(FfsError::UnsupportedFeature(_)),
            ));
            assert_eq!(fixture.device.0.lock().unwrap().reads.len(), 3);
            assert_eq!(fixture.device.0.lock().unwrap().writes, writes);

            let mut fixture = sparse_fixture(&cx, order, true);
            let mut inventory = ScanInventory::new();
            assert!(matches!(
                inventory.objectset(&cx, &mut fixture.view, 99, &fixture.root, &fixture.os),
                Err(FfsError::Corruption { .. }),
            ));
            assert_eq!(fixture.device.0.lock().unwrap().reads.len(), 4);
        }
    }
}
}
