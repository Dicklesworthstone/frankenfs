//! Resumable pool-wide scrub and resilver engine persisted in MOS `"scan"`
//! (`dsl_scan_phys_t`, `24 × u64 = 192` bytes, OpenZFS `zfs-2.4.0`).
//!
//! Deterministically walks MOS (`objset = 0`) plus every dataset head and
//! snapshot in ascending `(objset, object, level, blkid)` order, verifies every
//! physical replica / RAIDZ column / dRAID column, heals recoverable damage
//! directly on disk (`ScanHealWrite` + `ScanHealBarrier`), persists exact
//! resumption bookmarks in MOS object 1 `"scan"` at bounded chunk intervals,
//! and cleanly reconciles concurrent foreground writes across pause/resume.

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
use ffs_ondisk::zfs_dmu::{DNODE_BLOCK_BYTES, DNODE_BYTES, Dnode, ObjectSet, dnode_at};
use ffs_ondisk::zfs_zap::Entry as RawZapEntry;
use serde::Serialize;
use std::borrow::Cow;
use std::collections::BTreeMap;

use super::dmu_cow::{AllocatorWriteTopology, PoolSpaceAllocator};
use super::{
    ZfsPersistenceStage, ZfsTransactionEngine, ZfsTxOutcome, checkpoint, corrupt, parse_err,
    unsupported,
};
use crate::reader::dmu::Objects;
use crate::reader::pool::vdev::{PoolTopology, TopVdevKind, VdevHealth};

const DMU_POOL_SCAN_KEY: &[u8] = b"scan";

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

/// Enumerate all non-hole, non-embedded block pointers across MOS (`objset=0`)
/// and every dataset head & snapshot in deterministic ascending bookmark order.
pub(super) fn collect_pool_blocks(cx: &Cx, mos: &mut Objects) -> Result<Vec<DiscoveredBlock>> {
    checkpoint(cx)?;
    let mut blocks = Vec::new();
    let mos_meta = mos.meta_dnode().clone();
    let mos_ceil = mos.root_birth_txg();
    collect_objset_blocks(cx, mos, 0, &mos_meta, mos_ceil, &mut blocks)?;

    let datasets = mos.datasets(cx)?;
    for ds in datasets {
        checkpoint(cx)?;
        if ds.objectset_kind.is_none() {
            continue;
        }
        let (hd_dn, hd_ceil) = mos.object_with_ceiling(cx, ds.head_object)?;
        if hd_dn.bonus().len() < 256 {
            continue;
        }
        let ds_bp = BlockPointer::parse(&hd_dn.bonus()[128..256], hd_dn.order())
            .map_err(|e| parse_err(&e))?;
        if !ds_bp.hole() && !ds_bp.embedded() {
            blocks.push(DiscoveredBlock {
                bookmark: ZBookmarkPhys {
                    objset: ds.head_object,
                    object: 0,
                    level: 0,
                    blkid: 0,
                },
                bp: ds_bp.clone(),
            });
            if let Ok((ds_raw, ds_ord, ds_birth)) =
                mos.read_dataset_objset_block_raw(cx, &ds_bp, hd_ceil, None, true)
                && let Ok(ds_os) = ObjectSet::parse(&ds_raw, ds_ord)
            {
                let mut ds_view = mos.open_objectset_view(ds_os.meta.clone(), ds_birth, mos.txg);
                collect_objset_blocks(
                    cx,
                    &mut ds_view,
                    ds.head_object,
                    &ds_os.meta,
                    ds_birth,
                    &mut blocks,
                )?;
            }
        }
    }

    blocks.sort_by_key(|item| bookmark_key(&item.bookmark));
    Ok(blocks)
}

fn collect_objset_blocks(
    cx: &Cx,
    view: &mut Objects,
    objset_id: u64,
    meta: &Dnode,
    ceiling: u64,
    out: &mut Vec<DiscoveredBlock>,
) -> Result<()> {
    collect_dnode_tree(cx, view, objset_id, 0, meta, ceiling, out)?;
    let slots_per_blk = (DNODE_BLOCK_BYTES / DNODE_BYTES) as u64;
    let max_blk = meta.max_block().min(4096);
    for bid in 0..=max_blk {
        checkpoint(cx)?;
        let Some((blk_bytes, blk_ord, blk_birth)) =
            view.object_data_block(cx, meta, ceiling, bid)?
        else {
            continue;
        };
        for slot in 0..(slots_per_blk as usize) {
            let obj_id = bid * slots_per_blk + slot as u64;
            if obj_id == 0 {
                continue;
            }
            if let Ok(Some(dn)) = dnode_at(&blk_bytes, slot, blk_ord) {
                collect_dnode_tree(cx, view, objset_id, obj_id, &dn, blk_birth, out)?;
            }
        }
    }
    Ok(())
}

fn collect_dnode_tree(
    cx: &Cx,
    view: &mut Objects,
    objset_id: u64,
    object_id: u64,
    node: &Dnode,
    ceiling: u64,
    out: &mut Vec<DiscoveredBlock>,
) -> Result<()> {
    let top_level = node.levels().saturating_sub(1);
    let fanout = (node.indirect_bytes() / 128) as u64;
    for (slot, bp) in node.pointers().iter().enumerate() {
        walk_bp_tree(
            cx,
            view,
            objset_id,
            object_id,
            node,
            bp,
            top_level,
            slot as u64,
            fanout,
            ceiling,
            out,
        )?;
    }
    if let Some(spill) = node.spill()
        && !spill.hole()
        && !spill.embedded()
    {
        out.push(DiscoveredBlock {
            bookmark: ZBookmarkPhys {
                objset: objset_id,
                object: object_id,
                level: -1,
                blkid: 0,
            },
            bp: spill.clone(),
        });
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn walk_bp_tree(
    cx: &Cx,
    view: &mut Objects,
    objset_id: u64,
    object_id: u64,
    node: &Dnode,
    bp: &BlockPointer,
    level: u8,
    blkid: u64,
    fanout: u64,
    ceiling: u64,
    out: &mut Vec<DiscoveredBlock>,
) -> Result<()> {
    checkpoint(cx)?;
    if bp.hole() || bp.embedded() {
        return Ok(());
    }
    out.push(DiscoveredBlock {
        bookmark: ZBookmarkPhys {
            objset: objset_id,
            object: object_id,
            level: i64::from(level),
            blkid,
        },
        bp: bp.clone(),
    });
    if level == 0 {
        return Ok(());
    }
    if let Ok(Some((raw, ord, birth))) = view.checked_raw(
        cx,
        bp,
        node.object_type(),
        level,
        node.indirect_bytes(),
        ceiling,
    ) {
        for (slot, chunk) in raw.as_chunks::<128>().0.iter().enumerate() {
            if let Ok(child) = BlockPointer::parse(chunk, ord)
                && !child.hole()
            {
                let child_blkid = blkid.saturating_mul(fanout).saturating_add(slot as u64);
                walk_bp_tree(
                    cx,
                    view,
                    objset_id,
                    object_id,
                    node,
                    &child,
                    level - 1,
                    child_blkid,
                    fanout,
                    birth,
                    out,
                )?;
            }
        }
    }
    Ok(())
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
                let report = scan_report_from_phys(&scan, 0, 0, new_txg);
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

        let all_blocks = match collect_pool_blocks(cx, &mut mos) {
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
        let outcome = self.execute_staged_txg_typed(
            cx,
            op_name,
            |mos, _mos_dirty, _features, alloc, new_txg, _staged| {
                stage_scan_phys_in_mos(cx, mos, alloc, &final_scan)?;
                let report = scan_report_from_phys(
                    &final_scan,
                    repaired_this_chunk,
                    repair_unavailable_this_chunk,
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
    txg: u64,
) -> ZfsScanReport {
    ZfsScanReport {
        func: phys.func as u64,
        state: phys.state as u64,
        examined_blocks: phys.examined,
        processed_blocks: phys.processed,
        repaired_blocks,
        repair_unavailable_blocks,
        unrecoverable_errors: phys.errors,
        completed: phys.state == DslScanState::Finished,
        bookmark_objset: phys.bookmark.objset,
        bookmark_object: phys.bookmark.object,
        bookmark_level: phys.bookmark.level,
        bookmark_blkid: phys.bookmark.blkid,
        txg,
    }
}
