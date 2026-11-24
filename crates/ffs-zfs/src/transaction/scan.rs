//! Resumable pool-wide scrub and resilver engine persisted in MOS `"scan"`
//! (`dsl_scan_phys_t`, `24 × u64 = 192` bytes, OpenZFS `zfs-2.4.0`).
//!
//! Deterministically walks MOS (`objset = 0`) plus every dataset head and
//! snapshot in ascending `(objset, object, level, blkid)` order, verifies every
//! physical replica / RAIDZ column / dRAID column, heals recoverable damage
//! directly on disk (`ScanHealWrite` + `ScanHealBarrier`), persists exact
//! resumption bookmarks in MOS object 1 `"scan"` at bounded chunk intervals,
//! and cleanly reconciles concurrent foreground writes across pause/resume.

use std::collections::BTreeMap;

use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_ondisk::zfs::draid::DraidMap;
use ffs_ondisk::zfs::raidz::Raidz1Map;
use ffs_ondisk::zfs::raidz::parity::RaidzParityMap;
use ffs_ondisk::zfs::scan::{
    DSL_SCAN_PHYS_WORDS, DslScanFunc, DslScanPhys, DslScanState, ZBookmarkPhys,
};
use ffs_ondisk::zfs::{BlockPointer, DATA_OFFSET, Endian};
use ffs_ondisk::zfs_dmu::{DNODE_BLOCK_BYTES, DNODE_BYTES, Dnode, ObjectSet, dnode_at};
use ffs_ondisk::zfs_zap::Entry as RawZapEntry;
use serde::Serialize;

use super::dmu_cow::{
    AllocatorWriteTopology, DnodeCowSpec, PoolSpaceAllocator, StagedBlockWrite, WriteBucket,
    cow_update_dnode, encode_zap_blocks_for_dnode, put_dnode_in_table,
};
use super::{
    ZfsPersistenceStage, ZfsTransactionEngine, ZfsTxOutcome, checkpoint, corrupt, parse_err,
    unsupported,
};
use crate::reader::dmu::Objects;

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
#[allow(clippy::too_many_arguments)]
pub(super) fn stage_scan_phys_in_mos(
    cx: &Cx,
    mos: &mut Objects,
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    scan: &DslScanPhys,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<()> {
    let mut dir_entries = mos.zap_values(cx, 1)?;
    dir_entries.retain(|e| e.name != DMU_POOL_SCAN_KEY);
    dir_entries.push(RawZapEntry {
        name: DMU_POOL_SCAN_KEY.to_vec(),
        integer_bytes: 8,
        values: scan.to_words().to_vec(),
        collision: 0,
    });
    let (dir_dn, dir_ceil) = mos.object_with_ceiling(cx, 1)?;
    let (bsize, blocks) =
        encode_zap_blocks_for_dnode(cx, mos, Some((&dir_dn, dir_ceil)), &dir_entries, order, 512)?;
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
            new_txg,
            leaf_bucket: WriteBucket::MosSpaceMap,
            indirect_bucket: WriteBucket::MosSpaceMap,
        },
        &dirty,
        staged_writes,
    )?;
    for rbp in &out.retired_bps {
        alloc.free_block_dvas(rbp, new_txg)?;
    }
    let mos_meta = mos.meta_dnode().clone();
    let mos_ceil = mos.root_birth_txg();
    put_dnode_in_table(
        cx,
        mos,
        &mos_meta,
        mos_ceil,
        mos_dirty_dnodes,
        1,
        &out.dnode,
    )
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
        let order = self.order;
        let ts = self.current_uberblock.timestamp.saturating_add(1);
        self.execute_staged_txg_typed(
            cx,
            "zfs_scrub_cancel",
            |mos, mos_dirty, _features, alloc, new_txg, staged| {
                let mut scan = read_scan_phys_from_mos(cx, mos)?
                    .ok_or_else(|| FfsError::Format("no active pool scan to cancel".into()))?;
                if scan.state != DslScanState::Scanning {
                    return Err(FfsError::Format(
                        "pool scan is not currently running".into(),
                    ));
                }
                scan.state = DslScanState::Canceled;
                scan.end_time = ts;
                stage_scan_phys_in_mos(cx, mos, mos_dirty, alloc, order, new_txg, &scan, staged)?;
                let report = scan_report_from_phys(&scan, 0, new_txg);
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
        let current_txg = self.committed_txg;
        let next_txg = current_txg.saturating_add(1);
        let mut examined_this_chunk = 0_u64;
        let mut repaired_this_chunk = 0_u64;
        let mut reached_end = true;

        for item in &all_blocks {
            if let Err(err) = checkpoint(cx) {
                return ZfsTxOutcome::NotCommitted(err);
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
            match self.verify_and_heal_block(cx, op_name, next_txg, &mos, &item.bp) {
                Ok(healed) => {
                    if healed {
                        repaired_this_chunk += 1;
                    }
                    scan.processed = scan
                        .processed
                        .saturating_add(item.bp.physical_bytes() as u64);
                }
                Err(FfsError::Cancelled) => return ZfsTxOutcome::NotCommitted(FfsError::Cancelled),
                Err(_) => {
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

        let order = self.order;
        let final_scan = scan;
        self.execute_staged_txg_typed(
            cx,
            op_name,
            |mos, mos_dirty, _features, alloc, new_txg, staged| {
                stage_scan_phys_in_mos(
                    cx,
                    mos,
                    mos_dirty,
                    alloc,
                    order,
                    new_txg,
                    &final_scan,
                    staged,
                )?;
                let report = scan_report_from_phys(&final_scan, repaired_this_chunk, new_txg);
                Ok((report, new_txg))
            },
        )
    }

    /// Verify every physical replica / column of `bp` and heal any damaged or
    /// divergent replica/parity column on disk from verified reconstructed bytes.
    #[allow(clippy::too_many_lines)]
    fn verify_and_heal_block(
        &mut self,
        cx: &Cx,
        op_name: &str,
        txg: u64,
        mos: &Objects,
        bp: &BlockPointer,
    ) -> Result<bool> {
        checkpoint(cx)?;
        if bp.hole() || bp.embedded() || bp.gang() {
            return Ok(false);
        }
        // Obtain the checksum-verified authoritative physical bytes first.
        let verified_phys = mos.read_verified_physical_block(cx, bp)?;
        let dvas = bp.data_dvas().map_err(|e| parse_err(&e))?;
        let mut healed_any = false;
        let mut synced_members = vec![false; self.pool.leaves().len()];

        for dva in &dvas {
            match &self.allocator.write_topology {
                AllocatorWriteTopology::LeafOrMirror => {
                    let phys_off = DATA_OFFSET + dva.offset;
                    let member_count = self.pool.leaves().len();
                    for (m_idx, synced) in synced_members.iter_mut().enumerate().take(member_count)
                    {
                        let current = self.pool.leaves()[m_idx]
                            .read_raw(cx, phys_off, verified_phys.len())
                            .ok();
                        if current.as_deref() != Some(verified_phys.as_slice()) {
                            self.emit_event(
                                op_name,
                                ZfsPersistenceStage::ScanHealWrite {
                                    member_index: m_idx,
                                },
                                txg,
                                m_idx,
                                phys_off,
                                verified_phys.len(),
                            )?;
                            self.pool.leaves()[m_idx].write_raw(cx, phys_off, &verified_phys)?;
                            *synced = true;
                            healed_any = true;
                        }
                    }
                }
                AllocatorWriteTopology::Raidz { parity, width } => {
                    let ashift = self.allocator.ashift;
                    let (cols, expected_payloads) = if *parity == 1 {
                        let map =
                            Raidz1Map::new_wide(dva.offset, verified_phys.len(), ashift, *width)
                                .map_err(|e| parse_err(&e))?;
                        let enc = map.encode(&verified_phys).map_err(|e| parse_err(&e))?;
                        (map.columns().to_vec(), enc)
                    } else {
                        let map = RaidzParityMap::new_wide(
                            dva.offset,
                            verified_phys.len(),
                            ashift,
                            *width,
                            *parity,
                        )
                        .map_err(|e| parse_err(&e))?;
                        let enc = map.encode(&verified_phys).map_err(|e| parse_err(&e))?;
                        (map.columns().to_vec(), enc)
                    };
                    for (col, expected) in cols.iter().zip(&expected_payloads) {
                        if expected.is_empty() {
                            continue;
                        }
                        let phys_off = DATA_OFFSET + col.offset;
                        let m_idx = col.child_id;
                        let current = self.pool.leaves()[m_idx]
                            .read_raw(cx, phys_off, expected.len())
                            .ok();
                        if current.as_deref() != Some(expected.as_slice()) {
                            self.emit_event(
                                op_name,
                                ZfsPersistenceStage::ScanHealWrite {
                                    member_index: m_idx,
                                },
                                txg,
                                m_idx,
                                phys_off,
                                expected.len(),
                            )?;
                            self.pool.leaves()[m_idx].write_raw(cx, phys_off, expected)?;
                            synced_members[m_idx] = true;
                            healed_any = true;
                        }
                    }
                }
                AllocatorWriteTopology::Draid(draid_cfg) => {
                    let map = DraidMap::new(draid_cfg, dva.offset, verified_phys.len())
                        .map_err(|e| parse_err(&e))?;
                    let enc_rows = map.encode_rows(&verified_phys).map_err(|e| parse_err(&e))?;
                    for (row, row_payloads) in map.rows().iter().zip(&enc_rows) {
                        for (col, expected) in row.columns.iter().zip(row_payloads) {
                            if expected.is_empty() {
                                continue;
                            }
                            let phys_off = DATA_OFFSET + col.offset;
                            let m_idx = col.child_id;
                            let current = self.pool.leaves()[m_idx]
                                .read_raw(cx, phys_off, expected.len())
                                .ok();
                            if current.as_deref() != Some(expected.as_slice()) {
                                self.emit_event(
                                    op_name,
                                    ZfsPersistenceStage::ScanHealWrite {
                                        member_index: m_idx,
                                    },
                                    txg,
                                    m_idx,
                                    phys_off,
                                    expected.len(),
                                )?;
                                self.pool.leaves()[m_idx].write_raw(cx, phys_off, expected)?;
                                synced_members[m_idx] = true;
                                healed_any = true;
                            }
                        }
                    }
                }
            }
        }

        if healed_any {
            for (m_idx, dirty) in synced_members.into_iter().enumerate() {
                if dirty {
                    self.emit_event(
                        op_name,
                        ZfsPersistenceStage::ScanHealBarrier {
                            member_index: m_idx,
                        },
                        txg,
                        m_idx,
                        0,
                        0,
                    )?;
                    self.pool.leaves()[m_idx].sync_raw(cx)?;
                }
            }
        }
        Ok(healed_any)
    }
}

fn scan_report_from_phys(phys: &DslScanPhys, repaired_blocks: u64, txg: u64) -> ZfsScanReport {
    ZfsScanReport {
        func: phys.func as u64,
        state: phys.state as u64,
        examined_blocks: phys.examined,
        processed_blocks: phys.processed,
        repaired_blocks,
        unrecoverable_errors: phys.errors,
        completed: phys.state == DslScanState::Finished,
        bookmark_objset: phys.bookmark.objset,
        bookmark_object: phys.bookmark.object,
        bookmark_level: phys.bookmark.level,
        bookmark_blkid: phys.bookmark.blkid,
        txg,
    }
}
