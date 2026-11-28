//! Offline first-expansion protocol for a RAIDZ allocation prefix that fits
//! native scratch space. Scratch becomes read authority before any old data
//! placement is overwritten; an interrupted copy-out is therefore repeatable.

use super::{
    AllocatorWriteTopology, DATA_OFFSET, LABEL_CONFIG_BYTES, LABEL_CONFIG_OFFSET, Leaf, NvList,
    RaidzReflowInfo, RaidzReflowScratchState, UBERBLOCK_RING_OFFSET, Value, ZfsExpandRaidzReport,
    ZfsPersistenceStage, ZfsTopologyKind, ZfsTransactionEngine, ZfsTxOutcome, checkpoint, corrupt,
    label_offsets, parse_err, stamp_label_checksum, unsupported, update_mos_config_top_tree,
};
use crate::reader::dmu::Objects;
use crate::reader::pool::vdev::{ExpandedRaidzMeta, VdevHealth};
use crate::{Pool, ZfsDurableToken};
use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_ondisk::zfs::raidz::expand::VDEV_BOOT_SIZE;
use ffs_ondisk::zfs::{UBERBLOCK_RING_BYTES, verify_label_checksum};
use std::collections::BTreeMap;

const EXPANSION_FEATURE: &str = "org.openzfs:raidz_expansion";
const MAX_REFLOW_CHUNK: u64 = 1024 * 1024;

struct ReflowGeometry {
    old_width: usize,
    new_width: usize,
    parity: usize,
    sector: u64,
    prefix_end: u64,
    prefix_limit: u64,
    members: Vec<usize>,
}

impl ReflowGeometry {
    fn allocation_ceiling(&self) -> u64 {
        self.prefix_limit - self.old_width as u64 * self.sector
    }

    fn report(&self, cursor: u64, chunks: u64, completed: bool, txg: u64) -> ZfsExpandRaidzReport {
        ZfsExpandRaidzReport {
            old_width: self.old_width,
            new_width: self.new_width,
            parity: self.parity,
            reflow_offset: cursor,
            total_reflow_bytes: self.prefix_end,
            chunks_processed: chunks,
            completed,
            txg,
        }
    }
}

struct ExpansionAdmission {
    mos: Objects,
    top_tree: NvList,
    geometry: ReflowGeometry,
    state: RaidzReflowInfo,
    active: bool,
}

impl ZfsTransactionEngine {
    #[allow(clippy::too_many_lines)]
    pub(super) fn expand_raidz_inner(
        &mut self,
        cx: &Cx,
        new_disk: Leaf,
        chunk_bytes: u64,
        max_chunks_per_txg: usize,
    ) -> ZfsTxOutcome<ZfsExpandRaidzReport> {
        let admission =
            match self.admit_raidz_expansion(cx, &new_disk, chunk_bytes, max_chunks_per_txg) {
                Ok(admission) => admission,
                Err(error) => return ZfsTxOutcome::NotCommitted(error),
            };
        if !admission.active {
            return self.bootstrap_raidz_expansion(cx, new_disk, admission);
        }
        let ExpansionAdmission {
            mos,
            top_tree,
            geometry,
            state,
            ..
        } = admission;
        if matches!(
            state.state,
            RaidzReflowScratchState::InvalidSynced
                | RaidzReflowScratchState::InvalidSyncedOnImport
                | RaidzReflowScratchState::InvalidSyncedReflow
        ) {
            return self.complete_raidz_expansion(cx, mos, top_tree, &geometry);
        }

        let preparing_scratch = state.state == RaidzReflowScratchState::NotInUse;
        let mut cursor = self.allocator.raidz_reflow_cursor;
        let mut chunks = 0_u64;
        let chunk_limit = chunk_bytes.min(MAX_REFLOW_CHUNK);
        while cursor < geometry.prefix_end && chunks < max_chunks_per_txg as u64 {
            if let Err(error) = checkpoint(cx) {
                return ZfsTxOutcome::NotCommitted(error);
            }
            let end = cursor.saturating_add(chunk_limit).min(geometry.prefix_end);
            if let Err(error) =
                self.copy_raidz_reflow_chunk(cx, &geometry, cursor, end, preparing_scratch)
            {
                // The selected root still reads either the untouched old data
                // area or the complete, immutable scratch image.
                return ZfsTxOutcome::NotCommitted(error);
            }
            cursor = end;
            chunks += 1;
            self.allocator.raidz_reflow_cursor = cursor;
        }
        if cursor == geometry.prefix_end {
            let next_state = if preparing_scratch {
                RaidzReflowScratchState::Valid
            } else {
                RaidzReflowScratchState::InvalidSynced
            };
            match self.publish_raidz_reflow_authority(cx, next_state, geometry.prefix_end) {
                ZfsTxOutcome::Committed { token, .. } => {
                    self.allocator.raidz_reflow_cursor = 0;
                    return ZfsTxOutcome::Committed {
                        value: geometry.report(cursor, chunks, false, self.committed_txg),
                        token,
                    };
                }
                ZfsTxOutcome::NotCommitted(error) => return ZfsTxOutcome::NotCommitted(error),
                ZfsTxOutcome::Uncertain {
                    reason,
                    target_txg,
                    target_slot,
                } => {
                    return ZfsTxOutcome::Uncertain {
                        reason,
                        target_txg,
                        target_slot,
                    };
                }
            }
        }
        ZfsTxOutcome::Committed {
            value: geometry.report(cursor, chunks, false, self.committed_txg),
            token: self.raidz_reflow_token("zfs_pool_expand_raidz_progress", cursor),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn admit_raidz_expansion(
        &self,
        cx: &Cx,
        new_disk: &Leaf,
        chunk_bytes: u64,
        max_chunks_per_txg: usize,
    ) -> Result<ExpansionAdmission> {
        checkpoint(cx)?;
        if self.requires_recovery() {
            return Err(unsupported(
                "RAIDZ expansion requires recovery of the uncertain writer",
            ));
        }
        let ZfsTopologyKind::Raidz { parity, width } = self.storage_identity.topology else {
            return Err(unsupported(
                "expand_raidz requires one complete RAIDZ1/2/3 vdev",
            ));
        };
        let sector = 1_u64 << self.allocator.ashift;
        if chunk_bytes == 0 || !chunk_bytes.is_multiple_of(sector) || max_chunks_per_txg == 0 {
            return Err(FfsError::Format(
                "expand_raidz requires ashift-aligned chunk_bytes > 0 and max_chunks_per_txg >= 1"
                    .into(),
            ));
        }
        self.committed_txg
            .checked_add(1)
            .ok_or_else(|| corrupt("ZFS TXG counter overflow"))?;
        self.current_uberblock
            .timestamp
            .checked_add(1)
            .ok_or_else(|| corrupt("ZFS uberblock timestamp overflow"))?;
        self.generation
            .checked_add(1)
            .ok_or_else(|| corrupt("ZFS token generation overflow"))?;
        let checkpoint_active = self.current_uberblock.checkpoint_txg != 0
            || self.allocator.checkpoint_txg != 0
            || !self.allocator.checkpoint_deferred_frees.is_empty()
            || [
                &self.mos_features.read_features,
                &self.mos_features.write_features,
            ]
            .iter()
            .any(|features| {
                features
                    .get("com.delphix:zpool_checkpoint")
                    .copied()
                    .unwrap_or(0)
                    != 0
            });
        if checkpoint_active {
            return Err(unsupported(
                "RAIDZ expansion requires discarding the pool checkpoint first",
            ));
        }
        let mut mos = self.open_read_objects(cx)?;
        let config = mos.load_mos_config_nvlist(cx)?;
        let root = config
            .list("vdev_tree")
            .ok_or_else(|| corrupt("missing MOS vdev tree"))?;
        let Some(Value::Lists(tops)) = root.fields.get("children") else {
            return Err(corrupt("missing MOS top-level vdevs"));
        };
        if tops.len() != 1 || self.allocator.vdev_id != 0 {
            return Err(unsupported(
                "bounded RAIDZ expansion requires a single allocating vdev",
            ));
        }
        let top_tree = tops[0].clone();
        let Some(Value::Lists(children)) = top_tree.fields.get("children") else {
            return Err(corrupt("RAIDZ expansion has no native children"));
        };
        if top_tree.text("type") != Some("raidz")
            || children.len() != width
            || top_tree.unsigned("nparity") != Some(parity as u64)
            || !VdevHealth::from_vdev_tree(&top_tree).is_healthy()
            || top_tree.unsigned("nonallocating").unwrap_or(0) != 0
            || children.iter().enumerate().any(|(id, child)| {
                !matches!(child.text("type"), Some("file" | "disk"))
                    || child.unsigned("id") != Some(id as u64)
                    || !VdevHealth::from_vdev_tree(child).is_healthy()
            })
        {
            return Err(unsupported(
                "RAIDZ expansion requires healthy direct native children",
            ));
        }
        let metadata = ExpandedRaidzMeta::from_vdev_tree(&top_tree, width)?;
        if metadata
            .as_ref()
            .is_some_and(|meta| !meta.expand_txgs.is_empty())
        {
            return Err(unsupported(
                "bounded scratch reflow currently supports the first RAIDZ expansion",
            ));
        }
        let active = metadata.as_ref().is_some_and(|meta| meta.expanding);
        if active != self.allocator.raidz_expanding {
            return Err(corrupt("RAIDZ allocator and MOS expansion state disagree"));
        }
        let old_width = width - usize::from(active);
        let new_width = old_width + 1;
        if old_width <= parity || new_width > 255 {
            return Err(unsupported(
                "expanded RAIDZ width is outside native writer bounds",
            ));
        }
        // Completion must be representable before a bootstrap can freeze the
        // pool in an active expansion that its allocator cannot finish.
        let old_asize = top_tree
            .unsigned("asize")
            .ok_or_else(|| corrupt("RAIDZ asize is missing"))?;
        let metaslab_size = 1_u64 << self.allocator.metaslab_shift;
        let grown_asize = (old_asize / old_width as u64)
            .checked_mul(new_width as u64)
            .ok_or_else(|| corrupt("expanded RAIDZ asize overflow"))?
            / metaslab_size
            * metaslab_size;
        if grown_asize <= old_asize || (grown_asize >> self.allocator.metaslab_shift) > 65_536 {
            return Err(unsupported(
                "RAIDZ expansion cannot add an admitted complete metaslab",
            ));
        }
        let mut native_guids = Vec::with_capacity(new_width);
        for child in children {
            native_guids.push(
                child
                    .unsigned("guid")
                    .ok_or_else(|| corrupt("RAIDZ child has no GUID"))?,
            );
        }
        let supplied: BTreeMap<_, _> = self
            .storage_identity
            .member_guids
            .iter()
            .copied()
            .enumerate()
            .map(|(index, guid)| (guid, index))
            .collect();
        if supplied.len() != width
            || supplied.len() != self.pool.leaves().len()
            || supplied.contains_key(&0)
        {
            return Err(corrupt("RAIDZ physical member identity is incomplete"));
        }
        let mut members = Vec::with_capacity(new_width);
        for guid in &native_guids {
            let index = supplied
                .get(guid)
                .copied()
                .ok_or_else(|| corrupt("native RAIDZ child has no admitted physical member"))?;
            if members.contains(&index) {
                return Err(corrupt("duplicate native RAIDZ child GUID"));
            }
            members.push(index);
        }
        let min_len = self
            .pool
            .leaves()
            .iter()
            .map(Leaf::length_bytes)
            .min()
            .unwrap_or(0);
        if new_disk.length_bytes() < min_len {
            return Err(FfsError::InvalidGeometry(
                "RAIDZ expansion disk is smaller than existing RAIDZ children".into(),
            ));
        }
        if active {
            let label = new_disk.label(cx, 0)?;
            if label.config.unsigned("pool_guid") != Some(self.storage_identity.pool_guid)
                || label.config.unsigned("guid") != native_guids.last().copied()
            {
                return Err(corrupt(
                    "resumed RAIDZ expansion names a different new child",
                ));
            }
        } else {
            members.push(width);
        }

        // Consecutive widths are coprime. Align to both geometries, and leave a
        // full old-width row after the last allocation so every phantom column
        // considered by the native read mapper lies below the authority cursor.
        let row_bytes = (old_width as u64)
            .checked_mul(new_width as u64)
            .and_then(|n| n.checked_mul(sector))
            .ok_or_else(|| corrupt("RAIDZ expansion row alignment overflow"))?;
        let data_end = label_offsets(min_len).map_err(|error| parse_err(&error))?[2];
        let data_bytes = data_end
            .checked_sub(DATA_OFFSET)
            .ok_or_else(|| corrupt("RAIDZ leaf has no data area"))?;
        let source_limit = data_bytes
            .checked_mul(old_width as u64)
            .ok_or_else(|| corrupt("RAIDZ source capacity overflow"))?;
        let scratch_limit = VDEV_BOOT_SIZE
            .checked_mul(new_width as u64)
            .ok_or_else(|| corrupt("RAIDZ scratch capacity overflow"))?;
        let prefix_limit = source_limit.min(scratch_limit) / row_bytes * row_bytes;
        let padding = old_width as u64 * sector;
        if prefix_limit <= padding {
            return Err(unsupported(
                "RAIDZ width and ashift cannot fit native expansion scratch",
            ));
        }
        let highest = self.raidz_highest_owned_end()?;
        let prefix_end = highest
            .checked_add(padding)
            .and_then(|end| end.checked_add(row_bytes - 1))
            .map(|end| end / row_bytes * row_bytes)
            .ok_or_else(|| corrupt("RAIDZ scratch prefix overflow"))?;
        if prefix_end > prefix_limit {
            return Err(unsupported(
                "allocated RAIDZ prefix exceeds native scratch capacity; larger online reflow is not yet supported",
            ));
        }
        let state = RaidzReflowInfo::decode(self.current_uberblock.raidz_reflow_info)
            .map_err(|error| parse_err(&error))?;
        if (!active && state.state != RaidzReflowScratchState::NotInUse)
            || (state.state == RaidzReflowScratchState::NotInUse && state.offset != 0)
            || (active
                && state.state != RaidzReflowScratchState::NotInUse
                && state.offset != prefix_end)
            || self.allocator.raidz_reflow_cursor > prefix_end
            || !self.allocator.raidz_reflow_cursor.is_multiple_of(sector)
        {
            return Err(unsupported(
                "RAIDZ reflow state does not describe the complete bounded prefix",
            ));
        }
        Ok(ExpansionAdmission {
            mos,
            top_tree,
            geometry: ReflowGeometry {
                old_width,
                new_width,
                parity,
                sector,
                prefix_end,
                prefix_limit,
                members,
            },
            state,
            active,
        })
    }

    fn raidz_highest_owned_end(&self) -> Result<u64> {
        let mut highest = self
            .allocator
            .metaslabs
            .iter()
            .flat_map(|metaslab| metaslab.final_map.ranges())
            .map(|range| range.end)
            .max()
            .unwrap_or(0);
        for dva in self
            .current_uberblock
            .root
            .data_dvas()
            .map_err(|error| parse_err(&error))?
        {
            if dva.vdev != self.allocator.vdev_id || dva.gang {
                return Err(unsupported(
                    "RAIDZ scratch reflow requires a concrete local MOS root",
                ));
            }
            highest = highest.max(
                dva.offset
                    .checked_add(dva.allocated_bytes)
                    .ok_or_else(|| corrupt("MOS root extent overflow"))?,
            );
        }
        Ok(highest)
    }

    #[allow(clippy::too_many_lines)]
    fn bootstrap_raidz_expansion(
        &mut self,
        cx: &Cx,
        new_disk: Leaf,
        admission: ExpansionAdmission,
    ) -> ZfsTxOutcome<ZfsExpandRaidzReport> {
        let ExpansionAdmission {
            mos,
            mut top_tree,
            mut geometry,
            ..
        } = admission;
        let next_txg = self.committed_txg + 1;
        let draft = (|| -> Result<_> {
            // Native expansion owns this reserved area only after its topology
            // is published. Refuse pre-existing boot-area contents at admission.
            for leaf in self.pool.leaves() {
                let mut offset = DATA_OFFSET - VDEV_BOOT_SIZE;
                while offset < DATA_OFFSET {
                    checkpoint(cx)?;
                    let count = (DATA_OFFSET - offset).min(MAX_REFLOW_CHUNK) as usize;
                    if leaf
                        .read_raw(cx, offset, count)?
                        .iter()
                        .any(|byte| *byte != 0)
                    {
                        return Err(unsupported(
                            "RAIDZ expansion scratch area contains existing boot data",
                        ));
                    }
                    offset += count as u64;
                }
            }
            let new_guid = self
                .storage_identity
                .member_guids
                .iter()
                .copied()
                .max()
                .unwrap_or(self.storage_identity.top_guid)
                .checked_add(0x307)
                .ok_or_else(|| corrupt("new RAIDZ child GUID overflow"))?;
            if new_guid == 0
                || new_guid == self.storage_identity.pool_guid
                || new_guid == self.storage_identity.top_guid
            {
                return Err(corrupt("new RAIDZ child GUID is not distinct"));
            }
            let Some(Value::Lists(children)) = top_tree.fields.get_mut("children") else {
                return Err(corrupt("RAIDZ expansion lost its native children"));
            };
            children.push(super::nv_list(vec![
                ("type", Value::String("file".into())),
                ("id", Value::Unsigned(geometry.old_width as u64)),
                ("guid", Value::Unsigned(new_guid)),
                (
                    "path",
                    Value::String(format!("/dev/ffs-raidz-{}", geometry.old_width)),
                ),
            ]));
            top_tree
                .fields
                .insert("raidz_expanding".into(), Value::Boolean(true));
            top_tree.fields.remove("raidz_expand_txgs");
            self.admit_new_raidz_labels(cx, &new_disk, new_guid, &top_tree, next_txg)?;
            let mut guids = self.storage_identity.member_guids.clone();
            guids.push(new_guid);
            let labels = self.raidz_expansion_labels(cx, &top_tree, next_txg, &guids)?;
            let mut leaves = self.pool.leaves().to_vec();
            leaves.push(new_disk);
            let pool = Pool::from_wide_leaves(leaves)?;
            let offsets = pool
                .leaves()
                .iter()
                .map(|leaf| label_offsets(leaf.length_bytes()).map_err(|error| parse_err(&error)))
                .collect::<Result<Vec<_>>>()?;
            Ok((pool, offsets, guids, new_guid, labels))
        })();
        let (new_pool, new_offsets, new_guids, new_guid, labels) = match draft {
            Ok(draft) => draft,
            Err(error) => return ZfsTxOutcome::NotCommitted(error),
        };
        let old_pool = std::mem::replace(&mut self.pool, new_pool);
        let old_offsets = std::mem::replace(&mut self.label_offsets_per_member, new_offsets);
        let old_identity = self.storage_identity.clone();
        let old_allocator = self.allocator.clone();
        self.storage_identity.member_guids = new_guids;
        self.storage_identity.guid_sum = old_identity.guid_sum.wrapping_add(new_guid);
        self.storage_identity.label_txg = next_txg;
        self.storage_identity.topology = ZfsTopologyKind::Raidz {
            parity: geometry.parity,
            width: geometry.new_width,
        };
        self.storage_identity.member_dev_inos.push(None);
        self.allocator.allocation_ceiling = Some(geometry.allocation_ceiling());
        let protected_pool = self.pool.clone();
        let mut protection = match protected_pool.defer_protection(cx) {
            Ok(protection) => protection,
            Err(error) => {
                self.pool = old_pool;
                self.label_offsets_per_member = old_offsets;
                self.storage_identity = old_identity;
                self.allocator = old_allocator;
                return ZfsTxOutcome::NotCommitted(error);
            }
        };
        let seed_index = geometry.members[geometry.old_width];
        if let Err(error) =
            self.seed_raidz_generation_label(cx, seed_index, next_txg, &labels[seed_index])
        {
            self.pool = old_pool;
            self.label_offsets_per_member = old_offsets;
            self.storage_identity = old_identity;
            self.allocator = old_allocator;
            return ZfsTxOutcome::NotCommitted(error);
        }
        let order = self.order;
        let outcome = self.execute_staged_txg_publication(
            cx,
            "zfs_pool_expand_raidz_bootstrap",
            Some(mos),
            &[],
            false,
            |mos, dirty, features, alloc, txg, staged| {
                features
                    .read_features
                    .entry(EXPANSION_FEATURE.into())
                    .or_insert(0);
                features.increment_read(EXPANSION_FEATURE, txg)?;
                alloc.raidz_expanding = true;
                alloc.raidz_reflow_cursor = 0;
                // Bootstrap COW still uses the old physical width. The active
                // topology and state0 reader use that same placement.
                update_mos_config_top_tree(cx, mos, dirty, alloc, order, txg, 0, top_tree, staged)?;
                Ok(((), txg))
            },
        );
        match outcome {
            ZfsTxOutcome::NotCommitted(error) => {
                self.pool = old_pool;
                self.label_offsets_per_member = old_offsets;
                self.storage_identity = old_identity;
                self.allocator = old_allocator;
                ZfsTxOutcome::NotCommitted(error)
            }
            ZfsTxOutcome::Uncertain {
                reason,
                target_txg,
                target_slot,
            } => ZfsTxOutcome::Uncertain {
                reason,
                target_txg,
                target_slot,
            },
            ZfsTxOutcome::Committed { token, .. } => {
                self.allocator.write_topology = AllocatorWriteTopology::Raidz {
                    parity: geometry.parity,
                    width: geometry.new_width,
                };
                self.allocator.write_member_guids.push(new_guid);
                self.allocator.allocation_ceiling = None;
                if !self
                    .read_features
                    .iter()
                    .any(|feature| feature == EXPANSION_FEATURE)
                {
                    self.read_features.push(EXPANSION_FEATURE.into());
                }
                if let Err(reason) = self.publish_raidz_generation_labels(cx, next_txg, &labels) {
                    self.poisoned_uncertain = true;
                    return ZfsTxOutcome::Uncertain {
                        reason,
                        target_txg: next_txg,
                        target_slot: self.committed_slot,
                    };
                }
                let row_bytes =
                    geometry.old_width as u64 * geometry.new_width as u64 * geometry.sector;
                let end = match self.raidz_highest_owned_end() {
                    Ok(end) => end,
                    Err(reason) => {
                        self.poisoned_uncertain = true;
                        return ZfsTxOutcome::Uncertain {
                            reason,
                            target_txg: next_txg,
                            target_slot: self.committed_slot,
                        };
                    }
                };
                geometry.prefix_end = (end + geometry.old_width as u64 * geometry.sector)
                    .div_ceil(row_bytes)
                    * row_bytes;
                for hold in &mut protection {
                    hold.complete();
                }
                self.acknowledge_committed_txg("zfs_pool_expand_raidz_bootstrap");
                ZfsTxOutcome::Committed {
                    value: geometry.report(0, 0, false, self.committed_txg),
                    token,
                }
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn complete_raidz_expansion(
        &mut self,
        cx: &Cx,
        mos: Objects,
        mut top_tree: NvList,
        geometry: &ReflowGeometry,
    ) -> ZfsTxOutcome<ZfsExpandRaidzReport> {
        let next_txg = self.committed_txg + 1;
        let draft = (|| -> Result<_> {
            let old_asize = top_tree
                .unsigned("asize")
                .ok_or_else(|| corrupt("RAIDZ asize is missing"))?;
            let metaslab_size = 1_u64 << self.allocator.metaslab_shift;
            let new_asize = (old_asize / geometry.old_width as u64)
                .checked_mul(geometry.new_width as u64)
                .ok_or_else(|| corrupt("expanded RAIDZ asize overflow"))?
                / metaslab_size
                * metaslab_size;
            if new_asize <= old_asize {
                return Err(unsupported(
                    "RAIDZ expansion does not add a complete metaslab",
                ));
            }
            for leaf in self.pool.leaves() {
                let data_end =
                    label_offsets(leaf.length_bytes()).map_err(|error| parse_err(&error))?[2];
                if new_asize / geometry.new_width as u64 > data_end.saturating_sub(DATA_OFFSET) {
                    return Err(corrupt("expanded RAIDZ asize exceeds a member data area"));
                }
            }
            top_tree.fields.remove("raidz_expanding");
            top_tree.fields.insert(
                "raidz_expand_txgs".into(),
                Value::UnsignedArray(vec![next_txg]),
            );
            top_tree
                .fields
                .insert("asize".into(), Value::Unsigned(new_asize));
            let labels = self.raidz_expansion_labels(
                cx,
                &top_tree,
                next_txg,
                &self.storage_identity.member_guids,
            )?;
            // Validate growth in memory before the first label write.
            let mut allocation = self.allocator.clone();
            allocation.grow_to_asize(new_asize)?;
            Ok((new_asize, labels))
        })();
        let (new_asize, labels) = match draft {
            Ok(draft) => draft,
            Err(error) => return ZfsTxOutcome::NotCommitted(error),
        };
        let protected_pool = self.pool.clone();
        let mut protection = match protected_pool.defer_protection(cx) {
            Ok(protection) => protection,
            Err(error) => return ZfsTxOutcome::NotCommitted(error),
        };
        let seed_index = geometry.members[geometry.old_width];
        if let Err(error) =
            self.seed_raidz_generation_label(cx, seed_index, next_txg, &labels[seed_index])
        {
            // The completion seed touches an admitted member. Its first label
            // may now be torn or name the prepared successor, so the current
            // owner must reconcile native copies before another mutation.
            // No successor uberblock has been attempted yet.
            self.poisoned_uncertain = true;
            return ZfsTxOutcome::NotCommitted(error);
        }
        let previous_reflow = self.current_uberblock.raidz_reflow_info;
        let previous_identity = self.storage_identity.clone();
        self.current_uberblock.raidz_reflow_info = 0;
        self.storage_identity.asize = new_asize;
        self.storage_identity.label_txg = next_txg;
        let order = self.order;
        let outcome = self.execute_staged_txg_publication(
            cx,
            "zfs_pool_expand_raidz_complete",
            Some(mos),
            &[],
            false,
            |mos, dirty, _features, alloc, txg, staged| {
                alloc.raidz_expanding = false;
                alloc.raidz_reflow_cursor = 0;
                alloc.allocation_ceiling = None;
                alloc.grow_to_asize(new_asize)?;
                update_mos_config_top_tree(cx, mos, dirty, alloc, order, txg, 0, top_tree, staged)?;
                Ok((geometry.report(geometry.prefix_end, 0, true, txg), txg))
            },
        );
        match outcome {
            ZfsTxOutcome::Committed { value, token } => {
                if let Err(reason) = self.publish_raidz_generation_labels(cx, next_txg, &labels) {
                    self.poisoned_uncertain = true;
                    return ZfsTxOutcome::Uncertain {
                        reason,
                        target_txg: next_txg,
                        target_slot: self.committed_slot,
                    };
                }
                for hold in &mut protection {
                    hold.complete();
                }
                self.acknowledge_committed_txg("zfs_pool_expand_raidz_complete");
                ZfsTxOutcome::Committed { value, token }
            }
            ZfsTxOutcome::NotCommitted(error) => {
                self.current_uberblock.raidz_reflow_info = previous_reflow;
                self.storage_identity = previous_identity;
                // The successor configuration seed is already durable on an
                // admitted member even though no successor uberblock was
                // attempted. Reconcile those native label generations before
                // this owner can perform another mutation.
                self.poisoned_uncertain = true;
                ZfsTxOutcome::NotCommitted(error)
            }
            ZfsTxOutcome::Uncertain {
                reason,
                target_txg,
                target_slot,
            } => {
                self.current_uberblock.raidz_reflow_info = previous_reflow;
                ZfsTxOutcome::Uncertain {
                    reason,
                    target_txg,
                    target_slot,
                }
            }
        }
    }

    /// Only blank configuration spans or verified copies of this exact pending
    /// child are disposable, and every uberblock ring must still be empty.
    /// A retry before publication has only a seeded configuration; any attempted
    /// uberblock publication requires recovery rather than another bootstrap.
    /// Read failures cannot establish that a proposed device is unowned.
    fn admit_new_raidz_labels(
        &self,
        cx: &Cx,
        new_disk: &Leaf,
        new_guid: u64,
        expected_tree: &NvList,
        next_txg: u64,
    ) -> Result<()> {
        for offset in label_offsets(new_disk.length_bytes()).map_err(|error| parse_err(&error))? {
            checkpoint(cx)?;
            let config_offset = offset + LABEL_CONFIG_OFFSET;
            let raw = new_disk.read_raw(cx, config_offset, LABEL_CONFIG_BYTES)?;
            let ring =
                new_disk.read_raw(cx, offset + UBERBLOCK_RING_OFFSET, UBERBLOCK_RING_BYTES)?;
            if ring.iter().any(|byte| *byte != 0) {
                return Err(unsupported(
                    "RAIDZ expansion new member has existing uberblock evidence; recover before reusing it",
                ));
            }
            if raw.iter().all(|byte| *byte == 0) {
                continue;
            }
            verify_label_checksum(&raw, config_offset).map_err(|error| parse_err(&error))?;
            let config =
                NvList::parse(&raw[..raw.len() - 40]).map_err(|error| parse_err(&error))?;
            if config.unsigned("pool_guid") != Some(self.storage_identity.pool_guid)
                || config.unsigned("guid") != Some(new_guid)
                || config.unsigned("top_guid") != Some(self.storage_identity.top_guid)
                || config.unsigned("version") != Some(self.storage_identity.version)
                || config.unsigned("state") != Some(1)
                || config.unsigned("multihost").unwrap_or(0) != 0
                || config
                    .unsigned("txg")
                    .is_none_or(|txg| txg == 0 || txg > next_txg)
                || config.list("vdev_tree") != Some(expected_tree)
            {
                return Err(unsupported(
                    "RAIDZ expansion disk is not the verified pending new member",
                ));
            }
        }
        Ok(())
    }

    fn raidz_expansion_labels(
        &self,
        cx: &Cx,
        top_tree: &NvList,
        txg: u64,
        guids: &[u64],
    ) -> Result<Vec<Vec<u8>>> {
        let template = self.pool.leaves()[0].label(cx, 0)?.config;
        guids
            .iter()
            .map(|guid| {
                let mut label = template.clone();
                label.fields.insert("txg".into(), Value::Unsigned(txg));
                label.fields.insert("guid".into(), Value::Unsigned(*guid));
                label
                    .fields
                    .insert("vdev_tree".into(), Value::List(top_tree.clone()));
                let mut features = label
                    .list("features_for_read")
                    .cloned()
                    .unwrap_or_else(|| super::nv_list(Vec::new()));
                features
                    .fields
                    .insert(EXPANSION_FEATURE.into(), Value::Boolean(true));
                label
                    .fields
                    .insert("features_for_read".into(), Value::List(features));
                let packed = label.encode_xdr().map_err(|error| parse_err(&error))?;
                if packed.len() > LABEL_CONFIG_BYTES - 40 {
                    return Err(corrupt("expanded RAIDZ label exceeds native label space"));
                }
                Ok(packed)
            })
            .collect()
    }

    fn seed_raidz_generation_label(
        &mut self,
        cx: &Cx,
        member: usize,
        txg: u64,
        packed: &[u8],
    ) -> Result<()> {
        let pool = self.pool.clone();
        let mut protection = pool.defer_protection(cx)?;
        let offset = self.label_offsets_per_member[member][0] + LABEL_CONFIG_OFFSET;
        let mut raw = vec![0_u8; LABEL_CONFIG_BYTES];
        raw[..packed.len()].copy_from_slice(packed);
        stamp_label_checksum(&mut raw, offset, self.order).map_err(|error| parse_err(&error))?;
        self.emit_event(
            "zfs_pool_expand_raidz_seed",
            ZfsPersistenceStage::LabelConfigWrite {
                member_index: member,
                label: 0,
            },
            txg,
            member,
            offset,
            raw.len(),
        )?;
        pool.leaves()[member].write_raw(cx, offset, &raw)?;
        self.emit_event(
            "zfs_pool_expand_raidz_seed",
            ZfsPersistenceStage::LabelConfigBarrier {
                member_index: member,
                wave: 1,
            },
            txg,
            member,
            0,
            0,
        )?;
        pool.leaves()[member].sync_raw(cx)?;
        for hold in &mut protection {
            hold.complete();
        }
        Ok(())
    }

    fn publish_raidz_generation_labels(
        &mut self,
        cx: &Cx,
        txg: u64,
        labels: &[Vec<u8>],
    ) -> Result<()> {
        let pool = self.pool.clone();
        let refreshed = Pool::from_wide_leaves(pool.leaves().to_vec())?;
        let mut protection = pool.defer_protection(cx)?;
        self.publish_labels_2wave(cx, "zfs_pool_expand_raidz_labels", txg, labels)?;
        for hold in &mut protection {
            hold.complete();
        }
        self.pool = refreshed;
        Ok(())
    }

    fn copy_raidz_reflow_chunk(
        &mut self,
        cx: &Cx,
        geometry: &ReflowGeometry,
        start: u64,
        end: u64,
        preparing_scratch: bool,
    ) -> Result<()> {
        let pool = self.pool.clone();
        let mut protection = pool.defer_protection(cx)?;
        let first_sector = start / geometry.sector;
        let end_sector = end / geometry.sector;
        let mut source = Vec::new();
        if preparing_scratch {
            // Read all source bytes for this chunk before any scratch write.
            // Every logical sector is copied, including parity, skip sectors,
            // snapshot-only data, deadlists, space maps and the MOS root.
            for child in 0..geometry.old_width {
                let (first, last) =
                    column_rows(first_sector, end_sector, child, geometry.old_width);
                let bytes = if first == last {
                    Vec::new()
                } else {
                    pool.leaves()[geometry.members[child]].read_raw(
                        cx,
                        DATA_OFFSET + first * geometry.sector,
                        ((last - first) * geometry.sector) as usize,
                    )?
                };
                source.push((first, bytes));
            }
        }
        let mut writes = Vec::with_capacity(geometry.new_width);
        for child in 0..geometry.new_width {
            let (first, last) = column_rows(first_sector, end_sector, child, geometry.new_width);
            if first == last {
                continue;
            }
            let count = ((last - first) * geometry.sector) as usize;
            let member = geometry.members[child];
            let (destination, bytes) = if preparing_scratch {
                let mut bytes = vec![0_u8; count];
                for row in first..last {
                    let logical = row * geometry.new_width as u64 + child as u64;
                    let source_child = (logical % geometry.old_width as u64) as usize;
                    let source_row = logical / geometry.old_width as u64;
                    let (base, source_bytes) = &source[source_child];
                    let source_start = ((source_row - *base) * geometry.sector) as usize;
                    let destination_start = ((row - first) * geometry.sector) as usize;
                    let sector = geometry.sector as usize;
                    bytes[destination_start..destination_start + sector]
                        .copy_from_slice(&source_bytes[source_start..source_start + sector]);
                }
                (
                    DATA_OFFSET - VDEV_BOOT_SIZE + first * geometry.sector,
                    bytes,
                )
            } else {
                let bytes = pool.leaves()[member].read_raw(
                    cx,
                    DATA_OFFSET - VDEV_BOOT_SIZE + first * geometry.sector,
                    count,
                )?;
                (DATA_OFFSET + first * geometry.sector, bytes)
            };
            writes.push((member, destination, bytes));
        }
        let operation = if preparing_scratch {
            "zfs_pool_expand_raidz_scratch"
        } else {
            "zfs_pool_expand_raidz_copy"
        };
        for (member, destination, bytes) in &writes {
            checkpoint(cx)?;
            self.emit_event(
                operation,
                ZfsPersistenceStage::ReflowChunkWrite {
                    member_index: *member,
                },
                self.committed_txg,
                *member,
                *destination,
                bytes.len(),
            )?;
            pool.leaves()[*member].write_raw(cx, *destination, bytes)?;
        }
        for &member in &geometry.members {
            self.emit_event(
                operation,
                ZfsPersistenceStage::ReflowChunkBarrier {
                    member_index: member,
                },
                self.committed_txg,
                member,
                0,
                0,
            )?;
            pool.leaves()[member].sync_raw(cx)?;
        }
        for hold in &mut protection {
            hold.complete();
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn publish_raidz_reflow_authority(
        &mut self,
        cx: &Cx,
        state: RaidzReflowScratchState,
        offset: u64,
    ) -> ZfsTxOutcome<()> {
        let mut next = self.current_uberblock.clone();
        let Some(timestamp) = next.timestamp.checked_add(1) else {
            return ZfsTxOutcome::NotCommitted(corrupt("ZFS uberblock timestamp overflow"));
        };
        next.timestamp = timestamp;
        next.raidz_reflow_info = match (RaidzReflowInfo { offset, state }).encode() {
            Ok(raw) => raw,
            Err(error) => return ZfsTxOutcome::NotCommitted(parse_err(&error)),
        };
        let pool = self.pool.clone();
        let refreshed = match Pool::from_wide_leaves(pool.leaves().to_vec()) {
            Ok(pool) => pool,
            Err(error) => return ZfsTxOutcome::NotCommitted(error),
        };
        let mut protection = match pool.defer_protection(cx) {
            Ok(protection) => protection,
            Err(error) => return ZfsTxOutcome::NotCommitted(error),
        };
        let operation = if state == RaidzReflowScratchState::Valid {
            "zfs_pool_expand_raidz_scratch_authority"
        } else {
            "zfs_pool_expand_raidz_data_authority"
        };
        let software_version = self
            .current_software_version
            .unwrap_or(self.storage_identity.version);
        let mut started = false;
        for (wave, labels) in [(1_u8, [0_usize, 1]), (2_u8, [2_usize, 3])] {
            for member in 0..pool.leaves().len() {
                for label in labels {
                    if let Err(error) = checkpoint(cx) {
                        return self.raidz_authority_error(error, started);
                    }
                    let ub_offset = self.label_offsets_per_member[member][label]
                        + UBERBLOCK_RING_OFFSET
                        + (self.committed_slot * self.slot_bytes) as u64;
                    let bytes = match next.encode_with_meta(
                        self.slot_bytes,
                        ub_offset,
                        software_version,
                        0,
                        0,
                    ) {
                        Ok(bytes) => bytes,
                        Err(error) => {
                            return self.raidz_authority_error(parse_err(&error), started);
                        }
                    };
                    if let Err(error) = self.emit_event(
                        operation,
                        ZfsPersistenceStage::UberblockWrite {
                            member_index: member,
                            label,
                            slot: self.committed_slot,
                        },
                        self.committed_txg,
                        member,
                        ub_offset,
                        bytes.len(),
                    ) {
                        return self.raidz_authority_error(error, started);
                    }
                    started = true;
                    if let Err(error) = pool.leaves()[member].write_raw(cx, ub_offset, &bytes) {
                        return self.raidz_authority_error(error, true);
                    }
                }
            }
            for member in 0..pool.leaves().len() {
                if let Err(error) = self
                    .emit_event(
                        operation,
                        ZfsPersistenceStage::UberblockBarrier {
                            member_index: member,
                            wave,
                        },
                        self.committed_txg,
                        member,
                        0,
                        0,
                    )
                    .and_then(|()| pool.leaves()[member].sync_raw(cx))
                {
                    return self.raidz_authority_error(error, true);
                }
            }
        }
        for hold in &mut protection {
            hold.complete();
        }
        self.current_uberblock = next;
        self.pool = refreshed;
        let token = self.raidz_reflow_token(operation, offset);
        let _ = self.emit_event(
            operation,
            ZfsPersistenceStage::BeforeAcknowledge,
            self.committed_txg,
            0,
            0,
            0,
        );
        let _ = self.emit_event(
            operation,
            ZfsPersistenceStage::AckPublished,
            self.committed_txg,
            0,
            0,
            0,
        );
        ZfsTxOutcome::Committed { value: (), token }
    }

    fn raidz_authority_error(&mut self, reason: FfsError, started: bool) -> ZfsTxOutcome<()> {
        if started {
            self.poisoned_uncertain = true;
            ZfsTxOutcome::Uncertain {
                reason,
                target_txg: self.committed_txg,
                target_slot: self.committed_slot,
            }
        } else {
            ZfsTxOutcome::NotCommitted(reason)
        }
    }

    fn raidz_reflow_token(&mut self, operation: &str, cursor: u64) -> ZfsDurableToken {
        self.generation += 1;
        let root_bp = self.current_uberblock.root.encode(self.order);
        let mut digest = blake3::Hasher::new();
        digest.update(&self.storage_identity.pool_guid.to_le_bytes());
        digest.update(&self.storage_identity.guid_sum.to_le_bytes());
        digest.update(&self.committed_txg.to_le_bytes());
        digest.update(&self.current_uberblock.timestamp.to_le_bytes());
        digest.update(&self.current_uberblock.raidz_reflow_info.to_le_bytes());
        digest.update(&root_bp);
        digest.update(operation.as_bytes());
        digest.update(&cursor.to_le_bytes());
        ZfsDurableToken {
            storage: self.storage_identity.clone(),
            committed_txg: self.committed_txg,
            published_slot: self.committed_slot,
            root_bp,
            generation: self.generation,
            operation_digest: *digest.finalize().as_bytes(),
        }
    }
}

/// Half-open child-row interval occupied by consecutive logical sectors.
fn column_rows(first: u64, end: u64, child: usize, width: usize) -> (u64, u64) {
    (
        first.saturating_sub(child as u64).div_ceil(width as u64),
        end.saturating_sub(child as u64).div_ceil(width as u64),
    )
}

#[cfg(test)]
mod tests {
    use super::column_rows;

    #[test]
    fn column_intervals_partition_every_chunk_sector_once() {
        for width in 2..=16 {
            for first in 0..65_u64 {
                for count in 1..=35_u64 {
                    let mut sectors = Vec::new();
                    for child in 0..width {
                        let (start, end) = column_rows(first, first + count, child, width);
                        for row in start..end {
                            sectors.push(row * width as u64 + child as u64);
                        }
                    }
                    sectors.sort_unstable();
                    assert_eq!(sectors, (first..first + count).collect::<Vec<_>>());
                }
            }
        }
    }
}
