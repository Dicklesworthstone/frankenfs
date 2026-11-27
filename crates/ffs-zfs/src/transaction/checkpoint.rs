//! Pool checkpoint create, discard, and crash-safe monotonic rewind
//! (`com.delphix:zpool_checkpoint`, OpenZFS `zfs-2.4.0`).
//!
//! - `checkpoint_create`: snapshots the current committed `Uberblock` into MOS
//!   `"pool_checkpoint"`, activates `com.delphix:zpool_checkpoint`, stamps
//!   `ub_checkpoint_txg = checkpoint_txg` on subsequent uberblocks, and defers
//!   freeing any block born `<= checkpoint_txg` into a MOS checkpoint space
//!   record (`"vdev_checkpoint_sm"`) so pre-checkpoint state remains 100%
//!   unmodified.
//! - `checkpoint_discard`: replays all deferred pre-checkpoint frees back into
//!   the metaslab space maps, removes `"pool_checkpoint"` / `"vdev_checkpoint_sm"`,
//!   clears `ub_checkpoint_txg = 0`, and decrements `com.delphix:zpool_checkpoint`.
//! - `import_rewind_to_checkpoint`: reads and verifies the checkpointed
//!   `Uberblock` + its MOS root (including full scrub), then publishes the
//!   checkpointed MOS root at `max_ring_txg + 1` via 2-wave 4-label Uberblock
//!   publication (`CheckpointUberblockWrite` + `CheckpointUberblockBarrier`) so
//!   rewind is strictly monotonic in the ring and crash-safe at every cut!

use std::collections::{BTreeMap, BTreeSet};

use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_ondisk::zfs::{
    Endian, UBERBLOCK_RING_BYTES, UBERBLOCK_RING_OFFSET, Uberblock, label_offsets,
};
use ffs_ondisk::zfs_zap::Entry as RawZapEntry;
use serde::Serialize;

use super::dmu_cow::{
    DnodeCowSpec, PoolSpaceAllocator, StagedBlockWrite, WriteBucket, cow_update_dnode,
    encode_zap_blocks_for_dnode, put_dnode_in_table,
};
use super::{
    ZfsPersistenceStage, ZfsTransactionEngine, ZfsTxOutcome, ZfsWriteOptions, checkpoint, corrupt,
    parse_err,
};
use crate::reader::dmu::Objects;
use crate::reader::dmu::scrub::ScrubLimits;
use crate::{Leaf, Pool};

const DMU_POOL_CHECKPOINT_KEY: &[u8] = b"pool_checkpoint";
const DMU_POOL_CHECKPOINT_DEFERRED_KEY: &[u8] = b"vdev_checkpoint_sm";
const ZPOOL_CHECKPOINT_FEATURE: &str = "com.delphix:zpool_checkpoint";

/// Active pool checkpoint metadata reported to callers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZfsCheckpointInfo {
    pub checkpoint_txg: u64,
    pub timestamp: u64,
    pub deferred_free_bytes: u64,
    pub active: bool,
}

/// Summary returned after rewinding a pool to its verified checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZfsRewindReport {
    pub rewound_to_txg: u64,
    pub published_txg: u64,
    pub published_slot: usize,
    pub pool_guid: u64,
}

fn pack_uberblock_words(ub: &Uberblock) -> Result<Vec<u64>> {
    let raw = ub.encode(1024, 0).map_err(|e| parse_err(&e))?;
    let mut words = Vec::with_capacity(128);
    for chunk in raw.as_chunks::<8>().0 {
        words.push(ub.order.u64(chunk, 0).map_err(|e| parse_err(&e))?);
    }
    Ok(words)
}

fn unpack_uberblock_words(words: &[u64], order: Endian) -> Result<Uberblock> {
    if words.len() != 128 {
        return Err(corrupt("MOS pool_checkpoint entry is not 128 u64 words"));
    }
    let mut raw = vec![0_u8; 1024];
    for (idx, &w) in words.iter().enumerate() {
        raw[idx * 8..idx * 8 + 8].copy_from_slice(&order.encode(w));
    }
    Uberblock::parse(&raw, 0).map_err(|e| parse_err(&e))
}

fn encode_deferred_frees(entries: &[(u32, std::ops::Range<u64>)]) -> Vec<u64> {
    let mut words = Vec::with_capacity(entries.len() * 3);
    for (vdev, range) in entries {
        words.push(u64::from(*vdev));
        words.push(range.start);
        words.push(range.end);
    }
    words
}

fn decode_deferred_frees(words: &[u64]) -> Result<Vec<(u32, std::ops::Range<u64>)>> {
    if !words.len().is_multiple_of(3) {
        return Err(corrupt("vdev_checkpoint_sm deferred-free list misaligned"));
    }
    let mut out = Vec::with_capacity(words.len() / 3);
    for chunk in words.as_chunks::<3>().0 {
        let vdev = u32::try_from(chunk[0]).map_err(|_| corrupt("deferred free vdev overflow"))?;
        if chunk[2] < chunk[1] {
            return Err(corrupt("deferred free range inverted"));
        }
        out.push((vdev, chunk[1]..chunk[2]));
    }
    Ok(out)
}

pub(super) fn load_deferred_frees_from_mos(
    cx: &Cx,
    mos: &mut Objects,
) -> Result<Vec<(u32, std::ops::Range<u64>)>> {
    let dir = mos.zap_values(cx, 1)?;
    let Some(def_entry) = dir
        .iter()
        .find(|e| e.name == DMU_POOL_CHECKPOINT_DEFERRED_KEY)
    else {
        return Ok(Vec::new());
    };
    decode_deferred_frees(&def_entry.values)
}

pub(super) fn canonical_deferred_frees(
    entries: &[(u32, std::ops::Range<u64>)],
) -> Vec<(u32, std::ops::Range<u64>)> {
    entries
        .iter()
        .map(|(vdev, range)| (*vdev, range.start, range.end))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|(vdev, start, end)| (vdev, start..end))
        .collect()
}

pub(super) fn set_deferred_free_entry(
    dir: &mut Vec<RawZapEntry>,
    entries: &[(u32, std::ops::Range<u64>)],
) {
    dir.retain(|e| e.name != DMU_POOL_CHECKPOINT_DEFERRED_KEY);
    let words = encode_deferred_frees(entries);
    if !words.is_empty() {
        dir.push(RawZapEntry {
            name: DMU_POOL_CHECKPOINT_DEFERRED_KEY.to_vec(),
            integer_bytes: 8,
            values: words,
            collision: 0,
        });
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn stage_mos_dir_entries(
    cx: &Cx,
    mos: &mut Objects,
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    alloc: &mut PoolSpaceAllocator,
    order: Endian,
    new_txg: u64,
    entries: &[RawZapEntry],
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<()> {
    let (dir_dn, dir_ceil) = mos.object_with_ceiling(cx, 1)?;
    let (bsize, blocks) =
        encode_zap_blocks_for_dnode(cx, mos, Some((&dir_dn, dir_ceil)), entries, order, 512)?;
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

impl ZfsTransactionEngine {
    /// Inspect whether a pool checkpoint is currently active on this pool.
    pub fn checkpoint_status(&self, cx: &Cx) -> Result<Option<ZfsCheckpointInfo>> {
        let mut mos = self.open_read_objects(cx)?;
        let dir = mos.zap_values(cx, 1)?;
        let Some(entry) = dir.iter().find(|e| e.name == DMU_POOL_CHECKPOINT_KEY) else {
            return Ok(None);
        };
        let ub = unpack_uberblock_words(&entry.values, self.order)?;
        let mut unique: BTreeSet<(u32, u64, u64)> = BTreeSet::new();
        if let Some(def_entry) = dir
            .iter()
            .find(|e| e.name == DMU_POOL_CHECKPOINT_DEFERRED_KEY)
        {
            for (vdev, range) in decode_deferred_frees(&def_entry.values)? {
                unique.insert((vdev, range.start, range.end));
            }
        }
        for (vdev, range) in &self.allocator.checkpoint_deferred_frees {
            unique.insert((*vdev, range.start, range.end));
        }
        let deferred_bytes: u64 = unique.iter().fold(0_u64, |acc, (_, start, end)| {
            acc.saturating_add(end - start)
        });
        Ok(Some(ZfsCheckpointInfo {
            checkpoint_txg: ub.txg,
            timestamp: ub.timestamp,
            deferred_free_bytes: deferred_bytes,
            active: true,
        }))
    }

    /// Create a pool-wide checkpoint capturing the current committed MOS root
    /// and activating `com.delphix:zpool_checkpoint` with pre-checkpoint free deferral.
    pub fn checkpoint_create(&mut self, cx: &Cx) -> ZfsTxOutcome<ZfsCheckpointInfo> {
        if self.current_uberblock.checkpoint_txg != 0 {
            return ZfsTxOutcome::NotCommitted(FfsError::Format(
                "pool already has an active checkpoint; discard it before creating another".into(),
            ));
        }
        let saved_ub = self.current_uberblock.clone();
        let checkpoint_txg = saved_ub.txg;
        let checkpoint_ts = saved_ub.timestamp;
        let ub_words = match pack_uberblock_words(&saved_ub) {
            Ok(w) => w,
            Err(err) => return ZfsTxOutcome::NotCommitted(err),
        };
        // Set `checkpoint_txg` on the live uberblock & allocator BEFORE commit so the
        // newly published uberblock carries `ub_checkpoint_txg = checkpoint_txg` AND
        // pre-checkpoint MOS blocks retired during this very TXG are deferred!
        let prev_ub_ckpt = self.current_uberblock.checkpoint_txg;
        let prev_alloc_ckpt = self.allocator.checkpoint_txg;
        self.current_uberblock.checkpoint_txg = checkpoint_txg;
        self.allocator.checkpoint_txg = checkpoint_txg;

        let mut outcome = self.execute_staged_txg_typed(
            cx,
            "zfs_checkpoint_create",
            |mos, _mos_dirty, features, alloc, _new_txg, _staged| {
                let mut dir = mos.zap_values(cx, 1)?;
                dir.retain(|e| {
                    e.name != DMU_POOL_CHECKPOINT_KEY && e.name != DMU_POOL_CHECKPOINT_DEFERRED_KEY
                });
                dir.push(RawZapEntry {
                    name: DMU_POOL_CHECKPOINT_KEY.to_vec(),
                    integer_bytes: 8,
                    values: ub_words,
                    collision: 0,
                });
                let deferred_words = encode_deferred_frees(&alloc.checkpoint_deferred_frees);
                if !deferred_words.is_empty() {
                    dir.push(RawZapEntry {
                        name: DMU_POOL_CHECKPOINT_DEFERRED_KEY.to_vec(),
                        integer_bytes: 8,
                        values: deferred_words,
                        collision: 0,
                    });
                }
                features
                    .write_features
                    .insert(ZPOOL_CHECKPOINT_FEATURE.to_owned(), 1);
                features.write_dirty = true;
                alloc.pending_mos_directory = Some(dir);
                let info = ZfsCheckpointInfo {
                    checkpoint_txg,
                    timestamp: checkpoint_ts,
                    deferred_free_bytes: alloc
                        .checkpoint_deferred_frees
                        .iter()
                        .map(|(_, r)| r.end - r.start)
                        .sum(),
                    active: true,
                };
                Ok((info, checkpoint_txg))
            },
        );
        if let ZfsTxOutcome::Committed { value, .. } = &mut outcome {
            value.deferred_free_bytes = self
                .allocator
                .checkpoint_deferred_frees
                .iter()
                .fold(0_u64, |total, (_, range)| {
                    total.saturating_add(range.end - range.start)
                });
        } else {
            self.current_uberblock.checkpoint_txg = prev_ub_ckpt;
            self.allocator.checkpoint_txg = prev_alloc_ckpt;
        }
        outcome
    }

    /// Discard an active pool checkpoint, replaying all deferred pre-checkpoint
    /// frees back into metaslab space maps and clearing `ub_checkpoint_txg`.
    pub fn checkpoint_discard(&mut self, cx: &Cx) -> ZfsTxOutcome<ZfsCheckpointInfo> {
        let ckpt_txg = self.current_uberblock.checkpoint_txg;
        if ckpt_txg == 0 {
            return ZfsTxOutcome::NotCommitted(FfsError::Format(
                "pool has no active checkpoint to discard".into(),
            ));
        }
        let prev_ub_ckpt = self.current_uberblock.checkpoint_txg;
        let prev_alloc_ckpt = self.allocator.checkpoint_txg;
        self.current_uberblock.checkpoint_txg = 0;

        let outcome = self.execute_staged_txg_typed(
            cx,
            "zfs_checkpoint_discard",
            |mos, _mos_dirty, features, alloc, _new_txg, _staged| {
                let mut dir = mos.zap_values(cx, 1)?;
                let mut unique: BTreeSet<(u32, u64, u64)> = BTreeSet::new();
                if let Some(def_entry) = dir
                    .iter()
                    .find(|e| e.name == DMU_POOL_CHECKPOINT_DEFERRED_KEY)
                {
                    for (vdev, range) in decode_deferred_frees(&def_entry.values)? {
                        unique.insert((vdev, range.start, range.end));
                    }
                }
                let in_mem = std::mem::take(&mut alloc.checkpoint_deferred_frees);
                for (vdev, range) in in_mem {
                    unique.insert((vdev, range.start, range.end));
                }
                let mut deferred_total = 0_u64;
                for (vdev, start, end) in unique {
                    deferred_total = deferred_total.saturating_add(end - start);
                    alloc.release_deferred_free(vdev, start..end)?;
                }
                alloc.checkpoint_txg = 0;
                dir.retain(|e| {
                    e.name != DMU_POOL_CHECKPOINT_KEY && e.name != DMU_POOL_CHECKPOINT_DEFERRED_KEY
                });
                features
                    .write_features
                    .insert(ZPOOL_CHECKPOINT_FEATURE.to_owned(), 0);
                features.write_dirty = true;
                alloc.pending_mos_directory = Some(dir);
                let info = ZfsCheckpointInfo {
                    checkpoint_txg: ckpt_txg,
                    timestamp: 0,
                    deferred_free_bytes: deferred_total,
                    active: false,
                };
                Ok((info, ckpt_txg))
            },
        );
        if !outcome.is_committed() {
            self.current_uberblock.checkpoint_txg = prev_ub_ckpt;
            self.allocator.checkpoint_txg = prev_alloc_ckpt;
        }
        outcome
    }

    /// Rewind an exported pool to its verified active checkpoint, publishing
    /// the checkpointed MOS root atomically at `max_ring_txg + 1` across all
    /// 4 labels on every member via 2-wave Uberblock barriers.
    #[allow(clippy::too_many_lines)]
    pub fn import_rewind_to_checkpoint(
        cx: &Cx,
        leaves: Vec<Leaf>,
        options: ZfsWriteOptions,
    ) -> Result<ZfsTxOutcome<ZfsRewindReport>> {
        checkpoint(cx)?;
        if !options.offline_image || !options.allow_write {
            return Err(FfsError::PermissionDenied);
        }
        let mut engine =
            Self::from_leaves_with_dev_inos(cx, leaves.clone(), vec![None; leaves.len()], options)?;
        let mut mos = engine.open_read_objects(cx)?;
        let dir = mos.zap_values(cx, 1)?;
        let Some(entry) = dir.iter().find(|e| e.name == DMU_POOL_CHECKPOINT_KEY) else {
            return Err(FfsError::Format(
                "pool has no active checkpoint to rewind to".into(),
            ));
        };
        let ckpt_ub = unpack_uberblock_words(&entry.values, engine.order)?;
        if ckpt_ub.guid_sum != engine.storage_identity.guid_sum {
            return Err(corrupt(
                "checkpoint uberblock guid_sum disagrees with current pool topology",
            ));
        }

        // Verify the checkpointed MOS root block is 100% readable & clean BEFORE publishing!
        // Use `mos.read_verified_physical_block` so rewind works on Leaf, Mirror, RAIDZ, dRAID, and MultiVdev!
        let pool = Pool::from_wide_leaves(leaves)?;
        let first_lbl = pool.leaves()[0].label(cx, options.label)?;
        let slot_bytes = first_lbl.slot_bytes;
        let slots_per_label = UBERBLOCK_RING_BYTES / slot_bytes;
        let (_, _, active_root) = pool.import_active(cx, Some(options.pool_guid))?;
        let ckpt_phys = mos.read_verified_physical_block(cx, &ckpt_ub.root)?;
        let ckpt_data = ckpt_ub.root.decode(&ckpt_phys).map_err(|e| parse_err(&e))?;
        let mut verify_root = active_root;
        verify_root.uberblock = ckpt_ub.clone();
        verify_root.data = ckpt_data;
        let ckpt_mos = Objects::from_root(cx, pool, verify_root)?;
        let scrub = ckpt_mos.scrub(cx, ScrubLimits::default())?;
        if !scrub.is_clean() {
            return Err(corrupt(
                "refusing rewind: checkpointed MOS root failed integrity scrub",
            ));
        }

        // Publish rewound root monotonically at `max_ring_txg + 1` with `checkpoint_txg = 0`!
        let new_txg = engine
            .committed_txg
            .checked_add(1)
            .ok_or_else(|| corrupt("rewind TXG overflow"))?;
        let target_slot = (new_txg as usize) % slots_per_label;
        let rewound_ub = Uberblock {
            order: engine.order,
            version: ckpt_ub.version,
            txg: new_txg,
            guid_sum: ckpt_ub.guid_sum,
            timestamp: engine.current_uberblock.timestamp.saturating_add(1),
            root: ckpt_ub.root.clone(),
            checkpoint_txg: 0,
            raidz_reflow_info: 0,
        };
        let sw_version = engine.current_software_version.unwrap_or(5000);
        let member_count = engine.pool.leaves().len();
        let mut first_written = false;

        for (wave, labels) in [(1_u8, [0_usize, 1]), (2_u8, [2_usize, 3])] {
            for m_idx in 0..member_count {
                let offsets = label_offsets(engine.pool.leaves()[m_idx].length_bytes())
                    .map_err(|e| parse_err(&e))?;
                for l_idx in labels {
                    let ub_off =
                        offsets[l_idx] + UBERBLOCK_RING_OFFSET + (target_slot * slot_bytes) as u64;
                    let encoded = rewound_ub
                        .encode_with_meta(slot_bytes, ub_off, sw_version, 0, 0)
                        .map_err(|e| parse_err(&e))?;
                    if let Err(err) = engine.emit_event(
                        "zfs_checkpoint_rewind",
                        ZfsPersistenceStage::CheckpointUberblockWrite {
                            member_index: m_idx,
                            label: l_idx,
                            slot: target_slot,
                        },
                        new_txg,
                        m_idx,
                        ub_off,
                        encoded.len(),
                    ) {
                        return Ok(if first_written {
                            ZfsTxOutcome::Uncertain {
                                reason: err,
                                target_txg: new_txg,
                                target_slot,
                            }
                        } else {
                            ZfsTxOutcome::NotCommitted(err)
                        });
                    }
                    first_written = true;
                    if let Err(err) = engine.pool.leaves()[m_idx].write_raw(cx, ub_off, &encoded) {
                        return Ok(ZfsTxOutcome::Uncertain {
                            reason: err,
                            target_txg: new_txg,
                            target_slot,
                        });
                    }
                }
            }
            for m_idx in 0..member_count {
                if let Err(err) = engine.emit_event(
                    "zfs_checkpoint_rewind",
                    ZfsPersistenceStage::CheckpointUberblockBarrier {
                        member_index: m_idx,
                        wave,
                    },
                    new_txg,
                    m_idx,
                    0,
                    0,
                ) {
                    return Ok(ZfsTxOutcome::Uncertain {
                        reason: err,
                        target_txg: new_txg,
                        target_slot,
                    });
                }
                if let Err(err) = engine.pool.leaves()[m_idx].sync_raw(cx) {
                    return Ok(ZfsTxOutcome::Uncertain {
                        reason: err,
                        target_txg: new_txg,
                        target_slot,
                    });
                }
            }
        }

        let root_bp_bytes = rewound_ub.root.encode(engine.order);
        let mut hasher = blake3::Hasher::new();
        hasher.update(&engine.storage_identity.pool_guid.to_le_bytes());
        hasher.update(&new_txg.to_le_bytes());
        hasher.update(&root_bp_bytes);
        let token = super::ZfsDurableToken {
            storage: engine.storage_identity.clone(),
            committed_txg: new_txg,
            published_slot: target_slot,
            root_bp: root_bp_bytes,
            generation: engine.generation + 1,
            operation_digest: *hasher.finalize().as_bytes(),
        };
        Ok(ZfsTxOutcome::Committed {
            value: ZfsRewindReport {
                rewound_to_txg: ckpt_ub.txg,
                published_txg: new_txg,
                published_slot: target_slot,
                pool_guid: engine.storage_identity.pool_guid,
            },
            token,
        })
    }
}
