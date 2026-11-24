//! ZFS native `DMU_BACKUP_STREAM` sender for ZPL filesystems and ZVOL volumes.
//!
//! Supports full, incremental (`-i` from snapshot or bookmark), multi-snapshot
//! intermediary (`-I`), compressed (`-c`), embedded (`-e`), large-block (`-L`),
//! property-preserving (`-p`), keyless raw encrypted (`-w`), and token-resumed
//! (`-t`) streams with strict ascending `(object, offset)` ordering and rolling
//! Fletcher4 checksums.

use crate::reader::dmu::Objects;
use crate::reader::dmu::zpl::snapshots::SnapshotRoot;
use crate::transaction::{dmu_ot_is_byte_array, dmu_ot_is_metadata, list_bookmarks_in_mos};
use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_ondisk::zfs::crypto::{bp_crypt_iv, bp_crypt_mac, bp_crypt_salt, extract_raw_dnode_bonus};
use ffs_ondisk::zfs::nvlist::{NvList, Value};
use ffs_ondisk::zfs::send_stream::{
    DMU_BACKUP_FEATURE_COMPRESSED, DMU_BACKUP_FEATURE_EMBED_DATA, DMU_BACKUP_FEATURE_LARGE_BLOCKS,
    DMU_BACKUP_FEATURE_LARGE_DNODE, DMU_BACKUP_FEATURE_LZ4, DMU_BACKUP_FEATURE_RAW,
    DMU_BACKUP_FEATURE_RESUMING, DMU_BACKUP_FEATURE_SA_SPILL, DMU_BACKUP_FEATURE_ZSTD,
    DMU_BACKUP_MAGIC, DMU_OST_NONE, DMU_OST_ZFS, DMU_OST_ZVOL, DRR_FLAG_FREERECORDS,
    DRR_FLAG_SPILL_BLOCK, DRR_OBJECT_SPILL, DRR_RAW_BYTESWAP, DrrBegin, DrrEnd, DrrFree,
    DrrFreeObjects, DrrObject, DrrObjectRange, DrrRecord, DrrSpill, DrrWrite, DrrWriteEmbedded,
    Fletcher4Stream, ReceiveResumeToken, SendFeatureFlags, StreamCryptoKeydata, StreamHeaderType,
};
use ffs_ondisk::zfs::{BlockPointer, Endian};
use ffs_ondisk::zfs_dmu::{DMU_OT_DNODE, DNODE_BLOCK_BYTES, DNODE_BYTES, Dnode, dnode_at};
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::Write;

const MAX_SEND_RECORDS: u64 = 10_000_000;
const MAX_SEND_TREE_DEPTH: u8 = 8;
const LEGACY_MAX_BLOCK_BYTES: u64 = 128 * 1024;

/// Incremental send base source (`-i` / `-I`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZfsSendFrom {
    /// Named ancestor snapshot on the same dataset (`@snap`).
    Snapshot(Vec<u8>),
    /// Named bookmark on the same dataset (`#bookmark`).
    Bookmark(Vec<u8>),
}

/// Request parameters for native ZFS stream generation (`ffs-zfs send`).
#[derive(Debug, Clone)]
pub struct ZfsSendRequest {
    /// Pool-relative target dataset path components (e.g. `["data"]`).
    pub dataset: Vec<Vec<u8>>,
    /// Target snapshot name to send (required unless supplied solely via `resume_token` match).
    pub to_snapshot: Vec<u8>,
    /// Optional incremental base (`-i` / `-I`).
    pub from: Option<ZfsSendFrom>,
    /// Include intermediary snapshots (`-I`). Requires `from.is_some()`.
    pub include_intermediaries: bool,
    /// Raw encrypted/compressed send (`-w`); works keylessly on locked encrypted datasets.
    pub raw: bool,
    /// Send compressed physical blocks directly (`-c`, implied by `raw`).
    pub compressed: bool,
    /// Send embedded data blocks as `DRR_WRITE_EMBEDDED` (`-e`, implied by `raw`).
    pub embedded: bool,
    /// Allow blocks larger than 128 KiB (`-L`, implied by `raw`).
    pub large_blocks: bool,
    /// Emit compound stream packaging dataset local/received properties (`-p`).
    pub properties: bool,
    /// Optional OpenZFS v1 `receive_resume_token` (`-t`).
    pub resume_token: Option<String>,
    /// Stream byte order (defaults to `Endian::Little` matching x86_64/aarch64 OpenZFS).
    pub stream_order: Endian,
}

impl ZfsSendRequest {
    #[must_use]
    pub fn full(dataset: Vec<Vec<u8>>, to_snapshot: Vec<u8>) -> Self {
        Self {
            dataset,
            to_snapshot,
            from: None,
            include_intermediaries: false,
            raw: false,
            compressed: false,
            embedded: false,
            large_blocks: false,
            properties: false,
            resume_token: None,
            stream_order: Endian::Little,
        }
    }
}

/// Structured audit report emitted after a completed `send_stream`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZfsSendReport {
    pub substreams_sent: usize,
    pub compound: bool,
    pub raw: bool,
    pub resumed: bool,
    pub to_guid: u64,
    pub from_guid: u64,
    pub records_written: u64,
    pub objects_sent: u64,
    pub blocks_sent: u64,
    pub bytes_written: u64,
    pub final_checksum: [u64; 4],
}

#[derive(Debug, Clone)]
struct BaseIdentity {
    guid: u64,
    creation_txg: u64,
    ivset_guid: Option<u64>,
    name: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
struct ResumeCursor {
    object: u64,
    offset: u64,
}

fn checkpoint(cx: &Cx) -> Result<()> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)
}

fn corrupt(detail: impl Into<String>) -> FfsError {
    FfsError::Corruption {
        block: 0,
        detail: detail.into(),
    }
}

fn unsupported(detail: impl Into<String>) -> FfsError {
    FfsError::UnsupportedFeature(detail.into())
}

fn parse_err(err: &ffs_types::ParseError) -> FfsError {
    FfsError::Format(err.to_string())
}

fn io_err(err: &std::io::Error) -> FfsError {
    FfsError::Format(format!("send stream write I/O error: {err}"))
}

fn format_toname(pool_name: &str, dataset: &[Vec<u8>], snapshot: &[u8]) -> Result<Vec<u8>> {
    let mut name = pool_name.as_bytes().to_vec();
    for comp in dataset {
        name.push(b'/');
        name.extend_from_slice(comp);
    }
    name.push(b'@');
    name.extend_from_slice(snapshot);
    if name.len() >= 256 || name.contains(&0) {
        return Err(corrupt(
            "send stream drr_toname exceeds 255 bytes or contains NUL",
        ));
    }
    Ok(name)
}

fn resolve_from_source(
    cx: &Cx,
    mos: &mut Objects,
    dataset: &[Vec<u8>],
    from: &ZfsSendFrom,
    to_snap: &SnapshotRoot,
    chain: &[SnapshotRoot],
) -> Result<BaseIdentity> {
    match from {
        ZfsSendFrom::Snapshot(name) => {
            let found = chain
                .iter()
                .find(|s| s.info.name == *name)
                .ok_or_else(|| FfsError::NotFound("ZFS incremental base snapshot".into()))?;
            if found.info.creation_txg >= to_snap.info.creation_txg
                || found.info.guid == to_snap.info.guid
            {
                return Err(FfsError::Format(
                    "incremental base snapshot is not a strict ancestor of target snapshot".into(),
                ));
            }
            let ivset_guid = mos.dataset_ivset_guid(cx, found.info.object)?;
            Ok(BaseIdentity {
                guid: found.info.guid,
                creation_txg: found.info.creation_txg,
                ivset_guid,
                name: found.info.name.clone(),
            })
        }
        ZfsSendFrom::Bookmark(name) => {
            let bookmarks = list_bookmarks_in_mos(cx, mos, dataset)?;
            let bm = bookmarks
                .into_iter()
                .find(|b| b.name.as_bytes() == name.as_slice())
                .ok_or_else(|| FfsError::NotFound("ZFS incremental base bookmark".into()))?;
            if bm.creation_txg >= to_snap.info.creation_txg || bm.guid == to_snap.info.guid {
                return Err(FfsError::Format(
                    "incremental base bookmark is not a strict ancestor of target snapshot".into(),
                ));
            }
            Ok(BaseIdentity {
                guid: bm.guid,
                creation_txg: bm.creation_txg,
                ivset_guid: None,
                name: bm.name.into_bytes(),
            })
        }
    }
}

fn collect_dataset_props_nvlist(cx: &Cx, mos: &mut Objects, dataset: &[Vec<u8>]) -> Result<NvList> {
    let ds = mos
        .datasets(cx)?
        .into_iter()
        .find(|d| d.components == dataset)
        .ok_or_else(|| FfsError::NotFound("ZFS dataset for property packaging".into()))?;
    let dir_dn = mos.object(cx, ds.directory_object)?;
    let props_obj = dir_dn
        .order()
        .u64(dir_dn.bonus(), 80)
        .map_err(|e| parse_err(&e))?;
    let mut fields = BTreeMap::new();
    if props_obj != 0 {
        for entry in mos.zap_values(cx, props_obj)? {
            let Ok(name_str) = std::str::from_utf8(&entry.name) else {
                continue;
            };
            // Skip internal `$inherit` markers and host-sensitive local overrides; strip `$recvd` suffix.
            if name_str.ends_with("$inherit") {
                continue;
            }
            let clean_name = name_str.strip_suffix("$recvd").unwrap_or(name_str);
            // Local overrides received: skip `$recvd` if local already recorded.
            if name_str.ends_with("$recvd") && fields.contains_key(clean_name) {
                continue;
            }
            if entry.integer_bytes == 8 && entry.values.len() == 1 {
                fields.insert(clean_name.to_owned(), Value::Unsigned(entry.values[0]));
            } else if entry.integer_bytes == 1 {
                let raw: Vec<u8> = entry
                    .values
                    .iter()
                    .filter_map(|&v| u8::try_from(v).ok())
                    .collect();
                let trimmed = raw.strip_suffix(&[0]).unwrap_or(&raw);
                if let Ok(s) = std::str::from_utf8(trimmed)
                    && !s.contains('\0')
                {
                    fields.insert(clean_name.to_owned(), Value::String(s.to_owned()));
                }
            }
        }
    }
    Ok(NvList { fields })
}

struct StreamWriter<'a, W: Write> {
    out: &'a mut W,
    order: Endian,
    cksum: Option<Fletcher4Stream>,
    records_written: u64,
    bytes_written: u64,
}

impl<'a, W: Write> StreamWriter<'a, W> {
    fn new(out: &'a mut W, order: Endian, checksummed: bool) -> Self {
        Self {
            out,
            order,
            cksum: checksummed.then(|| Fletcher4Stream::new(order)),
            records_written: 0,
            bytes_written: 0,
        }
    }

    fn write_record(&mut self, cx: &Cx, rec: &DrrRecord, payload: &[u8]) -> Result<()> {
        checkpoint(cx)?;
        if self.records_written >= MAX_SEND_RECORDS {
            return Err(unsupported("send stream exceeded record safety bound"));
        }
        let mut header = rec.encode_header(self.order).map_err(|e| parse_err(&e))?;
        if let Some(ck) = &mut self.cksum {
            ck.stamp_record(&mut header, payload, rec.record_type())
                .map_err(|e| parse_err(&e))?;
        }
        self.out.write_all(&header).map_err(|e| io_err(&e))?;
        if !payload.is_empty() {
            self.out.write_all(payload).map_err(|e| io_err(&e))?;
        }
        self.records_written += 1;
        self.bytes_written = self
            .bytes_written
            .saturating_add((header.len() + payload.len()) as u64);
        Ok(())
    }

    fn final_checksum(&self) -> [u64; 4] {
        self.cksum.as_ref().map_or([0; 4], Fletcher4Stream::state)
    }
}

struct SubstreamContext<'a, W: Write> {
    writer: StreamWriter<'a, W>,
    to_guid: u64,
    from_txg: u64,
    raw: bool,
    compressed: bool,
    embedded: bool,
    large_blocks: bool,
    is_encrypted: bool,
    hole_birth_active: bool,
    resume: Option<ResumeCursor>,
    objects_sent: u64,
    blocks_sent: u64,
}

impl<W: Write> SubstreamContext<'_, W> {
    fn walk_meta_dnode(
        &mut self,
        cx: &Cx,
        view: &mut Objects,
        meta: &Dnode,
        ceiling: u64,
    ) -> Result<()> {
        let levels = meta.levels();
        if levels == 0 || levels > MAX_SEND_TREE_DEPTH {
            return Err(corrupt("invalid meta_dnode indirect level count"));
        }
        let ind_shift = usize::from(meta.indirect_shift());
        let ptrs_per_ind = if levels > 1 {
            (1_usize << ind_shift) / 128
        } else {
            1
        };
        let mut span: u64 = 1;
        for _ in 1..levels {
            span = span
                .checked_mul(ptrs_per_ind as u64)
                .ok_or_else(|| corrupt("meta_dnode span overflow"))?;
        }
        let max_bid = meta.max_block();
        let mut free_run: Option<(u64, u64)> = None;
        for (idx, bp) in meta.pointers().iter().enumerate() {
            let start_bid = (idx as u64).saturating_mul(span);
            if start_bid > max_bid {
                break;
            }
            self.walk_meta_bp(
                cx,
                view,
                bp,
                levels - 1,
                start_bid,
                max_bid,
                ptrs_per_ind,
                ceiling,
                &mut free_run,
            )?;
        }
        self.flush_free_objects(cx, &mut free_run)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_meta_bp(
        &mut self,
        cx: &Cx,
        view: &mut Objects,
        bp: &BlockPointer,
        level: u8,
        start_bid: u64,
        max_bid: u64,
        ptrs_per_ind: usize,
        ceiling: u64,
        free_run: &mut Option<(u64, u64)>,
    ) -> Result<()> {
        checkpoint(cx)?;
        if start_bid > max_bid {
            return Ok(());
        }
        let mut span: u64 = 1;
        for _ in 0..level {
            span = span
                .checked_mul(ptrs_per_ind as u64)
                .ok_or_else(|| corrupt("meta subtree span overflow"))?;
        }
        let end_bid = start_bid.saturating_add(span - 1).min(max_bid);
        let max_obj_in_subtree = end_bid
            .saturating_add(1)
            .saturating_mul(32)
            .saturating_sub(1);

        // Skip entire subtree strictly before resume cursor.
        if let Some(res) = self.resume
            && max_obj_in_subtree < res.object
        {
            return Ok(());
        }

        // Prune unchanged incremental subtrees in O(1).
        if self.from_txg > 0 && !bp.hole() && bp.birth() <= self.from_txg {
            return Ok(());
        }

        if bp.hole() {
            if self.from_txg > 0 && (!self.hole_birth_active || bp.birth() > self.from_txg) {
                let first = start_bid.saturating_mul(32).max(1);
                let last_excl = end_bid.saturating_add(1).saturating_mul(32);
                if last_excl > first {
                    self.record_free_objects(cx, free_run, first, last_excl - first)?;
                }
            }
            return Ok(());
        }
        if bp.dedup() {
            return Err(unsupported("send refuses legacy BP_IS_DEDUP block pointer"));
        }

        if level > 0 {
            let ind_size = bp.logical_bytes();
            let Some((raw_ind, ind_order, ind_birth)) =
                view.read_indirect_block(cx, bp, DMU_OT_DNODE, level, ind_size, ceiling)?
            else {
                return Ok(());
            };
            let count = raw_ind.len() / 128;
            let child_span = span / (ptrs_per_ind as u64);
            for slot in 0..count {
                let child_start = start_bid.saturating_add((slot as u64) * child_span);
                if child_start > max_bid {
                    break;
                }
                let child_bp =
                    BlockPointer::parse(&raw_ind[slot * 128..(slot + 1) * 128], ind_order)
                        .map_err(|e| parse_err(&e))?;
                self.walk_meta_bp(
                    cx,
                    view,
                    &child_bp,
                    level - 1,
                    child_start,
                    max_bid,
                    ptrs_per_ind,
                    ind_birth,
                    free_run,
                )?;
            }
            return Ok(());
        }

        // Level-0 16 KiB `DMU_OT_DNODE` block (32 dnode slots).
        let (dn_block, dn_order, dn_birth) = if self.raw && self.is_encrypted {
            let raw_phys = view.read_verified_physical_block(cx, bp)?;
            if raw_phys.len() != DNODE_BLOCK_BYTES || bp.compression() != 2 {
                return Err(corrupt(
                    "encrypted DMU_OT_DNODE block must be uncompressed 16 KiB",
                ));
            }
            (raw_phys, bp.payload_order(), bp.birth())
        } else {
            let Some(block) =
                view.read_logical_block(cx, bp, DMU_OT_DNODE, DNODE_BLOCK_BYTES, ceiling)?
            else {
                return Ok(());
            };
            block
        };

        // For raw encrypted streams, emit `DRR_OBJECT_RANGE` before any dnode in this 16 KiB block!
        if self.raw && self.is_encrypted && bp.is_encrypted() {
            self.flush_free_objects(cx, free_run)?;
            let flags = if dn_order == self.writer.order {
                0
            } else {
                DRR_RAW_BYTESWAP
            };
            self.writer.write_record(
                cx,
                &DrrRecord::ObjectRange(DrrObjectRange {
                    firstobj: start_bid.saturating_mul(32),
                    numslots: 32,
                    toguid: self.to_guid,
                    salt: bp_crypt_salt(bp),
                    iv: bp_crypt_iv(bp),
                    mac: bp_crypt_mac(bp),
                    flags,
                }),
                &[],
            )?;
        }

        let mut slot = 0_usize;
        while slot < 32 {
            checkpoint(cx)?;
            let obj_id = start_bid.saturating_mul(32).saturating_add(slot as u64);
            let base = slot * DNODE_BYTES;
            let dn_type = dn_block[base];
            if obj_id == 0 {
                slot += 1;
                continue;
            }
            if let Some(res) = self.resume
                && obj_id < res.object
            {
                let extra = if dn_type == 0 {
                    0
                } else {
                    usize::from(dn_block[base + 12])
                };
                slot += 1 + extra;
                continue;
            }

            if dn_type == 0 {
                if self.from_txg > 0 {
                    self.record_free_objects(cx, free_run, obj_id, 1)?;
                }
                slot += 1;
                continue;
            }

            self.flush_free_objects(cx, free_run)?;
            let Some(dnode) = dnode_at(&dn_block, slot, dn_order).map_err(|e| parse_err(&e))?
            else {
                slot += 1;
                continue;
            };
            let extra_slots = usize::from(dn_block[base + 12]);
            let dn_slots = u8::try_from(1 + extra_slots).unwrap_or(1);

            self.emit_dnode_and_data(
                cx, view, obj_id, &dnode, &dn_block, slot, dn_order, dn_slots, dn_birth,
            )?;

            slot += 1 + extra_slots;
        }
        Ok(())
    }

    fn record_free_objects(
        &mut self,
        cx: &Cx,
        free_run: &mut Option<(u64, u64)>,
        first: u64,
        count: u64,
    ) -> Result<()> {
        if count == 0 {
            return Ok(());
        }
        if let Some((start, len)) = free_run {
            if start.saturating_add(*len) == first {
                *len = len.saturating_add(count);
                return Ok(());
            }
            let emit = (*start, *len);
            *free_run = Some((first, count));
            self.writer.write_record(
                cx,
                &DrrRecord::FreeObjects(DrrFreeObjects {
                    firstobj: emit.0,
                    numobjs: emit.1,
                    toguid: self.to_guid,
                }),
                &[],
            )?;
        } else {
            *free_run = Some((first, count));
        }
        Ok(())
    }

    fn flush_free_objects(&mut self, cx: &Cx, free_run: &mut Option<(u64, u64)>) -> Result<()> {
        if let Some((firstobj, numobjs)) = free_run.take() {
            self.writer.write_record(
                cx,
                &DrrRecord::FreeObjects(DrrFreeObjects {
                    firstobj,
                    numobjs,
                    toguid: self.to_guid,
                }),
                &[],
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_dnode_and_data(
        &mut self,
        cx: &Cx,
        view: &mut Objects,
        obj_id: u64,
        dnode: &Dnode,
        dn_block: &[u8],
        slot: usize,
        dn_order: Endian,
        dn_slots: u8,
        dn_birth: u64,
    ) -> Result<()> {
        let resume_offset_for_obj = self
            .resume
            .and_then(|r| (r.object == obj_id).then_some(r.offset));
        let emit_obj_header = resume_offset_for_obj.is_none_or(|off| off == 0);

        if emit_obj_header {
            // Native send reblocks large objects for legacy streams. Until
            // that transformation is implemented, never advertise oversized
            // object geometry without the LARGE_BLOCKS feature.
            if !self.raw && !self.large_blocks && dnode.data_bytes() as u64 > LEGACY_MAX_BLOCK_BYTES
            {
                return Err(unsupported(
                    "send of an object block larger than 128 KiB requires large_blocks (-L)",
                ));
            }
            // Typed bonus payloads need native byte-order conversion. SA is
            // self-describing: its own magic determines attribute byte order.
            if !self.raw
                && dn_order != self.writer.order
                && !dnode.bonus().is_empty()
                && !dmu_ot_is_byte_array(dnode.bonus_type())
            {
                return Err(unsupported(
                    "non-raw send cannot convert a foreign-order dnode bonus",
                ));
            }
            let (raw_bonuslen, bonus_bytes) = if self.raw && self.is_encrypted {
                match extract_raw_dnode_bonus(dn_block, slot, dn_order)
                    .map_err(|e| parse_err(&e))?
                {
                    Some((rlen, bytes)) => (u32::try_from(rlen).unwrap_or(0), bytes),
                    None => (0, Vec::new()),
                }
            } else {
                (0, dnode.bonus().to_vec())
            };
            let padded_len = bonus_bytes.len().next_multiple_of(8);
            let mut bonus_payload = bonus_bytes;
            bonus_payload.resize(padded_len, 0);

            let mut obj_flags = 0_u8;
            if dnode.spill().is_some() {
                obj_flags |= DRR_OBJECT_SPILL;
            }
            if self.raw && dn_order != self.writer.order {
                obj_flags |= DRR_RAW_BYTESWAP;
            }
            let obj_rec = DrrRecord::Object(DrrObject {
                object: obj_id,
                object_type: u32::from(dnode.object_type()),
                bonus_type: u32::from(dnode.bonus_type()),
                blksz: u32::try_from(dnode.data_bytes())
                    .map_err(|_| corrupt("dnode block size exceeds u32"))?,
                bonuslen: u32::try_from(dnode.bonus().len())
                    .map_err(|_| corrupt("dnode bonus length exceeds u32"))?,
                checksumtype: dnode.checksum_type(),
                compress: dnode.compress_type(),
                dn_slots,
                flags: obj_flags,
                raw_bonuslen,
                toguid: self.to_guid,
                indblkshift: dnode.indirect_shift(),
                nlevels: dnode.levels(),
                nblkptr: u8::try_from(dnode.pointers().len()).unwrap_or(1),
                maxblkid: dnode.max_block(),
            });
            self.writer.write_record(cx, &obj_rec, &bonus_payload)?;
            self.objects_sent += 1;
        }

        // Emit spill block if present and modified after `from_txg`.
        if let Some(spill_bp) = dnode.spill()
            && !spill_bp.hole()
            && (self.from_txg == 0 || spill_bp.birth() > self.from_txg)
            && resume_offset_for_obj.is_none_or(|off| off == 0)
        {
            self.emit_spill_block(cx, view, obj_id, spill_bp, dn_birth)?;
        }

        // Walk data block tree in ascending `block_id`.
        let levels = dnode.levels();
        if levels == 0 || levels > MAX_SEND_TREE_DEPTH {
            return Err(corrupt("invalid dnode level count"));
        }
        let blksz = dnode.data_bytes() as u64;
        let ptrs_per_ind = if levels > 1 {
            (1_usize << usize::from(dnode.indirect_shift())) / 128
        } else {
            1
        };
        let mut span: u64 = 1;
        for _ in 1..levels {
            span = span
                .checked_mul(ptrs_per_ind as u64)
                .ok_or_else(|| corrupt("dnode span overflow"))?;
        }
        let max_bid = dnode.max_block();
        let mut free_range: Option<(u64, u64)> = None;
        for (idx, bp) in dnode.pointers().iter().enumerate() {
            let start_bid = (idx as u64).saturating_mul(span);
            if start_bid > max_bid {
                break;
            }
            self.walk_data_bp(
                cx,
                view,
                obj_id,
                dnode.object_type(),
                blksz,
                bp,
                levels - 1,
                start_bid,
                max_bid,
                ptrs_per_ind,
                dn_birth,
                resume_offset_for_obj,
                &mut free_range,
            )?;
        }
        self.flush_free_range(cx, obj_id, &mut free_range)?;

        // For incremental streams, explicitly truncate any blocks past `max_block()` on the receiver.
        if self.from_txg > 0 {
            let trunc_offset = max_bid.saturating_add(1).saturating_mul(blksz);
            if resume_offset_for_obj.is_none_or(|off| trunc_offset >= off) {
                self.writer.write_record(
                    cx,
                    &DrrRecord::Free(DrrFree {
                        object: obj_id,
                        offset: trunc_offset,
                        length: u64::MAX,
                        toguid: self.to_guid,
                    }),
                    &[],
                )?;
            }
        }
        Ok(())
    }

    fn emit_spill_block(
        &mut self,
        cx: &Cx,
        view: &mut Objects,
        obj_id: u64,
        bp: &BlockPointer,
        ceiling: u64,
    ) -> Result<()> {
        if bp.dedup() {
            return Err(unsupported("send refuses legacy BP_IS_DEDUP spill pointer"));
        }
        // OpenZFS dump_spill sets transformed fields only for raw streams.
        // Even `send -c` sends decoded logical SA spill bytes.
        if self.raw {
            if !bp.protected() {
                return Err(corrupt(
                    "raw encrypted send encountered an unprotected spill",
                ));
            }
            let raw_phys = view.read_verified_physical_block(cx, bp)?;
            let mut flags = 0_u8;
            if bp.payload_order() != self.writer.order {
                flags |= DRR_RAW_BYTESWAP;
            }
            let (salt, iv, mac) = if bp.is_encrypted() {
                (bp_crypt_salt(bp), bp_crypt_iv(bp), bp_crypt_mac(bp))
            } else {
                ([0; 8], [0; 12], bp_crypt_mac(bp))
            };
            self.writer.write_record(
                cx,
                &DrrRecord::Spill(DrrSpill {
                    object: obj_id,
                    length: bp.logical_bytes() as u64,
                    toguid: self.to_guid,
                    flags,
                    compressiontype: bp.compression(),
                    compressed_size: raw_phys.len() as u64,
                    salt,
                    iv,
                    mac,
                    object_type: 0,
                }),
                &raw_phys,
            )?;
        } else {
            let Some((logical, payload_order, _)) =
                view.read_logical_block(cx, bp, bp.object_type(), bp.logical_bytes(), ceiling)?
            else {
                return Ok(());
            };
            if payload_order != self.writer.order && !dmu_ot_is_byte_array(bp.object_type()) {
                return Err(unsupported(
                    "non-raw send cannot convert a foreign-order SA spill",
                ));
            }
            self.writer.write_record(
                cx,
                &DrrRecord::Spill(DrrSpill {
                    object: obj_id,
                    length: logical.len() as u64,
                    toguid: self.to_guid,
                    flags: 0,
                    compressiontype: 0,
                    compressed_size: 0,
                    salt: [0; 8],
                    iv: [0; 12],
                    mac: [0; 16],
                    object_type: 0,
                }),
                &logical,
            )?;
        }
        self.blocks_sent += 1;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_data_bp(
        &mut self,
        cx: &Cx,
        view: &mut Objects,
        obj_id: u64,
        obj_type: u8,
        blksz: u64,
        bp: &BlockPointer,
        level: u8,
        start_bid: u64,
        max_bid: u64,
        ptrs_per_ind: usize,
        ceiling: u64,
        resume_offset: Option<u64>,
        free_range: &mut Option<(u64, u64)>,
    ) -> Result<()> {
        checkpoint(cx)?;
        if start_bid > max_bid {
            return Ok(());
        }
        let mut span: u64 = 1;
        for _ in 0..level {
            span = span
                .checked_mul(ptrs_per_ind as u64)
                .ok_or_else(|| corrupt("data subtree span overflow"))?;
        }
        let end_bid = start_bid.saturating_add(span - 1).min(max_bid);
        let max_byte_end = end_bid.saturating_add(1).saturating_mul(blksz);
        if let Some(res_off) = resume_offset
            && max_byte_end <= res_off
        {
            return Ok(());
        }
        if self.from_txg > 0 && !bp.hole() && bp.birth() <= self.from_txg {
            return Ok(());
        }
        if bp.hole() {
            if self.from_txg > 0 && (!self.hole_birth_active || bp.birth() > self.from_txg) {
                let mut off = start_bid.saturating_mul(blksz);
                let mut len = end_bid
                    .saturating_sub(start_bid)
                    .saturating_add(1)
                    .saturating_mul(blksz);
                if let Some(res_off) = resume_offset
                    && off < res_off
                {
                    let skip = res_off - off;
                    if skip >= len {
                        return Ok(());
                    }
                    off = res_off;
                    len -= skip;
                }
                self.record_free_range(cx, obj_id, free_range, off, len)?;
            }
            return Ok(());
        }
        if bp.dedup() {
            return Err(unsupported("send refuses legacy BP_IS_DEDUP data pointer"));
        }

        if level > 0 {
            let Some((raw_ind, ind_order, ind_birth)) =
                view.read_indirect_block(cx, bp, obj_type, level, bp.logical_bytes(), ceiling)?
            else {
                return Ok(());
            };
            let count = raw_ind.len() / 128;
            let child_span = span / (ptrs_per_ind as u64);
            for slot in 0..count {
                let child_start = start_bid.saturating_add((slot as u64) * child_span);
                if child_start > max_bid {
                    break;
                }
                let child_bp =
                    BlockPointer::parse(&raw_ind[slot * 128..(slot + 1) * 128], ind_order)
                        .map_err(|e| parse_err(&e))?;
                self.walk_data_bp(
                    cx,
                    view,
                    obj_id,
                    obj_type,
                    blksz,
                    &child_bp,
                    level - 1,
                    child_start,
                    max_bid,
                    ptrs_per_ind,
                    ind_birth,
                    resume_offset,
                    free_range,
                )?;
            }
            return Ok(());
        }

        // Level-0 leaf data block.
        let byte_offset = start_bid.saturating_mul(blksz);
        if let Some(res_off) = resume_offset
            && byte_offset < res_off
        {
            return Ok(());
        }
        self.flush_free_range(cx, obj_id, free_range)?;

        // A resumed stream can omit the OBJECT record, so independently
        // enforce the negotiated size limit on every emitted data block.
        if !self.raw && !self.large_blocks && bp.logical_bytes() as u64 > LEGACY_MAX_BLOCK_BYTES {
            return Err(unsupported(
                "send of a block larger than 128 KiB requires large_blocks (-L)",
            ));
        }

        // File and volume payloads are byte strings. Other admitted DMU
        // structures may contain native integers and need an explicit encoder
        // before their payload order can differ from the stream header.
        if !self.raw && bp.payload_order() != self.writer.order && !dmu_ot_is_byte_array(obj_type) {
            return Err(unsupported(
                "non-raw send cannot convert foreign-order structured DMU data",
            ));
        }

        if self.raw && bp.embedded() {
            return Err(corrupt(
                "raw encrypted send encountered an embedded data block",
            ));
        }
        if bp.embedded() {
            if self.embedded {
                let (mut payload, lsize) = bp.raw_embedded_bytes().map_err(|e| parse_err(&e))?;
                let psize =
                    u32::try_from(payload.len()).map_err(|_| corrupt("embedded psize overflow"))?;
                let padded_len = payload.len().next_multiple_of(8);
                payload.resize(padded_len, 0);
                self.writer.write_record(
                    cx,
                    &DrrRecord::WriteEmbedded(DrrWriteEmbedded {
                        object: obj_id,
                        offset: byte_offset,
                        length: lsize as u64,
                        toguid: self.to_guid,
                        compression: bp.compression(),
                        etype: 0,
                        lsize: u32::try_from(lsize)
                            .map_err(|_| corrupt("embedded lsize overflow"))?,
                        psize,
                    }),
                    &payload,
                )?;
            } else {
                let logical = bp.decode_embedded().map_err(|e| parse_err(&e))?;
                self.writer.write_record(
                    cx,
                    &DrrRecord::Write(DrrWrite {
                        object: obj_id,
                        object_type: u32::from(obj_type),
                        offset: byte_offset,
                        logical_size: logical.len() as u64,
                        toguid: self.to_guid,
                        checksumtype: 2,
                        flags: 0,
                        compressiontype: 0,
                        ddt_key: [0; 40],
                        compressed_size: 0,
                        salt: [0; 8],
                        iv: [0; 12],
                        mac: [0; 16],
                    }),
                    &logical,
                )?;
            }
            self.blocks_sent += 1;
            return Ok(());
        }

        let use_raw = self.raw;
        let use_comp = self.compressed
            && !self.is_encrypted
            && bp.compression() != 2
            && !dmu_ot_is_metadata(bp.object_type())
            && bp.payload_order() == self.writer.order;
        if use_raw || use_comp {
            if use_raw && !bp.protected() {
                return Err(corrupt(
                    "raw encrypted send encountered an unprotected data block",
                ));
            }
            let raw_phys = view.read_verified_physical_block(cx, bp)?;
            let mut flags = 0_u8;
            if use_raw && bp.payload_order() != self.writer.order {
                flags |= DRR_RAW_BYTESWAP;
            }
            let (salt, iv, mac) = if use_raw && bp.protected() {
                if bp.is_encrypted() {
                    (bp_crypt_salt(bp), bp_crypt_iv(bp), bp_crypt_mac(bp))
                } else {
                    ([0; 8], [0; 12], bp_crypt_mac(bp))
                }
            } else {
                ([0; 8], [0; 12], [0; 16])
            };
            self.writer.write_record(
                cx,
                &DrrRecord::Write(DrrWrite {
                    object: obj_id,
                    object_type: u32::from(obj_type),
                    offset: byte_offset,
                    logical_size: bp.logical_bytes() as u64,
                    toguid: self.to_guid,
                    checksumtype: bp.checksum_type(),
                    flags,
                    compressiontype: bp.compression(),
                    ddt_key: [0; 40],
                    compressed_size: raw_phys.len() as u64,
                    salt,
                    iv,
                    mac,
                }),
                &raw_phys,
            )?;
        } else {
            let Some((logical, _, _)) =
                view.read_logical_block(cx, bp, obj_type, bp.logical_bytes(), ceiling)?
            else {
                return Ok(());
            };
            self.writer.write_record(
                cx,
                &DrrRecord::Write(DrrWrite {
                    object: obj_id,
                    object_type: u32::from(obj_type),
                    offset: byte_offset,
                    logical_size: logical.len() as u64,
                    toguid: self.to_guid,
                    checksumtype: if bp.protected() {
                        2
                    } else {
                        bp.checksum_type()
                    },
                    flags: 0,
                    compressiontype: 0,
                    ddt_key: [0; 40],
                    compressed_size: 0,
                    salt: [0; 8],
                    iv: [0; 12],
                    mac: [0; 16],
                }),
                &logical,
            )?;
        }
        self.blocks_sent += 1;
        Ok(())
    }

    fn record_free_range(
        &mut self,
        cx: &Cx,
        obj_id: u64,
        free_range: &mut Option<(u64, u64)>,
        off: u64,
        len: u64,
    ) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        if let Some((start, cur_len)) = free_range {
            if start.saturating_add(*cur_len) == off {
                *cur_len = cur_len.saturating_add(len);
                return Ok(());
            }
            let emit = (*start, *cur_len);
            *free_range = Some((off, len));
            self.writer.write_record(
                cx,
                &DrrRecord::Free(DrrFree {
                    object: obj_id,
                    offset: emit.0,
                    length: emit.1,
                    toguid: self.to_guid,
                }),
                &[],
            )?;
        } else {
            *free_range = Some((off, len));
        }
        Ok(())
    }

    fn flush_free_range(
        &mut self,
        cx: &Cx,
        obj_id: u64,
        free_range: &mut Option<(u64, u64)>,
    ) -> Result<()> {
        if let Some((offset, length)) = free_range.take() {
            self.writer.write_record(
                cx,
                &DrrRecord::Free(DrrFree {
                    object: obj_id,
                    offset,
                    length,
                    toguid: self.to_guid,
                }),
                &[],
            )?;
        }
        Ok(())
    }
}

/// Generate a native OpenZFS `DMU_BACKUP_STREAM` for a ZPL filesystem or ZVOL snapshot.
#[allow(clippy::too_many_lines)]
pub fn send_stream(
    cx: &Cx,
    mos: &mut Objects,
    req: &ZfsSendRequest,
    out: &mut impl Write,
) -> Result<ZfsSendReport> {
    checkpoint(cx)?;
    if req.include_intermediaries && req.from.is_none() {
        return Err(FfsError::Format(
            "intermediary send (-I) requires a --from-snapshot or --from-bookmark base".into(),
        ));
    }

    let chain = mos.snapshot_chain(cx, &req.dataset)?;
    let parsed_resume = match &req.resume_token {
        Some(raw) => Some(ReceiveResumeToken::parse(raw).map_err(|e| parse_err(&e))?),
        None => None,
    };

    // Resolve target snapshot (either by explicit name or by exact resume token `toguid`).
    let to_snap = if let Some(ref tok) = parsed_resume {
        let by_guid = chain
            .iter()
            .find(|s| s.info.guid == tok.toguid)
            .ok_or_else(|| {
                FfsError::NotFound("ZFS target snapshot matching resume token toguid".into())
            })?;
        if !req.to_snapshot.is_empty() && by_guid.info.name != req.to_snapshot {
            return Err(FfsError::Format(
                "resume token toguid does not match requested target snapshot".into(),
            ));
        }
        by_guid.clone()
    } else {
        chain
            .iter()
            .find(|s| s.info.name == req.to_snapshot)
            .ok_or_else(|| FfsError::NotFound("ZFS target snapshot for send".into()))?
            .clone()
    };

    // Resolve incremental base (resume token `fromguid` overrides or validates `req.from`).
    let base: Option<BaseIdentity> = if let Some(ref tok) = parsed_resume {
        if let Some(fg) = tok.fromguid {
            if let Some(snap) = chain.iter().find(|s| s.info.guid == fg) {
                if snap.info.creation_txg >= to_snap.info.creation_txg {
                    return Err(FfsError::Format(
                        "resume token fromguid is not an ancestor of target snapshot".into(),
                    ));
                }
                let ivset_guid = mos.dataset_ivset_guid(cx, snap.info.object)?;
                Some(BaseIdentity {
                    guid: snap.info.guid,
                    creation_txg: snap.info.creation_txg,
                    ivset_guid,
                    name: snap.info.name.clone(),
                })
            } else {
                let bms = list_bookmarks_in_mos(cx, mos, &req.dataset)?;
                let bm = bms.into_iter().find(|b| b.guid == fg).ok_or_else(|| {
                    FfsError::NotFound(
                        "ZFS base snapshot or bookmark matching resume token fromguid".into(),
                    )
                })?;
                if bm.creation_txg >= to_snap.info.creation_txg {
                    return Err(FfsError::Format(
                        "resume token fromguid bookmark is not an ancestor of target".into(),
                    ));
                }
                Some(BaseIdentity {
                    guid: bm.guid,
                    creation_txg: bm.creation_txg,
                    ivset_guid: None,
                    name: bm.name.into_bytes(),
                })
            }
        } else {
            None
        }
    } else if let Some(ref from_src) = req.from {
        Some(resolve_from_source(
            cx,
            mos,
            &req.dataset,
            from_src,
            &to_snap,
            &chain,
        )?)
    } else {
        None
    };

    // Resolve ordered list of `(Option<BaseIdentity>, SnapshotRoot)` substreams.
    let mut substreams: Vec<(Option<BaseIdentity>, SnapshotRoot)> = Vec::new();
    if req.include_intermediaries && parsed_resume.is_none() {
        let mut cur_base = base
            .clone()
            .ok_or_else(|| FfsError::Format("intermediary send requires base".into()))?;
        for snap in &chain {
            if snap.info.creation_txg > cur_base.creation_txg
                && snap.info.creation_txg <= to_snap.info.creation_txg
            {
                let next_ivset = mos.dataset_ivset_guid(cx, snap.info.object)?;
                let next_base = BaseIdentity {
                    guid: snap.info.guid,
                    creation_txg: snap.info.creation_txg,
                    ivset_guid: next_ivset,
                    name: snap.info.name.clone(),
                };
                substreams.push((Some(cur_base), snap.clone()));
                cur_base = next_base;
            }
        }
        if substreams.is_empty() {
            return Err(FfsError::Format(
                "no snapshots found in intermediary range".into(),
            ));
        }
    } else {
        substreams.push((base.clone(), to_snap.clone()));
    }

    let raw = req.raw || parsed_resume.as_ref().is_some_and(|t| t.rawok);
    let compressed = req.compressed || raw || parsed_resume.as_ref().is_some_and(|t| t.compressok);
    let embedded = req.embedded || raw || parsed_resume.as_ref().is_some_and(|t| t.embedok);
    let large_blocks =
        req.large_blocks || raw || parsed_resume.as_ref().is_some_and(|t| t.largeblockok);
    let compound = parsed_resume.is_none() && (req.properties || substreams.len() > 1);

    let pool_name = mos.pool_name(cx)?;
    let hole_birth_active = mos
        .config()
        .read_features
        .iter()
        .any(|f| f == "com.delphix:hole_birth");

    let mut total_records = 0_u64;
    let mut total_objects = 0_u64;
    let mut total_blocks = 0_u64;
    let mut total_bytes = 0_u64;
    let mut last_checksum = [0_u64; 4];

    // Optional compound package header (`-p` or `-I`).
    if compound {
        let mut pkg_fields = BTreeMap::new();
        let props_nv = if req.properties {
            collect_dataset_props_nvlist(cx, mos, &req.dataset)?
        } else {
            NvList {
                fields: BTreeMap::new(),
            }
        };
        let ds_row = mos
            .datasets(cx)?
            .into_iter()
            .find(|d| d.components == req.dataset)
            .ok_or_else(|| FfsError::NotFound("ZFS dataset for compound send".into()))?;
        let mut ds_entry = BTreeMap::new();
        let mut full_ds_name = pool_name.clone();
        for comp in &req.dataset {
            full_ds_name.push('/');
            full_ds_name.push_str(&String::from_utf8_lossy(comp));
        }
        ds_entry.insert("name".to_owned(), Value::String(full_ds_name));
        ds_entry.insert("parentfromsnap".to_owned(), Value::String(String::new()));
        ds_entry.insert("props".to_owned(), Value::List(props_nv));
        let mut snaps_nv = BTreeMap::new();
        let mut snapprops_nv = BTreeMap::new();
        for (_, snap) in &substreams {
            let sname = String::from_utf8_lossy(&snap.info.name).into_owned();
            snaps_nv.insert(sname.clone(), Value::Unsigned(snap.info.guid));
            snapprops_nv.insert(
                sname,
                Value::List(NvList {
                    fields: BTreeMap::new(),
                }),
            );
        }
        ds_entry.insert("snaps".to_owned(), Value::List(NvList { fields: snaps_nv }));
        ds_entry.insert(
            "snapprops".to_owned(),
            Value::List(NvList {
                fields: snapprops_nv,
            }),
        );
        let mut fss_map = BTreeMap::new();
        fss_map.insert(
            format!("{:x}", ds_row.guid),
            Value::List(NvList { fields: ds_entry }),
        );
        pkg_fields.insert("fss".to_owned(), Value::List(NvList { fields: fss_map }));
        pkg_fields.insert(
            "tosnap".to_owned(),
            Value::String(String::from_utf8_lossy(&to_snap.info.name).into_owned()),
        );
        if let Some(ref b) = base {
            pkg_fields.insert(
                "fromsnap".to_owned(),
                Value::String(String::from_utf8_lossy(&b.name).into_owned()),
            );
            pkg_fields.insert("fromguid".to_owned(), Value::Unsigned(b.guid));
        }
        let pkg_bytes = NvList { fields: pkg_fields }
            .encode_xdr()
            .map_err(|e| parse_err(&e))?;
        let pkg_len = u32::try_from(pkg_bytes.len())
            .map_err(|_| corrupt("compound send nvlist exceeds u32"))?;

        let compound_begin = DrrRecord::Begin(DrrBegin {
            magic: DMU_BACKUP_MAGIC,
            hdr_type: StreamHeaderType::CompoundStream,
            features: SendFeatureFlags::EMPTY,
            creation_time: to_snap.info.creation_time,
            objset_type: DMU_OST_NONE,
            flags: 0,
            toguid: 0,
            fromguid: 0,
            toname: format_toname(&pool_name, &req.dataset, &to_snap.info.name)?,
            payload_len: pkg_len,
        });
        let mut outer = StreamWriter::new(out, req.stream_order, false);
        outer.write_record(cx, &compound_begin, &pkg_bytes)?;
        total_records += outer.records_written;
        total_bytes += outer.bytes_written;
    }

    for (sub_base, sub_snap) in &substreams {
        let (os, mut view, crypto_info, portable_mac) =
            mos.open_snapshot_objectset(cx, &req.dataset, sub_snap, raw)?;
        let is_encrypted = crypto_info.is_some();
        let to_ivset_guid = mos.dataset_ivset_guid(cx, sub_snap.info.object)?;

        let has_lz4 = mos
            .config()
            .read_features
            .iter()
            .any(|f| f == "org.illumos:lz4_compress");
        let has_zstd = mos
            .config()
            .read_features
            .iter()
            .any(|f| f == "org.freebsd:zstd_compress");
        let has_large_dnode = mos
            .config()
            .read_features
            .iter()
            .any(|f| f == "org.zfsonlinux:large_dnode");

        let mut features = SendFeatureFlags::EMPTY.with(DMU_BACKUP_FEATURE_SA_SPILL);
        if has_large_dnode {
            features = features.with(DMU_BACKUP_FEATURE_LARGE_DNODE);
        }
        if compressed {
            features = features.with(DMU_BACKUP_FEATURE_COMPRESSED);
            if has_lz4 {
                features = features.with(DMU_BACKUP_FEATURE_LZ4);
            }
            if has_zstd {
                features = features.with(DMU_BACKUP_FEATURE_ZSTD);
            }
        }
        if embedded {
            features = features.with(DMU_BACKUP_FEATURE_EMBED_DATA);
        }
        if large_blocks {
            features = features.with(DMU_BACKUP_FEATURE_LARGE_BLOCKS);
        }
        if raw && is_encrypted {
            features = features.with(DMU_BACKUP_FEATURE_RAW);
            if has_lz4 {
                features = features.with(DMU_BACKUP_FEATURE_LZ4);
            }
            if has_zstd {
                features = features.with(DMU_BACKUP_FEATURE_ZSTD);
            }
        }
        if parsed_resume.is_some() {
            features = features.with(DMU_BACKUP_FEATURE_RESUMING);
        }

        let begin_payload = if raw && is_encrypted {
            let info = crypto_info
                .as_ref()
                .ok_or_else(|| corrupt("missing crypto info for raw encrypted send"))?;
            let key_len = info.record.suite.key_len().map_err(|e| parse_err(&e))?;
            let keydata = StreamCryptoKeydata {
                suite: info.record.suite,
                version: info.record.version,
                guid: info.record.guid,
                keyformat: info.record.keyformat,
                pbkdf2_salt: info.record.pbkdf2_salt,
                pbkdf2_iters: info.record.pbkdf2_iters,
                iv: info.record.iv,
                mac: info.record.mac,
                wrapped_master_key: info.record.encrypted_master_key[..key_len].to_vec(),
                wrapped_hmac_key: info.record.encrypted_hmac_key,
                portable_mac,
                to_ivset_guid: to_ivset_guid.unwrap_or(0),
                from_ivset_guid: sub_base.as_ref().and_then(|b| b.ivset_guid),
            };
            keydata
                .to_nvlist()
                .map_err(|e| parse_err(&e))?
                .encode_xdr()
                .map_err(|e| parse_err(&e))?
        } else {
            Vec::new()
        };
        let payload_len = u32::try_from(begin_payload.len())
            .map_err(|_| corrupt("DRR_BEGIN crypto payload exceeds u32"))?;

        let objset_type = match os.kind {
            2 => DMU_OST_ZFS,
            3 => DMU_OST_ZVOL,
            _ => return Err(unsupported("unsupported objectset kind for send")),
        };
        let mut begin_flags = DRR_FLAG_SPILL_BLOCK;
        if sub_base.is_some() {
            begin_flags |= DRR_FLAG_FREERECORDS;
        }
        let begin_rec = DrrRecord::Begin(DrrBegin {
            magic: DMU_BACKUP_MAGIC,
            hdr_type: StreamHeaderType::Substream,
            features,
            creation_time: sub_snap.info.creation_time,
            objset_type,
            flags: begin_flags,
            toguid: sub_snap.info.guid,
            fromguid: sub_base.as_ref().map_or(0, |b| b.guid),
            toname: format_toname(&pool_name, &req.dataset, &sub_snap.info.name)?,
            payload_len,
        });

        let resume_cursor = parsed_resume.as_ref().map(|tok| ResumeCursor {
            object: tok.object,
            offset: tok.offset,
        });

        let mut ctx = SubstreamContext {
            writer: StreamWriter::new(out, req.stream_order, true),
            to_guid: sub_snap.info.guid,
            from_txg: sub_base.as_ref().map_or(0, |b| b.creation_txg),
            raw: raw && is_encrypted,
            compressed,
            embedded,
            large_blocks,
            is_encrypted,
            hole_birth_active,
            resume: resume_cursor,
            objects_sent: 0,
            blocks_sent: 0,
        };
        ctx.writer.write_record(cx, &begin_rec, &begin_payload)?;
        ctx.walk_meta_dnode(cx, &mut view, &os.meta, sub_snap.root.birth())?;
        ctx.writer.write_record(
            cx,
            &DrrRecord::End(DrrEnd {
                checksum: [0; 4],
                toguid: sub_snap.info.guid,
            }),
            &[],
        )?;

        total_records += ctx.writer.records_written;
        total_objects += ctx.objects_sent;
        total_blocks += ctx.blocks_sent;
        total_bytes += ctx.writer.bytes_written;
        last_checksum = ctx.writer.final_checksum();
    }

    if compound {
        let mut outer = StreamWriter::new(out, req.stream_order, false);
        outer.write_record(
            cx,
            &DrrRecord::End(DrrEnd {
                checksum: [0; 4],
                toguid: 0,
            }),
            &[],
        )?;
        total_records += outer.records_written;
        total_bytes += outer.bytes_written;
    }

    Ok(ZfsSendReport {
        substreams_sent: substreams.len(),
        compound,
        raw,
        resumed: parsed_resume.is_some(),
        to_guid: to_snap.info.guid,
        from_guid: base.as_ref().map_or(0, |b| b.guid),
        records_written: total_records,
        objects_sent: total_objects,
        blocks_sent: total_blocks,
        bytes_written: total_bytes,
        final_checksum: last_checksum,
    })
}
