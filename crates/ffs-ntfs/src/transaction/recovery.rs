//! Persistent ARIES `$LogFile` Analysis, Winner Redo, Reverse-LSN Loser Undo,
//! Compensation Log Record (`0x01`) emission, single-torn-`RSTR` healing, and
//! clean checkpoint publication for [`super::NtfsTransactionEngine`].

use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::sync::Arc;

use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_error::{FfsError, Result};
use ffs_ondisk::ntfs::index::NtfsIndexRoot;
use ffs_ondisk::ntfs::logfile_writer::{
    LFS_RECORD_CLIENT, NtfsClientUpdateSpec, NtfsLogRingWriter, NtfsRestartConfig,
    encode_client_update_payload, encode_rstr_page, logfile_seq_num_bits, lsn_sequence, lsn_to_vbo,
    next_usa_token,
};
use ffs_ondisk::ntfs::recovery::{
    FileEdit, FileEditResult, FileOperation, IndexEdit, IndexOperation, RecoveryPass,
    apply_file_edit, apply_index_edit, deallocate_file_record_slot, initialize_file_record_slot,
};
use ffs_ondisk::ntfs::{
    DATA, NtfsFileRecord, NtfsLogOp, NtfsReference, NtfsRun, NtfsValue, VOLUME_INFORMATION,
    protect_record, restore_record,
};
use ffs_types::ByteOffset;

use crate::NtfsVolume;
use crate::reader::allocation::{AllocationLimits, NamespaceLimits, RecordOwnershipLimits};

use super::{
    LOG_PAGE_BYTES, MAX_ERASED_LOG_BYTES, NtfsLogStateSummary, NtfsPersistenceStage,
    NtfsRecoverySummary, NtfsTransactionEngine, OpenAttrRuntime, SECTOR_BYTES, checkpoint, corrupt,
    extract_plain_nonresident_runs, extract_plain_nonresident_stream, map_logical_offset,
    map_ring_err, parse_err, same_logical_record, unsupported,
};

const I30_NAME: [u16; 4] = [0x24, 0x49, 0x33, 0x30];
const LFS_CLIENT_RESTART: u32 = 2;
const CLEAN_RESTART_FLAG: u16 = 0x0002;
const NO_CLIENT: u16 = 0xFFFF;

#[derive(Debug, Clone)]
struct ParsedRestartPage {
    slot: usize,
    page_size: u32,
    version: (u16, u16),
    clean: bool,
    current_lsn: u64,
    seq_num_bits: u32,
    file_size: u64,
    last_lsn_data_len: u32,
    data_off: u16,
    open_log_count: u32,
    client_seq: u16,
    oldest_lsn: u64,
    client_restart_lsn: u64,
    usa_token: u16,
}

#[derive(Debug, Clone)]
struct RawLfsRecord {
    lsn: u64,
    previous_lsn: u64,
    undo_next_lsn: u64,
    record_type: u32,
    transaction_id: u32,
    payload: Vec<u8>,
}

#[derive(Debug, Clone)]
struct ClientRecord {
    lsn: u64,
    previous_lsn: u64,
    undo_next_lsn: u64,
    transaction_id: u32,
    redo_op: NtfsLogOp,
    undo_op: NtfsLogOp,
    target_attribute: u16,
    record_offset: u16,
    attribute_offset: u16,
    cluster_block_offset: u16,
    target_vcn: u64,
    target_lcns: Vec<u64>,
    redo_data: Vec<u8>,
    undo_data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TxState {
    Active,
    Prepared,
    Committed,
}

#[derive(Debug, Clone)]
struct TxRuntime {
    state: TxState,
    first_lsn: u64,
    last_lsn: u64,
    undo_next_lsn: u64,
}

fn le16(bytes: &[u8], off: usize) -> Result<u16> {
    let arr: [u8; 2] = bytes
        .get(off..off + 2)
        .ok_or_else(|| corrupt(off as u64, "truncated u16"))?
        .try_into()
        .map_err(|_| corrupt(off as u64, "u16 slice"))?;
    Ok(u16::from_le_bytes(arr))
}

fn le32(bytes: &[u8], off: usize) -> Result<u32> {
    let arr: [u8; 4] = bytes
        .get(off..off + 4)
        .ok_or_else(|| corrupt(off as u64, "truncated u32"))?
        .try_into()
        .map_err(|_| corrupt(off as u64, "u32 slice"))?;
    Ok(u32::from_le_bytes(arr))
}

fn le64(bytes: &[u8], off: usize) -> Result<u64> {
    let arr: [u8; 8] = bytes
        .get(off..off + 8)
        .ok_or_else(|| corrupt(off as u64, "truncated u64"))?
        .try_into()
        .map_err(|_| corrupt(off as u64, "u64 slice"))?;
    Ok(u64::from_le_bytes(arr))
}

fn parse_rstr_slot(slot: usize, raw: &[u8], stream_len: u64) -> Result<ParsedRestartPage> {
    let restored = restore_record(raw, b"RSTR").map_err(|err| parse_err(&err))?;
    if le64(&restored, 8)? != 0 {
        return Err(corrupt(0, "CHKDSK-modified or invalid RSTR system_lsn"));
    }
    let sys_page = le32(&restored, 16)?;
    let log_page = le32(&restored, 20)?;
    if sys_page != log_page || !matches!(sys_page, 512 | 1024 | 2048 | 4096) {
        return Err(unsupported("unsupported $LogFile RSTR page size"));
    }
    if restored.len() != sys_page as usize {
        return Err(corrupt(0, "RSTR buffer size mismatch"));
    }
    let version = (le16(&restored, 28)?, le16(&restored, 26)?);
    if !matches!(version, (1, 1) | (2, 0)) {
        return Err(unsupported("unsupported $LogFile LFS version"));
    }
    let usa_off = usize::from(le16(raw, 4)?);
    let usa_token = le16(raw, usa_off)?;
    let area_off = usize::from(le16(&restored, 24)?);
    let area_len = usize::from(le16(&restored, area_off + 20)?);
    let client_off = usize::from(le16(&restored, area_off + 22)?);
    if area_off + area_len > restored.len() || client_off + 64 > area_len {
        return Err(corrupt(0, "RSTR restart/client bounds overflow"));
    }
    let area = &restored[area_off..area_off + area_len];
    let current_lsn = le64(area, 0)?;
    let clients = le16(area, 8)?;
    let free_list = le16(area, 10)?;
    let in_use_list = le16(area, 12)?;
    let flags = le16(area, 14)?;
    let seq_num_bits = le32(area, 16)?;
    let file_size = le64(area, 24)?;
    let last_lsn_data_len = le32(area, 32)?;
    let rec_hdr_len = le16(area, 36)?;
    let data_off = le16(area, 38)?;
    let open_log_count = le32(area, 40)?;
    if file_size > stream_len
        || logfile_seq_num_bits(file_size).map_err(|err| parse_err(&err))? != seq_num_bits
        || rec_hdr_len != 48
        || flags & !0x0003 != 0
        || clients != 1
    {
        return Err(unsupported(
            "unsupported or invalid $LogFile RSTR client geometry",
        ));
    }
    let client = &area[client_off..];
    let oldest_lsn = le64(client, 0)?;
    let client_restart_lsn = le64(client, 8)?;
    let client_seq = le16(client, 20)?.max(1);
    let name_len = usize::try_from(le32(client, 28)?).map_err(|_| corrupt(0, "name overflow"))?;
    if in_use_list != NO_CLIENT && client.get(32..32 + name_len) != Some(b"N\0T\0F\0S\0".as_slice())
    {
        return Err(unsupported("unknown active $LogFile client"));
    }
    if !matches!((free_list, in_use_list), (0, NO_CLIENT) | (NO_CLIENT, 0)) {
        return Err(corrupt(0, "invalid RSTR client list pointers"));
    }
    let clean = in_use_list == NO_CLIENT || (flags & CLEAN_RESTART_FLAG != 0);
    Ok(ParsedRestartPage {
        slot,
        page_size: sys_page,
        version,
        clean,
        current_lsn,
        seq_num_bits,
        file_size,
        last_lsn_data_len,
        data_off,
        open_log_count,
        client_seq,
        oldest_lsn,
        client_restart_lsn,
        usa_token,
    })
}

fn choose_comparable_rstr(
    first: &ParsedRestartPage,
    second: &ParsedRestartPage,
) -> Result<ParsedRestartPage> {
    if first.page_size != second.page_size
        || first.version != second.version
        || first.seq_num_bits != second.seq_num_bits
        || first.file_size != second.file_size
        || first.data_off != second.data_off
        || first.client_seq != second.client_seq
    {
        return Err(corrupt(0, "incompatible $LogFile RSTR slots"));
    }
    let (older, newer) = if second.current_lsn > first.current_lsn
        || (second.current_lsn == first.current_lsn
            && second.client_restart_lsn > first.client_restart_lsn)
    {
        (first, second)
    } else {
        (second, first)
    };
    if older.current_lsn != 0 && newer.current_lsn != 0 {
        let old_seq =
            lsn_sequence(older.current_lsn, older.seq_num_bits).map_err(|err| parse_err(&err))?;
        let new_seq =
            lsn_sequence(newer.current_lsn, newer.seq_num_bits).map_err(|err| parse_err(&err))?;
        if new_seq < old_seq || new_seq - old_seq > 1 {
            return Err(corrupt(0, "RSTR wrap sequence jump exceeds 1"));
        }
    }
    if newer.oldest_lsn != 0 && older.oldest_lsn > newer.oldest_lsn {
        return Err(corrupt(0, "RSTR oldest_lsn moved backwards"));
    }
    Ok(newer.clone())
}

fn validate_supported_opcode(op: NtfsLogOp, is_undo: bool) -> Result<()> {
    match op {
        NtfsLogOp::CompensationLogRecord => {
            if is_undo {
                Ok(())
            } else {
                Err(corrupt(
                    0,
                    "CompensationLogRecord must appear in undo_op, not redo_op",
                ))
            }
        }
        NtfsLogOp::Noop
        | NtfsLogOp::InitializeFileRecordSegment
        | NtfsLogOp::DeallocateFileRecordSegment
        | NtfsLogOp::WriteEndOfFileRecordSegment
        | NtfsLogOp::CreateAttribute
        | NtfsLogOp::DeleteAttribute
        | NtfsLogOp::UpdateResidentValue
        | NtfsLogOp::UpdateMappingPairs
        | NtfsLogOp::SetNewAttributeSizes
        | NtfsLogOp::AddIndexEntryRoot
        | NtfsLogOp::DeleteIndexEntryRoot
        | NtfsLogOp::SetIndexEntryVcnRoot
        | NtfsLogOp::UpdateFileNameRoot
        | NtfsLogOp::AddIndexEntryAllocation
        | NtfsLogOp::DeleteIndexEntryAllocation
        | NtfsLogOp::WriteEndOfIndexBuffer
        | NtfsLogOp::SetIndexEntryVcnAllocation
        | NtfsLogOp::UpdateFileNameAllocation
        | NtfsLogOp::SetBitsInNonresidentBitMap
        | NtfsLogOp::ClearBitsInNonresidentBitMap => Ok(()),
        NtfsLogOp::EndTopLevelAction
        | NtfsLogOp::PrepareTransaction
        | NtfsLogOp::CommitTransaction
        | NtfsLogOp::ForgetTransaction
        | NtfsLogOp::OpenNonresidentAttribute
        | NtfsLogOp::OpenAttributeTableDump
        | NtfsLogOp::AttributeNamesDump
        | NtfsLogOp::DirtyPageTableDump
        | NtfsLogOp::TransactionTableDump => {
            if is_undo {
                Err(corrupt(0, "administrative opcode cannot be an undo action"))
            } else {
                Ok(())
            }
        }
        other => Err(unsupported(format!(
            "NTFS recovery refuses unsupported native opcode {other:?}"
        ))),
    }
}

fn decode_client_record(raw: &RawLfsRecord) -> Result<ClientRecord> {
    let data = &raw.payload;
    if data.len() < 40 || raw.transaction_id == 0 {
        return Err(corrupt(raw.lsn, "truncated or zero-tx LFS_CLIENT_RECORD"));
    }
    let redo_op = NtfsLogOp::from_raw(le16(data, 0)?);
    let undo_op = NtfsLogOp::from_raw(le16(data, 2)?);
    validate_supported_opcode(redo_op, false)?;
    validate_supported_opcode(undo_op, true)?;
    let redo_off = usize::from(le16(data, 4)?);
    let redo_len = usize::from(le16(data, 6)?);
    let undo_off = usize::from(le16(data, 8)?);
    let undo_len = usize::from(le16(data, 10)?);
    let target_attribute = le16(data, 12)?;
    let lcns_to_follow = usize::from(le16(data, 14)?);
    let record_offset = le16(data, 16)?;
    let attribute_offset = le16(data, 18)?;
    let cluster_block_offset = le16(data, 20)?;
    let target_vcn = le64(data, 24)?;
    let min_hdr = 32 + lcns_to_follow.max(1) * 8;
    if data.len() < min_hdr {
        return Err(corrupt(raw.lsn, "truncated client LCN array"));
    }
    let mut target_lcns = Vec::with_capacity(lcns_to_follow);
    for idx in 0..lcns_to_follow {
        let lcn = le64(data, 32 + idx * 8)?;
        if lcn == 0 || lcn > i64::MAX as u64 {
            return Err(corrupt(
                raw.lsn,
                "zero or negative physical LCN in client record",
            ));
        }
        target_lcns.push(lcn);
    }
    let redo_data = if redo_len == 0 {
        Vec::new()
    } else {
        if redo_off < min_hdr || !redo_off.is_multiple_of(8) || redo_off + redo_len > data.len() {
            return Err(corrupt(raw.lsn, "invalid redo_data slice"));
        }
        data[redo_off..redo_off + redo_len].to_vec()
    };
    let undo_data = if undo_len == 0 {
        Vec::new()
    } else {
        if undo_off < min_hdr || !undo_off.is_multiple_of(8) || undo_off + undo_len > data.len() {
            return Err(corrupt(raw.lsn, "invalid undo_data slice"));
        }
        data[undo_off..undo_off + undo_len].to_vec()
    };
    Ok(ClientRecord {
        lsn: raw.lsn,
        previous_lsn: raw.previous_lsn,
        undo_next_lsn: raw.undo_next_lsn,
        transaction_id: raw.transaction_id,
        redo_op,
        undo_op,
        target_attribute,
        record_offset,
        attribute_offset,
        cluster_block_offset,
        target_vcn,
        target_lcns,
        redo_data,
        undo_data,
    })
}

fn parse_restart_table_entries(
    bytes: &[u8],
    expected_entry_size: Option<u16>,
) -> Result<BTreeMap<u32, Vec<u8>>> {
    if bytes.len() < 24 {
        return Err(corrupt(0, "truncated RESTART_TABLE"));
    }
    let entry_size = le16(bytes, 0)?;
    if let Some(exp) = expected_entry_size
        && entry_size != exp
    {
        return Err(corrupt(0, "RESTART_TABLE entry_size mismatch"));
    }
    let entry_len = usize::from(entry_size);
    if entry_len < 8 || !entry_len.is_multiple_of(8) {
        return Err(corrupt(0, "invalid RESTART_TABLE entry alignment"));
    }
    let count = usize::from(le16(bytes, 2)?);
    if 24 + count * entry_len > bytes.len() {
        return Err(corrupt(0, "RESTART_TABLE exceeds payload"));
    }
    let mut map = BTreeMap::new();
    for idx in 0..count {
        let off = 24 + idx * entry_len;
        let state = le32(bytes, off)?;
        if state == u32::MAX {
            map.insert(
                u32::try_from(off).unwrap_or(0),
                bytes[off..off + entry_len].to_vec(),
            );
        }
    }
    Ok(map)
}

struct StagedSectorBuffer<'a> {
    base: &'a Arc<dyn ByteDevice>,
    length: u64,
    sectors: BTreeMap<u64, [u8; SECTOR_BYTES]>,
}

impl<'a> StagedSectorBuffer<'a> {
    fn new(base: &'a Arc<dyn ByteDevice>, length: u64) -> Self {
        Self {
            base,
            length,
            sectors: BTreeMap::new(),
        }
    }

    fn read(&self, cx: &Cx, offset: u64, out: &mut [u8]) -> Result<()> {
        if out.is_empty() {
            return Ok(());
        }
        let end = offset
            .checked_add(out.len() as u64)
            .filter(|&e| e <= self.length)
            .ok_or_else(|| corrupt(offset, "staged read exceeds volume"))?;
        let first_sec = offset / (SECTOR_BYTES as u64);
        let last_sec = (end - 1) / (SECTOR_BYTES as u64);
        for sec in first_sec..=last_sec {
            let sec_start = sec * (SECTOR_BYTES as u64);
            let start = offset.max(sec_start);
            let stop = end.min(sec_start + SECTOR_BYTES as u64);
            let dst = &mut out[(start - offset) as usize..(stop - offset) as usize];
            let within = (start - sec_start) as usize;
            if let Some(patch) = self.sectors.get(&sec) {
                dst.copy_from_slice(&patch[within..within + dst.len()]);
            } else {
                self.base.read_exact_at(cx, ByteOffset(start), dst)?;
            }
        }
        Ok(())
    }

    fn write(&mut self, cx: &Cx, offset: u64, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let end = offset
            .checked_add(data.len() as u64)
            .filter(|&e| e <= self.length)
            .ok_or_else(|| corrupt(offset, "staged write exceeds volume"))?;
        let first_sec = offset / (SECTOR_BYTES as u64);
        let last_sec = (end - 1) / (SECTOR_BYTES as u64);
        for sec in first_sec..=last_sec {
            let sec_start = sec * (SECTOR_BYTES as u64);
            let sec_end = self.length.min(sec_start + SECTOR_BYTES as u64);
            let start = offset.max(sec_start);
            let stop = end.min(sec_end);
            let mut patch = [0_u8; SECTOR_BYTES];
            if start != sec_start || stop != sec_end {
                if let Some(prev) = self.sectors.get(&sec) {
                    patch.copy_from_slice(prev);
                } else {
                    let valid = (sec_end - sec_start) as usize;
                    self.base
                        .read_exact_at(cx, ByteOffset(sec_start), &mut patch[..valid])?;
                }
            }
            let within = (start - sec_start) as usize;
            let src_off = (start - offset) as usize;
            let len = (stop - start) as usize;
            patch[within..within + len].copy_from_slice(&data[src_off..src_off + len]);
            self.sectors.insert(sec, patch);
        }
        Ok(())
    }

    fn coalesced_ranges(&self) -> Vec<(u64, Vec<u8>)> {
        let mut ranges: Vec<(u64, Vec<u8>)> = Vec::new();
        for (&sec, bytes) in &self.sectors {
            let offset = sec * (SECTOR_BYTES as u64);
            let valid = (self.length.saturating_sub(offset)).min(SECTOR_BYTES as u64) as usize;
            if let Some(last) = ranges.last_mut()
                && last.0 + last.1.len() as u64 == offset
            {
                last.1.extend_from_slice(&bytes[..valid]);
            } else {
                ranges.push((offset, bytes[..valid].to_vec()));
            }
        }
        ranges
    }
}

struct PreviewDevice {
    base: Arc<dyn ByteDevice>,
    length: u64,
    sectors: BTreeMap<u64, [u8; SECTOR_BYTES]>,
}

impl ByteDevice for PreviewDevice {
    fn len_bytes(&self) -> u64 {
        self.length
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        let view = StagedSectorBuffer {
            base: &self.base,
            length: self.length,
            sectors: self.sectors.clone(),
        };
        view.read(cx, offset.0, buf)
    }

    fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _buf: &[u8]) -> Result<()> {
        Err(FfsError::ReadOnly)
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        checkpoint(cx)
    }
}

impl NtfsTransactionEngine {
    pub(super) fn inspect_log_state(&self, cx: &Cx) -> Result<NtfsLogStateSummary> {
        checkpoint(cx)?;
        let prefix = self.read_logfile(cx, 0, SECTOR_BYTES)?;
        if prefix.iter().all(|&b| b == 0xFF) {
            if self.logfile_bytes > MAX_ERASED_LOG_BYTES {
                return Err(unsupported("erased $LogFile scan exceeds 64 MiB"));
            }
            let mut off = SECTOR_BYTES as u64;
            while off < self.logfile_bytes {
                checkpoint(cx)?;
                let chunk = (self.logfile_bytes - off).min(65_536) as usize;
                let data = self.read_logfile(cx, off, chunk)?;
                if data.iter().any(|&b| b != 0xFF) {
                    return Err(corrupt(off, "partially erased $LogFile"));
                }
                off += chunk as u64;
            }
            return Ok(NtfsLogStateSummary {
                erased: true,
                clean: true,
                version: (1, 1),
                page_size: LOG_PAGE_BYTES,
                file_size: self.logfile_bytes,
                oldest_lsn: 0,
                current_lsn: 0,
                client_restart_lsn: 0,
                torn_rstr_slot: None,
            });
        }

        let r0_raw = self.read_logfile(cx, 0, LOG_PAGE_BYTES as usize)?;
        let r1_raw = self.read_logfile(cx, u64::from(LOG_PAGE_BYTES), LOG_PAGE_BYTES as usize)?;
        let p0 = parse_rstr_slot(0, &r0_raw, self.logfile_bytes);
        let p1 = parse_rstr_slot(1, &r1_raw, self.logfile_bytes);
        match (p0, p1) {
            (Ok(a), Ok(b)) => {
                let chosen = choose_comparable_rstr(&a, &b)?;
                Ok(NtfsLogStateSummary {
                    erased: false,
                    clean: chosen.clean,
                    version: chosen.version,
                    page_size: chosen.page_size,
                    file_size: chosen.file_size,
                    oldest_lsn: chosen.oldest_lsn,
                    current_lsn: chosen.current_lsn,
                    client_restart_lsn: chosen.client_restart_lsn,
                    torn_rstr_slot: None,
                })
            }
            (Ok(valid), Err(_)) => Ok(NtfsLogStateSummary {
                erased: false,
                clean: false,
                version: valid.version,
                page_size: valid.page_size,
                file_size: valid.file_size,
                oldest_lsn: valid.oldest_lsn,
                current_lsn: valid.current_lsn,
                client_restart_lsn: valid.client_restart_lsn,
                torn_rstr_slot: Some(1),
            }),
            (Err(_), Ok(valid)) => Ok(NtfsLogStateSummary {
                erased: false,
                clean: false,
                version: valid.version,
                page_size: valid.page_size,
                file_size: valid.file_size,
                oldest_lsn: valid.oldest_lsn,
                current_lsn: valid.current_lsn,
                client_restart_lsn: valid.client_restart_lsn,
                torn_rstr_slot: Some(0),
            }),
            (Err(e0), Err(_)) => Err(e0),
        }
    }

    pub(super) fn load_clean_ring_if_present(&mut self, cx: &Cx) -> Result<()> {
        let state = self.inspect_log_state(cx)?;
        if state.erased || !state.clean || state.torn_rstr_slot.is_some() {
            return Ok(());
        }
        let r0_raw = self.read_logfile(cx, 0, state.page_size as usize)?;
        let r1_raw = self.read_logfile(cx, u64::from(state.page_size), state.page_size as usize)?;
        let chosen = choose_comparable_rstr(
            &parse_rstr_slot(0, &r0_raw, self.logfile_bytes)?,
            &parse_rstr_slot(1, &r1_raw, self.logfile_bytes)?,
        )?;
        let raw_cur_page = if chosen.current_lsn != 0 {
            let vbo = lsn_to_vbo(chosen.current_lsn, chosen.seq_num_bits)
                .map_err(|err| parse_err(&err))?;
            let page_vbo = vbo & !(u64::from(chosen.page_size) - 1);
            Some(self.read_logfile(cx, page_vbo, chosen.page_size as usize)?)
        } else {
            None
        };
        let ring = NtfsLogRingWriter::resume(
            chosen.page_size,
            chosen.version,
            chosen.file_size,
            chosen.client_seq,
            chosen.open_log_count.saturating_add(1),
            chosen.oldest_lsn,
            chosen.current_lsn,
            chosen.last_lsn_data_len,
            chosen.client_restart_lsn,
            raw_cur_page.as_deref(),
            chosen.slot ^ 1,
            chosen.usa_token,
        )
        .map_err(|err| parse_err(&err))?;
        if chosen.client_restart_lsn != 0 {
            let seeded = self.read_open_attrs_from_checkpoint(cx, &chosen)?;
            self.open_attrs = seeded;
        }
        self.ring = Some(ring);
        Ok(())
    }

    fn read_single_lfs_record(
        &self,
        cx: &Cx,
        rstr: &ParsedRestartPage,
        lsn: u64,
    ) -> Result<RawLfsRecord> {
        let vbo = lsn_to_vbo(lsn, rstr.seq_num_bits).map_err(|err| parse_err(&err))?;
        let page_bytes = u64::from(rstr.page_size);
        let page_vbo = vbo & !(page_bytes - 1);
        let rec_off = usize::try_from(vbo - page_vbo).map_err(|_| corrupt(vbo, "rec_off"))?;
        let raw_page = self.read_logfile(cx, page_vbo, rstr.page_size as usize)?;
        let page = restore_record(&raw_page, b"RCRD").map_err(|err| parse_err(&err))?;
        if rec_off < usize::from(rstr.data_off) || rec_off + 48 > page.len() {
            return Err(corrupt(vbo, "LFS record offset outside RCRD page"));
        }
        let this_lsn = le64(&page, rec_off)?;
        if this_lsn != lsn {
            return Err(corrupt(vbo, "LFS record LSN mismatch at target VBO"));
        }
        let prev_lsn = le64(&page, rec_off + 8)?;
        let undo_next = le64(&page, rec_off + 16)?;
        let data_len = usize::try_from(le32(&page, rec_off + 24)?)
            .map_err(|_| corrupt(vbo, "LFS data_len overflow"))?;
        let rec_type = le32(&page, rec_off + 32)?;
        let tx_id = le32(&page, rec_off + 36)?;
        let flags = le16(&page, rec_off + 40)?;
        if flags & 1 != 0 || rec_off + 48 + data_len > page.len() {
            return Err(unsupported(
                "multi-page LFS records are outside admitted single-page profile",
            ));
        }
        Ok(RawLfsRecord {
            lsn,
            previous_lsn: prev_lsn,
            undo_next_lsn: undo_next,
            record_type: rec_type,
            transaction_id: tx_id,
            payload: page[rec_off + 48..rec_off + 48 + data_len].to_vec(),
        })
    }

    fn read_open_attrs_from_checkpoint(
        &self,
        cx: &Cx,
        rstr: &ParsedRestartPage,
    ) -> Result<BTreeMap<u32, OpenAttrRuntime>> {
        let ckpt_rec = self.read_single_lfs_record(cx, rstr, rstr.client_restart_lsn)?;
        if ckpt_rec.record_type != LFS_CLIENT_RESTART || ckpt_rec.payload.len() < 64 {
            return Err(corrupt(
                rstr.client_restart_lsn,
                "invalid LFS_CLIENT_RESTART record",
            ));
        }
        let open_lsn = le64(&ckpt_rec.payload, 16)?;
        let names_lsn = le64(&ckpt_rec.payload, 24)?;
        let expected_open_bytes = usize::try_from(le32(&ckpt_rec.payload, 48)?)
            .map_err(|_| corrupt(rstr.client_restart_lsn, "open_attribute_table_len overflow"))?;
        let expected_names_bytes = usize::try_from(le32(&ckpt_rec.payload, 52)?)
            .map_err(|_| corrupt(rstr.client_restart_lsn, "attribute_names_len overflow"))?;
        if (open_lsn == 0) != (expected_open_bytes == 0)
            || (names_lsn == 0) != (expected_names_bytes == 0)
        {
            return Err(corrupt(
                rstr.client_restart_lsn,
                "unpaired $LogFile checkpoint dump LSN and length",
            ));
        }
        let mut attrs = BTreeMap::new();
        if open_lsn != 0 {
            let dump_raw = self.read_single_lfs_record(cx, rstr, open_lsn)?;
            let dump_client = decode_client_record(&dump_raw)?;
            if dump_client.redo_op != NtfsLogOp::OpenAttributeTableDump
                || dump_client.redo_data.len() != expected_open_bytes
            {
                return Err(corrupt(
                    open_lsn,
                    "expected OpenAttributeTableDump matching checkpoint length",
                ));
            }
            for (slot, entry) in parse_restart_table_entries(&dump_client.redo_data, Some(40))? {
                let index_bytes = le32(&entry, 4)?;
                let kind = le32(&entry, 8)?;
                let reference_raw = le64(&entry, 16)?;
                let opened_lsn = le64(&entry, 24)?;
                attrs.insert(
                    slot,
                    OpenAttrRuntime {
                        reference_raw,
                        kind,
                        name: Vec::new(),
                        index_bytes,
                        opened_lsn,
                    },
                );
            }
        }
        if names_lsn != 0 {
            let names_raw = self.read_single_lfs_record(cx, rstr, names_lsn)?;
            let names_client = decode_client_record(&names_raw)?;
            if names_client.redo_op != NtfsLogOp::AttributeNamesDump
                || names_client.redo_data.len() != expected_names_bytes
            {
                return Err(corrupt(
                    names_lsn,
                    "expected AttributeNamesDump matching checkpoint length",
                ));
            }
            let buf = &names_client.redo_data;
            let mut pos = 0_usize;
            while pos + 4 <= buf.len() {
                let slot = u32::from(le16(buf, pos)?);
                let byte_len = usize::from(le16(buf, pos + 2)?);
                pos += 4;
                if slot == 0 && byte_len == 0 {
                    break;
                }
                if !byte_len.is_multiple_of(2) || pos + byte_len > buf.len() {
                    return Err(corrupt(names_lsn, "truncated AttributeNamesDump entry"));
                }
                let units: Vec<u16> = buf[pos..pos + byte_len]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|&[lo, hi]| u16::from_le_bytes([lo, hi]))
                    .collect();
                if let Some(entry) = attrs.get_mut(&slot) {
                    entry.name = units;
                }
                pos += byte_len;
            }
        }
        Ok(attrs)
    }

    fn discover_ring_tail(&self, cx: &Cx, rstr: &mut ParsedRestartPage) -> Result<()> {
        if rstr.current_lsn == 0 {
            return Ok(());
        }
        let page_bytes = u64::from(rstr.page_size);
        let reserved = if rstr.version.0 >= 2 { 34_u64 } else { 4_u64 };
        let total_pages = rstr.file_size / page_bytes;
        if total_pages <= reserved || total_pages > 16_384 {
            return Err(unsupported(
                "$LogFile ring geometry exceeds bounded tail-discovery scan",
            ));
        }
        let oldest = if rstr.oldest_lsn != 0 {
            rstr.oldest_lsn
        } else {
            rstr.current_lsn
        };
        let address_bits = 64 - rstr.seq_num_bits;
        let base_seq = rstr.current_lsn >> address_bits;
        let old_seq = oldest >> address_bits;
        let old_vbo = lsn_to_vbo(oldest, rstr.seq_num_bits).map_err(|err| parse_err(&err))?;

        let mut max_started = rstr.current_lsn;
        let mut max_completed = rstr.current_lsn;

        for number in reserved..total_pages {
            checkpoint(cx)?;
            let at = number * page_bytes;
            let raw = self.read_logfile(cx, at, rstr.page_size as usize)?;
            if raw.iter().all(|&b| b == 0xFF) || raw.iter().all(|&b| b == 0) {
                continue;
            }
            let fixed = restore_record(&raw, b"RCRD").map_err(|err| parse_err(&err))?;
            let last = le64(&fixed, 8)?;
            let flags = le32(&fixed, 16)?;
            let completed = if flags & 1 != 0 { le64(&fixed, 32)? } else { 0 };
            if last == 0 || completed > last {
                return Err(corrupt(at, "invalid RCRD tail completion markers"));
            }
            if last < oldest && completed < oldest {
                continue;
            }
            let obs_seq = last >> address_bits;
            if obs_seq > base_seq && obs_seq - base_seq > 1 {
                return Err(unsupported(
                    "$LogFile tail generations exceed one ring wrap",
                ));
            }
            max_started = max_started.max(last);
            max_completed = max_completed.max(completed);
        }

        if max_started > max_completed {
            return Err(unsupported(
                "$LogFile has an incomplete multi-page tail record; refusing partial salvage",
            ));
        }
        if max_completed > rstr.current_lsn {
            let end_seq = max_completed >> address_bits;
            let end_vbo =
                lsn_to_vbo(max_completed, rstr.seq_num_bits).map_err(|err| parse_err(&err))?;
            if end_seq < old_seq
                || end_seq - old_seq > 1
                || (end_seq != old_seq && end_vbo >= old_vbo)
            {
                return Err(unsupported(
                    "$LogFile tail has overwritten or outlived the retained window",
                ));
            }
            let end_page_vbo = end_vbo & !(page_bytes - 1);
            let within = usize::try_from(end_vbo - end_page_vbo)
                .map_err(|_| corrupt(end_page_vbo, "tail record offset overflow"))?;
            let raw_end = self.read_logfile(cx, end_page_vbo, rstr.page_size as usize)?;
            let fixed_end = restore_record(&raw_end, b"RCRD").map_err(|err| parse_err(&err))?;
            if within < usize::from(rstr.data_off)
                || within + 48 > fixed_end.len()
                || le64(&fixed_end, within)? != max_completed
            {
                return Err(corrupt(
                    end_page_vbo,
                    "RCRD tail marker does not identify its claimed record",
                ));
            }
            rstr.current_lsn = max_completed;
            rstr.last_lsn_data_len = le32(&fixed_end, within + 24)?;
        }
        Ok(())
    }

    fn scan_active_rcrd_window(
        &self,
        cx: &Cx,
        rstr: &ParsedRestartPage,
        start_lsn: u64,
    ) -> Result<Vec<RawLfsRecord>> {
        if rstr.current_lsn == 0 || start_lsn == 0 || start_lsn > rstr.current_lsn {
            return Ok(Vec::new());
        }
        let page_bytes = u64::from(rstr.page_size);
        let reserved = if rstr.version.0 >= 2 { 34_u64 } else { 4_u64 };
        let first_ring_vbo = reserved * page_bytes;
        let start_vbo = lsn_to_vbo(start_lsn, rstr.seq_num_bits).map_err(|err| parse_err(&err))?;
        let end_vbo =
            lsn_to_vbo(rstr.current_lsn, rstr.seq_num_bits).map_err(|err| parse_err(&err))?;
        let mut page_vbo = start_vbo & !(page_bytes - 1);
        let end_page_vbo = end_vbo & !(page_bytes - 1);
        let max_pages = ((rstr.file_size - first_ring_vbo) / page_bytes) as usize + 2;

        let mut records = Vec::new();
        let mut prev_lsn = 0_u64;
        for _ in 0..max_pages {
            checkpoint(cx)?;
            let raw_page = self.read_logfile(cx, page_vbo, rstr.page_size as usize)?;
            let page = restore_record(&raw_page, b"RCRD").map_err(|err| parse_err(&err))?;
            let next_off = usize::from(le16(&page, 24)?);
            if next_off < usize::from(rstr.data_off) || next_off > page.len() {
                return Err(corrupt(page_vbo, "invalid RCRD next_record_off"));
            }
            let mut pos = usize::from(rstr.data_off);
            while pos + 48 <= next_off {
                let this_lsn = le64(&page, pos)?;
                if this_lsn == 0 {
                    break;
                }
                let prev = le64(&page, pos + 8)?;
                let undo_next = le64(&page, pos + 16)?;
                let data_len = usize::try_from(le32(&page, pos + 24)?)
                    .map_err(|_| corrupt(page_vbo, "RCRD data_len overflow"))?;
                let rec_type = le32(&page, pos + 32)?;
                let tx_id = le32(&page, pos + 36)?;
                let flags = le16(&page, pos + 40)?;
                let aligned = (48 + data_len + 7) & !7;
                if flags & 1 != 0 || pos + 48 + data_len > next_off {
                    return Err(corrupt(page_vbo, "corrupt or multi-page RCRD record"));
                }
                if this_lsn >= start_lsn && this_lsn <= rstr.current_lsn {
                    if prev_lsn != 0 && this_lsn <= prev_lsn {
                        return Err(corrupt(page_vbo, "non-monotonic LSN in RCRD scan"));
                    }
                    prev_lsn = this_lsn;
                    records.push(RawLfsRecord {
                        lsn: this_lsn,
                        previous_lsn: prev,
                        undo_next_lsn: undo_next,
                        record_type: rec_type,
                        transaction_id: tx_id,
                        payload: page[pos + 48..pos + 48 + data_len].to_vec(),
                    });
                }
                pos += aligned.max(48);
                if this_lsn == rstr.current_lsn {
                    if data_len as u32 != rstr.last_lsn_data_len {
                        return Err(corrupt(
                            page_vbo,
                            "current_lsn data_len disagrees with RSTR last_lsn_data_len",
                        ));
                    }
                    return Ok(records);
                }
            }
            if page_vbo == end_page_vbo && prev_lsn >= rstr.current_lsn {
                break;
            }
            page_vbo += page_bytes;
            if page_vbo >= rstr.file_size {
                page_vbo = first_ring_vbo;
            }
        }
        Err(corrupt(
            rstr.current_lsn,
            "RCRD ring scan did not reach RSTR current_lsn",
        ))
    }

    /// Run persistent ARIES recovery (`Analysis -> Winner Redo -> Reverse-LSN Loser Undo ->
    /// CLRs -> $MFTMirr sync -> Clean Checkpoint + Dual Clean RSTR`), refusing fail-closed
    /// before any write if unknown opcodes, torn `RCRD` records, or invalid targets are present.
    pub fn recover_in_place(&mut self, cx: &Cx) -> Result<NtfsRecoverySummary> {
        checkpoint(cx)?;
        self.recovery_required = true;
        let (vol_flags, _, _) = self.read_volume_status_and_mft_counts(cx)?;
        let log_state = self.inspect_log_state(cx)?;
        if log_state.clean && log_state.torn_rstr_slot.is_none() && (vol_flags & 0x0001 == 0) {
            // A prior failure can leave clean bytes visible but not durable.
            // Revalidate and synchronize before clearing the sticky guard.
            self.check_clean_consistency(cx)?;
            self.device.sync(cx)?;
            self.load_clean_ring_if_present(cx)?;
            self.recovery_required = false;
            return Ok(NtfsRecoverySummary::default());
        }
        if log_state.erased {
            return Err(corrupt(
                0,
                "NTFS volume dirty bit is set while $LogFile is completely erased; refusing to guess",
            ));
        }

        // Select the authoritative RSTR page (allowing at most one USA-torn RSTR slot).
        let r0_raw = self.read_logfile(cx, 0, log_state.page_size as usize)?;
        let r1_raw = self.read_logfile(
            cx,
            u64::from(log_state.page_size),
            log_state.page_size as usize,
        )?;
        let (mut selected, healed_slot) = match (
            parse_rstr_slot(0, &r0_raw, self.logfile_bytes),
            parse_rstr_slot(1, &r1_raw, self.logfile_bytes),
        ) {
            (Ok(a), Ok(b)) => (choose_comparable_rstr(&a, &b)?, None),
            (Ok(a), Err(_)) => (a, Some(1)),
            (Err(_), Ok(b)) => (b, Some(0)),
            (Err(e), Err(_)) => return Err(e),
        };

        // Discover complete USA-valid RCRD tail records appended after the RSTR checkpoint.
        self.discover_ring_tail(cx, &mut selected)?;

        // Seed OpenAttributeTable & TransactionTable from checkpoint if present.
        let mut open_attrs = if selected.client_restart_lsn != 0 {
            self.read_open_attrs_from_checkpoint(cx, &selected)?
        } else {
            BTreeMap::new()
        };
        let mut tx_table: BTreeMap<u32, TxRuntime> = BTreeMap::new();
        let mut scan_start = selected.oldest_lsn;
        if selected.client_restart_lsn != 0 {
            let ckpt_rec =
                self.read_single_lfs_record(cx, &selected, selected.client_restart_lsn)?;
            let start_ckpt = le64(&ckpt_rec.payload, 8)?;
            let tx_dump_lsn = le64(&ckpt_rec.payload, 40)?;
            if tx_dump_lsn != 0 {
                let tx_raw = self.read_single_lfs_record(cx, &selected, tx_dump_lsn)?;
                let tx_client = decode_client_record(&tx_raw)?;
                for (slot, entry) in parse_restart_table_entries(&tx_client.redo_data, Some(40))? {
                    let st = match entry[4] {
                        1 => TxState::Active,
                        2 => TxState::Prepared,
                        3 => TxState::Committed,
                        _ => return Err(corrupt(tx_dump_lsn, "unknown TRANSACTION_ENTRY state")),
                    };
                    tx_table.insert(
                        slot,
                        TxRuntime {
                            state: st,
                            first_lsn: le64(&entry, 8)?,
                            last_lsn: le64(&entry, 16)?,
                            undo_next_lsn: le64(&entry, 24)?,
                        },
                    );
                }
            }
            let anchor = if start_ckpt != 0 {
                start_ckpt
            } else {
                selected.client_restart_lsn
            };
            scan_start = if scan_start == 0 {
                anchor
            } else {
                scan_start.min(anchor)
            };
        }

        let raw_records = if selected.current_lsn != 0 && scan_start != 0 {
            self.scan_active_rcrd_window(cx, &selected, scan_start)?
        } else {
            Vec::new()
        };

        // Analysis pass over client records.
        let mut client_by_lsn: BTreeMap<u64, ClientRecord> = BTreeMap::new();
        let mut committed_lifetimes: BTreeSet<(u32, u64)> = BTreeSet::new();
        let mut record_first_lsn: BTreeMap<u64, u64> = BTreeMap::new();

        for raw in &raw_records {
            if raw.record_type == LFS_CLIENT_RESTART {
                continue;
            }
            if raw.record_type != LFS_RECORD_CLIENT {
                return Err(unsupported("unknown LFS record_type in recovery scan"));
            }
            let client = decode_client_record(raw)?;
            if client.redo_op == NtfsLogOp::OpenNonresidentAttribute {
                if client.redo_data.len() != 40 || !client.undo_data.len().is_multiple_of(2) {
                    return Err(corrupt(
                        client.lsn,
                        "invalid OpenNonresidentAttribute payload",
                    ));
                }
                let slot = u32::from(client.target_attribute);
                let name: Vec<u16> = client
                    .undo_data
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|&[lo, hi]| u16::from_le_bytes([lo, hi]))
                    .collect();
                open_attrs.insert(
                    slot,
                    OpenAttrRuntime {
                        reference_raw: le64(&client.redo_data, 16)?,
                        kind: le32(&client.redo_data, 8)?,
                        name,
                        index_bytes: le32(&client.redo_data, 4)?,
                        opened_lsn: client.lsn,
                    },
                );
            }

            let tx_id = client.transaction_id;
            if let std::collections::btree_map::Entry::Vacant(vacant) = tx_table.entry(tx_id) {
                if client.previous_lsn != 0 && scan_start <= client.previous_lsn {
                    return Err(corrupt(
                        client.lsn,
                        "transaction record references missing predecessor",
                    ));
                }
                vacant.insert(TxRuntime {
                    state: TxState::Active,
                    first_lsn: client.lsn,
                    last_lsn: 0,
                    undo_next_lsn: 0,
                });
            }
            let first_lsn = tx_table[&tx_id].first_lsn;
            record_first_lsn.insert(client.lsn, first_lsn);

            if client.redo_op == NtfsLogOp::ForgetTransaction {
                tx_table.remove(&tx_id);
                client_by_lsn.insert(client.lsn, client);
                continue;
            }

            let tx = tx_table
                .get_mut(&tx_id)
                .ok_or_else(|| corrupt(client.lsn, "missing tx slot"))?;
            tx.last_lsn = client.lsn;
            tx.undo_next_lsn = if client.undo_op == NtfsLogOp::CompensationLogRecord
                || client.redo_op == NtfsLogOp::EndTopLevelAction
            {
                client.undo_next_lsn
            } else {
                client.lsn
            };
            match client.redo_op {
                NtfsLogOp::PrepareTransaction => tx.state = TxState::Prepared,
                NtfsLogOp::CommitTransaction => {
                    tx.state = TxState::Committed;
                    committed_lifetimes.insert((tx_id, first_lsn));
                }
                _ => {}
            }
            client_by_lsn.insert(client.lsn, client);
        }

        // Refuse in-doubt Prepared transactions; collect Active losers.
        let mut undone_losers = Vec::new();
        let mut undo_heap: BinaryHeap<(u64, u32, u64)> = BinaryHeap::new();
        for (&tx_id, tx) in &tx_table {
            match tx.state {
                TxState::Prepared => {
                    return Err(unsupported(
                        "NTFS $LogFile contains an in-doubt Prepared transaction requiring external coordinator decision",
                    ));
                }
                TxState::Active => {
                    undone_losers.push(tx_id);
                    if tx.undo_next_lsn != 0 {
                        undo_heap.push((tx.undo_next_lsn, tx_id, tx.first_lsn));
                    }
                }
                TxState::Committed => {
                    committed_lifetimes.insert((tx_id, tx.first_lsn));
                }
            }
        }
        undone_losers.sort_unstable();
        let mut committed_winners: Vec<u32> =
            committed_lifetimes.iter().map(|&(id, _)| id).collect();
        committed_winners.sort_unstable();
        committed_winners.dedup();

        // Construct in-memory ring writer up front so CLRs allocate real monotonic LSNs
        // BEFORE any disk write occurs!
        let cur_rcrd_page = if selected.current_lsn != 0 {
            let vbo = lsn_to_vbo(selected.current_lsn, selected.seq_num_bits)
                .map_err(|err| parse_err(&err))?;
            let page_vbo = vbo & !(u64::from(selected.page_size) - 1);
            Some(self.read_logfile(cx, page_vbo, selected.page_size as usize)?)
        } else {
            None
        };
        let mut ring = NtfsLogRingWriter::resume(
            selected.page_size,
            selected.version,
            selected.file_size,
            selected.client_seq,
            selected.open_log_count.saturating_add(1),
            selected.oldest_lsn,
            selected.current_lsn,
            selected.last_lsn_data_len,
            selected.client_restart_lsn,
            cur_rcrd_page.as_deref(),
            healed_slot.unwrap_or(selected.slot ^ 1),
            selected.usa_token,
        )
        .map_err(|err| parse_err(&err))?;

        // ARIES Repeat-History Redo pass: stage ALL logged data mutations (winners, losers,
        // and prior CLRs) in chronological LSN order in private memory BEFORE Undo!
        let mut staged = StagedSectorBuffer::new(&self.device, self.geometry.volume_bytes());
        let mut redo_applied = 0_usize;
        let _ = &record_first_lsn;
        for (&lsn, rec) in &client_by_lsn {
            if !is_data_mutation_op(rec.redo_op) {
                continue;
            }
            if self.apply_logged_action_to_stage(
                cx,
                &mut staged,
                &open_attrs,
                rec,
                false,
                RecoveryPass::Redo(lsn),
            )? {
                redo_applied += 1;
            }
        }

        // ARIES Reverse-LSN Loser Undo pass + Compensation Log Record generation in memory.
        let mut undo_applied = 0_usize;
        let mut clr_written = 0_usize;
        let mut log_pages: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        let mut last_logged_lsn = selected.current_lsn;
        let mut visited_undo = BTreeSet::new();
        while let Some((undo_lsn, tx_id, first_lsn)) = undo_heap.pop() {
            checkpoint(cx)?;
            if !visited_undo.insert(undo_lsn) {
                return Err(corrupt(undo_lsn, "cycle in $LogFile undo_next_lsn chain"));
            }
            let rec = client_by_lsn.get(&undo_lsn).ok_or_else(|| {
                corrupt(
                    undo_lsn,
                    "active loser undo_next_lsn precedes retained log window",
                )
            })?;
            if rec.transaction_id != tx_id || undo_lsn < first_lsn {
                return Err(corrupt(undo_lsn, "undo chain crossed transaction lifetime"));
            }
            if rec.undo_op != NtfsLogOp::CompensationLogRecord
                && rec.redo_op != NtfsLogOp::EndTopLevelAction
                && is_data_mutation_op(rec.undo_op)
            {
                let clr_spec = NtfsClientUpdateSpec {
                    redo_op: rec.undo_op,
                    undo_op: NtfsLogOp::CompensationLogRecord,
                    target_attribute: rec.target_attribute,
                    record_offset: rec.record_offset,
                    attribute_offset: rec.attribute_offset,
                    cluster_block_offset: rec.cluster_block_offset,
                    target_vcn: rec.target_vcn,
                    target_lcns: rec.target_lcns.clone(),
                    redo_data: rec.undo_data.clone(),
                    undo_data: Vec::new(),
                };
                let prev = tx_table.get(&tx_id).map_or(0, |t| t.last_lsn);
                let payload =
                    encode_client_update_payload(&clr_spec).map_err(|err| parse_err(&err))?;
                let clr_rec = ring
                    .append_raw_record(LFS_RECORD_CLIENT, tx_id, prev, rec.undo_next_lsn, &payload)
                    .map_err(|err| map_ring_err(&err))?;
                if let Some(t) = tx_table.get_mut(&tx_id) {
                    t.last_lsn = clr_rec.lsn;
                }
                last_logged_lsn = clr_rec.lsn;
                log_pages.insert(clr_rec.page_vbo, clr_rec.protected_page);
                clr_written += 1;

                // Stamp the undone page with clr_rec.lsn so any post-TargetMetadataWrite crash
                // makes both the original loser record and this CLR idempotent on restart!
                if self.apply_logged_action_to_stage(
                    cx,
                    &mut staged,
                    &open_attrs,
                    rec,
                    true,
                    RecoveryPass::Redo(clr_rec.lsn),
                )? {
                    undo_applied += 1;
                }
            }
            if rec.undo_next_lsn != 0 {
                undo_heap.push((rec.undo_next_lsn, tx_id, first_lsn));
            }
        }

        // Sync $MFTMirr (records 0..mirrored_count) and clear $Volume dirty bit (0x0001) in staged buffer.
        self.sync_mft_mirror_and_clear_dirty_in_stage(cx, &mut staged)?;

        // Preview-check complete consistency BEFORE writing a single byte to disk!
        self.verify_staged_preview_consistency(cx, &staged, &selected)?;
        let coalesced_ranges = staged.coalesced_ranges();
        drop(staged);

        // Phase 2: Persist recovery in strict barrier order.
        // If one RSTR slot was torn, heal that slot first with the validated dirty state!
        if let Some(torn_slot) = healed_slot {
            let heal_cfg = NtfsRestartConfig {
                page_size: selected.page_size,
                version: selected.version,
                clean: false,
                current_lsn: selected.current_lsn,
                last_lsn_data_len: selected.last_lsn_data_len,
                file_size: selected.file_size,
                open_log_count: selected.open_log_count,
                client_seq: selected.client_seq,
                oldest_lsn: selected.oldest_lsn,
                client_restart_lsn: selected.client_restart_lsn,
                usa_token: next_usa_token(selected.usa_token),
            };
            let healed_bytes = encode_rstr_page(&heal_cfg).map_err(|err| parse_err(&err))?;
            self.write_logfile_page(
                cx,
                "recover_in_place",
                NtfsPersistenceStage::DirtyRestartWrite,
                0,
                selected.current_lsn,
                (torn_slot as u64) * u64::from(selected.page_size),
                &healed_bytes,
            )?;
            self.barrier(
                cx,
                "recover_in_place",
                NtfsPersistenceStage::DirtyRestartBarrier,
                0,
                selected.current_lsn,
            )?;
        }
        let forget_payload = encode_client_update_payload(&NtfsClientUpdateSpec {
            redo_op: NtfsLogOp::ForgetTransaction,
            undo_op: NtfsLogOp::Noop,
            target_attribute: 0,
            record_offset: 0,
            attribute_offset: 0,
            cluster_block_offset: 0,
            target_vcn: 0,
            target_lcns: Vec::new(),
            redo_data: Vec::new(),
            undo_data: Vec::new(),
        })
        .map_err(|err| parse_err(&err))?;
        let unresolved_ids: Vec<(u32, u64)> =
            tx_table.iter().map(|(&id, t)| (id, t.last_lsn)).collect();
        for (tx_id, prev_lsn) in unresolved_ids {
            let rec = ring
                .append_raw_record(LFS_RECORD_CLIENT, tx_id, prev_lsn, 0, &forget_payload)
                .map_err(|err| map_ring_err(&err))?;
            last_logged_lsn = rec.lsn;
            log_pages.insert(rec.page_vbo, rec.protected_page);
        }
        if !log_pages.is_empty() {
            for (vbo, bytes) in &log_pages {
                self.write_logfile_page(
                    cx,
                    "recover_in_place",
                    NtfsPersistenceStage::LogRecordWrite,
                    0,
                    last_logged_lsn,
                    *vbo,
                    bytes,
                )?;
            }
            self.barrier(
                cx,
                "recover_in_place",
                NtfsPersistenceStage::LogCommitBarrier,
                0,
                last_logged_lsn,
            )?;
        }

        // Write recovered target metadata and flush!
        for (off, data) in coalesced_ranges {
            self.write_volume(
                cx,
                "recover_in_place",
                NtfsPersistenceStage::TargetMetadataWrite,
                0,
                last_logged_lsn,
                off,
                &data,
            )?;
        }
        self.barrier(
            cx,
            "recover_in_place",
            NtfsPersistenceStage::TargetMetadataBarrier,
            0,
            last_logged_lsn,
        )?;

        self.open_attrs = open_attrs;
        self.ring = Some(ring);
        let final_ckpt_lsn = self.publish_clean_checkpoint_and_rstr(cx, "recover_in_place", 24)?;
        self.check_clean_consistency(cx)?;
        self.recovery_required = false;

        Ok(NtfsRecoverySummary {
            was_dirty: true,
            healed_torn_rstr_slot: healed_slot,
            committed_winners,
            undone_losers,
            redo_applied,
            undo_applied,
            clr_written,
            final_checkpoint_lsn: final_ckpt_lsn,
        })
    }

    fn apply_logged_action_to_stage(
        &self,
        cx: &Cx,
        staged: &mut StagedSectorBuffer<'_>,
        open_attrs: &BTreeMap<u32, OpenAttrRuntime>,
        rec: &ClientRecord,
        undo: bool,
        pass: RecoveryPass,
    ) -> Result<bool> {
        let op = if undo { rec.undo_op } else { rec.redo_op };
        let payload = if undo { &rec.undo_data } else { &rec.redo_data };
        if op == NtfsLogOp::Noop {
            return Ok(false);
        }
        let slot = u32::from(rec.target_attribute);
        let target_attr = open_attrs.get(&slot).ok_or_else(|| {
            corrupt(
                rec.lsn,
                "logged action references unopened target attribute slot",
            )
        })?;
        if rec.target_lcns.is_empty() {
            return Err(corrupt(rec.lsn, "logged action carries empty target_lcns"));
        }
        let cluster_bytes = u64::from(self.geometry.cluster_bytes());
        let span_bytes = (rec.target_lcns.len() as u64)
            .checked_mul(cluster_bytes)
            .ok_or_else(|| corrupt(rec.lsn, "target_lcns span overflow"))?;

        let read_transfer = |staged_buf: &StagedSectorBuffer<'_>| -> Result<Vec<u8>> {
            let mut buf = vec![0_u8; span_bytes as usize];
            for (idx, &lcn) in rec.target_lcns.iter().enumerate() {
                let phys = self
                    .geometry
                    .cluster_offset(lcn)
                    .map_err(|err| parse_err(&err))?;
                let at = idx * (cluster_bytes as usize);
                staged_buf.read(cx, phys, &mut buf[at..at + cluster_bytes as usize])?;
            }
            Ok(buf)
        };
        let write_transfer = |staged_buf: &mut StagedSectorBuffer<'_>, buf: &[u8]| -> Result<()> {
            for (idx, &lcn) in rec.target_lcns.iter().enumerate() {
                let phys = self
                    .geometry
                    .cluster_offset(lcn)
                    .map_err(|err| parse_err(&err))?;
                let at = idx * (cluster_bytes as usize);
                staged_buf.write(cx, phys, &buf[at..at + cluster_bytes as usize])?;
            }
            Ok(())
        };

        match op {
            NtfsLogOp::SetBitsInNonresidentBitMap | NtfsLogOp::ClearBitsInNonresidentBitMap => {
                if payload.len() != 8 {
                    return Err(corrupt(rec.lsn, "BITMAP_RANGE payload must be 8 bytes"));
                }
                let bit_off = le32(payload, 0)? as usize;
                let bit_count = le32(payload, 4)? as usize;
                let mut transfer = read_transfer(staged)?;
                let base_byte = usize::from(rec.cluster_block_offset) * SECTOR_BYTES;
                if base_byte > transfer.len()
                    || bit_off
                        .checked_add(bit_count)
                        .is_none_or(|end| end > (transfer.len() - base_byte) * 8)
                {
                    return Err(corrupt(rec.lsn, "BITMAP_RANGE exceeds target transfer"));
                }
                let set = op == NtfsLogOp::SetBitsInNonresidentBitMap;
                for b in bit_off..bit_off + bit_count {
                    let byte_idx = base_byte + (b / 8);
                    let mask = 1_u8 << (b % 8);
                    if set {
                        transfer[byte_idx] |= mask;
                    } else {
                        transfer[byte_idx] &= !mask;
                    }
                }
                write_transfer(staged, &transfer)?;
                Ok(true)
            }
            NtfsLogOp::AddIndexEntryAllocation
            | NtfsLogOp::DeleteIndexEntryAllocation
            | NtfsLogOp::WriteEndOfIndexBuffer
            | NtfsLogOp::SetIndexEntryVcnAllocation
            | NtfsLogOp::UpdateFileNameAllocation => {
                if target_attr.kind != 0xA0 || target_attr.name != I30_NAME {
                    return Err(corrupt(rec.lsn, "INDX action targets non-$I30 attribute"));
                }
                let owner_ref = NtfsReference::decode(target_attr.reference_raw);
                let mft0_raw = self.read_record_from_stage(cx, staged, 0)?;
                let mft0 = NtfsFileRecord::parse(&mft0_raw).map_err(|err| parse_err(&err))?;
                let dir_raw = self.read_record_from_stage_via_mft0(
                    cx,
                    staged,
                    &mft0,
                    u32::try_from(owner_ref.record).map_err(|_| corrupt(rec.lsn, "dir ref"))?,
                )?;
                let dir_rec = NtfsFileRecord::parse(&dir_raw).map_err(|err| parse_err(&err))?;
                let root_bytes = super::extract_resident_attr(&dir_rec, 0x90, &I30_NAME)?;
                let root = NtfsIndexRoot::parse(&root_bytes, self.geometry.cluster_bytes())
                    .map_err(|err| parse_err(&err))?;
                let block_len = root.block_bytes as usize;
                let mut transfer = read_transfer(staged)?;
                let block_off = usize::from(rec.cluster_block_offset) * SECTOR_BYTES
                    + usize::from(rec.record_offset);
                if block_off + block_len > transfer.len() {
                    return Err(corrupt(rec.lsn, "INDX block exceeds logged transfer"));
                }
                let logical_byte = rec.target_vcn * cluster_bytes + block_off as u64;
                let expected_vcn = logical_byte / u64::from(root.vcn_bytes);
                let idx_op = match op {
                    NtfsLogOp::AddIndexEntryAllocation => IndexOperation::AddEntry,
                    NtfsLogOp::DeleteIndexEntryAllocation => IndexOperation::DeleteEntry,
                    NtfsLogOp::WriteEndOfIndexBuffer => IndexOperation::WriteEnd,
                    NtfsLogOp::SetIndexEntryVcnAllocation => IndexOperation::SetChild,
                    _ => IndexOperation::UpdateFileName,
                };
                let edit = IndexEdit {
                    operation: idx_op,
                    entry_offset: rec.attribute_offset,
                    data: payload,
                };
                match apply_index_edit(
                    &transfer[block_off..block_off + block_len],
                    expected_vcn,
                    pass,
                    &edit,
                )
                .map_err(|err| parse_err(&err))?
                {
                    FileEditResult::AlreadyApplied => Ok(false),
                    FileEditResult::Applied(updated) => {
                        transfer[block_off..block_off + block_len].copy_from_slice(&updated);
                        write_transfer(staged, &transfer)?;
                        Ok(true)
                    }
                }
            }
            _ => {
                // FILE record target in $MFT::$DATA.
                let owner_ref = NtfsReference::decode(target_attr.reference_raw);
                if owner_ref.record != 0 || target_attr.kind != DATA || !target_attr.name.is_empty()
                {
                    return Err(corrupt(rec.lsn, "FILE action does not target $MFT::$DATA"));
                }
                let rec_len = self.geometry.record_bytes() as usize;
                let rec_byte_in_transfer = usize::from(rec.cluster_block_offset) * SECTOR_BYTES;
                if rec_byte_in_transfer + rec_len > span_bytes as usize {
                    return Err(corrupt(rec.lsn, "FILE record exceeds logged transfer"));
                }
                let logical_byte = rec.target_vcn * cluster_bytes + rec_byte_in_transfer as u64;
                if !logical_byte.is_multiple_of(rec_len as u64) {
                    return Err(corrupt(rec.lsn, "unaligned FILE logical offset"));
                }
                let record_number = u32::try_from(logical_byte / (rec_len as u64))
                    .map_err(|_| corrupt(rec.lsn, "MFT record number overflow"))?;
                let mut transfer = read_transfer(staged)?;
                let slice = &transfer[rec_byte_in_transfer..rec_byte_in_transfer + rec_len];
                let res = match op {
                    NtfsLogOp::InitializeFileRecordSegment => {
                        initialize_file_record_slot(slice, record_number, pass, payload)
                            .map_err(|err| parse_err(&err))?
                    }
                    NtfsLogOp::DeallocateFileRecordSegment => {
                        deallocate_file_record_slot(slice, record_number, pass)
                            .map_err(|err| parse_err(&err))?
                    }
                    _ => {
                        let file_op = match op {
                            NtfsLogOp::WriteEndOfFileRecordSegment => FileOperation::WriteEnd,
                            NtfsLogOp::CreateAttribute => FileOperation::CreateAttribute,
                            NtfsLogOp::DeleteAttribute => FileOperation::DeleteAttribute,
                            NtfsLogOp::UpdateResidentValue => FileOperation::UpdateResident {
                                resize: rec.redo_data.len() != rec.undo_data.len(),
                            },
                            NtfsLogOp::UpdateMappingPairs => FileOperation::UpdateMappingPairs {
                                volume_clusters: self.geometry.cluster_count(),
                            },
                            NtfsLogOp::SetNewAttributeSizes => FileOperation::SetSizes,
                            NtfsLogOp::AddIndexEntryRoot => {
                                FileOperation::IndexRoot(IndexOperation::AddEntry)
                            }
                            NtfsLogOp::DeleteIndexEntryRoot => {
                                FileOperation::IndexRoot(IndexOperation::DeleteEntry)
                            }
                            NtfsLogOp::SetIndexEntryVcnRoot => {
                                FileOperation::IndexRoot(IndexOperation::SetChild)
                            }
                            NtfsLogOp::UpdateFileNameRoot => {
                                FileOperation::IndexRoot(IndexOperation::UpdateFileName)
                            }
                            _ => return Err(unsupported("unexpected FILE opcode")),
                        };
                        apply_file_edit(
                            slice,
                            record_number,
                            pass,
                            &FileEdit {
                                operation: file_op,
                                record_offset: rec.record_offset,
                                attribute_offset: rec.attribute_offset,
                                data: payload,
                            },
                        )
                        .map_err(|err| parse_err(&err))?
                    }
                };
                match res {
                    FileEditResult::AlreadyApplied => Ok(false),
                    FileEditResult::Applied(updated) => {
                        transfer[rec_byte_in_transfer..rec_byte_in_transfer + rec_len]
                            .copy_from_slice(&updated);
                        write_transfer(staged, &transfer)?;
                        Ok(true)
                    }
                }
            }
        }
    }

    fn read_record_from_stage(
        &self,
        cx: &Cx,
        staged: &StagedSectorBuffer<'_>,
        record_zero_only: u32,
    ) -> Result<Vec<u8>> {
        debug_assert_eq!(record_zero_only, 0);
        let phys = self
            .geometry
            .cluster_offset(self.geometry.mft_cluster())
            .map_err(|err| parse_err(&err))?;
        let mut raw = vec![0_u8; self.geometry.record_bytes() as usize];
        staged.read(cx, phys, &mut raw)?;
        Ok(raw)
    }

    fn read_record_from_stage_via_mft0(
        &self,
        cx: &Cx,
        staged: &StagedSectorBuffer<'_>,
        mft0: &NtfsFileRecord,
        number: u32,
    ) -> Result<Vec<u8>> {
        let mft_runs = extract_plain_nonresident_runs(&self.geometry, mft0, DATA, &[])?;
        let rec_len = self.geometry.record_bytes() as usize;
        let logical = u64::from(number) * (rec_len as u64);
        let mut out = vec![0_u8; rec_len];
        let mut done = 0_usize;
        while done < rec_len {
            let (phys, avail, _) =
                map_logical_offset(&self.geometry, &mft_runs, logical + done as u64)?;
            let chunk = (rec_len - done).min(avail as usize);
            staged.read(cx, phys, &mut out[done..done + chunk])?;
            done += chunk;
        }
        Ok(out)
    }

    fn write_record_to_stage_via_runs(
        &self,
        cx: &Cx,
        staged: &mut StagedSectorBuffer<'_>,
        runs: &[NtfsRun],
        logical: u64,
        data: &[u8],
    ) -> Result<()> {
        let mut done = 0_usize;
        while done < data.len() {
            let (phys, avail, _) = map_logical_offset(&self.geometry, runs, logical + done as u64)?;
            let chunk = (data.len() - done).min(avail as usize);
            staged.write(cx, phys, &data[done..done + chunk])?;
            done += chunk;
        }
        Ok(())
    }

    fn sync_mft_mirror_and_clear_dirty_in_stage(
        &self,
        cx: &Cx,
        staged: &mut StagedSectorBuffer<'_>,
    ) -> Result<()> {
        let mft0_raw = self.read_record_from_stage(cx, staged, 0)?;
        let mft0 = NtfsFileRecord::parse(&mft0_raw).map_err(|err| parse_err(&err))?;
        let mft_runs = extract_plain_nonresident_runs(&self.geometry, &mft0, DATA, &[])?;

        // Clear dirty bit (0x0001) on $Volume (record 3) if set.
        let vol_raw = self.read_record_from_stage_via_mft0(cx, staged, &mft0, 3)?;
        let mut vol_restored = restore_record(&vol_raw, b"FILE").map_err(|err| parse_err(&err))?;
        let vol_parsed = NtfsFileRecord::parse(&vol_raw).map_err(|err| parse_err(&err))?;
        let mut attr_off = usize::from(le16(&vol_restored, 20)?);
        for attr in vol_parsed.attributes().map_err(|err| parse_err(&err))? {
            let len = le32(&vol_restored, attr_off + 4)? as usize;
            if attr.kind == VOLUME_INFORMATION && attr.name.is_empty() {
                if let NtfsValue::Resident(val) = attr.value
                    && val.len() >= 12
                {
                    let val_off = usize::from(le16(&vol_restored, attr_off + 20)?);
                    let flags = le16(&vol_restored, attr_off + val_off + 10)?;
                    if flags & 0x0001 != 0 {
                        let cleared = flags & !0x0001;
                        vol_restored[attr_off + val_off + 10..attr_off + val_off + 12]
                            .copy_from_slice(&cleared.to_le_bytes());
                        let usa = usize::from(le16(&vol_restored, 4)?);
                        let next_tok = next_usa_token(le16(&vol_raw, usa)?);
                        vol_restored[usa..usa + 2].copy_from_slice(&next_tok.to_le_bytes());
                        let protected =
                            protect_record(&vol_restored).map_err(|err| parse_err(&err))?;
                        let rec_len = u64::from(self.geometry.record_bytes());
                        self.write_record_to_stage_via_runs(
                            cx,
                            staged,
                            &mft_runs,
                            3 * rec_len,
                            &protected,
                        )?;
                    }
                }
                break;
            }
            attr_off += len;
        }

        // Synchronize $MFTMirr (records 0..mirrored_count) with primary $MFT.
        let mirr_rec_raw = self.read_record_from_stage_via_mft0(cx, staged, &mft0, 1)?;
        let mirr_rec = NtfsFileRecord::parse(&mirr_rec_raw).map_err(|err| parse_err(&err))?;
        let (mirr_runs, mirr_size, _) =
            extract_plain_nonresident_stream(&self.geometry, &mirr_rec, DATA, &[])?;
        let rec_bytes = u64::from(self.geometry.record_bytes());
        let mirr_count = mirr_size / rec_bytes;
        for idx in 0..mirr_count {
            let num = u32::try_from(idx).map_err(|_| corrupt(0, "mirror count overflow"))?;
            let pri_raw = self.read_record_from_stage_via_mft0(cx, staged, &mft0, num)?;
            let pri_rec = NtfsFileRecord::parse(&pri_raw).map_err(|err| parse_err(&err))?;
            let mut cur_mirr = vec![0_u8; rec_bytes as usize];
            let mut done = 0_usize;
            while done < cur_mirr.len() {
                let (phys, avail, _) =
                    map_logical_offset(&self.geometry, &mirr_runs, idx * rec_bytes + done as u64)?;
                let chunk = (cur_mirr.len() - done).min(avail as usize);
                staged.read(cx, phys, &mut cur_mirr[done..done + chunk])?;
                done += chunk;
            }
            let needs_copy = NtfsFileRecord::parse(&cur_mirr)
                .map_or(true, |m_rec| !same_logical_record(&pri_rec, &m_rec));
            if needs_copy {
                self.write_record_to_stage_via_runs(
                    cx,
                    staged,
                    &mirr_runs,
                    idx * rec_bytes,
                    &pri_raw,
                )?;
            }
        }
        Ok(())
    }

    fn verify_staged_preview_consistency(
        &self,
        cx: &Cx,
        staged: &StagedSectorBuffer<'_>,
        selected: &ParsedRestartPage,
    ) -> Result<()> {
        let mut preview_staged = StagedSectorBuffer {
            base: staged.base,
            length: staged.length,
            sectors: staged.sectors.clone(),
        };
        // Place clean RSTR copies in preview_staged so NtfsVolume::from_device admits the preview cleanly.
        let clean_rstr = encode_rstr_page(&NtfsRestartConfig {
            page_size: selected.page_size,
            version: selected.version,
            clean: true,
            current_lsn: selected.current_lsn.max(1),
            last_lsn_data_len: selected.last_lsn_data_len,
            file_size: selected.file_size,
            open_log_count: selected.open_log_count,
            client_seq: selected.client_seq,
            oldest_lsn: selected.oldest_lsn.max(1),
            client_restart_lsn: selected.client_restart_lsn,
            usa_token: next_usa_token(selected.usa_token),
        })
        .map_err(|err| parse_err(&err))?;
        for slot in [0_u64, 1_u64] {
            let vbo = slot * u64::from(selected.page_size);
            let mut done = 0_usize;
            while done < clean_rstr.len() {
                let (phys, avail, _) =
                    map_logical_offset(&self.geometry, &self.logfile_runs, vbo + done as u64)?;
                let chunk = (clean_rstr.len() - done).min(avail as usize);
                preview_staged.write(cx, phys, &clean_rstr[done..done + chunk])?;
                done += chunk;
            }
        }
        let preview_dev = PreviewDevice {
            base: Arc::clone(&self.device),
            length: self.geometry.volume_bytes(),
            sectors: preview_staged.sectors,
        };
        let vol =
            NtfsVolume::from_device(cx, Box::new(preview_dev), 0, self.geometry.volume_bytes())?;
        if !vol
            .check_allocations(cx, AllocationLimits::default())?
            .is_consistent()
        {
            return Err(corrupt(0, "post-recovery preview failed allocation check"));
        }
        if !vol
            .check_record_ownership(cx, RecordOwnershipLimits::default())?
            .is_consistent()
        {
            return Err(corrupt(0, "post-recovery preview failed ownership check"));
        }
        if !vol
            .check_mft_mirror(cx, RecordOwnershipLimits::default())?
            .is_consistent()
        {
            return Err(corrupt(0, "post-recovery preview failed $MFTMirr check"));
        }
        if !vol
            .check_namespace(cx, NamespaceLimits::default())?
            .is_consistent()
        {
            return Err(corrupt(0, "post-recovery preview failed namespace check"));
        }
        Ok(())
    }
}

const fn is_data_mutation_op(op: NtfsLogOp) -> bool {
    matches!(
        op,
        NtfsLogOp::InitializeFileRecordSegment
            | NtfsLogOp::DeallocateFileRecordSegment
            | NtfsLogOp::WriteEndOfFileRecordSegment
            | NtfsLogOp::CreateAttribute
            | NtfsLogOp::DeleteAttribute
            | NtfsLogOp::UpdateResidentValue
            | NtfsLogOp::UpdateMappingPairs
            | NtfsLogOp::SetNewAttributeSizes
            | NtfsLogOp::AddIndexEntryRoot
            | NtfsLogOp::DeleteIndexEntryRoot
            | NtfsLogOp::SetIndexEntryVcnRoot
            | NtfsLogOp::UpdateFileNameRoot
            | NtfsLogOp::AddIndexEntryAllocation
            | NtfsLogOp::DeleteIndexEntryAllocation
            | NtfsLogOp::WriteEndOfIndexBuffer
            | NtfsLogOp::SetIndexEntryVcnAllocation
            | NtfsLogOp::UpdateFileNameAllocation
            | NtfsLogOp::SetBitsInNonresidentBitMap
            | NtfsLogOp::ClearBitsInNonresidentBitMap
    )
}
