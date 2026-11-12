//! Bounded NTFS `$LogFile` (`RSTR` + `RCRD` + `RESTART_TABLE`) encoders.
//!
//! Produces native LFS 1.1 / 2.0 multi-sector USA-protected restart pages,
//! checkpoint records (`LFS_CLIENT_RESTART`), table dumps, and client redo/undo
//! update records (`LFS_CLIENT_RECORD`) without I/O or unsafe code.

use std::collections::BTreeMap;

use ffs_types::ParseError;

use super::{NtfsLogOp, NtfsLogRestartArea, invalid, le16, protect_record, restore_record};

const SECTOR_BYTES: usize = 512;
const NO_CLIENT: u16 = 0xFFFF;
const RESTART_CLEAN_FLAG: u16 = 0x0002;
const PAGE_RECORD_END: u32 = 0x0000_0001;
const LFS_HEADER_BYTES: usize = 48;
const CLIENT_RECORD_HEADER_BYTES: usize = 32;
const RESTART_TABLE_HEADER_BYTES: usize = 24;
const RESTART_SLOT_ALLOCATED: u32 = u32::MAX;

/// LFS client record kind (`LFS_RECORD_TYPE`).
pub const LFS_RECORD_CLIENT: u32 = 1;
/// LFS client checkpoint/restart record kind (`LFS_RECORD_TYPE`).
pub const LFS_RECORD_CLIENT_RESTART: u32 = 2;

fn bad(reason: &'static str) -> ParseError {
    invalid("ntfs.logfile_writer", reason)
}

/// Compute native NTFS `$LogFile` `seq_num_bits` for `file_size`.
pub fn logfile_seq_num_bits(file_size: u64) -> Result<u32, ParseError> {
    if !(50 * 512..=0x0001_0000_0000).contains(&file_size) {
        return Err(bad("$LogFile size outside admitted 25 KiB..=4 GiB bounds"));
    }
    let leading = file_size.leading_zeros();
    let address_bits_plus_3 = 64_u32
        .checked_sub(leading)
        .ok_or_else(|| bad("invalid $LogFile size bit width"))?;
    67_u32
        .checked_sub(address_bits_plus_3)
        .filter(|&bits| (3..64).contains(&bits))
        .ok_or_else(|| bad("computed seq_num_bits outside 3..64"))
}

/// Convert `(sequence, vbo)` into a 64-bit NTFS LSN for `seq_num_bits`.
pub fn make_lsn(sequence: u64, vbo: u64, seq_num_bits: u32) -> Result<u64, ParseError> {
    if !(3..64).contains(&seq_num_bits) || sequence == 0 || !vbo.is_multiple_of(8) {
        return Err(bad("invalid LSN sequence, width, or 8-byte VBO alignment"));
    }
    let address_bits = 64 - seq_num_bits;
    let shifted_vbo = vbo >> 3;
    if sequence >= (1_u64 << seq_num_bits) || shifted_vbo >= (1_u64 << address_bits) {
        return Err(bad("LSN sequence or VBO overflows field width"));
    }
    Ok((sequence << address_bits) | shifted_vbo)
}

/// Convert an NTFS LSN back to its `$LogFile` virtual byte offset (`VBO`).
pub fn lsn_to_vbo(lsn: u64, seq_num_bits: u32) -> Result<u64, ParseError> {
    if !(3..64).contains(&seq_num_bits) || lsn == 0 {
        return Err(bad("invalid LSN or sequence bit width"));
    }
    Ok(lsn.wrapping_shl(seq_num_bits) >> (seq_num_bits - 3))
}

/// Extract the wrap sequence number from an NTFS LSN.
pub fn lsn_sequence(lsn: u64, seq_num_bits: u32) -> Result<u64, ParseError> {
    if !(3..64).contains(&seq_num_bits) || lsn == 0 {
        return Err(bad("invalid LSN or sequence bit width"));
    }
    Ok(lsn >> (64 - seq_num_bits))
}

/// Advance a 16-bit USA token without ever producing `0` or `0xFFFF`.
#[must_use]
pub const fn next_usa_token(previous: u16) -> u16 {
    if previous >= u16::MAX - 1 || previous == 0 {
        1
    } else {
        previous + 1
    }
}

/// Parameters for encoding one `$LogFile` `RSTR` page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsRestartConfig {
    pub page_size: u32,
    pub version: (u16, u16),
    pub clean: bool,
    pub current_lsn: u64,
    pub last_lsn_data_len: u32,
    pub file_size: u64,
    pub open_log_count: u32,
    pub client_seq: u16,
    pub oldest_lsn: u64,
    pub client_restart_lsn: u64,
    pub usa_token: u16,
}

impl NtfsRestartConfig {
    #[must_use]
    pub const fn reserved_pages(&self) -> u64 {
        if self.version.0 >= 2 { 34 } else { 4 }
    }

    pub fn data_offset(&self) -> Result<u16, ParseError> {
        if !matches!(self.page_size, 512 | 1024 | 2048 | 4096) {
            return Err(bad("RSTR page_size must be 512, 1024, 2048, or 4096"));
        }
        let fix_count = (self.page_size as usize) / SECTOR_BYTES + 1;
        let raw = (40 + fix_count * 2).next_multiple_of(8);
        u16::try_from(raw).map_err(|_| bad("RCRD data_off overflow"))
    }
}

/// Encode a complete USA-protected `RSTR` page and validate it via `NtfsLogRestartArea::parse_page`.
pub fn encode_rstr_page(cfg: &NtfsRestartConfig) -> Result<Vec<u8>, ParseError> {
    if !matches!(cfg.page_size, 512 | 1024 | 2048 | 4096) {
        return Err(bad("unsupported RSTR page size"));
    }
    if !matches!(cfg.version, (1, 1) | (2, 0)) {
        return Err(bad("unsupported LFS restart version"));
    }
    if cfg.usa_token == 0 || cfg.usa_token == u16::MAX {
        return Err(bad("invalid USA token for RSTR page"));
    }
    let page_bytes = cfg.page_size as usize;
    let min_file_size = 2 * u64::from(cfg.page_size) + 48 * u64::from(cfg.page_size);
    if cfg.file_size < min_file_size || !cfg.file_size.is_multiple_of(u64::from(cfg.page_size)) {
        return Err(bad(
            "$LogFile file_size too small or unaligned to page_size",
        ));
    }
    let seq_bits = logfile_seq_num_bits(cfg.file_size)?;
    let fix_count = page_bytes / SECTOR_BYTES + 1;
    let usa_off = 30_usize;
    let area_offset = (usa_off + fix_count * 2).next_multiple_of(8);
    let client_offset = 64_usize;
    let area_length = 224_usize;
    if area_offset + area_length > page_bytes || area_offset + client_offset > SECTOR_BYTES - 2 {
        return Err(bad("RSTR page too small for single-client restart area"));
    }
    let data_off = cfg.data_offset()?;

    let mut page = vec![0_u8; page_bytes];
    page[0..4].copy_from_slice(b"RSTR");
    page[4..6].copy_from_slice(&(usa_off as u16).to_le_bytes());
    page[6..8].copy_from_slice(&(fix_count as u16).to_le_bytes());
    page[8..16].copy_from_slice(&0_u64.to_le_bytes());
    page[16..20].copy_from_slice(&cfg.page_size.to_le_bytes());
    page[20..24].copy_from_slice(&cfg.page_size.to_le_bytes());
    page[24..26].copy_from_slice(&(area_offset as u16).to_le_bytes());
    page[26..28].copy_from_slice(&cfg.version.1.to_le_bytes());
    page[28..30].copy_from_slice(&cfg.version.0.to_le_bytes());
    page[usa_off..usa_off + 2].copy_from_slice(&cfg.usa_token.to_le_bytes());

    let flags: u16 = if cfg.clean { RESTART_CLEAN_FLAG } else { 0 };
    let area = &mut page[area_offset..area_offset + area_length];
    area[0..8].copy_from_slice(&cfg.current_lsn.to_le_bytes());
    area[8..10].copy_from_slice(&1_u16.to_le_bytes());
    area[10..12].copy_from_slice(&NO_CLIENT.to_le_bytes());
    area[12..14].copy_from_slice(&0_u16.to_le_bytes());
    area[14..16].copy_from_slice(&flags.to_le_bytes());
    area[16..20].copy_from_slice(&seq_bits.to_le_bytes());
    area[20..22].copy_from_slice(&(area_length as u16).to_le_bytes());
    area[22..24].copy_from_slice(&(client_offset as u16).to_le_bytes());
    area[24..32].copy_from_slice(&cfg.file_size.to_le_bytes());
    area[32..36].copy_from_slice(&cfg.last_lsn_data_len.to_le_bytes());
    area[36..38].copy_from_slice(&(LFS_HEADER_BYTES as u16).to_le_bytes());
    area[38..40].copy_from_slice(&data_off.to_le_bytes());
    area[40..44].copy_from_slice(&cfg.open_log_count.to_le_bytes());

    let client = &mut area[client_offset..];
    client[0..8].copy_from_slice(&cfg.oldest_lsn.to_le_bytes());
    client[8..16].copy_from_slice(&cfg.client_restart_lsn.to_le_bytes());
    client[16..18].copy_from_slice(&NO_CLIENT.to_le_bytes());
    client[18..20].copy_from_slice(&NO_CLIENT.to_le_bytes());
    client[20..22].copy_from_slice(&cfg.client_seq.to_le_bytes());
    client[28..32].copy_from_slice(&8_u32.to_le_bytes());
    client[32..40].copy_from_slice(b"N\0T\0F\0S\0");

    let protected = protect_record(&page)?;
    let parsed = NtfsLogRestartArea::parse_page(&protected)?;
    if parsed.current_lsn != cfg.current_lsn
        || parsed.oldest_lsn != cfg.oldest_lsn
        || parsed.client_restart_lsn != cfg.client_restart_lsn
        || parsed.is_clean() != cfg.clean
    {
        return Err(bad("RSTR roundtrip mismatch"));
    }
    Ok(protected)
}

/// Encode a native `RESTART_TABLE` (`24`-byte header + slot array + free list).
/// Keys in `entries` are byte offsets (`24 + index * entry_size`).
pub fn encode_restart_table(
    entry_size: u16,
    entries: &BTreeMap<u32, Vec<u8>>,
) -> Result<Vec<u8>, ParseError> {
    let entry_len = usize::from(entry_size);
    if entry_len < 8 || !entry_len.is_multiple_of(8) {
        return Err(bad("restart-table entry_size must be >= 8 and 8-aligned"));
    }
    let mut max_slot_index: Option<usize> = None;
    for (&slot_offset, payload) in entries {
        if payload.len() != entry_len {
            return Err(bad("restart-table entry payload length mismatch"));
        }
        let off = usize::try_from(slot_offset).map_err(|_| bad("slot offset overflow"))?;
        let rel = off
            .checked_sub(RESTART_TABLE_HEADER_BYTES)
            .ok_or_else(|| bad("restart-table slot enters header"))?;
        if !rel.is_multiple_of(entry_len) {
            return Err(bad("unaligned restart-table slot offset"));
        }
        let idx = rel / entry_len;
        if idx >= 4096 {
            return Err(bad("restart-table slot index exceeds 4096"));
        }
        max_slot_index = Some(max_slot_index.map_or(idx, |cur| cur.max(idx)));
    }
    let capacity = max_slot_index.map_or(0, |idx| idx + 1);
    let allocated = entries.len();
    let total_bytes = RESTART_TABLE_HEADER_BYTES
        .checked_add(capacity * entry_len)
        .ok_or_else(|| bad("restart-table total bytes overflow"))?;
    let mut out = vec![0_u8; total_bytes];
    out[0..2].copy_from_slice(&entry_size.to_le_bytes());
    out[2..4].copy_from_slice(&(capacity as u16).to_le_bytes());
    out[4..6].copy_from_slice(&(allocated as u16).to_le_bytes());

    let mut free_offsets = Vec::new();
    for idx in 0..capacity {
        let off = RESTART_TABLE_HEADER_BYTES + idx * entry_len;
        let off_u32 = u32::try_from(off).map_err(|_| bad("slot offset u32 overflow"))?;
        if let Some(payload) = entries.get(&off_u32) {
            out[off..off + entry_len].copy_from_slice(payload);
            out[off..off + 4].copy_from_slice(&RESTART_SLOT_ALLOCATED.to_le_bytes());
        } else {
            free_offsets.push(off_u32);
        }
    }
    if let (Some(&first), Some(&last)) = (free_offsets.first(), free_offsets.last()) {
        out[16..20].copy_from_slice(&first.to_le_bytes());
        out[20..24].copy_from_slice(&last.to_le_bytes());
        for pair in free_offsets.windows(2) {
            let cur = pair[0] as usize;
            out[cur..cur + 4].copy_from_slice(&pair[1].to_le_bytes());
        }
        let last_at = last as usize;
        out[last_at..last_at + 4].copy_from_slice(&0_u32.to_le_bytes());
    }
    Ok(out)
}

/// Encode a 40-byte `OPEN_ATTR_ENTRY` for `OpenNonresidentAttribute` (`0x1C`) or `0x1D` dump.
#[must_use]
pub fn encode_open_attribute_entry(
    kind: u32,
    index_bytes: u32,
    file_reference_raw: u64,
    opened_lsn: u64,
) -> [u8; 40] {
    let mut entry = [0_u8; 40];
    entry[0..4].copy_from_slice(&RESTART_SLOT_ALLOCATED.to_le_bytes());
    entry[4..8].copy_from_slice(&index_bytes.to_le_bytes());
    entry[8..12].copy_from_slice(&kind.to_le_bytes());
    entry[16..24].copy_from_slice(&file_reference_raw.to_le_bytes());
    entry[24..32].copy_from_slice(&opened_lsn.to_le_bytes());
    entry
}

/// Encode `AttributeNamesDump` (`0x1E`) payload (`[u16 slot, u16 byte_len, utf16_le..., 0, 0]`).
pub fn encode_attribute_names_dump(names: &BTreeMap<u32, Vec<u16>>) -> Result<Vec<u8>, ParseError> {
    let mut out = Vec::new();
    for (&slot, units) in names {
        if units.is_empty() {
            continue;
        }
        if units.len() > 255 {
            return Err(bad("attribute name exceeds 255 UTF-16 units"));
        }
        let slot_u16 = u16::try_from(slot).map_err(|_| bad("attribute slot exceeds u16"))?;
        let byte_len = u16::try_from(units.len() * 2).map_err(|_| bad("name byte_len overflow"))?;
        out.extend_from_slice(&slot_u16.to_le_bytes());
        out.extend_from_slice(&byte_len.to_le_bytes());
        for &unit in units {
            out.extend_from_slice(&unit.to_le_bytes());
        }
    }
    out.extend_from_slice(&0_u16.to_le_bytes());
    out.extend_from_slice(&0_u16.to_le_bytes());
    Ok(out)
}

/// Encode a `DIR_PAGE_ENTRY` (`32 + lcns.len() * 8` bytes) for `DirtyPageTableDump` (`0x1F`).
pub fn encode_dirty_page_entry(
    target_attribute_slot: u32,
    transfer_length: u32,
    vcn: u64,
    oldest_lsn: u64,
    lcns: &[u64],
) -> Result<Vec<u8>, ParseError> {
    if lcns.is_empty() || transfer_length == 0 || oldest_lsn == 0 {
        return Err(bad(
            "dirty-page entry requires non-empty LCNs, transfer_length, and oldest_lsn",
        ));
    }
    let count_u32 = u32::try_from(lcns.len()).map_err(|_| bad("dirty-page LCN count overflow"))?;
    let mut out = vec![0_u8; 32 + lcns.len() * 8];
    out[0..4].copy_from_slice(&RESTART_SLOT_ALLOCATED.to_le_bytes());
    out[4..8].copy_from_slice(&target_attribute_slot.to_le_bytes());
    out[8..12].copy_from_slice(&transfer_length.to_le_bytes());
    out[12..16].copy_from_slice(&count_u32.to_le_bytes());
    out[16..24].copy_from_slice(&vcn.to_le_bytes());
    out[24..32].copy_from_slice(&oldest_lsn.to_le_bytes());
    for (idx, &lcn) in lcns.iter().enumerate() {
        if lcn > i64::MAX as u64 {
            return Err(bad("negative LCN in dirty-page entry"));
        }
        out[32 + idx * 8..40 + idx * 8].copy_from_slice(&lcn.to_le_bytes());
    }
    Ok(out)
}

/// Encode a 40-byte `TRANSACTION_ENTRY` (`state`: `1=Active`, `2=Prepared`, `3=Committed`).
pub fn encode_transaction_entry(
    state: u8,
    first_lsn: u64,
    previous_lsn: u64,
    undo_next_lsn: u64,
) -> Result<[u8; 40], ParseError> {
    if !(1..=3).contains(&state) {
        return Err(bad("invalid transaction-table state"));
    }
    let mut out = [0_u8; 40];
    out[0..4].copy_from_slice(&RESTART_SLOT_ALLOCATED.to_le_bytes());
    out[4] = state;
    out[8..16].copy_from_slice(&first_lsn.to_le_bytes());
    out[16..24].copy_from_slice(&previous_lsn.to_le_bytes());
    out[24..32].copy_from_slice(&undo_next_lsn.to_le_bytes());
    Ok(out)
}

/// Specification of a `64`-byte `NTFS_RESTART` (`LFS_CLIENT_RESTART`) checkpoint payload.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NtfsCheckpointPayload {
    pub start_of_checkpoint_lsn: u64,
    pub open_attribute_table_lsn: u64,
    pub open_attribute_table_len: u32,
    pub attribute_names_lsn: u64,
    pub attribute_names_len: u32,
    pub dirty_page_table_lsn: u64,
    pub dirty_page_table_len: u32,
    pub transaction_table_lsn: u64,
    pub transaction_table_len: u32,
}

impl NtfsCheckpointPayload {
    pub fn encode(&self) -> Result<[u8; 64], ParseError> {
        for (lsn, len) in [
            (self.open_attribute_table_lsn, self.open_attribute_table_len),
            (self.attribute_names_lsn, self.attribute_names_len),
            (self.dirty_page_table_lsn, self.dirty_page_table_len),
            (self.transaction_table_lsn, self.transaction_table_len),
        ] {
            if (lsn == 0) != (len == 0) {
                return Err(bad(
                    "checkpoint table LSN and length must both be zero or nonzero",
                ));
            }
        }
        let mut out = [0_u8; 64];
        out[0..4].copy_from_slice(&1_u32.to_le_bytes());
        out[4..8].copy_from_slice(&0_u32.to_le_bytes());
        out[8..16].copy_from_slice(&self.start_of_checkpoint_lsn.to_le_bytes());
        out[16..24].copy_from_slice(&self.open_attribute_table_lsn.to_le_bytes());
        out[24..32].copy_from_slice(&self.attribute_names_lsn.to_le_bytes());
        out[32..40].copy_from_slice(&self.dirty_page_table_lsn.to_le_bytes());
        out[40..48].copy_from_slice(&self.transaction_table_lsn.to_le_bytes());
        out[48..52].copy_from_slice(&self.open_attribute_table_len.to_le_bytes());
        out[52..56].copy_from_slice(&self.attribute_names_len.to_le_bytes());
        out[56..60].copy_from_slice(&self.dirty_page_table_len.to_le_bytes());
        out[60..64].copy_from_slice(&self.transaction_table_len.to_le_bytes());
        Ok(out)
    }
}

/// Specification of one NTFS client log record (`LFS_CLIENT_RECORD`, `record_type == 1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsClientUpdateSpec {
    pub redo_op: NtfsLogOp,
    pub undo_op: NtfsLogOp,
    pub target_attribute: u16,
    pub record_offset: u16,
    pub attribute_offset: u16,
    pub cluster_block_offset: u16,
    pub target_vcn: u64,
    pub target_lcns: Vec<u64>,
    pub redo_data: Vec<u8>,
    pub undo_data: Vec<u8>,
}

/// Encode the client payload of an `LFS_CLIENT_RECORD` (`LOG_RECORD_HEADER` + LCNs + redo + undo).
pub fn encode_client_update_payload(spec: &NtfsClientUpdateSpec) -> Result<Vec<u8>, ParseError> {
    let lcn_slots = spec.target_lcns.len().max(1);
    let lcns_to_follow =
        u16::try_from(spec.target_lcns.len()).map_err(|_| bad("target_lcns count overflow"))?;
    if spec
        .target_vcn
        .checked_add(u64::from(lcns_to_follow))
        .is_none()
    {
        return Err(bad("target_vcn + lcns_to_follow overflow"));
    }
    for &lcn in &spec.target_lcns {
        if lcn > i64::MAX as u64 {
            return Err(bad("negative physical LCN in client log record"));
        }
    }
    let mapping_bytes = CLIENT_RECORD_HEADER_BYTES
        .checked_add(lcn_slots * 8)
        .ok_or_else(|| bad("mapping header bytes overflow"))?;
    let redo_len_u16 =
        u16::try_from(spec.redo_data.len()).map_err(|_| bad("redo_data exceeds u16"))?;
    let undo_len_u16 =
        u16::try_from(spec.undo_data.len()).map_err(|_| bad("undo_data exceeds u16"))?;

    let (redo_off, after_redo) = if spec.redo_data.is_empty() {
        (0_u16, mapping_bytes)
    } else {
        let start = mapping_bytes.next_multiple_of(8);
        let end = start
            .checked_add(spec.redo_data.len())
            .ok_or_else(|| bad("redo_data offset overflow"))?;
        (
            u16::try_from(start).map_err(|_| bad("redo_off overflow"))?,
            end,
        )
    };
    let (undo_off, total_len) = if spec.undo_data.is_empty() {
        (0_u16, after_redo)
    } else {
        let start = after_redo.next_multiple_of(8);
        let end = start
            .checked_add(spec.undo_data.len())
            .ok_or_else(|| bad("undo_data offset overflow"))?;
        (
            u16::try_from(start).map_err(|_| bad("undo_off overflow"))?,
            end,
        )
    };

    let mut out = vec![0_u8; total_len.max(mapping_bytes)];
    out[0..2].copy_from_slice(&spec.redo_op.to_raw().to_le_bytes());
    out[2..4].copy_from_slice(&spec.undo_op.to_raw().to_le_bytes());
    out[4..6].copy_from_slice(&redo_off.to_le_bytes());
    out[6..8].copy_from_slice(&redo_len_u16.to_le_bytes());
    out[8..10].copy_from_slice(&undo_off.to_le_bytes());
    out[10..12].copy_from_slice(&undo_len_u16.to_le_bytes());
    out[12..14].copy_from_slice(&spec.target_attribute.to_le_bytes());
    out[14..16].copy_from_slice(&lcns_to_follow.to_le_bytes());
    out[16..18].copy_from_slice(&spec.record_offset.to_le_bytes());
    out[18..20].copy_from_slice(&spec.attribute_offset.to_le_bytes());
    out[20..22].copy_from_slice(&spec.cluster_block_offset.to_le_bytes());
    out[24..32].copy_from_slice(&spec.target_vcn.to_le_bytes());
    for (idx, &lcn) in spec.target_lcns.iter().enumerate() {
        out[32 + idx * 8..40 + idx * 8].copy_from_slice(&lcn.to_le_bytes());
    }
    if !spec.redo_data.is_empty() {
        let at = usize::from(redo_off);
        out[at..at + spec.redo_data.len()].copy_from_slice(&spec.redo_data);
    }
    if !spec.undo_data.is_empty() {
        let at = usize::from(undo_off);
        out[at..at + spec.undo_data.len()].copy_from_slice(&spec.undo_data);
    }
    Ok(out)
}

/// One staged `$LogFile` page write (`page_vbo` within `$LogFile::$DATA`, USA-protected `bytes`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedLogPage {
    pub page_vbo: u64,
    pub bytes: Vec<u8>,
}

/// Result of appending one LFS record into `NtfsLogRingWriter`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendedLogRecord {
    pub lsn: u64,
    pub page_vbo: u64,
    pub record_offset: u16,
    pub data_len: u32,
    pub protected_page: Vec<u8>,
}

/// Deterministic ring-buffer writer for NTFS `$LogFile` `RCRD` pages.
///
/// Preserves previously completed record prefixes byte-for-byte when appending
/// to an active page, enforces `oldest_lsn` ring-wrap non-overwrite before
/// mutating state, and USA-protects every emitted `RCRD` page.
#[derive(Debug, Clone)]
pub struct NtfsLogRingWriter {
    page_size: u32,
    version: (u16, u16),
    file_size: u64,
    seq_num_bits: u32,
    data_off: u16,
    client_seq: u16,
    open_log_count: u32,
    sequence: u64,
    oldest_lsn: u64,
    current_lsn: u64,
    last_lsn_data_len: u32,
    client_restart_lsn: u64,
    active_page_vbo: u64,
    active_page_restored: Vec<u8>,
    active_next_off: u16,
    usa_token: u16,
    next_rstr_slot: usize,
}

impl NtfsLogRingWriter {
    /// Initialize a fresh `$LogFile` ring writer at the start of the record ring.
    pub fn new_fresh(
        page_size: u32,
        version: (u16, u16),
        file_size: u64,
        client_seq: u16,
        open_log_count: u32,
    ) -> Result<Self, ParseError> {
        if !matches!(page_size, 512 | 1024 | 2048 | 4096) || !matches!(version, (1, 1) | (2, 0)) {
            return Err(bad("unsupported $LogFile page_size or LFS version"));
        }
        let min_file_size = 2 * u64::from(page_size) + 48 * u64::from(page_size);
        if file_size < min_file_size || !file_size.is_multiple_of(u64::from(page_size)) {
            return Err(bad("invalid $LogFile file_size"));
        }
        let seq_num_bits = logfile_seq_num_bits(file_size)?;
        let fix_count = (page_size as usize) / SECTOR_BYTES + 1;
        let data_off = u16::try_from((40 + fix_count * 2).next_multiple_of(8))
            .map_err(|_| bad("data_off overflow"))?;
        let reserved = if version.0 >= 2 { 34_u64 } else { 4_u64 };
        let first_vbo = reserved * u64::from(page_size);
        Ok(Self {
            page_size,
            version,
            file_size,
            seq_num_bits,
            data_off,
            client_seq: client_seq.max(1),
            open_log_count: open_log_count.max(1),
            sequence: 1,
            oldest_lsn: 0,
            current_lsn: 0,
            last_lsn_data_len: 0,
            client_restart_lsn: 0,
            active_page_vbo: first_vbo,
            active_page_restored: Self::blank_rcrd_restored(page_size),
            active_next_off: data_off,
            usa_token: 1,
            next_rstr_slot: 0,
        })
    }

    /// Resume a ring writer from an existing validated restart state and the raw
    /// `$LogFile` page at `current_lsn` (if `current_lsn != 0`).
    #[allow(clippy::too_many_arguments)]
    pub fn resume(
        page_size: u32,
        version: (u16, u16),
        file_size: u64,
        client_seq: u16,
        open_log_count: u32,
        oldest_lsn: u64,
        current_lsn: u64,
        last_lsn_data_len: u32,
        client_restart_lsn: u64,
        current_rcrd_raw_page: Option<&[u8]>,
        next_rstr_slot: usize,
        usa_token_seed: u16,
    ) -> Result<Self, ParseError> {
        let mut writer =
            Self::new_fresh(page_size, version, file_size, client_seq, open_log_count)?;
        writer.oldest_lsn = oldest_lsn;
        writer.current_lsn = current_lsn;
        writer.last_lsn_data_len = last_lsn_data_len;
        writer.client_restart_lsn = client_restart_lsn;
        writer.next_rstr_slot = next_rstr_slot & 1;
        writer.usa_token = next_usa_token(usa_token_seed);
        if current_lsn != 0 {
            writer.sequence = lsn_sequence(current_lsn, writer.seq_num_bits)?;
            let vbo = lsn_to_vbo(current_lsn, writer.seq_num_bits)?;
            let page_mask = u64::from(page_size) - 1;
            let page_vbo = vbo & !page_mask;
            writer.active_page_vbo = page_vbo;
            if let Some(raw_page) = current_rcrd_raw_page {
                let restored = restore_record(raw_page, b"RCRD")?;
                let end_off = le16(&restored, 24)?;
                if end_off < writer.data_off || u32::from(end_off) > page_size {
                    return Err(bad("invalid next_record_off in resumed RCRD page"));
                }
                let usa_off = usize::from(le16(&restored, 4)?);
                let page_token = le16(raw_page, usa_off)?;
                writer.usa_token = next_usa_token(writer.usa_token.max(page_token));
                writer.active_page_restored = restored;
                writer.active_next_off = end_off;
            }
        }
        Ok(writer)
    }

    fn blank_rcrd_restored(page_size: u32) -> Vec<u8> {
        let size = page_size as usize;
        let fix_count = size / SECTOR_BYTES + 1;
        let mut page = vec![0_u8; size];
        page[0..4].copy_from_slice(b"RCRD");
        page[4..6].copy_from_slice(&40_u16.to_le_bytes());
        page[6..8].copy_from_slice(&(fix_count as u16).to_le_bytes());
        page[16..20].copy_from_slice(&PAGE_RECORD_END.to_le_bytes());
        page[20..22].copy_from_slice(&1_u16.to_le_bytes());
        page[22..24].copy_from_slice(&1_u16.to_le_bytes());
        page
    }

    #[must_use]
    pub const fn first_ring_vbo(&self) -> u64 {
        let reserved = if self.version.0 >= 2 { 34_u64 } else { 4_u64 };
        reserved * (self.page_size as u64)
    }

    #[must_use]
    pub const fn page_size(&self) -> u32 {
        self.page_size
    }
    #[must_use]
    pub const fn version(&self) -> (u16, u16) {
        self.version
    }
    #[must_use]
    pub const fn file_size(&self) -> u64 {
        self.file_size
    }
    #[must_use]
    pub const fn seq_num_bits(&self) -> u32 {
        self.seq_num_bits
    }
    #[must_use]
    pub const fn client_seq(&self) -> u16 {
        self.client_seq
    }
    #[must_use]
    pub const fn open_log_count(&self) -> u32 {
        self.open_log_count
    }
    #[must_use]
    pub const fn oldest_lsn(&self) -> u64 {
        self.oldest_lsn
    }
    #[must_use]
    pub const fn current_lsn(&self) -> u64 {
        self.current_lsn
    }
    #[must_use]
    pub const fn last_lsn_data_len(&self) -> u32 {
        self.last_lsn_data_len
    }
    #[must_use]
    pub const fn client_restart_lsn(&self) -> u64 {
        self.client_restart_lsn
    }

    /// Maximum client payload bytes that fit in one single-page LFS record.
    #[must_use]
    pub const fn max_single_page_payload_bytes(&self) -> usize {
        (self.page_size as usize)
            .saturating_sub(self.data_off as usize)
            .saturating_sub(LFS_HEADER_BYTES)
    }

    /// Compute the free ring bytes available before colliding with `oldest_lsn`'s page.
    pub fn available_ring_bytes(&self) -> Result<u64, ParseError> {
        let page_bytes = u64::from(self.page_size);
        let ring_bytes = self.file_size - self.first_ring_vbo();
        let in_current_page = page_bytes.saturating_sub(u64::from(self.active_next_off));
        if self.oldest_lsn == 0 {
            return Ok(ring_bytes.saturating_sub(page_bytes) + in_current_page);
        }
        let oldest_vbo = lsn_to_vbo(self.oldest_lsn, self.seq_num_bits)?;
        let oldest_page = oldest_vbo & !(page_bytes - 1);
        let cur_page = self.active_page_vbo;
        let free_whole_pages = match cur_page.cmp(&oldest_page) {
            std::cmp::Ordering::Less => (oldest_page - cur_page) / page_bytes - 1,
            std::cmp::Ordering::Greater => {
                let to_end = (self.file_size - cur_page) / page_bytes - 1;
                let from_start = (oldest_page - self.first_ring_vbo()) / page_bytes;
                to_end + from_start
            }
            std::cmp::Ordering::Equal => {
                // Active page IS oldest_page (valid when oldest_lsn is earlier on the same page).
                let oldest_seq = lsn_sequence(self.oldest_lsn, self.seq_num_bits)?;
                if oldest_seq == self.sequence {
                    ring_bytes / page_bytes - 1
                } else {
                    return Ok(0);
                }
            }
        };
        Ok(free_whole_pages * page_bytes + in_current_page)
    }

    /// Check without mutating state whether a sequence of records with `payload_lengths`
    /// can be appended without overwriting `oldest_lsn`.
    pub fn check_space_for_payloads(&self, payload_lengths: &[usize]) -> Result<(), ParseError> {
        let mut probe = self.clone();
        for &len in payload_lengths {
            if len > probe.max_single_page_payload_bytes() {
                return Err(bad("client record exceeds single-page RCRD capacity"));
            }
            probe.reserve_record_slot(len)?;
        }
        Ok(())
    }

    fn reserve_record_slot(&mut self, payload_len: usize) -> Result<(u64, u16, usize), ParseError> {
        if payload_len > self.max_single_page_payload_bytes() {
            return Err(bad("client record exceeds single-page RCRD capacity"));
        }
        let aligned = (LFS_HEADER_BYTES + payload_len + 7) & !7;
        let aligned = aligned.max(LFS_HEADER_BYTES);
        let page_bytes = self.page_size as usize;
        if usize::from(self.active_next_off) + aligned > page_bytes {
            // Advance to next ring page (wrapping to first_ring_vbo if at end).
            let step = u64::from(self.page_size);
            let mut next_page = self.active_page_vbo + step;
            let mut next_seq = self.sequence;
            if next_page >= self.file_size {
                next_page = self.first_ring_vbo();
                next_seq = next_seq
                    .checked_add(1)
                    .filter(|&seq| seq < (1_u64 << self.seq_num_bits))
                    .ok_or_else(|| bad("$LogFile sequence rollover"))?;
            }
            if self.oldest_lsn != 0 {
                let oldest_page = lsn_to_vbo(self.oldest_lsn, self.seq_num_bits)? & !(step - 1);
                if next_page == oldest_page {
                    return Err(invalid(
                        "ntfs.logfile.space",
                        "$LogFile ring full: advancing would overwrite oldest retained LSN",
                    ));
                }
            }
            self.active_page_vbo = next_page;
            self.sequence = next_seq;
            self.active_page_restored = Self::blank_rcrd_restored(self.page_size);
            self.active_next_off = self.data_off;
        }
        let rec_off = self.active_next_off;
        let vbo = self.active_page_vbo + u64::from(rec_off);
        let lsn = make_lsn(self.sequence, vbo, self.seq_num_bits)?;
        if self.current_lsn != 0 && lsn <= self.current_lsn {
            return Err(bad("non-monotonic LSN generated by ring writer"));
        }
        Ok((lsn, rec_off, aligned))
    }

    /// Append one raw LFS record (`LFS_RECORD_CLIENT` or `LFS_RECORD_CLIENT_RESTART`).
    pub fn append_raw_record(
        &mut self,
        record_type: u32,
        transaction_id: u32,
        previous_lsn: u64,
        undo_next_lsn: u64,
        payload: &[u8],
    ) -> Result<AppendedLogRecord, ParseError> {
        if !matches!(record_type, LFS_RECORD_CLIENT | LFS_RECORD_CLIENT_RESTART) {
            return Err(bad("unsupported LFS record_type"));
        }
        if record_type == LFS_RECORD_CLIENT && transaction_id == 0 {
            return Err(bad("LFS_RECORD_CLIENT requires nonzero transaction_id"));
        }
        let data_len = u32::try_from(payload.len()).map_err(|_| bad("payload length overflow"))?;
        let (lsn, rec_off, aligned) = self.reserve_record_slot(payload.len())?;
        if previous_lsn >= lsn || undo_next_lsn >= lsn {
            return Err(bad("predecessor or undo_next LSN is not strictly older"));
        }
        let pos = usize::from(rec_off);
        let next_end = u16::try_from(pos + aligned).map_err(|_| bad("next_record_off overflow"))?;

        let page = &mut self.active_page_restored;
        page[pos..pos + aligned].fill(0);
        page[pos..pos + 8].copy_from_slice(&lsn.to_le_bytes());
        page[pos + 8..pos + 16].copy_from_slice(&previous_lsn.to_le_bytes());
        page[pos + 16..pos + 24].copy_from_slice(&undo_next_lsn.to_le_bytes());
        page[pos + 24..pos + 28].copy_from_slice(&data_len.to_le_bytes());
        page[pos + 28..pos + 30].copy_from_slice(&self.client_seq.to_le_bytes());
        page[pos + 30..pos + 32].copy_from_slice(&0_u16.to_le_bytes());
        page[pos + 32..pos + 36].copy_from_slice(&record_type.to_le_bytes());
        page[pos + 36..pos + 40].copy_from_slice(&transaction_id.to_le_bytes());
        page[pos + 40..pos + 42].copy_from_slice(&0_u16.to_le_bytes());
        page[pos + LFS_HEADER_BYTES..pos + LFS_HEADER_BYTES + payload.len()]
            .copy_from_slice(payload);

        page[8..16].copy_from_slice(&lsn.to_le_bytes());
        page[16..20].copy_from_slice(&PAGE_RECORD_END.to_le_bytes());
        page[24..26].copy_from_slice(&next_end.to_le_bytes());
        page[32..40].copy_from_slice(&lsn.to_le_bytes());

        self.usa_token = next_usa_token(self.usa_token);
        page[40..42].copy_from_slice(&self.usa_token.to_le_bytes());
        let protected_page = protect_record(page)?;

        self.active_next_off = next_end;
        self.current_lsn = lsn;
        self.last_lsn_data_len = data_len;
        if self.oldest_lsn == 0 {
            self.oldest_lsn = lsn;
        }
        if record_type == LFS_RECORD_CLIENT_RESTART {
            self.client_restart_lsn = lsn;
        }

        Ok(AppendedLogRecord {
            lsn,
            page_vbo: self.active_page_vbo,
            record_offset: rec_off,
            data_len,
            protected_page,
        })
    }

    /// Update `oldest_lsn` monotonically (never backwards, never past `current_lsn`).
    pub fn advance_oldest_lsn(&mut self, new_oldest_lsn: u64) -> Result<(), ParseError> {
        if new_oldest_lsn == 0
            || new_oldest_lsn < self.oldest_lsn
            || new_oldest_lsn > self.current_lsn
        {
            return Err(bad("invalid oldest_lsn advancement"));
        }
        self.oldest_lsn = new_oldest_lsn;
        Ok(())
    }

    /// Build the next `RSTR` page for alternating-slot publication (`slot 0` at `0`,
    /// `slot 1` at `page_size`), returning `(slot_page_vbo, protected_rstr_bytes)`.
    pub fn build_next_rstr_page(&mut self, clean: bool) -> Result<StagedLogPage, ParseError> {
        if self.current_lsn == 0 {
            return Err(bad(
                "cannot build active RSTR page before writing an initial record",
            ));
        }
        self.usa_token = next_usa_token(self.usa_token);
        let cfg = NtfsRestartConfig {
            page_size: self.page_size,
            version: self.version,
            clean,
            current_lsn: self.current_lsn,
            last_lsn_data_len: self.last_lsn_data_len,
            file_size: self.file_size,
            open_log_count: self.open_log_count,
            client_seq: self.client_seq,
            oldest_lsn: self.oldest_lsn,
            client_restart_lsn: self.client_restart_lsn,
            usa_token: self.usa_token,
        };
        let bytes = encode_rstr_page(&cfg)?;
        let slot = self.next_rstr_slot & 1;
        self.next_rstr_slot = slot ^ 1;
        Ok(StagedLogPage {
            page_vbo: (slot as u64) * u64::from(self.page_size),
            bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{le32, le64, parse_ntfs_logfile};
    use super::*;

    const PAGE: u32 = 4096;
    const LOG_BYTES: u64 = 4 * 1024 * 1024;

    #[test]
    fn rstr_and_rcrd_roundtrip_through_public_logfile_parser() {
        let mut ring = NtfsLogRingWriter::new_fresh(PAGE, (1, 1), LOG_BYTES, 1, 7).unwrap();
        let mut raw_log = vec![0xFF_u8; LOG_BYTES as usize];

        let update = NtfsClientUpdateSpec {
            redo_op: NtfsLogOp::UpdateResidentValue,
            undo_op: NtfsLogOp::UpdateResidentValue,
            target_attribute: 24,
            record_offset: 56,
            attribute_offset: 24,
            cluster_block_offset: 0,
            target_vcn: 4,
            target_lcns: vec![100],
            redo_data: b"NEW_DATA".to_vec(),
            undo_data: b"OLD_DATA".to_vec(),
        };
        let payload1 = encode_client_update_payload(&update).unwrap();
        let rec1 = ring
            .append_raw_record(LFS_RECORD_CLIENT, 24, 0, 0, &payload1)
            .unwrap();
        raw_log[rec1.page_vbo as usize..rec1.page_vbo as usize + PAGE as usize]
            .copy_from_slice(&rec1.protected_page);

        let commit = NtfsClientUpdateSpec {
            redo_op: NtfsLogOp::CommitTransaction,
            undo_op: NtfsLogOp::Noop,
            target_attribute: 0,
            record_offset: 0,
            attribute_offset: 0,
            cluster_block_offset: 0,
            target_vcn: 0,
            target_lcns: Vec::new(),
            redo_data: Vec::new(),
            undo_data: Vec::new(),
        };
        let payload2 = encode_client_update_payload(&commit).unwrap();
        let rec2 = ring
            .append_raw_record(LFS_RECORD_CLIENT, 24, rec1.lsn, rec1.lsn, &payload2)
            .unwrap();
        raw_log[rec2.page_vbo as usize..rec2.page_vbo as usize + PAGE as usize]
            .copy_from_slice(&rec2.protected_page);

        let rstr_a = ring.build_next_rstr_page(false).unwrap();
        let rstr_b = ring.build_next_rstr_page(false).unwrap();
        assert_eq!(rstr_a.page_vbo, 0);
        assert_eq!(rstr_b.page_vbo, 4096);
        raw_log[0..4096].copy_from_slice(&rstr_a.bytes);
        raw_log[4096..8192].copy_from_slice(&rstr_b.bytes);

        let plan = parse_ntfs_logfile(&raw_log).unwrap();
        assert!(!plan.restart.is_clean());
        assert_eq!(plan.restart.current_lsn, rec2.lsn);
        assert_eq!(plan.committed_transactions, vec![24]);
        assert_eq!(plan.aborted_transactions, [] as [u32; 0]);
        assert_eq!(plan.redo_actions.len(), 1);
        assert_eq!(plan.redo_actions[0].data, b"NEW_DATA");
    }

    #[test]
    fn ring_writer_wraps_sequence_and_refuses_overwriting_oldest_lsn() {
        let small_log = 52 * u64::from(PAGE);
        let mut ring = NtfsLogRingWriter::new_fresh(PAGE, (1, 1), small_log, 1, 1).unwrap();
        let big_payload = encode_client_update_payload(&NtfsClientUpdateSpec {
            redo_op: NtfsLogOp::Noop,
            undo_op: NtfsLogOp::Noop,
            target_attribute: 0,
            record_offset: 0,
            attribute_offset: 0,
            cluster_block_offset: 0,
            target_vcn: 0,
            target_lcns: Vec::new(),
            redo_data: vec![0xAB; 2500],
            undo_data: Vec::new(),
        })
        .unwrap();

        // 48 ring pages, 1 record fits per page -> 48 appends fill the ring, 49th must fail!
        let mut last_lsn = 0;
        for _ in 0..48 {
            let rec = ring
                .append_raw_record(LFS_RECORD_CLIENT, 24, last_lsn, 0, &big_payload)
                .unwrap();
            last_lsn = rec.lsn;
        }
        let state_before_full = ring.current_lsn();
        let err = ring
            .append_raw_record(LFS_RECORD_CLIENT, 24, last_lsn, 0, &big_payload)
            .unwrap_err();
        assert!(err.to_string().contains("ring full"));
        assert_eq!(ring.current_lsn(), state_before_full);

        // Advancing oldest_lsn past the first page unlocks wrapping with sequence == 2!
        ring.advance_oldest_lsn(last_lsn).unwrap();
        let wrapped = ring
            .append_raw_record(LFS_RECORD_CLIENT, 24, last_lsn, 0, &big_payload)
            .unwrap();
        assert_eq!(wrapped.page_vbo, ring.first_ring_vbo());
        assert_eq!(lsn_sequence(wrapped.lsn, ring.seq_num_bits()).unwrap(), 2);
        assert!(wrapped.lsn > last_lsn);
    }

    #[test]
    fn restart_table_and_opcodes_roundtrip_cleanly() {
        for raw in 0_u16..=0x26 {
            let op = NtfsLogOp::from_raw(raw);
            assert_eq!(op.to_raw(), raw);
        }
        let e0 = encode_open_attribute_entry(0x80, 0, 1_u64 << 48, 100);
        let e2 = encode_open_attribute_entry(0xA0, 4096, (2_u64 << 48) | 5, 200);
        let table = encode_restart_table(
            40,
            &BTreeMap::from([(24_u32, e0.to_vec()), (104_u32, e2.to_vec())]),
        )
        .unwrap();
        assert_eq!(le16(&table, 0).unwrap(), 40);
        assert_eq!(le16(&table, 2).unwrap(), 3);
        assert_eq!(le16(&table, 4).unwrap(), 2);
        assert_eq!(le32(&table, 16).unwrap(), 64);
        assert_eq!(le32(&table, 20).unwrap(), 64);
        assert_eq!(le64(&table, 24 + 16).unwrap(), 1_u64 << 48);
        assert_eq!(le64(&table, 104 + 16).unwrap(), (2_u64 << 48) | 5);
    }
}
