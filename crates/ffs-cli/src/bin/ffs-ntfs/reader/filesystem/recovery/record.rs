//! Bounded native NTFS $LogFile record and checkpoint preflight.
//!
//! This is the first read-only recovery primitive after restart-area admission.
//! It validates the record page's update-sequence protection and the native LFS
//! record envelope, then follows retained transaction and checkpoint references.
//! With a volume, preflight stages supported FILE edits privately. This does not
//! establish a recovered view or authorize backing writes.

mod payload;
mod preflight;

use super::{
    Cx, NtfsVolume, Restart, Result, SECTOR, bytes, checkpoint, corrupt, read_exact, u16_at, u32_at, u64_at,
    unsupported,
};

const RCRD: [u8; 4] = *b"RCRD";
const FFFF: [u8; 4] = [0xFF; 4];
const LFS_CLIENT_RECORD: u32 = 1;
const LFS_CLIENT_RESTART: u32 = 2;
const MULTI_PAGE: u16 = 0x0001;
const PAGE_RECORD_END: u32 = 0x0000_0001;
const LFS_HEADER_BYTES: usize = 0x30;
const LOG_RECORD_BYTES: usize = 0x20;
const NTFS_RESTART_BYTES: usize = 0x40;
const MAX_OPERATION: u16 = 0x25;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TailRecord {
    pub(super) transaction_id: u32,
    pub(super) redo_op: u16,
    pub(super) undo_op: u16,
}

/// An owned, validated LFS envelope. Keep client bytes and both native links
/// together; a recovery consumer must not confuse a transaction ID with an LSN.
#[derive(Debug)]
struct LogRecord {
    lsn: u64,
    previous: u64,
    undo_next: u64,
    kind: u32,
    summary: TailRecord,
    data: Vec<u8>,
}

#[derive(Debug)]
struct RecordPage {
    bytes: Vec<u8>,
    next_record_off: u16,
}

fn lsn_to_vbo(lsn: u64, seq_num_bits: u32) -> Result<u64> {
    if !(3..64).contains(&seq_num_bits) {
        return Err(corrupt(0, "invalid $LogFile LSN sequence width"));
    }
    Ok(lsn.wrapping_shl(seq_num_bits) >> (seq_num_bits - 3))
}

fn lsn_page_offset(lsn: u64, page_size: u32) -> Result<usize> {
    if page_size < SECTOR as u32 || !page_size.is_power_of_two() {
        return Err(corrupt(0, "invalid $LogFile record page size"));
    }
    let mask = u64::from(page_size - 1);
    usize::try_from(lsn.wrapping_shl(3) & mask)
        .map_err(|_| corrupt(0, "$LogFile record offset overflow"))
}

fn target_required(op: u16) -> bool {
    const BITS: [u8; 5] = [0xFC, 0xFB, 0xFF, 0x10, 0x06];
    op <= 0x22 && (BITS[usize::from(op >> 3)] >> (op & 7)) & 1 != 0
}

fn restore_page(
    cx: &Cx,
    mut page: Vec<u8>,
    restart: &Restart,
    page_vbo: u64,
) -> Result<RecordPage> {
    checkpoint(cx)?;
    let page_size = usize::try_from(restart.log_page)
        .map_err(|_| corrupt(page_vbo, "$LogFile page size overflow"))?;
    if page.len() != page_size || page_size < 64 {
        return Err(corrupt(page_vbo, "short $LogFile record page"));
    }
    let signature = bytes::<4>(&page, 0)?;
    if signature == FFFF {
        return Err(corrupt(
            page_vbo,
            "$LogFile current LSN points into an erased record page",
        ));
    }
    if signature != RCRD {
        return Err(corrupt(page_vbo, "invalid $LogFile record page signature"));
    }
    let fix_off = usize::from(u16_at(&page, 4)?);
    let fix_num = usize::from(u16_at(&page, 6)?);
    let data_off = usize::from(restart.data_off);
    if fix_num != page_size / SECTOR + 1
        || fix_off < 0x28
        || !fix_off.is_multiple_of(2)
        || fix_off
            .checked_add(fix_num * 2)
            .is_none_or(|end| end > data_off || end > SECTOR - 2)
    {
        return Err(corrupt(page_vbo, "invalid $LogFile record-page USA bounds"));
    }
    let token = bytes::<2>(&page, fix_off)?;
    for sector in 1..fix_num {
        checkpoint(cx)?;
        if bytes::<2>(&page, sector * SECTOR - 2)? != token {
            return Err(corrupt(page_vbo, "torn $LogFile record page"));
        }
    }
    for sector in 1..fix_num {
        let saved = bytes::<2>(&page, fix_off + sector * 2)?;
        page[sector * SECTOR - 2..sector * SECTOR].copy_from_slice(&saved);
    }

    let flags = u32_at(&page, 16)?;
    let page_count = u16_at(&page, 20)?;
    let page_pos = u16_at(&page, 22)?;
    let next_record_off = u16_at(&page, 24)?;
    let _last_end_lsn = u64_at(&page, 32)?;
    if flags & !PAGE_RECORD_END != 0
        || page_count == 0
        || page_pos == 0
        || page_pos > page_count
        || (next_record_off != 0
            && (usize::from(next_record_off) < data_off
                || usize::from(next_record_off) > page_size
                || !next_record_off.is_multiple_of(8)))
    {
        return Err(corrupt(page_vbo, "invalid $LogFile record-page envelope"));
    }
    if restart.version.0 >= 2 {
        let file_off = u64::from(u32_at(&page, 60)?);
        // Native v2 pages reset this tail-copy field to zero after publication.
        if file_off != 0 && file_off != page_vbo {
            return Err(corrupt(
                page_vbo,
                "$LogFile record page identifies a different file offset",
            ));
        }
    }
    checkpoint(cx)?;
    Ok(RecordPage {
        next_record_off,
        bytes: page,
    })
}

fn validate_lsn_reference(restart: &Restart, lsn: u64, label: &str) -> Result<()> {
    if lsn == 0 {
        return Ok(());
    }
    let vbo = lsn_to_vbo(lsn, restart.seq_num_bits)?;
    let offset = lsn_page_offset(lsn, restart.log_page)?;
    let page_bytes = u64::from(restart.log_page);
    let reserved = if restart.version.0 >= 2 { 34 } else { 4 };
    let header = usize::from(restart.record_header_len);
    if vbo >= restart.file_size
        || vbo / page_bytes < reserved
        || offset < usize::from(restart.data_off)
        || header < LFS_HEADER_BYTES
        || !header.is_multiple_of(8)
        || offset
            .checked_add(header)
            .is_none_or(|end| end as u64 > page_bytes)
        || lsn > restart.current_lsn
    {
        return Err(corrupt(
            vbo,
            format!("$LogFile {label} LSN does not address a retained record location"),
        ));
    }
    Ok(())
}

fn payload_range(total: usize, offset: u16, len: u16, minimum: usize, label: &str) -> Result<()> {
    let offset = usize::from(offset);
    let len = usize::from(len);
    if len == 0 {
        if offset != 0 && (offset < minimum || !offset.is_multiple_of(8)) {
            return Err(corrupt(0, format!("invalid empty $LogFile {label} range")));
        }
        return Ok(());
    }
    if offset < minimum
        || !offset.is_multiple_of(8)
        || offset.checked_add(len).is_none_or(|end| end > total)
    {
        return Err(corrupt(0, format!("invalid $LogFile {label} range")));
    }
    Ok(())
}

fn parse_client_update(data: &[u8]) -> Result<TailRecord> {
    if data.len() < LOG_RECORD_BYTES + 8 {
        return Err(corrupt(0, "short NTFS client log record"));
    }
    let redo_op = u16_at(data, 0)?;
    let undo_op = u16_at(data, 2)?;
    if redo_op > MAX_OPERATION || undo_op > MAX_OPERATION {
        return Err(unsupported(format!(
            "unknown NTFS $LogFile operation redo={redo_op:#04x} undo={undo_op:#04x}"
        )));
    }
    let redo_off = u16_at(data, 4)?;
    let redo_len = u16_at(data, 6)?;
    let undo_off = u16_at(data, 8)?;
    let undo_len = u16_at(data, 10)?;
    let target_attr = u16_at(data, 12)?;
    let lcns_follow = usize::from(u16_at(data, 14)?);
    let reserved = u16_at(data, 22)?;
    let mapping_bytes = LOG_RECORD_BYTES
        .checked_add(lcns_follow.max(1) * 8)
        .ok_or_else(|| corrupt(0, "$LogFile LCN-array size overflow"))?;
    if mapping_bytes > data.len() || reserved != 0 {
        return Err(corrupt(0, "invalid NTFS client log-record header"));
    }
    if target_attr == 0 && (target_required(redo_op) || target_required(undo_op)) {
        return Err(corrupt(
            0,
            "NTFS client log operation requires a target attribute",
        ));
    }
    payload_range(data.len(), redo_off, redo_len, mapping_bytes, "redo")?;
    payload_range(data.len(), undo_off, undo_len, mapping_bytes, "undo")?;
    Ok(TailRecord {
        transaction_id: 0,
        redo_op,
        undo_op,
    })
}

fn validate_client_restart(restart: &Restart, data: &[u8]) -> Result<()> {
    if data.len() < NTFS_RESTART_BYTES {
        return Err(corrupt(0, "short NTFS client restart record"));
    }
    let version = (u32_at(data, 0)?, u32_at(data, 4)?);
    if !matches!(version, (1, 0) | (1, 1) | (2, 0)) {
        return Err(unsupported(format!(
            "unsupported NTFS client restart version {}.{}",
            version.0, version.1
        )));
    }
    for (offset, label) in [
        (8, "checkpoint"),
        (16, "open-attribute-table"),
        (24, "attribute-name-table"),
        (32, "dirty-page-table"),
        (40, "transaction-table"),
    ] {
        validate_lsn_reference(restart, u64_at(data, offset)?, label)?;
    }
    for offset in [48, 52, 56, 60] {
        let bytes = u64::from(u32_at(data, offset)?);
        if bytes > restart.file_size {
            return Err(corrupt(0, "$LogFile restart table exceeds journal size"));
        }
    }
    Ok(())
}

fn read_record(
    cx: &Cx,
    restart: &Restart,
    stream_length: u64,
    lsn: u64,
    read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>>,
) -> Result<LogRecord> {
    checkpoint(cx)?;
    let Some(client_seq) = restart.active_client_seq else {
        return Err(corrupt(0, "dirty $LogFile has no active NTFS client"));
    };
    if lsn == 0 || restart.file_size > stream_length {
        return Err(corrupt(
            0,
            "invalid dirty $LogFile current LSN or file size",
        ));
    }
    validate_lsn_reference(restart, lsn, "requested-record")?;
    if restart
        .active_client_oldest_lsn
        .is_some_and(|oldest| lsn < oldest)
    {
        return Err(corrupt(
            0,
            "$LogFile record precedes the retained client window",
        ));
    }
    let vbo = lsn_to_vbo(lsn, restart.seq_num_bits)?;
    let page_size = u64::from(restart.log_page);
    let page_vbo = vbo & !(page_size - 1);
    let first_page = if restart.version.0 >= 2 {
        0x22_u64
            .checked_mul(page_size)
            .ok_or_else(|| corrupt(0, "$LogFile first-page offset overflow"))?
    } else {
        4_u64
            .checked_mul(page_size)
            .ok_or_else(|| corrupt(0, "$LogFile first-page offset overflow"))?
    };
    if vbo >= restart.file_size || page_vbo < first_page {
        return Err(corrupt(
            vbo,
            "$LogFile current LSN does not address a record page",
        ));
    }
    let page = restore_page(
        cx,
        read_exact(
            cx,
            stream_length,
            page_vbo,
            usize::try_from(restart.log_page)
                .map_err(|_| corrupt(page_vbo, "$LogFile page size overflow"))?,
            read,
        )?,
        restart,
        page_vbo,
    )?;
    let record_off = lsn_page_offset(lsn, restart.log_page)?;
    let header_len = usize::from(restart.record_header_len);
    if header_len < LFS_HEADER_BYTES
        || !header_len.is_multiple_of(8)
        || record_off < usize::from(restart.data_off)
        || record_off
            .checked_add(header_len)
            .is_none_or(|end| end > page.bytes.len())
    {
        return Err(corrupt(vbo, "invalid $LogFile current record offset"));
    }
    let header = &page.bytes[record_off..];
    if u64_at(header, 0)? != lsn {
        return Err(corrupt(vbo, "$LogFile current record LSN mismatch"));
    }
    let data_len = usize::try_from(u32_at(header, 24)?)
        .map_err(|_| corrupt(vbo, "$LogFile client data length overflow"))?;
    let record_type = u32_at(header, 32)?;
    let transaction_id = u32_at(header, 36)?;
    let flags = u16_at(header, 40)?;
    if flags & !MULTI_PAGE != 0 || u16_at(header, 28)? != client_seq || u16_at(header, 30)? != 0 {
        return Err(corrupt(
            vbo,
            "invalid $LogFile client identity or record flags",
        ));
    }
    let previous = u64_at(header, 8)?;
    let undo_next = u64_at(header, 16)?;
    for (reference, label) in [(previous, "previous-record"), (undo_next, "undo-next")] {
        validate_lsn_reference(restart, reference, label)?;
        if reference != 0 && reference >= lsn {
            return Err(corrupt(
                vbo,
                "$LogFile predecessor is self-referential or in the future",
            ));
        }
    }
    if u64::try_from(data_len).unwrap_or(u64::MAX) > restart.file_size {
        return Err(corrupt(
            vbo,
            "$LogFile client record exceeds journal capacity",
        ));
    }
    if lsn == restart.current_lsn && u32::try_from(data_len).ok() != Some(restart.last_lsn_data_len)
    {
        return Err(corrupt(
            vbo,
            "$LogFile current record length disagrees with restart metadata",
        ));
    }
    let data = payload::read(cx, restart, stream_length, lsn, page_vbo, page, read)?;
    let mut tail = match record_type {
        LFS_CLIENT_RECORD => parse_client_update(&data)?,
        LFS_CLIENT_RESTART => {
            validate_client_restart(restart, &data)?;
            TailRecord {
                transaction_id,
                redo_op: 0,
                undo_op: 0,
            }
        }
        other => {
            return Err(unsupported(format!(
                "unknown NTFS $LogFile record type {other}"
            )));
        }
    };
    tail.transaction_id = transaction_id;
    checkpoint(cx)?;
    Ok(LogRecord {
        lsn,
        previous,
        undo_next,
        kind: record_type,
        summary: tail,
        data,
    })
}

/// Preflight the selected checkpoint and reachable retained transaction links.
/// With an immutable volume, execute the supported MFT recovery profile in a
/// private stage. Success is NOT permission to publish it or mount a dirty log.
pub(super) fn validate_dirty_volume(
    cx: &Cx,
    restart: &Restart,
    stream_length: u64,
    read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>>,
    volume: Option<&NtfsVolume>,
) -> Result<TailRecord> {
    checkpoint(cx)?;
    for (reference, label) in [
        (restart.active_client_oldest_lsn, "oldest-client"),
        (restart.active_client_restart_lsn, "client-restart"),
    ] {
        if let Some(lsn) = reference {
            validate_lsn_reference(restart, lsn, label)?;
        }
    }
    // This shared budget covers the tail, checkpoint dumps, and every followed
    // link, including re-reads. Per-record bounds alone do not bound a graph.
    let mut remaining = 64_u64 * 1024 * 1024;
    let mut bounded = |offset: u64, size: usize| {
        checkpoint(cx)?;
        remaining = remaining.checked_sub(size as u64).ok_or_else(|| {
            unsupported("$LogFile recovery preflight exceeds the 64 MiB I/O budget")
        })?;
        read(offset, size)
    };
    let tail = read_record(
        cx,
        restart,
        stream_length,
        restart.current_lsn,
        &mut bounded,
    )?;
    preflight::validate(cx, restart, stream_length, &tail, &mut bounded, volume)?;
    checkpoint(cx)?;
    Ok(tail.summary)
}

/// Journal-only fixtures exercise the identical bounded decoding and Analysis
/// path without inventing target records or an allocation-bitmap authority.
#[cfg(test)]
pub(super) fn validate_dirty_tail(
    cx: &Cx,
    restart: &Restart,
    stream_length: u64,
    read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>>,
) -> Result<TailRecord> {
    validate_dirty_volume(cx, restart, stream_length, read, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffs_error::FfsError;

    const PAGE: usize = 4096;
    const LOG: u64 = 4 * 1024 * 1024;

    fn restart(lsn: u64) -> Restart {
        Restart {
            system_page: PAGE as u32,
            log_page: PAGE as u32,
            version: (2, 0),
            clean: false,
            current_lsn: lsn,
            seq_num_bits: 44,
            file_size: LOG,
            last_lsn_data_len: 48,
            record_header_len: LFS_HEADER_BYTES as u16,
            data_off: 64,
            active_client_seq: Some(9),
            active_client_oldest_lsn: Some(lsn),
            active_client_restart_lsn: None,
            area: Vec::new(),
        }
    }

    fn lsn_for(vbo: u64) -> u64 {
        (1_u64 << 20) + vbo / 8
    }

    fn protect(mut page: Vec<u8>, token: u16) -> Vec<u8> {
        let fix_num = PAGE / SECTOR + 1;
        page[4..6].copy_from_slice(&40_u16.to_le_bytes());
        page[6..8].copy_from_slice(&(fix_num as u16).to_le_bytes());
        page[40..42].copy_from_slice(&token.to_le_bytes());
        for sector in 1..fix_num {
            let end = sector * SECTOR;
            let saved = [page[end - 2], page[end - 1]];
            page[40 + sector * 2..42 + sector * 2].copy_from_slice(&saved);
            page[end - 2..end].copy_from_slice(&token.to_le_bytes());
        }
        page
    }

    fn page(op: u16, undo: u16) -> (Restart, Vec<u8>) {
        let page_vbo = 0x22_u64 * PAGE as u64;
        let record_off = 128_u64;
        let lsn = lsn_for(page_vbo + record_off);
        let restart = restart(lsn);
        let mut page = vec![0; PAGE];
        page[..4].copy_from_slice(b"RCRD");
        page[8..16].copy_from_slice(&lsn.to_le_bytes());
        page[16..20].copy_from_slice(&PAGE_RECORD_END.to_le_bytes());
        page[20..22].copy_from_slice(&1_u16.to_le_bytes());
        page[22..24].copy_from_slice(&1_u16.to_le_bytes());
        page[24..26].copy_from_slice(&256_u16.to_le_bytes());
        page[32..40].copy_from_slice(&lsn.to_le_bytes());
        page[60..64].copy_from_slice(&(page_vbo as u32).to_le_bytes());
        let at = record_off as usize;
        page[at..at + 8].copy_from_slice(&lsn.to_le_bytes());
        page[at + 24..at + 28].copy_from_slice(&48_u32.to_le_bytes());
        page[at + 28..at + 30].copy_from_slice(&9_u16.to_le_bytes());
        page[at + 30..at + 32].copy_from_slice(&0_u16.to_le_bytes());
        page[at + 32..at + 36].copy_from_slice(&LFS_CLIENT_RECORD.to_le_bytes());
        page[at + 36..at + 40].copy_from_slice(&17_u32.to_le_bytes());
        let data = at + LFS_HEADER_BYTES;
        page[data..data + 2].copy_from_slice(&op.to_le_bytes());
        page[data + 2..data + 4].copy_from_slice(&undo.to_le_bytes());
        page[data + 4..data + 6].copy_from_slice(&40_u16.to_le_bytes());
        page[data + 8..data + 10].copy_from_slice(&40_u16.to_le_bytes());
        page[data + 12..data + 14].copy_from_slice(&24_u16.to_le_bytes());
        page[data + 40..data + 48].copy_from_slice(&[1; 8]);
        (restart, protect(page, 0xCAFE))
    }

    fn check(restart: &Restart, page: &[u8]) -> Result<TailRecord> {
        let page_vbo = lsn_to_vbo(restart.current_lsn, restart.seq_num_bits)? & !(PAGE as u64 - 1);
        validate_dirty_tail(&Cx::for_testing(), restart, LOG, &mut |offset, size| {
            if offset != page_vbo || size != PAGE {
                return Err(corrupt(offset, "unexpected test read"));
            }
            Ok(page.to_vec())
        })
    }

    #[test]
    fn every_native_update_opcode_has_a_bounded_single_page_envelope() {
        for op in 0..=MAX_OPERATION {
            let (restart, page) = page(op, 0);
            let tail = check(&restart, &page).unwrap();
            assert_eq!(
                (tail.transaction_id, tail.redo_op, tail.undo_op),
                (17, op, 0)
            );
        }
    }

    #[test]
    fn unknown_operations_record_types_and_client_identity_are_refused() {
        let (restart, raw) = page(MAX_OPERATION + 1, 0);
        assert!(matches!(
            check(&restart, &raw),
            Err(FfsError::UnsupportedFeature(_))
        ));
        let (restart, mut raw2) = page(0, 0);
        let at = lsn_page_offset(restart.current_lsn, restart.log_page).unwrap();
        raw2[at + 32..at + 36].copy_from_slice(&99_u32.to_le_bytes());
        assert!(matches!(
            check(&restart, &raw2),
            Err(FfsError::UnsupportedFeature(_))
        ));
        let (restart, mut raw3) = page(0, 0);
        raw3[at + 28..at + 30].copy_from_slice(&8_u16.to_le_bytes());
        assert!(matches!(
            check(&restart, &raw3),
            Err(FfsError::Corruption { .. })
        ));
    }

    #[test]
    fn published_v2_record_pages_do_not_require_a_tail_copy_offset() {
        let (restart, mut raw) = page(7, 0);
        raw[60..64].fill(0);
        assert_eq!(check(&restart, &raw).unwrap().redo_op, 7);
    }

    #[test]
    fn single_page_records_require_valid_completion_evidence() {
        for mutation in 0..3 {
            let (restart, mut raw) = page(7, 0);
            match mutation {
                0 => raw[16..20].fill(0),
                1 => raw[32..40].fill(0),
                _ => raw[8..16].fill(0),
            }
            assert!(check(&restart, &raw).is_err());
        }
    }

    #[test]
    fn every_record_page_sector_requires_a_valid_update_sequence_trailer() {
        let (restart, page) = page(0, 0);
        for sector in 1..=PAGE / SECTOR {
            let mut torn = page.clone();
            torn[sector * SECTOR - 1] ^= 1;
            assert!(matches!(
                check(&restart, &torn),
                Err(FfsError::Corruption { .. })
            ));
        }
    }

    #[test]
    fn malformed_record_offsets_lengths_and_lsn_identity_never_escape() {
        let (restart, page) = page(0, 0);
        let at = lsn_page_offset(restart.current_lsn, restart.log_page).unwrap();
        for mutate in 0..4 {
            let mut bad = page.clone();
            match mutate {
                0 => bad[24..26].copy_from_slice(&64_u16.to_le_bytes()),
                1 => bad[at..at + 8].copy_from_slice(&1_u64.to_le_bytes()),
                2 => bad[at + 24..at + 28].copy_from_slice(&u32::MAX.to_le_bytes()),
                _ => bad[60..64].copy_from_slice(&4096_u32.to_le_bytes()),
            }
            assert!(matches!(
                check(&restart, &bad),
                Err(FfsError::Corruption { .. })
            ));
        }
    }

    #[test]
    fn inconsistent_multi_page_flags_are_refused() {
        let (restart, mut page) = page(0, 0);
        let at = lsn_page_offset(restart.current_lsn, restart.log_page).unwrap();
        page[at + 40..at + 42].copy_from_slice(&MULTI_PAGE.to_le_bytes());
        assert!(matches!(
            check(&restart, &page),
            Err(FfsError::Corruption { .. })
        ));
    }

    #[test]
    fn client_restart_records_validate_version_and_referenced_lsns() {
        let (mut restart, mut page) = page(0, 0);
        restart.last_lsn_data_len = NTFS_RESTART_BYTES as u32;
        let at = lsn_page_offset(restart.current_lsn, restart.log_page).unwrap();
        page[at + 24..at + 28].copy_from_slice(&(NTFS_RESTART_BYTES as u32).to_le_bytes());
        page[at + 32..at + 36].copy_from_slice(&LFS_CLIENT_RESTART.to_le_bytes());
        let data = at + LFS_HEADER_BYTES;
        page[data..data + NTFS_RESTART_BYTES].fill(0);
        page[data..data + 4].copy_from_slice(&1_u32.to_le_bytes());
        page[data + 4..data + 8].copy_from_slice(&1_u32.to_le_bytes());
        page[data + 8..data + 16].copy_from_slice(&restart.current_lsn.to_le_bytes());
        let page = protect(page, 0xCAFE);
        let tail = check(&restart, &page).unwrap();
        assert_eq!((tail.redo_op, tail.undo_op), (0, 0));

        let mut bad = page;
        let mut restored = bad.clone();
        // Change the on-page version through a fresh unprotected page so USA
        // checks still validate the intended corruption rather than the edit.
        for sector in 1..=PAGE / SECTOR {
            let saved = bytes::<2>(&restored, 40 + sector * 2).unwrap();
            restored[sector * SECTOR - 2..sector * SECTOR].copy_from_slice(&saved);
        }
        restored[data..data + 4].copy_from_slice(&3_u32.to_le_bytes());
        bad = protect(restored, 0xBEEF);
        assert!(matches!(
            check(&restart, &bad),
            Err(FfsError::UnsupportedFeature(_))
        ));
    }
}
