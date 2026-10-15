//! Chronological LFS traversal through the selected restart's current LSN.
//!
//! Native framing reference: Linux v6.17 fs/ntfs3/fslog.c, final_log_off and
//! next_log_lsn. Transaction predecessor links are NOT chronological links.
//! This does not discover a newer durable tail or authorize recovery writes.

use super::super::{
    Cx, LogRecord, Restart, Result, checkpoint, corrupt, lsn_to_vbo, read_exact,
    read_record, restore_page, u64_at, unsupported, validate_lsn_reference,
};

const MAX_RECORDS: usize = 4096;
const MAX_RETAINED_BYTES: usize = 16 * 1024 * 1024;

struct Position {
    page: u64,
    offset: usize,
    sequence: u64,
}

fn next_page(restart: &Restart, position: &mut Position) -> Result<()> {
    let page_bytes = u64::from(restart.log_page);
    let first = (if restart.version.0 >= 2 { 34_u64 } else { 4 }) * page_bytes;
    position.page = position.page.checked_add(page_bytes)
        .ok_or_else(|| corrupt(0, "$LogFile chronological page offset overflow"))?;
    if position.page == restart.file_size {
        position.page = first;
        position.sequence = position.sequence.checked_add(1)
            .filter(|sequence| *sequence < (1_u64 << restart.seq_num_bits))
            .ok_or_else(|| unsupported("$LogFile LSN sequence rollover is not admitted"))?;
    }
    if position.page < first || position.page >= restart.file_size {
        return Err(corrupt(0, "$LogFile chronological page leaves the record ring"));
    }
    position.offset = usize::from(restart.data_off);
    Ok(())
}

fn end_position(restart: &Restart, record: &LogRecord) -> Result<Position> {
    validate_lsn_reference(restart, record.lsn, "chronological")?;
    let page_size = usize::try_from(restart.log_page)
        .map_err(|_| corrupt(0, "$LogFile chronological page size overflow"))?;
    let page_bytes = u64::from(restart.log_page);
    let vbo = lsn_to_vbo(record.lsn, restart.seq_num_bits)?;
    let mut position = Position {
        page: vbo & !(page_bytes - 1),
        offset: usize::try_from(vbo & (page_bytes - 1))
            .map_err(|_| corrupt(0, "$LogFile chronological offset overflow"))?,
        sequence: record.lsn >> (64 - restart.seq_num_bits),
    };
    let mut remaining = usize::from(restart.record_header_len)
        .checked_add(record.data.len())
        .ok_or_else(|| corrupt(0, "$LogFile chronological record length overflow"))?;
    let first = (if restart.version.0 >= 2 { 34_u64 } else { 4 }) * page_bytes;
    let capacity = page_size.checked_sub(usize::from(restart.data_off))
        .filter(|capacity| *capacity != 0)
        .ok_or_else(|| corrupt(0, "$LogFile chronological page has no data area"))?;
    let ring_pages = restart.file_size.checked_sub(first)
        .filter(|bytes| bytes.is_multiple_of(page_bytes))
        .ok_or_else(|| corrupt(0, "$LogFile chronological ring geometry is invalid"))?
        / page_bytes;
    let initial_capacity = page_size - position.offset;
    let needed = 1 + remaining.saturating_sub(initial_capacity).div_ceil(capacity) as u64;
    if needed > ring_pages || needed > MAX_RECORDS as u64 {
        return Err(unsupported("$LogFile chronological record exceeds the page budget"));
    }
    while remaining > page_size - position.offset {
        remaining -= page_size - position.offset;
        next_page(restart, &mut position)?;
    }
    position.offset += remaining;
    Ok(position)
}

fn successor(
    cx: &Cx,
    restart: &Restart,
    record: &LogRecord,
    read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>>,
) -> Result<Option<u64>> {
    checkpoint(cx)?;
    if record.lsn == restart.current_lsn {
        return Ok(None);
    }
    let mut position = end_position(restart, record)?;
    let page_size = usize::try_from(restart.log_page)
        .map_err(|_| corrupt(0, "$LogFile chronological page size overflow"))?;
    let page = restore_page(
        cx,
        read_exact(cx, restart.file_size, position.page, page_size, read)?,
        restart,
        position.page,
    )?;
    let last = u64_at(&page.bytes, 8)?;
    let last_end = u64_at(&page.bytes, 32)?;
    if last < record.lsn || last_end < record.lsn || last_end > last {
        return Err(corrupt(position.page, "$LogFile chronological ending is stale"));
    }
    if last == record.lsn {
        // A partially filled page can be sealed. Padding is not a next record.
        next_page(restart, &mut position)?;
    } else {
        position.offset = position.offset.checked_add(7)
            .map(|offset| offset & !7)
            .ok_or_else(|| corrupt(0, "$LogFile chronological alignment overflow"))?;
        let header_end = position.offset.checked_add(usize::from(restart.record_header_len));
        if header_end.is_none_or(|end| end > page_size)
            || (page.next_record_off != 0 && position.offset >= usize::from(page.next_record_off))
        {
            return Err(corrupt(position.page, "$LogFile next record cannot fit its claimed page"));
        }
    }
    let address_bits = 64 - restart.seq_num_bits;
    let vbo = position.page.checked_add(position.offset as u64)
        .ok_or_else(|| corrupt(0, "$LogFile chronological LSN address overflow"))?;
    if vbo / 8 >= (1_u64 << address_bits) {
        return Err(corrupt(vbo, "$LogFile chronological address overlaps its sequence bits"));
    }
    let next = (position.sequence << address_bits) | (vbo / 8);
    if next <= record.lsn || next > restart.current_lsn {
        return Err(corrupt(vbo, "$LogFile chronology cannot reach the selected current LSN"));
    }
    validate_lsn_reference(restart, next, "next-chronological")?;
    Ok(Some(next))
}

/// Return every native record in an inclusive, physically contiguous window.
/// Every record is decoded through the ordinary protected payload reader.
/// On failure the private collection is dropped; no partial history escapes.
pub(super) fn collect(
    cx: &Cx,
    restart: &Restart,
    stream_length: u64,
    first: u64,
    read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>>,
) -> Result<Vec<LogRecord>> {
    checkpoint(cx)?;
    validate_lsn_reference(restart, first, "scan-start")?;
    let mut next = Some(first);
    let mut result = Vec::new();
    let mut retained = 0_usize;
    while let Some(lsn) = next {
        checkpoint(cx)?;
        if result.len() == MAX_RECORDS {
            return Err(unsupported("$LogFile chronology exceeds 4096 records"));
        }
        let record = read_record(cx, restart, stream_length, lsn, read)?;
        retained = retained.checked_add(record.data.len())
            .filter(|bytes| *bytes <= MAX_RETAINED_BYTES)
            .ok_or_else(|| unsupported("$LogFile chronological payloads exceed 16 MiB"))?;
        next = successor(cx, restart, &record, read)?;
        result.push(record);
    }
    checkpoint(cx)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::{LFS_CLIENT_RECORD, MULTI_PAGE, PAGE_RECORD_END, TailRecord};
    use std::collections::BTreeMap;

    const PAGE: usize = 4096;
    const LOG: u64 = 50 * PAGE as u64;
    const FIRST: u64 = 34 * PAGE as u64;

    fn lsn(sequence: u64, vbo: u64) -> u64 {
        (sequence << 15) | vbo / 8
    }

    fn restart(current: u64) -> Restart {
        Restart {
            system_page: PAGE as u32, log_page: PAGE as u32, version: (2, 0),
            clean: false, current_lsn: current, seq_num_bits: 49, file_size: LOG,
            last_lsn_data_len: 40, record_header_len: 48, data_off: 64,
            active_client_seq: Some(9), active_client_oldest_lsn: None,
            active_client_restart_lsn: None, area: Vec::new(),
        }
    }

    fn plain(last: u64, last_end: u64, next: u16) -> Vec<u8> {
        let mut page = vec![0; PAGE];
        page[..4].copy_from_slice(b"RCRD");
        page[4..6].copy_from_slice(&40_u16.to_le_bytes());
        page[6..8].copy_from_slice(&9_u16.to_le_bytes());
        page[8..16].copy_from_slice(&last.to_le_bytes());
        page[16..20].copy_from_slice(&PAGE_RECORD_END.to_le_bytes());
        page[20..22].copy_from_slice(&1_u16.to_le_bytes());
        page[22..24].copy_from_slice(&1_u16.to_le_bytes());
        page[24..26].copy_from_slice(&next.to_le_bytes());
        page[32..40].copy_from_slice(&last_end.to_le_bytes());
        page
    }

    fn put(page: &mut [u8], offset: usize, current: u64, transaction: u32, previous: u64) {
        let header = &mut page[offset..offset + 48];
        header[..8].copy_from_slice(&current.to_le_bytes());
        header[8..16].copy_from_slice(&previous.to_le_bytes());
        header[24..28].copy_from_slice(&40_u32.to_le_bytes());
        header[28..30].copy_from_slice(&9_u16.to_le_bytes());
        header[32..36].copy_from_slice(&LFS_CLIENT_RECORD.to_le_bytes());
        header[36..40].copy_from_slice(&transaction.to_le_bytes());
    }

    fn protect(mut page: Vec<u8>) -> Vec<u8> {
        let token = 0xCAFE_u16.to_le_bytes();
        page[40..42].copy_from_slice(&token);
        for sector in 1..=PAGE / 512 {
            let end = sector * 512;
            let saved = [page[end - 2], page[end - 1]];
            page[40 + sector * 2..42 + sector * 2].copy_from_slice(&saved);
            page[end - 2..end].copy_from_slice(&token);
        }
        page
    }

    fn check(restart: &Restart, first: u64, pages: &BTreeMap<u64, Vec<u8>>) -> Result<Vec<LogRecord>> {
        collect(&Cx::for_testing(), restart, LOG, first, &mut |offset, size| {
            assert_eq!(size, PAGE);
            pages.get(&offset).cloned().ok_or_else(|| corrupt(offset, "missing test page"))
        })
    }

    fn interleaved() -> (Restart, u64, BTreeMap<u64, Vec<u8>>) {
        let first = lsn(1, FIRST + 64);
        let middle = lsn(1, FIRST + 152);
        let last = lsn(1, FIRST + 240);
        let mut page = plain(last, last, 328);
        put(&mut page, 64, first, 24, 0);
        put(&mut page, 152, middle, 64, 0);
        put(&mut page, 240, last, 24, first);
        (restart(last), first, BTreeMap::from([(FIRST, protect(page))]))
    }

    #[test]
    fn physical_order_includes_transactions_missing_from_the_tail_chain() {
        let (restart, first, pages) = interleaved();
        let records = check(&restart, first, &pages).unwrap();
        assert_eq!(records.iter().map(|r| r.summary.transaction_id).collect::<Vec<_>>(), [24, 64, 24]);
        assert_eq!(records[2].previous, records[0].lsn);
        assert_ne!(records[2].previous, records[1].lsn);
    }

    #[test]
    fn sealed_page_padding_is_skipped_and_wrap_increments_sequence() {
        for wrap in [false, true] {
            let first_page = if wrap { LOG - PAGE as u64 } else { FIRST };
            let second_page = if wrap { FIRST } else { FIRST + PAGE as u64 };
            let first = lsn(1, first_page + 64);
            let last = lsn(if wrap { 2 } else { 1 }, second_page + 64);
            let mut a = plain(first, first, 152);
            let mut b = plain(last, last, 152);
            put(&mut a, 64, first, 24, 0);
            put(&mut b, 64, last, 64, 0);
            a[152..510].fill(0xA5);
            let pages = BTreeMap::from([(first_page, protect(a)), (second_page, protect(b))]);
            let records = check(&restart(last), first, &pages).unwrap();
            assert_eq!(records.iter().map(|r| r.lsn).collect::<Vec<_>>(), [first, last]);
        }
    }

    #[test]
    fn spanning_record_can_be_followed_by_another_record_on_its_final_page() {
        let first = lsn(1, FIRST + 4000);
        let last = lsn(1, FIRST + PAGE as u64 + 184);
        let mut a = plain(first, 0, 0);
        let mut b = plain(last, last, 272);
        a[16..20].fill(0);
        put(&mut a, 4000, first, 24, 0);
        a[4024..4028].copy_from_slice(&168_u32.to_le_bytes());
        a[4040..4042].copy_from_slice(&MULTI_PAGE.to_le_bytes());
        // First record: 48 payload bytes here, then 120 at offset 64.
        put(&mut b, 184, last, 64, 0);
        let pages = BTreeMap::from([(FIRST, protect(a)), (FIRST + PAGE as u64, protect(b))]);
        let records = check(&restart(last), first, &pages).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].data, vec![0; 168]);
        assert_eq!(records[1].lsn, last);
    }

    #[test]
    fn corrupt_interleaved_record_is_not_hidden_by_a_valid_tail_chain() {
        let (restart, first, mut pages) = interleaved();
        pages.get_mut(&FIRST).unwrap()[152 + 28..152 + 30]
            .copy_from_slice(&10_u16.to_le_bytes());
        assert!(check(&restart, first, &pages).is_err());
    }

    #[test]
    fn missing_torn_stale_and_short_successor_pages_fail_the_whole_scan() {
        let first = lsn(1, FIRST + 64);
        let last = lsn(1, FIRST + PAGE as u64 + 64);
        let mut a = plain(first, first, 152);
        let mut b = plain(last, last, 152);
        put(&mut a, 64, first, 24, 0);
        put(&mut b, 64, last, 64, 0);
        let good = protect(b);
        for damage in 0..4 {
            let mut pages = BTreeMap::from([(FIRST, protect(a.clone()))]);
            if damage != 0 {
                let mut bad = good.clone();
                match damage {
                    1 => bad[PAGE - 1] ^= 1,
                    2 => bad[64..72].copy_from_slice(&first.to_le_bytes()),
                    _ => { bad.pop(); }
                }
                pages.insert(FIRST + PAGE as u64, bad);
            }
            assert!(check(&restart(last), first, &pages).is_err());
        }
    }

    #[test]
    fn end_position_covers_exact_page_end_zero_tail_capacity_and_wrap() {
        for offset in [64, 4000, 4048] {
            for length in [40, 48, 4000, 8064] {
                let current = lsn(1, LOG - PAGE as u64 + offset);
                let record = LogRecord {
                    lsn: current, previous: 0, undo_next: 0, kind: LFS_CLIENT_RECORD,
                    summary: TailRecord { transaction_id: 24, redo_op: 0, undo_op: 0 },
                    data: vec![0; length],
                };
                let mut metadata = restart(lsn(2, FIRST + 3 * PAGE as u64 + 64));
                metadata.last_lsn_data_len = 40;
                let position = end_position(&metadata, &record).unwrap();
                let mut page = LOG - PAGE as u64;
                let mut at = offset as usize;
                let mut seq = 1;
                // Independent byte-by-byte oracle includes the first header.
                for _ in 0..48 + length {
                    if at == PAGE {
                        page += PAGE as u64;
                        if page == LOG { page = FIRST; seq += 1; }
                        at = 64;
                    }
                    at += 1;
                }
                assert_eq!((position.page, position.offset, position.sequence), (page, at, seq));
            }
        }
    }

    #[test]
    fn cancellation_remains_terminal_during_chronological_reads() {
        let (restart, first, pages) = interleaved();
        let mut calls = 0;
        let result = collect(&Cx::for_testing(), &restart, LOG, first, &mut |offset, _| {
            calls += 1;
            if calls == 2 { return Err(crate::reader::FfsError::Cancelled); }
            Ok(pages[&offset].clone())
        });
        assert!(matches!(result, Err(crate::reader::FfsError::Cancelled)));
        assert_eq!(calls, 2);
    }

    #[test]
    fn successor_cannot_jump_over_the_selected_tail_or_reuse_an_older_sequence() {
        let (mut restart, first, pages) = interleaved();
        restart.current_lsn = first + 1;
        assert!(check(&restart, first, &pages).is_err());
        restart.current_lsn = lsn(1, FIRST + 240);
        let mut bad = pages;
        bad.get_mut(&FIRST).unwrap()[152..160].copy_from_slice(&(first - 1).to_le_bytes());
        assert!(check(&restart, first, &bad).is_err());
    }

    #[test]
    fn integrated_preflight_checks_records_outside_the_tail_transaction() {
        let (mut restart, first, mut pages) = interleaved();
        restart.active_client_oldest_lsn = Some(first);
        pages.get_mut(&FIRST).unwrap()[152 + 28..152 + 30]
            .copy_from_slice(&10_u16.to_le_bytes());
        let cx = Cx::for_testing();
        let mut read = |offset, _| Ok(pages[&offset].clone());
        // The selected tail itself remains valid and points only to the first
        // transaction. The complete preflight must nevertheless see the damage.
        let tail = read_record(&cx, &restart, LOG, restart.current_lsn, &mut read).unwrap();
        assert!(super::super::validate(&cx, &restart, LOG, &tail, &mut read).is_err());
    }

    #[test]
    fn scan_record_budget_is_enforced_before_the_next_record_read() {
        let address_bits = 24;
        let first = (1_u64 << address_bits) | (FIRST + 64) / 8;
        let last = first + MAX_RECORDS as u64 * PAGE as u64 / 8;
        let mut metadata = restart(last);
        metadata.file_size = 64 * 1024 * 1024;
        metadata.seq_num_bits = 64 - address_bits;
        let mut calls = 0;
        let result = collect(
            &Cx::for_testing(), &metadata, metadata.file_size, first,
            &mut |offset, _| {
                calls += 1;
                let current = (1_u64 << address_bits) | (offset + 64) / 8;
                let mut page = plain(current, current, 152);
                put(&mut page, 64, current, 24, 0);
                Ok(protect(page))
            },
        );
        assert!(matches!(result, Err(crate::reader::FfsError::UnsupportedFeature(_))));
        assert_eq!(calls, 2 * MAX_RECORDS);
    }
}
