//! Reassemble a native LFS client record across protected pages and log wrap.
//!
//! This only returns validated bytes. It never applies redo/undo or relaxes the
//! clean-only mount policy. Page count/position describe an I/O transfer, not
//! the number of pages in a client record, so they are not continuation IDs.

use super::super::super::super::buffer;
use super::{
    Cx, MULTI_PAGE, PAGE_RECORD_END, RecordPage, Restart, Result, checkpoint, corrupt,
    lsn_page_offset, read_exact, restore_page, u16_at, u32_at, u64_at, unsupported,
};

const MAX_CLIENT_BYTES: usize = 16 * 1024 * 1024;
const MAX_CLIENT_PAGES: u64 = 4096;

fn first_page(restart: &Restart) -> Result<u64> {
    let reserved = if restart.version.0 >= 2 { 0x22_u64 } else { 4 };
    reserved
        .checked_mul(u64::from(restart.log_page))
        .ok_or_else(|| corrupt(0, "$LogFile reserved-page extent overflow"))
}

/// Reconstruct the client bytes at the restart area's current LSN. The first
/// page and LFS header have already been validated by the caller. Every further
/// page is independently read, USA-validated, and checked for record completion.
pub(super) fn read(
    cx: &Cx,
    restart: &Restart,
    stream_length: u64,
    mut page_vbo: u64,
    mut page: RecordPage,
    read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    checkpoint(cx)?;
    let page_size = page.bytes.len();
    let page_bytes = u64::from(restart.log_page);
    let first = first_page(restart)?;
    let data_off = usize::from(restart.data_off);
    if page_size as u64 != page_bytes
        || data_off >= page_size
        || restart.file_size > stream_length
        || first >= restart.file_size
        || !restart.file_size.is_multiple_of(page_bytes)
        || page_vbo < first
        || page_vbo >= restart.file_size
        || !page_vbo.is_multiple_of(page_bytes)
    {
        return Err(corrupt(page_vbo, "invalid $LogFile continuation geometry"));
    }
    let record_off = lsn_page_offset(restart.current_lsn, restart.log_page)?;
    let mut offset = record_off
        .checked_add(usize::from(restart.record_header_len))
        .filter(|end| *end <= page_size)
        .ok_or_else(|| corrupt(page_vbo, "$LogFile header crosses its first page"))?;
    let length = usize::try_from(u32_at(&page.bytes, record_off + 24)?)
        .map_err(|_| corrupt(page_vbo, "$LogFile client length overflow"))?;
    let flags = u16_at(&page.bytes, record_off + 40)?;
    let first_capacity = page_size - offset;
    if (flags & MULTI_PAGE != 0) != (length > first_capacity) {
        return Err(corrupt(
            page_vbo,
            "$LogFile multi-page flag disagrees with the client length",
        ));
    }
    if length > MAX_CLIENT_BYTES {
        return Err(unsupported(
            "$LogFile client record exceeds the 16 MiB read budget",
        ));
    }
    let continuation_bytes = page_size - data_off;
    let pages =
        1 + (length.saturating_sub(first_capacity) as u64).div_ceil(continuation_bytes as u64);
    let ring_pages = (restart.file_size - first) / page_bytes;
    if pages > ring_pages {
        return Err(corrupt(
            page_vbo,
            "$LogFile client record would revisit its first page",
        ));
    }
    if pages > MAX_CLIENT_PAGES {
        return Err(unsupported(
            "$LogFile client record exceeds the 4096-page read budget",
        ));
    }
    // Check capacity before allocating. A hostile length must not turn journal
    // inspection into an unbounded allocation, read loop, or repeated ring walk.
    let mut data = buffer(length)?;
    let mut copied = 0;
    for index in 0..pages {
        checkpoint(cx)?;
        let count = (length - copied).min(page_size - offset);
        let end = offset + count;
        let last_lsn = u64_at(&page.bytes, 8)?;
        let last_end_lsn = u64_at(&page.bytes, 32)?;
        let page_flags = u32_at(&page.bytes, 16)?;
        let final_page = index + 1 == pages;
        if last_lsn < restart.current_lsn || last_end_lsn > last_lsn {
            return Err(corrupt(
                page_vbo,
                "$LogFile continuation has stale or inconsistent LSNs",
            ));
        }
        if final_page {
            if page_flags & PAGE_RECORD_END == 0
                || last_end_lsn < restart.current_lsn
                || (page.next_record_off != 0 && end > usize::from(page.next_record_off))
            {
                return Err(corrupt(
                    page_vbo,
                    "$LogFile client record has no valid page ending",
                ));
            }
        } else if last_end_lsn >= restart.current_lsn {
            return Err(corrupt(
                page_vbo,
                "$LogFile client record ends before its declared length",
            ));
        }
        data[copied..copied + count].copy_from_slice(&page.bytes[offset..end]);
        copied += count;
        if final_page {
            break;
        }
        let next = page_vbo
            .checked_add(page_bytes)
            .ok_or_else(|| corrupt(page_vbo, "$LogFile continuation offset overflow"))?;
        page_vbo = if next == restart.file_size {
            first
        } else {
            next
        };
        page = restore_page(
            cx,
            read_exact(cx, restart.file_size, page_vbo, page_size, read)?,
            restart,
            page_vbo,
        )?;
        offset = data_off;
    }
    checkpoint(cx)?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const PAGE: usize = 4096;
    const LOG: u64 = 50 * PAGE as u64;

    struct Fixture {
        restart: Restart,
        pages: BTreeMap<u64, Vec<u8>>,
        expected: Vec<u8>,
        first_vbo: u64,
    }

    fn protect(mut page: Vec<u8>, token: u16) -> Vec<u8> {
        let count = PAGE / 512 + 1;
        page[4..6].copy_from_slice(&40_u16.to_le_bytes());
        page[6..8].copy_from_slice(&(count as u16).to_le_bytes());
        page[40..42].copy_from_slice(&token.to_le_bytes());
        for sector in 1..count {
            let end = sector * 512;
            let saved = [page[end - 2], page[end - 1]];
            page[40 + sector * 2..42 + sector * 2].copy_from_slice(&saved);
            page[end - 2..end].copy_from_slice(&token.to_le_bytes());
        }
        page
    }

    fn fixture(version: (u16, u16), wrap: bool, length: usize, header_at_end: bool) -> Fixture {
        let reserved = if version.0 >= 2 { 34 } else { 4 };
        let first = reserved * PAGE as u64;
        let first_vbo = if wrap { LOG - PAGE as u64 } else { first };
        let record_off = PAGE - if header_at_end { 48 } else { 64 };
        let seq_num_bits = 67 - (64 - LOG.leading_zeros());
        let lsn = (1_u64 << (64 - seq_num_bits)) | (first_vbo + record_off as u64) / 8;
        let restart = Restart {
            system_page: PAGE as u32,
            log_page: PAGE as u32,
            version,
            clean: false,
            current_lsn: lsn,
            seq_num_bits,
            file_size: LOG,
            last_lsn_data_len: length as u32,
            record_header_len: 48,
            data_off: 64,
            active_client_seq: Some(9),
            active_client_oldest_lsn: Some(lsn),
            active_client_restart_lsn: Some(lsn),
            area: Vec::new(),
        };
        let mut expected: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
        expected[..40].fill(0);
        expected[..2].copy_from_slice(&7_u16.to_le_bytes());
        expected[2..4].copy_from_slice(&7_u16.to_le_bytes());
        expected[4..6].copy_from_slice(&40_u16.to_le_bytes());
        expected[6..8].copy_from_slice(&8_u16.to_le_bytes());
        expected[12..14].copy_from_slice(&24_u16.to_le_bytes());
        let mut pages = BTreeMap::new();
        let mut vbo = first_vbo;
        let mut copied = 0;
        loop {
            let initial = pages.is_empty();
            let at = if initial { record_off + 48 } else { 64 };
            let count = (length - copied).min(PAGE - at);
            let last = copied + count == length;
            let mut page = vec![0; PAGE];
            page[..4].copy_from_slice(b"RCRD");
            page[8..16].copy_from_slice(&lsn.to_le_bytes());
            // Each page may be a separate I/O transfer even for one record.
            page[20..22].copy_from_slice(&1_u16.to_le_bytes());
            page[22..24].copy_from_slice(&1_u16.to_le_bytes());
            if last {
                page[16..20].copy_from_slice(&PAGE_RECORD_END.to_le_bytes());
                let next = (at + count).next_multiple_of(8) as u16;
                page[24..26].copy_from_slice(&next.to_le_bytes());
                page[32..40].copy_from_slice(&lsn.to_le_bytes());
            }
            if initial {
                let header = &mut page[record_off..record_off + 48];
                header[..8].copy_from_slice(&lsn.to_le_bytes());
                header[24..28].copy_from_slice(&(length as u32).to_le_bytes());
                header[28..30].copy_from_slice(&9_u16.to_le_bytes());
                header[32..36].copy_from_slice(&1_u32.to_le_bytes());
                header[36..40].copy_from_slice(&17_u32.to_le_bytes());
                if !last {
                    header[40..42].copy_from_slice(&MULTI_PAGE.to_le_bytes());
                }
            }
            page[at..at + count].copy_from_slice(&expected[copied..copied + count]);
            pages.insert(vbo, protect(page, 0xCAFE));
            copied += count;
            if last {
                break;
            }
            vbo += PAGE as u64;
            if vbo == LOG {
                vbo = first;
            }
        }
        Fixture {
            restart,
            pages,
            expected,
            first_vbo,
        }
    }

    fn collect(fixture: &Fixture) -> Result<Vec<u8>> {
        let cx = Cx::for_testing();
        let page = restore_page(
            &cx,
            fixture.pages[&fixture.first_vbo].clone(),
            &fixture.restart,
            fixture.first_vbo,
        )?;
        read(
            &cx,
            &fixture.restart,
            LOG,
            fixture.first_vbo,
            page,
            &mut |vbo, size| {
                assert_eq!(size, PAGE);
                fixture
                    .pages
                    .get(&vbo)
                    .cloned()
                    .ok_or_else(|| corrupt(vbo, "unexpected fixture read"))
            },
        )
    }

    #[test]
    fn native_versions_reassemble_payload_and_fixups_across_pages_and_wrap() {
        for version in [(1, 1), (2, 0)] {
            for wrap in [false, true] {
                for header_at_end in [false, true] {
                    let fixture = fixture(version, wrap, 9000, header_at_end);
                    assert_eq!(collect(&fixture).unwrap(), fixture.expected);
                    let tail = super::super::validate_dirty_tail(
                        &Cx::for_testing(),
                        &fixture.restart,
                        LOG,
                        &mut |vbo, size| {
                            assert_eq!(size, PAGE);
                            Ok(fixture.pages[&vbo].clone())
                        },
                    )
                    .unwrap();
                    assert_eq!(
                        (tail.transaction_id, tail.redo_op, tail.undo_op),
                        (17, 7, 7)
                    );
                }
            }
        }
    }

    #[test]
    fn every_sector_of_every_continuation_is_protected() {
        let mut fixture = fixture((2, 0), true, 9000, false);
        let offsets: Vec<u64> = fixture.pages.keys().copied().collect();
        for offset in offsets {
            for sector in 1..=PAGE / 512 {
                fixture.pages.get_mut(&offset).unwrap()[sector * 512 - 1] ^= 1;
                assert!(collect(&fixture).is_err());
                fixture.pages.get_mut(&offset).unwrap()[sector * 512 - 1] ^= 1;
            }
        }
    }

    #[test]
    fn stale_or_unfinished_continuations_are_not_returned() {
        for mutation in 0..6 {
            let mut fixture = fixture((2, 0), false, 9000, false);
            let last = *fixture.pages.keys().next_back().unwrap();
            let lsn = fixture.restart.current_lsn;
            let page = fixture.pages.get_mut(&last).unwrap();
            match mutation {
                0 => page[8..16].copy_from_slice(&(lsn - 1).to_le_bytes()),
                1 => page[16..20].fill(0),
                2 => page[32..40].copy_from_slice(&(lsn - 1).to_le_bytes()),
                3 => page[24..26].copy_from_slice(&64_u16.to_le_bytes()),
                4 => page[60..64].copy_from_slice(&4096_u32.to_le_bytes()),
                _ => page.fill(0xFF),
            }
            assert!(collect(&fixture).is_err());
        }
        let mut fixture = fixture((2, 0), false, 9000, false);
        let lsn = fixture.restart.current_lsn;
        fixture.pages.get_mut(&fixture.first_vbo).unwrap()[32..40]
            .copy_from_slice(&lsn.to_le_bytes());
        assert!(collect(&fixture).is_err());
    }

    #[test]
    fn exact_page_endings_and_adjacent_lengths_preserve_every_byte() {
        for full_pages in 1..=3 {
            for delta in [-1_isize, 0, 1] {
                let length = (16 + full_pages * (PAGE - 64)).saturating_add_signed(delta);
                let fixture = fixture((2, 0), true, length, false);
                assert_eq!(collect(&fixture).unwrap(), fixture.expected);
            }
        }
    }

    #[test]
    fn short_continuation_reads_fail_without_returning_partial_data() {
        let fixture = fixture((2, 0), false, 9000, false);
        let cx = Cx::for_testing();
        let first = restore_page(
            &cx,
            fixture.pages[&fixture.first_vbo].clone(),
            &fixture.restart,
            fixture.first_vbo,
        )
        .unwrap();
        assert!(
            read(
                &cx,
                &fixture.restart,
                LOG,
                fixture.first_vbo,
                first,
                &mut |vbo, _| { Ok(fixture.pages[&vbo][..PAGE - 1].to_vec()) },
            )
            .is_err()
        );
    }

    #[test]
    fn oversized_or_cyclic_records_fail_before_continuation_io() {
        let fixture = fixture((2, 0), false, 9000, false);
        for length in [MAX_CLIENT_BYTES + 1, LOG as usize] {
            let cx = Cx::for_testing();
            let mut page = restore_page(
                &cx,
                fixture.pages[&fixture.first_vbo].clone(),
                &fixture.restart,
                fixture.first_vbo,
            )
            .unwrap();
            let at =
                lsn_page_offset(fixture.restart.current_lsn, fixture.restart.log_page).unwrap();
            page.bytes[at + 24..at + 28].copy_from_slice(&(length as u32).to_le_bytes());
            let result = read(
                &cx,
                &fixture.restart,
                LOG,
                fixture.first_vbo,
                page,
                &mut |_, _| panic!("budget rejection must precede continuation I/O"),
            );
            assert!(result.is_err());
        }
    }
}
