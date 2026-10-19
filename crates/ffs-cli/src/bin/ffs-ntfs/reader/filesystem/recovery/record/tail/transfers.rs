//! Complete native tail transfers, selected without splicing publication attempts.
//!
//! Linux v6.17 fs/ntfs3/fslog.c uses two v2 banks of sixteen pages and checks
//! destination continuity, page_count/page_pos and LSN progress. This bounded
//! profile requires each transfer to be complete within one bank and not wrap
//! its destination range. Ambiguous overlapping transfer boundaries are refused.
//! Recovery consumes only private normalized copies; no native bytes are written.

use super::{
    BTreeMap, Cx, Page, Restart, Result, blank, checkpoint, corrupt, generation, read_exact,
    restore_page, u16_at, u32_at, u64_at, unsupported,
};

pub(super) struct Copies {
    pub(super) pages: BTreeMap<u64, Page>,
    pub(super) groups: Vec<Vec<u64>>,
}

#[derive(Clone, Copy)]
pub(super) enum Selection {
    Copy,
    Ring,
    Equal,
}

struct Transfer {
    pages: Vec<(u64, Page)>,
}

/// Validate the original fixups before touching destination/header words.
fn copy_page(cx: &Cx, restart: &Restart, slot: u64, mut raw: Vec<u8>) -> Result<(u64, Page)> {
    let page_bytes = u64::from(restart.log_page);
    let first = (if restart.version.0 == 2 { 34 } else { 4 }) * page_bytes;
    let destination = if restart.version.0 == 1 {
        u64_at(&raw, 8)?
    } else {
        u64::from(u32_at(&raw, 60)?)
    };
    if destination < first
        || destination >= restart.file_size
        || !destination.is_multiple_of(page_bytes)
    {
        return Err(corrupt(
            slot,
            "$LogFile tail copy has an invalid native destination",
        ));
    }
    let fixed = restore_page(cx, raw.clone(), restart, destination)?;
    if restart.version.0 == 1 {
        raw[8..16].copy_from_slice(&u64_at(&fixed.bytes, 32)?.to_le_bytes());
    } else {
        let usa = usize::from(u16_at(&fixed.bytes, 4)?);
        let end = usa + usize::from(u16_at(&fixed.bytes, 6)?) * 2;
        if usa < 64 && end > 60 {
            return Err(corrupt(
                slot,
                "$LogFile v2 tail normalization would overwrite its USA",
            ));
        }
        raw[60..64].fill(0);
    }
    Ok((destination, Page::parse(cx, restart, destination, raw)?))
}

fn transfer(cx: &Cx, restart: &Restart, oldest: u64, pages: Vec<(u64, Page)>) -> Result<Transfer> {
    let count = pages.len();
    let first = pages
        .first()
        .ok_or_else(|| corrupt(0, "empty native tail transfer"))?;
    let bytes = u64::from(restart.log_page);
    let sequence = first.1.last >> (64 - restart.seq_num_bits);
    let mut last = 0;
    let mut completed = 0;
    for (index, (destination, page)) in pages.iter().enumerate() {
        checkpoint(cx)?;
        let expected = first
            .0
            .checked_add(index as u64 * bytes)
            .filter(|at| *at < restart.file_size)
            .ok_or_else(|| unsupported("$LogFile tail transfer wraps its destination range"))?;
        if *destination != expected
            || usize::from(u16_at(&page.fixed.bytes, 20)?) != count
            || usize::from(u16_at(&page.fixed.bytes, 22)?) != index + 1
        {
            return Err(corrupt(
                *destination,
                "$LogFile tail transfer has discontinuous destinations or positions",
            ));
        }
        generation(restart, page.last, oldest)?;
        if page.completed != 0 {
            generation(restart, page.completed, oldest)?;
        }
        if page.last < last
            || page.last >> (64 - restart.seq_num_bits) != sequence
            || (page.completed != 0 && page.completed < completed)
        {
            return Err(unsupported(
                "$LogFile tail transfer has incompatible LSN progress",
            ));
        }
        last = page.last;
        completed = completed.max(page.completed);
    }
    let final_page = &pages[count - 1].1;
    if final_page.completed == 0
        || final_page.last != final_page.completed
        || final_page.fixed.next_record_off == 0
    {
        return Err(unsupported(
            "$LogFile tail transfer does not end with a complete record",
        ));
    }
    Ok(Transfer { pages })
}

/// Compare competing complete transfers only when their destination sets agree.
/// Mixed ordering is not resolved by taking a per-page maximum.
fn select(
    cx: &Cx,
    groups: &mut Vec<Transfer>,
    incoming: Transfer,
    restart: &Restart,
    source: &mut impl FnMut(u64, usize) -> Result<Vec<u8>>,
) -> Result<()> {
    let first = incoming.pages[0].0;
    let last = incoming.pages[incoming.pages.len() - 1].0;
    for previous in groups.iter_mut() {
        let old_first = previous.pages[0].0;
        let old_last = previous.pages[previous.pages.len() - 1].0;
        if last < old_first || old_last < first {
            continue;
        }
        if first != old_first || last != old_last || incoming.pages.len() != previous.pages.len() {
            return Err(unsupported(
                "$LogFile overlapping tail transfers have different publication boundaries",
            ));
        }
        let mut newer = false;
        let mut older = false;
        for ((destination, a), (_, b)) in incoming.pages.iter().zip(&previous.pages) {
            match a.compare(b, restart, *destination, &mut |from_incoming, origin| {
                let pages = if from_incoming {
                    &incoming.pages
                } else {
                    &previous.pages
                };
                let raw = match pages.iter().find(|(at, _)| *at == origin) {
                    Some((_, page)) => page.raw.clone(),
                    None => read_exact(
                        cx,
                        restart.file_size,
                        origin,
                        restart.log_page as usize,
                        source,
                    )?,
                };
                restore_page(cx, raw, restart, origin)
            })? {
                std::cmp::Ordering::Greater => newer = true,
                std::cmp::Ordering::Less => older = true,
                std::cmp::Ordering::Equal => {}
            }
        }
        if newer && older {
            return Err(unsupported(
                "$LogFile competing tail transfers have crossed publication order",
            ));
        }
        if newer {
            *previous = incoming;
        }
        return Ok(());
    }
    groups.push(incoming);
    Ok(())
}

pub(super) fn read(
    cx: &Cx,
    restart: &Restart,
    oldest: u64,
    source: &mut impl FnMut(u64, usize) -> Result<Vec<u8>>,
) -> Result<Copies> {
    let page_bytes = u64::from(restart.log_page);
    let page_size =
        usize::try_from(page_bytes).map_err(|_| corrupt(0, "$LogFile tail page size overflows"))?;
    let width = if restart.version.0 == 2 { 16_u64 } else { 1 };
    let mut groups = Vec::new();
    for bank in [2_u64, 2 + width] {
        let mut slot = bank;
        while slot < bank + width {
            checkpoint(cx)?;
            let at = slot * page_bytes;
            let raw = read_exact(cx, restart.file_size, at, page_size, source)?;
            if blank(&raw) {
                slot += 1;
                continue;
            }
            let first = copy_page(cx, restart, at, raw)?;
            let count = u64::from(u16_at(&first.1.fixed.bytes, 20)?);
            if u16_at(&first.1.fixed.bytes, 22)? != 1 || count == 0 || count > bank + width - slot {
                return Err(unsupported(
                    "$LogFile tail transfer is incomplete within its native bank",
                ));
            }
            let mut pages = vec![first];
            for index in 1..count {
                let at = (slot + index) * page_bytes;
                let raw = read_exact(cx, restart.file_size, at, page_size, source)?;
                if blank(&raw) {
                    return Err(unsupported(
                        "$LogFile tail transfer has a missing continuation page",
                    ));
                }
                pages.push(copy_page(cx, restart, at, raw)?);
            }
            select(
                cx,
                &mut groups,
                transfer(cx, restart, oldest, pages)?,
                restart,
                source,
            )?;
            slot += count;
        }
    }
    let mut result = Copies {
        pages: BTreeMap::new(),
        groups: Vec::new(),
    };
    for group in groups {
        result
            .groups
            .push(group.pages.iter().map(|(at, _)| *at).collect());
        for (at, page) in group.pages {
            if result.pages.insert(at, page).is_some() {
                return Err(corrupt(at, "$LogFile selected transfers overlap"));
            }
        }
    }
    checkpoint(cx)?;
    Ok(result)
}

/// The ring may contain an already-published equivalent transfer, or a wholly
/// newer one. A partially newer ring cannot be combined with a tail bank here.
pub(super) fn validate_selection(
    groups: &[Vec<u64>],
    decisions: &BTreeMap<u64, Selection>,
) -> Result<()> {
    for group in groups {
        let mut copied = false;
        let mut newer_ring = false;
        for at in group {
            match decisions.get(at) {
                Some(Selection::Copy) => copied = true,
                Some(Selection::Ring) => newer_ring = true,
                Some(Selection::Equal) => {}
                None => {
                    return Err(corrupt(
                        *at,
                        "$LogFile transfer lost a publication decision",
                    ));
                }
            }
        }
        if copied && newer_ring {
            return Err(unsupported(
                "$LogFile ring and tail require mixed-transfer salvage",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod prefix_tests {
    use super::super::{discover, validate_latest_volume};
    use super::*;
    use ffs_error::FfsError;
    use std::cmp::Ordering;

    const PAGE: usize = 4096;
    const LOG: usize = 50 * PAGE;
    const VALUE: usize = 64 + 48 + 40;

    fn lsn(sequence: u64, at: usize) -> u64 {
        (sequence << 15) | (at as u64 / 8)
    }

    fn first(version: (u16, u16)) -> usize {
        if version.0 == 1 { 4 * PAGE } else { 34 * PAGE }
    }

    fn restart(version: (u16, u16)) -> Restart {
        let anchor = lsn(1, first(version) + 64);
        Restart {
            system_page: PAGE as u32,
            log_page: PAGE as u32,
            version,
            clean: false,
            current_lsn: anchor,
            seq_num_bits: 49,
            file_size: LOG as u64,
            last_lsn_data_len: 48,
            record_header_len: 48,
            data_off: 64,
            active_client_seq: Some(9),
            active_client_oldest_lsn: Some(anchor),
            active_client_restart_lsn: None,
            area: Vec::new(),
        }
    }

    // Independently encode an UpdateResidentValue followed by an optional
    // CommitTransaction. The altered bytes below are actual redo payload, not
    // padding, a broken fixup, a changed record identity or an invalid length.
    fn page(destination: usize, sequence: u64, append: bool, token: u16) -> Vec<u8> {
        let anchor = lsn(sequence, destination + 64);
        let last = if append {
            lsn(sequence, destination + 160)
        } else {
            anchor
        };
        let mut raw = vec![0; PAGE];
        raw[..4].copy_from_slice(b"RCRD");
        raw[4..6].copy_from_slice(&40_u16.to_le_bytes());
        raw[6..8].copy_from_slice(&9_u16.to_le_bytes());
        raw[8..16].copy_from_slice(&last.to_le_bytes());
        raw[16..20].copy_from_slice(&1_u32.to_le_bytes());
        raw[20..22].copy_from_slice(&1_u16.to_le_bytes());
        raw[22..24].copy_from_slice(&1_u16.to_le_bytes());
        raw[24..26].copy_from_slice(&(if append { 248_u16 } else { 160 }).to_le_bytes());
        raw[32..40].copy_from_slice(&last.to_le_bytes());
        for (at, current, previous, length) in [(64, anchor, 0, 48_u32), (160, last, anchor, 40)]
            .into_iter()
            .take(if append { 2 } else { 1 })
        {
            raw[at..at + 8].copy_from_slice(&current.to_le_bytes());
            raw[at + 8..at + 16].copy_from_slice(&previous.to_le_bytes());
            raw[at + 24..at + 28].copy_from_slice(&length.to_le_bytes());
            raw[at + 28..at + 30].copy_from_slice(&9_u16.to_le_bytes());
            raw[at + 32..at + 36].copy_from_slice(&1_u32.to_le_bytes());
            raw[at + 36..at + 40].copy_from_slice(&24_u32.to_le_bytes());
            let body = at + 48;
            if at == 64 {
                raw[body..body + 2].copy_from_slice(&7_u16.to_le_bytes());
                raw[body + 4..body + 6].copy_from_slice(&40_u16.to_le_bytes());
                raw[body + 6..body + 8].copy_from_slice(&8_u16.to_le_bytes());
                raw[body + 12..body + 14].copy_from_slice(&24_u16.to_le_bytes());
                raw[body + 14..body + 16].copy_from_slice(&1_u16.to_le_bytes());
                raw[body + 32..body + 40].copy_from_slice(&100_u64.to_le_bytes());
                raw[VALUE..VALUE + 8].copy_from_slice(b"original");
            } else {
                raw[body..body + 2].copy_from_slice(&0x1A_u16.to_le_bytes());
            }
        }
        raw[40..42].copy_from_slice(&token.to_le_bytes());
        for sector in 1..=8 {
            let at = sector * 512 - 2;
            let saved = [raw[at], raw[at + 1]];
            raw[40 + sector * 2..42 + sector * 2].copy_from_slice(&saved);
            raw[at..at + 2].copy_from_slice(&token.to_le_bytes());
        }
        raw
    }

    fn copy(mut raw: Vec<u8>, version: (u16, u16), destination: usize) -> Vec<u8> {
        if version.0 == 1 {
            raw[8..16].copy_from_slice(&(destination as u64).to_le_bytes());
        } else {
            raw[60..64].copy_from_slice(&(destination as u32).to_le_bytes());
        }
        raw
    }

    fn install(log: &mut [u8], at: usize, raw: &[u8]) {
        log[at..at + PAGE].copy_from_slice(raw);
    }

    fn load(log: &[u8], at: u64, size: usize) -> Result<Vec<u8>> {
        let at = usize::try_from(at).map_err(|_| corrupt(0, "test address overflow"))?;
        let end = at
            .checked_add(size)
            .ok_or_else(|| corrupt(0, "test length overflow"))?;
        log.get(at..end)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| corrupt(0, "test bounds"))
    }

    fn check(restart: &Restart, log: &[u8]) -> Result<()> {
        validate_latest_volume(
            &Cx::for_testing(),
            restart,
            LOG as u64,
            &mut |at, size| load(log, at, size),
            None,
        )
        .map(|_| ())
    }

    fn assert_prefix_error(result: Result<()>) {
        assert!(matches!(
            result,
            Err(FfsError::Corruption { detail, .. }) if detail.contains("initialized record prefix")
        ));
    }

    #[test]
    fn higher_lsn_cannot_rewrite_completed_payload_in_either_tail_bank() {
        for version in [(1, 1), (2, 0)] {
            let at = first(version);
            let old = page(at, 1, false, 0xCAFE);
            let mut newer = page(at, 1, true, 0xBEEF);
            newer[VALUE] ^= 1;
            let second = if version.0 == 1 { 3 } else { 18 } * PAGE;
            for reverse in [false, true] {
                let mut log = vec![0xFF; LOG];
                install(&mut log, at, &old);
                let (a, b) = if reverse {
                    (&newer, &old)
                } else {
                    (&old, &newer)
                };
                install(&mut log, 2 * PAGE, &copy(a.clone(), version, at));
                install(&mut log, second, &copy(b.clone(), version, at));
                let before = log.clone();
                assert_prefix_error(check(&restart(version), &log));
                assert_eq!(log, before);
            }
        }
    }

    #[test]
    fn ring_and_tail_preserve_completed_payload_whichever_copy_is_newer() {
        for version in [(1, 1), (2, 0)] {
            let at = first(version);
            let old = page(at, 1, false, 0xCAFE);
            let mut newer = page(at, 1, true, 0xBEEF);
            newer[VALUE + 3] ^= 1;
            for ring_is_newer in [false, true] {
                let (ring, tail) = if ring_is_newer {
                    (&newer, &old)
                } else {
                    (&old, &newer)
                };
                let mut log = vec![0xFF; LOG];
                install(&mut log, at, ring);
                install(&mut log, 2 * PAGE, &copy(tail.clone(), version, at));
                let before = log.clone();
                assert_prefix_error(check(&restart(version), &log));
                assert_eq!(log, before);
            }
        }
    }

    #[test]
    fn malformed_completed_endpoints_cannot_hide_rewritten_redo_bd_ofjn7() {
        for version in [(1, 1), (2, 0)] {
            let at = first(version);
            let second = if version.0 == 1 { 3 } else { 18 } * PAGE;
            for end in [64_u16, 152, 160] {
                for poisoned in [false, true] {
                    for placement in 0..4 {
                        let mut old = page(at, 1, false, 0xCAFE);
                        old[24..26].copy_from_slice(&end.to_le_bytes());
                        let mut newer = page(at, 1, true, 0xBEEF);
                        if poisoned {
                            newer[VALUE] ^= 1;
                        }
                        let mut log = vec![0xFF; LOG];
                        match placement {
                            0 => {
                                install(&mut log, at, &old);
                                install(&mut log, 2 * PAGE, &copy(newer, version, at));
                            }
                            1 => {
                                install(&mut log, at, &newer);
                                install(&mut log, 2 * PAGE, &copy(old, version, at));
                            }
                            2 => {
                                install(&mut log, 2 * PAGE, &copy(old, version, at));
                                install(&mut log, second, &copy(newer, version, at));
                            }
                            _ => {
                                install(&mut log, 2 * PAGE, &copy(newer, version, at));
                                install(&mut log, second, &copy(old, version, at));
                            }
                        }
                        let before = log.clone();
                        let result = check(&restart(version), &log);
                        if end < 160 {
                            assert!(matches!(
                                result,
                                Err(FfsError::Corruption { detail, .. })
                                    if detail.contains("completed record endpoint")
                            ));
                        } else if poisoned {
                            assert_prefix_error(result);
                        } else {
                            result.unwrap();
                        }
                        assert_eq!(log, before);
                    }
                }
            }
        }
    }

    #[test]
    fn completed_payload_endpoint_allows_native_alignment_padding_bd_ofjn7() {
        for version in [(1, 1), (2, 0)] {
            let at = first(version);
            let mut older = page(at, 1, false, 7);
            let mut newer = page(at, 1, true, 9);
            // A 47-byte client payload ends at 159 and its next record starts
            // at 160. The seven-byte redo remains entirely inside that payload.
            for raw in [&mut older, &mut newer] {
                raw[88..92].copy_from_slice(&47_u32.to_le_bytes());
                raw[118..120].copy_from_slice(&7_u16.to_le_bytes());
            }
            let mut metadata = restart(version);
            metadata.last_lsn_data_len = 47;
            let mut log = vec![0xFF; LOG];
            install(&mut log, at, &older);
            install(&mut log, 2 * PAGE, &copy(newer, version, at));
            let before = log.clone();
            check(&metadata, &log).unwrap();
            assert_eq!(log, before);
        }
    }

    fn spanning_fixture(version: (u16, u16), wrap: bool) -> (Restart, Vec<u8>, Vec<u8>, usize) {
        let origin = if wrap { LOG - PAGE } else { first(version) };
        let destination = if wrap { first(version) } else { origin + PAGE };
        let anchor = lsn(1, origin + 64);
        let appended = lsn(if wrap { 2 } else { 1 }, destination + 280);
        let mut payload = vec![0; 4200];
        payload[..2].copy_from_slice(&7_u16.to_le_bytes());
        payload[4..6].copy_from_slice(&4192_u16.to_le_bytes());
        payload[6..8].copy_from_slice(&8_u16.to_le_bytes());
        payload[12..14].copy_from_slice(&24_u16.to_le_bytes());
        payload[14..16].copy_from_slice(&1_u16.to_le_bytes());
        payload[32..40].copy_from_slice(&100_u64.to_le_bytes());
        payload[40..48].copy_from_slice(b"original");
        payload[4192..].copy_from_slice(b"taildata");
        let mut start = vec![0; PAGE];
        start[..4].copy_from_slice(b"RCRD");
        start[8..16].copy_from_slice(&anchor.to_le_bytes());
        start[20..22].copy_from_slice(&1_u16.to_le_bytes());
        start[22..24].copy_from_slice(&1_u16.to_le_bytes());
        start[64..72].copy_from_slice(&anchor.to_le_bytes());
        start[88..92].copy_from_slice(&4200_u32.to_le_bytes());
        start[92..94].copy_from_slice(&9_u16.to_le_bytes());
        start[96..100].copy_from_slice(&1_u32.to_le_bytes());
        start[100..104].copy_from_slice(&24_u32.to_le_bytes());
        start[104..106].copy_from_slice(&1_u16.to_le_bytes());
        start[112..].copy_from_slice(&payload[..3984]);
        let mut older = vec![0; PAGE];
        older[..4].copy_from_slice(b"RCRD");
        older[8..16].copy_from_slice(&anchor.to_le_bytes());
        older[16..20].copy_from_slice(&1_u32.to_le_bytes());
        older[20..22].copy_from_slice(&1_u16.to_le_bytes());
        older[22..24].copy_from_slice(&1_u16.to_le_bytes());
        older[24..26].copy_from_slice(&280_u16.to_le_bytes());
        older[32..40].copy_from_slice(&anchor.to_le_bytes());
        older[64..280].copy_from_slice(&payload[3984..]);
        let mut newer = older.clone();
        newer[8..16].copy_from_slice(&appended.to_le_bytes());
        newer[24..26].copy_from_slice(&368_u16.to_le_bytes());
        newer[32..40].copy_from_slice(&appended.to_le_bytes());
        newer[280..288].copy_from_slice(&appended.to_le_bytes());
        newer[288..296].copy_from_slice(&anchor.to_le_bytes());
        newer[304..308].copy_from_slice(&40_u32.to_le_bytes());
        newer[308..310].copy_from_slice(&9_u16.to_le_bytes());
        newer[312..316].copy_from_slice(&1_u32.to_le_bytes());
        newer[316..320].copy_from_slice(&24_u32.to_le_bytes());
        newer[328..330].copy_from_slice(&0x1A_u16.to_le_bytes());
        for (raw, token) in [(&mut start, 0xCAFE_u16), (&mut older, 7), (&mut newer, 9)] {
            raw[4..6].copy_from_slice(&40_u16.to_le_bytes());
            raw[6..8].copy_from_slice(&9_u16.to_le_bytes());
            raw[40..42].copy_from_slice(&token.to_le_bytes());
            for sector in 1..=8 {
                let at = sector * 512 - 2;
                let saved = [raw[at], raw[at + 1]];
                raw[40 + sector * 2..42 + sector * 2].copy_from_slice(&saved);
                raw[at..at + 2].copy_from_slice(&token.to_le_bytes());
            }
        }
        let mut log = vec![0xFF; LOG];
        install(&mut log, origin, &start);
        install(&mut log, destination, &older);
        let mut metadata = restart(version);
        metadata.current_lsn = anchor;
        metadata.active_client_oldest_lsn = Some(anchor);
        metadata.last_lsn_data_len = 4200;
        (metadata, log, newer, destination)
    }

    #[test]
    fn completed_spanning_payloads_keep_their_actual_end_across_wrap_bd_ofjn7() {
        for version in [(1, 1), (2, 0)] {
            for wrap in [false, true] {
                let (metadata, source, appended, at) = spanning_fixture(version, wrap);
                let second = if version.0 == 1 { 3 } else { 18 } * PAGE;
                for end in [64_u16, 272, 280] {
                    for poisoned in [false, true] {
                        for placement in 0..4 {
                            let mut older = source[at..at + PAGE].to_vec();
                            older[24..26].copy_from_slice(&end.to_le_bytes());
                            let mut newer = appended.clone();
                            if poisoned {
                                newer[272] ^= 1; // Actual final client bytes, not page slack.
                            }
                            let mut log = source.clone();
                            match placement {
                                0 => {
                                    install(&mut log, at, &older);
                                    install(&mut log, 2 * PAGE, &copy(newer, version, at));
                                }
                                1 => {
                                    install(&mut log, at, &newer);
                                    install(&mut log, 2 * PAGE, &copy(older, version, at));
                                }
                                2 => {
                                    install(&mut log, 2 * PAGE, &copy(older, version, at));
                                    install(&mut log, second, &copy(newer, version, at));
                                }
                                _ => {
                                    install(&mut log, 2 * PAGE, &copy(newer, version, at));
                                    install(&mut log, second, &copy(older, version, at));
                                }
                            }
                            let before = log.clone();
                            let result = check(&metadata, &log);
                            if end < 280 {
                                assert!(matches!(
                                    result,
                                    Err(FfsError::Corruption { detail, .. })
                                        if detail.contains("completed record endpoint")
                                ));
                            } else if poisoned {
                                assert_prefix_error(result);
                            } else {
                                result.unwrap();
                            }
                            assert_eq!(log, before);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn completed_spans_read_their_own_transfer_origin_bd_ofjn7() {
        let version = (2, 0);
        let (metadata, source, newer, at) = spanning_fixture(version, false);
        let origin = first(version);
        let mut log = vec![0xFF; LOG];
        for (bank, last) in [(2, source[at..at + PAGE].to_vec()), (18, newer)] {
            let mut start = source[origin..origin + PAGE].to_vec();
            start[20..22].copy_from_slice(&2_u16.to_le_bytes());
            let mut last = last;
            last[20..22].copy_from_slice(&2_u16.to_le_bytes());
            last[22..24].copy_from_slice(&2_u16.to_le_bytes());
            install(&mut log, bank * PAGE, &copy(start, version, origin));
            install(&mut log, (bank + 1) * PAGE, &copy(last, version, at));
        }
        let before = log.clone();
        check(&metadata, &log).unwrap();
        assert_eq!(log, before);
    }

    #[test]
    fn completed_span_origin_corruption_and_read_failures_propagate_bd_ofjn7() {
        let version = (2, 0);
        let (metadata, mut log, newer, at) = spanning_fixture(version, true);
        let origin = LOG - PAGE;
        let older = log[at..at + PAGE].to_vec();
        install(&mut log, 2 * PAGE, &copy(older, version, at));
        install(&mut log, 18 * PAGE, &copy(newer, version, at));
        check(&metadata, &log).unwrap();
        for mutation in 0..5 {
            let mut bad = log.clone();
            match mutation {
                0 => bad[origin + 64] ^= 1,
                1 => bad[origin + 88..origin + 92].copy_from_slice(&u32::MAX.to_le_bytes()),
                2 => bad[origin + 104..origin + 106].copy_from_slice(&3_u16.to_le_bytes()),
                3 => {
                    bad[origin + 88..origin + 92].copy_from_slice(&3984_u32.to_le_bytes());
                    bad[origin + 104..origin + 106].fill(0);
                }
                _ => bad[origin + 104..origin + 106].fill(0),
            }
            let before = bad.clone();
            assert!(matches!(
                check(&metadata, &bad),
                Err(FfsError::Corruption { .. })
            ));
            assert_eq!(bad, before);
        }
        for fault in 0..3 {
            let before = log.clone();
            let mut failed = false;
            let result = validate_latest_volume(
                &Cx::for_testing(),
                &metadata,
                LOG as u64,
                &mut |offset, size| {
                    assert!(!failed, "origin failure must stop selection immediately");
                    if offset == origin as u64 {
                        failed = true;
                        return match fault {
                            0 => Err(FfsError::Cancelled),
                            1 => Err(FfsError::Io(std::io::Error::other("origin read failure"))),
                            _ => Ok(vec![0; size - 1]),
                        };
                    }
                    load(&log, offset, size)
                },
                None,
            );
            match fault {
                0 => assert!(matches!(result, Err(FfsError::Cancelled))),
                1 => assert!(matches!(result, Err(FfsError::Io(_)))),
                _ => assert!(matches!(result, Err(FfsError::Corruption { .. }))),
            }
            assert!(failed);
            assert_eq!(log, before);
        }
    }

    #[test]
    fn obsolete_completed_spans_allow_reused_origins_but_keep_prefix_checks_bd_ofjn7() {
        let version = (2, 0);
        let (mut metadata, mut log, newer, at) = spanning_fixture(version, false);
        let origin = first(version);
        let older = log[at..at + PAGE].to_vec();
        install(&mut log, 2 * PAGE, &copy(older, version, at));
        install(&mut log, at, &newer);
        install(&mut log, origin, &page(origin, 2, true, 0xBEEF));
        metadata.current_lsn = lsn(2, origin + 160);
        metadata.active_client_oldest_lsn = Some(lsn(2, origin + 64));
        metadata.last_lsn_data_len = 40;
        let before = log.clone();
        check(&metadata, &log).unwrap();
        assert_eq!(log, before);

        // Only the new origin proof is unnecessary for two obsolete copies.
        // The original prefix-byte refusal still applies to those copies.
        let mut poisoned = log.clone();
        poisoned[2 * PAGE + 272] ^= 1;
        let poisoned_before = poisoned.clone();
        assert_prefix_error(check(&metadata, &poisoned));
        assert_eq!(poisoned, poisoned_before);

        // An older unretained record does not exempt a newer retained one,
        // and an absent client-oldest pointer never authorizes the exception.
        for oldest in [Some(lsn(1, at + 280)), None] {
            metadata.active_client_oldest_lsn = oldest;
            assert!(matches!(
                check(&metadata, &log),
                Err(FfsError::Corruption { detail, .. })
                    if detail.contains("completed record endpoint")
            ));
            assert_eq!(log, before);
        }
    }

    #[test]
    fn correct_appends_ignore_fixup_tokens_and_unused_old_slack() {
        for version in [(1, 1), (2, 0)] {
            let at = first(version);
            let mut old = page(at, 1, false, 0xCAFE);
            old[600..620].fill(0x7B); // Outside the completed payload and USA.
            let newer = page(at, 1, true, 0xBEEF);
            for ring_is_newer in [false, true] {
                let (ring, tail) = if ring_is_newer {
                    (&newer, &old)
                } else {
                    (&old, &newer)
                };
                let mut log = vec![0xFF; LOG];
                install(&mut log, at, ring);
                install(&mut log, 2 * PAGE, &copy(tail.clone(), version, at));
                let before = log.clone();
                check(&restart(version), &log).unwrap();
                assert_eq!(log, before);
            }
        }
    }

    #[test]
    fn every_member_of_a_competing_multi_page_transfer_keeps_its_completed_prefix() {
        let version = (2, 0);
        let restart = restart(version);
        let at = first(version);
        for count in 2..=16 {
            for poisoned in 0..count {
                let mut log = vec![0xFF; LOG];
                for index in 0..count {
                    let destination = at + index * PAGE;
                    for (bank, append) in [(2, false), (18, true)] {
                        let mut raw = page(destination, 1, append, 0xCAFE + index as u16);
                        if append && index == poisoned {
                            raw[VALUE + 5] ^= 1;
                        }
                        raw[20..22].copy_from_slice(&(count as u16).to_le_bytes());
                        raw[22..24].copy_from_slice(&((index + 1) as u16).to_le_bytes());
                        install(
                            &mut log,
                            (bank + index) * PAGE,
                            &copy(raw, version, destination),
                        );
                    }
                }
                let before = log.clone();
                assert_prefix_error(
                    read(
                        &Cx::for_testing(),
                        &restart,
                        restart.current_lsn,
                        &mut |at, size| load(&log, at, size),
                    )
                    .map(|_| ()),
                );
                assert_eq!(log, before);
            }
        }
    }

    #[test]
    fn newer_lsn_and_shorter_or_equal_endpoint_are_not_valid_page_progress() {
        let restart = restart((2, 0));
        let at = first((2, 0));
        let cx = Cx::for_testing();
        let old = Page::parse(&cx, &restart, at as u64, page(at, 1, false, 7)).unwrap();
        for end in [152_u16, 160] {
            let mut raw = page(at, 1, true, 9);
            raw[24..26].copy_from_slice(&end.to_le_bytes());
            let newer = Page::parse(&cx, &restart, at as u64, raw).unwrap();
            for result in [
                old.compare(&newer, &restart, at as u64, &mut |_, _| {
                    panic!("local records must not read another origin page")
                }),
                newer.compare(&old, &restart, at as u64, &mut |_, _| {
                    panic!("local records must not read another origin page")
                }),
            ] {
                assert!(matches!(result, Err(FfsError::Corruption { .. })));
            }
        }
    }

    #[test]
    fn distinct_physical_generations_are_not_subject_to_same_page_prefix_equality() {
        let restart = restart((2, 0));
        let at = first((2, 0));
        let cx = Cx::for_testing();
        let old = Page::parse(&cx, &restart, at as u64, page(at, 1, false, 7)).unwrap();
        let mut raw = page(at, 2, false, 9);
        raw[VALUE] ^= 1;
        let newer = Page::parse(&cx, &restart, at as u64, raw).unwrap();
        assert_eq!(
            newer
                .compare(&old, &restart, at as u64, &mut |_, _| {
                    panic!("distinct generations must not compare old payloads")
                })
                .unwrap(),
            Ordering::Greater
        );
        assert_eq!(
            old.compare(&newer, &restart, at as u64, &mut |_, _| {
                panic!("distinct generations must not compare old payloads")
            })
            .unwrap(),
            Ordering::Less
        );
    }

    #[test]
    fn post_wrap_continuation_uses_its_destination_generation_and_complete_bytes() {
        let restart = restart((2, 0));
        let at = first((2, 0));
        let cx = Cx::for_testing();
        let mut raw = page(at, 1, false, 7);
        let origin_lsn = lsn(1, LOG - PAGE + 4000);
        raw[8..16].copy_from_slice(&origin_lsn.to_le_bytes());
        raw[16..20].fill(0);
        raw[24..26].fill(0);
        raw[32..40].fill(0);
        let a = Page::parse(&cx, &restart, at as u64, raw.clone()).unwrap();
        assert_eq!(a.progress(&restart, at as u64).unwrap(), lsn(2, at + PAGE));
        raw[800] ^= 1;
        let b = Page::parse(&cx, &restart, at as u64, raw).unwrap();
        assert!(matches!(
            a.compare(&b, &restart, at as u64, &mut |_, _| {
                panic!("equal incomplete pages must compare their complete bytes")
            }),
            Err(FfsError::Corruption { .. })
        ));
    }

    #[test]
    fn a_selection_read_failure_is_not_a_license_to_use_the_other_bank() {
        let restart = restart((2, 0));
        let at = first((2, 0));
        let mut log = vec![0xFF; LOG];
        install(&mut log, at, &page(at, 1, false, 7));
        install(&mut log, 2 * PAGE, &copy(page(at, 1, true, 9), (2, 0), at));
        let before = log.clone();
        let result = validate_latest_volume(
            &Cx::for_testing(),
            &restart,
            LOG as u64,
            &mut |offset, size| {
                if offset == 18 * PAGE as u64 {
                    return Err(FfsError::Cancelled);
                }
                load(&log, offset, size)
            },
            None,
        );
        assert!(matches!(result, Err(FfsError::Cancelled)));
        assert_eq!(log, before);
        // Exercise the same source without an injected failure as a positive
        // control: this is not a fixture which fails before the second bank.
        discover(
            &Cx::for_testing(),
            &restart,
            LOG as u64,
            &mut |offset, size| load(&log, offset, size),
        )
        .unwrap();
    }
}
