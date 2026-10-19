use super::*;
use ffs_error::FfsError;

const PAGE: usize = 4096;
const LOG: usize = 50 * PAGE;
const HEADER: usize = 48;
const RECORD: usize = HEADER + 40;

type Spec = (usize, u64, u32, u16, u64);

fn first(version: (u16, u16)) -> usize {
    (if version.0 == 2 { 34 } else { 4 }) * PAGE
}

fn lsn(sequence: u64, at: usize) -> u64 {
    (sequence << 15) | (at as u64 / 8)
}

fn restart(version: (u16, u16), current: u64, oldest: u64) -> Restart {
    Restart {
        system_page: PAGE as u32,
        log_page: PAGE as u32,
        version,
        clean: false,
        current_lsn: current,
        seq_num_bits: 49,
        file_size: LOG as u64,
        last_lsn_data_len: 40,
        record_header_len: HEADER as u16,
        data_off: 64,
        active_client_seq: Some(9),
        active_client_oldest_lsn: Some(oldest),
        active_client_restart_lsn: None,
        area: vec![0xA7; 224],
    }
}

// Independent native fixture encoding. Neither restore_page nor any production
// writer is used to manufacture the USA-protected test input.
fn protect(mut bytes: Vec<u8>, token: u16) -> Vec<u8> {
    let count = bytes.len() / 512 + 1;
    bytes[4..6].copy_from_slice(&40_u16.to_le_bytes());
    bytes[6..8].copy_from_slice(&(count as u16).to_le_bytes());
    bytes[40..42].copy_from_slice(&token.to_le_bytes());
    for sector in 1..count {
        let at = sector * 512 - 2;
        let saved = [bytes[at], bytes[at + 1]];
        bytes[40 + 2 * sector..42 + 2 * sector].copy_from_slice(&saved);
        bytes[at..at + 2].copy_from_slice(&token.to_le_bytes());
    }
    bytes
}

fn plain(last: u64, completed: u64, next: u16) -> Vec<u8> {
    let mut bytes = vec![0; PAGE];
    bytes[..4].copy_from_slice(b"RCRD");
    bytes[8..16].copy_from_slice(&last.to_le_bytes());
    if completed != 0 {
        bytes[16..20].copy_from_slice(&1_u32.to_le_bytes());
    }
    bytes[20..22].copy_from_slice(&1_u16.to_le_bytes());
    bytes[22..24].copy_from_slice(&1_u16.to_le_bytes());
    bytes[24..26].copy_from_slice(&next.to_le_bytes());
    bytes[32..40].copy_from_slice(&completed.to_le_bytes());
    bytes
}

fn put(bytes: &mut [u8], (at, current, transaction, opcode, previous): Spec) {
    bytes[at..at + 8].copy_from_slice(&current.to_le_bytes());
    bytes[at + 8..at + 16].copy_from_slice(&previous.to_le_bytes());
    bytes[at + 24..at + 28].copy_from_slice(&40_u32.to_le_bytes());
    bytes[at + 28..at + 30].copy_from_slice(&9_u16.to_le_bytes());
    bytes[at + 32..at + 36].copy_from_slice(&1_u32.to_le_bytes());
    bytes[at + 36..at + 40].copy_from_slice(&transaction.to_le_bytes());
    bytes[at + HEADER..at + HEADER + 2].copy_from_slice(&opcode.to_le_bytes());
}

fn page(specs: &[Spec], token: u16) -> Vec<u8> {
    let &(last_at, last, _, _, _) = specs.last().unwrap();
    let mut bytes = plain(last, last, (last_at + RECORD) as u16);
    for &spec in specs { put(&mut bytes, spec); }
    protect(bytes, token)
}

fn install(log: &mut [u8], at: usize, page: &[u8]) {
    log[at..at + PAGE].copy_from_slice(page);
}

fn source(log: &[u8], at: u64, size: usize) -> Result<Vec<u8>> {
    let at = usize::try_from(at).map_err(|_| corrupt(0, "fixture offset overflow"))?;
    let end = at.checked_add(size).ok_or_else(|| corrupt(0, "fixture range overflow"))?;
    log.get(at..end).map(<[u8]>::to_vec).ok_or_else(|| corrupt(0, "fixture read outside log"))
}

fn check(restart: &Restart, log: &[u8]) -> Result<TailRecord> {
    validate_latest_volume(&Cx::for_testing(), restart, log.len() as u64,
        &mut |at, size| source(log, at, size), None)
}

fn append_fixture(version: (u16, u16)) -> (Restart, Vec<u8>, u64) {
    let at = first(version);
    let a = lsn(1, at + 64);
    let b = lsn(1, at + 64 + RECORD);
    let mut log = vec![0xFF; LOG];
    install(&mut log, at, &page(&[(64, a, 24, 0, 0), (64 + RECORD, b, 24, 0x1A, a)], 0xCAFE));
    (restart(version, a, a), log, b)
}

fn tail_copy(mut raw: Vec<u8>, version: (u16, u16), destination: usize) -> Vec<u8> {
    if version.0 == 1 {
        raw[8..16].copy_from_slice(&(destination as u64).to_le_bytes());
    } else {
        raw[60..64].copy_from_slice(&(destination as u32).to_le_bytes());
    }
    raw
}

#[test]
fn commit_after_the_restart_boundary_is_analyzed_not_lost_or_undone() {
    for version in [(1, 1), (2, 0)] {
        let (restart, log, expected) = append_fixture(version);
        let before = log.clone();
        let native_area = restart.area.clone();
        let view = discover(&Cx::for_testing(), &restart, LOG as u64,
            &mut |at, size| source(&log, at, size)).unwrap();
        assert_eq!(view.boundary.current_lsn, expected);
        assert_eq!(view.boundary.last_lsn_data_len, 40);
        assert!(view.pages.is_empty());
        let tail = check(&restart, &log).unwrap();
        assert_eq!((tail.transaction_id, tail.redo_op), (24, 0x1A));
        assert_ne!(restart.current_lsn, expected);
        assert_eq!(restart.area, native_area, "no native restart is rewritten");
        assert_eq!(log, before, "preflight is strictly read-only");
    }
}

#[test]
fn complete_single_page_tail_copies_supply_the_newer_page_in_both_native_versions() {
    for version in [(1, 1), (2, 0)] {
        for slot in [2, if version.0 == 2 { 18 } else { 3 }] {
            let (restart, mut log, expected) = append_fixture(version);
            let at = first(version);
            let copy = tail_copy(log[at..at + PAGE].to_vec(), version, at);
            install(&mut log, slot * PAGE, &copy);
            install(&mut log, at, &page(&[(64, restart.current_lsn, 24, 0, 0)], 0xBEEF));
            let before = log.clone();
            let view = discover(&Cx::for_testing(), &restart, LOG as u64,
                &mut |at, size| source(&log, at, size)).unwrap();
            assert_eq!(view.boundary.current_lsn, expected);
            assert_eq!(view.pages.len(), 1);
            let fixed = restore_page(&Cx::for_testing(), view.pages[&(at as u64)].clone(),
                &restart, at as u64).unwrap();
            assert_eq!(u64_at(&fixed.bytes, 8).unwrap(), expected);
            if version.0 == 2 { assert_eq!(u32_at(&fixed.bytes, 60).unwrap(), 0); }
            assert_eq!(check(&restart, &log).unwrap().redo_op, 0x1A);
            assert_eq!(log, before);
        }
    }
}

#[test]
fn newest_complete_copy_wins_but_equal_lsn_conflicts_are_not_scan_order_choices() {
    for version in [(1, 1), (2, 0)] {
        let (restart, mut log, last) = append_fixture(version);
        let at = first(version);
        let old = tail_copy(page(&[(64, restart.current_lsn, 24, 0, 0)], 0xCAFE), version, at);
        let good = tail_copy(page(&[(64, restart.current_lsn, 24, 0, 0),
            (64 + RECORD, last, 24, 0x1A, restart.current_lsn)], 0xBEEF), version, at);
        for reverse in [false, true] {
            install(&mut log, 2 * PAGE, if reverse { &good } else { &old });
            install(&mut log, 3 * PAGE, if reverse { &old } else { &good });
            assert_eq!(check(&restart, &log).unwrap().redo_op, 0x1A);
        }
        // Identical logical records survive different USA tokens.
        install(&mut log, 2 * PAGE, &good);
        let equal = tail_copy(page(&[(64, restart.current_lsn, 24, 0, 0),
            (64 + RECORD, last, 24, 0x1A, restart.current_lsn)], 0xABCD), version, at);
        install(&mut log, 3 * PAGE, &equal);
        check(&restart, &log).unwrap();
        log[3 * PAGE + 64 + RECORD + 36] ^= 1;
        assert!(matches!(check(&restart, &log), Err(FfsError::Corruption { .. })));
    }
}

#[test]
fn sealed_page_padding_and_native_ring_wrap_do_not_hide_a_later_commit() {
    for version in [(1, 1), (2, 0)] {
        let at = first(version);
        let a = lsn(1, LOG - PAGE + 64);
        let b = lsn(2, at + 64);
        let mut log = vec![0xFF; LOG];
        install(&mut log, LOG - PAGE, &page(&[(64, a, 24, 0, 0)], 0xCAFE));
        install(&mut log, at, &page(&[(64, b, 24, 0x1A, a)], 0xBEEF));
        assert_eq!(check(&restart(version, a, a), &log).unwrap().redo_op, 0x1A);
    }
}

#[test]
fn spanning_new_record_reuses_the_existing_protected_payload_and_chronology_readers() {
    let version = (2, 0);
    let at = first(version);
    let a = lsn(1, at + 64);
    let b = lsn(1, at + 152);
    let c = lsn(1, at + PAGE + 368);
    let mut log = vec![0xFF; LOG];
    let mut start = plain(b, a, 0);
    put(&mut start, (64, a, 24, 0, 0));
    put(&mut start, (152, b, 64, 0, 0));
    start[152 + 24..152 + 28].copy_from_slice(&4200_u32.to_le_bytes());
    start[152 + 40..152 + 42].copy_from_slice(&1_u16.to_le_bytes());
    let mut end = plain(c, c, 456);
    put(&mut end, (368, c, 64, 0x1A, b));
    // 3896 client bytes in the first page, followed by 304 at offset 64.
    install(&mut log, at, &protect(start, 0xCAFE));
    install(&mut log, at + PAGE, &protect(end, 0xBEEF));
    let tail = check(&restart(version, a, a), &log).unwrap();
    assert_eq!((tail.transaction_id, tail.redo_op), (64, 0x1A));
}

#[test]
fn interleaved_bad_record_or_missing_successor_cannot_be_skipped_to_the_maximum_lsn() {
    let version = (2, 0);
    let at = first(version);
    let a = lsn(1, at + 64);
    let b = lsn(1, at + 152);
    let c = lsn(1, at + 240);
    let mut log = vec![0xFF; LOG];
    install(&mut log, at, &page(&[(64, a, 24, 0, 0), (152, b, 64, 0, 0),
        (240, c, 24, 0x1A, a)], 0xCAFE));
    log[at + 152 + 28..at + 152 + 30].copy_from_slice(&10_u16.to_le_bytes());
    assert!(check(&restart(version, a, a), &log).is_err());
    let mut log = vec![0xFF; LOG];
    let later = lsn(1, at + 2 * PAGE + 64);
    install(&mut log, at, &page(&[(64, a, 24, 0, 0)], 0xCAFE));
    install(&mut log, at + 2 * PAGE, &page(&[(64, later, 24, 0x1A, a)], 0xBEEF));
    assert!(check(&restart(version, a, a), &log).is_err());
    let mut no_oldest = restart(version, a, a);
    no_oldest.active_client_oldest_lsn = None;
    assert!(check(&no_oldest, &log).is_err(), "append continuity cannot depend on a seed pointer");
}

#[test]
fn torn_tail_slots_and_torn_ring_pages_are_not_downgraded_to_absent_data() {
    for version in [(1, 1), (2, 0)] {
        for tail_slot in [false, true] {
            let (restart, mut log, _) = append_fixture(version);
            let at = first(version);
            if tail_slot {
                let copy = tail_copy(log[at..at + PAGE].to_vec(), version, at);
                install(&mut log, 2 * PAGE, &copy);
            }
            let damaged = if tail_slot { 2 * PAGE } else { at };
            for sector in 1..=PAGE / 512 {
                let mut bad = log.clone();
                bad[damaged + sector * 512 - 1] ^= 1;
                assert!(matches!(check(&restart, &bad), Err(FfsError::Corruption { .. })));
            }
        }
    }
}

#[test]
fn incomplete_newest_record_and_multi_page_tail_transfers_are_explicit_refusals() {
    let version = (2, 0);
    let (restart, mut log, last) = append_fixture(version);
    let at = first(version);
    // An incomplete higher-LSN record cannot become a successful earlier view.
    log[at + 32..at + 40].copy_from_slice(&restart.current_lsn.to_le_bytes());
    assert!(matches!(check(&restart, &log), Err(FfsError::UnsupportedFeature(_))));
    let (restart, mut log, _) = append_fixture(version);
    let mut copy = tail_copy(log[at..at + PAGE].to_vec(), version, at);
    copy[20..22].copy_from_slice(&2_u16.to_le_bytes());
    install(&mut log, 2 * PAGE, &copy);
    assert!(matches!(check(&restart, &log), Err(FfsError::UnsupportedFeature(_))));
    assert!(last > restart.current_lsn);
}

#[test]
fn false_tail_identity_future_epoch_and_overwritten_retention_are_rejected() {
    let version = (2, 0);
    let (restart, log, _) = append_fixture(version);
    let at = first(version);
    for fake in [lsn(1, at + 400), lsn(3, at + 152), lsn(2, at + 152)] {
        let mut bad = log.clone();
        bad[at + 8..at + 16].copy_from_slice(&fake.to_le_bytes());
        bad[at + 32..at + 40].copy_from_slice(&fake.to_le_bytes());
        assert!(check(&restart, &bad).is_err());
    }
    let mut bad_anchor = restart.clone();
    bad_anchor.last_lsn_data_len += 1;
    assert!(check(&bad_anchor, &log).is_err());
    let mut future_checkpoint = restart.clone();
    future_checkpoint.active_client_restart_lsn = Some(lsn(1, at + 152));
    assert!(check(&future_checkpoint, &log).is_err());
}

#[test]
fn invalid_tail_destinations_cannot_redirect_recovery_into_reserved_or_unbounded_bytes() {
    let version = (2, 0);
    let (restart, log, _) = append_fixture(version);
    let at = first(version);
    for target in [0_u32, PAGE as u32, (at + 1) as u32, LOG as u32, u32::MAX] {
        let mut bad = log.clone();
        let mut copy = log[at..at + PAGE].to_vec();
        copy[60..64].copy_from_slice(&target.to_le_bytes());
        install(&mut bad, 2 * PAGE, &copy);
        assert!(matches!(check(&restart, &bad), Err(FfsError::Corruption { .. })));
    }
}

#[test]
fn source_failures_short_reads_and_cancellation_abort_without_any_partial_tail_result() {
    let (restart, log, _) = append_fixture((2, 0));
    for fail_at in [0, 3, 34] {
        for kind in 0..3 {
            let mut reads = 0;
            let result = validate_latest_volume(&Cx::for_testing(), &restart, LOG as u64,
                &mut |at, size| {
                    let fail = reads == fail_at;
                    reads += 1;
                    if fail {
                        return match kind {
                            0 => Err(FfsError::Cancelled),
                            1 => Err(FfsError::Io(std::io::Error::other("injected tail read"))),
                            _ => Ok(vec![0xFF; size - 1]),
                        };
                    }
                    source(&log, at, size)
                }, None);
            match kind {
                0 => assert!(matches!(result, Err(FfsError::Cancelled))),
                1 => assert!(matches!(result, Err(FfsError::Io(_)))),
                _ => assert!(matches!(result, Err(FfsError::Corruption { .. }))),
            }
            assert_eq!(reads, fail_at + 1);
        }
    }
}

#[test]
fn scan_budget_is_checked_before_io_and_partial_reads_cannot_bypass_overrides() {
    let (mut restart, log, _) = append_fixture((2, 0));
    restart.file_size = (MAX_PAGES + 1) * PAGE as u64;
    let mut reads = 0;
    assert!(discover(&Cx::for_testing(), &restart, restart.file_size, &mut |_, _| {
        reads += 1;
        Ok(Vec::new())
    }).is_err());
    assert_eq!(reads, 0);
    restart.file_size = LOG as u64;
    let view = discover(&Cx::for_testing(), &restart, LOG as u64,
        &mut |at, size| source(&log, at, size)).unwrap();
    assert!(view.read(&Cx::for_testing(), first((2, 0)) as u64 + 1, PAGE - 1,
        &mut |_, _| { reads += 1; Ok(Vec::new()) }).is_err());
    assert_eq!(reads, 0);
}

#[test]
fn v2_tail_destination_must_not_alias_saved_usa_words() {
    let (mut restart, mut log, _) = append_fixture((2, 0));
    let at = first((2, 0));
    restart.data_off = 72;
    restart.current_lsn = lsn(1, at + 128);
    restart.active_client_oldest_lsn = Some(restart.current_lsn);
    let old = log[at..at + PAGE].to_vec();
    let mut copy = old.clone();
    copy[4..6].copy_from_slice(&48_u16.to_le_bytes());
    copy[48..50].copy_from_slice(&0xCAFE_u16.to_le_bytes());
    for sector in 1..=8 {
        copy[48 + sector * 2..50 + sector * 2]
            .copy_from_slice(&old[40 + sector * 2..42 + sector * 2]);
    }
    // Both fields fit the page, but the destination now aliases two saved
    // trailer words. Clearing it would silently change restored client bytes.
    copy[60..64].copy_from_slice(&(at as u32).to_le_bytes());
    install(&mut log, 2 * PAGE, &copy);
    let before = log.clone();
    match check(&restart, &log) {
        Err(FfsError::Corruption { detail, .. }) => assert!(detail.contains("USA")),
        other => panic!("expected a tail/USA alias refusal, got {other:?}"),
    }
    assert_eq!(log, before);
}

fn transfer_copy(mut raw: Vec<u8>, destination: usize, count: usize, position: usize) -> Vec<u8> {
    // These native header fields do not overlap the USA or protected trailers.
    raw[20..22].copy_from_slice(&u16::try_from(count).unwrap().to_le_bytes());
    raw[22..24].copy_from_slice(&u16::try_from(position).unwrap().to_le_bytes());
    raw[60..64].copy_from_slice(&u32::try_from(destination).unwrap().to_le_bytes());
    raw
}

fn bank_fixture(count: usize, bank: usize) -> (Restart, Vec<u8>, u64) {
    assert!((2..=16).contains(&count));
    let at = first((2, 0));
    let anchor = lsn(1, at + 64);
    let mut previous = 0;
    let mut log = vec![0xFF; LOG];
    for index in 0..count {
        let destination = at + index * PAGE;
        let current = lsn(1, destination + 64);
        let opcode = if index + 1 == count { 0x1A } else { 0 };
        let raw = page(&[(64, current, 24, opcode, previous)], 0xA000 + index as u16);
        install(&mut log, (bank + index) * PAGE,
            &transfer_copy(raw, destination, count, index + 1));
        previous = current;
    }
    // The first page has already reached the ring; the other pages exist only
    // in the complete tail transfer. Equal published bytes are safe to retain.
    install(&mut log, at, &page(&[(64, anchor, 24, 0, 0)], 0xBEEF));
    (restart((2, 0), anchor, anchor), log, previous)
}

#[test]
fn complete_two_to_sixteen_page_transfers_in_either_bank_reach_transaction_analysis() {
    for count in 2..=16 {
        for bank in [2, 18] {
            let (restart, log, expected) = bank_fixture(count, bank);
            let before = log.clone();
            let view = discover(&Cx::for_testing(), &restart, LOG as u64,
                &mut |at, size| source(&log, at, size)).unwrap();
            assert_eq!(view.boundary.current_lsn, expected);
            assert_eq!(view.pages.len(), count - 1);
            let tail = check(&restart, &log).unwrap();
            assert_eq!((tail.transaction_id, tail.redo_op), (24, 0x1A));
            assert_eq!(log, before, "bank recovery must not rewrite native storage");
        }
    }
}

#[test]
fn duplicate_complete_banks_ignore_usa_tokens_but_not_log_contents() {
    let (restart, mut log, expected) = bank_fixture(3, 2);
    let at = first((2, 0));
    let mut previous = 0;
    for index in 0..3 {
        let destination = at + index * PAGE;
        let current = lsn(1, destination + 64);
        let raw = page(&[(64, current, 24, if index == 2 { 0x1A } else { 0 }, previous)],
            0xB000 + index as u16);
        install(&mut log, (18 + index) * PAGE, &transfer_copy(raw, destination, 3, index + 1));
        previous = current;
    }
    assert_eq!(check(&restart, &log).unwrap().redo_op, 0x1A);
    let view = discover(&Cx::for_testing(), &restart, LOG as u64,
        &mut |at, size| source(&log, at, size)).unwrap();
    assert_eq!(view.boundary.current_lsn, expected);
    // Keep valid fixups and an unchanged maximum LSN while changing one client.
    log[19 * PAGE + 64 + 36] ^= 1;
    assert!(matches!(check(&restart, &log), Err(FfsError::Corruption { .. })));
}

#[test]
fn a_spanning_record_in_a_complete_tail_transfer_is_reassembled_before_analysis() {
    let at = first((2, 0));
    let a = lsn(1, at + 64);
    let b = lsn(1, at + 152);
    let c = lsn(1, at + PAGE + 368);
    let mut log = vec![0xFF; LOG];
    let mut start = plain(b, a, 152);
    put(&mut start, (64, a, 24, 0, 0));
    put(&mut start, (152, b, 64, 0, 0));
    start[152 + 24..152 + 28].copy_from_slice(&4200_u32.to_le_bytes());
    start[152 + 40..152 + 42].copy_from_slice(&1_u16.to_le_bytes());
    let mut end = plain(c, c, 456);
    put(&mut end, (368, c, 64, 0x1A, b));
    install(&mut log, 2 * PAGE, &transfer_copy(protect(start, 0xABCD), at, 2, 1));
    install(&mut log, 3 * PAGE, &transfer_copy(protect(end, 0xBCDE), at + PAGE, 2, 2));
    install(&mut log, at, &page(&[(64, a, 24, 0, 0)], 0xCAFE));
    let before = log.clone();
    let metadata = restart((2, 0), a, a);
    let tail = check(&metadata, &log).unwrap();
    assert_eq!((tail.transaction_id, tail.redo_op), (64, 0x1A));
    assert_eq!(log, before);
    for mutation in 0..3 {
        let mut bad = log.clone();
        match mutation {
            0 => bad[2 * PAGE + 152 + 40..2 * PAGE + 152 + 42].fill(0),
            1 => bad[2 * PAGE + 152 + 28..2 * PAGE + 152 + 30]
                .copy_from_slice(&10_u16.to_le_bytes()),
            _ => bad[3 * PAGE + 368..3 * PAGE + 376].fill(0),
        }
        assert!(check(&metadata, &bad).is_err(), "bad spanning record {mutation}");
    }
}

#[test]
fn incomplete_page_comparison_includes_bytes_after_an_earlier_completed_record() {
    let at = first((2, 0));
    let a = lsn(1, at + 64);
    let b = lsn(1, at + 152);
    let metadata = restart((2, 0), a, a);
    let mut raw = plain(b, a, 152);
    put(&mut raw, (64, a, 24, 0, 0));
    put(&mut raw, (152, b, 64, 0, 0));
    raw[152 + 24..152 + 28].copy_from_slice(&4200_u32.to_le_bytes());
    raw[152 + 40..152 + 42].copy_from_slice(&1_u16.to_le_bytes());
    let cx = Cx::for_testing();
    let original = Page::parse(&cx, &metadata, at as u64, protect(raw.clone(), 0xABCD)).unwrap();
    let equal = Page::parse(&cx, &metadata, at as u64, protect(raw.clone(), 0xBCDE)).unwrap();
    assert!(original.same_contents(&equal, 64));
    for changed in [200, 510, 511, 1022, PAGE - 1] {
        let mut bad = raw.clone();
        bad[changed] ^= 1;
        let other = Page::parse(&cx, &metadata, at as u64, protect(bad, 0xCAFE)).unwrap();
        assert!(!original.same_contents(&other, 64), "continuation byte {changed}");
    }
}

#[test]
fn incomplete_discontinuous_torn_and_cross_generation_transfers_never_return_a_view() {
    let (restart, log, _) = bank_fixture(3, 2);
    let continuation = 3 * PAGE;
    for mutation in 0..8 {
        let mut bad = log.clone();
        match mutation {
            0 => bad[continuation..continuation + PAGE].fill(0xFF),
            1 => bad[continuation + 20..continuation + 22].copy_from_slice(&2_u16.to_le_bytes()),
            2 => bad[continuation + 22..continuation + 24].copy_from_slice(&1_u16.to_le_bytes()),
            3 => bad[continuation + 60..continuation + 64]
                .copy_from_slice(&u32::try_from(first((2, 0)) + 2 * PAGE).unwrap().to_le_bytes()),
            4 => bad[continuation + PAGE - 1] ^= 1,
            5 => {
                let future = lsn(2, first((2, 0)) + PAGE + 64);
                bad[continuation + 8..continuation + 16].copy_from_slice(&future.to_le_bytes());
                bad[continuation + 32..continuation + 40].copy_from_slice(&future.to_le_bytes());
            }
            6 => bad[4 * PAGE + 24..4 * PAGE + 26].fill(0),
            _ => bad[2 * PAGE + 22..2 * PAGE + 24].copy_from_slice(&2_u16.to_le_bytes()),
        }
        let before = bad.clone();
        assert!(check(&restart, &bad).is_err(), "invalid transfer {mutation}");
        assert_eq!(bad, before);
    }
}

#[test]
fn bank_capacity_and_destination_wrap_are_not_completed_from_neighboring_storage() {
    let (restart, log, _) = bank_fixture(2, 2);
    let mut beyond_bank = vec![0xFF; LOG];
    install(&mut beyond_bank, 17 * PAGE, &log[2 * PAGE..3 * PAGE]);
    install(&mut beyond_bank, 18 * PAGE, &log[3 * PAGE..4 * PAGE]);
    assert!(matches!(check(&restart, &beyond_bank), Err(FfsError::UnsupportedFeature(_))));
    let mut wrap = log;
    wrap[2 * PAGE + 60..2 * PAGE + 64]
        .copy_from_slice(&u32::try_from(LOG - PAGE).unwrap().to_le_bytes());
    wrap[3 * PAGE + 60..3 * PAGE + 64]
        .copy_from_slice(&u32::try_from(first((2, 0))).unwrap().to_le_bytes());
    assert!(matches!(check(&restart, &wrap), Err(FfsError::UnsupportedFeature(_))));
}

#[test]
fn competing_transfers_need_uniform_order_and_identical_destination_sets() {
    let at = first((2, 0));
    let anchor = lsn(1, at + 64);
    let metadata = restart((2, 0), anchor, anchor);
    for crossed in [false, true] {
        let mut log = vec![0xFF; LOG];
        for (bank, offsets) in [(2, [64, 152]), (18, [152, if crossed { 64 } else { 152 }])] {
            for (index, offset) in offsets.into_iter().enumerate() {
                let destination = at + index * PAGE;
                let current = lsn(1, destination + offset);
                // Include the same earlier record when this page has two.
                let mut specs = vec![(64, lsn(1, destination + 64), 24, 0, 0)];
                if offset != 64 { specs.push((offset, current, 64, 0, 0)); }
                let raw = page(&specs, 0xABCD);
                install(&mut log, (bank + index) * PAGE,
                    &transfer_copy(raw, destination, 2, index + 1));
            }
        }
        let result = transfers::read(&Cx::for_testing(), &metadata, anchor,
            &mut |at, size| source(&log, at, size));
        if crossed {
            assert!(matches!(result, Err(FfsError::UnsupportedFeature(_))));
        } else {
            let copies = result.unwrap();
            assert_eq!(copies.pages[&(at as u64)].last, lsn(1, at + 152));
            assert_eq!(copies.groups.len(), 1);
        }
    }
    let (_, mut log, _) = bank_fixture(2, 2);
    for index in 0..2 {
        let destination = at + (index + 1) * PAGE;
        let current = lsn(1, destination + 64);
        let raw = page(&[(64, current, 24, 0, 0)], 0xBCDE);
        install(&mut log, (18 + index) * PAGE,
            &transfer_copy(raw, destination, 2, index + 1));
    }
    assert!(matches!(transfers::read(&Cx::for_testing(), &metadata, anchor,
        &mut |at, size| source(&log, at, size)), Err(FfsError::UnsupportedFeature(_))));
}

#[test]
fn partially_newer_ring_cannot_be_spliced_with_an_older_tail_transfer() {
    let (restart, mut log, _) = bank_fixture(3, 2);
    let at = first((2, 0)) + PAGE;
    let first_lsn = lsn(1, at + 64);
    let later = lsn(1, at + 152);
    install(&mut log, at, &page(&[(64, first_lsn, 24, 0, restart.current_lsn),
        (152, later, 64, 0, 0)], 0xCAFE));
    // Page two is newer on the ring but page three exists only in the bank.
    // Both pages decode individually; combining them would mix publications.
    match discover(&Cx::for_testing(), &restart, LOG as u64,
        &mut |at, size| source(&log, at, size)) {
        Err(FfsError::UnsupportedFeature(detail)) => assert!(detail.contains("mixed-transfer")),
        _ => panic!("mixed ring/bank publication was not refused"),
    }
}

#[test]
fn cancellation_while_loading_a_transfer_never_returns_its_valid_prefix() {
    let (restart, log, _) = bank_fixture(16, 18);
    for failed_page in 0..16 {
        let failed_at = ((18 + failed_page) * PAGE) as u64;
        let mut failed = false;
        let result = validate_latest_volume(&Cx::for_testing(), &restart, LOG as u64,
            &mut |at, size| {
                assert!(!failed, "no source reads are allowed after cancellation");
                if at == failed_at {
                    failed = true;
                    Err(FfsError::Cancelled)
                } else {
                    source(&log, at, size)
                }
            }, None);
        assert!(failed);
        assert!(matches!(result, Err(FfsError::Cancelled)));
    }
}
