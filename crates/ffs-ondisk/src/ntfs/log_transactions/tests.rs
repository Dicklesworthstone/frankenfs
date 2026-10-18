use super::*;
use crate::ntfs::parse_ntfs_logfile;

fn update(lsn: u64, id: u32, previous: u64, next: u64) -> NtfsLogRecord {
    NtfsLogRecord {
        this_lsn: lsn,
        client_previous_lsn: previous,
        client_undo_next_lsn: next,
        transaction_id: id,
        record_type: 1,
        redo_op: NtfsLogOp::UpdateResidentValue,
        undo_op: NtfsLogOp::UpdateResidentValue,
        target_attribute: 24,
        record_offset: 64,
        attribute_offset: 24,
        cluster_block_offset: 0,
        target_vcn: 4,
        target_lcn: 100,
        redo_data: vec![u8::try_from(lsn).unwrap()],
        undo_data: vec![u8::try_from(lsn).unwrap() + 100],
    }
}

fn control(lsn: u64, id: u32, previous: u64, next: u64, op: NtfsLogOp) -> NtfsLogRecord {
    let mut record = update(lsn, id, previous, next);
    record.redo_op = op;
    record.undo_op = NtfsLogOp::Noop;
    record.target_lcn = 0;
    record.redo_data.clear();
    record.undo_data.clear();
    record
}

fn undo_lsns(plan: &Plan) -> Vec<u64> {
    plan.undo_actions.iter().map(|action| action.lsn).collect()
}

#[test]
fn opcode_numbers_are_literal_native_values_not_enum_ordinals_or_shifted_aliases() {
    use NtfsLogOp as Op;
    let expected = [
        (0x00, Op::Noop),
        (0x01, Op::CompensationLogRecord),
        (0x02, Op::InitializeFileRecordSegment),
        (0x03, Op::DeallocateFileRecordSegment),
        (0x04, Op::WriteEndOfFileRecordSegment),
        (0x05, Op::CreateAttribute),
        (0x06, Op::DeleteAttribute),
        (0x07, Op::UpdateResidentValue),
        (0x08, Op::UpdateNonresidentValue),
        (0x09, Op::UpdateMappingPairs),
        (0x0A, Op::DeleteDirtyClusters),
        (0x0B, Op::SetNewAttributeSizes),
        (0x0C, Op::AddIndexEntryRoot),
        (0x0D, Op::DeleteIndexEntryRoot),
        (0x0E, Op::AddIndexEntryAllocation),
        (0x0F, Op::DeleteIndexEntryAllocation),
        (0x10, Op::WriteEndOfIndexBuffer),
        (0x11, Op::SetIndexEntryVcnRoot),
        (0x12, Op::SetIndexEntryVcnAllocation),
        (0x13, Op::UpdateFileNameRoot),
        (0x14, Op::UpdateFileNameAllocation),
        (0x15, Op::SetBitsInNonresidentBitMap),
        (0x16, Op::ClearBitsInNonresidentBitMap),
        (0x17, Op::HotFix),
        (0x18, Op::EndTopLevelAction),
        (0x19, Op::PrepareTransaction),
        (0x1A, Op::CommitTransaction),
        (0x1B, Op::ForgetTransaction),
        (0x1C, Op::OpenNonresidentAttribute),
        (0x1D, Op::OpenAttributeTableDump),
        (0x1E, Op::AttributeNamesDump),
        (0x1F, Op::DirtyPageTableDump),
        (0x20, Op::TransactionTableDump),
        (0x21, Op::UpdateRecordDataRoot),
        (0x22, Op::UpdateRecordDataAllocation),
        (0x23, Op::UpdateRelativeDataInIndex),
        (0x24, Op::UpdateRelativeDataInIndex2),
        (0x25, Op::ZeroEndOfFileRecord),
    ];
    for (raw, expected) in expected {
        assert_eq!(Op::from_raw(raw), expected, "native opcode {raw:#04x}");
    }
    for raw in 0x26..=u16::MAX {
        assert_eq!(Op::from_raw(raw), Op::Unknown(raw));
    }
    for raw in 0x17..=0x20 {
        assert!(!Op::from_raw(raw).patches_bytes(), "control {raw:#04x}");
    }
}

#[test]
fn commit_preserves_winner_data_and_forget_is_not_itself_a_commit() {
    let records = [
        update(10, 24, 0, 0),
        control(20, 24, 10, 10, NtfsLogOp::CommitTransaction),
        control(30, 24, 20, 0, NtfsLogOp::ForgetTransaction),
        control(40, 64, 0, 0, NtfsLogOp::ForgetTransaction),
    ];
    let plan = build(&records).unwrap();
    assert_eq!(plan.committed, [24]);
    assert!(plan.active.is_empty());
    assert!(plan.undo_actions.is_empty());
}

#[test]
fn reused_transaction_slots_never_undo_a_forgotten_winner() {
    let records = [
        update(10, 24, 0, 0),
        control(20, 24, 10, 10, NtfsLogOp::CommitTransaction),
        control(30, 24, 20, 0, NtfsLogOp::ForgetTransaction),
        update(40, 24, 0, 0),
        update(50, 24, 40, 40),
    ];
    let plan = build(&records).unwrap();
    assert_eq!(plan.committed, [24]);
    assert_eq!(plan.active, [24]);
    assert_eq!(undo_lsns(&plan), [50, 40]);
    let mut stale = records.to_vec();
    stale[3].client_undo_next_lsn = 10;
    assert!(build(&stale).is_err());
    stale[3].client_undo_next_lsn = 0;
    stale[4].client_undo_next_lsn = 10;
    assert!(build(&stale).is_err());
}

#[test]
fn compensation_redo_is_retained_but_already_undone_work_is_not_undone_again() {
    let mut clr = update(30, 24, 20, 10);
    clr.undo_op = NtfsLogOp::CompensationLogRecord;
    let records = [update(10, 24, 0, 0), update(20, 24, 10, 10), clr];
    let before = records.to_vec();
    let plan = build(&records).unwrap();
    assert_eq!(undo_lsns(&plan), [10]);
    assert_eq!(records.as_slice(), before.as_slice());
    // A later operation may point back through a CLR. Following the native
    // undo-next chain still skips the compensated update at LSN 20.
    let mut later = records.to_vec();
    later.push(update(40, 24, 30, 30));
    assert_eq!(undo_lsns(&build(&later).unwrap()), [40, 10]);
}

#[test]
fn completed_top_level_actions_do_not_resurrect_nested_undo() {
    let records = [
        update(10, 24, 0, 0),
        update(20, 24, 10, 10),
        control(30, 24, 20, 10, NtfsLogOp::EndTopLevelAction),
        update(40, 24, 30, 30),
    ];
    assert_eq!(undo_lsns(&build(&records).unwrap()), [40, 10]);
}

#[test]
fn interleaved_losers_are_undone_in_global_descending_lsn_order() {
    let records = [
        update(10, 24, 0, 0),
        update(20, 64, 0, 0),
        update(30, 24, 10, 10),
        update(40, 64, 20, 20),
    ];
    let plan = build(&records).unwrap();
    assert_eq!(plan.active, [24, 64]);
    assert_eq!(undo_lsns(&plan), [40, 30, 20, 10]);
    assert!(plan.undo_actions.iter().all(|action| action.is_undo));
    assert_eq!(plan.undo_actions[0].data, [140]);
}

#[test]
fn prepared_work_needs_a_decision_but_a_retained_commit_resolves_it() {
    let mut records = vec![
        update(10, 24, 0, 0),
        control(20, 24, 10, 10, NtfsLogOp::PrepareTransaction),
    ];
    assert!(build(&records).is_err());
    records.push(control(30, 24, 20, 0, NtfsLogOp::CommitTransaction));
    let plan = build(&records).unwrap();
    assert_eq!(plan.committed, [24]);
    assert!(plan.undo_actions.is_empty());
}

#[test]
fn invalid_chain_order_missing_links_and_cross_owner_references_are_errors() {
    for mutation in 0..8 {
        let mut records = vec![
            update(10, 24, 0, 0),
            update(20, 64, 0, 0),
            update(30, 24, 10, 10),
        ];
        match mutation {
            0 => records[2].client_undo_next_lsn = 30,
            1 => records[2].client_undo_next_lsn = 40,
            2 => records[2].client_undo_next_lsn = 25,
            3 => records[2].client_undo_next_lsn = 20,
            4 => records[2].client_previous_lsn = 20,
            5 => records[0].client_previous_lsn = 1,
            6 => records.swap(0, 1),
            _ => records[2].this_lsn = 20,
        }
        assert!(build(&records).is_err(), "invalid chain mutation {mutation}");
    }
}

#[test]
fn committed_slots_cannot_be_modified_before_native_forget() {
    for op in [NtfsLogOp::CommitTransaction, NtfsLogOp::PrepareTransaction] {
        let records = [
            update(10, 24, 0, 0),
            control(20, 24, 10, 10, op),
            update(30, 24, 20, 20),
        ];
        assert!(build(&records).is_err());
    }
}

#[test]
fn unsupported_operations_are_not_silently_omitted_from_the_recovery_plan() {
    for raw in [0x0A, 0x15, 0x16, 0x17, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
                0x21, 0x22, 0x23, 0x24, 0x25, 0x26, u16::MAX] {
        for undo in [false, true] {
            let mut record = update(10, 24, 0, 0);
            if undo {
                record.undo_op = NtfsLogOp::from_raw(raw);
            } else {
                record.redo_op = NtfsLogOp::from_raw(raw);
            }
            assert!(build(&[record]).is_err(), "required opcode {raw:#04x}");
        }
    }
}

#[test]
fn missing_identity_targets_and_work_budget_fail_without_partial_actions() {
    for mutation in 0..4 {
        let mut record = update(10, 24, 0, 0);
        match mutation {
            0 => record.transaction_id = 0,
            1 => record.target_lcn = 0,
            2 => record.record_type = 2,
            _ => record.redo_op = NtfsLogOp::CompensationLogRecord,
        }
        assert!(build(&[record]).is_err());
    }
    assert!(build(&vec![update(10, 24, 0, 0); MAX_RECORDS + 1]).is_err());
    let records: Vec<_> = (1..=MAX_SLOTS + 1)
        .map(|id| {
            let mut record = update(10, 24, 0, 0);
            record.transaction_id = u32::try_from(id).unwrap();
            record.this_lsn = id as u64;
            record
        })
        .collect();
    assert!(build(&records).is_err());
    let empty = build(&[]).unwrap();
    assert!(empty.committed.is_empty() && empty.active.is_empty() && empty.undo_actions.is_empty());
}

// Independently encode protected 4 KiB RSTR/RCRCD pages with native wire
// opcodes. These are synthetic parser fixtures, not Windows interchange proof.
fn protect(mut page: Vec<u8>, usa: usize, token: u16) -> Vec<u8> {
    page[usa..usa + 2].copy_from_slice(&token.to_le_bytes());
    for sector in 1..=page.len() / 512 {
        let at = sector * 512 - 2;
        let saved = [page[at], page[at + 1]];
        page[usa + 2 * sector..usa + 2 * sector + 2].copy_from_slice(&saved);
        page[at..at + 2].copy_from_slice(&token.to_le_bytes());
    }
    page
}

fn wire_log(specs: &[(u16, u16, u32, Option<usize>, Option<usize>)]) -> Vec<u8> {
    const SIZE: usize = 262_144;
    const PAGE: usize = 4096;
    const RECORD: usize = 104; // LFS header + 40-byte header + two aligned payloads.
    let lsns: Vec<_> = (0..specs.len())
        .map(|index| (1_u64 << 16) | ((4 * PAGE + 64 + index * RECORD) as u64 / 8))
        .collect();
    let mut restart = vec![0; PAGE];
    restart[..4].copy_from_slice(b"RSTR");
    restart[4..6].copy_from_slice(&32_u16.to_le_bytes());
    restart[6..8].copy_from_slice(&9_u16.to_le_bytes());
    restart[16..20].copy_from_slice(&(PAGE as u32).to_le_bytes());
    restart[20..24].copy_from_slice(&(PAGE as u32).to_le_bytes());
    restart[24..26].copy_from_slice(&64_u16.to_le_bytes());
    restart[26..28].copy_from_slice(&1_u16.to_le_bytes());
    restart[28..30].copy_from_slice(&1_u16.to_le_bytes());
    let area = &mut restart[64..288];
    area[..8].copy_from_slice(&lsns.last().unwrap().to_le_bytes());
    area[8..10].copy_from_slice(&1_u16.to_le_bytes());
    area[10..12].copy_from_slice(&u16::MAX.to_le_bytes());
    area[16..20].copy_from_slice(&48_u32.to_le_bytes());
    area[20..22].copy_from_slice(&224_u16.to_le_bytes());
    area[22..24].copy_from_slice(&64_u16.to_le_bytes());
    area[24..32].copy_from_slice(&(SIZE as u64).to_le_bytes());
    area[32..36].copy_from_slice(&56_u32.to_le_bytes());
    area[36..38].copy_from_slice(&48_u16.to_le_bytes());
    area[38..40].copy_from_slice(&64_u16.to_le_bytes());
    area[64..72].copy_from_slice(&lsns[0].to_le_bytes());
    area[80..82].copy_from_slice(&u16::MAX.to_le_bytes());
    area[82..84].copy_from_slice(&u16::MAX.to_le_bytes());
    area[84..86].copy_from_slice(&7_u16.to_le_bytes());
    area[92..96].copy_from_slice(&8_u32.to_le_bytes());
    area[96..104].copy_from_slice(b"N\0T\0F\0S\0");
    let mut log = vec![0; SIZE];
    log[..PAGE].copy_from_slice(&protect(restart.clone(), 32, 0xABCD));
    log[PAGE..2 * PAGE].copy_from_slice(&protect(restart, 32, 0xBCDE));
    let mut page = vec![0; PAGE];
    page[..4].copy_from_slice(b"RCRD");
    page[4..6].copy_from_slice(&40_u16.to_le_bytes());
    page[6..8].copy_from_slice(&9_u16.to_le_bytes());
    page[8..16].copy_from_slice(&lsns.last().unwrap().to_le_bytes());
    page[16..20].copy_from_slice(&1_u32.to_le_bytes());
    page[20..22].copy_from_slice(&1_u16.to_le_bytes());
    page[22..24].copy_from_slice(&1_u16.to_le_bytes());
    page[24..26].copy_from_slice(&u16::try_from(64 + specs.len() * RECORD).unwrap().to_le_bytes());
    page[32..40].copy_from_slice(&lsns.last().unwrap().to_le_bytes());
    for (index, &(redo, undo, id, previous, next)) in specs.iter().enumerate() {
        let at = 64 + index * RECORD;
        page[at..at + 8].copy_from_slice(&lsns[index].to_le_bytes());
        for (offset, link) in [(8, previous), (16, next)] {
            page[at + offset..at + offset + 8]
                .copy_from_slice(&link.map_or(0, |index| lsns[index]).to_le_bytes());
        }
        page[at + 24..at + 28].copy_from_slice(&56_u32.to_le_bytes());
        page[at + 28..at + 30].copy_from_slice(&7_u16.to_le_bytes());
        page[at + 32..at + 36].copy_from_slice(&1_u32.to_le_bytes());
        page[at + 36..at + 40].copy_from_slice(&id.to_le_bytes());
        let payload = &mut page[at + 48..at + RECORD];
        payload[..2].copy_from_slice(&redo.to_le_bytes());
        payload[2..4].copy_from_slice(&undo.to_le_bytes());
        if redo == 0x07 {
            payload[4..6].copy_from_slice(&40_u16.to_le_bytes());
            payload[6..8].copy_from_slice(&4_u16.to_le_bytes());
            payload[8..10].copy_from_slice(&48_u16.to_le_bytes());
            payload[10..12].copy_from_slice(&4_u16.to_le_bytes());
            payload[12..14].copy_from_slice(&24_u16.to_le_bytes());
            payload[14..16].copy_from_slice(&1_u16.to_le_bytes());
            payload[16..18].copy_from_slice(&64_u16.to_le_bytes());
            payload[18..20].copy_from_slice(&24_u16.to_le_bytes());
            payload[32..40].copy_from_slice(&100_u64.to_le_bytes());
            payload[40..44].fill(u8::try_from(index).unwrap());
            payload[48..52].fill(100 + u8::try_from(index).unwrap());
        }
    }
    log[4 * PAGE..5 * PAGE].copy_from_slice(&protect(page, 40, 0xCDEF));
    log
}

#[test]
fn native_wire_commit_is_not_undone_and_open_attribute_is_not_forget() {
    let log = wire_log(&[(7, 7, 24, None, None), (0x1A, 0, 24, Some(0), Some(0))]);
    let before = log.clone();
    let plan = parse_ntfs_logfile(&log).unwrap();
    assert_eq!(plan.committed_transactions, [24]);
    assert_eq!(plan.redo_actions.len(), 1);
    assert!(plan.undo_actions.is_empty());
    assert_eq!(log, before);
    let unsupported = wire_log(&[(7, 7, 24, None, None), (0x1C, 0, 24, Some(0), Some(0))]);
    assert!(parse_ntfs_logfile(&unsupported).is_err());
}

#[test]
fn native_wire_compensation_and_slot_reuse_select_exact_undo_payloads() {
    let log = wire_log(&[
        (7, 7, 24, None, None),
        (0x1A, 0, 24, Some(0), Some(0)),
        (0x1B, 0, 24, Some(1), None),
        (7, 7, 24, None, None),
        (7, 7, 24, Some(3), Some(3)),
        (7, 1, 24, Some(4), Some(3)),
    ]);
    let plan = parse_ntfs_logfile(&log).unwrap();
    assert_eq!(plan.redo_actions.len(), 4, "redo retains the CLR");
    assert_eq!(plan.undo_actions.len(), 1);
    assert_eq!(plan.undo_actions[0].data, [103; 4]);
    assert_eq!(plan.committed_transactions, [24]);
    assert_eq!(plan.aborted_transactions, [24]);
}

#[test]
fn conflicting_duplicate_lsns_are_not_resolved_by_physical_scan_order() {
    let mut log = wire_log(&[(7, 7, 24, None, None)]);
    log.copy_within(4 * 4096..5 * 4096, 5 * 4096);
    assert_eq!(parse_ntfs_logfile(&log).unwrap().records_parsed, 1);
    log[5 * 4096 + 64 + 48 + 40] ^= 1;
    assert!(parse_ntfs_logfile(&log).is_err());
}

#[test]
fn torn_pages_truncated_commits_and_unknown_records_cannot_be_silently_skipped() {
    let good = wire_log(&[(7, 7, 24, None, None), (0x1A, 0, 24, Some(0), Some(0))]);
    let page = 4 * 4096;
    let commit = page + 64 + 104;
    for mutation in 0..5 {
        let mut bad = good.clone();
        match mutation {
            0 => bad[page + 511] ^= 1,
            1 => bad[commit + 24..commit + 28].copy_from_slice(&4096_u32.to_le_bytes()),
            2 => bad[page + 24..page + 26].copy_from_slice(&5000_u16.to_le_bytes()),
            3 => bad[commit + 32..commit + 36].copy_from_slice(&99_u32.to_le_bytes()),
            _ => bad[commit + 40..commit + 42].copy_from_slice(&1_u16.to_le_bytes()),
        }
        let before = bad.clone();
        assert!(parse_ntfs_logfile(&bad).is_err(), "damaged journal case {mutation}");
        assert_eq!(bad, before);
    }
}
