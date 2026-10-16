use super::*;

fn resident(id: u16, value: &[u8]) -> Vec<u8> {
    let mut attr = vec![0; (24 + value.len()).next_multiple_of(8)];
    attr[..4].copy_from_slice(&0x80_u32.to_le_bytes());
    let size = u32::try_from(attr.len()).unwrap();
    attr[4..8].copy_from_slice(&size.to_le_bytes());
    attr[14..16].copy_from_slice(&id.to_le_bytes());
    attr[16..20].copy_from_slice(&u32::try_from(value.len()).unwrap().to_le_bytes());
    attr[20..22].copy_from_slice(&24_u16.to_le_bytes());
    attr[24..24 + value.len()].copy_from_slice(value);
    attr
}

fn image(attrs: &[Vec<u8>]) -> Vec<u8> {
    let mut raw = vec![0xD3; 1024];
    raw[..64].fill(0);
    raw[..4].copy_from_slice(b"FILE");
    raw[4..6].copy_from_slice(&48_u16.to_le_bytes());
    raw[6..8].copy_from_slice(&3_u16.to_le_bytes());
    raw[8..16].copy_from_slice(&10_u64.to_le_bytes());
    raw[16..18].copy_from_slice(&7_u16.to_le_bytes());
    raw[18..20].copy_from_slice(&2_u16.to_le_bytes());
    raw[20..22].copy_from_slice(&64_u16.to_le_bytes());
    raw[22..24].copy_from_slice(&1_u16.to_le_bytes());
    raw[28..32].copy_from_slice(&1024_u32.to_le_bytes());
    raw[40..42].copy_from_slice(&3_u16.to_le_bytes());
    raw[44..48].copy_from_slice(&42_u32.to_le_bytes());
    let mut at = 64;
    for attr in attrs {
        raw[at..at + attr.len()].copy_from_slice(attr);
        at += attr.len();
    }
    raw[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    raw[at + 4..at + 8].fill(0);
    raw[24..28].copy_from_slice(&u32::try_from(at + 8).unwrap().to_le_bytes());
    // Independent fixture encoding, including nonzero bytes at both trailers.
    let token = 0xCAFE_u16.to_le_bytes();
    raw[48..50].copy_from_slice(&token);
    for sector in 1..=2 {
        let end = sector * 512;
        let saved = [raw[end - 2], raw[end - 1]];
        raw[48 + sector * 2..50 + sector * 2].copy_from_slice(&saved);
        raw[end - 2..end].copy_from_slice(&token);
    }
    raw
}

fn apply(raw: &[u8], pass: RecoveryPass, operation: FileOperation, at: u16, relative: u16, data: &[u8]) -> Vec<u8> {
    match apply_file_edit(raw, 42, pass, &FileEdit {
        operation, record_offset: at, attribute_offset: relative, data,
    }).unwrap() {
        FileEditResult::Applied(result) => result,
        FileEditResult::AlreadyApplied => panic!("fixture edit unexpectedly skipped"),
    }
}

fn values(raw: &[u8]) -> Vec<Vec<u8>> {
    let record = NtfsFileRecord::parse(raw).unwrap();
    record.attributes().unwrap().into_iter().map(|attr| {
        let NtfsValue::Resident(data) = attr.value else { panic!("expected resident") };
        data.to_vec()
    }).collect()
}

#[test]
fn resident_redo_and_undo_preserve_neighbors_and_do_not_mutate_input() {
    let raw = image(&[resident(1, b"original"), resident(2, b"neighbor")]);
    let before = raw.clone();
    let redone = apply(&raw, RecoveryPass::Redo(20), FileOperation::UpdateResident { resize: false }, 64, 26, b"XX");
    assert_eq!(values(&redone), [b"orXXinal".to_vec(), b"neighbor".to_vec()]);
    assert_eq!(le64(&redone, 8).unwrap(), 20);
    let undone = apply(&redone, RecoveryPass::Undo, FileOperation::UpdateResident { resize: false }, 64, 26, b"ig");
    assert_eq!(values(&undone), [b"original".to_vec(), b"neighbor".to_vec()]);
    assert_eq!(le64(&undone, 8).unwrap(), 20, "undo must not invent a durable CLR");
    assert_eq!(raw, before);
}

#[test]
fn redo_skips_equal_and_newer_lsns_but_still_checks_identity_and_fixups() {
    let raw = image(&[resident(1, b"old")]);
    let edit = FileEdit { operation: FileOperation::DeleteAttribute,
        record_offset: u16::MAX, attribute_offset: 0, data: &[] };
    for lsn in [1, 10] {
        assert_eq!(apply_file_edit(&raw, 42, RecoveryPass::Redo(lsn), &edit).unwrap(), FileEditResult::AlreadyApplied);
    }
    assert!(apply_file_edit(&raw, 41, RecoveryPass::Redo(1), &edit).is_err());
    assert!(apply_file_edit(&raw, 42, RecoveryPass::Redo(0), &edit).is_err());
    let mut torn = raw;
    torn[1023] ^= 1;
    assert!(apply_file_edit(&torn, 42, RecoveryPass::Redo(1), &edit).is_err());
}

#[test]
fn resident_growth_crosses_protected_sectors_without_exposing_slack() {
    let raw = image(&[resident(1, b"original"), resident(2, b"neighbor")]);
    let value: Vec<_> = (0..601).map(|index| u8::try_from(index % 251).unwrap()).collect();
    let result = apply(&raw, RecoveryPass::Redo(20), FileOperation::UpdateResident { resize: true }, 64, 24, &value);
    assert_eq!(values(&result), [value, b"neighbor".to_vec()]);
    let restored = restore_record(&result, b"FILE").unwrap();
    assert_eq!(&restored[64 + 625..64 + 632], &[0; 7]);
    assert_eq!(le32(&result, 24).unwrap(), 736);
    assert_eq!(le16(&result, 510).unwrap(), le16(&result, 48).unwrap());
    assert_eq!(le16(&result, 1022).unwrap(), le16(&result, 48).unwrap());
    assert_ne!(le16(&result, 48).unwrap(), le16(&raw, 48).unwrap());
}

#[test]
fn shrink_to_empty_and_undo_relocate_following_attributes_exactly() {
    let raw = image(&[resident(1, b"original"), resident(2, b"neighbor")]);
    let short = apply(&raw, RecoveryPass::Redo(20), FileOperation::UpdateResident { resize: true }, 64, 24, &[]);
    assert_eq!(values(&short), [Vec::<u8>::new(), b"neighbor".to_vec()]);
    assert_eq!(le32(&short, 24).unwrap(), 128);
    let restored = apply(&short, RecoveryPass::Undo, FileOperation::UpdateResident { resize: true }, 64, 24, b"original");
    assert_eq!(values(&restored), values(&raw));
    assert_eq!(le32(&restored, 24).unwrap(), le32(&raw, 24).unwrap());
}

#[test]
fn creation_and_deletion_update_instances_and_indexed_link_counts() {
    let raw = image(&[resident(1, b"left"), resident(2, b"right")]);
    let mut name = resident(9, &[0; 66]);
    name[..4].copy_from_slice(&0x30_u32.to_le_bytes());
    name[22..24].copy_from_slice(&1_u16.to_le_bytes());
    let created = apply(&raw, RecoveryPass::Redo(20), FileOperation::CreateAttribute, 96, 0, &name);
    assert_eq!(le16(&created, 18).unwrap(), 3);
    assert_eq!(le16(&created, 40).unwrap(), 10);
    assert_eq!(values(&created), [b"left".to_vec(), vec![0; 66], b"right".to_vec()]);
    let removed = apply(&created, RecoveryPass::Undo, FileOperation::DeleteAttribute, 96, 0, &[]);
    assert_eq!(values(&removed), values(&raw));
    assert_eq!(le16(&removed, 18).unwrap(), 2);
    assert_eq!(le16(&removed, 40).unwrap(), 10, "attribute IDs do not rewind");
}

#[test]
fn end_replacement_includes_the_native_terminator_and_preserves_prefix() {
    let raw = image(&[resident(1, b"keep"), resident(2, b"old")]);
    let mut tail = resident(2, b"new-tail");
    tail.extend_from_slice(&u32::MAX.to_le_bytes());
    tail.extend_from_slice(&[0; 4]);
    let result = apply(&raw, RecoveryPass::Redo(20), FileOperation::WriteEnd, 96, 0, &tail);
    assert_eq!(values(&result), [b"keep".to_vec(), b"new-tail".to_vec()]);
    let empty = apply(&result, RecoveryPass::Redo(30), FileOperation::WriteEnd, 96, 0, &u32::MAX.to_le_bytes());
    assert_eq!(values(&empty), [b"keep".to_vec()]);
    assert_eq!(le32(&empty, 24).unwrap(), 104);
}

#[test]
fn size_payload_uses_native_valid_before_data_order() {
    let mut attr = vec![0; 72];
    attr[..4].copy_from_slice(&0x80_u32.to_le_bytes());
    attr[4..8].copy_from_slice(&72_u32.to_le_bytes());
    attr[8] = 1;
    attr[14..16].copy_from_slice(&1_u16.to_le_bytes());
    attr[24..32].copy_from_slice(&1_u64.to_le_bytes());
    attr[32..34].copy_from_slice(&64_u16.to_le_bytes());
    attr[40..48].copy_from_slice(&1024_u64.to_le_bytes());
    attr[48..56].copy_from_slice(&600_u64.to_le_bytes());
    attr[56..64].copy_from_slice(&512_u64.to_le_bytes());
    attr[64..68].copy_from_slice(&[0x11, 2, 16, 0]);
    let raw = image(&[attr]);
    let payload: Vec<_> = [2048_u64, 900, 1000].into_iter().flat_map(u64::to_le_bytes).collect();
    let result = apply(&raw, RecoveryPass::Redo(20), FileOperation::SetSizes, 64, 0, &payload);
    assert_eq!(le64(&result, 104).unwrap(), 2048);
    assert_eq!(le64(&result, 112).unwrap(), 1000);
    assert_eq!(le64(&result, 120).unwrap(), 900);
    assert_eq!(&result[128..132], &[0x11, 2, 16, 0]);
    let bad: Vec<_> = [2048_u64, 1001, 1000].into_iter().flat_map(u64::to_le_bytes).collect();
    assert!(apply_file_edit(&raw, 42, RecoveryPass::Redo(20), &FileEdit {
        operation: FileOperation::SetSizes, record_offset: 64, attribute_offset: 0, data: &bad,
    }).is_err());
}

#[test]
fn late_invalid_edits_never_publish_partially_modified_records() {
    let raw = image(&[resident(1, b"keep"), resident(2, b"next")]);
    let duplicate = resident(1, b"duplicate");
    let large = vec![7; 1024];
    let edits = [
        FileEdit { operation: FileOperation::CreateAttribute, record_offset: 96, attribute_offset: 0, data: &duplicate },
        FileEdit { operation: FileOperation::WriteEnd, record_offset: 96, attribute_offset: 0, data: b"not-an-attribute" },
        FileEdit { operation: FileOperation::UpdateResident { resize: true }, record_offset: 64, attribute_offset: 24, data: &large },
        FileEdit { operation: FileOperation::UpdateResident { resize: true }, record_offset: 64, attribute_offset: 29, data: b"gap" },
        FileEdit { operation: FileOperation::UpdateResident { resize: false }, record_offset: 64, attribute_offset: 20, data: b"header" },
        FileEdit { operation: FileOperation::DeleteAttribute, record_offset: 88, attribute_offset: 0, data: &[] },
    ];
    for edit in edits {
        let before = raw.clone();
        assert!(apply_file_edit(&raw, 42, RecoveryPass::Redo(20), &edit).is_err());
        assert_eq!(raw, before);
    }
}

#[test]
fn every_truncation_and_sector_tear_is_rejected_before_edits() {
    let raw = image(&[resident(1, b"value")]);
    let edit = FileEdit { operation: FileOperation::UpdateResident { resize: false },
        record_offset: 64, attribute_offset: 24, data: b"new!!" };
    for len in 0..raw.len() {
        assert!(apply_file_edit(&raw[..len], 42, RecoveryPass::Redo(20), &edit).is_err());
    }
    for end in [512, 1024] {
        let mut bad = raw.clone();
        bad[end - 1] ^= 1;
        let before = bad.clone();
        assert!(apply_file_edit(&bad, 42, RecoveryPass::Redo(20), &edit).is_err());
        assert_eq!(bad, before);
    }
}

#[test]
fn repeated_resident_redo_is_idempotent_and_sequence_token_rollover_is_valid() {
    let raw = image(&[resident(1, b"old")]);
    let mut restored = restore_record(&raw, b"FILE").unwrap();
    restored[48..50].copy_from_slice(&(u16::MAX - 1).to_le_bytes());
    protect(&mut restored).unwrap();
    assert_eq!(le16(&restored, 48).unwrap(), 1);
    let edit = FileEdit { operation: FileOperation::UpdateResident { resize: false },
        record_offset: 64, attribute_offset: 24, data: b"new" };
    let FileEditResult::Applied(result) = apply_file_edit(&restored, 42, RecoveryPass::Redo(20), &edit).unwrap() else {
        panic!("expected edit");
    };
    assert_eq!(values(&result), [b"new".to_vec()]);
    assert_eq!(apply_file_edit(&result, 42, RecoveryPass::Redo(20), &edit).unwrap(), FileEditResult::AlreadyApplied);
}
