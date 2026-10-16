use super::*;
use super::super::{FileOperation, apply_file_edit};
use super::super::super::{NtfsFileRecord, index::NtfsIndexRoot};

const FILE_BYTES: usize = 1024;
const ATTR: usize = 56;
const VALUE: usize = 32;
const ENTRY: u16 = (VALUE + 32) as u16;

fn entry(name: &[u16], child: Option<u64>) -> Vec<u8> {
    let key_len = 66 + name.len() * 2;
    let length = (16 + key_len).next_multiple_of(8) + usize::from(child.is_some()) * 8;
    let mut bytes = vec![0; length];
    bytes[..8].copy_from_slice(&((7_u64 << 48) | 0x63).to_le_bytes());
    bytes[8..10].copy_from_slice(&(length as u16).to_le_bytes());
    bytes[10..12].copy_from_slice(&(key_len as u16).to_le_bytes());
    bytes[12..14].copy_from_slice(&u16::from(child.is_some()).to_le_bytes());
    bytes[16..24].copy_from_slice(&((3_u64 << 48) | 5).to_le_bytes());
    bytes[80] = name.len() as u8;
    bytes[81] = 1;
    for (i, unit) in name.iter().enumerate() {
        bytes[82 + 2 * i..84 + 2 * i].copy_from_slice(&unit.to_le_bytes());
    }
    if let Some(vcn) = child {
        bytes[length - 8..].copy_from_slice(&vcn.to_le_bytes());
    }
    bytes
}

fn terminal(child: Option<u64>) -> Vec<u8> {
    let length = if child.is_some() { 24 } else { 16 };
    let mut bytes = vec![0; length];
    bytes[8..10].copy_from_slice(&(length as u16).to_le_bytes());
    bytes[12..14].copy_from_slice(&(2 | u16::from(child.is_some())).to_le_bytes());
    if let Some(vcn) = child {
        bytes[length - 8..].copy_from_slice(&vcn.to_le_bytes());
    }
    bytes
}

fn file(keys: &[Vec<u8>], child: bool) -> Vec<u8> {
    let mut rows = keys.concat();
    rows.extend(terminal(child.then_some(17)));
    let mut root = vec![0; 32 + rows.len()];
    root[..4].copy_from_slice(&0x30_u32.to_le_bytes());
    root[4..8].copy_from_slice(&1_u32.to_le_bytes());
    root[8..12].copy_from_slice(&4096_u32.to_le_bytes());
    root[12] = 8;
    put32(&mut root, 16, 16).unwrap();
    put32(&mut root, 20, 16 + rows.len()).unwrap();
    put32(&mut root, 24, 16 + rows.len()).unwrap();
    root[28] = u8::from(child);
    root[32..].copy_from_slice(&rows);
    let size = VALUE + root.len();
    let used = ATTR + size + 32 + 8;
    assert!(used <= FILE_BYTES);
    let mut bytes = vec![0; FILE_BYTES];
    bytes[..4].copy_from_slice(b"FILE");
    bytes[4..6].copy_from_slice(&48_u16.to_le_bytes());
    bytes[6..8].copy_from_slice(&3_u16.to_le_bytes());
    bytes[8..16].copy_from_slice(&11_u64.to_le_bytes());
    bytes[16..18].copy_from_slice(&7_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&1_u16.to_le_bytes());
    bytes[20..22].copy_from_slice(&(ATTR as u16).to_le_bytes());
    bytes[22..24].copy_from_slice(&3_u16.to_le_bytes());
    put32(&mut bytes, 24, used).unwrap();
    put32(&mut bytes, 28, FILE_BYTES).unwrap();
    bytes[40..42].copy_from_slice(&10_u16.to_le_bytes());
    bytes[44..48].copy_from_slice(&42_u32.to_le_bytes());
    put32(&mut bytes, ATTR, 0x90).unwrap();
    put32(&mut bytes, ATTR + 4, size).unwrap();
    bytes[ATTR + 9] = 4;
    bytes[ATTR + 10..ATTR + 12].copy_from_slice(&24_u16.to_le_bytes());
    bytes[ATTR + 14..ATTR + 16].copy_from_slice(&4_u16.to_le_bytes());
    put32(&mut bytes, ATTR + 16, root.len()).unwrap();
    bytes[ATTR + 20..ATTR + 22].copy_from_slice(&(VALUE as u16).to_le_bytes());
    for (i, unit) in I30.iter().enumerate() {
        bytes[ATTR + 24 + i * 2..ATTR + 26 + i * 2].copy_from_slice(&unit.to_le_bytes());
    }
    bytes[ATTR + VALUE..ATTR + size].copy_from_slice(&root);
    let next = ATTR + size;
    put32(&mut bytes, next, 0x80).unwrap();
    put32(&mut bytes, next + 4, 32).unwrap();
    bytes[next + 14..next + 16].copy_from_slice(&9_u16.to_le_bytes());
    put32(&mut bytes, next + 16, 8).unwrap();
    bytes[next + 20..next + 22].copy_from_slice(&24_u16.to_le_bytes());
    bytes[next + 24..next + 32].copy_from_slice(b"neighbor");
    bytes[next + 32..next + 36].fill(0xFF);
    protect(&mut bytes).unwrap();
    NtfsFileRecord::parse(&bytes).unwrap();
    bytes
}

fn block(bytes: usize, keys: &[Vec<u8>], child: bool) -> (Vec<u8>, u16) {
    let count = bytes / 512 + 1;
    let first = (40 + count * 2).next_multiple_of(8);
    let mut rows = keys.concat();
    rows.extend(terminal(child.then_some(17)));
    assert!(first + rows.len() <= bytes);
    let mut raw = vec![0; bytes];
    raw[..4].copy_from_slice(b"INDX");
    raw[4..6].copy_from_slice(&40_u16.to_le_bytes());
    raw[6..8].copy_from_slice(&(count as u16).to_le_bytes());
    raw[8..16].copy_from_slice(&11_u64.to_le_bytes());
    raw[16..24].copy_from_slice(&27_u64.to_le_bytes());
    put32(&mut raw, 24, first - 24).unwrap();
    put32(&mut raw, 28, first + rows.len() - 24).unwrap();
    put32(&mut raw, 32, bytes - 24).unwrap();
    raw[36] = u8::from(child);
    raw[first..first + rows.len()].copy_from_slice(&rows);
    protect(&mut raw).unwrap();
    index::parse_index_block(&raw, 27).unwrap();
    (raw, first as u16)
}

fn applied(result: Result<FileEditResult, ParseError>) -> Vec<u8> {
    match result.unwrap() {
        FileEditResult::Applied(bytes) => bytes,
        FileEditResult::AlreadyApplied => panic!("expected a native byte edit"),
    }
}

fn root_edit(raw: &[u8], op: IndexOperation, offset: u16, data: &[u8], pass: RecoveryPass) -> Result<FileEditResult, ParseError> {
    apply_file_edit(raw, 42, pass, &FileEdit {
        operation: FileOperation::IndexRoot(op),
        record_offset: ATTR as u16, attribute_offset: offset, data,
    })
}

fn root_value(raw: &[u8]) -> Vec<u8> {
    let file = NtfsFileRecord::parse(raw).unwrap();
    let attrs = file.attributes().unwrap();
    let NtfsValue::Resident(value) = &attrs[0].value else { panic!("resident root") };
    value.to_vec()
}

#[test]
fn root_insert_delete_roundtrip_preserves_neighbor_and_native_identity() {
    let raw = file(&[entry(&[65], None)], false);
    let original = raw.clone();
    let added = entry(&[0xD800, 66], None);
    let grown = applied(root_edit(&raw, IndexOperation::AddEntry, ENTRY, &added, RecoveryPass::Redo(20)));
    let parsed = NtfsIndexRoot::parse(&root_value(&grown), 512).unwrap();
    assert_eq!(parsed.entries.len(), 3);
    assert_eq!(parsed.entries[0].key.as_ref().unwrap().1.name, vec![0xD800, 66]);
    let after = NtfsFileRecord::parse(&grown).unwrap();
    assert_eq!((after.number, after.sequence, after.hard_links), (42, 7, 1));
    let attrs = after.attributes().unwrap();
    assert!(matches!(&attrs[1].value, NtfsValue::Resident(value) if *value == b"neighbor"));
    let undone = applied(root_edit(&grown, IndexOperation::DeleteEntry, ENTRY, &[], RecoveryPass::Undo));
    assert_eq!(root_value(&undone), root_value(&raw));
    assert_eq!(le64(&undone, 8).unwrap(), 20);
    assert_eq!(raw, original);
}

#[test]
fn root_growth_across_sector_trailers_rebuilds_every_saved_word() {
    let raw = file(&[entry(&[65], None)], false);
    let added = entry(&vec![0x1234; 220], None);
    let grown = applied(root_edit(&raw, IndexOperation::AddEntry, ENTRY, &added, RecoveryPass::Redo(21)));
    let parsed = NtfsIndexRoot::parse(&root_value(&grown), 512).unwrap();
    assert_eq!(parsed.entries[0].key.as_ref().unwrap().1.name, vec![0x1234; 220]);
    for sector in 1..=FILE_BYTES / 512 {
        let mut bad = grown.clone();
        bad[sector * 512 - 1] ^= 1;
        assert!(root_edit(&bad, IndexOperation::DeleteEntry, ENTRY, &[], RecoveryPass::Redo(21)).is_err());
    }
}

#[test]
fn root_offsets_types_and_capacity_fail_without_changing_source() {
    let raw = file(&[entry(&vec![65; 240], None)], false);
    let original = raw.clone();
    let added = entry(&vec![66; 255], None);
    assert!(root_edit(&raw, IndexOperation::AddEntry, ENTRY, &added, RecoveryPass::Redo(20)).is_err());
    for at in [0, ENTRY - 8, ENTRY + 8, ENTRY + 16, u16::MAX] {
        assert!(root_edit(&raw, IndexOperation::DeleteEntry, at, &[], RecoveryPass::Redo(20)).is_err());
    }
    let mut wrong = restore_record(&raw, b"FILE").unwrap();
    wrong[ATTR + 24] = b'X';
    protect(&mut wrong).unwrap();
    assert!(root_edit(&wrong, IndexOperation::DeleteEntry, ENTRY, &[], RecoveryPass::Redo(20)).is_err());
    assert_eq!(raw, original);
}

#[test]
fn root_redo_skip_ignores_obsolete_entry_offsets_but_not_file_identity() {
    let raw = file(&[entry(&[65], None)], false);
    assert_eq!(root_edit(&raw, IndexOperation::DeleteEntry, u16::MAX, &[], RecoveryPass::Redo(11)).unwrap(), FileEditResult::AlreadyApplied);
    let edit = FileEdit { operation: FileOperation::IndexRoot(IndexOperation::DeleteEntry),
        record_offset: ATTR as u16, attribute_offset: ENTRY, data: &[] };
    assert!(apply_file_edit(&raw, 43, RecoveryPass::Redo(10), &edit).is_err());
    assert!(root_edit(&raw, IndexOperation::DeleteEntry, ENTRY, &[], RecoveryPass::Redo(0)).is_err());
}

#[test]
fn root_and_external_nodes_preserve_rightmost_children() {
    let row = entry(&[65], Some(3));
    let raw = file(std::slice::from_ref(&row), true);
    for at in [ENTRY, ENTRY + row.len() as u16] {
        let changed = applied(root_edit(&raw, IndexOperation::SetChild, at, &91_u64.to_le_bytes(), RecoveryPass::Redo(20)));
        let parsed = NtfsIndexRoot::parse(&root_value(&changed), 512).unwrap();
        let index = usize::from(at != ENTRY);
        assert_eq!(parsed.entries[index].child_vcn, Some(91));
    }
    let (raw, first) = block(1024, std::slice::from_ref(&row), true);
    let changed = applied(apply_index_edit(&raw, 27, RecoveryPass::Redo(20), &IndexEdit {
        operation: IndexOperation::SetChild, entry_offset: first + row.len() as u16,
        data: &91_u64.to_le_bytes(),
    }));
    assert_eq!(index::parse_index_block(&changed, 27).unwrap()[1].child_vcn, Some(91));
}

#[test]
fn duplicated_file_information_does_not_change_names_references_or_children() {
    let row = entry(&[65, 0xD800], Some(3));
    let payload = [0x5A; DUPLICATED_INFORMATION];
    let raw = file(std::slice::from_ref(&row), true);
    let changed = applied(root_edit(&raw, IndexOperation::UpdateFileName, ENTRY, &payload, RecoveryPass::Redo(20)));
    let root = root_value(&changed);
    assert_eq!(&root[32..56], &row[..24]);
    assert_eq!(&root[56..112], &payload);
    assert_eq!(&root[112..32 + row.len()], &row[80..]);
    let (raw, first) = block(1024, &[row], true);
    let changed = applied(apply_index_edit(&raw, 27, RecoveryPass::Redo(20), &IndexEdit {
        operation: IndexOperation::UpdateFileName, entry_offset: first, data: &payload,
    }));
    let parsed = index::parse_index_block(&changed, 27).unwrap();
    assert_eq!(parsed[0].key.as_ref().unwrap().1.name, vec![65, 0xD800]);
    assert_eq!(parsed[0].child_vcn, Some(3));
}

#[test]
fn external_insert_delete_preserves_capacity_and_is_idempotent() {
    for bytes in [512, 1024, 4096, 65_536] {
        let row = entry(&[65], None);
        let (raw, first) = block(bytes, &[row], false);
        let addition = entry(&[66], None);
        let edit = IndexEdit { operation: IndexOperation::AddEntry, entry_offset: first, data: &addition };
        let grown = applied(apply_index_edit(&raw, 27, RecoveryPass::Redo(20), &edit));
        assert_eq!(grown.len(), bytes);
        assert_eq!(le32(&grown, 32).unwrap(), le32(&raw, 32).unwrap());
        assert_eq!(apply_index_edit(&grown, 27, RecoveryPass::Redo(20), &edit).unwrap(), FileEditResult::AlreadyApplied);
        let undone = applied(apply_index_edit(&grown, 27, RecoveryPass::Undo, &IndexEdit {
            operation: IndexOperation::DeleteEntry, entry_offset: first, data: &[],
        }));
        let before = restore_record(&raw, b"INDX").unwrap();
        let after = restore_record(&undone, b"INDX").unwrap();
        assert_eq!(&before[usize::from(first)..], &after[usize::from(first)..]);
        assert_eq!(le64(&undone, 8).unwrap(), 20);
    }
}

#[test]
fn external_write_end_replaces_complete_suffix_and_zeroes_retired_bytes() {
    let a = entry(&[65], None);
    let b = entry(&[66], None);
    let (raw, first) = block(1024, &[a.clone(), b], false);
    let offset = first + a.len() as u16;
    let suffix = terminal(None);
    let changed = applied(apply_index_edit(&raw, 27, RecoveryPass::Redo(20), &IndexEdit {
        operation: IndexOperation::WriteEnd, entry_offset: offset, data: &suffix,
    }));
    assert_eq!(index::parse_index_block(&changed, 27).unwrap().len(), 2);
    let restored = restore_record(&changed, b"INDX").unwrap();
    let end = usize::from(offset) + suffix.len();
    let old_end = 24 + le32(&raw, 28).unwrap() as usize;
    assert!(restored[end..old_end].iter().all(|byte| *byte == 0));
    assert_eq!(le32(&changed, 32).unwrap(), le32(&raw, 32).unwrap());
}

#[test]
fn no_terminal_deletion_childless_pointer_write_or_short_metadata_payload() {
    let row = entry(&[65], None);
    let raw = file(std::slice::from_ref(&row), false);
    let terminator = ENTRY + row.len() as u16;
    for (operation, at, payload) in [
        (IndexOperation::DeleteEntry, terminator, Vec::new()),
        (IndexOperation::AddEntry, ENTRY, terminal(None)),
        (IndexOperation::SetChild, ENTRY, vec![0; 8]),
        (IndexOperation::UpdateFileName, ENTRY, vec![0; 55]),
        (IndexOperation::UpdateFileName, terminator, vec![0; 56]),
        (IndexOperation::WriteEnd, ENTRY, terminal(None)),
    ] {
        assert!(root_edit(&raw, operation, at, &payload, RecoveryPass::Redo(20)).is_err());
    }
}

#[test]
fn corrupt_inserted_key_and_malformed_suffix_never_escape_private_copy() {
    let (raw, first) = block(1024, &[entry(&[65], None)], false);
    let original = raw.clone();
    let mut bad = entry(&[66], None);
    bad[81] = 4;
    assert!(apply_index_edit(&raw, 27, RecoveryPass::Redo(20), &IndexEdit {
        operation: IndexOperation::AddEntry, entry_offset: first, data: &bad,
    }).is_err());
    let no_terminal = entry(&[66], None);
    assert!(apply_index_edit(&raw, 27, RecoveryPass::Redo(20), &IndexEdit {
        operation: IndexOperation::WriteEnd, entry_offset: first, data: &no_terminal,
    }).is_err());
    assert_eq!(raw, original);
}

#[test]
fn external_buffer_identity_capacity_and_all_sector_fixups_are_required() {
    let (raw, first) = block(1024, &[entry(&vec![65; 240], None)], false);
    let addition = entry(&vec![66; 240], None);
    let edit = IndexEdit { operation: IndexOperation::AddEntry, entry_offset: first, data: &addition };
    assert!(apply_index_edit(&raw, 27, RecoveryPass::Redo(20), &edit).is_err());
    assert!(apply_index_edit(&raw, 28, RecoveryPass::Redo(11), &edit).is_err());
    for sector in 1..=raw.len() / 512 {
        let mut bad = raw.clone();
        bad[sector * 512 - 1] ^= 1;
        assert!(apply_index_edit(&bad, 27, RecoveryPass::Redo(11), &edit).is_err());
    }
    for length in [0, 1, 511, 1023] {
        assert!(apply_index_edit(&raw[..length], 27, RecoveryPass::Redo(11), &edit).is_err());
    }
}
