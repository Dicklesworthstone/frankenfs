use super::*;
use crate::ntfs::recovery::{FileEdit, FileEditResult, FileOperation, RecoveryPass, apply_file_edit};
use crate::ntfs::{NtfsFileRecord, NtfsRun, restore_record};

fn nonresident(pairs: &[u8], first: u64, highest: u64, flags: u16, name: &[u16]) -> Vec<u8> {
    let header = if flags & (SPARSE | COMPRESSED) == 0 {
        64
    } else {
        72
    };
    let mapping = (header + name.len() * 2).next_multiple_of(8);
    let mut attr = vec![0; (mapping + pairs.len()).next_multiple_of(8)];
    attr[..4].copy_from_slice(&0x80_u32.to_le_bytes());
    let length = u32::try_from(attr.len()).unwrap();
    attr[4..8].copy_from_slice(&length.to_le_bytes());
    attr[8] = 1;
    attr[9] = u8::try_from(name.len()).unwrap();
    attr[10..12].copy_from_slice(&u16::try_from(header).unwrap().to_le_bytes());
    attr[12..14].copy_from_slice(&flags.to_le_bytes());
    attr[14..16].copy_from_slice(&1_u16.to_le_bytes());
    attr[16..24].copy_from_slice(&first.to_le_bytes());
    attr[24..32].copy_from_slice(&highest.to_le_bytes());
    attr[32..34].copy_from_slice(&u16::try_from(mapping).unwrap().to_le_bytes());
    if flags & COMPRESSED != 0 {
        attr[34..36].copy_from_slice(&4_u16.to_le_bytes());
    }
    // Size updates are separate log operations; mapping edits must not change
    // any of these fields even when the transient coverage differs from EOF.
    attr[40..48].copy_from_slice(&8192_u64.to_le_bytes());
    attr[48..56].copy_from_slice(&3000_u64.to_le_bytes());
    attr[56..64].copy_from_slice(&2000_u64.to_le_bytes());
    if header == 72 {
        attr[64..72].copy_from_slice(&4096_u64.to_le_bytes());
    }
    for (index, unit) in name.iter().enumerate() {
        attr[header + 2 * index..header + 2 * index + 2].copy_from_slice(&unit.to_le_bytes());
    }
    attr[mapping..mapping + pairs.len()].copy_from_slice(pairs);
    attr
}

fn image(attr: &[u8]) -> Vec<u8> {
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
    raw[64..64 + attr.len()].copy_from_slice(attr);
    let at = 64 + attr.len();
    let mut neighbor = [0; 32];
    neighbor[..4].copy_from_slice(&0x80_u32.to_le_bytes());
    neighbor[4..8].copy_from_slice(&32_u32.to_le_bytes());
    neighbor[14..16].copy_from_slice(&2_u16.to_le_bytes());
    neighbor[16..20].copy_from_slice(&8_u32.to_le_bytes());
    neighbor[20..22].copy_from_slice(&24_u16.to_le_bytes());
    neighbor[24..32].copy_from_slice(b"neighbor");
    raw[at..at + 32].copy_from_slice(&neighbor);
    raw[at + 32..at + 36].copy_from_slice(&u32::MAX.to_le_bytes());
    raw[at + 36..at + 40].fill(0);
    raw[24..28].copy_from_slice(&u32::try_from(at + 40).unwrap().to_le_bytes());
    let token = 0xCAFE_u16.to_le_bytes();
    raw[48..50].copy_from_slice(&token);
    for sector in 1..=2 {
        let end = sector * 512;
        let saved = [raw[end - 2], raw[end - 1]];
        raw[48 + 2 * sector..50 + 2 * sector].copy_from_slice(&saved);
        raw[end - 2..end].copy_from_slice(&token);
    }
    raw
}

fn change(
    raw: &[u8],
    pass: RecoveryPass,
    relative: u16,
    payload: &[u8],
    bound: u64,
) -> Result<Vec<u8>, ParseError> {
    match apply_file_edit(
        raw,
        42,
        pass,
        &FileEdit {
            operation: FileOperation::UpdateMappingPairs {
                volume_clusters: bound,
            },
            record_offset: 64,
            attribute_offset: relative,
            data: payload,
        },
    )? {
        FileEditResult::Applied(raw) => Ok(raw),
        FileEditResult::AlreadyApplied => panic!("unexpected redo skip"),
    }
}

fn attributes(raw: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let data = restore_record(raw, b"FILE").unwrap();
    let size = usize::try_from(le32(&data, 68).unwrap()).unwrap();
    (data[64..64 + size].to_vec(), data[64 + size..96 + size].to_vec())
}

fn runs(raw: &[u8]) -> Vec<RunTuple> {
    let record = NtfsFileRecord::parse(raw).unwrap();
    let attrs = record.attributes().unwrap();
    let NtfsValue::NonResident(value) = &attrs[0].value else {
        panic!("nonresident required");
    };
    decode_mapping_pairs(value.mapping_pairs, value.first_vcn, value.last_vcn, 4096)
        .unwrap()
        .into_iter()
        .map(|NtfsRun { vcn, clusters, lcn }| (vcn, clusters, lcn))
        .collect()
}

type RunTuple = (u64, u64, Option<u64>);

#[test]
fn suffix_redo_and_undo_preserve_prefix_sizes_names_neighbors_and_identity() {
    let old = nonresident(&[0x11, 2, 100, 0x11, 2, 20, 0], 0, 3, 0, &[]);
    let raw = image(&old);
    let before = raw.clone();
    let suffix = [0x11, 1, 0xE2, 0x11, 1, 40, 0x11, 2, 30, 0];
    let result = change(&raw, RecoveryPass::Redo(20), 67, &suffix, 4096).unwrap();
    assert_eq!(
        runs(&result),
        [
            (0, 2, Some(100)),
            (2, 1, Some(70)),
            (3, 1, Some(110)),
            (4, 2, Some(140)),
        ]
    );
    let (attr, neighbor) = attributes(&result);
    assert_eq!(le32(&attr, 4).unwrap(), 80);
    assert_eq!(&attr[64..67], &old[64..67]);
    assert_eq!(&attr[40..64], &old[40..64]);
    assert_eq!(le32(&result, 24).unwrap(), le32(&raw, 24).unwrap() + 8);
    assert_eq!(neighbor, attributes(&raw).1);
    for (offset, length) in [(16, 8), (32, 16)] {
        assert_eq!(
            &result[offset..offset + length],
            &raw[offset..offset + length]
        );
    }
    let undone = change(&result, RecoveryPass::Undo, 67, &old[67..], 4096).unwrap();
    assert_eq!(attributes(&undone), attributes(&raw));
    assert_eq!(le32(&undone, 24).unwrap(), le32(&raw, 24).unwrap());
    assert_eq!(crate::ntfs::le64(&undone, 8).unwrap(), 20);
    assert_eq!(raw, before);
}

#[test]
fn byte_suffix_may_start_inside_a_pair_without_resetting_its_prefix() {
    let raw = image(&nonresident(&[0x11, 2, 100, 0], 0, 1, 0, &[]));
    let result = change(&raw, RecoveryPass::Redo(20), 66, &[70, 0], 4096).unwrap();
    assert_eq!(runs(&result), [(0, 2, Some(70))]);
}

#[test]
fn sparse_runs_preserve_the_previous_physical_delta_base() {
    let raw = image(&nonresident(&[0x11, 2, 100, 0], 0, 1, SPARSE, &[]));
    let pairs = [0x11, 2, 100, 0x01, 3, 0x11, 1, 0xEC, 0];
    let result = change(&raw, RecoveryPass::Redo(20), 72, &pairs, 4096).unwrap();
    assert_eq!(
        runs(&result),
        [(0, 2, Some(100)), (2, 3, None), (5, 1, Some(80))]
    );
    assert_eq!(&attributes(&result).0[40..72], &attributes(&raw).0[40..72]);
}

#[test]
fn named_compressed_continuations_keep_native_fields_and_absolute_first_lcn() {
    let name = [0xD800, 0x0061];
    let old = nonresident(&[0x11, 2, 100, 0], 32, 33, COMPRESSED, &name);
    let raw = image(&old);
    let result = change(
        &raw,
        RecoveryPass::Redo(20),
        80,
        &[0x11, 1, 50, 0x01, 15, 0],
        4096,
    )
    .unwrap();
    assert_eq!(runs(&result), [(32, 1, Some(50)), (33, 15, None)]);
    let (attr, _) = attributes(&result);
    assert_eq!(&attr[8..24], &old[8..24]);
    assert_eq!(&attr[32..80], &old[32..80]);
    assert_eq!(crate::ntfs::le64(&attr, 24).unwrap(), 47);
}

#[test]
fn empty_initial_mapping_is_native_minus_one_but_empty_continuations_fail() {
    let raw = image(&nonresident(&[0x11, 2, 100, 0], 0, 1, 0, &[]));
    let result = change(&raw, RecoveryPass::Redo(20), 64, &[0], 4096).unwrap();
    assert_eq!(runs(&result), Vec::<RunTuple>::new());
    assert_eq!(
        crate::ntfs::le64(&attributes(&result).0, 24).unwrap(),
        u64::MAX
    );
    assert_eq!(&attributes(&result).0[40..64], &attributes(&raw).0[40..64]);
    let continuation = image(&nonresident(&[0x11, 2, 100, 0], 8, 9, 0, &[]));
    assert!(change(&continuation, RecoveryPass::Redo(20), 64, &[0], 4096).is_err());
}

#[test]
fn growing_pairs_across_sector_trailers_regenerates_usa_without_losing_neighbors() {
    let raw = image(&nonresident(&[0x11, 1, 10, 0], 0, 0, 0, &[]));
    let mut pairs = vec![0x11, 1, 10];
    for _ in 1..140 {
        pairs.extend_from_slice(&[0x11, 1, 1]);
    }
    pairs.push(0);
    let result = change(&raw, RecoveryPass::Redo(20), 64, &pairs, 4096).unwrap();
    assert_eq!(runs(&result).len(), 140);
    assert_eq!(runs(&result).last(), Some(&(139, 1, Some(149))));
    let (attr, neighbor) = attributes(&result);
    assert_eq!(&attr[64..64 + pairs.len()], pairs.as_slice());
    assert_eq!(neighbor, attributes(&raw).1);
    assert_eq!(le16(&result, 510).unwrap(), le16(&result, 48).unwrap());
    assert_eq!(le16(&result, 1022).unwrap(), le16(&result, 48).unwrap());
    assert_eq!(attr[64 + pairs.len()..], [0; 3]);
}

#[test]
fn bad_suffixes_do_not_borrow_alignment_zeroes_or_touch_the_callers_record() {
    let raw = image(&nonresident(&[0x11, 2, 100, 0], 0, 1, 0, &[]));
    let before = raw.clone();
    for payload in [
        &[][..],
        &[0x11, 1, 10][..],
        &[0x10, 1, 0][..],
        &[0x19, 0][..],
        &[0x91, 1, 0][..],
        &[0x11, 0, 10, 0][..],
        &[0x21, 1, 10][..],
        &[0x11, 1, 0xFF, 0][..],
        &[0x01, 1, 0][..],
    ] {
        assert!(
            change(&raw, RecoveryPass::Redo(20), 64, payload, 4096).is_err(),
            "{payload:?}"
        );
        assert_eq!(raw, before);
    }
    for relative in [0, 16, 32, 63, 73, u16::MAX] {
        assert!(change(&raw, RecoveryPass::Redo(20), relative, &[0], 4096).is_err());
    }
    let mut huge = vec![0x11, 1, 10];
    for _ in 1..400 {
        huge.extend_from_slice(&[0x11, 1, 1]);
    }
    huge.push(0);
    assert!(change(&raw, RecoveryPass::Redo(20), 64, &huge, 4096).is_err());
    assert_eq!(raw, before);
}

#[test]
fn volume_edges_aliases_and_signed_vcn_overflows_are_checked() {
    let raw = image(&nonresident(&[0x11, 2, 100, 0], 0, 1, 0, &[]));
    assert!(change(&raw, RecoveryPass::Redo(20), 64, &[0x11, 2, 100, 0], 102).is_ok());
    for bound in [0, 101, u64::MAX] {
        assert!(change(&raw, RecoveryPass::Redo(20), 64, &[0x11, 2, 100, 0], bound).is_err());
    }
    assert!(
        change(
            &raw,
            RecoveryPass::Redo(20),
            64,
            &[0x11, 2, 100, 0x11, 1, 1, 0],
            4096,
        )
        .is_err()
    );
    let near_limit = image(&nonresident(
        &[0x11, 1, 10, 0],
        i64::MAX as u64,
        i64::MAX as u64,
        0,
        &[],
    ));
    assert!(change(&near_limit, RecoveryPass::Redo(20), 64, &[0x11, 2, 10, 0], 4096).is_err());
    let mut negative_length = vec![0x18];
    negative_length.extend_from_slice(&u64::MAX.to_le_bytes());
    negative_length.extend_from_slice(&[10, 0]);
    assert!(change(&raw, RecoveryPass::Redo(20), 64, &negative_length, 4096).is_err());
}

#[test]
fn replay_lsn_skip_still_checks_record_identity_and_every_protected_sector() {
    let raw = image(&nonresident(&[0x11, 2, 100, 0], 0, 1, 0, &[]));
    let operation = FileEdit {
        operation: FileOperation::UpdateMappingPairs {
            volume_clusters: 4096,
        },
        record_offset: u16::MAX,
        attribute_offset: u16::MAX,
        data: &[],
    };
    for lsn in [1, 10] {
        assert_eq!(
            apply_file_edit(&raw, 42, RecoveryPass::Redo(lsn), &operation).unwrap(),
            FileEditResult::AlreadyApplied
        );
    }
    assert!(apply_file_edit(&raw, 41, RecoveryPass::Redo(10), &operation).is_err());
    for trailer in [511, 1023] {
        let mut torn = raw.clone();
        torn[trailer] ^= 1;
        assert!(apply_file_edit(&torn, 42, RecoveryPass::Redo(10), &operation).is_err());
    }
}

#[test]
fn resident_targets_and_offsets_inside_attribute_bodies_are_not_mapping_edits() {
    let baseline = image(&nonresident(&[0x11, 2, 100, 0], 0, 1, 0, &[]));
    let mut resident = attributes(&baseline).1;
    resident[14..16].copy_from_slice(&1_u16.to_le_bytes());
    let raw = image(&resident);
    NtfsFileRecord::parse(&raw).unwrap();
    assert!(change(&raw, RecoveryPass::Redo(20), 24, &[0], 4096).is_err());
    let edit = FileEdit {
        operation: FileOperation::UpdateMappingPairs {
            volume_clusters: 4096,
        },
        record_offset: 72,
        attribute_offset: 64,
        data: &[0],
    };
    assert!(apply_file_edit(&baseline, 42, RecoveryPass::Redo(20), &edit).is_err());
}
