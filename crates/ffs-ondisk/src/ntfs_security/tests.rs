use super::*;

const DESCRIPTOR: [u8; 96] = [
    1, 0, 4, 128, 20, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 48, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0,
    0, 0, 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0, 2, 0, 48, 0, 2, 0, 0, 0, 1, 18, 20, 0,
    2, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 3, 20, 0, 255, 1, 31, 0, 1, 1, 0, 0, 0, 0,
    0, 5, 18, 0, 0, 0,
];
const DESCRIPTOR_HASH: u32 = 0xF1C7_5D8C;

fn header(id: u32, offset: u64) -> [u8; 20] {
    let mut value = [0; 20];
    value[..4].copy_from_slice(&DESCRIPTOR_HASH.to_le_bytes());
    value[4..8].copy_from_slice(&id.to_le_bytes());
    value[8..16].copy_from_slice(&offset.to_le_bytes());
    value[16..20].copy_from_slice(&116_u32.to_le_bytes());
    value
}

fn entry(id: u32, offset: u64, child: Option<u64>) -> Vec<u8> {
    let length = if child.is_some() { 48 } else { 40 };
    let mut value = vec![0; length];
    value[..2].copy_from_slice(&20_u16.to_le_bytes());
    value[2..4].copy_from_slice(&20_u16.to_le_bytes());
    value[8..10].copy_from_slice(&(length as u16).to_le_bytes());
    value[10..12].copy_from_slice(&4_u16.to_le_bytes());
    value[12..14].copy_from_slice(&u16::from(child.is_some()).to_le_bytes());
    value[16..20].copy_from_slice(&id.to_le_bytes());
    value[20..40].copy_from_slice(&header(id, offset));
    if let Some(child) = child {
        value[40..48].copy_from_slice(&child.to_le_bytes());
    }
    value
}

fn terminal(child: Option<u64>) -> Vec<u8> {
    let length = if child.is_some() { 24 } else { 16 };
    let mut value = vec![0; length];
    value[8..10].copy_from_slice(&(length as u16).to_le_bytes());
    value[12..14].copy_from_slice(&(2 | u16::from(child.is_some())).to_le_bytes());
    if let Some(child) = child {
        value[16..24].copy_from_slice(&child.to_le_bytes());
    }
    value
}

fn root(entries: &[Vec<u8>], internal: bool) -> Vec<u8> {
    let mut value = vec![0; 32];
    value[4..8].copy_from_slice(&16_u32.to_le_bytes());
    value[8..12].copy_from_slice(&4096_u32.to_le_bytes());
    value[12] = 8;
    value[16..20].copy_from_slice(&16_u32.to_le_bytes());
    value[28] = u8::from(internal);
    for entry in entries {
        value.extend_from_slice(entry);
    }
    let used = (value.len() - 16) as u32;
    value[20..24].copy_from_slice(&used.to_le_bytes());
    value[24..28].copy_from_slice(&used.to_le_bytes());
    value
}

fn block(vcn: u64, entries: &[Vec<u8>]) -> Vec<u8> {
    let mut value = vec![0; 4096];
    value[..4].copy_from_slice(b"INDX");
    value[4..6].copy_from_slice(&40_u16.to_le_bytes());
    value[6..8].copy_from_slice(&9_u16.to_le_bytes());
    value[16..24].copy_from_slice(&vcn.to_le_bytes());
    value[24..28].copy_from_slice(&40_u32.to_le_bytes());
    value[32..36].copy_from_slice(&4072_u32.to_le_bytes());
    let mut at = 64;
    for entry in entries {
        value[at..at + entry.len()].copy_from_slice(entry);
        at += entry.len();
    }
    value[28..32].copy_from_slice(&((at - 24) as u32).to_le_bytes());
    value[40..42].copy_from_slice(&0x1234_u16.to_le_bytes());
    for sector in 1..=8 {
        let tail = sector * 512 - 2;
        let original = [value[tail], value[tail + 1]];
        value[40 + sector * 2..42 + sector * 2].copy_from_slice(&original);
        value[tail..tail + 2].copy_from_slice(&0x1234_u16.to_le_bytes());
    }
    value
}

#[test]
fn native_descriptor_preserves_owner_group_acl_and_hash() {
    let descriptor = NtfsSecurityDescriptor::parse(&DESCRIPTOR).unwrap();
    assert_eq!(descriptor.owner.unwrap().to_string(), "S-1-5-18");
    assert_eq!(descriptor.group.unwrap().to_string(), "S-1-5-32-544");
    assert_eq!(descriptor.control, 0x8004);
    assert!(!descriptor.sacl.present);
    assert_eq!(descriptor.dacl.offset, 48);
    assert_eq!(descriptor.dacl.ace_count, Some(2));
    assert_eq!(security_hash(&DESCRIPTOR), DESCRIPTOR_HASH);
    // Native hashing consumes complete DWORDs, not padded partial words.
    assert_eq!(security_hash(&[1, 2, 3, 4, 5]), 0x0403_0201);

    let mut value = DESCRIPTOR;
    value[22..28].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
    assert_eq!(
        NtfsSecurityDescriptor::parse(&value)
            .unwrap()
            .owner
            .unwrap()
            .to_string(),
        "S-1-0x010203040506-18"
    );
}

#[test]
fn absent_null_empty_and_opaque_acl_states_are_not_conflated() {
    let mut value = vec![0; 20];
    value[0] = 1;
    value[3] = 0x80;
    let absent = NtfsSecurityDescriptor::parse(&value).unwrap();
    assert!(!absent.dacl.present);
    assert!(absent.owner.is_none());
    value[2] = 4;
    let null = NtfsSecurityDescriptor::parse(&value).unwrap();
    assert!(null.dacl.present);
    assert_eq!(null.dacl.offset, 0);
    assert_eq!(null.dacl.ace_count, None);
    value[16..20].copy_from_slice(&20_u32.to_le_bytes());
    value.extend_from_slice(&[2, 0, 8, 0, 0, 0, 0, 0]);
    let empty = NtfsSecurityDescriptor::parse(&value).unwrap();
    assert_eq!(empty.dacl.ace_count, Some(0));
    assert_eq!(empty.dacl.revision, Some(2));

    let mut opaque = DESCRIPTOR;
    opaque[56] = 0x7F;
    opaque[1] = 0xA5;
    opaque[3] |= 0x40;
    let metadata = NtfsSecurityDescriptor::parse(&opaque).unwrap();
    assert_eq!(metadata.resource_manager_control, 0xA5);
    assert_eq!(metadata.dacl.ace_count, Some(2));
}

#[test]
fn descriptor_offsets_sid_and_ace_extents_are_bounded() {
    for length in 0..DESCRIPTOR.len() {
        assert!(NtfsSecurityDescriptor::parse(&DESCRIPTOR[..length]).is_err());
    }
    for (offset, byte) in [
        (0, 2),
        (3, 0),
        (4, 19),
        (4, 21),
        (20, 2),
        (21, 16),
        (33, 15),
        (48, 3),
        (50, 44),
        (52, 3),
        (58, 0),
        (58, 18),
        (58, 60),
    ] {
        let mut value = DESCRIPTOR;
        value[offset] = byte;
        assert!(
            NtfsSecurityDescriptor::parse(&value).is_err(),
            "offset {offset}, byte {byte}"
        );
    }
    let mut missing_flag = DESCRIPTOR;
    missing_flag[2] = 0;
    assert!(NtfsSecurityDescriptor::parse(&missing_flag).is_err());
    assert!(NtfsSecurityDescriptor::parse(&vec![0; MAX_SECURITY_DESCRIPTOR_BYTES + 1]).is_err());
    // Component order is not prescribed; owner and group may share a SID.
    let mut shared = DESCRIPTOR;
    shared[8..12].copy_from_slice(&20_u32.to_le_bytes());
    let shared = NtfsSecurityDescriptor::parse(&shared).unwrap();
    assert_eq!(shared.owner, shared.group);
    // A maximum-count owner at byte20 ends at byte88 and is bounded. The
    // group-count15 mutation above instead ends at byte100, outside this
    // 96-byte descriptor. Component offsets do not impose serialization order.
    let mut bounded_owner = DESCRIPTOR;
    bounded_owner[21] = 15;
    assert_eq!(
        NtfsSecurityDescriptor::parse(&bounded_owner)
            .unwrap()
            .owner
            .unwrap()
            .subauthorities
            .len(),
        15
    );
}

#[test]
fn sds_header_binds_primary_bucket_exact_length_identity_and_hash() {
    let expected = NtfsSecurityHeader::parse(&header(0x100, 464)).unwrap();
    let mut record = header(0x100, 464).to_vec();
    record.extend_from_slice(&DESCRIPTOR);
    assert_eq!(expected.descriptor(&record).unwrap(), DESCRIPTOR);
    for position in [0, 4, 8, 16, 20, 80] {
        let mut damaged = record.clone();
        damaged[position] ^= 1;
        assert!(expected.descriptor(&damaged).is_err(), "byte {position}");
    }
    assert!(expected.descriptor(&record[..record.len() - 1]).is_err());
    record.push(0);
    assert!(expected.descriptor(&record).is_err());
    for offset in [1, 0x4_0000, 0x3_FFD0, u64::MAX - 15] {
        assert!(NtfsSecurityHeader::parse(&header(0x100, offset)).is_err());
    }
    assert!(NtfsSecurityHeader::parse(&header(0, 0)).is_err());
    let mut oversized = header(0x100, 0);
    oversized[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(NtfsSecurityHeader::parse(&oversized).is_err());
    // Successive primary buckets are separated by primary+duplicate pairs.
    assert!(NtfsSecurityHeader::parse(&header(0x100, 0x8_0000)).is_ok());
}

#[test]
fn sii_root_and_native_index_block_decode_data_headers_and_fixups() {
    let keys = [
        entry(0x100, 464, None),
        entry(0x200, 592, None),
        terminal(None),
    ];
    let root_bytes = root(&keys, false);
    let parsed = NtfsSecurityIndexRoot::parse(&root_bytes, 512).unwrap();
    assert_eq!(parsed.entries.len(), 3);
    assert_eq!(parsed.entries[1].header.unwrap().security_id, 0x200);
    assert_eq!(parsed.block_bytes, 4096);
    assert_eq!(parsed.vcn_bytes, 512);
    // Sub-cluster indexes retain native 512-byte VBN units.
    assert_eq!(
        NtfsSecurityIndexRoot::parse(&root_bytes, 8192)
            .unwrap()
            .vcn_bytes,
        512
    );
    let raw = block(8, &keys);
    assert_eq!(parse_security_index_block(&raw, 8).unwrap().len(), 3);
    assert!(parse_security_index_block(&raw, 0).is_err());
    for sector in 1..=8 {
        let mut torn = raw.clone();
        torn[sector * 512 - 1] ^= 1;
        assert!(parse_security_index_block(&torn, 8).is_err());
    }
    let internal = root(&[entry(0x200, 592, Some(0)), terminal(Some(8))], true);
    let parsed = NtfsSecurityIndexRoot::parse(&internal, 512).unwrap();
    assert_eq!(parsed.entries[0].child_vcn, Some(0));
    assert_eq!(parsed.entries[1].child_vcn, Some(8));
}

#[test]
fn sii_index_rejects_wrong_collation_bounds_identity_order_and_terminators() {
    let source = root(
        &[
            entry(0x100, 464, None),
            entry(0x200, 592, None),
            terminal(None),
        ],
        false,
    );
    for (offset, byte) in [
        (0, 0x30),
        (4, 1),
        (12, 1),
        (16, 8),
        (28, 1),
        (32, 16),
        (34, 19),
        (36, 1),
        (40, 32),
        (42, 8),
        (44, 1),
        (48, 1),
        (32 + 40 + 17, 1),
        (32 + 80 + 10, 4),
    ] {
        let mut value = source.clone();
        value[offset] = byte;
        assert!(
            NtfsSecurityIndexRoot::parse(&value, 512).is_err(),
            "offset {offset}, byte {byte}"
        );
    }
    let duplicate = root(
        &[
            entry(0x100, 464, None),
            entry(0x100, 592, None),
            terminal(None),
        ],
        false,
    );
    assert!(NtfsSecurityIndexRoot::parse(&duplicate, 512).is_err());
    let mut no_terminal = source.clone();
    no_terminal.truncate(no_terminal.len() - 16);
    assert!(NtfsSecurityIndexRoot::parse(&no_terminal, 512).is_err());
}

#[test]
fn decoded_aces_preserve_native_order_masks_and_trustee_identity() {
    let descriptor = NtfsSecurityDescriptor::parse(&DESCRIPTOR).unwrap();
    let dacl = descriptor.dacl;
    assert_eq!(dacl.size, Some(48));
    assert_eq!(dacl.aces.len(), 2);
    assert_eq!(
        (dacl.aces[0].kind, dacl.aces[0].flags, dacl.aces[0].size),
        (1, 18, 20)
    );
    assert_eq!(dacl.aces[0].mask, Some(2));
    assert_eq!(dacl.aces[0].sid.as_ref().unwrap().to_string(), "S-1-1-0");
    assert_eq!((dacl.aces[1].kind, dacl.aces[1].flags), (0, 3));
    assert_eq!(dacl.aces[1].mask, Some(0x001F_01FF));
    assert_eq!(dacl.aces[1].sid.as_ref().unwrap().to_string(), "S-1-5-18");
    assert_eq!(dacl.padding, [] as [u8; 0]);

    let mut reordered = DESCRIPTOR;
    reordered[4..8].copy_from_slice(&32_u32.to_le_bytes());
    reordered[8..12].copy_from_slice(&20_u32.to_le_bytes());
    let descriptor = NtfsSecurityDescriptor::parse(&reordered).unwrap();
    assert_eq!(descriptor.owner.unwrap().to_string(), "S-1-5-32-544");
    assert_eq!(descriptor.group.unwrap().to_string(), "S-1-5-18");
}

#[test]
fn callback_object_and_unknown_ace_bodies_are_lossless_without_access_evaluation() {
    let mut value = vec![
        1, 0, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0,
    ];
    value.extend_from_slice(&[4, 0, 76, 0, 2, 0, 0, 0]);
    value.extend_from_slice(&[11, 3, 60, 0, 1, 0, 0, 0, 3, 0, 0, 0]);
    value.extend_from_slice(&[0xA1; 16]);
    value.extend_from_slice(&[0xB2; 16]);
    value.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]);
    value.extend_from_slice(b"artx");
    value.extend_from_slice(&[0xFE, 0x40, 8, 0, 0xDE, 0xAD, 0xBE, 0xEF]);
    let acl = NtfsSecurityDescriptor::parse(&value).unwrap().dacl;
    assert_eq!(acl.aces[0].object_flags, Some(3));
    assert_eq!(acl.aces[0].object_type, Some([0xA1; 16]));
    assert_eq!(acl.aces[0].inherited_object_type, Some([0xB2; 16]));
    assert_eq!(acl.aces[0].sid.as_ref().unwrap().to_string(), "S-1-5-18");
    assert_eq!(acl.aces[0].opaque, b"artx");
    assert_eq!(acl.aces[1].kind, 0xFE);
    assert_eq!(acl.aces[1].mask, None);
    assert_eq!(acl.aces[1].sid, None);
    assert_eq!(acl.aces[1].opaque, [0xDE, 0xAD, 0xBE, 0xEF]);
    for length in 0..value.len() {
        assert!(
            NtfsSecurityDescriptor::parse(&value[..length]).is_err(),
            "{length}"
        );
    }
    for (at, byte) in [(20, 2), (36, 4), (72, 2), (73, 15)] {
        let mut damaged = value.clone();
        damaged[at] = byte;
        assert!(NtfsSecurityDescriptor::parse(&damaged).is_err(), "{at}");
    }
}

#[test]
fn known_aces_reject_missing_or_invalid_trustees_reserved_acls_and_wrong_acl_roles() {
    for (at, byte) in [(49, 1), (54, 1), (64, 2), (65, 16), (65, 15), (56, 2)] {
        let mut damaged = DESCRIPTOR;
        damaged[at] = byte;
        assert!(NtfsSecurityDescriptor::parse(&damaged).is_err(), "{at}");
    }
    // Every envelope below is wholly inside the ACL; it is the missing
    // known-layout mask/SID, not an outer length error, that must refuse it.
    for length in [4_u16, 8, 12, 16] {
        let mut value = vec![
            1, 0, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0,
        ];
        value.extend_from_slice(&[2, 0, 0, 0, 1, 0, 0, 0]);
        value[22..24].copy_from_slice(&(8 + length).to_le_bytes());
        let mut ace = vec![0; usize::from(length)];
        ace[2..4].copy_from_slice(&length.to_le_bytes());
        if length >= 12 {
            ace[8..12].copy_from_slice(&[1, 1, 0, 0]);
        }
        value.extend_from_slice(&ace);
        assert!(NtfsSecurityDescriptor::parse(&value).is_err(), "{length}");
        // An unknown type has only the envelope contract and keeps the body.
        value[28] = 0xFE;
        let opaque = NtfsSecurityDescriptor::parse(&value).unwrap().dacl;
        assert_eq!(opaque.aces[0].opaque, ace[4..]);
    }
}

#[test]
fn system_ace_metadata_and_extra_native_bytes_remain_ordered_and_opaque() {
    for kind in [2, 13, 17, 18, 19] {
        let mut value = vec![
            1, 0, 0x10, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0,
        ];
        value.extend_from_slice(&[2, 0, 32, 0, 1, 0, 0, 0]);
        value.extend_from_slice(&[kind, 0x10, 24, 0, 1, 0, 0, 0]);
        value.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 16, 0, 0x10, 0, 0]);
        value.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        let descriptor = NtfsSecurityDescriptor::parse(&value).unwrap();
        assert_eq!(descriptor.sacl.aces[0].kind, kind);
        assert_eq!(descriptor.sacl.aces[0].mask, Some(1));
        assert_eq!(
            descriptor.sacl.aces[0].sid.as_ref().unwrap().to_string(),
            "S-1-16-4096"
        );
        assert_eq!(descriptor.sacl.aces[0].opaque, [0xAA, 0xBB, 0xCC, 0xDD]);
        value[2] = 4;
        value[12..16].fill(0);
        value[16..20].copy_from_slice(&20_u32.to_le_bytes());
        assert!(NtfsSecurityDescriptor::parse(&value).is_err(), "{kind}");
    }
    // Additional bytes are preserved even for an ordinary non-callback ACE.
    let mut value = DESCRIPTOR.to_vec();
    value[50..52].copy_from_slice(&52_u16.to_le_bytes());
    value[78..80].copy_from_slice(&24_u16.to_le_bytes());
    value.extend_from_slice(&[1, 2, 3, 4]);
    assert_eq!(
        NtfsSecurityDescriptor::parse(&value).unwrap().dacl.aces[1].opaque,
        [1, 2, 3, 4]
    );
}

#[test]
fn unused_acl_space_and_absent_null_empty_metadata_are_preserved() {
    let mut value = vec![
        1, 0, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0,
    ];
    value.extend_from_slice(&[2, 0, 12, 0, 0, 0, 0, 0, 0xAA, 0xBB, 0xCC, 0xDD]);
    let acl = NtfsSecurityDescriptor::parse(&value).unwrap().dacl;
    assert_eq!(acl.size, Some(12));
    assert_eq!(acl.aces, [] as [NtfsAce; 0]);
    assert_eq!(acl.padding, [0xAA, 0xBB, 0xCC, 0xDD]);
    value.truncate(20);
    value[16..20].fill(0);
    let null = NtfsSecurityDescriptor::parse(&value).unwrap().dacl;
    assert!(null.present);
    assert_eq!(null.size, None);
    assert_eq!(null.aces, [] as [NtfsAce; 0]);
    value[2] = 0;
    let absent = NtfsSecurityDescriptor::parse(&value).unwrap().dacl;
    assert!(!absent.present);
    assert_eq!(absent.size, None);
}

#[test]
fn selected_descriptor_lengths_cannot_hide_unhashed_partial_words() {
    assert_eq!(security_hash(&[1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0]), 83);
    assert_eq!(security_hash(&[255, 255, 255, 255, 1, 0, 0, 0]), 0);
    let valid = header(0x100, 464);
    let mut entry = valid.to_vec();
    entry.extend_from_slice(&DESCRIPTOR);
    // Keep the public prefix parser and complete-word hash contracts intact.
    assert_eq!(
        NtfsSecurityHeader::parse(&entry).unwrap(),
        NtfsSecurityHeader::parse(&valid).unwrap()
    );
    assert_eq!(security_hash(&[1, 2, 3, 4, 5]), 0x0403_0201);
    for extra in 1..=3 {
        let mut descriptor = DESCRIPTOR.to_vec();
        descriptor.extend(std::iter::repeat_n(0xA5, extra));
        assert_eq!(security_hash(&descriptor), DESCRIPTOR_HASH);
        assert!(NtfsSecurityDescriptor::parse(&descriptor).is_err());
        let mut value = valid;
        value[16..20].copy_from_slice(&(116_u32 + extra as u32).to_le_bytes());
        assert!(NtfsSecurityHeader::parse(&value).is_err());
    }
    let valid = NtfsSecurityHeader::parse(&valid).unwrap();
    assert!(
        NtfsSecurityHeader { length: 0, ..valid }
            .descriptor(&[])
            .is_err()
    );
}
