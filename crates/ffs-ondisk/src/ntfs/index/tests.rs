use super::*;

fn file_name(name: &[u16]) -> Vec<u8> {
    let mut value = vec![0; 66 + name.len() * 2];
    value[..8].copy_from_slice(&((7_u64 << 48) | 5).to_le_bytes());
    value[64] = name.len() as u8;
    value[65] = 1;
    for (i, unit) in name.iter().enumerate() {
        value[66 + i * 2..68 + i * 2].copy_from_slice(&unit.to_le_bytes());
    }
    value
}

fn root() -> Vec<u8> {
    let key = file_name(&[65]);
    let entry_len = (16 + key.len()).next_multiple_of(8);
    let mut value = vec![0; 32 + entry_len + 16];
    value[..4].copy_from_slice(&0x30_u32.to_le_bytes());
    value[4..8].copy_from_slice(&1_u32.to_le_bytes());
    value[8..12].copy_from_slice(&4096_u32.to_le_bytes());
    value[12] = 8;
    value[16..20].copy_from_slice(&16_u32.to_le_bytes());
    let used = (value.len() - 16) as u32;
    value[20..24].copy_from_slice(&used.to_le_bytes());
    value[24..28].copy_from_slice(&used.to_le_bytes());
    value[32..40].copy_from_slice(&((7_u64 << 48) | 24).to_le_bytes());
    value[40..42].copy_from_slice(&(entry_len as u16).to_le_bytes());
    value[42..44].copy_from_slice(&(key.len() as u16).to_le_bytes());
    value[48..48 + key.len()].copy_from_slice(&key);
    let end = 32 + entry_len;
    value[end + 8..end + 10].copy_from_slice(&16_u16.to_le_bytes());
    value[end + 12..end + 14].copy_from_slice(&2_u16.to_le_bytes());
    value
}

#[test]
fn filename_preserves_native_utf16_and_rejects_invalid_components() {
    let value = file_name(&[0xD800, 65]);
    let parsed = NtfsFileName::parse(&value).unwrap();
    assert_eq!(parsed.parent, NtfsReference { record: 5, sequence: 7 });
    assert_eq!(parsed.name, [0xD800, 65]);
    for unit in [0, 47, 92] { assert!(NtfsFileName::parse(&file_name(&[unit])).is_err()); }
    for end in 0..value.len() { assert!(NtfsFileName::parse(&value[..end]).is_err()); }
    let mut bad = value;
    bad[65] = 4;
    assert!(NtfsFileName::parse(&bad).is_err());
}

#[test]
fn resident_index_keys_and_subcluster_vbn_units_are_explicit() {
    let value = root();
    let parsed = NtfsIndexRoot::parse(&value, 512).unwrap();
    assert_eq!((parsed.block_bytes, parsed.vcn_bytes), (4096, 512));
    assert_eq!(parsed.entries.len(), 2);
    assert_eq!(parsed.entries[0].key.as_ref().unwrap().0.record, 24);
    assert!(parsed.entries[1].key.is_none());
    // This remains eight 512-byte units even on a 64-KiB-cluster volume.
    assert_eq!(NtfsIndexRoot::parse(&value, 65_536).unwrap().vcn_bytes, 512);
    assert!(NtfsIndexRoot::parse(&value, 4096).is_err());
    let mut large = value;
    large[12] = 1;
    assert_eq!(NtfsIndexRoot::parse(&large, 4096).unwrap().vcn_bytes, 4096);
}

#[test]
fn index_bounds_child_flags_key_lengths_and_terminal_are_mandatory() {
    let value = root();
    for end in 0..value.len() { assert!(NtfsIndexRoot::parse(&value[..end], 512).is_err()); }
    for (at, byte) in [(4, 0), (12, 0), (16, 8), (20, 16), (28, 1),
                       (40, 0), (40, 17), (42, 255), (44, 1), (44, 4)] {
        let mut bad = value.clone();
        bad[at] = byte;
        assert!(NtfsIndexRoot::parse(&bad, 512).is_err(), "offset {at}");
    }
    let mut bad = value;
    let at = bad.len() - 4;
    bad[at] = 0;
    assert!(NtfsIndexRoot::parse(&bad, 512).is_err());
}

fn index_block() -> Vec<u8> {
    let mut raw = vec![0; 4096];
    raw[..4].copy_from_slice(b"INDX");
    raw[4..6].copy_from_slice(&40_u16.to_le_bytes());
    raw[6..8].copy_from_slice(&9_u16.to_le_bytes());
    raw[16..24].copy_from_slice(&8_u64.to_le_bytes());
    raw[24..28].copy_from_slice(&40_u32.to_le_bytes());
    raw[28..32].copy_from_slice(&56_u32.to_le_bytes());
    raw[32..36].copy_from_slice(&4072_u32.to_le_bytes());
    raw[72..74].copy_from_slice(&16_u16.to_le_bytes());
    raw[76..78].copy_from_slice(&2_u16.to_le_bytes());
    for part in 1..=8 {
        raw[part * 512 - 2..part * 512].copy_from_slice(&0x2468_u16.to_le_bytes());
    }
    raw[40..42].copy_from_slice(&0x2468_u16.to_le_bytes());
    raw
}

#[test]
fn indx_requires_matching_vbn_valid_fixups_and_no_usa_overlap() {
    let raw = index_block();
    let entries = parse_index_block(&raw, 8).unwrap();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].key.is_none());
    assert!(parse_index_block(&raw, 0).is_err());
    let mut bad = raw.clone();
    bad[2046] ^= 1;
    assert!(parse_index_block(&bad, 8).is_err());
    let mut bad = raw;
    bad[24..28].copy_from_slice(&16_u32.to_le_bytes());
    assert!(parse_index_block(&bad, 8).is_err());
}
