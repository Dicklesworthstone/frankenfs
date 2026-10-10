use super::*;

fn boot() -> [u8; 512] {
    let mut b = [0_u8; 512];
    b[3..11].copy_from_slice(b"NTFS    ");
    b[11..13].copy_from_slice(&512_u16.to_le_bytes());
    b[13] = 8;
    b[21] = 0xF8;
    b[40..48].copy_from_slice(&8191_u64.to_le_bytes());
    b[48..56].copy_from_slice(&4_u64.to_le_bytes());
    b[56..64].copy_from_slice(&512_u64.to_le_bytes());
    b[64] = 0xF6;
    b[68] = 1;
    b[510..512].copy_from_slice(&[0x55, 0xAA]);
    b
}

fn protect(raw: &mut [u8]) {
    let offset = usize::from(u16::from_le_bytes([raw[4], raw[5]]));
    for part in 1..=raw.len() / 512 {
        let saved = [raw[part * 512 - 2], raw[part * 512 - 1]];
        raw[offset + part * 2..offset + part * 2 + 2].copy_from_slice(&saved);
        raw[part * 512 - 2..part * 512].copy_from_slice(&0xA55A_u16.to_le_bytes());
    }
    raw[offset..offset + 2].copy_from_slice(&0xA55A_u16.to_le_bytes());
}

fn record() -> Vec<u8> {
    let mut r = vec![0; 1024];
    r[..4].copy_from_slice(b"FILE");
    r[4..6].copy_from_slice(&48_u16.to_le_bytes());
    r[6..8].copy_from_slice(&3_u16.to_le_bytes());
    r[16..18].copy_from_slice(&7_u16.to_le_bytes());
    r[20..22].copy_from_slice(&56_u16.to_le_bytes());
    r[22..24].copy_from_slice(&1_u16.to_le_bytes());
    r[24..28].copy_from_slice(&96_u32.to_le_bytes());
    r[28..32].copy_from_slice(&1024_u32.to_le_bytes());
    r[44..48].copy_from_slice(&24_u32.to_le_bytes());
    let a = &mut r[56..88];
    a[..4].copy_from_slice(&DATA.to_le_bytes());
    a[4..8].copy_from_slice(&32_u32.to_le_bytes());
    a[16..20].copy_from_slice(&3_u32.to_le_bytes());
    a[20..22].copy_from_slice(&24_u16.to_le_bytes());
    a[24..27].copy_from_slice(b"abc");
    r[88..92].copy_from_slice(&u32::MAX.to_le_bytes());
    protect(&mut r);
    r
}

#[test]
fn boot_validates_addressable_range_and_both_record_size_encodings() {
    let mut b = boot();
    b[28..32].copy_from_slice(&2048_u32.to_le_bytes());
    let g = NtfsGeometry::parse(&b, 8192 * 512).unwrap();
    assert_eq!(g.record_bytes(), 1024);
    assert_eq!(g.index_bytes(), 4096);
    assert_eq!(g.cluster_count(), 1023);
    assert_eq!(g.cluster_offset(g.mft_cluster()).unwrap(), 16_384);
    assert_eq!(g.volume_bytes(), 8191 * 512);
    assert!(g.cluster_offset(1023).is_err());
    assert!(NtfsGeometry::parse(&b, 8191 * 512 - 1).is_err());
    for size in 0..512 { assert!(NtfsGeometry::parse(&b[..size], u64::MAX).is_err()); }
}

#[test]
fn boot_rejects_aliases_zero_divisors_and_overflow_encodings() {
    for (at, value) in [(13, 0), (13, 3), (14, 1), (64, 0), (64, 0x80), (64, 0xFF), (68, 0), (510, 0)] {
        let mut b = boot();
        b[at] = value;
        assert!(NtfsGeometry::parse(&b, u64::MAX).is_err(), "offset {at}");
    }
    let mut b = boot();
    b[56..64].copy_from_slice(&4_u64.to_le_bytes());
    assert!(NtfsGeometry::parse(&b, u64::MAX).is_err());
    b[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(NtfsGeometry::parse(&b, u64::MAX).is_err());
}

#[test]
fn all_trailers_are_checked_and_input_is_never_partially_restored() {
    let r = record();
    let fixed = restore_record(&r, b"FILE").unwrap();
    assert_eq!(&fixed[510..512], &[0, 0]);
    assert_eq!(&fixed[1022..1024], &[0, 0]);
    let mut torn = r.clone();
    torn[1023] ^= 1;
    let before = torn.clone();
    assert!(restore_record(&torn, b"FILE").is_err());
    assert_eq!(torn, before);
    assert!(restore_record(&r, b"INDX").is_err());
    for size in 0..r.len() { assert!(NtfsFileRecord::parse(&r[..size]).is_err()); }
    for (at, value) in [(4, 49), (4, 0), (6, 2), (6, 4)] {
        let mut bad = r.clone();
        bad[at] = value;
        assert!(NtfsFileRecord::parse(&bad).is_err());
    }
}

#[test]
fn update_sequence_stride_is_512_not_the_bpb_sector_size() {
    let mut raw = vec![0; 4096];
    raw[..4].copy_from_slice(b"INDX");
    raw[4..6].copy_from_slice(&40_u16.to_le_bytes());
    raw[6..8].copy_from_slice(&9_u16.to_le_bytes());
    for part in 1..=8 { raw[part * 512 - 2] = part as u8; }
    protect(&mut raw);
    let fixed = restore_record(&raw, b"INDX").unwrap();
    for part in 1..=8 { assert_eq!(fixed[part * 512 - 2], part as u8); }
    raw[1534] ^= 1;
    assert!(restore_record(&raw, b"INDX").is_err());
}

#[test]
fn file_record_exposes_resident_data_and_native_reference_identity() {
    let r = NtfsFileRecord::parse(&record()).unwrap();
    assert!(r.in_use());
    assert!(!r.is_directory());
    assert_eq!((r.number, r.sequence), (24, 7));
    let attributes = r.attributes().unwrap();
    assert_eq!(attributes.len(), 1);
    assert!(attributes[0].name.is_empty());
    let NtfsValue::Resident(value) = &attributes[0].value else { panic!("resident"); };
    assert_eq!(*value, b"abc");
    assert_eq!(NtfsReference::decode((7_u64 << 48) | 24), NtfsReference { record: 24, sequence: 7 });
}

#[test]
fn attributes_cannot_overlap_headers_escape_used_bytes_or_hide_bad_tails() {
    for (at, value) in [(20, 48), (24, 88), (56 + 4, 0), (56 + 4, 31), (56 + 8, 2),
                        (56 + 16, 200), (56 + 20, 16), (88, 0)] {
        let mut r = record();
        r[at] = value;
        assert!(NtfsFileRecord::parse(&r).is_err(), "offset {at}");
    }
    let mut r = record();
    r[56 + 9] = 1;
    r[56 + 10..56 + 12].copy_from_slice(&24_u16.to_le_bytes());
    assert!(NtfsFileRecord::parse(&r).is_err());
}

#[test]
fn mapping_pairs_handle_backward_deltas_and_sparse_runs_without_resetting_lcn() {
    let pairs = [0x11, 2, 100, 0x01, 3, 0x11, 1, 0xF6, 0];
    let runs = decode_mapping_pairs(&pairs, 0, 5, 1000).unwrap();
    assert_eq!(runs, [NtfsRun { vcn: 0, clusters: 2, lcn: Some(100) },
                     NtfsRun { vcn: 2, clusters: 3, lcn: None },
                     NtfsRun { vcn: 5, clusters: 1, lcn: Some(90) }]);
    assert_eq!(decode_mapping_pairs(&[0x11, 2, 10, 0], 8, 9, 100).unwrap()[0].vcn, 8);
    assert!(decode_mapping_pairs(&[0], 0, u64::MAX, 100).unwrap().is_empty());
}

#[test]
fn mapping_pairs_refuse_truncation_zero_runs_bad_widths_and_incomplete_coverage() {
    let good = [0x11, 2, 10, 0];
    for end in 0..good.len() { assert!(decode_mapping_pairs(&good[..end], 0, 1, 100).is_err()); }
    for pairs in [&[0x11, 0, 10, 0][..], &[0x10, 1, 0], &[0x91, 1, 0],
                  &[0x11, 3, 10, 0], &[0x11, 1, 10, 0], &[0x11, 2, 0xFF, 0]] {
        assert!(decode_mapping_pairs(pairs, 0, 1, 100).is_err());
    }
    assert!(decode_mapping_pairs(&good, 0, 1, 11).is_err());
    assert!(decode_mapping_pairs(&good, 9, 8, 100).is_err());
    assert!(decode_mapping_pairs(&good, u64::MAX, u64::MAX, 100).is_err());
}

#[test]
fn mapping_pair_length_and_signed_delta_extremes_do_not_wrap() {
    let mut pairs = vec![0x18];
    pairs.extend_from_slice(&u64::MAX.to_le_bytes());
    pairs.extend_from_slice(&[1, 0]);
    assert!(decode_mapping_pairs(&pairs, 1, 10, u64::MAX).is_err());
    let mut pairs = vec![0x81, 1];
    pairs.extend_from_slice(&i64::MIN.to_le_bytes());
    pairs.push(0);
    assert!(decode_mapping_pairs(&pairs, 0, 0, u64::MAX).is_err());
}

#[test]
fn nonresident_names_mappings_and_initialized_bounds_are_validated() {
    let mut r = restore_record(&record(), b"FILE").unwrap();
    r[56..160].fill(0);
    r[24..28].copy_from_slice(&152_u32.to_le_bytes());
    let a = &mut r[56..144];
    a[..4].copy_from_slice(&DATA.to_le_bytes());
    a[4..8].copy_from_slice(&88_u32.to_le_bytes());
    a[8] = 1;
    a[9] = 3;
    a[10..12].copy_from_slice(&64_u16.to_le_bytes());
    a[32..34].copy_from_slice(&72_u16.to_le_bytes());
    a[40..48].copy_from_slice(&4096_u64.to_le_bytes());
    a[48..56].copy_from_slice(&3_u64.to_le_bytes());
    a[56..64].copy_from_slice(&2_u64.to_le_bytes());
    a[64..70].copy_from_slice(&[b'a', 0, b'd', 0, b's', 0]);
    a[72..76].copy_from_slice(&[0x11, 1, 10, 0]);
    r[144..148].copy_from_slice(&u32::MAX.to_le_bytes());
    protect(&mut r);
    let file = NtfsFileRecord::parse(&r).unwrap();
    let attrs = file.attributes().unwrap();
    assert_eq!(attrs[0].name, [97, 100, 115]);
    let NtfsValue::NonResident(value) = &attrs[0].value else { panic!("nonresident"); };
    assert_eq!(value.initialized_bytes, 2);
    assert_eq!(decode_mapping_pairs(value.mapping_pairs, value.first_vcn, value.last_vcn, 100).unwrap()[0].lcn, Some(10));
    r[56 + 56] = 4;
    assert!(NtfsFileRecord::parse(&r).is_err());
}
