use super::*;

fn entry(name: &[u8], value: &[u8], flags: u8) -> Vec<u8> {
    let length = (9 + name.len() + value.len()).next_multiple_of(4);
    let mut bytes = vec![0xCD; length];
    bytes[..4].copy_from_slice(&(length as u32).to_le_bytes());
    bytes[4] = flags;
    bytes[5] = name.len() as u8;
    bytes[6..8].copy_from_slice(&(value.len() as u16).to_le_bytes());
    bytes[8..8 + name.len()].copy_from_slice(name);
    bytes[8 + name.len()] = 0;
    bytes[9 + name.len()..9 + name.len() + value.len()].copy_from_slice(value);
    bytes
}

fn information(packed: u16, need: u16, size: usize) -> NtfsEaInformation {
    let mut bytes = [0; 8];
    bytes[..2].copy_from_slice(&packed.to_le_bytes());
    bytes[2..4].copy_from_slice(&need.to_le_bytes());
    bytes[4..].copy_from_slice(&(size as u32).to_le_bytes());
    NtfsEaInformation::parse(&bytes).unwrap()
}

#[test]
fn native_nonzero_final_lengths_preserve_names_binary_values_and_need_count() {
    let mut bytes = entry(b"user.note", &[0, 0xFF, 1], FILE_NEED_EA);
    bytes.extend(entry(b"$LXUID", &[123, 0, 0, 0], 0));
    bytes.extend(entry(&[0x82, b'A'], &[], 0));
    // Packed sizes: (5 + 9 + 3) + (5 + 6 + 4) + (5 + 2 + 0).
    let info = information(39, 1, bytes.len());
    let parsed = parse_extended_attributes(&info, &bytes).unwrap();
    assert_eq!(parsed.len(), 3);
    assert_eq!(parsed[0].name, b"user.note");
    assert_eq!(parsed[0].value, [0, 0xFF, 1]);
    assert!(parsed[0].need_ea());
    assert!(!parsed[1].need_ea());
    assert_eq!(parsed[1].value, 123_u32.to_le_bytes());
    assert_eq!(parsed[2].name, [0x82, b'A']);
    assert_eq!(parsed[2].value, [] as [u8; 0]);
}

#[test]
fn zero_final_offset_accepts_arbitrary_alignment_padding_but_not_another_entry() {
    let mut bytes = entry(b"A", b"x", 0);
    bytes[..4].fill(0);
    for length in [11, 12] {
        assert_eq!(
            parse_extended_attributes(&information(7, 0, length), &bytes[..length]).unwrap()[0]
                .value,
            b"x"
        );
    }
    bytes.extend(entry(b"B", b"y", 0));
    assert!(parse_extended_attributes(&information(14, 0, bytes.len()), &bytes).is_err());
}

#[test]
fn packed_sizes_exclude_offsets_padding_and_the_count_is_only_for_needed_eas() {
    let mut bytes = entry(b"A", &[1, 2], FILE_NEED_EA);
    bytes.extend(entry(b"B", &[], 0));
    let info = information(14, 1, bytes.len());
    assert_eq!(parse_extended_attributes(&info, &bytes).unwrap().len(), 2);
    for bad in [
        information(13, 1, bytes.len()),
        information(15, 1, bytes.len()),
        information(14, 2, bytes.len()),
        information(14, 0, bytes.len()),
        information(14, 1, bytes.len() - 1),
        information(14, 1, bytes.len() + 1),
    ] {
        assert!(parse_extended_attributes(&bad, &bytes).is_err());
    }
    assert_eq!(
        parse_extended_attributes(&information(0, 0, 0), &[]).unwrap(),
        [] as [NtfsEa; 0]
    );
    assert!(parse_extended_attributes(&information(1, 0, 0), &[]).is_err());
    assert!(parse_extended_attributes(&information(0, 1, 0), &[]).is_err());
}

#[test]
fn full_native_name_and_value_limits_are_bounded_before_allocation() {
    let name = vec![b'N'; MAX_EA_NAME_BYTES];
    let value = vec![0xA7; MAX_EA_BYTES - 9 - name.len()];
    let bytes = entry(&name, &value, 0);
    assert_eq!(bytes.len(), MAX_EA_BYTES);
    let info = information(65_532, 0, bytes.len());
    let parsed = parse_extended_attributes(&info, &bytes).unwrap();
    assert_eq!(parsed[0].name, name);
    assert_eq!(parsed[0].value, value);
    let mut huge_info = [0; 8];
    huge_info[4..].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(NtfsEaInformation::parse(&huge_info).is_err());
    for length in [0, 7, 9, 64] {
        assert!(NtfsEaInformation::parse(&vec![0; length]).is_err());
    }
    let huge = vec![0; MAX_EA_BYTES + 1];
    let info = NtfsEaInformation {
        packed_bytes: 0,
        need_ea_count: 0,
        unpacked_bytes: huge.len() as u32,
    };
    assert!(parse_extended_attributes(&info, &huge).is_err());
}

#[test]
fn every_truncation_and_corrupt_second_entry_refuses_the_complete_catalog() {
    let first = entry(b"user.one", b"ready", 0);
    let mut bytes = first.clone();
    bytes.extend(entry(b"user.two", &[0, 0xFF], FILE_NEED_EA));
    let info = information(33, 1, bytes.len());
    assert_eq!(parse_extended_attributes(&info, &bytes).unwrap().len(), 2);
    for end in 0..bytes.len() {
        let truncated = information(33, 1, end);
        assert!(
            parse_extended_attributes(&truncated, &bytes[..end]).is_err(),
            "end {end}"
        );
    }
    for (field, replacement) in [
        (0, 4),     // Next entry overlaps header.
        (0, 19),    // Misaligned next entry.
        (0, 0xFF),  // Next entry leaves the stream.
        (4, 1),     // Unknown flags.
        (5, 0),     // Empty name.
        (5, 255),   // Name leaves the entry.
        (6, 255),   // Value leaves the entry.
        (8, 0),     // Embedded name terminator.
        (16, b'X'), // Missing terminator after user.two.
    ] {
        let mut bad = bytes.clone();
        bad[first.len() + field] = replacement;
        assert!(
            parse_extended_attributes(&info, &bad).is_err(),
            "field {field}"
        );
    }
    let mut trailer = bytes;
    trailer.extend_from_slice(&[0; 4]);
    assert!(parse_extended_attributes(&information(33, 1, trailer.len()), &trailer).is_err());
}

#[test]
fn exact_duplicates_are_refused_without_case_folding_distinct_native_names() {
    let mut bytes = entry(b"user.Name", b"upper", 0);
    bytes.extend(entry(b"user.name", b"lower", 0));
    let parsed = parse_extended_attributes(&information(38, 0, bytes.len()), &bytes).unwrap();
    assert_eq!(parsed.len(), 2);
    bytes.extend(entry(b"user.Name", b"again", 0));
    assert!(parse_extended_attributes(&information(57, 0, bytes.len()), &bytes).is_err());
}
