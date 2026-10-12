use super::*;

fn put16(raw: &mut [u8], at: usize, value: u16, order: Endian) {
    let bytes = match order {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    };
    raw[at..at + 2].copy_from_slice(&bytes);
}
fn legacy(order: Endian, mode: u64, size: u64) -> Vec<u8> {
    let mut raw = vec![0; 264];
    for (at, value) in [
        (0, u64::MAX),
        (8, 999_999_999),
        (16, 1_700_000_000),
        (24, 123),
        (64, 77),
        (72, mode),
        (80, size),
        (88, 2),
        (96, 2),
        (128, 1000),
        (136, 100),
    ] {
        raw[at..at + 8].copy_from_slice(&order.encode(value));
    }
    raw
}
fn entry(name: &str, width: u8, values: Vec<u64>) -> Entry {
    Entry {
        name: name.as_bytes().to_vec(),
        integer_bytes: width,
        values,
        collision: 0,
    }
}
fn registration(name: &str, id: u16, length: u16, swap: u8) -> Entry {
    entry(
        name,
        8,
        vec![u64::from(id) | (u64::from(swap) << 16) | (u64::from(length) << 24)],
    )
}
fn attributes(order: Endian, mode: u64, size: u64) -> Vec<(u16, Vec<u8>)> {
    let raw = legacy(order, mode, size);
    // Deliberately not enum/legacy order; field offsets are independent inputs.
    [
        (6, 80, 8),
        (3, 48, 16),
        (0, 0, 16),
        (12, 128, 8),
        (13, 136, 8),
        (5, 72, 8),
        (2, 32, 16),
        (4, 64, 8),
        (8, 96, 8),
        (1, 16, 16),
        (11, 120, 8),
        (7, 88, 8),
    ]
    .into_iter()
    .map(|(id, at, len)| (id, raw[at..at + len].to_vec()))
    .collect()
}
fn layout(id: u16, attrs: &[(u16, Vec<u8>)]) -> Entry {
    entry(
        &id.to_string(),
        2,
        attrs.iter().map(|(id, _)| u64::from(*id)).collect(),
    )
}
fn packed(id: u16, attrs: &[(u16, Vec<u8>)], variables: &[u16], order: Endian) -> Vec<u8> {
    let lengths: Vec<_> = attrs
        .iter()
        .filter(|(id, _)| variables.contains(id))
        .map(|(_, bytes)| bytes.len())
        .collect();
    let header = (6 + lengths.len() * 2).div_ceil(8) * 8;
    let mut raw = vec![0; header];
    raw[..4].copy_from_slice(match order {
        Endian::Little => &[0x5a, 0x50, 0x2f, 0],
        Endian::Big => &[0, 0x2f, 0x50, 0x5a],
    });
    put16(&mut raw, 4, id | ((header as u16 / 8) << 10), order);
    for (i, length) in lengths.iter().enumerate() {
        put16(&mut raw, 6 + i * 2, *length as u16, order);
    }
    for (_, bytes) in attrs {
        raw.extend_from_slice(bytes);
        raw.resize(raw.len().div_ceil(8) * 8, 0xCC); // Padding is not an attribute.
    }
    raw
}

#[test]
fn legacy_metadata_retains_native_times_ids_and_inline_links_in_both_orders() {
    for order in [Endian::Little, Endian::Big] {
        let raw = legacy(order, 0o100_640, 17);
        let value = Metadata::legacy(&raw, order).unwrap();
        assert_eq!(
            (
                value.kind,
                value.mode,
                value.size,
                value.parent,
                value.links
            ),
            (Kind::Regular, 0o100_640, 17, 2, 2)
        );
        assert_eq!((value.uid, value.gid, value.generation), (1000, 100, 77));
        assert_eq!(
            value.times[0],
            Timestamp {
                seconds: -1,
                nanos: 999_999_999
            }
        );
        assert_eq!(
            value.times[1],
            Timestamp {
                seconds: 1_700_000_000,
                nanos: 123
            }
        );
        let mut link = legacy(order, 0o120_777, 7);
        assert!(
            Metadata::legacy(&link, order)
                .unwrap()
                .inline_symlink
                .is_none()
        );
        link.extend_from_slice(b"../file");
        assert_eq!(
            Metadata::legacy(&link, order)
                .unwrap()
                .inline_symlink
                .unwrap(),
            b"../file"
        );
    }
}
#[test]
fn legacy_malformed_fields_and_truncation_never_publish_metadata() {
    for end in 0..264 {
        assert!(Metadata::legacy(&vec![0; end], Endian::Little).is_err());
    }
    let raw = legacy(Endian::Little, 0o100_600, 1);
    for (at, value) in [
        (8, 1_000_000_000_u64),
        (64, 0),
        (72, 0o030_000),
        (72, 0x1_8000),
        (88, 0),
        (88, 1 << 48),
    ] {
        let mut bad = raw.clone();
        bad[at..at + 8].copy_from_slice(&value.to_le_bytes());
        assert!(
            Metadata::legacy(&bad, Endian::Little).is_err(),
            "{at} {value}"
        );
    }
}
#[test]
fn native_directory_tags_do_not_become_part_of_object_identity() {
    assert_eq!(
        directory_reference((8 << 60) | 0x0385).unwrap(),
        (901, Some(Kind::Regular))
    );
    assert_eq!(directory_reference(901).unwrap(), (901, None));
    for value in [0, 8 << 60, (1 << 48) | 0x0385, (3 << 60) | 0x0385] {
        assert!(directory_reference(value).is_err());
    }
}
#[test]
fn sa_reordered_layout_and_dynamic_registration_decode_without_fixed_offsets() {
    for order in [Endian::Little, Endian::Big] {
        let mut attrs = attributes(order, 0o120_777, 7);
        attrs.insert(1, (47, b"../file".to_vec()));
        attrs.insert(2, (300, vec![9, 8, 7]));
        let registry = SaRegistry::from_zaps(
            &[
                registration("ZPL_SYMLINK", 47, 0, 3),
                registration("application:bytes", 300, 0, 3),
            ],
            &[layout(42, &attrs)],
        )
        .unwrap();
        let bytes = packed(42, &attrs, &[47, 300], order);
        assert_eq!(word16(&bytes, 4, order).unwrap() >> 10, 2); // Two lengths require 16-byte header.
        let value = registry.decode(&bytes, None).unwrap().metadata().unwrap();
        assert_eq!(value.inline_symlink.unwrap(), b"../file");
        assert_eq!(
            (
                value.size,
                value.uid,
                value.generation,
                value.times[0].seconds
            ),
            (7, 1000, 77, -1)
        );
    }
}
#[test]
fn bonus_and_spill_use_independent_layouts_and_value_byte_orders() {
    let bonus_attrs = attributes(Endian::Little, 0o100_640, 17);
    let spill_attrs = attributes(Endian::Big, 0o100_640, 17);
    let registry = SaRegistry::from_zaps(
        &[],
        &[layout(2, &bonus_attrs[..5]), layout(3, &spill_attrs[5..])],
    )
    .unwrap();
    let bonus = packed(2, &bonus_attrs[..5], &[], Endian::Little);
    let spill = packed(3, &spill_attrs[5..], &[], Endian::Big);
    let value = registry
        .decode(&bonus, Some(&spill))
        .unwrap()
        .metadata()
        .unwrap();
    assert_eq!(
        value,
        Metadata::legacy(&legacy(Endian::Little, 0o100_640, 17), Endian::Little).unwrap()
    );
    assert!(registry.decode(&bonus, Some(&bonus)).is_err());
    assert!(registry.decode(&bonus, None).unwrap().metadata().is_err());
}
#[test]
fn invalid_registrations_layouts_and_ambiguous_catalogs_are_refused() {
    for entries in [
        vec![registration("ZPL_SIZE", 17, 8, 0)],
        vec![registration("other", 6, 8, 0)],
        vec![registration("other", 17, 8, 9)],
        vec![
            registration("other", 17, 8, 0),
            registration("other", 18, 8, 0),
        ],
        vec![
            registration("other", 17, 8, 0),
            registration("third", 17, 8, 0),
        ],
        vec![entry("bad", 8, vec![1 << 48])],
    ] {
        assert!(SaRegistry::from_zaps(&entries, &[]).is_err());
    }
    for item in [
        entry("0", 2, vec![]),
        entry("02", 2, vec![0]),
        entry("1024", 2, vec![]),
        entry("2", 8, vec![0]),
        entry("2", 2, vec![999]),
        entry("2", 2, vec![0, 0]),
    ] {
        assert!(SaRegistry::from_zaps(&[], &[item]).is_err());
    }
    assert!(SaRegistry::from_zaps(&[registration("ZPL_SIZE", 6, 8, 0)], &[]).is_ok());
}
#[test]
fn sa_buffer_bounds_are_checked_even_for_unconsumed_attributes() {
    let attrs = vec![(47, vec![1, 2, 3]), (6, 17_u64.to_le_bytes().to_vec())];
    let registry =
        SaRegistry::from_zaps(&[registration("unknown", 47, 0, 3)], &[layout(2, &attrs)]).unwrap();
    let bytes = packed(2, &attrs, &[47], Endian::Little);
    for end in 1..bytes.len() {
        assert!(registry.decode(&bytes[..end], None).is_err(), "{end}");
    }
    for (at, value) in [(0, 0_u8), (4, 99), (5, 0), (6, 255)] {
        let mut bad = bytes.clone();
        bad[at] = value;
        assert!(registry.decode(&bad, None).is_err(), "{at}");
    }
    assert!(registry.decode(&vec![0; SA_BYTES + 1], None).is_err());
}
#[test]
fn symlink_type_and_length_cannot_be_changed_by_an_optional_attribute() {
    let mut attrs = attributes(Endian::Little, 0o100_600, 3);
    attrs.push((47, b"abc".to_vec()));
    let registry = SaRegistry::from_zaps(
        &[registration("ZPL_SYMLINK", 47, 0, 3)],
        &[layout(2, &attrs)],
    )
    .unwrap();
    assert!(
        registry
            .decode(&packed(2, &attrs, &[47], Endian::Little), None)
            .unwrap()
            .metadata()
            .is_err()
    );
    attrs = attributes(Endian::Little, 0o120_777, 4);
    attrs.push((47, b"abc".to_vec()));
    assert!(
        registry
            .decode(&packed(2, &attrs, &[47], Endian::Little), None)
            .unwrap()
            .metadata()
            .is_err()
    );
}

fn xdr_xattrs(fields: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = vec![1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    for (name, value) in fields {
        let mut pair = vec![0; 8];
        pair.extend_from_slice(&(name.len() as u32).to_be_bytes());
        pair.extend_from_slice(name.as_bytes());
        pair.resize(pair.len().next_multiple_of(4), 0);
        pair.extend_from_slice(&10_u32.to_be_bytes());
        pair.extend_from_slice(&(value.len() as u32).to_be_bytes());
        pair.extend_from_slice(value);
        pair.resize(pair.len().next_multiple_of(4), 0);
        let encoded = pair.len() as u32;
        pair[..4].copy_from_slice(&encoded.to_be_bytes());
        let decoded = (16 + name.len() + 1).next_multiple_of(8) + value.len().next_multiple_of(8);
        pair[4..8].copy_from_slice(&(decoded as u32).to_be_bytes());
        out.extend_from_slice(&pair);
    }
    out.extend_from_slice(&[0; 8]);
    out
}

#[test]
fn xattr_sources_decode_legacy_pointer_and_dynamic_sa_bytes_in_both_orders() {
    for order in [Endian::Little, Endian::Big] {
        let mut raw = legacy(order, 0o100_640, 17);
        assert_eq!(XattrSources::legacy(&raw, order).unwrap().directory, 0);
        raw[104..112].copy_from_slice(&order.encode(901));
        let source = XattrSources::legacy(&raw, order).unwrap();
        assert_eq!(source.directory, 901);
        assert!(source.inline.is_empty());
        raw[104..112].copy_from_slice(&order.encode(1 << 48));
        assert!(XattrSources::legacy(&raw, order).is_err());
        assert!(XattrSources::legacy(&raw[..263], order).is_err());

        let bonus_attrs = attributes(order, 0o100_640, 17);
        let other_order = if order == Endian::Little {
            Endian::Big
        } else {
            Endian::Little
        };
        let spill_attrs = vec![
            (
                423,
                xdr_xattrs(&[("user.bin", &[0, 255, 65]), ("empty", &[])]),
            ),
            (9, other_order.encode(901).to_vec()),
        ];
        let registry = SaRegistry::from_zaps(
            &[registration("ZPL_DXATTR", 423, 0, 3)],
            &[layout(2, &bonus_attrs), layout(3, &spill_attrs)],
        )
        .unwrap();
        let bonus = packed(2, &bonus_attrs, &[], order);
        assert_eq!(
            registry
                .decode(&bonus, None)
                .unwrap()
                .xattrs()
                .unwrap()
                .directory,
            0
        );
        let spill = packed(3, &spill_attrs, &[423], other_order);
        let decoded = registry.decode(&bonus, Some(&spill)).unwrap();
        assert_eq!(decoded.metadata().unwrap().size, 17);
        let source = decoded.xattrs().unwrap();
        assert_eq!(source.directory, 901);
        assert_eq!(source.inline["user.bin"], [0, 255, 65]);
        assert!(source.inline["empty"].is_empty());
    }
}

#[test]
fn dxattr_values_reject_wrong_native_types_duplicates_tails_and_bounds() {
    let good = xdr_xattrs(&[("user.bin", &[0, 255, 65])]);
    let mut wrong_kind = good.clone();
    wrong_kind[32..36].copy_from_slice(&23_u32.to_be_bytes()); // UINT8_ARRAY is not BYTE_ARRAY.
    let mut trailing = good.clone();
    trailing.extend_from_slice(&[0; 8]);
    let mut corrupt_pad = good.clone();
    corrupt_pad[43] = 1;
    for bytes in [
        wrong_kind,
        trailing,
        corrupt_pad,
        good[..good.len() - 1].to_vec(),
        xdr_xattrs(&[("same", &[]), ("same", &[])]),
        xdr_xattrs(&[(&"x".repeat(256), &[])]),
    ] {
        let attrs = vec![(61, bytes)];
        let registry = SaRegistry::from_zaps(
            &[registration("ZPL_DXATTR", 61, 0, 3)],
            &[layout(2, &attrs)],
        )
        .unwrap();
        assert!(
            registry
                .decode(&packed(2, &attrs, &[61], Endian::Little), None)
                .unwrap()
                .xattrs()
                .is_err()
        );
    }
    let attrs = vec![(61, good)];
    let registry = SaRegistry::from_zaps(
        &[registration("ZPL_DXATTR", 61, 0, 4)],
        &[layout(2, &attrs)],
    )
    .unwrap();
    assert!(
        registry
            .decode(&packed(2, &attrs, &[61], Endian::Little), None)
            .unwrap()
            .xattrs()
            .is_err()
    );
    let attrs = vec![(9, (1_u64 << 48).to_le_bytes().to_vec())];
    let registry = SaRegistry::from_zaps(&[], &[layout(2, &attrs)]).unwrap();
    assert!(
        registry
            .decode(&packed(2, &attrs, &[], Endian::Little), None)
            .unwrap()
            .xattrs()
            .is_err()
    );
}
