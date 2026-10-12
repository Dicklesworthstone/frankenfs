use super::attributes::{extension, list_entry};
use super::*;
use ffs_ondisk::ntfs::{EA, EA_INFORMATION};

fn value(entries: &[(&[u8], &[u8], u8)]) -> (Vec<u8>, Vec<u8>) {
    let mut bytes = Vec::new();
    let mut packed = 0_u16;
    let mut needed = 0_u16;
    for &(name, data, flags) in entries {
        let used = 9 + name.len() + data.len();
        let length = used.next_multiple_of(4);
        let mut entry = vec![0xDC; length];
        entry[..4].copy_from_slice(&(length as u32).to_le_bytes());
        entry[4] = flags;
        entry[5] = name.len() as u8;
        entry[6..8].copy_from_slice(&(data.len() as u16).to_le_bytes());
        entry[8..8 + name.len()].copy_from_slice(name);
        entry[8 + name.len()] = 0;
        entry[9 + name.len()..used].copy_from_slice(data);
        bytes.extend(entry);
        packed += (used - 4) as u16;
        needed += u16::from(flags & 0x80 != 0);
    }
    let mut info = vec![0; 8];
    info[..2].copy_from_slice(&packed.to_le_bytes());
    info[2..4].copy_from_slice(&needed.to_le_bytes());
    info[4..].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
    (info, bytes)
}

fn ea_mapped(pairs: &[u8], size: usize, initialized: usize) -> Vec<u8> {
    let mut attr = mapped(pairs, 2, size as u64, initialized as u64, 0);
    attr[..4].copy_from_slice(&EA.to_le_bytes());
    attr[14..16].copy_from_slice(&2_u16.to_le_bytes());
    attr
}

fn split_image(nonresident_list: bool) -> (Image, Vec<u8>) {
    let mut image = Image::new();
    let payload: Vec<_> = (0..700).map(|offset| (offset % 251) as u8).collect();
    let (info, bytes) = value(&[
        (b"user.large", &payload, 0x80),
        (b"other", &[0, 0xFF, 2], 0),
    ]);
    image.bytes[BASE + 180 * 512..BASE + 181 * 512].copy_from_slice(&bytes[..512]);
    image.bytes[BASE + 170 * 512..BASE + 170 * 512 + bytes.len() - 512]
        .copy_from_slice(&bytes[512..]);
    let mut first = ea_mapped(&[0x21, 1, 180, 0, 0], bytes.len(), bytes.len());
    first[24..32].copy_from_slice(&0_u64.to_le_bytes());
    let mut last = ea_mapped(&[0x21, 1, 170, 0, 0], 0, 0);
    last[14..16].copy_from_slice(&3_u16.to_le_bytes());
    last[16..24].copy_from_slice(&1_u64.to_le_bytes());
    last[40..64].fill(0xFF); // Continuation sizes are not authoritative.
    let mut list = list_entry(DATA, 25, 0, 0, "");
    list.extend(list_entry(EA_INFORMATION, 27, 1, 0, ""));
    list.extend(list_entry(EA, 27, 2, 0, ""));
    list.extend(list_entry(EA, 28, 3, 1, ""));
    let list_attr = if nonresident_list {
        image.bytes[BASE + 210 * 512..BASE + 210 * 512 + list.len()].copy_from_slice(&list);
        let mut attr = mapped(
            &[0x21, 1, 210, 0, 0],
            1,
            list.len() as u64,
            list.len() as u64,
            0,
        );
        attr[..4].copy_from_slice(&ATTRIBUTE_LIST.to_le_bytes());
        attr[14..16].copy_from_slice(&10_u16.to_le_bytes());
        attr
    } else {
        resident(ATTRIBUTE_LIST, 10, "", &list)
    };
    image.put_record(
        25,
        &file_record(25, &[list_attr, resident(DATA, 0, "", b"ordinary DATA")]),
    );
    image.put_record(
        27,
        &extension(27, 25, &[resident(EA_INFORMATION, 1, "", &info), first]),
    );
    image.put_record(28, &extension(28, 25, &[last]));
    (image, payload)
}

#[test]
fn resident_eas_are_binary_metadata_on_files_directories_and_efs_objects() {
    let cx = Cx::for_testing();
    for (directory, standard_flags) in [(false, 0), (true, 0), (false, 0x4000_u32)] {
        let mut image = Image::new();
        let (info, bytes) = value(&[
            (b"user.note", &[0, 0xFF, 1], 0x80),
            (b"$LXUID", &[123, 0, 0, 0], 0),
            (&[0x82, b'A'], &[], 0),
        ]);
        let mut standard = [0; 72];
        standard[32..36].copy_from_slice(&standard_flags.to_le_bytes());
        let mut raw = file_record(
            24,
            &[
                resident(0x10, 3, "", &standard),
                resident(EA_INFORMATION, 1, "", &info),
                resident(EA, 2, "", &bytes),
                resident(DATA, 0, "", b"DATA is not an EA"),
                resident(DATA, 4, "user.note", b"ADS is not an EA"),
            ],
        );
        if directory {
            raw[22..24].copy_from_slice(&3_u16.to_le_bytes());
        }
        image.put_record(24, &raw);
        let reads: Reads = Arc::default();
        let volume = image.open(Arc::clone(&reads), None).unwrap();
        let record = volume.record(&cx, 24, Some(7)).unwrap();
        reads.lock().unwrap().clear();
        let catalog = volume.extended_attributes(&cx, &record).unwrap();
        assert_eq!(catalog.entries.len(), 3);
        assert_eq!(catalog.information.unwrap().need_ea_count, 1);
        assert_eq!(catalog.find(b"user.note").unwrap().value, [0, 0xFF, 1]);
        assert_eq!(
            catalog.find(b"$LXUID").unwrap().value,
            123_u32.to_le_bytes()
        );
        assert!(catalog.find(&[0x82, b'A']).unwrap().value.is_empty());
        assert!(catalog.find(b"USER.NOTE").is_none());
        assert!(reads.lock().unwrap().is_empty());
        if standard_flags != 0 {
            assert!(matches!(
                volume.data_stream(&cx, &record, &[]),
                Err(FfsError::UnsupportedFeature(_))
            ));
        }
    }
    let volume = Image::new().volume();
    let record = volume.record(&cx, 24, Some(7)).unwrap();
    let catalog = volume.extended_attributes(&cx, &record).unwrap();
    assert!(catalog.information.is_none() && catalog.entries.is_empty());
}

#[test]
fn extension_only_eas_follow_complete_lists_and_fragmented_streams_without_slack() {
    let cx = Cx::for_testing();
    for nonresident in [false, true] {
        let (image, payload) = split_image(nonresident);
        let reads: Reads = Arc::default();
        let volume = image.open(Arc::clone(&reads), None).unwrap();
        let record = volume.record(&cx, 25, Some(7)).unwrap();
        reads.lock().unwrap().clear();
        let catalog = volume.extended_attributes(&cx, &record).unwrap();
        assert_eq!(catalog.entries.len(), 2);
        assert_eq!(catalog.find(b"user.large").unwrap().value, payload);
        assert_eq!(catalog.find(b"other").unwrap().value, [0, 0xFF, 2]);
        let size = catalog.information.unwrap().unpacked_bytes as usize;
        let reads = reads.lock().unwrap();
        assert_eq!(
            &reads[reads.len() - 2..],
            &[
                (BASE as u64 + 180 * 512, 512),
                (BASE as u64 + 170 * 512, size - 512),
            ]
        );
        assert!(reads.iter().all(|(offset, length)| *offset >= BASE as u64
            && *offset + *length as u64 <= (BASE + LENGTH) as u64));
    }
}

#[test]
fn ea_catalog_rejects_foreign_generations_and_direct_extension_selection() {
    let cx = Cx::for_testing();
    for (at, bytes) in [
        (16, 8_u16.to_le_bytes().to_vec()),
        (32, (24_u64 | (7_u64 << 48)).to_le_bytes().to_vec()),
        (32, (25_u64 | (8_u64 << 48)).to_le_bytes().to_vec()),
    ] {
        let (mut image, _) = split_image(false);
        let offset = Image::record_offset(28) + at;
        image.bytes[offset..offset + bytes.len()].copy_from_slice(&bytes);
        let volume = image.volume();
        let record = volume.record(&cx, 25, Some(7)).unwrap();
        assert!(matches!(
            volume.extended_attributes(&cx, &record),
            Err(FfsError::Corruption { .. })
        ));
    }
    let (image, _) = split_image(false);
    let volume = image.volume();
    let extension = volume.record(&cx, 27, Some(7)).unwrap();
    assert!(matches!(
        volume.extended_attributes(&cx, &extension),
        Err(FfsError::UnsupportedFeature(_))
    ));
}

#[test]
fn malformed_ea_pairs_sizes_and_storage_flags_never_read_a_data_payload() {
    let cx = Cx::for_testing();
    let (info, bytes) = value(&[(b"user.one", b"ready", 0)]);
    let good_info = resident(EA_INFORMATION, 1, "", &info);
    let good_ea = resident(EA, 2, "", &bytes);
    let mut transformed = good_ea.clone();
    transformed[12..14].copy_from_slice(&SPARSE.to_le_bytes());
    let mut huge_info = info.clone();
    huge_info[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    let mut nonresident_info = mapped(&[0x21, 1, 180, 0, 0], 1, 8, 8, 0);
    nonresident_info[..4].copy_from_slice(&EA_INFORMATION.to_le_bytes());
    for attributes in [
        vec![good_info.clone()],
        vec![good_ea.clone()],
        vec![
            good_info.clone(),
            resident(EA_INFORMATION, 3, "", &info),
            good_ea.clone(),
        ],
        vec![resident(EA_INFORMATION, 1, "named", &info), good_ea.clone()],
        vec![good_info.clone(), resident(EA, 2, "named", &bytes)],
        vec![resident(EA_INFORMATION, 1, "", &huge_info), good_ea.clone()],
        vec![nonresident_info, good_ea.clone()],
        vec![good_info.clone(), transformed],
        vec![
            good_info.clone(),
            good_ea.clone(),
            resident(EA, 3, "", &bytes),
        ],
        vec![
            good_info.clone(),
            ea_mapped(&[0x21, 2, 180, 0, 0], bytes.len(), bytes.len() - 1),
        ],
        vec![
            good_info.clone(),
            ea_mapped(&[0x21, 2, 180, 0, 0], bytes.len() + 1, bytes.len() + 1),
        ],
        vec![
            good_info,
            ea_mapped(&[0x01, 2, 0], bytes.len(), bytes.len()),
        ],
    ] {
        let mut image = Image::new();
        image.put_record(24, &file_record(24, &attributes));
        let reads: Reads = Arc::default();
        let volume = image.open(Arc::clone(&reads), None).unwrap();
        let record = volume.record(&cx, 24, Some(7)).unwrap();
        reads.lock().unwrap().clear();
        assert!(volume.extended_attributes(&cx, &record).is_err());
        assert!(reads.lock().unwrap().is_empty());
    }
}

#[test]
fn cancellation_and_malformed_tail_never_return_an_earlier_valid_ea() {
    let cx = Cx::for_testing();
    for at in [Image::record_offset(28) as u64, BASE as u64 + 170 * 512] {
        let (image, _) = split_image(false);
        let volume = image.open(Arc::default(), Some(at)).unwrap();
        let record = volume.record(&cx, 25, Some(7)).unwrap();
        assert!(matches!(
            volume.extended_attributes(&cx, &record),
            Err(FfsError::Cancelled)
        ));
    }
    let (mut image, _) = split_image(false);
    // The first 720-byte EA is valid; corrupt only the second EA's flags.
    image.bytes[BASE + 170 * 512 + 720 - 512 + 4] = 1;
    let volume = image.volume();
    let record = volume.record(&cx, 25, Some(7)).unwrap();
    assert!(matches!(
        volume.extended_attributes(&cx, &record),
        Err(FfsError::Corruption { .. })
    ));
}
