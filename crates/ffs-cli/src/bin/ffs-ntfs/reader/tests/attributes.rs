use super::*;

pub(super) fn list_entry(kind: u32, number: u64, id: u16, vcn: u64, name: &str) -> Vec<u8> {
    let name: Vec<u16> = name.encode_utf16().collect();
    let length = (26 + name.len() * 2).next_multiple_of(8);
    let mut entry = vec![0; length];
    entry[..4].copy_from_slice(&kind.to_le_bytes());
    entry[4..6].copy_from_slice(&(length as u16).to_le_bytes());
    entry[6] = name.len() as u8;
    entry[7] = 26;
    entry[8..16].copy_from_slice(&vcn.to_le_bytes());
    entry[16..24].copy_from_slice(&(number | (7_u64 << 48)).to_le_bytes());
    entry[24..26].copy_from_slice(&id.to_le_bytes());
    for (i, unit) in name.iter().enumerate() {
        entry[26 + i * 2..28 + i * 2].copy_from_slice(&unit.to_le_bytes());
    }
    entry
}

pub(super) fn extension(number: u32, owner: u64, attrs: &[Vec<u8>]) -> Vec<u8> {
    let mut record = file_record(number, attrs);
    record[32..40].copy_from_slice(&(owner | (7_u64 << 48)).to_le_bytes());
    record
}

fn first_extent() -> Vec<u8> {
    let mut attr = mapped(&[0x21, 1, 180, 0, 0], 2, 600, 600, 0);
    attr[24..32].copy_from_slice(&0_u64.to_le_bytes());
    attr
}

fn last_extent() -> Vec<u8> {
    let mut attr = mapped(&[0x21, 1, 170, 0, 0], 2, 0, 0, 0);
    attr[14..16].copy_from_slice(&4_u16.to_le_bytes());
    attr[16..24].copy_from_slice(&1_u64.to_le_bytes());
    // These fields are only meaningful in VCN zero. Do not derive final EOF
    // or allocation from an arbitrary continuation header.
    attr[40..64].fill(0xFF);
    attr
}

fn split_image(nonresident_list: bool) -> Image {
    let mut image = Image::new();
    let mut list = list_entry(DATA, 25, 0, 0, "");
    list.extend(list_entry(DATA, 27, 4, 1, ""));
    list.extend(list_entry(DATA, 27, 7, 0, "note"));
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
    image.put_record(25, &file_record(25, &[list_attr, first_extent()]));
    image.put_record(
        27,
        &extension(
            27,
            25,
            &[
                last_extent(),
                resident(DATA, 7, "note", b"extension resident stream"),
            ],
        ),
    );
    image
}

#[test]
fn resident_and_nonresident_lists_assemble_fragmented_and_named_streams() {
    let cx = Cx::for_testing();
    for nonresident in [false, true] {
        let reads: Reads = Arc::default();
        let volume = split_image(nonresident)
            .open(Arc::clone(&reads), None)
            .unwrap();
        let record = volume.record(&cx, 25, Some(7)).unwrap();
        let stream = volume.data_stream(&cx, &record, &[]).unwrap();
        assert_eq!(
            (stream.size, stream.initialized, stream.allocated),
            (600, 600, 1024)
        );
        reads.lock().unwrap().clear();
        let mut expected = vec![b'A'; 512];
        expected.extend_from_slice(&[b'B'; 88]);
        assert_eq!(volume.read(&cx, &stream, 0, 4096).unwrap(), expected);
        assert_eq!(
            *reads.lock().unwrap(),
            [
                (BASE as u64 + 180 * 512, 512),
                (BASE as u64 + 170 * 512, 88)
            ]
        );
        assert_eq!(
            volume.read(&cx, &stream, 510, 100).unwrap(),
            expected[510..]
        );
        assert_eq!(volume.read(&cx, &stream, 600, 100).unwrap(), [] as [u8; 0]);
        let named = volume
            .data_stream(&cx, &record, &[110, 111, 116, 101])
            .unwrap();
        assert!(named.resident());
        assert_eq!(
            volume.read(&cx, &named, 0, 100).unwrap(),
            b"extension resident stream"
        );
    }
}

#[test]
fn repeated_resident_attributes_are_preserved_but_not_selected_as_one_stream() {
    let cx = Cx::for_testing();
    let mut image = Image::new();
    let mut list = list_entry(0x30, 24, 2, 0, "");
    list.extend(list_entry(0x30, 27, 3, 0, ""));
    image.put_record(
        24,
        &file_record(
            24,
            &[
                resident(ATTRIBUTE_LIST, 10, "", &list),
                resident(0x30, 2, "", b"first link"),
            ],
        ),
    );
    image.put_record(
        27,
        &extension(27, 24, &[resident(0x30, 3, "", b"second link")]),
    );
    let volume = image.volume();
    let record = volume.record(&cx, 24, None).unwrap();
    let catalog = volume.attributes(&cx, &record).unwrap();
    let attrs = catalog.all().unwrap();
    assert_eq!(attrs.len(), 2);
    assert_eq!((attrs[0].id, attrs[1].id), (2, 3));
    assert!(catalog.select(&volume.geometry, 0x30, &[]).is_err());
}

#[test]
fn catalog_identity_failures_never_publish_a_stream() {
    let cx = Cx::for_testing();
    for case in 0..10 {
        let mut image = split_image(false);
        let mut list = list_entry(DATA, 25, 0, 0, "");
        let mut last_ref = list_entry(DATA, 27, 4, 1, "");
        let mut continuation = last_extent();
        let mut owner = 25;
        match case {
            0 => last_ref[22..24].copy_from_slice(&8_u16.to_le_bytes()),
            1 => last_ref[24..26].copy_from_slice(&5_u16.to_le_bytes()),
            2 => owner = 24,
            3 => last_ref[8..16].copy_from_slice(&2_u64.to_le_bytes()),
            4 => last_ref[..4].copy_from_slice(&0xA0_u32.to_le_bytes()),
            5 => list.clear(), // The initial DATA extent cannot be omitted.
            6 => {
                // A catalog-consistent VCN gap still cannot be assembled.
                last_ref[8..16].copy_from_slice(&2_u64.to_le_bytes());
                continuation[16..24].copy_from_slice(&2_u64.to_le_bytes());
                continuation[24..32].copy_from_slice(&2_u64.to_le_bytes());
            }
            7 => continuation[66] = 180, // Physical alias across different extents.
            8 => continuation[12..14].copy_from_slice(&SPARSE.to_le_bytes()),
            _ => {
                // Two extents both claim VCN zero.
                last_ref[8..16].fill(0);
                continuation[16..24].fill(0);
                continuation[24..32].fill(0);
                continuation[40..64].fill(0);
            }
        }
        list.extend(last_ref);
        list.extend(list_entry(DATA, 27, 7, 0, "note"));
        image.put_record(
            25,
            &file_record(
                25,
                &[resident(ATTRIBUTE_LIST, 10, "", &list), first_extent()],
            ),
        );
        image.put_record(
            27,
            &extension(
                27,
                owner,
                &[continuation, resident(DATA, 7, "note", b"named")],
            ),
        );
        let volume = image.volume();
        let base = volume.record(&cx, 25, None).unwrap();
        assert!(volume.data_stream(&cx, &base, &[]).is_err(), "case {case}");
    }
}

#[test]
fn missing_unlisted_recursive_and_torn_attributes_are_refused() {
    let cx = Cx::for_testing();
    for case in 0..4 {
        let mut image = split_image(false);
        let mut attrs = vec![last_extent()];
        if case != 0 {
            attrs.push(resident(DATA, 7, "note", b"named"));
        }
        if case == 1 {
            attrs.push(resident(DATA, 8, "unlisted", b"hidden"));
        }
        if case == 2 {
            attrs.push(resident(ATTRIBUTE_LIST, 9, "", &[0; 32]));
        }
        let mut record = extension(27, 25, &attrs);
        if case == 3 {
            record[1023] ^= 1;
        }
        image.put_record(27, &record);
        let volume = image.volume();
        let base = volume.record(&cx, 25, None).unwrap();
        assert!(volume.data_stream(&cx, &base, &[]).is_err(), "case {case}");
    }
}

#[test]
fn extension_io_cancellation_returns_no_mapping_and_does_not_read_payload() {
    let cx = Cx::for_testing();
    let reads: Reads = Arc::default();
    let at = Image::record_offset(27) as u64;
    let volume = split_image(false)
        .open(Arc::clone(&reads), Some(at))
        .unwrap();
    let base = volume.record(&cx, 25, None).unwrap();
    reads.lock().unwrap().clear();
    assert!(matches!(
        volume.data_stream(&cx, &base, &[]),
        Err(FfsError::Cancelled)
    ));
    assert_eq!(*reads.lock().unwrap(), [(at, 1024)]);
}

#[test]
fn split_sparse_streams_keep_holes_and_uninitialized_tails_zero() {
    let cx = Cx::for_testing();
    let mut image = Image::new();
    let mut first = mapped(&[0x21, 1, 200, 0, 0x01, 2, 0], 4, 2035, 1543, SPARSE);
    first[24..32].copy_from_slice(&2_u64.to_le_bytes());
    let mut continuation = mapped(&[0x21, 1, 190, 0, 0], 4, 0, 0, SPARSE);
    continuation[14..16].copy_from_slice(&4_u16.to_le_bytes());
    continuation[16..24].copy_from_slice(&3_u64.to_le_bytes());
    let mut list = list_entry(DATA, 26, 0, 0, "");
    list.extend(list_entry(DATA, 27, 4, 3, ""));
    image.put_record(
        26,
        &file_record(26, &[resident(ATTRIBUTE_LIST, 10, "", &list), first]),
    );
    image.put_record(27, &extension(27, 26, &[continuation]));
    let reads: Reads = Arc::default();
    let volume = image.open(Arc::clone(&reads), None).unwrap();
    let base = volume.record(&cx, 26, None).unwrap();
    let stream = volume.data_stream(&cx, &base, &[]).unwrap();
    reads.lock().unwrap().clear();
    let mut expected = vec![0; 2035];
    expected[..512].fill(b'C');
    expected[1536..1543].fill(b'D');
    assert_eq!(stream.allocated, 1024);
    assert_eq!(volume.read(&cx, &stream, 0, 4096).unwrap(), expected);
    assert_eq!(
        *reads.lock().unwrap(),
        [(BASE as u64 + 200 * 512, 512), (BASE as u64 + 190 * 512, 7)]
    );
}

#[test]
fn extension_reads_leave_file_backing_and_adjacent_regions_unchanged() {
    let image = split_image(true);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("disk.img");
    std::fs::write(&path, &image.bytes).unwrap();
    let cx = Cx::for_testing();
    let volume = NtfsVolume::open(&cx, &path, BASE as u64, Some(LENGTH as u64)).unwrap();
    let record = volume.record(&cx, 25, None).unwrap();
    let stream = volume.data_stream(&cx, &record, &[]).unwrap();
    assert_eq!(volume.read(&cx, &stream, 510, 4).unwrap(), b"AABB");
    assert_eq!(std::fs::read(&path).unwrap(), image.bytes);
}

fn split_mft_image(nonresident_list: bool) -> Image {
    let mut image = Image::new();
    // The middle mapping is stored in record 24, which becomes readable only
    // after the higher-VCN extent in already-reachable record 1 is discovered.
    let mut list = list_entry(DATA, 0, 0, 0, "");
    list.extend(list_entry(DATA, 24, 4, 16, ""));
    list.extend(list_entry(DATA, 1, 5, 32, ""));
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
    let mut first = mapped(&[0x11, 16, 4, 0], 64, 32_768, 32_768, 0);
    first[24..32].copy_from_slice(&15_u64.to_le_bytes());
    let base = file_record(0, &[list_attr, first]);
    image.put_record(0, &base);
    image.bytes[BASE + 128 * 512..BASE + 130 * 512].copy_from_slice(&base);
    let mut middle = mapped(&[0x11, 16, 40, 0], 32, 0, 0, 0);
    middle[14..16].copy_from_slice(&4_u16.to_le_bytes());
    middle[16..24].copy_from_slice(&16_u64.to_le_bytes());
    image.put_record(24, &extension(24, 0, &[middle]));
    let mut continuation = mapped(&[0x11, 32, 56, 0], 64, 0, 0, 0);
    continuation[14..16].copy_from_slice(&5_u16.to_le_bytes());
    continuation[16..24].copy_from_slice(&32_u64.to_le_bytes());
    image.put_record(1, &extension(1, 0, &[continuation]));
    image
}

#[test]
fn mft_bootstrap_resolves_out_of_order_extent_dependencies() {
    let cx = Cx::for_testing();
    for nonresident in [false, true] {
        let reads: Reads = Arc::default();
        let volume = split_mft_image(nonresident)
            .open(Arc::clone(&reads), None)
            .unwrap();
        assert_eq!(volume.record_count(), 32);
        let record = volume.record(&cx, 25, Some(7)).unwrap();
        let stream = volume.data_stream(&cx, &record, &[]).unwrap();
        assert_eq!(volume.read(&cx, &stream, 510, 4).unwrap(), b"AABB");
        let trace = reads.lock().unwrap();
        let before = trace
            .iter()
            .position(|(at, _)| *at == Image::record_offset(1) as u64)
            .unwrap();
        let after = trace
            .iter()
            .position(|(at, _)| *at == Image::record_offset(24) as u64)
            .unwrap();
        assert!(
            before < after,
            "record 24 must not be guessed from boot arithmetic"
        );
    }
}

#[test]
fn mft_bootstrap_deadlocks_fail_without_guessing_record_locations() {
    let mut image = Image::new();
    let mut list = list_entry(DATA, 0, 0, 0, "");
    list.extend(list_entry(DATA, 24, 4, 16, ""));
    let mut first = mapped(&[0x11, 16, 4, 0], 64, 32_768, 32_768, 0);
    first[24..32].copy_from_slice(&15_u64.to_le_bytes());
    let base = file_record(0, &[resident(ATTRIBUTE_LIST, 10, "", &list), first]);
    image.put_record(0, &base);
    image.bytes[BASE + 128 * 512..BASE + 130 * 512].copy_from_slice(&base);
    let reads: Reads = Arc::default();
    let result = image.open(Arc::clone(&reads), None);
    assert!(matches!(result, Err(FfsError::Corruption { .. })));
    assert!(
        !reads
            .lock()
            .unwrap()
            .iter()
            .any(|(at, _)| *at == Image::record_offset(24) as u64)
    );
}

#[test]
fn mft_extension_identity_fixup_and_cancellation_fail_before_publication() {
    for case in 0..4 {
        let mut image = split_mft_image(false);
        let at = Image::record_offset(1);
        match case {
            0 => image.bytes[at + 16] = 8,    // stale generation
            1 => image.bytes[at + 32] = 24,   // foreign owner
            2 => image.bytes[at + 1023] ^= 1, // torn sector
            _ => {}
        }
        let fail = (case == 3).then_some(at as u64);
        let result = image.open(Arc::default(), fail);
        if case == 3 {
            assert!(matches!(result, Err(FfsError::Cancelled)));
        } else {
            assert!(matches!(result, Err(FfsError::Corruption { .. })));
        }
    }
}
