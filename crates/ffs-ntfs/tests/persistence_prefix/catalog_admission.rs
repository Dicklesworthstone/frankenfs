//! Mutation admission must validate native FILE_NAME metadata before staging
//! either payload or journal writes, including names in extension records.

use super::{
    Arc, ByteDevice, ByteOffset, CLUSTER_BYTES, Cx, DEFAULT_FILETIME, FaultInjectingNtfsDevice,
    FfsError, NtfsFileRecord, NtfsReference, NtfsTransactionEngine, NtfsTxOutcome, RECORD_BYTES,
    SECTOR_BYTES, assert_native_hard_links, build_clean_ntfs_image, build_file_record,
    build_nonresident_attr, build_resident_attr, copied_test_record_attributes,
    write_options_clean,
};
use ffs_ondisk::ntfs::attribute_list::{NtfsAttributeListEntry, encode_attribute_list};
use ffs_ondisk::ntfs::{ATTRIBUTE_LIST, REPARSE_POINT, SPARSE};

fn attribute_list_entry(attribute: &[u8], reference: NtfsReference) -> NtfsAttributeListEntry {
    let name_at = usize::from(u16::from_le_bytes(attribute[10..12].try_into().unwrap()));
    let name = (0..usize::from(attribute[9]))
        .map(|index| {
            let at = name_at + index * 2;
            u16::from_le_bytes(attribute[at..at + 2].try_into().unwrap())
        })
        .collect();
    NtfsAttributeListEntry {
        kind: u32::from_le_bytes(attribute[..4].try_into().unwrap()),
        name,
        first_vcn: 0,
        reference,
        id: u16::from_le_bytes(attribute[14..16].try_into().unwrap()),
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn catalog_rejects_malformed_file_names_in_base_and_extension_before_any_write() {
    let cx = Cx::for_testing();
    let image = build_clean_ntfs_image(256, 64, 0xCA7A_1000_0000_0001);
    let length = image.len() as u64 - SECTOR_BYTES as u64;
    let seed = FaultInjectingNtfsDevice::new(image);
    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&seed) as Arc<dyn ByteDevice>,
        0,
        length,
        write_options_clean(),
    )
    .unwrap();
    let (reference, _) = engine
        .create_file(&cx, "/", "source", b"kept")
        .into_result()
        .unwrap();
    let clean = seed.snapshot_durable_only();
    let offset = CLUSTER_BYTES + usize::try_from(reference.record).unwrap() * RECORD_BYTES;

    for extension in [false, true] {
        for shape in [
            "unindexed",
            "invalid-indexed-bit",
            "reserved-byte",
            "named-attribute",
            "transformed-attribute",
            "nonresident-attribute",
            "duplicate-identity",
            "duplicate-with-different-sizes",
            "zero-link-count",
            "overstated-link-count",
            "maximum-link-count",
        ] {
            // Corrupt after writable admission to exercise each mutation's own
            // catalog checks, rather than relying on mount-time consistency.
            let device = FaultInjectingNtfsDevice::new(clean.clone());
            let mut engine = NtfsTransactionEngine::from_device(
                &cx,
                Arc::clone(&device) as Arc<dyn ByteDevice>,
                0,
                length,
                write_options_clean(),
            )
            .unwrap();
            let mut attributes =
                copied_test_record_attributes(&clean[offset..offset + RECORD_BYTES]);
            let position = attributes
                .iter()
                .position(|attribute| attribute[..4] == 0x30_u32.to_le_bytes())
                .unwrap();
            let mut changed_name = attributes[position].clone();
            let duplicate = shape.starts_with("duplicate");
            let mut links = if duplicate { 2 } else { 1 };
            match shape {
                "unindexed" => changed_name[22] = 0,
                "invalid-indexed-bit" => changed_name[22] = 2,
                "reserved-byte" => changed_name[23] = 1,
                "named-attribute" => {
                    let value_at =
                        usize::from(u16::from_le_bytes(changed_name[20..22].try_into().unwrap()));
                    let value_len =
                        u32::from_le_bytes(changed_name[16..20].try_into().unwrap()) as usize;
                    changed_name = build_resident_attr(
                        0x30,
                        30,
                        &[u16::from(b'x')],
                        true,
                        &changed_name[value_at..value_at + value_len],
                    );
                }
                "transformed-attribute" => {
                    changed_name[12..14].copy_from_slice(&SPARSE.to_le_bytes());
                }
                "nonresident-attribute" => {
                    changed_name = build_nonresident_attr(0x30, 30, &[], 255, 1, 80, 256);
                }
                "duplicate-identity" => {}
                "duplicate-with-different-sizes" => {
                    let value_at =
                        usize::from(u16::from_le_bytes(changed_name[20..22].try_into().unwrap()));
                    changed_name[value_at + 48..value_at + 56]
                        .copy_from_slice(&999_u64.to_le_bytes());
                }
                "zero-link-count" => links = 0,
                "overstated-link-count" => links = 2,
                "maximum-link-count" => links = u16::MAX,
                _ => unreachable!(),
            }
            changed_name[14..16].copy_from_slice(&30_u16.to_le_bytes());

            if extension {
                if !duplicate {
                    attributes.remove(position);
                }
                let extension_ref = NtfsReference {
                    record: 31,
                    sequence: 1,
                };
                let mut entries: Vec<_> = attributes
                    .iter()
                    .map(|attribute| attribute_list_entry(attribute, reference))
                    .collect();
                entries.push(attribute_list_entry(&changed_name, extension_ref));
                attributes.push(build_resident_attr(
                    ATTRIBUTE_LIST,
                    31,
                    &[],
                    false,
                    &encode_attribute_list(&entries).unwrap(),
                ));
                let mut extension_record = build_file_record(31, 1, 0, false, &[changed_name]);
                extension_record[32..40]
                    .copy_from_slice(&reference.encode().unwrap().to_le_bytes());
                device
                    .write_all_at(
                        &cx,
                        ByteOffset((CLUSTER_BYTES + 31 * RECORD_BYTES) as u64),
                        &extension_record,
                    )
                    .unwrap();

                // Allocate the extension in both $MFT and its mirror, so its
                // header/identity is the only intentionally invalid metadata.
                let mut mft_attributes = copied_test_record_attributes(
                    &clean[CLUSTER_BYTES..CLUSTER_BYTES + RECORD_BYTES],
                );
                let bitmap = mft_attributes
                    .iter_mut()
                    .find(|attribute| attribute[..4] == 0xB0_u32.to_le_bytes())
                    .unwrap();
                let value_at = usize::from(u16::from_le_bytes(bitmap[20..22].try_into().unwrap()));
                bitmap[value_at + 3] |= 0x80;
                let mft = build_file_record(0, 1, 0, false, &mft_attributes);
                for at in [CLUSTER_BYTES, 9 * CLUSTER_BYTES] {
                    device
                        .write_all_at(&cx, ByteOffset(at as u64), &mft)
                        .unwrap();
                }
            } else if duplicate {
                attributes.push(changed_name);
            } else {
                attributes[position] = changed_name;
            }
            attributes
                .sort_by_key(|attribute| u32::from_le_bytes(attribute[..4].try_into().unwrap()));
            let changed = build_file_record(
                reference.record as u32,
                reference.sequence,
                links,
                false,
                &attributes,
            );
            device
                .write_all_at(&cx, ByteOffset(offset as u64), &changed)
                .unwrap();
            device.sync(&cx).unwrap();
            let before = device.snapshot_durable_only();
            let writes = device.write_bytes_total();
            let events = engine.persistence_trace().len();
            for operation in ["empty-write", "write", "same-size-truncate", "create-ads"] {
                let result = match operation {
                    "empty-write" => engine
                        .write_stream_at(&cx, reference, &[], 0, b"", false, DEFAULT_FILETIME)
                        .into_result()
                        .map(|_| ()),
                    "write" => engine
                        .write_stream_at(&cx, reference, &[], 0, b"new", false, DEFAULT_FILETIME)
                        .into_result()
                        .map(|_| ()),
                    "same-size-truncate" => engine
                        .truncate_stream_at(&cx, reference, &[], 4, DEFAULT_FILETIME)
                        .into_result()
                        .map(|_| ()),
                    "create-ads" => engine
                        .write_stream_at(
                            &cx,
                            reference,
                            &[u16::from(b'x')],
                            0,
                            b"new stream",
                            true,
                            DEFAULT_FILETIME,
                        )
                        .into_result()
                        .map(|_| ()),
                    _ => unreachable!(),
                };
                let detail = if duplicate {
                    "NTFS mutation requires unambiguous native link identities"
                } else if shape.ends_with("link-count") {
                    "NTFS FILE_NAME catalog does not match the supported native link count"
                } else {
                    "NTFS FILE_NAME mutation requires an ordinary indexed resident attribute"
                };
                assert!(
                    matches!(&result, Err(FfsError::UnsupportedFeature(message)) if message == detail),
                    "extension={extension}, shape={shape}, operation={operation}: {result:?}"
                );
                assert_eq!(device.write_bytes_total(), writes);
                assert_eq!(device.snapshot_live(), before);
                assert_eq!(device.snapshot_durable_only(), before);
                assert_eq!(engine.persistence_trace().len(), events);
            }
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn catalog_rejects_orphan_reparse_marker_before_any_direct_mutation() {
    use ffs_ondisk::ntfs::reparse::{NtfsReparseData, NtfsReparsePoint};

    fn assert_refused<T: std::fmt::Debug>(operation: &str, outcome: &NtfsTxOutcome<T>) {
        assert!(
            matches!(
                outcome,
                NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(detail))
                    if detail == "NTFS reparse FILE attribute has no REPARSE_POINT metadata"
            ),
            "{operation} must refuse the orphan reparse marker before publication: {outcome:?}"
        );
    }

    let cx = Cx::for_testing();
    let image = build_clean_ntfs_image(256, 64, 0xCA7A_1000_0000_0004);
    let length = image.len() as u64 - SECTOR_BYTES as u64;
    let seed = FaultInjectingNtfsDevice::new(image);
    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&seed) as Arc<dyn ByteDevice>,
        0,
        length,
        write_options_clean(),
    )
    .unwrap();
    let payload = vec![0x51; 2 * CLUSTER_BYTES + 17];
    let (reference, _) = engine
        .create_file(&cx, "/", "provider", &payload)
        .into_result()
        .unwrap();
    let point = NtfsReparsePoint {
        tag: 0x9000_101A,
        guid: None,
        data: NtfsReparseData::Opaque(vec![0xFE, 0xCA, 0x01, 0x02]),
    };
    engine
        .set_reparse_point_at(&cx, reference, &point, true, DEFAULT_FILETIME)
        .into_result()
        .unwrap();
    let kept: Vec<_> = "kept".encode_utf16().collect();
    // A present opaque provider remains admissible for named-stream creation
    // and ordinary metadata updates; this guard must not reject all reparses.
    engine
        .create_stream_at(&cx, reference, &kept, b"kept ADS", DEFAULT_FILETIME)
        .into_result()
        .unwrap();
    engine
        .set_attributes_at(
            &cx,
            reference,
            &ffs_ntfs::NtfsSetAttributes {
                mtime_ticks: Some(DEFAULT_FILETIME + 9),
                ..ffs_ntfs::NtfsSetAttributes::default()
            },
            DEFAULT_FILETIME + 10,
        )
        .into_result()
        .unwrap();
    engine.check_clean_consistency(&cx).unwrap();

    let clean = seed.snapshot_durable_only();
    let device = FaultInjectingNtfsDevice::new(clean.clone());
    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&device) as Arc<dyn ByteDevice>,
        0,
        length,
        write_options_clean(),
    )
    .unwrap();
    let offset = CLUSTER_BYTES + usize::try_from(reference.record).unwrap() * RECORD_BYTES;
    let mut attributes = copied_test_record_attributes(&clean[offset..offset + RECORD_BYTES]);
    let position = attributes
        .iter()
        .position(|attribute| attribute[..4] == REPARSE_POINT.to_le_bytes())
        .unwrap();
    let reparse = attributes.remove(position);
    let value_at = usize::from(u16::from_le_bytes(reparse[20..22].try_into().unwrap()));
    let value_len = u32::from_le_bytes(reparse[16..20].try_into().unwrap()) as usize;
    assert_eq!(
        reparse[value_at..value_at + value_len],
        point.encode().unwrap()
    );
    // Remove only the provider metadata after clean admission. The FILE's
    // reparse marker and every native name/index identity remain unchanged.
    let changed = build_file_record(
        reference.record as u32,
        reference.sequence,
        1,
        false,
        &attributes,
    );
    device
        .write_all_at(&cx, ByteOffset(offset as u64), &changed)
        .unwrap();
    device.sync(&cx).unwrap();
    let before = device.snapshot_durable_only();
    let writes = device.write_bytes_total();
    let events = engine.persistence_trace().len();
    let new_stream: Vec<_> = "blocked".encode_utf16().collect();
    for operation in [
        "write",
        "empty-write",
        "truncate",
        "same-size-truncate",
        "named-write",
        "named-truncate",
        "create-ads",
        "punch-hole",
        "named-punch-hole",
        "compound-setattr",
    ] {
        match operation {
            "write" => assert_refused(
                operation,
                &engine.write_stream_at(&cx, reference, &[], 1, b"new", false, DEFAULT_FILETIME),
            ),
            "empty-write" => assert_refused(
                operation,
                &engine.write_stream_at(
                    &cx,
                    reference,
                    &[],
                    u64::MAX,
                    b"",
                    false,
                    DEFAULT_FILETIME,
                ),
            ),
            "truncate" => assert_refused(
                operation,
                &engine.truncate_stream_at(&cx, reference, &[], 4, DEFAULT_FILETIME),
            ),
            "same-size-truncate" => assert_refused(
                operation,
                &engine.truncate_stream_at(
                    &cx,
                    reference,
                    &[],
                    payload.len() as u64,
                    DEFAULT_FILETIME,
                ),
            ),
            "named-write" => assert_refused(
                operation,
                &engine.write_stream_at(&cx, reference, &kept, 0, b"new", false, DEFAULT_FILETIME),
            ),
            "named-truncate" => assert_refused(
                operation,
                &engine.truncate_stream_at(&cx, reference, &kept, 1, DEFAULT_FILETIME),
            ),
            "create-ads" => assert_refused(
                operation,
                &engine.create_stream_at(&cx, reference, &new_stream, b"new ADS", DEFAULT_FILETIME),
            ),
            "punch-hole" => assert_refused(
                operation,
                &engine.punch_hole_at(
                    &cx,
                    reference,
                    &[],
                    1,
                    CLUSTER_BYTES as u64,
                    DEFAULT_FILETIME,
                ),
            ),
            "named-punch-hole" => assert_refused(
                operation,
                &engine.punch_hole_at(&cx, reference, &kept, 1, 2, DEFAULT_FILETIME),
            ),
            "compound-setattr" => assert_refused(
                operation,
                &engine.set_attributes_at(
                    &cx,
                    reference,
                    &ffs_ntfs::NtfsSetAttributes {
                        size: Some(1),
                        read_only: Some(true),
                        mtime_ticks: Some(DEFAULT_FILETIME + 17),
                        ..ffs_ntfs::NtfsSetAttributes::default()
                    },
                    DEFAULT_FILETIME + 18,
                ),
            ),
            _ => unreachable!(),
        }
        assert_eq!(device.write_bytes_total(), writes, "{operation}");
        assert_eq!(device.snapshot_live(), before, "{operation}");
        assert_eq!(device.snapshot_durable_only(), before, "{operation}");
        assert_eq!(engine.persistence_trace().len(), events, "{operation}");
        assert!(!engine.requires_recovery(), "{operation}");
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn catalog_uses_complete_base_link_count_with_extension_names() {
    let cx = Cx::for_testing();
    let image = build_clean_ntfs_image(256, 64, 0xCA7A_1000_0000_0002);
    let length = image.len() as u64 - SECTOR_BYTES as u64;
    let seed = FaultInjectingNtfsDevice::new(image);
    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&seed) as Arc<dyn ByteDevice>,
        0,
        length,
        write_options_clean(),
    )
    .unwrap();
    let (reference, _) = engine
        .create_file(&cx, "/", "source", b"kept")
        .into_result()
        .unwrap();
    engine
        .link_file(&cx, "/source", "/", "alias")
        .into_result()
        .unwrap();
    let mut image = seed.snapshot_durable_only();
    let offset = CLUSTER_BYTES + usize::try_from(reference.record).unwrap() * RECORD_BYTES;
    let mut attributes = copied_test_record_attributes(&image[offset..offset + RECORD_BYTES]);
    let name_position = attributes
        .iter()
        .position(|attribute| attribute[..4] == 0x30_u32.to_le_bytes())
        .unwrap();
    let mut moved_name = attributes.remove(name_position);
    moved_name[14..16].copy_from_slice(&30_u16.to_le_bytes());
    let extension_ref = NtfsReference {
        record: 31,
        sequence: 1,
    };
    let mut entries: Vec<_> = attributes
        .iter()
        .map(|attribute| attribute_list_entry(attribute, reference))
        .collect();
    entries.push(attribute_list_entry(&moved_name, extension_ref));
    attributes.push(build_resident_attr(
        ATTRIBUTE_LIST,
        31,
        &[],
        false,
        &encode_attribute_list(&entries).unwrap(),
    ));
    attributes.sort_by_key(|attribute| u32::from_le_bytes(attribute[..4].try_into().unwrap()));
    let base = build_file_record(
        reference.record as u32,
        reference.sequence,
        2,
        false,
        &attributes,
    );
    image[offset..offset + RECORD_BYTES].copy_from_slice(&base);
    // The base counts both FILE_NAMEs; the extension has one name but its
    // header count is zero. Per-record equality would reject this valid file.
    let mut extension = build_file_record(31, 1, 0, false, &[moved_name]);
    extension[32..40].copy_from_slice(&reference.encode().unwrap().to_le_bytes());
    let extension_at = CLUSTER_BYTES + 31 * RECORD_BYTES;
    image[extension_at..extension_at + RECORD_BYTES].copy_from_slice(&extension);
    let mut mft_attributes =
        copied_test_record_attributes(&image[CLUSTER_BYTES..CLUSTER_BYTES + RECORD_BYTES]);
    let bitmap = mft_attributes
        .iter_mut()
        .find(|attribute| attribute[..4] == 0xB0_u32.to_le_bytes())
        .unwrap();
    let value_at = usize::from(u16::from_le_bytes(bitmap[20..22].try_into().unwrap()));
    assert_eq!(bitmap[value_at + 3] & 0x80, 0);
    bitmap[value_at + 3] |= 0x80;
    let mft = build_file_record(0, 1, 0, false, &mft_attributes);
    for at in [CLUSTER_BYTES, 9 * CLUSTER_BYTES] {
        image[at..at + RECORD_BYTES].copy_from_slice(&mft);
    }

    for links in [0_u16, 1, 2, 3, u16::MAX] {
        let device = FaultInjectingNtfsDevice::new(image.clone());
        let mut engine = NtfsTransactionEngine::from_device(
            &cx,
            Arc::clone(&device) as Arc<dyn ByteDevice>,
            0,
            length,
            write_options_clean(),
        )
        .expect("complete two-name base/extension catalog must pass all native checkers");
        device
            .write_all_at(&cx, ByteOffset((offset + 18) as u64), &links.to_le_bytes())
            .unwrap();
        device.sync(&cx).unwrap();
        let before = device.snapshot_durable_only();
        let writes = device.write_bytes_total();
        let events = engine.persistence_trace().len();
        let result = engine.write_stream_at(
            &cx,
            reference,
            &[],
            4,
            b" together",
            false,
            DEFAULT_FILETIME,
        );
        if links == 2 {
            result.into_result().unwrap();
            engine.check_clean_consistency(&cx).unwrap();
            assert_native_hard_links(
                &device.snapshot_durable_only(),
                reference,
                &["/source", "/alias"],
                b"kept together",
            );
        } else {
            assert!(
                matches!(
                    &result,
                    NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(detail))
                        if detail == "NTFS FILE_NAME catalog does not match the supported native link count"
                ),
                "links={links}: {result:?}"
            );
            assert_eq!(device.write_bytes_total(), writes);
            assert_eq!(device.snapshot_live(), before);
            assert_eq!(device.snapshot_durable_only(), before);
            assert_eq!(engine.persistence_trace().len(), events);
        }
    }
}

#[test]
fn catalog_preserves_an_unnamed_root_with_zero_native_links() {
    let cx = Cx::for_testing();
    let mut image = build_clean_ntfs_image(256, 64, 0xCA7A_1000_0000_0003);
    let length = image.len() as u64 - SECTOR_BYTES as u64;
    let root_at = CLUSTER_BYTES + 5 * RECORD_BYTES;
    let mut attributes = copied_test_record_attributes(&image[root_at..root_at + RECORD_BYTES]);
    attributes.retain(|attribute| attribute[..4] != 0x30_u32.to_le_bytes());
    let root = build_file_record(5, 5, 0, true, &attributes);
    image[root_at..root_at + RECORD_BYTES].copy_from_slice(&root);
    let device = FaultInjectingNtfsDevice::new(image);
    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&device) as Arc<dyn ByteDevice>,
        0,
        length,
        write_options_clean(),
    )
    .unwrap();
    let (reference, _) = engine
        .create_entry_at(
            &cx,
            NtfsReference {
                record: 5,
                sequence: 5,
            },
            &"child".encode_utf16().collect::<Vec<_>>(),
            false,
            false,
            b"native child",
            DEFAULT_FILETIME,
        )
        .into_result()
        .unwrap();
    engine.check_clean_consistency(&cx).unwrap();
    let durable = device.snapshot_durable_only();
    let root = NtfsFileRecord::parse(&durable[root_at..root_at + RECORD_BYTES]).unwrap();
    assert_eq!(root.hard_links, 0);
    assert!(
        root.attributes()
            .unwrap()
            .iter()
            .all(|attribute| attribute.kind != 0x30)
    );
    assert_native_hard_links(&durable, reference, &["/child"], b"native child");
}

#[test]
fn path_stream_mutations_preserve_strict_failure_for_corrupt_sibling() {
    let cx = Cx::for_testing();
    let image = build_clean_ntfs_image(256, 64, 0xCA7A_1000_0000_0005);
    let length = image.len() as u64 - SECTOR_BYTES as u64;
    let device = FaultInjectingNtfsDevice::new(image);
    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&device) as Arc<dyn ByteDevice>,
        0,
        length,
        write_options_clean(),
    )
    .unwrap();
    let (good, _) = engine
        .create_file(&cx, "/", "good", b"kept")
        .into_result()
        .unwrap();
    let stream = [u16::from(b'x')];
    engine
        .create_stream(&cx, good, &stream, b"kept stream")
        .into_result()
        .unwrap();
    let (bad, _) = engine
        .create_file(&cx, "/", "bad", b"unrelated")
        .into_result()
        .unwrap();
    let clean = device.snapshot_durable_only();
    let offset = CLUSTER_BYTES + usize::try_from(bad.record).unwrap() * RECORD_BYTES;
    let mut attributes = copied_test_record_attributes(&clean[offset..offset + RECORD_BYTES]);
    let name = attributes
        .iter_mut()
        .find(|attribute| attribute[..4] == 0x30_u32.to_le_bytes())
        .unwrap();
    let value_at = usize::from(u16::from_le_bytes(name[20..22].try_into().unwrap()));
    // Keep a structurally valid name, but break its identity against $I30.
    // The selected /good FILE and every one of its attributes remain intact.
    name[value_at + 65] ^= 1;
    let changed = build_file_record(bad.record as u32, bad.sequence, 1, false, &attributes);
    device
        .write_all_at(&cx, ByteOffset(offset as u64), &changed)
        .unwrap();
    device.sync(&cx).unwrap();
    let before = device.snapshot_durable_only();
    let writes = device.write_bytes_total();
    let events = engine.persistence_trace().len();
    let expected_detail = "directory index does not match target FILE_NAME";
    assert!(matches!(
        engine.resolve_path_reference(&cx, "/good"),
        Err(FfsError::Corruption { detail, .. }) if detail == expected_detail
    ));

    for operation in [
        "range",
        "empty range",
        "truncate",
        "same size",
        "create",
        "remove",
    ] {
        let outcome = match operation {
            "range" => engine.write_file_range(&cx, "/good", 0, b"bad"),
            "empty range" => engine.write_file_range(&cx, "/good", 0, b""),
            "truncate" => engine.truncate_file(&cx, "/good", 0),
            "same size" => engine.truncate_file(&cx, "/good", 4),
            "create" => engine.create_file_stream(&cx, "/good", &[u16::from(b'y')], b"new"),
            "remove" => engine.remove_file_stream(&cx, "/good", &stream),
            _ => unreachable!(),
        };
        assert!(
            matches!(
                &outcome,
                NtfsTxOutcome::NotCommitted(FfsError::Corruption { detail, .. })
                    if detail == expected_detail
            ),
            "{operation} must retain the strict lookup failure: {outcome:?}"
        );
        assert_eq!(device.write_bytes_total(), writes, "{operation}");
        assert_eq!(device.snapshot_live(), before, "{operation}");
        assert_eq!(device.snapshot_durable_only(), before, "{operation}");
        assert_eq!(engine.persistence_trace().len(), events, "{operation}");
    }
}
