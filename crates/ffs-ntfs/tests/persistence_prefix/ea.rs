//! EA publication, allocation and native recovery share the DATA fault oracle.

use super::{
    Arc, ByteDevice, ByteOffset, CLUSTER_BYTES, Cx, DEFAULT_FILETIME, FaultInjectingNtfsDevice,
    FfsError, Mutex, NtfsPersistenceStage, NtfsReference, NtfsTransactionEngine, NtfsTxOutcome,
    RECORD_BYTES, SECTOR_BYTES, build_clean_ntfs_image, build_file_record, build_nonresident_attr,
    copied_test_record_attributes, hard_link_index_values, write_options_clean,
    write_options_recover,
};
use ffs_core::vfs::XattrSetMode;
use ffs_core::{FsOps, RequestScope};
use ffs_ntfs::{NtfsEaSetMode, NtfsFs, NtfsVolume};
use ffs_ondisk::ntfs::attribute_list::{MAX_LIST_BYTES, parse_attribute_list};
use ffs_ondisk::ntfs::ea::{FILE_NEED_EA, NtfsEa};
use ffs_ondisk::ntfs::{ATTRIBUTE_LIST, EA, NtfsFileRecord, NtfsValue, decode_mapping_pairs};
use ffs_types::InodeNumber;
use std::collections::BTreeMap;
use std::ffi::OsStr;

fn fixture(
    clusters: u64,
) -> (
    Arc<FaultInjectingNtfsDevice>,
    NtfsTransactionEngine,
    NtfsReference,
) {
    let cx = Cx::for_testing();
    let image = build_clean_ntfs_image(clusters, 50, 0xEA00_0000_1234_5678);
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
    let (file, _) = engine
        .create_file(&cx, "/", "notes", b"DATA remains unchanged")
        .into_result()
        .unwrap();
    (device, engine, file)
}

fn entry(name: &[u8], flags: u8, value: &[u8]) -> NtfsEa {
    NtfsEa {
        name: name.to_vec(),
        flags,
        value: value.to_vec(),
    }
}

fn entries(engine: &NtfsTransactionEngine, file: NtfsReference) -> Vec<NtfsEa> {
    let cx = Cx::for_testing();
    let volume = engine.volume_view(&cx).unwrap();
    let record = volume
        .record(&cx, file.record, Some(file.sequence))
        .unwrap();
    let stream = volume.data_stream(&cx, &record, &[]).unwrap();
    assert_eq!(
        volume.read(&cx, &stream, 0, 100).unwrap(),
        b"DATA remains unchanged"
    );
    volume.extended_attributes(&cx, &record).unwrap().entries
}

fn used_clusters(device: &FaultInjectingNtfsDevice) -> u32 {
    // The fixture's native $Bitmap occupies cluster 60.
    device.snapshot_durable_only()[60 * CLUSTER_BYTES..61 * CLUSTER_BYTES]
        .iter()
        .map(|byte| byte.count_ones())
        .sum()
}

/// Follow native ATTRIBUTE_LIST references through public parsers so assertions
/// include metadata that has moved out of the base FILE record.
fn catalog_records(image: &[u8], volume: &NtfsVolume, file: NtfsReference) -> Vec<NtfsFileRecord> {
    let cx = Cx::for_testing();
    let base = volume
        .record(&cx, file.record, Some(file.sequence))
        .unwrap();
    let list = {
        let attributes = base.attributes().unwrap();
        attributes
            .iter()
            .find(|attribute| attribute.kind == ATTRIBUTE_LIST)
            .map(|attribute| {
                let bytes = match &attribute.value {
                    NtfsValue::Resident(bytes) => bytes.to_vec(),
                    NtfsValue::NonResident(extent) => {
                        assert_eq!(extent.first_vcn, 0);
                        assert_eq!(extent.initialized_bytes, extent.data_bytes);
                        assert!(
                            extent.data_bytes > 0 && extent.data_bytes <= MAX_LIST_BYTES as u64
                        );
                        let cluster_bytes = volume.geometry.cluster_bytes() as usize;
                        let mut bytes = vec![0; usize::try_from(extent.data_bytes).unwrap()];
                        for run in decode_mapping_pairs(
                            extent.mapping_pairs,
                            extent.first_vcn,
                            extent.last_vcn,
                            volume.geometry.cluster_count(),
                        )
                        .unwrap()
                        {
                            let start = usize::try_from(run.vcn).unwrap() * cluster_bytes;
                            let count = bytes
                                .len()
                                .saturating_sub(start)
                                .min(usize::try_from(run.clusters).unwrap() * cluster_bytes);
                            if count == 0 {
                                continue;
                            }
                            let physical =
                                usize::try_from(run.lcn.unwrap()).unwrap() * cluster_bytes;
                            bytes[start..start + count]
                                .copy_from_slice(&image[physical..physical + count]);
                        }
                        bytes
                    }
                };
                parse_attribute_list(&bytes).unwrap()
            })
            .unwrap_or_default()
    };
    let mut seen = BTreeMap::from([(file.record, file.sequence)]);
    let mut records = vec![base];
    for item in list {
        if let Some(sequence) = seen.insert(item.reference.record, item.reference.sequence) {
            assert_eq!(sequence, item.reference.sequence);
            continue;
        }
        let extension = volume
            .record(&cx, item.reference.record, Some(item.reference.sequence))
            .unwrap();
        assert!(extension.in_use());
        assert_eq!(extension.base, file);
        records.push(extension);
    }
    records
}

fn assert_packed_sizes(
    device: &FaultInjectingNtfsDevice,
    engine: &NtfsTransactionEngine,
    file: NtfsReference,
) {
    let cx = Cx::for_testing();
    let image = device.snapshot_live();
    let volume = engine.volume_view(&cx).unwrap();
    let records = catalog_records(&image, &volume, file);
    let information = volume
        .extended_attributes(&cx, &records[0])
        .unwrap()
        .information;
    let expected = information.map_or(0, |info| u32::from(info.packed_bytes));
    let mut ea_heads = 0;
    for record in &records {
        for attribute in record.attributes().unwrap() {
            if attribute.kind == EA {
                match attribute.value {
                    NtfsValue::Resident(bytes) => {
                        ea_heads += 1;
                        assert_eq!(
                            bytes.len() as u64,
                            u64::from(information.unwrap().unpacked_bytes)
                        );
                    }
                    NtfsValue::NonResident(extent) if extent.first_vcn == 0 => {
                        ea_heads += 1;
                        assert_eq!(extent.initialized_bytes, extent.data_bytes);
                        assert_eq!(
                            extent.data_bytes,
                            u64::from(information.unwrap().unpacked_bytes)
                        );
                    }
                    NtfsValue::NonResident(_) => {}
                }
                continue;
            }
            if attribute.kind != 0x30 {
                continue;
            }
            let NtfsValue::Resident(key) = attribute.value else {
                panic!("resident FILE_NAME");
            };
            assert_eq!(
                u32::from_le_bytes(key[60..64].try_into().unwrap()),
                expected
            );
            let parent_ref =
                NtfsReference::decode(u64::from_le_bytes(key[..8].try_into().unwrap()));
            let parent = volume
                .record(&cx, parent_ref.record, Some(parent_ref.sequence))
                .unwrap();
            let copies: Vec<_> = hard_link_index_values(&image, &volume, &parent, file)
                .into_iter()
                .filter(|copy| copy.raw_key[64..] == key[64..])
                .collect();
            assert_eq!(
                copies.len(),
                1,
                "each native link has one current index copy"
            );
            assert_eq!(
                copies[0].raw_key.as_slice(),
                key,
                "parent index must publish every FILE_NAME field"
            );
        }
    }
    assert_eq!(ea_heads, usize::from(information.is_some()));
}

#[test]
fn ea_native_transitions_preserve_links_unknown_entries_and_reclaim_clusters() {
    let cx = Cx::for_testing();
    let (device, mut engine, file) = fixture(256);
    let (archive, _) = engine.mkdir(&cx, "/", "archive").into_result().unwrap();
    for index in 0..12 {
        engine
            .create_file(
                &cx,
                "/archive",
                &format!("filler_{index:02}_long_name_to_force_external_directory_index.bin"),
                b"filler",
            )
            .into_result()
            .unwrap();
    }
    engine
        .link_file(&cx, "/notes", "/archive", "copy")
        .into_result()
        .unwrap();
    let image = device.snapshot_live();
    let volume = engine.volume_view(&cx).unwrap();
    let archive_records = catalog_records(&image, &volume, archive);
    assert!(
        archive_records.iter().any(|record| {
            record
                .attributes()
                .unwrap()
                .iter()
                .any(|attribute| attribute.kind == 0xA0)
        }),
        "the second parent must own an external INDEX_ALLOCATION"
    );
    let copies = hard_link_index_values(&image, &volume, &archive_records[0], file);
    assert_eq!(copies.len(), 1);
    assert!(
        copies[0].block_vcn.is_some(),
        "the hard link must live in INDX"
    );
    let original_used = used_clusters(&device);
    let retained = entry(b"opaque\x82", FILE_NEED_EA, &[0, 0xFF, 1]);
    engine
        .set_extended_attribute(
            &cx,
            file,
            &retained,
            NtfsEaSetMode::Create,
            DEFAULT_FILETIME,
        )
        .into_result()
        .unwrap();
    for value in [
        b"small".to_vec(),
        vec![0xA6; 9001],
        vec![],
        b"small again".to_vec(),
    ] {
        let updated = entry(b"user.note", 0, &value);
        engine
            .set_extended_attribute(
                &cx,
                file,
                &updated,
                NtfsEaSetMode::Set,
                DEFAULT_FILETIME + 7,
            )
            .into_result()
            .unwrap();
        assert_eq!(entries(&engine, file), [retained.clone(), updated]);
        assert_packed_sizes(&device, &engine, file);
        engine.check_clean_consistency(&cx).unwrap();
        if value.len() > 9000 {
            assert!(used_clusters(&device) >= original_used + 3);
        }
    }
    for name in [b"user.note".as_slice(), retained.name.as_slice()] {
        engine
            .remove_extended_attribute(&cx, file, name, DEFAULT_FILETIME + 9)
            .into_result()
            .unwrap();
        assert_packed_sizes(&device, &engine, file);
    }
    assert_eq!(entries(&engine, file), [] as [NtfsEa; 0]);
    assert_eq!(
        used_clusters(&device),
        original_used,
        "last removal reclaims EA and obsolete catalog storage"
    );
    engine.check_clean_consistency(&cx).unwrap();
    let volume = engine.volume_view(&cx).unwrap();
    let record = volume
        .record(&cx, file.record, Some(file.sequence))
        .unwrap();
    assert!(
        volume
            .extended_attributes(&cx, &record)
            .unwrap()
            .information
            .is_none()
    );
}

struct DirectoryBitmapFixture {
    image: Vec<u8>,
    file: NtfsReference,
    directory: NtfsReference,
    bitmap_cluster: u64,
    bitmap_bytes: Vec<u8>,
}

fn directory_bitmap_fixture() -> DirectoryBitmapFixture {
    let cx = Cx::for_testing();
    let (device, mut engine, file) = fixture(256);
    let (directory, _) = engine.mkdir(&cx, "/", "archive").into_result().unwrap();
    for index in 0..6 {
        engine
            .create_file(
                &cx,
                "/archive",
                &format!("entry_{index:02}_long_name_for_external_directory_index.bin"),
                b"filler",
            )
            .into_result()
            .unwrap();
    }
    engine
        .link_file(&cx, "/notes", "/archive", "copy")
        .into_result()
        .unwrap();
    let volume = engine.volume_view(&cx).unwrap();
    let record = volume
        .record(&cx, directory.record, Some(directory.sequence))
        .unwrap();
    let attributes = record.attributes().unwrap();
    assert!(
        !attributes
            .iter()
            .any(|attribute| attribute.kind == ATTRIBUTE_LIST)
    );
    let index = attributes
        .iter()
        .find(|attribute| attribute.kind == 0xA0)
        .unwrap();
    let NtfsValue::NonResident(index) = &index.value else {
        panic!("fixture must use an external directory index");
    };
    assert_eq!(index.allocated_bytes, CLUSTER_BYTES as u64);
    let bitmap = attributes
        .iter()
        .find(|attribute| attribute.kind == 0xB0)
        .unwrap();
    let NtfsValue::Resident(bitmap_bytes) = &bitmap.value else {
        panic!("fixture bitmap starts resident");
    };
    let bitmap_bytes = bitmap_bytes.to_vec();
    assert!(!bitmap_bytes.is_empty() && bitmap_bytes.len() <= 8);
    let mut image = device.snapshot_durable_only();
    let bitmap_cluster = 255_u64;
    let allocation_byte = 60 * CLUSTER_BYTES + bitmap_cluster as usize / 8;
    let allocation_mask = 1_u8 << (bitmap_cluster % 8);
    assert_eq!(image[allocation_byte] & allocation_mask, 0);
    image[allocation_byte] |= allocation_mask;
    let data_offset = bitmap_cluster as usize * CLUSTER_BYTES;
    image[data_offset..data_offset + bitmap_bytes.len()].copy_from_slice(&bitmap_bytes);
    let record_offset = CLUSTER_BYTES + directory.record as usize * RECORD_BYTES;
    let mut raw_attributes =
        copied_test_record_attributes(&image[record_offset..record_offset + RECORD_BYTES]);
    let bitmap_attribute = raw_attributes
        .iter_mut()
        .find(|attribute| attribute[..4] == 0xB0_u32.to_le_bytes())
        .unwrap();
    *bitmap_attribute = build_nonresident_attr(
        0xB0,
        bitmap.id,
        &bitmap.name,
        bitmap_cluster,
        1,
        bitmap_bytes.len() as u64,
        volume.geometry.cluster_count(),
    );
    image[record_offset..record_offset + RECORD_BYTES].copy_from_slice(&build_file_record(
        record.number,
        record.sequence,
        record.hard_links,
        true,
        &raw_attributes,
    ));
    DirectoryBitmapFixture {
        image,
        file,
        directory,
        bitmap_cluster,
        bitmap_bytes,
    }
}

fn open_bitmap_image(
    image: Vec<u8>,
    recover: bool,
) -> (Arc<FaultInjectingNtfsDevice>, NtfsTransactionEngine) {
    let cx = Cx::for_testing();
    let length = image.len() as u64 - SECTOR_BYTES as u64;
    let device = FaultInjectingNtfsDevice::new(image);
    let engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&device) as Arc<dyn ByteDevice>,
        0,
        length,
        if recover {
            write_options_recover()
        } else {
            write_options_clean()
        },
    )
    .unwrap();
    engine.check_clean_consistency(&cx).unwrap();
    (device, engine)
}

fn assert_directory_bitmap_storage(
    device: &FaultInjectingNtfsDevice,
    engine: &NtfsTransactionEngine,
    fixture: &DirectoryBitmapFixture,
    retired: bool,
) {
    let cx = Cx::for_testing();
    let image = device.snapshot_durable_only();
    let allocation_byte = 60 * CLUSTER_BYTES + fixture.bitmap_cluster as usize / 8;
    let mask = 1_u8 << (fixture.bitmap_cluster % 8);
    assert_eq!(image[allocation_byte] & mask == 0, retired);
    let volume = engine.volume_view(&cx).unwrap();
    let records = catalog_records(&image, &volume, fixture.directory);
    let mut count = 0;
    for record in &records {
        for attribute in record.attributes().unwrap() {
            if attribute.kind != 0xB0 {
                continue;
            }
            count += 1;
            match attribute.value {
                NtfsValue::Resident(bytes) => {
                    assert!(
                        retired,
                        "predecessor must retain the original bitmap mapping"
                    );
                    assert_eq!(bytes, fixture.bitmap_bytes);
                }
                NtfsValue::NonResident(extent) => {
                    assert!(!retired, "committed small bitmap must become resident");
                    let runs = decode_mapping_pairs(
                        extent.mapping_pairs,
                        extent.first_vcn,
                        extent.last_vcn,
                        volume.geometry.cluster_count(),
                    )
                    .unwrap();
                    assert_eq!(runs.len(), 1);
                    assert_eq!(runs[0].lcn, Some(fixture.bitmap_cluster));
                    assert_eq!(runs[0].clusters, 1);
                }
            }
        }
    }
    assert_eq!(count, 1);
    engine.check_clean_consistency(&cx).unwrap();
    let _ = entries(engine, fixture.file);
}

#[test]
fn ea_repack_reclaims_nonresident_directory_bitmap_and_recovers_atomically() {
    let cx = Cx::for_testing();
    let fixture = directory_bitmap_fixture();
    for target in [fixture.file, fixture.directory] {
        let (device, mut engine) = open_bitmap_image(fixture.image.clone(), false);
        let allocated_before = used_clusters(&device);
        assert_directory_bitmap_storage(&device, &engine, &fixture, false);
        let cuts = Arc::new(Mutex::new(Vec::<(bool, Vec<u8>)>::new()));
        if target == fixture.file {
            let captured = Arc::clone(&cuts);
            let backing = Arc::clone(&device);
            engine.set_stage_hook(Some(Box::new(move |event| {
                if matches!(
                    event.stage,
                    NtfsPersistenceStage::DirtyRestartBarrier
                        | NtfsPersistenceStage::LogCommitBarrier
                ) {
                    let committed = event.stage == NtfsPersistenceStage::LogCommitBarrier;
                    let mut cuts = captured.lock().unwrap();
                    if !cuts.iter().any(|(seen, _)| *seen == committed) {
                        cuts.push((committed, backing.snapshot_durable_only()));
                    }
                }
                Ok(())
            })));
        }
        // An empty value still dirties both EA metadata and the child's parent index.
        let attribute = entry(b"user.bitmap", 0, b"");
        engine
            .set_extended_attribute(
                &cx,
                target,
                &attribute,
                NtfsEaSetMode::Create,
                DEFAULT_FILETIME,
            )
            .into_result()
            .unwrap();
        engine.set_stage_hook(None);
        assert_directory_bitmap_storage(&device, &engine, &fixture, true);
        assert_eq!(used_clusters(&device), allocated_before - 1);
        assert_packed_sizes(&device, &engine, target);
        let volume = engine.volume_view(&cx).unwrap();
        let record = volume
            .record(&cx, target.record, Some(target.sequence))
            .unwrap();
        assert_eq!(
            volume
                .extended_attributes(&cx, &record)
                .unwrap()
                .entries
                .as_slice(),
            std::slice::from_ref(&attribute),
        );

        let captured = std::mem::take(&mut *cuts.lock().unwrap());
        assert_eq!(captured.len(), if target == fixture.file { 2 } else { 0 });
        for (committed, image) in captured {
            let (recovered_device, recovered) = open_bitmap_image(image, true);
            let volume = recovered.volume_view(&cx).unwrap();
            let record = volume
                .record(&cx, target.record, Some(target.sequence))
                .unwrap();
            assert_eq!(
                volume.extended_attributes(&cx, &record).unwrap().entries,
                if committed {
                    vec![attribute.clone()]
                } else {
                    Vec::new()
                },
            );
            assert_eq!(
                used_clusters(&recovered_device),
                allocated_before - u32::from(committed)
            );
            // Only the durable commit may retire the original directory bitmap.
            assert_directory_bitmap_storage(&recovered_device, &recovered, &fixture, committed);
            assert_packed_sizes(&recovered_device, &recovered, target);
        }
    }
}

#[test]
fn ea_repack_refuses_unallocated_directory_bitmap_before_writes() {
    let cx = Cx::for_testing();
    let fixture = directory_bitmap_fixture();
    let (device, mut engine) = open_bitmap_image(fixture.image.clone(), false);
    let allocation_byte = 60 * CLUSTER_BYTES + fixture.bitmap_cluster as usize / 8;
    let mask = 1_u8 << (fixture.bitmap_cluster % 8);
    device
        .write_all_at(
            &cx,
            ByteOffset(allocation_byte as u64),
            &[fixture.image[allocation_byte] & !mask],
        )
        .unwrap();
    device.sync(&cx).unwrap();
    let before = device.snapshot_durable_only();
    let writes = device.write_bytes_total();
    let events = engine.persistence_trace().len();
    for target in [fixture.file, fixture.directory] {
        let outcome = engine.set_extended_attribute(
            &cx,
            target,
            &entry(b"user.bitmap", 0, b""),
            NtfsEaSetMode::Create,
            DEFAULT_FILETIME,
        );
        assert!(
            matches!(
                &outcome,
                NtfsTxOutcome::NotCommitted(FfsError::Corruption { detail, .. })
                    if detail.contains("unallocated cluster")
            ),
            "{outcome:?}"
        );
        assert_eq!(device.write_bytes_total(), writes);
        assert_eq!(engine.persistence_trace().len(), events);
        assert_eq!(device.snapshot_live(), before);
        assert_eq!(device.snapshot_durable_only(), before);
    }
}

#[test]
fn ea_native_refusals_and_cancel_leave_image_unchanged() {
    let cx = Cx::for_testing();
    let (device, mut engine, file) = fixture(99);
    let original = entry(b"user.note", FILE_NEED_EA, b"original");
    engine
        .set_extended_attribute(
            &cx,
            file,
            &original,
            NtfsEaSetMode::Create,
            DEFAULT_FILETIME,
        )
        .into_result()
        .unwrap();
    let before = device.snapshot_live();
    let writes = device.write_bytes_total();
    let stale = NtfsReference {
        sequence: file.sequence + 1,
        ..file
    };
    for (reference, candidate, mode, errno) in [
        (file, original.clone(), NtfsEaSetMode::Create, libc::EEXIST),
        (
            file,
            entry(b"user.missing", 0, b"x"),
            NtfsEaSetMode::Replace,
            libc::ENODATA,
        ),
        (file, entry(b"", 0, b"x"), NtfsEaSetMode::Set, libc::EINVAL),
        (
            file,
            entry(b"user.a\0b", 0, b"x"),
            NtfsEaSetMode::Set,
            libc::EINVAL,
        ),
        (
            file,
            entry(b"user.note", 1, b"x"),
            NtfsEaSetMode::Set,
            libc::EINVAL,
        ),
        (
            file,
            entry(b"user.note", 0, &vec![1; 65_536]),
            NtfsEaSetMode::Set,
            libc::E2BIG,
        ),
        (
            file,
            entry(b"user.large", 0, &vec![1; 65_510]),
            NtfsEaSetMode::Set,
            libc::E2BIG,
        ),
        (
            file,
            entry(b"user.large", 0, &vec![1; 60_000]),
            NtfsEaSetMode::Set,
            libc::ENOSPC,
        ),
        (stale, original.clone(), NtfsEaSetMode::Set, libc::ESTALE),
    ] {
        let outcome =
            engine.set_extended_attribute(&cx, reference, &candidate, mode, DEFAULT_FILETIME);
        let NtfsTxOutcome::NotCommitted(error) = outcome else {
            panic!("invalid EA must not commit")
        };
        assert_eq!(error.to_errno(), errno, "{error}");
        assert_eq!(device.snapshot_live(), before);
        assert_eq!(device.write_bytes_total(), writes);
    }
    cx.set_cancel_requested(true);
    assert!(matches!(
        engine.remove_extended_attribute(&cx, file, &original.name, DEFAULT_FILETIME),
        NtfsTxOutcome::NotCommitted(FfsError::Cancelled)
    ));
    assert_eq!(device.snapshot_live(), before);
}

fn recovered_entries(image: &[u8], file: NtfsReference) -> Vec<NtfsEa> {
    let cx = Cx::for_testing();
    let device = FaultInjectingNtfsDevice::new(image.to_vec());
    let engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&device) as Arc<dyn ByteDevice>,
        0,
        image.len() as u64 - SECTOR_BYTES as u64,
        write_options_recover(),
    )
    .unwrap();
    engine.check_clean_consistency(&cx).unwrap();
    assert_packed_sizes(&device, &engine, file);
    entries(&engine, file)
}

#[test]
fn ea_crash_prefixes_publish_whole_catalog_and_allocation_transitions() {
    let cx = Cx::for_testing();
    let (device, mut engine, file) = fixture(256);
    let mut before = Vec::new();
    for value in [
        Some(b"resident".to_vec()),
        Some(vec![0xBA; 9001]),
        Some(b"again".to_vec()),
        None,
    ] {
        type Cut = (NtfsPersistenceStage, bool, Vec<u8>, Vec<u8>);
        let cuts: Arc<Mutex<Vec<Cut>>> = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&cuts);
        let backing = Arc::clone(&device);
        let mut committed = false;
        engine.set_stage_hook(Some(Box::new(move |event| {
            committed |= event.stage == NtfsPersistenceStage::LogCommitBarrier;
            captured.lock().unwrap().push((
                event.stage,
                committed,
                backing.snapshot_durable_only(),
                backing.snapshot_reordered_pending(true),
            ));
            Ok(())
        })));
        let after = value.map(|value| entry(b"user.note", FILE_NEED_EA, &value));
        if let Some(entry) = &after {
            engine
                .set_extended_attribute(&cx, file, entry, NtfsEaSetMode::Set, DEFAULT_FILETIME)
                .into_result()
                .unwrap();
        } else {
            engine
                .remove_extended_attribute(&cx, file, b"user.note", DEFAULT_FILETIME)
                .into_result()
                .unwrap();
        }
        engine.set_stage_hook(None);
        let after: Vec<_> = after.into_iter().collect();
        let captured = std::mem::take(&mut *cuts.lock().unwrap());
        assert!(captured.iter().any(|(_, committed, _, _)| !committed));
        assert!(captured.iter().any(|(_, committed, _, _)| *committed));
        for (stage, committed, durable, reordered) in captured {
            assert_eq!(
                recovered_entries(&durable, file),
                if committed { &after } else { &before }.clone(),
                "durable EA prefix at {stage:?}"
            );
            let observed = recovered_entries(&reordered, file);
            if committed {
                assert_eq!(observed, after, "committed EA at {stage:?}");
            } else {
                assert!(
                    observed == before || observed == after,
                    "partial EA publication at {stage:?}"
                );
            }
        }
        before = after;
    }
}

#[test]
fn ea_writable_fsops_update_live_view_preserve_flags_and_enforce_host_namespace() {
    let cx = Cx::for_testing();
    let (device, mut engine, file) = fixture(256);
    let original = entry(b"user.note", FILE_NEED_EA, b"old");
    engine
        .set_extended_attribute(
            &cx,
            file,
            &original,
            NtfsEaSetMode::Create,
            DEFAULT_FILETIME,
        )
        .into_result()
        .unwrap();
    let fs = NtfsFs::from_engine(&cx, engine, 1000, 1000).unwrap();
    let mut scope = RequestScope::empty();
    let ino = fs
        .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("notes"))
        .unwrap()
        .ino;
    assert_eq!(
        fs.getxattr(&cx, ino, "user.note").unwrap(),
        Some(b"old".to_vec())
    );
    fs.setxattr(
        &cx,
        &mut scope,
        ino,
        "user.note",
        &[0xB6; 9001],
        XattrSetMode::Replace,
    )
    .unwrap();
    assert_eq!(
        fs.getxattr(&cx, ino, "user.note").unwrap(),
        Some(vec![0xB6; 9001])
    );
    assert_eq!(fs.listxattr(&cx, ino).unwrap(), ["user.note"]);
    assert_eq!(
        recovered_entries(&device.snapshot_durable_only(), file)[0].flags,
        FILE_NEED_EA
    );
    assert_eq!(
        fs.setxattr(
            &cx,
            &mut scope,
            ino,
            "user.note",
            b"x",
            XattrSetMode::Create
        )
        .unwrap_err()
        .to_errno(),
        libc::EEXIST
    );
    assert_eq!(
        fs.setxattr(
            &cx,
            &mut scope,
            ino,
            "user.missing",
            b"x",
            XattrSetMode::Replace
        )
        .unwrap_err()
        .to_errno(),
        libc::ENODATA
    );
    assert_eq!(
        fs.setxattr(
            &cx,
            &mut scope,
            ino,
            "security.capability",
            b"x",
            XattrSetMode::Set
        )
        .unwrap_err()
        .to_errno(),
        libc::EOPNOTSUPP
    );
    assert!(
        !fs.removexattr(&cx, &mut scope, ino, "security.capability")
            .unwrap()
    );
    assert!(fs.removexattr(&cx, &mut scope, ino, "user.note").unwrap());
    assert!(!fs.removexattr(&cx, &mut scope, ino, "user.note").unwrap());
    assert_eq!(fs.listxattr(&cx, ino).unwrap(), [] as [String; 0]);
    let dir = fs
        .mkdir(
            &cx,
            &mut scope,
            InodeNumber(1),
            OsStr::new("dir"),
            0o755,
            1000,
            1000,
        )
        .unwrap();
    for ino in [dir.ino, InodeNumber(1)] {
        fs.setxattr(
            &cx,
            &mut scope,
            ino,
            "user.directory",
            b"metadata",
            XattrSetMode::Create,
        )
        .unwrap();
        assert_eq!(
            fs.getxattr(&cx, ino, "user.directory").unwrap(),
            Some(b"metadata".to_vec())
        );
        assert!(
            fs.removexattr(&cx, &mut scope, ino, "user.directory")
                .unwrap()
        );
    }
}

#[test]
fn ea_read_only_fsops_refuse_mutation_without_backing_writes() {
    let cx = Cx::for_testing();
    let (device, mut engine, file) = fixture(256);
    let original = entry(b"user.note", FILE_NEED_EA, b"retained");
    engine
        .set_extended_attribute(
            &cx,
            file,
            &original,
            NtfsEaSetMode::Create,
            DEFAULT_FILETIME,
        )
        .into_result()
        .unwrap();
    let fs = NtfsFs::new(&cx, engine.volume_view(&cx).unwrap(), 1000, 1000).unwrap();
    let mut scope = RequestScope::empty();
    let ino = fs
        .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("notes"))
        .unwrap()
        .ino;
    let before = device.snapshot_live();
    let writes = device.write_bytes_total();
    for mode in [
        XattrSetMode::Set,
        XattrSetMode::Create,
        XattrSetMode::Replace,
    ] {
        assert_eq!(
            fs.setxattr(&cx, &mut scope, ino, "user.note", b"denied", mode)
                .unwrap_err()
                .to_errno(),
            libc::EROFS
        );
    }
    assert_eq!(
        fs.removexattr(&cx, &mut scope, ino, "user.note")
            .unwrap_err()
            .to_errno(),
        libc::EROFS
    );
    assert_eq!(device.snapshot_live(), before);
    assert_eq!(device.write_bytes_total(), writes);
    assert_eq!(entries(&engine, file), [original]);
}

#[test]
fn ea_writable_fsops_finish_publication_after_committed_cancellation() {
    for stage in [
        NtfsPersistenceStage::LogCommitBarrier,
        NtfsPersistenceStage::TargetMetadataBarrier,
        NtfsPersistenceStage::AckPublished,
    ] {
        let cx = Cx::for_testing();
        let (device, mut engine, file) = fixture(256);
        let cancellation = cx.clone();
        engine.set_stage_hook(Some(Box::new(move |event| {
            if event.stage == stage {
                cancellation.set_cancel_requested(true);
            }
            Ok(())
        })));
        let fs = NtfsFs::from_engine(&cx, engine, 1000, 1000).unwrap();
        let mut scope = RequestScope::empty();
        let ino = fs
            .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("notes"))
            .unwrap()
            .ino;
        let value = vec![0xD7; 9001];
        fs.setxattr(
            &cx,
            &mut scope,
            ino,
            "user.note",
            &value,
            XattrSetMode::Create,
        )
        .unwrap_or_else(|error| panic!("committed EA must publish at {stage:?}: {error}"));
        assert!(cx.checkpoint().is_err());
        assert!(fs.last_durable_token().unwrap().is_some());
        let next = Cx::for_testing();
        assert_eq!(
            fs.getxattr(&next, ino, "user.note").unwrap(),
            Some(value.clone())
        );
        assert_eq!(
            recovered_entries(&device.snapshot_durable_only(), file),
            [entry(b"user.note", 0, &value)]
        );
        assert!(fs.removexattr(&next, &mut scope, ino, "user.note").unwrap());
        assert_eq!(fs.listxattr(&next, ino).unwrap(), [] as [String; 0]);
    }
}
