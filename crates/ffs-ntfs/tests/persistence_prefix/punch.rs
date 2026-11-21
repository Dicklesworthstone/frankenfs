//! Hole-punch allocation, metadata and recovery through the native transaction engine.

use super::{
    Arc, ByteDevice, CLUSTER_BYTES, Cx, DEFAULT_FILETIME, FaultInjectingNtfsDevice, FfsError,
    Mutex, NtfsFileRecord, NtfsPersistenceStage, NtfsReference, NtfsTransactionEngine,
    NtfsTxOutcome, NtfsVolume, SECTOR_BYTES, build_clean_ntfs_image, hard_link_index_values,
    large_sparse_stream_fixture, write_options_clean, write_options_recover,
};
use ffs_ntfs::NtfsEaSetMode;
use ffs_ondisk::ntfs::ea::{FILE_NEED_EA, NtfsEa};
use ffs_ondisk::ntfs::index::NtfsFileName;
use ffs_ondisk::ntfs::{ATTRIBUTE_LIST, DATA, NtfsValue, SPARSE, decode_mapping_pairs};
use std::collections::BTreeMap;

fn fixture(
    clusters: u64,
    payload: &[u8],
) -> (
    Arc<FaultInjectingNtfsDevice>,
    NtfsTransactionEngine,
    NtfsReference,
) {
    let cx = Cx::for_testing();
    let image = build_clean_ntfs_image(clusters, 50, 0xA01E_0000_1234_5678);
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
        .create_file(&cx, "/", "punch.bin", payload)
        .into_result()
        .unwrap();
    (device, engine, file)
}

fn view(engine: &NtfsTransactionEngine, file: NtfsReference) -> (NtfsVolume, NtfsFileRecord) {
    let cx = Cx::for_testing();
    let volume = engine.volume_view(&cx).unwrap();
    let record = volume
        .record(&cx, file.record, Some(file.sequence))
        .unwrap();
    (volume, record)
}

fn used_clusters(device: &FaultInjectingNtfsDevice) -> u32 {
    device.snapshot_durable_only()[60 * CLUSTER_BYTES..61 * CLUSTER_BYTES]
        .iter()
        .map(|byte| byte.count_ones())
        .sum()
}

fn standard_flags(record: &NtfsFileRecord) -> u32 {
    let attributes = record.attributes().unwrap();
    let standard = attributes
        .iter()
        .find(|attribute| attribute.kind == 0x10)
        .unwrap();
    let NtfsValue::Resident(bytes) = standard.value else {
        panic!("fixture STANDARD_INFORMATION must be resident");
    };
    u32::from_le_bytes(bytes[32..36].try_into().unwrap())
}

fn mapped_clusters(
    engine: &NtfsTransactionEngine,
    file: NtfsReference,
    name: &[u16],
) -> BTreeMap<u64, Option<u64>> {
    let (volume, record) = view(engine, file);
    let mut mappings = BTreeMap::new();
    for attribute in record.attributes().unwrap() {
        if attribute.kind != DATA || attribute.name != name {
            continue;
        }
        let NtfsValue::NonResident(extent) = attribute.value else {
            panic!("mapping assertions require nonresident fixture DATA");
        };
        for run in decode_mapping_pairs(
            extent.mapping_pairs,
            extent.first_vcn,
            extent.last_vcn,
            volume.geometry.cluster_count(),
        )
        .unwrap()
        {
            assert!(run.clusters <= 16, "helper only expands small fixtures");
            for relative in 0..run.clusters {
                assert!(
                    mappings
                        .insert(run.vcn + relative, run.lcn.map(|lcn| lcn + relative))
                        .is_none()
                );
            }
        }
    }
    mappings
}

fn assert_stream(
    engine: &NtfsTransactionEngine,
    file: NtfsReference,
    name: &[u16],
    expected: &[u8],
    allocated: u64,
    initialized: u64,
) {
    let cx = Cx::for_testing();
    let (volume, record) = view(engine, file);
    let stream = volume.data_stream(&cx, &record, name).unwrap();
    assert_eq!(stream.size, expected.len() as u64);
    assert_eq!(stream.allocated, allocated);
    assert_eq!(stream.initialized, initialized);
    assert_eq!(
        volume.read(&cx, &stream, 0, expected.len() + 1).unwrap(),
        expected
    );
}

fn assert_name_copies(
    device: &FaultInjectingNtfsDevice,
    engine: &NtfsTransactionEngine,
    file: NtfsReference,
    allocated: u64,
    size: u64,
) {
    let cx = Cx::for_testing();
    let image = device.snapshot_durable_only();
    let (volume, record) = view(engine, file);
    let flags = standard_flags(&record);
    let mut count = 0;
    for attribute in record.attributes().unwrap() {
        if attribute.kind != 0x30 {
            continue;
        }
        let NtfsValue::Resident(bytes) = attribute.value else {
            panic!("FILE_NAME must be resident");
        };
        let name = NtfsFileName::parse(bytes).unwrap();
        assert_eq!(
            u64::from_le_bytes(bytes[40..48].try_into().unwrap()),
            allocated
        );
        assert_eq!(u64::from_le_bytes(bytes[48..56].try_into().unwrap()), size);
        assert_eq!(u32::from_le_bytes(bytes[56..60].try_into().unwrap()), flags);
        let parent = volume
            .record(&cx, name.parent.record, Some(name.parent.sequence))
            .unwrap();
        let entries = hard_link_index_values(&image, &volume, &parent, file);
        let entry = entries.iter().find(|entry| entry.name == name).unwrap();
        assert_eq!(entry.allocated, allocated);
        assert_eq!(entry.size, size);
        assert_eq!(
            u32::from_le_bytes(entry.raw_key[56..60].try_into().unwrap()),
            flags
        );
        count += 1;
    }
    assert_eq!(count, usize::from(record.hard_links));
}

#[test]
fn hole_punch_reclaims_clusters_preserves_hard_links_and_native_metadata() {
    let cx = Cx::for_testing();
    let cb = CLUSTER_BYTES as u64;
    let original: Vec<_> = (0..6 * CLUSTER_BYTES + 29)
        .map(|index| (index % 251 + 1) as u8)
        .collect();
    let (device, mut engine, file) = fixture(256, &original);
    let (directory, _) = engine.mkdir(&cx, "/", "archive").into_result().unwrap();
    engine
        .link_file(&cx, "/punch.bin", "/archive", "alias")
        .into_result()
        .unwrap();
    let ads: Vec<_> = "audit".encode_utf16().collect();
    engine
        .create_file_stream(&cx, "/punch.bin", &ads, b"unchanged ADS")
        .into_result()
        .unwrap();
    let ea = NtfsEa {
        name: b"opaque\xff".to_vec(),
        flags: FILE_NEED_EA,
        value: vec![0, 0xff, 0x12],
    };
    engine
        .set_extended_attribute(&cx, file, &ea, NtfsEaSetMode::Set, DEFAULT_FILETIME)
        .into_result()
        .unwrap();
    let (volume, record) = view(&engine, file);
    let security = volume.security_descriptor(&cx, &record).unwrap().bytes;
    let original_mapping = mapped_clusters(&engine, file, &[]);
    let before = used_clusters(&device);
    let start = cb + 17;
    let end = 5 * cb + 23;
    engine
        .punch_hole_at(&cx, file, &[], start, end - start, DEFAULT_FILETIME + 1)
        .into_result()
        .unwrap();
    let mut expected = original;
    expected[start as usize..end as usize].fill(0);
    assert_stream(&engine, file, &[], &expected, 4 * cb, expected.len() as u64);
    assert_eq!(used_clusters(&device), before - 3);
    let current_mapping = mapped_clusters(&engine, file, &[]);
    for vcn in [0, 6] {
        assert_eq!(current_mapping[&vcn], original_mapping[&vcn]);
    }
    for vcn in [1, 5] {
        assert!(current_mapping[&vcn].is_some());
        assert_ne!(current_mapping[&vcn], original_mapping[&vcn]);
    }
    for vcn in 2..5 {
        assert_eq!(current_mapping[&vcn], None);
    }
    assert_name_copies(&device, &engine, file, 4 * cb, expected.len() as u64);
    let (volume, record) = view(&engine, file);
    assert_eq!(standard_flags(&record) & 0x200, 0x200);
    assert_eq!(
        volume.security_descriptor(&cx, &record).unwrap().bytes,
        security
    );
    assert_eq!(
        volume.extended_attributes(&cx, &record).unwrap().entries,
        [ea]
    );
    assert_eq!(
        engine
            .lookup_reference(&cx, directory, &"alias".encode_utf16().collect::<Vec<_>>())
            .unwrap(),
        file
    );
    assert_stream(&engine, file, &ads, b"unchanged ADS", 13, 13);

    engine
        .write_stream_range(&cx, file, &[], 3 * cb + 7, b"refill")
        .into_result()
        .unwrap();
    expected[3 * CLUSTER_BYTES + 7..3 * CLUSTER_BYTES + 13].copy_from_slice(b"refill");
    assert_stream(&engine, file, &[], &expected, 5 * cb, expected.len() as u64);
    assert_name_copies(&device, &engine, file, 5 * cb, expected.len() as u64);
    engine.check_clean_consistency(&cx).unwrap();
}

#[test]
fn hole_punch_resident_and_single_cluster_ranges_keep_storage_and_eof() {
    let cx = Cx::for_testing();
    let (device, mut engine, file) = fixture(128, b"ABCDEFGHIJKLMNO");
    let before = used_clusters(&device);
    engine
        .punch_hole_at(&cx, file, &[], 3, 5, DEFAULT_FILETIME)
        .into_result()
        .unwrap();
    let mut expected = b"ABCDEFGHIJKLMNO".to_vec();
    expected[3..8].fill(0);
    assert_stream(&engine, file, &[], &expected, 15, 15);
    let (_, record) = view(&engine, file);
    assert!(record.attributes().unwrap().iter().any(|attribute| {
        attribute.kind == DATA
            && attribute.name.is_empty()
            && matches!(&attribute.value, NtfsValue::Resident(_))
    }));
    assert_eq!(standard_flags(&record) & 0x200, 0);
    engine
        .punch_hole_at(&cx, file, &[], 11, 100, DEFAULT_FILETIME)
        .into_result()
        .unwrap();
    expected[11..].fill(0);
    assert_stream(&engine, file, &[], &expected, 15, 15);
    engine
        .punch_hole_at(&cx, file, &[], 15, 10, DEFAULT_FILETIME)
        .into_result()
        .unwrap();
    assert_stream(&engine, file, &[], &expected, 15, 15);
    assert_eq!(used_clusters(&device), before);

    let mut allocated = vec![0xA6; 2 * CLUSTER_BYTES];
    engine
        .write_file_data(&cx, "/punch.bin", &allocated)
        .into_result()
        .unwrap();
    let old_mapping = mapped_clusters(&engine, file, &[]);
    engine
        .punch_hole_at(&cx, file, &[], 7, 12, DEFAULT_FILETIME)
        .into_result()
        .unwrap();
    allocated[7..19].fill(0);
    let size = allocated.len() as u64;
    assert_stream(&engine, file, &[], &allocated, size, size);
    let new_mapping = mapped_clusters(&engine, file, &[]);
    assert_ne!(new_mapping[&0], old_mapping[&0]);
    assert_eq!(new_mapping[&1], old_mapping[&1]);
    let (_, record) = view(&engine, file);
    assert_eq!(standard_flags(&record) & 0x200, 0);
    engine.check_clean_consistency(&cx).unwrap();
}

#[test]
fn hole_punch_named_data_converts_without_changing_unnamed_sparse_flags() {
    let cx = Cx::for_testing();
    let cb = CLUSTER_BYTES as u64;
    let (device, mut engine, file) = fixture(128, b"BASE");
    let name = [0xD800, u16::from(b'x')];
    let mut expected = vec![0x5A; 4 * CLUSTER_BYTES];
    engine
        .create_file_stream(&cx, "/punch.bin", &name, &expected)
        .into_result()
        .unwrap();
    let before = used_clusters(&device);
    engine
        .punch_hole_at(&cx, file, &name, cb, 2 * cb, DEFAULT_FILETIME)
        .into_result()
        .unwrap();
    expected[CLUSTER_BYTES..3 * CLUSTER_BYTES].fill(0);
    assert_stream(&engine, file, &name, &expected, 2 * cb, 4 * cb);
    assert_stream(&engine, file, &[], b"BASE", 4, 4);
    assert_eq!(used_clusters(&device), before - 2);
    let (_, record) = view(&engine, file);
    assert_eq!(standard_flags(&record) & 0x200, 0);
    let attributes = record.attributes().unwrap();
    let attribute = attributes
        .iter()
        .find(|attribute| attribute.kind == DATA && attribute.name == name)
        .unwrap();
    assert_eq!(attribute.flags & SPARSE, SPARSE);
    let NtfsValue::NonResident(extent) = &attribute.value else {
        panic!("large ADS must remain nonresident");
    };
    assert_eq!(extent.compression_unit, 0);
    assert_eq!(extent.compressed_size, Some(2 * cb));
    assert_name_copies(&device, &engine, file, 8, 4);
    engine.check_clean_consistency(&cx).unwrap();
}

#[test]
fn hole_punch_large_sparse_ads_preserves_valid_tail_and_extension_streams() {
    let cx = Cx::for_testing();
    let cb = CLUSTER_BYTES as u64;
    let (device, mut engine, file, name) = large_sparse_stream_fixture();
    let sentinels = [vec![u16::from(b'a'); 240], vec![u16::from(b'z'); 240]];
    for sentinel in &sentinels {
        engine
            .create_file_stream(&cx, "/sparse.bin", sentinel, b"sentinel payload")
            .into_result()
            .unwrap();
    }
    let (_, record) = view(&engine, file);
    assert!(
        record
            .attributes()
            .unwrap()
            .iter()
            .any(|attribute| attribute.kind == ATTRIBUTE_LIST)
    );
    let before = used_clusters(&device);
    engine
        .punch_hole_at(&cx, file, &name, 2, (1 << 26) + 17, DEFAULT_FILETIME)
        .into_result()
        .unwrap();
    let (volume, record) = view(&engine, file);
    let stream = volume.data_stream(&cx, &record, &name).unwrap();
    assert_eq!(stream.size, 1 << 30);
    assert_eq!(stream.initialized, 5);
    assert_eq!(stream.allocated, cb);
    assert_eq!(used_clusters(&device), before - 2);
    let mut expected = [0_u8; 16];
    expected[..2].fill(0xA6);
    assert_eq!(volume.read(&cx, &stream, 0, 16).unwrap(), expected);
    assert_eq!(volume.read(&cx, &stream, 1 << 27, 16).unwrap(), [0; 16]);
    assert_eq!(standard_flags(&record) & 0x200, 0);
    assert_stream(&engine, file, &[], b"BASE", 4, 4);
    for sentinel in &sentinels {
        assert_stream(&engine, file, sentinel, b"sentinel payload", 16, 16);
    }

    // Exposing a formerly uninitialized tail must not reveal stale allocation.
    engine
        .write_stream_range(&cx, file, &name, cb + 7, b"X")
        .into_result()
        .unwrap();
    let (volume, record) = view(&engine, file);
    let stream = volume.data_stream(&cx, &record, &name).unwrap();
    assert_eq!(stream.size, 1 << 30);
    assert_eq!(stream.initialized, cb + 8);
    let bytes = volume.read(&cx, &stream, 0, CLUSTER_BYTES + 8).unwrap();
    assert_eq!(&bytes[..2], [0xA6, 0xA6]);
    assert!(bytes[2..CLUSTER_BYTES + 7].iter().all(|&byte| byte == 0));
    assert_eq!(bytes[CLUSTER_BYTES + 7], b'X');
    engine.check_clean_consistency(&cx).unwrap();
}

#[test]
fn hole_punch_large_dense_range_stages_only_partial_boundary_clusters() {
    let cx = Cx::for_testing();
    let cb = CLUSTER_BYTES as u64;
    let limit = ffs_ntfs::transaction::MAX_FILE_EDIT_BYTES;
    let (device, mut engine, file) = fixture(4352, &vec![0xA5; limit as usize]);
    engine
        .write_stream_range(&cx, file, &[], limit, &vec![0xB6; 3 * CLUSTER_BYTES])
        .into_result()
        .unwrap();
    let before = used_clusters(&device);
    let trace_start = engine.persistence_trace().len();
    let start = cb + 17;
    let end = limit + cb + 23;
    engine
        .punch_hole_at(&cx, file, &[], start, end - start, DEFAULT_FILETIME)
        .into_result()
        .unwrap();
    let payload_bytes: usize = engine.persistence_trace()[trace_start..]
        .iter()
        .filter(|event| event.stage == NtfsPersistenceStage::PayloadDataWrite)
        .map(|event| event.bytes)
        .sum();
    assert_eq!(payload_bytes, 2 * CLUSTER_BYTES);
    let (volume, record) = view(&engine, file);
    let stream = volume.data_stream(&cx, &record, &[]).unwrap();
    let size = limit + 3 * cb;
    assert_eq!(stream.size, size);
    assert_eq!(stream.initialized, size);
    assert_eq!(stream.allocated, 4 * cb);
    assert_eq!(used_clusters(&device), before - 4095);
    assert_eq!(volume.read(&cx, &stream, start - 1, 2).unwrap(), [0xA5, 0]);
    assert_eq!(volume.read(&cx, &stream, end - 1, 2).unwrap(), [0, 0xB6]);
    assert_eq!(volume.read(&cx, &stream, limit / 2, 16).unwrap(), [0; 16]);
    assert_eq!(
        volume.read(&cx, &stream, size - 16, 32).unwrap(),
        [0xB6; 16]
    );
    assert_name_copies(&device, &engine, file, 4 * cb, size);
    engine.check_clean_consistency(&cx).unwrap();
}

#[test]
fn hole_punch_preflight_errors_and_boundary_enospc_do_not_write() {
    let cx = Cx::for_testing();
    let cb = CLUSTER_BYTES as u64;
    let mut expected = vec![0x79; 5 * CLUSTER_BYTES];
    let (device, mut engine, file) = fixture(99, &expected);
    let before = device.snapshot_durable_only();
    let written = device.write_bytes_total();
    let stale = NtfsReference {
        record: file.record,
        sequence: file.sequence.wrapping_add(1),
    };
    let missing = [u16::from(b'x')];
    let invalid = [u16::from(b':')];
    let overlong = vec![u16::from(b'x'); 256];
    for (target, name, offset, length, errno) in [
        (file, &[][..], 0, 0, libc::EINVAL),
        (file, &[][..], u64::MAX, 2, libc::EFBIG),
        (file, &[][..], i64::MAX as u64, 1, libc::EFBIG),
        (stale, &[][..], 0, 1, libc::ESTALE),
        (stale, &[][..], 1 << 30, 1, libc::ESTALE),
        (file, &missing[..], 0, 1, libc::ENOENT),
        (file, &invalid[..], 0, 1, libc::EINVAL),
        (file, &overlong[..], 0, 1, libc::ENAMETOOLONG),
        (file, &[][..], 1, 4 * cb - 2, libc::ENOSPC),
    ] {
        let outcome = engine.punch_hole_at(&cx, target, name, offset, length, DEFAULT_FILETIME);
        let NtfsTxOutcome::NotCommitted(error) = outcome else {
            panic!("preflight error must not publish: {outcome:?}");
        };
        assert_eq!(error.to_errno(), errno);
        assert_eq!(device.write_bytes_total(), written);
        assert_eq!(device.snapshot_live(), before);
        assert_eq!(device.snapshot_durable_only(), before);
    }
    let cancelled = Cx::for_testing();
    cancelled.set_cancel_requested(true);
    assert!(matches!(
        engine.punch_hole_at(&cancelled, file, &[], 0, 1, DEFAULT_FILETIME),
        NtfsTxOutcome::NotCommitted(FfsError::Cancelled)
    ));
    assert_eq!(device.write_bytes_total(), written);
    assert_eq!(device.snapshot_live(), before);

    // An aligned punch needs no fresh payload allocation even on this volume.
    engine
        .punch_hole_at(&cx, file, &[], cb, 2 * cb, DEFAULT_FILETIME)
        .into_result()
        .unwrap();
    expected[CLUSTER_BYTES..3 * CLUSTER_BYTES].fill(0);
    assert_stream(&engine, file, &[], &expected, 3 * cb, 5 * cb);
    engine.check_clean_consistency(&cx).unwrap();
}

#[test]
fn hole_punch_recovers_whole_bytes_flags_and_allocation_at_every_cut() {
    let cx = Cx::for_testing();
    let cb = CLUSTER_BYTES as u64;
    let original = vec![0xA8; 4 * CLUSTER_BYTES + 11];
    let (device, mut engine, file) = fixture(128, &original);
    let before = used_clusters(&device);
    let mut expected = original.clone();
    expected[13..3 * CLUSTER_BYTES + 13].fill(0);
    type Cut = (NtfsPersistenceStage, bool, Vec<u8>, Vec<u8>);
    let cuts: Arc<Mutex<Vec<Cut>>> = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&cuts);
    let source = Arc::clone(&device);
    let mut committed = false;
    engine.set_stage_hook(Some(Box::new(move |event| {
        committed |= event.stage == NtfsPersistenceStage::LogCommitBarrier;
        captured.lock().unwrap().push((
            event.stage,
            committed,
            source.snapshot_durable_only(),
            source.snapshot_reordered_pending(true),
        ));
        Ok(())
    })));
    engine
        .punch_hole_at(&cx, file, &[], 13, 3 * cb, DEFAULT_FILETIME)
        .into_result()
        .unwrap();
    engine.set_stage_hook(None);
    let captured = cuts.lock().unwrap();
    assert!(captured.iter().any(|(_, committed, _, _)| !committed));
    assert!(captured.iter().any(|(_, committed, _, _)| *committed));
    for (stage, committed, durable, reordered) in captured.iter() {
        for (image, may_be_newer) in [(durable, false), (reordered, true)] {
            let recovered_device = FaultInjectingNtfsDevice::new(image.clone());
            let recovered = NtfsTransactionEngine::from_device(
                &cx,
                Arc::clone(&recovered_device) as Arc<dyn ByteDevice>,
                0,
                image.len() as u64 - SECTOR_BYTES as u64,
                write_options_recover(),
            )
            .unwrap_or_else(|error| panic!("recovery at {stage:?}: {error}"));
            recovered.check_clean_consistency(&cx).unwrap();
            let (volume, record) = view(&recovered, file);
            let stream = volume.data_stream(&cx, &record, &[]).unwrap();
            let observed = volume.read(&cx, &stream, 0, original.len() + 1).unwrap();
            let applied = observed == expected;
            assert!(
                applied || observed == original,
                "mixed hole-punch bytes at {stage:?}"
            );
            if *committed || !may_be_newer {
                assert_eq!(applied, *committed, "wrong durable prefix at {stage:?}");
            }
            let allocated = if applied { 3 * cb } else { 5 * cb };
            assert_eq!(stream.size, original.len() as u64);
            assert_eq!(stream.initialized, original.len() as u64);
            assert_eq!(stream.allocated, allocated);
            assert_eq!(
                standard_flags(&record) & 0x200,
                if applied { 0x200 } else { 0 }
            );
            assert_eq!(
                used_clusters(&recovered_device),
                if applied { before - 2 } else { before }
            );
            assert_name_copies(
                &recovered_device,
                &recovered,
                file,
                allocated,
                original.len() as u64,
            );
        }
    }
}

#[test]
fn hole_punch_payload_barrier_failure_preserves_the_previous_allocation() {
    let cx = Cx::for_testing();
    let cb = CLUSTER_BYTES as u64;
    let original = vec![0xB9; 4 * CLUSTER_BYTES];
    let (device, mut engine, file) = fixture(128, &original);
    let before = used_clusters(&device);
    device.set_fail_sync_call(Some(1));
    assert!(matches!(
        engine.punch_hole_at(&cx, file, &[], 13, 3 * cb, DEFAULT_FILETIME),
        NtfsTxOutcome::NotCommitted(_)
    ));
    device.set_fail_sync_call(None);
    assert_stream(&engine, file, &[], &original, 4 * cb, 4 * cb);
    assert_eq!(used_clusters(&device), before);
    assert!(!engine.requires_recovery());
    engine.check_clean_consistency(&cx).unwrap();
}
