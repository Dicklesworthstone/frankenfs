//! Hole-punch and allocated zero-range metadata and recovery through the native engine.

use super::{
    Arc, ByteDevice, CLUSTER_BYTES, Cx, DEFAULT_FILETIME, FaultInjectingNtfsDevice, FfsError,
    Mutex, NtfsFileRecord, NtfsPersistenceStage, NtfsReference, NtfsTransactionEngine,
    NtfsTxOutcome, NtfsVolume, SECTOR_BYTES, build_clean_ntfs_image, hard_link_index_values,
    large_sparse_stream_fixture, write_options_clean, write_options_recover,
};
use ffs_core::{FsOps, RequestScope};
use ffs_ntfs::NtfsEaSetMode;
use ffs_ntfs::efs::NtfsEfsKey;
use ffs_ntfs::formatter::{NtfsFormatOptions, format_image_file};
use ffs_ntfs::reader::filesystem::NtfsFs;
use ffs_ondisk::ntfs::ea::{FILE_NEED_EA, NtfsEa};
use ffs_ondisk::ntfs::index::NtfsFileName;
use ffs_ondisk::ntfs::reparse::{NtfsReparseData, NtfsReparsePoint};
use ffs_ondisk::ntfs::usn::{
    USN_REASON_BASIC_INFO_CHANGE, USN_REASON_CLOSE, USN_REASON_DATA_EXTEND,
    USN_REASON_DATA_OVERWRITE, USN_REASON_NAMED_DATA_EXTEND, USN_REASON_NAMED_DATA_OVERWRITE,
    UsnRecordV2, parse_usn_journal_slice,
};
use ffs_ondisk::ntfs::{ATTRIBUTE_LIST, DATA, NtfsValue, SPARSE, decode_mapping_pairs};
use ffs_types::InodeNumber;
use std::collections::BTreeMap;
use std::ffi::OsStr;

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

#[test]
fn zero_range_resident_and_keep_size_allocation_preserve_existing_bytes() {
    let cx = Cx::for_testing();
    let cb = CLUSTER_BYTES as u64;
    let (device, mut engine, file) = fixture(128, b"ABCDEFGHIJKLMNO");
    let before = used_clusters(&device);
    let mut expected = b"ABCDEFGHIJKLMNO".to_vec();
    expected[3..8].fill(0);
    engine
        .zero_range_at(&cx, file, &[], 3, 5, false, DEFAULT_FILETIME)
        .into_result()
        .unwrap();
    assert_stream(&engine, file, &[], &expected, 15, 15);
    assert_eq!(used_clusters(&device), before);

    // KEEP_SIZE still allocates past EOF; promotion must retain all old resident
    // bytes even though none overlaps the requested range.
    engine
        .zero_range_at(&cx, file, &[], 2 * cb + 7, 13, true, DEFAULT_FILETIME + 1)
        .into_result()
        .unwrap();
    assert_stream(&engine, file, &[], &expected, 3 * cb, 15);
    assert_eq!(used_clusters(&device), before + 3);
    assert_name_copies(&device, &engine, file, 3 * cb, 15);
    let durable = device.snapshot_durable_only();
    for (vcn, lcn) in mapped_clusters(&engine, file, &[]) {
        let at = lcn.unwrap() as usize * CLUSTER_BYTES;
        let mut physical = vec![0; CLUSTER_BYTES];
        if vcn == 0 {
            physical[..expected.len()].copy_from_slice(&expected);
        }
        assert_eq!(&durable[at..at + CLUSTER_BYTES], physical);
    }
    let mut reopened = NtfsTransactionEngine::from_device(
        &cx,
        FaultInjectingNtfsDevice::new(durable.clone()) as Arc<dyn ByteDevice>,
        0,
        durable.len() as u64 - SECTOR_BYTES as u64,
        write_options_clean(),
    )
    .unwrap();
    assert_stream(&reopened, file, &[], &expected, 3 * cb, 15);
    reopened
        .write_stream_range(&cx, file, &[], 2 * cb + 7, b"tail")
        .into_result()
        .unwrap();
    expected.resize(2 * CLUSTER_BYTES + 11, 0);
    expected[2 * CLUSTER_BYTES + 7..].copy_from_slice(b"tail");
    assert_stream(
        &reopened,
        file,
        &[],
        &expected,
        3 * cb,
        expected.len() as u64,
    );
    reopened.check_clean_consistency(&cx).unwrap();
}

#[test]
fn zero_range_sparse_ads_preserves_valid_prefix_extension_catalogs_and_holes() {
    let cx = Cx::for_testing();
    let cb = CLUSTER_BYTES as u64;
    let (device, mut engine, file, name) = large_sparse_stream_fixture();
    let sentinels: Vec<Vec<u16>> = (0..8)
        .map(|index| {
            format!("sentinel-stream-with-a-long-name-{index}")
                .encode_utf16()
                .collect()
        })
        .collect();
    for sentinel in &sentinels {
        engine
            .create_stream(&cx, file, sentinel, b"sentinel payload")
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
    // VDL is five bytes. Zeroing later bytes in the same physical cluster must
    // preserve those five bytes, not clear the whole uninitialized boundary.
    engine
        .zero_range_at(&cx, file, &name, 7, 3, true, DEFAULT_FILETIME)
        .into_result()
        .unwrap();
    let far = (1_u64 << 29) + 13;
    engine
        .zero_range_at(&cx, file, &name, far, 2 * cb, true, DEFAULT_FILETIME)
        .into_result()
        .unwrap();
    let (volume, record) = view(&engine, file);
    let stream = volume.data_stream(&cx, &record, &name).unwrap();
    assert_eq!(
        (stream.size, stream.initialized, stream.allocated),
        (1 << 30, 5, 6 * cb)
    );
    let mut prefix = [0; 16];
    prefix[..5].fill(0xA6);
    assert_eq!(volume.read(&cx, &stream, 0, 16).unwrap(), prefix);
    assert_eq!(
        volume
            .read(&cx, &stream, far - 1, 2 * CLUSTER_BYTES + 2)
            .unwrap(),
        vec![0; 2 * CLUSTER_BYTES + 2]
    );
    assert_eq!(used_clusters(&device), before + 3);
    assert_eq!(
        standard_flags(&record) & 0x200,
        0,
        "ADS allocation must not change unnamed DATA policy"
    );
    assert_stream(&engine, file, &[], b"BASE", 4, 4);
    for sentinel in &sentinels {
        assert_stream(&engine, file, sentinel, b"sentinel payload", 16, 16);
    }
    engine
        .write_stream_range(&cx, file, &name, cb + 7, b"X")
        .into_result()
        .unwrap();
    let (volume, record) = view(&engine, file);
    let stream = volume.data_stream(&cx, &record, &name).unwrap();
    let prefix = volume.read(&cx, &stream, 0, CLUSTER_BYTES + 8).unwrap();
    assert_eq!(&prefix[..5], [0xA6; 5]);
    assert!(prefix[5..CLUSTER_BYTES + 7].iter().all(|&byte| byte == 0));
    assert_eq!(prefix[CLUSTER_BYTES + 7], b'X');
    engine.check_clean_consistency(&cx).unwrap();
}

#[test]
fn zero_range_rejects_invalid_and_unaffordable_edits_without_writes() {
    let cx = Cx::for_testing();
    let cb = CLUSTER_BYTES as u64;
    let (device, mut engine, file) = fixture(99, &vec![0x79; 5 * CLUSTER_BYTES]);
    let before = device.snapshot_durable_only();
    let written = device.write_bytes_total();
    let stale = NtfsReference {
        record: file.record,
        sequence: file.sequence.wrapping_add(1),
    };
    for (target, name, offset, length, errno) in [
        (file, &[][..], 0, 0, libc::EINVAL),
        (file, &[][..], u64::MAX, 2, libc::EFBIG),
        (file, &[][..], i64::MAX as u64 - 1, 1, libc::EFBIG),
        (
            file,
            &[][..],
            0,
            ffs_ntfs::transaction::MAX_FILE_EDIT_BYTES + 3 * cb,
            libc::EFBIG,
        ),
        (stale, &[][..], 0, 1, libc::ESTALE),
        (file, &[u16::from(b'x')][..], 0, 1, libc::ENOENT),
        (file, &[u16::from(b':')][..], 0, 1, libc::EINVAL),
        (file, &[][..], 1, 4 * cb - 2, libc::ENOSPC),
    ] {
        let outcome =
            engine.zero_range_at(&cx, target, name, offset, length, true, DEFAULT_FILETIME);
        let NtfsTxOutcome::NotCommitted(error) = outcome else {
            panic!("zero-range admission must precede writes: {outcome:?}");
        };
        assert_eq!(error.to_errno(), errno);
        assert_eq!(device.write_bytes_total(), written);
        assert_eq!(device.snapshot_live(), before);
        assert_eq!(device.snapshot_durable_only(), before);
    }
    let cancelled = Cx::for_testing();
    cancelled.set_cancel_requested(true);
    assert!(matches!(
        engine.zero_range_at(&cancelled, file, &[], 0, 1, false, DEFAULT_FILETIME),
        NtfsTxOutcome::NotCommitted(FfsError::Cancelled)
    ));
    assert_eq!(device.write_bytes_total(), written);
}

#[test]
fn zero_range_transformed_and_provider_refusals_preserve_native_state() {
    let cx = Cx::for_testing();
    for transform in ["compressed", "encrypted", "reparse"] {
        let (device, mut engine, file) = journal_fixture(&vec![0x4B; 3 * CLUSTER_BYTES]);
        match transform {
            "compressed" => engine
                .set_compression_at(&cx, file, true, DEFAULT_FILETIME)
                .into_result()
                .unwrap(),
            "encrypted" => engine
                .encrypt_file_at(
                    &cx,
                    file,
                    &NtfsEfsKey::from_raw_bytes([0x37; 32]),
                    DEFAULT_FILETIME,
                )
                .into_result()
                .unwrap(),
            "reparse" => engine
                .set_reparse_point_at(
                    &cx,
                    file,
                    &NtfsReparsePoint {
                        tag: 0x9000_0017,
                        guid: None,
                        data: NtfsReparseData::Opaque(vec![0xAC; 16]),
                    },
                    true,
                    DEFAULT_FILETIME,
                )
                .into_result()
                .unwrap(),
            _ => unreachable!(),
        };
        let before = device.snapshot_durable_only();
        let writes = device.write_bytes_total();
        for keep_size in [false, true] {
            assert!(
                matches!(
                    engine.zero_range_at(
                        &cx,
                        file,
                        &[],
                        1,
                        CLUSTER_BYTES as u64,
                        keep_size,
                        DEFAULT_FILETIME + 1
                    ),
                    NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(_))
                ),
                "{transform}"
            );
            assert_eq!(device.write_bytes_total(), writes);
            assert_eq!(device.snapshot_live(), before);
            assert_eq!(device.snapshot_durable_only(), before);
        }
    }
}

#[test]
fn zero_range_recovers_complete_allocations_and_eof_at_every_publication_cut() {
    let cx = Cx::for_testing();
    let cb = CLUSTER_BYTES as u64;
    for keep_size in [false, true] {
        let mut original = vec![0x68; 3 * CLUSTER_BYTES + 17];
        let (device, mut engine, file) = fixture(160, &original);
        engine
            .punch_hole_at(&cx, file, &[], cb, cb, DEFAULT_FILETIME)
            .into_result()
            .unwrap();
        original[CLUSTER_BYTES..2 * CLUSTER_BYTES].fill(0);
        engine
            .link_file(&cx, "/punch.bin", "/", "alias.bin")
            .into_result()
            .unwrap();
        let ads: Vec<_> = "audit".encode_utf16().collect();
        engine
            .create_stream(&cx, file, &ads, b"unchanged stream")
            .into_result()
            .unwrap();
        let before = used_clusters(&device);
        let mut expected = original.clone();
        if !keep_size {
            expected.resize(5 * CLUSTER_BYTES + 5, 0);
        }
        expected[CLUSTER_BYTES + 5..].fill(0);
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
            .zero_range_at(
                &cx,
                file,
                &[],
                cb + 5,
                4 * cb,
                keep_size,
                DEFAULT_FILETIME + 1,
            )
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
                .unwrap_or_else(|error| panic!("zero-range recovery at {stage:?}: {error}"));
                recovered.check_clean_consistency(&cx).unwrap();
                let (volume, record) = view(&recovered, file);
                let stream = volume.data_stream(&cx, &record, &[]).unwrap();
                let observed = volume.read(&cx, &stream, 0, 6 * CLUSTER_BYTES).unwrap();
                let applied = observed == expected;
                assert!(applied || observed == original, "mixed bytes at {stage:?}");
                if *committed || !may_be_newer {
                    assert_eq!(applied, *committed, "wrong committed prefix at {stage:?}");
                }
                let allocated = if applied { 6 * cb } else { 3 * cb };
                assert_eq!(stream.allocated, allocated);
                assert_eq!(stream.initialized, original.len() as u64);
                assert_eq!(
                    used_clusters(&recovered_device),
                    if applied { before + 3 } else { before }
                );
                assert_stream(&recovered, file, &ads, b"unchanged stream", 16, 16);
                assert_name_copies(
                    &recovered_device,
                    &recovered,
                    file,
                    allocated,
                    observed.len() as u64,
                );
            }
        }
    }
}

#[test]
fn zero_range_payload_failure_and_native_usn_publication_remain_consistent() {
    let cx = Cx::for_testing();
    let cb = CLUSTER_BYTES as u64;
    let original = vec![0xA9; 3 * CLUSTER_BYTES];
    let (device, mut engine, file) = journal_fixture(&original);
    let ads: Vec<_> = "audit".encode_utf16().collect();
    engine
        .create_stream(&cx, file, &ads, b"named bytes")
        .into_result()
        .unwrap();
    let before = journal_records(&engine.volume_view(&cx).unwrap());
    device.set_fail_sync_call(Some(1));
    assert!(matches!(
        engine.zero_range_at(&cx, file, &[], 7, 4 * cb, false, DEFAULT_FILETIME + 1),
        NtfsTxOutcome::NotCommitted(_)
    ));
    device.set_fail_sync_call(None);
    assert_stream(&engine, file, &[], &original, 3 * cb, 3 * cb);
    assert_eq!(journal_records(&engine.volume_view(&cx).unwrap()), before);
    assert!(!engine.requires_recovery());
    engine
        .zero_range_at(&cx, file, &[], 7, 4 * cb, false, DEFAULT_FILETIME + 2)
        .into_result()
        .unwrap();
    let after = assert_punch_record(
        &engine,
        file,
        &before,
        USN_REASON_DATA_OVERWRITE | USN_REASON_DATA_EXTEND | USN_REASON_CLOSE,
        DEFAULT_FILETIME + 2,
    );
    engine
        .zero_range_at(&cx, file, &ads, 5, cb, false, DEFAULT_FILETIME + 3)
        .into_result()
        .unwrap();
    assert_punch_record(
        &engine,
        file,
        &after,
        USN_REASON_NAMED_DATA_OVERWRITE | USN_REASON_NAMED_DATA_EXTEND | USN_REASON_CLOSE,
        DEFAULT_FILETIME + 3,
    );
    let durable = device.snapshot_durable_only();
    let reopened = NtfsTransactionEngine::from_device(
        &cx,
        FaultInjectingNtfsDevice::new(durable.clone()) as Arc<dyn ByteDevice>,
        0,
        durable.len() as u64 - SECTOR_BYTES as u64,
        write_options_clean(),
    )
    .unwrap();
    let mut expected = vec![0; 4 * CLUSTER_BYTES + 7];
    expected[..7].fill(0xA9);
    assert_stream(&reopened, file, &[], &expected, 5 * cb, 3 * cb);
    let mut named = vec![0; CLUSTER_BYTES + 5];
    named[..5].copy_from_slice(b"named");
    assert_stream(&reopened, file, &ads, &named, 2 * cb, 11);
    reopened.check_clean_consistency(&cx).unwrap();
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
fn compressed_hole_punch_reclaims_units_preserves_links_streams_and_eof() {
    let cx = Cx::for_testing();
    let cb = CLUSTER_BYTES as u64;
    let unit = 16 * CLUSTER_BYTES;
    let mut expected = vec![0x6D; 4 * unit + 37];
    // Keep one literal (incompressible) unit alongside compressed units. Both
    // representations must survive the partial-unit decode/COW path.
    let mut random = 0x8B1D_716E_0154_32A9_u64;
    for byte in &mut expected[unit..2 * unit] {
        random = random
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *byte = (random >> 33) as u8;
    }
    let (device, mut engine, file) = fixture(256, &expected);
    engine
        .set_compression_at(&cx, file, true, DEFAULT_FILETIME)
        .into_result()
        .unwrap();
    engine
        .link_file(&cx, "/punch.bin", "/", "alias.bin")
        .into_result()
        .unwrap();
    let ads: Vec<_> = "audit".encode_utf16().collect();
    engine
        .create_file_stream(&cx, "/punch.bin", &ads, b"independent stream")
        .into_result()
        .unwrap();
    let before = used_clusters(&device);
    let start = unit + 137;
    let end = 3 * unit + 29;
    let trace_start = engine.persistence_trace().len();
    engine
        .punch_hole_at(
            &cx,
            file,
            &[],
            start as u64,
            (end - start) as u64,
            DEFAULT_FILETIME + 1,
        )
        .into_result()
        .unwrap();
    expected[start..end].fill(0);
    let payload_bytes: usize = engine.persistence_trace()[trace_start..]
        .iter()
        .filter(|event| event.stage == NtfsPersistenceStage::PayloadDataWrite)
        .map(|event| event.bytes)
        .sum();
    assert!(payload_bytes <= 2 * unit);
    assert_stream(&engine, file, &[], &expected, 4 * cb, expected.len() as u64);
    assert!(used_clusters(&device) < before);
    assert_name_copies(&device, &engine, file, 4 * cb, expected.len() as u64);
    let (volume, record) = view(&engine, file);
    assert_eq!(standard_flags(&record) & (0x800 | 0x200), 0x800);
    assert_eq!(
        u64::from(volume.resolve(&cx, "/alias.bin").unwrap().number),
        file.record
    );
    let alternate = volume.data_stream(&cx, &record, &ads).unwrap();
    assert_eq!(
        volume.read(&cx, &alternate, 0, 64).unwrap(),
        b"independent stream"
    );
    engine.check_clean_consistency(&cx).unwrap();

    // Removing every visible byte must retain compressed identity and EOF,
    // including the short final unit, while reclaiming all physical DATA.
    engine
        .punch_hole_at(
            &cx,
            file,
            &[],
            0,
            (expected.len() + unit) as u64,
            DEFAULT_FILETIME + 2,
        )
        .into_result()
        .unwrap();
    expected.fill(0);
    assert_stream(&engine, file, &[], &expected, 0, expected.len() as u64);
    assert_name_copies(&device, &engine, file, 0, expected.len() as u64);
    engine.check_clean_consistency(&cx).unwrap();

    let image = device.snapshot_durable_only();
    let length = image.len() as u64 - SECTOR_BYTES as u64;
    let reopened_device = FaultInjectingNtfsDevice::new(image);
    let reopened = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&reopened_device) as Arc<dyn ByteDevice>,
        0,
        length,
        write_options_clean(),
    )
    .unwrap();
    assert_stream(&reopened, file, &[], &expected, 0, expected.len() as u64);
    assert_eq!(
        standard_flags(&view(&reopened, file).1) & (0x800 | 0x200),
        0x800
    );
    reopened.check_clean_consistency(&cx).unwrap();
    assert_eq!(reopened_device.write_bytes_total(), 0);
}

#[test]
fn compressed_hole_punch_large_sparse_tail_preserves_valid_data_length() {
    let cx = Cx::for_testing();
    let cb = CLUSTER_BYTES as u64;
    let unit = 16 * cb;
    let original = vec![0xB2; 4 * unit as usize];
    let (device, mut engine, file) = fixture(256, &original);
    engine
        .set_compression_at(&cx, file, true, DEFAULT_FILETIME)
        .into_result()
        .unwrap();
    let size = 1_u64 << 40;
    engine
        .truncate_stream_at(&cx, file, &[], size, DEFAULT_FILETIME)
        .into_result()
        .unwrap();
    let before = used_clusters(&device);
    let trace_start = engine.persistence_trace().len();
    let start = unit + 7;
    let end = size - 9;
    engine
        .punch_hole_at(&cx, file, &[], start, end - start, DEFAULT_FILETIME + 1)
        .into_result()
        .unwrap();
    let payload_bytes: usize = engine.persistence_trace()[trace_start..]
        .iter()
        .filter(|event| event.stage == NtfsPersistenceStage::PayloadDataWrite)
        .map(|event| event.bytes)
        .sum();
    assert_eq!(payload_bytes, CLUSTER_BYTES);
    assert_eq!(used_clusters(&device), before - 2);
    let (volume, record) = view(&engine, file);
    let stream = volume.data_stream(&cx, &record, &[]).unwrap();
    assert_eq!(stream.size, size);
    assert_eq!(stream.initialized, original.len() as u64);
    assert_eq!(stream.allocated, 2 * cb);
    assert_eq!(standard_flags(&record) & (0x800 | 0x200), 0x800);
    assert_eq!(volume.read(&cx, &stream, start - 1, 2).unwrap(), [0xB2, 0]);
    assert_eq!(volume.read(&cx, &stream, size / 2, 17).unwrap(), [0; 17]);
    assert_eq!(volume.read(&cx, &stream, size - 17, 32).unwrap(), [0; 17]);
    assert_name_copies(&device, &engine, file, 2 * cb, size);
    engine.check_clean_consistency(&cx).unwrap();

    // A range beyond EOF is still a read-only no-op for a compressed stream.
    let snapshot = device.snapshot_durable_only();
    let written = device.write_bytes_total();
    engine
        .punch_hole_at(&cx, file, &[], size, 1, DEFAULT_FILETIME + 2)
        .into_result()
        .unwrap();
    assert_eq!(device.write_bytes_total(), written);
    assert_eq!(device.snapshot_live(), snapshot);
}

#[test]
fn hole_punch_noop_keeps_durable_token_without_writes_or_barriers() {
    let cx = Cx::for_testing();
    for (length, compressed) in [
        (17, false),
        (2 * CLUSTER_BYTES, false),
        (32 * CLUSTER_BYTES, true),
    ] {
        let original = vec![0x6B; length];
        let (device, mut engine, file) = fixture(256, &original);
        if compressed {
            engine
                .set_compression_at(&cx, file, true, DEFAULT_FILETIME)
                .into_result()
                .unwrap();
        }
        let before = device.snapshot_durable_only();
        let writes = device.write_bytes_total();
        let syncs = device.state.lock().unwrap().sync_calls;
        let events = engine.persistence_trace().len();
        for offset in [length as u64, length as u64 + 4096, i64::MAX as u64 - 1] {
            let ((), token) = engine
                .punch_hole_at(&cx, file, &[], offset, 1, DEFAULT_FILETIME + 1)
                .into_result()
                .unwrap();
            assert_eq!(token.transaction_id(), 0, "no transaction was needed");
            assert!(token.matches_engine(&engine));
            assert_ne!(token.commit_lsn(), 0);
            assert!(!engine.requires_recovery());
            assert_eq!(device.write_bytes_total(), writes);
            assert_eq!(device.state.lock().unwrap().sync_calls, syncs);
            assert_eq!(engine.persistence_trace().len(), events);
            assert_eq!(device.snapshot_live(), before);
            assert_eq!(device.snapshot_durable_only(), before);
        }
        let cancelled = Cx::for_testing();
        cancelled.set_cancel_requested(true);
        assert!(matches!(
            engine.punch_hole_at(
                &cancelled,
                file,
                &[],
                length as u64,
                1,
                DEFAULT_FILETIME + 2,
            ),
            NtfsTxOutcome::NotCommitted(FfsError::Cancelled)
        ));
        assert_eq!(device.write_bytes_total(), writes);
        assert_eq!(device.state.lock().unwrap().sync_calls, syncs);
        assert_eq!(engine.persistence_trace().len(), events);
        assert_eq!(device.snapshot_live(), before);
    }
}

#[test]
fn hole_punch_noop_refuses_pending_native_recovery() {
    let cx = Cx::for_testing();
    for stage in [
        NtfsPersistenceStage::DirtyRestartBarrier,
        NtfsPersistenceStage::LogCommitBarrier,
        NtfsPersistenceStage::TargetMetadataBarrier,
    ] {
        let (device, mut engine, file) = fixture(128, b"retained payload");
        engine.set_stage_hook(Some(Box::new(move |event| {
            if event.stage == stage {
                return Err(FfsError::Io(std::io::Error::other("publication cut")));
            }
            Ok(())
        })));
        let outcome = engine.punch_hole_at(&cx, file, &[], 1, 2, DEFAULT_FILETIME);
        if stage == NtfsPersistenceStage::DirtyRestartBarrier {
            assert!(matches!(outcome, NtfsTxOutcome::NotCommitted(_)));
        } else {
            assert!(matches!(outcome, NtfsTxOutcome::Uncertain { .. }));
        }
        engine.set_stage_hook(None);
        assert!(engine.requires_recovery(), "{stage:?}");
        let live = device.snapshot_live();
        let durable = device.snapshot_durable_only();
        let writes = device.write_bytes_total();
        let syncs = device.state.lock().unwrap().sync_calls;
        let events = engine.persistence_trace().len();
        assert!(matches!(
            engine.punch_hole_at(&cx, file, &[], 4096, 1, DEFAULT_FILETIME + 1),
            NtfsTxOutcome::NotCommitted(FfsError::RequestRejected {
                errno: libc::EIO,
                ..
            })
        ));
        assert!(engine.requires_recovery());
        assert_eq!(device.write_bytes_total(), writes);
        assert_eq!(device.state.lock().unwrap().sync_calls, syncs);
        assert_eq!(engine.persistence_trace().len(), events);
        assert_eq!(device.snapshot_live(), live);
        assert_eq!(device.snapshot_durable_only(), durable);
    }
}

#[test]
fn compressed_hole_punch_on_full_volume_retires_only_whole_units_without_cow() {
    let cx = Cx::for_testing();
    let unit = 16 * CLUSTER_BYTES;
    let mut expected = vec![0x92; 4 * unit];
    let (device, mut engine, file) = fixture(180, &expected);
    engine
        .set_compression_at(&cx, file, true, DEFAULT_FILETIME)
        .into_result()
        .unwrap();
    let free = 180 - used_clusters(&device) as usize;
    engine
        .create_file(&cx, "/", "fill.bin", &vec![0x53; free * CLUSTER_BYTES])
        .into_result()
        .unwrap();
    assert_eq!(used_clusters(&device), 180);
    let before = device.snapshot_durable_only();
    let writes = device.write_bytes_total();
    let outcome = engine.punch_hole_at(
        &cx,
        file,
        &[],
        1,
        (3 * unit) as u64 - 2,
        DEFAULT_FILETIME + 1,
    );
    let NtfsTxOutcome::NotCommitted(error) = outcome else {
        panic!("partial compressed units require fresh COW allocation: {outcome:?}");
    };
    assert_eq!(error.to_errno(), libc::ENOSPC);
    assert_eq!(device.snapshot_live(), before);
    assert_eq!(device.write_bytes_total(), writes);

    let trace_start = engine.persistence_trace().len();
    engine
        .punch_hole_at(
            &cx,
            file,
            &[],
            unit as u64,
            (2 * unit) as u64,
            DEFAULT_FILETIME + 2,
        )
        .into_result()
        .unwrap();
    assert!(
        !engine.persistence_trace()[trace_start..]
            .iter()
            .any(|event| { event.stage == NtfsPersistenceStage::PayloadDataWrite })
    );
    expected[unit..3 * unit].fill(0);
    assert_stream(
        &engine,
        file,
        &[],
        &expected,
        (2 * CLUSTER_BYTES) as u64,
        expected.len() as u64,
    );
    assert_eq!(used_clusters(&device), 178);
    engine.check_clean_consistency(&cx).unwrap();
}

#[test]
fn compressed_hole_punch_recovers_data_allocation_and_usn_at_every_cut() {
    let cx = Cx::for_testing();
    let cb = CLUSTER_BYTES as u64;
    let unit = 16 * CLUSTER_BYTES;
    let original = vec![0xA8; 4 * unit + 11];
    let (device, mut engine, file) = journal_fixture(&original);
    engine
        .set_compression_at(&cx, file, true, DEFAULT_FILETIME)
        .into_result()
        .unwrap();
    let journal_before = journal_records(&engine.volume_view(&cx).unwrap());
    let mut expected = original.clone();
    expected[13..3 * unit + 13].fill(0);

    // A failed payload barrier must leave the previously committed compressed
    // stream authoritative; deferred frees must not become reusable early.
    device.set_fail_sync_call(Some(1));
    assert!(matches!(
        engine.punch_hole_at(&cx, file, &[], 13, (3 * unit) as u64, DEFAULT_FILETIME + 1),
        NtfsTxOutcome::NotCommitted(_)
    ));
    device.set_fail_sync_call(None);
    assert_stream(&engine, file, &[], &original, 5 * cb, original.len() as u64);
    assert_eq!(
        journal_records(&engine.volume_view(&cx).unwrap()),
        journal_before
    );
    engine.check_clean_consistency(&cx).unwrap();

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
        .punch_hole_at(&cx, file, &[], 13, (3 * unit) as u64, DEFAULT_FILETIME + 1)
        .into_result()
        .unwrap();
    engine.set_stage_hook(None);
    let journal_after = assert_punch_record(
        &engine,
        file,
        &journal_before,
        USN_REASON_DATA_OVERWRITE | USN_REASON_CLOSE,
        DEFAULT_FILETIME + 1,
    );
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
            .unwrap_or_else(|error| panic!("compressed punch recovery at {stage:?}: {error}"));
            let (volume, record) = view(&recovered, file);
            let stream = volume.data_stream(&cx, &record, &[]).unwrap();
            let observed = volume.read(&cx, &stream, 0, original.len() + 1).unwrap();
            let applied = observed == expected;
            assert!(
                applied || observed == original,
                "mixed compressed bytes at {stage:?}"
            );
            if *committed || !may_be_newer {
                assert_eq!(
                    applied, *committed,
                    "wrong compressed durable prefix at {stage:?}"
                );
            }
            assert_eq!(stream.size, original.len() as u64);
            assert_eq!(stream.initialized, original.len() as u64);
            assert_eq!(stream.allocated, if applied { 3 * cb } else { 5 * cb });
            assert_eq!(standard_flags(&record) & (0x800 | 0x200), 0x800);
            assert_eq!(
                journal_records(&volume).as_slice(),
                if applied {
                    journal_after.as_slice()
                } else {
                    journal_before.as_slice()
                }
            );
            assert_name_copies(
                &recovered_device,
                &recovered,
                file,
                if applied { 3 * cb } else { 5 * cb },
                original.len() as u64,
            );
            recovered.check_clean_consistency(&cx).unwrap();
        }
    }
}

#[test]
fn compressed_hole_punch_rejects_malformed_unit_layout_before_noop_or_writes() {
    let cx = Cx::for_testing();
    let unit = 16 * CLUSTER_BYTES;
    let (device, mut engine, file) = fixture(256, &vec![0x5D; unit]);
    engine
        .set_compression_at(&cx, file, true, DEFAULT_FILETIME)
        .into_result()
        .unwrap();
    let (volume, record) = view(&engine, file);
    let record_start = CLUSTER_BYTES + usize::try_from(file.record).unwrap() * super::RECORD_BYTES;
    let before = device.snapshot_durable_only();
    let mut attributes = super::copied_test_record_attributes(
        &before[record_start..record_start + super::RECORD_BYTES],
    );
    let data = attributes
        .iter_mut()
        .find(|attribute| u32::from_le_bytes(attribute[..4].try_into().unwrap()) == DATA)
        .unwrap();
    let pairs_at = usize::from(u16::from_le_bytes(data[32..34].try_into().unwrap()));
    let last_vcn = u64::from_le_bytes(data[24..32].try_into().unwrap());
    let runs = decode_mapping_pairs(
        &data[pairs_at..],
        0,
        last_vcn,
        volume.geometry.cluster_count(),
    )
    .unwrap();
    assert_eq!(last_vcn, 15);
    assert_eq!(
        runs.iter()
            .filter(|run| run.lcn.is_some())
            .map(|run| run.clusters)
            .sum::<u64>(),
        1
    );
    let lcn = runs.iter().find_map(|run| run.lcn).unwrap();
    // Keep the physical allocation and full unit span intact, but move the
    // physical prefix after sparse padding. The ordinary reader rejects this.
    let malformed = [
        ffs_ondisk::ntfs::NtfsRun {
            vcn: 0,
            clusters: 1,
            lcn: None,
        },
        ffs_ondisk::ntfs::NtfsRun {
            vcn: 1,
            clusters: 1,
            lcn: Some(lcn),
        },
        ffs_ondisk::ntfs::NtfsRun {
            vcn: 2,
            clusters: 14,
            lcn: None,
        },
    ];
    let (pairs, last_vcn) =
        ffs_ondisk::ntfs::encode_mapping_pairs(&malformed, 0, volume.geometry.cluster_count())
            .unwrap();
    data.resize((pairs_at + pairs.len()).next_multiple_of(8), 0);
    data[pairs_at..].fill(0);
    data[pairs_at..pairs_at + pairs.len()].copy_from_slice(&pairs);
    let attribute_bytes = u32::try_from(data.len()).unwrap();
    data[4..8].copy_from_slice(&attribute_bytes.to_le_bytes());
    data[24..32].copy_from_slice(&last_vcn.to_le_bytes());
    let changed = super::build_file_record(
        u32::try_from(file.record).unwrap(),
        file.sequence,
        record.hard_links,
        false,
        &attributes,
    );
    device
        .write_all_at(&cx, ffs_types::ByteOffset(record_start as u64), &changed)
        .unwrap();
    device.sync(&cx).unwrap();
    let (volume, record) = view(&engine, file);
    assert!(matches!(
        volume.data_stream(&cx, &record, &[]),
        Err(FfsError::Corruption { .. })
    ));

    let before = device.snapshot_durable_only();
    let writes = device.write_bytes_total();
    let events = engine.persistence_trace().len();
    for (offset, length) in [(unit as u64, 1), (0, unit as u64)] {
        let outcome = engine.punch_hole_at(&cx, file, &[], offset, length, DEFAULT_FILETIME + 1);
        assert!(
            matches!(
                outcome,
                NtfsTxOutcome::NotCommitted(FfsError::Corruption { .. })
            ),
            "malformed compressed mapping must be refused before publication: {outcome:?}"
        );
        assert_eq!(device.write_bytes_total(), writes);
        assert_eq!(engine.persistence_trace().len(), events);
        assert_eq!(device.snapshot_live(), before);
        assert_eq!(device.snapshot_durable_only(), before);
    }
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
fn path_stream_edits_preserve_sparse_data_and_extension_catalogs_after_reopen() {
    let cx = Cx::for_testing();
    let cb = CLUSTER_BYTES as u64;
    let (device, mut engine, file, sparse_name) = large_sparse_stream_fixture();
    let sentinels = [vec![u16::from(b'a'); 240], vec![u16::from(b'z'); 240]];
    for name in &sentinels {
        let (created, _) = engine
            .create_file_stream(&cx, "/SPARSE.BIN", name, b"sentinel payload")
            .into_result()
            .unwrap();
        assert_eq!(created, file);
    }
    let (_, record) = view(&engine, file);
    assert!(
        record
            .attributes()
            .unwrap()
            .iter()
            .any(|attribute| attribute.kind == ATTRIBUTE_LIST)
    );

    // The path API must retain the catalog engine's ValidDataLength rules:
    // old allocated bytes after the initialized prefix are logically zero.
    let (written, _) = engine
        .write_file_stream_range(&cx, "/SPARSE.BIN", &sparse_name, cb + 7, b"X")
        .into_result()
        .unwrap();
    assert_eq!(written, file);
    let (truncated, _) = engine
        .truncate_file_stream(&cx, "/sparse.bin", &sparse_name, 2 * cb)
        .into_result()
        .unwrap();
    assert_eq!(truncated, file);

    // A lossless non-Unicode ADS also uses the path-based catalog operation.
    let raw_name = [0xD800, u16::from(b'x')];
    engine
        .create_file_stream(&cx, "/sparse.bin", &raw_name, b"raw stream")
        .into_result()
        .unwrap();
    let (removed, _) = engine
        .remove_file_stream(&cx, "/SPARSE.BIN", &sentinels[0])
        .into_result()
        .unwrap();
    assert_eq!(removed, file);
    engine.check_clean_consistency(&cx).unwrap();

    let durable = device.snapshot_durable_only();
    let length = durable.len() as u64 - SECTOR_BYTES as u64;
    let reopened_device = FaultInjectingNtfsDevice::new(durable);
    let reopened = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&reopened_device) as Arc<dyn ByteDevice>,
        0,
        length,
        write_options_clean(),
    )
    .unwrap();
    let mut expected = vec![0; 2 * CLUSTER_BYTES];
    expected[..5].fill(0xA6);
    expected[CLUSTER_BYTES + 7] = b'X';
    assert_stream(&reopened, file, &sparse_name, &expected, 2 * cb, cb + 8);
    assert_stream(&reopened, file, &[], b"BASE", 4, 4);
    assert_stream(&reopened, file, &sentinels[1], b"sentinel payload", 16, 16);
    assert_stream(&reopened, file, &raw_name, b"raw stream", 10, 10);
    let (volume, record) = view(&reopened, file);
    assert!(matches!(
        volume.data_stream(&cx, &record, &sentinels[0]),
        Err(FfsError::NotFound(_))
    ));
    assert_eq!(standard_flags(&record) & 0x200, 0);
    reopened.check_clean_consistency(&cx).unwrap();
    assert_eq!(reopened_device.write_bytes_total(), 0);
}

#[test]
fn path_stream_refusals_on_sparse_catalogs_do_not_write() {
    let cx = Cx::for_testing();
    let (device, mut engine, _, name) = large_sparse_stream_fixture();
    let folded: Vec<_> = "SPARSE".encode_utf16().collect();
    let missing: Vec<_> = "missing".encode_utf16().collect();
    let before = device.snapshot_durable_only();
    let writes = device.write_bytes_total();
    let events = engine.persistence_trace().len();
    for (outcome, errno) in [
        (
            engine.create_file_stream(&cx, "/sparse.bin", &folded, b"collision"),
            libc::EEXIST,
        ),
        (
            engine.remove_file_stream(&cx, "/sparse.bin", &folded),
            libc::ENOENT,
        ),
        (
            engine.write_file_stream_range(&cx, "/sparse.bin", &folded, 0, b"wrong"),
            libc::ENOENT,
        ),
        (
            engine.truncate_file_stream(&cx, "/sparse.bin", &missing, 0),
            libc::ENOENT,
        ),
        (
            engine.create_file_stream(&cx, "/sparse.bin", &[], b"unnamed"),
            libc::EINVAL,
        ),
        (
            engine.remove_file_stream(&cx, "/sparse.bin", &[]),
            libc::EINVAL,
        ),
        (
            engine.create_file_stream(&cx, "/sparse.bin", &[0x3A], b"invalid"),
            libc::EINVAL,
        ),
        (
            engine.write_file_stream_range(&cx, "/missing", &name, 0, b"missing"),
            libc::ENOENT,
        ),
        (
            engine.truncate_file_stream(&cx, "/", &name, 0),
            libc::EISDIR,
        ),
    ] {
        let NtfsTxOutcome::NotCommitted(error) = outcome else {
            panic!("path stream refusal must precede publication: {outcome:?}");
        };
        assert_eq!(error.to_errno(), errno, "{error}");
    }
    let cancelled = Cx::for_testing();
    cancelled.set_cancel_requested(true);
    assert!(matches!(
        engine.create_file_stream(&cancelled, "/sparse.bin", &missing, b"cancelled"),
        NtfsTxOutcome::NotCommitted(FfsError::Cancelled)
    ));
    assert_eq!(engine.persistence_trace().len(), events);
    assert_eq!(device.write_bytes_total(), writes);
    assert_eq!(device.snapshot_live(), before);
    assert_eq!(device.snapshot_durable_only(), before);
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

fn journal_fixture(
    payload: &[u8],
) -> (
    Arc<FaultInjectingNtfsDevice>,
    NtfsTransactionEngine,
    NtfsReference,
) {
    let cx = Cx::for_testing();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("journal-punch.img");
    let mut options = NtfsFormatOptions::new_image(path.clone(), 4);
    options.cluster_bytes = Some(CLUSTER_BYTES as u32);
    options.logfile_bytes = Some(256 * 1024);
    options.serial = Some(0xA01E_0001_1234_5678);
    let report = format_image_file(&cx, &options, None).unwrap();
    assert!(report.boot_published && report.check_clean);
    let image = std::fs::read(path).unwrap();
    let volume_bytes = image.len() as u64 - SECTOR_BYTES as u64;
    let device = FaultInjectingNtfsDevice::new(image);
    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&device) as Arc<dyn ByteDevice>,
        0,
        volume_bytes,
        write_options_clean(),
    )
    .unwrap();
    engine
        .enable_usn_journal(&cx, 65_536, 4096, DEFAULT_FILETIME)
        .into_result()
        .unwrap();
    let (file, _) = engine
        .create_file(&cx, "/", "punch.bin", payload)
        .into_result()
        .unwrap();
    (device, engine, file)
}

fn journal_records(volume: &NtfsVolume) -> Vec<UsnRecordV2> {
    let cx = Cx::for_testing();
    let summary = volume.usn_summary(&cx).unwrap().expect("active journal");
    let record = volume.record(&cx, u64::from(summary.record), None).unwrap();
    let stream = volume
        .data_stream(&cx, &record, &[u16::from(b'$'), u16::from(b'J')])
        .unwrap();
    let bytes = volume
        .read(
            &cx,
            &stream,
            summary.lowest_valid_usn,
            usize::try_from(summary.next_usn - summary.lowest_valid_usn).unwrap(),
        )
        .unwrap();
    parse_usn_journal_slice(summary.lowest_valid_usn, &bytes).unwrap()
}

fn standard_usn(record: &NtfsFileRecord) -> u64 {
    let attributes = record.attributes().unwrap();
    let standard = attributes
        .iter()
        .find(|attribute| attribute.kind == 0x10)
        .unwrap();
    let NtfsValue::Resident(bytes) = standard.value else {
        panic!("STANDARD_INFORMATION must be resident");
    };
    assert_eq!(bytes.len(), 72, "NTFS 3.1 fixture must retain native USN");
    u64::from_le_bytes(bytes[64..72].try_into().unwrap())
}

fn assert_punch_record(
    engine: &NtfsTransactionEngine,
    file: NtfsReference,
    before: &[UsnRecordV2],
    reason: u32,
    timestamp: u64,
) -> Vec<UsnRecordV2> {
    let (volume, record) = view(engine, file);
    let records = journal_records(&volume);
    assert_eq!(records.len(), before.len() + 1);
    assert_eq!(&records[..before.len()], before);
    let event = records.last().unwrap();
    assert_eq!(event.file_ref, file);
    assert_eq!(event.reason, reason);
    assert_eq!(event.timestamp, timestamp);
    assert_eq!(event.name, "punch.bin".encode_utf16().collect::<Vec<_>>());
    assert_eq!(event.file_attributes, standard_flags(&record));
    assert_eq!(standard_usn(&record), event.usn);
    records
}

#[test]
fn hole_punch_records_unnamed_and_named_changes_without_noop_events() {
    let cx = Cx::for_testing();
    let cb = CLUSTER_BYTES as u64;
    let mut resident = b"original resident bytes".to_vec();
    let (_device, mut engine, file) = journal_fixture(&resident);
    let name: Vec<_> = "audit".encode_utf16().collect();
    let mut named = vec![0xA7; 3 * CLUSTER_BYTES];
    engine
        .create_file_stream(&cx, "/punch.bin", &name, &named)
        .into_result()
        .unwrap();
    let before = journal_records(&engine.volume_view(&cx).unwrap());
    engine
        .punch_hole_at(&cx, file, &[], 3, 5, DEFAULT_FILETIME + 1)
        .into_result()
        .unwrap();
    resident[3..8].fill(0);
    assert_stream(
        &engine,
        file,
        &[],
        &resident,
        resident.len() as u64,
        resident.len() as u64,
    );
    let after_resident = assert_punch_record(
        &engine,
        file,
        &before,
        USN_REASON_DATA_OVERWRITE | USN_REASON_CLOSE,
        DEFAULT_FILETIME + 1,
    );
    engine
        .punch_hole_at(&cx, file, &name, cb, cb, DEFAULT_FILETIME + 2)
        .into_result()
        .unwrap();
    named[CLUSTER_BYTES..2 * CLUSTER_BYTES].fill(0);
    assert_stream(&engine, file, &name, &named, 2 * cb, 3 * cb);
    assert_eq!(standard_flags(&view(&engine, file).1) & 0x200, 0);
    assert_punch_record(
        &engine,
        file,
        &after_resident,
        USN_REASON_NAMED_DATA_OVERWRITE | USN_REASON_CLOSE,
        DEFAULT_FILETIME + 2,
    );

    let mut dense = vec![0xBD; 3 * CLUSTER_BYTES];
    // The ADS is now sparse, so replacing unnamed DATA needs the complete
    // catalog path even though the unnamed stream itself is still resident.
    engine
        .write_file_data_extended(&cx, "/punch.bin", &dense)
        .into_result()
        .unwrap();
    assert_stream(&engine, file, &[], &dense, 3 * cb, 3 * cb);
    assert_stream(&engine, file, &name, &named, 2 * cb, 3 * cb);
    assert_eq!(standard_flags(&view(&engine, file).1) & 0x200, 0);
    let before_dense = journal_records(&engine.volume_view(&cx).unwrap());
    engine
        .punch_hole_at(&cx, file, &[], cb, cb, DEFAULT_FILETIME + 3)
        .into_result()
        .unwrap();
    dense[CLUSTER_BYTES..2 * CLUSTER_BYTES].fill(0);
    assert_stream(&engine, file, &[], &dense, 2 * cb, 3 * cb);
    let after_dense = assert_punch_record(
        &engine,
        file,
        &before_dense,
        USN_REASON_DATA_OVERWRITE | USN_REASON_BASIC_INFO_CHANGE | USN_REASON_CLOSE,
        DEFAULT_FILETIME + 3,
    );
    engine
        .punch_hole_at(&cx, file, &[], 0, 5, DEFAULT_FILETIME + 4)
        .into_result()
        .unwrap();
    dense[..5].fill(0);
    assert_stream(&engine, file, &[], &dense, 2 * cb, 3 * cb);
    let after = assert_punch_record(
        &engine,
        file,
        &after_dense,
        USN_REASON_DATA_OVERWRITE | USN_REASON_CLOSE,
        DEFAULT_FILETIME + 4,
    );

    let usn_before_noop = standard_usn(&view(&engine, file).1);
    engine
        .punch_hole_at(&cx, file, &[], 3 * cb, cb, DEFAULT_FILETIME + 5)
        .into_result()
        .unwrap();
    assert_stream(&engine, file, &[], &dense, 2 * cb, 3 * cb);
    assert_eq!(standard_usn(&view(&engine, file).1), usn_before_noop);
    assert_eq!(journal_records(&engine.volume_view(&cx).unwrap()), after);
    assert_stream(&engine, file, &name, &named, 2 * cb, 3 * cb);
    engine.check_clean_consistency(&cx).unwrap();
}

#[test]
fn hole_punch_fsops_updates_the_active_native_change_journal() {
    let cx = Cx::for_testing();
    let cb = CLUSTER_BYTES as u64;
    let mut expected = vec![0x79; 2 * CLUSTER_BYTES];
    let (device, engine, file) = journal_fixture(&expected);
    let before = journal_records(&engine.volume_view(&cx).unwrap());
    let fs = NtfsFs::from_engine(&cx, engine, 1000, 1000).unwrap();
    let mut scope = RequestScope::empty();
    let attr = fs
        .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("punch.bin"))
        .unwrap();
    fs.fallocate(
        &cx,
        &mut scope,
        attr.ino,
        cb,
        cb,
        libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
    )
    .unwrap();
    let image = device.snapshot_durable_only();
    let volume = NtfsVolume::from_device(
        &cx,
        Box::new(FaultInjectingNtfsDevice::new(image.clone())),
        0,
        image.len() as u64 - SECTOR_BYTES as u64,
    )
    .unwrap();
    let record = volume
        .record(&cx, file.record, Some(file.sequence))
        .unwrap();
    let stream = volume.data_stream(&cx, &record, &[]).unwrap();
    expected[CLUSTER_BYTES..].fill(0);
    assert_eq!(
        volume.read(&cx, &stream, 0, expected.len()).unwrap(),
        expected
    );
    let records = journal_records(&volume);
    assert_eq!(records.len(), before.len() + 1);
    assert_eq!(&records[..before.len()], before.as_slice());
    let event = records.last().unwrap();
    assert_eq!(event.file_ref, file);
    assert_eq!(
        event.reason,
        USN_REASON_DATA_OVERWRITE | USN_REASON_BASIC_INFO_CHANGE | USN_REASON_CLOSE
    );
    assert_eq!(standard_usn(&record), event.usn);
}

#[test]
fn hole_punch_refuses_provider_and_encrypted_files_before_writes_or_noop_acknowledgment() {
    let cx = Cx::for_testing();
    for transform in ["reparse", "encrypted"] {
        let (device, mut engine, file) = journal_fixture(&vec![0x4B; 3 * CLUSTER_BYTES]);
        match transform {
            "reparse" => {
                let point = NtfsReparsePoint {
                    tag: 0x9000_0017,
                    guid: None,
                    data: NtfsReparseData::Opaque(vec![0xAC; 16]),
                };
                engine
                    .set_reparse_point_at(&cx, file, &point, true, DEFAULT_FILETIME)
                    .into_result()
                    .unwrap();
            }
            "encrypted" => {
                let key = NtfsEfsKey::from_raw_bytes([0x37; 32]);
                engine
                    .encrypt_file_at(&cx, file, &key, DEFAULT_FILETIME)
                    .into_result()
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let before = device.snapshot_durable_only();
        let written = device.write_bytes_total();
        let events = engine.persistence_trace().len();
        let journal = journal_records(&engine.volume_view(&cx).unwrap());
        for offset in [0, 1 << 30] {
            let outcome = engine.punch_hole_at(
                &cx,
                file,
                &[],
                offset,
                CLUSTER_BYTES as u64,
                DEFAULT_FILETIME + 1,
            );
            assert!(
                matches!(
                    outcome,
                    NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(_))
                ),
                "{transform} hole punch was admitted at offset {offset}: {outcome:?}"
            );
            assert_eq!(device.write_bytes_total(), written);
            assert_eq!(device.snapshot_live(), before);
            assert_eq!(device.snapshot_durable_only(), before);
            assert_eq!(engine.persistence_trace().len(), events);
            assert_eq!(journal_records(&engine.volume_view(&cx).unwrap()), journal);
        }
    }
}

#[test]
fn compressed_hole_punch_fsops_publishes_native_usn_and_invalidates_read_cache() {
    let cx = Cx::for_testing();
    let unit = 16 * CLUSTER_BYTES;
    let mut expected = vec![0x79; 3 * unit];
    let (device, mut engine, file) = journal_fixture(&expected);
    engine
        .set_compression_at(&cx, file, true, DEFAULT_FILETIME)
        .into_result()
        .unwrap();
    let before = journal_records(&engine.volume_view(&cx).unwrap());
    let fs = NtfsFs::from_engine(&cx, engine, 1000, 1000).unwrap();
    let mut scope = RequestScope::empty();
    let attr = fs
        .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("punch.bin"))
        .unwrap();
    assert_eq!(
        fs.read(&cx, &mut scope, attr.ino, 0, expected.len() as u32)
            .unwrap(),
        expected
    );
    fs.fallocate(
        &cx,
        &mut scope,
        attr.ino,
        unit as u64 - 7,
        unit as u64 + 14,
        libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
    )
    .unwrap();
    expected[unit - 7..2 * unit + 7].fill(0);
    assert_eq!(
        fs.read(&cx, &mut scope, attr.ino, 0, expected.len() as u32)
            .unwrap(),
        expected
    );
    assert_eq!(
        fs.getattr(&cx, &mut scope, attr.ino).unwrap().size,
        expected.len() as u64
    );

    let image = device.snapshot_durable_only();
    let volume = NtfsVolume::from_device(
        &cx,
        Box::new(FaultInjectingNtfsDevice::new(image.clone())),
        0,
        image.len() as u64 - SECTOR_BYTES as u64,
    )
    .unwrap();
    let record = volume
        .record(&cx, file.record, Some(file.sequence))
        .unwrap();
    let stream = volume.data_stream(&cx, &record, &[]).unwrap();
    assert_eq!(
        volume.read(&cx, &stream, 0, expected.len()).unwrap(),
        expected
    );
    assert_eq!(stream.allocated, (2 * CLUSTER_BYTES) as u64);
    assert_eq!(standard_flags(&record) & (0x800 | 0x200), 0x800);
    let records = journal_records(&volume);
    assert_eq!(records.len(), before.len() + 1);
    assert_eq!(&records[..before.len()], before.as_slice());
    let event = records.last().unwrap();
    assert_eq!(event.file_ref, file);
    assert_eq!(event.reason, USN_REASON_DATA_OVERWRITE | USN_REASON_CLOSE);
    assert_eq!(standard_usn(&record), event.usn);
}

#[test]
fn hole_punch_data_and_usn_recover_together_across_native_publication() {
    let cx = Cx::for_testing();
    let original = vec![0x68; 3 * CLUSTER_BYTES];
    let (device, mut engine, file) = journal_fixture(&original);
    let before = journal_records(&engine.volume_view(&cx).unwrap());
    let old_usn = standard_usn(&view(&engine, file).1);
    let mut expected = original.clone();
    expected[13..2 * CLUSTER_BYTES + 13].fill(0);
    type Cut = (NtfsPersistenceStage, bool, Vec<u8>, Vec<u8>);
    let cuts: Arc<Mutex<Vec<Cut>>> = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&cuts);
    let source = Arc::clone(&device);
    let mut committed = false;
    engine.set_stage_hook(Some(Box::new(move |event| {
        committed |= event.stage == NtfsPersistenceStage::LogCommitBarrier;
        if matches!(
            event.stage,
            NtfsPersistenceStage::PayloadBarrier
                | NtfsPersistenceStage::DirtyRestartBarrier
                | NtfsPersistenceStage::LogCommitBarrier
                | NtfsPersistenceStage::TargetMetadataBarrier
                | NtfsPersistenceStage::AckPublished
        ) {
            captured.lock().unwrap().push((
                event.stage,
                committed,
                source.snapshot_durable_only(),
                source.snapshot_reordered_pending(true),
            ));
        }
        Ok(())
    })));
    engine
        .punch_hole_at(
            &cx,
            file,
            &[],
            13,
            2 * CLUSTER_BYTES as u64,
            DEFAULT_FILETIME + 33,
        )
        .into_result()
        .unwrap();
    engine.set_stage_hook(None);
    let after = assert_punch_record(
        &engine,
        file,
        &before,
        USN_REASON_DATA_OVERWRITE | USN_REASON_BASIC_INFO_CHANGE | USN_REASON_CLOSE,
        DEFAULT_FILETIME + 33,
    );
    let captured = cuts.lock().unwrap();
    for required in [
        NtfsPersistenceStage::PayloadBarrier,
        NtfsPersistenceStage::DirtyRestartBarrier,
        NtfsPersistenceStage::LogCommitBarrier,
        NtfsPersistenceStage::TargetMetadataBarrier,
        NtfsPersistenceStage::AckPublished,
    ] {
        assert!(
            captured.iter().any(|(stage, _, _, _)| *stage == required),
            "missing publication boundary {required:?}"
        );
    }
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
            .unwrap_or_else(|error| panic!("journal recovery at {stage:?}: {error}"));
            recovered.check_clean_consistency(&cx).unwrap();
            let (volume, record) = view(&recovered, file);
            let stream = volume.data_stream(&cx, &record, &[]).unwrap();
            let observed = volume.read(&cx, &stream, 0, original.len()).unwrap();
            let applied = observed == expected;
            assert!(applied || observed == original, "mixed data at {stage:?}");
            if *committed || !may_be_newer {
                assert_eq!(applied, *committed, "wrong durable prefix at {stage:?}");
            }
            let observed_journal = journal_records(&volume);
            assert_eq!(
                &observed_journal,
                if applied { &after } else { &before },
                "data/journal disagreement at {stage:?}"
            );
            assert_eq!(
                standard_usn(&record),
                if applied {
                    after.last().unwrap().usn
                } else {
                    old_usn
                },
                "target/journal USN disagreement at {stage:?}"
            );
            assert_eq!(
                standard_flags(&record) & 0x200,
                if applied { 0x200 } else { 0 }
            );
        }
    }
}
