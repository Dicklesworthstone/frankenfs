//! Extend the existing constructed fragmented-MFT fixture, not a native oracle.

use super::*;

fn ownership(volume: &NtfsVolume) -> RecordOwnershipReport {
    volume
        .check_record_ownership(&Cx::for_testing(), RecordOwnershipLimits::default())
        .unwrap()
}

fn list_value(image: &Image) -> Vec<u8> {
    let at = image.offset(24);
    let record = NtfsFileRecord::parse(&image.bytes[at..at + 1024]).unwrap();
    let attrs = record.attributes().unwrap();
    let attr = attrs.iter().find(|attr| attr.kind == 0x20).unwrap();
    let NtfsValue::Resident(value) = &attr.value else {
        panic!("resident fixture list");
    };
    value.to_vec()
}

fn replace_list(image: &mut Image, list: Option<&[u8]>) {
    let mut attrs = vec![mapped(
        image.cluster,
        0,
        &[0x21, 1, 180, 0, 0],
        0,
        1,
        2 * image.cluster as u64,
        false,
    )];
    if let Some(list) = list {
        attrs.push(resident(0x20, 1, list));
    }
    image.put(24, &record(24, &attrs, 0));
}

fn clear_mft_bit(image: &mut Image, number: usize) {
    let at = image.offset(0);
    let mut raw = image.bytes[at..at + 1024].to_vec();
    let data_length = u32::from_le_bytes(raw[60..64].try_into().unwrap()) as usize;
    let value = 56 + data_length + 24;
    raw[value + number / 8] &= !(1 << (number % 8));
    image.put(0, &raw);
    let mirror = BASE + 128 * image.cluster;
    image.bytes[mirror..mirror + 1024].copy_from_slice(&raw);
}

#[test]
fn record_ownership_validates_fragmented_catalogs_without_reading_payload_or_writing() {
    for cluster in [512, 4096] {
        let image = Image::new(cluster);
        let original = image.bytes.clone();
        let (volume, reads, bytes) = image.open(None);
        reads.lock().unwrap().clear();
        let report = ownership(&volume);
        assert!(report.is_consistent(), "{report:?}");
        assert_eq!(report.record_slots_examined, 32);
        assert_eq!(report.base_records_examined, 8);
        assert_eq!(report.extension_records_examined, 1);
        assert_eq!(report.referenced_extension_records, 1);
        assert_eq!(report.extensions_without_owner, Some(0));
        assert_eq!(report.metadata_bytes_attempted, 11 * 1024 + 64 + 4);
        assert_eq!(bytes.as_slice(), original);
        let mut physical_bytes = 0;
        for &(at, count) in reads.lock().unwrap().iter() {
            physical_bytes += count as u64;
            assert!(at >= BASE as u64 && at + count as u64 <= (BASE + 256 * cluster) as u64);
            for lcn in [170, 180, 200] {
                let start = (BASE + lcn * cluster) as u64;
                assert!(at + count as u64 <= start || at >= start + cluster as u64);
            }
        }
        assert!(physical_bytes <= report.metadata_bytes_attempted);
    }
}

#[test]
fn record_ownership_finds_unlisted_extensions_even_when_cluster_accounting_agrees() {
    for cluster in [512, 4096] {
        let mut image = Image::new(cluster);
        replace_list(&mut image, None);
        let (volume, _, _) = image.open(None);
        assert!(
            volume
                .check_allocations(&Cx::for_testing(), AllocationLimits::default())
                .unwrap()
                .is_consistent()
        );
        let report = ownership(&volume);
        assert!(report.complete);
        assert!(!report.is_consistent());
        assert_eq!(report.errors, 1);
        assert_eq!(report.extensions_without_owner, Some(1));
        assert_eq!(report.issues[0].record, Some(25));
        assert_eq!(report.issues[0].category, "extension_without_owner");
    }
}

#[test]
fn record_ownership_refuses_free_catalog_targets_before_reading_their_file_bytes() {
    let mut image = Image::new(512);
    let extension = image.offset(25) as u64;
    clear_mft_bit(&mut image, 25);
    let (volume, reads, _) = image.open(None);
    reads.lock().unwrap().clear();
    let report = ownership(&volume);
    assert!(!report.is_consistent() && !report.complete);
    assert_eq!(report.extensions_without_owner, None);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.record == Some(24) && issue.detail.contains("marked free"))
    );
    assert!(!reads.lock().unwrap().iter().any(|(at, _)| *at == extension));
}

#[test]
fn record_ownership_preserves_native_sequence_base_and_attribute_identity_checks() {
    for case in 0..5 {
        let mut image = Image::new(512);
        let mut list = list_value(&image);
        match case {
            0 => list[48..56].copy_from_slice(&((8_u64 << 48) | 0x0019).to_le_bytes()),
            1 => list[56..58].copy_from_slice(&9_u16.to_le_bytes()),
            2 => list[40..48].copy_from_slice(&2_u64.to_le_bytes()),
            3 => list[48..56].copy_from_slice(&((7_u64 << 48) | 32).to_le_bytes()),
            _ => image.put(
                25,
                &record(
                    25,
                    &[mapped(512, 0, &[0x21, 1, 170, 0, 0], 1, 1, 0, false)],
                    (8 << 48) | 0x0018,
                ),
            ),
        }
        replace_list(&mut image, Some(&list));
        let (volume, _, _) = image.open(None);
        let report = ownership(&volume);
        assert!(!report.is_consistent() && !report.complete, "case {case}");
        assert!(report.errors > 0);
        assert_eq!(report.extensions_without_owner, None);
        assert_eq!(report.referenced_extension_records, 0);
    }
}

#[test]
fn record_ownership_incomplete_catalogs_suppress_absence_and_cancel_is_terminal() {
    for case in 0..3 {
        let mut image = Image::new(512);
        replace_list(&mut image, None);
        let at = image.offset(27);
        if case == 0 {
            image.bytes[at + 510] ^= 1;
        }
        let fault = (case != 0).then_some((at as u64, case == 2));
        let (volume, reads, _) = image.open(fault);
        let result =
            volume.check_record_ownership(&Cx::for_testing(), RecordOwnershipLimits::default());
        if case == 2 {
            assert!(matches!(result, Err(FfsError::Cancelled)));
            assert_eq!(reads.lock().unwrap().last().unwrap().0, at as u64);
        } else {
            let report = result.unwrap();
            assert!(!report.complete && !report.is_consistent());
            assert_eq!(report.extensions_without_owner, None);
            assert_eq!(report.errors, 1);
            assert_eq!(report.issues[0].record, Some(27));
        }
    }
}

#[test]
fn record_ownership_budget_is_reserved_before_bootstrap_catalog_and_extension_io() {
    let image = Image::new(512);
    let extension = image.offset(25) as u64;
    let (volume, reads, _) = image.open(None);
    let cx = Cx::for_testing();
    for (max_bytes, expected_work) in [(1023, 0), (1028, 1028), (7236, 7236)] {
        reads.lock().unwrap().clear();
        let report = volume
            .check_record_ownership(
                &cx,
                RecordOwnershipLimits {
                    metadata_bytes: max_bytes,
                    ..RecordOwnershipLimits::default()
                },
            )
            .unwrap();
        assert_eq!(report.limit_reached, Some("metadata work budget"));
        assert_eq!(report.metadata_bytes_attempted, expected_work);
        assert_eq!(report.extensions_without_owner, None);
        assert!(!report.is_consistent());
        assert!(!reads.lock().unwrap().iter().any(|(at, _)| *at == extension));
        if max_bytes == 1023 {
            assert!(reads.lock().unwrap().is_empty());
        }
    }
    reads.lock().unwrap().clear();
    let report = volume
        .check_record_ownership(
            &cx,
            RecordOwnershipLimits {
                records: 1,
                ..RecordOwnershipLimits::default()
            },
        )
        .unwrap();
    assert_eq!(report.limit_reached, Some("MFT record budget"));
    assert!(reads.lock().unwrap().is_empty());
    for limits in [
        RecordOwnershipLimits {
            records: 0,
            ..RecordOwnershipLimits::default()
        },
        RecordOwnershipLimits {
            metadata_bytes: 0,
            ..RecordOwnershipLimits::default()
        },
    ] {
        assert!(volume.check_record_ownership(&cx, limits).is_err());
    }
}

#[test]
fn record_ownership_meters_nonresident_lists_and_refuses_overlay_authority() {
    let mut image = Image::new(512);
    let list = list_value(&image);
    let list_at = BASE + 210 * 512;
    image.bytes[list_at..list_at + list.len()].copy_from_slice(&list);
    let mut list_attr = mapped(
        512,
        1,
        &[0x21, 1, 210, 0, 0],
        0,
        1,
        list.len() as u64,
        false,
    );
    list_attr[..4].copy_from_slice(&0x20_u32.to_le_bytes());
    image.put(
        24,
        &record(
            24,
            &[
                mapped(512, 0, &[0x21, 1, 180, 0, 0], 0, 1, 1024, false),
                list_attr,
            ],
            0,
        ),
    );
    let (mut volume, reads, _) = image.open(None);
    reads.lock().unwrap().clear();
    let limited = volume
        .check_record_ownership(
            &Cx::for_testing(),
            RecordOwnershipLimits {
                metadata_bytes: 7172,
                ..RecordOwnershipLimits::default()
            },
        )
        .unwrap();
    assert_eq!(limited.limit_reached, Some("metadata work budget"));
    assert!(
        !reads
            .lock()
            .unwrap()
            .iter()
            .any(|(at, _)| *at == list_at as u64)
    );
    assert!(ownership(&volume).is_consistent());
    assert!(
        reads
            .lock()
            .unwrap()
            .iter()
            .any(|(at, _)| *at == list_at as u64)
    );
    volume.source.overlay.insert(0, [0; 512]);
    reads.lock().unwrap().clear();
    assert!(
        volume
            .check_record_ownership(&Cx::for_testing(), RecordOwnershipLimits::default())
            .is_err()
    );
    assert!(reads.lock().unwrap().is_empty());
}

#[test]
fn record_ownership_invalid_bitmap_authority_fails_instead_of_returning_clean() {
    let mut image = Image::new(512);
    clear_mft_bit(&mut image, 0);
    let (volume, _, _) = image.open(None);
    let result =
        volume.check_record_ownership(&Cx::for_testing(), RecordOwnershipLimits::default());
    assert!(result.unwrap_err().to_string().contains("own base record"));
}
