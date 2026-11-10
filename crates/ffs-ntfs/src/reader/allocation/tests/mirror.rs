//! Native-byte controls for mirror comparison; no Windows qualification claim.

use super::*;

fn mirrored_image(cluster: usize, records: usize) -> Image {
    let mut image = Image::new(cluster);
    // This fixture's original physical-allocation tests do not need $LogFile;
    // a complete recovery mirror does, including its allocated MFT bit.
    image.put(2, &record(2, &[resident(DATA, 0, b"log metadata")], 0));
    for number in [4, 5] {
        image.put(number, &record(number as u32, &[], 0));
    }
    let at = image.offset(0);
    let mut raw = image.bytes[at..at + 1024].to_vec();
    let data_length = u32::from_le_bytes(raw[60..64].try_into().unwrap()) as usize;
    raw[56 + data_length + 24] |= 1 << 2;
    image.put(0, &raw);
    let length = records * 1024;
    let clusters = length.div_ceil(cluster);
    image.put(
        1,
        &record(
            1,
            &[mapped(
                cluster,
                0,
                &[0x21, clusters as u8, 128, 0, 0],
                0,
                clusters as u64,
                length as u64,
                false,
            )],
            0,
        ),
    );
    for number in 0..records {
        let at = image.offset(number);
        let raw = image.bytes[at..at + 1024].to_vec();
        let mirror = BASE + 128 * cluster + number * 1024;
        image.bytes[mirror..mirror + 1024].copy_from_slice(&raw);
    }
    image
}

fn mirror(volume: &NtfsVolume) -> MftMirrorReport {
    volume
        .check_mft_mirror(&Cx::for_testing(), RecordOwnershipLimits::default())
        .unwrap()
}

#[test]
fn mft_mirror_compares_all_declared_records_without_reading_file_payloads_or_writing() {
    for cluster in [512, 4096] {
        for records in [4, 8] {
            let image = mirrored_image(cluster, records);
            let original = image.bytes.clone();
            let (volume, reads, bytes) = image.open(None);
            reads.lock().unwrap().clear();
            let report = mirror(&volume);
            assert!(report.is_consistent(), "{report:?}");
            assert_eq!(report.declared_records, records as u64);
            assert_eq!(report.record_pairs_examined, records as u64);
            assert_eq!(report.matching_records, records as u64);
            assert_eq!(report.required_prefix_matches, Some(true));
            assert_eq!(
                report.metadata_bytes_attempted,
                (2 + 2 * records) as u64 * 1024 + 4
            );
            assert_eq!(bytes.as_slice(), original);
            for &(offset, size) in reads.lock().unwrap().iter() {
                assert!(offset >= BASE as u64);
                assert!(offset + size as u64 <= (BASE + 256 * cluster) as u64);
                for lcn in [170, 180, 200] {
                    let start = (BASE + lcn * cluster) as u64;
                    assert!(offset + size as u64 <= start || offset >= start + cluster as u64);
                }
            }
        }
    }
}

#[test]
fn mft_mirror_ignores_unused_slack_and_valid_per_write_usa_tokens() {
    let mut image = mirrored_image(512, 4);
    let start = BASE + 128 * 512 + 2 * 1024;
    let raw = &mut image.bytes[start..start + 1024];
    let used = u32::from_le_bytes(raw[24..28].try_into().unwrap()) as usize;
    raw[used + 20] ^= 0xA5;
    for offset in [48, 510, 1022] {
        raw[offset..offset + 2].copy_from_slice(&0x2468_u16.to_le_bytes());
    }
    raw[50..54].fill(0xA5); // Restored sector trailers are outside this record's used bytes.
    let (volume, _, _) = image.open(None);
    assert!(mirror(&volume).is_consistent());
}

#[test]
fn mft_mirror_compares_restored_sector_trailers_that_contain_used_metadata() {
    let mut image = mirrored_image(512, 4);
    let raw = record(2, &[resident(DATA, 0, &[0xA5; 600])], 0);
    image.put(2, &raw);
    let start = BASE + 128 * 512 + 2 * 1024;
    image.bytes[start..start + 1024].copy_from_slice(&raw);
    // USA validation still succeeds, but restoration exposes different bytes
    // in the resident DATA value crossing the first sector trailer.
    image.bytes[start + 50] ^= 1;
    let (volume, _, _) = image.open(None);
    let report = mirror(&volume);
    assert!(report.complete);
    assert_eq!(report.required_prefix_matches, Some(false));
    assert_eq!(report.different_records, 1);
    assert_eq!(report.issues[0].record, Some(2));
    assert!(!report.is_consistent());
}

#[test]
fn mft_mirror_required_and_extended_disagreements_remain_distinct() {
    for number in [2, 3, 4, 7] {
        let mut image = mirrored_image(4096, 8);
        let at = BASE + 128 * 4096 + number * 1024;
        image.bytes[at + 8] ^= 1; // Valid record, different native LSN.
        let (volume, _, _) = image.open(None);
        let report = mirror(&volume);
        assert!(report.complete);
        assert!(!report.is_consistent());
        assert_eq!(report.record_pairs_examined, 8);
        assert_eq!(report.different_records, 1);
        assert_eq!(report.matching_records, 7);
        assert_eq!(report.required_prefix_matches, Some(number >= 4));
        assert_eq!(report.extended_record_differences, u64::from(number >= 4));
        assert_eq!(report.errors, u64::from(number < 4));
        assert_eq!(report.issues[0].record, Some(number as u64));
        assert_eq!(
            report.issues[0].category,
            if number < 4 {
                "required_mirror_difference"
            } else {
                "extended_mirror_difference"
            }
        );
    }
}

#[test]
fn mft_mirror_rejects_torn_stale_and_invalid_record_pairs_without_choosing_a_copy() {
    for case in 0..4 {
        let mut image = mirrored_image(512, 4);
        let at = BASE + 128 * 512 + 2 * 1024;
        match case {
            0 => image.bytes[at + 510] ^= 1,
            1 => image.bytes[at + 44..at + 48].copy_from_slice(&9_u32.to_le_bytes()),
            2 => image.bytes[at + 16..at + 18].fill(0),
            _ => {
                let primary = image.offset(2);
                image.bytes[primary + 510] ^= 1;
            }
        }
        let (volume, _, _) = image.open(None);
        let report = mirror(&volume);
        assert!(!report.complete && !report.is_consistent());
        assert_eq!(report.required_prefix_matches, None);
        assert_eq!(report.errors, 1);
        assert_eq!(report.issues[0].record, Some(2));
        assert_eq!(report.record_pairs_examined, 3);
    }
}

#[test]
fn mft_mirror_checks_boot_location_physical_independence_and_initialized_geometry() {
    for case in 0..7 {
        let mut image = mirrored_image(512, 4);
        let mut attr = mapped(512, 0, &[0x21, 8, 128, 0, 0], 0, 8, 4096, false);
        match case {
            0 => attr[66] = 129, // Same bytes elsewhere would not establish boot binding.
            1 => attr = mapped(512, 0, &[0x21, 4, 128, 0, 0x11, 4, 2, 0], 0, 8, 4096, false),
            2 => {
                attr = mapped(
                    512,
                    0,
                    &[0x21, 4, 128, 0, 0x11, 4, 0x84, 0],
                    0,
                    8,
                    4096,
                    false,
                )
            }
            3 => attr[48..56].copy_from_slice(&3072_u64.to_le_bytes()),
            4 => attr[56..64].copy_from_slice(&3072_u64.to_le_bytes()),
            5 => attr[48..56].copy_from_slice(&4095_u64.to_le_bytes()),
            _ => attr = mapped(512, 0, &[0x21, 8, 128, 0, 0], 0, 8, 4096, true),
        }
        if matches!(case, 3 | 5) {
            let length = attr[48..56].to_vec();
            attr[56..64].copy_from_slice(&length);
        }
        image.put(1, &record(1, &[attr], 0));
        let (volume, reads, _) = image.open(None);
        reads.lock().unwrap().clear();
        let report = mirror(&volume);
        assert!(
            !report.complete && !report.is_consistent(),
            "case {case}: {report:?}"
        );
        assert_eq!(report.record_pairs_examined, 0);
        assert_eq!(report.required_prefix_matches, None);
        assert_eq!(report.errors + report.unsupported, 1);
        // No candidate mirror payload is trusted after metadata admission fails.
        assert!(
            reads
                .lock()
                .unwrap()
                .iter()
                .all(|&(at, _)| at < (BASE + 128 * 512) as u64)
        );
    }
}

#[test]
fn mft_mirror_does_not_certify_a_bootstrap_record_marked_free_by_its_bitmap() {
    let mut image = mirrored_image(512, 4);
    ownership::clear_mft_bit(&mut image, 2);
    let (volume, reads, _) = image.open(None);
    reads.lock().unwrap().clear();
    let report = mirror(&volume);
    assert!(!report.complete && !report.is_consistent());
    assert!(report.issues[0].detail.contains("does not allocate"));
    assert_eq!(report.record_pairs_examined, 0);
    assert_eq!(reads.lock().unwrap().len(), 1); // The resident bitmap needs no further I/O.
}

#[test]
fn mft_mirror_reserves_work_before_each_pair_and_preserves_unknown_prefixes() {
    let (volume, reads, _) = mirrored_image(512, 4).open(None);
    for (budget, pairs, used) in [
        (1023, 0, 0),
        (1028, 0, 1028),
        (2052, 0, 2052),
        (4100, 1, 4100),
        (8196, 3, 8196),
    ] {
        reads.lock().unwrap().clear();
        let report = volume
            .check_mft_mirror(
                &Cx::for_testing(),
                RecordOwnershipLimits {
                    metadata_bytes: budget,
                    ..RecordOwnershipLimits::default()
                },
            )
            .unwrap();
        assert!(!report.is_consistent());
        assert_eq!(report.limit_reached, Some("metadata work budget"));
        assert_eq!(report.record_pairs_examined, pairs);
        assert_eq!(report.metadata_bytes_attempted, used);
        assert_eq!(report.required_prefix_matches, None);
        assert!(
            reads
                .lock()
                .unwrap()
                .iter()
                .map(|&(_, size)| size as u64)
                .sum::<u64>()
                <= used
        );
    }
    reads.lock().unwrap().clear();
    let report = volume
        .check_mft_mirror(
            &Cx::for_testing(),
            RecordOwnershipLimits {
                records: 31,
                ..RecordOwnershipLimits::default()
            },
        )
        .unwrap();
    assert_eq!(report.limit_reached, Some("MFT record budget"));
    assert!(reads.lock().unwrap().is_empty());
    assert!(
        volume
            .check_mft_mirror(
                &Cx::for_testing(),
                RecordOwnershipLimits {
                    metadata_bytes: 0,
                    ..RecordOwnershipLimits::default()
                }
            )
            .is_err()
    );
}

#[test]
fn mft_mirror_io_failure_is_incomplete_and_cancellation_is_terminal() {
    for cancel in [false, true] {
        let at = (BASE + 128 * 512 + 2 * 1024) as u64;
        let (volume, reads, _) = mirrored_image(512, 4).open(Some((at, cancel)));
        let result = volume.check_mft_mirror(&Cx::for_testing(), RecordOwnershipLimits::default());
        if cancel {
            assert!(matches!(result, Err(FfsError::Cancelled)));
            assert_eq!(reads.lock().unwrap().last().unwrap().0, at);
        } else {
            let report = result.unwrap();
            assert!(!report.complete && !report.is_consistent());
            assert_eq!(report.required_prefix_matches, None);
            assert_eq!(report.issues[0].category, "io");
            assert_eq!(report.issues[0].record, Some(2));
        }
    }
    let (mut volume, reads, _) = mirrored_image(512, 4).open(None);
    for overlay in [false, true] {
        reads.lock().unwrap().clear();
        if overlay {
            volume.volume_flags = 0;
            volume.source.overlay.insert(0, [0; 512]);
        } else {
            volume.volume_flags = 1;
        }
        assert!(
            volume
                .check_mft_mirror(&Cx::for_testing(), RecordOwnershipLimits::default())
                .is_err()
        );
        assert!(reads.lock().unwrap().is_empty());
    }
}
