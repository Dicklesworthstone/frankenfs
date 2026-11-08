//! Constructed native metadata tests; these are not independent Windows proof.

use super::super::attributes::{extension, list_entry};
use super::*;
use crate::reader::allocation::{NamespaceLimits, NamespaceReport};

const ALLOCATED: &[usize] = &[0, 3, 5, 10, 24, 25, 27, 28, 29];

fn bitmap(image: &mut Image, records: &[usize]) {
    let mut bits = [0_u8; 4];
    for &number in records {
        bits[number / 8] |= 1 << (number % 8);
    }
    let mft = file_record(
        0,
        &[
            mapped(&[0x11, 16, 4, 0x11, 48, 36, 0], 64, 32 * 1024, 32 * 1024, 0),
            resident(0xB0, 1, "", &bits),
        ],
    );
    image.put_record(0, &mft);
    image.bytes[BASE + 128 * 512..BASE + 130 * 512].copy_from_slice(&mft);
}

fn fixture(external: bool) -> Image {
    let mut image = namespace_image(external);
    bitmap(&mut image, ALLOCATED);
    image
}

fn root(image: &mut Image, keys: &[Vec<u8>]) {
    image.put_record(
        5,
        &directory_record(5, &[resident(0x90, 0, "$I30", &index_root(keys, false))]),
    );
}

fn check(image: Image) -> NamespaceReport {
    open(image, Arc::default(), None)
        .unwrap()
        .check_namespace(&Cx::for_testing(), NamespaceLimits::default())
        .unwrap()
}

fn has(report: &NamespaceReport, category: &str) -> bool {
    report.issues.iter().any(|issue| issue.category == category)
}

#[test]
fn namespace_check_reconciles_native_catalogs_and_multilevel_indexes_without_payload_reads() {
    for external in [false, true] {
        let reads: Reads = Arc::default();
        let volume = open(fixture(external), Arc::clone(&reads), None).unwrap();
        reads.lock().unwrap().clear();
        let report = volume
            .check_namespace(&Cx::for_testing(), NamespaceLimits::default())
            .unwrap();
        assert!(report.is_consistent(), "{report:?}");
        assert_eq!(report.record_slots_examined, 32);
        assert_eq!(report.base_records_examined, 9);
        assert_eq!(report.directories_examined, 2);
        assert_eq!(report.file_names_examined, 6);
        assert_eq!(report.index_entries_examined, 6);
        assert_eq!(report.missing_index_entries, Some(0));
        assert_eq!(report.unreachable_records, Some(0));
        let mut physical_bytes = 0_u64;
        for &(offset, count) in reads.lock().unwrap().iter() {
            physical_bytes += count as u64;
            assert!(
                offset >= BASE as u64 && offset + count as u64 <= (BASE + NAMESPACE_LENGTH) as u64
            );
            for cluster in [170, 180, 190, 200] {
                let start = (BASE + cluster * 512) as u64;
                assert!(
                    offset + count as u64 <= start || offset >= start + 512,
                    "read ordinary data cluster {cluster}"
                );
            }
        }
        assert!(physical_bytes <= report.metadata_bytes_attempted);
    }
}

#[test]
fn namespace_check_finds_missing_reverse_entries_and_unreachable_files() {
    let mut image = fixture(false);
    let mut keys = root_keys();
    keys.remove(4);
    root(&mut image, &keys);
    let report = check(image);
    assert!(report.complete && !report.is_consistent());
    assert_eq!(report.missing_index_entries, Some(1));
    assert_eq!(report.unreachable_records, Some(1));
    assert!(has(&report, "missing_index_entry"));
    assert!(has(&report, "unreachable_record"));
}

#[test]
fn namespace_check_rejects_free_and_stale_index_targets_without_trusting_header_flags() {
    let mut image = fixture(false);
    let records: Vec<_> = ALLOCATED
        .iter()
        .copied()
        .filter(|number| *number != 24)
        .collect();
    bitmap(&mut image, &records);
    let reads: Reads = Arc::default();
    let volume = open(image, Arc::clone(&reads), None).unwrap();
    reads.lock().unwrap().clear();
    let report = volume
        .check_namespace(&Cx::for_testing(), NamespaceLimits::default())
        .unwrap();
    assert!(report.complete && !report.is_consistent());
    assert!(has(&report, "invalid_index_target"));
    assert!(
        !reads
            .lock()
            .unwrap()
            .iter()
            .any(|(at, _)| *at == Image::record_offset(24) as u64)
    );

    let mut image = fixture(false);
    let mut keys = root_keys();
    keys[0][..8].copy_from_slice(&((8_u64 << 48) | 24).to_le_bytes());
    root(&mut image, &keys);
    let report = check(image);
    assert!(has(&report, "invalid_index_target"));
    assert_eq!(report.missing_index_entries, Some(1));
}

#[test]
fn namespace_check_detects_exact_name_conflicts_across_different_namespaces() {
    let mut image = fixture(false);
    let mut records = ALLOCATED.to_vec();
    records.push(26);
    bitmap(&mut image, &records);
    image.put_record(
        26,
        &file_record(26, &[resident(0x30, 0, "", &name_value(5, "A.txt", 0))]),
    );
    let mut keys = root_keys();
    keys.insert(1, key(26, 5, "A.txt", 0, None));
    root(&mut image, &keys);
    let report = check(image);
    assert!(report.complete && !report.is_consistent());
    assert!(has(&report, "conflicting_index_name"));
    assert_eq!(report.missing_index_entries, Some(0));
    assert_eq!(report.unreachable_records, Some(0));
}

#[test]
fn namespace_check_preserves_distinct_case_sensitive_posix_names() {
    let mut image = fixture(false);
    let mut records = ALLOCATED.to_vec();
    records.push(26);
    bitmap(&mut image, &records);
    image.put_record(
        26,
        &file_record(26, &[resident(0x30, 0, "", &name_value(5, "MiXeD", 0))]),
    );
    let mut keys = root_keys();
    keys.insert(3, key(26, 5, "MiXeD", 0, None));
    root(&mut image, &keys);
    let report = check(image);
    assert!(report.is_consistent(), "{report:?}");
    assert_eq!(report.file_names_examined, 7);
    assert_eq!(report.index_entries_examined, 7);
}

fn extension_fixture(nonresident_list: bool, allocate_extension: bool) -> Image {
    let mut image = fixture(true);
    if allocate_extension {
        let mut records = ALLOCATED.to_vec();
        records.push(26);
        bitmap(&mut image, &records);
    }
    let mut list = list_entry(0x30, 24, 2, 0, "");
    list.extend(list_entry(0x30, 26, 3, 0, ""));
    let list_attr = if nonresident_list {
        let mut attr = mapped(
            &[0x21, 1, 200, 0, 0],
            1,
            list.len() as u64,
            list.len() as u64,
            0,
        );
        attr[..4].copy_from_slice(&0x20_u32.to_le_bytes());
        image.bytes[BASE + 200 * 512..BASE + 200 * 512 + list.len()].copy_from_slice(&list);
        attr
    } else {
        resident(0x20, 0, "", &list)
    };
    image.put_record(
        24,
        &file_record(
            24,
            &[list_attr, resident(0x30, 2, "", &name_value(5, "A.txt", 1))],
        ),
    );
    image.put_record(
        26,
        &extension(
            26,
            24,
            &[resident(0x30, 3, "", &name_value(5, "A~1.TXT", 2))],
        ),
    );
    image
}

#[test]
fn namespace_check_reconciles_file_names_in_allocated_extension_catalogs() {
    for nonresident_list in [false, true] {
        let report = check(extension_fixture(nonresident_list, true));
        assert!(report.is_consistent(), "{report:?}");
        assert_eq!(report.base_records_examined, 9);
        assert_eq!(report.file_names_examined, 6);
        assert_eq!(report.index_entries_examined, 6);

        let reads: Reads = Arc::default();
        let volume = open(
            extension_fixture(nonresident_list, false),
            Arc::clone(&reads),
            None,
        )
        .unwrap();
        reads.lock().unwrap().clear();
        let report = volume
            .check_namespace(&Cx::for_testing(), NamespaceLimits::default())
            .unwrap();
        assert!(!report.complete && report.errors > 0, "{report:?}");
        assert_eq!(report.missing_index_entries, None);
        assert_eq!(report.unreachable_records, None);
        assert!(
            !reads
                .lock()
                .unwrap()
                .iter()
                .any(|(at, _)| *at == Image::record_offset(26) as u64),
            "a bitmap-free extension must be rejected before its FILE read"
        );
    }
}

#[test]
fn namespace_check_accepts_file_hard_links_and_directory_dos_aliases() {
    let mut image = fixture(false);
    image.put_record(
        24,
        &file_record(
            24,
            &[
                resident(0x30, 0, "", &name_value(5, "A.txt", 1)),
                resident(0x30, 1, "", &name_value(5, "A~1.TXT", 2)),
                resident(0x30, 2, "", &name_value(27, "SECOND.TXT", 1)),
            ],
        ),
    );
    image.put_record(
        27,
        &directory_record(
            27,
            &[
                resident(
                    0x90,
                    0,
                    "$I30",
                    &index_root(
                        &[
                            key(28, 27, "NESTED.BIN", 1, None),
                            key(24, 27, "SECOND.TXT", 1, None),
                            terminal(None),
                        ],
                        false,
                    ),
                ),
                resident(0x30, 1, "", &name_value(5, "Subdir", 1)),
                resident(0x30, 2, "", &name_value(5, "SUBDIR~1", 2)),
            ],
        ),
    );
    let mut keys = root_keys();
    keys.insert(4, key(27, 5, "SUBDIR~1", 2, None));
    root(&mut image, &keys);
    let report = check(image);
    assert!(report.is_consistent(), "{report:?}");
    assert_eq!(report.file_names_examined, 8);
    assert_eq!(report.index_entries_examined, 8);
}

#[test]
fn namespace_check_detects_root_reachable_cycles_and_multiple_directory_parents() {
    let mut image = fixture(false);
    let mut keys = root_keys();
    keys.remove(2);
    root(&mut image, &keys);
    image.put_record(
        27,
        &directory_record(
            27,
            &[
                resident(
                    0x90,
                    0,
                    "$I30",
                    &index_root(
                        &[
                            key(29, 27, "CHILD", 1, None),
                            key(28, 27, "NESTED.BIN", 1, None),
                            terminal(None),
                        ],
                        false,
                    ),
                ),
                resident(0x30, 1, "", &name_value(5, "Subdir", 1)),
                resident(0x30, 2, "", &name_value(29, "LOOP", 1)),
            ],
        ),
    );
    image.put_record(
        29,
        &directory_record(
            29,
            &[
                resident(
                    0x90,
                    0,
                    "$I30",
                    &index_root(&[key(27, 29, "LOOP", 1, None), terminal(None)], false),
                ),
                resident(0x30, 1, "", &name_value(27, "CHILD", 1)),
            ],
        ),
    );
    let report = check(image);
    assert!(report.complete && !report.is_consistent());
    assert!(has(&report, "directory_cycle"));
    assert!(has(&report, "multiple_directory_parents"));
    assert_eq!(report.missing_index_entries, Some(0));
    assert_eq!(report.unreachable_records, Some(0));
}

#[test]
fn namespace_check_distinguishes_native_root_dot_from_an_ordinary_self_link() {
    let mut image = fixture(false);
    image.put_record(
        5,
        &directory_record(
            5,
            &[
                resident(0x90, 0, "$I30", &index_root(&root_keys(), false)),
                resident(0x30, 1, "", &name_value(5, ".", 3)),
            ],
        ),
    );
    let report = check(image);
    assert!(report.is_consistent(), "{report:?}");
    assert_eq!(report.file_names_examined, 7);
    assert_eq!(report.missing_index_entries, Some(0));

    let mut image = fixture(false);
    let mut keys = root_keys();
    keys.insert(3, key(5, 5, "ROOT", 1, None));
    image.put_record(
        5,
        &directory_record(
            5,
            &[
                resident(0x90, 0, "$I30", &index_root(&keys, false)),
                resident(0x30, 1, "", &name_value(5, "ROOT", 1)),
            ],
        ),
    );
    let report = check(image);
    assert!(report.complete && !report.is_consistent());
    assert!(has(&report, "invalid_root_name"));
    assert!(has(&report, "directory_cycle"));
}

#[test]
fn namespace_check_suppresses_absence_conclusions_after_damaged_or_unordered_indexes() {
    for case in 0..3 {
        let mut image = fixture(case != 0);
        match case {
            0 => {
                let mut keys = root_keys();
                keys.swap(0, 1);
                root(&mut image, &keys);
            }
            1 => image.put_record(5, &root_record(true, 15)),
            _ => image.bytes[INDEX_START + 510] ^= 1,
        }
        let report = check(image);
        assert!(
            !report.complete && !report.is_consistent(),
            "case {case}: {report:?}"
        );
        assert!(report.errors > 0);
        assert_eq!(report.missing_index_entries, None);
        assert_eq!(report.unreachable_records, None);
    }
}

#[test]
fn namespace_check_limits_are_global_and_charged_before_metadata_io() {
    for limits in [
        NamespaceLimits {
            records: 31,
            ..NamespaceLimits::default()
        },
        NamespaceLimits {
            metadata_bytes: 1,
            ..NamespaceLimits::default()
        },
        NamespaceLimits {
            metadata_bytes: 1024 + 4 + 1024,
            ..NamespaceLimits::default()
        },
        NamespaceLimits {
            entries: 1,
            ..NamespaceLimits::default()
        },
        NamespaceLimits {
            entries: 11,
            ..NamespaceLimits::default()
        },
    ] {
        let reads: Reads = Arc::default();
        let volume = open(fixture(true), Arc::clone(&reads), None).unwrap();
        reads.lock().unwrap().clear();
        let report = volume.check_namespace(&Cx::for_testing(), limits).unwrap();
        assert!(
            !report.complete && report.limit_reached.is_some(),
            "{report:?}"
        );
        assert_eq!(report.missing_index_entries, None);
        assert_eq!(report.unreachable_records, None);
        assert!(report.metadata_bytes_attempted <= limits.metadata_bytes);
        assert!(report.file_names_examined + report.index_entries_examined <= limits.entries);
        let physical: u64 = reads
            .lock()
            .unwrap()
            .iter()
            .map(|(_, count)| *count as u64)
            .sum();
        assert!(physical <= report.metadata_bytes_attempted);
        if limits.records == 31 || limits.metadata_bytes == 1 {
            assert!(reads.lock().unwrap().is_empty());
        }
    }
}

#[test]
fn namespace_check_cancellation_is_not_an_incomplete_success() {
    for at in [Image::record_offset(24), INDEX_START] {
        let volume = open(fixture(true), Arc::default(), Some(at as u64)).unwrap();
        assert!(matches!(
            volume.check_namespace(&Cx::for_testing(), NamespaceLimits::default()),
            Err(FfsError::Cancelled)
        ));
    }
}

#[test]
fn namespace_check_rejects_reparse_directories_as_unqualified_namespace() {
    let mut image = fixture(false);
    image.put_record(
        27,
        &directory_record(
            27,
            &[
                resident(
                    0x90,
                    0,
                    "$I30",
                    &index_root(&[key(28, 27, "NESTED.BIN", 1, None), terminal(None)], false),
                ),
                resident(0x30, 1, "", &name_value(5, "Subdir", 1)),
                resident(REPARSE_POINT, 2, "", &[0x17, 0, 0, 0x80, 0, 0, 0, 0]),
            ],
        ),
    );
    let report = check(image);
    assert!(!report.complete && report.unsupported == 1);
    assert_eq!(report.missing_index_entries, None);
    assert_eq!(report.unreachable_records, None);
}
