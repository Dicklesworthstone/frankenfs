use super::*;

pub(super) fn checked_image(kind: FatKind) -> Image {
    let mut image = Image::new(kind);
    if kind == FatKind::Fat32 {
        for (offset, value) in [
            (0, 0x4161_5252_u32),
            (484, 0x6141_7272),
            (488, u32::MAX),
            (492, 2), // A formatter's last-allocated search hint is legal.
            (508, 0xAA55_0000),
        ] {
            let at = image.base + 512 + offset;
            image.bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
    }
    image
}

fn has_finding(report: &super::super::check::FatCheckReport, code: &str) -> bool {
    report.issues.iter().any(|issue| issue.kind == code)
}

fn one_long_name(alias: &[u8; 11], text: &str) -> [u8; 32] {
    let mut slot = [0_u8; 32];
    slot[0] = 0x41;
    slot[11] = 0x0F;
    slot[13] = ffs_ondisk::fat::short_name_checksum(alias);
    let units: Vec<_> = text.encode_utf16().collect();
    assert!(units.len() <= 13);
    for (index, offset) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
        .into_iter()
        .enumerate()
    {
        let unit = units
            .get(index)
            .copied()
            .unwrap_or(if index == units.len() { 0 } else { 0xFFFF });
        slot[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
    }
    slot
}

#[test]
fn selected_oem_aliases_collide_with_native_lfns_consistently() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for page in [FatOemCodePage::Cp437, FatOemCodePage::Cp850] {
            let mut image = checked_image(kind);
            let root = image.root_location();
            image.record(root, b"\x90COLE   TXT", 5, 1029, false);
            let alias = *b"LONGNA~1TXT";
            image.bytes[root + 64..root + 96].copy_from_slice(&one_long_name(&alias, "école.txt"));
            image.record(root + 96, &alias, 0, 0, false);
            let volume = image.volume().with_oem_code_page(page);
            assert!(matches!(
                volume.lookup(&cx, Directory::Root, "ÉCOLE.TXT"),
                Err(FfsError::Corruption { .. })
            ));
            let report = volume.check(&cx).unwrap();
            assert!(report.complete);
            assert!(has_finding(&report, "name_collision"));
            assert_eq!(report.lost_clusters, Some(0));
            assert!(matches!(
                crate::filesystem::FatFs::new(&cx, volume, 0, 0),
                Err(FfsError::Corruption { .. })
            ));
        }
    }
}

#[test]
fn allocation_check_accounts_for_both_native_roots_and_fragmented_files() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let volume = checked_image(kind).volume();
        let report = volume.check(&cx).unwrap();
        assert!(report.is_clean(), "{kind:?}: {report:?}");
        assert_eq!(report.files, 3);
        assert_eq!(report.directories, 2);
        assert_eq!(report.lost_clusters, Some(0));
        let allocated = if kind == FatKind::Fat16 { 5 } else { 6 };
        assert_eq!(report.allocated_clusters, allocated);
        assert_eq!(report.referenced_clusters, allocated);
        assert_eq!(report.scanned_clusters, u64::from(report.data_clusters));
        assert_eq!(
            report.free_clusters + report.allocated_clusters,
            u64::from(report.data_clusters)
        );
        assert_eq!(report.bad_clusters, 0);
        assert_eq!(report.reserved_clusters, 0);
        assert_eq!(report.conflicting_clusters, 0);
    }
}

#[test]
fn allocation_check_reports_cross_links_with_both_native_owners() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let mut image = checked_image(kind);
        let original = (image.root_location() - image.base) as u64;
        image.record(image.root_location() + 96, b"SHARED  TXT", 9, 517, false);
        let report = image.volume().check(&cx).unwrap();
        assert!(!report.is_clean());
        assert!(report.complete);
        assert_eq!(report.lost_clusters, Some(0));
        let cross_link = report
            .issues
            .iter()
            .find(|issue| issue.kind == "cross_link")
            .unwrap();
        assert_eq!(cross_link.entry_offset, Some(original + 96));
        assert_eq!(cross_link.other_entry_offset, Some(original));
        assert_eq!(cross_link.cluster, Some(9));
    }
}

#[test]
fn allocation_check_finds_unreachable_chains_and_cycles_without_repairing_them() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let mut image = checked_image(kind);
        image.set_link(20, 21);
        image.set_link(21, image.end());
        image.set_link(22, 23);
        image.set_link(23, 22);
        let report = image.volume().check(&cx).unwrap();
        assert!(report.complete);
        assert!(!report.is_clean());
        assert_eq!(report.lost_clusters, Some(4));
        assert!(has_finding(&report, "lost_allocation"));
        assert_eq!(report.allocated_clusters - report.referenced_clusters, 4);
    }
}

#[test]
fn allocation_check_separates_native_bad_clusters_from_invalid_reachable_allocation() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let mut image = checked_image(kind);
        let bad = if kind == FatKind::Fat16 {
            0xFFF7
        } else {
            0x0FFF_FFF7
        };
        image.set_link(20, bad);
        let report = image.volume().check(&cx).unwrap();
        assert!(report.is_clean(), "{report:?}");
        assert_eq!(report.bad_clusters, 1);
        assert_eq!(report.lost_clusters, Some(0));
        assert_eq!(
            report.free_clusters + report.allocated_clusters + report.bad_clusters,
            u64::from(report.data_clusters)
        );

        let mut image = checked_image(kind);
        image.set_link(5, bad);
        let report = image.volume().check(&cx).unwrap();
        assert!(!report.is_clean());
        assert!(has_finding(&report, "invalid_live_chain"));
    }
}

#[test]
fn allocation_check_covers_short_excess_cyclic_free_and_invalid_file_chains() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for scenario in 0..6 {
            let mut image = checked_image(kind);
            let expected = match scenario {
                0 => {
                    image.set_link(5, image.end());
                    Some("short_file_chain")
                }
                1 => {
                    image.set_link(7, 12);
                    image.set_link(12, image.end());
                    None
                }
                2 => {
                    image.set_link(7, 9);
                    Some("cyclic_chain")
                }
                3 => {
                    image.set_link(9, 0);
                    Some("invalid_live_chain")
                }
                4 => {
                    let next = if kind == FatKind::Fat16 { 5002 } else { 70_002 };
                    image.set_link(5, next);
                    Some("invalid_successor")
                }
                _ => {
                    image.set_link(12, image.end());
                    image.record(image.root_location() + 64, b"EMPTY   TXT", 12, 0, false);
                    None
                }
            };
            let report = image.volume().check(&cx).unwrap();
            if let Some(expected) = expected {
                assert!(!report.is_clean());
                assert!(
                    has_finding(&report, expected),
                    "{kind:?} scenario {scenario}: {report:?}"
                );
            } else {
                assert!(
                    report.is_clean(),
                    "{kind:?} scenario {scenario}: {report:?}"
                );
                assert_eq!(report.preallocated_clusters, 1);
                assert_eq!(report.lost_clusters, Some(0));
            }
        }
    }
}

#[test]
fn allocation_check_does_not_infer_orphans_through_unreadable_or_shared_directories() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for scenario in 0..3 {
            let mut image = checked_image(kind);
            image.set_link(20, image.end()); // Not provably orphaned after a scan gap.
            let expected = match scenario {
                0 => {
                    let at = image.cluster(3) + 64;
                    image.bytes[at + 11] = 0xC0;
                    "unreadable_directory"
                }
                1 => {
                    image.record(image.root_location() + 96, b"ALIAS      ", 3, 0, true);
                    "cross_link"
                }
                _ => {
                    image.record(image.cluster(3) + 96, b"CYCLE      ", 3, 0, true);
                    "cross_link"
                }
            };
            let report = image.volume().check(&cx).unwrap();
            assert!(!report.complete, "{kind:?} scenario {scenario}: {report:?}");
            assert!(!report.is_clean());
            assert_eq!(report.lost_clusters, None);
            assert!(!has_finding(&report, "lost_allocation"));
            assert!(has_finding(&report, expected));
        }
    }
}

#[test]
fn allocation_check_verifies_dot_parent_links_without_following_them() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let mut image = checked_image(kind);
        image.record(image.cluster(3), b".          ", 11, 0, true);
        image.record(image.cluster(3) + 32, b"..         ", 5, 0, true);
        let report = image.volume().check(&cx).unwrap();
        assert!(report.complete);
        assert_eq!(report.files, 3);
        assert_eq!(report.directories, 2);
        assert_eq!(report.lost_clusters, Some(0));
        assert_eq!(
            report
                .issues
                .iter()
                .filter(|issue| issue.kind == "parent_link")
                .count(),
            2
        );
        assert!(!has_finding(&report, "cross_link"));
    }
}

#[test]
fn allocation_check_rejects_duplicate_empty_file_names_and_long_short_alias_collisions() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for long in [false, true] {
            let mut image = checked_image(kind);
            let at = image.root_location() + 96;
            if long {
                let alias = *b"OTHER   TXT";
                image.bytes[at..at + 32].copy_from_slice(&one_long_name(&alias, "hello.txt"));
                image.record(at + 32, &alias, 0, 0, false);
            } else {
                image.record(at, b"HELLO   TXT", 0, 0, false);
            }
            let report = image.volume().check(&cx).unwrap();
            assert!(report.complete);
            assert!(!report.is_clean());
            assert_eq!(report.lost_clusters, Some(0));
            assert!(has_finding(&report, "name_collision"));
            assert!(!has_finding(&report, "cross_link"));
        }
    }
}

#[test]
fn allocation_check_reports_orphan_bad_and_trailing_lfn_sets_despite_reader_fallback() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for scenario in 0..5 {
            let mut image = checked_image(kind);
            let alias = *b"OTHER   TXT";
            let root = image.root_location();
            let mut position = root + 96;
            let mut long = one_long_name(&alias, "Other.txt");
            if scenario == 4 {
                let length = if kind == FatKind::Fat16 { 1024 } else { 512 };
                for at in (position..root + length).step_by(32) {
                    image.bytes[at..at + 32].fill(0);
                    image.bytes[at] = 0xE5;
                }
                position = root + length - 32;
            } else if scenario != 0 {
                image.record(position + 32, &alias, 0, 0, false);
                match scenario {
                    1 => long[0] = 1,
                    2 => long[13] = long[13].wrapping_add(1),
                    _ => image.bytes[position + 32] = 0xE5,
                }
            }
            image.bytes[position..position + 32].copy_from_slice(&long);
            let volume = image.volume();
            assert!(volume.list(&cx, Directory::Root).is_ok());
            let report = volume.check(&cx).unwrap();
            assert!(report.complete);
            assert!(!report.is_clean());
            assert_eq!(report.lost_clusters, Some(0));
            assert!(has_finding(&report, "invalid_long_name"), "{report:?}");
        }
    }
}

#[test]
fn allocation_check_never_silently_filters_extra_dot_records() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for root_entry in [false, true] {
            let mut image = checked_image(kind);
            let at = if root_entry {
                image.root_location() + 96
            } else {
                image.cluster(3) + 96
            };
            image.record(at, b"..         ", 0, 0, true);
            let volume = image.volume();
            assert!(volume.list(&cx, Directory::Root).is_ok());
            let report = volume.check(&cx).unwrap();
            assert!(report.complete);
            assert!(!report.is_clean());
            assert_eq!(report.lost_clusters, Some(0));
            assert!(has_finding(&report, "misplaced_dot_entry"));
        }
    }
}

#[test]
fn allocation_check_retains_mirror_ambiguity_including_unreferenced_clusters() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let mut image = checked_image(kind);
        image.set_copy_link(1, 20, image.end());
        let report = image.volume().check(&cx).unwrap();
        assert!(!report.complete);
        assert!(!report.is_clean());
        assert_eq!(report.conflicting_clusters, 1);
        assert_eq!(report.lost_clusters, None);
        assert!(has_finding(&report, "fat_copies_disagree"));
        assert!(!has_finding(&report, "lost_allocation"));
        assert_eq!(
            report.free_clusters + report.allocated_clusters + report.conflicting_clusters,
            u64::from(report.data_clusters)
        );
    }
}

#[test]
fn allocation_check_honors_active_fat_and_masks_reserved_high_bits() {
    let cx = Cx::for_testing();
    let mut image = checked_image(FatKind::Fat32);
    image.bytes[image.base + 40..image.base + 42].copy_from_slice(&0x81_u16.to_le_bytes());
    image.copy_backup();
    image.set_copy_link(0, 5, 0);
    image.set_copy_link(0, 20, image.end());
    image.set_copy_link(1, 5, 0xA000_0009);
    let report = image.volume().check(&cx).unwrap();
    assert!(report.is_clean(), "{report:?}");
    assert_eq!(report.allocated_clusters, 6);

    let mut image = checked_image(FatKind::Fat32);
    image.set_copy_link(0, 5, 0xB000_0009);
    image.set_copy_link(1, 5, 0xC000_0009);
    assert!(image.volume().check(&cx).unwrap().is_clean());
}

#[test]
fn allocation_check_checks_fsinfo_hints_without_treating_them_as_allocation_truth() {
    let cx = Cx::for_testing();
    for (field, value, expected) in [
        (0, 0_u32, "fs_info_signature"),
        (484, 0, "fs_info_signature"),
        (508, 0, "fs_info_signature"),
        (488, 0, "fs_info_free_count"),
        (488, 70_001, "fs_info_free_count"),
        (492, 1, "fs_info_next_free"),
        (492, 70_002, "fs_info_next_free"),
    ] {
        let mut image = checked_image(FatKind::Fat32);
        let at = image.base + 512 + field;
        image.bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        let report = image.volume().check(&cx).unwrap();
        assert!(report.complete);
        assert!(!report.is_clean());
        assert_eq!(report.free_clusters, 69_994);
        assert_eq!(report.lost_clusters, Some(0));
        assert!(has_finding(&report, expected), "{report:?}");
    }
    for hint in [u32::MAX, 2, 5, 70_001] {
        let mut image = checked_image(FatKind::Fat32);
        let at = image.base + 512 + 488;
        image.bytes[at..at + 4].copy_from_slice(&69_994_u32.to_le_bytes());
        image.bytes[at + 4..at + 8].copy_from_slice(&hint.to_le_bytes());
        let report = image.volume().check(&cx).unwrap();
        assert!(report.is_clean(), "hint {hint}: {report:?}");
    }
}

#[test]
fn allocation_check_cancellation_never_becomes_a_clean_or_partial_success() {
    let cx = Cx::for_testing();
    for location in 0..3 {
        let image = checked_image(FatKind::Fat32);
        let fail_at = match location {
            0 => image.base + image.fat_start + 512,
            1 => image.cluster(3),
            _ => image.base + 512,
        };
        let volume = FatVolume::from_device(
            &cx,
            Box::new(Memory {
                bytes: Arc::new(image.bytes),
                reads: Arc::new(AtomicUsize::new(0)),
                fail_at: Some(fail_at as u64),
            }),
            image.base as u64,
            image.length as u64,
        )
        .unwrap();
        assert!(matches!(volume.check(&cx), Err(FfsError::Cancelled)));
    }
}

#[test]
fn allocation_check_bounds_diagnostics_without_hiding_remaining_errors() {
    let mut image = checked_image(FatKind::Fat16);
    for cluster in 100..2100 {
        image.set_link(cluster, 0xFFF0);
    }
    let report = image.volume().check(&Cx::for_testing()).unwrap();
    assert!(report.complete);
    assert!(!report.is_clean());
    assert_eq!(report.reserved_clusters, 2000);
    assert_eq!(report.issues.len(), 1024);
    assert_eq!(report.omitted_issues, 976);
    assert_eq!(report.lost_clusters, Some(0));
}

#[test]
fn allocation_check_preserves_real_file_bytes_and_adjacent_partition_sentinels() {
    let cx = Cx::for_testing();
    let directory = tempfile::tempdir().unwrap();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let mut image = checked_image(kind);
        image.set_link(20, image.end());
        let path = directory.path().join(format!("{kind:?}.img"));
        std::fs::write(&path, &image.bytes).unwrap();
        let volume =
            FatVolume::open(&cx, &path, image.base as u64, Some(image.length as u64)).unwrap();
        let report = volume.check(&cx).unwrap();
        assert_eq!(report.lost_clusters, Some(1));
        assert_eq!(std::fs::read(&path).unwrap(), image.bytes);
    }
}

fn check_image(kind: FatKind) -> Image {
    let mut image = Image::new(kind);
    if kind == FatKind::Fat32 {
        let at = image.base + 512;
        for (offset, value) in [
            (0, 0x4161_5252_u32),
            (484, 0x6141_7272),
            (488, u32::MAX),
            (492, u32::MAX),
            (508, 0xAA55_0000),
        ] {
            image.bytes[at + offset..at + offset + 4].copy_from_slice(&value.to_le_bytes());
        }
    }
    image
}

#[test]
fn checker_counts_clean_namespaces_without_reading_file_payloads() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let image = check_image(kind);
        let fail_at = image.cluster(5) as u64;
        let volume = FatVolume::from_device(
            &cx,
            Box::new(Memory {
                bytes: Arc::new(image.bytes),
                reads: Arc::new(AtomicUsize::new(0)),
                fail_at: Some(fail_at),
            }),
            image.base as u64,
            image.length as u64,
        )
        .unwrap();
        let report = volume.check(&cx).unwrap();
        assert!(report.clean, "{:?}", report.issues);
        assert!(report.read_only && report.namespace_complete);
        assert_eq!((report.files, report.directories), (3, 2));
        let (total, allocated) = match kind {
            FatKind::Fat16 => (5000, 5),
            FatKind::Fat32 => (70_000, 6),
        };
        assert_eq!(report.scanned_clusters, total);
        assert_eq!(report.allocated_clusters, allocated);
        assert_eq!(report.free_clusters, total - allocated);
        assert_eq!(report.bad_clusters, 0);
        assert_eq!(report.preallocated_clusters, 0);
        assert_eq!(report.lost_clusters, Some(0));
        assert_eq!(report.fs_info_free_hint, None);
    }
}

#[test]
fn checker_distinguishes_preallocation_bad_clusters_and_lost_allocation() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let mut image = check_image(kind);
        image.set_link(7, 12);
        image.set_link(12, image.end());
        image.set_link(
            14,
            match kind {
                FatKind::Fat16 => 0xFFF7,
                FatKind::Fat32 => 0x0FFF_FFF7,
            },
        );
        let report = image.volume().check(&cx).unwrap();
        assert!(report.clean, "{:?}", report.issues);
        assert_eq!(report.preallocated_clusters, 1);
        assert_eq!(report.bad_clusters, 1);
        assert_eq!(report.lost_clusters, Some(0));

        let mut image = check_image(kind);
        image.set_link(12, 13);
        image.set_link(13, image.end());
        let report = image.volume().check(&cx).unwrap();
        assert!(!report.clean);
        assert_eq!(report.lost_clusters, Some(2));
        assert_eq!(report.issues.len(), 1);
        assert_eq!(report.issues[0].kind, "lost_allocation");
        assert_eq!(report.issues[0].cluster, Some(12));
    }
}

#[test]
fn checker_reports_shared_file_clusters_with_both_directory_offsets() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let mut image = check_image(kind);
        let root = image.root_location();
        let first_offset = (root - image.base) as u64;
        image.record(root + 96, b"SHARED  BIN", 9, 1024, false);
        let report = image.volume().check(&cx).unwrap();
        assert!(!report.clean);
        assert!(report.namespace_complete);
        assert_eq!(report.lost_clusters, Some(0));
        assert_eq!(report.files, 4);
        let conflicts: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.kind == "cross_link")
            .collect();
        assert_eq!(conflicts.len(), 2);
        assert_eq!(conflicts[0].cluster, Some(9));
        assert_eq!(conflicts[1].cluster, Some(7));
        for conflict in conflicts {
            assert_eq!(conflict.entry_offset, Some(first_offset + 96));
            assert_eq!(conflict.other_entry_offset, Some(first_offset));
        }
    }
}

#[test]
fn checker_bounds_shared_directory_traversal_and_withholds_lost_classification() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for ancestor in [false, true] {
            let mut image = check_image(kind);
            if ancestor {
                let at = image.cluster(3) + 96;
                let target = if kind == FatKind::Fat32 { 2 } else { 3 };
                image.record(at, b"ANCESTOR   ", target, 0, true);
            } else {
                let at = image.root_location() + 96;
                image.record(at, b"ALIAS      ", 3, 0, true);
            }
            let report = image.volume().check(&cx).unwrap();
            assert!(!report.clean);
            assert!(!report.namespace_complete);
            assert_eq!(report.lost_clusters, None);
            assert_eq!(report.directories, 3);
            assert_eq!(report.files, 3);
            assert!(report.issues.iter().any(|issue| issue.kind == "cross_link"));
            assert!(
                report
                    .issues
                    .iter()
                    .all(|issue| issue.kind != "lost_allocation")
            );
        }
    }
}

#[test]
fn checker_reports_parent_links_directory_sizes_and_name_collisions() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let mut image = check_image(kind);
        let root = image.root_location();
        image.record(root + 32, b"SUBDIR     ", 3, 7, true);
        image.record(root + 96, b"HELLO   TXT", 0, 0, false);
        let parent = image.cluster(3) + 32;
        image.record(parent, b"..         ", 11, 0, true);
        let report = image.volume().check(&cx).unwrap();
        assert!(!report.clean);
        assert!(report.namespace_complete);
        for kind in ["parent_link", "directory_size", "name_collision"] {
            assert!(report.issues.iter().any(|issue| issue.kind == kind));
        }
        assert_eq!(report.lost_clusters, Some(0));
    }
}

#[test]
fn checker_treats_fsinfo_as_optional_hints_and_reports_stale_values() {
    let cx = Cx::for_testing();
    for (free, next, expected) in [
        (69_994_u32, 5_u32, None),
        (1, u32::MAX, Some("fs_info_free_count")),
        (u32::MAX, 1, Some("fs_info_next_free")),
    ] {
        let mut image = check_image(FatKind::Fat32);
        let at = image.base + 512;
        image.bytes[at + 488..at + 492].copy_from_slice(&free.to_le_bytes());
        image.bytes[at + 492..at + 496].copy_from_slice(&next.to_le_bytes());
        let report = image.volume().check(&cx).unwrap();
        if let Some(expected) = expected {
            assert!(!report.clean);
            assert_eq!(report.issues.len(), 1);
            assert_eq!(report.issues[0].kind, expected);
        } else {
            // A next-free search start may already be allocated.
            assert!(report.clean, "{:?}", report.issues);
            assert_eq!(report.fs_info_free_hint, Some(69_994));
        }
    }
    let report = Image::new(FatKind::Fat32).volume().check(&cx).unwrap();
    assert!(!report.clean);
    assert_eq!(report.issues.len(), 1);
    assert_eq!(report.issues[0].kind, "fs_info_signature");
    assert_eq!(report.fs_info_free_hint, None);
}

#[test]
fn checker_never_returns_clean_for_bad_chains_mirror_conflicts_or_cancelled_scans() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let mut image = check_image(kind);
        image.set_link(7, 5);
        let report = image.volume().check(&cx).unwrap();
        assert!(!report.clean);
        assert!(report.complete && report.namespace_complete);
        assert_eq!(report.status, "issues_found");
        assert!(has_finding(&report, "cyclic_chain"));
        assert_eq!(report.lost_clusters, Some(0));

        let mut image = check_image(kind);
        image.set_copy_link(1, 300, image.end());
        let report = image.volume().check(&cx).unwrap();
        assert!(!report.clean);
        assert!(!report.complete && !report.namespace_complete);
        assert_eq!(report.status, "incomplete");
        assert_eq!(report.conflicting_clusters, 1);
        assert!(has_finding(&report, "fat_copies_disagree"));
        assert_eq!(report.lost_clusters, None);
        assert!(!has_finding(&report, "lost_allocation"));

        let image = check_image(kind);
        let fat_sector = 300 * kind.entry_bytes() as usize / 512 * 512;
        let fail_at = (image.base + image.fat_start + fat_sector) as u64;
        let volume = FatVolume::from_device(
            &cx,
            Box::new(Memory {
                bytes: Arc::new(image.bytes),
                reads: Arc::new(AtomicUsize::new(0)),
                fail_at: Some(fail_at),
            }),
            image.base as u64,
            image.length as u64,
        )
        .unwrap();
        assert!(matches!(volume.check(&cx), Err(FfsError::Cancelled)));
    }
}

#[test]
fn checker_caps_reports_without_hiding_additional_inconsistencies() {
    let cx = Cx::for_testing();
    let mut image = check_image(FatKind::Fat16);
    for cluster in 100..1200 {
        image.set_link(cluster, 1);
    }
    let report = image.volume().check(&cx).unwrap();
    assert!(!report.clean);
    assert_eq!(report.issues.len(), 1024);
    assert_eq!(report.omitted_issues, 76);
    assert!(
        report
            .issues
            .iter()
            .all(|issue| issue.kind == "reserved_allocation")
    );
}

#[test]
fn checker_preserves_the_image_and_bytes_outside_the_selected_volume() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let image = check_image(kind);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("check.img");
        std::fs::write(&path, &image.bytes).unwrap();
        let volume =
            FatVolume::open(&cx, &path, image.base as u64, Some(image.length as u64)).unwrap();
        assert!(volume.check(&cx).unwrap().clean);
        assert_eq!(std::fs::read(&path).unwrap(), image.bytes);
    }
}

#[test]
fn checker_terminates_when_a_shared_suffix_is_itself_cyclic() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let mut image = checked_image(kind);
        image.set_link(7, 9);
        image.record(image.root_location() + 96, b"SHARED  BIN", 9, 1024, false);
        let report = image.volume().check(&cx).unwrap();
        assert!(!report.clean);
        assert!(report.complete);
        assert_eq!(report.lost_clusters, Some(0));
        assert_eq!(report.referenced_clusters, report.allocated_clusters);
        assert_eq!(report.omitted_issues, 0);
        assert_eq!(
            report
                .issues
                .iter()
                .filter(|issue| issue.kind == "cyclic_chain")
                .count(),
            2
        );
        for cluster in [9, 7] {
            assert!(
                report
                    .issues
                    .iter()
                    .any(|issue| { issue.kind == "cross_link" && issue.cluster == Some(cluster) })
            );
        }
    }
}
