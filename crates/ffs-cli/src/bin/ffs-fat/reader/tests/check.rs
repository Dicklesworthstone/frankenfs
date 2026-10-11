use super::*;

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
        assert!(matches!(
            image.volume().check(&cx),
            Err(FfsError::Corruption { .. })
        ));

        let mut image = check_image(kind);
        image.set_copy_link(1, 300, image.end());
        assert!(
            image
                .volume()
                .check(&cx)
                .unwrap_err()
                .to_string()
                .contains("copies disagree")
        );

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
