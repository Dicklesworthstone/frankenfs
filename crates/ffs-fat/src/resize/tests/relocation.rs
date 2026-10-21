//! Exercise relocation through the existing resize checker, view and publisher.
//! Fixtures are native byte layouts, not independent proof of interoperability.

use super::*;
use crate::resize::relocation::prepare as relocate;

fn fat_word(source: &Device, slice: &Slice, geometry: &FatGeometry, cluster: u32, low: u32) {
    let width = geometry.kind().entry_bytes() as usize;
    let mask = if width == 2 { 0xFFFF } else { 0x0FFF_FFFF };
    let mut state = source.memory.lock().unwrap();
    for copy in 0..geometry.fat_count() {
        if !geometry.mirrored() && copy != geometry.active_fat() {
            continue;
        }
        let at = slice.base + geometry.entry_offset(copy, cluster).unwrap();
        let mut bytes = [0; 4];
        state.read(at, &mut bytes[..width]);
        let raw = (u32::from_le_bytes(bytes) & !mask) | low;
        state.put(at, &raw.to_le_bytes()[..width]);
    }
}

fn pointer(bytes: &mut [u8], kind: FatKind, first: u32) {
    if kind == FatKind::Fat32 {
        let high = u16::from_le_bytes([bytes[20], bytes[21]]) & 0xF000;
        bytes[20..22].copy_from_slice(&(high | (first >> 16) as u16).to_le_bytes());
    }
    bytes[26..28].copy_from_slice(&(first as u16).to_le_bytes());
}

fn root(geometry: &FatGeometry) -> u64 {
    geometry.fixed_root().map_or_else(
        || geometry.cluster_offset(geometry.root_cluster()).unwrap(),
        |(start, _)| start,
    )
}

fn tail_file(kind: FatKind, sector: u32, active: bool) -> (Arc<Device>, Slice, FatGeometry) {
    let (source, slice, geometry) = fixture(kind, sector, active);
    let tail = geometry.cluster_count() + 1;
    for (old, new) in [(5, tail - 2), (6, tail), (7, tail - 1)] {
        let payload = read(
            &slice,
            geometry.cluster_offset(old).unwrap(),
            sector as usize,
        );
        source
            .memory
            .lock()
            .unwrap()
            .put(slice.base + geometry.cluster_offset(new).unwrap(), &payload);
        fat_word(&source, &slice, &geometry, old, 0);
    }
    let end = if kind == FatKind::Fat16 {
        0xFFFF
    } else {
        0x0FFF_FFFF
    };
    for (cluster, next) in [(tail - 2, 9), (9, tail), (tail, tail - 1), (tail - 1, end)] {
        fat_word(&source, &slice, &geometry, cluster, next);
    }
    let at = root(&geometry) + 32;
    let mut entry = read(&slice, at, 32);
    pointer(&mut entry, kind, tail - 2);
    source.memory.lock().unwrap().put(slice.base + at, &entry);
    (source, slice, geometry)
}

fn shrink(cx: &Cx, slice: Slice, geometry: &FatGeometry) -> (Slice, Arc<Plan>, usize) {
    let length = geometry.volume_bytes() - 500 * u64::from(geometry.sector_bytes());
    let (compacted, moved) = relocate(cx, slice, length, FatOemCodePage::Ascii).unwrap();
    let plan = Plan::prepare(cx, compacted.clone(), length, FatOemCodePage::Ascii).unwrap();
    (compacted, plan, moved)
}

#[test]
fn live_tail_relocation_preserves_chain_order_metadata_and_preallocation_in_both_dialects() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for sector in [512, 4096] {
            for active in [false, true] {
                if active && kind == FatKind::Fat16 {
                    continue;
                }
                let (source, slice, geometry) = tail_file(kind, sector, active);
                let before = source.memory.lock().unwrap().pages.clone();
                let original = volume(&cx, Arc::new(slice.clone()));
                let entry = original.resolve(&cx, "/KEEP.BIN").unwrap().unwrap();
                let chain = original.file_chain(&cx, &entry).unwrap();
                let payload = original.read(&cx, &chain, 0, 4 * sector as usize).unwrap();
                let length = geometry.volume_bytes() - 500 * u64::from(sector);
                // The unchanged default still refuses to silently relocate.
                assert!(Plan::prepare(&cx, slice.clone(), length, FatOemCodePage::Ascii).is_err());
                let (compacted, plan, moved) = shrink(&cx, slice.clone(), &geometry);
                assert_eq!(moved, 3);
                let resized = volume(&cx, plan.clone());
                let new_entry = resized.resolve(&cx, "/KEEP.BIN").unwrap().unwrap();
                let new_chain = resized.file_chain(&cx, &new_entry).unwrap();
                let expected = if kind == FatKind::Fat16 {
                    [2, 9, 4, 3]
                } else {
                    [3, 9, 5, 4]
                };
                assert_eq!(new_chain.clusters, expected);
                assert_eq!(
                    resized
                        .read(&cx, &new_chain, 0, 4 * sector as usize)
                        .unwrap(),
                    payload
                );
                let mut raw = read(&slice, entry.offset, 32);
                pointer(&mut raw, kind, expected[0]);
                assert_eq!(read(plan.as_ref(), new_entry.offset, 32), raw);
                // Read the entire retained preallocation, not just logical EOF.
                assert_eq!(
                    read(
                        plan.as_ref(),
                        plan.new.cluster_offset(expected[3]).unwrap(),
                        sector as usize
                    ),
                    vec![0x94; sector as usize]
                );
                assert_eq!(resized.check(&cx).unwrap().preallocated_clusters, 1);
                for cluster in expected.into_iter().filter(|cluster| *cluster != 9) {
                    for copy in 0..2 {
                        if !geometry.mirrored() && copy != geometry.active_fat() {
                            continue;
                        }
                        if kind == FatKind::Fat32 {
                            let raw = read(
                                plan.as_ref(),
                                plan.new.entry_offset(copy, cluster).unwrap(),
                                4,
                            );
                            assert_eq!(word(&raw, 0) >> 28, 10 + u32::from(copy));
                        }
                    }
                }
                if active {
                    assert_eq!(
                        read(&compacted, fat_start(&geometry, 0).unwrap(), 64),
                        read(&slice, fat_start(&geometry, 0).unwrap(), 64)
                    );
                }
                // Old tail content is unreachable and sanitized in the view.
                assert_eq!(
                    read(
                        &compacted,
                        geometry.cluster_offset(geometry.cluster_count()).unwrap(),
                        sector as usize
                    ),
                    vec![0; sector as usize]
                );
                assert_eq!(source.memory.lock().unwrap().pages, before);
                assert!(source.memory.lock().unwrap().writes.is_empty());
                assert_eq!(source.memory.lock().unwrap().syncs, 0);
            }
        }
    }
}

fn directory_record(name: &[u8; 11], cluster: u32) -> [u8; 32] {
    let mut bytes = record(name, cluster, 0, FatKind::Fat32);
    bytes[11] = if name == b".          " || name == b"..         " {
        0x17
    } else {
        0x10
    };
    bytes
}

#[test]
fn relocation_moves_fat32_root_and_nested_directories_with_native_dotdot_links() {
    let cx = Cx::for_testing();
    for active in [false, true] {
        let (source, slice, geometry) = fixture(FatKind::Fat32, 512, active);
        let tail = geometry.cluster_count() + 1;
        let keep = read(&slice, root(&geometry) + 32, 32);
        let mut moved_root = read(&slice, root(&geometry), 512);
        moved_root[32..64].copy_from_slice(&directory_record(b"PARENT     ", tail - 1));
        fat_word(&source, &slice, &geometry, 2, 0);
        for cluster in [tail, tail - 1, tail - 2] {
            fat_word(&source, &slice, &geometry, cluster, 0x0FFF_FFFF);
        }
        {
            let mut state = source.memory.lock().unwrap();
            for boot in [0, 6 * 512] {
                state.put(slice.base + boot + 44, &tail.to_le_bytes());
            }
            state.put(
                slice.base + geometry.cluster_offset(tail).unwrap(),
                &moved_root,
            );
            for (first, parent, child) in
                [(tail - 1, 0, Some(tail - 2)), (tail - 2, tail - 1, None)]
            {
                let at = slice.base + geometry.cluster_offset(first).unwrap();
                state.put(at, &directory_record(b".          ", first));
                state.put(at + 32, &directory_record(b"..         ", parent));
                state.put(
                    at + 64,
                    &child.map_or_else(
                        || keep.clone(),
                        |child| directory_record(b"CHILD      ", child).to_vec(),
                    ),
                );
            }
        }
        let before = source.memory.lock().unwrap().pages.clone();
        // Source geometry now legitimately has a root in the removed tail.
        let original = volume(&cx, Arc::new(slice.clone()));
        assert_eq!(original.geometry.root_cluster(), tail);
        let (_, plan, moved) = shrink(&cx, slice.clone(), &geometry);
        assert_eq!(moved, 3);
        let resized = volume(&cx, plan.clone());
        assert_eq!(resized.geometry.root_cluster(), 4);
        assert_eq!(word(&read(plan.as_ref(), 44, 4), 0), 4);
        assert_eq!(word(&read(plan.as_ref(), 6 * 512 + 44, 4), 0), 4);
        let parent = resized.resolve(&cx, "/PARENT").unwrap().unwrap();
        let child = resized.resolve(&cx, "/PARENT/CHILD").unwrap().unwrap();
        assert_eq!(
            (parent.native.first_cluster, child.native.first_cluster),
            (3, 2)
        );
        for (first, parent) in [(3, 0), (2, 3)] {
            let dots = read(plan.as_ref(), plan.new.cluster_offset(first).unwrap(), 64);
            assert_eq!(&dots[..11], b".          ");
            assert_eq!(&dots[32..43], b"..         ");
            assert_eq!((dots[11], dots[43]), (0x17, 0x17));
            assert_eq!(u16::from_le_bytes([dots[26], dots[27]]), first as u16);
            assert_eq!(u16::from_le_bytes([dots[58], dots[59]]), parent as u16);
            assert_eq!(u16::from_le_bytes([dots[20], dots[21]]) & 0xF000, 0xA000);
        }
        let file = resized
            .resolve(&cx, "/PARENT/CHILD/KEEP.BIN")
            .unwrap()
            .unwrap();
        assert_eq!(read(plan.as_ref(), file.offset, 32), keep);
        assert!(resized.check(&cx).unwrap().clean);
        assert_eq!(source.memory.lock().unwrap().pages, before);
    }
}

#[test]
fn relocation_needs_no_new_name_slots_even_in_a_full_fat16_root() {
    let cx = Cx::for_testing();
    let (source, slice, geometry) = tail_file(FatKind::Fat16, 512, false);
    let (root, length) = geometry.fixed_root().unwrap();
    {
        let mut state = source.memory.lock().unwrap();
        for index in 3..length / 32 {
            let name = format!("E{index:07}TXT");
            state.put(
                slice.base + root + index * 32,
                &record(name.as_bytes().try_into().unwrap(), 0, 0, FatKind::Fat16),
            );
        }
    }
    let (_, plan, moved) = shrink(&cx, slice, &geometry);
    assert_eq!(moved, 3);
    let resized = volume(&cx, plan);
    assert_eq!(
        resized.list(&cx, Directory::Root).unwrap().len(),
        length as usize / 32 - 1
    );
    assert_eq!(resized.check(&cx).unwrap().preallocated_clusters, 1);
}

#[test]
fn relocation_preserves_unpaired_utf16_lfn_bytes_and_short_alias_binding() {
    let cx = Cx::for_testing();
    let (source, slice, geometry) = tail_file(FatKind::Fat32, 512, false);
    let root_offset = root(&geometry);
    let keep = read(&slice, root_offset + 32, 32);
    let empty = read(&slice, root_offset + 64, 32);
    let mut lfn = [0; 32];
    lfn[0] = 0x41;
    lfn[11] = 0x0F;
    lfn[13] = ffs_ondisk::fat::short_name_checksum(b"KEEP    BIN");
    for (index, at) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
        .into_iter()
        .enumerate()
    {
        let unit: u16 = match index {
            0 => 0xD800,
            1 => 0x0061,
            2 => 0,
            _ => 0xFFFF,
        };
        lfn[at..at + 2].copy_from_slice(&unit.to_le_bytes());
    }
    {
        let mut state = source.memory.lock().unwrap();
        state.put(slice.base + root_offset + 32, &lfn);
        state.put(slice.base + root_offset + 64, &keep);
        state.put(slice.base + root_offset + 96, &empty);
    }
    let (_, plan, _) = shrink(&cx, slice, &geometry);
    let output = volume(&cx, plan.clone());
    let entry = output.list(&cx, Directory::Root).unwrap().remove(0);
    assert!(entry.name().is_err());
    assert_eq!(
        entry.native.long_name.as_deref(),
        Some([0xD800, 0x0061].as_slice())
    );
    assert_eq!(entry.native.short_name, *b"KEEP    BIN");
    assert_eq!(read(plan.as_ref(), root(&plan.new) + 32, 32), lfn);
    assert_eq!(
        output.file_chain(&cx, &entry).unwrap().clusters,
        [3, 9, 5, 4]
    );
}

#[test]
fn relocation_refuses_bad_tail_and_insufficient_capacity_but_never_uses_bad_lower_slots() {
    let cx = Cx::for_testing();
    let (source, slice, geometry) = tail_file(FatKind::Fat16, 512, false);
    let length = geometry.volume_bytes() - 500 * 512;
    fat_word(&source, &slice, &geometry, 2, 0xFFF7);
    let (_, plan, _) = shrink(&cx, slice.clone(), &geometry);
    let resized = volume(&cx, plan);
    let file = resized.resolve(&cx, "/KEEP.BIN").unwrap().unwrap();
    assert_eq!(
        resized.file_chain(&cx, &file).unwrap().clusters,
        [3, 9, 5, 4]
    );
    fat_word(
        &source,
        &slice,
        &geometry,
        geometry.cluster_count() - 3,
        0xFFF7,
    );
    assert!(
        relocate(&cx, slice.clone(), length, FatOemCodePage::Ascii)
            .err()
            .unwrap()
            .to_string()
            .contains("bad tail")
    );
    assert!(source.memory.lock().unwrap().writes.is_empty());

    let (source, slice, geometry) = fixture(FatKind::Fat16, 512, false);
    let (_, target) = layout(&read(&slice, 0, 512), &geometry, length).unwrap();
    // One file owns every retained cluster plus one high preallocated cluster.
    for cluster in 2..=target.cluster_count() + 1 {
        let next = if cluster == target.cluster_count() + 1 {
            geometry.cluster_count() + 1
        } else {
            cluster + 1
        };
        fat_word(&source, &slice, &geometry, cluster, next);
    }
    fat_word(
        &source,
        &slice,
        &geometry,
        geometry.cluster_count() + 1,
        0xFFFF,
    );
    let at = root(&geometry) + 32;
    let mut entry = read(&slice, at, 32);
    pointer(&mut entry, FatKind::Fat16, 2);
    source.memory.lock().unwrap().put(slice.base + at, &entry);
    assert!(checked(&cx, &volume(&cx, Arc::new(slice.clone()))).is_ok());
    assert!(
        relocate(&cx, slice, length, FatOemCodePage::Ascii)
            .err()
            .unwrap()
            .to_string()
            .contains("insufficient free")
    );
    assert!(source.memory.lock().unwrap().writes.is_empty());
}

#[test]
fn relocation_view_handles_partial_native_words_and_unaligned_payload_windows() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let (_source, slice, geometry) = tail_file(kind, 512, false);
        let (compacted, _, _) = shrink(&cx, slice.clone(), &geometry);
        let tail = geometry.cluster_count() + 1;
        let first = if kind == FatKind::Fat16 { 2 } else { 3 };
        let width = kind.entry_bytes() as usize;
        let mask = if kind == FatKind::Fat16 {
            0xFFFF
        } else {
            0x0FFF_FFFF
        };
        let mut points = Vec::new();
        for copy in 0..2 {
            for (cluster, low) in [
                (first, 9),
                (first + 1, mask),
                (first + 2, first + 1),
                (9, first + 2),
                (tail, 0),
                (tail - 1, 0),
                (tail - 2, 0),
            ] {
                let at = geometry.entry_offset(copy, cluster).unwrap();
                let mut old_raw = [0; 4];
                old_raw[..width].copy_from_slice(&read(&slice, at, width));
                let expected = ((u32::from_le_bytes(old_raw) & !mask) | low).to_le_bytes();
                for start in 0..width {
                    for count in 0..=width - start {
                        assert_eq!(
                            read(&compacted, at + start as u64, count),
                            expected[start..start + count]
                        );
                    }
                }
                points.push(at);
            }
        }
        for (destination, origin) in [(first, tail - 2), (first + 1, tail - 1), (first + 2, tail)] {
            let expected = read(&slice, geometry.cluster_offset(origin).unwrap(), 512);
            let at = geometry.cluster_offset(destination).unwrap();
            for start in [0, 1, 27, 128, 511] {
                for count in [0, 1, (512 - start).min(129), 512 - start] {
                    assert_eq!(
                        read(&compacted, at + start as u64, count),
                        expected[start..start + count]
                    );
                }
            }
            points.push(at);
        }
        // Adjacent caller fragments must agree with a single spanning read.
        // The hard-coded native words and source payloads above are the oracle.
        for at in points {
            let start = at.saturating_sub(3);
            let whole = read(&compacted, start, 17);
            for split in 0..=17 {
                let mut joined = read(&compacted, start, split);
                joined.extend(read(&compacted, start + split as u64, 17 - split));
                assert_eq!(joined, whole);
            }
        }
    }
}

#[test]
fn relocated_publisher_reopens_and_faults_keep_the_source_and_withheld_primary() {
    let cx = Cx::for_testing();
    let (source, slice, geometry) = tail_file(FatKind::Fat16, 512, false);
    let before = source.memory.lock().unwrap().pages.clone();
    let (_, plan, _) = shrink(&cx, slice.clone(), &geometry);
    let output = device(plan.len_bytes(), true);
    publish(&cx, &plan, output.clone(), || Ok(())).unwrap();
    let reopened = volume(&cx, output.clone());
    let file = reopened.resolve(&cx, "/KEEP.BIN").unwrap().unwrap();
    assert_eq!(
        reopened.file_chain(&cx, &file).unwrap().clusters,
        [2, 9, 4, 3]
    );
    assert!(reopened.check(&cx).unwrap().clean);
    assert_eq!(output.memory.lock().unwrap().writes.last(), Some(&(0, 512)));
    for fault in 0..7 {
        let output = device(plan.len_bytes(), true);
        {
            let mut state = output.memory.lock().unwrap();
            match fault {
                0 => state.drop_write = Some(512),
                1 => state.fail_write = Some(512),
                2 => state.fail_sync = Some(1),
                3 => state.fail_read = Some(512),
                4 => state.cancel_write = Some(512),
                _ => {}
            }
        }
        if fault == 6 {
            source.memory.lock().unwrap().fail_read = Some(
                slice.base
                    + geometry
                        .cluster_offset(geometry.cluster_count() - 1)
                        .unwrap(),
            );
        }
        assert!(
            publish(&Cx::for_testing(), &plan, output.clone(), || {
                if fault == 5 {
                    bail!("changed source identity");
                }
                Ok(())
            })
            .is_err()
        );
        assert_eq!(read(output.as_ref(), 0, 512), vec![0; 512]);
        assert!(
            !output
                .memory
                .lock()
                .unwrap()
                .writes
                .iter()
                .any(|(at, _)| *at == 0)
        );
        assert_eq!(source.memory.lock().unwrap().pages, before);
    }
    assert!(source.memory.lock().unwrap().writes.is_empty());
    assert_eq!(source.memory.lock().unwrap().syncs, 0);
}

#[test]
fn relocation_preflight_refuses_corruption_cancellation_and_ranges_without_write_authority() {
    for fault in 0..4 {
        let cx = Cx::for_testing();
        let (source, slice, geometry) = tail_file(FatKind::Fat32, 512, false);
        match fault {
            0 => cx.set_cancel_requested(true),
            1 => {
                source.memory.lock().unwrap().put(
                    slice.base + geometry.entry_offset(1, 9).unwrap(),
                    &0_u32.to_le_bytes(),
                );
            }
            2 => {
                source.memory.lock().unwrap().put(slice.base + 65, &[1]);
            }
            _ => {
                source.memory.lock().unwrap().fail_read = Some(slice.base + root(&geometry));
            }
        }
        assert!(
            relocate(
                &cx,
                slice,
                geometry.volume_bytes() - 512 * 500,
                FatOemCodePage::Ascii
            )
            .is_err()
        );
        assert!(source.memory.lock().unwrap().writes.is_empty());
        assert_eq!(source.memory.lock().unwrap().syncs, 0);
    }
    let cx = Cx::for_testing();
    let (_source, slice, geometry) = tail_file(FatKind::Fat16, 512, false);
    let (compacted, _, _) = shrink(&cx, slice, &geometry);
    for at in [compacted.len_bytes(), u64::MAX] {
        assert!(
            compacted
                .read_exact_at(&cx, ByteOffset(at), &mut [0])
                .is_err()
        );
    }
    assert!(matches!(
        compacted.write_all_at(&cx, ByteOffset(0), b"x"),
        Err(FfsError::ReadOnly)
    ));
    assert!(matches!(compacted.sync(&cx), Err(FfsError::ReadOnly)));
}

#[test]
fn relocation_cli_is_explicit_and_real_file_shrink_retains_source_bytes() {
    let cx = Cx::for_testing();
    let (source, slice, geometry) = tail_file(FatKind::Fat16, 4096, false);
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.fat");
    let output = dir.path().join("output.fat");
    // Materialize the already independently constructed source image only.
    fs::write(&input, read(&slice, 0, geometry.volume_bytes() as usize)).unwrap();
    let before = fs::read(&input).unwrap();
    let arguments = [
        "ffs-fat",
        "resize",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--size-mib",
        "20",
        "--offline-image",
        "--dry-run",
        "--relocate",
    ];
    let crate::Command::Resize { mut options } =
        crate::Cli::try_parse_from(arguments).unwrap().command
    else {
        panic!("resize");
    };
    assert!(options.relocate);
    options.relocate = false;
    assert!(run(&cx, &options).is_err());
    assert!(!output.exists());
    options.relocate = true;
    let report = run(&cx, &options).unwrap();
    assert_eq!(report["relocation_requested"], true);
    assert_eq!(report["relocated_clusters"], 3);
    assert_eq!(report["cluster_numbers_preserved"], false);
    assert!(!output.exists());
    options.dry_run = false;
    let report = run(&cx, &options).unwrap();
    assert_eq!(report["source_modified"], false);
    assert_eq!(fs::metadata(&output).unwrap().len(), 20 * 1024 * 1024);
    assert_eq!(fs::metadata(&output).unwrap().mode() & 0o777, 0o600);
    assert_eq!(fs::read(&input).unwrap(), before);
    assert!(
        FatVolume::open(&cx, &output, 0, None)
            .unwrap()
            .check(&cx)
            .unwrap()
            .clean
    );
    assert!(run(&cx, &options).is_err());
    assert!(source.memory.lock().unwrap().writes.is_empty());
}

#[test]
fn relocation_moves_empty_file_preallocation_without_exposing_it_as_payload() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let (source, slice, geometry) = tail_file(kind, 512, false);
        let at = root(&geometry) + 32;
        source
            .memory
            .lock()
            .unwrap()
            .put(slice.base + at + 28, &0_u32.to_le_bytes());
        let (_, plan, moved) = shrink(&cx, slice, &geometry);
        assert_eq!(moved, 3);
        let output = volume(&cx, plan.clone());
        let file = output.resolve(&cx, "/KEEP.BIN").unwrap().unwrap();
        let chain = output.file_chain(&cx, &file).unwrap();
        assert_eq!(chain.size, 0);
        assert_eq!(chain.clusters.len(), 4);
        assert!(output.read(&cx, &chain, 0, 4096).unwrap().is_empty());
        assert_eq!(output.check(&cx).unwrap().preallocated_clusters, 4);
        for (&cluster, byte) in chain.clusters.iter().zip([0x31, 0x52, 0x73, 0x94]) {
            assert_eq!(
                read(
                    plan.as_ref(),
                    plan.new.cluster_offset(cluster).unwrap(),
                    512
                ),
                vec![byte; 512]
            );
        }
        assert!(source.memory.lock().unwrap().writes.is_empty());
    }
}

#[test]
fn relocation_rewrites_entries_inside_a_moved_fragment_of_a_retained_directory_chain() {
    let cx = Cx::for_testing();
    let (source, slice, geometry) = tail_file(FatKind::Fat32, 512, false);
    let tail = geometry.cluster_count() + 1;
    let first = geometry.cluster_offset(10).unwrap();
    let fragment = geometry.cluster_offset(tail - 3).unwrap();
    let keep = read(&slice, root(&geometry) + 32, 32);
    fat_word(&source, &slice, &geometry, 10, tail - 3);
    fat_word(&source, &slice, &geometry, tail - 3, 0x0FFF_FFFF);
    {
        let mut state = source.memory.lock().unwrap();
        state.put(
            slice.base + root(&geometry) + 32,
            &directory_record(b"PARENT     ", 10),
        );
        state.put(slice.base + first, &directory_record(b".          ", 10));
        state.put(
            slice.base + first + 32,
            &directory_record(b"..         ", 0),
        );
        for index in 2..16 {
            let name = format!("F{index:07}TXT");
            state.put(
                slice.base + first + index * 32,
                &record(name.as_bytes().try_into().unwrap(), 0, 0, FatKind::Fat32),
            );
        }
        state.put(slice.base + fragment, &keep);
    }
    let (_, plan, moved) = shrink(&cx, slice, &geometry);
    assert_eq!(moved, 4);
    let output = volume(&cx, plan.clone());
    let parent = output.resolve(&cx, "/PARENT").unwrap().unwrap();
    assert_eq!(parent.native.first_cluster, 10);
    assert_eq!(
        output
            .directory_size(&cx, parent.directory().unwrap())
            .unwrap(),
        1024
    );
    assert_eq!(
        output.list(&cx, parent.directory().unwrap()).unwrap().len(),
        15
    );
    let file = output.resolve(&cx, "/PARENT/KEEP.BIN").unwrap().unwrap();
    assert_eq!(file.offset, plan.new.cluster_offset(3).unwrap());
    assert_eq!(
        output.file_chain(&cx, &file).unwrap().clusters,
        [4, 9, 6, 5]
    );
    let mut expected = keep;
    pointer(&mut expected, FatKind::Fat32, 4);
    assert_eq!(read(plan.as_ref(), file.offset, 32), expected);
    assert!(output.check(&cx).unwrap().clean);
    assert!(source.memory.lock().unwrap().writes.is_empty());
}
