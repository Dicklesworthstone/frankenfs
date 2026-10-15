//! Native directory-creation controls using the shared pending/durable fixture.

use super::*;

fn mark_chain_end(image: &Image, kind: FatKind, cluster: u32) {
    let end = if kind == FatKind::Fat16 {
        0xFFFF
    } else {
        0x0FFF_FFFF
    };
    let volume = image.volume();
    let copies = volume.copies();
    let width = kind.entry_bytes() as usize;
    let mut state = image.device.state.lock().unwrap();
    for copy in copies {
        let at = image.base + image.geometry.entry_offset(copy, cluster).unwrap();
        let mut raw = [0; 4];
        state.read(at, &mut raw[..width]);
        let mask = if kind == FatKind::Fat16 {
            0xFFFF
        } else {
            0x0FFF_FFFF
        };
        let updated = (u32::from_le_bytes(raw) & !mask) | end;
        state.put(at, &updated.to_le_bytes()[..width]);
    }
}

fn add_subdirectory(image: &Image, kind: FatKind, cluster: u32) {
    mark_chain_end(image, kind, cluster);
    let mut state = image.device.state.lock().unwrap();
    let mut parent = short_entry(b"SUB        ", cluster, 0);
    parent[11] = 0x10;
    state.put(image.root + 32, &parent);
    state.put(image.root + 64, &[0; 32]);

    let mut dot = short_entry(b".          ", cluster, 0);
    dot[11] = 0x10;
    let mut dotdot = short_entry(b"..         ", 0, 0);
    dotdot[11] = 0x10;
    let start = image.base + image.geometry.cluster_offset(cluster).unwrap();
    state.put(start, &dot);
    state.put(start + 32, &dotdot);
    state.put(start + 64, &[0; 32]);
    state.persist();
}

fn raw_cluster(kind: FatKind, entry: &[u8]) -> u32 {
    let low = u32::from(u16::from_le_bytes([entry[26], entry[27]]));
    if kind == FatKind::Fat32 {
        low | (u32::from(u16::from_le_bytes([entry[20], entry[21]]) & 0x0FFF) << 16)
    } else {
        low
    }
}

#[test]
fn mkdir_root_and_nested_long_names_initialize_dot_and_dotdot() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for sector in [512, 4096] {
            let image = Image::new(kind, sector, kind == FatKind::Fat32);
            let volume = image.volume();
            let before = volume.check(&cx).unwrap();
            let plan =
                mkdir::DirectoryCreation::prepare(&cx, &volume, "/Release notes 🦀", NOW).unwrap();
            let cluster = plan.directory_cluster;
            plan.execute(&cx, &volume).unwrap();

            let reopened = image.volume();
            let entry = reopened.resolve(&cx, "/Release notes 🦀").unwrap().unwrap();
            assert!(entry.native.is_directory());
            assert_eq!(entry.native.first_cluster, cluster);
            assert!(
                reopened
                    .list(&cx, Directory::Cluster(cluster))
                    .unwrap()
                    .is_empty()
            );
            let raw = image.bytes(
                image.base + image.geometry.cluster_offset(cluster).unwrap(),
                64,
            );
            assert_eq!(&raw[..11], b".          ");
            assert_eq!(raw_cluster(kind, &raw[..32]), cluster);
            assert_eq!(&raw[32..43], b"..         ");
            assert_eq!(raw_cluster(kind, &raw[32..64]), 0);
            let after = reopened.check(&cx).unwrap();
            assert!(after.clean);
            assert_eq!(after.files, before.files);
            assert_eq!(after.directories, before.directories + 1);

            image.guards();

            let nested_image = Image::new(kind, sector, kind == FatKind::Fat32);
            add_subdirectory(&nested_image, kind, 8);
            let volume = nested_image.volume();
            let nested =
                mkdir::DirectoryCreation::prepare(&cx, &volume, "/SUB/Child folder", NOW).unwrap();
            let child = nested.directory_cluster;
            nested.execute(&cx, &volume).unwrap();
            let reopened = nested_image.volume();
            let raw = nested_image.bytes(
                nested_image.base + nested_image.geometry.cluster_offset(child).unwrap(),
                64,
            );
            assert_eq!(raw_cluster(kind, &raw[..32]), child);
            assert_eq!(raw_cluster(kind, &raw[32..64]), 8);
            assert!(reopened.check(&cx).unwrap().clean);
            nested_image.guards();
        }
    }
}

#[test]
fn mkdir_full_fat32_root_grows_parent_and_preserves_existing_sector() {
    let cx = Cx::for_testing();
    let image = Image::new(FatKind::Fat32, 512, true);
    {
        let mut state = image.device.state.lock().unwrap();
        for index in 1..16 {
            let name = format!("F{index:07}TXT");
            state.put(
                image.root + index * 32,
                &short_entry(name.as_bytes().try_into().unwrap(), 0, 0),
            );
        }
        state.persist();
    }
    let volume = image.volume();
    let before = volume.check(&cx).unwrap();
    let first_sector = image.bytes(image.root, 512);
    let plan =
        mkdir::DirectoryCreation::prepare(&cx, &volume, "/A long directory name", NOW).unwrap();
    let parent_clusters = plan.namespace.directory_clusters();
    assert!(parent_clusters >= 1);
    plan.execute(&cx, &volume).unwrap();

    let reopened = image.volume();
    let entry = reopened
        .resolve(&cx, "/A long directory name")
        .unwrap()
        .unwrap();
    assert!(entry.native.is_directory());
    assert_eq!(image.bytes(image.root, 512), first_sector);
    let after = reopened.check(&cx).unwrap();
    assert!(after.clean);
    assert_eq!(
        before.free_clusters - after.free_clusters,
        1 + parent_clusters as u64
    );
    assert_eq!(after.directories, before.directories + 1);
    image.guards();
}

#[test]
fn mkdir_collision_fixed_root_and_cancellation_refuse_without_writes() {
    let cx = Cx::for_testing();
    let image = Image::new(FatKind::Fat16, 512, false);
    let volume = image.volume();
    for path in ["/KEEP.BIN", "/keep.bin", "/", "/../BAD"] {
        assert!(mkdir::DirectoryCreation::prepare(&cx, &volume, path, NOW).is_err());
    }
    assert_eq!(image.device.state.lock().unwrap().operations, 0);

    let (_, length) = image.geometry.fixed_root().unwrap();
    {
        let mut state = image.device.state.lock().unwrap();
        for index in 1..length / 32 {
            let name = format!("F{index:07}TXT");
            state.put(
                image.root + index * 32,
                &short_entry(name.as_bytes().try_into().unwrap(), 0, 0),
            );
        }
        state.persist();
    }
    assert!(volume.check(&cx).unwrap().clean);
    assert!(mkdir::DirectoryCreation::prepare(&cx, &volume, "/NEW-DIR", NOW).is_err());
    assert_eq!(image.device.state.lock().unwrap().operations, 0);

    let cancelled = Cx::for_testing();
    cancelled.cancel_with(
        asupersync::types::CancelKind::User,
        Some("mkdir cancellation control"),
    );
    assert!(mkdir::DirectoryCreation::prepare(&cancelled, &volume, "/CANCEL", NOW).is_err());
    assert_eq!(image.device.state.lock().unwrap().operations, 0);
    image.guards();
}

fn rename_target(image: &Image, name: &str) -> (u64, usize) {
    let cx = Cx::for_testing();
    let native = names::NativeName::plan(&cx, &image.volume(), Directory::Root, name).unwrap();
    let count = native.long_slots();
    mark_chain_end(image, image.geometry.kind(), 8);
    let mut entry = short_entry(&native.short, 8, 4);
    entry[12] = native.flags;
    let start = image.root + 32;
    let mut state = image.device.state.lock().unwrap();
    for index in 0..count {
        state.put(start + index as u64 * 32, &native.slot(count - index));
    }
    let short = start + count as u64 * 32;
    state.put(short, &entry);
    state.put(short + 32, &[0; 32]);
    state.put(image.base + image.geometry.cluster_offset(8).unwrap(), b"OLD!");
    state.persist();
    (short, count)
}

#[test]
fn rename_rejects_native_subtree_cycles_through_case_alias_and_dot_paths() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let image = Image::new(kind, 512, false);
        let volume = image.volume();
        mkdir::mkdir_in_volume(&cx, &volume, "/Source directory", NOW, false).unwrap();
        mkdir::mkdir_in_volume(&cx, &volume, "/Source directory/Child", NOW, false).unwrap();
        let source = volume.resolve(&cx, "/Source directory").unwrap().unwrap();
        let alias = source.short_alias().unwrap();
        let before = image.device.state.lock().unwrap().clone();
        for path in [
            "/source directory/moved".to_owned(),
            format!("/{alias}/moved"),
            format!("//./{}/./Child/moved", alias.to_lowercase()),
            "/Source directory/Child/DEEP".to_owned(),
        ] {
            for dry_run in [true, false] {
                let error = mkdir::rename_in_volume(
                    &cx, &volume, "/Source directory", &path, dry_run,
                ).unwrap_err();
                assert!(format!("{error:#}").contains("subtree"), "{error:#}");
                let after = image.device.state.lock().unwrap();
                assert_eq!(after.operations, before.operations);
                assert_eq!(after.durable, before.durable);
                assert_eq!(after.pending, before.pending);
            }
        }
        assert!(volume.check(&cx).unwrap().clean);
        image.guards();
    }
}

#[test]
fn rename_replacement_keeps_destination_lfn_and_matches_dry_run() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for sector in [512, 4096] {
            for active in [false, true] {
                if kind == FatKind::Fat16 && active { continue; }
                let image = Image::new(kind, sector, active);
                let (short, count) = rename_target(&image, "Existing long destination.txt");
                let volume = image.volume();
                let old_target = volume.resolve(&cx, "/Existing long destination.txt").unwrap().unwrap();
                let alias_path = format!("/{}", old_target.short_alias().unwrap());
                let lfn = image.bytes(image.root + 32, count * 32);
                let before = volume.check(&cx).unwrap();
                let snapshot = image.device.state.lock().unwrap().clone();
                let dry = mkdir::rename_in_volume(&cx, &volume, "/KEEP.BIN", &alias_path, true).unwrap();
                {
                    let state = image.device.state.lock().unwrap();
                    assert_eq!(state.operations, snapshot.operations);
                    assert_eq!(state.durable, snapshot.durable);
                    assert_eq!(state.pending, snapshot.pending);
                }
                let result = mkdir::rename_in_volume(&cx, &volume, "/KEEP.BIN", &alias_path, false).unwrap();
                assert_eq!(dry["new_entry_offset"], result["new_entry_offset"]);
                assert_eq!(dry["free_clusters_after"], result["free_clusters_after"]);
                assert_eq!(result["new_entry_offset"], short - image.base);
                assert_eq!(result["replaced_existing"], true);
                assert_eq!(result["released_clusters"], 1);
                assert_eq!(image.bytes(image.root + 32, count * 32), lfn);
                assert_eq!(contents(&volume, "/Existing long destination.txt"), b"SAFE");
                assert_eq!(contents(&volume, &alias_path), b"SAFE");
                assert!(matches!(volume.resolve(&cx, "/KEEP.BIN"), Err(FfsError::NotFound(_))));
                let after = volume.check(&cx).unwrap();
                assert!(after.clean && after.complete && after.namespace_complete);
                assert_eq!(after.files, before.files - 1);
                assert_eq!(after.free_clusters, before.free_clusters + 1);
                for copy in 0..2 {
                    let at = image.base + image.geometry.entry_offset(copy, 8).unwrap();
                    let width = kind.entry_bytes() as usize;
                    let mut old = [0; 4];
                    snapshot.read(at, &mut old[..width]);
                    let mut new = [0; 4];
                    new[..width].copy_from_slice(&image.bytes(at, width));
                    let mask = if kind == FatKind::Fat16 { 0xFFFF } else { 0x0FFF_FFFF };
                    let old = u32::from_le_bytes(old);
                    let new = u32::from_le_bytes(new);
                    if active && copy == 0 {
                        assert_eq!(new, old, "inactive FAT must remain untouched");
                    } else {
                        assert_eq!(new & mask, 0);
                        assert_eq!(new & !mask, old & !mask);
                    }
                }
                image.guards();
            }
        }
    }
}

#[test]
fn rename_replacement_uses_existing_slot_in_full_native_directories() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let image = Image::new(kind, 512, false);
        let (short, _) = rename_target(&image, "TARGET.BIN");
        let bytes = image.geometry.fixed_root()
            .map_or(u64::from(image.geometry.cluster_bytes()), |(_, length)| length);
        {
            let mut state = image.device.state.lock().unwrap();
            for index in 2..bytes / 32 {
                let name = format!("F{index:07}TXT");
                state.put(image.root + index * 32,
                    &short_entry(name.as_bytes().try_into().unwrap(), 0, 0));
            }
            state.persist();
        }
        let volume = image.volume();
        let before = volume.check(&cx).unwrap();
        assert!(before.clean);
        let report = mkdir::rename_in_volume(&cx, &volume, "/KEEP.BIN", "/TARGET.BIN", false).unwrap();
        assert_eq!(report["new_entry_offset"], short - image.base);
        assert_eq!(contents(&volume, "/TARGET.BIN"), b"SAFE");
        let after = volume.check(&cx).unwrap();
        assert!(after.clean);
        assert_eq!(after.free_clusters, before.free_clusters + 1);
        image.guards();
    }
}

#[test]
fn rename_directory_replacement_preserves_children_and_parent_reserved_bits() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let image = Image::new(kind, 512, false);
        let volume = image.volume();
        for path in ["/SOURCE", "/SOURCE/Child", "/PARENT", "/PARENT/TARGET"] {
            mkdir::mkdir_in_volume(&cx, &volume, path, NOW, false).unwrap();
        }
        let source = volume.resolve(&cx, "/SOURCE").unwrap().unwrap();
        let parent = volume.resolve(&cx, "/PARENT").unwrap().unwrap();
        let target = volume.resolve(&cx, "/PARENT/TARGET").unwrap().unwrap();
        let at = image.base + image.geometry.cluster_offset(source.native.first_cluster).unwrap() + 32;
        let reserved = if kind == FatKind::Fat16 { 0xBEEF_u16 } else { 0xA000 };
        {
            let mut state = image.device.state.lock().unwrap();
            state.put(at + 20, &reserved.to_le_bytes());
            state.persist();
        }
        let before = volume.check(&cx).unwrap();
        assert!(before.clean);
        let report = mkdir::rename_in_volume(&cx, &volume, "/SOURCE", "/PARENT/TARGET", false).unwrap();
        assert_eq!(report["new_entry_offset"], target.offset);
        let moved = volume.resolve(&cx, "/PARENT/TARGET").unwrap().unwrap();
        assert_eq!(moved.native.first_cluster, source.native.first_cluster);
        assert!(volume.resolve(&cx, "/PARENT/TARGET/Child").unwrap().unwrap().native.is_directory());
        let dotdot = image.bytes(at, 32);
        assert_eq!(raw_cluster(kind, &dotdot), parent.native.first_cluster);
        assert_eq!(u16::from_le_bytes([dotdot[20], dotdot[21]]), reserved);
        let after = volume.check(&cx).unwrap();
        assert!(after.clean);
        assert_eq!(after.directories, before.directories - 1);
        assert_eq!(after.free_clusters, before.free_clusters + 1);
        image.guards();
    }
}

#[test]
fn rename_preflight_refusals_preserve_both_names_and_all_native_bytes() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let image = Image::new(kind, 512, false);
        let (short, _) = rename_target(&image, "TARGET.BIN");
        let volume = image.volume();
        mkdir::mkdir_in_volume(&cx, &volume, "/DIR", NOW, false).unwrap();
        {
            let mut state = image.device.state.lock().unwrap();
            state.put(short + 11, &[0x21]);
            state.persist();
        }
        let before = image.device.state.lock().unwrap().clone();
        for path in ["/TARGET.BIN", "/DIR", "/bad:name", "/NUL", "/DIR/../TARGET.BIN"] {
            for dry in [true, false] {
                assert!(mkdir::rename_in_volume(&cx, &volume, "/KEEP.BIN", path, dry).is_err());
                let state = image.device.state.lock().unwrap();
                assert_eq!(state.operations, before.operations);
                assert_eq!(state.durable, before.durable);
                assert_eq!(state.pending, before.pending);
            }
        }
        assert_eq!(contents(&volume, "/TARGET.BIN"), b"OLD!");
        assert_eq!(contents(&volume, "/KEEP.BIN"), b"SAFE");
        image.guards();
    }
}

#[test]
fn rename_directory_rejects_nonempty_target_without_mutation() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let image = Image::new(kind, 512, false);
        let volume = image.volume();
        for path in ["/SOURCE", "/TARGET", "/TARGET/Child"] {
            mkdir::mkdir_in_volume(&cx, &volume, path, NOW, false).unwrap();
        }
        let before = image.device.state.lock().unwrap().clone();
        for dry in [true, false] {
            let error = mkdir::rename_in_volume(&cx, &volume, "/SOURCE", "/TARGET", dry).unwrap_err();
            assert!(matches!(error.downcast_ref::<FfsError>(), Some(FfsError::NotEmpty)));
            let state = image.device.state.lock().unwrap();
            assert_eq!(state.operations, before.operations);
            assert_eq!(state.durable, before.durable);
            assert_eq!(state.pending, before.pending);
        }
        image.guards();
    }
}

#[test]
fn rename_to_new_long_name_preserves_file_chain_and_metadata() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let image = Image::new(kind, 512, false);
        let volume = image.volume();
        let before = volume.check(&cx).unwrap();
        let original = image.bytes(image.root, 32);
        let dry = mkdir::rename_in_volume(&cx, &volume, "/KEEP.BIN", "/A new long name.txt", true).unwrap();
        assert_eq!(image.device.state.lock().unwrap().operations, 0);
        let result = mkdir::rename_in_volume(&cx, &volume, "/KEEP.BIN", "/A new long name.txt", false).unwrap();
        assert_eq!(dry["new_entry_offset"], result["new_entry_offset"]);
        let entry = volume.resolve(&cx, "/A new long name.txt").unwrap().unwrap();
        let raw = image.bytes(image.base + entry.offset, 32);
        assert_eq!(raw[11], original[11]);
        assert_eq!(&raw[13..], &original[13..]);
        assert_eq!(contents(&volume, "/A new long name.txt"), b"SAFE");
        let after = volume.check(&cx).unwrap();
        assert!(after.clean);
        assert_eq!(after.files, before.files);
        assert_eq!(after.free_clusters, before.free_clusters);
        image.guards();
    }
}

#[test]
fn rename_fault_boundaries_never_reclaim_a_still_live_destination() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let control = Image::new(kind, 512, false);
        rename_target(&control, "TARGET.BIN");
        mkdir::rename_in_volume(&cx, &control.volume(), "/KEEP.BIN", "/TARGET.BIN", false).unwrap();
        let operations = control.device.state.lock().unwrap().operations;
        assert!(operations > 8);
        for fail in 1..=operations {
            for tear in [0, 1, 31, 511] {
                let image = Image::new(kind, 512, false);
                let (short, _) = rename_target(&image, "TARGET.BIN");
                let volume = image.volume();
                {
                    let mut state = image.device.state.lock().unwrap();
                    state.fail = Some(fail);
                    state.tear = tear;
                }
                let error = mkdir::rename_in_volume(&cx, &volume, "/KEEP.BIN", "/TARGET.BIN", false).unwrap_err();
                assert!(format!("{error:#}").contains("no rollback or atomicity"));
                let state = image.device.state.lock().unwrap().clone();
                for retain_pending in [false, true] {
                    let mut crashed = state.clone();
                    if retain_pending { crashed.persist(); } else { crashed.pending.clear(); }
                    let mut entry = [0; 32];
                    crashed.read(short, &mut entry);
                    for copy in 0..2 {
                        let mut old_fat = [0; 4];
                        let width = kind.entry_bytes() as usize;
                        let at = image.base + image.geometry.entry_offset(copy, 8).unwrap();
                        crashed.read(at, &mut old_fat[..width]);
                        if entry[0] != 0 && entry[0] != 0xE5 && raw_cluster(kind, &entry) == 8 {
                            assert_ne!(kind.decode_entry(u32::from_le_bytes(old_fat)), FatEntry::Free,
                                "live replaced chain was freed: {kind:?}, fail={fail}, tear={tear}");
                        }
                        let at = image.base + image.geometry.entry_offset(copy, 5).unwrap();
                        crashed.read(at, &mut old_fat[..width]);
                        assert_eq!(kind.decode_entry(u32::from_le_bytes(old_fat)), FatEntry::End);
                    }
                    let mut payload = [0; 4];
                    crashed.read(image.base + image.geometry.cluster_offset(5).unwrap(), &mut payload);
                    assert_eq!(&payload, b"SAFE");
                    crashed.read(image.base + image.geometry.cluster_offset(8).unwrap(), &mut payload);
                    assert_eq!(&payload, b"OLD!");
                }
                image.guards();
            }
        }
    }
}
