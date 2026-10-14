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
