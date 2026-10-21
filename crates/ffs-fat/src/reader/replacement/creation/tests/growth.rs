//! Growth controls use the same pending/durable device as create-only tests.

use super::*;

fn full_parent(kind: FatKind, sector: u32, active: bool, nested: bool) -> (Image, String, u32) {
    let image = Image::new(kind, sector, active);
    let end = if kind == FatKind::Fat16 {
        0xFFFF
    } else {
        0x0FFF_FFFF
    };
    let first = if nested { 8 } else { 2 };
    let start = image.base + image.geometry.cluster_offset(first).unwrap();
    // Select copies before locking the device; opening a volume reads it.
    let copies = image.volume().copies();
    {
        let mut state = image.device.state.lock().unwrap();
        if nested {
            for copy in copies {
                let at = image.base + image.geometry.entry_offset(copy, first).unwrap();
                let width = kind.entry_bytes() as usize;
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
            let mut directory = short_entry(b"SUB        ", first, 0);
            directory[11] = 0x10;
            state.put(image.root + 32, &directory);
            state.put(image.root + 64, &[0; 32]);
            for (index, name, cluster) in [(0, b".          ", first), (1, b"..         ", 0)] {
                let mut entry = short_entry(name, cluster, 0);
                entry[11] = 0x10;
                state.put(start + index * 32, &entry);
            }
        } else {
            assert_eq!(kind, FatKind::Fat32);
        }
        for index in (if nested { 2 } else { 1 })..u64::from(sector) / 32 {
            let name = format!("F{index:07}TXT");
            state.put(
                start + index * 32,
                &short_entry(name.as_bytes().try_into().unwrap(), 0, 0),
            );
        }
        state.persist();
    }
    let path = if nested { "/SUB/NEW.BIN" } else { "/NEW.BIN" }.to_owned();
    assert!(image.volume().check(&Cx::for_testing()).unwrap().clean);
    (image, path, first)
}

#[test]
fn creation_grows_full_root_and_subdirectories_without_replacing_existing_allocation() {
    let cx = Cx::for_testing();
    for (kind, nested) in [
        (FatKind::Fat16, true),
        (FatKind::Fat32, false),
        (FatKind::Fat32, true),
    ] {
        for sector in [512, 4096] {
            for active in [false, true] {
                if active && kind == FatKind::Fat16 {
                    continue;
                }
                let (image, path, first) = full_parent(kind, sector, active, nested);
                let volume = image.volume();
                let old_parent = image.bytes(
                    image.base + image.geometry.cluster_offset(first).unwrap(),
                    sector as usize,
                );
                let before = volume.check(&cx).unwrap();
                let input = source(&vec![0xD5; 1300]);
                let probe = prepare(&cx, &volume, &path, &input, NOW).unwrap();
                let extension = probe
                    .creation
                    .as_ref()
                    .unwrap()
                    .extension
                    .as_ref()
                    .unwrap()
                    .cluster;
                // Free space need not be zero. Initialization must overwrite it
                // without ever publishing it as live directory records.
                image.device.state.lock().unwrap().put(
                    image.base + image.geometry.cluster_offset(extension).unwrap(),
                    &vec![0xCC; sector as usize],
                );
                let plan = prepare(&cx, &volume, &path, &input, NOW).unwrap();
                assert!(!plan.clusters.contains(&extension));
                assert_eq!(plan.creation.as_ref().unwrap().directory_clusters(), 1);
                let report = plan.execute(&cx, &volume, &input, || Ok(())).unwrap();
                assert_eq!(report["new_directory_clusters"], 1);
                let reopened = image.volume();
                assert_eq!(contents(&reopened, &path), vec![0xD5; 1300]);
                assert_eq!(contents(&reopened, "/KEEP.BIN"), b"SAFE");
                assert_eq!(
                    image.bytes(
                        image.base + image.geometry.cluster_offset(first).unwrap(),
                        sector as usize
                    ),
                    old_parent
                );
                assert_eq!(
                    image.bytes(
                        image.base + image.geometry.cluster_offset(extension).unwrap() + 32,
                        sector as usize - 32
                    ),
                    vec![0; sector as usize - 32]
                );
                let after = reopened.check(&cx).unwrap();
                assert!(after.clean);
                assert_eq!(
                    before.free_clusters - after.free_clusters,
                    plan.clusters.len() as u64 + 1
                );
                assert_eq!(after.files, before.files + 1);
                assert_eq!(after.directories, before.directories);
                image.guards();
            }
        }
    }
}

#[test]
fn creation_extension_changed_tail_is_refused_before_any_writer_operation() {
    let cx = Cx::for_testing();
    let (image, path, first) = full_parent(FatKind::Fat32, 512, false, false);
    let volume = image.volume();
    let input = source(b"new");
    let plan = prepare(&cx, &volume, &path, &input, NOW).unwrap();
    // Modify a selected tail after prepare, not a source-owned data cluster.
    let copies = volume.copies();
    {
        let mut state = image.device.state.lock().unwrap();
        for copy in copies {
            let at = image.base + image.geometry.entry_offset(copy, first).unwrap();
            state.put(at, &0xA000_0000_u32.to_le_bytes());
        }
    }
    assert!(plan.execute(&cx, &volume, &input, || Ok(())).is_err());
    assert_eq!(image.device.state.lock().unwrap().operations, 0);
    image.guards();
}

#[test]
fn creation_extension_each_write_and_flush_cut_refuses_uncommitted_directory_growth() {
    let cx = Cx::for_testing();
    for (kind, nested) in [(FatKind::Fat16, true), (FatKind::Fat32, false)] {
        let (probe, path, _) = full_parent(kind, 512, false, nested);
        let input = source(b"complete new data");
        let volume = probe.volume();
        prepare(&cx, &volume, &path, &input, NOW)
            .unwrap()
            .execute(&cx, &volume, &input, || Ok(()))
            .unwrap();
        let operations = probe.device.state.lock().unwrap().operations;
        for fail in 1..=operations {
            for tear in [0, 27, 511] {
                let (image, path, _) = full_parent(kind, 512, false, nested);
                let volume = image.volume();
                let plan = prepare(&cx, &volume, &path, &input, NOW).unwrap();
                {
                    let mut state = image.device.state.lock().unwrap();
                    state.fail = Some(fail);
                    state.tear = tear;
                }
                assert!(plan.execute(&cx, &volume, &input, || Ok(())).is_err());
                for retain in [false, true] {
                    let mut state = image.device.state.lock().unwrap().clone();
                    if retain {
                        state.persist();
                    } else {
                        state.pending.clear();
                    }
                    let device = Device {
                        state: Arc::new(Mutex::new(state)),
                        length: image.device.length,
                        writable: false,
                    };
                    match FatVolume::from_device(
                        &cx,
                        Box::new(device),
                        image.base,
                        image.geometry.volume_bytes(),
                    ) {
                        Ok(reopened) => {
                            assert!(
                                reopened.check(&cx).unwrap().clean,
                                "{kind:?} growth cut {fail} tear {tear}"
                            );
                            assert_eq!(contents(&reopened, "/KEEP.BIN"), b"SAFE");
                            match reopened.resolve(&cx, &path) {
                                Ok(Some(_)) => {
                                    assert_eq!(contents(&reopened, &path), b"complete new data");
                                }
                                Err(FfsError::NotFound(_)) => (),
                                other => panic!("unexpected growth result: {other:?}"),
                            }
                        }
                        Err(FfsError::UnsupportedFeature(reason)) => assert!(
                            reason.contains("dirty") || reason.contains("I/O errors"),
                            "{reason}"
                        ),
                        Err(error) => panic!("unexpected growth reopen error: {error}"),
                    }
                }
                image.guards();
            }
        }
    }
}
