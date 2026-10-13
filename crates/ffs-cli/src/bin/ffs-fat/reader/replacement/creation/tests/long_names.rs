//! Long-name publication against native sparse image fixtures and fault cuts.

use super::*;

#[test]
fn creation_long_names_roundtrip_utf16_aliases_and_contents_in_both_dialects() {
    let cx = Cx::for_testing();
    let input = source(&vec![0xD3; 1300]);
    let names = [
        "Mixed.txt".to_owned(), "long name.txt".to_owned(), "é.txt".to_owned(),
        "A.B.C".to_owned(), "notes 🦀.txt".to_owned(), "x".repeat(255),
    ];
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for sector in [512, 4096] {
            for name in &names {
                let image = Image::new(kind, sector, kind == FatKind::Fat32);
                let volume = image.volume();
                let keep = image.bytes(image.root, 32);
                let path = format!("/{name}");
                let plan = prepare(&cx, &volume, &path, &input, NOW).unwrap();
                assert!(!plan.creation.as_ref().unwrap().long_slots.is_empty());
                assert_eq!(image.device.state.lock().unwrap().operations, 0);
                plan.execute(&cx, &volume, &input, || Ok(())).unwrap();
                let reopened = image.volume();
                let entry = reopened.resolve(&cx, &path).unwrap().unwrap();
                assert_eq!(entry.name().unwrap(), *name);
                assert_eq!(entry.native.long_name, Some(name.encode_utf16().collect()));
                let alias = entry.short_alias().unwrap();
                let by_alias = reopened.resolve(&cx, &format!("/{alias}")).unwrap().unwrap();
                assert_eq!(entry.offset, by_alias.offset);
                assert_eq!(contents(&reopened, &path), vec![0xD3; 1300]);
                assert_eq!(contents(&reopened, &format!("/{alias}")), vec![0xD3; 1300]);
                assert_eq!(image.bytes(image.root, 32), keep);
                assert!(matches!(reopened.resolve(&cx, "/GHOST.BIN"), Err(FfsError::NotFound(_))));
                assert!(reopened.check(&cx).unwrap().clean);
                image.guards();
            }
        }
    }
    assert_eq!(input.state.lock().unwrap().operations, 0);
}

#[test]
fn creation_long_aliases_skip_existing_short_and_visible_long_names() {
    let cx = Cx::for_testing();
    let image = Image::new(FatKind::Fat32, 512, false);
    let input = source(b"payload");
    let volume = image.volume();
    for (path, expected) in [
        ("/Long filename one.txt", "LONGFI~1.TXT"),
        ("/Long filename two.txt", "LONGFI~2.TXT"),
        ("/LONGFI~3.TXT", "LONGFI~3.TXT"),
        ("/Long filename three.txt", "LONGFI~4.TXT"),
    ] {
        let plan = prepare(&cx, &volume, path, &input, NOW).unwrap();
        plan.execute(&cx, &volume, &input, || Ok(())).unwrap();
        let entry = image.volume().resolve(&cx, path).unwrap().unwrap();
        assert_eq!(entry.short_alias().unwrap(), expected);
        assert_eq!(contents(&image.volume(), &format!("/{expected}")), b"payload");
    }
    let count = image.device.state.lock().unwrap().operations;
    for path in ["/long filename ONE.txt", "/longfi~1.txt", "/KEEP.BIN"] {
        assert!(prepare(&cx, &volume, path, &input, NOW).is_err());
    }
    assert_eq!(image.device.state.lock().unwrap().operations, count);
    assert!(image.volume().check(&cx).unwrap().clean);
    image.guards();

    // Reserve an alias-looking LFN whose actual short alias is different.
    let image = Image::new(FatKind::Fat16, 512, false);
    let native = NativeName { short: *b"KEEP    BIN", flags: 0, long: "LONGFI~1.TXT".encode_utf16().collect() };
    {
        let mut state = image.device.state.lock().unwrap();
        state.put(image.root, &native.slot(1));
        state.put(image.root + 32, &short_entry(b"KEEP    BIN", 5, 4));
        state.put(image.root + 64, &[0; 32]);
        state.persist();
    }
    let volume = image.volume();
    let plan = prepare(&cx, &volume, "/Long filename.txt", &input, NOW).unwrap();
    assert_eq!(&plan.updated[..11], b"LONGFI~2TXT");
    plan.execute(&cx, &volume, &input, || Ok(())).unwrap();
    assert_eq!(contents(&image.volume(), "/LONGFI~1.TXT"), b"SAFE");
}

#[test]
fn creation_long_name_grows_two_clusters_and_initializes_nonzero_free_space() {
    let cx = Cx::for_testing();
    let image = Image::new(FatKind::Fat32, 512, true);
    {
        let mut state = image.device.state.lock().unwrap();
        for index in 1..16 {
            let name = format!("F{index:07}TXT");
            state.put(image.root + index * 32, &short_entry(name.as_bytes().try_into().unwrap(), 0, 0));
        }
        state.persist();
    }
    let volume = image.volume();
    let path = format!("/{}", "x".repeat(255));
    let input = source(b"");
    let probe = prepare(&cx, &volume, &path, &input, NOW).unwrap();
    let extra: Vec<_> = probe.creation.as_ref().unwrap().extension.as_ref().unwrap().clusters().collect();
    assert_eq!(extra.len(), 2);
    {
        let mut state = image.device.state.lock().unwrap();
        for cluster in &extra {
            state.put(image.base + image.geometry.cluster_offset(*cluster).unwrap(), &[0xCC; 512]);
        }
        state.persist();
    }
    let before = volume.check(&cx).unwrap();
    let plan = prepare(&cx, &volume, &path, &input, NOW).unwrap();
    assert_eq!(plan.creation.as_ref().unwrap().directory_clusters(), 2);
    assert!(plan.clusters.is_empty());
    let report = plan.execute(&cx, &volume, &input, || Ok(())).unwrap();
    assert_eq!(report["new_directory_clusters"], 2);
    let reopened = image.volume();
    assert_eq!(contents(&reopened, &path), b"");
    assert_eq!(reopened.resolve(&cx, &path).unwrap().unwrap().name().unwrap(), "x".repeat(255));
    let after = reopened.check(&cx).unwrap();
    assert!(after.clean);
    assert_eq!(before.free_clusters - after.free_clusters, 2);
    assert_eq!(image.bytes(image.base + image.geometry.cluster_offset(extra[1]).unwrap() + 5 * 32, 512 - 5 * 32), vec![0; 512 - 5 * 32]);
    image.guards();
}

#[test]
fn creation_long_name_requires_contiguous_slots_and_revalidates_each_reserved_slot() {
    let cx = Cx::for_testing();
    let input = source(b"payload");
    let image = Image::new(FatKind::Fat16, 512, false);
    {
        let mut state = image.device.state.lock().unwrap();
        for index in 1..32 {
            let name = format!("F{index:07}TXT");
            let mut entry = short_entry(name.as_bytes().try_into().unwrap(), 0, 0);
            if index % 2 == 1 { entry[0] = 0xE5; }
            state.put(image.root + index * 32, &entry);
        }
        state.persist();
    }
    let volume = image.volume();
    assert!(volume.check(&cx).unwrap().clean);
    assert!(prepare(&cx, &volume, "/Long filename.txt", &input, NOW).is_err());
    assert_eq!(image.device.state.lock().unwrap().operations, 0);
    assert!(prepare(&cx, &volume, "/NEW.TXT", &input, NOW).is_ok());
    for position in 0..3 {
        let image = Image::new(FatKind::Fat16, 512, false);
        let volume = image.volume();
        let plan = prepare(&cx, &volume, "/A name occupying three slots.txt", &input, NOW).unwrap();
        let offset = plan.creation.as_ref().unwrap().long_slots[position].offset;
        image.device.state.lock().unwrap().put(image.base + offset + 12, &[77]);
        assert!(plan.execute(&cx, &volume, &input, || Ok(())).is_err());
        assert_eq!(image.device.state.lock().unwrap().operations, 0);
        image.guards();
    }
}

fn boundary_image(kind: FatKind) -> Image {
    let image = Image::new(kind, 512, false);
    {
        let mut state = image.device.state.lock().unwrap();
        for index in 1..15 {
            let name = format!("F{index:07}TXT");
            state.put(image.root + index * 32, &short_entry(name.as_bytes().try_into().unwrap(), 0, 0));
        }
        state.put(image.root + 15 * 32, &[0; 32]);
        state.put(image.root + 16 * 32, &short_entry(b"GHOST   BIN", 5, 4));
        state.persist();
    }
    image
}

#[test]
fn creation_long_name_each_write_and_sync_cut_never_admits_partial_or_stale_namespace() {
    let cx = Cx::for_testing();
    let input = source(b"new file contents");
    let path = "/A name across sector boundaries.txt";
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let probe = boundary_image(kind);
        let volume = probe.volume();
        prepare(&cx, &volume, path, &input, NOW).unwrap().execute(&cx, &volume, &input, || Ok(())).unwrap();
        let operations = probe.device.state.lock().unwrap().operations;
        for fail in 1..=operations {
            for tear in [0, 27, 511] {
                let image = boundary_image(kind);
                let volume = image.volume();
                let plan = prepare(&cx, &volume, path, &input, NOW).unwrap();
                {
                    let mut state = image.device.state.lock().unwrap();
                    state.fail = Some(fail);
                    state.tear = tear;
                }
                assert!(plan.execute(&cx, &volume, &input, || Ok(())).is_err());
                for retain in [false, true] {
                    let mut state = image.device.state.lock().unwrap().clone();
                    if retain { state.persist(); } else { state.pending.clear(); }
                    let device = Device { state: Arc::new(Mutex::new(state)), length: image.device.length, writable: false };
                    match FatVolume::from_device(&cx, Box::new(device), image.base, image.geometry.volume_bytes()) {
                        Ok(reopened) => {
                            assert!(reopened.check(&cx).unwrap().clean, "{kind:?} cut {fail} tear {tear}");
                            assert_eq!(contents(&reopened, "/KEEP.BIN"), b"SAFE");
                            match reopened.resolve(&cx, path) {
                                Ok(Some(entry)) => {
                                    assert_eq!(entry.name().unwrap(), &path[1..]);
                                    assert_eq!(contents(&reopened, path), b"new file contents");
                                }
                                Err(FfsError::NotFound(_)) => (),
                                other => panic!("unexpected LFN result: {other:?}"),
                            }
                            assert!(matches!(reopened.resolve(&cx, "/GHOST.BIN"), Err(FfsError::NotFound(_))));
                        }
                        Err(FfsError::UnsupportedFeature(reason)) => assert!(reason.contains("dirty") || reason.contains("I/O errors"), "{reason}"),
                        Err(error) => panic!("unexpected LFN reopen error: {error}"),
                    }
                }
                image.guards();
            }
        }
    }
}
