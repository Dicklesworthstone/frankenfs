//! Real repair plans on sparse constructed native images; not native-tool proof.
use super::*;
use super::super::fsinfo::FsInfoPlan;
use clap::Parser as _;

fn damage(device: &Device, geometry: &FatGeometry, backup: bool) {
    let size = geometry.sector_bytes() as usize;
    let mut info = vec![0xA6; size];
    info[488..492].copy_from_slice(&70_000_u32.to_le_bytes());
    info[492..496].copy_from_slice(&2_u32.to_le_bytes());
    let mut state = device.state.lock().unwrap();
    state.put(BASE + u64::from(geometry.fs_info_sector().unwrap()) * size as u64, &info);
    if backup {
        info[..4].copy_from_slice(&0x4161_5252_u32.to_le_bytes());
        info[484..488].copy_from_slice(&0x6141_7272_u32.to_le_bytes());
        info[508..512].copy_from_slice(&0xAA55_0000_u32.to_le_bytes());
        state.put(BASE + 7 * size as u64, &info);
    }
    state.persist();
}

fn expected(mut bytes: Vec<u8>, free: u32, next: u32) -> Vec<u8> {
    bytes[..4].copy_from_slice(b"RRaA");
    bytes[484..488].copy_from_slice(b"rrAa");
    bytes[488..492].copy_from_slice(&free.to_le_bytes());
    bytes[492..496].copy_from_slice(&next.to_le_bytes());
    bytes[508..512].copy_from_slice(&[0, 0, 0x55, 0xAA]);
    bytes
}

fn assert_payload(device: &Device, geometry: &FatGeometry) {
    assert_eq!(device.bytes(BASE + geometry.cluster_offset(5).unwrap(), PAYLOAD.len()), PAYLOAD);
    assert_eq!(device.bytes(0, PAGE), vec![0xA7; PAGE]);
    assert_eq!(device.bytes(device.length - BASE, PAGE), vec![0xB9; PAGE]);
}

#[test]
fn reconstructs_exact_hints_and_only_five_words_in_primary_and_recognized_backup() {
    for sector in [512, 4096] {
        for active in [false, true] {
            let (device, args, geometry) = fixture(FatKind::Fat32, sector, active);
            damage(&device, &geometry, true);
            let primary = BASE + u64::from(sector);
            let backup = BASE + 7 * u64::from(sector);
            let old_primary = device.bytes(primary, sector as usize);
            let old_backup = device.bytes(backup, sector as usize);
            let cx = Cx::for_testing();
            let diagnostic = device.diagnostic(&cx, &args);
            assert!(Plan::prepare(&cx, &diagnostic, true, false).is_err(), "ordinary recovery must not gain this authority");
            let plan = FsInfoPlan::prepare(&cx, &diagnostic).unwrap();
            let before = diagnostic.report(&cx).unwrap();
            assert_eq!(before.free_clusters, 69_996);
            let initial = device.state.lock().unwrap().image();
            device.arm(None);
            let dry = plan.report(true);
            assert_eq!(dry["next_free_cluster"], 3);
            assert_eq!(device.state.lock().unwrap().attempts, 0);
            assert_eq!(device.state.lock().unwrap().image(), initial);
            let report = plan.execute(&cx, &diagnostic).unwrap();
            assert_eq!(report["changed"], true);
            assert_eq!(report["reclaimed_clusters"], 0);
            assert_eq!(report["verification"]["lost_clusters"], 2);
            assert_eq!(report["verification"]["clean"], false);
            assert_eq!(device.bytes(primary, sector as usize), expected(old_primary, 69_996, 3));
            assert_eq!(device.bytes(backup, sector as usize), expected(old_backup, 69_996, 3));
            let after = diagnostic.report(&cx).unwrap();
            assert_eq!(after.referenced_clusters, before.referenced_clusters);
            assert_eq!(after.preallocated_clusters, before.preallocated_clusters);
            assert!(after.issues.iter().all(|issue| matches!(issue.kind, "native_boot_dirty" | "native_fat_dirty" | "lost_allocation")));
            // All ordinary allocation words and inactive reserved entries survive.
            let actual = device.state.lock().unwrap().image();
            let mut expected_image = Storage { durable: initial, ..Storage::default() };
            for number in [0_u16, 6] {
                expected_image.put(BASE + u64::from(number) * u64::from(sector) + 65, &[1]);
            }
            for copy in diagnostic.volume.copies() {
                let at = BASE + geometry.entry_offset(copy, 2).unwrap() - 1;
                expected_image.put(at, &[((10 + copy) << 4) | 7]);
            }
            expected_image.put(primary, &device.bytes(primary, sector as usize));
            expected_image.put(backup, &device.bytes(backup, sector as usize));
            assert_eq!(actual, expected_image.image());
            assert_payload(&device, &geometry);
        }
    }
}

#[test]
fn unknown_reserved_backup_is_preserved_instead_of_inventing_fsinfo() {
    let (device, args, geometry) = fixture(FatKind::Fat32, 4096, false);
    damage(&device, &geometry, false);
    let reserved = BASE + 7 * 4096;
    device.state.lock().unwrap().put(reserved, &[0xD3; 4096]);
    device.state.lock().unwrap().persist();
    let cx = Cx::for_testing();
    let diagnostic = device.diagnostic(&cx, &args);
    let plan = FsInfoPlan::prepare(&cx, &diagnostic).unwrap();
    device.arm(None);
    let report = plan.execute(&cx, &diagnostic).unwrap();
    assert_eq!(report["backup_policy"], "unrecognized_reserved_sector_preserved");
    assert_eq!(device.bytes(reserved, 4096), vec![0xD3; 4096]);
    assert!(!device.state.lock().unwrap().events.iter().any(|event| matches!(event, Event::Write(at, _) if *at == reserved)));
}

#[test]
fn refuses_fat16_absent_or_overlapping_fsinfo_and_ambiguous_allocation_without_writes() {
    for problem in ["fat16", "absent", "overlap", "mirror", "crosslink", "io_error", "boot_geometry"] {
        let kind = if problem == "fat16" { FatKind::Fat16 } else { FatKind::Fat32 };
        let (device, args, geometry) = fixture(kind, 512, false);
        if kind == FatKind::Fat32 { damage(&device, &geometry, true); }
        {
            let mut state = device.state.lock().unwrap();
            match problem {
                "absent" | "overlap" => {
                    let info = if problem == "absent" { 0_u16 } else { 6 };
                    for base in [BASE, BASE + 6 * 512] { state.put(base + 48, &info.to_le_bytes()); }
                }
                "mirror" => state.put(BASE + geometry.entry_offset(0, 300).unwrap(), &0xAFFF_FFFF_u32.to_le_bytes()),
                "crosslink" => {
                    let root = BASE + geometry.cluster_offset(2).unwrap();
                    let mut record = [0; 32];
                    state.read(root, &mut record);
                    record[..11].copy_from_slice(b"ALIAS   BIN");
                    state.put(root + 32, &record);
                }
                "io_error" => state.put(BASE + geometry.entry_offset(1, 2).unwrap() - 4, &0xBBFF_FFFF_u32.to_le_bytes()),
                _ => {}
            }
            state.persist();
        }
        let cx = Cx::for_testing();
        let diagnostic = device.diagnostic(&cx, &args);
        if problem == "boot_geometry" {
            device.state.lock().unwrap().put(BASE + 13, &[2]);
            device.state.lock().unwrap().persist();
        }
        let before = device.state.lock().unwrap().image();
        device.arm(None);
        assert!(FsInfoPlan::prepare(&cx, &diagnostic).is_err(), "{problem}");
        assert_eq!(device.state.lock().unwrap().attempts, 0, "{problem}");
        assert_eq!(device.state.lock().unwrap().image(), before);
    }
}

#[test]
fn same_count_namespace_or_allocation_changes_and_stale_hint_sector_refuse_before_writes() {
    for change in ["name", "orphan_successor", "reserved_hint_byte"] {
        let (device, args, geometry) = fixture(FatKind::Fat32, 512, false);
        damage(&device, &geometry, true);
        let cx = Cx::for_testing();
        let diagnostic = device.diagnostic(&cx, &args);
        let plan = FsInfoPlan::prepare(&cx, &diagnostic).unwrap();
        let before = serde_json::to_value(diagnostic.report(&cx).unwrap()).unwrap();
        {
            let mut state = device.state.lock().unwrap();
            match change {
                "name" => state.put(BASE + geometry.cluster_offset(2).unwrap(), b"N"),
                "orphan_successor" => for copy in 0..2_u8 {
                    state.put(BASE + geometry.entry_offset(copy, 300).unwrap(), &(((10 + u32::from(copy)) << 28) | 300).to_le_bytes());
                },
                _ => state.put(BASE + 512 + 100, &[0x43]),
            }
            state.persist();
        }
        assert_eq!(serde_json::to_value(diagnostic.report(&cx).unwrap()).unwrap(), before);
        let changed = device.state.lock().unwrap().image();
        device.arm(None);
        assert!(plan.execute(&cx, &diagnostic).is_err(), "{change}");
        assert_eq!(device.state.lock().unwrap().attempts, 0);
        assert_eq!(device.state.lock().unwrap().image(), changed);
    }
}

#[test]
fn no_free_space_uses_unknown_next_hint_and_bad_clusters_never_count_as_free() {
    let (device, args, geometry) = fixture(FatKind::Fat32, 512, false);
    damage(&device, &geometry, true);
    {
        let mut state = device.state.lock().unwrap();
        for copy in 0..2_u8 {
            for cluster in 2..=geometry.cluster_count() + 1 {
                if !matches!(cluster, 2 | 5 | 300 | 301) {
                    let bad = ((10 + u32::from(copy)) << 28) | 0x0FFF_FFF7;
                    state.put(BASE + geometry.entry_offset(copy, cluster).unwrap(), &bad.to_le_bytes());
                }
            }
        }
        state.persist();
    }
    let cx = Cx::for_testing();
    let diagnostic = device.diagnostic(&cx, &args);
    let report = FsInfoPlan::prepare(&cx, &diagnostic).unwrap().execute(&cx, &diagnostic).unwrap();
    assert_eq!(report["free_clusters"], 0);
    assert_eq!(report["next_free_cluster"], u32::MAX);
    assert_eq!(report["verification"]["bad_clusters"], 69_996);
    assert_eq!(device.bytes(BASE + 512 + 488, 8), [0, 0, 0, 0, 255, 255, 255, 255]);
    assert_payload(&device, &geometry);
}

#[test]
fn every_write_sync_failure_stops_without_cleanup_or_payload_changes() {
    let (initial, args, geometry) = fixture(FatKind::Fat32, 512, false);
    damage(&initial, &geometry, true);
    let pages = initial.state.lock().unwrap().image();
    let cx = Cx::for_testing();
    let diagnostic = initial.diagnostic(&cx, &args);
    let plan = FsInfoPlan::prepare(&cx, &diagnostic).unwrap();
    initial.arm(None);
    plan.execute(&cx, &diagnostic).unwrap();
    let attempts = initial.state.lock().unwrap().attempts;
    assert!(attempts >= 9);
    for cut in 1..=attempts {
        for prefix in [0, 67, 511] {
            let device = Device { state: Arc::new(Mutex::new(Storage { durable: pages.clone(), ..Storage::default() })), length: initial.length };
            let cx = Cx::for_testing();
            let diagnostic = device.diagnostic(&cx, &args);
            let plan = FsInfoPlan::prepare(&cx, &diagnostic).unwrap();
            device.arm(Some(Fault::Fail(cut, prefix)));
            assert!(plan.execute(&cx, &diagnostic).is_err(), "cut {cut}, prefix {prefix}");
            assert_eq!(device.state.lock().unwrap().attempts, cut);
            assert_payload(&device, &geometry);
            for pending in [false, true] {
                let state = device.state.lock().unwrap();
                let durable = if pending { state.image() } else { state.durable.clone() };
                drop(state);
                let crashed = Device { state: Arc::new(Mutex::new(Storage { durable, ..Storage::default() })), length: device.length };
                assert_payload(&crashed, &geometry);
                for copy in 0..2_u8 {
                    let at = BASE + geometry.entry_offset(copy, 300).unwrap();
                    assert_eq!(crashed.bytes(at, 8), initial.bytes(at, 8));
                }
            }
        }
    }
}

#[test]
fn sync_time_loss_corruption_read_failure_and_cancellation_are_not_success() {
    for fault in [
        Fault::DiscardAtSync(1), Fault::DiscardAtSync(2), Fault::DiscardAtSync(3),
        Fault::FlipAtSync(2, BASE + 512 + 100), Fault::ReadAfterSync(2),
        Fault::CancelAtSync(2), Fault::ReadAt(BASE + 512),
    ] {
        let (device, args, geometry) = fixture(FatKind::Fat32, 512, false);
        damage(&device, &geometry, true);
        let cx = Cx::for_testing();
        let diagnostic = device.diagnostic(&cx, &args);
        let plan = FsInfoPlan::prepare(&cx, &diagnostic).unwrap();
        device.arm(Some(fault));
        assert!(plan.execute(&cx, &diagnostic).is_err());
        assert_payload(&device, &geometry);
        let state = device.state.lock().unwrap();
        if matches!(fault, Fault::DiscardAtSync(1)) {
            assert_eq!(state.syncs, 1);
            assert!(!state.events.iter().any(|event| matches!(event, Event::Write(at, _) if *at == BASE + 512 || *at == BASE + 7 * 512)));
        }
        if matches!(fault, Fault::ReadAt(_)) { assert_eq!(state.attempts, 0); }
    }
}

#[test]
fn repeated_reconstruction_and_cancelled_preflight_have_no_write_or_sync_attempts() {
    let (device, args, geometry) = fixture(FatKind::Fat32, 512, true);
    damage(&device, &geometry, true);
    let cx = Cx::for_testing();
    let diagnostic = device.diagnostic(&cx, &args);
    FsInfoPlan::prepare(&cx, &diagnostic).unwrap().execute(&cx, &diagnostic).unwrap();
    let repeated = FsInfoPlan::prepare(&cx, &diagnostic).unwrap();
    device.arm(None);
    assert_eq!(repeated.execute(&cx, &diagnostic).unwrap()["changed"], false);
    assert_eq!(device.state.lock().unwrap().attempts, 0);
    cx.set_cancel_requested(true);
    assert!(FsInfoPlan::prepare(&cx, &diagnostic).is_err());
    assert_eq!(device.state.lock().unwrap().attempts, 0);
}

#[test]
fn namespace_change_during_dirty_sync_stops_before_any_fsinfo_write() {
    let (device, args, geometry) = fixture(FatKind::Fat32, 4096, false);
    damage(&device, &geometry, true);
    let cx = Cx::for_testing();
    let diagnostic = device.diagnostic(&cx, &args);
    let plan = FsInfoPlan::prepare(&cx, &diagnostic).unwrap();
    let primary = device.bytes(BASE + 4096, 4096);
    let backup = device.bytes(BASE + 7 * 4096, 4096);
    let root = BASE + geometry.cluster_offset(2).unwrap();
    device.arm(Some(Fault::FlipAtSync(1, root)));
    assert!(plan.execute(&cx, &diagnostic).is_err());
    assert_eq!(device.bytes(BASE + 4096, 4096), primary);
    assert_eq!(device.bytes(BASE + 7 * 4096, 4096), backup);
    assert_no_writes_after_sync(&device);
    assert_payload(&device, &geometry);
}

#[test]
fn public_cli_dry_run_and_repair_round_trip_to_separate_ordinary_recovery() {
    let (device, _args, geometry) = fixture(FatKind::Fat32, 512, false);
    damage(&device, &geometry, true);
    {
        let mut state = device.state.lock().unwrap();
        for copy in 0..2_u8 {
            for cluster in [300, 301] {
                state.put(BASE + geometry.entry_offset(copy, cluster).unwrap(), &((10 + u32::from(copy)) << 28).to_le_bytes());
            }
        }
        state.persist();
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fsinfo.fat");
    let file = File::create(&path).unwrap();
    file.set_len(device.length).unwrap();
    for (page, bytes) in device.state.lock().unwrap().image() {
        let at = page * PAGE as u64;
        let count = (device.length - at).min(PAGE as u64) as usize;
        file.write_all_at(&bytes[..count], at).unwrap();
    }
    file.sync_all().unwrap();
    drop(file);
    let initial = fs::read(&path).unwrap();
    let cx = Cx::for_testing();
    for dry in [true, false, false] {
        let mut argv = vec!["ffs-fat", "repair-fsinfo", path.to_str().unwrap(), "--offline-image", "--offset", "4096"];
        if dry { argv.push("--dry-run"); }
        let crate::Command::RepairFsInfo { options } = crate::Cli::try_parse_from(argv).unwrap().command else { panic!("expected FSInfo repair"); };
        let report = super::super::fsinfo::repair_fsinfo(&cx, &options).unwrap();
        assert_eq!(report["dry_run"], dry);
        if dry { assert_eq!(fs::read(&path).unwrap(), initial); }
    }
    let crate::Command::Recover { options } = crate::Cli::try_parse_from([
        "ffs-fat", "recover", path.to_str().unwrap(), "--offline-image", "--offset", "4096",
    ]).unwrap().command else { panic!("expected ordinary recovery"); };
    assert_eq!(recover(&cx, &options).unwrap()["verification"]["clean"], true);
    let after = fs::read(&path).unwrap();
    assert_eq!(&after[..BASE as usize], &initial[..BASE as usize]);
    assert_eq!(&after[(device.length - BASE) as usize..], &initial[(device.length - BASE) as usize..]);
    let at = (BASE + geometry.cluster_offset(5).unwrap()) as usize;
    assert_eq!(&after[at..at + PAYLOAD.len()], PAYLOAD);
}

#[test]
fn command_authority_is_explicit_and_has_no_reclamation_or_force_switch() {
    assert!(crate::Cli::try_parse_from(["ffs-fat", "repair-fsinfo", "image"]).is_err());
    for flag in ["--force", "--reclaim-lost", "--repair-mirrors-from", "--discard-orphan-lfn"] {
        assert!(crate::Cli::try_parse_from(["ffs-fat", "repair-fsinfo", "image", "--offline-image", flag]).is_err());
    }
    let crate::Command::RepairFsInfo { options } = crate::Cli::try_parse_from([
        "ffs-fat", "repair-fsinfo", "never-opened.img", "--offline-image", "--sidecar", "never-opened.sidecar",
    ]).unwrap().command else { panic!("expected repair"); };
    let error = super::super::fsinfo::repair_fsinfo(&Cx::for_testing(), &options).unwrap_err();
    assert!(error.to_string().contains("sidecar"));
}
