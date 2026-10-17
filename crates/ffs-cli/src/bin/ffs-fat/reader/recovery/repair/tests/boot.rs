//! Real formatter/native-checker recovery tests. Planted damage and storage
//! faults exercise the implementation; they are not native-OS qualification.

use super::*;
use super::super::boot::BootPlan;
use ffs_ondisk::fat::FatGeometry;
use std::sync::atomic::{AtomicBool, Ordering};

fn options(image: ImageArgs, source: u64) -> RecoverArgs {
    RecoverArgs {
        image, offline_image: true, reclaim_lost: false, discard_orphan_lfn: false,
        repair_mirrors_from: None, repair_boot_from: Some(source), salvage_to: None, dry_run: false,
    }
}

fn backup(geometry: &FatGeometry) -> u64 {
    u64::from(geometry.backup_boot_sector().unwrap()) * u64::from(geometry.sector_bytes())
}

fn boot_damage(image: &ImageArgs, at: u64) {
    patch(image, at + 11, &[0; 2]);
    patch(image, at + 510, &[0; 2]);
}

fn assert_only_boot_and_clean_bits(before: &[u8], after: &[u8], image: &ImageArgs, geometry: &FatGeometry) {
    let base = image.offset as usize;
    let size = geometry.sector_bytes() as usize;
    let backup = backup(geometry) as usize;
    for (at, (&old, &new)) in before.iter().zip(after).enumerate() {
        if old == new { continue; }
        let in_boot = (base..base + size).contains(&at)
            || (base + backup..base + backup + size).contains(&at);
        let clean_bit = (0..geometry.fat_count()).any(|copy| {
            // An explicitly inactive FAT is outside this repair's write set.
            let selected = geometry.mirrored() || copy == geometry.active_fat();
            selected && at as u64 == image.offset + geometry.entry_offset(copy, 2).unwrap() - 1
                && old ^ new == 0x08 && new & 0x08 == 0
        });
        assert!(in_boot || clean_bit, "unexpected changed byte {at}");
    }
    assert_eq!(before.len(), after.len());
}

#[test]
fn corrupt_primary_can_be_restored_from_explicit_backup_but_cleaning_is_separate() {
    let (_directory, image, geometry) = populated("fat32");
    let cx = Cx::for_testing();
    let source = backup(&geometry);
    boot_damage(&image, 0);
    assert!(image.open(&cx).is_err());
    assert!(super::super::super::check(&cx, &image).is_err());
    let original = fs::read(&image.image).unwrap();
    let mut args = options(image, source);
    args.dry_run = true;
    let dry = recover(&cx, &args).unwrap();
    assert_eq!(dry["source_byte_offset"], source);
    assert_eq!(dry["destination_byte_offset"], 0);
    assert_eq!(dry["changed"], false);
    assert_eq!(dry["original_destination_parseable"], false);
    assert_eq!(fs::read(&args.image.image).unwrap(), original);
    args.dry_run = false;
    let report = recover(&cx, &args).unwrap();
    assert_eq!(report["changed"], true);
    assert_eq!(report["requires_recovery"], true);
    assert_eq!(report["clean_state_published"], false);
    assert_eq!(report["verification"]["files"], 1);
    assert_eq!(report["verification"]["lost_clusters"], 0);
    assert!(args.image.open(&cx).is_err(), "boot repair must not implicitly grant clean mount admission");
    let after = fs::read(&args.image.image).unwrap();
    assert_only_boot_and_clean_bits(&original, &after, &args.image, &geometry);
    assert_eq!(&after[..geometry.sector_bytes() as usize],
        &after[source as usize..source as usize + geometry.sector_bytes() as usize]);
    args.repair_boot_from = None;
    assert!(recover(&cx, &args).unwrap()["verification"]["clean"].as_bool().unwrap());
    retained(&cx, &args.image.open(&cx).unwrap());
}

#[test]
fn primary_restores_backup_and_matching_boots_are_no_write_noops() {
    let (_directory, image, geometry) = populated("fat32");
    let cx = Cx::for_testing();
    let original = fs::read(&image.image).unwrap();
    let device = fault_device(&original, Some(1), 0);
    let plan = BootPlan::prepare(&cx, Box::new(device.clone()), &image, 0).unwrap();
    assert_eq!(plan.execute(&cx).unwrap()["changed"], false);
    assert_eq!(device.0.lock().unwrap().operations, 0);
    boot_damage(&image, backup(&geometry));
    let before = fs::read(&image.image).unwrap();
    let args = options(image, 0);
    let report = recover(&cx, &args).unwrap();
    assert_eq!(report["destination_byte_offset"], backup(&geometry));
    assert_eq!(report["requires_recovery"], true);
    let after = fs::read(&args.image.image).unwrap();
    assert_only_boot_and_clean_bits(&before, &after, &args.image, &geometry);
    let repeated = fault_device(&after, Some(1), 0);
    let plan = BootPlan::prepare(&cx, Box::new(repeated.clone()), &args.image, 0).unwrap();
    assert_eq!(plan.execute(&cx).unwrap()["changed"], false);
    assert_eq!(repeated.0.lock().unwrap().operations, 0);
}

#[test]
fn source_location_geometry_identity_and_native_damage_refuse_before_writes() {
    let (_directory, image, geometry) = populated("fat32");
    let original = fs::read(&image.image).unwrap();
    let source = backup(&geometry);
    let cx = Cx::for_testing();
    for damage in ["source", "location", "overflow", "self_pointer", "identity", "geometry", "other_format",
        "source_flags", "target_flags", "reserved", "error", "mirror", "live_chain", "fsinfo"]
    {
        let device = fault_device(&original, None, 0);
        let mut chosen = source;
        {
            let mut state = device.0.lock().unwrap();
            match damage {
                "source" => state.pending[source as usize + 510] = 0,
                "location" => chosen += 512,
                "overflow" => chosen = u64::MAX,
                "self_pointer" => state.pending[source as usize + 50..source as usize + 52]
                    .copy_from_slice(&9_u16.to_le_bytes()),
                "identity" => state.pending[67] ^= 1,
                "geometry" => state.pending[44..48].copy_from_slice(&3_u32.to_le_bytes()),
                "other_format" => state.pending[3..11].copy_from_slice(b"NTFS    "),
                "source_flags" => state.pending[source as usize + 65] |= 2,
                "target_flags" => state.pending[65] |= 2,
                "reserved" => state.pending[(geometry.entry_offset(1, 2).unwrap() - 8) as usize] = 0,
                "error" => state.pending[(geometry.entry_offset(1, 2).unwrap() - 1) as usize] &= !4,
                "mirror" => state.pending[geometry.entry_offset(1, 100).unwrap() as usize] = 3,
                "live_chain" => {
                    let volume = image.open(&cx).unwrap();
                    let entry = volume.resolve(&cx, "/KEEP.BIN").unwrap().unwrap();
                    for copy in 0..2 {
                        let at = geometry.entry_offset(copy, entry.native.first_cluster).unwrap() as usize;
                        state.pending[at..at + 4].fill(0);
                    }
                }
                _ => state.pending[geometry.fs_info_sector().unwrap() as usize * 512] = 0,
            }
        }
        let before = device.0.lock().unwrap().pending.clone();
        assert!(BootPlan::prepare(&cx, Box::new(device.clone()), &image, chosen).is_err(), "{damage}");
        assert_eq!(device.0.lock().unwrap().operations, 0, "{damage}");
        assert_eq!(device.0.lock().unwrap().pending, before, "{damage}");
    }
    let (_directory, fat16, _) = populated("fat16");
    let device = fault_device(&fs::read(&fat16.image).unwrap(), None, 0);
    assert!(BootPlan::prepare(&cx, Box::new(device.clone()), &fat16, 0).is_err());
    assert_eq!(device.0.lock().unwrap().operations, 0);
}

#[test]
fn stale_boot_fat_namespace_or_hint_evidence_cannot_begin_publication() {
    let (_directory, image, geometry) = populated("fat32");
    boot_damage(&image, 0);
    let original = fs::read(&image.image).unwrap();
    let cx = Cx::for_testing();
    for at in [0, backup(&geometry) + 100, geometry.entry_offset(0, 100).unwrap(),
        geometry.entry_offset(1, 100).unwrap(), geometry.entry_offset(0, 2).unwrap() - 1,
        geometry.cluster_offset(geometry.root_cluster()).unwrap() + 13,
        u64::from(geometry.fs_info_sector().unwrap()) * 512 + 488]
    {
        let device = fault_device(&original, None, 0);
        let plan = BootPlan::prepare(&cx, Box::new(device.clone()), &image, backup(&geometry)).unwrap();
        device.0.lock().unwrap().pending[at as usize] ^= 1;
        let changed = device.0.lock().unwrap().pending.clone();
        assert!(plan.execute(&cx).is_err(), "changed {at}");
        assert_eq!(device.0.lock().unwrap().operations, 0);
        assert_eq!(device.0.lock().unwrap().pending, changed);
    }
}

#[test]
fn active_fat_and_partition_boundaries_survive_and_lost_allocation_is_not_reclaimed() {
    let (directory, mut image, geometry) = populated("fat32");
    for offset in [0, backup(&geometry)] {
        patch(&image, offset + 40, &0x0081_u16.to_le_bytes());
    }
    fat(&image, &geometry, 0, 0, 0); // inactive copy is not an admission source
    fat(&image, &geometry, 1, 1, 0xAFFF_FFFF);
    fat(&image, &geometry, 1, 100, 0xBFFF_FFFF);
    patch(&image, geometry.cluster_offset(100).unwrap(), b"unclaimed bytes");
    boot_damage(&image, 0);
    let selected = fs::read(&image.image).unwrap();
    let mut disk = vec![0x6A; 8192];
    disk.extend_from_slice(&selected);
    disk.extend_from_slice(&[0xA6; 8192]);
    image.image = directory.path().join("partitioned.fat");
    image.offset = 8192;
    image.length = Some(selected.len() as u64);
    fs::write(&image.image, &disk).unwrap();
    let mut args = options(image, backup(&geometry));
    let cx = Cx::for_testing();
    let report = recover(&cx, &args).unwrap();
    assert_eq!(report["verification"]["lost_clusters"], 1);
    assert_eq!(report["requires_recovery"], true);
    let after = fs::read(&args.image.image).unwrap();
    let admitted = FatGeometry::parse(&after[8192..], selected.len() as u64).unwrap();
    assert!(!admitted.mirrored());
    assert_only_boot_and_clean_bits(&disk, &after, &args.image, &admitted);
    let at = args.image.offset as usize + geometry.entry_offset(1, 100).unwrap() as usize;
    assert_eq!(&after[at..at + 4], &0xBFFF_FFFF_u32.to_le_bytes());
    args.repair_boot_from = None;
    assert!(recover(&cx, &args).is_err(), "lost-cluster discard needs separate consent");
    assert_eq!(fs::read(&args.image.image).unwrap(), after);
}

#[test]
fn every_boot_write_sync_cut_keeps_allocation_and_never_publishes_clean_repair() {
    let (_directory, image, geometry) = populated("fat32");
    let cx = Cx::for_testing();
    for source in [0, backup(&geometry)] {
        let target = if source == 0 { backup(&geometry) } else { 0 };
        let mut original = fs::read(&image.image).unwrap();
        original[target as usize + 510..target as usize + 512].fill(0);
        let device = fault_device(&original, None, 0);
        let plan = BootPlan::prepare(&cx, Box::new(device.clone()), &image, source).unwrap();
        assert_eq!(plan.execute(&cx).unwrap()["changed"], true);
        let operations = device.0.lock().unwrap().operations;
        assert!(operations >= 7);
        drop(plan);
        drop(device);
        for cut in 1..=operations {
            for tear in [0, 7, 66, 511, 512] {
                let device = fault_device(&original, Some(cut), tear);
                let plan = BootPlan::prepare(&cx, Box::new(device.clone()), &image, source).unwrap();
                assert!(plan.execute(&cx).is_err(), "source={source} cut={cut} tear={tear}");
                assert_eq!(device.0.lock().unwrap().operations, cut, "no cleanup after failure");
                for retain in [false, true] {
                    let state = device.0.lock().unwrap();
                    let bytes = if retain { &state.pending } else { &state.durable };
                    assert_only_boot_and_clean_bits(&original, bytes, &image, &geometry);
                    let restarted = fault_device(bytes, None, 0);
                    assert!(FatVolume::from_device(&cx, Box::new(restarted.clone()), 0,
                        geometry.volume_bytes()).is_err(), "damaged or dirty image cannot be mounted");
                    assert_eq!(restarted.0.lock().unwrap().operations, 0);
                }
            }
        }
    }
}

struct StorageFault {
    device: FaultDevice,
    offset: u64,
    drop_write: bool,
    cancel: bool,
    pending_damage: AtomicBool,
}

impl ByteDevice for StorageFault {
    fn len_bytes(&self) -> u64 { self.device.len_bytes() }
    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        self.device.read_exact_at(cx, at, bytes)
    }
    fn write_all_at(&self, cx: &Cx, at: ByteOffset, bytes: &[u8]) -> ffs_error::Result<()> {
        if at.0 == self.offset && self.drop_write { return Ok(()); }
        self.device.write_all_at(cx, at, bytes)?;
        if at.0 == self.offset {
            if self.cancel { cx.set_cancel_requested(true); }
            else { self.pending_damage.store(true, Ordering::Release); }
        }
        Ok(())
    }
    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        if self.pending_damage.swap(false, Ordering::AcqRel) {
            self.device.0.lock().unwrap().pending[self.offset as usize + 200] ^= 0x80;
        }
        self.device.sync(cx)
    }
}

#[test]
fn lost_writes_post_readback_corruption_and_cancellation_are_errors_without_cleanup() {
    let (_directory, image, geometry) = populated("fat32");
    boot_damage(&image, 0);
    let original = fs::read(&image.image).unwrap();
    for offset in [0, backup(&geometry), geometry.entry_offset(0, 2).unwrap() - 8,
        geometry.entry_offset(1, 2).unwrap() - 8]
    {
        for fault in ["drop", "damage", "cancel"] {
            let cx = Cx::for_testing();
            let device = fault_device(&original, None, 0);
            let plan = BootPlan::prepare(&cx, Box::new(StorageFault {
                device: device.clone(), offset, drop_write: fault == "drop", cancel: fault == "cancel",
                pending_damage: AtomicBool::new(false),
            }), &image, backup(&geometry)).unwrap();
            assert!(plan.execute(&cx).is_err(), "{fault} at {offset}");
            let bytes = device.0.lock().unwrap().pending.clone();
            let restarted = fault_device(&bytes, None, 0);
            assert!(FatVolume::from_device(&Cx::for_testing(), Box::new(restarted), 0,
                geometry.volume_bytes()).is_err());
        }
    }
    let cx = Cx::for_testing();
    let device = fault_device(&original, None, 0);
    let plan = BootPlan::prepare(&cx, Box::new(device.clone()), &image, backup(&geometry)).unwrap();
    cx.set_cancel_requested(true);
    assert!(plan.execute(&cx).is_err());
    assert_eq!(device.0.lock().unwrap().operations, 0);
    assert!(BootPlan::prepare(&cx, Box::new(device.clone()), &image, backup(&geometry)).is_err());
}

#[test]
fn boot_cli_requires_explicit_source_and_offline_ownership_and_disallows_combined_authority() {
    let cli = crate::Cli::try_parse_from([
        "ffs-fat", "recover", "image", "--offline-image", "--repair-boot-from", "3072", "--dry-run",
    ]).unwrap();
    let crate::Command::Recover { options: parsed } = cli.command else { panic!("expected recover"); };
    assert_eq!(parsed.repair_boot_from, Some(3072));
    assert!(parsed.dry_run && parsed.offline_image);
    assert!(crate::Cli::try_parse_from([
        "ffs-fat", "recover", "image", "--repair-boot-from", "3072",
    ]).is_err());
    for extra in [vec!["--reclaim-lost"], vec!["--discard-orphan-lfn"],
        vec!["--repair-mirrors-from", "0"], vec!["--salvage-to", "output"]]
    {
        let mut args = vec!["ffs-fat", "recover", "image", "--offline-image", "--repair-boot-from", "0"];
        args.extend(extra);
        assert!(crate::Cli::try_parse_from(args).is_err());
    }
    let (_directory, image, _) = populated("fat32");
    let original = fs::read(&image.image).unwrap();
    let mut args = options(image, 0);
    args.reclaim_lost = true; // direct API callers cannot bypass clap conflicts
    assert!(recover(&Cx::for_testing(), &args).is_err());
    assert_eq!(fs::read(&args.image.image).unwrap(), original);
}
