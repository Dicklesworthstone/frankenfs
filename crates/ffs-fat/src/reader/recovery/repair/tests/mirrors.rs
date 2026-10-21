//! Actual formatter/checker/repair paths with explicit mirror authority.
//! Fault devices are deterministic models, not native hardware qualification.

use super::super::mirrors::MirrorPlan;
use super::*;
use ffs_ondisk::fat::FatGeometry;
use std::sync::atomic::{AtomicBool, Ordering};

fn options(image: ImageArgs, copy: u8) -> RecoverArgs {
    RecoverArgs {
        image,
        offline_image: true,
        reclaim_lost: false,
        discard_orphan_lfn: false,
        repair_mirrors_from: Some(copy),
        repair_boot_from: None,
        salvage_to: None,
        dry_run: false,
    }
}

fn end(geometry: &FatGeometry) -> u32 {
    if geometry.kind() == FatKind::Fat16 {
        0xFFFF
    } else {
        0x0FFF_FFFF
    }
}

fn diagnostic(image: &ImageArgs, device: &FaultDevice) -> DiagnosticVolume {
    DiagnosticVolume::from_device(&Cx::for_testing(), Box::new(device.clone()), image).unwrap()
}

#[test]
fn both_dialects_and_either_selected_copy_restore_mirrors_without_payload_changes() {
    for kind in ["fat16", "fat32"] {
        for copy in 0..2 {
            let (_directory, image, geometry) = populated(kind);
            // Make the rejected copy claim an otherwise unused cluster. The
            // operator-selected copy remains the original consistent table.
            fat(&image, &geometry, 1 - copy, 100, end(&geometry));
            let original = fs::read(&image.image).unwrap();
            let mut args = options(image, copy);
            args.dry_run = true;
            let dry = recover(&Cx::for_testing(), &args).unwrap();
            assert_eq!(dry["authoritative_copy"], copy);
            assert_eq!(dry["different_entries"], 1);
            assert_eq!(dry["changed"], false);
            assert_eq!(dry["file_contents_verified"], false);
            assert_eq!(fs::read(&args.image.image).unwrap(), original);
            args.dry_run = false;
            let report = recover(&Cx::for_testing(), &args).unwrap();
            assert_eq!(report["changed"], true);
            assert_eq!(report["native_recovery_required"], false);
            assert_eq!(report["verification"]["clean"], true);
            assert_eq!(report["verification"]["files"], 1);
            let cx = Cx::for_testing();
            retained(&cx, &args.image.open(&cx).unwrap());
            let finished = fs::read(&args.image.image).unwrap();
            assert_eq!(recover(&cx, &args).unwrap()["changed"], false);
            assert_eq!(fs::read(&args.image.image).unwrap(), finished);
        }
    }
}

#[test]
fn fat32_high_nibbles_padding_and_neighboring_volumes_are_not_copied() {
    let (directory, mut image, geometry) = populated("fat32");
    fat(&image, &geometry, 0, 100, 0xA000_0000);
    fat(&image, &geometry, 1, 100, 0xBFFF_FFFF);
    let source_start = geometry.entry_offset(0, 2).unwrap() as usize;
    let used = geometry
        .entry_offset(1, geometry.cluster_count() + 1)
        .unwrap()
        + 4;
    let aligned = used.div_ceil(512) * 512;
    if used < aligned {
        patch(&image, used, &vec![0xD9; (aligned - used) as usize]);
    }
    let bytes = fs::read(&image.image).unwrap();
    let mut disk = vec![0xA6; 4096];
    disk.extend_from_slice(&bytes);
    disk.extend_from_slice(&[0x6A; 4096]);
    image.image = directory.path().join("selected-volume.img");
    image.offset = 4096;
    image.length = Some(bytes.len() as u64);
    fs::write(&image.image, &disk).unwrap();
    let args = options(image, 0);
    assert_eq!(
        recover(&Cx::for_testing(), &args).unwrap()["verification"]["clean"],
        true
    );
    let after = fs::read(&args.image.image).unwrap();
    assert_eq!(&after[..4096], &disk[..4096]);
    assert_eq!(&after[4096 + bytes.len()..], &disk[4096 + bytes.len()..]);
    let source_len = geometry.cluster_count() as usize * 4;
    assert_eq!(
        &after[4096 + source_start..4096 + source_start + source_len],
        &disk[4096 + source_start..4096 + source_start + source_len]
    );
    let target = 4096 + geometry.entry_offset(1, 100).unwrap() as usize;
    assert_eq!(&after[target..target + 4], &0xB000_0000_u32.to_le_bytes());
    assert_eq!(
        &after[4096 + used as usize..4096 + aligned as usize],
        &disk[4096 + used as usize..4096 + aligned as usize]
    );
    retained(
        &Cx::for_testing(),
        &args.image.open(&Cx::for_testing()).unwrap(),
    );
}

#[test]
fn selected_lost_allocation_is_not_reclaimed_or_marked_clean_implicitly() {
    let (_directory, image, geometry) = populated("fat32");
    fat(&image, &geometry, 1, 100, end(&geometry));
    patch(
        &image,
        geometry.cluster_offset(100).unwrap(),
        b"unclaimed evidence",
    );
    let mut args = options(image, 1);
    let cx = Cx::for_testing();
    let report = recover(&cx, &args).unwrap();
    assert_eq!(report["native_recovery_required"], true);
    assert_eq!(report["verification"]["lost_clusters"], 1);
    assert_eq!(report["verification"]["clean"], false);
    assert!(
        args.image.open(&cx).is_err(),
        "lost allocation must keep normal admission dirty"
    );
    let bytes = fs::read(&args.image.image).unwrap();
    for number in std::iter::once(0).chain(geometry.backup_boot_sector()) {
        assert_eq!(bytes[number as usize * 512 + 65] & 1, 1);
    }
    for copy in 0..2 {
        let at = geometry.entry_offset(copy, 2).unwrap() as usize - 4;
        assert_eq!(bytes[at + 3] & 0x08, 0);
        let at = geometry.entry_offset(copy, 100).unwrap() as usize;
        assert_eq!(
            u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) & 0x0FFF_FFFF,
            0x0FFF_FFFF
        );
    }
    // A separate, explicit allocation-discard action can finish recovery.
    args.repair_mirrors_from = None;
    args.reclaim_lost = true;
    assert_eq!(recover(&cx, &args).unwrap()["reclaimed_clusters"], 1);
    retained(&cx, &args.image.open(&cx).unwrap());
    let after = fs::read(&args.image.image).unwrap();
    let at = geometry.cluster_offset(100).unwrap() as usize;
    assert_eq!(&after[at..at + 18], b"unclaimed evidence");
}

#[test]
fn selected_corruption_error_state_and_bad_cluster_downgrades_refuse_before_writes() {
    for damage in [
        "live_chain",
        "reserved",
        "hard_error",
        "surface",
        "bad_cluster",
        "inactive",
        "index",
    ] {
        let (_directory, image, geometry) = populated("fat32");
        let cx = Cx::for_testing();
        let volume = image.open(&cx).unwrap();
        let first = volume
            .resolve(&cx, "/KEEP.BIN")
            .unwrap()
            .unwrap()
            .native
            .first_cluster;
        drop(volume);
        let mut copy = 0;
        match damage {
            "live_chain" => fat(&image, &geometry, 0, first, 0),
            "reserved" => fat(&image, &geometry, 1, 0, 0),
            "hard_error" => fat(&image, &geometry, 1, 1, 0x0BFF_FFFF),
            "surface" => patch(&image, 65, &[2]),
            "bad_cluster" => fat(&image, &geometry, 1, 100, 0x0FFF_FFF7),
            "inactive" => {
                for sector in std::iter::once(0).chain(geometry.backup_boot_sector()) {
                    patch(
                        &image,
                        u64::from(sector) * 512 + 40,
                        &0x0081_u16.to_le_bytes(),
                    );
                }
            }
            _ => copy = 2,
        }
        let before = fs::read(&image.image).unwrap();
        let device = fault_device(&before, None, 0);
        assert!(
            MirrorPlan::prepare(&cx, diagnostic(&image, &device), copy, &image).is_err(),
            "{damage}"
        );
        assert_eq!(device.0.lock().unwrap().operations, 0, "{damage}");
        assert_eq!(device.0.lock().unwrap().pending, before, "{damage}");
    }
}

#[test]
fn stale_source_target_namespace_or_boot_evidence_cannot_start_publication() {
    for change in ["source", "target", "namespace", "boot"] {
        let (_directory, image, geometry) = populated("fat16");
        fat(&image, &geometry, 1, 100, end(&geometry));
        let before = fs::read(&image.image).unwrap();
        let device = fault_device(&before, None, 0);
        let cx = Cx::for_testing();
        let plan = MirrorPlan::prepare(&cx, diagnostic(&image, &device), 0, &image).unwrap();
        let at = match change {
            "source" => geometry.entry_offset(0, 101).unwrap() as usize,
            "target" => geometry.entry_offset(1, 101).unwrap() as usize,
            "namespace" => geometry.fixed_root().unwrap().0 as usize + 13,
            _ => 39, // native volume serial, not geometry alone
        };
        device.0.lock().unwrap().pending[at] ^= 1;
        let changed = device.0.lock().unwrap().pending.clone();
        assert!(plan.execute(&cx).is_err(), "{change}");
        assert_eq!(device.0.lock().unwrap().operations, 0, "{change}");
        assert_eq!(device.0.lock().unwrap().pending, changed, "{change}");
    }
}

#[test]
fn each_mirror_write_and_sync_failure_preserves_selected_allocation_and_live_payload() {
    let (_directory, image, geometry) = populated("fat32");
    for cluster in [100, 500] {
        fat(&image, &geometry, 1, cluster, end(&geometry));
    }
    let initial = fs::read(&image.image).unwrap();
    let cx = Cx::for_testing();
    let operations = {
        let device = fault_device(&initial, None, 0);
        let plan = MirrorPlan::prepare(&cx, diagnostic(&image, &device), 0, &image).unwrap();
        assert_eq!(plan.execute(&cx).unwrap()["verification"]["clean"], true);
        device.0.lock().unwrap().operations
    };
    assert!(operations >= 10);
    let first = geometry.entry_offset(0, 2).unwrap() as usize;
    let last = first + geometry.cluster_count() as usize * 4;
    for cut in 1..=operations {
        for tear in [0, 7, 511, 512] {
            let device = fault_device(&initial, Some(cut), tear);
            let plan = MirrorPlan::prepare(&cx, diagnostic(&image, &device), 0, &image).unwrap();
            assert!(plan.execute(&cx).is_err(), "cut {cut} tear {tear}");
            assert_eq!(
                device.0.lock().unwrap().operations,
                cut,
                "no cleanup writes"
            );
            for pending in [false, true] {
                let bytes = {
                    let state = device.0.lock().unwrap();
                    if pending {
                        state.pending.clone()
                    } else {
                        state.durable.clone()
                    }
                };
                assert_eq!(
                    &bytes[first..last],
                    &initial[first..last],
                    "selected FAT data never changes"
                );
                let restarted = fault_device(&bytes, None, 0);
                let diagnostic = diagnostic(&image, &restarted);
                retained(&cx, &diagnostic.volume);
                let after = diagnostic.report(&cx).unwrap();
                if after.clean {
                    assert_eq!(after.conflicting_clusters, 0);
                }
                assert_eq!(restarted.0.lock().unwrap().operations, 0);
            }
        }
    }
}

struct LostWrite {
    inner: FaultDevice,
    at: u64,
    drop: bool,
    pending_damage: AtomicBool,
}

impl ByteDevice for LostWrite {
    fn len_bytes(&self) -> u64 {
        self.inner.len_bytes()
    }
    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        self.inner.read_exact_at(cx, at, bytes)
    }
    fn write_all_at(&self, cx: &Cx, at: ByteOffset, bytes: &[u8]) -> ffs_error::Result<()> {
        if at.0 == self.at {
            if self.drop {
                return Ok(());
            }
            self.pending_damage.store(true, Ordering::Release);
        }
        self.inner.write_all_at(cx, at, bytes)
    }
    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        if self.pending_damage.swap(false, Ordering::AcqRel) {
            self.inner.0.lock().unwrap().pending[self.at as usize + 300] ^= 0x80;
        }
        self.inner.sync(cx)
    }
}

#[test]
fn dropped_sector_and_damage_after_immediate_readback_are_not_reported_as_repaired() {
    for drop in [false, true] {
        let (_directory, image, geometry) = populated("fat16");
        fat(&image, &geometry, 1, 500, end(&geometry));
        let before = fs::read(&image.image).unwrap();
        let device = fault_device(&before, None, 0);
        let at = geometry.entry_offset(1, 500).unwrap() / 512 * 512;
        let cx = Cx::for_testing();
        let view = DiagnosticVolume::from_device(
            &cx,
            Box::new(LostWrite {
                inner: device.clone(),
                at,
                drop,
                pending_damage: AtomicBool::new(false),
            }),
            &image,
        )
        .unwrap();
        let plan = MirrorPlan::prepare(&cx, view, 0, &image).unwrap();
        assert!(plan.execute(&cx).is_err());
        let reopened = diagnostic(&image, &device);
        retained(&cx, &reopened.volume);
        assert!(!reopened.report(&cx).unwrap().clean);
    }
}

#[test]
fn mirror_cli_authority_conflicts_cancellation_and_matching_tables_make_no_writes() {
    let (directory, image, _geometry) = populated("fat16");
    let before = fs::read(&image.image).unwrap();
    let device = fault_device(&before, Some(1), 0);
    let cx = Cx::for_testing();
    let plan = MirrorPlan::prepare(&cx, diagnostic(&image, &device), 0, &image).unwrap();
    assert_eq!(plan.execute(&cx).unwrap()["changed"], false);
    assert_eq!(device.0.lock().unwrap().operations, 0);
    cx.set_cancel_requested(true);
    assert!(MirrorPlan::prepare(&cx, diagnostic(&image, &device), 0, &image).is_err());
    assert_eq!(device.0.lock().unwrap().operations, 0);
    let mut args = options(image, 0);
    args.salvage_to = Some(directory.path().join("not-created"));
    assert!(recover(&Cx::for_testing(), &args).is_err());
    assert!(!args.salvage_to.as_ref().unwrap().exists());
    assert_eq!(fs::read(&args.image.image).unwrap(), before);
    for conflicting in ["--reclaim-lost", "--discard-orphan-lfn"] {
        assert!(
            crate::Cli::try_parse_from([
                "ffs-fat",
                "recover",
                "image",
                "--offline-image",
                "--repair-mirrors-from",
                "0",
                conflicting,
            ])
            .is_err()
        );
    }
    assert!(
        crate::Cli::try_parse_from(["ffs-fat", "recover", "image", "--repair-mirrors-from", "1",])
            .is_err()
    );
    let cli = crate::Cli::try_parse_from([
        "ffs-fat",
        "recover",
        "image",
        "--offline-image",
        "--repair-mirrors-from",
        "1",
        "--dry-run",
    ])
    .unwrap();
    let crate::Command::Recover { options } = cli.command else {
        panic!("expected recovery");
    };
    assert_eq!(options.repair_mirrors_from, Some(1));
    assert!(options.dry_run && !options.reclaim_lost && !options.discard_orphan_lfn);
}

#[test]
fn chosen_bad_cluster_evidence_propagates_without_reusing_its_storage() {
    let (_directory, image, geometry) = populated("fat16");
    fat(&image, &geometry, 0, 100, 0xFFF7);
    let cx = Cx::for_testing();
    let args = options(image, 0);
    let report = recover(&cx, &args).unwrap();
    assert_eq!(report["verification"]["clean"], true);
    assert_eq!(report["verification"]["bad_clusters"], 1);
    let volume = args.image.open(&cx).unwrap();
    assert_eq!(
        FatTable::new(&volume).entry(&cx, 100).unwrap(),
        FatEntry::Bad
    );
    retained(&cx, &volume);
}

struct ChangeSelectedAfterSnapshot {
    inner: FaultDevice,
    source: u64,
    length: usize,
    changed_entry: usize,
    armed: AtomicBool,
}

impl ByteDevice for ChangeSelectedAfterSnapshot {
    fn len_bytes(&self) -> u64 {
        self.inner.len_bytes()
    }
    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        self.inner.read_exact_at(cx, at, bytes)?;
        if at.0 == self.source
            && bytes.len() == self.length
            && self.armed.swap(false, Ordering::AcqRel)
        {
            let mut state = self.inner.0.lock().unwrap();
            state.pending[self.changed_entry..self.changed_entry + 2].fill(0xFF);
        }
        Ok(())
    }
    fn write_all_at(&self, cx: &Cx, at: ByteOffset, bytes: &[u8]) -> ffs_error::Result<()> {
        self.inner.write_all_at(cx, at, bytes)
    }
    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        self.inner.sync(cx)
    }
}

#[test]
fn chosen_source_change_during_overlay_preflight_is_not_copied_back_as_authority() {
    let (_directory, image, geometry) = populated("fat16");
    fat(&image, &geometry, 1, 500, end(&geometry));
    let before = fs::read(&image.image).unwrap();
    let device = fault_device(&before, None, 0);
    let cx = Cx::for_testing();
    let view = DiagnosticVolume::from_device(
        &cx,
        Box::new(ChangeSelectedAfterSnapshot {
            inner: device.clone(),
            source: geometry.entry_offset(0, 2).unwrap(),
            length: geometry.cluster_count() as usize * 2,
            changed_entry: geometry.entry_offset(0, 100).unwrap() as usize,
            armed: AtomicBool::new(true),
        }),
        &image,
    )
    .unwrap();
    assert!(MirrorPlan::prepare(&cx, view, 0, &image).is_err());
    assert_eq!(device.0.lock().unwrap().operations, 0);
}
