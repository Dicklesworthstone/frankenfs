use super::*;
use super::super::tests::{fat, fixture, mark_dirty, patch};
use clap::Parser as _;
use std::sync::Mutex;

const NOW: u64 = 1_700_000_000;
const PAYLOAD: &[u8] = b"acknowledged reachable contents must survive structural recovery";

fn populated(kind: &str) -> (tempfile::TempDir, ImageArgs, super::super::FatGeometry) {
    let (directory, args, geometry) = fixture(kind);
    let cx = Cx::for_testing();
    let volume = super::super::super::replacement::open_volume(&cx, &args, true).unwrap();
    super::super::super::replacement::create_in_volume(
        &cx, &volume, "/KEEP.BIN", PAYLOAD, NOW, false,
    ).unwrap();
    drop(volume);
    (directory, args, geometry)
}

fn orphan(args: &ImageArgs, geometry: &super::super::FatGeometry) {
    mark_dirty(args, geometry);
    let end = if geometry.kind() == FatKind::Fat16 { 0xFFFF } else { 0x0FFF_FFFF };
    for copy in 0..geometry.fat_count() {
        fat(args, geometry, copy, 100, 101);
        fat(args, geometry, copy, 101, end);
        fat(args, geometry, copy, 102, 102); // unreachable cycle, not a live owner
    }
}

fn retained(cx: &Cx, volume: &FatVolume) {
    let entry = volume.resolve(cx, "/KEEP.BIN").unwrap().unwrap();
    let chain = volume.file_chain(cx, &entry).unwrap();
    assert_eq!(volume.read(cx, &chain, 0, 256).unwrap(), PAYLOAD);
}

#[test]
fn both_dialects_recover_lost_allocation_hints_and_dirty_state_without_touching_live_files() {
    for kind in ["fat16", "fat32"] {
        let (_directory, image, geometry) = populated(kind);
        orphan(&image, &geometry);
        let cx = Cx::for_testing();
        let before = fs::read(&image.image).unwrap();
        let mut args = RecoverArgs { image, offline_image: true, reclaim_lost: false, salvage_to: None, dry_run: false };
        assert!(recover(&cx, &args).is_err());
        assert_eq!(fs::read(&args.image.image).unwrap(), before);
        args.reclaim_lost = true;
        args.dry_run = true;
        let report = recover(&cx, &args).unwrap();
        assert_eq!(report["planned_reclaimed_clusters"], 3);
        assert_eq!(report["file_contents_verified"], false);
        assert_eq!(fs::read(&args.image.image).unwrap(), before);
        args.dry_run = false;
        let report = recover(&cx, &args).unwrap();
        assert_eq!(report["reclaimed_clusters"], 3);
        assert_eq!(report["verification"]["clean"], true);
        assert_eq!(report["verification"]["files"], 1);
        let volume = args.image.open(&cx).unwrap();
        retained(&cx, &volume);
        let mut table = FatTable::new(&volume);
        for cluster in 100..=102 { assert_eq!(table.entry(&cx, cluster).unwrap(), FatEntry::Free); }
        drop(volume);
        let finished = fs::read(&args.image.image).unwrap();
        assert_eq!(recover(&cx, &args).unwrap()["changed"], false);
        assert_eq!(fs::read(&args.image.image).unwrap(), finished);
    }
}

#[test]
fn nonmirrored_recovery_preserves_inactive_fat_and_each_reserved_high_nibble() {
    let (_directory, image, geometry) = populated("fat32");
    for sector in std::iter::once(0_u16).chain(geometry.backup_boot_sector()) {
        let base = u64::from(sector) * u64::from(geometry.sector_bytes());
        patch(&image, base + 40, &0x0081_u16.to_le_bytes());
        patch(&image, base + 65, &[1]);
    }
    fat(&image, &geometry, 0, 0, 0); // inactive copy is not recovery authority
    fat(&image, &geometry, 0, 1, 0);
    fat(&image, &geometry, 1, 1, 0xC7FF_FFFF);
    fat(&image, &geometry, 1, 100, 0xBFFF_FFFF);
    let before = fs::read(&image.image).unwrap();
    let first = (geometry.entry_offset(0, 2).unwrap() - 8) as usize;
    let second = (geometry.entry_offset(1, 2).unwrap() - 8) as usize;
    let args = RecoverArgs { image, offline_image: true, reclaim_lost: true, salvage_to: None, dry_run: false };
    let report = recover(&Cx::for_testing(), &args).unwrap();
    assert_eq!(report["verification"]["clean"], true);
    let after = fs::read(&args.image.image).unwrap();
    assert_eq!(&after[first..second], &before[first..second]);
    assert_eq!(&after[second + 4..second + 8], &0xCFFF_FFFF_u32.to_le_bytes());
    let at = geometry.entry_offset(1, 100).unwrap() as usize;
    assert_eq!(&after[at..at + 4], &0xB000_0000_u32.to_le_bytes());
}

#[test]
fn recovery_refuses_ambiguous_or_unknown_damage_before_any_writes() {
    for damage in ["mirror", "hard_error", "reserved", "surface", "fsinfo", "crosslink"] {
        let (_directory, image, geometry) = populated("fat32");
        match damage {
            "mirror" => fat(&image, &geometry, 0, 100, 0x0FFF_FFFF),
            "hard_error" => fat(&image, &geometry, 0, 1, 0x0BFF_FFFF),
            "reserved" => fat(&image, &geometry, 0, 0, 0),
            "surface" => patch(&image, 65, &[2]),
            "fsinfo" => patch(&image, u64::from(geometry.fs_info_sector().unwrap()) * 512, &[0; 4]),
            _ => {
                let cx = Cx::for_testing();
                let volume = super::super::super::replacement::open_volume(&cx, &image, true).unwrap();
                super::super::super::replacement::create_in_volume(
                    &cx, &volume, "/ALIAS.BIN", PAYLOAD, NOW, false,
                ).unwrap();
                let first = volume.resolve(&cx, "/KEEP.BIN").unwrap().unwrap();
                let other = volume.resolve(&cx, "/ALIAS.BIN").unwrap().unwrap();
                drop(volume);
                patch(&image, other.offset + 26, &(first.native.first_cluster as u16).to_le_bytes());
                patch(&image, other.offset + 20, &((first.native.first_cluster >> 16) as u16).to_le_bytes());
            }
        }
        let before = fs::read(&image.image).unwrap();
        let args = RecoverArgs { image, offline_image: true, reclaim_lost: true, salvage_to: None, dry_run: false };
        assert!(recover(&Cx::for_testing(), &args).is_err(), "{damage}");
        assert_eq!(fs::read(&args.image.image).unwrap(), before, "{damage}");
    }
}

#[test]
fn selected_volume_recovery_never_modifies_neighboring_regions() {
    let (directory, mut image, geometry) = populated("fat16");
    orphan(&image, &geometry);
    let volume_bytes = fs::read(&image.image).unwrap();
    let mut disk = vec![0xA5; 8192];
    disk.extend_from_slice(&volume_bytes);
    disk.extend_from_slice(&[0x5A; 8192]);
    image.image = directory.path().join("partitioned.img");
    image.offset = 8192;
    image.length = Some(volume_bytes.len() as u64);
    fs::write(&image.image, &disk).unwrap();
    let args = RecoverArgs { image, offline_image: true, reclaim_lost: true, salvage_to: None, dry_run: false };
    assert_eq!(recover(&Cx::for_testing(), &args).unwrap()["reclaimed_clusters"], 3);
    let after = fs::read(&args.image.image).unwrap();
    assert_eq!(&after[..8192], &disk[..8192]);
    assert_eq!(&after[8192 + volume_bytes.len()..], &disk[8192 + volume_bytes.len()..]);
    retained(&Cx::for_testing(), &args.image.open(&Cx::for_testing()).unwrap());
}

struct FaultState {
    pending: Vec<u8>,
    durable: Vec<u8>,
    operations: usize,
    fail: Option<usize>,
    tear: usize,
}

#[derive(Clone)]
struct FaultDevice(Arc<Mutex<FaultState>>);

impl ByteDevice for FaultDevice {
    fn len_bytes(&self) -> u64 { self.0.lock().unwrap().pending.len() as u64 }
    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        let state = self.0.lock().unwrap();
        let at = offset.0 as usize;
        bytes.copy_from_slice(&state.pending[at..at + bytes.len()]);
        Ok(())
    }
    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, bytes: &[u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        let mut state = self.0.lock().unwrap();
        state.operations += 1;
        let fail = state.fail == Some(state.operations);
        let count = if fail { state.tear.min(bytes.len()) } else { bytes.len() };
        let at = offset.0 as usize;
        state.pending[at..at + count].copy_from_slice(&bytes[..count]);
        if fail { return Err(std::io::Error::other("injected recovery write failure").into()); }
        Ok(())
    }
    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        let mut state = self.0.lock().unwrap();
        state.operations += 1;
        if state.fail == Some(state.operations) {
            return Err(std::io::Error::other("injected recovery sync failure").into());
        }
        state.durable = state.pending.clone();
        Ok(())
    }
}

fn fault_device(bytes: &[u8], fail: Option<usize>, tear: usize) -> FaultDevice {
    FaultDevice(Arc::new(Mutex::new(FaultState {
        pending: bytes.to_vec(), durable: bytes.to_vec(), operations: 0, fail, tear,
    })))
}

#[test]
fn every_recovery_write_sync_cut_preserves_reachable_payload_and_never_reports_success() {
    let (_directory, image, geometry) = populated("fat16");
    orphan(&image, &geometry);
    let initial = fs::read(&image.image).unwrap();
    let cx = Cx::for_testing();
    let device = fault_device(&initial, None, 0);
    let diagnostic = DiagnosticVolume::from_device(&cx, Box::new(device.clone()), &image).unwrap();
    let plan = Plan::prepare(&cx, &diagnostic, true).unwrap();
    assert_eq!(plan.execute(&cx, &diagnostic).unwrap()["verification"]["clean"], true);
    let operations = device.0.lock().unwrap().operations;
    assert!(operations > 2);
    for cut in 1..=operations {
        for tear in [0, 17, 511] {
            let device = fault_device(&initial, Some(cut), tear);
            let diagnostic = DiagnosticVolume::from_device(&cx, Box::new(device.clone()), &image).unwrap();
            let plan = Plan::prepare(&cx, &diagnostic, true).unwrap();
            assert!(plan.execute(&cx, &diagnostic).is_err(), "cut {cut}, tear {tear}");
            assert_eq!(device.0.lock().unwrap().operations, cut, "no cleanup writes after failure");
            for retain_pending in [false, true] {
                let bytes = {
                    let state = device.0.lock().unwrap();
                    if retain_pending { state.pending.clone() } else { state.durable.clone() }
                };
                let crashed = fault_device(&bytes, None, 0);
                let reopened = DiagnosticVolume::from_device(&cx, Box::new(crashed.clone()), &image).unwrap();
                retained(&cx, &reopened.volume);
                let report = reopened.report(&cx).unwrap();
                if report.clean { assert_eq!(report.lost_clusters, Some(0)); }
                assert_eq!(crashed.0.lock().unwrap().operations, 0);
            }
        }
    }
}

#[test]
fn recovery_cli_requires_offline_authority_and_rejects_force_bypasses() {
    assert!(crate::Cli::try_parse_from(["ffs-fat", "recover", "image"]).is_err());
    assert!(crate::Cli::try_parse_from(["ffs-fat", "recover", "image", "--offline-image", "--force"]).is_err());
    let cli = crate::Cli::try_parse_from([
        "ffs-fat", "recover", "image", "--offline-image", "--reclaim-lost", "--dry-run",
        "--offset", "4096", "--length", "4194304",
    ]).unwrap();
    let crate::Command::Recover { options } = cli.command else { panic!("expected recover"); };
    assert!(options.dry_run && options.reclaim_lost && options.offline_image);
    assert_eq!(options.image.offset, 4096);
    assert_eq!(options.image.length, Some(4_194_304));
}

#[test]
fn cancelled_recovery_and_noop_clean_recovery_do_not_mutate() {
    let (_directory, image, _geometry) = populated("fat16");
    let before = fs::read(&image.image).unwrap();
    let args = RecoverArgs { image, offline_image: true, reclaim_lost: false, salvage_to: None, dry_run: false };
    let cx = Cx::for_testing();
    cx.set_cancel_requested(true);
    assert!(recover(&cx, &args).is_err());
    assert_eq!(fs::read(&args.image.image).unwrap(), before);
    let cx = Cx::for_testing();
    let device = fault_device(&before, Some(1), 0);
    let diagnostic = DiagnosticVolume::from_device(&cx, Box::new(device.clone()), &args.image).unwrap();
    let plan = Plan::prepare(&cx, &diagnostic, false).unwrap();
    assert_eq!(plan.execute(&cx, &diagnostic).unwrap()["changed"], false);
    assert_eq!(device.0.lock().unwrap().operations, 0);
    assert_eq!(fs::read(&args.image.image).unwrap(), before);
}

struct CancelOnWrite(FaultDevice);

impl ByteDevice for CancelOnWrite {
    fn len_bytes(&self) -> u64 { self.0.len_bytes() }
    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        self.0.read_exact_at(cx, offset, bytes)
    }
    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, bytes: &[u8]) -> ffs_error::Result<()> {
        self.0.write_all_at(cx, offset, bytes)?;
        cx.set_cancel_requested(true);
        Ok(())
    }
    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> { self.0.sync(cx) }
}

#[test]
fn cancellation_after_publication_stops_recovery_without_cleaning_up() {
    let (_directory, image, geometry) = populated("fat16");
    orphan(&image, &geometry);
    let initial = fs::read(&image.image).unwrap();
    let device = fault_device(&initial, None, 0);
    let cx = Cx::for_testing();
    let diagnostic = DiagnosticVolume::from_device(&cx, Box::new(CancelOnWrite(device.clone())), &image).unwrap();
    let plan = Plan::prepare(&cx, &diagnostic, true).unwrap();
    assert!(plan.execute(&cx, &diagnostic).is_err());
    // Already-dirty FAT16 needs one barrier before its first reclamation write.
    assert_eq!(device.0.lock().unwrap().operations, 2);
    let bytes = device.0.lock().unwrap().pending.clone();
    let fresh = Cx::for_testing();
    let reopened = DiagnosticVolume::from_device(&fresh, Box::new(fault_device(&bytes, None, 0)), &image).unwrap();
    retained(&fresh, &reopened.volume);
    assert!(!reopened.report(&fresh).unwrap().clean);
}
