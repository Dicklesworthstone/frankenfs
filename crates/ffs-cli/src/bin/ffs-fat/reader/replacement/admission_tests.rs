//! Reject damaged retained-volume state before backing writes or synchronization.
//! The device records attempts, including syncs, not only successful writes.

use super::*;
use clap::Parser as _;
use ffs_ondisk::fat::{FatGeometry, FatOemCodePage};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

const NOW: u64 = 1_700_000_000;
const BASE: u64 = 4096;

#[derive(Clone)]
struct Device {
    bytes: Arc<Mutex<Vec<u8>>>,
    attempts: Arc<AtomicUsize>,
    fail_read: Arc<Mutex<Option<u64>>>,
}

impl Device {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Arc::new(Mutex::new(bytes)),
            attempts: Arc::new(AtomicUsize::new(0)),
            fail_read: Arc::new(Mutex::new(None)),
        }
    }

    fn open(&self, cx: &Cx) -> FatVolume {
        FatVolume::from_device(cx, Box::new(self.clone()), BASE, self.len_bytes() - 2 * BASE)
            .unwrap()
    }

    fn patch(&self, at: u64, bytes: &[u8]) {
        let at = usize::try_from(BASE + at).unwrap();
        self.bytes.lock().unwrap()[at..at + bytes.len()].copy_from_slice(bytes);
    }

    fn snapshot(&self) -> Vec<u8> {
        self.bytes.lock().unwrap().clone()
    }

    fn assert_unchanged(&self, expected: &[u8]) {
        assert_eq!(self.attempts.load(Ordering::SeqCst), 0, "unexpected write or sync attempt");
        assert_eq!(self.bytes.lock().unwrap().as_slice(), expected);
    }
}

impl ByteDevice for Device {
    fn len_bytes(&self) -> u64 {
        self.bytes.lock().unwrap().len() as u64
    }

    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, out: &mut [u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        if self.fail_read.lock().unwrap().is_some_and(|fault| {
            at.0 <= fault && fault < at.0.saturating_add(out.len() as u64)
        }) {
            return Err(std::io::Error::other("injected admission read failure").into());
        }
        let bytes = self.bytes.lock().unwrap();
        let start = usize::try_from(at.0).map_err(|_| corrupt(at.0, "test offset overflow"))?;
        let end = start.checked_add(out.len()).ok_or_else(|| corrupt(at.0, "test range overflow"))?;
        let source = bytes.get(start..end).ok_or_else(|| corrupt(at.0, "test read out of range"))?;
        out.copy_from_slice(source);
        checkpoint(cx)
    }

    fn write_all_at(&self, cx: &Cx, at: ByteOffset, input: &[u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        self.attempts.fetch_add(1, Ordering::SeqCst);
        let mut bytes = self.bytes.lock().unwrap();
        let start = usize::try_from(at.0).unwrap();
        assert!(at.0 >= BASE && at.0 + input.len() as u64 <= bytes.len() as u64 - BASE);
        bytes[start..start + input.len()].copy_from_slice(input);
        Ok(())
    }

    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        self.attempts.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn fixture(kind: &str) -> (tempfile::TempDir, Device, FatVolume) {
    let directory = tempfile::tempdir().unwrap();
    let image = directory.path().join("admission.fat");
    let cli = crate::Cli::try_parse_from([
        "ffs-fat", "format", image.to_str().unwrap(), "--kind", kind,
        "--size-mib", if kind == "fat16" { "4" } else { "64" },
    ]).unwrap();
    let crate::Command::Format { options } = cli.command else { panic!("expected formatter"); };
    let cx = Cx::for_testing();
    crate::formatter::create(&cx, &options).unwrap();
    let args = ImageArgs { image, offset: 0, length: None,
        oem_code_page: FatOemCodePage::Ascii, sidecar: None };
    let volume = open_volume(&cx, &args, true).unwrap();
    create_in_volume(&cx, &volume, "/SOURCE.BIN", b"source contents", NOW, false).unwrap();
    create_in_volume(&cx, &volume, "/TARGET.BIN", b"target contents", NOW, false).unwrap();
    mkdir_in_volume(&cx, &volume, "/EMPTY", NOW, false).unwrap();
    drop(volume);
    let mut bytes = vec![0xA5; BASE as usize];
    bytes.extend_from_slice(&std::fs::read(&args.image).unwrap());
    bytes.extend_from_slice(&vec![0x5A; BASE as usize]);
    let device = Device::new(bytes);
    let volume = device.open(&cx);
    (directory, device, volume)
}

fn reserved(geometry: &FatGeometry, copy: u8, index: u64) -> u64 {
    geometry.entry_offset(copy, 2).unwrap()
        - (2 - index) * u64::from(geometry.kind().entry_bytes())
}

fn inject(device: &Device, geometry: &FatGeometry, damage: &str) {
    let width = geometry.kind().entry_bytes() as usize;
    let (state_at, mask, clean, io_ok) = match geometry.kind() {
        FatKind::Fat16 => (37, 0xFFFF_u32, 0x8000, 0x4000),
        FatKind::Fat32 => (65, 0x0FFF_FFFF, 0x0800_0000, 0x0400_0000),
    };
    let last = geometry.fat_count() - 1;
    match damage {
        "media" => {
            let current = device.bytes.lock().unwrap()[BASE as usize + 21];
            let different = if current == 0xF0 { 0xF8 } else { 0xF0 };
            device.patch(21, &[different]);
        }
        "fat0" => device.patch(reserved(geometry, last, 0), &[0; 4][..width]),
        "dirty" => device.patch(reserved(geometry, last, 1), &(mask & !clean).to_le_bytes()[..width]),
        "io_error" => device.patch(reserved(geometry, last, 1), &(mask & !io_ok).to_le_bytes()[..width]),
        "unknown_boot" => device.patch(state_at, &[0x40]),
        "geometry" => {
            let bytes = device.snapshot();
            let at = BASE as usize + 14;
            let sectors = u16::from_le_bytes([bytes[at], bytes[at + 1]]);
            device.patch(14, &(sectors + 1).to_le_bytes());
        }
        "backup" => device.patch(
            u64::from(geometry.backup_boot_sector().unwrap()) * u64::from(geometry.sector_bytes()) + state_at,
            &[1],
        ),
        "fsinfo" => device.patch(
            u64::from(geometry.fs_info_sector().unwrap()) * u64::from(geometry.sector_bytes()), &[0; 4],
        ),
        _ => panic!("unknown damage"),
    }
}

fn mutate(cx: &Cx, volume: &FatVolume, action: usize) -> Result<()> {
    match action {
        0 => { create_in_volume(cx, volume, "/NEW.BIN", b"new", NOW, false)?; }
        1 => { replace_in_volume(cx, volume, "/SOURCE.BIN", b"replacement", NOW)?; }
        2 => { mkdir_in_volume(cx, volume, "/NEWDIR", NOW, false)?; }
        3 => { unlink_in_volume(cx, volume, "/SOURCE.BIN", false)?; }
        4 => { rmdir_in_volume(cx, volume, "/EMPTY", false)?; }
        5 => { rename_in_volume(cx, volume, "/SOURCE.BIN", "/TARGET.BIN", false)?; }
        6 => { set_attr_in_volume(cx, volume, "/SOURCE.BIN", Some(true), None, None)?; }
        7 => { write_range_in_volume(cx, volume, "/SOURCE.BIN", 0, b"changed", NOW)?; }
        8 => { truncate_in_volume(cx, volume, "/SOURCE.BIN", 1, NOW)?; }
        9 => { volume.preallocate(cx, "/SOURCE.BIN", 0, 4096, libc::FALLOC_FL_KEEP_SIZE, NOW)?; }
        _ => panic!("unknown mutation"),
    }
    Ok(())
}

#[test]
fn every_mutation_refuses_retained_geometry_and_reserved_damage_without_writes() {
    let cx = Cx::for_testing();
    for kind in ["fat16", "fat32"] {
        let (_directory, initial, geometry_volume) = fixture(kind);
        let geometry = geometry_volume.geometry.clone();
        let baseline = initial.snapshot();
        for damage in ["media", "fat0", "dirty", "io_error", "unknown_boot", "geometry", "backup", "fsinfo"] {
            if kind == "fat16" && matches!(damage, "backup" | "fsinfo") { continue; }
            let device = Device::new(baseline.clone());
            let volume = device.open(&cx);
            inject(&device, &geometry, damage);
            let before = device.snapshot();
            for action in 0..10 {
                assert!(mutate(&cx, &volume, action).is_err(), "{kind} {damage} action={action}");
                device.assert_unchanged(&before);
            }
        }
    }
}

#[test]
fn prepared_create_and_replace_recheck_admission_at_the_dirty_transition() {
    let cx = Cx::for_testing();
    for kind in ["fat16", "fat32"] {
        let (_directory, initial, geometry_volume) = fixture(kind);
        let geometry = geometry_volume.geometry.clone();
        let baseline = initial.snapshot();
        for creation_request in [false, true] {
            let device = Device::new(baseline.clone());
            let volume = device.open(&cx);
            let source = SliceSource(b"prepared payload");
            let plan = if creation_request {
                creation::prepare(&cx, &volume, "/PREPARED.BIN", &source, NOW).unwrap()
            } else {
                Replacement::prepare(&cx, &volume, "/SOURCE.BIN", &source, NOW).unwrap()
            };
            inject(&device, &geometry, "dirty");
            let before = device.snapshot();
            assert!(plan.execute(&cx, &volume, &source, || Ok(())).is_err());
            device.assert_unchanged(&before);
        }
    }
}

#[test]
fn late_reserved_state_read_failure_and_cancellation_do_not_start_publication() {
    let cx = Cx::for_testing();
    let (_directory, device, volume) = fixture("fat16");
    let before = device.snapshot();
    *device.fail_read.lock().unwrap() = Some(BASE + reserved(&volume.geometry, 1, 1));
    assert!(set_dirty(&cx, &volume, true).is_err());
    device.assert_unchanged(&before);
    *device.fail_read.lock().unwrap() = None;
    let cancelled = Cx::for_testing();
    cancelled.set_cancel_requested(true);
    assert!(set_dirty(&cancelled, &volume, true).is_err());
    device.assert_unchanged(&before);
}

#[test]
fn active_fat_admission_preserves_inactive_damage_and_reserved_high_bits() {
    let cx = Cx::for_testing();
    let (_directory, device, volume) = fixture("fat32");
    let geometry = volume.geometry.clone();
    drop(volume);
    for sector in std::iter::once(0_u16).chain(geometry.backup_boot_sector()) {
        device.patch(u64::from(sector) * u64::from(geometry.sector_bytes()) + 40, &0x0081_u16.to_le_bytes());
    }
    device.patch(reserved(&geometry, 0, 0), &[0; 8]);
    device.patch(reserved(&geometry, 1, 0), &0xAFFF_FFF8_u32.to_le_bytes());
    device.patch(reserved(&geometry, 1, 1), &0xBFFF_FFFF_u32.to_le_bytes());
    let volume = device.open(&cx);
    let before = device.snapshot();
    validate_boot_state(&cx, &volume).unwrap();
    device.assert_unchanged(&before);
    rename_in_volume(&cx, &volume, "/SOURCE.BIN", "/MOVED.BIN", false).unwrap();
    let after = device.snapshot();
    let first = (BASE + reserved(&geometry, 0, 0)) as usize;
    let second = (BASE + reserved(&geometry, 1, 0)) as usize;
    assert_eq!(&after[first..second], &before[first..second]);
    assert_eq!(&after[second..second + 8], &before[second..second + 8]);
    assert_eq!(&after[..BASE as usize], &before[..BASE as usize]);
    assert_eq!(&after[after.len() - BASE as usize..], &before[before.len() - BASE as usize..]);
    assert!(volume.check(&cx).unwrap().clean);
    let entry = volume.resolve(&cx, "/MOVED.BIN").unwrap().unwrap();
    let chain = volume.file_chain(&cx, &entry).unwrap();
    assert_eq!(volume.read(&cx, &chain, 0, 64).unwrap(), b"source contents");
}

#[test]
fn free_counts_remain_advisory_at_the_shared_state_gate() {
    let cx = Cx::for_testing();
    let (_directory, device, volume) = fixture("fat32");
    let at = u64::from(volume.geometry.fs_info_sector().unwrap()) * u64::from(volume.geometry.sector_bytes());
    device.patch(at + 488, &u32::MAX.to_le_bytes());
    device.patch(at + 492, &u32::MAX.to_le_bytes());
    let before = device.snapshot();
    validate_boot_state(&cx, &volume).unwrap();
    device.assert_unchanged(&before);
    create_in_volume(&cx, &volume, "/NEW.BIN", b"new payload", NOW, false).unwrap();
    assert!(volume.check(&cx).unwrap().clean);
}

#[test]
fn preflight_refusal_does_not_fence_a_mount_that_attempted_no_writes() {
    use ffs_core::{FsOps, RequestScope};
    use ffs_types::InodeNumber;
    use std::ffi::OsStr;

    let cx = Cx::for_testing();
    let (_directory, device, volume) = fixture("fat16");
    let geometry = volume.geometry.clone();
    let filesystem = crate::filesystem::FatFs::new_with_mode(&cx, volume, 0, 0, true).unwrap();
    inject(&device, &geometry, "dirty");
    let before = device.snapshot();
    assert!(filesystem.create(&cx, &mut RequestScope::empty(), InodeNumber(1),
        OsStr::new("REFUSED.BIN"), 0o644, 0, 0).is_err());
    device.assert_unchanged(&before);
    assert!(filesystem.getattr(&cx, &mut RequestScope::empty(), InodeNumber(1)).is_ok());
    // Repair only the fixture's injected state; no running filesystem does this.
    device.patch(reserved(&geometry, 1, 1), &0xFFFF_u16.to_le_bytes());
    filesystem.create(&cx, &mut RequestScope::empty(), InodeNumber(1),
        OsStr::new("HEALTHY.BIN"), 0o644, 0, 0).unwrap();
}

#[test]
fn healthy_mutations_still_publish_and_return_to_clean_native_state() {
    let cx = Cx::for_testing();
    for kind in ["fat16", "fat32"] {
        let (_directory, initial, _volume) = fixture(kind);
        let baseline = initial.snapshot();
        for action in 0..10 {
            let device = Device::new(baseline.clone());
            let volume = device.open(&cx);
            mutate(&cx, &volume, action).unwrap();
            assert!(device.attempts.load(Ordering::SeqCst) > 0, "{kind} action={action}");
            validate_boot_state(&cx, &volume).unwrap();
            let report = volume.check(&cx).unwrap();
            assert!(report.clean && report.complete && report.namespace_complete,
                "{kind} action={action}");
            let after = device.snapshot();
            assert_eq!(&after[..BASE as usize], &baseline[..BASE as usize]);
            assert_eq!(&after[after.len() - BASE as usize..], &baseline[baseline.len() - BASE as usize..]);
        }
    }
}
