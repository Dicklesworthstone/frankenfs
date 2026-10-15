use super::*;
use clap::Parser as _;
use ffs_ondisk::fat::FatOemCodePage;
use ffs_types::ByteOffset;
use std::os::unix::fs::FileExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

fn fixture(kind: &str) -> (tempfile::TempDir, ImageArgs, FatGeometry) {
    let directory = tempfile::tempdir().unwrap();
    let image = directory.path().join("diagnostic.fat");
    let cli = crate::Cli::try_parse_from([
        "ffs-fat", "format", image.to_str().unwrap(), "--kind", kind,
        "--size-mib", if kind == "fat16" { "4" } else { "64" },
    ]).unwrap();
    let crate::Command::Format { options } = cli.command else {
        panic!("expected formatter options");
    };
    let cx = Cx::for_testing();
    crate::formatter::create(&cx, &options).unwrap();
    let args = ImageArgs {
        image, offset: 0, length: None,
        oem_code_page: FatOemCodePage::Ascii, sidecar: None,
    };
    let geometry = args.open(&cx).unwrap().geometry.clone();
    (directory, args, geometry)
}

fn patch(args: &ImageArgs, at: u64, bytes: &[u8]) {
    let file = OpenOptions::new().write(true).open(&args.image).unwrap();
    file.write_all_at(bytes, args.offset + at).unwrap();
}

fn fat(args: &ImageArgs, geometry: &FatGeometry, copy: u8, cluster: u32, raw: u32) {
    let width = geometry.kind().entry_bytes() as usize;
    let at = geometry.entry_offset(copy, cluster.max(2)).unwrap()
        - u64::from(2_u32.saturating_sub(cluster)) * width as u64;
    patch(args, at, &raw.to_le_bytes()[..width]);
}

fn mark_dirty(args: &ImageArgs, geometry: &FatGeometry) {
    let (at, value) = match geometry.kind() {
        FatKind::Fat16 => (37, 0x7FFF),
        FatKind::Fat32 => (65, 0x07FF_FFFF),
    };
    for sector in std::iter::once(0_u16).chain(geometry.backup_boot_sector()) {
        patch(args, u64::from(sector) * u64::from(geometry.sector_bytes()) + at, &[1]);
    }
    for copy in 0..geometry.fat_count() {
        fat(args, geometry, copy, 1, value);
    }
}

fn has(report: &FatCheckReport, kind: &str) -> bool {
    report.issues.iter().any(|issue| issue.kind == kind)
}

#[test]
fn dirty_fat16_and_fat32_receive_complete_zero_write_diagnosis() {
    for kind in ["fat16", "fat32"] {
        let (_directory, args, geometry) = fixture(kind);
        let cx = Cx::for_testing();
        assert!(check(&cx, &args).unwrap().clean);
        mark_dirty(&args, &geometry);
        let before = fs::read(&args.image).unwrap();
        let report = check(&cx, &args).unwrap();
        assert!(report.complete && report.namespace_complete && report.read_only);
        assert!(!report.clean);
        assert_eq!(report.status, "issues_found");
        assert_eq!(report.lost_clusters, Some(0));
        assert!(has(&report, "native_boot_dirty") && has(&report, "native_fat_dirty"));
        assert!(args.open(&cx).is_err(), "diagnosis must not grant reader admission");
        assert_eq!(fs::read(&args.image).unwrap(), before);
    }
}

#[test]
fn dirty_lost_allocation_is_reported_but_mirror_ambiguity_has_no_orphan_authority() {
    let (_directory, args, geometry) = fixture("fat32");
    let cx = Cx::for_testing();
    mark_dirty(&args, &geometry);
    for copy in 0..geometry.fat_count() {
        fat(&args, &geometry, copy, 10, 11);
        fat(&args, &geometry, copy, 11, 0x0FFF_FFFF);
    }
    let before = fs::read(&args.image).unwrap();
    let report = check(&cx, &args).unwrap();
    assert!(report.complete && report.namespace_complete);
    assert_eq!(report.lost_clusters, Some(2));
    assert!(has(&report, "lost_chain") && has(&report, "native_fat_dirty"));
    assert_eq!(fs::read(&args.image).unwrap(), before);
    fat(&args, &geometry, 1, 10, 0);
    let report = check(&cx, &args).unwrap();
    assert!(!report.namespace_complete);
    assert_eq!(report.lost_clusters, None);
    assert!(has(&report, "fat_copy_mismatch"));
}

#[test]
fn native_errors_reserved_records_and_backup_dirty_state_remain_visible() {
    for kind in ["fat16", "fat32"] {
        let (_directory, args, geometry) = fixture(kind);
        let mask = if kind == "fat16" { 0xFFFF } else { 0x0FFF_FFFF };
        let io_ok = if kind == "fat16" { 0x4000 } else { 0x0400_0000 };
        fat(&args, &geometry, 0, 0, 0);
        fat(&args, &geometry, 0, 1, mask & !io_ok & !4);
        let at = if kind == "fat16" { 37 } else { 65 };
        patch(&args, at, &[6]);
        let report = check(&Cx::for_testing(), &args).unwrap();
        for issue in ["native_reserved_zero", "native_reserved_fat", "native_io_error",
            "native_surface_test", "native_boot_flags"] {
            assert!(has(&report, issue), "missing {issue}");
        }
    }
    let (_directory, args, geometry) = fixture("fat32");
    let at = u64::from(geometry.backup_boot_sector().unwrap())
        * u64::from(geometry.sector_bytes());
    patch(&args, at + 65, &[1]);
    let report = check(&Cx::for_testing(), &args).unwrap();
    assert!(has(&report, "native_boot_dirty"));
    assert!(!report.clean && report.complete);
    patch(&args, at + 13, &[2]);
    assert!(check(&Cx::for_testing(), &args).is_err());
}

#[test]
fn nonmirrored_fat32_ignores_inactive_state_and_retains_reserved_high_bits() {
    let (_directory, args, geometry) = fixture("fat32");
    for sector in std::iter::once(0_u16).chain(geometry.backup_boot_sector()) {
        patch(&args, u64::from(sector) * u64::from(geometry.sector_bytes()) + 40,
            &0x0081_u16.to_le_bytes());
    }
    fat(&args, &geometry, 0, 0, 0);
    fat(&args, &geometry, 0, 1, 0);
    fat(&args, &geometry, 1, 0, 0xAFFF_FFF8);
    fat(&args, &geometry, 1, 1, 0xBFFF_FFFF);
    let before = fs::read(&args.image).unwrap();
    assert!(check(&Cx::for_testing(), &args).unwrap().clean);
    assert_eq!(fs::read(&args.image).unwrap(), before);
}

struct ObservedReadOnly {
    file: File,
    length: u64,
    mutations: Arc<AtomicUsize>,
}

impl ByteDevice for ObservedReadOnly {
    fn len_bytes(&self) -> u64 { self.length }
    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        self.file.read_exact_at(bytes, offset.0)?;
        Ok(())
    }
    fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _bytes: &[u8]) -> ffs_error::Result<()> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        Err(FfsError::ReadOnly)
    }
    fn sync(&self, _cx: &Cx) -> ffs_error::Result<()> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        Err(FfsError::ReadOnly)
    }
}

#[test]
fn diagnostic_device_performs_neither_writes_nor_syncs() {
    let (_directory, args, geometry) = fixture("fat16");
    mark_dirty(&args, &geometry);
    let mutations = Arc::new(AtomicUsize::new(0));
    let file = File::open(&args.image).unwrap();
    let length = file.metadata().unwrap().len();
    let cx = Cx::for_testing();
    let diagnostic = DiagnosticVolume::from_device(&cx, Box::new(ObservedReadOnly {
        file, length, mutations: Arc::clone(&mutations),
    }), &args).unwrap();
    assert!(!diagnostic.report(&cx).unwrap().clean);
    assert_eq!(mutations.load(Ordering::SeqCst), 0);
}

#[test]
fn diagnostic_admission_refuses_sidecars_symlinks_bad_bounds_and_cancellation() {
    let (directory, mut args, _geometry) = fixture("fat16");
    let cx = Cx::for_testing();
    args.sidecar = Some(directory.path().join("must-not-be-opened"));
    assert!(matches!(check(&cx, &args).unwrap_err().downcast::<FfsError>().unwrap(),
        FfsError::UnsupportedFeature(_)));
    args.sidecar = None;
    args.offset = u64::MAX;
    args.length = Some(512);
    assert!(check(&cx, &args).is_err());
    args.offset = 0;
    args.length = Some(511);
    assert!(check(&cx, &args).is_err());
    args.length = None;
    let alias = directory.path().join("alias");
    std::os::unix::fs::symlink(&args.image, &alias).unwrap();
    args.image = alias;
    assert!(check(&cx, &args).is_err());
    cx.set_cancel_requested(true);
    assert!(matches!(check(&cx, &args).unwrap_err().downcast::<FfsError>().unwrap(),
        FfsError::Cancelled));
}

#[test]
fn bounded_dirty_volume_diagnosis_preserves_surrounding_image_bytes() {
    let (directory, mut args, geometry) = fixture("fat16");
    mark_dirty(&args, &geometry);
    let payload = fs::read(&args.image).unwrap();
    let mut disk = vec![0xA5; 4096];
    disk.extend_from_slice(&payload);
    disk.extend_from_slice(&[0x5A; 4096]);
    args.image = directory.path().join("disk.img");
    fs::write(&args.image, &disk).unwrap();
    args.offset = 4096;
    args.length = Some(payload.len() as u64);
    let report = check(&Cx::for_testing(), &args).unwrap();
    assert_eq!(report.volume_offset, 4096);
    assert_eq!(report.volume_bytes, payload.len() as u64);
    assert!(report.complete && has(&report, "native_fat_dirty"));
    assert_eq!(fs::read(&args.image).unwrap(), disk);
}
