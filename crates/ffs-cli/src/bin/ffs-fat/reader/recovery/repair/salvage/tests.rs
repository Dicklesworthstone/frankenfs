//! Synthetic native images and real host exports; not mounted/native-OS proof.

use super::*;
use super::super::{DiagnosticVolume, ImageArgs, RecoverArgs, recover};
use super::super::super::tests::{fat, fixture, mark_dirty, patch};
use clap::Parser as _;
use ffs_block::ByteDevice;
use ffs_types::ByteOffset;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

fn end(kind: FatKind) -> u32 {
    if kind == FatKind::Fat16 { 0xFFFF } else { 0x0FFF_FFFF }
}

fn options(image: ImageArgs, output: &Path) -> RecoverArgs {
    RecoverArgs {
        image, offline_image: true, reclaim_lost: false, discard_orphan_lfn: false,
        salvage_to: Some(output.to_path_buf()), dry_run: false,
    }
}

fn fragmented(kind: &str) -> (tempfile::TempDir, ImageArgs, Vec<u8>) {
    let (directory, image, geometry) = fixture(kind);
    let mut expected = Vec::new();
    for (index, cluster) in [100, 300, 200].into_iter().enumerate() {
        let bytes = vec![0x31 + index as u8; geometry.cluster_bytes() as usize];
        patch(&image, geometry.cluster_offset(cluster).unwrap(), &bytes);
        expected.extend_from_slice(&bytes);
    }
    for copy in 0..geometry.fat_count() {
        fat(&image, &geometry, copy, 100, 300);
        fat(&image, &geometry, copy, 300, 200);
        fat(&image, &geometry, copy, 200, end(geometry.kind()));
    }
    mark_dirty(&image, &geometry);
    (directory, image, expected)
}

#[test]
fn chain_graph_keeps_allocation_order_and_native_end_ranges() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let terminal = end(kind);
        let lost = [(20, 300), (40, terminal - 7), (100, 20), (300, terminal)];
        assert_eq!(chains(&cx, kind, &lost).unwrap(), vec![vec![40], vec![100, 20, 300]]);
        assert!(chains(&cx, kind, &[]).unwrap().is_empty());
    }
}

#[test]
fn chain_graph_refuses_ambiguous_invalid_or_unbounded_exports() {
    let cx = Cx::for_testing();
    for lost in [
        vec![(2, 2)],                             // self-cycle
        vec![(2, 3), (3, 2)],                     // headless cycle
        vec![(2, 4), (3, 4), (4, 0xFFFF)],       // merged ownership
        vec![(2, 99)],                            // outside lost allocation
        vec![(2, 0)], vec![(2, 0xFFF7)],          // free/bad
        vec![(2, 0xFFF0)],                        // reserved
        vec![(2, 0xFFFF), (2, 0xFFFF)],           // duplicate ID
        vec![(3, 0xFFFF), (2, 0xFFFF)],           // noncanonical evidence
        vec![(0, 0xFFFF)],                        // reserved ID
    ] {
        assert!(chains(&cx, FatKind::Fat16, &lost).is_err(), "{lost:?}");
    }
    let many: Vec<_> = (2..MAX_FILES as u32 + 3).map(|id| (id, 0xFFFF)).collect();
    assert!(chains(&cx, FatKind::Fat16, &many).is_err());
    cx.set_cancel_requested(true);
    assert!(chains(&cx, FatKind::Fat16, &[(2, 0xFFFF)]).is_err());
}

#[test]
fn both_dialects_export_fragmented_raw_clusters_with_private_verified_manifest() {
    for kind in ["fat16", "fat32"] {
        let (directory, image, expected) = fragmented(kind);
        let initial = fs::read(&image.image).unwrap();
        let output = directory.path().join("salvaged");
        let args = options(image, &output);
        let report = recover(&Cx::for_testing(), &args).unwrap();
        assert_eq!(report["image_changed"], false);
        assert_eq!(report["image_repaired"], false);
        assert_eq!(report["original_lengths_known"], false);
        assert_eq!(report["exported_files"], 1);
        assert_eq!(report["files"][0]["clusters"], serde_json::json!([100, 300, 200]));
        assert_eq!(fs::read(output.join("FILE0000.CHK")).unwrap(), expected);
        let digest: [u8; 32] = Sha256::digest(&expected).into();
        assert_eq!(report["files"][0]["sha256"], hex_digest(&digest));
        let manifest: serde_json::Value = serde_json::from_slice(
            &fs::read(output.join("manifest.json")).unwrap(),
        ).unwrap();
        assert_eq!(manifest, report);
        assert_eq!(fs::metadata(&output).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(output.join("FILE0000.CHK")).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::read(&args.image.image).unwrap(), initial);
        assert!(args.image.open(&Cx::for_testing()).is_err(), "export must not clear dirty state");
    }
}

#[test]
fn active_fat_selection_and_reachable_preallocation_are_preserved() {
    let (directory, image, geometry) = fixture("fat32");
    let cx = Cx::for_testing();
    {
        let volume = crate::reader::replacement::open_volume(&cx, &image, true).unwrap();
        crate::reader::replacement::create_in_volume(
            &cx, &volume, "/KEEP.BIN", b"live", 1_700_000_000, false,
        ).unwrap();
        volume.preallocate(&cx, "/KEEP.BIN", 0, u64::from(geometry.cluster_bytes()) * 3,
            libc::FALLOC_FL_KEEP_SIZE, 1_700_000_000).unwrap();
    }
    for sector in std::iter::once(0_u16).chain(geometry.backup_boot_sector()) {
        let offset = u64::from(sector) * u64::from(geometry.sector_bytes());
        patch(&image, offset + 40, &0x0081_u16.to_le_bytes());
        patch(&image, offset + 65, &[1]);
    }
    fat(&image, &geometry, 0, 0, 0); // explicitly inactive, not repair authority
    fat(&image, &geometry, 0, 1, 0);
    fat(&image, &geometry, 1, 1, 0xA7FF_FFFF);
    fat(&image, &geometry, 1, 100, 0xBFFF_FFFF);
    let payload = vec![0xD7; geometry.cluster_bytes() as usize];
    patch(&image, geometry.cluster_offset(100).unwrap(), &payload);
    let before = fs::read(&image.image).unwrap();
    let output = directory.path().join("active");
    let args = options(image, &output);
    let report = recover(&cx, &args).unwrap();
    assert_eq!(report["planned_clusters"], 1);
    assert_eq!(report["before"]["preallocated_clusters"], 2);
    assert_eq!(fs::read(output.join("FILE0000.CHK")).unwrap(), payload);
    assert_eq!(fs::read(&args.image.image).unwrap(), before);
}

#[test]
fn full_fat16_root_and_full_data_volume_need_no_source_capacity_for_salvage() {
    let (directory, mut image, geometry) = fixture("fat16");
    let mut bytes = fs::read(&image.image).unwrap();
    let (root, length) = geometry.fixed_root().unwrap();
    for (index, slot) in bytes[root as usize..(root + length) as usize].chunks_exact_mut(32).enumerate() {
        slot.fill(0);
        let name = format!("F{index:07}BIN");
        slot[..11].copy_from_slice(name.as_bytes());
        slot[11] = 0x20; // live, distinct, empty native files occupy EVERY slot
    }
    for copy in 0..geometry.fat_count() {
        for cluster in 2..=geometry.cluster_count() + 1 {
            let at = geometry.entry_offset(copy, cluster).unwrap() as usize;
            let next = if cluster == geometry.cluster_count() + 1 { 0xFFFF } else { cluster + 1 };
            bytes[at..at + 2].copy_from_slice(&(next as u16).to_le_bytes());
        }
    }
    for cluster in 2..=geometry.cluster_count() + 1 {
        let at = geometry.cluster_offset(cluster).unwrap() as usize;
        bytes[at..at + geometry.cluster_bytes() as usize].fill((cluster % 251) as u8);
    }
    // Exercise selected-volume offsets and adjacent-region preservation too.
    let mut disk = vec![0xA5; 8192];
    disk.extend_from_slice(&bytes);
    disk.extend_from_slice(&[0x5A; 8192]);
    image.image = directory.path().join("full-disk.img");
    image.offset = 8192;
    image.length = Some(bytes.len() as u64);
    fs::write(&image.image, &disk).unwrap();
    mark_dirty(&image, &geometry);
    let before = fs::read(&image.image).unwrap();
    let output = directory.path().join("full-salvage");
    let args = options(image, &output);
    let report = recover(&Cx::for_testing(), &args).unwrap();
    assert_eq!(report["before"]["free_clusters"], 0);
    assert_eq!(report["before"]["files"], length / 32);
    assert_eq!(report["planned_clusters"], geometry.cluster_count());
    let recovered = fs::read(output.join("FILE0000.CHK")).unwrap();
    assert_eq!(recovered.len() as u64, u64::from(geometry.cluster_count()) * u64::from(geometry.cluster_bytes()));
    for (index, block) in recovered.chunks_exact(geometry.cluster_bytes() as usize).enumerate() {
        assert!(block.iter().all(|&byte| byte == ((index + 2) % 251) as u8));
    }
    assert_eq!(fs::read(&args.image.image).unwrap(), before);
}

#[test]
fn dry_run_noop_and_existing_destinations_create_nothing_and_never_overwrite() {
    let (directory, image, _) = fragmented("fat16");
    let output = directory.path().join("dry");
    let mut args = options(image, &output);
    args.dry_run = true;
    let before = fs::read(&args.image.image).unwrap();
    assert_eq!(recover(&Cx::for_testing(), &args).unwrap()["planned_files"], 1);
    assert!(!output.exists());
    args.dry_run = false;
    fs::create_dir(&output).unwrap();
    fs::write(output.join("FILE0000.CHK"), b"keep host data").unwrap();
    assert!(recover(&Cx::for_testing(), &args).is_err());
    assert_eq!(fs::read(output.join("FILE0000.CHK")).unwrap(), b"keep host data");
    let link = directory.path().join("link");
    symlink(&output, &link).unwrap();
    args.salvage_to = Some(link);
    assert!(recover(&Cx::for_testing(), &args).is_err());
    assert_eq!(fs::read(&args.image.image).unwrap(), before);

    let (directory, image, _) = fixture("fat16");
    let output = directory.path().join("empty");
    let args = options(image, &output);
    assert_eq!(recover(&Cx::for_testing(), &args).unwrap()["output_created"], false);
    assert!(!output.exists());
}

#[test]
fn ambiguous_lost_graph_and_mirror_conflicts_are_refused_before_creating_output() {
    for damage in ["cycle", "merge", "dangling", "mirror"] {
        let (directory, image, _) = fragmented("fat16");
        let geometry = diagnostic(&image).0.volume.geometry.clone();
        for copy in 0..geometry.fat_count() {
            match damage {
                "cycle" => fat(&image, &geometry, copy, 200, 100),
                "merge" => fat(&image, &geometry, copy, 400, 200),
                "dangling" => fat(&image, &geometry, copy, 200, 500),
                _ => if copy == 0 { fat(&image, &geometry, copy, 300, 0xFFFF); },
            }
        }
        let output = directory.path().join("refused");
        let before = fs::read(&image.image).unwrap();
        let args = options(image, &output);
        assert!(recover(&Cx::for_testing(), &args).is_err(), "{damage}");
        assert!(!output.exists());
        assert_eq!(fs::read(&args.image.image).unwrap(), before);
    }
}

/// Any backing write OR sync is a test failure, even when export succeeds.
#[derive(Clone)]
struct ReadOnlyDevice {
    bytes: Arc<Vec<u8>>,
    fail_at: Arc<AtomicU64>,
}

impl ByteDevice for ReadOnlyDevice {
    fn len_bytes(&self) -> u64 { self.bytes.len() as u64 }
    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        if offset.0 == self.fail_at.load(Ordering::Acquire) {
            bytes.fill(0xEE); // model a partially filled destination on failure
            return Err(std::io::Error::other("injected salvage read failure").into());
        }
        let at = usize::try_from(offset.0).unwrap();
        let source = self.bytes.get(at..at + bytes.len())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
        bytes.copy_from_slice(source);
        Ok(())
    }
    fn write_all_at(&self, _: &Cx, _: ByteOffset, _: &[u8]) -> ffs_error::Result<()> {
        panic!("salvage must never write the backing")
    }
    fn sync(&self, _: &Cx) -> ffs_error::Result<()> {
        panic!("salvage must never sync the backing")
    }
}

fn diagnostic(image: &ImageArgs) -> (DiagnosticVolume, ReadOnlyDevice) {
    let device = ReadOnlyDevice {
        bytes: Arc::new(fs::read(&image.image).unwrap()),
        fail_at: Arc::new(AtomicU64::new(u64::MAX)),
    };
    let diagnostic = DiagnosticVolume::from_device(&Cx::for_testing(), Box::new(device.clone()), image).unwrap();
    (diagnostic, device)
}

#[test]
fn backing_is_read_only_even_during_success_and_failed_reads_do_not_emit_partial_buffers() {
    let (directory, image, expected) = fragmented("fat16");
    let (diagnostic, device) = diagnostic(&image);
    let cx = Cx::for_testing();
    let plan = Plan::prepare(&cx, &diagnostic, true, false).unwrap();
    let export = Salvage::prepare(&cx, &diagnostic.volume, plan, &directory.path().join("readonly")).unwrap();
    export.execute(&cx, &diagnostic.volume, || Ok(())).unwrap();
    let cluster = diagnostic.volume.geometry.cluster_bytes() as usize;
    let second = diagnostic.volume.cluster_offset(300).unwrap();
    device.fail_at.store(second, Ordering::Release);
    let mut received = Vec::new();
    let mut buffer = vec![0xAA; cluster];
    assert!(stream_chain(&cx, &diagnostic.volume, &[100, 300, 200], &mut received, &mut buffer).is_err());
    assert_eq!(received, expected[..cluster]);
    let output = directory.path().join("failed");
    let plan = Plan::prepare(&cx, &diagnostic, true, false).unwrap();
    let export = Salvage::prepare(&cx, &diagnostic.volume, plan, &output).unwrap();
    assert!(export.execute(&cx, &diagnostic.volume, || Ok(())).is_err());
    assert!(!output.join("manifest.json").exists());
    assert_eq!(fs::read(output.join("FILE0000.CHK")).unwrap(), expected[..cluster]);
}

#[test]
fn cancellation_and_changed_source_keep_partial_evidence_without_success_manifest() {
    let (directory, image, _) = fragmented("fat16");
    let (diagnostic, _) = diagnostic(&image);
    for cancel in [false, true] {
        let cx = Cx::for_testing();
        let output = directory.path().join(if cancel { "cancelled" } else { "changed" });
        let plan = Plan::prepare(&cx, &diagnostic, true, false).unwrap();
        let export = Salvage::prepare(&cx, &diagnostic.volume, plan, &output).unwrap();
        let mut checks = 0;
        assert!(export.execute(&cx, &diagnostic.volume, || {
            checks += 1;
            if checks == 3 {
                if cancel { cx.set_cancel_requested(true); }
                else { bail!("image identity changed during salvage"); }
            }
            Ok(())
        }).is_err());
        assert!(output.join("FILE0000.CHK").exists());
        assert!(!output.join("manifest.json").exists());
    }
}

struct FailingOutput(usize);

impl Write for FailingOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.0 == 0 { return Err(std::io::Error::other("output capacity exhausted")); }
        let count = self.0.min(bytes.len());
        self.0 -= count;
        Ok(count)
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

#[test]
fn output_failure_and_output_readback_corruption_cannot_be_success() {
    let (directory, image, _) = fragmented("fat16");
    let (diagnostic, _) = diagnostic(&image);
    let cx = Cx::for_testing();
    let mut buffer = vec![0; 512];
    assert!(stream_chain(&cx, &diagnostic.volume, &[100], &mut FailingOutput(7), &mut buffer).is_err());
    let mut file = new_file(&directory.path().join("readback.chk")).unwrap();
    file.write_all(b"wrong").unwrap();
    assert!(verify_output(&cx, &mut file, 5, &[0; 32], &mut buffer).is_err());
    assert!(verify_output(&cx, &mut file, 6, &[0; 32], &mut buffer).is_err());
}

#[test]
fn salvage_cli_is_explicit_and_mutually_exclusive_with_destructive_reclaim() {
    let cli = crate::Cli::try_parse_from([
        "ffs-fat", "recover", "disk.img", "--offline-image", "--salvage-to", "rescued", "--dry-run",
    ]).unwrap();
    let crate::Command::Recover { options: parsed } = cli.command else { panic!("expected recovery"); };
    assert_eq!(parsed.salvage_to, Some(PathBuf::from("rescued")));
    assert!(!parsed.reclaim_lost && parsed.dry_run);
    assert!(crate::Cli::try_parse_from([
        "ffs-fat", "recover", "disk.img", "--offline-image", "--salvage-to", "rescued", "--reclaim-lost",
    ]).is_err());
    assert!(crate::Cli::try_parse_from([
        "ffs-fat", "recover", "disk.img", "--salvage-to", "rescued",
    ]).is_err());
    let (directory, image, _) = fragmented("fat16");
    let output = directory.path().join("conflicting");
    let mut args = options(image, &output);
    args.reclaim_lost = true;
    let before = fs::read(&args.image.image).unwrap();
    assert!(recover(&Cx::for_testing(), &args).is_err());
    assert!(!output.exists());
    assert_eq!(fs::read(&args.image.image).unwrap(), before);
}
