//! Constructed-image and direct production recovery tests; not native fsck proof.

use super::*;
use super::super::parents::{ParentPlan, RepairParentsArgs, repair_parents};
use std::sync::atomic::{AtomicBool, Ordering};

fn options(image: &ImageArgs, dry_run: bool) -> RepairParentsArgs {
    let mut args = vec![
        "ffs-fat".to_owned(), "repair-parents".to_owned(),
        image.image.to_str().unwrap().to_owned(), "--offline-image".to_owned(),
        "--offset".to_owned(), image.offset.to_string(),
    ];
    if let Some(length) = image.length {
        args.extend(["--length".to_owned(), length.to_string()]);
    }
    if dry_run { args.push("--dry-run".to_owned()); }
    let crate::Command::RepairParents { options } = crate::Cli::try_parse_from(args).unwrap().command else {
        panic!("parent repair command");
    };
    options
}

// Root -> PARENT -> CHILD; derive expected parents from names, not damaged dots.
fn tree(kind: &str) -> (tempfile::TempDir, ImageArgs, super::super::super::FatGeometry, Vec<(u32, u32)>) {
    let (directory, image, geometry) = populated(kind);
    let cx = Cx::for_testing();
    let volume = crate::reader::replacement::open_volume(&cx, &image, true).unwrap();
    crate::reader::replacement::mkdir_in_volume(&cx, &volume, "/PARENT", NOW, false).unwrap();
    crate::reader::replacement::mkdir_in_volume(&cx, &volume, "/PARENT/CHILD", NOW, false).unwrap();
    crate::reader::replacement::create_in_volume(
        &cx, &volume, "/PARENT/CHILD/Raw long name.txt", b"nested acknowledged payload", NOW, false,
    ).unwrap();
    let parent = volume.resolve(&cx, "/PARENT").unwrap().unwrap().native.first_cluster;
    let child = volume.resolve(&cx, "/PARENT/CHILD").unwrap().unwrap().native.first_cluster;
    drop(volume);
    (directory, image, geometry, vec![(parent, 0), (child, parent)])
}

fn damage(image: &ImageArgs, geometry: &super::super::super::FatGeometry, directories: &[(u32, u32)]) {
    for &(first, _) in directories {
        let start = geometry.cluster_offset(first).unwrap();
        for at in [start, start + 32] {
            // Preserve non-pointer metadata while deliberately breaking both
            // links. FAT16's EA word is not part of a cluster address.
            let high: u16 = if geometry.kind() == FatKind::Fat32 { 0xA000 } else { 0x5678 };
            patch(image, at + 20, &high.to_le_bytes());
            patch(image, at + 26, &1_u16.to_le_bytes());
        }
    }
    mark_dirty(image, geometry);
}

fn pointer_value(bytes: &[u8], kind: FatKind) -> u32 {
    u32::from(u16::from_le_bytes([bytes[26], bytes[27]]))
        | if kind == FatKind::Fat32 {
            u32::from(u16::from_le_bytes([bytes[20], bytes[21]]) & 0x0FFF) << 16
        } else { 0 }
}

#[test]
fn parent_repair_uses_unique_rooted_ancestry_preserves_all_other_bytes_and_leaves_dirty() {
    for kind in ["fat16", "fat32"] {
        let (_dir, image, geometry, directories) = tree(kind);
        damage(&image, &geometry, &directories);
        let original = fs::read(&image.image).unwrap();
        let cx = Cx::for_testing();
        // Default recovery must continue to refuse parent-link corruption.
        let cli = crate::Cli::try_parse_from([
            "ffs-fat", "recover", image.image.to_str().unwrap(), "--offline-image",
        ]).unwrap();
        let crate::Command::Recover { options: ordinary } = cli.command else { panic!("recover"); };
        assert!(recover(&cx, &ordinary).is_err());
        let dry = repair_parents(&cx, &options(&image, true)).unwrap();
        assert_eq!(dry["planned_directory_repairs"], 2);
        assert_eq!(fs::read(&image.image).unwrap(), original);
        let report = repair_parents(&cx, &options(&image, false)).unwrap();
        assert_eq!(report["repaired_directories"], 2);
        assert_eq!(report["left_dirty"], true);
        assert_eq!(report["file_contents_verified"], false);
        assert_eq!(report["verification"]["clean"], false);
        let after = fs::read(&image.image).unwrap();
        let mut expected = original.clone();
        for &(first, parent) in &directories {
            let start = (image.offset + geometry.cluster_offset(first).unwrap()) as usize;
            for (offset, cluster) in [(start, first), (start + 32, parent)] {
                expected[offset + 26..offset + 28].copy_from_slice(&(cluster as u16).to_le_bytes());
                if geometry.kind() == FatKind::Fat32 {
                    expected[offset + 20..offset + 22].copy_from_slice(&(0xA000 | (cluster >> 16) as u16).to_le_bytes());
                }
                assert_eq!(pointer_value(&after[offset..offset + 32], geometry.kind()), cluster);
            }
        }
        // Input was already dirty, so no other native byte should change.
        assert_eq!(after, expected);
        assert!(image.open(&cx).is_err());
        let clean = recover(&cx, &ordinary).unwrap();
        assert_eq!(clean["verification"]["clean"], true);
        let volume = image.open(&cx).unwrap();
        retained(&cx, &volume);
        let entry = volume.resolve(&cx, "/PARENT/CHILD/Raw long name.txt").unwrap().unwrap();
        assert_eq!(volume.read(&cx, &volume.file_chain(&cx, &entry).unwrap(), 0, 128).unwrap(), b"nested acknowledged payload");
    }
}

#[test]
fn missing_substituted_or_nonzero_size_dot_records_are_not_recreated() {
    let (_dir, image, geometry, directories) = tree("fat16");
    damage(&image, &geometry, &directories);
    let baseline = fs::read(&image.image).unwrap();
    let start = geometry.cluster_offset(directories[0].0).unwrap() as usize;
    for (within, bytes) in [(0, vec![0]), (0, vec![0xE5]), (32, b"REAL    BIN".to_vec()),
        (11, vec![0x20]), (28, vec![1]), (43, vec![0x18])] {
        let mut damaged = baseline.clone();
        damaged[start + within..start + within + bytes.len()].copy_from_slice(&bytes);
        let device = fault_device(&damaged, None, 0);
        let cx = Cx::for_testing();
        let diagnostic = DiagnosticVolume::from_device(&cx, Box::new(device.clone()), &image).unwrap();
        assert!(ParentPlan::prepare(&cx, &diagnostic).is_err(), "offset {within}");
        assert_eq!(device.0.lock().unwrap().operations, 0);
        assert_eq!(device.0.lock().unwrap().pending, damaged);
    }
}

#[test]
fn crosslinks_mirror_disagreement_hard_errors_and_incomplete_names_refuse_prewrite() {
    let (_dir, image, geometry, directories) = tree("fat16");
    damage(&image, &geometry, &directories);
    let baseline = fs::read(&image.image).unwrap();
    let root = geometry.fixed_root().unwrap().0 as usize;
    for action in 0..4 {
        let mut bytes = baseline.clone();
        match action {
            0 => {
                // Append another root owner of PARENT, without allocating data.
                let parent = bytes[root..root + 512].chunks_exact(32)
                    .find(|record| &record[..11] == b"PARENT     ").unwrap().to_vec();
                let end = bytes[root..root + 512].chunks_exact(32)
                    .position(|record| record[0] == 0).unwrap() * 32;
                bytes[root + end..root + end + 32].copy_from_slice(&parent);
                bytes[root + end..root + end + 11].copy_from_slice(b"ALIAS      ");
            }
            1 => {
                let at = geometry.entry_offset(0, directories[0].0).unwrap() as usize;
                bytes[at..at + 2].fill(0);
            }
            2 => {
                let at = geometry.entry_offset(0, 2).unwrap() as usize - 2;
                bytes[at..at + 2].copy_from_slice(&0x3FFF_u16.to_le_bytes());
            }
            _ => {
                let end = bytes[root..root + 512].chunks_exact(32)
                    .position(|record| record[0] == 0).unwrap() * 32;
                bytes[root + end] = 0x41;
                bytes[root + end + 11] = 0x0F; // unbound malformed LFN is another authority
            }
        }
        let device = fault_device(&bytes, None, 0);
        let cx = Cx::for_testing();
        let diagnostic = DiagnosticVolume::from_device(&cx, Box::new(device.clone()), &image).unwrap();
        assert!(ParentPlan::prepare(&cx, &diagnostic).is_err(), "action {action}");
        assert_eq!(device.0.lock().unwrap().operations, 0);
        assert_eq!(device.0.lock().unwrap().pending, bytes);
    }
}

#[test]
fn parent_repair_preserves_lost_allocation_instead_of_implicitly_reclaiming_it() {
    let (_dir, image, geometry, directories) = tree("fat16");
    damage(&image, &geometry, &directories);
    orphan(&image, &geometry);
    let cx = Cx::for_testing();
    let report = repair_parents(&cx, &options(&image, false)).unwrap();
    assert_eq!(report["before"]["lost_clusters"], 3);
    assert_eq!(report["verification"]["lost_clusters"], 3);
    assert_eq!(report["before"]["allocated_clusters"], report["verification"]["allocated_clusters"]);
    let bytes = fs::read(&image.image).unwrap();
    for copy in 0..geometry.fat_count() {
        for (cluster, expected) in [(100, 101_u16), (101, 0xFFFF), (102, 102)] {
            let at = geometry.entry_offset(copy, cluster).unwrap() as usize;
            assert_eq!(&bytes[at..at + 2], &expected.to_le_bytes());
        }
    }
}

#[test]
fn parent_repair_noop_cancellation_and_stale_evidence_do_not_write_or_sync() {
    let (_dir, image, geometry, directories) = tree("fat16");
    let clean_bytes = fs::read(&image.image).unwrap();
    let cx = Cx::for_testing();
    let device = fault_device(&clean_bytes, Some(1), 0);
    let diagnostic = DiagnosticVolume::from_device(&cx, Box::new(device.clone()), &image).unwrap();
    let plan = ParentPlan::prepare(&cx, &diagnostic).unwrap();
    assert_eq!(plan.execute(&cx, &diagnostic).unwrap()["changed"], false);
    assert_eq!(device.0.lock().unwrap().operations, 0);
    damage(&image, &geometry, &directories);
    let bytes = fs::read(&image.image).unwrap();
    let device = fault_device(&bytes, None, 0);
    let diagnostic = DiagnosticVolume::from_device(&cx, Box::new(device.clone()), &image).unwrap();
    let plan = ParentPlan::prepare(&cx, &diagnostic).unwrap();
    let cancelled = Cx::for_testing();
    cancelled.set_cancel_requested(true);
    assert!(plan.execute(&cancelled, &diagnostic).is_err());
    assert_eq!(device.0.lock().unwrap().operations, 0);
    // A change after a directory's end marker is still retained-storage damage.
    let at = geometry.cluster_offset(directories[1].0).unwrap() as usize + 400;
    device.0.lock().unwrap().pending[at] ^= 0x80;
    assert!(plan.execute(&cx, &diagnostic).is_err());
    assert_eq!(device.0.lock().unwrap().operations, 0);
}

#[test]
fn parent_repair_every_write_sync_cut_retains_payload_and_stops_without_cleanup() {
    let (_dir, image, geometry, directories) = tree("fat16");
    damage(&image, &geometry, &directories);
    let baseline = fs::read(&image.image).unwrap();
    let cx = Cx::for_testing();
    let device = fault_device(&baseline, None, 0);
    let diagnostic = DiagnosticVolume::from_device(&cx, Box::new(device.clone()), &image).unwrap();
    ParentPlan::prepare(&cx, &diagnostic).unwrap().execute(&cx, &diagnostic).unwrap();
    let operations = device.0.lock().unwrap().operations;
    assert!(operations >= 5);
    for cut in 1..=operations {
        for tear in [0, 21, 27, 53, 511] {
            let device = fault_device(&baseline, Some(cut), tear);
            let diagnostic = DiagnosticVolume::from_device(&cx, Box::new(device.clone()), &image).unwrap();
            let plan = ParentPlan::prepare(&cx, &diagnostic).unwrap();
            assert!(plan.execute(&cx, &diagnostic).is_err(), "cut {cut}, tear {tear}");
            assert_eq!(device.0.lock().unwrap().operations, cut);
            for pending in [false, true] {
                let state = device.0.lock().unwrap();
                let bytes = if pending { state.pending.clone() } else { state.durable.clone() };
                drop(state);
                let check = DiagnosticVolume::from_device(&cx, Box::new(fault_device(&bytes, None, 0)), &image).unwrap();
                retained(&cx, &check.volume);
                assert!(!check.report(&cx).unwrap().clean);
            }
        }
    }
}

struct PublicationFault {
    inner: FaultDevice,
    target: u64,
    mode: u8,
    armed: AtomicBool,
}

impl ByteDevice for PublicationFault {
    fn len_bytes(&self) -> u64 { self.inner.len_bytes() }
    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        if self.armed.load(Ordering::SeqCst) && self.mode == 2 && at.0 == self.target {
            return Err(std::io::Error::other("parent repair readback failure").into());
        }
        self.inner.read_exact_at(cx, at, bytes)
    }
    fn write_all_at(&self, cx: &Cx, at: ByteOffset, bytes: &[u8]) -> ffs_error::Result<()> {
        if at.0 == self.target {
            self.armed.store(true, Ordering::SeqCst);
            if self.mode == 0 { return Ok(()); }
        }
        self.inner.write_all_at(cx, at, bytes)?;
        if self.armed.load(Ordering::SeqCst) && self.mode == 3 { cx.set_cancel_requested(true); }
        Ok(())
    }
    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        self.inner.sync(cx)?;
        if self.armed.load(Ordering::SeqCst) && self.mode == 1 {
            let mut state = self.inner.0.lock().unwrap();
            let at = self.target as usize + 90;
            state.pending[at] ^= 0x80;
            state.durable[at] ^= 0x80;
        }
        Ok(())
    }
}

#[test]
fn dropped_repairs_post_sync_corruption_read_failures_and_cancellation_are_errors() {
    let (_dir, image, geometry, directories) = tree("fat16");
    damage(&image, &geometry, &directories);
    let bytes = fs::read(&image.image).unwrap();
    for mode in 0..4 {
        let cx = Cx::for_testing();
        let inner = fault_device(&bytes, None, 0);
        let fault = PublicationFault {
            inner: inner.clone(), target: geometry.cluster_offset(directories[0].0).unwrap(),
            mode, armed: AtomicBool::new(false),
        };
        let diagnostic = DiagnosticVolume::from_device(&cx, Box::new(fault), &image).unwrap();
        let plan = ParentPlan::prepare(&cx, &diagnostic).unwrap();
        assert!(plan.execute(&cx, &diagnostic).is_err(), "mode {mode}");
        let fresh = Cx::for_testing();
        let after = inner.0.lock().unwrap().pending.clone();
        let reopened = DiagnosticVolume::from_device(&fresh, Box::new(fault_device(&after, None, 0)), &image).unwrap();
        retained(&fresh, &reopened.volume);
        assert!(!reopened.report(&fresh).unwrap().clean);
        // Failure in the first directory must not patch the second one.
        let child = geometry.cluster_offset(directories[1].0).unwrap() as usize;
        assert_eq!(&after[child..child + 64], &bytes[child..child + 64]);
    }
}

#[test]
fn parent_repair_honors_selected_volume_bounds_and_active_fat() {
    let (dir, mut image, geometry, directories) = tree("fat32");
    damage(&image, &geometry, &directories);
    for sector in std::iter::once(0_u16).chain(geometry.backup_boot_sector()) {
        patch(&image, u64::from(sector) * u64::from(geometry.sector_bytes()) + 40, &0x81_u16.to_le_bytes());
    }
    fat(&image, &geometry, 0, 0, 0); // unselected copy is deliberately unusable
    let original = fs::read(&image.image).unwrap();
    let mut partitioned = vec![0xA5; 8192];
    partitioned.extend_from_slice(&original);
    partitioned.extend_from_slice(&[0x5A; 8192]);
    image.image = dir.path().join("selected.img");
    image.offset = 8192;
    image.length = Some(original.len() as u64);
    fs::write(&image.image, &partitioned).unwrap();
    repair_parents(&Cx::for_testing(), &options(&image, false)).unwrap();
    let after = fs::read(&image.image).unwrap();
    assert_eq!(&after[..8192], &partitioned[..8192]);
    assert_eq!(&after[8192 + original.len()..], &partitioned[8192 + original.len()..]);
    let first = 8192 + geometry.entry_offset(0, 2).unwrap() as usize - 8;
    let second = 8192 + geometry.entry_offset(1, 2).unwrap() as usize - 8;
    assert_eq!(&after[first..second], &partitioned[first..second]);
}

#[test]
fn parent_repair_cli_requires_authority_and_cannot_mix_other_repair_modes() {
    assert!(crate::Cli::try_parse_from(["ffs-fat", "repair-parents", "image"]).is_err());
    for flag in ["--reclaim-lost", "--discard-orphan-lfn", "--force"] {
        assert!(crate::Cli::try_parse_from(["ffs-fat", "repair-parents", "image", "--offline-image", flag]).is_err());
    }
    for flag in ["--repair-mirrors-from", "--repair-boot-from", "--salvage-to"] {
        assert!(crate::Cli::try_parse_from(["ffs-fat", "repair-parents", "image", "--offline-image", flag, "0"]).is_err());
    }
    let cli = crate::Cli::try_parse_from([
        "ffs-fat", "repair-parents", "does-not-exist.img", "--offline-image", "--sidecar", "also-not-opened",
    ]).unwrap();
    let crate::Command::RepairParents { options } = cli.command else { panic!("parent repair"); };
    let error = repair_parents(&Cx::for_testing(), &options).unwrap_err().to_string();
    assert!(error.contains("sidecar"));
}
