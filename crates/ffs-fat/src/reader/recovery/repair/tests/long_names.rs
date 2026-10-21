//! Interrupted native namespace recovery, using the existing real formatter,
//! reader/checker and pending/durable fault device. No native-OS proof implied.

use super::*;
use ffs_ondisk::fat::{FatGeometry, short_name_checksum};

fn root(geometry: &FatGeometry) -> u64 {
    geometry.fixed_root().map_or_else(
        || geometry.cluster_offset(geometry.root_cluster()).unwrap(),
        |(start, _)| start,
    )
}

fn encoded(text: &str, short: &[u8; 11]) -> Vec<[u8; 32]> {
    let units: Vec<_> = text.encode_utf16().collect();
    let count = units.len().div_ceil(13);
    (1..=count)
        .rev()
        .map(|ordinal| {
            let mut slot = [0; 32];
            slot[0] = ordinal as u8 | if ordinal == count { 0x40 } else { 0 };
            slot[11] = 0x0F;
            slot[13] = short_name_checksum(short);
            for (index, at) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
                .into_iter()
                .enumerate()
            {
                let index = (ordinal - 1) * 13 + index;
                let value = units
                    .get(index)
                    .copied()
                    .unwrap_or(if index == units.len() { 0 } else { 0xFFFF });
                slot[at..at + 2].copy_from_slice(&value.to_le_bytes());
            }
            slot
        })
        .collect()
}

fn plant(image: &ImageArgs, geometry: &FatGeometry, deleted: bool) -> Vec<u64> {
    let records = encoded("Unpublished long name.txt", b"UNPUBL~1TXT");
    assert_eq!(records.len(), 2);
    let start = root(geometry) + 32;
    let mut offsets = Vec::new();
    for (index, record) in records.iter().enumerate() {
        let offset = start + index as u64 * 32;
        patch(image, offset, record);
        offsets.push(offset);
    }
    let mut terminal = [0; 32];
    if deleted {
        terminal[0] = 0xE5;
    }
    patch(image, start + records.len() as u64 * 32, &terminal);
    patch(image, start + (records.len() as u64 + 1) * 32, &[0; 32]);
    offsets
}

fn options(image: ImageArgs) -> RecoverArgs {
    RecoverArgs {
        image,
        offline_image: true,
        reclaim_lost: false,
        discard_orphan_lfn: true,
        repair_mirrors_from: None,
        repair_boot_from: None,
        salvage_to: None,
        dry_run: false,
    }
}

fn assert_retired(before: &[u8], after: &[u8], base: u64, offsets: &[u64]) {
    for &offset in offsets {
        let at = (base + offset) as usize;
        assert_eq!(after[at], 0xE5);
        assert_eq!(
            &after[at + 1..at + 32],
            &before[at + 1..at + 32],
            "retain raw name evidence"
        );
    }
}

#[test]
fn explicit_cleanup_preserves_live_files_and_does_not_authorize_lost_cluster_reclaim() {
    for kind in ["fat16", "fat32"] {
        for deleted in [false, true] {
            let (_directory, image, geometry) = populated(kind);
            let offsets = plant(&image, &geometry, deleted);
            orphan(&image, &geometry);
            let before = fs::read(&image.image).unwrap();
            let cx = Cx::for_testing();
            let mut args = options(image);
            assert!(
                recover(&cx, &args).is_err(),
                "name cleanup cannot authorize data discard"
            );
            args.reclaim_lost = true;
            args.discard_orphan_lfn = false;
            assert!(
                recover(&cx, &args).is_err(),
                "cluster discard cannot authorize name cleanup"
            );
            assert_eq!(fs::read(&args.image.image).unwrap(), before);
            args.discard_orphan_lfn = true;
            args.dry_run = true;
            let dry = recover(&cx, &args).unwrap();
            assert_eq!(dry["planned_retired_lfn_records"], 2);
            assert_eq!(dry["planned_reclaimed_clusters"], 3);
            assert_eq!(fs::read(&args.image.image).unwrap(), before);
            args.dry_run = false;
            let report = recover(&cx, &args).unwrap();
            assert_eq!(report["retired_lfn_records"], 2);
            assert_eq!(report["verification"]["clean"], true);
            let after = fs::read(&args.image.image).unwrap();
            assert_retired(&before, &after, 0, &offsets);
            let at = root(&geometry) as usize;
            assert_eq!(&after[at..at + 32], &before[at..at + 32]);
            retained(&cx, &args.image.open(&cx).unwrap());
            assert_eq!(recover(&cx, &args).unwrap()["changed"], false);
            assert_eq!(fs::read(&args.image.image).unwrap(), after);
        }
    }
}

#[test]
fn cleanup_rejects_corrupt_names_attached_to_live_entries_without_any_write() {
    for kind in ["fat16", "fat32"] {
        for unsafe_component in [false, true] {
            let (_directory, image, geometry) = populated(kind);
            let cx = Cx::for_testing();
            let volume = crate::reader::replacement::open_volume(&cx, &image, true).unwrap();
            crate::reader::replacement::create_in_volume(
                &cx,
                &volume,
                "/Live long name.txt",
                b"must keep",
                NOW,
                false,
            )
            .unwrap();
            let entry = volume.resolve(&cx, "/Live long name.txt").unwrap().unwrap();
            drop(volume);
            if unsafe_component {
                // Ordinal one, directly preceding the short record, changes the
                // first Unicode character without changing the valid checksum.
                patch(
                    &image,
                    entry.offset - 32 + 1,
                    &u16::from(b'/').to_le_bytes(),
                );
            } else {
                patch(
                    &image,
                    entry.offset - 32 + 13,
                    &[short_name_checksum(&entry.native.short_name) ^ 1],
                );
            }
            let before = fs::read(&image.image).unwrap();
            let device = fault_device(&before, None, 0);
            let diagnostic =
                DiagnosticVolume::from_device(&cx, Box::new(device.clone()), &image).unwrap();
            assert!(
                diagnostic
                    .report(&cx)
                    .unwrap()
                    .issues
                    .iter()
                    .any(|issue| issue.kind == "invalid_long_name")
            );
            assert!(Plan::prepare(&cx, &diagnostic, true, true).is_err());
            assert_eq!(device.0.lock().unwrap().operations, 0);
            assert_eq!(device.0.lock().unwrap().pending, before);
            assert_eq!(root(&geometry), root(&diagnostic.volume.geometry));
        }
    }
}

#[test]
fn full_root_tail_is_recoverable_but_records_after_end_marker_are_not_touched() {
    let (_directory, image, geometry) = populated("fat16");
    let (start, length) = geometry.fixed_root().unwrap();
    let mut deleted = [0; 32];
    deleted[0] = 0xE5;
    for at in (start + 32..start + length).step_by(32) {
        patch(&image, at, &deleted);
    }
    let records = encoded("Orphan at allocation end", b"ORPHAN~1TXT");
    let offsets: Vec<_> = (0..records.len())
        .map(|index| start + length - (records.len() - index) as u64 * 32)
        .collect();
    for (&offset, record) in offsets.iter().zip(&records) {
        patch(&image, offset, record);
    }
    let before = fs::read(&image.image).unwrap();
    let args = options(image);
    let cx = Cx::for_testing();
    assert_eq!(recover(&cx, &args).unwrap()["retired_lfn_records"], 2);
    let after = fs::read(&args.image.image).unwrap();
    assert_retired(&before, &after, 0, &offsets);
    retained(&cx, &args.image.open(&cx).unwrap());

    let (_directory, image, geometry) = populated("fat16");
    patch(&image, root(&geometry) + 64, &records[0]); // hidden behind the end at +32
    let before = fs::read(&image.image).unwrap();
    let args = options(image);
    assert_eq!(recover(&cx, &args).unwrap()["changed"], false);
    assert_eq!(fs::read(&args.image.image).unwrap(), before);
}

#[test]
fn fragmented_fat32_lfn_cleanup_respects_logical_order_active_copy_and_volume_bounds() {
    let (directory, mut image, geometry) = populated("fat32");
    let first = geometry.root_cluster();
    for copy in 0..geometry.fat_count() {
        fat(&image, &geometry, copy, first, 500);
        fat(&image, &geometry, copy, 500, 200);
        fat(&image, &geometry, copy, 200, 0x0FFF_FFFF);
    }
    let mut deleted = [0; 32];
    deleted[0] = 0xE5;
    for cluster in [first, 500, 200] {
        let start = geometry.cluster_offset(cluster).unwrap();
        for index in 0..geometry.cluster_bytes() / 32 {
            if cluster == first && index == 0 {
                continue;
            }
            patch(&image, start + u64::from(index) * 32, &deleted);
        }
    }
    let records = encoded("Orphan spanning fragments", b"ORPHAN~1TXT");
    let offsets = [
        geometry.cluster_offset(500).unwrap() + u64::from(geometry.cluster_bytes()) - 32,
        geometry.cluster_offset(200).unwrap(),
    ];
    assert!(offsets[0] > offsets[1]);
    for (&offset, record) in offsets.iter().zip(&records) {
        patch(&image, offset, record);
    }
    patch(&image, offsets[1] + 64, &[0; 32]);
    for sector in std::iter::once(0_u16).chain(geometry.backup_boot_sector()) {
        patch(
            &image,
            u64::from(sector) * u64::from(geometry.sector_bytes()) + 40,
            &0x0081_u16.to_le_bytes(),
        );
    }
    fat(&image, &geometry, 0, 0, 0); // inactive garbage is not authority
    let native = fs::read(&image.image).unwrap();
    let mut disk = vec![0xAA; 4096];
    disk.extend_from_slice(&native);
    disk.extend_from_slice(&[0x55; 4096]);
    image.image = directory.path().join("bounded.img");
    image.offset = 4096;
    image.length = Some(native.len() as u64);
    fs::write(&image.image, &disk).unwrap();
    let args = options(image);
    assert_eq!(
        recover(&Cx::for_testing(), &args).unwrap()["retired_lfn_records"],
        2
    );
    let after = fs::read(&args.image.image).unwrap();
    assert_eq!(&after[..4096], &disk[..4096]);
    assert_eq!(&after[4096 + native.len()..], &disk[4096 + native.len()..]);
    let fat0 = 4096 + (geometry.entry_offset(0, 2).unwrap() - 8) as usize;
    let fat1 = 4096 + (geometry.entry_offset(1, 2).unwrap() - 8) as usize;
    assert_eq!(&after[fat0..fat1], &disk[fat0..fat1]);
    assert_retired(&disk, &after, 4096, &offsets);
    retained(
        &Cx::for_testing(),
        &args.image.open(&Cx::for_testing()).unwrap(),
    );
}

#[test]
fn changed_terminal_or_retained_metadata_invalidates_the_plan_before_dirty_publication() {
    for terminal in [false, true] {
        let (_directory, image, geometry) = populated("fat16");
        plant(&image, &geometry, true);
        let before = fs::read(&image.image).unwrap();
        let device = fault_device(&before, None, 0);
        let cx = Cx::for_testing();
        let diagnostic =
            DiagnosticVolume::from_device(&cx, Box::new(device.clone()), &image).unwrap();
        let plan = Plan::prepare(&cx, &diagnostic, false, true).unwrap();
        {
            let mut state = device.0.lock().unwrap();
            let offset = root(&geometry) as usize;
            if terminal {
                state.pending[offset + 96..offset + 128].fill(0);
                state.pending[offset + 96..offset + 107].copy_from_slice(b"NEW     TXT");
                state.pending[offset + 107] = 0x20;
            } else {
                state.pending[offset + 13] ^= 1; // retained live metadata in same sector
            }
        }
        let changed = device.0.lock().unwrap().pending.clone();
        assert!(plan.execute(&cx, &diagnostic).is_err());
        assert_eq!(device.0.lock().unwrap().operations, 0);
        assert_eq!(device.0.lock().unwrap().pending, changed);
    }
}

#[test]
fn every_cleanup_write_sync_cut_preserves_live_data_and_can_be_retried_when_unambiguous() {
    let (_directory, image, geometry) = populated("fat16");
    let offsets = plant(&image, &geometry, true);
    orphan(&image, &geometry);
    let baseline = fs::read(&image.image).unwrap();
    let cx = Cx::for_testing();
    let control = fault_device(&baseline, None, 0);
    let diagnostic = DiagnosticVolume::from_device(&cx, Box::new(control.clone()), &image).unwrap();
    Plan::prepare(&cx, &diagnostic, true, true)
        .unwrap()
        .execute(&cx, &diagnostic)
        .unwrap();
    let operations = control.0.lock().unwrap().operations;
    assert!(operations > 4);
    let mut retried = 0;
    let mut refused_mirrors = 0;
    for cut in 1..=operations {
        for tear in [0, 1, 31, 511, 512] {
            let device = fault_device(&baseline, Some(cut), tear);
            let diagnostic =
                DiagnosticVolume::from_device(&cx, Box::new(device.clone()), &image).unwrap();
            let plan = Plan::prepare(&cx, &diagnostic, true, true).unwrap();
            assert!(
                plan.execute(&cx, &diagnostic).is_err(),
                "cut {cut}, tear {tear}"
            );
            assert_eq!(device.0.lock().unwrap().operations, cut);
            for pending in [false, true] {
                let bytes = {
                    let state = device.0.lock().unwrap();
                    if pending {
                        state.pending.clone()
                    } else {
                        state.durable.clone()
                    }
                };
                let restarted = fault_device(&bytes, None, 0);
                let diagnostic =
                    DiagnosticVolume::from_device(&cx, Box::new(restarted.clone()), &image)
                        .unwrap();
                retained(&cx, &diagnostic.volume);
                if diagnostic.report(&cx).unwrap().conflicting_clusters != 0 {
                    // Reclamation can stop between FAT copies. Name cleanup
                    // must NEVER manufacture an authoritative mirror choice.
                    assert!(Plan::prepare(&cx, &diagnostic, true, true).is_err());
                    assert_eq!(restarted.0.lock().unwrap().operations, 0);
                    assert_eq!(restarted.0.lock().unwrap().pending, bytes);
                    refused_mirrors += 1;
                    continue;
                }
                let plan = Plan::prepare(&cx, &diagnostic, true, true).unwrap();
                let repaired = plan.execute(&cx, &diagnostic).unwrap();
                assert!(repaired["changed"] == false || repaired["verification"]["clean"] == true);
                assert!(diagnostic.report(&cx).unwrap().clean);
                retained(&cx, &diagnostic.volume);
                assert_retired(&baseline, &restarted.0.lock().unwrap().pending, 0, &offsets);
                retried += 1;
            }
        }
    }
    assert!(retried > 0 && refused_mirrors > 0);
}

#[test]
fn interrupted_native_lfn_creation_can_recover_without_touching_acknowledged_files() {
    let (_directory, image, _geometry) = populated("fat16");
    let initial = fs::read(&image.image).unwrap();
    let cx = Cx::for_testing();
    let create = |device: FaultDevice| {
        let volume =
            FatVolume::from_device(&cx, Box::new(device), 0, initial.len() as u64).unwrap();
        crate::reader::replacement::create_in_volume(
            &cx,
            &volume,
            "/Interrupted native creation.txt",
            b"unacknowledged",
            NOW,
            false,
        )
    };
    let control = fault_device(&initial, None, 0);
    create(control.clone()).unwrap();
    let operations = control.0.lock().unwrap().operations;
    let mut recovered = 0;
    for cut in 1..=operations {
        let device = fault_device(&initial, Some(cut), 0);
        assert!(create(device.clone()).is_err());
        for pending in [false, true] {
            let bytes = {
                let state = device.0.lock().unwrap();
                if pending {
                    state.pending.clone()
                } else {
                    state.durable.clone()
                }
            };
            let restarted = fault_device(&bytes, None, 0);
            let diagnostic =
                DiagnosticVolume::from_device(&cx, Box::new(restarted.clone()), &image).unwrap();
            let before = diagnostic.report(&cx).unwrap();
            if !before
                .issues
                .iter()
                .any(|issue| issue.kind == "invalid_long_name")
            {
                continue;
            }
            // These are actual incomplete name publications produced by the
            // writer, not hand-built corruption presented as native execution.
            assert_eq!(before.files, 1);
            let plan = Plan::prepare(&cx, &diagnostic, true, true).unwrap();
            assert!(plan.orphan_names.count() > 0);
            assert_eq!(
                plan.execute(&cx, &diagnostic).unwrap()["verification"]["clean"],
                true
            );
            retained(&cx, &diagnostic.volume);
            assert!(matches!(
                diagnostic
                    .volume
                    .resolve(&cx, "/Interrupted native creation.txt"),
                Err(FfsError::NotFound(_))
            ));
            recovered += 1;
        }
    }
    assert!(
        recovered > 0,
        "must actually exercise the writer's orphan-LFN interval"
    );
}

struct NameFault {
    inner: FaultDevice,
    sector: u64,
    drop_write: bool,
    changed: std::sync::atomic::AtomicBool,
}

impl ByteDevice for NameFault {
    fn len_bytes(&self) -> u64 {
        self.inner.len_bytes()
    }
    fn read_exact_at(
        &self,
        cx: &Cx,
        offset: ByteOffset,
        bytes: &mut [u8],
    ) -> ffs_error::Result<()> {
        self.inner.read_exact_at(cx, offset, bytes)
    }
    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, bytes: &[u8]) -> ffs_error::Result<()> {
        if offset.0 == self.sector {
            self.changed
                .store(true, std::sync::atomic::Ordering::Release);
            if self.drop_write {
                return Ok(());
            }
        }
        self.inner.write_all_at(cx, offset, bytes)
    }
    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        if !self.drop_write
            && self
                .changed
                .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            // Corrupt a neighbor AFTER the per-sector readback, at its sync.
            self.inner.0.lock().unwrap().pending[self.sector as usize + 13] ^= 1;
        }
        self.inner.sync(cx)
    }
}

#[test]
fn dropped_tombstone_and_post_readback_neighbor_damage_block_cluster_reclamation() {
    for drop_write in [false, true] {
        let (_directory, image, geometry) = populated("fat16");
        plant(&image, &geometry, true);
        orphan(&image, &geometry);
        let initial = fs::read(&image.image).unwrap();
        let device = fault_device(&initial, None, 0);
        let cx = Cx::for_testing();
        let diagnostic = DiagnosticVolume::from_device(
            &cx,
            Box::new(NameFault {
                inner: device.clone(),
                sector: root(&geometry),
                drop_write,
                changed: std::sync::atomic::AtomicBool::new(false),
            }),
            &image,
        )
        .unwrap();
        let plan = Plan::prepare(&cx, &diagnostic, true, true).unwrap();
        assert!(plan.execute(&cx, &diagnostic).is_err());
        let mut table = FatTable::new(&diagnostic.volume);
        assert_eq!(table.entry(&cx, 100).unwrap(), FatEntry::Next(101));
        assert_eq!(table.entry(&cx, 101).unwrap(), FatEntry::End);
        assert_eq!(table.entry(&cx, 102).unwrap(), FatEntry::Next(102));
        retained(&cx, &diagnostic.volume);
        assert!(!diagnostic.report(&cx).unwrap().clean);
    }
}

#[test]
fn bounded_name_recovery_cancellation_and_authority_conflicts_are_zero_write_refusals() {
    let (directory, image, geometry) = populated("fat16");
    let slot = encoded("Orphan", b"ORPHAN~1TXT")[0];
    for index in 0..21 {
        patch(&image, root(&geometry) + 32 + index * 32, &slot);
    }
    let initial = fs::read(&image.image).unwrap();
    let device = fault_device(&initial, None, 0);
    let cx = Cx::for_testing();
    let diagnostic = DiagnosticVolume::from_device(&cx, Box::new(device.clone()), &image).unwrap();
    assert!(Plan::prepare(&cx, &diagnostic, true, true).is_err());
    assert_eq!(device.0.lock().unwrap().operations, 0);
    cx.set_cancel_requested(true);
    assert!(Plan::prepare(&cx, &diagnostic, true, true).is_err());
    let mut args = options(image);
    args.salvage_to = Some(directory.path().join("must-not-exist"));
    assert!(recover(&Cx::for_testing(), &args).is_err());
    assert!(!args.salvage_to.as_ref().unwrap().exists());
    assert_eq!(fs::read(&args.image.image).unwrap(), initial);
    assert!(
        crate::Cli::try_parse_from([
            "ffs-fat",
            "recover",
            "image",
            "--offline-image",
            "--discard-orphan-lfn",
            "--salvage-to",
            "output",
        ])
        .is_err()
    );
    let parsed = crate::Cli::try_parse_from([
        "ffs-fat",
        "recover",
        "image",
        "--offline-image",
        "--discard-orphan-lfn",
        "--dry-run",
    ])
    .unwrap();
    let crate::Command::Recover { options } = parsed.command else {
        panic!("expected recover");
    };
    assert!(options.discard_orphan_lfn && options.dry_run && !options.reclaim_lost);
}
