//! Constructed native-image tests for the boundary BEFORE namespace exposure.
//! Reuse the existing image/device fixtures; these are not native-OS evidence.

use super::*;
use crate::reader::FatTable;

#[derive(Clone, Copy)]
enum Effect {
    DropWrite,
    FailRead,
    CancelAfterSync,
}

struct Fault {
    at: u64,
    expected: Vec<u8>,
    effect: Effect,
    fired: bool,
    cancelled: bool,
}

struct FaultDevice {
    inner: Device,
    fault: Arc<Mutex<Fault>>,
}

impl ByteDevice for FaultDevice {
    fn len_bytes(&self) -> u64 {
        self.inner.len_bytes()
    }

    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        {
            let fault = self.fault.lock().unwrap();
            if fault.fired
                && matches!(fault.effect, Effect::FailRead)
                && at.0 <= fault.at
                && fault.at < at.0 + bytes.len() as u64
            {
                return Err(
                    io::Error::other("injected directory initialization read failure").into(),
                );
            }
        }
        self.inner.read_exact_at(cx, at, bytes)
    }

    fn write_all_at(&self, cx: &Cx, at: ByteOffset, bytes: &[u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        let drop_write = {
            let mut fault = self.fault.lock().unwrap();
            let matches = fault
                .at
                .checked_sub(at.0)
                .and_then(|within| usize::try_from(within).ok())
                .and_then(|within| {
                    within
                        .checked_add(fault.expected.len())
                        .map(|end| (within, end))
                })
                .and_then(|(within, end)| bytes.get(within..end))
                .is_some_and(|actual| actual == fault.expected.as_slice());
            if !fault.fired && matches {
                fault.fired = true;
                matches!(fault.effect, Effect::DropWrite)
            } else {
                false
            }
        };
        if drop_write {
            // Acknowledge a whole dropped sector/cluster write. Later syncs
            // cannot repair it; the production reader must discover the loss.
            return Ok(());
        }
        self.inner.write_all_at(cx, at, bytes)
    }

    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        self.inner.sync(cx)?;
        let mut fault = self.fault.lock().unwrap();
        if fault.fired && !fault.cancelled && matches!(fault.effect, Effect::CancelAfterSync) {
            fault.cancelled = true;
            cx.cancel_with(
                asupersync::types::CancelKind::User,
                Some("directory initialization barrier"),
            );
        }
        Ok(())
    }
}

fn fault_volume(
    image: &Image,
    at: u64,
    expected: &[u8],
    effect: Effect,
) -> (FatVolume, Arc<Mutex<Fault>>) {
    let fault = Arc::new(Mutex::new(Fault {
        at,
        expected: expected.to_vec(),
        effect,
        fired: false,
        cancelled: false,
    }));
    let volume = FatVolume::from_device(
        &Cx::for_testing(),
        Box::new(FaultDevice {
            inner: image.device.clone(),
            fault: Arc::clone(&fault),
        }),
        image.base,
        image.geometry.volume_bytes(),
    )
    .unwrap();
    (volume, fault)
}

fn raw_fat(image: &Image, copy: u8, cluster: u32) -> Vec<u8> {
    image.bytes(
        image.base + image.geometry.entry_offset(copy, cluster).unwrap(),
        image.geometry.kind().entry_bytes() as usize,
    )
}

/// Force actual parent growth, with valid stale bytes in unallocated clusters.
/// FAT16 grows a subdirectory; FAT32 grows its native root. No fake allocator.
fn growth_fixture(kind: FatKind, sector: u32, active: bool) -> (Image, FatVolume, String) {
    let image = Image::new(kind, sector, active);
    let cx = Cx::for_testing();
    let volume = image.volume();
    let (parent, start, first_unused) = if kind == FatKind::Fat16 {
        mkdir_in_volume(&cx, &volume, "/DIR", NOW, false).unwrap();
        let entry = volume.resolve(&cx, "/DIR").unwrap().unwrap();
        (
            "/DIR",
            image.base + volume.cluster_offset(entry.native.first_cluster).unwrap(),
            2,
        )
    } else {
        ("", image.root, 1)
    };
    {
        let mut state = image.device.state.lock().unwrap();
        for index in first_unused..sector / 32 {
            let name: [u8; 11] = format!("N{index:07}BIN").as_bytes().try_into().unwrap();
            state.put(start + u64::from(index) * 32, &short_entry(&name, 0, 0));
        }
        state.persist();
    }
    let mut table = FatTable::new(&volume);
    let mut poisoned = 0;
    for cluster in 2..=image.geometry.cluster_count() + 1 {
        if table.entry(&cx, cluster).unwrap() == FatEntry::Free {
            let mut bytes = vec![0xD6; sector as usize];
            bytes[..32].copy_from_slice(&short_entry(b"STALE   BIN", 5, 4));
            let mut state = image.device.state.lock().unwrap();
            state.put(image.base + volume.cluster_offset(cluster).unwrap(), &bytes);
            state.persist();
            poisoned += 1;
            if poisoned == 2 {
                break;
            }
        }
    }
    assert_eq!(poisoned, 2);
    assert!(volume.check(&cx).unwrap().clean);
    (image, volume, format!("{parent}/{}.TXT", "L".repeat(251)))
}

#[test]
fn verified_growth_reuses_native_paths_and_preserves_active_copy_and_guards() {
    let cx = Cx::for_testing();
    for (kind, active) in [
        (FatKind::Fat16, false),
        (FatKind::Fat32, false),
        (FatKind::Fat32, true),
    ] {
        for sector in [512, 4096] {
            let (image, volume, path) = growth_fixture(kind, sector, active);
            let input = source(&[]);
            let plan = prepare(&cx, &volume, &path, &input, NOW).unwrap();
            let namespace = plan.creation.as_ref().unwrap();
            assert_eq!(
                namespace.directory_clusters(),
                if sector == 512 { 2 } else { 1 }
            );
            let fat0 = image.base + image.geometry.entry_offset(0, 2).unwrap()
                - 2 * u64::from(kind.entry_bytes());
            let inactive = image.bytes(fat0, sector as usize);
            let allocated: Vec<_> = namespace.extension.as_ref().unwrap().clusters().collect();
            let high: Vec<_> = volume
                .copies()
                .flat_map(|copy| allocated.iter().map(move |&cluster| (copy, cluster)))
                .map(|(copy, cluster)| (copy, cluster, raw_fat(&image, copy, cluster)))
                .collect();
            plan.execute(&cx, &volume, &input, || Ok(())).unwrap();
            let reopened = image.volume();
            assert_eq!(contents(&reopened, &path), Vec::<u8>::new());
            assert!(reopened.check(&cx).unwrap().clean);
            for (copy, cluster, before) in high {
                if kind == FatKind::Fat32 {
                    assert_eq!(raw_fat(&image, copy, cluster)[3] & 0xF0, before[3] & 0xF0);
                }
            }
            if active {
                assert_eq!(image.bytes(fat0, sector as usize), inactive);
            }
            image.guards();
        }
    }
}

#[test]
fn dropped_directory_initialization_cannot_attach_poisoned_storage() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for chosen in 0..2 {
            let (image, volume, path) = growth_fixture(kind, 512, false);
            let cx = Cx::for_testing();
            let input = source(&[]);
            let plan = prepare(&cx, &volume, &path, &input, NOW).unwrap();
            let extension = plan.creation.as_ref().unwrap().extension.as_ref().unwrap();
            let clusters: Vec<_> = extension.clusters().collect();
            let tails: Vec<_> = volume
                .copies()
                .map(|copy| raw_fat(&image, copy, extension.tail))
                .collect();
            let at = image.base + volume.cluster_offset(clusters[chosen]).unwrap();
            let (faulted, fault) = fault_volume(&image, at, &[0; 32], Effect::DropWrite);
            let error = plan.execute(&cx, &faulted, &input, || Ok(())).unwrap_err();
            assert!(format!("{error:#}").contains("initialized directory data failed readback"));
            assert!(fault.lock().unwrap().fired);
            let mut table = FatTable::new(&volume);
            for cluster in clusters {
                assert_eq!(table.entry(&cx, cluster).unwrap(), FatEntry::Free);
            }
            for (copy, before) in volume.copies().zip(tails) {
                assert_eq!(raw_fat(&image, copy, extension.tail), before);
            }
            image.guards();
        }
    }
}

#[test]
fn missing_extension_link_in_any_selected_copy_stops_before_old_tail_changes() {
    for active in [false, true] {
        let (image, volume, path) = growth_fixture(FatKind::Fat32, 512, active);
        let cx = Cx::for_testing();
        let input = source(&[]);
        let plan = prepare(&cx, &volume, &path, &input, NOW).unwrap();
        let extension = plan.creation.as_ref().unwrap().extension.as_ref().unwrap();
        let cluster = extension.clusters().last().unwrap();
        let copy = volume.copies().last().unwrap();
        let mut expected: [u8; 4] = raw_fat(&image, copy, cluster).try_into().unwrap();
        let end = (u32::from_le_bytes(expected) & 0xF000_0000) | 0x0FFF_FFFF;
        expected.copy_from_slice(&end.to_le_bytes());
        let tails: Vec<_> = volume
            .copies()
            .map(|c| raw_fat(&image, c, extension.tail))
            .collect();
        let (faulted, fault) = fault_volume(
            &image,
            image.base + image.geometry.entry_offset(copy, cluster).unwrap(),
            &expected,
            Effect::DropWrite,
        );
        let error = plan.execute(&cx, &faulted, &input, || Ok(())).unwrap_err();
        assert!(
            format!("{error:#}").contains("directory extension link failed readback")
                || format!("{error:#}").contains("FAT copies disagree")
        );
        assert!(fault.lock().unwrap().fired);
        for (copy, before) in volume.copies().zip(tails) {
            assert_eq!(raw_fat(&image, copy, extension.tail), before);
        }
        image.guards();
    }
}

#[test]
fn dropped_successor_terminator_keeps_the_old_end_marker_and_ghost_hidden() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let image = Image::new(kind, 512, false);
        let cx = Cx::for_testing();
        let volume = image.volume();
        let input = source(&[]);
        let plan = prepare(&cx, &volume, "/NEW.BIN", &input, NOW).unwrap();
        let successor = plan.creation.as_ref().unwrap().successor.as_ref().unwrap();
        let (faulted, fault) = fault_volume(
            &image,
            image.base + successor.offset,
            &[0; 32],
            Effect::DropWrite,
        );
        assert!(plan.execute(&cx, &faulted, &input, || Ok(())).is_err());
        assert!(fault.lock().unwrap().fired);
        assert_eq!(image.bytes(image.root + 32, 32), [0; 32]);
        assert!(matches!(
            volume.resolve(&cx, "/GHOST.BIN"),
            Err(FfsError::NotFound(_))
        ));
        assert!(matches!(
            volume.resolve(&cx, "/NEW.BIN"),
            Err(FfsError::NotFound(_))
        ));
        image.guards();
    }
}

#[test]
fn dropped_hidden_tombstones_do_not_consume_an_end_marker_inside_a_deleted_run() {
    let name = "/A long filename crossing several native slots.txt";
    for marker_in_middle in [false, true] {
        for target_short in [false, true] {
            let image = Image::new(FatKind::Fat16, 512, false);
            if marker_in_middle {
                let mut state = image.device.state.lock().unwrap();
                state.put(image.root + 32, &deleted_slot());
                state.put(image.root + 64, &[0; 32]);
                state.persist();
            }
            let cx = Cx::for_testing();
            let volume = image.volume();
            let input = source(&[]);
            let probe = prepare(&cx, &volume, name, &input, NOW).unwrap();
            let ns = probe.creation.as_ref().unwrap();
            let hidden = if target_short {
                ns.entry.offset
            } else {
                ns.long_slots[2].offset
            };
            {
                let mut state = image.device.state.lock().unwrap();
                state.put(image.base + hidden, &short_entry(b"GHOST   BIN", 5, 4));
                state.persist();
            }
            let plan = prepare(&cx, &volume, name, &input, NOW).unwrap();
            let (faulted, fault) = fault_volume(
                &image,
                image.base + hidden,
                &deleted_slot(),
                Effect::DropWrite,
            );
            assert!(plan.execute(&cx, &faulted, &input, || Ok(())).is_err());
            assert!(fault.lock().unwrap().fired);
            let marker = image.root + if marker_in_middle { 64 } else { 32 };
            assert_eq!(image.bytes(marker, 1), [0]);
            assert!(matches!(
                volume.resolve(&cx, "/GHOST.BIN"),
                Err(FfsError::NotFound(_))
            ));
            image.guards();
        }
    }
}

#[test]
fn mkdir_initialization_and_allocation_are_verified_before_the_parent_entry() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for lose_allocation in [false, true] {
            let image = Image::new(kind, 512, false);
            let cx = Cx::for_testing();
            let volume = image.volume();
            let plan = mkdir::DirectoryCreation::prepare(&cx, &volume, "/NEWDIR", NOW).unwrap();
            let cluster = plan.directory_cluster;
            let start = image.base + volume.cluster_offset(cluster).unwrap();
            {
                let mut state = image.device.state.lock().unwrap();
                state.put(start, &[0xD6; 512]);
                state.persist();
            }
            let (at, expected) = if lose_allocation {
                let copy = volume.copies().last().unwrap();
                let old = raw_fat(&image, copy, cluster);
                let mut bytes = [0; 4];
                bytes[..old.len()].copy_from_slice(&old);
                let mask = if kind == FatKind::Fat16 {
                    0xFFFF
                } else {
                    0x0FFF_FFFF
                };
                let raw = (u32::from_le_bytes(bytes) & !mask) | mask;
                (
                    image.base + image.geometry.entry_offset(copy, cluster).unwrap(),
                    raw.to_le_bytes()[..old.len()].to_vec(),
                )
            } else {
                (start, b".          ".to_vec())
            };
            let (faulted, fault) = fault_volume(&image, at, &expected, Effect::DropWrite);
            assert!(plan.execute(&cx, &faulted).is_err());
            assert!(fault.lock().unwrap().fired);
            assert!(matches!(
                volume.resolve(&cx, "/NEWDIR"),
                Err(FfsError::NotFound(_))
            ));
            if !lose_allocation {
                assert_eq!(
                    FatTable::new(&volume).entry(&cx, cluster).unwrap(),
                    FatEntry::Free
                );
            }
            image.guards();
        }
    }
}

#[test]
fn initialization_read_error_and_cancellation_stop_before_reachability() {
    for effect in [Effect::FailRead, Effect::CancelAfterSync] {
        let (image, volume, path) = growth_fixture(FatKind::Fat32, 4096, false);
        let cx = Cx::for_testing();
        let input = source(&[]);
        let plan = prepare(&cx, &volume, &path, &input, NOW).unwrap();
        let ext = plan.creation.as_ref().unwrap().extension.as_ref().unwrap();
        let at = image.base + volume.cluster_offset(ext.cluster).unwrap();
        let (faulted, fault) = fault_volume(&image, at, &[0; 32], effect);
        assert!(plan.execute(&cx, &faulted, &input, || Ok(())).is_err());
        assert!(fault.lock().unwrap().fired);
        let fresh = Cx::for_testing();
        assert_eq!(
            FatTable::new(&volume).entry(&fresh, ext.cluster).unwrap(),
            FatEntry::Free
        );
        assert_eq!(
            FatTable::new(&volume).entry(&fresh, ext.tail).unwrap(),
            FatEntry::End
        );
        image.guards();
    }
}

#[test]
fn directory_initialization_rejects_invalid_reservations_without_io() {
    let image = Image::new(FatKind::Fat16, 512, false);
    let volume = image.volume();
    let cx = Cx::for_testing();
    for clusters in [vec![], vec![2, 2], vec![2, 3, 4], vec![2, u32::MAX]] {
        assert!(initialize_directory(&cx, &volume, &clusters.into_iter(), &[0; 512]).is_err());
    }
    assert!(initialize_directory(&cx, &volume, &std::iter::once(2), &[0; 511]).is_err());
    assert_eq!(image.device.state.lock().unwrap().operations, 0);
    image.guards();
}

#[test]
fn dropped_tail_attachment_stops_before_long_name_staging() {
    let (image, volume, path) = growth_fixture(FatKind::Fat32, 512, false);
    let cx = Cx::for_testing();
    let input = source(&[]);
    let plan = prepare(&cx, &volume, &path, &input, NOW).unwrap();
    let namespace = plan.creation.as_ref().unwrap();
    let ext = namespace.extension.as_ref().unwrap();
    let copy = volume.copies().last().unwrap();
    let old: [u8; 4] = raw_fat(&image, copy, ext.tail).try_into().unwrap();
    let expected = ((u32::from_le_bytes(old) & 0xF000_0000) | ext.cluster).to_le_bytes();
    let (faulted, fault) = fault_volume(
        &image,
        image.base + image.geometry.entry_offset(copy, ext.tail).unwrap(),
        &expected,
        Effect::DropWrite,
    );
    assert!(plan.execute(&cx, &faulted, &input, || Ok(())).is_err());
    assert!(fault.lock().unwrap().fired);
    // Some mirrors can now contain the attachment: rollback is not claimed.
    // Nevertheless no namespace record has been staged in the new storage.
    for slot in namespace
        .long_slots
        .iter()
        .chain(std::iter::once(&namespace.entry))
    {
        assert_eq!(image.bytes(image.base + slot.offset, 32), [0; 32]);
    }
    image.guards();
}
