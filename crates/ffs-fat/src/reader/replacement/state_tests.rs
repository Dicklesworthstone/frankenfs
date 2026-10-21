//! Constructed FAT images and a pending/durable fault device. These exercise
//! the shared native writer, not hardware atomicity or native-system recovery.

use super::*;
use asupersync::types::CancelKind;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

type Pages = BTreeMap<u64, [u8; 512]>;
const NOW: u64 = 1_700_000_000;
const PAYLOAD: &[u8] = b"keep acknowledged contents";

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Read(u64, usize),
    Write(u64, usize),
    Sync,
}

#[derive(Default)]
struct Disk {
    current: Pages,
    durable: Pages,
    events: Vec<Event>,
    operations: usize,
    fail_at: Option<usize>,
    tear: usize,
    drop_writes: BTreeSet<u64>,
    corrupt_at_sync: Option<u64>,
    fail_readback: bool,
    cancel_at_sync: bool,
    synced: bool,
}

impl Disk {
    fn read(&self, mut offset: u64, mut bytes: &mut [u8]) {
        while !bytes.is_empty() {
            let within = (offset % 512) as usize;
            let count = bytes.len().min(512 - within);
            if let Some(page) = self.current.get(&(offset / 512)) {
                bytes[..count].copy_from_slice(&page[within..within + count]);
            } else {
                bytes[..count].fill(0);
            }
            offset += count as u64;
            bytes = &mut bytes[count..];
        }
    }

    fn put(&mut self, mut offset: u64, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let number = offset / 512;
            let within = (offset % 512) as usize;
            let count = bytes.len().min(512 - within);
            let mut page = self.current.get(&number).copied().unwrap_or([0; 512]);
            page[within..within + count].copy_from_slice(&bytes[..count]);
            if page == [0; 512] {
                self.current.remove(&number);
            } else {
                self.current.insert(number, page);
            }
            offset += count as u64;
            bytes = &bytes[count..];
        }
    }

    fn reset(&mut self, pages: &Pages) {
        *self = Self {
            current: pages.clone(),
            durable: pages.clone(),
            ..Self::default()
        };
    }

    fn writes(&self) -> usize {
        self.events
            .iter()
            .filter(|event| matches!(event, Event::Write(..)))
            .count()
    }
}

struct Device {
    disk: Arc<Mutex<Disk>>,
    length: u64,
}

impl ByteDevice for Device {
    fn len_bytes(&self) -> u64 {
        self.length
    }

    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        assert!(
            at.0.checked_add(bytes.len() as u64)
                .is_some_and(|end| end <= self.length)
        );
        let mut disk = self.disk.lock().unwrap();
        disk.events.push(Event::Read(at.0, bytes.len()));
        if disk.fail_readback && disk.synced {
            return Err(std::io::Error::other("injected state readback failure").into());
        }
        disk.read(at.0, bytes);
        drop(disk);
        checkpoint(cx)
    }

    fn write_all_at(&self, cx: &Cx, at: ByteOffset, bytes: &[u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        assert!(
            at.0.checked_add(bytes.len() as u64)
                .is_some_and(|end| end <= self.length)
        );
        let mut disk = self.disk.lock().unwrap();
        disk.events.push(Event::Write(at.0, bytes.len()));
        disk.operations += 1;
        let fail = disk.fail_at == Some(disk.operations);
        let count = if fail {
            disk.tear.min(bytes.len())
        } else {
            bytes.len()
        };
        if !disk.drop_writes.contains(&at.0) {
            disk.put(at.0, &bytes[..count]);
        }
        if fail {
            return Err(std::io::Error::other("injected state write failure").into());
        }
        Ok(())
    }

    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        let mut disk = self.disk.lock().unwrap();
        disk.events.push(Event::Sync);
        disk.operations += 1;
        if disk.fail_at == Some(disk.operations) {
            return Err(std::io::Error::other("injected state flush failure").into());
        }
        if let Some(offset) = disk.corrupt_at_sync.take() {
            let mut byte = [0];
            disk.read(offset, &mut byte);
            byte[0] ^= 0x40;
            disk.put(offset, &byte);
        }
        disk.durable = disk.current.clone();
        disk.synced = true;
        let cancel = disk.cancel_at_sync;
        drop(disk);
        if cancel {
            cx.cancel_with(CancelKind::User, Some("state publication sync"));
        }
        Ok(())
    }
}

fn fixture(kind: FatKind, sector: u32, active: bool) -> (FatVolume, Arc<Mutex<Disk>>) {
    let cx = Cx::for_testing();
    let clusters = if kind == FatKind::Fat16 {
        5_000_u32
    } else {
        70_000
    };
    let reserved = if kind == FatKind::Fat16 { 1_u16 } else { 32 };
    let root_entries = if kind == FatKind::Fat16 { 512_u16 } else { 0 };
    let fat_sectors = ((u64::from(clusters) + 2) * u64::from(kind.entry_bytes()))
        .div_ceil(u64::from(sector)) as u32;
    let total = u32::from(reserved)
        + 2 * fat_sectors
        + (u32::from(root_entries) * 32).div_ceil(sector)
        + clusters;
    let length = u64::from(total) * u64::from(sector);
    let base = u64::from(sector);
    let mut boot = [0; 512];
    boot[..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
    boot[3..11].copy_from_slice(b"MSWIN4.1");
    boot[11..13].copy_from_slice(&(sector as u16).to_le_bytes());
    boot[13] = 1;
    boot[14..16].copy_from_slice(&reserved.to_le_bytes());
    boot[16] = 2;
    boot[17..19].copy_from_slice(&root_entries.to_le_bytes());
    boot[21] = 0xF8;
    boot[32..36].copy_from_slice(&total.to_le_bytes());
    if kind == FatKind::Fat16 {
        boot[22..24].copy_from_slice(&(fat_sectors as u16).to_le_bytes());
    } else {
        boot[36..40].copy_from_slice(&fat_sectors.to_le_bytes());
        boot[40..42].copy_from_slice(&(if active { 0x81_u16 } else { 0 }).to_le_bytes());
        boot[44..48].copy_from_slice(&2_u32.to_le_bytes());
        boot[48..50].copy_from_slice(&1_u16.to_le_bytes());
        boot[50..52].copy_from_slice(&6_u16.to_le_bytes());
    }
    boot[510..].copy_from_slice(&[0x55, 0xAA]);
    let geometry = FatGeometry::parse(&boot, length).unwrap();
    let mut disk = Disk::default();
    disk.put(0, &[0xA5; 512]);
    disk.put(base + length, &[0x5A; 512]);
    disk.put(base, &boot);
    if kind == FatKind::Fat32 {
        disk.put(base + 6 * u64::from(sector), &boot);
        let mut info = [0; 512];
        info[..4].copy_from_slice(&0x4161_5252_u32.to_le_bytes());
        info[484..488].copy_from_slice(&0x6141_7272_u32.to_le_bytes());
        info[488..492].copy_from_slice(&(clusters - 1).to_le_bytes());
        info[492..496].copy_from_slice(&u32::MAX.to_le_bytes());
        info[508..512].copy_from_slice(&0xAA55_0000_u32.to_le_bytes());
        disk.put(base + u64::from(sector), &info);
    }
    for copy in 0..2 {
        let start =
            base + geometry.entry_offset(copy, 2).unwrap() - 2 * u64::from(kind.entry_bytes());
        if kind == FatKind::Fat16 {
            disk.put(start, &[0xF8, 0xFF, 0xFF, 0xFF]);
        } else {
            // Different reserved high nibbles in each copy remain untouched.
            let high = (0xA + u32::from(copy)) << 28;
            disk.put(start, &(high | 0x0FFF_FFF8).to_le_bytes());
            disk.put(start + 4, &(high | 0x0FFF_FFFF).to_le_bytes());
            disk.put(start + 8, &0x0FFF_FFFF_u32.to_le_bytes());
        }
    }
    disk.durable = disk.current.clone();
    let disk = Arc::new(Mutex::new(disk));
    let volume = FatVolume::from_device(
        &cx,
        Box::new(Device {
            disk: Arc::clone(&disk),
            length: base + length + u64::from(sector),
        }),
        base,
        length,
    )
    .unwrap();
    create_in_volume(&cx, &volume, "/KEEP.BIN", PAYLOAD, NOW, false).unwrap();
    let pages = disk.lock().unwrap().current.clone();
    disk.lock().unwrap().reset(&pages);
    (volume, disk)
}

fn state_offsets(volume: &FatVolume) -> Vec<u64> {
    let geometry = &volume.geometry;
    std::iter::once(0_u16)
        .chain(geometry.backup_boot_sector())
        .map(|number| volume.base + u64::from(number) * u64::from(geometry.sector_bytes()))
        .chain(volume.copies().map(|copy| {
            volume.base + geometry.entry_offset(copy, 2).unwrap()
                - 2 * u64::from(geometry.kind().entry_bytes())
        }))
        .collect()
}

fn payload(volume: &FatVolume) -> Vec<u8> {
    let cx = Cx::for_testing();
    let entry = volume.resolve(&cx, "/KEEP.BIN").unwrap().unwrap();
    let chain = volume.file_chain(&cx, &entry).unwrap();
    volume.read(&cx, &chain, 0, PAYLOAD.len()).unwrap()
}

#[test]
fn state_roundtrip_syncs_then_verifies_complete_sectors_and_preserves_native_bytes() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for sector in [512, 4096] {
            for active in [false, true] {
                if active && kind == FatKind::Fat16 {
                    continue;
                }
                let (volume, disk) = fixture(kind, sector, active);
                let original = disk.lock().unwrap().current.clone();
                let offsets = state_offsets(&volume);
                for dirty in [true, false] {
                    disk.lock().unwrap().events.clear();
                    set_dirty(&Cx::for_testing(), &volume, dirty).unwrap();
                    let state = disk.lock().unwrap();
                    let first = state
                        .events
                        .iter()
                        .position(|event| matches!(event, Event::Write(..)))
                        .unwrap();
                    let mut expected: Vec<_> = offsets
                        .iter()
                        .map(|&at| Event::Write(at, sector as usize))
                        .collect();
                    expected.push(Event::Sync);
                    expected.extend(offsets.iter().map(|&at| Event::Read(at, sector as usize)));
                    assert_eq!(&state.events[first..], expected);
                    assert_eq!(state.current, state.durable);
                }
                assert_eq!(disk.lock().unwrap().current, original);
                validate_boot_state(&Cx::for_testing(), &volume).unwrap();
                assert_eq!(payload(&volume), PAYLOAD);
            }
        }
    }
}

#[test]
fn clean_transition_refuses_late_hard_errors_geometry_and_flags_before_any_write() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let (volume, disk) = fixture(kind, 512, false);
        set_dirty(&Cx::for_testing(), &volume, true).unwrap();
        let dirty = disk.lock().unwrap().current.clone();
        let width = u64::from(kind.entry_bytes());
        let last = volume.base + volume.geometry.entry_offset(1, 2).unwrap() - 2 * width;
        let boot = volume.base + u64::from(volume.geometry.backup_boot_sector().unwrap_or(0)) * 512;
        let state_at = if kind == FatKind::Fat16 { 37 } else { 65 };
        let io_error = if kind == FatKind::Fat16 { 0x40 } else { 0x04 };
        for (at, mask) in [
            (last + 2 * width - 1, io_error),
            (last, 1),
            (boot + state_at, 0x80),
            (boot + 13, 3),
        ] {
            let before = {
                let mut state = disk.lock().unwrap();
                state.reset(&dirty);
                let mut byte = [0];
                state.read(at, &mut byte);
                byte[0] ^= mask;
                state.put(at, &byte);
                state.current.clone()
            };
            assert!(set_dirty(&Cx::for_testing(), &volume, false).is_err());
            let state = disk.lock().unwrap();
            assert_eq!(state.writes(), 0);
            assert!(!state.events.contains(&Event::Sync));
            assert_eq!(state.current, before);
        }
    }
}

#[test]
fn each_lost_state_write_and_post_flush_neighbor_corruption_is_detected() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let (volume, disk) = fixture(kind, 4096, false);
        let clean = disk.lock().unwrap().current.clone();
        set_dirty(&Cx::for_testing(), &volume, true).unwrap();
        let dirty_pages = disk.lock().unwrap().current.clone();
        let offsets = state_offsets(&volume);
        for dirty in [true, false] {
            for &at in &offsets {
                for corrupt_neighbor in [false, true] {
                    {
                        let mut state = disk.lock().unwrap();
                        state.reset(if dirty { &clean } else { &dirty_pages });
                        if corrupt_neighbor {
                            // Beyond byte 512: flag-only/header-only checks miss this.
                            state.corrupt_at_sync = Some(at + 2048);
                        } else {
                            state.drop_writes.insert(at);
                        }
                    }
                    let error = set_dirty(&Cx::for_testing(), &volume, dirty).unwrap_err();
                    assert!(
                        error.to_string().contains("state sector readback"),
                        "{error:#}"
                    );
                    let state = disk.lock().unwrap();
                    assert_eq!(state.writes(), offsets.len());
                    assert_eq!(
                        state
                            .events
                            .iter()
                            .filter(|event| **event == Event::Sync)
                            .count(),
                        1
                    );
                    assert_eq!(state.current, state.durable);
                }
            }
        }
    }
}

#[test]
fn every_state_write_and_sync_failure_stops_without_rollback_or_retry() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let (volume, disk) = fixture(kind, 512, false);
        let clean = disk.lock().unwrap().current.clone();
        set_dirty(&Cx::for_testing(), &volume, true).unwrap();
        let dirty_pages = disk.lock().unwrap().current.clone();
        let offsets = state_offsets(&volume);
        for dirty in [true, false] {
            let initial = if dirty { &clean } else { &dirty_pages };
            for fail_at in 1..=offsets.len() + 1 {
                for tear in [0, 3, 66, 512] {
                    {
                        let mut state = disk.lock().unwrap();
                        state.reset(initial);
                        state.fail_at = Some(fail_at);
                        state.tear = tear;
                    }
                    assert!(set_dirty(&Cx::for_testing(), &volume, dirty).is_err());
                    let state = disk.lock().unwrap();
                    assert_eq!(state.operations, fail_at);
                    assert_eq!(state.durable, *initial);
                    assert_eq!(state.writes(), fail_at.min(offsets.len()));
                }
            }
        }
    }
}

#[test]
fn state_readback_error_and_cancellation_never_start_following_mutation() {
    let (volume, disk) = fixture(FatKind::Fat32, 512, false);
    let original = disk.lock().unwrap().current.clone();
    let offsets = state_offsets(&volume);
    let cx = Cx::for_testing();
    cx.cancel_with(CancelKind::User, Some("before state publication"));
    assert!(set_dirty(&cx, &volume, true).is_err());
    assert!(disk.lock().unwrap().events.is_empty());
    for cancel in [false, true] {
        {
            let mut state = disk.lock().unwrap();
            state.reset(&original);
            state.cancel_at_sync = cancel;
            state.fail_readback = !cancel;
        }
        assert!(set_dirty(&Cx::for_testing(), &volume, true).is_err());
        let mut state = disk.lock().unwrap();
        assert_eq!(state.operations, offsets.len() + 1);
        assert_eq!(state.writes(), offsets.len());
        state.fail_readback = false;
        drop(state);
        assert_eq!(payload(&volume), PAYLOAD);
    }
}

#[test]
fn dropped_dirty_publication_cannot_overwrite_previously_acknowledged_payload() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let (volume, disk) = fixture(kind, 512, false);
        let original = disk.lock().unwrap().current.clone();
        disk.lock()
            .unwrap()
            .drop_writes
            .extend(state_offsets(&volume));
        assert!(
            write_range_in_volume(&Cx::for_testing(), &volume, "/KEEP.BIN", 0, b"LOST", NOW)
                .is_err()
        );
        // The old implementation reached live data before detecting that its
        // dirty markers had been dropped. This must fail before even FSInfo.
        assert_eq!(payload(&volume), PAYLOAD);
        assert_eq!(disk.lock().unwrap().current, original);
        assert_eq!(disk.lock().unwrap().durable, original);
        disk.lock().unwrap().reset(&original);
        write_range_in_volume(&Cx::for_testing(), &volume, "/KEEP.BIN", 0, b"KEPT", NOW).unwrap();
        let mut expected = PAYLOAD.to_vec();
        expected[..4].copy_from_slice(b"KEPT");
        assert_eq!(payload(&volume), expected);
        assert!(volume.check(&Cx::for_testing()).unwrap().clean);
    }
}

#[test]
fn failed_state_barrier_quarantines_the_actual_mounted_adapter() {
    use ffs_core::{FsOps, RequestScope};
    use ffs_types::InodeNumber;
    use std::ffi::OsStr;

    let (volume, disk) = fixture(FatKind::Fat16, 512, false);
    let offsets = state_offsets(&volume);
    let cx = Cx::for_testing();
    let fs = crate::filesystem::FatFs::new_with_mode(&cx, volume, 1000, 1000, true).unwrap();
    let mut scope = RequestScope::empty();
    let ino = fs
        .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("KEEP.BIN"))
        .unwrap()
        .ino;
    disk.lock().unwrap().drop_writes.extend(offsets);
    assert!(fs.write(&cx, &mut scope, ino, 0, b"LOST").is_err());
    let events = disk.lock().unwrap().events.len();
    assert!(fs.getattr(&cx, &mut scope, ino).is_err());
    assert!(fs.read(&cx, &mut scope, ino, 0, 4).is_err());
    assert!(fs.fsync(&cx, &mut scope, ino, 0, false).is_err());
    assert_eq!(disk.lock().unwrap().events.len(), events);
}
