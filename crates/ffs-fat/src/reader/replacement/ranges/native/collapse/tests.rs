//! Constructed FAT images and pending/durable storage faults, not native-tool
//! interoperability evidence. Exercise the public native and FsOps entry points.

use super::*;
use ffs_block::ByteDevice;
use ffs_core::{FsOps, RequestScope};
use ffs_ondisk::fat::FatGeometry;
use ffs_types::{ByteOffset, InodeNumber};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::sync::{Arc, Mutex};

const BASE: u64 = 4096;
const PAGE: usize = 4096;
const NOW: u64 = 1_700_000_000;
const CHAIN: [u32; 7] = [7, 4, 9, 3, 11, 6, 10];
type Pages = BTreeMap<u64, [u8; PAGE]>;

#[derive(Clone, Debug)]
enum Event {
    Read(u64, usize),
    Write(usize, u64, Vec<u8>),
    Sync,
}

#[derive(Clone, Copy)]
enum Fault {
    Error(usize), // bytes of a failed write retained in the pending page cache
    Drop,
    Cancel,
}

#[derive(Default)]
struct Storage {
    durable: Pages,
    pending: Pages,
    attempts: usize,
    events: Vec<Event>,
    fault: Option<(usize, Fault)>,
    read_failure_after: Option<usize>,
}

impl Storage {
    fn read(&self, mut at: u64, mut bytes: &mut [u8]) {
        while !bytes.is_empty() {
            let page = at / PAGE as u64;
            let within = (at % PAGE as u64) as usize;
            let count = bytes.len().min(PAGE - within);
            if let Some(source) = self.pending.get(&page).or_else(|| self.durable.get(&page)) {
                bytes[..count].copy_from_slice(&source[within..within + count]);
            } else {
                bytes[..count].fill(0);
            }
            at += count as u64;
            bytes = &mut bytes[count..];
        }
    }

    fn put(&mut self, mut at: u64, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let page = at / PAGE as u64;
            let within = (at % PAGE as u64) as usize;
            let count = bytes.len().min(PAGE - within);
            let old = self.durable.get(&page).copied().unwrap_or([0; PAGE]);
            self.pending.entry(page).or_insert(old)[within..within + count]
                .copy_from_slice(&bytes[..count]);
            at += count as u64;
            bytes = &bytes[count..];
        }
    }

    fn persist(&mut self) {
        self.durable.append(&mut self.pending);
    }
}

#[derive(Clone)]
struct Device {
    state: Arc<Mutex<Storage>>,
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
        let mut state = self.state.lock().unwrap();
        state.events.push(Event::Read(at.0, bytes.len()));
        if state
            .read_failure_after
            .is_some_and(|cut| state.attempts >= cut)
        {
            bytes.fill(0xEE);
            return Err(std::io::Error::other("injected collapse read failure").into());
        }
        state.read(at.0, bytes);
        Ok(())
    }

    fn write_all_at(&self, cx: &Cx, at: ByteOffset, bytes: &[u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        assert!(at.0 >= BASE && at.0 + bytes.len() as u64 <= self.length - BASE);
        let mut state = self.state.lock().unwrap();
        state.attempts += 1;
        let attempt = state.attempts;
        state
            .events
            .push(Event::Write(attempt, at.0, bytes.to_vec()));
        match state
            .fault
            .filter(|(cut, _)| *cut == attempt)
            .map(|(_, fault)| fault)
        {
            Some(Fault::Error(tear)) => {
                state.put(at.0, &bytes[..tear.min(bytes.len())]);
                return Err(std::io::Error::other("injected collapse write failure").into());
            }
            Some(Fault::Drop) => return Ok(()),
            Some(Fault::Cancel) => {
                state.put(at.0, bytes);
                cx.set_cancel_requested(true);
                return Err(FfsError::Cancelled);
            }
            None => state.put(at.0, bytes),
        }
        Ok(())
    }

    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        let mut state = self.state.lock().unwrap();
        state.attempts += 1;
        state.events.push(Event::Sync);
        if state.fault.is_some_and(|(cut, _)| cut == state.attempts) {
            return Err(std::io::Error::other("injected collapse sync failure").into());
        }
        state.persist();
        Ok(())
    }
}

impl Device {
    fn open(&self) -> FatVolume {
        FatVolume::from_device(
            &Cx::for_testing(),
            Box::new(self.clone()),
            BASE,
            self.length - 2 * BASE,
        )
        .unwrap()
    }

    fn reset(&self) {
        let mut state = self.state.lock().unwrap();
        assert!(state.pending.is_empty());
        state.events.clear();
        state.attempts = 0;
    }

    fn bytes(&self, at: u64, length: usize) -> Vec<u8> {
        let mut bytes = vec![0; length];
        self.state.lock().unwrap().read(at, &mut bytes);
        bytes
    }

    fn restart(&self, retain: bool) -> Self {
        let state = self.state.lock().unwrap();
        let mut durable = state.durable.clone();
        if retain {
            durable.extend(state.pending.clone());
        }
        Self {
            state: Arc::new(Mutex::new(Storage {
                durable,
                ..Storage::default()
            })),
            length: self.length,
        }
    }
}

fn record(name: &[u8; 11], first: u32, size: u32, kind: FatKind) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..11].copy_from_slice(name);
    bytes[11] = 0x06; // hidden/system; collapse must preserve both and set archive
    bytes[13] = 157;
    for at in [16, 18, 24] {
        bytes[at..at + 2].copy_from_slice(&0x21_u16.to_le_bytes());
    }
    let high = if kind == FatKind::Fat32 {
        0xA000 | (first >> 16) as u16
    } else {
        0x1234
    };
    bytes[20..22].copy_from_slice(&high.to_le_bytes());
    bytes[26..28].copy_from_slice(&(first as u16).to_le_bytes());
    bytes[28..32].copy_from_slice(&size.to_le_bytes());
    bytes
}

fn fixture(kind: FatKind, sector: u32, full: bool, active: bool) -> (Device, FatGeometry, Vec<u8>) {
    let count = if kind == FatKind::Fat16 {
        5000_u32
    } else {
        70_000
    };
    let reserved = if kind == FatKind::Fat16 { 1_u32 } else { 32 };
    let width = kind.entry_bytes();
    let fat = ((count + 2) * width).div_ceil(sector);
    let roots = if kind == FatKind::Fat16 {
        (sector / 32).max(32) as u16
    } else {
        0
    };
    let total = reserved + 2 * fat + (u32::from(roots) * 32).div_ceil(sector) + count;
    let mut boot = [0; 512];
    boot[..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
    boot[3..11].copy_from_slice(b"MSWIN4.1");
    boot[11..13].copy_from_slice(&(sector as u16).to_le_bytes());
    boot[13] = 1;
    boot[14..16].copy_from_slice(&(reserved as u16).to_le_bytes());
    boot[16] = 2;
    boot[17..19].copy_from_slice(&roots.to_le_bytes());
    boot[21] = 0xF8;
    boot[510..512].copy_from_slice(&[0x55, 0xAA]);
    if kind == FatKind::Fat16 {
        boot[19..21].copy_from_slice(&(total as u16).to_le_bytes());
        boot[22..24].copy_from_slice(&(fat as u16).to_le_bytes());
        boot[38] = 0x29;
    } else {
        boot[32..36].copy_from_slice(&total.to_le_bytes());
        boot[36..40].copy_from_slice(&fat.to_le_bytes());
        boot[40..42].copy_from_slice(&(if active { 0x81_u16 } else { 0 }).to_le_bytes());
        boot[44..48].copy_from_slice(&2_u32.to_le_bytes());
        boot[48..50].copy_from_slice(&1_u16.to_le_bytes());
        boot[50..52].copy_from_slice(&6_u16.to_le_bytes());
        boot[66] = 0x29;
    }
    let geometry = FatGeometry::parse(&boot, u64::from(total) * u64::from(sector)).unwrap();
    let end = if kind == FatKind::Fat16 {
        0xFFFF_u32
    } else {
        0x0FFF_FFFF
    };
    let mut links = BTreeMap::from([(0, end & !7), (1, end)]);
    if kind == FatKind::Fat32 {
        links.insert(2, end);
    }
    for (index, cluster) in CHAIN.into_iter().enumerate() {
        links.insert(cluster, CHAIN.get(index + 1).copied().unwrap_or(end));
    }
    let other: Vec<u32> = if full {
        (2..=count + 1)
            .filter(|cluster| !links.contains_key(cluster))
            .collect()
    } else {
        vec![5]
    };
    for (index, &cluster) in other.iter().enumerate() {
        links.insert(cluster, other.get(index + 1).copied().unwrap_or(end));
    }
    let mut state = Storage::default();
    state.put(0, &[0xA7; PAGE]);
    state.put(BASE + geometry.volume_bytes(), &[0xB9; PAGE]);
    state.put(BASE, &boot);
    if kind == FatKind::Fat32 {
        state.put(BASE + 6 * u64::from(sector), &boot);
        let mut info = [0; 512];
        info[..4].copy_from_slice(&0x4161_5252_u32.to_le_bytes());
        info[484..488].copy_from_slice(&0x6141_7272_u32.to_le_bytes());
        info[488..496].fill(0xFF);
        info[508..512].copy_from_slice(&0xAA55_0000_u32.to_le_bytes());
        state.put(BASE + u64::from(sector), &info);
    }
    for copy in 0..2_u8 {
        let start = BASE + u64::from(reserved + u32::from(copy) * fat) * u64::from(sector);
        for cluster in 0..count + 2 {
            let low = links.get(&cluster).copied().unwrap_or(0);
            let high = if kind == FatKind::Fat32 {
                (10 + u32::from(copy)) << 28
            } else {
                0
            };
            state.put(
                start + u64::from(cluster * width),
                &(low | high).to_le_bytes()[..width as usize],
            );
        }
    }
    if active {
        state.put(
            BASE + geometry.entry_offset(0, CHAIN[0]).unwrap(),
            &0xA000_0001_u32.to_le_bytes(),
        );
    }
    let root = geometry
        .fixed_root()
        .map_or_else(|| geometry.cluster_offset(2).unwrap(), |(at, _)| at);
    let size = 4 * sector + 37;
    state.put(BASE + root, &record(b"FILE    BIN", CHAIN[0], size, kind));
    state.put(
        BASE + root + 32,
        &record(
            b"OTHER   BIN",
            other[0],
            if full { other.len() as u32 * sector } else { 8 },
            kind,
        ),
    );
    let payload: Vec<u8> = (0..size).map(|index| (index % 251) as u8).collect();
    for (index, cluster) in CHAIN.into_iter().enumerate() {
        let mut bytes = vec![0xE7; sector as usize];
        let start = index * sector as usize;
        let length = payload.len().saturating_sub(start).min(bytes.len());
        if length != 0 {
            bytes[..length].copy_from_slice(&payload[start..start + length]);
        }
        state.put(BASE + geometry.cluster_offset(cluster).unwrap(), &bytes);
    }
    state.persist();
    let device = Device {
        state: Arc::new(Mutex::new(state)),
        length: BASE * 2 + geometry.volume_bytes(),
    };
    let check = device.open().check(&Cx::for_testing()).unwrap();
    assert!(
        check.clean && check.complete && check.namespace_complete,
        "{check:?}"
    );
    assert_eq!(check.preallocated_clusters, 2);
    if full {
        assert_eq!(check.free_clusters, 0);
    }
    device.reset();
    (device, geometry, payload)
}

fn collapse(volume: &FatVolume, first: u64, count: u64) -> Result<()> {
    let cluster = u64::from(volume.geometry.cluster_bytes());
    volume.preallocate(
        &Cx::for_testing(),
        "/file.bin",
        first * cluster,
        count * cluster,
        libc::FALLOC_FL_COLLAPSE_RANGE,
        NOW,
    )
}

fn target(volume: &FatVolume) -> (super::super::Entry, super::super::FileChain) {
    let cx = Cx::for_testing();
    let entry = volume.resolve(&cx, "/FILE.BIN").unwrap().unwrap();
    let chain = volume.file_chain(&cx, &entry).unwrap();
    (entry, chain)
}

#[test]
fn collapse_prefix_and_interior_preserve_fragmented_payload_preallocation_and_metadata() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for sector in [512, 4096] {
            for (first, count) in [(0, 2), (1, 2), (3, 1)] {
                let (device, geometry, original) = fixture(kind, sector, false, false);
                let volume = device.open();
                let (entry, _) = target(&volume);
                let before = device.bytes(BASE + entry.offset, 64);
                let free = volume.check(&Cx::for_testing()).unwrap().free_clusters;
                device.reset();
                collapse(&volume, first, count).unwrap();
                let audit = device.state.lock().unwrap().events.clone();
                for event in audit {
                    let (at, size) = match event {
                        Event::Read(at, size) => (at, size),
                        Event::Write(_, at, bytes) => (at, bytes.len()),
                        Event::Sync => continue,
                    };
                    // No payload read OR write, including preallocation/slack.
                    for cluster in CHAIN {
                        let start = BASE + geometry.cluster_offset(cluster).unwrap();
                        assert!(at + size as u64 <= start || at >= start + u64::from(sector));
                    }
                }
                let cx = Cx::for_testing();
                let (after, chain) = target(&volume);
                let mut expected = original.clone();
                expected.drain(
                    (first * u64::from(sector)) as usize
                        ..((first + count) * u64::from(sector)) as usize,
                );
                assert_eq!(
                    volume.read(&cx, &chain, 0, original.len()).unwrap(),
                    expected
                );
                let mut expected_chain = CHAIN.to_vec();
                expected_chain.drain(first as usize..(first + count) as usize);
                assert_eq!(chain.clusters, expected_chain);
                assert_eq!(after.offset, entry.offset);
                let mut expected_record = before[..32].to_vec();
                expected_record[11] |= 0x20;
                expected_record[26..28].copy_from_slice(&(expected_chain[0] as u16).to_le_bytes());
                expected_record[28..32].copy_from_slice(&(expected.len() as u32).to_le_bytes());
                let (date, time) = modified_timestamp(NOW).unwrap();
                expected_record[22..24].copy_from_slice(&time.to_le_bytes());
                expected_record[24..26].copy_from_slice(&date.to_le_bytes());
                assert_eq!(device.bytes(BASE + entry.offset, 32), expected_record);
                assert_eq!(device.bytes(BASE + entry.offset + 32, 32), before[32..]);
                let check = volume.check(&cx).unwrap();
                assert!(check.clean && check.complete && check.namespace_complete);
                assert_eq!(check.free_clusters, free + count);
                assert_eq!(check.preallocated_clusters, 2);
                assert_eq!(device.bytes(0, PAGE), vec![0xA7; PAGE]);
                assert_eq!(
                    device.bytes(BASE + geometry.volume_bytes(), PAGE),
                    vec![0xB9; PAGE]
                );
            }
        }
    }
}

#[test]
fn collapse_frees_capacity_on_full_volumes_without_new_clusters() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let (device, _, _) = fixture(kind, 512, true, false);
        let volume = device.open();
        collapse(&volume, 1, 2).unwrap();
        assert_eq!(target(&volume).1.clusters, [7, 3, 11, 6, 10]);
        let report = volume.check(&Cx::for_testing()).unwrap();
        assert!(report.clean);
        assert_eq!(report.free_clusters, 2);
        let mut table = FatTable::new(&volume);
        for cluster in [4, 9] {
            assert_eq!(
                table.entry(&Cx::for_testing(), cluster).unwrap(),
                FatEntry::Free
            );
        }
    }
}

#[test]
fn collapse_honors_active_fat_and_preserves_every_reserved_high_nibble() {
    let (device, geometry, _) = fixture(FatKind::Fat32, 4096, false, true);
    let first = BASE + geometry.entry_offset(0, 2).unwrap() - 8;
    let second = BASE + geometry.entry_offset(1, 2).unwrap() - 8;
    let inactive = device.bytes(first, (second - first) as usize);
    collapse(&device.open(), 0, 2).unwrap();
    assert_eq!(device.bytes(first, inactive.len()), inactive);
    let active = device.bytes(second, ((geometry.cluster_count() + 2) * 4) as usize);
    for entry in active.chunks_exact(4) {
        assert_eq!(entry[3] & 0xF0, 0xB0);
    }
    assert!(device.open().check(&Cx::for_testing()).unwrap().clean);
}

#[test]
fn prefix_collapse_can_publish_a_fat32_head_above_the_low_word_boundary() {
    let (device, geometry, original) = fixture(FatKind::Fat32, 512, false, false);
    let moved = 70_000;
    let bytes = device.bytes(BASE + geometry.cluster_offset(9).unwrap(), 512);
    {
        let mut state = device.state.lock().unwrap();
        for copy in 0..2_u8 {
            let high = (10 + u32::from(copy)) << 28;
            for (cluster, value) in [(4, moved), (moved, 3), (9, 0)] {
                state.put(
                    BASE + geometry.entry_offset(copy, cluster).unwrap(),
                    &(high | value).to_le_bytes(),
                );
            }
        }
        state.put(BASE + geometry.cluster_offset(moved).unwrap(), &bytes);
        state.persist();
    }
    let volume = device.open();
    assert!(volume.check(&Cx::for_testing()).unwrap().clean);
    collapse(&volume, 0, 2).unwrap();
    let (entry, chain) = target(&volume);
    assert_eq!(chain.clusters, [moved, 3, 11, 6, 10]);
    let record = device.bytes(BASE + entry.offset, 32);
    assert_eq!(
        u16::from_le_bytes(record[20..22].try_into().unwrap()),
        0xA001
    );
    assert_eq!(
        u16::from_le_bytes(record[26..28].try_into().unwrap()),
        moved as u16
    );
    assert_eq!(
        volume
            .read(&Cx::for_testing(), &chain, 0, original.len())
            .unwrap(),
        original[1024..]
    );
}

#[test]
fn invalid_collapse_ranges_flags_calendar_and_cancellation_never_write() {
    let (device, _, _) = fixture(FatKind::Fat16, 512, false, false);
    let volume = device.open();
    let cx = Cx::for_testing();
    let before = device.state.lock().unwrap().durable.clone();
    for (offset, length) in [
        (0, 0),
        (1, 512),
        (0, 1),
        (2048, 512),
        (2560, 512),
        (!511_u64, 512),
    ] {
        let error = volume
            .preallocate(
                &cx,
                "/file.bin",
                offset,
                length,
                libc::FALLOC_FL_COLLAPSE_RANGE,
                NOW,
            )
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<FfsError>().unwrap().to_errno(),
            libc::EINVAL
        );
    }
    for extra in [
        libc::FALLOC_FL_KEEP_SIZE,
        libc::FALLOC_FL_ZERO_RANGE,
        libc::FALLOC_FL_PUNCH_HOLE,
        -1,
    ] {
        assert!(
            volume
                .preallocate(
                    &cx,
                    "/file.bin",
                    0,
                    512,
                    libc::FALLOC_FL_COLLAPSE_RANGE | extra,
                    NOW
                )
                .is_err()
        );
    }
    assert!(
        volume
            .preallocate(
                &cx,
                "/file.bin",
                0,
                512,
                libc::FALLOC_FL_COLLAPSE_RANGE,
                u64::MAX
            )
            .is_err()
    );
    let cancelled = Cx::for_testing();
    cancelled.set_cancel_requested(true);
    assert!(
        volume
            .preallocate(
                &cancelled,
                "/file.bin",
                0,
                512,
                libc::FALLOC_FL_COLLAPSE_RANGE,
                NOW
            )
            .is_err()
    );
    assert_eq!(device.state.lock().unwrap().attempts, 0);
    assert_eq!(device.state.lock().unwrap().durable, before);
    collapse(&volume, 1, 1).unwrap();
}

#[test]
fn collapse_refuses_readonly_directories_crosslinks_and_dirty_state_before_io() {
    for scenario in 0..4 {
        let (device, _, _) = fixture(FatKind::Fat32, 512, false, false);
        let volume = device.open();
        let (entry, _) = target(&volume);
        {
            let mut state = device.state.lock().unwrap();
            match scenario {
                0 => state.put(BASE + entry.offset + 11, &[0x07]),
                1 => {}
                2 => state.put(
                    BASE + entry.offset + 32 + 26,
                    &(CHAIN[0] as u16).to_le_bytes(),
                ),
                _ => state.put(BASE + 65, &[1]),
            }
            state.persist();
        }
        let before = device.state.lock().unwrap().durable.clone();
        let path = if scenario == 1 { "/" } else { "/file.bin" };
        assert!(
            volume
                .preallocate(
                    &Cx::for_testing(),
                    path,
                    0,
                    512,
                    libc::FALLOC_FL_COLLAPSE_RANGE,
                    NOW
                )
                .is_err()
        );
        assert_eq!(device.state.lock().unwrap().attempts, 0);
        assert_eq!(device.state.lock().unwrap().durable, before);
    }
}

fn publication_cuts(events: &[Event], root: u64, fat: u64) -> (usize, Vec<usize>) {
    let directory = events
        .iter()
        .find_map(|event| match event {
            Event::Write(n, at, _) if *at == root => Some(*n),
            _ => None,
        })
        .unwrap();
    let splice = events
        .iter()
        .filter_map(|event| match event {
            Event::Write(n, at, _) if *n > directory && *at == fat => Some(*n),
            _ => None,
        })
        .take(2)
        .collect(); // first splice and later reclamation in this copy
    (directory, splice)
}

#[test]
fn dropped_publication_or_splice_and_failed_readback_never_free_reachable_clusters() {
    for prefix in [false, true] {
        let (probe, geometry, _) = fixture(FatKind::Fat16, 512, false, false);
        let first = u64::from(!prefix);
        collapse(&probe.open(), first, 2).unwrap();
        let events = probe.state.lock().unwrap().events.clone();
        let root = BASE + geometry.fixed_root().unwrap().0;
        let fat = BASE + geometry.entry_offset(0, 2).unwrap() - 4;
        let (_, fat_cuts) = publication_cuts(&events, root, fat);
        let mut cuts: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                Event::Write(n, at, _) if *at == root => Some(*n),
                _ => None,
            })
            .collect();
        if !prefix {
            cuts.push(fat_cuts[0]);
        }
        for cut in cuts {
            for read_failure in [false, true] {
                let (device, _, _) = fixture(FatKind::Fat16, 512, false, false);
                let volume = device.open();
                {
                    let mut state = device.state.lock().unwrap();
                    if read_failure {
                        state.read_failure_after = Some(cut + 1);
                    } else {
                        state.fault = Some((cut, Fault::Drop));
                    }
                }
                assert!(collapse(&volume, first, 2).is_err());
                // Read raw storage, independent of the failing reader/admission.
                for cluster in CHAIN {
                    let bytes = device.bytes(BASE + geometry.entry_offset(0, cluster).unwrap(), 2);
                    assert_ne!(u16::from_le_bytes(bytes.try_into().unwrap()), 0);
                }
                assert_eq!(device.bytes(BASE + 37, 1), [1]);
            }
        }
    }
}

#[test]
fn every_collapse_write_and_sync_cut_preserves_payload_and_never_readmits_partial_clean_state() {
    for first in [0, 1] {
        let (probe, geometry, original) = fixture(FatKind::Fat16, 512, false, false);
        collapse(&probe.open(), first, 2).unwrap();
        let total = probe.state.lock().unwrap().attempts;
        assert!(total > 8);
        let mut expected = original.clone();
        expected.drain((first * 512) as usize..((first + 2) * 512) as usize);
        for cut in 1..=total {
            for tear in [0, 31, 511, 512] {
                let (device, _, _) = fixture(FatKind::Fat16, 512, false, false);
                let volume = device.open();
                let payload_before: Vec<_> = CHAIN
                    .iter()
                    .map(|&cluster| {
                        device.bytes(BASE + geometry.cluster_offset(cluster).unwrap(), 512)
                    })
                    .collect();
                device.state.lock().unwrap().fault = Some((cut, Fault::Error(tear)));
                assert!(
                    collapse(&volume, first, 2).is_err(),
                    "cut={cut}, tear={tear}"
                );
                assert_eq!(device.state.lock().unwrap().attempts, cut);
                for (index, cluster) in CHAIN.into_iter().enumerate() {
                    assert_eq!(
                        device.bytes(BASE + geometry.cluster_offset(cluster).unwrap(), 512),
                        payload_before[index]
                    );
                }
                for retain in [false, true] {
                    let crashed = device.restart(retain);
                    let cx = Cx::for_testing();
                    if let Ok(reopened) = FatVolume::from_device(
                        &cx,
                        Box::new(crashed.clone()),
                        BASE,
                        geometry.volume_bytes(),
                    ) {
                        assert!(reopened.check(&cx).unwrap().clean, "cut={cut}, tear={tear}");
                        let (_, chain) = target(&reopened);
                        let bytes = reopened.read(&cx, &chain, 0, original.len()).unwrap();
                        assert!(bytes == original || bytes == expected);
                    }
                }
            }
        }
    }
}

#[test]
fn torn_prefix_head_publication_cannot_keep_the_old_eof_over_preallocation() {
    let (probe, geometry, _) = fixture(FatKind::Fat16, 512, false, false);
    collapse(&probe.open(), 0, 2).unwrap();
    let root = BASE + geometry.fixed_root().unwrap().0;
    let head_publication = probe
        .state
        .lock()
        .unwrap()
        .events
        .iter()
        .filter_map(|event| match event {
            Event::Write(n, at, _) if *at == root => Some(*n),
            _ => None,
        })
        .nth(1)
        .expect("prefix collapse must publish EOF before changing the head");
    let (device, _, _) = fixture(FatKind::Fat16, 512, false, false);
    let volume = device.open();
    // Persist the entire head, but stop before the size field in that record.
    device.state.lock().unwrap().fault = Some((head_publication, Fault::Error(28)));
    assert!(collapse(&volume, 0, 2).is_err());
    let record = device.bytes(root, 32);
    assert_eq!(
        u16::from_le_bytes(record[26..28].try_into().unwrap()),
        CHAIN[2] as u16
    );
    assert_eq!(u32::from_le_bytes(record[28..32].try_into().unwrap()), 0);
    for cluster in CHAIN {
        assert_ne!(
            device.bytes(BASE + geometry.entry_offset(0, cluster).unwrap(), 2),
            [0; 2]
        );
    }
}

#[test]
fn mounted_collapse_refreshes_cached_chain_size_free_space_and_held_inode() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let (device, _, original) = fixture(kind, 512, true, false);
        let cx = Cx::for_testing();
        let fs =
            crate::filesystem::FatFs::new_with_mode(&cx, device.open(), 1000, 1000, true).unwrap();
        let mut scope = RequestScope::empty();
        let ino = fs
            .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("FILE.BIN"))
            .unwrap()
            .ino;
        assert_ne!(fs.open(&cx, &mut scope, ino, libc::O_RDWR).unwrap().0, 0);
        assert_eq!(
            fs.read(&cx, &mut scope, ino, 0, original.len() as u32)
                .unwrap(),
            original
        );
        assert_eq!(fs.statfs(&cx, &mut scope, ino).unwrap().blocks_free, 0);
        fs.fallocate(
            &cx,
            &mut scope,
            ino,
            512,
            1024,
            libc::FALLOC_FL_COLLAPSE_RANGE,
        )
        .unwrap();
        let attr = fs.getattr(&cx, &mut scope, ino).unwrap();
        assert_eq!(attr.size, original.len() as u64 - 1024);
        assert_eq!(attr.blocks, 5);
        assert_eq!(fs.statfs(&cx, &mut scope, ino).unwrap().blocks_free, 2);
        assert_eq!(
            fs.lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("file.bin"))
                .unwrap()
                .ino,
            ino
        );
        let mut expected = original;
        expected.drain(512..1536);
        assert_eq!(fs.read(&cx, &mut scope, ino, 0, 4096).unwrap(), expected);
    }
}

#[test]
fn mounted_collapse_preflight_refusal_stays_usable_but_uncertain_mutation_quarantines() {
    for cancel in [false, true] {
        let (device, _, _) = fixture(FatKind::Fat16, 512, false, false);
        let cx = Cx::for_testing();
        let fs = crate::filesystem::FatFs::new_with_mode(&cx, device.open(), 0, 0, true).unwrap();
        let mut scope = RequestScope::empty();
        let ino = fs
            .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("file.bin"))
            .unwrap()
            .ino;
        device.reset();
        assert_eq!(
            fs.fallocate(&cx, &mut scope, ino, 1, 512, libc::FALLOC_FL_COLLAPSE_RANGE)
                .unwrap_err()
                .to_errno(),
            libc::EINVAL
        );
        fs.getattr(&cx, &mut scope, ino).unwrap();
        assert_eq!(device.state.lock().unwrap().attempts, 0);
        device.state.lock().unwrap().fault = Some((
            1,
            if cancel {
                Fault::Cancel
            } else {
                Fault::Error(64)
            },
        ));
        assert!(
            fs.fallocate(&cx, &mut scope, ino, 0, 512, libc::FALLOC_FL_COLLAPSE_RANGE)
                .is_err()
        );
        let fresh = Cx::for_testing();
        assert_eq!(
            fs.getattr(&fresh, &mut scope, ino).unwrap_err().to_errno(),
            libc::EIO
        );
        assert_eq!(
            fs.read(&fresh, &mut scope, ino, 0, 1)
                .unwrap_err()
                .to_errno(),
            libc::EIO
        );
        assert_eq!(
            fs.statfs(&fresh, &mut scope, ino).unwrap_err().to_errno(),
            libc::EIO
        );
    }
}

#[test]
fn concurrent_collapses_serialize_chain_and_cache_publication() {
    let (device, _, original) = fixture(FatKind::Fat32, 512, false, false);
    let cx = Cx::for_testing();
    let fs = crate::filesystem::FatFs::new_with_mode(&cx, device.open(), 0, 0, true).unwrap();
    let ino = fs
        .lookup(
            &cx,
            &mut RequestScope::empty(),
            InodeNumber(1),
            OsStr::new("file.bin"),
        )
        .unwrap()
        .ino;
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|threads| {
        for _ in 0..2 {
            let (fs, barrier) = (&fs, &barrier);
            threads.spawn(move || {
                barrier.wait();
                fs.fallocate(
                    &Cx::for_testing(),
                    &mut RequestScope::empty(),
                    ino,
                    512,
                    512,
                    libc::FALLOC_FL_COLLAPSE_RANGE,
                )
                .unwrap();
            });
        }
    });
    let mut expected = original;
    expected.drain(512..1536);
    assert_eq!(
        fs.read(&cx, &mut RequestScope::empty(), ino, 0, 4096)
            .unwrap(),
        expected
    );
    assert!(device.open().check(&cx).unwrap().clean);
}
