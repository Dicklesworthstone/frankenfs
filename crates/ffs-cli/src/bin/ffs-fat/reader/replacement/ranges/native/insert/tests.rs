//! Constructed native images and pending/durable faults. These exercise the
//! production entry points, not a second allocator or native-system oracle.

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
enum Event { Read(u64, usize), Write(usize, u64, Vec<u8>), Sync }
#[derive(Clone, Copy)]
enum Fault { Error(usize), Drop, Cancel }
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
            } else { bytes[..count].fill(0); }
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
            self.pending.entry(page).or_insert(old)[within..within + count].copy_from_slice(&bytes[..count]);
            at += count as u64;
            bytes = &bytes[count..];
        }
    }
    fn persist(&mut self) { self.durable.append(&mut self.pending); }
}
#[derive(Clone)]
struct Device { state: Arc<Mutex<Storage>>, length: u64 }
impl ByteDevice for Device {
    fn len_bytes(&self) -> u64 { self.length }
    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        assert!(at.0.checked_add(bytes.len() as u64).is_some_and(|end| end <= self.length));
        let mut state = self.state.lock().unwrap();
        state.events.push(Event::Read(at.0, bytes.len()));
        if state.read_failure_after.is_some_and(|cut| state.attempts >= cut) {
            bytes.fill(0xEE);
            return Err(std::io::Error::other("injected insertion read failure").into());
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
        state.events.push(Event::Write(attempt, at.0, bytes.to_vec()));
        match state.fault.filter(|(cut, _)| *cut == attempt).map(|(_, fault)| fault) {
            Some(Fault::Error(tear)) => {
                state.put(at.0, &bytes[..tear.min(bytes.len())]);
                return Err(std::io::Error::other("injected insertion write failure").into());
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
            return Err(std::io::Error::other("injected insertion sync failure").into());
        }
        state.persist();
        Ok(())
    }
}
impl Device {
    fn open(&self) -> FatVolume {
        FatVolume::from_device(&Cx::for_testing(), Box::new(self.clone()), BASE, self.length - 2 * BASE).unwrap()
    }
    fn reset(&self) {
        let mut state = self.state.lock().unwrap();
        assert!(state.pending.is_empty());
        state.events.clear(); state.attempts = 0;
    }
    fn bytes(&self, at: u64, length: usize) -> Vec<u8> {
        let mut bytes = vec![0; length];
        self.state.lock().unwrap().read(at, &mut bytes);
        bytes
    }
    fn restart(&self, retain: bool) -> Self {
        let state = self.state.lock().unwrap();
        let mut durable = state.durable.clone();
        if retain { durable.extend(state.pending.clone()); }
        Self { state: Arc::new(Mutex::new(Storage { durable, ..Storage::default() })), length: self.length }
    }
}
fn record(name: &[u8; 11], first: u32, size: u32, kind: FatKind) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..11].copy_from_slice(name);
    bytes[11] = 0x06;
    bytes[13] = 157;
    for at in [16, 18, 24] { bytes[at..at + 2].copy_from_slice(&0x21_u16.to_le_bytes()); }
    let high = if kind == FatKind::Fat32 { 0xA000 | (first >> 16) as u16 } else { 0x1234 };
    bytes[20..22].copy_from_slice(&high.to_le_bytes());
    bytes[26..28].copy_from_slice(&(first as u16).to_le_bytes());
    bytes[28..32].copy_from_slice(&size.to_le_bytes());
    bytes
}
fn root(geometry: &FatGeometry) -> u64 {
    BASE + geometry.fixed_root().map_or_else(|| geometry.cluster_offset(2).unwrap(), |(at, _)| at)
}

/// Some(free) fills every other cluster with a second reachable file. None
/// leaves ordinary free capacity. Available slots contain poisoned old bytes.
fn fixture(kind: FatKind, sector: u32, active: bool, free: Option<&[u32]>) -> (Device, FatGeometry, Vec<u8>) {
    let count = if kind == FatKind::Fat16 { 5000_u32 } else { 70_000 };
    let reserved = if kind == FatKind::Fat16 { 1_u32 } else { 32 };
    let width = kind.entry_bytes();
    let fat = ((count + 2) * width).div_ceil(sector);
    let roots = if kind == FatKind::Fat16 { (sector / 32).max(32) as u16 } else { 0 };
    let total = reserved + 2 * fat + (u32::from(roots) * 32).div_ceil(sector) + count;
    let mut boot = [0; 512];
    boot[..3].copy_from_slice(&[0xEB, 0x58, 0x90]); boot[3..11].copy_from_slice(b"MSWIN4.1");
    boot[11..13].copy_from_slice(&(sector as u16).to_le_bytes()); boot[13] = 1;
    boot[14..16].copy_from_slice(&(reserved as u16).to_le_bytes()); boot[16] = 2;
    boot[17..19].copy_from_slice(&roots.to_le_bytes()); boot[21] = 0xF8;
    boot[510..512].copy_from_slice(&[0x55, 0xAA]);
    if kind == FatKind::Fat16 {
        boot[19..21].copy_from_slice(&(total as u16).to_le_bytes());
        boot[22..24].copy_from_slice(&(fat as u16).to_le_bytes()); boot[38] = 0x29;
    } else {
        boot[32..36].copy_from_slice(&total.to_le_bytes()); boot[36..40].copy_from_slice(&fat.to_le_bytes());
        boot[40..42].copy_from_slice(&(if active { 0x81_u16 } else { 0 }).to_le_bytes());
        boot[44..48].copy_from_slice(&2_u32.to_le_bytes()); boot[48..50].copy_from_slice(&1_u16.to_le_bytes());
        boot[50..52].copy_from_slice(&6_u16.to_le_bytes()); boot[66] = 0x29;
    }
    let geometry = FatGeometry::parse(&boot, u64::from(total) * u64::from(sector)).unwrap();
    let end = if kind == FatKind::Fat16 { 0xFFFF_u32 } else { 0x0FFF_FFFF };
    let mut links = BTreeMap::from([(0, end & !7), (1, end)]);
    if kind == FatKind::Fat32 { links.insert(2, end); }
    for (index, cluster) in CHAIN.into_iter().enumerate() {
        links.insert(cluster, CHAIN.get(index + 1).copied().unwrap_or(end));
    }
    let other: Vec<u32> = if let Some(free) = free {
        assert!(free.iter().all(|cluster| !links.contains_key(cluster)));
        (2..=count + 1).filter(|cluster| !links.contains_key(cluster) && !free.contains(cluster)).collect()
    } else { vec![5] };
    for (index, &cluster) in other.iter().enumerate() {
        links.insert(cluster, other.get(index + 1).copied().unwrap_or(end));
    }
    let mut state = Storage::default();
    state.put(0, &[0xA7; PAGE]); state.put(BASE + geometry.volume_bytes(), &[0xB9; PAGE]); state.put(BASE, &boot);
    if kind == FatKind::Fat32 {
        state.put(BASE + 6 * u64::from(sector), &boot);
        let mut info = [0; 512];
        info[..4].copy_from_slice(&0x4161_5252_u32.to_le_bytes());
        info[484..488].copy_from_slice(&0x6141_7272_u32.to_le_bytes());
        info[488..496].fill(0xFF); info[508..512].copy_from_slice(&0xAA55_0000_u32.to_le_bytes());
        state.put(BASE + u64::from(sector), &info);
    }
    for copy in 0..2_u8 {
        let start = BASE + u64::from(reserved + u32::from(copy) * fat) * u64::from(sector);
        for cluster in 0..count + 2 {
            let low = links.get(&cluster).copied().unwrap_or(0);
            let high = if kind == FatKind::Fat32 { (10 + u32::from(copy)) << 28 } else { 0 };
            state.put(start + u64::from(cluster * width), &(low | high).to_le_bytes()[..width as usize]);
        }
    }
    if active { state.put(BASE + geometry.entry_offset(0, CHAIN[0]).unwrap(), &0xA000_0001_u32.to_le_bytes()); }
    let size = 4 * sector + 37;
    state.put(root(&geometry), &record(b"FILE    BIN", CHAIN[0], size, kind));
    state.put(root(&geometry) + 32, &record(b"OTHER   BIN", other[0], if free.is_some() { other.len() as u32 * sector } else { 8 }, kind));
    let payload: Vec<u8> = (0..size).map(|index| (index % 251) as u8).collect();
    for (index, cluster) in CHAIN.into_iter().enumerate() {
        let mut bytes = vec![0xE7; sector as usize];
        let start = index * sector as usize;
        let length = payload.len().saturating_sub(start).min(bytes.len());
        if length != 0 { bytes[..length].copy_from_slice(&payload[start..start + length]); }
        state.put(BASE + geometry.cluster_offset(cluster).unwrap(), &bytes);
    }
    for cluster in (2..=count + 1).filter(|cluster| !links.contains_key(cluster)).take(32) {
        state.put(BASE + geometry.cluster_offset(cluster).unwrap(), &vec![0xD3; sector as usize]);
    }
    state.persist();
    let device = Device { state: Arc::new(Mutex::new(state)), length: BASE * 2 + geometry.volume_bytes() };
    let check = device.open().check(&Cx::for_testing()).unwrap();
    assert!(check.clean && check.complete && check.namespace_complete, "{check:?}");
    assert_eq!(check.preallocated_clusters, 2);
    if let Some(free) = free { assert_eq!(check.free_clusters, free.len() as u64); }
    device.reset();
    (device, geometry, payload)
}
fn insert(volume: &FatVolume, split: u64, count: u64) -> Result<()> {
    let cluster = u64::from(volume.geometry.cluster_bytes());
    volume.preallocate(&Cx::for_testing(), "/file.bin", split * cluster, count * cluster, libc::FALLOC_FL_INSERT_RANGE, NOW)
}
fn expected(original: &[u8], offset: usize, length: usize) -> Vec<u8> {
    let mut bytes = original[..offset].to_vec();
    bytes.resize(offset + length, 0); bytes.extend_from_slice(&original[offset..]); bytes
}
fn payload(volume: &FatVolume) -> Vec<u8> {
    let cx = Cx::for_testing();
    let entry = volume.resolve(&cx, "/file.bin").unwrap().unwrap();
    let chain = volume.file_chain(&cx, &entry).unwrap();
    volume.read(&cx, &chain, 0, chain.size as usize).unwrap()
}
fn expect_errno(result: Result<()>, want: i32) {
    let error = result.unwrap_err();
    assert_eq!(error.downcast_ref::<FfsError>().expect("native errno").to_errno(), want, "{error:#}");
}
fn old_payload(device: &Device, geometry: &FatGeometry) -> Vec<Vec<u8>> {
    CHAIN.iter().map(|&c| device.bytes(BASE + geometry.cluster_offset(c).unwrap(), geometry.cluster_bytes() as usize)).collect()
}

#[test]
fn insertion_preserves_fragmented_payload_preallocation_and_metadata_without_copying() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for sector in [512, 4096] {
            for active in [false, true] {
                if active && kind == FatKind::Fat16 { continue; }
                for split in [0, 2, 4] {
                    let (device, geometry, original) = fixture(kind, sector, active, None);
                    let volume = device.open(); let cx = Cx::for_testing();
                    let before = volume.check(&cx).unwrap();
                    let old_bytes = old_payload(&device, &geometry);
                    let record_before = device.bytes(root(&geometry), 32);
                    let neighbor = device.bytes(root(&geometry) + 32, 32);
                    let inactive = active.then(|| {
                        let start = BASE + geometry.entry_offset(0, 2).unwrap() - 8;
                        let size = geometry.entry_offset(1, 2).unwrap() - geometry.entry_offset(0, 2).unwrap();
                        (start, device.bytes(start, size as usize))
                    });
                    device.reset(); insert(&volume, split, 2).unwrap();
                    let events = device.state.lock().unwrap().events.clone();
                    for event in &events {
                        let (at, len) = match event {
                            Event::Read(at, len) => (*at, *len), Event::Write(_, at, bytes) => (*at, bytes.len()), Event::Sync => continue,
                        };
                        for cluster in CHAIN {
                            let start = BASE + geometry.cluster_offset(cluster).unwrap();
                            assert!(at + len as u64 <= start || at >= start + u64::from(sector), "old payload I/O: {event:?}");
                        }
                    }
                    assert_eq!(payload(&volume), expected(&original, split as usize * sector as usize, 2 * sector as usize));
                    assert_eq!(old_payload(&device, &geometry), old_bytes);
                    let entry = volume.resolve(&cx, "/file.bin").unwrap().unwrap();
                    let chain = volume.file_chain(&cx, &entry).unwrap();
                    let split = split as usize;
                    assert_eq!(&chain.clusters[..split], &CHAIN[..split]);
                    assert_eq!(&chain.clusters[split + 2..], &CHAIN[split..]);
                    let after = volume.check(&cx).unwrap();
                    assert!(after.clean && after.complete);
                    assert_eq!(after.free_clusters + 2, before.free_clusters);
                    assert_eq!(after.preallocated_clusters, before.preallocated_clusters);
                    let mut wanted = record_before;
                    let head = chain.clusters[0];
                    if kind == FatKind::Fat32 { wanted[20..22].copy_from_slice(&(0xA000 | (head >> 16) as u16).to_le_bytes()); }
                    wanted[26..28].copy_from_slice(&(head as u16).to_le_bytes());
                    wanted[28..32].copy_from_slice(&(original.len() as u32 + 2 * sector).to_le_bytes());
                    let (date, time) = modified_timestamp(NOW).unwrap();
                    wanted[22..24].copy_from_slice(&time.to_le_bytes()); wanted[24..26].copy_from_slice(&date.to_le_bytes()); wanted[11] |= 0x20;
                    assert_eq!(device.bytes(root(&geometry), 32), wanted);
                    assert_eq!(device.bytes(root(&geometry) + 32, 32), neighbor);
                    if let Some((at, bytes)) = inactive { assert_eq!(device.bytes(at, bytes.len()), bytes); }
                    if kind == FatKind::Fat32 {
                        for copy in if active { 1..2 } else { 0..2 } {
                            for &cluster in &chain.clusters {
                                assert_eq!(device.bytes(BASE + geometry.entry_offset(copy, cluster).unwrap() + 3, 1)[0] >> 4, 10 + copy);
                            }
                        }
                    }
                    assert_eq!(device.bytes(0, PAGE), [0xA7; PAGE]);
                    assert_eq!(device.bytes(BASE + geometry.volume_bytes(), PAGE), [0xB9; PAGE]);
                }
            }
        }
    }
}

#[test]
fn insertion_reserves_only_gap_capacity_and_never_consumes_existing_preallocation() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for free in [&[][..], &[8][..], &[8, 12][..]] {
            let (device, _, original) = fixture(kind, 512, false, Some(free));
            let volume = device.open(); let before = device.state.lock().unwrap().durable.clone();
            if free.len() < 2 {
                expect_errno(insert(&volume, 1, 2), libc::ENOSPC);
                assert_eq!(device.state.lock().unwrap().attempts, 0);
                assert_eq!(device.state.lock().unwrap().durable, before);
                assert_eq!(payload(&volume), original);
            } else {
                insert(&volume, 1, 2).unwrap();
                assert_eq!(payload(&volume), expected(&original, 512, 1024));
                let report = volume.check(&Cx::for_testing()).unwrap();
                assert!(report.clean); assert_eq!(report.free_clusters, 0); assert_eq!(report.preallocated_clusters, 2);
            }
        }
    }
}

#[test]
fn insertion_invalid_ranges_flags_overflow_and_cancellation_are_no_write_refusals() {
    let (device, _, original) = fixture(FatKind::Fat16, 512, false, None);
    let volume = device.open(); let cx = Cx::for_testing();
    for (offset, length, code) in [(0, 0, libc::EINVAL), (1, 512, libc::EINVAL), (0, 513, libc::EINVAL),
        (2560, 512, libc::EINVAL), (0, 1_u64 << 32, libc::EFBIG), (0, u64::MAX - 511, libc::EFBIG)] {
        expect_errno(volume.preallocate(&cx, "/file.bin", offset, length, libc::FALLOC_FL_INSERT_RANGE, NOW), code);
    }
    for extra in [libc::FALLOC_FL_KEEP_SIZE, libc::FALLOC_FL_ZERO_RANGE, libc::FALLOC_FL_COLLAPSE_RANGE, libc::FALLOC_FL_PUNCH_HOLE] {
        expect_errno(volume.preallocate(&cx, "/file.bin", 0, 512, libc::FALLOC_FL_INSERT_RANGE | extra, NOW), libc::EOPNOTSUPP);
    }
    expect_errno(volume.preallocate(&cx, "/", 0, 512, libc::FALLOC_FL_INSERT_RANGE, NOW), libc::EISDIR);
    assert!(volume.preallocate(&cx, "/file.bin", 0, 512, libc::FALLOC_FL_INSERT_RANGE, u64::MAX).is_err());
    let cancelled = Cx::for_testing(); cancelled.set_cancel_requested(true);
    assert!(volume.preallocate(&cancelled, "/file.bin", 0, 512, libc::FALLOC_FL_INSERT_RANGE, NOW).is_err());
    assert_eq!(device.state.lock().unwrap().attempts, 0);
    assert_eq!(payload(&volume), original);
    // INSERT_RANGE constrains the offset, not offset+length relative to old EOF.
    insert(&volume, 4, 8).unwrap();
    assert_eq!(payload(&volume), expected(&original, 2048, 4096));
}

#[test]
fn insertion_refuses_readonly_dirty_empty_crosslinked_or_disagreeing_allocation() {
    for case in 0..5 {
        let (device, geometry, _) = fixture(FatKind::Fat32, 512, false, None);
        let volume = device.open();
        {
            let mut state = device.state.lock().unwrap();
            match case {
                0 => state.put(root(&geometry) + 11, &[7]),
                1 => state.put(BASE + 65, &[1]),
                2 => state.put(root(&geometry) + 28, &[0; 4]),
                3 => state.put(root(&geometry) + 32, &record(b"OTHER   BIN", CHAIN[0], 8, FatKind::Fat32)),
                _ => state.put(BASE + geometry.entry_offset(1, CHAIN[0]).unwrap(), &0xBFFF_FFFF_u32.to_le_bytes()),
            }
            state.persist();
        }
        let before = device.state.lock().unwrap().durable.clone();
        assert!(insert(&volume, 0, 1).is_err(), "case {case}");
        assert_eq!(device.state.lock().unwrap().attempts, 0);
        assert_eq!(device.state.lock().unwrap().durable, before);
    }
}

#[test]
fn prefix_insertion_handles_high_fat32_heads_and_roundtrips_through_collapse() {
    let (device, geometry, original) = fixture(FatKind::Fat32, 512, true, Some(&[65_536, 65_538]));
    let volume = device.open();
    insert(&volume, 0, 2).unwrap();
    assert_eq!(payload(&volume), expected(&original, 0, 1024));
    let raw = device.bytes(root(&geometry), 32);
    assert_eq!(u16::from_le_bytes(raw[20..22].try_into().unwrap()), 0xA001);
    assert_eq!(u16::from_le_bytes(raw[26..28].try_into().unwrap()), 0);
    volume.preallocate(&Cx::for_testing(), "/file.bin", 0, 1024, libc::FALLOC_FL_COLLAPSE_RANGE, NOW).unwrap();
    assert_eq!(payload(&volume), original);
    let entry = volume.resolve(&Cx::for_testing(), "/file.bin").unwrap().unwrap();
    assert_eq!(volume.file_chain(&Cx::for_testing(), &entry).unwrap().clusters, CHAIN);
    assert_eq!(volume.check(&Cx::for_testing()).unwrap().free_clusters, 2);
}

#[test]
fn dropped_zero_initialization_cannot_publish_links_or_hide_existing_eof() {
    let (probe, geometry, _) = fixture(FatKind::Fat16, 512, false, None);
    insert(&probe.open(), 0, 2).unwrap();
    let data = BASE + geometry.cluster_offset(2).unwrap();
    let cut = probe.state.lock().unwrap().events.iter().find_map(|event| match event {
        Event::Write(n, at, _) if *at == data => Some(*n), _ => None,
    }).unwrap();
    for fault in [Fault::Drop, Fault::Error(511), Fault::Cancel] {
        let (device, _, original) = fixture(FatKind::Fat16, 512, false, None);
        let volume = device.open(); let old = old_payload(&device, &geometry);
        let raw = device.bytes(root(&geometry), 32);
        device.state.lock().unwrap().fault = Some((cut, fault));
        assert!(insert(&volume, 0, 2).is_err());
        assert_eq!(device.bytes(root(&geometry), 32), raw);
        assert_eq!(old_payload(&device, &geometry), old);
        assert_eq!(payload(&volume), original);
        for copy in 0..2 { assert_eq!(device.bytes(BASE + geometry.entry_offset(copy, 2).unwrap(), 2), [0; 2]); }
    }
}

#[test]
fn dropped_link_and_record_publications_are_detected_without_freeing_original_clusters() {
    for split in [0, 2] {
        let (probe, geometry, _) = fixture(FatKind::Fat16, 512, false, None);
        insert(&probe.open(), split, 2).unwrap();
        let fat = BASE + geometry.entry_offset(0, 2).unwrap() - 4;
        let cuts: Vec<_> = probe.state.lock().unwrap().events.iter().filter_map(|event| match event {
            Event::Write(n, at, bytes) if *at == root(&geometry) || (*at == fat && bytes[4..6] != [0; 2]) => Some(*n),
            _ => None,
        }).collect();
        assert!(cuts.len() >= 4);
        for cut in cuts {
            let (device, _, _) = fixture(FatKind::Fat16, 512, false, None);
            let volume = device.open(); let old = old_payload(&device, &geometry);
            device.state.lock().unwrap().fault = Some((cut, Fault::Drop));
            assert!(insert(&volume, split, 2).is_err(), "split={split} cut={cut}");
            assert_eq!(old_payload(&device, &geometry), old);
            for cluster in CHAIN {
                for copy in 0..2 { assert_ne!(device.bytes(BASE + geometry.entry_offset(copy, cluster).unwrap(), 2), [0; 2]); }
            }
        }
    }
}

#[test]
fn every_insertion_write_or_sync_failure_preserves_old_payload_and_clean_admission() {
    for split in [0, 2] {
        let (probe, geometry, original) = fixture(FatKind::Fat16, 512, false, None);
        insert(&probe.open(), split, 2).unwrap();
        let total = probe.state.lock().unwrap().attempts;
        let wanted = expected(&original, split as usize * 512, 1024);
        for cut in 1..=total {
            for tear in [0, 31, 511, 512] {
                let (device, _, _) = fixture(FatKind::Fat16, 512, false, None);
                let volume = device.open(); let old = old_payload(&device, &geometry);
                device.state.lock().unwrap().fault = Some((cut, Fault::Error(tear)));
                assert!(insert(&volume, split, 2).is_err(), "split={split} cut={cut}");
                assert_eq!(device.state.lock().unwrap().attempts, cut);
                assert_eq!(old_payload(&device, &geometry), old);
                for retain in [false, true] {
                    let crashed = device.restart(retain); let cx = Cx::for_testing();
                    if let Ok(volume) = FatVolume::from_device(&cx, Box::new(crashed), BASE, geometry.volume_bytes()) {
                        assert!(volume.check(&cx).unwrap().clean, "split={split} cut={cut} tear={tear}");
                        let bytes = payload(&volume); assert!(bytes == original || bytes == wanted);
                    }
                }
            }
        }
    }
}

#[test]
fn insertion_readback_failure_and_torn_prefix_head_keep_eof_hidden() {
    let (probe, geometry, _) = fixture(FatKind::Fat16, 512, false, None);
    insert(&probe.open(), 0, 2).unwrap();
    let cuts: Vec<_> = probe.state.lock().unwrap().events.iter().filter_map(|event| match event {
        Event::Write(n, at, _) if *at == root(&geometry) => Some(*n), _ => None,
    }).collect();
    assert_eq!(cuts.len(), 3);
    let (device, _, _) = fixture(FatKind::Fat16, 512, false, None);
    let volume = device.open();
    device.state.lock().unwrap().fault = Some((cuts[1], Fault::Error(28)));
    assert!(insert(&volume, 0, 2).is_err());
    assert_eq!(device.bytes(root(&geometry) + 28, 4), [0; 4]);
    assert_eq!(device.bytes(root(&geometry) + 26, 2), 2_u16.to_le_bytes());
    let (device, _, _) = fixture(FatKind::Fat16, 512, false, None);
    let volume = device.open(); let original = old_payload(&device, &geometry);
    device.state.lock().unwrap().read_failure_after = Some(cuts[0]);
    assert!(insert(&volume, 0, 2).is_err());
    assert_eq!(device.state.lock().unwrap().attempts, cuts[0] + 1); // sync, then failed readback
    assert_eq!(old_payload(&device, &geometry), original);
}

#[test]
fn mounted_insertion_refreshes_held_inode_allocation_and_payload_cache() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let (device, _, original) = fixture(kind, 512, false, Some(&[8, 12]));
        let cx = Cx::for_testing();
        let fs = crate::filesystem::FatFs::new_with_mode(&cx, device.open(), 1000, 1000, true).unwrap();
        let mut scope = RequestScope::empty();
        let ino = fs.lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("FILE.BIN")).unwrap().ino;
        assert_ne!(fs.open(&cx, &mut scope, ino, libc::O_RDWR).unwrap().0, 0);
        assert_eq!(fs.read(&cx, &mut scope, ino, 0, 4096).unwrap(), original);
        assert_eq!(fs.statfs(&cx, &mut scope, ino).unwrap().blocks_free, 2);
        fs.fallocate(&cx, &mut scope, ino, 512, 1024, libc::FALLOC_FL_INSERT_RANGE).unwrap();
        let attr = fs.getattr(&cx, &mut scope, ino).unwrap();
        assert_eq!(attr.size, original.len() as u64 + 1024); assert_eq!(attr.blocks, 9);
        assert_eq!(fs.statfs(&cx, &mut scope, ino).unwrap().blocks_free, 0);
        assert_eq!(fs.lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("file.bin")).unwrap().ino, ino);
        let mut wanted = expected(&original, 512, 1024);
        assert_eq!(fs.read(&cx, &mut scope, ino, 0, 8192).unwrap(), wanted);
        fs.write(&cx, &mut scope, ino, 513, b"held handle").unwrap();
        wanted[513..524].copy_from_slice(b"held handle");
        assert_eq!(fs.read(&cx, &mut scope, ino, 0, 8192).unwrap(), wanted);
    }
}

#[test]
fn mounted_preflight_refusal_keeps_mount_usable_and_failed_insertion_quarantines() {
    for cancel in [false, true] {
        let (device, _, _) = fixture(FatKind::Fat16, 512, false, None);
        let cx = Cx::for_testing();
        let fs = crate::filesystem::FatFs::new_with_mode(&cx, device.open(), 0, 0, true).unwrap();
        let mut scope = RequestScope::empty();
        let ino = fs.lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("file.bin")).unwrap().ino;
        device.reset();
        assert_eq!(fs.fallocate(&cx, &mut scope, ino, 1, 512, libc::FALLOC_FL_INSERT_RANGE).unwrap_err().to_errno(), libc::EINVAL);
        fs.getattr(&cx, &mut scope, ino).unwrap(); assert_eq!(device.state.lock().unwrap().attempts, 0);
        device.state.lock().unwrap().fault = Some((1, if cancel { Fault::Cancel } else { Fault::Error(64) }));
        assert!(fs.fallocate(&cx, &mut scope, ino, 0, 512, libc::FALLOC_FL_INSERT_RANGE).is_err());
        let fresh = Cx::for_testing();
        assert_eq!(fs.getattr(&fresh, &mut scope, ino).unwrap_err().to_errno(), libc::EIO);
        assert_eq!(fs.read(&fresh, &mut scope, ino, 0, 1).unwrap_err().to_errno(), libc::EIO);
        assert_eq!(fs.statfs(&fresh, &mut scope, ino).unwrap_err().to_errno(), libc::EIO);
    }
}

#[test]
fn concurrent_insertions_serialize_reservations_and_shifted_cache_state() {
    let (device, _, original) = fixture(FatKind::Fat32, 512, false, Some(&[8, 12]));
    let cx = Cx::for_testing();
    let fs = crate::filesystem::FatFs::new_with_mode(&cx, device.open(), 0, 0, true).unwrap();
    let ino = fs.lookup(&cx, &mut RequestScope::empty(), InodeNumber(1), OsStr::new("file.bin")).unwrap().ino;
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|threads| {
        for _ in 0..2 {
            let (fs, barrier) = (&fs, &barrier);
            threads.spawn(move || {
                barrier.wait();
                fs.fallocate(&Cx::for_testing(), &mut RequestScope::empty(), ino, 512, 512, libc::FALLOC_FL_INSERT_RANGE).unwrap();
            });
        }
    });
    assert_eq!(fs.read(&cx, &mut RequestScope::empty(), ino, 0, 8192).unwrap(), expected(&original, 512, 1024));
    let check = device.open().check(&cx).unwrap();
    assert!(check.clean); assert_eq!(check.free_clusters, 0); assert_eq!(check.preallocated_clusters, 2);
}

#[test]
fn insertion_through_unlinked_handle_never_addresses_replacement_name() {
    let (device, _, original) = fixture(FatKind::Fat32, 512, false, None);
    let cx = Cx::for_testing();
    let fs = crate::filesystem::FatFs::new_with_mode(&cx, device.open(), 1000, 1000, true).unwrap();
    let mut scope = RequestScope::empty();
    let root = InodeNumber(1);
    let ino = fs.lookup(&cx, &mut scope, root, OsStr::new("FILE.BIN")).unwrap().ino;
    fs.open(&cx, &mut scope, ino, libc::O_RDWR).unwrap();
    fs.unlink(&cx, &mut scope, root, OsStr::new("FILE.BIN")).unwrap();
    assert_eq!(fs.lookup(&cx, &mut scope, root, OsStr::new("FILE.BIN")).unwrap_err().to_errno(), libc::ENOENT);
    let replacement = fs.create(&cx, &mut scope, root, OsStr::new("FILE.BIN"), 0o644, 1000, 1000).unwrap();
    assert_ne!(replacement.ino, ino);
    fs.write(&cx, &mut scope, replacement.ino, 0, b"different object").unwrap();
    fs.fallocate(&cx, &mut scope, ino, 0, 1024, libc::FALLOC_FL_INSERT_RANGE).unwrap();
    assert_eq!(fs.read(&cx, &mut scope, ino, 0, 8192).unwrap(), expected(&original, 0, 1024));
    assert_eq!(fs.read(&cx, &mut scope, replacement.ino, 0, 8192).unwrap(), b"different object");
    assert_eq!(fs.lookup(&cx, &mut scope, root, OsStr::new("file.bin")).unwrap().ino, replacement.ino);
    assert!(device.open().check(&cx).unwrap().clean);
}
