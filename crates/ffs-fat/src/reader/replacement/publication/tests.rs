//! Constructed native images and fault injection, not native-tool qualification.
use super::*;
use crate::reader::replacement::{SliceSource, creation};
use ffs_block::ByteDevice;
use ffs_error::FfsError;
use ffs_ondisk::fat::{FatGeometry, FatKind};
use ffs_types::ByteOffset;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

const BASE: u64 = 4096;
const NOW: u64 = 1_700_000_000;
type Pages = BTreeMap<u64, [u8; 512]>;

#[derive(Clone, Copy)]
enum Fault {
    Drop,
    Prefix(usize),
    Error(usize),
    Cancel,
    Corrupt(u64),
}

#[derive(Default)]
struct State {
    durable: Pages,
    pending: Pages,
    attempts: usize,
    writes: Vec<(usize, u64, Vec<u8>)>,
    reads: Vec<(usize, u64, usize)>,
    fault: Option<(usize, Fault)>,
    fail_read: Option<u64>,
    cancel_read: bool,
}

impl State {
    fn read(&self, at: u64, bytes: &mut [u8]) {
        for (index, byte) in bytes.iter_mut().enumerate() {
            let position = at + index as u64;
            *byte = self.pending.get(&(position / 512))
                .or_else(|| self.durable.get(&(position / 512)))
                .map_or(0, |page| page[(position % 512) as usize]);
        }
    }

    fn put(&mut self, at: u64, bytes: &[u8]) {
        for (index, &byte) in bytes.iter().enumerate() {
            let position = at + index as u64;
            let key = position / 512;
            let old = self.durable.get(&key).copied().unwrap_or([0; 512]);
            self.pending.entry(key).or_insert(old)[(position % 512) as usize] = byte;
        }
    }

    fn persist(&mut self) {
        self.durable.append(&mut self.pending);
    }
}

#[derive(Clone)]
struct Device {
    state: Arc<Mutex<State>>,
    length: u64,
}

impl Device {
    fn bytes(&self, at: u64, size: usize) -> Vec<u8> {
        let mut bytes = vec![0; size];
        self.state.lock().unwrap().read(at, &mut bytes);
        bytes
    }

    fn open(&self) -> FatVolume {
        FatVolume::from_device(
            &Cx::for_testing(), Box::new(self.clone()), BASE, self.length - 2 * BASE,
        ).unwrap()
    }

    fn restart(&self, retain: bool) -> Self {
        let state = self.state.lock().unwrap();
        let mut durable = state.durable.clone();
        if retain {
            durable.extend(state.pending.clone());
        }
        Self {
            state: Arc::new(Mutex::new(State { durable, ..State::default() })),
            length: self.length,
        }
    }
}

impl ByteDevice for Device {
    fn len_bytes(&self) -> u64 {
        self.length
    }

    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        assert!(at.0.checked_add(bytes.len() as u64).is_some_and(|end| end <= self.length));
        let mut state = self.state.lock().unwrap();
        let attempt = state.attempts;
        state.reads.push((attempt, at.0, bytes.len()));
        if state.fail_read.is_some_and(|bad| at.0 <= bad && bad < at.0 + bytes.len() as u64) {
            bytes.fill(0xEE);
            if state.cancel_read {
                cx.set_cancel_requested(true);
                return Err(FfsError::Cancelled);
            }
            return Err(std::io::Error::other("injected staged read failure").into());
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
        state.writes.push((attempt, at.0, bytes.to_vec()));
        match state.fault.filter(|(cut, _)| *cut == attempt).map(|(_, fault)| fault) {
            Some(Fault::Drop) => return Ok(()),
            Some(Fault::Prefix(count)) => state.put(at.0, &bytes[..count.min(bytes.len())]),
            Some(Fault::Error(count)) => {
                state.put(at.0, &bytes[..count.min(bytes.len())]);
                return Err(std::io::Error::other("injected publication write failure").into());
            }
            Some(Fault::Cancel) => {
                state.put(at.0, bytes);
                cx.set_cancel_requested(true);
                return Err(FfsError::Cancelled);
            }
            Some(Fault::Corrupt(position)) => {
                state.put(at.0, bytes);
                let mut byte = [0];
                state.read(position, &mut byte);
                byte[0] ^= 1;
                state.put(position, &byte);
            }
            None => state.put(at.0, bytes),
        }
        Ok(())
    }

    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        let mut state = self.state.lock().unwrap();
        state.attempts += 1;
        if state.fault.is_some_and(|(cut, _)| cut == state.attempts) {
            return Err(std::io::Error::other("injected publication sync failure").into());
        }
        state.persist();
        Ok(())
    }
}

fn record(name: &[u8; 11], first: u32, size: u32, kind: FatKind) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..11].copy_from_slice(name);
    bytes[11] = 0x26;
    bytes[13] = 157;
    for at in [16, 18, 24] {
        bytes[at..at + 2].copy_from_slice(&0x21_u16.to_le_bytes());
    }
    let high = if kind == FatKind::Fat32 { 0xA000 | (first >> 16) as u16 } else { 0x1234 };
    bytes[20..22].copy_from_slice(&high.to_le_bytes());
    bytes[26..28].copy_from_slice(&(first as u16).to_le_bytes());
    bytes[28..32].copy_from_slice(&size.to_le_bytes());
    bytes
}

fn fixture(kind: FatKind, sector: u32, active: bool) -> (Device, FatGeometry, u64) {
    let count = if kind == FatKind::Fat16 { 5000_u32 } else { 70_000 };
    let reserved = if kind == FatKind::Fat16 { 1_u32 } else { 32 };
    let width = kind.entry_bytes();
    let fat = ((count + 2) * width).div_ceil(sector);
    let roots = if kind == FatKind::Fat16 { (sector / 32).max(32) as u16 } else { 0 };
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
    let length = u64::from(total) * u64::from(sector);
    let geometry = FatGeometry::parse(&boot, length).unwrap();
    let mut state = State::default();
    state.put(0, &[0xA7; 512]);
    state.put(BASE + length, &[0xB9; 512]);
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
    let end = if kind == FatKind::Fat16 { 0xFFFF_u32 } else { 0x0FFF_FFFF };
    for copy in 0..2_u8 {
        let start = BASE + u64::from(reserved + u32::from(copy) * fat) * u64::from(sector);
        for cluster in 0..16_u32 {
            let low = match cluster {
                0 => end & !7,
                1 | 5 | 9 => end,
                2 if kind == FatKind::Fat32 => end,
                7 => 9,
                _ => 0,
            };
            let high = if kind == FatKind::Fat32 { (10 + u32::from(copy)) << 28 } else { 0 };
            state.put(start + u64::from(cluster * width), &(low | high).to_le_bytes()[..width as usize]);
        }
    }
    if active {
        state.put(BASE + geometry.entry_offset(0, 7).unwrap(), &0xA000_0001_u32.to_le_bytes());
    }
    let root = geometry.fixed_root().map_or_else(|| geometry.cluster_offset(2).unwrap(), |(at, _)| at);
    state.put(BASE + root, &record(b"OLD     BIN", 7, sector + 7, kind));
    state.put(BASE + root + 32, &record(b"KEEP    BIN", 5, 4, kind));
    let mut deleted = record(b"DELETED BIN", 5, 4, kind);
    deleted[0] = 0xE5;
    state.put(BASE + root + 64, &deleted);
    state.put(BASE + geometry.cluster_offset(5).unwrap(), b"SAFE");
    for cluster in 3..16 {
        if cluster != 5 {
            let byte = if cluster == 7 || cluster == 9 { 0x31 } else { 0xE7 };
            state.put(BASE + geometry.cluster_offset(cluster).unwrap(), &vec![byte; sector as usize]);
        }
    }
    state.persist();
    let device = Device { state: Arc::new(Mutex::new(state)), length: length + 2 * BASE };
    assert!(device.open().check(&Cx::for_testing()).unwrap().clean);
    (device, geometry, BASE + root)
}

fn plan(cx: &Cx, volume: &FatVolume, source: &SliceSource<'_>, create: bool) -> Replacement {
    if create {
        creation::prepare(cx, volume, "/Fresh name.bin", source, NOW).unwrap()
    } else {
        Replacement::prepare(cx, volume, "/OLD.BIN", source, NOW).unwrap()
    }
}

fn payload(volume: &FatVolume, path: &str) -> Vec<u8> {
    let cx = Cx::for_testing();
    let entry = volume.resolve(&cx, path).unwrap().unwrap();
    let chain = volume.file_chain(&cx, &entry).unwrap();
    volume.read(&cx, &chain, 0, chain.size as usize).unwrap()
}

fn guards(device: &Device, geometry: &FatGeometry) {
    assert_eq!(device.bytes(0, 512), vec![0xA7; 512]);
    assert_eq!(device.bytes(BASE + geometry.volume_bytes(), 512), vec![0xB9; 512]);
    assert_eq!(device.bytes(BASE + geometry.cluster_offset(5).unwrap(), 4), b"SAFE");
}

#[test]
fn staged_replacement_roundtrips_dialects_sector_widths_active_fat_and_slack() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for sector in [512, 4096] {
            for active in [false, true] {
                if active && kind == FatKind::Fat16 { continue; }
                for create in [false, true] {
                    let (device, geometry, root) = fixture(kind, sector, active);
                    let old_record = device.bytes(root, 32);
                    let inactive_start = BASE + geometry.entry_offset(0, 2).unwrap() - 8;
                    let inactive = if active { device.bytes(inactive_start, sector as usize) } else { Vec::new() };
                    let bytes = vec![0x93; 2 * sector as usize + 17];
                    let source = SliceSource(&bytes);
                    let volume = device.open();
                    let plan = plan(&cx, &volume, &source, create);
                    plan.execute(&cx, &volume, &source, || Ok(())).unwrap();
                    let reopened = device.open();
                    assert_eq!(payload(&reopened, &plan.path), bytes);
                    assert!(reopened.check(&cx).unwrap().clean);
                    if create { assert_eq!(device.bytes(root, 32), old_record); }
                    let last = *plan.clusters.last().unwrap();
                    assert_eq!(device.bytes(BASE + geometry.cluster_offset(last).unwrap() + 17,
                        sector as usize - 17), vec![0; sector as usize - 17]);
                    if active { assert_eq!(device.bytes(inactive_start, sector as usize), inactive); }
                    guards(&device, &geometry);
                }
            }
        }
    }
}

#[test]
fn dropped_payload_stops_before_allocation_or_any_file_publication() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for create in [false, true] {
            let (probe, geometry, _) = fixture(kind, 512, false);
            let bytes = vec![0x93; 1041];
            let source = SliceSource(&bytes);
            let volume = probe.open();
            let prepared = plan(&cx, &volume, &source, create);
            let physical = BASE + geometry.cluster_offset(prepared.clusters[0]).unwrap();
            prepared.execute(&cx, &volume, &source, || Ok(())).unwrap();
            let cut = probe.state.lock().unwrap().writes.iter().find(|(_, at, _)| *at == physical).unwrap().0;
            let (device, _, root) = fixture(kind, 512, false);
            let volume = device.open();
            let prepared = plan(&cx, &volume, &source, create);
            let directory = device.bytes(root, 512);
            device.state.lock().unwrap().fault = Some((cut, Fault::Drop));
            let error = prepared.execute(&cx, &volume, &source, || Ok(())).unwrap_err();
            assert!(format!("{error:#}").contains("staged replacement"));
            assert_eq!(device.bytes(root, 512), directory);
            let mut table = FatTable::new(&volume);
            for cluster in prepared.clusters { assert_eq!(table.entry(&cx, cluster).unwrap(), FatEntry::Free); }
            assert_eq!(payload(&volume, "/OLD.BIN"), vec![0x31; 519]);
            guards(&device, &geometry);
        }
    }
}

#[test]
fn correct_payload_with_dropped_slack_is_not_publishable() {
    let cx = Cx::for_testing();
    let (probe, geometry, _) = fixture(FatKind::Fat32, 4096, false);
    let source = SliceSource(b"replacement");
    let volume = probe.open();
    let prepared = plan(&cx, &volume, &source, false);
    let physical = BASE + geometry.cluster_offset(prepared.clusters[0]).unwrap();
    prepared.execute(&cx, &volume, &source, || Ok(())).unwrap();
    let cut = probe.state.lock().unwrap().writes.iter().find(|(_, at, _)| *at == physical).unwrap().0;
    let (device, _, root) = fixture(FatKind::Fat32, 4096, false);
    let volume = device.open();
    let prepared = plan(&cx, &volume, &source, false);
    let original = device.bytes(root, 32);
    device.state.lock().unwrap().fault = Some((cut, Fault::Prefix(source.0.len())));
    let error = prepared.execute(&cx, &volume, &source, || Ok(())).unwrap_err();
    assert!(format!("{error:#}").contains("slack"));
    assert_eq!(device.bytes(root, 32), original);
    assert_eq!(device.bytes(physical, source.0.len()), source.0);
}

fn allocation_cut(device: &Device, geometry: &FatGeometry, cluster: u32, copy: u8) -> usize {
    let position = BASE + geometry.entry_offset(copy, cluster).unwrap();
    let width = geometry.kind().entry_bytes() as usize;
    device.state.lock().unwrap().writes.iter().find(|(_, at, bytes)| {
        if *at > position || position + width as u64 > *at + bytes.len() as u64 { return false; }
        let within = (position - *at) as usize;
        let mut value = [0; 4];
        value[..width].copy_from_slice(&bytes[within..within + width]);
        geometry.kind().decode_entry(u32::from_le_bytes(value)) != FatEntry::Free
    }).unwrap().0
}

#[test]
fn dropped_selected_allocation_stops_before_namespace_or_old_reclamation() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for copy in 0..2 {
            let (probe, geometry, _) = fixture(kind, 512, false);
            let source = SliceSource(&[0x93; 1041]);
            let volume = probe.open();
            let prepared = plan(&cx, &volume, &source, false);
            let cluster = prepared.clusters[0];
            prepared.execute(&cx, &volume, &source, || Ok(())).unwrap();
            let cut = allocation_cut(&probe, &geometry, cluster, copy);
            let (device, _, root) = fixture(kind, 512, false);
            let volume = device.open();
            let prepared = plan(&cx, &volume, &source, false);
            let original = device.bytes(root, 32);
            device.state.lock().unwrap().fault = Some((cut, Fault::Drop));
            assert!(prepared.execute(&cx, &volume, &source, || Ok(())).is_err());
            assert_eq!(device.bytes(root, 32), original);
            assert_eq!(payload(&volume, "/OLD.BIN"), vec![0x31; 519]);
            assert!(!device.state.lock().unwrap().writes.iter().any(|(_, at, _)| *at == root));
            guards(&device, &geometry);
        }
    }
}

#[test]
fn stale_reservations_and_retained_links_are_prewrite_refusals() {
    let cx = Cx::for_testing();
    for reserved in [false, true] {
        let (device, geometry, _) = fixture(FatKind::Fat16, 512, false);
        let volume = device.open();
        let source = SliceSource(b"new contents");
        let prepared = plan(&cx, &volume, &source, false);
        let cluster = if reserved { prepared.clusters[0] } else { 7 };
        {
            let mut state = device.state.lock().unwrap();
            for copy in 0..2 {
                state.put(BASE + geometry.entry_offset(copy, cluster).unwrap(), &0xFFFF_u16.to_le_bytes());
            }
            state.persist();
        }
        let before = device.state.lock().unwrap().durable.clone();
        assert!(prepared.execute(&cx, &volume, &source, || Ok(())).is_err());
        let state = device.state.lock().unwrap();
        assert_eq!(state.attempts, 0);
        assert_eq!(state.durable, before);
        assert!(state.pending.is_empty());
    }
}

#[test]
fn retained_link_damage_in_new_fat_sector_cannot_publish_replacement() {
    let cx = Cx::for_testing();
    let (probe, geometry, _) = fixture(FatKind::Fat32, 512, true);
    let source = SliceSource(b"new contents");
    let volume = probe.open();
    let prepared = plan(&cx, &volume, &source, false);
    let cluster = prepared.clusters[0];
    prepared.execute(&cx, &volume, &source, || Ok(())).unwrap();
    let cut = allocation_cut(&probe, &geometry, cluster, 1);
    let (device, _, root) = fixture(FatKind::Fat32, 512, true);
    let volume = device.open();
    let prepared = plan(&cx, &volume, &source, false);
    let original = device.bytes(root, 32);
    device.state.lock().unwrap().fault = Some((cut, Fault::Corrupt(BASE + geometry.entry_offset(1, 7).unwrap())));
    let error = prepared.execute(&cx, &volume, &source, || Ok(())).unwrap_err();
    assert!(format!("{error:#}").contains("retained allocation"));
    assert_eq!(device.bytes(root, 32), original);
}

#[test]
fn staged_payload_read_error_or_cancellation_never_publishes_namespace() {
    for cancel in [false, true] {
        let cx = Cx::for_testing();
        let (device, geometry, root) = fixture(FatKind::Fat32, 512, false);
        let volume = device.open();
        let source = SliceSource(b"new contents");
        let prepared = plan(&cx, &volume, &source, false);
        let original = device.bytes(root, 32);
        {
            let mut state = device.state.lock().unwrap();
            state.fail_read = Some(BASE + geometry.cluster_offset(prepared.clusters[0]).unwrap());
            state.cancel_read = cancel;
        }
        assert!(prepared.execute(&cx, &volume, &source, || Ok(())).is_err());
        assert_eq!(device.bytes(root, 32), original);
        assert!(!device.state.lock().unwrap().writes.iter().any(|(_, at, _)| *at == root));
    }
}

#[test]
fn directory_neighbor_corruption_fails_before_old_allocation_release() {
    let cx = Cx::for_testing();
    let (probe, geometry, root) = fixture(FatKind::Fat16, 512, false);
    let source = SliceSource(b"new contents");
    let volume = probe.open();
    let prepared = plan(&cx, &volume, &source, false);
    prepared.execute(&cx, &volume, &source, || Ok(())).unwrap();
    let cut = probe.state.lock().unwrap().writes.iter().find(|(_, at, _)| *at == root).unwrap().0;
    let (device, _, _) = fixture(FatKind::Fat16, 512, false);
    let volume = device.open();
    let prepared = plan(&cx, &volume, &source, false);
    device.state.lock().unwrap().fault = Some((cut, Fault::Corrupt(root + 32 + 13)));
    let error = prepared.execute(&cx, &volume, &source, || Ok(())).unwrap_err();
    assert!(format!("{error:#}").contains("directory sector"));
    let mut table = FatTable::new(&volume);
    assert_eq!(table.entry(&cx, 7).unwrap(), FatEntry::Next(9));
    assert_eq!(table.entry(&cx, 9).unwrap(), FatEntry::End);
    guards(&device, &geometry);
}

#[test]
fn every_write_sync_failure_and_write_cancellation_retains_original_payload() {
    let cx = Cx::for_testing();
    let (probe, geometry, _) = fixture(FatKind::Fat16, 512, false);
    let source = SliceSource(&[0x93; 1041]);
    let volume = probe.open();
    let prepared = plan(&cx, &volume, &source, false);
    prepared.execute(&cx, &volume, &source, || Ok(())).unwrap();
    let total = probe.state.lock().unwrap().attempts;
    for cut in 1..=total {
        for fault in [Fault::Error(0), Fault::Error(31), Fault::Error(511), Fault::Cancel] {
            let request = Cx::for_testing();
            let (device, _, _) = fixture(FatKind::Fat16, 512, false);
            let volume = device.open();
            let prepared = plan(&request, &volume, &source, false);
            let retained: Vec<_> = [7, 9].map(|cluster| {
                device.bytes(BASE + geometry.cluster_offset(cluster).unwrap(), 512)
            }).into_iter().collect();
            device.state.lock().unwrap().fault = Some((cut, fault));
            assert!(prepared.execute(&request, &volume, &source, || Ok(())).is_err());
            assert_eq!(device.state.lock().unwrap().attempts, cut);
            for (index, cluster) in [7, 9].into_iter().enumerate() {
                assert_eq!(device.bytes(BASE + geometry.cluster_offset(cluster).unwrap(), 512), retained[index]);
            }
            for keep in [false, true] {
                let restarted = device.restart(keep);
                if let Ok(reopened) = FatVolume::from_device(
                    &cx, Box::new(restarted), BASE, geometry.volume_bytes(),
                ) {
                    assert!(reopened.check(&cx).unwrap().clean);
                    let bytes = payload(&reopened, "/OLD.BIN");
                    assert!(bytes == vec![0x31; 519] || bytes == source.0);
                }
            }
            guards(&device, &geometry);
        }
    }
}

fn head(kind: FatKind, bytes: &[u8]) -> u32 {
    let low = u32::from(u16::from_le_bytes([bytes[26], bytes[27]]));
    if kind == FatKind::Fat16 {
        low
    } else {
        low | (u32::from(u16::from_le_bytes([bytes[20], bytes[21]]) & 0x0FFF) << 16)
    }
}

fn size(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[28..32].try_into().unwrap())
}

#[test]
fn replacement_separates_old_eof_new_head_and_final_length_publications() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for sector in [512, 4096] {
            for empty in [false, true] {
                let (device, geometry, root) = fixture(kind, sector, false);
                let source = SliceSource(if empty { b"" } else { b"new file" });
                let volume = device.open();
                let prepared = plan(&cx, &volume, &source, false);
                prepared.execute(&cx, &volume, &source, || Ok(())).unwrap();
                let state = device.state.lock().unwrap();
                let writes: Vec<_> = state.writes.iter().filter(|(_, at, _)| *at == root).collect();
                assert_eq!(writes.len(), if empty { 2 } else { 3 });
                assert_eq!(head(kind, &writes[0].2), 7);
                assert_eq!(size(&writes[0].2), 0);
                assert_eq!(head(kind, &writes[1].2), prepared.clusters.first().copied().unwrap_or(0));
                assert_eq!(size(&writes[1].2), 0);
                for pair in writes.windows(2) {
                    // A sync and exact readback intervene before each next write.
                    assert!(state.reads.iter().any(|&(attempt, at, length)| {
                        attempt > pair[0].0 && attempt < pair[1].0
                            && at == root && length == sector as usize
                    }));
                }
                assert_eq!(&writes.last().unwrap().2[..32], &prepared.updated);
                drop(state);
                assert_eq!(payload(&device.open(), "/OLD.BIN"), source.0);
                guards(&device, &geometry);
            }
        }
    }
}

fn high_head_fixture() -> (Device, FatGeometry, u64) {
    let (device, geometry, root) = fixture(FatKind::Fat32, 512, false);
    let mut state = device.state.lock().unwrap();
    // An interrupted high-word change used to select cluster 5 (KEEP.BIN)
    // while the old nonzero size remained. Both chains independently validate.
    for copy in 0..2 {
        let high = (10 + u32::from(copy)) << 28;
        for cluster in [7, 9] {
            state.put(BASE + geometry.entry_offset(copy, cluster).unwrap(), &high.to_le_bytes());
        }
        state.put(BASE + geometry.entry_offset(copy, 65_541).unwrap(), &(high | 0x0FFF_FFFF).to_le_bytes());
    }
    state.put(root, &record(b"OLD     BIN", 65_541, 4, FatKind::Fat32));
    state.put(BASE + geometry.cluster_offset(65_541).unwrap(), b"ORIG");
    state.persist();
    drop(state);
    assert!(device.open().check(&Cx::for_testing()).unwrap().clean);
    (device, geometry, root)
}

#[test]
fn torn_fat32_head_cannot_expose_another_live_file_through_old_eof() {
    let cx = Cx::for_testing();
    let (probe, _, root) = high_head_fixture();
    let source = SliceSource(b"replacement payload");
    let volume = probe.open();
    let prepared = plan(&cx, &volume, &source, false);
    prepared.execute(&cx, &volume, &source, || Ok(())).unwrap();
    let cut = probe.state.lock().unwrap().writes.iter()
        .filter(|(_, at, _)| *at == root).nth(1).unwrap().0;
    for tear in [20, 21, 22, 26, 27, 28, 31, 32] {
        let (device, geometry, root) = high_head_fixture();
        let volume = device.open();
        let prepared = plan(&cx, &volume, &source, false);
        device.state.lock().unwrap().fault = Some((cut, Fault::Error(tear)));
        assert!(prepared.execute(&cx, &volume, &source, || Ok(())).is_err());
        let record = device.bytes(root, 32);
        assert_eq!(size(&record), 0);
        if (22..=26).contains(&tear) { assert_eq!(head(FatKind::Fat32, &record), 5); }
        assert_eq!(FatTable::new(&volume).entry(&cx, 65_541).unwrap(), FatEntry::End);
        assert_eq!(device.bytes(BASE + geometry.cluster_offset(65_541).unwrap(), 4), b"ORIG");
        guards(&device, &geometry);
    }
}

#[test]
fn creation_initializes_deleted_slot_before_exposing_any_new_name_byte() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for marker in [0, 0xE5] {
            let (probe, _, root) = fixture(kind, 512, false);
            {
                let mut state = probe.state.lock().unwrap();
                state.put(root + 64, &[marker]);
                state.persist();
            }
            let source = SliceSource(b"new contents");
            let volume = probe.open();
            let prepared = creation::prepare(&cx, &volume, "/NEW.BIN", &source, NOW).unwrap();
            assert_eq!(prepared.entry_offset + BASE, root + 64);
            prepared.execute(&cx, &volume, &source, || Ok(())).unwrap();
            let writes: Vec<_> = probe.state.lock().unwrap().writes.iter()
                .filter(|(_, at, bytes)| *at == root && bytes[65..75] == prepared.updated[1..11])
                .map(|(attempt, _, bytes)| (*attempt, bytes[64])).collect();
            assert_eq!(writes.len(), 2);
            assert_eq!(writes[0].1, 0xE5);
            assert_eq!(writes[1].1, b'N');
            for (stage, &(cut, _)) in writes.iter().enumerate() {
                for tear in [0, 1, 11, 20, 22, 26, 28, 31, 32] {
                    let (device, geometry, root) = fixture(kind, 512, false);
                    {
                        let mut state = device.state.lock().unwrap();
                        state.put(root + 64, &[marker]);
                        state.persist();
                    }
                    let volume = device.open();
                    let prepared = creation::prepare(&cx, &volume, "/NEW.BIN", &source, NOW).unwrap();
                    device.state.lock().unwrap().fault = Some((cut, Fault::Error(64 + tear)));
                    assert!(prepared.execute(&cx, &volume, &source, || Ok(())).is_err());
                    let bytes = device.bytes(root + 64, 32);
                    if stage == 0 || tear == 0 {
                        assert!(bytes[0] == 0 || bytes[0] == 0xE5);
                    } else {
                        assert_eq!(bytes, prepared.updated);
                        assert_eq!(payload(&volume, "/NEW.BIN"), source.0);
                    }
                    guards(&device, &geometry);
                }
            }
        }
    }
}

#[test]
fn dropped_eof_or_head_guard_never_reaches_final_size_or_reclamation() {
    let cx = Cx::for_testing();
    let (probe, _, root) = fixture(FatKind::Fat16, 512, false);
    let source = SliceSource(b"replacement");
    let volume = probe.open();
    let prepared = plan(&cx, &volume, &source, false);
    prepared.execute(&cx, &volume, &source, || Ok(())).unwrap();
    let cuts: Vec<_> = probe.state.lock().unwrap().writes.iter()
        .filter(|(_, at, _)| *at == root).take(2).map(|(attempt, _, _)| *attempt).collect();
    assert_eq!(cuts.len(), 2);
    for (stage, cut) in cuts.into_iter().enumerate() {
        let (device, _, root) = fixture(FatKind::Fat16, 512, false);
        let volume = device.open();
        let prepared = plan(&cx, &volume, &source, false);
        device.state.lock().unwrap().fault = Some((cut, Fault::Drop));
        assert!(prepared.execute(&cx, &volume, &source, || Ok(())).is_err());
        let bytes = device.bytes(root, 32);
        assert_eq!(size(&bytes), if stage == 0 { 519 } else { 0 });
        assert_eq!(head(FatKind::Fat16, &bytes), 7);
        let mut table = FatTable::new(&volume);
        assert_eq!(table.entry(&cx, 7).unwrap(), FatEntry::Next(9));
        assert_eq!(table.entry(&cx, 9).unwrap(), FatEntry::End);
        assert_eq!(device.state.lock().unwrap().attempts, cut + 1);
    }
}

#[test]
fn mounted_empty_creation_guard_failure_quarantines_cached_namespace() {
    use ffs_core::{FsOps, RequestScope};
    use ffs_types::InodeNumber;
    use std::ffi::OsStr;

    let cx = Cx::for_testing();
    let (probe, _, root) = fixture(FatKind::Fat16, 512, false);
    let fs = crate::FatFs::new_with_mode(&cx, probe.open(), 1000, 1000, true).unwrap();
    fs.create(&cx, &mut RequestScope::empty(), InodeNumber(1), OsStr::new("NEW.BIN"), 0o644, 1000, 1000).unwrap();
    let cut = probe.state.lock().unwrap().writes.iter()
        .find(|(_, at, bytes)| *at == root && bytes[64] == 0xE5 && bytes[65] == b'E').unwrap().0;
    let (device, _, root) = fixture(FatKind::Fat16, 512, false);
    let fs = crate::FatFs::new_with_mode(&cx, device.open(), 1000, 1000, true).unwrap();
    device.state.lock().unwrap().fault = Some((cut, Fault::Drop));
    assert!(fs.create(&cx, &mut RequestScope::empty(), InodeNumber(1), OsStr::new("NEW.BIN"), 0o644, 1000, 1000).is_err());
    assert_eq!(device.bytes(root + 64, 1), [0xE5]);
    assert_eq!(fs.getattr(&cx, &mut RequestScope::empty(), InodeNumber(1)).unwrap_err().to_errno(), libc::EIO);
}
