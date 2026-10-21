//! Production truncation with native records and pending/durable storage cuts.
//! Constructed images are not independent native-filesystem qualification.

mod growth;

use super::*;
use ffs_core::{FsOps, RequestScope, SetAttrRequest};
use ffs_types::InodeNumber;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::sync::{Arc, Mutex};

const BASE: u64 = 4096;
const PAGE: usize = 4096;
const NOW: u64 = 1_700_000_000;
type Pages = BTreeMap<u64, [u8; PAGE]>;

#[derive(Clone, Copy)]
enum Fault {
    Tear(usize),
    Drop,
    Cancel,
}

#[derive(Default)]
struct Storage {
    durable: Pages,
    pending: Pages,
    attempts: usize,
    writes: Vec<(usize, u64, Vec<u8>)>,
    fault: Option<(usize, Fault)>,
    read_failure: Option<(usize, u64)>,
}

impl Storage {
    fn read(&self, at: u64, bytes: &mut [u8]) {
        for (index, byte) in bytes.iter_mut().enumerate() {
            let position = at + index as u64;
            *byte = self.pending.get(&(position / PAGE as u64))
                .or_else(|| self.durable.get(&(position / PAGE as u64)))
                .map_or(0, |page| page[(position % PAGE as u64) as usize]);
        }
    }

    fn put(&mut self, at: u64, bytes: &[u8]) {
        for (index, &byte) in bytes.iter().enumerate() {
            let position = at + index as u64;
            let key = position / PAGE as u64;
            let old = self.durable.get(&key).copied().unwrap_or([0; PAGE]);
            self.pending.entry(key).or_insert(old)[(position % PAGE as u64) as usize] = byte;
        }
    }

    fn persist(&mut self) {
        self.durable.append(&mut self.pending);
    }
}

#[derive(Clone)]
struct Device {
    storage: Arc<Mutex<Storage>>,
    length: u64,
}

impl Device {
    fn bytes(&self, at: u64, count: usize) -> Vec<u8> {
        let mut bytes = vec![0; count];
        self.storage.lock().unwrap().read(at, &mut bytes);
        bytes
    }

    fn restart(&self, retain: bool) -> Self {
        let storage = self.storage.lock().unwrap();
        let mut durable = storage.durable.clone();
        if retain {
            durable.extend(storage.pending.clone());
        }
        Self {
            storage: Arc::new(Mutex::new(Storage { durable, ..Storage::default() })),
            length: self.length,
        }
    }

    fn open(&self) -> ffs_error::Result<FatVolume> {
        FatVolume::from_device(&Cx::for_testing(), Box::new(self.clone()), BASE, self.length - 2 * BASE)
    }
}

impl ByteDevice for Device {
    fn len_bytes(&self) -> u64 { self.length }

    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        assert!(at.0.checked_add(bytes.len() as u64).is_some_and(|end| end <= self.length));
        let storage = self.storage.lock().unwrap();
        if storage.read_failure.is_some_and(|(after, bad)| {
            storage.attempts >= after && at.0 <= bad && bad < at.0 + bytes.len() as u64
        }) {
            bytes.fill(0xEE);
            return Err(std::io::Error::other("injected shrink readback error").into());
        }
        storage.read(at.0, bytes);
        checkpoint(cx)
    }

    fn write_all_at(&self, cx: &Cx, at: ByteOffset, bytes: &[u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        assert!(at.0 >= BASE && at.0 + bytes.len() as u64 <= self.length - BASE);
        let mut storage = self.storage.lock().unwrap();
        storage.attempts += 1;
        let attempt = storage.attempts;
        storage.writes.push((attempt, at.0, bytes.to_vec()));
        let fault = storage.fault.filter(|(cut, _)| *cut == attempt).map(|(_, fault)| fault);
        match fault {
            Some(Fault::Drop) => return Ok(()),
            Some(Fault::Tear(prefix)) => {
                storage.put(at.0, &bytes[..prefix.min(bytes.len())]);
                return Err(std::io::Error::other("injected prefix-torn shrink write").into());
            }
            Some(Fault::Cancel) => {
                storage.put(at.0, bytes);
                cx.set_cancel_requested(true);
                return Err(FfsError::Cancelled);
            }
            None => storage.put(at.0, bytes),
        }
        Ok(())
    }

    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        let mut storage = self.storage.lock().unwrap();
        storage.attempts += 1;
        if storage.fault.is_some_and(|(cut, _)| cut == storage.attempts) {
            return Err(std::io::Error::other("injected shrink synchronization error").into());
        }
        storage.persist();
        Ok(())
    }
}

struct Image {
    device: Device,
    geometry: FatGeometry,
    sector_start: u64,
    entry: u64,
    chain: Vec<u32>,
    payload: Vec<u8>,
}

fn fixture(kind: FatKind, sector: u32, active: bool, size: u32) -> Image {
    let count = if kind == FatKind::Fat16 { 5000_u32 } else { 70_000 };
    let reserved = if kind == FatKind::Fat16 { 1_u32 } else { 32 };
    let width = kind.entry_bytes();
    let fats = ((count + 2) * width).div_ceil(sector);
    let roots = if kind == FatKind::Fat16 { (2 * sector / 32) as u16 } else { 0 };
    let total = reserved + 2 * fats + u32::from(roots) * 32 / sector + count;
    let mut boot = [0_u8; 512];
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
        boot[22..24].copy_from_slice(&(fats as u16).to_le_bytes());
        boot[38] = 0x29;
    } else {
        boot[32..36].copy_from_slice(&total.to_le_bytes());
        boot[36..40].copy_from_slice(&fats.to_le_bytes());
        boot[40..42].copy_from_slice(&(if active { 0x81_u16 } else { 0 }).to_le_bytes());
        boot[44..48].copy_from_slice(&2_u32.to_le_bytes());
        boot[48..50].copy_from_slice(&1_u16.to_le_bytes());
        boot[50..52].copy_from_slice(&6_u16.to_le_bytes());
        boot[66] = 0x29;
    }
    let geometry = FatGeometry::parse(&boot, u64::from(total) * u64::from(sector)).unwrap();
    // Enough poisoned preallocation that the old torn-size bug can actually
    // expose bytes, not just turn a valid file into a too-short-chain error.
    let clusters = (2 * size).div_ceil(sector) + 2;
    let mut chain: Vec<u32> = (100..100 + clusters).rev().collect();
    if kind == FatKind::Fat32 { chain[0] = 65_538; }
    let end = if kind == FatKind::Fat16 { 0xFFFF_u32 } else { 0x0FFF_FFFF };
    let mut storage = Storage::default();
    storage.put(0, &[0xA7; PAGE]);
    storage.put(BASE + geometry.volume_bytes(), &[0xB9; PAGE]);
    storage.put(BASE, &boot);
    if kind == FatKind::Fat32 {
        storage.put(BASE + 6 * u64::from(sector), &boot);
        let mut info = [0; 512];
        info[..4].copy_from_slice(&0x4161_5252_u32.to_le_bytes());
        info[484..488].copy_from_slice(&0x6141_7272_u32.to_le_bytes());
        info[488..496].fill(0xFF);
        info[508..512].copy_from_slice(&0xAA55_0000_u32.to_le_bytes());
        storage.put(BASE + u64::from(sector), &info);
    }
    for copy in 0..2_u8 {
        let high = if kind == FatKind::Fat32 { (10 + u32::from(copy)) << 28 } else { 0 };
        let start = BASE + geometry.entry_offset(copy, 2).unwrap() - 2 * u64::from(width);
        for (cluster, value) in [(0_u32, end & !7), (1, end), (4, end)] {
            storage.put(start + u64::from(cluster * width), &(high | value).to_le_bytes()[..width as usize]);
        }
        if kind == FatKind::Fat32 {
            storage.put(start + 2 * u64::from(width), &(high | end).to_le_bytes());
        }
        for (index, &cluster) in chain.iter().enumerate() {
            let value = if active && copy == 0 { 1 } else { chain.get(index + 1).copied().unwrap_or(end) };
            storage.put(BASE + geometry.entry_offset(copy, cluster).unwrap(), &(high | value).to_le_bytes()[..width as usize]);
        }
    }
    let root = BASE + geometry.fixed_root().map_or_else(|| geometry.cluster_offset(2).unwrap(), |(at, _)| at);
    let mut slots = vec![0; sector as usize];
    for slot in slots.chunks_exact_mut(32) { slot[0] = 0xE5; }
    let record = |name: &[u8; 11], first: u32, length: u32| {
        let mut record = [0; 32];
        record[..11].copy_from_slice(name);
        record[11] = 0x06;
        record[13] = 137;
        for at in [16, 18, 24] { record[at..at + 2].copy_from_slice(&0x21_u16.to_le_bytes()); }
        let high = if kind == FatKind::Fat32 { 0xC000 | (first >> 16) as u16 } else { 0x4321 };
        record[20..22].copy_from_slice(&high.to_le_bytes());
        record[26..28].copy_from_slice(&(first as u16).to_le_bytes());
        record[28..32].copy_from_slice(&length.to_le_bytes());
        record
    };
    slots[..32].copy_from_slice(&record(b"OTHER   BIN", 4, 4));
    let within = slots.len() - 32;
    slots[within..].copy_from_slice(&record(b"TARGET  BIN", chain[0], size));
    storage.put(root, &slots);
    storage.put(BASE + geometry.cluster_offset(4).unwrap(), b"SAFE");
    let payload: Vec<u8> = (0..size).map(|index| (index % 251) as u8).collect();
    for (index, &cluster) in chain.iter().enumerate() {
        let mut bytes = vec![0xE7; sector as usize];
        let at = index * sector as usize;
        let count = payload.len().saturating_sub(at).min(bytes.len());
        if count != 0 { bytes[..count].copy_from_slice(&payload[at..at + count]); }
        storage.put(BASE + geometry.cluster_offset(cluster).unwrap(), &bytes);
    }
    storage.persist();
    let device = Device { storage: Arc::new(Mutex::new(storage)), length: geometry.volume_bytes() + 2 * BASE };
    assert!(device.open().unwrap().check(&Cx::for_testing()).unwrap().clean);
    Image { device, geometry, sector_start: root, entry: root + u64::from(sector) - 32, chain, payload }
}

fn entry_size(image: &Image) -> u32 {
    u32::from_le_bytes(image.device.bytes(image.entry + 28, 4).try_into().unwrap())
}

fn publications(image: &Image) -> Vec<(usize, Vec<u8>)> {
    image.device.storage.lock().unwrap().writes.iter()
        .filter(|(_, at, _)| *at == image.sector_start)
        .map(|(n, _, bytes)| (*n, bytes[(image.entry - image.sector_start) as usize..][..32].to_vec()))
        .collect()
}

fn assert_old_allocation(image: &Image, before: &[Vec<u8>]) {
    for (index, &cluster) in image.chain.iter().enumerate() {
        assert_eq!(image.device.bytes(BASE + image.geometry.entry_offset(image.geometry.active_fat(), cluster).unwrap(), image.geometry.kind().entry_bytes() as usize), before[index]);
    }
}

fn allocation(image: &Image) -> Vec<Vec<u8>> {
    image.chain.iter().map(|&cluster| image.device.bytes(
        BASE + image.geometry.entry_offset(image.geometry.active_fat(), cluster).unwrap(),
        image.geometry.kind().entry_bytes() as usize,
    )).collect()
}

#[test]
fn shrink_guard_retains_common_prefix_and_avoids_an_unnecessary_barrier() {
    let cx = Cx::for_testing();
    for (old, new, guard) in [(768, 511, Some(256)), (65_536, 65_535, Some(0)), (65_535, 32_767, None), (65_536, 0, Some(0))] {
        for kind in [FatKind::Fat16, FatKind::Fat32] {
            let image = fixture(kind, 512, false, old);
            truncate_in_volume(&cx, &image.device.open().unwrap(), "/target.bin", new, NOW).unwrap();
            let records = publications(&image);
            assert_eq!(records.len(), if guard.is_some() { 2 } else { 1 });
            if let Some(size) = guard {
                assert_eq!(u32::from_le_bytes(records[0].1[28..32].try_into().unwrap()), size);
                assert_eq!(u16::from_le_bytes(records[0].1[26..28].try_into().unwrap()), image.chain[0] as u16);
            }
            let volume = image.device.open().unwrap();
            let entry = volume.resolve(&cx, "/target.bin").unwrap().unwrap();
            let chain = volume.file_chain(&cx, &entry).unwrap();
            assert_eq!(volume.read(&cx, &chain, 0, old as usize).unwrap(), image.payload[..new as usize]);
            assert!(volume.check(&cx).unwrap().clean);
        }
    }
}

#[test]
fn guarded_shrink_preserves_neighbors_payload_high_bits_active_copy_and_volume_bounds() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for sector in [512, 4096] {
            for active in [false, true] {
                if active && kind == FatKind::Fat16 { continue; }
                let image = fixture(kind, sector, active, 65_536);
                let volume = image.device.open().unwrap();
                let before = volume.check(&cx).unwrap();
                let neighbors = image.device.bytes(image.sector_start, sector as usize - 32);
                let record = image.device.bytes(image.entry, 32);
                let old_payload: Vec<_> = image.chain.iter().map(|&c| image.device.bytes(BASE + image.geometry.cluster_offset(c).unwrap(), sector as usize)).collect();
                let inactive: Vec<_> = image.chain.iter().map(|&c| image.device.bytes(BASE + image.geometry.entry_offset(0, c).unwrap(), kind.entry_bytes() as usize)).collect();
                truncate_in_volume(&cx, &volume, "/target.bin", 65_535, NOW).unwrap();
                let after = volume.check(&cx).unwrap();
                let kept = 65_535_u64.div_ceil(u64::from(sector));
                assert!(after.clean);
                assert_eq!(after.free_clusters, before.free_clusters + image.chain.len() as u64 - kept);
                assert_eq!(after.preallocated_clusters, 0);
                assert_eq!(image.device.bytes(image.sector_start, sector as usize - 32), neighbors);
                let updated = image.device.bytes(image.entry, 32);
                for range in [0..11, 12..22, 26..28] { assert_eq!(updated[range.clone()], record[range]); }
                assert_eq!(updated[11], record[11] | 0x20);
                for (index, &cluster) in image.chain.iter().enumerate() {
                    assert_eq!(image.device.bytes(BASE + image.geometry.cluster_offset(cluster).unwrap(), sector as usize), old_payload[index]);
                    if active { assert_eq!(image.device.bytes(BASE + image.geometry.entry_offset(0, cluster).unwrap(), 4), inactive[index]); }
                    if kind == FatKind::Fat32 {
                        for copy in if active { 1..2 } else { 0..2 } {
                            assert_eq!(image.device.bytes(BASE + image.geometry.entry_offset(copy, cluster).unwrap() + 3, 1)[0] & 0xF0, (10 + copy) << 4);
                        }
                    }
                }
                assert_eq!(image.device.bytes(0, PAGE), [0xA7; PAGE]);
                assert_eq!(image.device.bytes(BASE + image.geometry.volume_bytes(), PAGE), [0xB9; PAGE]);
            }
        }
    }
}

#[test]
fn every_torn_size_prefix_stays_below_old_eof_and_never_reclaims_allocation() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let probe = fixture(kind, 512, false, 65_536);
        truncate_in_volume(&Cx::for_testing(), &probe.device.open().unwrap(), "/target.bin", 65_535, NOW).unwrap();
        let writes = publications(&probe);
        assert_eq!(writes.len(), 2);
        for (phase, (attempt, _)) in writes.iter().enumerate() {
            for prefix in 0..=32 {
                let image = fixture(kind, 512, false, 65_536);
                let volume = image.device.open().unwrap();
                let before = allocation(&image);
                image.device.storage.lock().unwrap().fault = Some((*attempt, Fault::Tear(480 + prefix)));
                assert!(truncate_in_volume(&Cx::for_testing(), &volume, "/target.bin", 65_535, NOW).is_err());
                assert!(entry_size(&image) <= if phase == 0 { 65_536 } else { 65_535 });
                assert_old_allocation(&image, &before);
                assert_eq!(image.device.storage.lock().unwrap().attempts, *attempt);
                for retain in [false, true] {
                    let crashed = image.device.restart(retain);
                    let size = u32::from_le_bytes(crashed.bytes(image.entry + 28, 4).try_into().unwrap());
                    assert!(size <= 65_536);
                }
            }
        }
    }
}

#[test]
fn truncate_zero_persists_empty_size_before_clearing_either_head_word() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let probe = fixture(kind, 512, false, 65_536);
        truncate_in_volume(&Cx::for_testing(), &probe.device.open().unwrap(), "/target.bin", 0, NOW).unwrap();
        let writes = publications(&probe);
        assert_eq!(writes.len(), 2);
        for prefix in [20, 21, 22, 26, 27, 28, 29, 32] {
            let image = fixture(kind, 512, false, 65_536);
            let volume = image.device.open().unwrap();
            let before = allocation(&image);
            image.device.storage.lock().unwrap().fault = Some((writes[1].0, Fault::Tear(480 + prefix)));
            assert!(truncate_in_volume(&Cx::for_testing(), &volume, "/target.bin", 0, NOW).is_err());
            assert_eq!(entry_size(&image), 0);
            assert_old_allocation(&image, &before);
            assert_eq!(image.device.bytes(image.entry + 20, 2)[1] & 0xF0, if kind == FatKind::Fat32 { 0xC0 } else { 0x40 });
        }
    }
}

#[test]
fn lost_guard_sync_readback_and_cancellation_stop_before_final_size_or_reclamation() {
    let probe = fixture(FatKind::Fat16, 512, false, 65_536);
    truncate_in_volume(&Cx::for_testing(), &probe.device.open().unwrap(), "/target.bin", 65_535, NOW).unwrap();
    let guard = publications(&probe)[0].0;
    for case in 0..4 {
        let image = fixture(FatKind::Fat16, 512, false, 65_536);
        let volume = image.device.open().unwrap();
        let before = allocation(&image);
        {
            let mut storage = image.device.storage.lock().unwrap();
            match case {
                0 => storage.fault = Some((guard, Fault::Drop)),
                1 => storage.fault = Some((guard + 1, Fault::Tear(0))),
                2 => storage.read_failure = Some((guard + 1, image.sector_start)),
                _ => storage.fault = Some((guard, Fault::Cancel)),
            }
        }
        assert!(truncate_in_volume(&Cx::for_testing(), &volume, "/target.bin", 65_535, NOW).is_err());
        assert_eq!(publications(&image).len(), 1);
        assert!(entry_size(&image) <= 65_536);
        assert_old_allocation(&image, &before);
    }
}

#[test]
fn every_shrink_write_or_sync_failure_has_no_clean_partial_result() {
    let probe = fixture(FatKind::Fat16, 512, false, 65_536);
    truncate_in_volume(&Cx::for_testing(), &probe.device.open().unwrap(), "/target.bin", 65_535, NOW).unwrap();
    let total = probe.device.storage.lock().unwrap().attempts;
    for attempt in 1..=total {
        for tear in [0, 31, 509, 512] {
            let image = fixture(FatKind::Fat16, 512, false, 65_536);
            let volume = image.device.open().unwrap();
            image.device.storage.lock().unwrap().fault = Some((attempt, Fault::Tear(tear)));
            assert!(truncate_in_volume(&Cx::for_testing(), &volume, "/target.bin", 65_535, NOW).is_err());
            assert_eq!(image.device.storage.lock().unwrap().attempts, attempt);
            assert!(entry_size(&image) <= 65_536);
            for retain in [false, true] {
                let crashed = image.device.restart(retain);
                if let Ok(volume) = crashed.open() {
                    let cx = Cx::for_testing();
                    assert!(volume.check(&cx).unwrap().clean);
                    let entry = volume.resolve(&cx, "/target.bin").unwrap().unwrap();
                    assert!(entry.native.size == 65_536 || entry.native.size == 65_535);
                    let chain = volume.file_chain(&cx, &entry).unwrap();
                    assert_eq!(volume.read(&cx, &chain, 0, 65_536).unwrap(), image.payload[..entry.native.size as usize]);
                }
            }
        }
    }
}

#[test]
fn mounted_setattr_and_truncating_open_keep_inode_identity_and_refresh_cache() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let image = fixture(kind, 512, false, 65_536);
        let cx = Cx::for_testing();
        let fs = crate::filesystem::FatFs::new_with_mode(&cx, image.device.open().unwrap(), 1000, 1000, true).unwrap();
        let mut scope = RequestScope::empty();
        let ino = fs.lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("TARGET.BIN")).unwrap().ino;
        fs.open(&cx, &mut scope, ino, libc::O_RDWR).unwrap();
        let free = fs.statfs(&cx, &mut scope, ino).unwrap().blocks_free;
        assert_eq!(fs.read(&cx, &mut scope, ino, 0, 65_536).unwrap(), image.payload);
        let attrs = SetAttrRequest { size: Some(65_535), ..SetAttrRequest::default() };
        assert_eq!(fs.setattr(&cx, &mut scope, ino, &attrs).unwrap().size, 65_535);
        assert_eq!(fs.read(&cx, &mut scope, ino, 0, 65_536).unwrap(), image.payload[..65_535]);
        assert!(fs.statfs(&cx, &mut scope, ino).unwrap().blocks_free > free);
        fs.open(&cx, &mut scope, ino, libc::O_RDWR | libc::O_TRUNC).unwrap();
        assert_eq!(fs.getattr(&cx, &mut scope, ino).unwrap().size, 0);
        assert!(fs.read(&cx, &mut scope, ino, 0, 10).unwrap().is_empty());
        assert_eq!(fs.lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("target.bin")).unwrap().ino, ino);
        assert!(image.device.open().unwrap().check(&cx).unwrap().clean);
    }
}

#[test]
fn mounted_guard_failure_quarantines_reads_without_freeing_the_old_chain() {
    let probe = fixture(FatKind::Fat16, 512, false, 65_536);
    truncate_in_volume(&Cx::for_testing(), &probe.device.open().unwrap(), "/target.bin", 65_535, NOW).unwrap();
    let guard = publications(&probe)[0].0;
    let image = fixture(FatKind::Fat16, 512, false, 65_536);
    let before = allocation(&image);
    let cx = Cx::for_testing();
    let fs = crate::filesystem::FatFs::new_with_mode(&cx, image.device.open().unwrap(), 0, 0, true).unwrap();
    let mut scope = RequestScope::empty();
    let ino = fs.lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("TARGET.BIN")).unwrap().ino;
    let invalid = SetAttrRequest { size: Some(u64::MAX), ..SetAttrRequest::default() };
    assert!(fs.setattr(&cx, &mut scope, ino, &invalid).is_err());
    fs.getattr(&cx, &mut scope, ino).unwrap();
    assert_eq!(image.device.storage.lock().unwrap().attempts, 0);
    image.device.storage.lock().unwrap().fault = Some((guard, Fault::Drop));
    let attrs = SetAttrRequest { size: Some(65_535), ..SetAttrRequest::default() };
    assert!(fs.setattr(&cx, &mut scope, ino, &attrs).is_err());
    assert_eq!(fs.getattr(&cx, &mut scope, ino).unwrap_err().to_errno(), libc::EIO);
    assert_eq!(fs.read(&cx, &mut scope, ino, 0, 1).unwrap_err().to_errno(), libc::EIO);
    assert_old_allocation(&image, &before);
}
