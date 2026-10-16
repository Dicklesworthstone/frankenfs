//! Instrument the real ByteDevice boundary, not only the run arithmetic.
//! Sparse synthetic images retain native admission, mirrors and chain parsing.

use super::*;
use std::collections::BTreeMap;
use std::io;
use std::ops::Range;
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Default)]
enum Failure {
    #[default]
    Media,
    Corruption,
    Cancelled,
    Denied,
}

#[derive(Default)]
struct Trace {
    reads: Vec<(u64, usize)>,
    fail: Option<Range<u64>>,
    cancel_after: Option<usize>,
    failure: Failure,
}

#[derive(Clone)]
struct Device {
    length: u64,
    fats: [Range<u64>; 2],
    pages: Arc<Mutex<BTreeMap<u64, [u8; 512]>>>,
    trace: Arc<Mutex<Trace>>,
}

impl Device {
    fn put(&self, mut at: u64, mut bytes: &[u8]) {
        let mut pages = self.pages.lock().unwrap();
        while !bytes.is_empty() {
            let within = (at % 512) as usize;
            let count = bytes.len().min(512 - within);
            let page = pages.entry(at / 512).or_insert([0; 512]);
            page[within..within + count].copy_from_slice(&bytes[..count]);
            at += count as u64;
            bytes = &bytes[count..];
        }
    }

    fn reset(&self) {
        *self.trace.lock().unwrap() = Trace::default();
    }
}

impl ByteDevice for Device {
    fn len_bytes(&self) -> u64 {
        self.length
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, bytes: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        let end = offset.0.checked_add(bytes.len() as u64)
            .filter(|end| *end <= self.length)
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        let mut trace = self.trace.lock().unwrap();
        trace.reads.push((offset.0, bytes.len()));
        if trace.fail.as_ref().is_some_and(|bad| offset.0 < bad.end && bad.start < end) {
            // A failed device may already have overwritten its entire output.
            // None of these bytes may become a successful logical read.
            bytes.fill(0xee);
            return Err(match trace.failure {
                Failure::Media => io::Error::from(io::ErrorKind::UnexpectedEof).into(),
                Failure::Corruption => corrupt(offset.0, "injected read verification failure"),
                Failure::Cancelled => FfsError::Cancelled,
                Failure::Denied => io::Error::from(io::ErrorKind::PermissionDenied).into(),
            });
        }
        let pages = self.pages.lock().unwrap();
        for (index, byte) in bytes.iter_mut().enumerate() {
            let at = offset.0 + index as u64;
            *byte = if let Some(page) = pages.get(&(at / 512)) {
                page[(at % 512) as usize]
            } else if self.fats.iter().any(|fat| fat.contains(&at)) {
                0
            } else {
                (at % 251) as u8
            };
        }
        if trace.cancel_after == Some(trace.reads.len()) {
            cx.set_cancel_requested(true);
        }
        Ok(())
    }

    fn write_all_at(&self, _cx: &Cx, _at: ByteOffset, _bytes: &[u8]) -> Result<()> {
        panic!("native read path wrote the backing image")
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        panic!("native read path synchronized the backing image")
    }
}

struct Fixture {
    device: Device,
    volume: FatVolume,
    entry: Entry,
}

impl Fixture {
    fn new(kind: FatKind, sector: u16, sectors_per_cluster: u8, chain: &[u32], size: u32) -> Self {
        let sector_bytes = u64::from(sector);
        let cluster_count = if kind == FatKind::Fat16 { 5000_u32 } else { 70_000 };
        let reserved = if kind == FatKind::Fat16 { 1_u16 } else { 32 };
        let fat_sectors = ((u64::from(cluster_count) + 2) * u64::from(kind.entry_bytes()))
            .div_ceil(sector_bytes) as u32;
        let root_entries = if kind == FatKind::Fat16 { (sector / 32).max(32) } else { 0 };
        let root_sectors = (u64::from(root_entries) * 32).div_ceil(sector_bytes);
        let total = u64::from(reserved) + 2 * u64::from(fat_sectors) + root_sectors
            + u64::from(cluster_count) * u64::from(sectors_per_cluster);
        let mut boot = [0; 512];
        boot[..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
        boot[3..11].copy_from_slice(b"MSWIN4.1");
        boot[11..13].copy_from_slice(&sector.to_le_bytes());
        boot[13] = sectors_per_cluster;
        boot[14..16].copy_from_slice(&reserved.to_le_bytes());
        boot[16] = 2;
        boot[17..19].copy_from_slice(&root_entries.to_le_bytes());
        boot[21] = 0xf8;
        boot[510..512].copy_from_slice(&[0x55, 0xaa]);
        if kind == FatKind::Fat16 {
            if total <= u64::from(u16::MAX) {
                boot[19..21].copy_from_slice(&(total as u16).to_le_bytes());
            } else {
                boot[32..36].copy_from_slice(&(total as u32).to_le_bytes());
            }
            boot[22..24].copy_from_slice(&(fat_sectors as u16).to_le_bytes());
            boot[38] = 0x29;
            boot[54..62].copy_from_slice(b"FAT16   ");
        } else {
            boot[32..36].copy_from_slice(&(total as u32).to_le_bytes());
            boot[36..40].copy_from_slice(&fat_sectors.to_le_bytes());
            boot[44..48].copy_from_slice(&2_u32.to_le_bytes());
            boot[48..50].copy_from_slice(&1_u16.to_le_bytes());
            boot[50..52].copy_from_slice(&6_u16.to_le_bytes());
            boot[66] = 0x29;
            boot[82..90].copy_from_slice(b"FAT32   ");
        }
        let base = 8192;
        let length = total * sector_bytes;
        let geometry = FatGeometry::parse(&boot, length).unwrap();
        let fat_start = base + u64::from(reserved) * sector_bytes;
        let fat_bytes = u64::from(fat_sectors) * sector_bytes;
        let device = Device {
            length: base + length + 8192,
            fats: [fat_start..fat_start + fat_bytes, fat_start + fat_bytes..fat_start + 2 * fat_bytes],
            pages: Arc::default(),
            trace: Arc::default(),
        };
        device.put(base, &boot);
        if kind == FatKind::Fat32 {
            device.put(base + 6 * sector_bytes, &boot);
        }
        let end = if kind == FatKind::Fat16 { 0xffff_u32 } else { 0x0fff_ffff };
        let width = kind.entry_bytes() as usize;
        for copy in 0..2 {
            let start = device.fats[copy].start;
            device.put(start, &(end & !7).to_le_bytes()[..width]);
            device.put(start + width as u64, &end.to_le_bytes()[..width]);
            if kind == FatKind::Fat32 {
                device.put(start + 2 * width as u64, &end.to_le_bytes()[..width]);
            }
            for (index, &cluster) in chain.iter().enumerate() {
                let value = chain.get(index + 1).copied().unwrap_or(end);
                device.put(start + u64::from(cluster) * width as u64, &value.to_le_bytes()[..width]);
            }
        }
        let root = geometry.fixed_root().map_or_else(|| geometry.cluster_offset(2).unwrap(), |(at, _)| at);
        let mut record = [0; 32];
        record[..11].copy_from_slice(b"DATA    BIN");
        record[11] = 0x20;
        let first = chain.first().copied().unwrap_or(0);
        if kind == FatKind::Fat32 {
            record[20..22].copy_from_slice(&((first >> 16) as u16).to_le_bytes());
        }
        record[26..28].copy_from_slice(&(first as u16).to_le_bytes());
        record[28..32].copy_from_slice(&size.to_le_bytes());
        device.put(base + root, &record);
        let volume = FatVolume::from_device(&Cx::for_testing(), Box::new(device.clone()), base, length).unwrap();
        let entry = volume.lookup(&Cx::for_testing(), Directory::Root, "DATA.BIN").unwrap();
        device.reset();
        Self { device, volume, entry }
    }

    fn chain(&self) -> FileChain {
        let chain = self.volume.file_chain(&Cx::for_testing(), &self.entry).unwrap();
        self.device.reset();
        chain
    }

    fn expected(&self, chain: &FileChain, offset: u64, size: usize) -> Vec<u8> {
        let length = u64::from(chain.size).saturating_sub(offset).min(size as u64);
        let cluster_bytes = u64::from(self.volume.geometry.cluster_bytes());
        (offset..offset + length).map(|at| {
            let cluster = chain.clusters[(at / cluster_bytes) as usize];
            let physical = self.volume.base + self.volume.geometry.cluster_offset(cluster).unwrap()
                + at % cluster_bytes;
            (physical % 251) as u8
        }).collect()
    }
}

#[test]
fn contiguous_reads_merge_clusters_but_never_fetch_slack_or_preallocation() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let clusters: Vec<_> = (32..332).collect();
        let fixture = Fixture::new(kind, 512, 1, &clusters, 256 * 512 + 37);
        let chain = fixture.chain();
        let offset = 7;
        let actual = fixture.volume.read(&Cx::for_testing(), &chain, offset, 1024 * 1024).unwrap();
        assert_eq!(actual, fixture.expected(&chain, offset, 1024 * 1024));
        let trace = fixture.device.trace.lock().unwrap();
        let start = fixture.volume.base + fixture.volume.cluster_offset(32).unwrap() + offset;
        assert_eq!(trace.reads, [(start, 65536), (start + 65536, 65536), (start + 131072, 30)]);
        assert_eq!(trace.reads.iter().map(|(_, count)| *count).sum::<usize>(), actual.len());
    }
}

#[test]
fn fragmented_and_backward_links_keep_logical_order_and_skip_unowned_gaps() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let fixture = Fixture::new(kind, 512, 1, &[60, 61, 62, 20, 21, 90, 91, 92, 93], 9 * 512 - 19);
        let chain = fixture.chain();
        let actual = fixture.volume.read(&Cx::for_testing(), &chain, 499, 5000).unwrap();
        assert_eq!(actual, fixture.expected(&chain, 499, 5000));
        let at = |cluster| fixture.volume.base + fixture.volume.cluster_offset(cluster).unwrap();
        assert_eq!(fixture.device.trace.lock().unwrap().reads,
            [(at(60) + 499, 1037), (at(20), 1024), (at(90), 2029)]);
    }
}

#[test]
fn run_boundaries_work_with_large_sectors_clusters_and_unaligned_requests() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let fixture = Fixture::new(kind, 4096, 8, &[50, 51, 52, 80, 81, 82], 6 * 32768 - 3);
        let chain = fixture.chain();
        for (offset, length) in [(0, 1), (32761, 65537), (65535, 65538), (98303, 100000)] {
            fixture.device.reset();
            let actual = fixture.volume.read(&Cx::for_testing(), &chain, offset, length).unwrap();
            assert_eq!(actual, fixture.expected(&chain, offset, length));
            let trace = fixture.device.trace.lock().unwrap();
            assert!(trace.reads.iter().all(|(at, count)| *at >= fixture.volume.base
                && *at + *count as u64 <= fixture.volume.base + fixture.volume.geometry.volume_bytes()
                && *count <= MAX_READ_RUN_BYTES));
            assert_eq!(trace.reads.iter().map(|(_, count)| *count).sum::<usize>(), actual.len());
        }
    }
}

#[test]
fn eof_empty_and_oversized_requests_do_not_touch_the_device() {
    let fixture = Fixture::new(FatKind::Fat16, 512, 1, &[32, 33], 513);
    let chain = fixture.chain();
    for (offset, size) in [(0, 0), (513, 512), (u64::MAX, 512)] {
        assert!(fixture.volume.read(&Cx::for_testing(), &chain, offset, size).unwrap().is_empty());
    }
    assert!(fixture.volume.read(&Cx::for_testing(), &chain, 0, MAX_READ_BYTES + 1).is_err());
    assert!(fixture.device.trace.lock().unwrap().reads.is_empty());
}

#[test]
fn a_failed_or_cancelled_later_run_never_returns_a_successful_prefix() {
    let clusters: Vec<_> = (32..332).collect();
    let fixture = Fixture::new(FatKind::Fat16, 512, 1, &clusters, 300 * 512);
    let chain = fixture.chain();
    let start = fixture.volume.base + fixture.volume.cluster_offset(32).unwrap();
    fixture.device.trace.lock().unwrap().fail = Some(start + 65536..start + 65537);
    assert!(matches!(fixture.volume.read(&Cx::for_testing(), &chain, 0, chain.size as usize), Err(FfsError::Io(_))));
    assert_eq!(fixture.device.trace.lock().unwrap().reads.len(), 2);
    fixture.device.reset();
    fixture.device.trace.lock().unwrap().cancel_after = Some(2);
    assert!(matches!(fixture.volume.read(&Cx::for_testing(), &chain, 0, chain.size as usize), Err(FfsError::Cancelled)));
    assert_eq!(fixture.device.trace.lock().unwrap().reads.len(), 2);
    fixture.device.reset();
    assert_eq!(fixture.volume.read(&Cx::for_testing(), &chain, 0, chain.size as usize).unwrap(),
        fixture.expected(&chain, 0, chain.size as usize));
}

#[test]
fn complete_chain_validation_still_rejects_bad_links_after_logical_eof() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let fixture = Fixture::new(kind, 512, 1, &[32, 33, 34], 1);
        let bad = if kind == FatKind::Fat16 { 0xfff7 } else { 0x0fff_fff7 };
        for successor in [0_u32, 32, bad] {
            for copy in 0..2 {
                let at = fixture.device.fats[copy].start + 34 * u64::from(kind.entry_bytes());
                fixture.device.put(at, &successor.to_le_bytes()[..kind.entry_bytes() as usize]);
            }
            fixture.device.reset();
            assert!(fixture.volume.file_chain(&Cx::for_testing(), &fixture.entry).is_err());
            assert!(fixture.device.trace.lock().unwrap().reads.iter().all(|(at, length)|
                fixture.device.fats.iter().any(|fat| fat.contains(at) && *at + *length as u64 <= fat.end)));
        }
    }
}

#[test]
fn malformed_supplied_maps_cannot_coalesce_past_the_volume() {
    let fixture = Fixture::new(FatKind::Fat16, 512, 1, &[32], 1);
    let last = fixture.volume.geometry.cluster_count() + 1;
    for chain in [
        FileChain { clusters: vec![last, last + 1], size: 1024 },
        FileChain { clusters: vec![32], size: 1024 },
        FileChain { clusters: vec![0], size: 1 },
    ] {
        assert!(fixture.volume.read(&Cx::for_testing(), &chain, 0, 1024).is_err());
    }
    assert!(fixture.device.trace.lock().unwrap().reads.is_empty());
}

#[test]
fn the_maximum_logical_request_is_streamed_as_bounded_device_runs() {
    let clusters: Vec<_> = (32..32 + (MAX_READ_BYTES / 512) as u32).collect();
    let fixture = Fixture::new(FatKind::Fat32, 512, 1, &clusters, MAX_READ_BYTES as u32);
    let chain = fixture.chain();
    let actual = fixture.volume.read(&Cx::for_testing(), &chain, 0, MAX_READ_BYTES).unwrap();
    assert_eq!(actual, fixture.expected(&chain, 0, MAX_READ_BYTES));
    let trace = fixture.device.trace.lock().unwrap();
    assert_eq!(trace.reads.len(), MAX_READ_BYTES / MAX_READ_RUN_BYTES);
    assert!(trace.reads.iter().all(|(_, length)| *length == MAX_READ_RUN_BYTES));
}

mod fat_windows_tests;
