//! Actual FsOps calls on sparse native-layout devices, not kernel mount evidence.
use super::*;
use super::super::{FileChain, ROOT, fat_fiemap};
use crate::reader::FatVolume;
use ffs_block::ByteDevice;
use ffs_core::{FsOps, RequestScope};
use ffs_ondisk::fat::{FatGeometry, FatKind};
use ffs_types::ByteOffset;
use std::ffi::OsStr;
use std::ops::Range;
use std::sync::{Arc, Mutex};

const BASE: u64 = 8192;

#[derive(Default)]
struct Trace {
    calls: usize,
    maximum: usize,
    fail: Option<Range<u64>>,
    cancel_after: Option<usize>,
    overrides: BTreeMap<(u8, u32), u32>,
}

struct Image {
    boot: [u8; 512],
    geometry: FatGeometry,
    fats: [Range<u64>; 2],
    root: u64,
    record: [u8; 32],
    linear: usize,
    successors: BTreeMap<u32, u32>,
    active: bool,
    trace: Mutex<Trace>,
}

#[derive(Clone)]
struct Device(Arc<Image>);

impl Device {
    fn raw(&self, copy: u8, cluster: u32, trace: &Trace) -> u32 {
        if let Some(&raw) = trace.overrides.get(&(copy, cluster)) {
            return raw;
        }
        if self.0.active && copy == 0 {
            return 0; // Deliberately unusable inactive header and allocation.
        }
        let end = if self.0.geometry.kind() == FatKind::Fat16 {
            0xffff
        } else {
            0x0fff_ffff
        };
        let value = match cluster {
            0 => end & !7,
            1 => end,
            2 if self.0.geometry.kind() == FatKind::Fat32 => end,
            n if n >= 3 && (n - 3) < self.0.linear as u32 => {
                if (n - 2) == self.0.linear as u32 { end } else { n + 1 }
            }
            n => self.0.successors.get(&n).copied().unwrap_or(0),
        };
        if self.0.active { value | 0xa000_0000 } else { value }
    }

    fn reset(&self) {
        *self.0.trace.lock().unwrap() = Trace::default();
    }

    fn fault(&self, copy: u8, cluster: u32, value: u32) {
        self.0.trace.lock().unwrap().overrides.insert((copy, cluster), value);
    }
}

impl ByteDevice for Device {
    fn len_bytes(&self) -> u64 {
        BASE + self.0.geometry.volume_bytes() + BASE
    }

    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        let end = at.0.checked_add(bytes.len() as u64).unwrap();
        assert!(at.0 >= BASE && end <= BASE + self.0.geometry.volume_bytes());
        let mut trace = self.0.trace.lock().unwrap();
        trace.calls += 1;
        trace.maximum = trace.maximum.max(bytes.len());
        if trace.fail.as_ref().is_some_and(|bad| at.0 < bad.end && end > bad.start) {
            bytes.fill(0xee);
            return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
        }
        let sector = u64::from(self.0.geometry.sector_bytes());
        let backup = self.0.geometry.backup_boot_sector().map(|n| BASE + u64::from(n) * sector);
        let width = u64::from(self.0.geometry.kind().entry_bytes());
        for (index, byte) in bytes.iter_mut().enumerate() {
            let position = at.0 + index as u64;
            *byte = if (BASE..BASE + 512).contains(&position) {
                self.0.boot[(position - BASE) as usize]
            } else if backup.is_some_and(|start| (start..start + 512).contains(&position)) {
                self.0.boot[(position - backup.unwrap()) as usize]
            } else if let Some(copy) = self.0.fats.iter().position(|fat| fat.contains(&position)) {
                let relative = position - self.0.fats[copy].start;
                self.raw(copy as u8, (relative / width) as u32, &trace)
                    .to_le_bytes()[(relative % width) as usize]
            } else if (self.0.root..self.0.root + sector).contains(&position) {
                self.0.record.get((position - self.0.root) as usize).copied().unwrap_or(0)
            } else {
                panic!("extent query read payload or unrelated storage at {position}");
            };
        }
        if trace.cancel_after == Some(trace.calls) {
            cx.set_cancel_requested(true);
        }
        Ok(())
    }

    fn write_all_at(&self, _: &Cx, _: ByteOffset, _: &[u8]) -> Result<()> {
        panic!("extent query wrote backing storage")
    }

    fn sync(&self, _: &Cx) -> Result<()> {
        panic!("extent query synchronized backing storage")
    }
}

struct Fixture {
    device: Device,
    fs: FatFs,
    entry: Entry,
    ino: InodeNumber,
}

impl Fixture {
    fn new(kind: FatKind, sector: u16, chain: &[u32], linear: usize, size: u32,
        active: bool, writable: bool) -> Self {
        let sector_bytes = u64::from(sector);
        let minimum: u32 = if kind == FatKind::Fat16 { 5000 } else { 70_000 };
        let clusters = minimum.max(chain.iter().copied().max().unwrap_or(3 + linear as u32) + 1);
        let reserved = if kind == FatKind::Fat16 { 1_u16 } else { 32 };
        let width = u64::from(kind.entry_bytes());
        let fat_sectors = ((u64::from(clusters) + 2) * width).div_ceil(sector_bytes);
        let root_entries = if kind == FatKind::Fat16 { sector / 32 } else { 0 };
        let total = u64::from(reserved) + 2 * fat_sectors
            + u64::from(root_entries) * 32 / sector_bytes + u64::from(clusters);
        let mut boot = [0_u8; 512];
        boot[..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
        boot[3..11].copy_from_slice(b"MSWIN4.1");
        boot[11..13].copy_from_slice(&sector.to_le_bytes());
        boot[13] = 1;
        boot[14..16].copy_from_slice(&reserved.to_le_bytes());
        boot[16] = 2;
        boot[17..19].copy_from_slice(&root_entries.to_le_bytes());
        boot[21] = 0xf8;
        boot[32..36].copy_from_slice(&(total as u32).to_le_bytes());
        boot[510..512].copy_from_slice(&[0x55, 0xaa]);
        if kind == FatKind::Fat16 {
            boot[22..24].copy_from_slice(&(fat_sectors as u16).to_le_bytes());
            boot[38] = 0x29;
        } else {
            boot[36..40].copy_from_slice(&(fat_sectors as u32).to_le_bytes());
            boot[44..48].copy_from_slice(&2_u32.to_le_bytes());
            boot[50..52].copy_from_slice(&6_u16.to_le_bytes());
            boot[66] = 0x29;
            if active { boot[40..42].copy_from_slice(&0x81_u16.to_le_bytes()); }
        }
        let geometry = FatGeometry::parse(&boot, total * sector_bytes).unwrap();
        assert_eq!(geometry.kind(), kind);
        let first = chain.first().copied().unwrap_or(if linear == 0 { 0 } else { 3 });
        let mut record = [0; 32];
        record[..11].copy_from_slice(b"DATA    BIN");
        record[11] = 0x20;
        record[26..28].copy_from_slice(&(first as u16).to_le_bytes());
        if kind == FatKind::Fat32 {
            record[20..22].copy_from_slice(&((first >> 16) as u16).to_le_bytes());
        }
        record[28..32].copy_from_slice(&size.to_le_bytes());
        let terminal = if kind == FatKind::Fat16 { 0xffff } else { 0x0fff_ffff };
        let successors = chain.iter().enumerate().map(|(i, &cluster)| {
            (cluster, chain.get(i + 1).copied().unwrap_or(terminal))
        }).collect();
        let start = BASE + u64::from(reserved) * sector_bytes;
        let fat_bytes = fat_sectors * sector_bytes;
        let root = BASE + geometry.fixed_root()
            .map_or_else(|| geometry.cluster_offset(2).unwrap(), |(at, _)| at);
        let device = Device(Arc::new(Image {
            boot, geometry, fats: [start..start + fat_bytes, start + fat_bytes..start + 2 * fat_bytes],
            root, record, linear, successors, active, trace: Mutex::default(),
        }));
        let cx = Cx::for_testing();
        let volume = FatVolume::from_device(&cx, Box::new(device.clone()), BASE, total * sector_bytes).unwrap();
        let entry = volume.lookup(&cx, crate::Directory::Root, "DATA.BIN").unwrap();
        let fs = FatFs::new_with_mode(&cx, volume, 1000, 1000, writable).unwrap();
        let page = fs.readdir(&cx, &mut RequestScope::empty(), ROOT, 0).unwrap();
        let ino = page.iter().find(|entry| entry.name == b"DATA.BIN").unwrap().ino;
        device.reset();
        Self { device, fs, entry, ino }
    }

    fn query(&self, start: u64, length: u64) -> Result<Vec<FiemapExtent>> {
        self.fs.fiemap(&Cx::for_testing(), &mut RequestScope::empty(), self.ino, start, length)
    }

    fn reference(&self, chain: &[u32], start: u64, length: u64) -> Vec<FiemapExtent> {
        let geometry = &self.device.0.geometry;
        fat_fiemap(&Cx::for_testing(), &FileChain {
            clusters: chain.to_vec(), size: self.entry.native.size,
        }, geometry.cluster_bytes(), geometry.cluster_offset(2).unwrap(), geometry.volume_bytes(),
            start, length).unwrap()
    }
}

#[test]
fn streamed_fiemap_matches_materialized_extent_semantics() {
    let chain = [3, 4, 11, 12, 13, 7];
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for sector in [512_u16, 4096] {
            for size in [0, 1, 4 * u32::from(sector) - 17, 6 * u32::from(sector)] {
                let fixture = Fixture::new(kind, sector, &chain, 0, size, false, false);
                let capacity = chain.len() as u64 * u64::from(sector);
                for (start, length) in [(0, u64::MAX), (0, 0), (1, 1),
                    (2 * u64::from(sector) + 1, 7), (capacity - 1, u64::MAX),
                    (capacity, 1), (u64::MAX, u64::MAX)] {
                    assert_eq!(fixture.query(start, length).unwrap(), fixture.reference(&chain, start, length));
                }
                assert_eq!(fixture.fs.immutable_cache_usage(), (0, 0, 0));
                assert!(fixture.device.0.trace.lock().unwrap().maximum <= 64 * 1024);
            }
        }
    }
}

#[test]
fn maximum_native_file_returns_two_extents_without_any_cluster_map_cache() {
    let count = u64::from(u32::MAX).div_ceil(4096) as usize;
    let fixture = Fixture::new(FatKind::Fat32, 4096, &[], count, u32::MAX, false, false);
    let physical = fixture.device.0.geometry.cluster_offset(3).unwrap();
    let all = fixture.query(0, u64::MAX).unwrap();
    assert_eq!(all, [
        FiemapExtent { logical: 0, physical, length: u64::from(u32::MAX), flags: FIEMAP_EXTENT_NOT_ALIGNED },
        FiemapExtent { logical: u64::from(u32::MAX), physical: physical + u64::from(u32::MAX), length: 1,
            flags: FIEMAP_EXTENT_LAST | FIEMAP_EXTENT_UNWRITTEN | FIEMAP_EXTENT_NOT_ALIGNED },
    ]);
    assert_eq!(fixture.query(1234, 1).unwrap(), all[..1]);
    assert_eq!(fixture.fs.immutable_cache_usage(), (0, 0, 0));
    assert!(fixture.device.0.trace.lock().unwrap().maximum <= 64 * 1024);
}

#[test]
fn many_fragmented_runs_only_retain_query_intersections() {
    let chain: Vec<_> = (0..1031_u32).map(|n| 3 + (n * 37) % 1031).collect();
    let fixture = Fixture::new(FatKind::Fat32, 512, &chain, 0, 900 * 512 + 7, false, false);
    for index in [0, 1, 255, 256, 899, 900, 1029, 1030] {
        let at = index * 512 + 11;
        let actual = fixture.query(at, 1).unwrap();
        assert_eq!(actual, fixture.reference(&chain, at, 1));
        assert_eq!(actual.len(), 1);
    }
    assert_eq!(fixture.fs.immutable_cache_usage(), (0, 0, 0));
}

#[test]
fn tail_corruption_defeats_even_empty_and_early_extent_queries() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for fault in ["free", "bad", "reserved", "cycle", "outside", "mirror"] {
            let fixture = Fixture::new(kind, 512, &[], 600, 1, false, false);
            let value = match (kind, fault) {
                (FatKind::Fat16, "bad") => 0xfff7,
                (FatKind::Fat32, "bad") => 0x0fff_fff7,
                (FatKind::Fat16, "reserved") => 0xfff0,
                (FatKind::Fat32, "reserved") => 0x0fff_fff0,
                (_, "cycle") => 259,
                (_, "outside") => fixture.device.0.geometry.cluster_count() + 2,
                _ => 0,
            };
            for copy in 0..if fault == "mirror" { 1 } else { 2 } {
                fixture.device.fault(copy, 602, value);
            }
            for (start, length) in [(0, 1), (0, 0), (u64::MAX, 1)] {
                assert!(fixture.query(start, length).is_err(), "{kind:?}/{fault}");
            }
            assert_eq!(fixture.fs.immutable_cache_usage(), (0, 0, 0));
        }
    }
}

#[test]
fn read_and_cancellation_failures_drop_the_entire_extent_result_and_allow_retry() {
    let chain: Vec<_> = (0..1031_u32).map(|n| 3 + (n * 37) % 1031).collect();
    let fixture = Fixture::new(FatKind::Fat32, 512, &chain, 0, 500_000, false, false);
    let last = *chain.last().unwrap();
    let at = BASE + fixture.device.0.geometry.entry_offset(1, last).unwrap();
    fixture.device.0.trace.lock().unwrap().fail = Some(at..at + 4);
    assert!(fixture.query(0, u64::MAX).is_err());
    fixture.device.reset();
    let cx = Cx::for_testing();
    fixture.device.0.trace.lock().unwrap().cancel_after = Some(3);
    assert!(matches!(fixture.fs.fiemap(&cx, &mut RequestScope::empty(), fixture.ino, 0, u64::MAX),
        Err(FfsError::Cancelled)));
    fixture.device.reset();
    assert_eq!(fixture.query(0, u64::MAX).unwrap(), fixture.reference(&chain, 0, u64::MAX));
    let cancelled = Cx::for_testing();
    cancelled.set_cancel_requested(true);
    fixture.device.reset();
    assert!(matches!(fixture.fs.fiemap(&cancelled, &mut RequestScope::empty(), fixture.ino, 0, 0),
        Err(FfsError::Cancelled)));
    assert_eq!(fixture.device.0.trace.lock().unwrap().calls, 0);
}

#[test]
fn selected_active_fat_ignores_inactive_damage_and_reserved_high_bits() {
    let chain = [3, 4, 70_000, 70_001, 9];
    let fixture = Fixture::new(FatKind::Fat32, 4096, &chain, 0, 8193, true, false);
    fixture.device.0.trace.lock().unwrap().fail = Some(fixture.device.0.fats[0].clone());
    assert_eq!(fixture.query(0, u64::MAX).unwrap(), fixture.reference(&chain, 0, u64::MAX));
    assert_eq!(fixture.fs.immutable_cache_usage(), (0, 0, 0));
}

#[test]
fn warm_sparse_cache_cannot_mask_extent_walk_failure() {
    let fixture = Fixture::new(FatKind::Fat32, 512, &[], 600, 1, false, false);
    fixture.fs.lookup(&Cx::for_testing(), &mut RequestScope::empty(), ROOT, OsStr::new("DATA.BIN")).unwrap();
    let usage = fixture.fs.immutable_cache_usage();
    assert_eq!((usage.0, usage.2), (1, 0));
    let at = BASE + fixture.device.0.geometry.entry_offset(1, 602).unwrap();
    fixture.device.0.trace.lock().unwrap().fail = Some(at..at + 4);
    assert!(fixture.query(0, 1).is_err());
    assert_eq!(fixture.fs.immutable_cache_usage(), usage);
}

#[test]
fn empty_short_and_directory_requests_keep_native_refusals() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let empty = Fixture::new(kind, 512, &[], 0, 0, false, false);
        assert_eq!(empty.query(0, u64::MAX).unwrap(), Vec::<FiemapExtent>::new());
        let short = Fixture::new(kind, 512, &[3], 0, 513, false, false);
        assert!(short.query(0, 1).is_err());
        assert_eq!(empty.fs.fiemap(&Cx::for_testing(), &mut RequestScope::empty(), ROOT, 0, 1)
            .unwrap_err().to_errno(), libc::EINVAL);
    }
}

#[test]
fn writable_fiemap_keeps_existing_maps_and_refuses_immutable_helper() {
    let chain = [3, 4, 11, 12];
    let fixture = Fixture::new(FatKind::Fat16, 512, &chain, 0, 1025, false, true);
    assert!(fixture.fs.readonly_fiemap(&Cx::for_testing(), &fixture.entry, 0, 1).is_err());
    assert_eq!(fixture.device.0.trace.lock().unwrap().calls, 0);
    assert_eq!(fixture.query(0, u64::MAX).unwrap(), fixture.reference(&chain, 0, u64::MAX));
    assert_eq!(fixture.fs.immutable_cache_usage(), (0, 0, 1));
}

#[test]
fn concurrent_extent_requests_have_independent_run_state_and_no_cache_publication() {
    let chain: Vec<_> = (0..257_u32).map(|n| 3 + (n * 37) % 257).collect();
    let fixture = Fixture::new(FatKind::Fat32, 512, &chain, 0, 100_001, false, false);
    let expected: Vec<_> = (0..8).map(|n| fixture.reference(&chain, n * 7919, 4097)).collect();
    std::thread::scope(|threads| {
        for (n, expected) in expected.into_iter().enumerate() {
            let fixture = &fixture;
            threads.spawn(move || {
                assert_eq!(fixture.query(n as u64 * 7919, 4097).unwrap(), expected);
            });
        }
    });
    assert_eq!(fixture.fs.immutable_cache_usage(), (0, 0, 0));
}
