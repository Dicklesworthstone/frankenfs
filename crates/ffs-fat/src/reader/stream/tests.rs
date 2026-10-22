//! Real reader calls over native-layout synthetic images. This is not a kernel
//! mount or an independent native-tool interoperability campaign.

mod mounted;

use super::*;
use crate::{Directory, EntrySlots};
use ffs_block::ByteDevice;
use ffs_ondisk::fat::{FatGeometry, FatKind};
use ffs_types::ByteOffset;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::ops::Range;
use std::sync::{Arc, Mutex};

const BASE: u64 = 8192;

#[derive(Default)]
struct Trace {
    reads: Vec<(u64, usize)>,
    fail: Option<Range<u64>>,
    cancel_after: Option<usize>,
}

struct Image {
    boot: [u8; 512],
    geometry: FatGeometry,
    fats: [Range<u64>; 2],
    root: u64,
    record: [u8; 32],
    linear: usize,
    overrides: BTreeMap<(u8, u32), u32>,
    patches: Mutex<BTreeMap<u64, u8>>,
    trace: Mutex<Trace>,
}

#[derive(Clone)]
struct Device(Arc<Image>);

impl Device {
    fn put(&self, offset: u64, bytes: &[u8]) {
        let mut patches = self.0.patches.lock().unwrap();
        for (index, byte) in bytes.iter().enumerate() {
            patches.insert(offset + index as u64, *byte);
        }
    }

    fn reset(&self) {
        *self.0.trace.lock().unwrap() = Trace::default();
    }

    fn volume(&self) -> FatVolume {
        FatVolume::from_device(
            &Cx::for_testing(),
            Box::new(self.clone()),
            BASE,
            self.0.geometry.volume_bytes(),
        )
        .unwrap()
    }

    fn data_reads(&self) -> Vec<(u64, usize)> {
        let data = BASE + self.0.geometry.cluster_offset(3).unwrap();
        self.0
            .trace
            .lock()
            .unwrap()
            .reads
            .iter()
            .copied()
            .filter(|(at, _)| *at >= data)
            .collect()
    }

    fn fat_value(&self, copy: u8, cluster: u32) -> u32 {
        let end = if self.0.geometry.kind() == FatKind::Fat16 {
            0xffff
        } else {
            0x0fff_ffff
        };
        if let Some(&value) = self.0.overrides.get(&(copy, cluster)) {
            return value;
        }
        match cluster {
            0 => end & !7,
            1 => end,
            2 if self.0.geometry.kind() == FatKind::Fat32 => end,
            n if n >= 3 && (n - 3) < self.0.linear as u32 => {
                if (n - 2) == self.0.linear as u32 {
                    end
                } else {
                    n + 1
                }
            }
            _ => 0,
        }
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
        trace.reads.push((at.0, bytes.len()));
        if trace
            .fail
            .as_ref()
            .is_some_and(|range| at.0 < range.end && end > range.start)
        {
            bytes.fill(0xee); // Failed device output must never become successful data.
            return Err(io::Error::from_raw_os_error(libc::EIO).into());
        }
        let patches = self.0.patches.lock().unwrap();
        let sector = u64::from(self.0.geometry.sector_bytes());
        let backup = self
            .0
            .geometry
            .backup_boot_sector()
            .map(|n| BASE + u64::from(n) * sector);
        let width = u64::from(self.0.geometry.kind().entry_bytes());
        for (index, byte) in bytes.iter_mut().enumerate() {
            let position = at.0 + index as u64;
            *byte = if let Some(&patched) = patches.get(&position) {
                patched
            } else if (BASE..BASE + 512).contains(&position) {
                self.0.boot[(position - BASE) as usize]
            } else if backup.is_some_and(|start| (start..start + 512).contains(&position)) {
                self.0.boot[(position - backup.unwrap()) as usize]
            } else if let Some(copy) = self
                .0
                .fats
                .iter()
                .position(|range| range.contains(&position))
            {
                let relative = position - self.0.fats[copy].start;
                self.fat_value(copy as u8, (relative / width) as u32)
                    .to_le_bytes()[(relative % width) as usize]
            } else if (self.0.root..self.0.root + sector).contains(&position) {
                let index = (position - self.0.root) as usize;
                self.0.record.get(index).copied().unwrap_or(0)
            } else {
                (position % 251) as u8
            };
        }
        if trace.cancel_after == Some(trace.reads.len()) {
            cx.set_cancel_requested(true);
        }
        Ok(())
    }

    fn write_all_at(&self, _: &Cx, _: ByteOffset, _: &[u8]) -> Result<()> {
        panic!("bounded read issued a backing write")
    }
    fn sync(&self, _: &Cx) -> Result<()> {
        panic!("bounded read synchronized its backing")
    }
}

struct Fixture {
    device: Device,
    volume: FatVolume,
    entry: Entry,
}

impl Fixture {
    fn new(kind: FatKind, sector: u16, chain: &[u32], size: u32) -> Self {
        Self::build(kind, sector, 0, chain, size)
    }

    fn linear(kind: FatKind, sector: u16, length: usize, size: u32) -> Self {
        Self::build(kind, sector, length, &[], size)
    }

    fn build(kind: FatKind, sector: u16, linear: usize, chain: &[u32], size: u32) -> Self {
        let sector_bytes = u64::from(sector);
        let largest = chain.iter().copied().max().unwrap_or(3 + linear as u32);
        let clusters = if kind == FatKind::Fat16 {
            5000_u32
        } else {
            70_000
        }
        .max(largest + 1);
        let reserved = if kind == FatKind::Fat16 { 1_u16 } else { 32 };
        let width = u64::from(kind.entry_bytes());
        let fat_sectors = ((u64::from(clusters) + 2) * width).div_ceil(sector_bytes);
        let root_entries = if kind == FatKind::Fat16 {
            sector / 32
        } else {
            0
        };
        let total = u64::from(reserved)
            + 2 * fat_sectors
            + u64::from(root_entries) * 32 / sector_bytes
            + u64::from(clusters);
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
            // No FSInfo declaration: this fixture exercises file allocation,
            // not hint reconstruction. The backup boot record is still real.
            boot[50..52].copy_from_slice(&6_u16.to_le_bytes());
            boot[66] = 0x29;
        }
        let geometry = FatGeometry::parse(&boot, total * sector_bytes).unwrap();
        assert_eq!(geometry.kind(), kind);
        let first = chain
            .first()
            .copied()
            .unwrap_or(if linear == 0 { 0 } else { 3 });
        let mut record = [0_u8; 32];
        record[..11].copy_from_slice(b"DATA    BIN");
        record[11] = 0x20;
        record[26..28].copy_from_slice(&(first as u16).to_le_bytes());
        if kind == FatKind::Fat32 {
            record[20..22].copy_from_slice(&((first >> 16) as u16).to_le_bytes());
        }
        record[28..32].copy_from_slice(&size.to_le_bytes());
        let end = if kind == FatKind::Fat16 {
            0xffff
        } else {
            0x0fff_ffff
        };
        let mut overrides = BTreeMap::new();
        for copy in 0..2_u8 {
            for (index, &cluster) in chain.iter().enumerate() {
                overrides.insert(
                    (copy, cluster),
                    chain.get(index + 1).copied().unwrap_or(end),
                );
            }
        }
        let start = BASE + u64::from(reserved) * sector_bytes;
        let fat_bytes = fat_sectors * sector_bytes;
        let root = BASE
            + geometry
                .fixed_root()
                .map_or_else(|| geometry.cluster_offset(2).unwrap(), |(at, _)| at);
        let device = Device(Arc::new(Image {
            boot,
            geometry,
            fats: [
                start..start + fat_bytes,
                start + fat_bytes..start + 2 * fat_bytes,
            ],
            root,
            record,
            linear,
            overrides,
            patches: Mutex::default(),
            trace: Mutex::default(),
        }));
        let volume = device.volume();
        let entry = volume
            .lookup(&Cx::for_testing(), Directory::Root, "DATA.BIN")
            .unwrap();
        device.reset();
        Self {
            device,
            volume,
            entry,
        }
    }

    fn expected(&self, chain: &[u32], offset: u64, count: usize) -> Vec<u8> {
        let sector = u64::from(self.volume.geometry.cluster_bytes());
        let count = u64::from(self.entry.native.size)
            .saturating_sub(offset)
            .min(count as u64);
        (offset..offset + count)
            .map(|logical| {
                let index = (logical / sector) as usize;
                let cluster = if chain.is_empty() {
                    3 + index as u32
                } else {
                    chain[index]
                };
                let physical =
                    BASE + self.volume.geometry.cluster_offset(cluster).unwrap() + logical % sector;
                (physical % 251) as u8
            })
            .collect()
    }
}

#[test]
fn fragmented_random_and_reverse_reads_match_independent_physical_byte_oracle() {
    let chain: Vec<_> = (0..1031_u32).map(|index| 3 + (index * 37) % 1031).collect();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for sector in [512_u16, 4096] {
            let fixture = Fixture::new(kind, sector, &chain, 1000 * u32::from(sector) - 17);
            let cx = Cx::for_testing();
            let mut reader = fixture
                .volume
                .open_file_reader(&cx, &fixture.entry)
                .unwrap();
            assert_eq!(reader.allocated_clusters(), chain.len());
            assert_eq!(reader.anchors.len(), chain.len().div_ceil(ANCHOR_STRIDE));
            assert!(
                fixture.device.data_reads().is_empty(),
                "indexing must not read payload"
            );
            for index in [999, 0, 256, 255, 513, 512, 1, 998, 768, 767] {
                let at = index * u64::from(sector) + 13;
                assert_eq!(
                    reader.read(&cx, at, 8197).unwrap(),
                    fixture.expected(&chain, at, 8197)
                );
            }
            let materialized = fixture.volume.file_chain(&cx, &fixture.entry).unwrap();
            assert_eq!(
                materialized.clusters, chain,
                "writers retain the same shared validation"
            );
            for index in (0..50_u64).rev() {
                let at = index * 7919 % reader.len_bytes();
                let expected = fixture.expected(&chain, at, 4099);
                assert_eq!(reader.read(&cx, at, 4099).unwrap(), expected);
                assert_eq!(
                    fixture.volume.read(&cx, &materialized, at, 4099).unwrap(),
                    expected
                );
            }
        }
    }
}

#[test]
fn maximum_native_file_uses_small_index_and_exact_u32_eof() {
    let count = u64::from(u32::MAX).div_ceil(4096) as usize;
    let fixture = Fixture::linear(FatKind::Fat32, 4096, count, u32::MAX);
    let cx = Cx::for_testing();
    let mut reader = fixture
        .volume
        .open_file_reader(&cx, &fixture.entry)
        .unwrap();
    assert_eq!(reader.len_bytes(), u64::from(u32::MAX));
    assert_eq!(reader.allocated_clusters(), count);
    assert_eq!(reader.anchors.len(), 4096);
    assert!(reader.index_storage_bytes() <= 16 * 1024);
    assert_eq!(fixture.device.data_reads(), Vec::<(u64, usize)>::new());
    for at in [0, 1, 1_048_575, 2_147_483_647, u64::from(u32::MAX) - 4097] {
        assert_eq!(
            reader.read(&cx, at, 8192).unwrap(),
            fixture.expected(&[], at, 8192)
        );
    }
    fixture.device.reset();
    for at in [u64::from(u32::MAX), u64::MAX] {
        assert_eq!(reader.read(&cx, at, 1024).unwrap(), Vec::<u8>::new());
    }
    assert_eq!(
        fixture.device.0.trace.lock().unwrap().reads,
        Vec::<(u64, usize)>::new()
    );
}

#[test]
fn contiguous_runs_stay_bounded_and_do_not_read_slack_or_preallocation() {
    let fixture = Fixture::linear(FatKind::Fat32, 512, 1200, 1000 * 512 - 19);
    let cx = Cx::for_testing();
    let mut reader = fixture
        .volume
        .open_file_reader(&cx, &fixture.entry)
        .unwrap();
    fixture.device.reset();
    let at = 17;
    assert_eq!(
        reader.read(&cx, at, 1024 * 1024).unwrap(),
        fixture.expected(&[], at, 1024 * 1024)
    );
    let reads = fixture.device.data_reads();
    let count = fixture.entry.native.size as usize - at as usize;
    assert_eq!(reads.len(), count.div_ceil(MAX_READ_RUN_BYTES));
    assert_eq!(reads.iter().map(|(_, len)| len).sum::<usize>(), count);
    assert!(reads.iter().all(|(_, len)| *len <= MAX_READ_RUN_BYTES));
    assert_eq!(
        reads[0].0,
        BASE + fixture.volume.geometry.cluster_offset(3).unwrap() + at
    );
    let last = reads.last().unwrap();
    assert_eq!(
        last.0 + last.1 as u64,
        BASE + fixture.volume.geometry.cluster_offset(3).unwrap() + reader.len_bytes()
    );
}

#[test]
fn invalid_preallocated_tail_is_rejected_before_any_payload_or_stream_output() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for fault in ["free", "reserved", "bad", "cycle", "outside", "mirror"] {
            let fixture = Fixture::linear(kind, 512, 600, 1);
            let geometry = &fixture.volume.geometry;
            let value = match (kind, fault) {
                (FatKind::Fat16, "reserved") => 0xfff0,
                (FatKind::Fat32, "reserved") => 0x0fff_fff0,
                (FatKind::Fat16, "bad") => 0xfff7,
                (FatKind::Fat32, "bad") => 0x0fff_fff7,
                (_, "cycle") => 259,
                (_, "outside") => geometry.cluster_count() + 2,
                _ => 0,
            };
            for copy in 0..if fault == "mirror" { 1 } else { 2 } {
                let at = BASE + geometry.entry_offset(copy, 602).unwrap();
                fixture
                    .device
                    .put(at, &value.to_le_bytes()[..kind.entry_bytes() as usize]);
            }
            let cx = Cx::for_testing();
            assert!(
                fixture
                    .volume
                    .open_file_reader(&cx, &fixture.entry)
                    .is_err(),
                "{kind:?}/{fault}"
            );
            assert!(fixture.volume.file_chain(&cx, &fixture.entry).is_err());
            let mut output = Vec::new();
            assert!(crate::stream_file(&cx, &fixture.volume, &fixture.entry, &mut output).is_err());
            assert_eq!(output, Vec::<u8>::new());
            assert_eq!(fixture.device.data_reads(), Vec::<(u64, usize)>::new());
        }
    }
}

#[test]
fn empty_preallocated_and_short_files_keep_native_length_rules() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for allocated in [0, 600] {
            let fixture = Fixture::linear(kind, 512, allocated, 0);
            let cx = Cx::for_testing();
            let mut reader = fixture
                .volume
                .open_file_reader(&cx, &fixture.entry)
                .unwrap();
            assert_eq!(reader.allocated_clusters(), allocated);
            fixture.device.reset();
            assert_eq!(reader.read(&cx, 0, 4096).unwrap(), Vec::<u8>::new());
            assert!(reader.read(&cx, 0, MAX_READ_BYTES + 1).is_err());
            assert_eq!(
                fixture.device.0.trace.lock().unwrap().reads,
                Vec::<(u64, usize)>::new()
            );
        }
        let fixture = Fixture::linear(kind, 512, 2, 1025);
        let cx = Cx::for_testing();
        assert!(
            fixture
                .volume
                .open_file_reader(&cx, &fixture.entry)
                .is_err()
        );
        let mut entry = fixture.entry.clone();
        entry.native.attributes = 0x10;
        assert!(matches!(
            fixture.volume.open_file_reader(&cx, &entry),
            Err(FfsError::IsDirectory)
        ));
    }
}

#[test]
fn active_copy_policy_ignores_inactive_damage_and_masks_reserved_high_bits() {
    let fixture = Fixture::linear(FatKind::Fat32, 4096, 600, 600 * 4096);
    for sector in [0, 6] {
        fixture
            .device
            .put(BASE + sector * 4096 + 40, &0x81_u16.to_le_bytes());
    }
    fixture.device.put(fixture.device.0.fats[0].start, &[0; 8]);
    for cluster in 3..603 {
        let value = fixture.device.fat_value(1, cluster) | 0xa000_0000;
        fixture.device.put(
            BASE + fixture.volume.geometry.entry_offset(1, cluster).unwrap(),
            &value.to_le_bytes(),
        );
    }
    let volume = fixture.device.volume();
    fixture.device.reset();
    fixture.device.0.trace.lock().unwrap().fail = Some(fixture.device.0.fats[0].clone());
    let cx = Cx::for_testing();
    let mut reader = volume.open_file_reader(&cx, &fixture.entry).unwrap();
    for at in [0, 512 * 4096 + 1, 200 * 4096, 600 * 4096 - 17] {
        assert_eq!(
            reader.read(&cx, at, 4097).unwrap(),
            fixture.expected(&[], at, 4097)
        );
    }
}

#[test]
fn failed_late_payload_and_table_reads_never_return_partial_success() {
    let fixture = Fixture::linear(FatKind::Fat32, 512, 2000, 2000 * 512);
    let cx = Cx::for_testing();
    let mut reader = fixture
        .volume
        .open_file_reader(&cx, &fixture.entry)
        .unwrap();
    fixture.device.reset();
    let fail = BASE + fixture.volume.geometry.cluster_offset(3).unwrap() + 65536;
    fixture.device.0.trace.lock().unwrap().fail = Some(fail..fail + 1);
    assert!(reader.read(&cx, 0, 131_072).is_err());
    assert_eq!(fixture.device.data_reads().len(), 2);
    fixture.device.reset();
    assert_eq!(
        reader.read(&cx, 0, 131_072).unwrap(),
        fixture.expected(&[], 0, 131_072)
    );
    // A new reader starts with demand caches, not its completed validation cache.
    let mut reader = fixture
        .volume
        .open_file_reader(&cx, &fixture.entry)
        .unwrap();
    fixture.device.reset();
    let fail = BASE + fixture.volume.geometry.entry_offset(1, 260).unwrap();
    fixture.device.0.trace.lock().unwrap().fail = Some(fail..fail + 4);
    assert!(reader.read(&cx, 270 * 512, 1).is_err());
    assert_eq!(fixture.device.data_reads(), Vec::<(u64, usize)>::new());
}

#[test]
fn cancellation_is_checked_during_indexing_cached_seeks_and_after_payload_io() {
    let fixture = Fixture::linear(FatKind::Fat16, 512, 600, 600 * 512);
    let cx = Cx::for_testing();
    fixture.device.0.trace.lock().unwrap().cancel_after = Some(2);
    assert!(matches!(
        fixture.volume.open_file_reader(&cx, &fixture.entry),
        Err(FfsError::Cancelled)
    ));
    assert_eq!(fixture.device.data_reads(), Vec::<(u64, usize)>::new());
    fixture.device.reset();
    let cx = Cx::for_testing();
    let mut reader = fixture
        .volume
        .open_file_reader(&cx, &fixture.entry)
        .unwrap();
    fixture.device.reset();
    fixture.device.0.trace.lock().unwrap().cancel_after = Some(1);
    assert!(matches!(reader.read(&cx, 0, 1), Err(FfsError::Cancelled)));
    fixture.device.reset();
    assert!(matches!(
        reader.read(&cx, u64::MAX, 0),
        Err(FfsError::Cancelled)
    ));
    assert_eq!(
        fixture.device.0.trace.lock().unwrap().reads,
        Vec::<(u64, usize)>::new()
    );
}

#[test]
fn common_chain_walker_enforces_work_and_visitor_failure_before_extra_io() {
    let fixture = Fixture::linear(FatKind::Fat16, 512, 600, 600 * 512);
    let cx = Cx::for_testing();
    let mut visited = Vec::new();
    assert!(matches!(
        fixture
            .volume
            .walk_chain(&cx, 3, 0, 0, 3, |index, cluster| {
                visited.push((index, cluster));
                Ok(())
            }),
        Err(FfsError::UnsupportedFeature(_))
    ));
    assert_eq!(visited, [(0, 3), (1, 4), (2, 5)]);
    fixture.device.reset();
    assert!(matches!(
        fixture
            .volume
            .walk_chain(&cx, 3, 0, 0, 600, |_, _| { Err(FfsError::Cancelled) }),
        Err(FfsError::Cancelled)
    ));
    assert_eq!(
        fixture.device.0.trace.lock().unwrap().reads,
        Vec::<(u64, usize)>::new()
    );
}

struct Sink {
    bytes: Vec<u8>,
    fail_write: bool,
    fail_flush: bool,
    flushes: usize,
}
impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.fail_write {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        if self.fail_flush {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        } else {
            Ok(())
        }
    }
}

#[test]
fn public_stream_and_exact_selector_use_bounded_reader_and_propagate_output_failures() {
    let fixture = Fixture::linear(FatKind::Fat32, 512, 4300, 4200 * 512 - 1);
    let cx = Cx::for_testing();
    let expected = fixture.expected(&[], 0, fixture.entry.native.size as usize);
    let slots = EntrySlots::parse(&fixture.entry.offset.to_string()).unwrap();
    let mut output = Vec::new();
    crate::extract_slots(&cx, &fixture.volume, &slots, &mut output).unwrap();
    assert_eq!(output, expected);
    for (fail_write, fail_flush) in [(true, false), (false, true), (false, false)] {
        let mut sink = Sink {
            bytes: Vec::new(),
            fail_write,
            fail_flush,
            flushes: 0,
        };
        let result = crate::stream_file(&cx, &fixture.volume, &fixture.entry, &mut sink);
        assert_eq!(result.is_err(), fail_write || fail_flush);
        assert_eq!(sink.flushes, usize::from(!fail_write));
        if !fail_write {
            assert_eq!(sink.bytes, expected);
        }
    }
    fixture.device.reset();
    let fail = BASE + fixture.volume.geometry.cluster_offset(3).unwrap() + 1024 * 1024;
    fixture.device.0.trace.lock().unwrap().fail = Some(fail..fail + 1);
    let mut output = Vec::new();
    assert!(crate::stream_file(&cx, &fixture.volume, &fixture.entry, &mut output).is_err());
    assert_eq!(
        output,
        expected[..1024 * 1024],
        "already emitted stdout cannot be rolled back"
    );
}
