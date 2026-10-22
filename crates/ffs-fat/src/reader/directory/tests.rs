//! Constructed native images at the real ByteDevice boundary. No kernel mount
//! or independent producer is implied by these tests.

use super::*;
use crate::reader::{FatGeometry, FatKind, FatOemCodePage};
use ffs_block::ByteDevice;
use ffs_ondisk::fat::short_name_checksum;
use ffs_types::ByteOffset;
use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::{Arc, Mutex};

const BASE: u64 = 8192;

#[derive(Default)]
struct State {
    pages: BTreeMap<u64, [u8; 512]>,
    reads: Vec<(u64, usize)>,
    fail: Option<Range<u64>>,
    cancel_at: Option<u64>,
}

#[derive(Clone)]
struct Device {
    length: u64,
    state: Arc<Mutex<State>>,
}

impl Device {
    fn put(&self, mut at: u64, mut bytes: &[u8]) {
        let mut state = self.state.lock().unwrap();
        while !bytes.is_empty() {
            let within = at as usize % 512;
            let count = bytes.len().min(512 - within);
            state.pages.entry(at / 512).or_insert([0; 512])[within..within + count]
                .copy_from_slice(&bytes[..count]);
            bytes = &bytes[count..];
            at += count as u64;
        }
    }
}

impl ByteDevice for Device {
    fn len_bytes(&self) -> u64 {
        self.length
    }

    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        let end = at
            .0
            .checked_add(bytes.len() as u64)
            .filter(|end| *end <= self.length)
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
        let mut state = self.state.lock().unwrap();
        state.reads.push((at.0, bytes.len()));
        if state
            .fail
            .as_ref()
            .is_some_and(|range| at.0 < range.end && range.start < end)
        {
            bytes.fill(0xA5); // Failed buffers must never be parsed.
            return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
        }
        for (index, byte) in bytes.iter_mut().enumerate() {
            let position = at.0 + index as u64;
            *byte = state
                .pages
                .get(&(position / 512))
                .map_or(0, |page| page[position as usize % 512]);
        }
        if state.cancel_at == Some(at.0) {
            cx.set_cancel_requested(true);
        }
        Ok(())
    }

    fn write_all_at(&self, _: &Cx, _: ByteOffset, _: &[u8]) -> Result<()> {
        panic!("directory reads must not write backing storage")
    }

    fn sync(&self, _: &Cx) -> Result<()> {
        panic!("directory reads must not synchronize backing storage")
    }
}

struct Fixture {
    device: Device,
    geometry: FatGeometry,
    directory: Directory,
    offsets: Vec<u64>,
    unit: usize,
}

impl Fixture {
    fn new(kind: FatKind, sector: u16, sectors_per_cluster: u8, chain: &[u32]) -> Self {
        let count = if kind == FatKind::Fat16 {
            5000_u32
        } else {
            70_000
        };
        let reserved = if kind == FatKind::Fat16 { 1_u16 } else { 32 };
        let roots = if kind == FatKind::Fat16 {
            3 * (sector / 32)
        } else {
            0
        };
        let fat_sectors = ((u64::from(count) + 2) * u64::from(kind.entry_bytes()))
            .div_ceil(u64::from(sector));
        let total = u64::from(reserved)
            + 2 * fat_sectors
            + u64::from(roots) * 32 / u64::from(sector)
            + u64::from(count) * u64::from(sectors_per_cluster);
        let length = total * u64::from(sector);
        let mut boot = [0; 512];
        boot[..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
        boot[3..11].copy_from_slice(b"MSWIN4.1");
        boot[11..13].copy_from_slice(&sector.to_le_bytes());
        boot[13] = sectors_per_cluster;
        boot[14..16].copy_from_slice(&reserved.to_le_bytes());
        boot[16] = 2;
        boot[17..19].copy_from_slice(&roots.to_le_bytes());
        boot[21] = 0xF8;
        boot[510..512].copy_from_slice(&[0x55, 0xAA]);
        if kind == FatKind::Fat16 {
            boot[22..24].copy_from_slice(&(fat_sectors as u16).to_le_bytes());
            if let Ok(small) = u16::try_from(total) {
                boot[19..21].copy_from_slice(&small.to_le_bytes());
            } else {
                boot[32..36].copy_from_slice(&(total as u32).to_le_bytes());
            }
            boot[38] = 0x29;
        } else {
            boot[32..36].copy_from_slice(&(total as u32).to_le_bytes());
            boot[36..40].copy_from_slice(&(fat_sectors as u32).to_le_bytes());
            boot[44..48].copy_from_slice(&chain[0].to_le_bytes());
            boot[48..50].copy_from_slice(&1_u16.to_le_bytes());
            boot[50..52].copy_from_slice(&6_u16.to_le_bytes());
            boot[66] = 0x29;
        }
        let geometry = FatGeometry::parse(&boot, length).unwrap();
        let device = Device {
            length: BASE + length + BASE,
            state: Arc::default(),
        };
        device.put(BASE, &boot);
        if kind == FatKind::Fat32 {
            device.put(BASE + 6 * u64::from(sector), &boot);
        }
        let directory = if kind == FatKind::Fat32 || chain.is_empty() {
            Directory::Root
        } else {
            Directory::Cluster(chain[0])
        };
        let (offsets, unit) = if chain.is_empty() {
            let (start, bytes) = geometry.fixed_root().unwrap();
            (
                (start..start + bytes).step_by(sector as usize).collect(),
                sector as usize,
            )
        } else {
            (
                chain
                    .iter()
                    .map(|&cluster| geometry.cluster_offset(cluster).unwrap())
                    .collect(),
                geometry.cluster_bytes() as usize,
            )
        };
        let fixture = Self {
            device,
            geometry,
            directory,
            offsets,
            unit,
        };
        let end = if kind == FatKind::Fat16 {
            0xFFFF_u32
        } else {
            0x0FFF_FFFF
        };
        let width = kind.entry_bytes() as usize;
        for copy in 0..2 {
            let start = fixture.geometry.entry_offset(copy, 2).unwrap() - (2 * width) as u64;
            fixture
                .device
                .put(BASE + start, &(end & !7).to_le_bytes()[..width]);
            fixture.device.put(
                BASE + start + width as u64,
                &end.to_le_bytes()[..width],
            );
            for (index, &cluster) in chain.iter().enumerate() {
                fixture.fat(copy, cluster, chain.get(index + 1).copied().unwrap_or(end));
            }
        }
        let mut deleted = vec![0; unit];
        for slot in deleted.as_chunks_mut::<32>().0 {
            slot[0] = 0xE5;
        }
        for &offset in &fixture.offsets {
            fixture.device.put(BASE + offset, &deleted);
        }
        fixture
    }

    fn volume(&self) -> FatVolume {
        let volume = FatVolume::from_device(
            &Cx::for_testing(),
            Box::new(self.device.clone()),
            BASE,
            self.geometry.volume_bytes(),
        )
        .unwrap();
        self.device.state.lock().unwrap().reads.clear();
        volume
    }

    fn fat(&self, copy: u8, cluster: u32, value: u32) {
        let width = self.geometry.kind().entry_bytes() as usize;
        self.device.put(
            BASE + self.geometry.entry_offset(copy, cluster).unwrap(),
            &value.to_le_bytes()[..width],
        );
    }

    fn slot(&self, index: usize, bytes: &[u8; 32]) -> u64 {
        let logical = index * 32;
        let offset = self.offsets[logical / self.unit] + (logical % self.unit) as u64;
        self.device.put(BASE + offset, bytes);
        offset
    }

    fn data_reads(&self) -> Vec<(u64, usize)> {
        self.device
            .state
            .lock()
            .unwrap()
            .reads
            .iter()
            .copied()
            .filter(|&(at, _)| {
                self.offsets.iter().any(|&offset| {
                    at >= BASE + offset && at < BASE + offset + self.unit as u64
                })
            })
            .collect()
    }
}

fn short(name: &[u8; 11]) -> [u8; 32] {
    let mut record = [0; 32];
    record[..11].copy_from_slice(name);
    record[11] = 0x20;
    record
}

fn long(units: &[u16], alias: &[u8; 11]) -> Vec<[u8; 32]> {
    let count = units.len().div_ceil(13);
    let mut records = Vec::new();
    for ordinal in (1..=count).rev() {
        let mut record = [0; 32];
        record[0] = ordinal as u8 | if ordinal == count { 0x40 } else { 0 };
        record[11] = 0x0F;
        record[13] = short_name_checksum(alias);
        for (local, at) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
            .into_iter()
            .enumerate()
        {
            let index = (ordinal - 1) * 13 + local;
            let value = units
                .get(index)
                .copied()
                .unwrap_or(if index == units.len() { 0 } else { 0xFFFF });
            record[at..at + 2].copy_from_slice(&value.to_le_bytes());
        }
        records.push(record);
    }
    records.push(short(alias));
    records
}

fn drain(reader: &mut DirectoryReader<'_>, cx: &Cx) -> Result<Vec<Entry>> {
    let mut result = Vec::new();
    while let Some(entry) = reader.next_entry(cx)? {
        result.push(entry);
    }
    Ok(result)
}

#[test]
fn fixed_and_fragmented_directories_preserve_native_records_across_buffer_boundaries() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for sector in [512, 4096] {
            for clustered in [false, true] {
                if kind == FatKind::Fat32 && !clustered {
                    continue;
                }
                let chain = if clustered { &[9, 3, 12][..] } else { &[][..] };
                let fixture = Fixture::new(kind, sector, 1, chain);
                let mut dot = short(b".          ");
                dot[11] = 0x10;
                fixture.slot(0, &dot);
                dot[..11].copy_from_slice(b"..         ");
                fixture.slot(1, &dot);
                let mut label = short(b"VOLUME     ");
                label[11] = 8;
                fixture.slot(2, &label);
                let start = fixture.unit / 32 - 1;
                let name = "Boundary \u{394} music.bin";
                let units: Vec<_> = name.encode_utf16().collect();
                let records = long(&units, b"BOUND~1 BIN");
                let mut expected_offset = 0;
                for (index, record) in records.iter().enumerate() {
                    expected_offset = fixture.slot(start + index, record);
                }
                fixture.slot(start + records.len(), &short(b"SECOND  TXT"));
                fixture.slot(start + records.len() + 1, &[0; 32]);
                let volume = fixture.volume();
                let cx = Cx::for_testing();
                let mut cursor: crate::reader::DirectoryReader<'_> = volume
                    .open_directory_reader(&cx, fixture.directory)
                    .unwrap();
                assert!(fixture.data_reads().is_empty());
                let entries = drain(&mut cursor, &cx).unwrap();
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0].offset, expected_offset);
                assert_eq!(entries[0].native.long_name.as_deref(), Some(units.as_slice()));
                assert_eq!(entries[0].name().unwrap(), name);
                assert_eq!(entries[0].short_alias().as_deref(), Some("BOUND~1.BIN"));
                assert_eq!(entries[1].name().unwrap(), "SECOND.TXT");
                let listed = volume.list(&cx, fixture.directory).unwrap();
                assert_eq!(listed.len(), entries.len());
                for (left, right) in listed.iter().zip(&entries) {
                    assert_eq!(left.offset, right.offset);
                    assert_eq!(left.native, right.native);
                }
                assert_eq!(
                    volume
                        .lookup(&cx, fixture.directory, "bound~1.bin")
                        .unwrap()
                        .offset,
                    expected_offset
                );
                let before = fixture.device.state.lock().unwrap().reads.len();
                assert!(cursor.next_entry(&cx).unwrap().is_none());
                assert_eq!(fixture.device.state.lock().unwrap().reads.len(), before);
            }
        }
    }
}

#[test]
fn late_invalid_entries_never_become_successful_listings_or_lookups() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let fixture = Fixture::new(kind, 512, 1, &[9, 3]);
        fixture.slot(0, &short(b"FIRST   BIN"));
        let mut invalid = short(b"BROKEN  BIN");
        invalid[28] = 1;
        fixture.slot(16, &invalid);
        let volume = fixture.volume();
        let cx = Cx::for_testing();
        let mut cursor = volume
            .open_directory_reader(&cx, fixture.directory)
            .unwrap();
        assert_eq!(
            cursor.next_entry(&cx).unwrap().unwrap().name().unwrap(),
            "FIRST.BIN"
        );
        assert_eq!(
            fixture.data_reads().len(),
            1,
            "no eager read of later directory storage"
        );
        assert!(cursor.next_entry(&cx).is_err());
        fixture.slot(16, &[0; 32]);
        let before = fixture.device.state.lock().unwrap().reads.len();
        assert!(cursor.next_entry(&Cx::for_testing()).is_err());
        assert_eq!(fixture.device.state.lock().unwrap().reads.len(), before);
        fixture.slot(16, &invalid);
        assert!(volume.list(&cx, fixture.directory).is_err());
        for name in ["FIRST.BIN", "MISSING.BIN"] {
            assert!(matches!(
                volume.lookup(&cx, fixture.directory, name),
                Err(FfsError::Corruption { .. })
            ));
        }
    }
}

#[test]
fn later_long_name_alias_collisions_defeat_an_early_exact_match() {
    let fixture = Fixture::new(FatKind::Fat32, 4096, 1, &[9, 3]);
    fixture.slot(0, &short(b"TARGET  BIN"));
    let units: Vec<_> = "target.bin".encode_utf16().collect();
    for (index, record) in long(&units, b"OTHER   BIN").iter().enumerate() {
        fixture.slot(128 + index, record);
    }
    let volume = fixture.volume();
    let cx = Cx::for_testing();
    for name in ["TARGET.BIN", "target.bin", "Target.Bin"] {
        let error = volume.lookup(&cx, fixture.directory, name).unwrap_err();
        assert!(error.to_string().contains("ambiguous FAT"));
    }
    assert_eq!(
        volume
            .lookup(&cx, fixture.directory, "OTHER.BIN")
            .unwrap()
            .native
            .short_name,
        *b"OTHER   BIN"
    );
}

#[test]
fn late_partial_device_errors_poison_only_the_cursor_and_never_return_partial_success() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let fixture = Fixture::new(kind, 512, 1, &[9, 3]);
        fixture.slot(0, &short(b"FIRST   BIN"));
        fixture.slot(16, &short(b"SECOND  BIN"));
        let volume = fixture.volume();
        let cx = Cx::for_testing();
        let mut cursor = volume
            .open_directory_reader(&cx, fixture.directory)
            .unwrap();
        assert!(cursor.next_entry(&cx).unwrap().is_some());
        let second = BASE + fixture.offsets[1];
        fixture.device.state.lock().unwrap().fail = Some(second..second + 512);
        assert!(cursor.next_entry(&cx).is_err());
        assert!(volume.list(&cx, fixture.directory).is_err());
        for name in ["FIRST.BIN", "MISSING.BIN"] {
            assert_eq!(
                volume
                    .lookup(&cx, fixture.directory, name)
                    .unwrap_err()
                    .to_errno(),
                libc::EIO
            );
        }
        fixture.device.state.lock().unwrap().fail = None;
        let before = fixture.device.state.lock().unwrap().reads.len();
        assert!(cursor.next_entry(&cx).is_err());
        assert_eq!(fixture.device.state.lock().unwrap().reads.len(), before);
        assert_eq!(volume.list(&cx, fixture.directory).unwrap().len(), 2);
    }
}

#[test]
fn cancellation_is_observed_between_buffered_records_and_after_physical_reads() {
    let fixture = Fixture::new(FatKind::Fat16, 512, 1, &[]);
    fixture.slot(0, &short(b"FIRST   BIN"));
    fixture.slot(1, &short(b"SECOND  BIN"));
    let volume = fixture.volume();
    let cx = Cx::for_testing();
    let mut cursor = volume
        .open_directory_reader(&cx, fixture.directory)
        .unwrap();
    assert!(cursor.next_entry(&cx).unwrap().is_some());
    let reads = fixture.device.state.lock().unwrap().reads.len();
    cx.set_cancel_requested(true);
    assert!(matches!(cursor.next_entry(&cx), Err(FfsError::Cancelled)));
    assert_eq!(fixture.device.state.lock().unwrap().reads.len(), reads);
    assert!(cursor.next_entry(&Cx::for_testing()).is_err());
    let cx = Cx::for_testing();
    let mut cursor = volume
        .open_directory_reader(&cx, fixture.directory)
        .unwrap();
    fixture.device.state.lock().unwrap().cancel_at = Some(BASE + fixture.offsets[0]);
    assert!(matches!(cursor.next_entry(&cx), Err(FfsError::Cancelled)));
    assert!(cursor.next_entry(&Cx::for_testing()).is_err());
    fixture.device.state.lock().unwrap().cancel_at = None;
    assert_eq!(
        volume
            .list(&Cx::for_testing(), fixture.directory)
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn complete_chain_admission_precedes_even_an_immediate_end_marker() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let end = if kind == FatKind::Fat16 {
            0xFFFF
        } else {
            0x0FFF_FFFF
        };
        for fault in [0_u32, end - 8, end - 15, 9, 500_000] {
            let fixture = Fixture::new(kind, 512, 1, &[9, 3]);
            fixture.slot(0, &[0; 32]);
            for copy in 0..2 {
                fixture.fat(copy, 3, fault);
            }
            let volume = fixture.volume();
            assert!(
                volume
                    .open_directory_reader(&Cx::for_testing(), fixture.directory)
                    .is_err(),
                "{kind:?}: {fault}"
            );
            assert!(fixture.data_reads().is_empty());
        }
        let fixture = Fixture::new(kind, 512, 1, &[9, 3]);
        fixture.slot(0, &[0; 32]);
        fixture.fat(0, 3, 12);
        let volume = fixture.volume();
        assert!(
            volume
                .open_directory_reader(&Cx::for_testing(), fixture.directory)
                .is_err()
        );
        assert!(fixture.data_reads().is_empty());
    }
}

#[test]
fn full_roots_and_maximum_native_directory_storage_have_bounded_cursor_memory() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let chain: Vec<_> = if kind == FatKind::Fat32 {
            (2..4098).collect()
        } else {
            Vec::new()
        };
        let fixture = Fixture::new(kind, 512, 1, &chain);
        let slots = fixture.offsets.len() * fixture.unit / 32;
        for index in 0..slots {
            let name: [u8; 11] = format!("N{index:07}BIN").into_bytes().try_into().unwrap();
            fixture.slot(index, &short(&name));
        }
        let volume = fixture.volume();
        let cx = Cx::for_testing();
        let mut cursor = volume
            .open_directory_reader(&cx, fixture.directory)
            .unwrap();
        let capacity = cursor.bytes.capacity();
        let map_capacity = match &cursor.storage {
            Storage::Fixed { .. } => 0,
            Storage::Chain(clusters) => {
                assert_eq!(clusters.len(), chain.len());
                clusters.capacity()
            }
        };
        assert_eq!(cursor.bytes.len(), 512);
        assert!(chain.len() <= 4096);
        for index in 0..slots {
            let entry = cursor.next_entry(&cx).unwrap().unwrap();
            assert_eq!(entry.name().unwrap(), format!("N{index:07}.BIN"));
            assert_eq!(cursor.bytes.capacity(), capacity);
            if let Storage::Chain(clusters) = &cursor.storage {
                assert_eq!(clusters.capacity(), map_capacity);
            }
        }
        assert!(cursor.next_entry(&cx).unwrap().is_none());
        assert_eq!(cursor.slots, slots);
        assert_eq!(fixture.data_reads().len(), fixture.offsets.len());
    }
    let chain: Vec<_> = (2..4099).collect();
    let fixture = Fixture::new(FatKind::Fat32, 512, 1, &chain);
    fixture.slot(0, &[0; 32]);
    let volume = fixture.volume();
    assert!(matches!(
        volume.open_directory_reader(&Cx::for_testing(), fixture.directory),
        Err(FfsError::UnsupportedFeature(_))
    ));
    assert!(fixture.data_reads().is_empty());
}

#[test]
fn selected_active_fat_high_bits_and_volume_boundaries_are_preserved() {
    let fixture = Fixture::new(FatKind::Fat32, 4096, 16, &[9, 3]);
    for number in [0_u64, 6] {
        fixture
            .device
            .put(BASE + number * 4096 + 40, &0x0081_u16.to_le_bytes());
    }
    let inactive = fixture.geometry.entry_offset(0, 2).unwrap() - 8;
    fixture.device.put(BASE + inactive, &[0; 8]);
    fixture.fat(0, 9, 0);
    fixture.fat(0, 3, 0);
    fixture.fat(1, 9, 0xA000_0003);
    fixture.fat(1, 3, 0xBFFF_FFFF);
    fixture.slot(0, &short(b"ACTIVE  BIN"));
    fixture.slot(1, &[0; 32]);
    let before = fixture.device.state.lock().unwrap().pages.clone();
    let volume = fixture.volume();
    let cx = Cx::for_testing();
    assert_eq!(volume.list(&cx, Directory::Root).unwrap().len(), 1);
    let active = fixture.geometry.entry_offset(1, 2).unwrap() - 8;
    let state = fixture.device.state.lock().unwrap();
    assert_eq!(state.pages, before);
    for &(at, length) in &state.reads {
        assert!(at >= BASE && at + length as u64 <= BASE + fixture.geometry.volume_bytes());
        assert!(!(BASE + inactive..BASE + active).contains(&at));
        assert!(length <= 64 * 1024);
    }
}

#[test]
fn malformed_and_unrepresentable_long_names_keep_the_existing_native_decoder_policy() {
    let fixture = Fixture::new(FatKind::Fat32, 512, 1, &[9, 3]);
    let mut bad = long(
        &"must not steal this alias".encode_utf16().collect::<Vec<_>>(),
        b"SAFE    BIN",
    );
    bad[0][13] ^= 1;
    for (index, record) in bad.iter().enumerate() {
        fixture.slot(index, record);
    }
    let raw = [0xD800_u16, 0x0061];
    let start = 15;
    for (index, record) in long(&raw, b"RAW     BIN").iter().enumerate() {
        fixture.slot(start + index, record);
    }
    fixture.slot(start + 2, &[0; 32]);
    let volume = fixture.volume().with_oem_code_page(FatOemCodePage::Cp437);
    let cx = Cx::for_testing();
    let entries = volume.list(&cx, Directory::Root).unwrap();
    assert_eq!(entries.len(), 2);
    assert!(entries[0].native.long_name.is_none());
    assert_eq!(entries[0].name().unwrap(), "SAFE.BIN");
    assert_eq!(entries[1].native.long_name.as_deref(), Some(raw.as_slice()));
    assert_eq!(entries[1].short_alias().as_deref(), Some("RAW.BIN"));
    assert!(matches!(
        entries[1].name(),
        Err(FfsError::UnsupportedFeature(_))
    ));
    // Existing named lookup refuses unsupported sibling presentation; the new
    // native cursor must not quietly weaken that policy to return SAFE.BIN.
    assert!(volume.lookup(&cx, Directory::Root, "SAFE.BIN").is_err());
}

#[test]
fn public_catalog_and_nested_resolve_use_the_shared_native_scanner() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let root: &[u32] = if kind == FatKind::Fat16 { &[] } else { &[9, 3] };
        let fixture = Fixture::new(kind, 512, 1, root);
        let end = if kind == FatKind::Fat16 {
            0xFFFF
        } else {
            0x0FFF_FFFF
        };
        for copy in 0..2 {
            fixture.fat(copy, 40, end);
        }
        let mut child = short(b"DIRECTOR   ");
        child[11] = 0x10;
        child[26..28].copy_from_slice(&40_u16.to_le_bytes());
        fixture.slot(0, &child);
        fixture.slot(1, &[0; 32]);
        let nested = fixture.geometry.cluster_offset(40).unwrap();
        fixture.device.put(BASE + nested, &short(b"CHILD   BIN"));
        let volume = fixture.volume();
        let cx = Cx::for_testing();
        let entry = volume.resolve(&cx, "/director/child.bin").unwrap().unwrap();
        assert_eq!(entry.offset, nested);
        let report =
            crate::native_catalog(&cx, &volume, &crate::EntrySlots::default(), BASE).unwrap();
        assert_eq!(report["entries"].as_array().unwrap().len(), 1);
        assert_eq!(report["entries"][0]["name"], "DIRECTOR");
        let selector =
            crate::EntrySlots::parse(report["entries"][0]["entry_slots"].as_str().unwrap()).unwrap();
        let child_report = crate::native_catalog(&cx, &volume, &selector, BASE).unwrap();
        assert_eq!(child_report["entries"][0]["name"], "CHILD.BIN");
    }
}
