//! Constructed native images and the real CLI/library resize path. These tests
//! do not stand in for dosfstools/mtools, Windows or kernel FUSE qualification.

use super::*;
use super::super::{Plan, ResizeArgs, publish, run};
use clap::Parser as _;
use crate::reader::{Directory, ImageArgs};
use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::Mutex;

const BASE: u64 = 4096;
const PAGE: usize = 4096;
const NOW: u64 = 1_700_000_000;

#[derive(Default)]
struct Memory {
    pages: BTreeMap<u64, [u8; PAGE]>,
    attempts: usize,
    fail: Option<usize>,
    drop_write: Option<usize>,
    fail_read: Option<Range<u64>>,
    max_read: usize,
}

impl Memory {
    fn read(&self, mut at: u64, mut out: &mut [u8]) {
        while !out.is_empty() {
            let page = at / PAGE as u64;
            let within = (at % PAGE as u64) as usize;
            let count = out.len().min(PAGE - within);
            if let Some(bytes) = self.pages.get(&page) {
                out[..count].copy_from_slice(&bytes[within..within + count]);
            } else {
                out[..count].fill(0);
            }
            at += count as u64;
            out = &mut out[count..];
        }
    }

    fn put(&mut self, mut at: u64, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let within = (at % PAGE as u64) as usize;
            let count = bytes.len().min(PAGE - within);
            self.pages.entry(at / PAGE as u64).or_insert([0; PAGE])
                [within..within + count].copy_from_slice(&bytes[..count]);
            at += count as u64;
            bytes = &bytes[count..];
        }
    }
}

#[derive(Clone)]
struct Device {
    memory: Arc<Mutex<Memory>>,
    length: u64,
    writable: bool,
}

impl Device {
    fn new(length: u64, writable: bool) -> Self {
        Self { memory: Arc::new(Mutex::new(Memory::default())), length, writable }
    }

    fn bytes(&self, at: u64, length: usize) -> Vec<u8> {
        let mut bytes = vec![0; length];
        self.memory.lock().unwrap().read(at, &mut bytes);
        bytes
    }
}

impl ByteDevice for Device {
    fn len_bytes(&self) -> u64 { self.length }

    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, out: &mut [u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        assert!(at.0.checked_add(out.len() as u64).is_some_and(|end| end <= self.length));
        let mut memory = self.memory.lock().unwrap();
        memory.max_read = memory.max_read.max(out.len());
        if memory.fail_read.as_ref().is_some_and(|range| at.0 < range.end && at.0 + out.len() as u64 > range.start) {
            return Err(std::io::Error::other("injected root-view source read failure").into());
        }
        memory.read(at.0, out);
        Ok(())
    }

    fn write_all_at(&self, cx: &Cx, at: ByteOffset, bytes: &[u8]) -> ffs_error::Result<()> {
        assert!(self.writable, "root expansion must not write its source");
        checkpoint(cx)?;
        assert!(at.0 + bytes.len() as u64 <= self.length);
        let mut memory = self.memory.lock().unwrap();
        memory.attempts += 1;
        if memory.fail == Some(memory.attempts) {
            memory.put(at.0, &bytes[..bytes.len().min(31)]);
            return Err(std::io::Error::other("injected root output write failure").into());
        }
        if memory.drop_write != Some(memory.attempts) {
            memory.put(at.0, bytes);
        }
        Ok(())
    }

    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        assert!(self.writable, "root expansion must not synchronize its source");
        checkpoint(cx)?;
        let mut memory = self.memory.lock().unwrap();
        memory.attempts += 1;
        if memory.fail == Some(memory.attempts) {
            return Err(std::io::Error::other("injected root output sync failure").into());
        }
        Ok(())
    }
}

fn record(name: &[u8; 11], first: u16, size: u32, directory: bool) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..11].copy_from_slice(name);
    bytes[11] = if directory { 0x10 } else { 0x26 };
    bytes[12] = 0x18;
    bytes[13] = 123;
    for at in [16, 18, 24] { bytes[at..at + 2].copy_from_slice(&0x21_u16.to_le_bytes()); }
    bytes[20..22].copy_from_slice(&0x1234_u16.to_le_bytes()); // Native EA word, not a FAT16 address.
    bytes[26..28].copy_from_slice(&first.to_le_bytes());
    bytes[28..32].copy_from_slice(&size.to_le_bytes());
    bytes
}

fn fixture(sector: u32, total: u32, live_tail: bool) -> (Device, Slice, FatGeometry, Vec<u8>) {
    let fat = (total * 2).div_ceil(sector);
    let first_data = 1 + 2 * fat + 1;
    let count = total - first_data;
    let root_entries = (sector / 32) as u16;
    let mut boot = vec![0; sector as usize];
    boot[..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    boot[3..11].copy_from_slice(b"MSDOS5.0");
    boot[11..13].copy_from_slice(&(sector as u16).to_le_bytes());
    boot[13] = 1;
    boot[14..16].copy_from_slice(&1_u16.to_le_bytes());
    boot[16] = 2;
    boot[17..19].copy_from_slice(&root_entries.to_le_bytes());
    boot[19..21].copy_from_slice(&u16::try_from(total).unwrap().to_le_bytes());
    boot[21] = 0xF8;
    boot[22..24].copy_from_slice(&(fat as u16).to_le_bytes());
    boot[36] = 0x80;
    boot[38] = 0x29;
    boot[39..43].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
    boot[43..54].copy_from_slice(b"ROOT TEST  ");
    boot[54..62].copy_from_slice(b"FAT16   ");
    boot[510..512].copy_from_slice(&[0x55, 0xAA]);
    boot[512..].fill(0x7A); // Preserve the rest of large logical boot sectors too.
    let length = u64::from(total) * u64::from(sector);
    let geometry = FatGeometry::parse(&boot, length).unwrap();
    assert_eq!(geometry.cluster_count(), count);
    let device = Device::new(length + 2 * BASE, false);
    let tail = if live_tail { count + 1 } else { 9 };
    let payload: Vec<u8> = (0..sector + 37).map(|i| (i % 251) as u8).collect();
    {
        let mut memory = device.memory.lock().unwrap();
        memory.put(0, &[0xA5; PAGE]);
        memory.put(BASE + length, &[0x5A; PAGE]);
        memory.put(BASE, &boot);
        for copy in 0..2 {
            let base = BASE + u64::from(1 + copy * fat) * u64::from(sector);
            for (cluster, value) in [(0, 0xFFF8), (1, 0xFFFF), (7, 4), (4, tail), (tail, 0xFFFF), (5, 0xFFFF), (6, 0xFFFF)] {
                memory.put(base + u64::from(cluster) * 2, &(value as u16).to_le_bytes());
            }
        }
        let root = BASE + geometry.fixed_root().unwrap().0;
        for index in 0..root_entries {
            let name: [u8; 11] = format!("N{index:07}BIN").as_bytes().try_into().unwrap();
            let (first, size) = match index { 0 => (7, payload.len() as u32), 1 => (5, 0), _ => (0, 0) };
            memory.put(root + u64::from(index) * 32, &record(&name, first, size, index == 1));
        }
        // Put a checksum-bound LFN at the very end of the completely full root.
        let alias: [u8; 11] = format!("N{:07}BIN", root_entries - 1).as_bytes().try_into().unwrap();
        let mut long = [0; 32];
        long[0] = 0x41;
        long[11] = 0x0F;
        long[13] = ffs_ondisk::fat::short_name_checksum(&alias);
        let units: Vec<_> = "Root name α".encode_utf16().collect();
        for (index, at) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30].into_iter().enumerate() {
            let value = units.get(index).copied().unwrap_or(if index == units.len() { 0 } else { 0xFFFF });
            long[at..at + 2].copy_from_slice(&value.to_le_bytes());
        }
        memory.put(root + u64::from(root_entries - 2) * 32, &long);
        let directory = BASE + geometry.cluster_offset(5).unwrap();
        memory.put(directory, &record(b".          ", 5, 0, true));
        memory.put(directory + 32, &record(b"..         ", 0, 0, true));
        memory.put(directory + 64, &record(b"CHILD   BIN", 6, 17, false));
        memory.put(BASE + geometry.cluster_offset(6).unwrap(), &[0xD3; 17]);
        for (index, cluster) in [7, 4, tail].into_iter().enumerate() {
            let mut bytes = vec![0xE7; sector as usize];
            let begin = index * sector as usize;
            let count = payload.len().saturating_sub(begin).min(bytes.len());
            if count != 0 { bytes[..count].copy_from_slice(&payload[begin..begin + count]); }
            memory.put(BASE + geometry.cluster_offset(cluster).unwrap(), &bytes);
        }
        // Physical bytes immediately following the old root are NOT new slots.
        memory.put(BASE + geometry.cluster_offset(2).unwrap(), &vec![0xCF; sector as usize]);
    }
    let source = Slice { inner: Arc::new(device.clone()), base: BASE, length };
    let volume = FatVolume::from_device(&Cx::for_testing(), Box::new(source.clone()), 0, length).unwrap();
    assert_eq!(checked(&Cx::for_testing(), &volume).unwrap().0.preallocated, 1);
    (device, source, geometry, payload)
}

fn file_bytes(volume: &FatVolume) -> Vec<u8> {
    let cx = Cx::for_testing();
    let entry = volume.resolve(&cx, "/N0000000.BIN").unwrap().unwrap();
    let chain = volume.file_chain(&cx, &entry).unwrap();
    volume.read(&cx, &chain, 0, chain.size as usize).unwrap()
}

#[test]
fn expanded_view_preserves_full_root_and_native_bytes_across_every_region_boundary() {
    for sector in [512, 4096] {
        let (device, source, geometry, payload) = fixture(sector, 8192, false);
        let baseline = device.memory.lock().unwrap().pages.clone();
        let entries = (sector / 32 * 4) as u16;
        let cx = Cx::for_testing();
        let (view, change) = prepare(&cx, source, entries, FatOemCodePage::Ascii).unwrap();
        let root_end = geometry.cluster_offset(2).unwrap();
        let extra = u64::from(sector) * 3;
        let mut expected = device.bytes(BASE, root_end as usize);
        expected.resize((root_end + extra) as usize, 0);
        expected.extend_from_slice(&device.bytes(BASE + root_end, (geometry.volume_bytes() - root_end) as usize));
        expected[17..19].copy_from_slice(&entries.to_le_bytes());
        expected[19..21].copy_from_slice(&8195_u16.to_le_bytes());
        expected[32..36].fill(0);
        device.memory.lock().unwrap().max_read = 0;
        for start in [0, 16, 31, 510, u64::from(sector) - 1, root_end - 33, root_end - 1, root_end, root_end + extra - 1, root_end + extra, view.length - 1, view.length] {
            for length in [0_usize, 1, 17, 64, 4097, TRANSFER + 31] {
                let length = length.min((view.length - start) as usize);
                let mut actual = vec![0xAA; length];
                view.read_exact_at(&cx, ByteOffset(start), &mut actual).unwrap();
                assert_eq!(actual, expected[start as usize..start as usize + length]);
            }
        }
        assert!(device.memory.lock().unwrap().max_read <= TRANSFER);
        assert_eq!(change.source_bytes, geometry.volume_bytes());
        assert_eq!(change.before, (sector / 32) as u16);
        assert_eq!(change.after, entries);
        let volume = FatVolume::from_device(&cx, Box::new(view.clone()), 0, view.length).unwrap();
        assert_eq!(file_bytes(&volume), payload);
        assert_eq!(checked(&cx, &volume).unwrap().0.preallocated, 1);
        assert_eq!(device.memory.lock().unwrap().pages, baseline);
    }
}

#[test]
fn expanded_root_composes_with_resize_and_native_creation_without_rebuilding_old_names() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("source.img");
    let output = directory.path().join("expanded.img");
    let (device, _, geometry, payload) = fixture(512, 8192, false);
    let original = device.bytes(0, device.length as usize);
    std::fs::write(&input, &original).unwrap();
    let mut args = options(&input, &output, geometry.volume_bytes(), 64, false);
    args.dry_run = true;
    let cx = Cx::for_testing();
    let report = run(&cx, &args).unwrap();
    assert!(!output.exists());
    assert_eq!(report["source_volume_bytes"], geometry.volume_bytes());
    assert_eq!(report["source_root_entries"], 16);
    assert_eq!(report["output_root_entries"], 64);
    assert_eq!(report["root_directory_expanded"], true);
    args.dry_run = false;
    assert_eq!(run(&cx, &args).unwrap()["source_modified"], false);
    assert_eq!(std::fs::read(&input).unwrap(), original);
    let image = ImageArgs { image: output, offset: 0, length: None, oem_code_page: FatOemCodePage::Ascii, sidecar: None };
    let volume = crate::reader::replacement::open_volume(&cx, &image, true).unwrap();
    assert_eq!(file_bytes(&volume), payload);
    let (start, length) = volume.geometry.fixed_root().unwrap();
    assert_eq!(length, 64 * 32);
    let output_bytes = std::fs::read(&image.image).unwrap();
    let root = &output_bytes[start as usize..(start + length) as usize];
    assert_eq!(&root[..512], &original[(BASE + geometry.fixed_root().unwrap().0) as usize..(BASE + geometry.fixed_root().unwrap().0 + 512) as usize]);
    assert!(root[512..].iter().all(|byte| *byte == 0));
    let names = volume.list(&cx, Directory::Root).unwrap().len();
    crate::reader::replacement::create_in_volume(&cx, &volume, "/NEW.BIN", b"new root capacity", NOW, false).unwrap();
    assert_eq!(volume.list(&cx, Directory::Root).unwrap().len(), names + 1);
    assert_eq!(file_bytes(&volume), payload);
    assert!(volume.check(&cx).unwrap().clean);
    assert_eq!(std::fs::read(&input).unwrap(), original);
    assert!(run(&cx, &args).is_err(), "existing output must never be overwritten");
}

fn options(input: &std::path::Path, output: &std::path::Path, length: u64, entries: u16, relocate: bool) -> ResizeArgs {
    let cli = crate::Cli::try_parse_from([
        "ffs-fat", "resize", input.to_str().unwrap(), "--output", output.to_str().unwrap(),
        "--size-mib", "4", "--offline-image", "--offset", "4096", "--length", &length.to_string(),
        "--root-entries", &entries.to_string(),
    ]).unwrap();
    let crate::Command::Resize { mut options } = cli.command else { panic!("expected resize"); };
    options.relocate = relocate;
    options
}

#[test]
fn same_size_root_growth_requires_explicit_relocation_for_live_tail_preallocation() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("source.img");
    let output = directory.path().join("expanded.img");
    let (device, _, geometry, payload) = fixture(512, 8192, true);
    let original = device.bytes(0, device.length as usize);
    std::fs::write(&input, &original).unwrap();
    let mut args = options(&input, &output, geometry.volume_bytes(), 64, false);
    let cx = Cx::for_testing();
    assert!(run(&cx, &args).is_err());
    assert!(!output.exists());
    args.relocate = true;
    let report = run(&cx, &args).unwrap();
    assert_eq!(report["relocated_clusters"], 1);
    assert_eq!(report["cluster_numbers_preserved"], false);
    assert_eq!(report["source_volume_bytes"], geometry.volume_bytes());
    let image = ImageArgs { image: output, offset: 0, length: None, oem_code_page: FatOemCodePage::Ascii, sidecar: None };
    let volume = image.open(&cx).unwrap();
    assert_eq!(file_bytes(&volume), payload);
    let entry = volume.resolve(&cx, "/N0000000.BIN").unwrap().unwrap();
    let chain = volume.file_chain(&cx, &entry).unwrap();
    assert_eq!(chain.clusters.len(), 3);
    assert_eq!(&chain.clusters[..2], &[7, 4]);
    assert_ne!(chain.clusters[2], geometry.cluster_count() + 1);
    assert_eq!(checked(&cx, &volume).unwrap().0.preallocated, 1);
    assert_eq!(std::fs::read(&input).unwrap(), original);
}

#[test]
fn invalid_root_requests_and_too_small_output_refuse_before_output_creation() {
    for sector in [512, 4096] {
        let (device, source, _, _) = fixture(sector, 8192, false);
        let baseline = device.memory.lock().unwrap().pages.clone();
        let cx = Cx::for_testing();
        for entries in [0, 1, (sector / 32 - 1) as u16, (sector / 32 + 1) as u16, u16::MAX] {
            assert!(prepare(&cx, source.clone(), entries, FatOemCodePage::Ascii).is_err());
        }
        assert_eq!(device.memory.lock().unwrap().pages, baseline);
        assert_eq!(device.memory.lock().unwrap().attempts, 0);
    }
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("source.img");
    let output = directory.path().join("invalid.img");
    let (device, _, geometry, _) = fixture(512, 8192, false);
    let original = device.bytes(0, device.length as usize);
    std::fs::write(&input, &original).unwrap();
    let args = options(&input, &output, geometry.volume_bytes(), 65_520, true);
    assert!(run(&Cx::for_testing(), &args).is_err(), "large root must not turn FAT16 into FAT12");
    assert!(!output.exists());
    assert_eq!(std::fs::read(&input).unwrap(), original);
    assert!(crate::Cli::try_parse_from(["ffs-fat", "resize", "image", "--output", "out", "--size-mib", "4", "--offline-image", "--root-entries", "65536"]).is_err());
}

#[test]
fn source_damage_cannot_be_hidden_by_new_directory_end_markers() {
    for damage in 0..4 {
        let (device, source, geometry, _) = fixture(512, 8192, false);
        {
            let mut memory = device.memory.lock().unwrap();
            match damage {
                0 => memory.put(BASE + 37, &[1]),
                1 => memory.put(BASE + geometry.entry_offset(1, 7).unwrap(), &0xFFFF_u16.to_le_bytes()),
                2 => {
                    let root = BASE + geometry.fixed_root().unwrap().0;
                    memory.put(root + 2 * 32 + 26, &7_u16.to_le_bytes()); // A second owner.
                }
                _ => {
                    let root = BASE + geometry.fixed_root().unwrap().0;
                    memory.put(root + 512 - 32 + 11, &[0x0F]); // Trailing unbound LFN.
                }
            }
        }
        let baseline = device.memory.lock().unwrap().pages.clone();
        assert!(prepare(&Cx::for_testing(), source, 64, FatOemCodePage::Ascii).is_err());
        assert_eq!(device.memory.lock().unwrap().pages, baseline);
        assert_eq!(device.memory.lock().unwrap().attempts, 0);
    }
}

#[test]
fn projection_enforces_read_only_authority_ranges_cancellation_and_source_errors() {
    let (device, source, geometry, _) = fixture(512, 8192, false);
    let cx = Cx::for_testing();
    let (view, _) = prepare(&cx, source.clone(), 64, FatOemCodePage::Ascii).unwrap();
    let mut bytes = [0xA5; 16];
    assert!(view.read_exact_at(&cx, ByteOffset(u64::MAX), &mut bytes).is_err());
    assert!(view.read_exact_at(&cx, ByteOffset(view.length - 1), &mut bytes).is_err());
    assert_eq!(bytes, [0xA5; 16]);
    assert!(matches!(view.write_all_at(&cx, ByteOffset(0), &bytes), Err(FfsError::ReadOnly)));
    assert!(matches!(view.sync(&cx), Err(FfsError::ReadOnly)));
    let cancelled = Cx::for_testing();
    cancelled.set_cancel_requested(true);
    assert!(prepare(&cancelled, source, 64, FatOemCodePage::Ascii).is_err());
    assert!(matches!(view.read_exact_at(&cancelled, ByteOffset(0), &mut bytes), Err(FfsError::Cancelled)));
    let old_data = geometry.cluster_offset(2).unwrap();
    device.memory.lock().unwrap().fail_read = Some(BASE + old_data..BASE + old_data + 512);
    assert!(view.read_exact_at(&cx, ByteOffset(old_data + 1536), &mut bytes).is_err());
    view.read_exact_at(&cx, ByteOffset(old_data), &mut bytes).unwrap();
    assert_eq!(bytes, [0; 16], "new slots are zeros, not reads from neighboring allocation");
    device.memory.lock().unwrap().fail_read = Some(BASE..BASE + 512);
    assert!(view.read_exact_at(&cx, ByteOffset(0), &mut bytes).is_err());
    assert_eq!(device.memory.lock().unwrap().attempts, 0);
}

#[test]
fn publication_failures_never_mutate_source_or_acknowledge_a_dropped_root() {
    let (device, source, geometry, _) = fixture(512, 8192, false);
    let baseline = device.memory.lock().unwrap().pages.clone();
    let cx = Cx::for_testing();
    let (source, _) = prepare(&cx, source, 64, FatOemCodePage::Ascii).unwrap();
    let plan = Plan::prepare(&cx, source, geometry.volume_bytes(), FatOemCodePage::Ascii).unwrap();
    let probe = Device::new(plan.len_bytes(), true);
    publish(&cx, &plan, Arc::new(probe.clone()), || Ok(())).unwrap();
    let operations = probe.memory.lock().unwrap().attempts;
    for cut in 1..=operations {
        let output = Device::new(plan.len_bytes(), true);
        output.memory.lock().unwrap().fail = Some(cut);
        assert!(publish(&cx, &plan, Arc::new(output.clone()), || Ok(())).is_err(), "cut {cut}");
        assert_eq!(output.memory.lock().unwrap().attempts, cut);
        assert_eq!(device.memory.lock().unwrap().pages, baseline);
    }
    let output = Device::new(plan.len_bytes(), true);
    output.memory.lock().unwrap().drop_write = Some(1); // FATs/root lie in the first body transfer.
    assert!(publish(&cx, &plan, Arc::new(output.clone()), || Ok(())).is_err());
    assert_eq!(output.bytes(0, 512), vec![0; 512]);
    assert_eq!(device.memory.lock().unwrap().pages, baseline);
}

#[test]
fn equal_capacity_is_a_read_only_noop_and_large_root_handles_total_sector_field_transition() {
    for total in [8192, 65_520] {
        let (device, source, geometry, payload) = fixture(512, total, false);
        let baseline = device.memory.lock().unwrap().pages.clone();
        let cx = Cx::for_testing();
        let (same, change) = prepare(&cx, source.clone(), 16, FatOemCodePage::Ascii).unwrap();
        assert_eq!(change.before, change.after);
        assert_eq!(same.length, geometry.volume_bytes());
        let (large, _) = prepare(&cx, source, 1024, FatOemCodePage::Ascii).unwrap();
        let mut boot = [0; 512];
        large.read_exact_at(&cx, ByteOffset(0), &mut boot).unwrap();
        let expected = total + 63;
        if expected > u32::from(u16::MAX) {
            assert_eq!(&boot[19..21], &[0; 2]);
            assert_eq!(u32::from_le_bytes(boot[32..36].try_into().unwrap()), expected);
        } else {
            assert_eq!(u16::from_le_bytes(boot[19..21].try_into().unwrap()), expected as u16);
            assert_eq!(&boot[32..36], &[0; 4]);
        }
        let volume = FatVolume::from_device(&cx, Box::new(large.clone()), 0, large.length).unwrap();
        assert_eq!(volume.geometry.cluster_count(), geometry.cluster_count());
        assert_eq!(file_bytes(&volume), payload);
        assert_eq!(device.memory.lock().unwrap().pages, baseline);
    }
}

#[test]
fn fat32_root_option_is_refused_without_changing_the_existing_resize_profile() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("fat32.img");
    let cli = crate::Cli::try_parse_from(["ffs-fat", "format", input.to_str().unwrap(), "--kind", "fat32", "--size-mib", "64"]).unwrap();
    let crate::Command::Format { options } = cli.command else { panic!("expected format"); };
    let cx = Cx::for_testing();
    crate::formatter::create(&cx, &options).unwrap();
    let output = directory.path().join("out.img");
    let cli = crate::Cli::try_parse_from(["ffs-fat", "resize", input.to_str().unwrap(), "--output", output.to_str().unwrap(), "--size-mib", "64", "--offline-image", "--root-entries", "512", "--dry-run"]).unwrap();
    let crate::Command::Resize { mut options } = cli.command else { panic!("expected resize"); };
    let before = std::fs::read(&input).unwrap();
    assert!(run(&cx, &options).unwrap_err().to_string().contains("only to FAT16"));
    assert!(!output.exists());
    options.root_entries = None;
    assert_eq!(run(&cx, &options).unwrap()["format"], "Fat32");
    assert!(!output.exists());
    assert_eq!(std::fs::read(&input).unwrap(), before);
}
