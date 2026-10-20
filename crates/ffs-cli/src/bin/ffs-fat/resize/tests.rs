//! Constructed native images and real-file CLI integration, not native-system
//! interchange qualification. Faults target the production publisher and view.

use super::*;
use crate::reader::Directory;
use clap::Parser as _;
use std::sync::Mutex;

const PAGE: usize = 4096;

#[derive(Default)]
struct Memory {
    pages: BTreeMap<u64, [u8; PAGE]>,
    writes: Vec<(u64, usize)>,
    syncs: usize,
    fail_write: Option<u64>,
    drop_write: Option<u64>,
    fail_read: Option<u64>,
    fail_sync: Option<usize>,
    cancel_write: Option<u64>,
}

impl Memory {
    fn read(&self, mut at: u64, mut bytes: &mut [u8]) {
        while !bytes.is_empty() {
            let within = at as usize % PAGE;
            let count = bytes.len().min(PAGE - within);
            if let Some(page) = self.pages.get(&(at / PAGE as u64)) {
                bytes[..count].copy_from_slice(&page[within..within + count]);
            } else { bytes[..count].fill(0); }
            at += count as u64;
            bytes = &mut bytes[count..];
        }
    }
    fn put(&mut self, mut at: u64, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let within = at as usize % PAGE;
            let count = bytes.len().min(PAGE - within);
            let key = at / PAGE as u64;
            if bytes[..count].iter().any(|byte| *byte != 0) || self.pages.contains_key(&key) {
                let page = self.pages.entry(key).or_insert([0; PAGE]);
                page[within..within + count].copy_from_slice(&bytes[..count]);
                if page.iter().all(|byte| *byte == 0) { self.pages.remove(&key); }
            }
            at += count as u64;
            bytes = &bytes[count..];
        }
    }
}

struct Device {
    memory: Mutex<Memory>,
    length: u64,
    writable: bool,
}

impl ByteDevice for Device {
    fn len_bytes(&self) -> u64 { self.length }
    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        assert!(at.0.checked_add(bytes.len() as u64).is_some_and(|end| end <= self.length));
        let state = self.memory.lock().unwrap();
        if state.fail_read.is_some_and(|bad| at.0 <= bad && bad < at.0 + bytes.len() as u64) {
            bytes.fill(0xEE);
            return Err(io::Error::other("injected resize read failure").into());
        }
        state.read(at.0, bytes);
        Ok(())
    }
    fn write_all_at(&self, cx: &Cx, at: ByteOffset, bytes: &[u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        assert!(self.writable, "resize must never write its source");
        assert!(at.0 + bytes.len() as u64 <= self.length);
        let mut state = self.memory.lock().unwrap();
        state.writes.push((at.0, bytes.len()));
        if state.fail_write == Some(at.0) {
            state.put(at.0, &bytes[..bytes.len().min(511)]);
            return Err(io::Error::other("injected torn resize write").into());
        }
        if state.drop_write != Some(at.0) { state.put(at.0, bytes); }
        if state.cancel_write == Some(at.0) {
            cx.set_cancel_requested(true);
            return Err(FfsError::Cancelled);
        }
        Ok(())
    }
    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        assert!(self.writable, "resize must never synchronize its source");
        let mut state = self.memory.lock().unwrap();
        state.syncs += 1;
        if state.fail_sync == Some(state.syncs) {
            return Err(io::Error::other("injected resize sync failure").into());
        }
        Ok(())
    }
}

fn device(length: u64, writable: bool) -> Arc<Device> {
    Arc::new(Device { memory: Mutex::new(Memory::default()), length, writable })
}

fn record(name: &[u8; 11], first: u32, size: u32, kind: FatKind) -> [u8; 32] {
    let mut entry = [0; 32];
    entry[..11].copy_from_slice(name);
    entry[11] = 0x27; // read-only, hidden, system and archive are retained.
    entry[13] = 157;
    for at in [16, 18, 24] { entry[at..at + 2].copy_from_slice(&0x21_u16.to_le_bytes()); }
    let high = if kind == FatKind::Fat32 { 0xA000 | (first >> 16) as u16 } else { 0x1234 };
    entry[20..22].copy_from_slice(&high.to_le_bytes());
    entry[26..28].copy_from_slice(&(first as u16).to_le_bytes());
    entry[28..32].copy_from_slice(&size.to_le_bytes());
    entry
}

fn fixture(kind: FatKind, sector: u32, active: bool) -> (Arc<Device>, Slice, FatGeometry) {
    let clusters = if kind == FatKind::Fat16 { 6000_u32 } else { 70_000 };
    let reserved = if kind == FatKind::Fat16 { 1_u32 } else { 32 };
    let width = kind.entry_bytes();
    let fats = ((clusters + 2) * width).div_ceil(sector);
    let roots = if kind == FatKind::Fat16 { (sector / 32).max(32) as u16 } else { 0 };
    let total = reserved + 2 * fats + (u32::from(roots) * 32).div_ceil(sector) + clusters;
    let length = u64::from(total) * u64::from(sector);
    let base = 1024;
    let source = device(base + length + 512, false);
    let mut boot = vec![0; sector as usize];
    boot[..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
    boot[3..11].copy_from_slice(b"MSWIN4.1");
    boot[11..13].copy_from_slice(&(sector as u16).to_le_bytes());
    boot[13] = 1;
    boot[14..16].copy_from_slice(&(reserved as u16).to_le_bytes());
    boot[16] = 2;
    boot[17..19].copy_from_slice(&roots.to_le_bytes());
    boot[21] = 0xF8;
    boot[28..32].copy_from_slice(&123_u32.to_le_bytes());
    boot[510..512].copy_from_slice(&[0x55, 0xAA]);
    if kind == FatKind::Fat16 {
        boot[19..21].copy_from_slice(&(total as u16).to_le_bytes());
        boot[22..24].copy_from_slice(&(fats as u16).to_le_bytes());
        boot[38] = 0x29;
        boot[39..43].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
    } else {
        boot[32..36].copy_from_slice(&total.to_le_bytes());
        boot[36..40].copy_from_slice(&fats.to_le_bytes());
        boot[40..42].copy_from_slice(&(if active { 0x81_u16 } else { 0 }).to_le_bytes());
        boot[44..48].copy_from_slice(&2_u32.to_le_bytes());
        boot[48..50].copy_from_slice(&1_u16.to_le_bytes());
        boot[50..52].copy_from_slice(&6_u16.to_le_bytes());
        boot[66] = 0x29;
        boot[67..71].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
    }
    let geometry = FatGeometry::parse(&boot, length).unwrap();
    {
        let mut state = source.memory.lock().unwrap();
        state.put(0, &[0xA7; 1024]);
        state.put(base + length, &[0xB9; 512]);
        state.put(base, &boot);
        if kind == FatKind::Fat32 {
            state.put(base + 6 * u64::from(sector), &boot);
            let mut info = vec![0; sector as usize];
            info[..4].copy_from_slice(&0x4161_5252_u32.to_le_bytes());
            info[484..488].copy_from_slice(&0x6141_7272_u32.to_le_bytes());
            info[488..496].fill(0xFF);
            info[508..512].copy_from_slice(&0xAA55_0000_u32.to_le_bytes());
            state.put(base + u64::from(sector), &info);
            state.put(base + 7 * u64::from(sector), &info);
        }
        let end = if kind == FatKind::Fat16 { 0xFFFF_u32 } else { 0x0FFF_FFFF };
        for copy in 0..2_u8 {
            let start = base + fat_start(&geometry, copy).unwrap();
            for cluster in 0..16_u32 {
                let low = match cluster {
                    0 => end & !7, 1 | 7 => end,
                    2 if kind == FatKind::Fat32 => end,
                    5 => 9, 9 => 6, 6 => 7,
                    _ => 0,
                };
                let raw = low | if kind == FatKind::Fat32 { (10 + u32::from(copy)) << 28 } else { 0 };
                state.put(start + u64::from(cluster * width), &raw.to_le_bytes()[..width as usize]);
            }
        }
        let root = geometry.fixed_root().map_or_else(|| geometry.cluster_offset(2).unwrap(), |(at, _)| at);
        let mut label = [0; 32];
        label[..11].copy_from_slice(b"NATIVEVOL  ");
        label[11] = 8;
        state.put(base + root, &label);
        state.put(base + root + 32, &record(b"KEEP    BIN", 5, 2 * sector + 11, kind));
        state.put(base + root + 64, &record(b"EMPTY   TXT", 0, 0, kind));
        for (cluster, byte) in [(5, 0x31), (9, 0x52), (6, 0x73), (7, 0x94), (8, 0xDE)] {
            state.put(base + geometry.cluster_offset(cluster).unwrap(), &vec![byte; sector as usize]);
        }
        if active {
            // The unselected copy is intentionally unusable, not an authority.
            state.put(base + geometry.entry_offset(0, 5).unwrap(), &0xF000_0001_u32.to_le_bytes());
        }
    }
    let inner: Arc<dyn ByteDevice> = source.clone();
    let slice = Slice { inner, base, length };
    (source, slice, geometry)
}

fn volume(cx: &Cx, inner: Arc<dyn ByteDevice>) -> FatVolume {
    let length = inner.len_bytes();
    FatVolume::from_device(cx, Box::new(Slice { inner, base: 0, length }), 0, length).unwrap()
}

fn read(device: &dyn ByteDevice, at: u64, count: usize) -> Vec<u8> {
    let mut bytes = vec![0; count];
    device.read_exact_at(&Cx::for_testing(), ByteOffset(at), &mut bytes).unwrap();
    bytes
}

#[test]
fn resize_view_grows_and_shrinks_both_dialects_without_native_identity_changes() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for sector in [512, 4096] {
            for active in [false, true] {
                if active && kind == FatKind::Fat16 { continue; }
                let (source, slice, old) = fixture(kind, sector, active);
                let source_before = source.memory.lock().unwrap().pages.clone();
                let original = volume(&cx, Arc::new(slice.clone()));
                let entries = original.list(&cx, Directory::Root).unwrap();
                let original_chain = original.file_chain(&cx, &entries[0]).unwrap();
                let payload = original.read(&cx, &original_chain, 0, 3 * sector).unwrap();
                for growing in [false, true] {
                    let delta = 500 * u64::from(sector);
                    let length = if growing { old.volume_bytes() + delta } else { old.volume_bytes() - delta };
                    let plan = Plan::prepare(&cx, slice.clone(), length, FatOemCodePage::Ascii).unwrap();
                    if sector == 512 { assert_ne!(plan.old_data, plan.new_data); }
                    assert_eq!(plan.new_data, plan.fat_start
                        + 2 * plan.new_fat_bytes + plan.new.fixed_root().map_or(0, |(_, bytes)| bytes));
                    let resized = volume(&cx, plan.clone());
                    let after = resized.list(&cx, Directory::Root).unwrap();
                    assert_eq!(after.len(), entries.len());
                    for (left, right) in entries.iter().zip(&after) { assert_eq!(left.native, right.native); }
                    let chain = resized.file_chain(&cx, &after[0]).unwrap();
                    assert_eq!(chain.clusters, [5, 9, 6, 7]);
                    assert_eq!(resized.read(&cx, &chain, 0, 3 * sector).unwrap(), payload);
                    assert_eq!(read(plan.as_ref(), plan.new.cluster_offset(7).unwrap(), sector as usize), vec![0x94; sector as usize]);
                    assert_eq!(read(plan.as_ref(), plan.new.cluster_offset(8).unwrap(), sector as usize), vec![0; sector as usize]);
                    assert_eq!(read(plan.as_ref(), 28, 4), [0; 4]);
                    for copy in 0..2_u8 {
                        assert_eq!(
                            read(plan.as_ref(), plan.new.entry_offset(copy, 5).unwrap(), kind.entry_bytes() as usize),
                            read(&slice, old.entry_offset(copy, 5).unwrap(), kind.entry_bytes() as usize),
                        );
                    }
                    if kind == FatKind::Fat32 {
                        for number in [1, 7] {
                            assert_eq!(read(plan.as_ref(), u64::from(number * sector) + 488, 4), (plan.free as u32).to_le_bytes());
                        }
                    }
                }
                let state = source.memory.lock().unwrap();
                assert_eq!(state.pages, source_before);
                assert!(state.writes.is_empty());
                assert_eq!(state.syncs, 0);
            }
        }
    }
}

#[test]
fn resize_refuses_live_tail_preallocation_bad_clusters_and_invalid_geometry() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for bad in [false, true] {
            let (source, slice, geometry) = fixture(kind, 512, false);
            let tail = geometry.cluster_count() + 1;
            let width = kind.entry_bytes() as usize;
            let end = if kind == FatKind::Fat16 { 0xFFFF_u32 } else { 0x0FFF_FFFF };
            {
                let mut state = source.memory.lock().unwrap();
                for copy in 0..2 {
                    let value = if bad { end - 8 } else { end };
                    state.put(slice.base + geometry.entry_offset(copy, tail).unwrap(), &value.to_le_bytes()[..width]);
                    if !bad {
                        state.put(slice.base + geometry.entry_offset(copy, 7).unwrap(), &tail.to_le_bytes()[..width]);
                    }
                }
            }
            assert!(checked(&cx, &volume(&cx, Arc::new(slice.clone()))).is_ok());
            let error = Plan::prepare(&cx, slice.clone(), geometry.volume_bytes() - 512 * 500, FatOemCodePage::Ascii).err().unwrap();
            assert!(error.to_string().contains("compaction is not performed"));
            for length in [0, 511, u64::MAX, 4096] {
                assert!(Plan::prepare(&cx, slice.clone(), length, FatOemCodePage::Ascii).is_err());
            }
            assert!(source.memory.lock().unwrap().writes.is_empty());
        }
    }
}

#[test]
fn resize_publication_verifies_all_bytes_before_primary_boot_and_can_reopen() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let (source, slice, old) = fixture(kind, 512, false);
        let plan = Plan::prepare(&cx, slice, old.volume_bytes() + 512 * 500, FatOemCodePage::Ascii).unwrap();
        let output = device(plan.len_bytes(), true);
        let digest = publish(&cx, &plan, output.clone(), || Ok(())).unwrap();
        assert_eq!(digest.len(), 64);
        let reopened = volume(&cx, output.clone());
        assert!(reopened.check(&cx).unwrap().clean);
        assert_eq!(reopened.geometry, plan.new);
        let state = output.memory.lock().unwrap();
        assert_eq!(state.writes.last(), Some(&(0, 512)));
        assert!(state.writes[..state.writes.len() - 1].iter().all(|(at, _)| *at >= 512));
        assert_eq!(state.syncs, 2);
        drop(state);
        assert!(source.memory.lock().unwrap().writes.is_empty());
        assert_eq!(source.memory.lock().unwrap().syncs, 0);
    }
}

#[test]
fn dropped_torn_failed_and_cancelled_output_cannot_publish_unverified_primary() {
    let (_source, slice, old) = fixture(FatKind::Fat16, 512, false);
    let cx = Cx::for_testing();
    let plan = Plan::prepare(&cx, slice, old.volume_bytes() + 512 * 500, FatOemCodePage::Ascii).unwrap();
    for fault in 0..6 {
        let output = device(plan.len_bytes(), true);
        {
            let mut state = output.memory.lock().unwrap();
            match fault {
                0 => state.drop_write = Some(512),
                1 => state.fail_write = Some(512),
                2 => state.fail_sync = Some(1),
                3 => state.fail_read = Some(512),
                4 => state.cancel_write = Some(512),
                _ => {}
            }
        }
        let request = Cx::for_testing();
        let result = publish(&request, &plan, output.clone(), || {
            if fault == 5 { bail!("source identity changed"); }
            Ok(())
        });
        assert!(result.is_err(), "fault {fault}");
        assert_eq!(read(output.as_ref(), 0, 512), vec![0; 512]);
        assert!(!output.memory.lock().unwrap().writes.iter().any(|(at, _)| *at == 0));
    }
}

#[test]
fn every_output_write_failure_retains_source_and_never_acknowledges_success() {
    let cx = Cx::for_testing();
    let (source, slice, old) = fixture(FatKind::Fat16, 512, false);
    let before = source.memory.lock().unwrap().pages.clone();
    let plan = Plan::prepare(&cx, slice, old.volume_bytes() + 512 * 500, FatOemCodePage::Ascii).unwrap();
    let probe = device(plan.len_bytes(), true);
    publish(&cx, &plan, probe.clone(), || Ok(())).unwrap();
    let writes = probe.memory.lock().unwrap().writes.clone();
    for (at, _) in writes {
        let output = device(plan.len_bytes(), true);
        output.memory.lock().unwrap().fail_write = Some(at);
        assert!(publish(&cx, &plan, output.clone(), || Ok(())).is_err());
        if at != 0 { assert_eq!(read(output.as_ref(), 0, 512), vec![0; 512]); }
        assert_eq!(source.memory.lock().unwrap().pages, before);
    }
    let output = device(plan.len_bytes(), true);
    output.memory.lock().unwrap().fail_sync = Some(2);
    assert!(publish(&cx, &plan, output.clone(), || Ok(())).is_err());
    // A failed final sync can leave a complete image; it is not a rollback.
    assert!(volume(&cx, output).check(&cx).unwrap().clean);
}

#[test]
fn resize_source_read_failure_and_cancelled_preflight_perform_no_source_io_mutation() {
    let cx = Cx::for_testing();
    let (source, slice, old) = fixture(FatKind::Fat16, 512, false);
    let plan = Plan::prepare(&cx, slice.clone(), old.volume_bytes() + 512 * 500, FatOemCodePage::Ascii).unwrap();
    source.memory.lock().unwrap().fail_read = Some(slice.base + old.cluster_offset(5).unwrap());
    let output = device(plan.len_bytes(), true);
    assert!(publish(&cx, &plan, output.clone(), || Ok(())).is_err());
    assert_eq!(read(output.as_ref(), 0, 512), vec![0; 512]);
    let cancelled = Cx::for_testing();
    cancelled.set_cancel_requested(true);
    assert!(Plan::prepare(&cancelled, slice, old.volume_bytes(), FatOemCodePage::Ascii).is_err());
    assert_eq!(source.memory.lock().unwrap().syncs, 0);
    assert!(source.memory.lock().unwrap().writes.is_empty());
}

#[test]
fn resize_rejects_unknown_backup_state_and_unbounded_view_ranges() {
    let cx = Cx::for_testing();
    let (source, slice, old) = fixture(FatKind::Fat32, 512, true);
    let plan = Plan::prepare(&cx, slice.clone(), old.volume_bytes() + 512 * 500, FatOemCodePage::Ascii).unwrap();
    let mut byte = [0];
    for offset in [plan.len_bytes(), u64::MAX] {
        assert!(plan.read_exact_at(&cx, ByteOffset(offset), &mut byte).is_err());
    }
    assert!(matches!(plan.write_all_at(&cx, ByteOffset(0), b"x"), Err(FfsError::ReadOnly)));
    assert!(matches!(plan.sync(&cx), Err(FfsError::ReadOnly)));
    source.memory.lock().unwrap().put(slice.base + 6 * 512 + 65, &[2]);
    assert!(Plan::prepare(&cx, slice, old.volume_bytes(), FatOemCodePage::Ascii).is_err());
    assert!(source.memory.lock().unwrap().writes.is_empty());
}

#[test]
fn resize_cli_is_create_only_dry_run_is_non_mutating_and_real_files_round_trip() {
    let cx = Cx::for_testing();
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.fat");
    let output = dir.path().join("grown.fat");
    let cli = crate::Cli::try_parse_from([
        "ffs-fat", "format", source.to_str().unwrap(), "--kind", "fat16", "--size-mib", "8",
    ]).unwrap();
    let crate::Command::Format { options } = cli.command else { panic!("format"); };
    crate::formatter::create(&cx, &options).unwrap();
    let image = ImageArgs {
        image: source.clone(), offset: 0, length: None, oem_code_page: FatOemCodePage::Ascii, sidecar: None,
    };
    {
        let volume = crate::reader::replacement::open_volume(&cx, &image, true).unwrap();
        crate::reader::replacement::mkdir_in_volume(&cx, &volume, "/Nested directory", 1_700_000_000, false).unwrap();
        crate::reader::replacement::create_in_volume(&cx, &volume, "/Nested directory/Mixed name.txt", b"native payload", 1_700_000_000, true).unwrap();
    }
    let original = fs::read(&source).unwrap();
    let cli = crate::Cli::try_parse_from([
        "ffs-fat", "resize", source.to_str().unwrap(), "--output", output.to_str().unwrap(),
        "--size-mib", "16", "--offline-image", "--dry-run",
    ]).unwrap();
    let crate::Command::Resize { mut options } = cli.command else { panic!("resize"); };
    assert_eq!(run(&cx, &options).unwrap()["dry_run"], true);
    assert!(!output.exists());
    assert_eq!(fs::read(&source).unwrap(), original);
    options.dry_run = false;
    let report = run(&cx, &options).unwrap();
    assert_eq!(report["source_modified"], false);
    assert_eq!(fs::metadata(&output).unwrap().len(), 16 * 1024 * 1024);
    assert_eq!(fs::metadata(&output).unwrap().mode() & 0o777, 0o600);
    let resized = FatVolume::open(&cx, &output, 0, None).unwrap();
    let file = resized.resolve(&cx, "/Nested directory/Mixed name.txt").unwrap().unwrap();
    assert_ne!(file.native.attributes & 1, 0);
    let chain = resized.file_chain(&cx, &file).unwrap();
    assert_eq!(resized.read(&cx, &chain, 0, 100).unwrap(), b"native payload");
    assert!(resized.check(&cx).unwrap().clean);
    assert_eq!(fs::read(&source).unwrap(), original);
    let output_before = fs::read(&output).unwrap();
    assert!(run(&cx, &options).is_err());
    assert_eq!(fs::read(&output).unwrap(), output_before);
    options.output = source.clone();
    assert!(run(&cx, &options).is_err());
    options.output = dir.path().join("alias.fat");
    std::os::unix::fs::symlink(&source, &options.output).unwrap();
    assert!(run(&cx, &options).is_err());
    options.image.sidecar = Some(dir.path().join("not-opened.ffs-rq"));
    assert!(run(&cx, &options).unwrap_err().to_string().contains("sidecars"));
    assert_eq!(fs::read(&source).unwrap(), original);
}

#[test]
fn resize_cli_requires_explicit_size_destination_and_offline_authority() {
    for args in [
        vec!["ffs-fat", "resize", "source.fat", "--output", "new.fat", "--size-mib", "16"],
        vec!["ffs-fat", "resize", "source.fat", "--size-mib", "16", "--offline-image"],
        vec!["ffs-fat", "resize", "source.fat", "--output", "new.fat", "--offline-image"],
    ] { assert!(crate::Cli::try_parse_from(args).is_err()); }
}

#[test]
fn resize_read_windows_match_independently_materialized_native_regions() {
    let cx = Cx::for_testing();
    let (_source, slice, old) = fixture(FatKind::Fat16, 512, false);
    let plan = Plan::prepare(&cx, slice.clone(), old.volume_bytes() + 512 * 500, FatOemCodePage::Ascii).unwrap();
    let mut expected = vec![0; plan.len_bytes() as usize];
    let reserved = fat_start(&old, 0).unwrap() as usize;
    expected[..reserved].copy_from_slice(&read(&slice, 0, reserved));
    let entries = (old.cluster_count() as usize + 2) * 2;
    for copy in 0..2 {
        let start = fat_start(&plan.new, copy).unwrap() as usize;
        expected[start..start + entries].copy_from_slice(&read(&slice, fat_start(&old, copy).unwrap(), entries));
    }
    let (root, length) = plan.new.fixed_root().unwrap();
    let old_root = old.fixed_root().unwrap().0;
    expected[root as usize..(root + length) as usize].copy_from_slice(&read(&slice, old_root, length as usize));
    for cluster in [5, 9, 6, 7] {
        let start = plan.new.cluster_offset(cluster).unwrap() as usize;
        expected[start..start + 512].copy_from_slice(&read(&slice, old.cluster_offset(cluster).unwrap(), 512));
    }
    expected[19..21].copy_from_slice(&((plan.len_bytes() / 512) as u16).to_le_bytes());
    expected[22..24].copy_from_slice(&(((plan.new.cluster_count() + 2) * 2).div_ceil(512) as u16).to_le_bytes());
    expected[28..36].fill(0);
    let mut points = vec![0, 19, 22, 28, 510, 512, root, root + length, plan.len_bytes()];
    points.extend((0..plan.len_bytes()).step_by(TRANSFER));
    points.extend([5, 8, 9].map(|cluster| plan.new.cluster_offset(cluster).unwrap()));
    for point in points {
        for start in point.saturating_sub(2)..=point.saturating_add(2).min(plan.len_bytes()) {
            for length in [0, 1, 7, 31, 511, 513, TRANSFER] {
                let length = length.min((plan.len_bytes() - start) as usize);
                assert_eq!(read(plan.as_ref(), start, length), expected[start as usize..start as usize + length]);
            }
        }
    }
}

#[test]
fn resize_preserves_raw_unpaired_utf16_names_without_host_path_conversion() {
    let cx = Cx::for_testing();
    let (source, slice, old) = fixture(FatKind::Fat32, 512, false);
    let root = old.cluster_offset(2).unwrap();
    let keep = read(&slice, root + 32, 32);
    let empty = read(&slice, root + 64, 32);
    let mut long = [0; 32];
    long[0] = 0x41;
    long[11] = 0x0F;
    long[13] = ffs_ondisk::fat::short_name_checksum(b"KEEP    BIN");
    for (index, at) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30].into_iter().enumerate() {
        let unit: u16 = match index { 0 => 0xD800, 1 => 0x0061, 2 => 0, _ => 0xFFFF };
        long[at..at + 2].copy_from_slice(&unit.to_le_bytes());
    }
    {
        let mut memory = source.memory.lock().unwrap();
        memory.put(slice.base + root + 32, &long);
        memory.put(slice.base + root + 64, &keep);
        memory.put(slice.base + root + 96, &empty);
    }
    let original = volume(&cx, Arc::new(slice.clone()));
    let entries = original.list(&cx, Directory::Root).unwrap();
    assert!(entries[0].name().is_err());
    let plan = Plan::prepare(&cx, slice, old.volume_bytes() + 512 * 500, FatOemCodePage::Ascii).unwrap();
    let output = volume(&cx, plan);
    let copied = output.list(&cx, Directory::Root).unwrap();
    assert_eq!(copied[0].native, entries[0].native);
    assert!(copied[0].name().is_err());
}

#[test]
fn resize_refuses_ambiguous_ownership_and_dirty_source_without_output_authority() {
    let cx = Cx::for_testing();
    for dirty in [false, true] {
        let (source, slice, old) = fixture(FatKind::Fat16, 512, false);
        {
            let mut state = source.memory.lock().unwrap();
            if dirty { state.put(slice.base + 37, &[1]); }
            else {
                let root = old.fixed_root().unwrap().0;
                state.put(slice.base + root + 64, &record(b"OTHER   BIN", 5, 512, FatKind::Fat16));
            }
        }
        assert!(Plan::prepare(&cx, slice, old.volume_bytes() + 512 * 500, FatOemCodePage::Ascii).is_err());
        assert!(source.memory.lock().unwrap().writes.is_empty());
        assert_eq!(source.memory.lock().unwrap().syncs, 0);
    }
}
