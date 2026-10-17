//! Deterministic sparse device with separate pending/durable state. A successful
//! sync persists all prior writes; a failed write/sync can lose pending bytes.
//! Torn-prefix cases test refusal while dirty, not hardware atomicity claims.

use super::*;
use ffs_ondisk::fat::{FatGeometry, FatTimestamp, short_name_checksum};
use std::collections::BTreeMap;
use std::io;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

type Pages = BTreeMap<u64, [u8; 512]>;
const NOW: u64 = 1_700_000_001;

#[derive(Default)]
struct State {
    durable: Pages,
    pending: Pages,
    operations: usize,
    fail: Option<usize>,
    tear: Option<usize>,
    written: Vec<(u64, usize)>,
}

impl State {
    fn read(&self, mut at: u64, mut bytes: &mut [u8]) {
        while !bytes.is_empty() {
            let page = at / 512;
            let within = (at % 512) as usize;
            let count = bytes.len().min(512 - within);
            if let Some(value) = self.pending.get(&page).or_else(|| self.durable.get(&page)) {
                bytes[..count].copy_from_slice(&value[within..within + count]);
            } else {
                bytes[..count].fill(0);
            }
            at += count as u64;
            bytes = &mut bytes[count..];
        }
    }

    fn put(&mut self, mut at: u64, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let page = at / 512;
            let within = (at % 512) as usize;
            let count = bytes.len().min(512 - within);
            let previous = self.durable.get(&page).copied().unwrap_or([0; 512]);
            let value = self.pending.entry(page).or_insert(previous);
            value[within..within + count].copy_from_slice(&bytes[..count]);
            at += count as u64;
            bytes = &bytes[count..];
        }
    }

    fn persist(&mut self) {
        self.durable.append(&mut self.pending);
    }

    fn crash(&self, retain_pending: bool) -> Self {
        let mut result = Self {
            durable: self.durable.clone(),
            ..Self::default()
        };
        if retain_pending {
            result.durable.extend(self.pending.clone());
        }
        result
    }
}

#[derive(Clone)]
struct Device {
    state: Arc<Mutex<State>>,
    length: u64,
    writable: bool,
}

impl ByteDevice for Device {
    fn len_bytes(&self) -> u64 {
        self.length
    }

    fn read_exact_at(
        &self,
        cx: &Cx,
        offset: ByteOffset,
        bytes: &mut [u8],
    ) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        if offset
            .0
            .checked_add(bytes.len() as u64)
            .is_none_or(|end| end > self.length)
        {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }
        self.state.lock().unwrap().read(offset.0, bytes);
        checkpoint(cx)
    }

    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, bytes: &[u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        if !self.writable {
            return Err(FfsError::ReadOnly);
        }
        assert!(offset.0 + bytes.len() as u64 <= self.length);
        let mut state = self.state.lock().unwrap();
        state.operations += 1;
        let fail = state.fail == Some(state.operations);
        let count = if fail {
            state.tear.unwrap_or(0).min(bytes.len())
        } else {
            bytes.len()
        };
        if count != 0 {
            state.put(offset.0, &bytes[..count]);
            state.written.push((offset.0, count));
        }
        if fail {
            return Err(io::Error::other("injected write failure").into());
        }
        Ok(())
    }

    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        if !self.writable {
            return Err(FfsError::ReadOnly);
        }
        let mut state = self.state.lock().unwrap();
        state.operations += 1;
        if state.fail == Some(state.operations) {
            return Err(io::Error::other("injected flush failure").into());
        }
        state.persist();
        Ok(())
    }
}

struct Input {
    bytes: Vec<u8>,
    fail_at: Option<u64>,
    flip_after: Option<usize>,
    reads: AtomicUsize,
    declared_length: Option<u64>,
}

impl Input {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            fail_at: None,
            flip_after: None,
            reads: AtomicUsize::new(0),
            declared_length: None,
        }
    }
}

impl ByteDevice for Input {
    fn len_bytes(&self) -> u64 {
        self.declared_length.unwrap_or(self.bytes.len() as u64)
    }

    fn read_exact_at(
        &self,
        cx: &Cx,
        offset: ByteOffset,
        bytes: &mut [u8],
    ) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        if self.fail_at == Some(offset.0) {
            return Err(FfsError::Cancelled);
        }
        let at = offset.0 as usize;
        bytes.copy_from_slice(&self.bytes[at..at + bytes.len()]);
        let count = self.reads.fetch_add(1, Ordering::SeqCst) + 1;
        if self.flip_after.is_some_and(|limit| count > limit) && !bytes.is_empty() {
            bytes[0] ^= 0x80;
        }
        Ok(())
    }

    fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _bytes: &[u8]) -> ffs_error::Result<()> {
        panic!("replacement must never write its source")
    }
    fn sync(&self, _cx: &Cx) -> ffs_error::Result<()> {
        panic!("source flush")
    }
}

struct Fixture {
    device: Device,
    base: u64,
    geometry: FatGeometry,
    target: u64,
    original: Vec<u8>,
}

impl Fixture {
    fn new(kind: FatKind, sector_bytes: u32, active_only: bool, long_name: bool) -> Self {
        let sector = u64::from(sector_bytes);
        let clusters = if kind == FatKind::Fat16 {
            5000_u32
        } else {
            70_000
        };
        let reserved = if kind == FatKind::Fat16 { 1_u32 } else { 32 };
        let fat_sectors =
            ((u64::from(clusters) + 2) * u64::from(kind.entry_bytes())).div_ceil(sector) as u32;
        let root_entries = if kind == FatKind::Fat16 {
            (sector_bytes / 32).max(32) as u16
        } else {
            0
        };
        let root_sectors = (u64::from(root_entries) * 32).div_ceil(sector) as u32;
        let total = reserved + 2 * fat_sectors + root_sectors + clusters;
        let mut boot = [0_u8; 512];
        boot[..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
        boot[3..11].copy_from_slice(b"MSWIN4.1");
        boot[11..13].copy_from_slice(&(sector_bytes as u16).to_le_bytes());
        boot[13] = 1;
        boot[14..16].copy_from_slice(&(reserved as u16).to_le_bytes());
        boot[16] = 2;
        boot[17..19].copy_from_slice(&root_entries.to_le_bytes());
        boot[21] = 0xF8;
        boot[510..512].copy_from_slice(&[0x55, 0xAA]);
        if kind == FatKind::Fat16 {
            boot[19..21].copy_from_slice(&(total as u16).to_le_bytes());
            boot[22..24].copy_from_slice(&(fat_sectors as u16).to_le_bytes());
            boot[38] = 0x29;
            boot[54..62].copy_from_slice(b"FAT16   ");
        } else {
            boot[32..36].copy_from_slice(&total.to_le_bytes());
            boot[36..40].copy_from_slice(&fat_sectors.to_le_bytes());
            if active_only {
                boot[40..42].copy_from_slice(&0x0081_u16.to_le_bytes());
            }
            boot[44..48].copy_from_slice(&2_u32.to_le_bytes());
            boot[48..50].copy_from_slice(&1_u16.to_le_bytes());
            boot[50..52].copy_from_slice(&6_u16.to_le_bytes());
            boot[66] = 0x29;
            boot[82..90].copy_from_slice(b"FAT32   ");
        }
        let length = u64::from(total) * sector;
        let geometry = FatGeometry::parse(&boot, length).unwrap();
        assert_eq!(geometry.cluster_count(), clusters);
        let base = 1024;
        let mut state = State::default();
        state.put(0, &[0xA7; 512]);
        state.put(base + length, &[0xB9; 512]);
        state.put(base, &boot);
        if kind == FatKind::Fat32 {
            state.put(base + 6 * sector, &boot);
            let mut info = [0; 512];
            info[..4].copy_from_slice(&0x4161_5252_u32.to_le_bytes());
            info[484..488].copy_from_slice(&0x6141_7272_u32.to_le_bytes());
            info[488..496].fill(0xFF);
            info[508..512].copy_from_slice(&0xAA55_0000_u32.to_le_bytes());
            state.put(base + sector, &info);
        }
        let end = if kind == FatKind::Fat16 {
            0xFFFF
        } else {
            0x0FFF_FFFF
        };
        for copy in 0..2 {
            let start = base + u64::from(reserved + copy * fat_sectors) * sector;
            for cluster in 0_u32..=16 {
                let low = match cluster {
                    0 => end & !7,
                    1 | 6 | 7 => end,
                    2 if kind == FatKind::Fat32 => end,
                    5 => 9,
                    9 => 7,
                    _ => 0,
                };
                let raw = if kind == FatKind::Fat32 {
                    ((10 + copy) << 28) | low
                } else {
                    low
                };
                let width = kind.entry_bytes() as usize;
                state.put(
                    start + u64::from(cluster) * width as u64,
                    &raw.to_le_bytes()[..width],
                );
            }
        }
        let root = base
            + geometry
                .fixed_root()
                .map_or_else(|| geometry.cluster_offset(2).unwrap(), |(at, _)| at);
        let target = root + if long_name { 32 } else { 0 };
        if long_name {
            let mut record = [0_u8; 32];
            record[0] = 0x41;
            record[11] = 0x0F;
            record[13] = short_name_checksum(b"HELLO   TXT");
            let units: Vec<u16> = "Long name.txt".encode_utf16().collect();
            for (index, at) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
                .into_iter()
                .enumerate()
            {
                record[at..at + 2].copy_from_slice(&units[index].to_le_bytes());
            }
            state.put(root, &record);
        }
        let size = sector_bytes * 2 + 5;
        for (offset, name, cluster, size) in [
            (target, b"HELLO   TXT", 5_u32, size),
            (target + 32, b"KEEP    BIN", 6, 4),
            (target + 64, b"EMPTY   TXT", 0, 0),
        ] {
            let mut record = [0_u8; 32];
            record[..11].copy_from_slice(name);
            record[11] = 0x20;
            record[13] = 37;
            record[14..16].copy_from_slice(&0x1234_u16.to_le_bytes());
            record[16..18].copy_from_slice(&0x5421_u16.to_le_bytes());
            record[18..20].copy_from_slice(&0x5422_u16.to_le_bytes());
            record[20..22].copy_from_slice(
                &if kind == FatKind::Fat16 {
                    0xABCD_u16
                } else {
                    0xA000
                }
                .to_le_bytes(),
            );
            record[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
            record[28..32].copy_from_slice(&size.to_le_bytes());
            state.put(offset, &record);
        }
        let mut original = Vec::new();
        original.extend(vec![b'A'; sector_bytes as usize]);
        original.extend(vec![b'B'; sector_bytes as usize]);
        original.extend_from_slice(b"CCCCC");
        for (cluster, byte) in [(5, b'A'), (9, b'B'), (7, b'C')] {
            state.put(
                base + geometry.cluster_offset(cluster).unwrap(),
                &vec![byte; sector_bytes as usize],
            );
        }
        state.put(base + geometry.cluster_offset(6).unwrap(), b"SAFE");
        state.persist();
        Self {
            device: Device {
                state: Arc::new(Mutex::new(state)),
                length: base + length + 512,
                writable: true,
            },
            base,
            geometry,
            target,
            original,
        }
    }

    fn volume(&self) -> FatVolume {
        FatVolume::from_device(
            &Cx::for_testing(),
            Box::new(self.device.clone()),
            self.base,
            self.geometry.volume_bytes(),
        )
        .unwrap()
    }

    fn read(&self, at: u64, count: usize) -> Vec<u8> {
        let mut bytes = vec![0; count];
        self.device.state.lock().unwrap().read(at, &mut bytes);
        bytes
    }

    fn assert_guards(&self) {
        assert_eq!(self.read(0, 512), [0xA7; 512]);
        assert_eq!(
            self.read(self.base + self.geometry.volume_bytes(), 512),
            [0xB9; 512]
        );
        assert_eq!(
            self.read(self.base + self.geometry.cluster_offset(6).unwrap(), 4),
            b"SAFE"
        );
        for &(at, count) in &self.device.state.lock().unwrap().written {
            assert!(
                at >= self.base && at + count as u64 <= self.base + self.geometry.volume_bytes()
            );
        }
    }
}

fn contents(volume: &FatVolume, name: &str) -> Vec<u8> {
    let cx = Cx::for_testing();
    let entry = volume.resolve(&cx, name).unwrap().unwrap();
    let chain = volume.file_chain(&cx, &entry).unwrap();
    volume.read(&cx, &chain, 0, 128 * 1024).unwrap()
}

#[test]
fn native_replacement_grows_shrinks_and_empties_both_dialects_without_changing_names_or_other_files()
 {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for sector in [512, 4096] {
            let image = Fixture::new(kind, sector, false, true);
            let volume = image.volume();
            assert!(volume.check(&cx).unwrap().clean);
            let preserved = image.read(image.target, 22);
            for length in [sector as usize * 4 + 31, 17, 0, 513] {
                let source = Input::new((0..length).map(|at| (at % 251) as u8).collect());
                let plan =
                    Replacement::prepare(&cx, &volume, "/Long name.txt", &source, NOW).unwrap();
                let old_clusters: Vec<_> =
                    plan.release.iter().map(|&(cluster, _)| cluster).collect();
                let report = plan.execute(&cx, &volume, &source, || Ok(())).unwrap();
                assert_eq!(report["new_bytes"], length);
                let reopened = image.volume();
                assert_eq!(contents(&reopened, "/Long name.txt"), source.bytes);
                assert_eq!(contents(&reopened, "/HELLO.TXT"), source.bytes);
                assert_eq!(contents(&reopened, "/KEEP.BIN"), b"SAFE");
                let actual = image.read(image.target, 22);
                assert_eq!(&actual[..20], &preserved[..20]);
                assert_eq!(&actual[20..22], &preserved[20..22]);
                let mut table = FatTable::new(&reopened);
                for cluster in old_clusters {
                    assert_eq!(table.entry(&cx, cluster).unwrap(), FatEntry::Free);
                }
                if let Some(&last) = plan.clusters.last() {
                    let tail = length % sector as usize;
                    if tail != 0 {
                        assert_eq!(
                            image.read(
                                image.base
                                    + image.geometry.cluster_offset(last).unwrap()
                                    + tail as u64,
                                sector as usize - tail
                            ),
                            vec![0; sector as usize - tail]
                        );
                    }
                }
                assert!(reopened.check(&cx).unwrap().clean);
                image.assert_guards();
            }
            let source = Input::new(b"first contents".to_vec());
            let plan = Replacement::prepare(&cx, &volume, "/EMPTY.TXT", &source, NOW).unwrap();
            assert_eq!(plan.release, [] as [(u32, u32); 0]);
            plan.execute(&cx, &volume, &source, || Ok(())).unwrap();
            assert_eq!(contents(&image.volume(), "/EMPTY.TXT"), source.bytes);
        }
    }
}

#[test]
fn fat32_active_copy_and_each_reserved_high_nibble_are_preserved() {
    let cx = Cx::for_testing();
    for active in [false, true] {
        let image = Fixture::new(FatKind::Fat32, 512, active, false);
        let volume = image.volume();
        let inactive = image.base + image.geometry.entry_offset(0, 2).unwrap() - 8;
        let untouched = image.read(inactive, 512);
        let source = Input::new(vec![0xD5; 1300]);
        let plan = Replacement::prepare(&cx, &volume, "/HELLO.TXT", &source, NOW).unwrap();
        plan.execute(&cx, &volume, &source, || Ok(())).unwrap();
        for copy in volume.copies() {
            for cluster in 0_u32..=16 {
                let at = image.base + image.geometry.entry_offset(copy, 2).unwrap() - 8
                    + u64::from(cluster) * 4;
                let raw = u32::from_le_bytes(image.read(at, 4).try_into().unwrap());
                assert_eq!(raw >> 28, 10 + u32::from(copy));
            }
        }
        if active {
            assert_eq!(image.read(inactive, 512), untouched);
        }
        assert_eq!(contents(&image.volume(), "/HELLO.TXT"), source.bytes);
    }
}

#[test]
fn preflight_capacity_permissions_corruption_and_source_size_fail_without_writes() {
    let cx = Cx::for_testing();
    let image = Fixture::new(FatKind::Fat16, 512, false, false);
    let volume = image.volume();
    let source = Input::new(b"new contents".to_vec());
    assert!(Replacement::prepare(&cx, &volume, "/", &source, NOW).is_err());
    assert!(Replacement::prepare(&cx, &volume, "/missing", &source, NOW).is_err());
    let mut huge = Input::new(Vec::new());
    huge.declared_length = Some(u64::from(u32::MAX) + 1);
    assert!(Replacement::prepare(&cx, &volume, "/HELLO.TXT", &huge, NOW).is_err());
    huge.declared_length = Some(5000 * 512);
    assert!(Replacement::prepare(&cx, &volume, "/HELLO.TXT", &huge, NOW).is_err());
    image
        .device
        .state
        .lock()
        .unwrap()
        .put(image.target + 11, &[0x21]);
    assert!(Replacement::prepare(&cx, &volume, "/HELLO.TXT", &source, NOW).is_err());
    image
        .device
        .state
        .lock()
        .unwrap()
        .put(image.target + 11, &[0x20]);
    for copy in 0..2 {
        let at = image.base + image.geometry.entry_offset(copy, 6).unwrap();
        image
            .device
            .state
            .lock()
            .unwrap()
            .put(at, &5_u16.to_le_bytes());
    }
    assert!(Replacement::prepare(&cx, &volume, "/HELLO.TXT", &source, NOW).is_err());
    assert_eq!(image.device.state.lock().unwrap().operations, 0);
    assert_eq!(huge.reads.load(Ordering::SeqCst), 0);
}

#[test]
fn native_boot_dirty_and_surface_test_states_fail_before_mutation() {
    let cx = Cx::for_testing();
    let source = Input::new(b"new contents".to_vec());
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let state_at = if kind == FatKind::Fat16 { 37 } else { 65 };
        for state in [1, 2, 3] {
            for backup in [false, true] {
                if backup && kind == FatKind::Fat16 {
                    continue;
                }
                let image = Fixture::new(kind, 512, false, false);
                let volume = image.volume();
                let sector = if backup {
                    image.geometry.backup_boot_sector().unwrap()
                } else {
                    0
                };
                let at = image.base + u64::from(sector) * 512 + state_at;
                image.device.state.lock().unwrap().put(at, &[state]);
                assert!(Replacement::prepare(&cx, &volume, "/HELLO.TXT", &source, NOW).is_err());
                assert_eq!(image.device.state.lock().unwrap().operations, 0);
                assert_eq!(image.read(at, 1), [state]);
            }
        }
    }
    assert_eq!(source.reads.load(Ordering::SeqCst), 0);
}

#[test]
fn source_changes_cancellation_and_stale_entries_never_publish_a_new_file() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for failure in 0..4 {
            let cx = Cx::for_testing();
            let image = Fixture::new(kind, 512, false, false);
            let volume = image.volume();
            let mut source = Input::new(vec![0xD5; 1300]);
            let plan = Replacement::prepare(&cx, &volume, "/HELLO.TXT", &source, NOW).unwrap();
            let entry = image.read(image.target, 32);
            match failure {
                0 => source.flip_after = Some(source.reads.load(Ordering::SeqCst)),
                1 => source.fail_at = Some(512),
                2 => cx.cancel_with(CancelKind::User, Some("replacement test")),
                _ => image
                    .device
                    .state
                    .lock()
                    .unwrap()
                    .put(image.target + 13, &[99]),
            }
            assert!(plan.execute(&cx, &volume, &source, || Ok(())).is_err());
            if failure != 3 {
                assert_eq!(image.read(image.target, 32), entry);
            }
            if failure >= 2 {
                assert_eq!(image.device.state.lock().unwrap().operations, 0);
            }
            image.assert_guards();
        }
    }
}

#[test]
fn every_write_and_flush_failure_preserves_acknowledged_data_and_refuses_dirty_reopen() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let probe = Fixture::new(kind, 512, false, false);
        let volume = probe.volume();
        let source = Input::new(vec![0xD5; 1700]);
        let plan = Replacement::prepare(&cx, &volume, "/HELLO.TXT", &source, NOW).unwrap();
        plan.execute(&cx, &volume, &source, || Ok(())).unwrap();
        let operations = probe.device.state.lock().unwrap().operations;
        assert!(operations >= 15);
        for operation in 1..=operations {
            for tear in [None, Some(27), Some(66), Some(511)] {
                let image = Fixture::new(kind, 512, false, false);
                let volume = image.volume();
                let source = Input::new(vec![0xD5; 1700]);
                let plan = Replacement::prepare(&cx, &volume, "/HELLO.TXT", &source, NOW).unwrap();
                {
                    let mut state = image.device.state.lock().unwrap();
                    state.fail = Some(operation);
                    state.tear = tear;
                }
                assert!(
                    plan.execute(&cx, &volume, &source, || Ok(())).is_err(),
                    "{kind:?} operation {operation}"
                );
                for retain in [false, true] {
                    let state = image.device.state.lock().unwrap().crash(retain);
                    let device = Device {
                        state: Arc::new(Mutex::new(state)),
                        length: image.device.length,
                        writable: false,
                    };
                    let opened = FatVolume::from_device(
                        &cx,
                        Box::new(device.clone()),
                        image.base,
                        image.geometry.volume_bytes(),
                    );
                    match opened {
                        Ok(reopened) => {
                            assert!(reopened.check(&cx).unwrap().clean);
                            let bytes = contents(&reopened, "/HELLO.TXT");
                            assert!(
                                bytes == image.original || bytes == source.bytes,
                                "mixed clean contents at {operation}"
                            );
                            assert_eq!(contents(&reopened, "/KEEP.BIN"), b"SAFE");
                        }
                        Err(FfsError::UnsupportedFeature(reason)) => assert!(
                            reason.contains("dirty") || reason.contains("I/O errors"),
                            "{reason}"
                        ),
                        Err(other) => panic!("unexpected reopen error: {other}"),
                    }
                    let mut untouched = [0; 4];
                    device
                        .read_exact_at(
                            &cx,
                            ByteOffset(image.base + image.geometry.cluster_offset(6).unwrap()),
                            &mut untouched,
                        )
                        .unwrap();
                    assert_eq!(&untouched, b"SAFE");
                }
                image.assert_guards();
            }
        }
    }
}

#[test]
fn utc_modification_projection_covers_calendar_boundaries_without_touching_creation_time() {
    for seconds in [315_532_800, 951_868_799, 951_868_800, NOW, 4_354_819_199] {
        let (date, time) = modified_timestamp(seconds).unwrap();
        let timestamp = FatTimestamp::parse(date, time, 0).unwrap();
        assert_eq!(timestamp.utc_projection().as_secs(), seconds / 2 * 2);
    }
    for seconds in [0, 315_532_799, 4_354_819_200, u64::MAX] {
        assert!(modified_timestamp(seconds).is_err());
    }
}

#[test]
fn cli_requires_offline_ownership_and_preserves_explicit_selection() {
    use clap::Parser;
    let argv = [
        "ffs-fat",
        "replace",
        "image.img",
        "/HELLO.TXT",
        "--source",
        "new.bin",
        "--offset",
        "1024",
        "--length",
        "65536",
        "--oem-code-page",
        "850",
        "--offline-image",
        "--dry-run",
    ];
    let cli = crate::Cli::try_parse_from(argv).unwrap();
    let crate::Command::Replace { options } = cli.command else {
        panic!("replace command");
    };
    assert_eq!(options.image.offset, 1024);
    assert_eq!(options.image.length, Some(65_536));
    assert_eq!(
        options.image.oem_code_page,
        ffs_ondisk::fat::FatOemCodePage::Cp850
    );
    assert!(options.dry_run && options.offline_image);
    assert_eq!(options.path, "/HELLO.TXT");
    assert_eq!(options.source, PathBuf::from("new.bin"));
    assert!(
        crate::Cli::try_parse_from([
            "ffs-fat",
            "replace",
            "image.img",
            "/file",
            "--source",
            "new.bin"
        ])
        .is_err()
    );
}

#[test]
fn bd_nu8nf_fat_unlink_rmdir_rename_and_writable_fsops_contract() {
    use crate::filesystem::FatFs;
    use ffs_core::{FsOps, ReleaseRequest, RequestScope, SetAttrRequest};
    use ffs_types::InodeNumber;
    use std::ffi::OsStr;

    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let image = Fixture::new(kind, 512, false, true);
        let volume = image.volume();
        let fs = FatFs::new_with_mode(&cx, volume, 1000, 1000, true).unwrap();
        let root = InodeNumber(1);

        // 1. Create a file, write, partial-write, gap-write, truncate down & up.
        let created = fs
            .create(
                &cx,
                &mut scope,
                root,
                OsStr::new("created.txt"),
                0o644,
                1000,
                1000,
            )
            .unwrap();
        assert_eq!(created.size, 0);
        assert_eq!(created.perm, 0o644);
        assert_eq!(
            fs.write(&cx, &mut scope, created.ino, 0, b"hello world")
                .unwrap(),
            11
        );
        assert_eq!(
            fs.write(&cx, &mut scope, created.ino, 6, b"FAT!!").unwrap(),
            5
        );
        assert_eq!(
            fs.write(&cx, &mut scope, created.ino, 20, b"END").unwrap(),
            3
        );
        assert_eq!(
            fs.read(&cx, &mut scope, created.ino, 0, 64).unwrap(),
            b"hello FAT!!\0\0\0\0\0\0\0\0\0END"
        );
        let truncated = fs
            .setattr(
                &cx,
                &mut scope,
                created.ino,
                &SetAttrRequest {
                    size: Some(11),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(truncated.size, 11);
        assert_eq!(
            fs.read(&cx, &mut scope, created.ino, 0, 64).unwrap(),
            b"hello FAT!!"
        );
        let extended = fs
            .setattr(
                &cx,
                &mut scope,
                created.ino,
                &SetAttrRequest {
                    size: Some(16),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(extended.size, 16);
        assert_eq!(
            fs.read(&cx, &mut scope, created.ino, 0, 64).unwrap(),
            b"hello FAT!!\0\0\0\0\0"
        );
        let (truncate_fh, _) = fs
            .open(&cx, &mut scope, created.ino, libc::O_WRONLY | libc::O_TRUNC)
            .unwrap();
        assert_eq!(fs.getattr(&cx, &mut scope, created.ino).unwrap().size, 0);
        fs.release(
            &cx,
            &mut scope,
            ReleaseRequest {
                ino: created.ino,
                fh: truncate_fh,
                flags: libc::O_WRONLY | libc::O_TRUNC,
                lock_owner: None,
                flush: false,
            },
        )
        .unwrap();
        assert_eq!(
            fs.write(&cx, &mut scope, created.ino, 0, b"renamed payload")
                .unwrap(),
            15
        );

        // 2. Mkdir, cross-dir rename of file preserving ino, rmdir ENOTEMPTY, cross-dir rename of dir updating '..'.
        let dir = fs
            .mkdir(
                &cx,
                &mut scope,
                root,
                OsStr::new("work_dir"),
                0o755,
                1000,
                1000,
            )
            .unwrap();
        assert_eq!(dir.perm, 0o755);
        fs.rename(
            &cx,
            &mut scope,
            root,
            OsStr::new("created.txt"),
            dir.ino,
            OsStr::new("moved_long_name.txt"),
        )
        .unwrap();
        let moved = fs
            .lookup(&cx, &mut scope, dir.ino, OsStr::new("moved_long_name.txt"))
            .unwrap();
        assert_eq!(moved.ino, created.ino);
        assert_eq!(
            fs.read(&cx, &mut scope, moved.ino, 0, 64).unwrap(),
            b"renamed payload"
        );
        assert!(matches!(
            fs.rmdir(&cx, &mut scope, root, OsStr::new("work_dir")),
            Err(FfsError::NotEmpty)
        ));

        let child_dir = fs
            .mkdir(
                &cx,
                &mut scope,
                dir.ino,
                OsStr::new("nested_sub"),
                0o755,
                1000,
                1000,
            )
            .unwrap();
        assert_eq!(
            fs.lookup(&cx, &mut scope, child_dir.ino, OsStr::new(".."))
                .unwrap()
                .ino,
            dir.ino
        );
        fs.rename(
            &cx,
            &mut scope,
            dir.ino,
            OsStr::new("nested_sub"),
            root,
            OsStr::new("promoted_sub"),
        )
        .unwrap();
        let promoted = fs
            .lookup(&cx, &mut scope, root, OsStr::new("promoted_sub"))
            .unwrap();
        assert_eq!(promoted.ino, child_dir.ino);
        assert_eq!(
            fs.lookup(&cx, &mut scope, promoted.ino, OsStr::new(".."))
                .unwrap()
                .ino,
            root
        );

        // 3. Unlink LFN file and rmdir directories, then verify full volume check is clean.
        fs.unlink(&cx, &mut scope, dir.ino, OsStr::new("moved_long_name.txt"))
            .unwrap();
        assert!(matches!(
            fs.lookup(&cx, &mut scope, dir.ino, OsStr::new("moved_long_name.txt")),
            Err(FfsError::NotFound(_))
        ));
        fs.rmdir(&cx, &mut scope, root, OsStr::new("work_dir"))
            .unwrap();
        fs.rmdir(&cx, &mut scope, root, OsStr::new("promoted_sub"))
            .unwrap();
        fs.unlink(&cx, &mut scope, root, OsStr::new("Long name.txt"))
            .unwrap();
        fs.flush_on_destroy(&cx).unwrap();

        let reopened = image.volume();
        let report = reopened.check(&cx).unwrap();
        assert!(report.clean, "{kind:?}: {report:?}");
        assert!(report.complete);
        assert!(report.namespace_complete);
        assert_eq!(report.lost_clusters, Some(0));
        image.assert_guards();
    }
}
