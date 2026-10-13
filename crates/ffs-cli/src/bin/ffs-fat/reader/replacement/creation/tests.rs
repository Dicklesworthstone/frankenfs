//! Synthetic native-image and storage-fault controls, not native interchange proof.

use super::*;
use ffs_error::FfsError;
use ffs_ondisk::fat::{FatGeometry, short_name_checksum};
use ffs_types::ByteOffset;
use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Mutex};

const NOW: u64 = 1_700_000_001;
type Pages = BTreeMap<u64, [u8; 512]>;

#[derive(Default, Clone)]
struct State {
    durable: Pages,
    pending: Pages,
    operations: usize,
    fail: Option<usize>,
    tear: usize,
}

impl State {
    fn read(&self, offset: u64, output: &mut [u8]) {
        for (index, byte) in output.iter_mut().enumerate() {
            let at = offset + index as u64;
            *byte = self
                .pending
                .get(&(at / 512))
                .or_else(|| self.durable.get(&(at / 512)))
                .map_or(0, |page| page[(at % 512) as usize]);
        }
    }

    fn put(&mut self, offset: u64, input: &[u8]) {
        for (index, byte) in input.iter().copied().enumerate() {
            let at = offset + index as u64;
            let old = self.durable.get(&(at / 512)).copied().unwrap_or([0; 512]);
            self.pending.entry(at / 512).or_insert(old)[(at % 512) as usize] = byte;
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
        output: &mut [u8],
    ) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        if offset
            .0
            .checked_add(output.len() as u64)
            .is_none_or(|end| end > self.length)
        {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }
        self.state.lock().unwrap().read(offset.0, output);
        Ok(())
    }

    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, input: &[u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        assert!(self.writable, "source must never be written");
        assert!(offset.0 + input.len() as u64 <= self.length);
        let mut state = self.state.lock().unwrap();
        state.operations += 1;
        let failed = state.fail == Some(state.operations);
        let count = if failed {
            state.tear.min(input.len())
        } else {
            input.len()
        };
        state.put(offset.0, &input[..count]);
        if failed {
            return Err(io::Error::other("injected creation write failure").into());
        }
        Ok(())
    }

    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        assert!(self.writable, "source must never be synchronized");
        let mut state = self.state.lock().unwrap();
        state.operations += 1;
        if state.fail == Some(state.operations) {
            return Err(io::Error::other("injected creation sync failure").into());
        }
        state.persist();
        Ok(())
    }
}

fn source(bytes: &[u8]) -> Device {
    let mut state = State::default();
    state.put(0, bytes);
    state.persist();
    Device {
        state: Arc::new(Mutex::new(state)),
        length: bytes.len() as u64,
        writable: false,
    }
}

fn short_entry(name: &[u8; 11], cluster: u32, size: u32) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..11].copy_from_slice(name);
    bytes[11] = 0x20;
    for at in [16, 18, 24] {
        bytes[at..at + 2].copy_from_slice(&0x21_u16.to_le_bytes());
    }
    bytes[20..22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
    bytes[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
    bytes[28..32].copy_from_slice(&size.to_le_bytes());
    bytes
}

struct Image {
    device: Device,
    geometry: FatGeometry,
    base: u64,
    root: u64,
}

impl Image {
    fn new(kind: FatKind, sector: u32, active: bool) -> Self {
        let clusters = if kind == FatKind::Fat16 {
            5000_u32
        } else {
            70_000
        };
        let reserved = if kind == FatKind::Fat16 { 1_u32 } else { 32 };
        let fat = ((u64::from(clusters) + 2) * u64::from(kind.entry_bytes()))
            .div_ceil(u64::from(sector)) as u32;
        let roots = if kind == FatKind::Fat16 {
            (sector / 32).max(32) as u16
        } else {
            0
        };
        let total = reserved + 2 * fat + (u32::from(roots) * 32).div_ceil(sector) + clusters;
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
            boot[54..62].copy_from_slice(b"FAT16   ");
        } else {
            boot[32..36].copy_from_slice(&total.to_le_bytes());
            boot[36..40].copy_from_slice(&fat.to_le_bytes());
            boot[40..42].copy_from_slice(&(if active { 0x81_u16 } else { 0 }).to_le_bytes());
            boot[44..48].copy_from_slice(&2_u32.to_le_bytes());
            boot[48..50].copy_from_slice(&1_u16.to_le_bytes());
            boot[50..52].copy_from_slice(&6_u16.to_le_bytes());
            boot[66] = 0x29;
            boot[82..90].copy_from_slice(b"FAT32   ");
        }
        let length = u64::from(total) * u64::from(sector);
        let geometry = FatGeometry::parse(&boot, length).unwrap();
        let base = 1024;
        let mut state = State::default();
        state.put(0, &[0xA7; 512]);
        state.put(base + length, &[0xB9; 512]);
        state.put(base, &boot);
        if kind == FatKind::Fat32 {
            state.put(base + 6 * u64::from(sector), &boot);
            let mut info = [0; 512];
            info[..4].copy_from_slice(&0x4161_5252_u32.to_le_bytes());
            info[484..488].copy_from_slice(&0x6141_7272_u32.to_le_bytes());
            info[488..496].fill(0xFF);
            info[508..512].copy_from_slice(&0xAA55_0000_u32.to_le_bytes());
            state.put(base + u64::from(sector), &info);
        }
        let end = if kind == FatKind::Fat16 {
            0xFFFF_u32
        } else {
            0x0FFF_FFFF
        };
        let width = kind.entry_bytes() as usize;
        for copy in 0..2_u32 {
            let start = base + u64::from(reserved + copy * fat) * u64::from(sector);
            for cluster in 0..16_u32 {
                let low = match cluster {
                    0 => end & !7,
                    1 | 5 => end,
                    2 if kind == FatKind::Fat32 => end,
                    _ => 0,
                };
                let raw = low
                    | if kind == FatKind::Fat32 {
                        (10 + copy) << 28
                    } else {
                        0
                    };
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
        state.put(root, &short_entry(b"KEEP    BIN", 5, 4));
        // This looks like a live alias/cross-link, but is after the end marker.
        // Creating a new entry at root+32 must never resurrect it.
        state.put(root + 64, &short_entry(b"GHOST   BIN", 5, 4));
        state.put(base + geometry.cluster_offset(5).unwrap(), b"SAFE");
        state.persist();
        Self {
            device: Device {
                state: Arc::new(Mutex::new(state)),
                length: base + length + 512,
                writable: true,
            },
            geometry,
            base,
            root,
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

    fn bytes(&self, at: u64, count: usize) -> Vec<u8> {
        let mut bytes = vec![0; count];
        self.device.state.lock().unwrap().read(at, &mut bytes);
        bytes
    }

    fn guards(&self) {
        assert_eq!(self.bytes(0, 512), [0xA7; 512]);
        assert_eq!(
            self.bytes(self.base + self.geometry.volume_bytes(), 512),
            [0xB9; 512]
        );
        assert_eq!(
            self.bytes(self.base + self.geometry.cluster_offset(5).unwrap(), 4),
            b"SAFE"
        );
    }
}

fn contents(volume: &FatVolume, path: &str) -> Vec<u8> {
    let cx = Cx::for_testing();
    let entry = volume.resolve(&cx, path).unwrap().unwrap();
    let chain = volume.file_chain(&cx, &entry).unwrap();
    volume.read(&cx, &chain, 0, 16 * 1024).unwrap()
}

#[test]
fn creation_both_dialects_sectors_empty_files_and_active_fat_preserve_native_bytes() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for sector in [512, 4096] {
            for active in [false, true] {
                if active && kind == FatKind::Fat16 {
                    continue;
                }
                let image = Image::new(kind, sector, active);
                let volume = image.volume();
                assert!(volume.check(&cx).unwrap().clean);
                let keep = image.bytes(image.root, 32);
                let fat0 = image.base + image.geometry.entry_offset(0, 2).unwrap()
                    - 2 * u64::from(kind.entry_bytes());
                let previous = image.bytes(fat0, sector as usize);
                for (path, bytes) in [("/new.bin", vec![0xD5; 1300]), ("/EMPTY.TXT", Vec::new())] {
                    let input = source(&bytes);
                    let plan = prepare(&cx, &volume, path, &input, NOW).unwrap();
                    let dry_run = plan.report(&volume, true);
                    assert_eq!(dry_run["operation"], "create_new_file");
                    assert_eq!(dry_run["created_new_file"], false);
                    let report = plan.execute(&cx, &volume, &input, || Ok(())).unwrap();
                    assert_eq!(report["created_new_file"], true);
                    assert!(plan.release.is_empty());
                    let reopened = image.volume();
                    assert_eq!(contents(&reopened, path), bytes);
                    assert_eq!(contents(&reopened, "/KEEP.BIN"), b"SAFE");
                    assert!(matches!(
                        reopened.resolve(&cx, "/GHOST.BIN"),
                        Err(FfsError::NotFound(_))
                    ));
                    assert!(reopened.check(&cx).unwrap().clean);
                    assert_eq!(input.state.lock().unwrap().operations, 0);
                    if let Some(last) = plan.clusters.last() {
                        let tail = bytes.len() % sector as usize;
                        if tail != 0 {
                            assert_eq!(
                                image.bytes(
                                    image.base
                                        + image.geometry.cluster_offset(*last).unwrap()
                                        + tail as u64,
                                    sector as usize - tail
                                ),
                                vec![0; sector as usize - tail]
                            );
                        }
                    }
                }
                assert_eq!(image.bytes(image.root, 32), keep);
                assert_eq!(image.bytes(image.root + 32 + 12, 1), [24]);
                if active {
                    assert_eq!(image.bytes(fat0, sector as usize), previous);
                }
                image.guards();
            }
        }
    }
}

#[test]
fn deleted_slot_creation_preserves_live_successor_and_rejects_names_without_writes() {
    let cx = Cx::for_testing();
    let image = Image::new(FatKind::Fat16, 512, false);
    {
        let mut state = image.device.state.lock().unwrap();
        state.put(image.root, &[0xE5]);
        state.put(image.root + 32, &short_entry(b"KEEP    BIN", 5, 4));
        state.put(image.root + 64, &[0; 32]);
        state.persist();
    }
    let volume = image.volume();
    let input = source(b"payload");
    for path in [
        "/keep.bin",
        "/KEEP.BIN",
        "/CON",
        "/LPT1.TXT",
        "/TRAIL.",
        "/",
        "/../NEW.TXT",
        "/KEEP.BIN/NEW.TXT",
    ] {
        assert!(prepare(&cx, &volume, path, &input, NOW).is_err(), "{path}");
    }
    // LFN publication controls exercise these formerly unsupported names.
    for path in ["/Mixed.txt", "/long name.txt", "/é.txt", "/A.B.C"] {
        assert!(prepare(&cx, &volume, path, &input, NOW).is_ok(), "{path}");
    }
    assert_eq!(image.device.state.lock().unwrap().operations, 0);
    let plan = prepare(&cx, &volume, "/NEW.TXT", &input, NOW).unwrap();
    assert_eq!(plan.entry_offset, image.root - image.base);
    plan.execute(&cx, &volume, &input, || Ok(())).unwrap();
    assert_eq!(contents(&image.volume(), "/KEEP.BIN"), b"SAFE");
    assert_eq!(contents(&image.volume(), "/NEW.TXT"), b"payload");
    image.guards();
}

#[test]
fn creation_refuses_existing_long_name_and_native_short_alias() {
    let cx = Cx::for_testing();
    let image = Image::new(FatKind::Fat16, 512, false);
    let mut lfn = [0; 32];
    lfn[0] = 0x41;
    lfn[11] = 0x0F;
    lfn[13] = short_name_checksum(b"KEEP    BIN");
    let units: Vec<u16> = "OTHER.TXT"
        .encode_utf16()
        .chain(std::iter::once(0))
        .chain(std::iter::repeat(0xFFFF))
        .take(13)
        .collect();
    for (at, unit) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
        .into_iter()
        .zip(units)
    {
        lfn[at..at + 2].copy_from_slice(&unit.to_le_bytes());
    }
    {
        let mut state = image.device.state.lock().unwrap();
        state.put(image.root, &lfn);
        state.put(image.root + 32, &short_entry(b"KEEP    BIN", 5, 4));
        state.put(image.root + 64, &[0; 32]);
        state.persist();
    }
    let volume = image.volume();
    assert!(volume.check(&cx).unwrap().clean);
    for path in ["/OTHER.TXT", "/other.txt", "/KEEP.BIN"] {
        assert!(prepare(&cx, &volume, path, &source(b"new"), NOW).is_err());
    }
    assert_eq!(image.device.state.lock().unwrap().operations, 0);
}

#[test]
fn creation_stale_successor_size_overflow_cancellation_and_full_root_are_prewrite_errors() {
    let cx = Cx::for_testing();
    let image = Image::new(FatKind::Fat16, 512, false);
    let volume = image.volume();
    let mut input = source(b"new");
    input.length = u64::from(u32::MAX) + 1;
    assert!(prepare(&cx, &volume, "/NEW.BIN", &input, NOW).is_err());
    input.length = 3;
    let plan = prepare(&cx, &volume, "/NEW.BIN", &input, NOW).unwrap();
    image
        .device
        .state
        .lock()
        .unwrap()
        .put(image.root + 64 + 13, &[77]);
    assert!(plan.execute(&cx, &volume, &input, || Ok(())).is_err());
    assert_eq!(image.device.state.lock().unwrap().operations, 0);
    let cancelled = Cx::for_testing();
    cancelled.cancel_with(
        asupersync::types::CancelKind::User,
        Some("creation control"),
    );
    assert!(prepare(&cancelled, &volume, "/NEW.BIN", &input, NOW).is_err());
    let (_, length) = image.geometry.fixed_root().unwrap();
    {
        let mut state = image.device.state.lock().unwrap();
        for index in 1..length / 32 {
            let name = format!("F{index:07}TXT");
            state.put(
                image.root + index * 32,
                &short_entry(name.as_bytes().try_into().unwrap(), 0, 0),
            );
        }
        state.persist();
    }
    assert!(volume.check(&cx).unwrap().clean);
    assert!(prepare(&cx, &volume, "/NEW.BIN", &input, NOW).is_err());
    assert_eq!(image.device.state.lock().unwrap().operations, 0);
    image.guards();
}

#[test]
fn creation_every_write_and_sync_cut_has_no_clean_partial_file_or_resurrected_entry() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let probe = Image::new(kind, 512, false);
        let input = source(&vec![0xD5; 1300]);
        let volume = probe.volume();
        prepare(&cx, &volume, "/NEW.BIN", &input, NOW)
            .unwrap()
            .execute(&cx, &volume, &input, || Ok(()))
            .unwrap();
        let operations = probe.device.state.lock().unwrap().operations;
        assert!(operations >= 15);
        for fail in 1..=operations {
            for tear in [0, 27, 66, 511] {
                let image = Image::new(kind, 512, false);
                let volume = image.volume();
                let plan = prepare(&cx, &volume, "/NEW.BIN", &input, NOW).unwrap();
                {
                    let mut state = image.device.state.lock().unwrap();
                    state.fail = Some(fail);
                    state.tear = tear;
                }
                assert!(plan.execute(&cx, &volume, &input, || Ok(())).is_err());
                for retain in [false, true] {
                    let mut state = image.device.state.lock().unwrap().clone();
                    if retain {
                        state.persist();
                    } else {
                        state.pending.clear();
                    }
                    let device = Device {
                        state: Arc::new(Mutex::new(state)),
                        length: image.device.length,
                        writable: false,
                    };
                    match FatVolume::from_device(
                        &cx,
                        Box::new(device),
                        image.base,
                        image.geometry.volume_bytes(),
                    ) {
                        Ok(reopened) => {
                            assert!(
                                reopened.check(&cx).unwrap().clean,
                                "{kind:?} cut {fail} tear {tear}"
                            );
                            assert_eq!(contents(&reopened, "/KEEP.BIN"), b"SAFE");
                            match reopened.resolve(&cx, "/NEW.BIN") {
                                Ok(Some(_)) => {
                                    assert_eq!(contents(&reopened, "/NEW.BIN"), vec![0xD5; 1300])
                                }
                                Err(FfsError::NotFound(_)) => (),
                                other => panic!("unexpected created-file result: {other:?}"),
                            }
                            assert!(matches!(
                                reopened.resolve(&cx, "/GHOST.BIN"),
                                Err(FfsError::NotFound(_))
                            ));
                        }
                        Err(FfsError::UnsupportedFeature(reason)) => assert!(
                            reason.contains("dirty") || reason.contains("I/O errors"),
                            "{reason}"
                        ),
                        Err(error) => panic!("unexpected reopen error: {error}"),
                    }
                }
                image.guards();
            }
        }
    }
}

#[test]
fn cli_create_is_explicit_and_does_not_change_replace_default() {
    use clap::Parser;
    for create in [false, true] {
        let mut args = vec![
            "ffs-fat",
            "replace",
            "image.img",
            "/NEW.BIN",
            "--source",
            "source.bin",
            "--offline-image",
            "--dry-run",
        ];
        if create {
            args.push("--create");
        }
        let cli = crate::Cli::try_parse_from(args).unwrap();
        let crate::Command::Replace { options } = cli.command else {
            panic!("replace command");
        };
        assert_eq!(options.create, create);
        assert!(options.dry_run && options.offline_image);
    }
    assert!(
        crate::Cli::try_parse_from([
            "ffs-fat",
            "replace",
            "image.img",
            "/NEW.BIN",
            "--source",
            "source.bin",
            "--create"
        ])
        .is_err()
    );
}

mod growth;
mod long_names;
