use super::*;
use super::super::{rename_in_volume, run_rename};
use super::super::super::super::{create_in_volume, mkdir_in_volume, open_volume};
use clap::Parser as _;
use ffs_block::ByteDevice;
use ffs_error::FfsError;
use ffs_ondisk::fat::{FatGeometry, FatOemCodePage};
use ffs_types::ByteOffset;
use std::sync::{Arc, Mutex};

const NOW: u64 = 1_700_000_000;
const PAYLOAD: &[u8] = b"native payload must survive every spelling transition";

fn fixture(kind: &str) -> (tempfile::TempDir, crate::reader::ImageArgs, FatVolume) {
    let directory = tempfile::tempdir().unwrap();
    let image = directory.path().join("rename.fat");
    let cli = crate::Cli::try_parse_from([
        "ffs-fat", "format", image.to_str().unwrap(), "--kind", kind,
        "--size-mib", if kind == "fat16" { "4" } else { "64" },
    ]).unwrap();
    let crate::Command::Format { options } = cli.command else { panic!("format"); };
    crate::formatter::create(&Cx::for_testing(), &options).unwrap();
    let args = crate::reader::ImageArgs {
        image, offset: 0, length: None, oem_code_page: FatOemCodePage::Ascii, sidecar: None,
    };
    let volume = open_volume(&Cx::for_testing(), &args, true).unwrap();
    (directory, args, volume)
}

fn add(volume: &FatVolume, path: &str) {
    create_in_volume(&Cx::for_testing(), volume, path, PAYLOAD, NOW, false).unwrap();
}

fn healthy(volume: &FatVolume) {
    let cx = Cx::for_testing();
    let report = volume.check(&cx).unwrap();
    assert!(report.clean && report.complete && report.namespace_complete);
    clean_state(&cx, volume).unwrap();
}

#[test]
fn case_rename_round_trips_sfn_lfn_and_keeps_native_alias_metadata_and_payload() {
    for kind in ["fat16", "fat32"] {
        let (_directory, args, volume) = fixture(kind);
        let cx = Cx::for_testing();
        add(&volume, "/HELLO.TXT");
        let entry = volume.resolve(&cx, "/HELLO.TXT").unwrap().unwrap();
        let mut record = read_slot(&cx, &volume, entry.offset, false).unwrap().bytes;
        let cluster_high = u16::from_le_bytes([record[20], record[21]]);
        let retained = if kind == "fat16" { 0x4321 } else { cluster_high | 0xA000 };
        record[20..22].copy_from_slice(&retained.to_le_bytes());
        volume.device.write_all_at(&cx, ByteOffset(entry.offset), &record).unwrap();
        volume.device.sync(&cx).unwrap();
        let original = volume.resolve(&cx, "/HELLO.TXT").unwrap().unwrap();
        let original_chain = rename_chain(&cx, &volume, &original).unwrap();
        let original_raw = read_slot(&cx, &volume, original.offset, false).unwrap().bytes;
        let original_free = volume.free_clusters(&cx).unwrap();
        let mut previous = "/HELLO.TXT";
        for wanted in ["/hello.txt", "/Hello.txt", "/hELLO.TXT", "/HELLO.TXT"] {
            let before = std::fs::read(&args.image).unwrap();
            let dry = rename_in_volume(&cx, &volume, previous, wanted, true).unwrap();
            assert_eq!(dry["case_only"], true);
            assert_eq!(dry["renamed"], false);
            assert_eq!(std::fs::read(&args.image).unwrap(), before);
            let report = rename_in_volume(&cx, &volume, previous, wanted, false).unwrap();
            assert_eq!(report["case_only"], true);
            let actual = volume.resolve(&cx, wanted).unwrap().unwrap();
            assert_eq!(actual.name().unwrap(), &wanted[1..]);
            assert_eq!(actual.native.short_name, original.native.short_name);
            assert_eq!(rename_chain(&cx, &volume, &actual).unwrap(), original_chain);
            let mut raw = read_slot(&cx, &volume, actual.offset, false).unwrap().bytes;
            raw[12] = original_raw[12];
            assert_eq!(raw, original_raw);
            let chain = volume.file_chain(&cx, &actual).unwrap();
            assert_eq!(volume.read(&cx, &chain, 0, 4096).unwrap(), PAYLOAD);
            assert_eq!(volume.free_clusters(&cx).unwrap(), original_free);
            healthy(&volume);
            previous = wanted;
        }
        let before = std::fs::read(&args.image).unwrap();
        let report = rename_in_volume(&cx, &volume, previous, previous, false).unwrap();
        assert_eq!(report["unchanged"], true);
        assert_eq!(std::fs::read(&args.image).unwrap(), before);
    }
}

#[test]
fn long_spelling_and_nonempty_directory_case_changes_preserve_native_identity() {
    for kind in ["fat16", "fat32"] {
        let (_directory, _args, volume) = fixture(kind);
        let cx = Cx::for_testing();
        add(&volume, "/A detailed quarterly report.txt");
        let original = volume.resolve(&cx, "/A detailed quarterly report.txt").unwrap().unwrap();
        rename_in_volume(&cx, &volume, "/A detailed quarterly report.txt", "/A DETAILED QUARTERLY REPORT.TXT", false).unwrap();
        let entry = volume.resolve(&cx, "/A DETAILED QUARTERLY REPORT.TXT").unwrap().unwrap();
        assert_eq!(entry.offset, original.offset);
        assert_eq!(entry.native.short_name, original.native.short_name);
        assert_eq!(entry.name().unwrap(), "A DETAILED QUARTERLY REPORT.TXT");
        let alias = original.short_alias().unwrap();
        assert_eq!(volume.lookup(&cx, Directory::Root, &alias).unwrap().offset, original.offset);

        mkdir_in_volume(&cx, &volume, "/DOCS", NOW, false).unwrap();
        add(&volume, "/DOCS/KEEP.TXT");
        let directory = volume.resolve(&cx, "/DOCS").unwrap().unwrap();
        let mut dot_entries = [0; 64];
        volume.read_exact(&cx, volume.cluster_offset(directory.native.first_cluster).unwrap(), &mut dot_entries).unwrap();
        rename_in_volume(&cx, &volume, "/DOCS", "/Docs", false).unwrap();
        let renamed = volume.resolve(&cx, "/Docs").unwrap().unwrap();
        assert_eq!(renamed.native.first_cluster, directory.native.first_cluster);
        assert_eq!(renamed.name().unwrap(), "Docs");
        let mut after = [0; 64];
        volume.read_exact(&cx, volume.cluster_offset(directory.native.first_cluster).unwrap(), &mut after).unwrap();
        assert_eq!(after, dot_entries);
        let child = volume.resolve(&cx, "/Docs/KEEP.TXT").unwrap().unwrap();
        assert_eq!(volume.read(&cx, &volume.file_chain(&cx, &child).unwrap(), 0, 4096).unwrap(), PAYLOAD);
        healthy(&volume);
    }
}

#[test]
fn full_fat16_root_allows_sfn_case_flags_but_refuses_extra_slots_without_writes() {
    let (_directory, args, volume) = fixture("fat16");
    let cx = Cx::for_testing();
    add(&volume, "/HELLO.TXT");
    let (start, length) = volume.geometry.fixed_root().unwrap();
    for index in 1..length / 32 {
        let mut record = [0; 32];
        record[..11].copy_from_slice(format!("F{index:07}TXT").as_bytes());
        record[11] = 0x20;
        volume.device.write_all_at(&cx, ByteOffset(start + index * 32), &record).unwrap();
    }
    volume.device.sync(&cx).unwrap();
    healthy(&volume);
    rename_in_volume(&cx, &volume, "/HELLO.TXT", "/hello.txt", false).unwrap();
    assert_eq!(volume.lookup(&cx, Directory::Root, "hello.txt").unwrap().name().unwrap(), "hello.txt");
    let before = std::fs::read(&args.image).unwrap();
    for dry in [true, false] {
        assert!(rename_in_volume(&cx, &volume, "/hello.txt", "/Hello.txt", dry).is_err());
        assert_eq!(std::fs::read(&args.image).unwrap(), before);
    }
    healthy(&volume);
}

#[test]
fn no_replace_refuses_existing_names_aliases_and_same_entry_without_mutation() {
    for kind in ["fat16", "fat32"] {
        let (_directory, args, volume) = fixture(kind);
        let cx = Cx::for_testing();
        add(&volume, "/SOURCE.TXT");
        add(&volume, "/An existing long name.txt");
        let target = volume.resolve(&cx, "/An existing long name.txt").unwrap().unwrap();
        let alias = format!("/{}", target.short_alias().unwrap());
        let before = std::fs::read(&args.image).unwrap();
        for to in ["/source.txt", "/SOURCE.TXT", "/AN EXISTING LONG NAME.TXT", alias.as_str()] {
            for dry in [true, false] {
                let error = volume.rename_noreplace(&cx, "/SOURCE.TXT", to, dry).unwrap_err();
                assert!(matches!(error.downcast_ref::<FfsError>(), Some(FfsError::Exists)));
                assert_eq!(std::fs::read(&args.image).unwrap(), before);
            }
        }
        volume.rename_noreplace(&cx, "/SOURCE.TXT", "/DEST.TXT", false).unwrap();
        assert!(matches!(volume.resolve(&cx, "/SOURCE.TXT"), Err(FfsError::NotFound(_))));
        let entry = volume.resolve(&cx, "/DEST.TXT").unwrap().unwrap();
        assert_eq!(volume.read(&cx, &volume.file_chain(&cx, &entry).unwrap(), 0, 4096).unwrap(), PAYLOAD);
        healthy(&volume);
    }
}

#[test]
fn rename_cli_no_replace_runs_the_native_preflight_and_preserves_dry_run() {
    let (_directory, args, volume) = fixture("fat16");
    add(&volume, "/SOURCE.TXT");
    drop(volume);
    let cx = Cx::for_testing();
    let before = std::fs::read(&args.image).unwrap();
    let cli = crate::Cli::try_parse_from([
        "ffs-fat", "rename", args.image.to_str().unwrap(), "/SOURCE.TXT", "/DEST.TXT",
        "--offline-image", "--no-replace", "--dry-run",
    ]).unwrap();
    let crate::Command::Rename { mut options } = cli.command else { panic!("rename"); };
    assert!(options.no_replace);
    let dry = run_rename(&cx, &options).unwrap();
    assert_eq!(dry["dry_run"], true);
    assert_eq!(std::fs::read(&args.image).unwrap(), before);
    options.dry_run = false;
    run_rename(&cx, &options).unwrap();
    let after = std::fs::read(&args.image).unwrap();
    options.from.clone_from(&options.to);
    assert!(run_rename(&cx, &options).is_err());
    assert_eq!(std::fs::read(&args.image).unwrap(), after);
}

struct ImageState {
    bytes: Vec<u8>,
    durable: Vec<u8>,
    operations: usize,
    fail: Option<usize>,
    tear: usize,
    drop_write: Option<usize>,
    cancel: Option<usize>,
}

#[derive(Clone)]
struct FaultDevice(Arc<Mutex<ImageState>>, u64);

impl FaultDevice {
    fn new(bytes: Vec<u8>) -> Self {
        let len = bytes.len() as u64;
        Self(Arc::new(Mutex::new(ImageState {
            durable: bytes.clone(), bytes, operations: 0, fail: None,
            tear: 0, drop_write: None, cancel: None,
        })), len)
    }

    fn volume(&self) -> FatVolume {
        FatVolume::from_device(&Cx::for_testing(), Box::new(self.clone()), 0, self.1).unwrap()
    }
}

impl ByteDevice for FaultDevice {
    fn len_bytes(&self) -> u64 { self.1 }

    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        let state = self.0.lock().unwrap();
        let start = at.0 as usize;
        let end = start.checked_add(bytes.len()).unwrap();
        let source = state.bytes.get(start..end).ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
        bytes.copy_from_slice(source);
        Ok(())
    }

    fn write_all_at(&self, cx: &Cx, at: ByteOffset, bytes: &[u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        let mut state = self.0.lock().unwrap();
        state.operations += 1;
        let fail = state.fail == Some(state.operations);
        let count = if fail { state.tear.min(bytes.len()) } else { bytes.len() };
        if state.drop_write != Some(state.operations) {
            state.bytes[at.0 as usize..at.0 as usize + count].copy_from_slice(&bytes[..count]);
        }
        if state.cancel == Some(state.operations) { cx.set_cancel_requested(true); }
        if fail { return Err(std::io::Error::other("injected case-rename write failure").into()); }
        Ok(())
    }

    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        let mut state = self.0.lock().unwrap();
        state.operations += 1;
        if state.fail == Some(state.operations) {
            return Err(std::io::Error::other("injected case-rename sync failure").into());
        }
        state.durable = state.bytes.clone();
        if state.cancel == Some(state.operations) { cx.set_cancel_requested(true); }
        Ok(())
    }
}

#[test]
fn case_rename_write_sync_cuts_never_change_payload_or_admit_a_missing_clean_file() {
    for (original_name, new_name) in [
        ("/HELLO.TXT", "/Hello.txt"),
        ("/A detailed quarterly report.txt", "/A DETAILED QUARTERLY REPORT.TXT"),
    ] {
        let (_directory, args, volume) = fixture("fat16");
        add(&volume, original_name);
        add(&volume, "/KEEP.BIN");
        let start_data = volume.geometry.cluster_offset(2).unwrap() as usize;
        let bytes = std::fs::read(&args.image).unwrap();
        let success = FaultDevice::new(bytes.clone());
        rename_in_volume(&Cx::for_testing(), &success.volume(), original_name, new_name, false).unwrap();
        let operations = success.0.lock().unwrap().operations;
        assert!(operations > 4);
        for cut in 1..=operations {
            for tear in [0, 1, 31, 511] {
                let device = FaultDevice::new(bytes.clone());
                let volume = device.volume();
                {
                    let mut state = device.0.lock().unwrap();
                    state.fail = Some(cut);
                    state.tear = tear;
                }
                assert!(rename_in_volume(&Cx::for_testing(), &volume, original_name, new_name, false).is_err());
                for retain in [false, true] {
                    let snapshot = {
                        let state = device.0.lock().unwrap();
                        if retain { state.bytes.clone() } else { state.durable.clone() }
                    };
                    assert_eq!(&snapshot[start_data..], &bytes[start_data..]);
                    let restart = FaultDevice::new(snapshot);
                    let cx = Cx::for_testing();
                    if let Ok(volume) = FatVolume::from_device(&cx, Box::new(restart.clone()), 0, restart.1) {
                        let entry = volume.resolve(&cx, new_name).unwrap().unwrap();
                        let name = entry.name().unwrap();
                        assert!(name == &original_name[1..] || name == &new_name[1..]);
                        assert_eq!(volume.read(&cx, &volume.file_chain(&cx, &entry).unwrap(), 0, 4096).unwrap(), PAYLOAD);
                        assert!(volume.resolve(&cx, "/KEEP.BIN").unwrap().is_some());
                        healthy(&volume);
                    }
                }
            }
        }
    }
}

#[test]
fn cancelled_or_dropped_spelling_publication_is_never_reported_as_success() {
    let (_directory, args, volume) = fixture("fat16");
    add(&volume, "/HELLO.TXT");
    let bytes = std::fs::read(&args.image).unwrap();
    let success = FaultDevice::new(bytes.clone());
    rename_in_volume(&Cx::for_testing(), &success.volume(), "/HELLO.TXT", "/hello.txt", false).unwrap();
    let operations = success.0.lock().unwrap().operations;
    for cut in 1..operations {
        let device = FaultDevice::new(bytes.clone());
        let volume = device.volume();
        device.0.lock().unwrap().cancel = Some(cut);
        assert!(rename_in_volume(&Cx::for_testing(), &volume, "/HELLO.TXT", "/hello.txt", false).is_err());
    }
    // FAT16 dirty publication is BPB + two FAT copies + sync. The next write
    // updates the target SFN; dropping an acknowledged write must fail readback.
    let device = FaultDevice::new(bytes);
    let volume = device.volume();
    device.0.lock().unwrap().drop_write = Some(5);
    assert!(rename_in_volume(&Cx::for_testing(), &volume, "/HELLO.TXT", "/hello.txt", false).is_err());
    assert_eq!(volume.resolve(&Cx::for_testing(), "/HELLO.TXT").unwrap().unwrap().name().unwrap(), "HELLO.TXT");
}

#[test]
fn case_rename_honors_fat32_active_copy_reserved_bits_and_volume_boundaries() {
    let (_directory, args, volume) = fixture("fat32");
    let cx = Cx::for_testing();
    add(&volume, "/HELLO.TXT");
    let mut bytes = std::fs::read(&args.image).unwrap();
    let sector = u64::from(volume.geometry.sector_bytes());
    let backup = u64::from(volume.geometry.backup_boot_sector().unwrap()) * sector;
    for at in [40_usize, backup as usize + 40] {
        bytes[at..at + 2].copy_from_slice(&0x81_u16.to_le_bytes());
    }
    let geometry = FatGeometry::parse(&bytes[..512], bytes.len() as u64).unwrap();
    let width = 4_u64;
    let inactive = geometry.entry_offset(0, 2).unwrap() - 2 * width;
    let active = geometry.entry_offset(1, 2).unwrap() - 2 * width;
    let fat_len = (active - inactive) as usize;
    bytes[inactive as usize..active as usize].fill(0xA5);
    for at in (active as usize..active as usize + fat_len).step_by(4) {
        let raw = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        bytes[at..at + 4].copy_from_slice(&(raw | 0xB000_0000).to_le_bytes());
    }
    let original = bytes.clone();
    let base = 8192;
    let length = bytes.len();
    let mut backing = vec![0xC3; base];
    backing.extend(bytes);
    backing.extend([0xD4; 4096]);
    let device = FaultDevice::new(backing);
    let volume = FatVolume::from_device(&cx, Box::new(device.clone()), base as u64, length as u64).unwrap();
    rename_in_volume(&cx, &volume, "/HELLO.TXT", "/Hello.txt", false).unwrap();
    healthy(&volume);
    let state = device.0.lock().unwrap();
    assert_eq!(&state.bytes[..base], vec![0xC3; base]);
    assert_eq!(&state.bytes[base + length..], &[0xD4; 4096]);
    assert_eq!(&state.bytes[base + inactive as usize..base + active as usize], &original[inactive as usize..active as usize]);
    for at in (active as usize..active as usize + fat_len).step_by(4) {
        assert_eq!(state.bytes[base + at + 3] & 0xF0, 0xB0);
    }
}
