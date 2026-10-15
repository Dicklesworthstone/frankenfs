//! Native-format fixtures with pending/durable storage, not mounted FUSE proof.

use super::*;
use super::super::{find_entry_slots, mkdir_in_volume, rename_in_volume};
use crate::reader::replacement::{create_in_volume, write_volume};
use crate::reader::{Directory, Entry, FileChain};
use clap::Parser as _;
use ffs_block::ByteDevice;
use ffs_types::ByteOffset;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

const NOW: u64 = 1_700_000_000;
const BASE: usize = 4096;

#[derive(Clone, Debug)]
enum Event {
    Write(u64),
    Sync,
}

struct Storage {
    durable: Vec<u8>,
    pending: BTreeMap<usize, [u8; 512]>,
    events: Vec<Event>,
    fail_at: Option<usize>,
    drop_at: Option<usize>,
    tear: usize,
}

impl Storage {
    fn put(&mut self, mut at: usize, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let page = at / 512 * 512;
            let within = at % 512;
            let count = bytes.len().min(512 - within);
            let initial = self.durable[page..page + 512].try_into().unwrap();
            self.pending.entry(page).or_insert(initial)[within..within + count]
                .copy_from_slice(&bytes[..count]);
            at += count;
            bytes = &bytes[count..];
        }
    }

    fn snapshot(&self, retain: bool) -> Vec<u8> {
        let mut bytes = self.durable.clone();
        if retain {
            for (&at, page) in &self.pending {
                bytes[at..at + 512].copy_from_slice(page);
            }
        }
        bytes
    }
}

#[derive(Clone)]
struct Device(Arc<Mutex<Storage>>);

impl Device {
    fn new(bytes: Vec<u8>) -> Self {
        Self(Arc::new(Mutex::new(Storage {
            durable: bytes,
            pending: BTreeMap::new(),
            events: Vec::new(),
            fail_at: None,
            drop_at: None,
            tear: 0,
        })))
    }

    fn open(&self) -> ffs_error::Result<FatVolume> {
        FatVolume::from_device(
            &Cx::for_testing(),
            Box::new(self.clone()),
            BASE as u64,
            self.len_bytes() - (2 * BASE) as u64,
        )
    }

    fn snapshot(&self, retain: bool) -> Vec<u8> {
        self.0.lock().unwrap().snapshot(retain)
    }

    fn reset_audit(&self) {
        let mut state = self.0.lock().unwrap();
        assert!(state.pending.is_empty());
        state.events.clear();
    }
}

impl ByteDevice for Device {
    fn len_bytes(&self) -> u64 {
        self.0.lock().unwrap().durable.len() as u64
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        let state = self.0.lock().unwrap();
        let mut at = usize::try_from(offset.0).unwrap();
        let end = at.checked_add(bytes.len()).unwrap();
        if end > state.durable.len() {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
        }
        let mut filled = 0;
        while filled < bytes.len() {
            let page = at / 512 * 512;
            let within = at % 512;
            let count = (bytes.len() - filled).min(512 - within);
            let source = state.pending.get(&page)
                .map_or(&state.durable[page..page + 512], |pending| &pending[..]);
            bytes[filled..filled + count].copy_from_slice(&source[within..within + count]);
            at += count;
            filled += count;
        }
        Ok(())
    }

    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, bytes: &[u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        let mut state = self.0.lock().unwrap();
        let at = usize::try_from(offset.0).unwrap();
        assert!(at >= BASE);
        assert!(at + bytes.len() <= state.durable.len() - BASE);
        state.events.push(Event::Write(offset.0));
        let attempt = state.events.len();
        if state.drop_at == Some(attempt) {
            return Ok(());
        }
        let fail = state.fail_at == Some(attempt);
        let count = if fail { bytes.len().min(state.tear) } else { bytes.len() };
        state.put(at, &bytes[..count]);
        if fail {
            return Err(std::io::Error::other("injected rename write failure").into());
        }
        Ok(())
    }

    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        let mut state = self.0.lock().unwrap();
        state.events.push(Event::Sync);
        if state.fail_at == Some(state.events.len()) {
            return Err(std::io::Error::other("injected rename sync failure").into());
        }
        for (at, bytes) in std::mem::take(&mut state.pending) {
            state.durable[at..at + 512].copy_from_slice(&bytes);
        }
        Ok(())
    }
}

fn formatted(kind: &str) -> Device {
    let directory = tempfile::tempdir().unwrap();
    let image = directory.path().join("rename.fat");
    let cli = crate::Cli::try_parse_from([
        "ffs-fat", "format", image.to_str().unwrap(), "--kind", kind,
        "--size-mib", if kind == "fat16" { "4" } else { "64" },
    ]).unwrap();
    let crate::Command::Format { options } = cli.command else {
        panic!("expected formatter options");
    };
    crate::formatter::create(&Cx::for_testing(), &options).unwrap();
    let mut bytes = vec![0xA5; BASE];
    bytes.extend_from_slice(&std::fs::read(image).unwrap());
    bytes.extend_from_slice(&vec![0x5A; BASE]);
    Device::new(bytes)
}

fn clean(volume: &FatVolume) -> crate::reader::check::FatCheckReport {
    let report = volume.check(&Cx::for_testing()).unwrap();
    assert!(report.clean && report.complete && report.namespace_complete, "{report:?}");
    report
}

fn file(volume: &FatVolume, path: &str) -> (Entry, FileChain) {
    let cx = Cx::for_testing();
    let entry = volume.resolve(&cx, path).unwrap().unwrap();
    let chain = volume.file_chain(&cx, &entry).unwrap();
    (entry, chain)
}

/// Plant valid, empty 8.3 files in otherwise unused fixed-root slots. This
/// avoids hundreds of unrelated whole-volume mutation checks during setup.
/// The real reader/checker must accept the resulting complete native namespace.
fn fill_root_until(volume: &FatVolume, stop: u64) {
    let cx = Cx::for_testing();
    let (start, length) = volume.geometry.fixed_root().unwrap();
    for (index, at) in (start..start + length).step_by(32).enumerate() {
        if at >= stop {
            break;
        }
        let slot = super::super::read_slot(&cx, volume, at, false).unwrap();
        if !matches!(slot.bytes[0], 0 | 0xE5) {
            continue;
        }
        let mut raw = [0; 32];
        let name = format!("F{index:07}TXT");
        raw[..11].copy_from_slice(name.as_bytes());
        raw[11] = 0x20;
        raw[24..26].copy_from_slice(&0x5821_u16.to_le_bytes());
        write_volume(&cx, volume, at, &raw).unwrap();
    }
    volume.device.sync(&cx).unwrap();
    clean(volume);
}

fn fill_root(volume: &FatVolume) {
    let (start, length) = volume.geometry.fixed_root().unwrap();
    fill_root_until(volume, start + length);
}

fn assert_only_name_bytes_changed(before: &[u8], after: &[u8], short: &Slot, long: &[Slot]) {
    assert_eq!(before.len(), after.len());
    let mut permitted = before.to_vec();
    let at = BASE + short.offset as usize;
    // Only the short spelling and NT lowercase flags change in a live SFN.
    permitted[at..at + 11].copy_from_slice(&after[at..at + 11]);
    permitted[at + 12] = after[at + 12];
    for slot in long {
        let at = BASE + slot.offset as usize;
        permitted[at..at + 32].copy_from_slice(&after[at..at + 32]);
    }
    assert_eq!(permitted, after, "rename changed data, allocation, dot entries, hints or neighboring names");
}

#[test]
fn full_fat16_root_and_data_volume_can_rename_without_allocation() {
    let cx = Cx::for_testing();
    let device = formatted("fat16");
    let volume = device.open().unwrap();
    let payload = vec![0x73; 1507];
    create_in_volume(&cx, &volume, "/old.bin", &payload, NOW, false).unwrap();
    let filler = vec![0x6A; (clean(&volume).free_clusters
        * u64::from(volume.geometry.cluster_bytes())) as usize];
    create_in_volume(&cx, &volume, "/filler.bin", &filler, NOW, false).unwrap();
    fill_root(&volume);
    assert_eq!(clean(&volume).free_clusters, 0);
    let (old, old_chain) = file(&volume, "/old.bin");
    let (short, long) = find_entry_slots(&cx, &volume, Directory::Root, old.offset).unwrap();
    assert!(long.is_empty());
    let before = device.snapshot(false);
    device.reset_audit();
    let report = rename_in_volume(&cx, &volume, "/old.bin", "/new.bin", true).unwrap();
    assert_eq!(report["reused_source_slots"], true);
    assert_eq!(report["dry_run"], true);
    assert_eq!(device.snapshot(true), before);
    assert!(device.0.lock().unwrap().events.is_empty());

    let report = rename_in_volume(&cx, &volume, "/old.bin", "/new.bin", false).unwrap();
    assert_eq!(report["new_entry_offset"], old.offset);
    let (new, chain) = file(&volume, "/new.bin");
    assert_eq!(new.offset, old.offset);
    assert_eq!(chain.clusters, old_chain.clusters);
    assert_eq!(volume.read(&cx, &chain, 0, payload.len()).unwrap(), payload);
    assert!(matches!(volume.resolve(&cx, "/old.bin"), Err(FfsError::NotFound(_))));
    assert_eq!(clean(&volume).free_clusters, 0);
    assert_only_name_bytes_changed(&before, &device.snapshot(false), &short, &long);
    let reopened = Device::new(device.snapshot(false)).open().unwrap();
    clean(&reopened);
    assert_eq!(file(&reopened, "/new.bin").1.clusters, old_chain.clusters);
}

#[test]
fn fsops_full_root_rename_preserves_cached_inode_and_payload() {
    use crate::filesystem::FatFs;
    use ffs_core::{FsOps, RequestScope};
    use ffs_types::InodeNumber;
    use std::ffi::OsStr;

    let cx = Cx::for_testing();
    let device = formatted("fat16");
    let volume = device.open().unwrap();
    create_in_volume(&cx, &volume, "/old.bin", b"cached payload", NOW, false).unwrap();
    fill_root(&volume);
    let fs = FatFs::new_with_mode(&cx, volume, 0, 0, true).unwrap();
    let mut scope = RequestScope::empty();
    let root = InodeNumber(1);
    let old = fs.lookup(&cx, &mut scope, root, OsStr::new("old.bin")).unwrap();
    fs.open(&cx, &mut scope, old.ino, libc::O_RDONLY).unwrap();
    assert_eq!(fs.read(&cx, &mut scope, old.ino, 0, 14).unwrap(), b"cached payload");

    fs.rename(&cx, &mut scope, root, OsStr::new("old.bin"), root, OsStr::new("new.bin"))
        .unwrap();
    let new = fs.lookup(&cx, &mut scope, root, OsStr::new("new.bin")).unwrap();
    assert_eq!(new.ino, old.ino);
    assert_eq!(new.size, old.size);
    assert_eq!(fs.read(&cx, &mut scope, old.ino, 0, 14).unwrap(), b"cached payload");
    assert!(matches!(
        fs.lookup(&cx, &mut scope, root, OsStr::new("old.bin")),
        Err(FfsError::NotFound(_))
    ));
    clean(&Device::new(device.snapshot(false)).open().unwrap());
}

#[test]
fn full_root_lfn_reuse_preserves_adjacency_across_sectors_and_retires_surplus() {
    let cx = Cx::for_testing();
    let device = formatted("fat16");
    let volume = device.open().unwrap();
    let (root, _) = volume.geometry.fixed_root().unwrap();
    fill_root_until(&volume, root + 14 * 32);
    let original = "/Original document with a name crossing a sector boundary.bin";
    create_in_volume(&cx, &volume, original, b"retained", NOW, false).unwrap();
    fill_root(&volume);
    let (entry, chain) = file(&volume, original);
    let (short, long) = find_entry_slots(&cx, &volume, Directory::Root, entry.offset).unwrap();
    assert!(long.iter().any(|slot| slot.offset / 512 != short.offset / 512));
    let initial = device.snapshot(false);
    let mut old = original;
    for new in ["/Destination still long.bin", "/Renamed 🦀 notes.txt", "/FINAL.BIN"] {
        let report = rename_in_volume(&cx, &volume, old, new, false).unwrap();
        assert_eq!(report["reused_source_slots"], true);
        let (entry, actual) = file(&volume, new);
        assert_eq!(entry.name().unwrap(), new.trim_start_matches('/'));
        assert_eq!(entry.offset, short.offset);
        assert_eq!(actual.clusters, chain.clusters);
        assert_eq!(volume.read(&cx, &actual, 0, 8).unwrap(), b"retained");
        let (_, current) = find_entry_slots(&cx, &volume, Directory::Root, entry.offset).unwrap();
        for slot in &long[current.len()..] {
            assert_eq!(super::super::read_slot(&cx, &volume, slot.offset, false).unwrap().bytes[0], 0xE5);
        }
        clean(&volume);
        old = new;
    }
    assert_only_name_bytes_changed(&initial, &device.snapshot(false), &short, &long);
}

#[test]
fn source_footprint_too_small_refuses_without_dirtying_or_writes() {
    let cx = Cx::for_testing();
    let device = formatted("fat16");
    let volume = device.open().unwrap();
    create_in_volume(&cx, &volume, "/old.bin", b"keep", NOW, false).unwrap();
    fill_root(&volume);
    let before = device.snapshot(false);
    device.reset_audit();
    for dry_run in [false, true] {
        assert!(rename_in_volume(&cx, &volume, "/old.bin", "/a much longer name.bin", dry_run).is_err());
    }
    let cancelled = Cx::for_testing();
    cancelled.set_cancel_requested(true);
    assert!(rename_in_volume(&cancelled, &volume, "/old.bin", "/new.bin", false).is_err());
    assert!(device.0.lock().unwrap().events.is_empty());
    assert_eq!(device.snapshot(true), before);
}

#[test]
fn directory_rename_keeps_descendants_and_native_parent_links() {
    let cx = Cx::for_testing();
    for kind in ["fat16", "fat32"] {
        let device = formatted(kind);
        let volume = device.open().unwrap();
        mkdir_in_volume(&cx, &volume, "/old", NOW, false).unwrap();
        create_in_volume(&cx, &volume, "/old/child.bin", b"child", NOW, false).unwrap();
        if kind == "fat16" {
            fill_root(&volume);
        }
        let entry = volume.resolve(&cx, "/old").unwrap().unwrap();
        let (short, long) = find_entry_slots(&cx, &volume, Directory::Root, entry.offset).unwrap();
        let before = device.snapshot(false);
        let report = rename_in_volume(&cx, &volume, "/old", "/new", false).unwrap();
        assert_eq!(report["reused_source_slots"], true);
        assert_eq!(volume.resolve(&cx, "/new").unwrap().unwrap().native.first_cluster,
            entry.native.first_cluster);
        let (_, chain) = file(&volume, "/new/child.bin");
        assert_eq!(volume.read(&cx, &chain, 0, 5).unwrap(), b"child");
        assert_only_name_bytes_changed(&before, &device.snapshot(false), &short, &long);
        clean(&volume);
    }
}

#[test]
fn alias_paths_resolve_the_same_native_parent_for_reuse() {
    let cx = Cx::for_testing();
    let device = formatted("fat16");
    let volume = device.open().unwrap();
    let parent = "/Parent directory with a long name";
    mkdir_in_volume(&cx, &volume, parent, NOW, false).unwrap();
    let entry = volume.resolve(&cx, parent).unwrap().unwrap();
    let alias = entry.short_alias().unwrap();
    let from = format!("{parent}/old.bin");
    let to = format!("/{alias}/new.bin");
    create_in_volume(&cx, &volume, &from, b"aliases", NOW, false).unwrap();
    let (old, chain) = file(&volume, &from);
    let report = rename_in_volume(&cx, &volume, &from, &to, false).unwrap();
    assert_eq!(report["reused_source_slots"], true);
    let (new, actual) = file(&volume, &format!("{parent}/new.bin"));
    assert_eq!(new.offset, old.offset);
    assert_eq!(actual.clusters, chain.clusters);
    clean(&volume);
}

#[test]
fn fault_device_loses_only_unflushed_bytes_on_restart() {
    let cx = Cx::for_testing();
    let device = Device::new(vec![0; 3 * BASE]);
    device.write_all_at(&cx, ByteOffset(BASE as u64 + 7), b"pending").unwrap();
    assert_eq!(&device.snapshot(false)[BASE + 7..BASE + 14], &[0; 7]);
    assert_eq!(&device.snapshot(true)[BASE + 7..BASE + 14], b"pending");
    device.sync(&cx).unwrap();
    assert_eq!(&device.snapshot(false)[BASE + 7..BASE + 14], b"pending");
    device.write_all_at(&cx, ByteOffset(BASE as u64 + 7), b"changed").unwrap();
    let next = device.0.lock().unwrap().events.len() + 1;
    device.0.lock().unwrap().fail_at = Some(next);
    assert!(device.sync(&cx).is_err());
    assert_eq!(&device.snapshot(false)[BASE + 7..BASE + 14], b"pending");
    assert_eq!(&device.snapshot(true)[BASE + 7..BASE + 14], b"changed");
}

#[test]
fn every_write_and_sync_cut_refuses_dirty_or_preserves_a_complete_name() {
    let cx = Cx::for_testing();
    let initial = formatted("fat16");
    let volume = initial.open().unwrap();
    let from = "/Original long file name spanning records.bin";
    let to = "/Replacement long name.bin";
    create_in_volume(&cx, &volume, from, b"durable content", NOW, false).unwrap();
    let (_, original) = file(&volume, from);
    let baseline = initial.snapshot(false);
    let success = Device::new(baseline.clone());
    rename_in_volume(&cx, &success.open().unwrap(), from, to, false).unwrap();
    let events = success.0.lock().unwrap().events.len();
    assert!(events > 12);
    let mut clean_outcomes = 0;
    let mut dirty_outcomes = 0;
    for cut in 1..=events {
        for tear in [0, 1, 31, 511, 512] {
            let device = Device::new(baseline.clone());
            let volume = device.open().unwrap();
            {
                let mut state = device.0.lock().unwrap();
                state.fail_at = Some(cut);
                state.tear = tear;
            }
            assert!(rename_in_volume(&cx, &volume, from, to, false).is_err(), "cut={cut}, tear={tear}");
            for retain in [false, true] {
                let restarted = Device::new(device.snapshot(retain));
                match restarted.open() {
                    Ok(reopened) => {
                        clean_outcomes += 1;
                        clean(&reopened);
                        let old = reopened.resolve(&cx, from);
                        let new = reopened.resolve(&cx, to);
                        let path = match (old, new) {
                            (Ok(Some(_)), Err(FfsError::NotFound(_))) => from,
                            (Err(FfsError::NotFound(_)), Ok(Some(_))) => to,
                            _ => panic!("incomplete clean namespace at cut={cut}, tear={tear}, retain={retain}"),
                        };
                        let (_, chain) = file(&reopened, path);
                        assert_eq!(chain.clusters, original.clusters);
                        assert_eq!(reopened.read(&cx, &chain, 0, 15).unwrap(), b"durable content");
                    }
                    Err(FfsError::UnsupportedFeature(detail)) => {
                        assert!(detail.contains("dirty"), "unexpected admission refusal: {detail}");
                        dirty_outcomes += 1;
                    }
                    Err(error) => panic!("unexpected restart error: {error}"),
                }
            }
        }
    }
    assert!(clean_outcomes > 0);
    assert!(dirty_outcomes > 0);
}

#[test]
fn dropped_namespace_writes_fail_readback_instead_of_claiming_success() {
    let cx = Cx::for_testing();
    let initial = formatted("fat16");
    let volume = initial.open().unwrap();
    let from = "/Source long name for dropped writes.bin";
    let to = "/New long name.bin";
    create_in_volume(&cx, &volume, from, b"not freed", NOW, false).unwrap();
    let (root, length) = volume.geometry.fixed_root().unwrap();
    let baseline = initial.snapshot(false);
    let success = Device::new(baseline.clone());
    rename_in_volume(&cx, &success.open().unwrap(), from, to, false).unwrap();
    let events = success.0.lock().unwrap().events.clone();
    let mut tested = 0;
    for (index, event) in events.iter().enumerate() {
        if !matches!(event, Event::Write(at) if *at >= BASE as u64 + root && *at < BASE as u64 + root + length) {
            continue;
        }
        tested += 1;
        let device = Device::new(baseline.clone());
        let volume = device.open().unwrap();
        device.0.lock().unwrap().drop_at = Some(index + 1);
        assert!(rename_in_volume(&cx, &volume, from, to, false).is_err(), "dropped write {}", index + 1);
        assert!(matches!(
            Device::new(device.snapshot(false)).open(),
            Err(FfsError::UnsupportedFeature(_))
        ));
    }
    assert!(tested >= 5);
}
