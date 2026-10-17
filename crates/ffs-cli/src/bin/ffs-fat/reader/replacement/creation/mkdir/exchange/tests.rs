//! Native-image and deterministic device tests; not mounted or hardware proof.

use super::*;
use crate::reader::replacement::{create_in_volume, mkdir_in_volume, open_volume};
use crate::reader::{FileChain, ImageArgs};
use clap::Parser as _;
use ffs_block::ByteDevice;
use ffs_ondisk::fat::FatOemCodePage;
use ffs_types::ByteOffset;
use std::sync::{Arc, Mutex};

const BASE: usize = 4096;
const NOW: u64 = 1_700_000_000;

#[derive(Clone, Debug)]
enum Event {
    Write(u64, usize),
    Sync,
}

struct Storage {
    pending: Vec<u8>,
    durable: Vec<u8>,
    events: Vec<Event>,
    fail: Option<usize>,
    drop_write: Option<usize>,
    cancel: Option<usize>,
    tear: usize,
}

#[derive(Clone)]
struct Device(Arc<Mutex<Storage>>);

impl Device {
    fn new(bytes: Vec<u8>) -> Self {
        Self(Arc::new(Mutex::new(Storage {
            pending: bytes.clone(),
            durable: bytes,
            events: Vec::new(),
            fail: None,
            drop_write: None,
            cancel: None,
            tear: 0,
        })))
    }

    fn open(&self) -> FatVolume {
        FatVolume::from_device(
            &Cx::for_testing(),
            Box::new(self.clone()),
            BASE as u64,
            self.len_bytes() - (2 * BASE) as u64,
        )
        .unwrap()
    }

    fn snapshot(&self) -> Vec<u8> {
        self.0.lock().unwrap().pending.clone()
    }

    fn reset(&self) {
        let mut state = self.0.lock().unwrap();
        assert_eq!(state.pending, state.durable);
        state.events.clear();
    }
}

impl ByteDevice for Device {
    fn len_bytes(&self) -> u64 {
        self.0.lock().unwrap().pending.len() as u64
    }
    fn read_exact_at(
        &self,
        cx: &Cx,
        offset: ByteOffset,
        bytes: &mut [u8],
    ) -> ffs_error::Result<()> {
        super::super::checkpoint(cx)?;
        let state = self.0.lock().unwrap();
        let at = usize::try_from(offset.0).unwrap();
        let end = at.checked_add(bytes.len()).unwrap();
        if end > state.pending.len() {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
        }
        bytes.copy_from_slice(&state.pending[at..end]);
        Ok(())
    }
    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, bytes: &[u8]) -> ffs_error::Result<()> {
        super::super::checkpoint(cx)?;
        let mut state = self.0.lock().unwrap();
        let at = offset.0 as usize;
        assert!(at >= BASE && at + bytes.len() <= state.pending.len() - BASE);
        state.events.push(Event::Write(offset.0, bytes.len()));
        let attempt = state.events.len();
        let fail = state.fail == Some(attempt);
        if state.drop_write != Some(attempt) {
            let length = if fail {
                state.tear.min(bytes.len())
            } else {
                bytes.len()
            };
            state.pending[at..at + length].copy_from_slice(&bytes[..length]);
        }
        if state.cancel == Some(attempt) {
            cx.set_cancel_requested(true);
        }
        if fail {
            return Err(std::io::Error::other("injected exchange write failure").into());
        }
        Ok(())
    }
    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        super::super::checkpoint(cx)?;
        let mut state = self.0.lock().unwrap();
        state.events.push(Event::Sync);
        let attempt = state.events.len();
        if state.fail == Some(attempt) {
            return Err(std::io::Error::other("injected exchange sync failure").into());
        }
        state.durable = state.pending.clone();
        if state.cancel == Some(attempt) {
            cx.set_cancel_requested(true);
        }
        Ok(())
    }
}

fn formatted(kind: &str) -> Device {
    let directory = tempfile::tempdir().unwrap();
    let image = directory.path().join("exchange.fat");
    let cli = crate::Cli::try_parse_from([
        "ffs-fat",
        "format",
        image.to_str().unwrap(),
        "--kind",
        kind,
        "--size-mib",
        if kind == "fat16" { "4" } else { "64" },
    ])
    .unwrap();
    let crate::Command::Format { options } = cli.command else {
        panic!("expected format");
    };
    let cx = Cx::for_testing();
    crate::formatter::create(&cx, &options).unwrap();
    let args = ImageArgs {
        image,
        offset: 0,
        length: None,
        oem_code_page: FatOemCodePage::Ascii,
        sidecar: None,
    };
    let volume = open_volume(&cx, &args, true).unwrap();
    create_in_volume(
        &cx,
        &volume,
        "/left.bin",
        b"left object payload",
        NOW,
        false,
    )
    .unwrap();
    create_in_volume(&cx, &volume, "/right.bin", b"RIGHT", NOW + 86400, false).unwrap();
    drop(volume);
    let mut bytes = vec![0xA5; BASE];
    bytes.extend_from_slice(&std::fs::read(args.image).unwrap());
    bytes.extend_from_slice(&[0x5A; BASE]);
    Device::new(bytes)
}

fn object(volume: &FatVolume, path: &str) -> (Entry, FileChain, [u8; 32]) {
    let cx = Cx::for_testing();
    let entry = volume.resolve(&cx, path).unwrap().unwrap();
    let chain = volume.file_chain(&cx, &entry).unwrap();
    let record = read_slot(&cx, volume, entry.offset, false).unwrap().bytes;
    (entry, chain, record)
}

fn clean(volume: &FatVolume) {
    let report = volume.check(&Cx::for_testing()).unwrap();
    assert!(
        report.clean && report.complete && report.namespace_complete,
        "{report:?}"
    );
}

#[test]
fn exchange_keeps_names_aliases_and_moves_complete_object_metadata() {
    for kind in ["fat16", "fat32"] {
        let device = formatted(kind);
        let volume = device.open();
        let cx = Cx::for_testing();
        let (_, left_chain, left) = object(&volume, "/left.bin");
        let (_, right_chain, right) = object(&volume, "/right.bin");
        let before = device.snapshot();
        volume
            .rename_exchange(&cx, "/LEFT.BIN", "/right.bin", false)
            .unwrap();
        let (_, at_left, left_record) = object(&volume, "/left.bin");
        let (_, at_right, right_record) = object(&volume, "/right.bin");
        assert_eq!(left_record[..11], left[..11]);
        assert_eq!(left_record[12], left[12]);
        assert_eq!(left_record[11], right[11]);
        assert_eq!(left_record[13..], right[13..]);
        assert_eq!(right_record[13..], left[13..]);
        assert_eq!(at_left.clusters, right_chain.clusters);
        assert_eq!(at_right.clusters, left_chain.clusters);
        assert_eq!(volume.read(&cx, &at_left, 0, 100).unwrap(), b"RIGHT");
        assert_eq!(
            volume.read(&cx, &at_right, 0, 100).unwrap(),
            b"left object payload"
        );
        clean(&volume);
        volume
            .rename_exchange(&cx, "/left.bin", "/RIGHT.BIN", false)
            .unwrap();
        assert_eq!(
            device.snapshot(),
            before,
            "two exchanges restore the entire image"
        );
    }
}

#[test]
fn full_fat16_root_and_data_area_need_no_temporary_name_or_cluster() {
    let device = formatted("fat16");
    let volume = device.open();
    let cx = Cx::for_testing();
    let free = volume.free_clusters(&cx).unwrap();
    let filler = vec![0x79; free as usize * volume.geometry.cluster_bytes() as usize];
    create_in_volume(&cx, &volume, "/filler.bin", &filler, NOW, false).unwrap();
    let (root, length) = volume.geometry.fixed_root().unwrap();
    {
        let mut state = device.0.lock().unwrap();
        for index in 0..length / 32 {
            let at = BASE + (root + index * 32) as usize;
            if matches!(state.pending[at], 0 | 0xE5) {
                let mut slot = [0; 32];
                slot[..11].copy_from_slice(format!("F{index:07}BIN").as_bytes());
                slot[11] = 0x20;
                state.pending[at..at + 32].copy_from_slice(&slot);
            }
        }
        state.durable = state.pending.clone();
    }
    clean(&volume);
    assert_eq!(volume.free_clusters(&cx).unwrap(), 0);
    let offsets = [
        object(&volume, "/left.bin").0.offset,
        object(&volume, "/right.bin").0.offset,
    ];
    let before = device.snapshot();
    device.reset();
    let report = volume
        .rename_exchange(&cx, "/left.bin", "/right.bin", false)
        .unwrap();
    assert_eq!(report["allocated_clusters"], 0);
    assert_eq!(report["released_clusters"], 0);
    assert_eq!(report["metadata_sectors"], 1);
    assert_eq!(volume.free_clusters(&cx).unwrap(), 0);
    let root_sector = BASE as u64 + root;
    let state = device.0.lock().unwrap();
    let updates = state
        .events
        .iter()
        .filter(|event| matches!(event, Event::Write(at, _) if *at == root_sector))
        .count();
    assert_eq!(updates, 1, "same-sector names must be coalesced");
    for (at, (&old, &new)) in before.iter().zip(&state.pending).enumerate() {
        if old != new {
            assert!(offsets.iter().any(|&offset| {
                (BASE + offset as usize..BASE + offset as usize + 32).contains(&at)
            }));
        }
    }
}

#[test]
fn exchange_nonempty_directories_and_mixed_types_updates_both_native_parents() {
    for kind in ["fat16", "fat32"] {
        let device = formatted(kind);
        let volume = device.open();
        let cx = Cx::for_testing();
        for path in ["/parent", "/leftdir", "/parent/rightdir"] {
            mkdir_in_volume(&cx, &volume, path, NOW, false).unwrap();
        }
        create_in_volume(&cx, &volume, "/leftdir/a.bin", b"A", NOW, false).unwrap();
        create_in_volume(&cx, &volume, "/parent/rightdir/b.bin", b"B", NOW, false).unwrap();
        let left = volume.resolve(&cx, "/leftdir").unwrap().unwrap();
        let right = volume.resolve(&cx, "/parent/rightdir").unwrap().unwrap();
        let parent_entry = volume.resolve(&cx, "/parent").unwrap().unwrap();
        volume
            .rename_exchange(&cx, "/leftdir", "/parent/rightdir", false)
            .unwrap();
        assert!(volume.resolve(&cx, "/leftdir/b.bin").is_ok());
        assert!(volume.resolve(&cx, "/parent/rightdir/a.bin").is_ok());
        for (entry, expected) in [(&left, parent_entry.native.first_cluster), (&right, 0)] {
            let at = volume.cluster_offset(entry.native.first_cluster).unwrap() + 32;
            let dotdot = read_slot(&cx, &volume, at, false).unwrap();
            assert_eq!(raw_cluster(volume.geometry.kind(), &dotdot.bytes), expected);
        }
        volume
            .rename_exchange(&cx, "/leftdir", "/left.bin", false)
            .unwrap();
        assert!(volume.resolve(&cx, "/left.bin/b.bin").is_ok());
        let (_, chain, _) = object(&volume, "/leftdir");
        assert_eq!(
            volume.read(&cx, &chain, 0, 100).unwrap(),
            b"left object payload"
        );
        clean(&volume);
    }
}

#[test]
fn exchange_long_names_keep_every_lfn_byte_and_empty_preallocation() {
    for kind in ["fat16", "fat32"] {
        let device = formatted(kind);
        let volume = device.open();
        let cx = Cx::for_testing();
        let from = "/Long original name.bin";
        let to = "/Second longer native name 🦀.bin";
        create_in_volume(&cx, &volume, from, b"contents", NOW, false).unwrap();
        create_in_volume(&cx, &volume, to, &[], NOW + 172_800, false).unwrap();
        volume
            .preallocate(&cx, to, 0, 2048, libc::FALLOC_FL_KEEP_SIZE, NOW)
            .unwrap();
        let (from_entry, from_chain, _) = object(&volume, from);
        let (to_entry, to_chain, _) = object(&volume, to);
        let before = device.snapshot();
        volume.rename_exchange(&cx, from, to, false).unwrap();
        let (new_from, new_chain, _) = object(&volume, from);
        assert_eq!(new_from.native.long_name, from_entry.native.long_name);
        assert_eq!(new_from.native.short_name, from_entry.native.short_name);
        assert_eq!(new_chain.size, 0);
        assert_eq!(new_chain.clusters, to_chain.clusters);
        assert_eq!(object(&volume, to).1.clusters, from_chain.clusters);
        let after = device.snapshot();
        for index in 0..after.len() {
            let in_short = [from_entry.offset, to_entry.offset]
                .iter()
                .any(|&at| (BASE + at as usize..BASE + at as usize + 32).contains(&index));
            if !in_short {
                assert_eq!(after[index], before[index], "unchanged byte {index}");
            }
        }
        clean(&volume);
    }
}

#[test]
fn exchange_refusals_dry_run_and_same_entry_alias_are_zero_write() {
    let device = formatted("fat16");
    let volume = device.open();
    let cx = Cx::for_testing();
    mkdir_in_volume(&cx, &volume, "/parent", NOW, false).unwrap();
    mkdir_in_volume(&cx, &volume, "/parent/subdir", NOW, false).unwrap();
    create_in_volume(&cx, &volume, "/parent/child.bin", b"child", NOW, false).unwrap();
    create_in_volume(&cx, &volume, "/readonly.bin", b"locked", NOW, true).unwrap();
    device.reset();
    let before = device.snapshot();
    for (from, to) in [
        ("/parent", "/PARENT/subdir"),
        ("/parent/child.bin", "/parent"),
        ("/", "/left.bin"),
        ("/left.bin", "/missing"),
        ("/left.bin", "/readonly.bin"),
    ] {
        assert!(
            volume.rename_exchange(&cx, from, to, false).is_err(),
            "{from} -> {to}"
        );
    }
    assert_eq!(
        volume
            .rename_exchange(&cx, "/left.bin", "/LEFT.BIN", false)
            .unwrap()["unchanged"],
        true
    );
    assert_eq!(
        volume
            .rename_exchange(&cx, "/left.bin", "/right.bin", true)
            .unwrap()["dry_run"],
        true
    );
    let cancelled = Cx::for_testing();
    cancelled.set_cancel_requested(true);
    assert!(
        volume
            .rename_exchange(&cancelled, "/left.bin", "/right.bin", false)
            .is_err()
    );
    assert!(device.0.lock().unwrap().events.is_empty());
    assert_eq!(device.snapshot(), before);
}

#[test]
fn active_fat_reserved_bits_ea_metadata_and_adjacent_volumes_survive_exchange() {
    for kind in ["fat16", "fat32"] {
        let device = formatted(kind);
        let initial = device.open();
        let (left, _, _) = object(&initial, "/left.bin");
        let (right, _, _) = object(&initial, "/right.bin");
        let geometry = initial.geometry.clone();
        drop(initial);
        {
            let mut state = device.0.lock().unwrap();
            if kind == "fat32" {
                for sector in std::iter::once(0_u16).chain(geometry.backup_boot_sector()) {
                    let at = BASE + usize::from(sector) * geometry.sector_bytes() as usize + 40;
                    state.pending[at..at + 2].copy_from_slice(&0x0081_u16.to_le_bytes());
                }
                for cluster in 0..=geometry.cluster_count() + 1 {
                    let at = BASE
                        + (geometry.entry_offset(1, cluster.max(2)).unwrap()
                            - u64::from(2_u32.saturating_sub(cluster)) * 4)
                            as usize;
                    state.pending[at + 3] |= 0xA0;
                }
            }
            for (entry, high) in [(&left, 0xB000_u16), (&right, 0xC000_u16)] {
                let at = BASE + entry.offset as usize + 20;
                state.pending[at..at + 2].copy_from_slice(&high.to_le_bytes());
            }
            state.durable = state.pending.clone();
        }
        let before = device.snapshot();
        let volume = device.open();
        let before_left = object(&volume, "/left.bin").2;
        let before_right = object(&volume, "/right.bin").2;
        volume
            .rename_exchange(&Cx::for_testing(), "/left.bin", "/right.bin", false)
            .unwrap();
        assert_eq!(object(&volume, "/left.bin").2[20..22], before_right[20..22]);
        assert_eq!(object(&volume, "/right.bin").2[20..22], before_left[20..22]);
        let after = device.snapshot();
        let root = u64::from(geometry.kind().entry_bytes());
        let fat_start = BASE + (geometry.entry_offset(0, 2).unwrap() - 2 * root) as usize;
        let fat_end = BASE
            + geometry
                .entry_offset(geometry.fat_count() - 1, geometry.cluster_count() + 1)
                .unwrap() as usize
            + root as usize;
        assert_eq!(before[fat_start..fat_end], after[fat_start..fat_end]);
        assert_eq!(before[..BASE], after[..BASE]);
        assert_eq!(before[before.len() - BASE..], after[after.len() - BASE..]);
        clean(&volume);
    }
}

#[test]
fn every_write_sync_cut_preserves_payload_and_only_admits_complete_exchanges() {
    let initial = formatted("fat16");
    let volume = initial.open();
    let cx = Cx::for_testing();
    mkdir_in_volume(&cx, &volume, "/other", NOW, false).unwrap();
    create_in_volume(&cx, &volume, "/other/dest.bin", b"destination", NOW, false).unwrap();
    let (_, left_chain, _) = object(&volume, "/left.bin");
    let (_, right_chain, _) = object(&volume, "/other/dest.bin");
    let baseline = initial.snapshot();
    let successful = Device::new(baseline.clone());
    successful
        .open()
        .rename_exchange(&cx, "/left.bin", "/other/dest.bin", false)
        .unwrap();
    let finished = successful.snapshot();
    let operations = successful.0.lock().unwrap().events.len();
    for cut in 1..=operations {
        for tear in [0, 1, 31, 511, 512] {
            let device = Device::new(baseline.clone());
            let fs = device.open();
            {
                let mut state = device.0.lock().unwrap();
                state.fail = Some(cut);
                state.tear = tear;
            }
            assert!(
                fs.rename_exchange(&cx, "/left.bin", "/other/dest.bin", false)
                    .is_err()
            );
            assert_eq!(device.0.lock().unwrap().events.len(), cut);
            for retain in [false, true] {
                let bytes = {
                    let state = device.0.lock().unwrap();
                    if retain {
                        state.pending.clone()
                    } else {
                        state.durable.clone()
                    }
                };
                for &cluster in left_chain.clusters.iter().chain(&right_chain.clusters) {
                    let start = BASE + volume.cluster_offset(cluster).unwrap() as usize;
                    let end = start + volume.geometry.cluster_bytes() as usize;
                    assert_eq!(&bytes[start..end], &baseline[start..end]);
                }
                let reopened = FatVolume::from_device(
                    &cx,
                    Box::new(Device::new(bytes.clone())),
                    BASE as u64,
                    (bytes.len() - 2 * BASE) as u64,
                );
                if let Ok(reopened) = reopened {
                    clean(&reopened);
                    assert!(
                        bytes == baseline || bytes == finished,
                        "cut={cut}, tear={tear}, retain={retain}"
                    );
                }
            }
        }
    }
}

#[test]
fn dropped_marker_or_metadata_writes_and_cancellation_never_report_success() {
    let initial = formatted("fat16");
    let baseline = initial.snapshot();
    let success = Device::new(baseline.clone());
    success
        .open()
        .rename_exchange(&Cx::for_testing(), "/left.bin", "/right.bin", false)
        .unwrap();
    let events = success.0.lock().unwrap().events.clone();
    for (index, event) in events.iter().enumerate() {
        if let Event::Write(_, bytes) = event {
            assert_eq!(*bytes, 512);
            let device = Device::new(baseline.clone());
            let volume = device.open();
            device.0.lock().unwrap().drop_write = Some(index + 1);
            assert!(
                volume
                    .rename_exchange(&Cx::for_testing(), "/left.bin", "/right.bin", false)
                    .is_err(),
                "dropped write {}",
                index + 1
            );
        }
        let device = Device::new(baseline.clone());
        let volume = device.open();
        device.0.lock().unwrap().cancel = Some(index + 1);
        assert!(
            volume
                .rename_exchange(&Cx::for_testing(), "/left.bin", "/right.bin", false)
                .is_err(),
            "cancel {}",
            index + 1
        );
        assert_eq!(device.0.lock().unwrap().events.len(), index + 1);
    }
}

#[test]
fn cli_exchange_conflicts_with_noreplace_and_reaches_native_writer() {
    assert!(
        crate::Cli::try_parse_from([
            "ffs-fat",
            "rename",
            "image",
            "/a",
            "/b",
            "--offline-image",
            "--exchange",
            "--no-replace",
        ])
        .is_err()
    );
    assert!(
        crate::Cli::try_parse_from(["ffs-fat", "rename", "image", "/a", "/b", "--exchange",])
            .is_err()
    );
    let directory = tempfile::tempdir().unwrap();
    let image = directory.path().join("cli.fat");
    let bytes = formatted("fat16").snapshot();
    std::fs::write(&image, &bytes[BASE..bytes.len() - BASE]).unwrap();
    let cli = crate::Cli::try_parse_from([
        "ffs-fat",
        "rename",
        image.to_str().unwrap(),
        "/left.bin",
        "/right.bin",
        "--offline-image",
        "--exchange",
    ])
    .unwrap();
    let crate::Command::Rename { options } = cli.command else {
        panic!("expected rename");
    };
    let report = super::super::run_rename(&Cx::for_testing(), &options).unwrap();
    assert_eq!(report["operation"], "exchange");
    assert_eq!(report["verification"]["clean"], true);
}
