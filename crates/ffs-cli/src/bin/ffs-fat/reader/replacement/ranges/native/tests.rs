//! Native-image tests; the fault device separates pending and durable bytes.
//! These are deterministic storage cuts, not hardware sector-atomicity claims.

use super::*;
use super::super::{truncate_in_volume, write_range_in_volume};
use super::super::super::{create_in_volume, creation, hash_device};
use clap::Parser as _;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

const NOW: u64 = 1_700_000_000;
const BASE: u64 = 4096;

struct Storage {
    durable: Vec<u8>,
    pending: BTreeMap<usize, [u8; 512]>,
    attempts: usize,
    fail_at: Option<usize>,
    tear: usize,
    writes: Vec<(u64, usize)>,
}

impl Storage {
    fn image(&self, pending: bool) -> Vec<u8> {
        let mut bytes = self.durable.clone();
        if pending {
            for (&at, page) in &self.pending {
                bytes[at..at + 512].copy_from_slice(page);
            }
        }
        bytes
    }

    fn put(&mut self, mut offset: usize, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let page = offset / 512 * 512;
            let within = offset % 512;
            let count = bytes.len().min(512 - within);
            let initial: [u8; 512] = self.durable[page..page + 512].try_into().unwrap();
            self.pending.entry(page).or_insert(initial)[within..within + count]
                .copy_from_slice(&bytes[..count]);
            bytes = &bytes[count..];
            offset += count;
        }
    }
}

#[derive(Clone)]
struct Device(Arc<Mutex<Storage>>);

impl Device {
    fn new(bytes: Vec<u8>) -> Self {
        Self(Arc::new(Mutex::new(Storage {
            durable: bytes,
            pending: BTreeMap::new(),
            attempts: 0,
            fail_at: None,
            tear: 0,
            writes: Vec::new(),
        })))
    }

    fn open(&self) -> FatVolume {
        FatVolume::from_device(
            &Cx::for_testing(),
            Box::new(self.clone()),
            BASE,
            self.len_bytes() - 2 * BASE,
        ).unwrap()
    }

    fn restart(&self, retain_pending: bool) -> Device {
        Device::new(self.0.lock().unwrap().image(retain_pending))
    }

    fn reset_audit(&self) {
        let mut state = self.0.lock().unwrap();
        assert!(state.pending.is_empty());
        state.attempts = 0;
        state.writes.clear();
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
            let source = state.pending.get(&page).map_or(&state.durable[page..page + 512], |p| &p[..]);
            bytes[filled..filled + count].copy_from_slice(&source[within..within + count]);
            at += count;
            filled += count;
        }
        Ok(())
    }

    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, bytes: &[u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        let mut state = self.0.lock().unwrap();
        assert!(offset.0 >= BASE);
        assert!(offset.0 + bytes.len() as u64 <= state.durable.len() as u64 - BASE);
        state.attempts += 1;
        let fail = state.fail_at == Some(state.attempts);
        let count = if fail { state.tear.min(bytes.len()) } else { bytes.len() };
        state.put(offset.0 as usize, &bytes[..count]);
        state.writes.push((offset.0, count));
        if fail {
            return Err(std::io::Error::other("injected native range write failure").into());
        }
        Ok(())
    }

    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        let mut state = self.0.lock().unwrap();
        state.attempts += 1;
        if state.fail_at == Some(state.attempts) {
            return Err(std::io::Error::other("injected native range sync failure").into());
        }
        for (at, page) in std::mem::take(&mut state.pending) {
            state.durable[at..at + 512].copy_from_slice(&page);
        }
        Ok(())
    }
}

fn formatted(kind: &str) -> Device {
    let directory = tempfile::tempdir().unwrap();
    let image = directory.path().join("native.fat");
    let cli = crate::Cli::try_parse_from([
        "ffs-fat", "format", image.to_str().unwrap(), "--kind", kind,
        "--size-mib", if kind == "fat16" { "4" } else { "64" },
    ]).unwrap();
    let crate::Command::Format { options } = cli.command else {
        panic!("expected format options");
    };
    crate::formatter::create(&Cx::for_testing(), &options).unwrap();
    let mut bytes = vec![0xA5; BASE as usize];
    bytes.extend_from_slice(&std::fs::read(image).unwrap());
    bytes.extend_from_slice(&vec![0x5A; BASE as usize]);
    Device::new(bytes)
}

fn file(volume: &FatVolume) -> (Entry, FileChain) {
    let cx = Cx::for_testing();
    let entry = volume.resolve(&cx, "/file.bin").unwrap().unwrap();
    let chain = volume.file_chain(&cx, &entry).unwrap();
    (entry, chain)
}

fn clean(volume: &FatVolume) -> u64 {
    let check = volume.check(&Cx::for_testing()).unwrap();
    assert!(check.clean && check.complete && check.namespace_complete, "{check:?}");
    check.free_clusters
}

struct Pattern(u64);

impl ByteDevice for Pattern {
    fn len_bytes(&self) -> u64 { self.0 }
    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        super::super::checked_end(at.0, bytes.len(), self.0)?;
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = ((at.0 + index as u64) % 251) as u8;
        }
        Ok(())
    }
    fn write_all_at(&self, _: &Cx, _: ByteOffset, _: &[u8]) -> ffs_error::Result<()> {
        panic!("source must never be written")
    }
    fn sync(&self, _: &Cx) -> ffs_error::Result<()> { panic!("source must never be synced") }
}

#[test]
fn full_volumes_allow_overwrite_shrink_and_delta_only_regrowth() {
    for kind in ["fat16", "fat32"] {
        let device = formatted(kind);
        let volume = device.open();
        let cx = Cx::for_testing();
        let cluster = u64::from(volume.geometry.cluster_bytes());
        let length = clean(&volume) * cluster;
        let source = Pattern(length);
        let plan = creation::prepare(&cx, &volume, "/file.bin", &source, NOW).unwrap();
        plan.execute(&cx, &volume, &source, || Ok(())).unwrap();
        assert_eq!(clean(&volume), 0);
        let (_, original) = file(&volume);
        device.reset_audit();
        let offset = cluster - 3;
        let patch = b"cross-cluster overwrite";
        assert_eq!(write_range_in_volume(&cx, &volume, "/file.bin", offset, patch, NOW).unwrap(), patch.len());
        let (_, overwritten) = file(&volume);
        assert_eq!(overwritten.clusters, original.clusters);
        assert_eq!(clean(&volume), 0);
        let mut expected = vec![0; (2 * cluster) as usize];
        source.read_exact_at(&cx, ByteOffset(0), &mut expected).unwrap();
        expected[offset as usize..offset as usize + patch.len()].copy_from_slice(patch);
        assert_eq!(volume.read(&cx, &overwritten, 0, expected.len()).unwrap(), expected);
        // Payload I/O must cover only the patch, not a replacement-sized copy.
        let state = device.0.lock().unwrap();
        let payload_bytes: usize = state.writes.iter().filter_map(|&(at, count)| {
            original.clusters.iter().any(|&c| {
                let start = BASE + volume.cluster_offset(c).unwrap();
                at >= start && at < start + cluster
            }).then_some(count)
        }).sum();
        assert_eq!(payload_bytes, patch.len());
        drop(state);

        let shorter = length - 3 * cluster + 17;
        truncate_in_volume(&cx, &volume, "/file.bin", shorter, NOW).unwrap();
        assert_eq!(clean(&volume), 2);
        let (_, shrunk) = file(&volume);
        assert_eq!(shrunk.clusters, original.clusters[..original.clusters.len() - 2]);
        truncate_in_volume(&cx, &volume, "/file.bin", length, NOW).unwrap();
        assert_eq!(clean(&volume), 0);
        let (_, grown) = file(&volume);
        assert_eq!(volume.read(&cx, &grown, 0, expected.len()).unwrap(), expected);
        assert_eq!(volume.read(&cx, &grown, shorter, (length - shorter) as usize).unwrap(), vec![0; (length - shorter) as usize]);
        truncate_in_volume(&cx, &volume, "/file.bin", 0, NOW).unwrap();
        let (empty, chain) = file(&volume);
        assert_eq!(empty.native.first_cluster, 0);
        assert!(chain.clusters.is_empty());
        assert_eq!(clean(&volume), length / cluster);
    }
}

#[test]
fn fragmented_growth_initializes_gap_and_poisoned_reused_storage() {
    for kind in ["fat16", "fat32"] {
        let device = formatted(kind);
        let volume = device.open();
        let cx = Cx::for_testing();
        let cluster = u64::from(volume.geometry.cluster_bytes());
        create_in_volume(&cx, &volume, "/file.bin", b"prefix", NOW, false).unwrap();
        let blocker = vec![0x7B; 2 * cluster as usize];
        create_in_volume(&cx, &volume, "/other.bin", &blocker, NOW, false).unwrap();
        let (_, old) = file(&volume);
        let free = clean(&volume);
        let mut table = FatTable::new(&volume);
        let next = (2..=volume.geometry.cluster_count() + 1).find(|&c| table.entry(&cx, c).unwrap() == FatEntry::Free).unwrap();
        let poison = vec![0xE7; cluster as usize];
        device.write_all_at(&cx, ByteOffset(BASE + volume.cluster_offset(next).unwrap()), &poison).unwrap();
        device.write_all_at(&cx, ByteOffset(BASE + volume.cluster_offset(old.clusters[0]).unwrap() + 6), &poison[6..]).unwrap();
        device.sync(&cx).unwrap();
        let offset = cluster + 17;
        write_range_in_volume(&cx, &volume, "/file.bin", offset, b"tail", NOW).unwrap();
        let (_, chain) = file(&volume);
        assert_eq!(chain.clusters, vec![old.clusters[0], next]);
        assert_ne!(next, old.clusters[0] + 1);
        assert_eq!(clean(&volume), free - 1);
        let mut expected = b"prefix".to_vec();
        expected.resize(offset as usize, 0);
        expected.extend_from_slice(b"tail");
        assert_eq!(volume.read(&cx, &chain, 0, expected.len()).unwrap(), expected);
        let other = volume.resolve(&cx, "/other.bin").unwrap().unwrap();
        let other_chain = volume.file_chain(&cx, &other).unwrap();
        assert_eq!(volume.read(&cx, &other_chain, 0, blocker.len()).unwrap(), blocker);
        let mut slack = vec![0xA5; cluster as usize - 21];
        volume.read_exact(&cx, volume.cluster_offset(next).unwrap() + 21, &mut slack).unwrap();
        assert!(slack.iter().all(|&byte| byte == 0));
    }
}

#[test]
fn refused_and_noop_ranges_perform_no_backing_writes() {
    let device = formatted("fat16");
    let volume = device.open();
    let cx = Cx::for_testing();
    create_in_volume(&cx, &volume, "/file.bin", b"original", NOW, false).unwrap();
    create_in_volume(&cx, &volume, "/readonly.bin", b"locked", NOW, true).unwrap();
    device.reset_audit();
    let before = hash_device(&cx, &device).unwrap();
    assert!(write_range_in_volume(&cx, &volume, "/file.bin", u64::MAX, b"x", NOW).is_err());
    assert!(truncate_in_volume(&cx, &volume, "/file.bin", u64::from(u32::MAX) + 1, NOW).is_err());
    assert!(write_range_in_volume(&cx, &volume, "/file.bin", 0, b"x", u64::MAX).is_err());
    assert!(truncate_in_volume(&cx, &volume, "/file.bin", u64::from(u32::MAX), NOW).is_err());
    assert!(write_range_in_volume(&cx, &volume, "/readonly.bin", 0, b"x", NOW).is_err());
    assert!(truncate_in_volume(&cx, &volume, "/readonly.bin", 0, NOW).is_err());
    assert_eq!(write_range_in_volume(&cx, &volume, "/file.bin", u64::MAX, &[], NOW).unwrap(), 0);
    truncate_in_volume(&cx, &volume, "/file.bin", 8, NOW).unwrap();
    let cancelled = Cx::for_testing();
    cancelled.set_cancel_requested(true);
    assert!(truncate_in_volume(&cancelled, &volume, "/file.bin", 0, NOW).is_err());
    assert_eq!(device.0.lock().unwrap().attempts, 0);
    assert_eq!(hash_device(&cx, &device).unwrap(), before);
}

#[test]
fn active_fat_and_reserved_high_bits_survive_incremental_ranges() {
    let device = formatted("fat32");
    let initial = device.open();
    let geometry = initial.geometry.clone();
    drop(initial);
    {
        let mut state = device.0.lock().unwrap();
        for sector in [0_u64, u64::from(geometry.backup_boot_sector().unwrap())] {
            let at = (BASE + sector * u64::from(geometry.sector_bytes()) + 40) as usize;
            state.durable[at..at + 2].copy_from_slice(&0x0081_u16.to_le_bytes());
        }
        for copy in 0..2 {
            let start = BASE + geometry.entry_offset(copy, 2).unwrap() - 8;
            for entry in 0..geometry.cluster_count() + 2 {
                state.durable[(start + u64::from(entry) * 4 + 3) as usize] |= if copy == 0 { 0xB0 } else { 0xA0 };
            }
        }
    }
    let original = device.0.lock().unwrap().image(false);
    let volume = device.open();
    let cx = Cx::for_testing();
    create_in_volume(&cx, &volume, "/file.bin", b"old", NOW, false).unwrap();
    let cluster = u64::from(volume.geometry.cluster_bytes());
    write_range_in_volume(&cx, &volume, "/file.bin", 2 * cluster + 3, b"new", NOW).unwrap();
    truncate_in_volume(&cx, &volume, "/file.bin", 2, NOW).unwrap();
    truncate_in_volume(&cx, &volume, "/file.bin", 4 * cluster, NOW).unwrap();
    clean(&volume);
    let current = device.0.lock().unwrap().image(false);
    let first = (BASE + geometry.entry_offset(0, 2).unwrap() - 8) as usize;
    let second = (BASE + geometry.entry_offset(1, 2).unwrap() - 8) as usize;
    assert_eq!(&current[first..second], &original[first..second]);
    for entry in 0..geometry.cluster_count() + 2 {
        assert_eq!(current[second + entry as usize * 4 + 3] & 0xF0, 0xA0);
    }
    assert_eq!(&current[..BASE as usize], &original[..BASE as usize]);
    assert_eq!(&current[current.len() - BASE as usize..], &original[original.len() - BASE as usize..]);
}

#[test]
fn every_write_and_sync_cut_only_readmits_consistent_clean_images() {
    let initial = formatted("fat16");
    let volume = initial.open();
    let cx = Cx::for_testing();
    let cluster = u64::from(volume.geometry.cluster_bytes());
    let original = vec![0x36; 3 * cluster as usize + 7];
    create_in_volume(&cx, &volume, "/file.bin", &original, NOW, false).unwrap();
    drop(volume);
    let baseline = initial.0.lock().unwrap().image(false);
    for action in 0..3 {
        let execute = |volume: &FatVolume| -> Result<()> {
            match action {
                0 => truncate_in_volume(&cx, volume, "/file.bin", 5 * cluster + 19, NOW),
                1 => truncate_in_volume(&cx, volume, "/file.bin", cluster - 1, NOW),
                _ => write_range_in_volume(&cx, volume, "/file.bin", cluster - 3, &[0x97; 31], NOW).map(|_| ()),
            }
        };
        let success = Device::new(baseline.clone());
        execute(&success.open()).unwrap();
        let total = success.0.lock().unwrap().attempts;
        let mut expected = original.clone();
        match action {
            0 => expected.resize((5 * cluster + 19) as usize, 0),
            1 => expected.truncate((cluster - 1) as usize),
            _ => expected[cluster as usize - 3..cluster as usize + 28].fill(0x97),
        }
        assert!(total > 8);
        for cut in 1..=total {
            for tear in [0, 1, 31, 511, 512] {
                let device = Device::new(baseline.clone());
                {
                    let mut state = device.0.lock().unwrap();
                    state.fail_at = Some(cut);
                    state.tear = tear;
                }
                assert!(execute(&device.open()).is_err(), "action={action}, cut={cut}");
                for retain in [false, true] {
                    let crashed = device.restart(retain);
                    let admitted = FatVolume::from_device(&cx, Box::new(crashed.clone()), BASE, crashed.len_bytes() - 2 * BASE);
                    if let Ok(reopened) = admitted {
                        clean(&reopened);
                        let (_, chain) = file(&reopened);
                        let bytes = reopened.read(&cx, &chain, 0, 8192).unwrap();
                        assert!(bytes == original || bytes == expected, "action={action}, cut={cut}, tear={tear}, retain={retain}");
                    }
                }
            }
        }
    }
}
