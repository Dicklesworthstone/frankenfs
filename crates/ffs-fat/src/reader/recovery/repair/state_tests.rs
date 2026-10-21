//! Exercise the real state publisher and recovery plans on constructed native
//! images. Pending bytes and sync-time loss are distinct; this is not hardware
//! or native-tool interoperability qualification.

mod reclamation;

use super::*;
use ffs_ondisk::fat::{FatGeometry, FatOemCodePage};
use std::collections::BTreeMap;
use std::sync::Mutex;

const BASE: u64 = 4096;
const PAGE: usize = 4096;
const PAYLOAD: &[u8] = b"retained live bytes";
type Pages = BTreeMap<u64, [u8; PAGE]>;

#[derive(Clone, Copy)]
enum Fault {
    Fail(usize, usize), // write/sync ordinal, retained write prefix
    DiscardAtSync(usize),
    FlipAtSync(usize, u64),
    ReadAfterSync(usize),
    CancelAtSync(usize),
    ReadAt(u64),
}

#[derive(Clone, Debug)]
enum Event {
    Read(u64, usize),
    Write(u64, usize),
    Sync,
}

#[derive(Default)]
struct Storage {
    durable: Pages,
    pending: Pages,
    events: Vec<Event>,
    attempts: usize,
    syncs: usize,
    fault: Option<Fault>,
}

impl Storage {
    fn read(&self, mut at: u64, mut target: &mut [u8]) {
        while !target.is_empty() {
            let key = at / PAGE as u64;
            let within = (at % PAGE as u64) as usize;
            let count = target.len().min(PAGE - within);
            if let Some(page) = self.pending.get(&key).or_else(|| self.durable.get(&key)) {
                target[..count].copy_from_slice(&page[within..within + count]);
            } else {
                target[..count].fill(0);
            }
            target = &mut target[count..];
            at += count as u64;
        }
    }

    fn put(&mut self, mut at: u64, mut source: &[u8]) {
        while !source.is_empty() {
            let key = at / PAGE as u64;
            let within = (at % PAGE as u64) as usize;
            let count = source.len().min(PAGE - within);
            let durable = &self.durable;
            self.pending
                .entry(key)
                .or_insert_with(|| durable.get(&key).copied().unwrap_or([0; PAGE]))
                [within..within + count]
                .copy_from_slice(&source[..count]);
            source = &source[count..];
            at += count as u64;
        }
    }

    fn persist(&mut self) {
        self.durable.append(&mut self.pending);
    }

    fn image(&self) -> Pages {
        let mut image = self.durable.clone();
        image.extend(self.pending.clone());
        image
    }
}

#[derive(Clone)]
struct Device {
    state: Arc<Mutex<Storage>>,
    length: u64,
}

impl Device {
    fn bytes(&self, at: u64, length: usize) -> Vec<u8> {
        let mut bytes = vec![0; length];
        self.state.lock().unwrap().read(at, &mut bytes);
        bytes
    }

    fn arm(&self, fault: Option<Fault>) {
        let mut state = self.state.lock().unwrap();
        state.events.clear();
        state.attempts = 0;
        state.syncs = 0;
        state.fault = fault;
    }

    fn diagnostic(&self, cx: &Cx, args: &ImageArgs) -> DiagnosticVolume {
        DiagnosticVolume::from_device(cx, Box::new(self.clone()), args).unwrap()
    }
}

impl ByteDevice for Device {
    fn len_bytes(&self) -> u64 {
        self.length
    }

    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        assert!(at.0.checked_add(bytes.len() as u64).is_some_and(|end| end <= self.length));
        let mut state = self.state.lock().unwrap();
        state.events.push(Event::Read(at.0, bytes.len()));
        let fail = match state.fault {
            Some(Fault::ReadAt(bad)) => at.0 <= bad && bad < at.0 + bytes.len() as u64,
            Some(Fault::ReadAfterSync(count)) => state.syncs >= count,
            _ => false,
        };
        if fail {
            return Err(std::io::Error::other("injected recovery-state read failure").into());
        }
        state.read(at.0, bytes);
        Ok(())
    }

    fn write_all_at(&self, cx: &Cx, at: ByteOffset, bytes: &[u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        assert!(at.0 >= BASE && at.0 + bytes.len() as u64 <= self.length - BASE);
        let mut state = self.state.lock().unwrap();
        state.attempts += 1;
        state.events.push(Event::Write(at.0, bytes.len()));
        if let Some(Fault::Fail(cut, tear)) = state.fault
            && state.attempts == cut
        {
            state.put(at.0, &bytes[..tear.min(bytes.len())]);
            return Err(std::io::Error::other("injected recovery-state write failure").into());
        }
        state.put(at.0, bytes);
        Ok(())
    }

    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        let mut state = self.state.lock().unwrap();
        state.attempts += 1;
        state.syncs += 1;
        state.events.push(Event::Sync);
        if let Some(Fault::Fail(cut, _)) = state.fault
            && state.attempts == cut
        {
            return Err(std::io::Error::other("injected recovery-state sync failure").into());
        }
        if matches!(state.fault, Some(Fault::DiscardAtSync(count)) if count == state.syncs) {
            state.pending.clear();
            return Ok(());
        }
        state.persist();
        if let Some(Fault::FlipAtSync(count, at)) = state.fault
            && count == state.syncs
        {
            let mut byte = [0];
            state.read(at, &mut byte);
            byte[0] ^= 1;
            state.put(at, &byte);
            state.persist();
        }
        if matches!(state.fault, Some(Fault::CancelAtSync(count)) if count == state.syncs) {
            cx.set_cancel_requested(true);
        }
        Ok(())
    }
}

fn fixture(kind: FatKind, sector: u32, active: bool) -> (Device, ImageArgs, FatGeometry) {
    let count: u32 = if kind == FatKind::Fat16 { 6000 } else { 70_000 };
    let reserved: u32 = if kind == FatKind::Fat16 { 1 } else { 32 };
    let roots: u16 = if kind == FatKind::Fat16 { 512 } else { 0 };
    let width = kind.entry_bytes();
    let tables = ((count + 2) * width).div_ceil(sector);
    let total = reserved + 2 * tables + (u32::from(roots) * 32).div_ceil(sector) + count;
    let mut boot = vec![0; sector as usize];
    boot[..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
    boot[3..11].copy_from_slice(b"MSWIN4.1");
    boot[11..13].copy_from_slice(&(sector as u16).to_le_bytes());
    boot[13] = 1;
    boot[14..16].copy_from_slice(&(reserved as u16).to_le_bytes());
    boot[16] = 2;
    boot[17..19].copy_from_slice(&roots.to_le_bytes());
    boot[21] = 0xF8;
    boot[32..36].copy_from_slice(&total.to_le_bytes());
    boot[510..512].copy_from_slice(&[0x55, 0xAA]);
    if kind == FatKind::Fat16 {
        boot[22..24].copy_from_slice(&(tables as u16).to_le_bytes());
        boot[38] = 0x29;
    } else {
        boot[36..40].copy_from_slice(&tables.to_le_bytes());
        boot[40..42].copy_from_slice(&(if active { 0x81_u16 } else { 0 }).to_le_bytes());
        boot[44..48].copy_from_slice(&2_u32.to_le_bytes());
        boot[48..50].copy_from_slice(&1_u16.to_le_bytes());
        boot[50..52].copy_from_slice(&6_u16.to_le_bytes());
        boot[66] = 0x29;
    }
    let length = u64::from(total) * u64::from(sector);
    let geometry = FatGeometry::parse(&boot, length).unwrap();
    let mut state = Storage::default();
    state.put(0, &[0xA7; PAGE]);
    state.put(BASE + length, &[0xB9; PAGE]);
    state.put(BASE, &boot);
    if kind == FatKind::Fat32 {
        state.put(BASE + 6 * u64::from(sector), &boot);
        let mut info = vec![0; sector as usize];
        info[..4].copy_from_slice(&0x4161_5252_u32.to_le_bytes());
        info[484..488].copy_from_slice(&0x6141_7272_u32.to_le_bytes());
        info[488..496].fill(0xFF);
        info[508..512].copy_from_slice(&0xAA55_0000_u32.to_le_bytes());
        state.put(BASE + u64::from(sector), &info);
    }
    let end = if kind == FatKind::Fat16 { 0xFFFF_u32 } else { 0x0FFF_FFFF };
    for copy in 0..2_u8 {
        let start = BASE + u64::from(reserved + u32::from(copy) * tables) * u64::from(sector);
        for cluster in 0..=count + 1 {
            let low = match cluster {
                0 => end & !7,
                1 | 5 | 301 => end,
                2 if kind == FatKind::Fat32 => end,
                300 => 301,
                _ => 0,
            };
            let high = if kind == FatKind::Fat32 { (10 + u32::from(copy)) << 28 } else { 0 };
            state.put(start + u64::from(cluster * width), &(high | low).to_le_bytes()[..width as usize]);
        }
    }
    if active {
        // The unselected header must neither grant authority nor be repaired.
        let first = geometry.entry_offset(0, 2).unwrap() - 2 * u64::from(width);
        state.put(BASE + first, &[0; 8]);
    }
    let root = geometry.fixed_root().map_or_else(|| geometry.cluster_offset(2).unwrap(), |(at, _)| at);
    let mut record = [0; 32];
    record[..11].copy_from_slice(b"KEEP    BIN");
    record[11] = 0x20;
    record[26..28].copy_from_slice(&5_u16.to_le_bytes());
    record[28..32].copy_from_slice(&(PAYLOAD.len() as u32).to_le_bytes());
    state.put(BASE + root, &record);
    state.put(BASE + geometry.cluster_offset(5).unwrap(), PAYLOAD);
    state.persist();
    let device = Device { state: Arc::new(Mutex::new(state)), length: length + 2 * BASE };
    let args = ImageArgs {
        image: PathBuf::from("constructed-recovery-state.img"),
        offset: BASE,
        length: Some(length),
        oem_code_page: FatOemCodePage::Ascii,
        sidecar: None,
    };
    let cx = Cx::for_testing();
    let report = device.diagnostic(&cx, &args).report(&cx).unwrap();
    assert!(report.complete && report.namespace_complete);
    assert_eq!(report.lost_clusters, Some(2));
    assert!(report.issues.iter().all(|issue| issue.kind == "lost_allocation"));
    device.arm(None);
    (device, args, geometry)
}

/// Native byte positions are derived directly from the format, not StateSector.
fn markers(geometry: &FatGeometry) -> Vec<(u64, u8, bool)> {
    let state_at = if geometry.kind() == FatKind::Fat16 { 37 } else { 65 };
    let mut result: Vec<_> = std::iter::once(0_u16).chain(geometry.backup_boot_sector())
        .map(|sector| (BASE + u64::from(sector) * u64::from(geometry.sector_bytes()) + state_at, 1, true))
        .collect();
    for copy in 0..geometry.fat_count() {
        if !geometry.mirrored() && copy != geometry.active_fat() {
            continue;
        }
        let bit = if geometry.kind() == FatKind::Fat16 { 0x80 } else { 0x08 };
        result.push((BASE + geometry.entry_offset(copy, 2).unwrap() - 1, bit, false));
    }
    result
}

fn assert_only_state_bytes(before: &Pages, device: &Device, geometry: &FatGeometry) {
    let state = device.state.lock().unwrap();
    let actual = state.image();
    let allowed = markers(geometry);
    for key in before.keys().chain(actual.keys()) {
        let old = before.get(key).copied().unwrap_or([0; PAGE]);
        let new = actual.get(key).copied().unwrap_or([0; PAGE]);
        for (index, (&old, &new)) in old.iter().zip(&new).enumerate() {
            let at = key * PAGE as u64 + index as u64;
            let mask = allowed.iter().find(|(position, _, _)| *position == at)
                .map_or(0, |(_, mask, _)| *mask);
            assert_eq!((old ^ new) & !mask, 0, "non-state change at {at}");
        }
    }
}

fn assert_no_writes_after_sync(device: &Device) {
    let state = device.state.lock().unwrap();
    let first = state.events.iter().position(|event| matches!(event, Event::Sync)).unwrap();
    assert!(state.events[first + 1..].iter().all(|event| matches!(event, Event::Read(_, _))));
}

#[test]
fn state_roundtrip_verifies_after_sync_and_preserves_every_other_byte() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for sector in [512, 4096] {
            for active in [false, true] {
                if active && kind == FatKind::Fat16 { continue; }
                let (device, args, geometry) = fixture(kind, sector, active);
                let cx = Cx::for_testing();
                let diagnostic = device.diagnostic(&cx, &args);
                let before = device.state.lock().unwrap().image();
                for dirty in [true, true, false] {
                    device.arm(None);
                    set_state(&cx, &diagnostic, dirty).unwrap();
                    for (at, mask, boot) in markers(&geometry) {
                        assert_eq!(device.bytes(at, 1)[0] & mask != 0, dirty == boot);
                    }
                    assert_only_state_bytes(&before, &device, &geometry);
                    assert_no_writes_after_sync(&device);
                    let state = device.state.lock().unwrap();
                    assert_eq!(state.syncs, 1);
                    let sync = state.events.iter().position(|event| matches!(event, Event::Sync)).unwrap();
                    for (at, _, _) in markers(&geometry) {
                        let start = at / u64::from(sector) * u64::from(sector);
                        assert!(state.events[sync + 1..].iter().any(|event| {
                            matches!(event, Event::Read(position, length) if *position == start && *length == sector as usize)
                        }));
                    }
                }
                assert_eq!(device.state.lock().unwrap().image(), before);
            }
        }
    }
}

#[test]
fn late_reserved_or_boot_damage_refuses_both_transitions_without_partial_publication() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for dirty in [false, true] {
            for damage in ["reserved", "media", "geometry", "boot_flag"] {
                let (device, args, geometry) = fixture(kind, 512, false);
                let cx = Cx::for_testing();
                let diagnostic = device.diagnostic(&cx, &args);
                if !dirty { set_state(&cx, &diagnostic, true).unwrap(); }
                let last = BASE + geometry.entry_offset(1, 2).unwrap();
                let backup = BASE + u64::from(geometry.backup_boot_sector().unwrap_or(0)) * 512;
                let (at, value) = match damage {
                    "reserved" => (last - 1, 0),
                    "media" => (last - 2 * u64::from(kind.entry_bytes()), 0),
                    "geometry" => (backup + 13, 2),
                    _ => (backup + if kind == FatKind::Fat16 { 37 } else { 65 }, 2),
                };
                device.state.lock().unwrap().put(at, &[value]);
                let before = device.state.lock().unwrap().image();
                device.arm(None);
                assert!(set_state(&cx, &diagnostic, dirty).is_err(), "{kind:?} {dirty} {damage}");
                assert_eq!(device.state.lock().unwrap().attempts, 0);
                assert_eq!(device.state.lock().unwrap().image(), before);
            }
        }
    }
}

#[test]
fn sync_discard_blocks_reclamation_before_any_lost_cluster_is_released() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for sector in [512, 4096] {
            let (device, args, geometry) = fixture(kind, sector, false);
            let cx = Cx::for_testing();
            let diagnostic = device.diagnostic(&cx, &args);
            let plan = Plan::prepare(&cx, &diagnostic, true, false).unwrap();
            let before = device.state.lock().unwrap().image();
            device.arm(Some(Fault::DiscardAtSync(1)));
            let error = plan.execute(&cx, &diagnostic).unwrap_err();
            assert!(error.to_string().contains("persisting native dirty state"));
            assert_no_writes_after_sync(&device);
            assert_eq!(device.state.lock().unwrap().image(), before);
            assert_eq!(device.bytes(BASE + geometry.cluster_offset(5).unwrap(), PAYLOAD.len()), PAYLOAD);
            assert_eq!(device.state.lock().unwrap().syncs, 1);
        }
    }
}

#[test]
fn whole_sector_postsync_corruption_read_errors_and_cancellation_are_fatal() {
    for dirty in [false, true] {
        for fault in 0..5 {
            let (device, args, geometry) = fixture(FatKind::Fat32, 4096, true);
            let cx = Cx::for_testing();
            let diagnostic = device.diagnostic(&cx, &args);
            if !dirty { set_state(&cx, &diagnostic, true).unwrap(); }
            let fault = match fault {
                0 => Fault::FlipAtSync(1, BASE + 400),
                1 => Fault::FlipAtSync(1, BASE + 6 * 4096 + 4095),
                2 => Fault::FlipAtSync(1, BASE + geometry.entry_offset(1, 2).unwrap() + 4),
                3 => Fault::ReadAfterSync(1),
                _ => Fault::CancelAtSync(1),
            };
            device.arm(Some(fault));
            assert!(set_state(&cx, &diagnostic, dirty).is_err());
            assert_eq!(device.state.lock().unwrap().syncs, 1);
            assert_no_writes_after_sync(&device);
        }
    }
}

#[test]
fn already_dirty_pending_state_is_not_accepted_without_verified_sync() {
    let (device, args, geometry) = fixture(FatKind::Fat32, 512, false);
    for (at, mask, boot) in markers(&geometry) {
        let byte = device.bytes(at, 1)[0];
        device.state.lock().unwrap().put(at, &[if boot { byte | mask } else { byte & !mask }]);
    }
    let cx = Cx::for_testing();
    let diagnostic = device.diagnostic(&cx, &args);
    device.arm(Some(Fault::DiscardAtSync(1)));
    assert!(set_state(&cx, &diagnostic, true).is_err());
    let state = device.state.lock().unwrap();
    assert_eq!(state.syncs, 1);
    assert!(!state.events.iter().any(|event| matches!(event, Event::Write(_, _))));
}

#[test]
fn every_state_write_sync_cut_preserves_nonstate_bytes_and_stops_without_cleanup() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let (probe, args, _) = fixture(kind, 512, false);
        let cx = Cx::for_testing();
        set_state(&cx, &probe.diagnostic(&cx, &args), true).unwrap();
        let total = probe.state.lock().unwrap().attempts;
        for dirty in [false, true] {
            for cut in 1..=total {
                for tear in [0, 31, 511, 512] {
                    let (device, args, geometry) = fixture(kind, 512, false);
                    let cx = Cx::for_testing();
                    let diagnostic = device.diagnostic(&cx, &args);
                    if !dirty { set_state(&cx, &diagnostic, true).unwrap(); }
                    let before = device.state.lock().unwrap().image();
                    device.arm(Some(Fault::Fail(cut, tear)));
                    assert!(set_state(&cx, &diagnostic, dirty).is_err());
                    assert_eq!(device.state.lock().unwrap().attempts, cut);
                    assert_only_state_bytes(&before, &device, &geometry);
                }
            }
        }
    }
}

#[test]
fn late_preflight_read_failure_and_cancelled_context_make_no_mutation_attempt() {
    for cancelled in [false, true] {
        let (device, args, geometry) = fixture(FatKind::Fat32, 512, false);
        let cx = Cx::for_testing();
        let diagnostic = device.diagnostic(&cx, &args);
        let before = device.state.lock().unwrap().image();
        device.arm(Some(Fault::ReadAt(BASE + geometry.entry_offset(1, 2).unwrap() - 8)));
        cx.set_cancel_requested(cancelled);
        assert!(set_state(&cx, &diagnostic, true).is_err());
        assert_eq!(device.state.lock().unwrap().attempts, 0);
        assert_eq!(device.state.lock().unwrap().image(), before);
    }
}

#[test]
fn recovery_reclaims_only_lost_allocation_and_finishes_with_verified_clean_state() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for sector in [512, 4096] {
            let (device, args, geometry) = fixture(kind, sector, kind == FatKind::Fat32);
            let cx = Cx::for_testing();
            let diagnostic = device.diagnostic(&cx, &args);
            let plan = Plan::prepare(&cx, &diagnostic, true, false).unwrap();
            device.arm(None);
            assert_eq!(plan.execute(&cx, &diagnostic).unwrap()["verification"]["clean"], true);
            let mut table = FatTable::new(&diagnostic.volume);
            for cluster in [300, 301] { assert_eq!(table.entry(&cx, cluster).unwrap(), FatEntry::Free); }
            assert_eq!(device.bytes(BASE + geometry.cluster_offset(5).unwrap(), PAYLOAD.len()), PAYLOAD);
            assert_eq!(device.bytes(0, PAGE), [0xA7; PAGE]);
            assert_eq!(device.bytes(BASE + geometry.volume_bytes(), PAGE), [0xB9; PAGE]);
            let state = device.state.lock().unwrap();
            assert!(state.pending.is_empty());
            assert!(state.events.iter().filter_map(|event| match event {
                Event::Write(at, length) => Some((*at, *length)),
                _ => None,
            }).all(|(at, length)| at >= BASE && at + length as u64 <= device.length - BASE));
        }
    }
}

#[test]
fn mirror_reconciliation_does_not_start_after_dirty_flush_loss() {
    let (device, args, geometry) = fixture(FatKind::Fat32, 512, false);
    let at = BASE + geometry.entry_offset(0, 300).unwrap();
    device.state.lock().unwrap().put(at, &0xA000_0000_u32.to_le_bytes());
    device.state.lock().unwrap().persist();
    let cx = Cx::for_testing();
    let diagnostic = device.diagnostic(&cx, &args);
    let plan = mirrors::MirrorPlan::prepare(&cx, diagnostic, 1, &args).unwrap();
    let before = device.state.lock().unwrap().image();
    device.arm(Some(Fault::DiscardAtSync(1)));
    assert!(plan.execute(&cx).is_err());
    assert_no_writes_after_sync(&device);
    assert_eq!(device.state.lock().unwrap().image(), before);
    assert_eq!(device.bytes(at, 4), 0xA000_0000_u32.to_le_bytes());
}
