//! Reclamation authority must come from current rooted ownership, not counts or
//! bounded issue examples. Inject changes around the actual production plan.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

fn end(kind: FatKind) -> u32 {
    if kind == FatKind::Fat16 { 0xFFFF } else { 0x0FFF_FFFF }
}

fn root(geometry: &FatGeometry) -> u64 {
    BASE + geometry.fixed_root().map_or_else(
        || geometry.cluster_offset(geometry.root_cluster()).unwrap(),
        |(at, _)| at,
    )
}

fn links(device: &Device, geometry: &FatGeometry, changes: &[(u32, u32)]) {
    let width = geometry.kind().entry_bytes() as usize;
    let mask = end(geometry.kind());
    for copy in 0..geometry.fat_count() {
        if !geometry.mirrored() && copy != geometry.active_fat() { continue; }
        for &(cluster, value) in changes {
            let at = BASE + geometry.entry_offset(copy, cluster).unwrap();
            let mut raw = [0; 4];
            raw[..width].copy_from_slice(&device.bytes(at, width));
            let value = (u32::from_le_bytes(raw) & !mask) | value;
            device.state.lock().unwrap().put(at, &value.to_le_bytes()[..width]);
        }
    }
    device.state.lock().unwrap().persist();
}

fn swap_fixture(kind: FatKind, sector: u32) -> (Device, ImageArgs, FatGeometry) {
    let (device, args, geometry) = fixture(kind, sector, false);
    // Two equal-sized chains can trade live ownership without changing counts.
    // The always-lost cluster 3 also keeps the bounded finding's first example
    // unchanged. Thus the complete serialized diagnostic stays identical.
    links(&device, &geometry, &[(3, end(kind)), (5, 6), (6, end(kind))]);
    device.arm(None);
    (device, args, geometry)
}

fn select_other_chain(device: &Device, geometry: &FatGeometry) {
    device.state.lock().unwrap().put(root(geometry) + 26, &300_u16.to_le_bytes());
    device.state.lock().unwrap().persist();
}

fn assert_links_retained(device: &Device, geometry: &FatGeometry) {
    let width = geometry.kind().entry_bytes() as usize;
    for copy in 0..geometry.fat_count() {
        for (cluster, expected) in [(3, end(geometry.kind())), (5, 6),
            (6, end(geometry.kind())), (300, 301), (301, end(geometry.kind()))]
        {
            let mut raw = [0; 4];
            raw[..width].copy_from_slice(&device.bytes(
                BASE + geometry.entry_offset(copy, cluster).unwrap(), width));
            assert_eq!(u32::from_le_bytes(raw) & end(geometry.kind()), expected);
        }
    }
    assert_eq!(device.bytes(BASE + geometry.cluster_offset(5).unwrap(), PAYLOAD.len()), PAYLOAD);
}

#[test]
fn identical_reports_cannot_authorize_freeing_a_newly_live_chain() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for sector in [512, 4096] {
            let (device, args, geometry) = swap_fixture(kind, sector);
            let cx = Cx::for_testing();
            let diagnostic = device.diagnostic(&cx, &args);
            let plan = Plan::prepare(&cx, &diagnostic, true, false).unwrap();
            assert_eq!(plan.lost.iter().map(|&(cluster, _)| cluster).collect::<Vec<_>>(), [3, 300, 301]);
            select_other_chain(&device, &geometry);
            assert_eq!(serde_json::to_value(diagnostic.report(&cx).unwrap()).unwrap(),
                serde_json::to_value(&plan.before).unwrap(), "counts and examples are not authority");
            let before = device.state.lock().unwrap().image();
            device.arm(None);
            let error = plan.execute(&cx, &diagnostic).unwrap_err();
            assert!(format!("{error:#}").contains("unreachable allocation changed"));
            assert_eq!(device.state.lock().unwrap().attempts, 0);
            assert_eq!(device.state.lock().unwrap().image(), before);
            assert_links_retained(&device, &geometry);
        }
    }
}

#[test]
fn identical_lost_counts_do_not_hide_changed_orphan_successors() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let (device, args, geometry) = swap_fixture(kind, 512);
        let cx = Cx::for_testing();
        let diagnostic = device.diagnostic(&cx, &args);
        let plan = Plan::prepare(&cx, &diagnostic, true, false).unwrap();
        links(&device, &geometry, &[(300, end(kind)), (301, 300)]);
        assert_eq!(serde_json::to_value(diagnostic.report(&cx).unwrap()).unwrap(),
            serde_json::to_value(&plan.before).unwrap());
        let before = device.state.lock().unwrap().image();
        device.arm(None);
        assert!(plan.execute(&cx, &diagnostic).is_err());
        // A late expected-value mismatch while freeing would be too late:
        // cluster 3 is in an earlier FAT sector and might already be released.
        assert_eq!(device.state.lock().unwrap().attempts, 0);
        assert_eq!(device.state.lock().unwrap().image(), before);
    }
}

struct NamespaceAfterSync {
    device: Device,
    geometry: FatGeometry,
    unreadable: bool,
    synced: AtomicBool,
}

impl ByteDevice for NamespaceAfterSync {
    fn len_bytes(&self) -> u64 { self.device.len_bytes() }

    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        let record = root(&self.geometry);
        if self.unreadable && self.synced.load(Ordering::SeqCst)
            && at.0 <= record && record < at.0 + bytes.len() as u64
        {
            return Err(std::io::Error::other("namespace became unreadable after dirty barrier").into());
        }
        self.device.read_exact_at(cx, at, bytes)
    }

    fn write_all_at(&self, cx: &Cx, at: ByteOffset, bytes: &[u8]) -> ffs_error::Result<()> {
        self.device.write_all_at(cx, at, bytes)
    }

    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        self.device.sync(cx)?;
        if !self.synced.swap(true, Ordering::SeqCst) && !self.unreadable {
            select_other_chain(&self.device, &self.geometry);
        }
        Ok(())
    }
}

#[test]
fn ownership_is_rebuilt_after_the_dirty_barrier_before_any_cluster_is_freed() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for unreadable in [false, true] {
            let (device, args, geometry) = swap_fixture(kind, 512);
            let cx = Cx::for_testing();
            let diagnostic = DiagnosticVolume::from_device(&cx, Box::new(NamespaceAfterSync {
                device: device.clone(), geometry: geometry.clone(), unreadable,
                synced: AtomicBool::new(false),
            }), &args).unwrap();
            let plan = Plan::prepare(&cx, &diagnostic, true, false).unwrap();
            device.arm(None);
            let error = plan.execute(&cx, &diagnostic).unwrap_err();
            assert!(format!("{error:#}").contains("revalidating unreachable allocation"), "{error:#}");
            assert_links_retained(&device, &geometry);
            let state = device.state.lock().unwrap();
            assert!(state.syncs > 0);
            // No write to either FAT sector containing clusters 300 and 301.
            for event in &state.events {
                if let Event::Write(at, length) = event {
                    for copy in 0..geometry.fat_count() {
                        let lost = BASE + geometry.entry_offset(copy, 300).unwrap();
                        assert!(!(*at <= lost && lost < *at + *length as u64));
                    }
                }
            }
        }
    }
}

#[test]
fn a_previously_clean_plan_does_not_report_success_after_new_damage() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let (device, args, geometry) = fixture(kind, 512, false);
        links(&device, &geometry, &[(300, 0), (301, 0)]);
        let cx = Cx::for_testing();
        let diagnostic = device.diagnostic(&cx, &args);
        let plan = Plan::prepare(&cx, &diagnostic, false, false).unwrap();
        assert!(plan.before.clean);
        device.arm(None);
        assert_eq!(plan.execute(&cx, &diagnostic).unwrap()["changed"], false);
        assert_eq!(device.state.lock().unwrap().attempts, 0);
        links(&device, &geometry, &[(300, end(kind))]);
        let before = device.state.lock().unwrap().image();
        device.arm(None);
        assert!(plan.execute(&cx, &diagnostic).is_err());
        assert_eq!(device.state.lock().unwrap().attempts, 0);
        assert_eq!(device.state.lock().unwrap().image(), before);
    }
}

#[test]
fn a_clean_noop_still_revalidates_primary_geometry() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let (device, args, geometry) = fixture(kind, 512, false);
        links(&device, &geometry, &[(300, 0), (301, 0)]);
        let cx = Cx::for_testing();
        let diagnostic = device.diagnostic(&cx, &args);
        let plan = Plan::prepare(&cx, &diagnostic, false, false).unwrap();
        assert!(plan.before.clean);
        device.state.lock().unwrap().put(BASE + 13, &[2]);
        device.state.lock().unwrap().persist();
        let before = device.state.lock().unwrap().image();
        device.arm(None);
        assert!(plan.execute(&cx, &diagnostic).is_err());
        assert_eq!(device.state.lock().unwrap().attempts, 0);
        assert_eq!(device.state.lock().unwrap().image(), before);
    }
}
