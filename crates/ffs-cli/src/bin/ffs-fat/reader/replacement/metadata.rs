//! Ordered native metadata publication, sharing the file writer's dirty markers.
//! A failed mutation is not rolled back or falsely marked clean. Native sector
//! atomicity is not assumed; interrupted writes still require native recovery.

use super::{
    FatVolume, allocate, checkpoint, modified_timestamp, set_dirty, validate_boot_state,
    write_volume,
};
use anyhow::{Context, Result, anyhow, bail};
use asupersync::Cx;
use ffs_ondisk::fat::FatKind;

/// Validate every selected FAT's reserved clean/error state before any writes.
/// The allocation checker deliberately ignores dirty bits so it can also check
/// a writer's completed, not-yet-clean transaction; admission must not ignore them.
fn validate_reserved_state(cx: &Cx, volume: &FatVolume) -> Result<()> {
    let width = volume.geometry.kind().entry_bytes() as usize;
    let mask = match volume.geometry.kind() {
        FatKind::Fat16 => 0xFFFF,
        FatKind::Fat32 => 0x0FFF_FFFF,
    };
    for copy in volume.copies() {
        let offset = volume
            .geometry
            .entry_offset(copy, 2)
            .map_err(|error| anyhow!("{error}"))?
            - width as u64;
        let mut bytes = [0; 4];
        volume.read_exact(cx, offset, &mut bytes[..width])?;
        let raw = u32::from_le_bytes(bytes);
        if raw & mask != mask {
            bail!("metadata update requires clean, error-free reserved FAT state in copy {copy}");
        }
    }
    Ok(())
}

pub fn set_attr_in_volume(
    cx: &Cx,
    volume: &FatVolume,
    path: &str,
    read_only: Option<bool>,
    mtime_secs: Option<u64>,
    atime_secs: Option<u64>,
) -> Result<()> {
    checkpoint(cx)?;
    let entry = volume
        .resolve(cx, path)?
        .ok_or_else(|| anyhow!("cannot modify root directory entry attributes"))?;
    if entry.native.attributes & 0xC8 != 0 {
        bail!("unsupported native attributes on metadata target");
    }
    let mut original = [0; 32];
    volume.read_exact(cx, entry.offset, &mut original)?;
    let mut updated = original;
    if let Some(ro) = read_only {
        updated[11] = (updated[11] & !1) | u8::from(ro);
    }
    // Encode every requested field before dirty publication. An invalid later
    // timestamp must not leave an earlier permission or time update behind.
    if let Some(secs) = mtime_secs {
        let (date, time) = modified_timestamp(secs.max(315_532_800))?;
        updated[22..24].copy_from_slice(&time.to_le_bytes());
        updated[24..26].copy_from_slice(&date.to_le_bytes());
    }
    if let Some(secs) = atime_secs {
        let (date, _) = modified_timestamp(secs.max(315_532_800))?;
        updated[18..20].copy_from_slice(&date.to_le_bytes());
    }
    if updated == original {
        checkpoint(cx)?;
        return Ok(());
    }
    validate_boot_state(cx, volume)?;
    validate_reserved_state(cx, volume)?;
    let before = volume.check(cx)?;
    if !before.clean || !before.complete || !before.namespace_complete {
        bail!(
            "metadata update requires a complete clean allocation/namespace check: {}",
            serde_json::to_string(&before)?
        );
    }
    let sector_bytes = u64::from(volume.geometry.sector_bytes());
    let start = entry.offset / sector_bytes * sector_bytes;
    let within = (entry.offset - start) as usize;
    let mut sector = allocate(sector_bytes as usize)?;
    let mut verified = allocate(sector_bytes as usize)?;
    volume.read_exact(cx, start, &mut sector)?;
    if sector[within..within + 32] != original {
        bail!("metadata target changed before dirty publication");
    }
    let mut phase = "publishing dirty state";
    let result = (|| -> Result<()> {
        set_dirty(cx, volume, true)?;
        volume.device.sync(cx)?;
        phase = "publishing the metadata directory entry";
        // Read the full sector again, retaining all neighboring directory/LFN
        // records. Only the target's supported native fields may be changed.
        volume.read_exact(cx, start, &mut sector)?;
        if sector[within..within + 32] != original {
            bail!("metadata target changed after dirty publication");
        }
        sector[within..within + 32].copy_from_slice(&updated);
        write_volume(cx, volume, start, &sector)?;
        volume.device.sync(cx)?;
        phase = "verifying published metadata";
        volume.read_exact(cx, start, &mut verified)?;
        if verified != sector {
            bail!("metadata sector readback differs from the prepared publication");
        }
        let after = volume.check(cx)?;
        if !after.clean
            || !after.complete
            || !after.namespace_complete
            || after.free_clusters != before.free_clusters
            || after.allocated_clusters != before.allocated_clusters
            || after.files != before.files
            || after.directories != before.directories
        {
            bail!("metadata update changed allocation or namespace consistency");
        }
        phase = "synchronizing final clean state";
        set_dirty(cx, volume, false)?;
        volume.device.sync(cx)?;
        Ok(())
    })();
    result.with_context(|| {
        format!(
            "FAT metadata update failed while {phase}; image retained and may be dirty or partially changed; no rollback or atomicity is claimed"
        )
    })
}

companion_bin_tests! {
#[cfg(test)]
mod tests {
    use super::super::{create_in_volume, open_volume};
    use super::*;
    use ffs_block::ByteDevice;
    use ffs_error::FfsError;
    use ffs_types::ByteOffset;
    use std::sync::{Arc, Mutex};

    const NOW: u64 = 1_700_000_000;

    #[derive(Clone, Debug)]
    enum Event {
        Write(u64, Vec<u8>),
        Sync,
    }

    #[derive(Default)]
    struct Trace {
        events: Vec<Event>,
        fail_at: Option<usize>,
        torn_prefix: Option<usize>,
    }

    struct TracedDevice {
        inner: Box<dyn ByteDevice>,
        trace: Arc<Mutex<Trace>>,
    }

    impl TracedDevice {
        fn event(&self, event: Event) -> ffs_error::Result<()> {
            let mut trace = self.trace.lock().unwrap();
            trace.events.push(event);
            if trace.fail_at == Some(trace.events.len()) {
                return Err(std::io::Error::other("injected metadata I/O failure").into());
            }
            Ok(())
        }
    }

    impl ByteDevice for TracedDevice {
        fn len_bytes(&self) -> u64 {
            self.inner.len_bytes()
        }

        fn read_exact_at(
            &self,
            cx: &Cx,
            offset: ByteOffset,
            bytes: &mut [u8],
        ) -> ffs_error::Result<()> {
            self.inner.read_exact_at(cx, offset, bytes)
        }

        fn write_all_at(
            &self,
            cx: &Cx,
            offset: ByteOffset,
            bytes: &[u8],
        ) -> ffs_error::Result<()> {
            checkpoint(cx)?;
            if let Err(error) = self.event(Event::Write(offset.0, bytes.to_vec())) {
                let torn = self.trace.lock().unwrap().torn_prefix;
                if let Some(length) = torn {
                    self.inner.write_all_at(cx, offset, &bytes[..length.min(bytes.len())])?;
                }
                return Err(error);
            }
            self.inner.write_all_at(cx, offset, bytes)
        }

        fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
            checkpoint(cx)?;
            self.event(Event::Sync)?;
            self.inner.sync(cx)
        }
    }

    fn fixture(kind: &str) -> (tempfile::TempDir, FatVolume, Arc<Mutex<Trace>>) {
        use clap::Parser as _;

        let cx = Cx::for_testing();
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("metadata.fat");
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
            panic!("expected formatter options");
        };
        crate::formatter::create(&cx, &options).unwrap();
        let args = crate::reader::ImageArgs {
            image,
            offset: 0,
            length: None,
            oem_code_page: ffs_ondisk::fat::FatOemCodePage::Ascii,
            sidecar: None,
        };
        let volume = open_volume(&cx, &args, true).unwrap();
        create_in_volume(&cx, &volume, "/entry.bin", b"unchanged payload", NOW, false)
            .unwrap();
        create_in_volume(&cx, &volume, "/neighbor.bin", b"neighbor", NOW, false).unwrap();
        let length = volume.device.len_bytes();
        let trace = Arc::new(Mutex::new(Trace::default()));
        let volume = FatVolume::from_device(
            &cx,
            Box::new(TracedDevice {
                inner: volume.device,
                trace: trace.clone(),
            }),
            0,
            length,
        )
        .unwrap();
        (dir, volume, trace)
    }

    fn raw_entry(cx: &Cx, volume: &FatVolume, path: &str) -> (u64, [u8; 32]) {
        let entry = volume.resolve(cx, path).unwrap().unwrap();
        let mut bytes = [0; 32];
        volume.read_exact(cx, entry.offset, &mut bytes).unwrap();
        (entry.offset, bytes)
    }

    #[test]
    fn metadata_preserves_allocation_payload_neighbors_and_orders_barriers() {
        for kind in ["fat16", "fat32"] {
            let (_dir, volume, trace) = fixture(kind);
            let cx = Cx::for_testing();
            let (offset, before) = raw_entry(&cx, &volume, "/entry.bin");
            let neighbor = raw_entry(&cx, &volume, "/neighbor.bin");
            let free = volume.free_clusters(&cx).unwrap();
            set_attr_in_volume(
                &cx, &volume, "/entry.bin", Some(true), Some(NOW + 86400), Some(NOW),
            )
            .unwrap();
            let (_, after) = raw_entry(&cx, &volume, "/entry.bin");
            let mut expected = before;
            expected[11] |= 1;
            let (date, time) = modified_timestamp(NOW + 86400).unwrap();
            expected[22..24].copy_from_slice(&time.to_le_bytes());
            expected[24..26].copy_from_slice(&date.to_le_bytes());
            expected[18..20].copy_from_slice(&modified_timestamp(NOW).unwrap().0.to_le_bytes());
            assert_eq!(after, expected);
            assert_eq!(raw_entry(&cx, &volume, "/neighbor.bin"), neighbor);
            assert_eq!(volume.free_clusters(&cx).unwrap(), free);
            let entry = volume.resolve(&cx, "/entry.bin").unwrap().unwrap();
            let chain = volume.file_chain(&cx, &entry).unwrap();
            assert_eq!(volume.read(&cx, &chain, 0, 64).unwrap(), b"unchanged payload");
            validate_boot_state(&cx, &volume).unwrap();
            validate_reserved_state(&cx, &volume).unwrap();
            let events = trace.lock().unwrap().events.clone();
            let sector = offset / 512 * 512;
            let publication = events
                .iter()
                .position(|event| matches!(event, Event::Write(at, _) if *at == sector))
                .unwrap();
            assert!(matches!(events[publication - 1], Event::Sync));
            assert!(matches!(events[publication + 1], Event::Sync));
            assert!(matches!(events.last(), Some(Event::Sync)));
            for event in &events {
                if let Event::Write(at, bytes) = event {
                    assert_eq!(at % 512, 0);
                    assert_eq!(bytes.len(), 512);
                }
            }
        }
    }

    #[test]
    fn invalid_noop_cancelled_and_dirty_metadata_requests_never_write() {
        let (_dir, volume, trace) = fixture("fat32");
        let cx = Cx::for_testing();
        set_attr_in_volume(&cx, &volume, "/entry.bin", None, None, None).unwrap();
        set_attr_in_volume(&cx, &volume, "/entry.bin", Some(false), Some(NOW), None)
            .unwrap();
        assert!(set_attr_in_volume(
            &cx, &volume, "/entry.bin", Some(true), Some(NOW), Some(u64::MAX),
        )
        .is_err());
        cx.set_cancel_requested(true);
        assert!(set_attr_in_volume(&cx, &volume, "/entry.bin", Some(true), None, None)
            .unwrap_err()
            .downcast_ref::<FfsError>()
            .is_some_and(|error| matches!(error, FfsError::Cancelled)));
        assert!(trace.lock().unwrap().events.is_empty());
        let cx = Cx::for_testing();
        set_dirty(&cx, &volume, true).unwrap();
        trace.lock().unwrap().events.clear();
        assert!(set_attr_in_volume(&cx, &volume, "/entry.bin", Some(true), None, None)
            .is_err());
        assert!(trace.lock().unwrap().events.is_empty());
    }

    #[test]
    fn metadata_stops_at_every_injected_write_or_sync_failure() {
        let (_dir, volume, trace) = fixture("fat16");
        let cx = Cx::for_testing();
        set_attr_in_volume(&cx, &volume, "/entry.bin", Some(true), None, None).unwrap();
        let operations = trace.lock().unwrap().events.len();
        assert!(operations > 3);
        for fail_at in 1..=operations {
            let (_dir, volume, trace) = fixture("fat16");
            trace.lock().unwrap().fail_at = Some(fail_at);
            let error = set_attr_in_volume(
                &cx, &volume, "/entry.bin", Some(true), None, None,
            )
            .unwrap_err();
            assert!(error.to_string().contains("no rollback or atomicity is claimed"));
            assert_eq!(trace.lock().unwrap().events.len(), fail_at);
            let entry = volume.resolve(&cx, "/entry.bin").unwrap().unwrap();
            let chain = volume.file_chain(&cx, &entry).unwrap();
            assert_eq!(volume.read(&cx, &chain, 0, 64).unwrap(), b"unchanged payload");
        }
    }

    #[test]
    fn dirty_fat_reserved_state_is_rejected_before_changing_clean_boot_copies() {
        let (_dir, volume, trace) = fixture("fat32");
        let cx = Cx::for_testing();
        let original = raw_entry(&cx, &volume, "/entry.bin");
        let copy = volume.copies().next().unwrap();
        let offset = volume.geometry.entry_offset(copy, 2).unwrap() - 4;
        let mut bytes = [0; 4];
        volume.read_exact(&cx, offset, &mut bytes).unwrap();
        let dirty = u32::from_le_bytes(bytes) & !0x0800_0000;
        write_volume(&cx, &volume, offset, &dirty.to_le_bytes()).unwrap();
        trace.lock().unwrap().events.clear();
        assert!(set_attr_in_volume(&cx, &volume, "/entry.bin", Some(true), None, None)
            .is_err());
        assert!(trace.lock().unwrap().events.is_empty());
        validate_boot_state(&cx, &volume).unwrap();
        assert_eq!(raw_entry(&cx, &volume, "/entry.bin"), original);
    }

    #[test]
    fn torn_metadata_sector_never_clears_dirty_markers() {
        let (_dir, volume, trace) = fixture("fat32");
        let cx = Cx::for_testing();
        let (offset, _) = raw_entry(&cx, &volume, "/entry.bin");
        set_attr_in_volume(&cx, &volume, "/entry.bin", Some(true), None, None).unwrap();
        let sector = offset / 512 * 512;
        let publication = trace
            .lock()
            .unwrap()
            .events
            .iter()
            .position(|event| matches!(event, Event::Write(at, _) if *at == sector))
            .unwrap();
        let (_dir, volume, trace) = fixture("fat32");
        {
            let mut trace = trace.lock().unwrap();
            trace.fail_at = Some(publication + 1);
            trace.torn_prefix = Some((offset % 512) as usize + 12);
        }
        assert!(set_attr_in_volume(
            &cx, &volume, "/entry.bin", Some(true), Some(NOW + 86400), None,
        )
        .is_err());
        assert_eq!(trace.lock().unwrap().events.len(), publication + 1);
        assert!(validate_boot_state(&cx, &volume).is_err());
        assert!(validate_reserved_state(&cx, &volume).is_err());
    }

    #[test]
    fn readonly_creation_never_publishes_a_writable_directory_entry() {
        let (_dir, volume, trace) = fixture("fat32");
        let cx = Cx::for_testing();
        create_in_volume(&cx, &volume, "/readonly.bin", b"protected", NOW, true).unwrap();
        let (offset, entry) = raw_entry(&cx, &volume, "/readonly.bin");
        assert_eq!(entry[11] & 1, 1);
        let trace = trace.lock().unwrap();
        let mut published = 0;
        for event in &trace.events {
            if let Event::Write(at, bytes) = event
                && *at <= offset
                && offset + 32 <= *at + bytes.len() as u64
            {
                let within = (offset - at) as usize;
                let record = &bytes[within..within + 32];
                if record[..11] == entry[..11] {
                    published += 1;
                    assert_eq!(record[11] & 1, 1);
                }
            }
        }
        assert_eq!(published, 1);
    }
}
}
