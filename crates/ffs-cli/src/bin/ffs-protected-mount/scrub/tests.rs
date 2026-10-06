use super::*;
use clap::Parser;
use ffs_repair::sidecar::{SidecarOptions, protect, verify};
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::sync::mpsc::{self, SyncSender};

#[derive(Debug, Clone, Copy)]
enum Fault {
    None,
    Error,
    Cancel,
    Panic,
    WaitForCancel,
}

#[derive(Debug)]
struct ProbeDevice {
    length: AtomicU64,
    reads: Mutex<Vec<(u64, usize)>>,
    fault: Fault,
    entered: Option<SyncSender<()>>,
}

impl ProbeDevice {
    fn new(length: u64) -> Self {
        Self {
            length: AtomicU64::new(length),
            reads: Mutex::new(Vec::new()),
            fault: Fault::None,
            entered: None,
        }
    }
}

impl ByteDevice for ProbeDevice {
    fn len_bytes(&self) -> u64 {
        self.length.load(Ordering::Acquire)
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> ffs_error::Result<()> {
        assert!(!buf.is_empty() && buf.len() <= READ_BYTES);
        assert!(offset.0 <= self.len_bytes() - u64::try_from(buf.len()).unwrap());
        self.reads.lock().unwrap().push((offset.0, buf.len()));
        if let Some(entered) = &self.entered {
            entered.send(()).unwrap();
        }
        assert!(!matches!(self.fault, Fault::Panic), "injected read panic");
        if matches!(self.fault, Fault::WaitForCancel) {
            loop {
                cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
                thread::yield_now();
            }
        }
        buf.fill(0x5A);
        if matches!(self.fault, Fault::Error) {
            return Err(FfsError::Io(std::io::Error::other("injected read failure")));
        }
        if matches!(self.fault, Fault::Cancel) {
            cx.set_cancel_requested(true);
        }
        Ok(())
    }

    fn write_all_at(&self, _: &Cx, _: ByteOffset, _: &[u8]) -> ffs_error::Result<()> {
        panic!("a source scrub must not write caller data");
    }

    fn sync(&self, _: &Cx) -> ffs_error::Result<()> {
        panic!("a source scrub must not publish a pending epoch");
    }
}

#[test]
fn source_pass_covers_exact_ranges_including_empty_and_short_tail() {
    for length in [
        0,
        1,
        READ_BYTES - 1,
        READ_BYTES,
        READ_BYTES + 1,
        3 * READ_BYTES + 17,
    ] {
        let length = u64::try_from(length).unwrap();
        let device = ProbeDevice::new(length);
        let mut pass = SourcePass::new(length).unwrap();
        while pass.step(&Cx::for_testing(), &device).unwrap() {}
        assert_eq!(pass.verified_bytes, length);
        let expected: Vec<_> = (0..length)
            .step_by(READ_BYTES)
            .map(|offset| {
                (
                    offset,
                    usize::try_from(length - offset).unwrap().min(READ_BYTES),
                )
            })
            .collect();
        assert_eq!(*device.reads.lock().unwrap(), expected);
        assert_eq!(pass.buffer.len(), READ_BYTES);
    }
}

#[test]
fn last_range_at_u64_limit_does_not_overflow() {
    let device = ProbeDevice::new(u64::MAX);
    let mut pass = SourcePass::new(u64::MAX).unwrap();
    pass.verified_bytes = u64::MAX - 7;
    assert!(pass.step(&Cx::for_testing(), &device).unwrap());
    assert_eq!(pass.verified_bytes, u64::MAX);
    assert!(!pass.step(&Cx::for_testing(), &device).unwrap());
    assert_eq!(*device.reads.lock().unwrap(), [(u64::MAX - 7, 7)]);
}

#[test]
fn failed_or_cancelled_read_never_advances_progress() {
    for cancel in [false, true] {
        let mut device = ProbeDevice::new(100);
        device.fault = if cancel { Fault::Cancel } else { Fault::Error };
        let mut pass = SourcePass::new(100).unwrap();
        let error = pass.step(&Cx::for_testing(), &device).unwrap_err();
        assert_eq!(pass.verified_bytes, 0);
        assert_eq!(device.reads.lock().unwrap().len(), 1);
        if cancel {
            assert!(matches!(
                error.downcast_ref::<FfsError>(),
                Some(FfsError::Cancelled)
            ));
        } else {
            assert!(format!("{error:#}").contains("injected read failure"));
        }
    }
}

#[test]
fn cancellation_and_geometry_changes_are_rejected_before_io() {
    let device = ProbeDevice::new(100);
    let mut pass = SourcePass::new(100).unwrap();
    let cx = Cx::for_testing();
    cx.set_cancel_requested(true);
    assert!(pass.step(&cx, &device).is_err());
    device.length.store(99, Ordering::Release);
    assert!(pass.step(&Cx::for_testing(), &device).is_err());
    assert!(device.reads.lock().unwrap().is_empty());
    assert_eq!(pass.verified_bytes, 0);
}

#[test]
fn worker_error_and_panic_request_unmount_and_survive_join() {
    for panic in [false, true] {
        let (entered, ready) = mpsc::sync_channel(1);
        let mut device = ProbeDevice::new(1);
        device.fault = if panic { Fault::Panic } else { Fault::Error };
        device.entered = Some(entered);
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut guard = ScrubGuard::spawn(
            &Cx::for_testing(),
            Arc::new(device),
            Arc::clone(&shutdown),
            Duration::from_secs(86_400),
            |_| panic!("failed scan must not emit a complete pass"),
        )
        .unwrap();
        ready.recv_timeout(Duration::from_secs(5)).unwrap();
        // Even if stop races the I/O failure, only cancellation may be ignored.
        let error = guard.stop().unwrap_err();
        assert!(shutdown.load(Ordering::Acquire));
        let expected = if panic {
            "panicked"
        } else {
            "injected read failure"
        };
        assert!(format!("{error:#}").contains(expected));
        guard.stop().unwrap();
    }
}

#[test]
fn worker_reports_complete_passes_and_restarts_from_zero() {
    let device = Arc::new(ProbeDevice::new(1));
    let shutdown = Arc::new(AtomicBool::new(false));
    let finish = Arc::clone(&shutdown);
    let (sent, reports) = mpsc::sync_channel(2);
    let mut guard = ScrubGuard::spawn(
        &Cx::for_testing(),
        device.clone(),
        shutdown,
        Duration::ZERO,
        move |report| {
            sent.send((report.completed_passes, report.source_bytes_verified))
                .unwrap();
            assert_eq!(report.consistency, "per_read_not_snapshot");
            if report.completed_passes == 2 {
                finish.store(true, Ordering::Release);
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(reports.recv_timeout(Duration::from_secs(5)).unwrap(), (1, 1));
    assert_eq!(reports.recv_timeout(Duration::from_secs(5)).unwrap(), (2, 1));
    guard.stop().unwrap();
    assert_eq!(*device.reads.lock().unwrap(), [(0, 1), (0, 1)]);
}

#[test]
fn failed_report_requests_unmount_instead_of_silent_scrub_loss() {
    let (sent, reported) = mpsc::sync_channel(1);
    let shutdown = Arc::new(AtomicBool::new(false));
    let mut guard = ScrubGuard::spawn(
        &Cx::for_testing(),
        Arc::new(ProbeDevice::new(1)),
        Arc::clone(&shutdown),
        Duration::from_secs(86_400),
        move |_| {
            sent.send(()).unwrap();
            bail!("injected evidence failure")
        },
    )
    .unwrap();
    reported.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(
        guard
            .stop()
            .unwrap_err()
            .to_string()
            .contains("evidence failure")
    );
    assert!(shutdown.load(Ordering::Acquire));
}

#[test]
fn dropping_worker_cancels_inflight_io_and_releases_ownership_before_returning() {
    let (entered, ready) = mpsc::sync_channel(1);
    let mut device = ProbeDevice::new(1);
    device.fault = Fault::WaitForCancel;
    device.entered = Some(entered);
    let device = Arc::new(device);
    let shutdown = Arc::new(AtomicBool::new(false));
    let guard = ScrubGuard::spawn(
        &Cx::for_testing(),
        device.clone(),
        Arc::clone(&shutdown),
        Duration::from_secs(86_400),
        |_| panic!("cancelled read must not emit a completed pass"),
    )
    .unwrap();
    ready.recv_timeout(Duration::from_secs(5)).unwrap();
    drop(guard);
    assert_eq!(Arc::strong_count(&device), 1);
    assert!(!shutdown.load(Ordering::Acquire));
}

#[test]
fn stopping_after_a_pass_does_not_wait_for_the_next_scan_interval() {
    let device = Arc::new(ProbeDevice::new(1));
    let shutdown = Arc::new(AtomicBool::new(false));
    let (sent, reports) = mpsc::sync_channel(1);
    let mut guard = ScrubGuard::spawn(
        &Cx::for_testing(),
        device.clone(),
        Arc::clone(&shutdown),
        Duration::from_secs(86_400),
        move |_| {
            sent.send(()).unwrap();
            Ok(())
        },
    )
    .unwrap();
    reports.recv_timeout(Duration::from_secs(5)).unwrap();
    guard.stop().unwrap();
    assert_eq!(Arc::strong_count(&device), 1);
    assert_eq!(*device.reads.lock().unwrap(), [(0, 1)]);
    assert!(!shutdown.load(Ordering::Acquire));
}

struct Fixture {
    _dir: tempfile::TempDir,
    image: PathBuf,
    sidecar: PathBuf,
    original: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("source.img");
        let sidecar = dir.path().join("source.ffsrq");
        let original: Vec<_> = (0..READ_BYTES * 2 + 37)
            .map(|index| u8::try_from((index * 31 + index / 512) % 251).unwrap())
            .collect();
        std::fs::write(&image, &original).unwrap();
        protect(
            &Cx::for_testing(),
            &image,
            &sidecar,
            SidecarOptions {
                block_size: 512,
                group_blocks: 8,
                repair_symbols: 4,
            },
        )
        .unwrap();
        Self {
            _dir: dir,
            image,
            sidecar,
            original,
        }
    }

    fn open(&self) -> SidecarImageDevice {
        SidecarImageDevice::open(&Cx::for_testing(), &self.image, &self.sidecar).unwrap()
    }

    fn damage(&self, offset: usize, len: usize) {
        let file = File::options().write(true).open(&self.image).unwrap();
        file.write_all_at(&vec![0xE7; len], u64::try_from(offset).unwrap())
            .unwrap();
        file.sync_all().unwrap();
    }

    fn scan(device: &SidecarImageDevice) -> Result<SourcePass> {
        let mut pass = SourcePass::new(device.len_bytes())?;
        while pass.step(&Cx::for_testing(), device)? {}
        Ok(pass)
    }
}

#[test]
fn source_scan_repairs_unread_blocks_and_partial_tail_without_republishing_archive() {
    let fixture = Fixture::new();
    let device = fixture.open();
    let archive = std::fs::read(&fixture.sidecar).unwrap();
    for (offset, len) in [(512, 512), (READ_BYTES + 512, 512), (READ_BYTES * 2, 37)] {
        fixture.damage(offset, len);
    }
    assert_ne!(std::fs::read(&fixture.image).unwrap(), fixture.original);
    let pass = Fixture::scan(&device).unwrap();
    assert_eq!(
        pass.verified_bytes,
        u64::try_from(fixture.original.len()).unwrap()
    );
    assert_eq!(std::fs::read(&fixture.image).unwrap(), fixture.original);
    assert_eq!(std::fs::read(&fixture.sidecar).unwrap(), archive);
    drop(device);
    // No scanner sync or explicit refresh: the read-repair path must persist it.
    assert!(
        verify(&Cx::for_testing(), &fixture.image, &fixture.sidecar)
            .unwrap()
            .is_healthy()
    );
    drop(fixture.open());
}

#[test]
fn dirty_epoch_scan_repairs_only_unchanged_groups_and_never_publishes_writes() {
    let fixture = Fixture::new();
    let device = fixture.open();
    let cx = Cx::for_testing();
    device
        .write_all_at(&cx, ByteOffset(0), &[0x53; 512])
        .unwrap();
    let pending = std::fs::read(&fixture.sidecar).unwrap();
    fixture.damage(READ_BYTES + 512, 512);
    Fixture::scan(&device).unwrap();
    let mut expected = fixture.original.clone();
    expected[..512].fill(0x53);
    assert_eq!(std::fs::read(&fixture.image).unwrap(), expected);
    assert_eq!(std::fs::read(&fixture.sidecar).unwrap(), pending);
    assert!(device.protection(&cx).is_err());
    drop(device);
    assert!(SidecarImageDevice::open(&cx, &fixture.image, &fixture.sidecar).is_err());
}

#[test]
fn changed_peer_forbids_scrub_rollback_and_preserves_the_pending_fence() {
    let fixture = Fixture::new();
    let device = fixture.open();
    device
        .write_all_at(&Cx::for_testing(), ByteOffset(0), &[0x53; 512])
        .unwrap();
    fixture.damage(512, 512);
    let image = std::fs::read(&fixture.image).unwrap();
    let pending = std::fs::read(&fixture.sidecar).unwrap();
    let error = Fixture::scan(&device).err().unwrap();
    assert!(format!("{error:#}").contains("old parity is not current"));
    assert_eq!(std::fs::read(&fixture.image).unwrap(), image);
    assert_eq!(std::fs::read(&fixture.sidecar).unwrap(), pending);
}

#[test]
fn insufficient_redundancy_never_returns_a_successful_source_pass() {
    let fixture = Fixture::new();
    let device = fixture.open();
    // Eight lost source blocks, only four repair symbols.
    fixture.damage(0, 8 * 512);
    let image = std::fs::read(&fixture.image).unwrap();
    let archive = std::fs::read(&fixture.sidecar).unwrap();
    assert!(Fixture::scan(&device).is_err());
    assert_eq!(std::fs::read(&fixture.image).unwrap(), image);
    assert_eq!(std::fs::read(&fixture.sidecar).unwrap(), archive);
}

#[test]
fn concurrent_epoch_change_between_steps_uses_new_protection_not_a_stale_snapshot() {
    let fixture = Fixture::new();
    let device = fixture.open();
    let cx = Cx::for_testing();
    let mut pass = SourcePass::new(device.len_bytes()).unwrap();
    assert!(pass.step(&cx, &device).unwrap());
    assert_eq!(pass.verified_bytes, u64::try_from(READ_BYTES).unwrap());
    let offset = READ_BYTES + 512;
    device
        .write_all_at(
            &cx,
            ByteOffset(u64::try_from(offset).unwrap()),
            &[0x53; 512],
        )
        .unwrap();
    device.sync(&cx).unwrap(); // Explicit writer barrier, NOT part of the scanner.
    let refreshed = std::fs::read(&fixture.sidecar).unwrap();
    fixture.damage(offset, 512);
    while pass.step(&cx, &device).unwrap() {}
    let mut expected = fixture.original.clone();
    expected[offset..offset + 512].fill(0x53);
    assert_eq!(std::fs::read(&fixture.image).unwrap(), expected);
    assert_eq!(std::fs::read(&fixture.sidecar).unwrap(), refreshed);
}

#[test]
fn command_scrub_option_is_explicit_bounded_and_requires_a_mount() {
    let base = [
        "ffs-protected-mount",
        "image",
        "archive",
        "mountpoint",
        "--exclusive-image",
        "--allow-repair",
    ];
    let defaults = crate::Args::try_parse_from(base).unwrap();
    assert!(defaults.scrub.interval_secs.is_none());
    for rw in [false, true] {
        let mut argv = base.to_vec();
        argv.extend(["--scrub-interval-secs", "300"]);
        if rw {
            argv.push("--rw");
        }
        let args = crate::Args::try_parse_from(argv).unwrap();
        assert_eq!(args.scrub.interval_secs, Some(300));
        args.scrub.validate(args.check).unwrap();
    }
    for seconds in ["0", "86401", "18446744073709551615", "invalid"] {
        assert!(
            crate::Args::try_parse_from(
                base.into_iter().chain(["--scrub-interval-secs", seconds])
            )
            .is_err()
        );
    }
    assert!(
        crate::Args::try_parse_from([
            "ffs-protected-mount",
            "image",
            "archive",
            "--check",
            "--exclusive-image",
            "--allow-repair",
            "--scrub-interval-secs",
            "300",
        ])
        .is_err()
    );
    assert!(
        Options {
            interval_secs: Some(300)
        }
        .validate(true)
        .is_err()
    );
    assert!(
        Options {
            interval_secs: Some(0)
        }
        .validate(false)
        .is_err()
    );
}

#[test]
fn background_worker_repairs_real_sidecar_source_without_a_foreground_read() {
    let fixture = Fixture::new();
    let device = Arc::new(fixture.open());
    let archive = std::fs::read(&fixture.sidecar).unwrap();
    fixture.damage(READ_BYTES + 512, 512);
    let shutdown = Arc::new(AtomicBool::new(false));
    let finish = Arc::clone(&shutdown);
    let (sent, reports) = mpsc::sync_channel(1);
    let mut guard = ScrubGuard::spawn(
        &Cx::for_testing(),
        device.clone(),
        shutdown,
        Duration::from_secs(86_400),
        move |report| {
            sent.send(report.source_bytes_verified).unwrap();
            finish.store(true, Ordering::Release);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        reports.recv_timeout(Duration::from_secs(30)).unwrap(),
        u64::try_from(fixture.original.len()).unwrap()
    );
    guard.stop().unwrap();
    assert_eq!(Arc::strong_count(&device), 1);
    assert_eq!(std::fs::read(&fixture.image).unwrap(), fixture.original);
    assert_eq!(std::fs::read(&fixture.sidecar).unwrap(), archive);
}
