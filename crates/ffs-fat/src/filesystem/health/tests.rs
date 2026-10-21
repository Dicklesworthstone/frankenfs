//! Exercise the real native writer and FsOps cache publication with injected
//! device errors and cancellation. No hardware power-loss result is implied.

use super::super::{FatFs, FatVolume, FsOps, InodeNumber, ROOT, RequestScope, SetAttrRequest};
use super::*;
use clap::Parser as _;
use ffs_block::ByteDevice;
use ffs_types::ByteOffset;
use std::ffi::OsStr;
use std::sync::Mutex;

struct Storage {
    bytes: Vec<u8>,
    reads: u64,
    writes: u64,
    syncs: u64,
    fail_write: bool,
    fail_sync: bool,
    fail_read: bool,
    cancel_after_clean: bool,
    fail_read_after_clean: bool,
    state_offset: usize,
}

#[derive(Clone)]
struct Device(Arc<Mutex<Storage>>);

impl Device {
    fn counts(&self) -> (u64, u64, u64) {
        let state = self.0.lock().unwrap();
        (state.reads, state.writes, state.syncs)
    }

    fn open(&self) -> FatVolume {
        FatVolume::from_device(
            &Cx::for_testing(),
            Box::new(self.clone()),
            0,
            self.len_bytes(),
        )
        .unwrap()
    }
}

impl ByteDevice for Device {
    fn len_bytes(&self) -> u64 {
        self.0.lock().unwrap().bytes.len() as u64
    }

    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        let mut state = self.0.lock().unwrap();
        state.reads += 1;
        if std::mem::take(&mut state.fail_read) {
            return Err(std::io::Error::other("injected cache-publication read failure").into());
        }
        let start = usize::try_from(at.0).unwrap();
        let end = start.checked_add(bytes.len()).unwrap();
        bytes.copy_from_slice(state.bytes.get(start..end).unwrap());
        Ok(())
    }

    fn write_all_at(&self, cx: &Cx, at: ByteOffset, bytes: &[u8]) -> Result<()> {
        checkpoint(cx)?;
        let mut state = self.0.lock().unwrap();
        state.writes += 1;
        let fail = std::mem::take(&mut state.fail_write);
        let count = if fail {
            bytes.len().min(17)
        } else {
            bytes.len()
        };
        let start = usize::try_from(at.0).unwrap();
        state.bytes[start..start + count].copy_from_slice(&bytes[..count]);
        if fail {
            return Err(std::io::Error::other("injected partial write failure").into());
        }
        Ok(())
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        checkpoint(cx)?;
        let mut state = self.0.lock().unwrap();
        state.syncs += 1;
        if std::mem::take(&mut state.fail_sync) {
            return Err(std::io::Error::other("injected synchronization failure").into());
        }
        if state.bytes[state.state_offset] & 1 == 0 {
            if std::mem::take(&mut state.cancel_after_clean) {
                // Return success from the native final sync, then interrupt the
                // mount adapter before it can refresh cached entry/chain state.
                cx.set_cancel_requested(true);
            }
            if std::mem::take(&mut state.fail_read_after_clean) {
                state.fail_read = true;
            }
        }
        Ok(())
    }
}

fn fixture(kind: &str, writable: bool) -> (FatFs, Device, InodeNumber) {
    let cx = Cx::for_testing();
    let directory = tempfile::tempdir().unwrap();
    let image = directory.path().join("health.fat");
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
        panic!("expected format options");
    };
    crate::formatter::create(&cx, &options).unwrap();
    let device = Device(Arc::new(Mutex::new(Storage {
        bytes: std::fs::read(image).unwrap(),
        reads: 0,
        writes: 0,
        syncs: 0,
        fail_write: false,
        fail_sync: false,
        fail_read: false,
        cancel_after_clean: false,
        fail_read_after_clean: false,
        state_offset: if kind == "fat16" { 37 } else { 65 },
    })));
    let volume = device.open();
    crate::reader::replacement::create_in_volume(
        &cx,
        &volume,
        "/file.bin",
        b"original",
        1_700_000_000,
        false,
    )
    .unwrap();
    crate::reader::replacement::mkdir_in_volume(&cx, &volume, "/empty", 1_700_000_000, false)
        .unwrap();
    let fs = FatFs::new_with_mode(&cx, volume, 1000, 1000, writable).unwrap();
    let ino = fs
        .lookup(
            &cx,
            &mut RequestScope::empty(),
            ROOT,
            OsStr::new("file.bin"),
        )
        .unwrap()
        .ino;
    assert_eq!(
        fs.read(&cx, &mut RequestScope::empty(), ino, 0, 8).unwrap(),
        b"original"
    );
    fs.statfs(&cx, &mut RequestScope::empty(), ROOT).unwrap();
    (fs, device, ino)
}

fn assert_quarantined(fs: &FatFs, device: &Device, ino: InodeNumber) {
    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    let before = device.counts();
    assert!(matches!(
        fs.getattr(&cx, &mut scope, ino),
        Err(FfsError::Io(_))
    ));
    assert!(matches!(
        fs.read(&cx, &mut scope, ino, 0, 8),
        Err(FfsError::Io(_))
    ));
    assert!(matches!(
        fs.lookup(&cx, &mut scope, ROOT, OsStr::new("file.bin")),
        Err(FfsError::Io(_))
    ));
    assert!(matches!(
        fs.readdir(&cx, &mut scope, ROOT, 0),
        Err(FfsError::Io(_))
    ));
    assert!(matches!(
        fs.statfs(&cx, &mut scope, ROOT),
        Err(FfsError::Io(_))
    ));
    assert!(matches!(
        fs.write(&cx, &mut scope, ino, 0, b"unsafe"),
        Err(FfsError::Io(_))
    ));
    assert!(matches!(
        fs.fallocate(&cx, &mut scope, ino, 0, 4096, 0),
        Err(FfsError::Io(_))
    ));
    assert!(matches!(
        fs.rename2(
            &cx,
            &mut scope,
            ROOT,
            OsStr::new("file.bin"),
            ROOT,
            OsStr::new("no.bin"),
            libc::RENAME_NOREPLACE,
        ),
        Err(FfsError::Io(_))
    ));
    assert!(matches!(
        fs.create(
            &cx,
            &mut scope,
            ROOT,
            OsStr::new("no.bin"),
            0o644,
            1000,
            1000
        ),
        Err(FfsError::Io(_))
    ));
    assert!(matches!(
        fs.unlink(&cx, &mut scope, ROOT, OsStr::new("file.bin")),
        Err(FfsError::Io(_))
    ));
    assert!(matches!(
        fs.flush(&cx, &mut scope, ino, 0, 0),
        Err(FfsError::Io(_))
    ));
    assert!(matches!(
        fs.fsync(&cx, &mut scope, ino, 0, false),
        Err(FfsError::Io(_))
    ));
    assert!(matches!(
        fs.fsyncdir(&cx, &mut scope, ROOT, 0, false),
        Err(FfsError::Io(_))
    ));
    assert!(matches!(fs.flush_on_destroy(&cx), Err(FfsError::Io(_))));
    assert_eq!(
        device.counts(),
        before,
        "quarantine must precede cached access and device I/O"
    );
}

#[test]
fn completed_and_no_write_requests_do_not_latch_but_failed_publication_does() {
    let cx = Cx::for_testing();
    let epoch = Arc::new(AtomicU64::new(0));
    let health = MountHealth::new(Arc::clone(&epoch));
    let gate = RwLock::new(());
    drop(health.operation(&cx, &gate, true).unwrap());
    assert!(!health.failed.load(Ordering::Acquire));
    let success = health.operation(&cx, &gate, true).unwrap();
    epoch.fetch_add(1, Ordering::AcqRel);
    success.complete(()).unwrap();
    assert!(!health.failed.load(Ordering::Acquire));
    let failed = health.operation(&cx, &gate, true).unwrap();
    epoch.fetch_add(1, Ordering::AcqRel);
    assert!(matches!(
        gate.try_read(),
        Err(std::sync::TryLockError::WouldBlock)
    ));
    drop(failed);
    assert!(health.failed.load(Ordering::Acquire));
    assert!(gate.try_write().is_ok(), "not dependent on panic poisoning");
    assert!(health.operation(&cx, &gate, false).is_err());
    assert!(health.operation(&cx, &gate, true).is_err());
}

#[test]
fn native_preflight_errors_allow_following_valid_mutations() {
    let (fs, device, ino) = fixture("fat16", true);
    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    let before = device.counts();
    assert!(matches!(
        fs.write(&cx, &mut scope, ino, u64::from(u32::MAX) - 1, b"x"),
        Err(FfsError::NoSpace)
    ));
    assert!(fs.write(&cx, &mut scope, ino, u64::MAX, b"x").is_err());
    assert!(
        fs.setattr(
            &cx,
            &mut scope,
            ino,
            &SetAttrRequest {
                mode: Some(0o600),
                size: Some(0),
                ..Default::default()
            }
        )
        .is_err()
    );
    let cancelled = Cx::for_testing();
    cancelled.set_cancel_requested(true);
    assert!(matches!(
        fs.write(&cancelled, &mut scope, ino, 0, b"x"),
        Err(FfsError::Cancelled)
    ));
    let after = device.counts();
    assert_eq!((after.1, after.2), (before.1, before.2));
    assert_eq!(fs.read(&cx, &mut scope, ino, 0, 8).unwrap(), b"original");
    fs.write(&cx, &mut scope, ino, 0, b"accepted").unwrap();
    assert_eq!(fs.read(&cx, &mut scope, ino, 0, 8).unwrap(), b"accepted");
    assert!(fs.volume.check(&cx).unwrap().clean);
}

#[test]
fn actual_partial_write_and_sync_errors_stop_the_mount_before_further_io() {
    for kind in ["fat16", "fat32"] {
        for sync_failure in [false, true] {
            let (fs, device, ino) = fixture(kind, true);
            let cx = Cx::for_testing();
            if sync_failure {
                device.0.lock().unwrap().fail_sync = true;
                assert!(
                    fs.fsync(&cx, &mut RequestScope::empty(), ino, 0, false)
                        .is_err()
                );
            } else {
                device.0.lock().unwrap().fail_write = true;
                assert!(
                    fs.write(&cx, &mut RequestScope::empty(), ino, 0, b"partial")
                        .is_err()
                );
            }
            assert_quarantined(&fs, &device, ino);
        }
    }
}

#[test]
fn completed_native_growth_with_failed_cache_refresh_is_quarantined() {
    for kind in ["fat16", "fat32"] {
        for cancel in [false, true] {
            let (fs, device, ino) = fixture(kind, true);
            let cx = Cx::for_testing();
            let offset = u64::from(fs.volume.geometry.cluster_bytes()) + 7;
            {
                let mut state = device.0.lock().unwrap();
                state.cancel_after_clean = cancel;
                state.fail_read_after_clean = !cancel;
            }
            assert!(
                fs.write(&cx, &mut RequestScope::empty(), ino, offset, b"new")
                    .is_err()
            );
            // The old cache is deliberately still present: quarantine, not
            // guessed refresh/rollback, must prevent its subsequent use.
            assert_eq!(
                fs.state().unwrap().nodes[&ino]
                    .entry
                    .as_ref()
                    .unwrap()
                    .native
                    .size,
                8
            );
            assert_quarantined(&fs, &device, ino);
            let reopened = device.open();
            let fresh = Cx::for_testing();
            let check = reopened.check(&fresh).unwrap();
            assert!(check.clean && check.complete && check.namespace_complete);
            let entry = reopened.resolve(&fresh, "/file.bin").unwrap().unwrap();
            let chain = reopened.file_chain(&fresh, &entry).unwrap();
            let mut expected = b"original".to_vec();
            expected.resize(offset as usize, 0);
            expected.extend_from_slice(b"new");
            assert_eq!(
                reopened.read(&fresh, &chain, 0, expected.len()).unwrap(),
                expected
            );
        }
    }
}

#[test]
fn namespace_metadata_and_truncating_open_failures_share_the_health_gate() {
    for action in [
        "create", "mkdir", "rename", "unlink", "rmdir", "setattr", "open",
    ] {
        let (fs, device, ino) = fixture("fat16", true);
        let cx = Cx::for_testing();
        let mut scope = RequestScope::empty();
        device.0.lock().unwrap().cancel_after_clean = true;
        let result = match action {
            "create" => fs
                .create(
                    &cx,
                    &mut scope,
                    ROOT,
                    OsStr::new("new.bin"),
                    0o644,
                    1000,
                    1000,
                )
                .map(|_| ()),
            "mkdir" => fs
                .mkdir(
                    &cx,
                    &mut scope,
                    ROOT,
                    OsStr::new("newdir"),
                    0o755,
                    1000,
                    1000,
                )
                .map(|_| ()),
            "rename" => fs.rename(
                &cx,
                &mut scope,
                ROOT,
                OsStr::new("file.bin"),
                ROOT,
                OsStr::new("moved.bin"),
            ),
            "unlink" => fs.unlink(&cx, &mut scope, ROOT, OsStr::new("file.bin")),
            "rmdir" => fs.rmdir(&cx, &mut scope, ROOT, OsStr::new("empty")),
            "setattr" => fs
                .setattr(
                    &cx,
                    &mut scope,
                    ino,
                    &SetAttrRequest {
                        mode: Some(0o444),
                        ..Default::default()
                    },
                )
                .map(|_| ()),
            _ => fs
                .open(&cx, &mut scope, ino, libc::O_RDWR | libc::O_TRUNC)
                .map(|_| ()),
        };
        // Unlink/rmdir have no fallible cache refresh after their completed
        // native update. If they return success, their cache is already correct;
        // success is not retroactively changed by a pending cancellation.
        if result.is_ok() {
            assert!(matches!(action, "unlink" | "rmdir"));
            assert!(!fs.health.failed.load(Ordering::Acquire));
        } else {
            assert_quarantined(&fs, &device, ino);
        }
        let reopened = device.open();
        let check = reopened.check(&Cx::for_testing()).unwrap();
        assert!(check.clean && check.complete && check.namespace_complete);
    }
}

#[test]
fn readonly_sync_and_flush_do_not_add_backing_io() {
    let (fs, device, ino) = fixture("fat16", false);
    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    let before = device.counts();
    fs.fsync(&cx, &mut scope, ino, 0, false).unwrap();
    fs.fsyncdir(&cx, &mut scope, ROOT, 0, false).unwrap();
    fs.flush(&cx, &mut scope, ino, 0, 0).unwrap();
    fs.flush_on_destroy(&cx).unwrap();
    assert_eq!(device.counts(), before);
    assert_eq!(fs.health.epoch.load(Ordering::Acquire), 0);
}

#[test]
fn fallocate_failures_and_post_commit_cache_errors_use_the_existing_health_gate() {
    for kind in ["fat16", "fat32"] {
        for failure in 0..4 {
            let (fs, device, ino) = fixture(kind, true);
            let cx = Cx::for_testing();
            {
                let mut state = device.0.lock().unwrap();
                match failure {
                    0 => state.fail_write = true,
                    1 => state.fail_sync = true,
                    2 => state.fail_read_after_clean = true,
                    _ => state.cancel_after_clean = true,
                }
            }
            let offset = u64::from(fs.volume.geometry.cluster_bytes()) + 7;
            assert!(
                fs.fallocate(&cx, &mut RequestScope::empty(), ino, offset, 19, 0)
                    .is_err()
            );
            assert_quarantined(&fs, &device, ino);
            if failure >= 2 {
                // Publication completed; quarantine must not pretend it was
                // rolled back or serve the old eight-byte cache as current.
                let reopened = device.open();
                let fresh = Cx::for_testing();
                let entry = reopened.resolve(&fresh, "/file.bin").unwrap().unwrap();
                let chain = reopened.file_chain(&fresh, &entry).unwrap();
                let mut expected = b"original".to_vec();
                expected.resize((offset + 19) as usize, 0);
                assert_eq!(
                    reopened.read(&fresh, &chain, 0, expected.len()).unwrap(),
                    expected
                );
                assert!(reopened.check(&fresh).unwrap().clean);
            }
        }
    }
}

#[test]
fn noreplace_rename_failures_share_the_existing_mount_quarantine() {
    for kind in ["fat16", "fat32"] {
        for fail_after_publication in [false, true] {
            let (fs, device, ino) = fixture(kind, true);
            let cx = Cx::for_testing();
            {
                let mut state = device.0.lock().unwrap();
                if fail_after_publication {
                    state.fail_read_after_clean = true;
                } else {
                    state.fail_write = true;
                }
            }
            assert!(
                fs.rename2(
                    &cx,
                    &mut RequestScope::empty(),
                    ROOT,
                    OsStr::new("file.bin"),
                    ROOT,
                    OsStr::new("moved.bin"),
                    libc::RENAME_NOREPLACE,
                )
                .is_err()
            );
            assert_quarantined(&fs, &device, ino);
            if fail_after_publication {
                let reopened = device.open();
                let fresh = Cx::for_testing();
                assert!(matches!(
                    reopened.resolve(&fresh, "/file.bin"),
                    Err(FfsError::NotFound(_))
                ));
                let entry = reopened.resolve(&fresh, "/moved.bin").unwrap().unwrap();
                let chain = reopened.file_chain(&fresh, &entry).unwrap();
                assert_eq!(reopened.read(&fresh, &chain, 0, 8).unwrap(), b"original");
                assert!(reopened.check(&fresh).unwrap().clean);
            }
        }
    }
}
