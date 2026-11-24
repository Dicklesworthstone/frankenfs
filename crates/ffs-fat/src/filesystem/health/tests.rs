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
    cancel_after_dirty: bool,
    cancel_after_clean: bool,
    fail_sync_after_clean: bool,
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
                // Model ImageFile's cancellation point after a successful
                // physical barrier, before native/cache acknowledgment.
                cx.set_cancel_requested(true);
            }
            if std::mem::take(&mut state.fail_sync_after_clean) {
                state.fail_sync = true;
            }
            if std::mem::take(&mut state.fail_read_after_clean) {
                state.fail_read = true;
            }
        } else if std::mem::take(&mut state.cancel_after_dirty) {
            cx.set_cancel_requested(true);
        }
        checkpoint(cx)
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
        cancel_after_dirty: false,
        cancel_after_clean: false,
        fail_sync_after_clean: false,
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

fn assert_late_cancel_preserved(fs: &FatFs, device: &Device, cx: &Cx) {
    assert!(matches!(checkpoint(cx), Err(FfsError::Cancelled)));
    assert!(!fs.health.failed.load(Ordering::Acquire));
    let before = device.counts();
    assert!(matches!(
        fs.getattr(cx, &mut RequestScope::empty(), ROOT),
        Err(FfsError::Cancelled)
    ));
    assert_eq!(
        device.counts(),
        before,
        "the next request remains cancellable"
    );
}

fn assert_mounted_and_reopened_payload(
    fs: &FatFs,
    device: &Device,
    ino: InodeNumber,
    path: &str,
    expected: &[u8],
) {
    let fresh = Cx::for_testing();
    let mut scope = RequestScope::empty();
    assert_eq!(
        fs.getattr(&fresh, &mut scope, ino).unwrap().size,
        expected.len() as u64
    );
    assert_eq!(
        fs.read(&fresh, &mut scope, ino, 0, expected.len() as u32)
            .unwrap(),
        expected
    );
    let reopened = device.open();
    let check = reopened.check(&fresh).unwrap();
    assert!(check.clean && check.complete && check.namespace_complete);
    let entry = reopened.resolve(&fresh, path).unwrap().unwrap();
    let chain = reopened.file_chain(&fresh, &entry).unwrap();
    assert_eq!(
        reopened.read(&fresh, &chain, 0, expected.len()).unwrap(),
        expected
    );
    assert_eq!(
        fs.statfs(&fresh, &mut scope, ROOT).unwrap().blocks_free,
        reopened.free_clusters(&fresh).unwrap()
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
        // A pending late cancellation must not hide a genuine cache read error.
        for cancel in [false, true] {
            let (fs, device, ino) = fixture(kind, true);
            let cx = Cx::for_testing();
            let offset = u64::from(fs.volume.geometry.cluster_bytes()) + 7;
            {
                let mut state = device.0.lock().unwrap();
                state.cancel_after_clean = cancel;
                state.fail_read_after_clean = true;
            }
            assert!(matches!(
                fs.write(&cx, &mut RequestScope::empty(), ino, offset, b"new"),
                Err(FfsError::Io(_))
            ));
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
fn committed_growth_finishes_cache_publication_despite_late_cancellation() {
    for kind in ["fat16", "fat32"] {
        let (fs, device, ino) = fixture(kind, true);
        let cx = Cx::for_testing();
        let offset = u64::from(fs.volume.geometry.cluster_bytes()) + 7;
        device.0.lock().unwrap().cancel_after_clean = true;
        assert_eq!(
            fs.write(&cx, &mut RequestScope::empty(), ino, offset, b"new")
                .unwrap(),
            3
        );
        assert_late_cancel_preserved(&fs, &device, &cx);
        let mut expected = b"original".to_vec();
        expected.resize(offset as usize, 0);
        expected.extend_from_slice(b"new");
        assert_mounted_and_reopened_payload(&fs, &device, ino, "/file.bin", &expected);

        // A later, independent request can still use the committed chain.
        let fresh = Cx::for_testing();
        fs.write(&fresh, &mut RequestScope::empty(), ino, 0, b"accepted")
            .unwrap();
        expected[..8].copy_from_slice(b"accepted");
        assert_mounted_and_reopened_payload(&fs, &device, ino, "/file.bin", &expected);
    }
}

#[test]
fn cancellation_before_native_finalization_still_interrupts_and_quarantines() {
    for kind in ["fat16", "fat32"] {
        let (fs, device, ino) = fixture(kind, true);
        let cx = Cx::for_testing();
        device.0.lock().unwrap().cancel_after_dirty = true;
        assert!(matches!(
            fs.write(&cx, &mut RequestScope::empty(), ino, 0, b"new"),
            Err(FfsError::Cancelled)
        ));
        assert_quarantined(&fs, &device, ino);
        let fresh = Cx::for_testing();
        {
            let state = device.0.lock().unwrap();
            assert_ne!(state.bytes[state.state_offset] & 1, 0);
        }
        assert!(
            FatVolume::from_device(&fresh, Box::new(device.clone()), 0, device.len_bytes())
                .is_err(),
            "an interrupted dirty volume must fail fresh admission"
        );
        let entry = fs.volume.resolve(&fresh, "/file.bin").unwrap().unwrap();
        let chain = fs.volume.file_chain(&fresh, &entry).unwrap();
        assert_eq!(fs.volume.read(&fresh, &chain, 0, 8).unwrap(), b"original");
    }
}

#[test]
fn late_cancellation_does_not_hide_a_real_post_commit_sync_failure() {
    for kind in ["fat16", "fat32"] {
        let (fs, device, ino) = fixture(kind, true);
        let cx = Cx::for_testing();
        {
            let mut state = device.0.lock().unwrap();
            state.cancel_after_clean = true;
            state.fail_sync_after_clean = true;
        }
        assert!(matches!(
            fs.write(&cx, &mut RequestScope::empty(), ino, 0, b"accepted"),
            Err(FfsError::Io(_))
        ));
        assert_quarantined(&fs, &device, ino);
        let reopened = device.open();
        let fresh = Cx::for_testing();
        let check = reopened.check(&fresh).unwrap();
        assert!(check.clean && check.complete && check.namespace_complete);
        let entry = reopened.resolve(&fresh, "/file.bin").unwrap().unwrap();
        let chain = reopened.file_chain(&fresh, &entry).unwrap();
        assert_eq!(reopened.read(&fresh, &chain, 0, 8).unwrap(), b"accepted");
    }
}

#[test]
fn committed_namespace_metadata_and_truncation_survive_late_cancellation() {
    for kind in ["fat16", "fat32"] {
        for action in [
            "create", "mkdir", "rename", "unlink", "rmdir", "setattr", "open",
        ] {
            let (fs, device, ino) = fixture(kind, true);
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
            result.unwrap_or_else(|error| panic!("{kind} {action}: {error}"));
            assert_late_cancel_preserved(&fs, &device, &cx);
            let fresh = Cx::for_testing();
            let reopened = device.open();
            let check = reopened.check(&fresh).unwrap();
            assert!(check.clean && check.complete && check.namespace_complete);
            match action {
                "create" => {
                    let created = fs
                        .lookup(&fresh, &mut scope, ROOT, OsStr::new("new.bin"))
                        .unwrap();
                    assert_mounted_and_reopened_payload(&fs, &device, created.ino, "/new.bin", b"");
                }
                "mkdir" => {
                    let created = fs
                        .lookup(&fresh, &mut scope, ROOT, OsStr::new("newdir"))
                        .unwrap();
                    assert_eq!(created.kind, ffs_core::FileType::Directory);
                    assert!(
                        reopened
                            .resolve(&fresh, "/newdir")
                            .unwrap()
                            .unwrap()
                            .native
                            .is_directory()
                    );
                }
                "rename" => {
                    assert!(matches!(
                        fs.lookup(&fresh, &mut scope, ROOT, OsStr::new("file.bin")),
                        Err(FfsError::NotFound(_))
                    ));
                    assert_eq!(
                        fs.lookup(&fresh, &mut scope, ROOT, OsStr::new("moved.bin"))
                            .unwrap()
                            .ino,
                        ino
                    );
                    assert_mounted_and_reopened_payload(
                        &fs,
                        &device,
                        ino,
                        "/moved.bin",
                        b"original",
                    );
                }
                "unlink" | "rmdir" => {
                    let name = if action == "unlink" {
                        "file.bin"
                    } else {
                        "empty"
                    };
                    assert!(matches!(
                        fs.lookup(&fresh, &mut scope, ROOT, OsStr::new(name)),
                        Err(FfsError::NotFound(_))
                    ));
                    assert!(matches!(
                        reopened.resolve(&fresh, &format!("/{name}")),
                        Err(FfsError::NotFound(_))
                    ));
                }
                "setattr" => {
                    assert_eq!(fs.getattr(&fresh, &mut scope, ino).unwrap().perm, 0o444);
                    assert_eq!(
                        reopened
                            .resolve(&fresh, "/file.bin")
                            .unwrap()
                            .unwrap()
                            .native
                            .attributes
                            & 1,
                        1
                    );
                }
                _ => assert_mounted_and_reopened_payload(&fs, &device, ino, "/file.bin", b""),
            }
        }
    }
}

#[test]
fn readonly_sync_and_flush_do_not_add_backing_io() {
    let (fs, device, ino) = fixture("fat16", false);
    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    let before = device.counts();
    fs.sync_fs(&cx, &mut RequestScope::empty()).unwrap();
    fs.fsync(&cx, &mut scope, ino, 0, false).unwrap();
    fs.fsyncdir(&cx, &mut scope, ROOT, 0, false).unwrap();
    fs.flush(&cx, &mut scope, ino, 0, 0).unwrap();
    fs.flush_on_destroy(&cx).unwrap();
    assert_eq!(device.counts(), before);
    assert_eq!(fs.health.epoch.load(Ordering::Acquire), 0);
}

#[test]
fn successful_sync_barriers_do_not_become_interruptions_at_the_tail_checkpoint() {
    for kind in ["fat16", "fat32"] {
        for action in ["fsync", "fsyncdir", "sync_fs", "destroy"] {
            let (fs, device, ino) = fixture(kind, true);
            let cx = Cx::for_testing();
            let mut scope = RequestScope::empty();
            device.0.lock().unwrap().cancel_after_clean = true;
            let before = device.counts();
            match action {
                "fsync" => fs.fsync(&cx, &mut scope, ino, 0, false),
                "fsyncdir" => fs.fsyncdir(&cx, &mut scope, ROOT, 0, false),
                "sync_fs" => fs.sync_fs(&cx, &mut scope),
                _ => fs.flush_on_destroy(&cx),
            }
            .unwrap();
            let after = device.counts();
            assert_eq!(after.1, before.1);
            assert_eq!(after.2, before.2 + 1, "{kind} {action}: one real barrier");
            assert_late_cancel_preserved(&fs, &device, &cx);
            assert_mounted_and_reopened_payload(&fs, &device, ino, "/file.bin", b"original");
        }
    }
}

#[test]
fn filesystem_wide_sync_flushes_both_fat_dialects_and_preserves_failures() {
    for kind in ["fat16", "fat32"] {
        let (fs, device, ino) = fixture(kind, true);
        let cx = Cx::for_testing();
        let before = device.counts();
        fs.sync_fs(&cx, &mut RequestScope::empty()).unwrap();
        let after = device.counts();
        assert_eq!(after.1, before.1, "sync must not rewrite native metadata");
        assert_eq!(after.2, before.2 + 1, "one real backing sync");

        let cancelled = Cx::for_testing();
        cancelled.set_cancel_requested(true);
        let before = device.counts();
        assert!(matches!(
            fs.sync_fs(&cancelled, &mut RequestScope::empty()),
            Err(FfsError::Cancelled)
        ));
        assert_eq!(device.counts(), before, "cancelled sync cannot issue I/O");

        device.0.lock().unwrap().fail_sync = true;
        assert!(matches!(
            fs.sync_fs(&cx, &mut RequestScope::empty()),
            Err(FfsError::Io(_))
        ));
        assert_eq!(device.counts().2, after.2 + 1);
        // Failed native synchronization leaves durability uncertain. Preserve
        // the existing mount fence rather than retry through stale cache state.
        let before = device.counts();
        assert!(matches!(
            fs.sync_fs(&cx, &mut RequestScope::empty()),
            Err(FfsError::Io(_))
        ));
        assert_eq!(device.counts(), before);
        assert_quarantined(&fs, &device, ino);

        let volume = device.open();
        let checked = volume.check(&cx).unwrap();
        assert!(checked.clean && checked.complete && checked.namespace_complete);
        let reopened = FatFs::new_with_mode(&cx, volume, 1000, 1000, true).unwrap();
        reopened.sync_fs(&cx, &mut RequestScope::empty()).unwrap();
        let ino = reopened
            .lookup(
                &cx,
                &mut RequestScope::empty(),
                ROOT,
                OsStr::new("file.bin"),
            )
            .unwrap()
            .ino;
        assert_eq!(
            reopened
                .read(&cx, &mut RequestScope::empty(), ino, 0, 8)
                .unwrap(),
            b"original"
        );
    }
}

#[test]
fn fallocate_failures_and_post_commit_cache_errors_use_the_existing_health_gate() {
    for kind in ["fat16", "fat32"] {
        for failure in 0..3 {
            let (fs, device, ino) = fixture(kind, true);
            let cx = Cx::for_testing();
            {
                let mut state = device.0.lock().unwrap();
                match failure {
                    0 => state.fail_write = true,
                    1 => state.fail_sync = true,
                    _ => state.fail_read_after_clean = true,
                }
            }
            let offset = u64::from(fs.volume.geometry.cluster_bytes()) + 7;
            assert!(matches!(
                fs.fallocate(&cx, &mut RequestScope::empty(), ino, offset, 19, 0),
                Err(FfsError::Io(_))
            ));
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
fn allocation_copy_and_exchange_publish_committed_state_after_late_cancellation() {
    for kind in ["fat16", "fat32"] {
        for action in ["fallocate", "copy", "exchange"] {
            let (fs, device, ino) = fixture(kind, true);
            let cx = Cx::for_testing();
            let mut scope = RequestScope::empty();
            let other = if action == "fallocate" {
                ino
            } else {
                let attr = fs
                    .create(
                        &cx,
                        &mut scope,
                        ROOT,
                        OsStr::new("other.bin"),
                        0o644,
                        1000,
                        1000,
                    )
                    .unwrap();
                fs.write(&cx, &mut scope, attr.ino, 0, b"target").unwrap();
                assert_eq!(fs.read(&cx, &mut scope, attr.ino, 0, 6).unwrap(), b"target");
                attr.ino
            };
            let offset = u64::from(fs.volume.geometry.cluster_bytes()) + 7;
            device.0.lock().unwrap().cancel_after_clean = true;
            match action {
                "fallocate" => fs.fallocate(&cx, &mut scope, ino, offset, 19, 0).unwrap(),
                "copy" => assert_eq!(
                    fs.copy_file_range(&cx, &mut scope, ino, 0, other, offset, 8)
                        .unwrap(),
                    8
                ),
                _ => fs
                    .rename2(
                        &cx,
                        &mut scope,
                        ROOT,
                        OsStr::new("file.bin"),
                        ROOT,
                        OsStr::new("other.bin"),
                        libc::RENAME_EXCHANGE,
                    )
                    .unwrap(),
            }
            assert_late_cancel_preserved(&fs, &device, &cx);
            match action {
                "fallocate" => {
                    let mut expected = b"original".to_vec();
                    expected.resize((offset + 19) as usize, 0);
                    assert_mounted_and_reopened_payload(&fs, &device, ino, "/file.bin", &expected);
                }
                "copy" => {
                    let mut expected = b"target".to_vec();
                    expected.resize(offset as usize, 0);
                    expected.extend_from_slice(b"original");
                    assert_mounted_and_reopened_payload(
                        &fs,
                        &device,
                        other,
                        "/other.bin",
                        &expected,
                    );
                    assert_mounted_and_reopened_payload(
                        &fs,
                        &device,
                        ino,
                        "/file.bin",
                        b"original",
                    );
                }
                _ => {
                    let fresh = Cx::for_testing();
                    assert_eq!(
                        fs.lookup(&fresh, &mut scope, ROOT, OsStr::new("file.bin"))
                            .unwrap()
                            .ino,
                        other
                    );
                    assert_eq!(
                        fs.lookup(&fresh, &mut scope, ROOT, OsStr::new("other.bin"))
                            .unwrap()
                            .ino,
                        ino
                    );
                    assert_mounted_and_reopened_payload(
                        &fs,
                        &device,
                        other,
                        "/file.bin",
                        b"target",
                    );
                    assert_mounted_and_reopened_payload(
                        &fs,
                        &device,
                        ino,
                        "/other.bin",
                        b"original",
                    );
                }
            }
        }
    }
}

#[test]
fn compound_setattr_remains_cancellable_between_native_mutations() {
    let (fs, device, ino) = fixture("fat16", true);
    let cx = Cx::for_testing();
    device.0.lock().unwrap().cancel_after_clean = true;
    assert!(matches!(
        fs.setattr(
            &cx,
            &mut RequestScope::empty(),
            ino,
            &SetAttrRequest {
                size: Some(1),
                mode: Some(0o444),
                ..Default::default()
            }
        ),
        Err(FfsError::Cancelled)
    ));
    assert_quarantined(&fs, &device, ino);
    // The first native commit stands; the separate metadata mutation never
    // started. An encompassing syscall mask would wrongly apply both.
    let reopened = device.open();
    let fresh = Cx::for_testing();
    let entry = reopened.resolve(&fresh, "/file.bin").unwrap().unwrap();
    assert_eq!(entry.native.size, 1);
    assert_eq!(entry.native.attributes & 1, 0);
    let chain = reopened.file_chain(&fresh, &entry).unwrap();
    assert_eq!(reopened.read(&fresh, &chain, 0, 8).unwrap(), b"o");
}

#[test]
fn retained_files_and_directories_publish_and_reap_after_late_cancellation() {
    for kind in ["fat16", "fat32"] {
        for directory in [false, true] {
            let (fs, device, file) = fixture(kind, true);
            let cx = Cx::for_testing();
            let mut scope = RequestScope::empty();
            let (name, ino) = if directory {
                (
                    "empty",
                    fs.lookup(&cx, &mut scope, ROOT, OsStr::new("empty"))
                        .unwrap()
                        .ino,
                )
            } else {
                ("file.bin", file)
            };
            let pins = Arc::new(AtomicU64::new(1));
            let observed = Arc::clone(&pins);
            fs.install_open_handle_oracle(Arc::new(move |which| {
                if which == ino {
                    observed.load(Ordering::Acquire)
                } else {
                    0
                }
            }));
            device.0.lock().unwrap().cancel_after_clean = true;
            if directory {
                fs.rmdir(&cx, &mut scope, ROOT, OsStr::new(name)).unwrap();
            } else {
                fs.unlink(&cx, &mut scope, ROOT, OsStr::new(name)).unwrap();
            }
            assert_late_cancel_preserved(&fs, &device, &cx);
            let fresh = Cx::for_testing();
            assert_eq!(fs.getattr(&fresh, &mut scope, ino).unwrap().nlink, 0);
            assert!(matches!(
                fs.lookup(&fresh, &mut scope, ROOT, OsStr::new(name)),
                Err(FfsError::NotFound(_))
            ));
            if directory {
                assert_eq!(
                    fs.lookup(&fresh, &mut scope, ino, OsStr::new(".."))
                        .unwrap()
                        .ino,
                    ROOT
                );
            } else {
                assert_eq!(fs.read(&fresh, &mut scope, ino, 0, 8).unwrap(), b"original");
            }
            let recovery = fs.path_for_inode(ino).unwrap();
            assert!(device.open().resolve(&fresh, &recovery).is_ok());
            pins.store(0, Ordering::Release);
            device.0.lock().unwrap().cancel_after_clean = true;
            assert!(fs.finalize_unlinked_inode(&fresh, &mut scope, ino).unwrap());
            assert_late_cancel_preserved(&fs, &device, &fresh);
            let after = Cx::for_testing();
            assert!(matches!(
                fs.getattr(&after, &mut scope, ino),
                Err(FfsError::NotFound(_))
            ));
            let reopened = device.open();
            let check = reopened.check(&after).unwrap();
            assert!(check.clean && check.complete && check.namespace_complete);
            assert!(matches!(
                reopened.resolve(&after, &recovery),
                Err(FfsError::NotFound(_))
            ));
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
