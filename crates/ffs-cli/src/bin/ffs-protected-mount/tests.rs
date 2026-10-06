use super::*;
use ffs_repair::sidecar::{SidecarOptions, protect};
use std::ffi::OsStr;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::Condvar;
use tempfile::TempDir;

// A spawned child holds a copy of every open descriptor of this process
// until it execs, and a flock belongs to the open file description: a
// sibling test's mkfs/debugfs child could still hold an image or sidecar
// lock a test had just released, and its re-open failed with WouldBlock
// (flaky on CI and locally). Spawns are counted until `spawn` returns, which
// is after the child has exec'd; re-opens wait until none is in progress.
// Spawns never wait, so a test holding a device can still run a command.
static SPAWNS_IN_PROGRESS: Mutex<usize> = Mutex::new(0);
static SPAWNS_DONE: Condvar = Condvar::new();

fn wait_for_spawns() {
    let mut count = SPAWNS_IN_PROGRESS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    while *count > 0 {
        count = SPAWNS_DONE
            .wait(count)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    }
}

/// `prepare`, after any in-flight child spawn has exec'd (see above).
pub fn prepare(cx: &Cx, args: &Args) -> Result<Prepared> {
    wait_for_spawns();
    super::prepare(cx, args)
}

/// `ffs_repair::sidecar::verify`, after any in-flight child spawn has exec'd.
pub fn verify(
    cx: &Cx,
    image: &Path,
    sidecar: &Path,
) -> ffs_error::Result<ffs_repair::sidecar::SidecarReport> {
    wait_for_spawns();
    ffs_repair::sidecar::verify(cx, image, sidecar)
}

/// `SidecarImageDevice::open`, after any in-flight child spawn has exec'd.
pub fn open_device(cx: &Cx, image: &Path, sidecar: &Path) -> ffs_error::Result<SidecarImageDevice> {
    wait_for_spawns();
    SidecarImageDevice::open(cx, image, sidecar)
}

fn check_args(image: &Path, sidecar: &Path) -> Args {
    Args {
        image: image.to_owned(),
        sidecar: sidecar.to_owned(),
        mountpoint: None,
        scrub: scrub::Options::default(),
        authority: Authority {
            exclusive_image: true,
            allow_repair: true,
        },
        check: true,
        rw: false,
        allow_other: false,
    }
}

pub fn command(command: &mut Command) -> Output {
    *SPAWNS_IN_PROGRESS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) += 1;
    let spawned = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();
    {
        let mut count = SPAWNS_IN_PROGRESS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *count -= 1;
        if *count == 0 {
            SPAWNS_DONE.notify_all();
        }
    }
    let output = spawned
        .and_then(std::process::Child::wait_with_output)
        .expect("required filesystem oracle must be installed");
    assert!(
        output.status.success(),
        "oracle failed: {command:?}\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    output
}

struct Fixture {
    dir: TempDir,
    image: PathBuf,
    sidecar: PathBuf,
    payload: Vec<u8>,
}

impl Fixture {
    fn ext4() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("image.ext4");
        let sidecar = dir.path().join("image.ffs-rq");
        File::create(&image)
            .unwrap()
            .set_len(8 * 1024 * 1024)
            .unwrap();
        command(
            Command::new("mkfs.ext4")
                .args(["-q", "-F", "-b", "4096", "-O", "^has_journal"])
                .arg(&image),
        );
        let payload: Vec<u8> = (0_u32..12_288)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect();
        let source = dir.path().join("payload.bin");
        std::fs::write(&source, &payload).unwrap();
        let output = command(
            Command::new("debugfs")
                .args(["-w", "-R"])
                .arg(format!("write {} /payload", source.display()))
                .arg(&image),
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("Allocated inode"));
        protect(
            &Cx::for_testing(),
            &image,
            &sidecar,
            SidecarOptions {
                block_size: 4096,
                group_blocks: 16,
                repair_symbols: 4,
            },
        )
        .expect("protect formatted image");
        Self {
            dir,
            image,
            sidecar,
            payload,
        }
    }

    fn args(&self) -> Args {
        check_args(&self.image, &self.sidecar)
    }

    fn first_block(&self, path: &str) -> u64 {
        let output = command(
            Command::new("debugfs")
                .arg("-R")
                .arg(format!("blocks {path}"))
                .arg(&self.image),
        );
        String::from_utf8(output.stdout)
            .unwrap()
            .split_whitespace()
            .next()
            .expect("file must have a physical block")
            .parse()
            .unwrap()
    }

    fn read_block(&self, block: u64) -> Vec<u8> {
        let mut bytes = vec![0; 4096];
        File::open(&self.image)
            .unwrap()
            .read_exact_at(&mut bytes, block * 4096)
            .unwrap();
        bytes
    }

    fn damage_block(&self, block: u64) {
        // Deliberate media-fault injection after admission. Normal operators
        // must never bypass the protected device like this.
        let file = File::options().write(true).open(&self.image).unwrap();
        file.write_all_at(&[0xE7; 4096], block * 4096).unwrap();
        file.sync_all().unwrap();
    }

    fn assert_healthy(&self) {
        assert!(
            verify(&Cx::for_testing(), &self.image, &self.sidecar)
                .unwrap()
                .is_healthy()
        );
        command(Command::new("e2fsck").arg("-fn").arg(&self.image));
    }
}

#[test]
fn command_requires_authority_and_a_single_execution_mode() {
    let base = ["ffs-protected-mount", "image", "archive", "--check"];
    assert!(Args::try_parse_from(base).is_err());
    assert!(Args::try_parse_from(base.into_iter().chain(["--exclusive-image"])).is_err());
    assert!(Args::try_parse_from(base.into_iter().chain(["--allow-repair"])).is_err());
    let args = Args::try_parse_from(
        base.into_iter()
            .chain(["--exclusive-image", "--allow-repair"]),
    )
    .unwrap();
    assert!(args.check);
    let options = mount_options(&args);
    assert!(options.read_only);
    assert!(!options.allow_other);
    assert!(options.auto_unmount);
    assert!(!options.writeback_cache.is_enabled());
    assert!(
        Args::try_parse_from([
            "ffs-protected-mount",
            "image",
            "archive",
            "mountpoint",
            "--check",
            "--exclusive-image",
            "--allow-repair",
        ])
        .is_err()
    );
}

#[test]
fn invalid_mountpoint_is_rejected_before_device_admission() {
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("image");
    let sidecar = dir.path().join("archive");
    std::fs::write(&image, b"not an image").unwrap();
    std::fs::write(&sidecar, b"not an archive").unwrap();
    let mut args = check_args(&image, &sidecar);
    args.check = false;
    args.mountpoint = Some(image.clone());
    let error = prepare(&Cx::for_testing(), &args).err().unwrap();
    assert!(error.to_string().contains("not a directory"));
    assert_eq!(std::fs::read(image).unwrap(), b"not an image");
    assert_eq!(std::fs::read(sidecar).unwrap(), b"not an archive");
}

#[test]
fn filesystem_read_repairs_corrupt_data_before_returning_it() {
    let fixture = Fixture::ext4();
    let cx = Cx::for_testing();
    let block = fixture.first_block("/payload");
    let prepared = prepare(&cx, &fixture.args()).expect("open protected filesystem");
    // `OpenFs::` explicitly: `Arc<OpenFs>` also implements `FsOps`, whose
    // scope-taking methods method resolution would otherwise pick.
    let inode = OpenFs::lookup(&prepared.fs, &cx, InodeNumber(2), OsStr::new("payload"))
        .unwrap()
        .ino;
    let original = fixture.read_block(block);
    fixture.damage_block(block);
    assert_ne!(fixture.read_block(block), original);
    assert_eq!(
        OpenFs::read(
            &prepared.fs,
            &cx,
            inode,
            0,
            u32::try_from(fixture.payload.len()).unwrap()
        )
        .unwrap(),
        fixture.payload,
    );
    assert_eq!(
        fixture.read_block(block),
        original,
        "repair must reach physical storage"
    );
    prepared.finish(&cx).unwrap();
    fixture.assert_healthy();
}

#[test]
fn filesystem_lookup_repairs_directory_metadata_before_parsing_it() {
    let fixture = Fixture::ext4();
    let cx = Cx::for_testing();
    let block = fixture.first_block("/");
    let prepared = prepare(&cx, &fixture.args()).unwrap();
    let original = fixture.read_block(block);
    fixture.damage_block(block);
    let attr = OpenFs::lookup(&prepared.fs, &cx, InodeNumber(2), OsStr::new("payload")).unwrap();
    assert_eq!(attr.size, u64::try_from(fixture.payload.len()).unwrap());
    assert_eq!(fixture.read_block(block), original);
    prepared.finish(&cx).unwrap();
    fixture.assert_healthy();
}

#[test]
fn startup_difference_is_not_silently_rolled_back() {
    let fixture = Fixture::ext4();
    fixture.damage_block(fixture.first_block("/payload"));
    let damaged = std::fs::read(&fixture.image).unwrap();
    let archive = std::fs::read(&fixture.sidecar).unwrap();
    let error = prepare(&Cx::for_testing(), &fixture.args()).err().unwrap();
    assert!(format!("{error:#}").contains("refusing implicit rollback"));
    assert_eq!(std::fs::read(&fixture.image).unwrap(), damaged);
    assert_eq!(std::fs::read(&fixture.sidecar).unwrap(), archive);
}

#[test]
fn pending_epoch_is_not_admitted_or_relabelled_clean() {
    let fixture = Fixture::ext4();
    let cx = Cx::for_testing();
    let device = open_device(&cx, &fixture.image, &fixture.sidecar).unwrap();
    device
        .write_all_at(&cx, ByteOffset(device.len_bytes() - 4096), &[0x5A; 4096])
        .unwrap();
    drop(device);
    let damaged = std::fs::read(&fixture.image).unwrap();
    let pending = std::fs::read(&fixture.sidecar).unwrap();
    let error = prepare(&cx, &fixture.args()).err().unwrap();
    assert!(format!("{error:#}").contains("unfinished write epoch"));
    assert_eq!(std::fs::read(&fixture.image).unwrap(), damaged);
    assert_eq!(std::fs::read(&fixture.sidecar).unwrap(), pending);
}

#[test]
fn readonly_filesystem_and_adapter_cannot_write_caller_data() {
    let fixture = Fixture::ext4();
    let cx = Cx::for_testing();
    let prepared = prepare(&cx, &fixture.args()).unwrap();
    let before = std::fs::read(&fixture.image).unwrap();
    let device = ProtectedDevice {
        inner: Arc::clone(&prepared.device),
        writable: false,
    };
    assert!(matches!(
        device.write_all_at(&cx, ByteOffset(4096), &[1]),
        Err(FfsError::ReadOnly)
    ));
    let error = OpenFs::create(
        &prepared.fs,
        &cx,
        InodeNumber(2),
        OsStr::new("no-write"),
        0o600,
        0,
        0,
    )
    .unwrap_err();
    assert_eq!(error.to_errno(), libc::EROFS);
    let cancelled = Cx::for_testing();
    cancelled.set_cancel_requested(true);
    assert!(matches!(
        device.write_all_at(&cancelled, ByteOffset(4096), &[1]),
        Err(FfsError::Cancelled)
    ));
    assert_eq!(std::fs::read(&fixture.image).unwrap(), before);
    drop(device);
    prepared.finish(&cx).unwrap();
    fixture.assert_healthy();
}

#[test]
fn unfinished_dispatch_cannot_be_reported_as_completed_shutdown() {
    let fixture = Fixture::ext4();
    let cx = Cx::for_testing();
    let prepared = prepare(&cx, &fixture.args()).unwrap();
    let in_flight = Arc::clone(&prepared.fs);
    let error = prepared.finish(&cx).unwrap_err();
    assert!(error.to_string().contains("shutdown is incomplete"));
    assert!(open_device(&cx, &fixture.image, &fixture.sidecar).is_err());
    drop(in_flight);
    let device = open_device(&cx, &fixture.image, &fixture.sidecar).unwrap();
    device.sync(&cx).unwrap();
}

impl Fixture {
    fn writable_args(&self) -> Args {
        let mountpoint = self.dir.path().join("mountpoint");
        std::fs::create_dir_all(&mountpoint).unwrap();
        let mut args = self.args();
        args.check = false;
        args.rw = true;
        args.mountpoint = Some(mountpoint);
        args
    }

    fn btrfs() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("image.btrfs");
        let sidecar = dir.path().join("image.ffs-rq");
        File::create(&image)
            .unwrap()
            .set_len(128 * 1024 * 1024)
            .unwrap();
        command(
            Command::new("mkfs.btrfs")
                .args([
                    "-q", "-f", "-n", "16384", "-s", "4096", "-m", "single", "-d", "single",
                ])
                .arg(&image),
        );
        protect(
            &Cx::for_testing(),
            &image,
            &sidecar,
            SidecarOptions {
                block_size: 4096,
                group_blocks: 64,
                repair_symbols: 4,
            },
        )
        .expect("protect btrfs image");
        Self {
            dir,
            image,
            sidecar,
            payload: Vec::new(),
        }
    }
}

fn create_written(prepared: &Prepared, cx: &Cx, parent: InodeNumber, data: &[u8]) -> InodeNumber {
    let inode = OpenFs::create(&prepared.fs, cx, parent, OsStr::new("written"), 0o600, 0, 0)
        .unwrap()
        .ino;
    let written = OpenFs::write(&prepared.fs, cx, inode, 0, data).unwrap();
    assert_eq!(usize::try_from(written).unwrap(), data.len());
    inode
}

fn assert_file(prepared: &Prepared, cx: &Cx, parent: InodeNumber, name: &str, data: &[u8]) {
    let attr = OpenFs::lookup(&prepared.fs, cx, parent, OsStr::new(name)).unwrap();
    assert_eq!(attr.size, u64::try_from(data.len()).unwrap());
    assert_eq!(
        OpenFs::read(
            &prepared.fs,
            cx,
            attr.ino,
            0,
            u32::try_from(data.len()).unwrap(),
        )
        .unwrap(),
        data,
    );
}

/// Capture the pair only AFTER the synchronous filesystem barrier has returned,
/// with no other thread mutating it. Reopening an independent copy bypasses the
/// original process's MVCC and block caches and tests archive publication timing.
fn assert_published(fixture: &Fixture, parent: InodeNumber, data: &[u8]) {
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("captured.image");
    let sidecar = dir.path().join("captured.ffsrq");
    std::fs::copy(&fixture.image, &image).unwrap();
    std::fs::copy(&fixture.sidecar, &sidecar).unwrap();
    let cx = Cx::for_testing();
    assert!(verify(&cx, &image, &sidecar).unwrap().is_healthy());
    let reopened = prepare(&cx, &check_args(&image, &sidecar)).expect("admit captured protection");
    assert_file(&reopened, &cx, parent, "written", data);
    reopened.finish(&cx).unwrap();
}

#[test]
fn rw_requires_a_mount_and_keeps_kernel_writeback_disabled() {
    let args = Args::try_parse_from([
        "ffs-protected-mount",
        "image",
        "archive",
        "mountpoint",
        "--rw",
        "--exclusive-image",
        "--allow-repair",
    ])
    .unwrap();
    assert!(args.rw);
    let options = mount_options(&args);
    assert!(!options.read_only);
    assert!(options.auto_unmount);
    assert!(!options.writeback_cache.is_enabled());
    assert!(
        Args::try_parse_from([
            "ffs-protected-mount",
            "image",
            "archive",
            "--check",
            "--rw",
            "--exclusive-image",
            "--allow-repair",
        ])
        .is_err()
    );
    let mut direct = check_args(Path::new("absent-image"), Path::new("absent-sidecar"));
    direct.rw = true;
    assert!(
        checked_paths(&direct)
            .unwrap_err()
            .to_string()
            .contains("--check")
    );
}

#[test]
fn writable_ext4_finish_persists_noninline_data_and_namespace() {
    let fixture = Fixture::ext4();
    let cx = Cx::for_testing();
    let before = std::fs::read(&fixture.sidecar).unwrap();
    let prepared = prepare(&cx, &fixture.writable_args()).unwrap();
    assert!(prepared.fs.is_writable());
    let data: Vec<u8> = (0_u32..65_553)
        .map(|index| u8::try_from(index % 239).unwrap())
        .collect();
    create_written(&prepared, &cx, InodeNumber(2), &data);
    // No caller fsync: shutdown must drain the filesystem, not just the device.
    prepared.finish(&cx).unwrap();
    assert_ne!(std::fs::read(&fixture.sidecar).unwrap(), before);
    fixture.assert_healthy();
    assert_published(&fixture, InodeNumber(2), &data);
    let reopened = prepare(&cx, &fixture.args()).unwrap();
    assert_file(&reopened, &cx, InodeNumber(2), "payload", &fixture.payload);
    reopened.finish(&cx).unwrap();
}

#[test]
fn filesystem_fsync_and_fdatasync_publish_each_new_protection_point() {
    let fixture = Fixture::ext4();
    let cx = Cx::for_testing();
    let prepared = prepare(&cx, &fixture.writable_args()).unwrap();
    let inode = create_written(&prepared, &cx, InodeNumber(2), &[0; 8193]);
    for (datasync, byte) in [(false, 0x37), (true, 0x92)] {
        let data = vec![byte; 8193];
        let written = OpenFs::write(&prepared.fs, &cx, inode, 0, &data).unwrap();
        assert_eq!(usize::try_from(written).unwrap(), data.len());
        FsOps::fsync(
            prepared.fs.as_ref(),
            &cx,
            &mut RequestScope::empty(),
            inode,
            0,
            datasync,
        )
        .unwrap();
        // This must work BEFORE finish(), which would otherwise hide a missing
        // sidecar refresh at the actual filesystem fsync boundary.
        assert_published(&fixture, InodeNumber(2), &data);
    }
    prepared.finish(&cx).unwrap();
    fixture.assert_healthy();
}

#[test]
fn refreshed_protection_repairs_new_file_bytes_after_reopen() {
    let fixture = Fixture::ext4();
    let cx = Cx::for_testing();
    let prepared = prepare(&cx, &fixture.writable_args()).unwrap();
    let data = vec![0x6D; 65_553];
    create_written(&prepared, &cx, InodeNumber(2), &data);
    prepared.finish(&cx).unwrap();
    let block = fixture.first_block("/written");
    let original = fixture.read_block(block);
    let reopened = prepare(&cx, &fixture.args()).unwrap();
    fixture.damage_block(block);
    assert_file(&reopened, &cx, InodeNumber(2), "written", &data);
    assert_eq!(fixture.read_block(block), original);
    reopened.finish(&cx).unwrap();
    fixture.assert_healthy();
}

#[test]
fn rw_still_refuses_startup_mismatch_and_pending_epochs_without_mutation() {
    for pending in [false, true] {
        let fixture = Fixture::ext4();
        let cx = Cx::for_testing();
        let block = fixture.first_block("/payload");
        if pending {
            let device = open_device(&cx, &fixture.image, &fixture.sidecar).unwrap();
            device
                .write_all_at(&cx, ByteOffset(block * 4096), &[0x5A; 4096])
                .unwrap();
        } else {
            fixture.damage_block(block);
        }
        let image = std::fs::read(&fixture.image).unwrap();
        let archive = std::fs::read(&fixture.sidecar).unwrap();
        let error = prepare(&cx, &fixture.writable_args()).err().unwrap();
        let expected = if pending {
            "unfinished write epoch"
        } else {
            "refusing implicit rollback"
        };
        assert!(format!("{error:#}").contains(expected));
        assert_eq!(std::fs::read(&fixture.image).unwrap(), image);
        assert_eq!(std::fs::read(&fixture.sidecar).unwrap(), archive);
    }
}

#[test]
fn shutdown_uses_an_uncancelled_capability_to_persist_writes() {
    let fixture = Fixture::ext4();
    let startup = Cx::for_testing();
    let prepared = prepare(&startup, &fixture.writable_args()).unwrap();
    let data = vec![0x47; 16_385];
    create_written(&prepared, &startup, InodeNumber(2), &data);
    startup.set_cancel_requested(true);
    prepared.finish(&Cx::for_testing()).unwrap();
    fixture.assert_healthy();
    assert_published(&fixture, InodeNumber(2), &data);
}

#[test]
fn archive_publication_failure_is_a_failed_filesystem_shutdown() {
    let fixture = Fixture::ext4();
    let cx = Cx::for_testing();
    let prepared = prepare(&cx, &fixture.writable_args()).unwrap();
    create_written(&prepared, &cx, InodeNumber(2), &[0x4B; 8193]);
    // Deliberately obstruct atomic archive replacement after admission. This
    // is fault injection, not a supported operator namespace change.
    let retained = fixture.dir.path().join("retained.ffsrq");
    std::fs::rename(&fixture.sidecar, &retained).unwrap();
    std::fs::create_dir(&fixture.sidecar).unwrap();
    let error = prepared.finish(&cx).unwrap_err();
    assert!(format!("{error:#}").contains("checkpoint protected filesystem"));
    assert!(open_device(&cx, &fixture.image, &retained).is_err());
}

#[test]
fn writable_shutdown_does_not_flush_while_dispatch_still_owns_the_filesystem() {
    let fixture = Fixture::ext4();
    let cx = Cx::for_testing();
    let prepared = prepare(&cx, &fixture.writable_args()).unwrap();
    create_written(&prepared, &cx, InodeNumber(2), &[0x51; 8193]);
    let image = std::fs::read(&fixture.image).unwrap();
    let archive = std::fs::read(&fixture.sidecar).unwrap();
    let in_flight = Arc::clone(&prepared.fs);
    let error = prepared.finish(&cx).unwrap_err();
    assert!(error.to_string().contains("shutdown is incomplete"));
    assert_eq!(std::fs::read(&fixture.image).unwrap(), image);
    assert_eq!(std::fs::read(&fixture.sidecar).unwrap(), archive);
    assert!(open_device(&cx, &fixture.image, &fixture.sidecar).is_err());
    // The surviving dispatcher, not finish(), owns any subsequent persistence.
    FsOps::fsyncdir(
        in_flight.as_ref(),
        &cx,
        &mut RequestScope::empty(),
        InodeNumber(1),
        0,
        false,
    )
    .unwrap();
    drop(in_flight);
    fixture.assert_healthy();
}

#[test]
fn writable_btrfs_finish_publishes_data_roots_and_matching_protection() {
    let fixture = Fixture::btrfs();
    let cx = Cx::for_testing();
    let prepared = prepare(&cx, &fixture.writable_args()).unwrap();
    assert_eq!(prepared.filesystem, "btrfs");
    assert!(prepared.fs.is_writable());
    let data: Vec<u8> = (0_u32..65_553)
        .map(|index| u8::try_from(index % 241).unwrap())
        .collect();
    create_written(&prepared, &cx, InodeNumber(1), &data);
    prepared.finish(&cx).unwrap();
    assert!(
        verify(&cx, &fixture.image, &fixture.sidecar)
            .unwrap()
            .is_healthy()
    );
    command(
        Command::new("btrfs")
            .args(["check", "--readonly"])
            .arg(&fixture.image),
    );
    assert_published(&fixture, InodeNumber(1), &data);
}
