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
// (flaky on CI and locally). Spawns are counted until the child has exited
// (see `command`); re-opens wait until none is in progress. Spawns never
// wait, so a test holding a device can still run a command.
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
        commit_interval_secs: None,
        allow_other: false,
    }
}

pub fn command(command: &mut Command) -> Output {
    *SPAWNS_IN_PROGRESS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) += 1;
    let output = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(std::process::Child::wait_with_output);
    // Released only once the child has EXITED: `spawn` returns when execve
    // releases the parent (exec_mmap), before the kernel closes the child's
    // close-on-exec descriptors, so for a moment after `spawn` the child
    // can still hold a sibling test's just-released lock (bd-hi96g).
    {
        let mut count = SPAWNS_IN_PROGRESS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *count -= 1;
        if *count == 0 {
            SPAWNS_DONE.notify_all();
        }
    }
    let output = output.expect("required filesystem oracle must be installed");
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
        Self::ext4_with_journal(false)
    }

    fn ext4_with_journal(journalled: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("image.ext4");
        let sidecar = dir.path().join("image.ffs-rq");
        File::create(&image)
            .unwrap()
            .set_len(if journalled { 32 } else { 8 } * 1024 * 1024)
            .unwrap();
        command(
            Command::new("mkfs.ext4")
                .args([
                    "-q",
                    "-F",
                    "-b",
                    "4096",
                    "-O",
                    if journalled {
                        "has_journal"
                    } else {
                        "^has_journal"
                    },
                ])
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
fn periodic_commit_options_require_writable_mount() {
    let base = [
        "ffs-protected-mount",
        "image",
        "archive",
        "mount",
        "--exclusive-image",
        "--allow-repair",
    ];
    for seconds in ["0", "1", "30"] {
        assert!(
            Args::try_parse_from(base.into_iter().chain(["--commit-interval-secs", seconds,]))
                .is_err()
        );
        let args = Args::try_parse_from(base.into_iter().chain([
            "--rw",
            "--commit-interval-secs",
            seconds,
        ]))
        .unwrap();
        assert_eq!(args.commit_interval_secs, Some(seconds.parse().unwrap()));
    }
    let defaults = Args::try_parse_from(base.into_iter().chain(["--rw"])).unwrap();
    assert!(defaults.commit_interval_secs.is_none());
    assert!(
        Args::try_parse_from(
            base.into_iter()
                .chain(["--rw", "--commit-interval-secs", "-1",])
        )
        .is_err()
    );
}

#[test]
fn disabled_periodic_commit_retains_no_filesystem_owner() {
    let fixture = Fixture::ext4();
    let runtime = mount_worker::mount_background_runtime().unwrap();
    let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
    let prepared = prepare(&cx, &fixture.writable_args()).unwrap();
    let worker = mount_worker::start_periodic_commit(
        &cx,
        &runtime,
        &prepared.fs,
        Some(std::time::Duration::ZERO),
        "disabled-test",
    )
    .unwrap();
    assert!(worker.is_none());
    prepared.finish(&cx).unwrap();
    fixture.assert_healthy();
}

#[test]
fn stopped_periodic_commit_releases_filesystem_before_final_checkpoint() {
    let fixture = Fixture::ext4();
    let runtime = mount_worker::mount_background_runtime().unwrap();
    let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
    let prepared = prepare(&cx, &fixture.writable_args()).unwrap();
    let mut worker = mount_worker::start_periodic_commit(
        &cx,
        &runtime,
        &prepared.fs,
        Some(std::time::Duration::from_hours(24)),
        "stop-test",
    )
    .unwrap()
    .unwrap();
    let written = [0x57; 8193];
    create_written(&prepared, &cx, InodeNumber(2), &written);
    worker.request_stop().unwrap();
    worker.stop().unwrap();
    prepared
        .finish(&cx)
        .expect("stopped worker must not retain the filesystem");
    assert_published(&fixture, InodeNumber(2), &written);
    fixture.assert_healthy();
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
fn protected_journalled_ext4_uses_internal_writer_and_publishes_fsync_bd_7zjfh() {
    let fixture = Fixture::ext4_with_journal(true);
    let cx = Cx::for_testing();
    let prepared = prepare(&cx, &fixture.writable_args()).unwrap();
    assert!(
        prepared
            .fs
            .ext4_superblock()
            .unwrap()
            .has_compat(ffs_ondisk::Ext4CompatFeatures::HAS_JOURNAL)
    );
    assert!(
        prepared.fs.has_jbd2_writer(),
        "protected journalled ext4 must not bypass the ordinary journal durability rule"
    );
    let data: Vec<u8> = (0_u32..65_553)
        .map(|index| u8::try_from(index % 239).unwrap())
        .collect();
    let inode = create_written(&prepared, &cx, InodeNumber(2), &data);
    FsOps::fsync(
        prepared.fs.as_ref(),
        &cx,
        &mut RequestScope::empty(),
        inode,
        0,
        false,
    )
    .unwrap();
    assert_published(&fixture, InodeNumber(2), &data);
    prepared.finish(&cx).unwrap();
    fixture.assert_healthy();
    let reopened = prepare(&cx, &fixture.args()).unwrap();
    assert_file(&reopened, &cx, InodeNumber(2), "written", &data);
    assert_file(&reopened, &cx, InodeNumber(2), "payload", &fixture.payload);
    reopened.finish(&cx).unwrap();
}

#[test]
fn protected_journalled_ext4_refuses_missing_or_empty_journal_bd_7zjfh() {
    for (mutation, diagnostic) in [
        (
            "set_super_value journal_inum 0",
            "no JBD2 writer is attached",
        ),
        (
            "set_inode_field <8> block[0] 0x0000f30a",
            "no JBD2 writer is attached",
        ),
    ] {
        let mut fixture = Fixture::ext4_with_journal(true);
        let cx = Cx::for_testing();
        let original = prepare(&cx, &fixture.args()).unwrap();
        assert_eq!(original.fs.ext4_superblock().unwrap().journal_inum, 8);
        let original_inode = original.fs.read_inode(&cx, InodeNumber(8)).unwrap();
        assert_ne!(original_inode.flags & ffs_types::EXT4_EXTENTS_FL, 0);
        let (original_header, _) =
            ffs_ondisk::parse_extent_tree(&original_inode.extent_bytes).unwrap();
        assert_eq!(original_header.depth, 0);
        assert!(original_header.entries > 0);
        original.finish(&cx).unwrap();
        command(
            Command::new("debugfs")
                .args(["-w", "-R", mutation])
                .arg(&fixture.image),
        );
        // Preserve a valid leaf header while clearing eh_entries. An invalid
        // magic fails earlier during read-only fast-commit inspection, even
        // with replay skipped; this empty mapping must reach the writer guard.
        // Fresh protection makes the missing journal, not stale parity, the
        // reason write admission refuses this filesystem.
        fixture.sidecar = fixture.dir.path().join("invalid-journal.ffsrq");
        protect(
            &Cx::for_testing(),
            &fixture.image,
            &fixture.sidecar,
            SidecarOptions {
                block_size: 4096,
                group_blocks: 16,
                repair_symbols: 4,
            },
        )
        .unwrap();
        let source = std::fs::read(&fixture.image).unwrap();
        let archive = std::fs::read(&fixture.sidecar).unwrap();
        let readonly = prepare(&cx, &fixture.args()).unwrap();
        if mutation == "set_super_value journal_inum 0" {
            assert_eq!(readonly.fs.ext4_superblock().unwrap().journal_inum, 0);
        } else {
            assert_eq!(readonly.fs.ext4_superblock().unwrap().journal_inum, 8);
            let inode = readonly.fs.read_inode(&cx, InodeNumber(8)).unwrap();
            let (header, tree) = ffs_ondisk::parse_extent_tree(&inode.extent_bytes).unwrap();
            assert_eq!(header.magic, original_header.magic);
            assert_eq!(header.max_entries, original_header.max_entries);
            assert_eq!(header.depth, 0);
            assert_eq!(header.entries, 0, "debugfs must clear the journal mapping");
            assert_eq!(tree, ffs_ondisk::ExtentTree::Leaf(Vec::new()));
        }
        assert_file(&readonly, &cx, InodeNumber(2), "payload", &fixture.payload);
        readonly.finish(&cx).unwrap();
        let error = prepare(&Cx::for_testing(), &fixture.writable_args())
            .err()
            .expect("journalled write admission must fail");
        assert!(format!("{error:#}").contains(diagnostic), "{error:#}");
        assert_eq!(std::fs::read(&fixture.image).unwrap(), source);
        assert_eq!(std::fs::read(&fixture.sidecar).unwrap(), archive);
        let cx = Cx::for_testing();
        let readonly = prepare(&cx, &fixture.args()).unwrap();
        assert_file(&readonly, &cx, InodeNumber(2), "payload", &fixture.payload);
        readonly.finish(&cx).unwrap();
        assert_eq!(std::fs::read(&fixture.image).unwrap(), source);
        assert_eq!(std::fs::read(&fixture.sidecar).unwrap(), archive);
    }
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

#[test]
fn protected_mount_fat32_repairs_multi_block_corruption_and_refreshes_on_rw_bd_q19uk() {
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("image.fat32");
    let sidecar = dir.path().join("image.ffs-rq");
    let cx = Cx::for_testing();
    File::create(&image)
        .unwrap()
        .set_len(36 * 1024 * 1024)
        .unwrap();
    command(
        Command::new("mkfs.fat")
            .args(["-F", "32", "-S", "512", "-s", "1"])
            .arg(&image),
    );
    let payload: Vec<u8> = (0_u32..16_384).map(|i| (i % 251) as u8).collect();
    {
        let volume = fat::reader::replacement::open_volume(
            &cx,
            &fat::reader::ImageArgs {
                image: image.clone(),
                offset: 0,
                length: None,
                oem_code_page: ffs_ondisk::fat::FatOemCodePage::Ascii,
                sidecar: None,
            },
            true,
        )
        .unwrap();
        fat::reader::replacement::create_in_volume(
            &cx,
            &volume,
            "/payload.bin",
            &payload,
            1_700_000_000,
            false,
        )
        .unwrap();
    }
    protect(
        &cx,
        &image,
        &sidecar,
        SidecarOptions {
            block_size: 4096,
            group_blocks: 16,
            repair_symbols: 4,
        },
    )
    .expect("protect fat32 image");

    let fixture = Fixture {
        dir,
        image,
        sidecar,
        payload,
    };

    // Find physical 4096-byte blocks of /payload.bin
    let data_block_0 = {
        let vol = fat::reader::FatVolume::open(&cx, &fixture.image, 0, None).unwrap();
        let entry = vol.resolve(&cx, "/payload.bin").unwrap().unwrap();
        let chain = vol.file_chain(&cx, &entry).unwrap();
        assert!(chain.clusters.len() >= 2);
        let offset = fixture.read_block(0);
        let _ = offset;
        let bpb =
            ffs_ondisk::fat::FatGeometry::parse(&fixture.read_block(0)[..512], 64 * 1024 * 1024)
                .unwrap();
        bpb.cluster_offset(chain.clusters[0]).unwrap() / 4096
    };
    let data_block_1 = data_block_0 + 1;
    let orig_0 = fixture.read_block(data_block_0);
    let orig_1 = fixture.read_block(data_block_1);

    let prepared = prepare(&cx, &fixture.args()).expect("admit protected fat32");
    assert_eq!(prepared.filesystem, "fat32");
    // Inject multi-block corruption (2 blocks in the same group!)
    fixture.damage_block(data_block_0);
    fixture.damage_block(data_block_1);
    assert_ne!(fixture.read_block(data_block_0), orig_0);
    assert_ne!(fixture.read_block(data_block_1), orig_1);

    let mut scope = RequestScope::empty();
    let attr = FsOps::lookup(
        prepared.fs.as_ref(),
        &cx,
        &mut scope,
        InodeNumber(1),
        OsStr::new("payload.bin"),
    )
    .unwrap();
    let read_back = FsOps::read(
        prepared.fs.as_ref(),
        &cx,
        &mut scope,
        attr.ino,
        0,
        u32::try_from(fixture.payload.len()).unwrap(),
    )
    .unwrap();
    assert_eq!(read_back, fixture.payload);
    assert_eq!(
        fixture.read_block(data_block_0),
        orig_0,
        "block 0 must be self-healed on disk"
    );
    assert_eq!(
        fixture.read_block(data_block_1),
        orig_1,
        "block 1 must be self-healed on disk"
    );
    prepared.finish(&cx).unwrap();
    assert!(
        verify(&cx, &fixture.image, &fixture.sidecar)
            .unwrap()
            .is_healthy()
    );

    // Now mount writable (--rw), write a new file, and verify sidecar refreshes on finish
    let rw_prepared = prepare(&cx, &fixture.writable_args()).expect("admit writable fat32");
    assert!(rw_prepared.fs.is_writable());
    let new_data = vec![0xA7_u8; 12_288];
    let created = FsOps::create(
        rw_prepared.fs.as_ref(),
        &cx,
        &mut scope,
        InodeNumber(1),
        OsStr::new("written.bin"),
        0o644,
        0,
        0,
    )
    .unwrap();
    let written = FsOps::write(
        rw_prepared.fs.as_ref(),
        &cx,
        &mut scope,
        created.ino,
        0,
        &new_data,
    )
    .unwrap();
    assert_eq!(written as usize, new_data.len());
    rw_prepared.finish(&cx).unwrap();
    assert!(
        verify(&cx, &fixture.image, &fixture.sidecar)
            .unwrap()
            .is_healthy()
    );
}

#[test]
fn protected_mount_ntfs_repairs_multi_block_corruption_on_read_bd_q19uk() {
    let dir = tempfile::tempdir().unwrap();
    let image_path = dir.path().join("image.ntfs");
    let sidecar_path = dir.path().join("image.ffs-rq");
    let cx = Cx::for_testing();

    // Build a valid 1 MiB NTFS 3.1 image with 512-byte sectors/clusters and a 16 KiB non-resident file
    let length = 1024 * 1024_usize;
    let mut image = vec![0_u8; length];
    let boot = &mut image[..512];
    boot[3..11].copy_from_slice(b"NTFS    ");
    boot[11..13].copy_from_slice(&512_u16.to_le_bytes());
    boot[13] = 1;
    boot[21] = 0xF8;
    boot[40..48].copy_from_slice(&2047_u64.to_le_bytes());
    boot[48..56].copy_from_slice(&4_u64.to_le_bytes());
    boot[56..64].copy_from_slice(&128_u64.to_le_bytes());
    boot[64] = 0xF6;
    boot[68] = 0xF4;
    boot[510..512].copy_from_slice(&[0x55, 0xAA]);

    let resident = |kind: u32, id: u16, name: &str, value: &[u8]| -> Vec<u8> {
        let name: Vec<_> = name.encode_utf16().collect();
        let start = (24 + name.len() * 2).next_multiple_of(8);
        let len = (start + value.len()).next_multiple_of(8);
        let mut attr = vec![0; len];
        attr[..4].copy_from_slice(&kind.to_le_bytes());
        attr[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        attr[9] = name.len() as u8;
        attr[10..12].copy_from_slice(&24_u16.to_le_bytes());
        attr[14..16].copy_from_slice(&id.to_le_bytes());
        attr[16..20].copy_from_slice(&(value.len() as u32).to_le_bytes());
        attr[20..22].copy_from_slice(&(start as u16).to_le_bytes());
        for (idx, unit) in name.iter().enumerate() {
            attr[24 + idx * 2..26 + idx * 2].copy_from_slice(&unit.to_le_bytes());
        }
        attr[start..start + value.len()].copy_from_slice(value);
        attr
    };
    let mapped = |pairs: &[u8], clusters: u64, size: u64| -> Vec<u8> {
        let start = 64_usize;
        let len = (start + pairs.len()).next_multiple_of(8);
        let mut attr = vec![0; len];
        attr[..4].copy_from_slice(&0x80_u32.to_le_bytes());
        attr[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        attr[8] = 1;
        attr[24..32].copy_from_slice(&(clusters - 1).to_le_bytes());
        attr[32..34].copy_from_slice(&(start as u16).to_le_bytes());
        attr[40..48].copy_from_slice(&(clusters * 512).to_le_bytes());
        attr[48..56].copy_from_slice(&size.to_le_bytes());
        attr[56..64].copy_from_slice(&size.to_le_bytes());
        attr[start..start + pairs.len()].copy_from_slice(pairs);
        attr
    };
    let mut std_info = [0_u8; 72];
    for i in 0..4 {
        std_info[i * 8..i * 8 + 8].copy_from_slice(&116_444_736_000_000_000_u64.to_le_bytes());
    }
    let standard = resident(0x10, 500, "", &std_info);
    let filename = |parent: u64, name: &str, ns: u8| -> Vec<u8> {
        let units: Vec<_> = name.encode_utf16().collect();
        let mut bytes = vec![0; 66 + units.len() * 2];
        bytes[..8].copy_from_slice(&((7_u64 << 48) | parent).to_le_bytes());
        bytes[64] = units.len() as u8;
        bytes[65] = ns;
        for (i, u) in units.iter().enumerate() {
            bytes[66 + i * 2..68 + i * 2].copy_from_slice(&u.to_le_bytes());
        }
        bytes
    };
    let make_record = |number: u32, directory: bool, links: u16, attrs: &[Vec<u8>]| -> Vec<u8> {
        let mut raw = vec![0; 1024];
        raw[..4].copy_from_slice(b"FILE");
        raw[4..6].copy_from_slice(&48_u16.to_le_bytes());
        raw[6..8].copy_from_slice(&3_u16.to_le_bytes());
        raw[16..18].copy_from_slice(&7_u16.to_le_bytes());
        raw[18..20].copy_from_slice(&links.to_le_bytes());
        raw[20..22].copy_from_slice(&56_u16.to_le_bytes());
        raw[22..24].copy_from_slice(&(if directory { 3_u16 } else { 1 }).to_le_bytes());
        raw[28..32].copy_from_slice(&1024_u32.to_le_bytes());
        raw[44..48].copy_from_slice(&number.to_le_bytes());
        let mut at = 56;
        for attr in attrs {
            raw[at..at + attr.len()].copy_from_slice(attr);
            at += attr.len();
        }
        raw[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        raw[24..28].copy_from_slice(&((at + 8) as u32).to_le_bytes());
        raw[48..50].copy_from_slice(&0x1234_u16.to_le_bytes());
        for part in 1..=2 {
            let saved = [raw[part * 512 - 2], raw[part * 512 - 1]];
            raw[48 + part * 2..50 + part * 2].copy_from_slice(&saved);
            raw[part * 512 - 2..part * 512].copy_from_slice(&0x1234_u16.to_le_bytes());
        }
        raw
    };
    let put = |img: &mut [u8], number: u32, bytes: &[u8]| {
        let at = 4 * 512 + number as usize * 1024;
        img[at..at + 1024].copy_from_slice(bytes);
    };
    let mft = make_record(
        0,
        false,
        1,
        &[
            mapped(&[0x11, 80, 4, 0], 80, 40960),
            resident(0xB0, 1, "", &[0xFF, 0, 0, 0x01, 0]),
        ],
    );
    put(&mut image, 0, &mft);
    image[128 * 512..130 * 512].copy_from_slice(&mft);
    // Supply the native journal required by clean-only NTFS admission. Its
    // fully initialized erased bytes are disjoint from MFT, mirror, UpCase
    // and the protected file payload; no recovery bypass is involved.
    put(
        &mut image,
        2,
        &make_record(
            2,
            false,
            1,
            &[
                standard.clone(),
                mapped(&[0x21, 64, 0xC0, 0, 0], 64, 32_768),
            ],
        ),
    );
    image[192 * 512..256 * 512].fill(0xFF);
    let mut vol_info = [0_u8; 12];
    vol_info[8..10].copy_from_slice(&[3, 1]);
    put(
        &mut image,
        3,
        &make_record(3, false, 1, &[resident(0x70, 0, "", &vol_info)]),
    );
    let mut root_idx = vec![0_u8; 32];
    root_idx[..4].copy_from_slice(&0x30_u32.to_le_bytes());
    root_idx[4..8].copy_from_slice(&1_u32.to_le_bytes());
    root_idx[8..12].copy_from_slice(&4096_u32.to_le_bytes());
    root_idx[12] = 8;
    root_idx[16..20].copy_from_slice(&16_u32.to_le_bytes());
    {
        let val = filename(5, "payload.bin", 1);
        let len = (16 + val.len()).next_multiple_of(8);
        let mut entry = vec![0_u8; len];
        entry[..8].copy_from_slice(&((7_u64 << 48) | 24).to_le_bytes());
        entry[8..10].copy_from_slice(&(len as u16).to_le_bytes());
        entry[10..12].copy_from_slice(&(val.len() as u16).to_le_bytes());
        entry[16..16 + val.len()].copy_from_slice(&val);
        root_idx.extend(entry);
    }
    let mut last_entry = [0_u8; 16];
    last_entry[8] = 16;
    last_entry[12] = 2;
    root_idx.extend(last_entry);
    let used = root_idx.len() as u32 - 16;
    root_idx[20..24].copy_from_slice(&used.to_le_bytes());
    root_idx[24..28].copy_from_slice(&used.to_le_bytes());
    put(
        &mut image,
        5,
        &make_record(
            5,
            true,
            1,
            &[standard.clone(), resident(0x90, 40, "$I30", &root_idx)],
        ),
    );
    put(
        &mut image,
        6,
        &make_record(6, false, 1, &[resident(0x80, 0, "", &[0xFF; 256])]),
    );
    // $UpCase at LCN 300 (256 sectors = 128 KiB)
    put(
        &mut image,
        10,
        &make_record(
            10,
            false,
            1,
            &[mapped(&[0x22, 0, 1, 44, 1, 0], 256, 131_072)],
        ),
    );
    for unit in 0..=u16::MAX {
        let upper = if (97..=122).contains(&unit) {
            unit - 32
        } else {
            unit
        };
        let at = 300 * 512 + usize::from(unit) * 2;
        image[at..at + 2].copy_from_slice(&upper.to_le_bytes());
    }
    // Record 24: non-resident 12 KiB file at LCN 640 (byte offset 327,680 = 4096-block 80)
    // Mapping pairs for 24 clusters starting at LCN 640 (0x0280): [0x21, 24, 0x80, 0x02, 0]
    let payload: Vec<u8> = (0_u32..12_288).map(|i| (i % 241) as u8).collect();
    image[640 * 512..640 * 512 + payload.len()].copy_from_slice(&payload);
    put(
        &mut image,
        24,
        &make_record(
            24,
            false,
            1,
            &[
                standard,
                mapped(&[0x21, 24, 0x80, 0x02, 0], 24, payload.len() as u64),
                resident(0x30, 2, "", &filename(5, "payload.bin", 1)),
            ],
        ),
    );

    std::fs::write(&image_path, &image).unwrap();
    protect(
        &cx,
        &image_path,
        &sidecar_path,
        SidecarOptions {
            block_size: 4096,
            group_blocks: 16,
            repair_symbols: 4,
        },
    )
    .expect("protect ntfs image");

    let fixture = Fixture {
        dir,
        image: image_path,
        sidecar: sidecar_path,
        payload,
    };

    // Refuse --rw for NTFS
    assert!(prepare(&cx, &fixture.writable_args()).is_err());

    let prepared = prepare(&cx, &fixture.args()).expect("admit protected ntfs");
    assert_eq!(prepared.filesystem, "ntfs");
    assert_eq!(
        std::fs::read(&fixture.image).unwrap(),
        image,
        "clean NTFS preparation must not alter the native journal or backing bytes"
    );

    // Corrupt TWO 4096-byte blocks in the file's data region (blocks 80 and 81)
    let orig_80 = fixture.read_block(80);
    let orig_81 = fixture.read_block(81);
    fixture.damage_block(80);
    fixture.damage_block(81);
    assert_ne!(fixture.read_block(80), orig_80);
    assert_ne!(fixture.read_block(81), orig_81);

    let mut scope = RequestScope::empty();
    let attr = FsOps::lookup(
        prepared.fs.as_ref(),
        &cx,
        &mut scope,
        InodeNumber(1),
        OsStr::new("payload.bin"),
    )
    .unwrap();
    let read_back = FsOps::read(
        prepared.fs.as_ref(),
        &cx,
        &mut scope,
        attr.ino,
        0,
        u32::try_from(fixture.payload.len()).unwrap(),
    )
    .unwrap();
    assert_eq!(read_back, fixture.payload);
    assert_eq!(
        fixture.read_block(80),
        orig_80,
        "NTFS block 80 must be self-healed on disk"
    );
    assert_eq!(
        fixture.read_block(81),
        orig_81,
        "NTFS block 81 must be self-healed on disk"
    );
    prepared.finish(&cx).unwrap();
    assert!(
        verify(&cx, &fixture.image, &fixture.sidecar)
            .unwrap()
            .is_healthy()
    );
}

#[test]
fn protected_mount_zfs_repairs_multi_block_corruption_on_read_bd_q19uk() {
    use ffs_ondisk::zfs::{
        DATA_OFFSET, Endian, LABEL_BYTES, LABEL_CONFIG_BYTES, LABEL_CONFIG_OFFSET,
        UBERBLOCK_RING_OFFSET, checksum, label_offsets,
    };
    use sha2::{Digest, Sha256};

    let dir = tempfile::tempdir().unwrap();
    let image_path = dir.path().join("image.zfs");
    let sidecar_path = dir.path().join("image.ffs-rq");
    let cx = Cx::for_testing();

    let length = 8 * 1024 * 1024_usize;
    let order = Endian::Little;
    let mut image = vec![0_u8; length];

    let u16put = |raw: &mut [u8], at: usize, value: u16| {
        raw[at..at + 2].copy_from_slice(&value.to_le_bytes());
    };
    let bp = |raw: &[u8], at: u64, kind: u8, level: u8, birth: u64| -> Vec<u8> {
        let mut words = [0_u64; 16];
        words[0] = raw.len() as u64 / 512;
        words[1] = (at - DATA_OFFSET) / 512;
        words[6] = (raw.len() as u64 / 512 - 1)
            | ((raw.len() as u64 / 512 - 1) << 16)
            | (2 << 32)
            | (7 << 40)
            | (u64::from(kind) << 48)
            | (u64::from(level) << 56)
            | (1_u64 << 63);
        words[10] = birth;
        words[12..].copy_from_slice(&checksum(raw, 7, order).unwrap());
        words.into_iter().flat_map(|w| order.encode(w)).collect()
    };
    let node =
        |kind: u8, block: usize, levels: u8, max: u64, bonus: &[u8], bonus_type: u8| -> Vec<u8> {
            let mut raw = vec![0_u8; 512];
            raw[0] = kind;
            raw[1] = 12;
            raw[2] = levels;
            raw[3] = 1;
            raw[4] = bonus_type;
            raw[7] = 1;
            u16put(&mut raw, 8, (block / 512) as u16);
            u16put(&mut raw, 10, bonus.len() as u16);
            raw[16..24].copy_from_slice(&order.encode(max));
            raw[192..192 + bonus.len()].copy_from_slice(bonus);
            raw
        };
    let legacy = |mode: u64, size: u64, parent: u64| -> Vec<u8> {
        let mut raw = vec![0_u8; 264];
        for (at, value) in [
            (0, 1_700_000_000),
            (8, 123),
            (64, 10),
            (72, mode),
            (80, size),
            (88, parent),
            (96, 2),
            (128, 1000),
            (136, 100),
        ] {
            raw[at..at + 8].copy_from_slice(&order.encode(value));
        }
        raw
    };
    let micro = |entries: &[(&[u8], u64)]| -> Vec<u8> {
        let mut raw = vec![0_u8; 512];
        raw[..8].copy_from_slice(&order.encode((1 << 63) + 3));
        for (i, (name, value)) in entries.iter().enumerate() {
            let at = 64 + i * 64;
            raw[at..at + 8].copy_from_slice(&order.encode(*value));
            raw[at + 14..at + 14 + name.len()].copy_from_slice(name);
        }
        raw
    };

    let mos_at = DATA_OFFSET + 0x10000;
    let pool_map_at = DATA_OFFSET + 0x14000;
    let os_at = DATA_OFFSET + 0x18000;
    let table_at = DATA_OFFSET + 0x20000;
    let master_at = DATA_OFFSET + 0x25000;
    let root_map_at = DATA_OFFSET + 0x26000;
    let file_blk0_at = DATA_OFFSET + 0x28000;
    let file_blk1_at = DATA_OFFSET + 0x29000;
    let indirect_at = DATA_OFFSET + 0x2e000;

    let mut table = vec![0_u8; 16_384];
    let master = micro(&[(b"ROOT", 2), (b"VERSION", 4)]);
    image[master_at as usize..master_at as usize + 512].copy_from_slice(&master);
    let mut master_node = node(21, 512, 1, 0, &[], 0);
    master_node[64..192].copy_from_slice(&bp(&master, master_at, 21, 0, 20));
    table[512..1024].copy_from_slice(&master_node);

    let root_dir = micro(&[(b"payload.bin", (8 << 60) | 3)]);
    image[root_map_at as usize..root_map_at as usize + 512].copy_from_slice(&root_dir);
    let mut root_dn = node(20, 512, 1, 0, &legacy(0o040_755, 2, 2), 17);
    root_dn[64..192].copy_from_slice(&bp(&root_dir, root_map_at, 20, 0, 20));
    table[2 * 512..3 * 512].copy_from_slice(&root_dn);

    let blk0: Vec<u8> = (0_u32..4096).map(|i| (i % 239) as u8).collect();
    let blk1: Vec<u8> = (0_u32..4096).map(|i| ((i + 77) % 239) as u8).collect();
    let mut payload = blk0.clone();
    payload.extend_from_slice(&blk1);
    image[file_blk0_at as usize..file_blk0_at as usize + 4096].copy_from_slice(&blk0);
    image[file_blk1_at as usize..file_blk1_at as usize + 4096].copy_from_slice(&blk1);

    let mut indirect = vec![0_u8; 4096];
    indirect[..128].copy_from_slice(&bp(&blk0, file_blk0_at, 19, 0, 20));
    indirect[128..256].copy_from_slice(&bp(&blk1, file_blk1_at, 19, 0, 20));
    image[indirect_at as usize..indirect_at as usize + 4096].copy_from_slice(&indirect);

    let mut file_dn = node(
        19,
        4096,
        2,
        1,
        &legacy(0o100_644, payload.len() as u64, 2),
        17,
    );
    file_dn[24..32].copy_from_slice(&order.encode(8192));
    file_dn[64..192].copy_from_slice(&bp(&indirect, indirect_at, 19, 1, 30));
    table[3 * 512..4 * 512].copy_from_slice(&file_dn);
    image[table_at as usize..table_at as usize + table.len()].copy_from_slice(&table);

    let mut os = vec![0_u8; 1024];
    let mut os_meta = node(10, 16_384, 1, 0, &[], 0);
    os_meta[64..192].copy_from_slice(&bp(&table, table_at, 10, 0, 40));
    os[..512].copy_from_slice(&os_meta);
    os[704..712].copy_from_slice(&order.encode(2));
    image[os_at as usize..os_at as usize + 1024].copy_from_slice(&os);

    let mut mos_table = vec![0_u8; 16_384];
    let pool_zap = micro(&[
        (b"root_dataset", 2),
        (b"features_for_read", 29),
        (b"features_for_write", 30),
        (b"feature_descriptions", 31),
    ]);
    image[pool_map_at as usize..pool_map_at as usize + 512].copy_from_slice(&pool_zap);
    let mut pool_dn = node(1, 512, 1, 0, &[], 0);
    pool_dn[64..192].copy_from_slice(&bp(&pool_zap, pool_map_at, 1, 0, 20));
    mos_table[512..1024].copy_from_slice(&pool_dn);
    let mut dir_bonus = vec![0_u8; 256];
    dir_bonus[8..16].copy_from_slice(&order.encode(3));
    mos_table[1024..1536].copy_from_slice(&node(12, 512, 1, 0, &dir_bonus, 12));
    let mut ds_bonus = vec![0_u8; 320];
    for (at, value) in [(0, 2), (56, 5), (112, 987), (120, 4)] {
        ds_bonus[at..at + 8].copy_from_slice(&order.encode(value));
    }
    ds_bonus[128..256].copy_from_slice(&bp(&os, os_at, 11, 0, 45));
    mos_table[1536..2048].copy_from_slice(&node(16, 512, 1, 0, &ds_bonus, 16));
    // Version 5000 requires distinct native MOS feature catalogs, even when
    // this uncompressed fixture enables no features. These blocks occupy the
    // unused gap after the pool directory and before the dataset object set.
    for (object, at) in [
        (29, DATA_OFFSET + 0x14400),
        (30, DATA_OFFSET + 0x14600),
        (31, DATA_OFFSET + 0x14800),
    ] {
        let catalog = micro(&[]);
        image[at as usize..at as usize + catalog.len()].copy_from_slice(&catalog);
        let mut catalog_dn = node(196, 512, 1, 0, &[], 0);
        catalog_dn[64..192].copy_from_slice(&bp(&catalog, at, 196, 0, 20));
        mos_table[object * 512..(object + 1) * 512].copy_from_slice(&catalog_dn);
    }
    image[mos_at as usize..mos_at as usize + mos_table.len()].copy_from_slice(&mos_table);

    let mut mos_os = vec![0_u8; 1024];
    let mut mos_meta = node(10, 16_384, 1, 0, &[], 0);
    mos_meta[64..192].copy_from_slice(&bp(&mos_table, mos_at, 10, 0, 50));
    mos_os[..512].copy_from_slice(&mos_meta);
    mos_os[704..712].copy_from_slice(&order.encode(1));
    let mos_os_at = DATA_OFFSET + 0x1000;
    image[mos_os_at as usize..mos_os_at as usize + 1024].copy_from_slice(&mos_os);

    let mut ub = vec![0_u8; 1024];
    for (at, value) in [
        (0, 0x00ba_b10c),
        (8, 5000),
        (16, 50),
        (24, 1122),
        (32, 1_700_000_000),
    ] {
        ub[at..at + 8].copy_from_slice(&order.encode(value));
    }
    ub[40..168].copy_from_slice(&bp(&mos_os, mos_os_at, 11, 0, 50));

    let xstring = |value: &str| -> Vec<u8> {
        let mut bytes = (value.len() as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(value.as_bytes());
        bytes.resize(bytes.len().next_multiple_of(4), 0);
        bytes
    };
    let pair = |name: &str, kind: u32, data: &[u8]| -> Vec<u8> {
        let mut bytes = vec![0; 8];
        bytes.extend_from_slice(&xstring(name));
        bytes.extend_from_slice(&kind.to_be_bytes());
        bytes.extend_from_slice(&1_u32.to_be_bytes());
        bytes.extend_from_slice(data);
        let len = bytes.len() as u32;
        bytes[..4].copy_from_slice(&len.to_be_bytes());
        bytes[4..8].copy_from_slice(&64_u32.to_be_bytes());
        bytes
    };
    let uint = |name: &str, value: u64| pair(name, 8, &value.to_be_bytes());
    let list = |pairs: &[Vec<u8>]| -> Vec<u8> {
        let mut bytes = vec![0, 0, 0, 0, 0, 0, 0, 1];
        for p in pairs {
            bytes.extend_from_slice(p);
        }
        bytes.extend_from_slice(&[0; 8]);
        bytes
    };
    let vdev_tree = list(&[
        pair("type", 9, &xstring("file")),
        uint("id", 0),
        uint("guid", 999),
        uint("ashift", 9),
        uint("asize", length as u64 - DATA_OFFSET - 2 * LABEL_BYTES),
        uint("is_log", 0),
    ]);
    let mut cfg = vec![1, 1, 0, 0];
    cfg.extend_from_slice(&list(&[
        uint("version", 5000),
        uint("state", 1),
        uint("txg", 50),
        uint("pool_guid", 123),
        uint("guid", 999),
        uint("top_guid", 999),
        uint("vdev_children", 1),
        pair("name", 9, &xstring("tank")),
        pair("vdev_tree", 19, &vdev_tree),
        pair("features_for_read", 19, &list(&[])),
    ]));
    let stamp = |bytes: &mut [u8], offset: u64| {
        let at = bytes.len() - 40;
        bytes[at..at + 8].copy_from_slice(&order.encode(0x0210_da7a_b10c_7a11));
        bytes[at + 8..].fill(0);
        bytes[at + 8..at + 16].copy_from_slice(&order.encode(offset));
        let digest = Sha256::digest(&*bytes);
        for i in 0..4 {
            let word = u64::from_be_bytes(std::array::from_fn(|n| digest[i * 8 + n]));
            bytes[at + 8 + i * 8..at + 16 + i * 8].copy_from_slice(&order.encode(word));
        }
    };
    for label in label_offsets(length as u64).unwrap() {
        let cfg_off = label + LABEL_CONFIG_OFFSET;
        let mut cfg_blk = vec![0_u8; LABEL_CONFIG_BYTES];
        cfg_blk[..cfg.len()].copy_from_slice(&cfg);
        stamp(&mut cfg_blk, cfg_off);
        image[cfg_off as usize..cfg_off as usize + LABEL_CONFIG_BYTES].copy_from_slice(&cfg_blk);

        let ub_off = label + UBERBLOCK_RING_OFFSET;
        let mut ub_blk = ub.clone();
        stamp(&mut ub_blk, ub_off);
        image[ub_off as usize..ub_off as usize + ub_blk.len()].copy_from_slice(&ub_blk);
    }

    std::fs::write(&image_path, &image).unwrap();
    protect(
        &cx,
        &image_path,
        &sidecar_path,
        SidecarOptions {
            block_size: 4096,
            group_blocks: 16,
            repair_symbols: 4,
        },
    )
    .expect("protect zfs image");

    let fixture = Fixture {
        dir,
        image: image_path,
        sidecar: sidecar_path,
        payload,
    };

    // Refuse --rw for ZFS
    assert!(prepare(&cx, &fixture.writable_args()).is_err());

    let prepared = prepare(&cx, &fixture.args()).expect("admit protected zfs");
    assert_eq!(prepared.filesystem, "zfs");
    assert_eq!(std::fs::read(&fixture.image).unwrap(), image);

    // Corrupt TWO 4096-byte blocks in the same group (file_blk0_at and file_blk1_at)
    let blk_a = file_blk0_at / 4096;
    let blk_b = file_blk1_at / 4096;
    let orig_a = fixture.read_block(blk_a);
    let orig_b = fixture.read_block(blk_b);
    fixture.damage_block(blk_a);
    fixture.damage_block(blk_b);
    assert_ne!(fixture.read_block(blk_a), orig_a);
    assert_ne!(fixture.read_block(blk_b), orig_b);

    let mut scope = RequestScope::empty();
    let attr = FsOps::lookup(
        prepared.fs.as_ref(),
        &cx,
        &mut scope,
        InodeNumber(1),
        OsStr::new("payload.bin"),
    )
    .unwrap();
    let read_back = FsOps::read(
        prepared.fs.as_ref(),
        &cx,
        &mut scope,
        attr.ino,
        0,
        u32::try_from(fixture.payload.len()).unwrap(),
    )
    .unwrap();
    assert_eq!(read_back, fixture.payload);
    assert_eq!(
        fixture.read_block(blk_a),
        orig_a,
        "ZFS block A must be self-healed on disk"
    );
    assert_eq!(
        fixture.read_block(blk_b),
        orig_b,
        "ZFS block B must be self-healed on disk"
    );
    prepared.finish(&cx).unwrap();
    assert!(
        verify(&cx, &fixture.image, &fixture.sidecar)
            .unwrap()
            .is_healthy()
    );
}
