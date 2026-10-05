use super::*;
use ffs_repair::sidecar::{SidecarOptions, protect, verify};
use std::ffi::OsStr;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

fn check_args(image: &Path, sidecar: &Path) -> Args {
    Args {
        image: image.to_owned(),
        sidecar: sidecar.to_owned(),
        mountpoint: None,
        authority: Authority {
            exclusive_image: true,
            allow_repair: true,
        },
        check: true,
        allow_other: false,
    }
}

fn command(command: &mut Command) -> Output {
    let output = command
        .output()
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
    _dir: TempDir,
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
            _dir: dir,
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
    let inode = prepared
        .fs
        .lookup(&cx, InodeNumber(2), OsStr::new("payload"))
        .unwrap()
        .ino;
    let original = fixture.read_block(block);
    fixture.damage_block(block);
    assert_ne!(fixture.read_block(block), original);
    assert_eq!(
        prepared
            .fs
            .read(&cx, inode, 0, u32::try_from(fixture.payload.len()).unwrap())
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
    let attr = prepared
        .fs
        .lookup(&cx, InodeNumber(2), OsStr::new("payload"))
        .unwrap();
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
    let device = SidecarImageDevice::open(&cx, &fixture.image, &fixture.sidecar).unwrap();
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
    let device = ProtectedReadOnly(Arc::clone(&prepared.device));
    assert!(matches!(
        device.write_all_at(&cx, ByteOffset(4096), &[1]),
        Err(FfsError::ReadOnly)
    ));
    let error = prepared
        .fs
        .create(&cx, InodeNumber(2), OsStr::new("no-write"), 0o600, 0, 0)
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
    assert!(SidecarImageDevice::open(&cx, &fixture.image, &fixture.sidecar).is_err());
    drop(in_flight);
    let device = SidecarImageDevice::open(&cx, &fixture.image, &fixture.sidecar).unwrap();
    device.sync(&cx).unwrap();
}
