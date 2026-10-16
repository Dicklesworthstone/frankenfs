//! Production FsOps tests against native images; no kernel-mount claim.

use super::*;
use crate::filesystem::{ROOT, MAX_SYNTHETIC_INO};
use crate::reader::{FatVolume, ImageArgs};
use clap::Parser as _;
use ffs_core::{FsOps, RequestScope};
use ffs_ondisk::fat::FatOemCodePage;

fn fixture(kind: &str) -> (tempfile::TempDir, ImageArgs) {
    let directory = tempfile::tempdir().unwrap();
    let image = directory.path().join("mounted.fat");
    let cli = crate::Cli::try_parse_from([
        "ffs-fat", "format", image.to_str().unwrap(), "--kind", kind,
        "--size-mib", if kind == "fat16" { "4" } else { "64" },
    ]).unwrap();
    let crate::Command::Format { options } = cli.command else { panic!("expected formatter"); };
    let cx = Cx::for_testing();
    crate::formatter::create(&cx, &options).unwrap();
    let args = ImageArgs { image, offset: 0, length: None,
        oem_code_page: FatOemCodePage::Ascii, sidecar: None };
    let volume = crate::reader::replacement::open_volume(&cx, &args, true).unwrap();
    for (path, bytes) in [("/left.bin", b"left".as_slice()), ("/right.bin", b"right object")] {
        crate::reader::replacement::create_in_volume(&cx, &volume, path, bytes, 1_700_000_000, false).unwrap();
    }
    drop(volume);
    (directory, args)
}

fn mounted(args: &ImageArgs, writable: bool) -> FatFs {
    let cx = Cx::for_testing();
    let volume = crate::reader::replacement::open_volume(&cx, args, writable).unwrap();
    FatFs::new_with_mode(&cx, volume, 1000, 1000, writable).unwrap()
}

fn lookup(fs: &FatFs, parent: InodeNumber, name: &str) -> InodeNumber {
    fs.lookup(&Cx::for_testing(), &mut RequestScope::empty(), parent, OsStr::new(name)).unwrap().ino
}

fn bytes(fs: &FatFs, ino: InodeNumber) -> Vec<u8> {
    fs.read(&Cx::for_testing(), &mut RequestScope::empty(), ino, 0, 1024).unwrap()
}

#[test]
fn exchange_open_inodes_keep_payload_and_subsequent_writes_follow_objects() {
    for kind in ["fat16", "fat32"] {
        let (_directory, args) = fixture(kind);
        let fs = mounted(&args, true);
        let cx = Cx::for_testing();
        let mut scope = RequestScope::empty();
        let left = lookup(&fs, ROOT, "left.bin");
        let right = lookup(&fs, ROOT, "right.bin");
        fs.open(&cx, &mut scope, left, libc::O_RDWR).unwrap();
        fs.open(&cx, &mut scope, right, libc::O_RDWR).unwrap();
        assert_eq!(bytes(&fs, left), b"left");
        assert_eq!(bytes(&fs, right), b"right object");
        let ops: &dyn FsOps = &fs;
        ops.rename2(&cx, &mut scope, ROOT, OsStr::new("left.bin"), ROOT,
            OsStr::new("right.bin"), libc::RENAME_EXCHANGE).unwrap();
        assert_eq!(lookup(&fs, ROOT, "LEFT.BIN"), right);
        assert_eq!(lookup(&fs, ROOT, "right.bin"), left);
        assert_eq!(bytes(&fs, left), b"left");
        assert_eq!(bytes(&fs, right), b"right object");
        fs.write(&cx, &mut scope, left, 4, b" follows inode").unwrap();
        assert_eq!(bytes(&fs, lookup(&fs, ROOT, "right.bin")), b"left follows inode");
        assert_eq!(bytes(&fs, lookup(&fs, ROOT, "left.bin")), b"right object");
        let listing = fs.readdir(&cx, &mut scope, ROOT, 0).unwrap();
        assert!(listing.iter().any(|entry| entry.name == b"left.bin" && entry.ino == right));
        assert!(listing.iter().any(|entry| entry.name == b"right.bin" && entry.ino == left));
        assert!(fs.volume.check(&cx).unwrap().clean);
    }
}

#[test]
fn exchange_moves_both_directory_parents_without_invalidating_descendant_inodes() {
    let (_directory, args) = fixture("fat16");
    let fs = mounted(&args, true);
    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    let parent = fs.mkdir(&cx, &mut scope, ROOT, OsStr::new("parent"), 0o755, 1000, 1000).unwrap().ino;
    let left = fs.mkdir(&cx, &mut scope, ROOT, OsStr::new("leftdir"), 0o755, 1000, 1000).unwrap().ino;
    let right = fs.mkdir(&cx, &mut scope, parent, OsStr::new("rightdir"), 0o755, 1000, 1000).unwrap().ino;
    let left_child = fs.create(&cx, &mut scope, left, OsStr::new("a.bin"), 0o644, 1000, 1000).unwrap().ino;
    let right_child = fs.create(&cx, &mut scope, right, OsStr::new("b.bin"), 0o644, 1000, 1000).unwrap().ino;
    fs.write(&cx, &mut scope, left_child, 0, b"A").unwrap();
    fs.write(&cx, &mut scope, right_child, 0, b"B").unwrap();
    fs.rename2(&cx, &mut scope, ROOT, OsStr::new("leftdir"), parent,
        OsStr::new("rightdir"), libc::RENAME_EXCHANGE).unwrap();
    assert_eq!(lookup(&fs, ROOT, "leftdir"), right);
    assert_eq!(lookup(&fs, parent, "rightdir"), left);
    assert_eq!(lookup(&fs, left, ".."), parent);
    assert_eq!(lookup(&fs, right, ".."), ROOT);
    assert_eq!(lookup(&fs, left, "a.bin"), left_child);
    assert_eq!(lookup(&fs, right, "b.bin"), right_child);
    fs.write(&cx, &mut scope, left_child, 1, b" moved").unwrap();
    assert_eq!(bytes(&fs, left_child), b"A moved");
    assert!(fs.volume.resolve(&cx, "/parent/rightdir/a.bin").is_ok());
    // Swap a nonempty directory and a file; inode types follow objects too.
    let file = lookup(&fs, ROOT, "left.bin");
    fs.rename2(&cx, &mut scope, ROOT, OsStr::new("leftdir"), ROOT,
        OsStr::new("left.bin"), libc::RENAME_EXCHANGE).unwrap();
    assert_eq!(lookup(&fs, ROOT, "left.bin"), right);
    assert_eq!(lookup(&fs, ROOT, "leftdir"), file);
    assert_eq!(bytes(&fs, file), b"left");
    assert_eq!(lookup(&fs, right, "b.bin"), right_child);
    assert!(fs.volume.check(&cx).unwrap().clean);
}

#[test]
fn exchange_refusal_and_readonly_mode_leave_healthy_mounts_and_images_unchanged() {
    let (_directory, args) = fixture("fat16");
    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    let fs = mounted(&args, true);
    let before = std::fs::read(&args.image).unwrap();
    for (name, flag, error) in [
        ("missing", libc::RENAME_EXCHANGE, libc::ENOENT),
        ("right.bin", libc::RENAME_EXCHANGE | libc::RENAME_NOREPLACE, libc::EINVAL),
        ("right.bin", libc::RENAME_EXCHANGE | libc::RENAME_WHITEOUT, libc::EINVAL),
        ("right.bin", u32::MAX, libc::EINVAL),
        ("right.bin", libc::RENAME_NOREPLACE, libc::EEXIST),
    ] {
        let result = fs.rename2(&cx, &mut scope, ROOT, OsStr::new("left.bin"), ROOT, OsStr::new(name), flag);
        assert_eq!(result.unwrap_err().to_errno(), error);
    }
    fs.rename2(&cx, &mut scope, ROOT, OsStr::new("left.bin"), ROOT,
        OsStr::new("LEFT.BIN"), libc::RENAME_EXCHANGE).unwrap();
    assert_eq!(std::fs::read(&args.image).unwrap(), before);
    assert_eq!(bytes(&fs, lookup(&fs, ROOT, "left.bin")), b"left");
    drop(fs);
    let fs = mounted(&args, false);
    assert_eq!(fs.rename2(&cx, &mut scope, ROOT, OsStr::new("left.bin"), ROOT,
        OsStr::new("right.bin"), libc::RENAME_EXCHANGE).unwrap_err().to_errno(), libc::EROFS);
    assert_eq!(std::fs::read(&args.image).unwrap(), before);
}

#[test]
fn second_inode_capacity_failure_happens_before_native_exchange() {
    let (_directory, args) = fixture("fat16");
    let fs = mounted(&args, true);
    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    let before = std::fs::read(&args.image).unwrap();
    fs.state().unwrap().next_synthetic_ino = MAX_SYNTHETIC_INO;
    assert_eq!(fs.rename2(&cx, &mut scope, ROOT, OsStr::new("left.bin"), ROOT,
        OsStr::new("right.bin"), libc::RENAME_EXCHANGE).unwrap_err().to_errno(), libc::EOVERFLOW);
    assert_eq!(std::fs::read(&args.image).unwrap(), before);
    assert!(fs.getattr(&cx, &mut scope, ROOT).is_ok());
}

#[test]
fn failed_exchange_fences_cached_reads_and_sync_instead_of_publishing_stale_success() {
    use ffs_block::ByteDevice;
    use ffs_types::ByteOffset;
    use std::os::unix::fs::FileExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FailMetadata {
        file: std::fs::File,
        length: u64,
        writes: AtomicUsize,
    }
    impl ByteDevice for FailMetadata {
        fn len_bytes(&self) -> u64 { self.length }
        fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, bytes: &mut [u8]) -> Result<()> {
            checkpoint(cx)?;
            self.file.read_exact_at(bytes, offset.0)?;
            Ok(())
        }
        fn write_all_at(&self, cx: &Cx, offset: ByteOffset, bytes: &[u8]) -> Result<()> {
            checkpoint(cx)?;
            // Two FAT copies plus BPB dirty state precede the metadata write.
            if self.writes.fetch_add(1, Ordering::SeqCst) == 3 {
                self.file.write_all_at(&bytes[..bytes.len().min(63)], offset.0)?;
                return Err(std::io::Error::other("injected partial exchange metadata").into());
            }
            self.file.write_all_at(bytes, offset.0)?;
            Ok(())
        }
        fn sync(&self, cx: &Cx) -> Result<()> { checkpoint(cx)?; self.file.sync_all()?; Ok(()) }
    }
    let (_directory, args) = fixture("fat16");
    let file = std::fs::OpenOptions::new().read(true).write(true).open(&args.image).unwrap();
    let length = file.metadata().unwrap().len();
    let cx = Cx::for_testing();
    let device = FailMetadata { file, length, writes: AtomicUsize::new(0) };
    let volume = FatVolume::from_device(&cx, Box::new(device), 0, length).unwrap();
    let fs = FatFs::new_with_mode(&cx, volume, 1000, 1000, true).unwrap();
    let mut scope = RequestScope::empty();
    let left = lookup(&fs, ROOT, "left.bin");
    let right = lookup(&fs, ROOT, "right.bin");
    assert_eq!(bytes(&fs, left), b"left");
    assert_eq!(bytes(&fs, right), b"right object");
    assert!(fs.rename2(&cx, &mut scope, ROOT, OsStr::new("left.bin"), ROOT,
        OsStr::new("right.bin"), libc::RENAME_EXCHANGE).is_err());
    assert!(fs.read(&cx, &mut scope, left, 0, 64).is_err());
    assert!(fs.read(&cx, &mut scope, right, 0, 64).is_err());
    assert!(fs.readdir(&cx, &mut scope, ROOT, 0).is_err());
    assert!(fs.fsync(&cx, &mut scope, left, 0, false).is_err());
}
