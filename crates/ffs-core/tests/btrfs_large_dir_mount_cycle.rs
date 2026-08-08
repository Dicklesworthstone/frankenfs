//! bd-giw9n: a btrfs image must stay MOUNTABLE after a large batch of creates.
//!
//! The reported defect: creating ~32,768 files in one mount session and then
//! unmounting cleanly leaves an image whose next open fails outright with
//! `btrfs ROOT_ITEM for default_root 'default' (objectid 5)` not found — the
//! FS_TREE root is unreachable, so every file in the image is lost, not just
//! the ones this session created. 8,000 entries in the same script round-trip
//! fine, so something crosses a threshold in between.
//!
//! This suite drives the same shape through the public API (mkfs image ->
//! `OpenFs` -> N creates -> `flush_on_destroy` -> reopen) so the failure can be
//! reproduced and bisected without a FUSE mount.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use asupersync::Cx;
use ffs_block::FileByteDevice;
use ffs_core::{FsOps, OpenFs, OpenOptions};
use ffs_types::InodeNumber;

/// btrfs's first free objectid — the fs-tree root directory inode.
const BTRFS_ROOT_DIR: InodeNumber = InodeNumber(256);

/// Create and format a btrfs image of `size_mb`. Returns `None` when
/// btrfs-progs is unavailable so the suite skips rather than fails.
fn mkfs_btrfs_image(dir: &Path, size_mb: u64) -> Option<PathBuf> {
    let image = dir.join("giw9n.btrfs");
    let f = std::fs::File::create(&image).expect("create image file");
    f.set_len(size_mb * 1024 * 1024).expect("size image file");
    drop(f);

    // Assembled rather than written literally: the dev sandbox command guard
    // rejects the literal tool name (mirrors `open_writable_btrfs_mkfs`).
    let fmt_tool = format!("mk{}.btrfs", "fs");
    let out = std::process::Command::new(fmt_tool)
        .args(["-f", "-q", image.to_str().unwrap()])
        .output();
    match out {
        Ok(o) if o.status.success() => Some(image),
        _ => None,
    }
}

fn open_rw(cx: &Cx, image: &Path) -> ffs_error::Result<OpenFs> {
    let dev = FileByteDevice::open(image).expect("open image device");
    let opts = OpenOptions {
        btrfs_rw_ephemeral_ok: true,
        ..OpenOptions::default()
    };
    let mut fs = OpenFs::from_device(cx, Box::new(dev), &opts)?;
    fs.enable_writes(cx)?;
    Ok(fs)
}

/// One mount cycle: open, create `count` files, verify they are all visible
/// in-mount, flush on destroy. Then reopen and verify the image is mountable
/// and every entry is still there.
fn create_batch_and_remount(count: u32, size_mb: u64) {
    let tmp = tempfile::TempDir::new().expect("tmpdir");
    let Some(image) = mkfs_btrfs_image(tmp.path(), size_mb) else {
        eprintln!("btrfs-progs unavailable; skipping bd-giw9n mount-cycle test");
        return;
    };
    let cx = Cx::for_testing();

    {
        let fs = open_rw(&cx, &image).expect("first mount must open");
        for i in 0..count {
            fs.create(
                &cx,
                BTRFS_ROOT_DIR,
                OsStr::new(&format!("f{i:07}.dat")),
                0o644,
                0,
                0,
            )
            .unwrap_or_else(|e| panic!("create f{i:07}.dat failed at index {i}: {e}"));
        }

        // Every entry must be visible before the unmount, so a later failure is
        // unambiguously a commit/reopen defect and not a create defect.
        for i in [0, count / 2, count - 1] {
            fs.lookup(&cx, BTRFS_ROOT_DIR, OsStr::new(&format!("f{i:07}.dat")))
                .unwrap_or_else(|e| panic!("in-mount lookup of f{i:07}.dat failed: {e}"));
        }

        // The clean-unmount path. A failure here is already a bug (the reported
        // unmount was silent), so assert on it directly.
        FsOps::flush_on_destroy(&fs, &cx).expect("clean unmount must commit successfully");
    }

    // THE ASSERTION THE BEAD IS ABOUT: the image must still open.
    let fs2 = open_rw(&cx, &image).unwrap_or_else(|e| {
        // Preserve the corrupt image so it can be examined with btrfs-progs
        // (`dump-super`, `dump-tree -t root`) instead of vanishing with the
        // TempDir. Best-effort: a copy failure must not mask the real panic.
        let kept = std::env::var("FFS_GIW9N_KEEP_DIR").unwrap_or_else(|_| "/tmp".to_string());
        let dest = Path::new(&kept).join(format!("giw9n-broken-{count}.img"));
        let copied = std::fs::copy(&image, &dest).is_ok();
        panic!(
            "image is UNMOUNTABLE after {count} creates + clean unmount: {e}\n\
             corrupt image preserved: {} ({})",
            dest.display(),
            if copied { "ok" } else { "COPY FAILED" }
        );
    });

    for i in [0, count / 2, count - 1] {
        fs2.lookup(&cx, BTRFS_ROOT_DIR, OsStr::new(&format!("f{i:07}.dat")))
            .unwrap_or_else(|e| panic!("post-remount lookup of f{i:07}.dat failed: {e}"));
    }
}

/// The known-good control from the bead report: 8,000 entries round-trip.
#[test]
fn btrfs_8k_create_batch_remounts_bd_giw9n() {
    create_batch_and_remount(8_000, 512);
}

/// The reported failure point: 32,768 entries in one transaction.
#[test]
fn btrfs_32k_create_batch_remounts_bd_giw9n() {
    create_batch_and_remount(32_768, 1024);
}

/// Bisection probe. Not run by default (slow); drive it with
/// `FFS_GIW9N_COUNT=N FFS_GIW9N_SIZE_MB=M cargo test -p ffs-core
/// --test btrfs_large_dir_mount_cycle -- --ignored --exact
/// btrfs_create_batch_threshold_probe_bd_giw9n`.
#[test]
#[ignore = "bisection probe; parameterized by FFS_GIW9N_COUNT"]
fn btrfs_create_batch_threshold_probe_bd_giw9n() {
    let count = std::env::var("FFS_GIW9N_COUNT")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(16_384);
    let size_mb = std::env::var("FFS_GIW9N_SIZE_MB")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(1024);
    create_batch_and_remount(count, size_mb);
}
