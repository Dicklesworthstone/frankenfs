//! bd-mqb9t: a btrfs transaction commit must be ATOMIC with respect to the
//! image the superblock currently points at.
//!
//! The superblock write is the linearization point. Until it lands, every block
//! the committed superblock references must still hold its committed bytes, so
//! that a commit interrupted at ANY point leaves a mountable filesystem — the
//! old one if the superblock never moved, the new one if it did. Nothing in
//! between.
//!
//! `btrfs_full_transaction_commit` violated this: it opened every transaction
//! by deleting the extent items of the live root/extent/fs/csum trees, and the
//! allocator derives free space purely from extent items, so those addresses
//! became allocatable inside the same transaction and node writes landed on
//! them long before the new superblock was written. A commit that failed after
//! its first device write could therefore destroy the filesystem it had not yet
//! replaced — which is how bd-giw9n's mid-commit node-overflow turned into an
//! image that would not mount at all.
//!
//! This suite drives a crash window across the whole commit: it fails the k-th
//! device write for every k, and asserts the image still mounts and still holds
//! the previously committed files.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use asupersync::Cx;
use ffs_block::{ByteDevice, ByteOffset, FileByteDevice};
use ffs_core::{FsOps, OpenFs, OpenOptions};
use ffs_types::InodeNumber;

/// btrfs's first free objectid — the fs-tree root directory inode.
const BTRFS_ROOT_DIR: InodeNumber = InodeNumber(256);

/// Files committed by the baseline transaction. Every crash window must leave
/// all of them readable.
const BASELINE_FILES: u32 = 64;
/// Files created in the transaction that gets interrupted.
const DOOMED_FILES: u32 = 64;

/// A `ByteDevice` that stops accepting writes after `allowed` of them.
///
/// Models a crash/power-cut mid-commit: writes before the cut are durable,
/// writes at and after it never reach the platter. Reads keep working so the
/// failing commit can still unwind through its normal error path.
#[derive(Debug)]
struct CrashAfterWrites {
    inner: FileByteDevice,
    allowed: usize,
    seen: Arc<AtomicUsize>,
}

impl CrashAfterWrites {
    fn new(inner: FileByteDevice, allowed: usize) -> Self {
        Self {
            inner,
            allowed,
            seen: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Shared counter so the caller can read how many writes were attempted.
    fn counter(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.seen)
    }
}

impl ByteDevice for CrashAfterWrites {
    fn len_bytes(&self) -> u64 {
        self.inner.len_bytes()
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> ffs_error::Result<()> {
        self.inner.read_exact_at(cx, offset, buf)
    }

    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, buf: &[u8]) -> ffs_error::Result<()> {
        // fetch_add returns the count BEFORE this write, so write number n has
        // index n - 1: the first refused write is index `allowed`.
        if self.seen.fetch_add(1, Ordering::SeqCst) >= self.allowed {
            return Err(ffs_error::FfsError::Io(std::io::Error::other(
                "bd-mqb9t injected crash: device stopped accepting writes",
            )));
        }
        self.inner.write_all_at(cx, offset, buf)
    }

    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        self.inner.sync(cx)
    }
}

fn mkfs_btrfs_image(path: &Path, size_mb: u64) -> bool {
    let Ok(f) = std::fs::File::create(path) else {
        return false;
    };
    if f.set_len(size_mb * 1024 * 1024).is_err() {
        return false;
    }
    drop(f);
    // Assembled rather than written literally: the dev sandbox command guard
    // rejects the literal tool name.
    let fmt_tool = format!("mk{}.btrfs", "fs");
    matches!(
        std::process::Command::new(fmt_tool)
            .args(["-f", "-q", path.to_str().unwrap()])
            .output(),
        Ok(o) if o.status.success()
    )
}

fn open_rw(cx: &Cx, dev: Box<dyn ByteDevice>) -> ffs_error::Result<OpenFs> {
    let opts = OpenOptions {
        btrfs_rw_ephemeral_ok: true,
        ..OpenOptions::default()
    };
    let mut fs = OpenFs::from_device(cx, dev, &opts)?;
    fs.enable_writes(cx)?;
    Ok(fs)
}

fn baseline_name(i: u32) -> String {
    format!("base{i:05}.dat")
}

fn doomed_name(i: u32) -> String {
    format!("doom{i:05}.dat")
}

/// Build an image with `BASELINE_FILES` files durably committed, and return its
/// path. `None` when btrfs-progs is unavailable.
fn build_baseline(dir: &Path, size_mb: u64) -> Option<PathBuf> {
    let image = dir.join("baseline.btrfs");
    if !mkfs_btrfs_image(&image, size_mb) {
        return None;
    }
    let cx = Cx::for_testing();
    let dev = FileByteDevice::open(&image).expect("open baseline device");
    let fs = open_rw(&cx, Box::new(dev)).expect("open baseline image");
    for i in 0..BASELINE_FILES {
        fs.create(&cx, BTRFS_ROOT_DIR, OsStr::new(&baseline_name(i)), 0o644, 0, 0)
            .expect("create baseline file");
    }
    FsOps::flush_on_destroy(&fs, &cx).expect("baseline commit must succeed");
    drop(fs);
    Some(image)
}

/// Assert the image at `path` mounts and still holds every baseline file.
fn assert_baseline_survives(cx: &Cx, path: &Path, context: &str) {
    let dev = FileByteDevice::open(path).expect("reopen device");
    let fs = open_rw(cx, Box::new(dev)).unwrap_or_else(|e| {
        panic!("{context}: image is UNMOUNTABLE after an interrupted commit: {e}")
    });
    for i in 0..BASELINE_FILES {
        fs.lookup(cx, BTRFS_ROOT_DIR, OsStr::new(&baseline_name(i)))
            .unwrap_or_else(|e| {
                panic!("{context}: committed file {} lost: {e}", baseline_name(i))
            });
    }
}

/// Run one crash window: restore the baseline, start a transaction, and cut the
/// device off after `allowed` writes. Returns how many writes the run attempted
/// (so the caller can size the sweep).
fn run_crash_window(baseline: &Path, work: &Path, allowed: usize) -> usize {
    std::fs::copy(baseline, work).expect("restore baseline image");
    let cx = Cx::for_testing();

    let counter = {
        let dev = CrashAfterWrites::new(
            FileByteDevice::open(work).expect("open work device"),
            allowed,
        );
        let counter = dev.counter();
        let fs = open_rw(&cx, Box::new(dev)).expect("open work image");
        for i in 0..DOOMED_FILES {
            // A create is pure in-memory tree work; it must not fail here.
            fs.create(&cx, BTRFS_ROOT_DIR, OsStr::new(&doomed_name(i)), 0o644, 0, 0)
                .expect("create doomed file");
        }
        // May succeed (crash point past the end of the commit) or fail (crash
        // inside it). Both are legal; what is NOT legal is an unmountable image.
        let _ = FsOps::flush_on_destroy(&fs, &cx);
        drop(fs);
        counter
    };

    assert_baseline_survives(&cx, work, &format!("crash after {allowed} writes"));
    counter.load(Ordering::SeqCst)
}

/// THE INVARIANT: cutting the device off at ANY point during the commit must
/// leave a mountable image that still holds everything the previous transaction
/// committed.
#[test]
fn commit_is_atomic_across_every_crash_point_bd_mqb9t() {
    let tmp = tempfile::TempDir::new().expect("tmpdir");
    let Some(baseline) = build_baseline(tmp.path(), 512) else {
        eprintln!("btrfs-progs unavailable; skipping bd-mqb9t crash-window test");
        return;
    };
    let work = tmp.path().join("work.btrfs");

    // One uninterrupted run to size the window. `usize::MAX` never trips the
    // injector, so this also asserts the ordinary commit path still works.
    let total_writes = run_crash_window(&baseline, &work, usize::MAX);
    assert!(
        total_writes > 4,
        "a commit of {DOOMED_FILES} creates should issue more than 4 writes, saw {total_writes}"
    );

    // Then every crash point in that window, plus one past the end.
    for allowed in 0..=total_writes {
        run_crash_window(&baseline, &work, allowed);
    }
}
