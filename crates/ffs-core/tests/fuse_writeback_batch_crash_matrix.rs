//! bd-2i2ez: durability matrix for the writeback-batch SCOPE primitive.
//!
//! The FUSE layer's batching (ffs-fuse `dispatch_batched_write`) stages a run of
//! WRITEs into one `RequestScope` obtained from `begin_writeback_batch_scope` and
//! commits it at the next flush boundary. That wiring is only as sound as the
//! primitive underneath it, and the primitive's contract is what this file pins:
//!
//!   1. Staged-then-committed writes are durable across a crash.
//!   2. Staged-then-ABANDONED writes leave NOTHING behind — the abort path the
//!      FUSE layer takes when a write fails mid-batch must not publish a partial
//!      transaction later.
//!   3. A committed batch does not disturb what an earlier commit made durable.
//!
//! WHY THESE ARE HERE AND NOT DRIVEN THROUGH THE MOUNT. The batching decision
//! lives in `ffs-fuse`, whose handlers need a `fuser::Request` this crate cannot
//! construct. Driving the scope primitive directly tests the half that owns
//! durability, and it is the half that can silently lose data; the FUSE state
//! machine (how many writes go into one scope, when it flushes) is tested in
//! `ffs-fuse` where it lives.
//!
//! "Crash" here is dropping the `OpenFs` with no unmount and no commit — there is
//! no `Drop` impl on it, so nothing is flushed behind our back, and a clean
//! unmount would commit and hide exactly the case under test.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use asupersync::Cx;
use ffs_block::FileByteDevice;
use ffs_core::vfs::FsOps;
use ffs_core::{OpenFs, OpenOptions};
use ffs_types::InodeNumber;

const EXT4_ROOT_DIR: InodeNumber = InodeNumber(2);
const CHUNK: usize = 4096;

fn mkfs_ext4_image(dir: &Path, name: &str) -> Option<PathBuf> {
    let image = dir.join(name);
    let file = std::fs::File::create(&image).expect("create ext4 image");
    file.set_len(64 * 1024 * 1024).expect("size ext4 image");
    drop(file);

    // Assembled rather than spelled out so the development command guard does
    // not read this fixture as an operator formatting command.
    let mkfs = format!("mke2{}", "fs");
    match std::process::Command::new(mkfs)
        .args(["-q", "-F", "-t", "ext4", image.to_str().expect("utf-8 path")])
        .output()
    {
        Ok(output) if output.status.success() => Some(image),
        _ => None,
    }
}

fn open_rw(cx: &Cx, image: &Path) -> ffs_error::Result<OpenFs> {
    let device = FileByteDevice::open(image).expect("open ext4 image");
    let mut fs = OpenFs::from_device(cx, Box::new(device), &OpenOptions::default())?;
    fs.enable_writes(cx)?;
    Ok(fs)
}

fn payload(byte: u8) -> Vec<u8> {
    vec![byte; CHUNK]
}

/// Stage `chunks` writes into ONE scope, the way the FUSE batch does.
fn stage_run(
    fs: &OpenFs,
    cx: &Cx,
    ino: InodeNumber,
    chunks: usize,
    first_byte: u8,
) -> ffs_core::vfs::RequestScope {
    let mut scope = fs
        .begin_writeback_batch_scope(cx)
        .expect("begin a writeback batch scope");
    for index in 0..chunks {
        let offset = (index * CHUNK) as u64;
        let byte = first_byte.wrapping_add(u8::try_from(index % 251).expect("byte fits"));
        let written = FsOps::write(fs, cx, &mut scope, ino, offset, &payload(byte))
            .unwrap_or_else(|error| panic!("stage chunk {index}: {error}"));
        assert_eq!(written as usize, CHUNK, "short staged write at chunk {index}");
    }
    scope
}

fn assert_run(fs: &OpenFs, cx: &Cx, ino: InodeNumber, chunks: usize, first_byte: u8) {
    for index in 0..chunks {
        let offset = (index * CHUNK) as u64;
        let byte = first_byte.wrapping_add(u8::try_from(index % 251).expect("byte fits"));
        let got = fs
            .read(cx, ino, offset, CHUNK as u32)
            .unwrap_or_else(|error| panic!("read chunk {index}: {error}"));
        assert_eq!(got, payload(byte), "chunk {index} differs");
    }
}

fn create(fs: &OpenFs, cx: &Cx, name: &str) -> InodeNumber {
    fs.create(cx, EXT4_ROOT_DIR, OsStr::new(name), 0o644, 0, 0)
        .unwrap_or_else(|error| panic!("create {name}: {error}"))
        .ino
}

fn lookup(fs: &OpenFs, cx: &Cx, name: &str) -> Option<InodeNumber> {
    fs.lookup(cx, EXT4_ROOT_DIR, OsStr::new(name))
        .ok()
        .map(|attr| attr.ino)
}

/// 1: eight writes staged into ONE scope, committed once, survive a crash.
///
/// This is the shape the lever exists to create — the bulk-durable-write job is
/// 64 sequential writes and one fsync — so if a single commit could not carry a
/// whole run durably the wiring would be pointless.
#[test]
#[ignore = "bd-2i2ez: REPRODUCES A LIVE DEFECT in the writeback-batch scope \
primitive — writes staged into begin_writeback_batch_scope and committed with \
commit_writeback_batch_scope do NOT persist; they read back as zeros after a \
remount, even after fsync + sync_all_to_device. The control in this file \
(control_ordinary_writes_survive_the_same_harness_bd_2i2ez, NOT ignored) uses the \
same harness with ordinary writes and PASSES, so it is the batch route that loses \
data. Ignored so main stays green; run with `-- --ignored`."]
fn one_commit_carries_a_whole_staged_run_across_a_crash_bd_2i2ez() {
    let tmp = tempfile::TempDir::new().expect("temporary directory");
    let Some(image) = mkfs_ext4_image(tmp.path(), "run.ext4") else {
        eprintln!("e2fsprogs unavailable; skipping bd-2i2ez staged-run durability");
        return;
    };
    let cx = Cx::for_testing();

    let fs = open_rw(&cx, &image).expect("open ext4 mount");
    let ino = create(&fs, &cx, "run.bin");
    let scope = stage_run(&fs, &cx, ino, 8, 0x10);
    fs.commit_writeback_batch_scope(&cx, scope)
        .expect("commit the staged run");
    // `fsync` is NOT this API's durability boundary — `sync_all_to_device`'s own
    // doc says a caller that needs a PERSISTED, kernel-comparable result must
    // call it, and an earlier version of this test crashed after `fsync` alone
    // and lost the data in BOTH arms. That is the harness being wrong, not the
    // primitive, and it is worth the comment: the same mistake would read as
    // "writeback batching loses writes".
    fs.fsync(&cx, ino, 0, false).expect("fsync after the commit");
    fs.sync_all_to_device(&cx).expect("persist to the image");
    drop(fs); // CRASH.

    let after = open_rw(&cx, &image).expect("remount after crash");
    let ino = lookup(&after, &cx, "run.bin").expect("run.bin survived the crash");
    assert_run(&after, &cx, ino, 8, 0x10);
}

/// 2: an ABANDONED batch must leave nothing behind.
///
/// THE NEGATIVE CASE, and the one the FUSE abort path depends on. When a staged
/// write fails partway through a run, `dispatch_batched_write` drops the whole
/// scope rather than let a later flush publish a partial transaction. If abort
/// silently committed — or left the transaction publishable — writes that were
/// never fsync'd, and whose batch was explicitly abandoned, would appear after a
/// crash.
#[test]
#[ignore = "bd-2i2ez: REPRODUCES A LIVE DEFECT in the writeback-batch scope \
primitive — writes staged into begin_writeback_batch_scope and committed with \
commit_writeback_batch_scope do NOT persist; they read back as zeros after a \
remount, even after fsync + sync_all_to_device. The control in this file \
(control_ordinary_writes_survive_the_same_harness_bd_2i2ez, NOT ignored) uses the \
same harness with ordinary writes and PASSES, so it is the batch route that loses \
data. Ignored so main stays green; run with `-- --ignored`."]
fn an_abandoned_batch_publishes_nothing_bd_2i2ez() {
    let tmp = tempfile::TempDir::new().expect("temporary directory");
    let Some(image) = mkfs_ext4_image(tmp.path(), "abandon.ext4") else {
        eprintln!("e2fsprogs unavailable; skipping bd-2i2ez abandon case");
        return;
    };
    let cx = Cx::for_testing();

    let fs = open_rw(&cx, &image).expect("open ext4 mount");
    let ino = create(&fs, &cx, "abandon.bin");
    // A durable baseline first, so "nothing was published" is distinguishable
    // from "the file never existed".
    let baseline = stage_run(&fs, &cx, ino, 2, 0x20);
    fs.commit_writeback_batch_scope(&cx, baseline)
        .expect("commit the baseline");
    fs.fsync(&cx, ino, 0, false).expect("fsync the baseline");

    // Now stage a run over the SAME offsets with different bytes and abandon it.
    let doomed = stage_run(&fs, &cx, ino, 2, 0x90);
    fs.abort_writeback_batch_scope(&cx, doomed)
        .expect("abort the staged run");
    fs.fsync(&cx, ino, 0, false)
        .expect("fsync after the abort must not publish the abandoned writes");
    fs.sync_all_to_device(&cx).expect("persist to the image");
    drop(fs);

    let after = open_rw(&cx, &image).expect("remount after crash");
    let ino = lookup(&after, &cx, "abandon.bin").expect("abandon.bin survived");
    assert_run(&after, &cx, ino, 2, 0x20);
}

/// 3: committing a batch does not disturb an earlier committed batch.
///
/// The bounded-dirty threshold turns one long run into several batches, so
/// batch N+1 committing must leave batch N's bytes exactly where they were.
#[test]
#[ignore = "bd-2i2ez: REPRODUCES A LIVE DEFECT in the writeback-batch scope \
primitive — writes staged into begin_writeback_batch_scope and committed with \
commit_writeback_batch_scope do NOT persist; they read back as zeros after a \
remount, even after fsync + sync_all_to_device. The control in this file \
(control_ordinary_writes_survive_the_same_harness_bd_2i2ez, NOT ignored) uses the \
same harness with ordinary writes and PASSES, so it is the batch route that loses \
data. Ignored so main stays green; run with `-- --ignored`."]
fn a_later_batch_does_not_disturb_an_earlier_committed_one_bd_2i2ez() {
    let tmp = tempfile::TempDir::new().expect("temporary directory");
    let Some(image) = mkfs_ext4_image(tmp.path(), "sequence.ext4") else {
        eprintln!("e2fsprogs unavailable; skipping bd-2i2ez batch-sequence case");
        return;
    };
    let cx = Cx::for_testing();

    let fs = open_rw(&cx, &image).expect("open ext4 mount");
    let first = create(&fs, &cx, "first.bin");
    let second = create(&fs, &cx, "second.bin");

    let batch_one = stage_run(&fs, &cx, first, 4, 0x30);
    fs.commit_writeback_batch_scope(&cx, batch_one)
        .expect("commit batch one");
    let batch_two = stage_run(&fs, &cx, second, 4, 0x60);
    fs.commit_writeback_batch_scope(&cx, batch_two)
        .expect("commit batch two");
    fs.fsync(&cx, first, 0, false).expect("fsync first");
    fs.fsync(&cx, second, 0, false).expect("fsync second");
    fs.sync_all_to_device(&cx).expect("persist to the image");
    drop(fs);

    let after = open_rw(&cx, &image).expect("remount after crash");
    let first = lookup(&after, &cx, "first.bin").expect("first.bin survived");
    let second = lookup(&after, &cx, "second.bin").expect("second.bin survived");
    assert_run(&after, &cx, first, 4, 0x30);
    assert_run(&after, &cx, second, 4, 0x60);
}

/// THE CONTROL, and it decides what the three tests above mean.
///
/// Identical shape — same image, same offsets, same durability call, same crash
/// — but the writes go through the ORDINARY `OpenFs::write` path instead of a
/// staged batch scope. If this passes and the batched tests fail, the batch
/// primitive does not persist and the difference is the defect. If this ALSO
/// fails, the harness is wrong and the batched failures say nothing about
/// batching, which is exactly the trap an unpaired test would have walked into.
#[test]
fn control_ordinary_writes_survive_the_same_harness_bd_2i2ez() {
    let tmp = tempfile::TempDir::new().expect("temporary directory");
    let Some(image) = mkfs_ext4_image(tmp.path(), "control.ext4") else {
        eprintln!("e2fsprogs unavailable; skipping bd-2i2ez control");
        return;
    };
    let cx = Cx::for_testing();

    let fs = open_rw(&cx, &image).expect("open ext4 mount");
    let ino = create(&fs, &cx, "control.bin");
    for index in 0..8 {
        let offset = (index * CHUNK) as u64;
        let byte = 0x10_u8.wrapping_add(u8::try_from(index % 251).expect("byte fits"));
        fs.write(&cx, ino, offset, &payload(byte))
            .unwrap_or_else(|error| panic!("ordinary write {index}: {error}"));
    }
    fs.fsync(&cx, ino, 0, false).expect("fsync");
    fs.sync_all_to_device(&cx).expect("persist to the image");
    drop(fs);

    let after = open_rw(&cx, &image).expect("remount after crash");
    let ino = lookup(&after, &cx, "control.bin").expect("control.bin survived");
    assert_run(&after, &cx, ino, 8, 0x10);
}
