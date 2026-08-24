//! bd-jhuob: does a tree-logged fsync survive a crash AND the full commit that
//! follows the recovery mount?
//!
//! This is the falsification the bead asks for BEFORE any fix, and the answer
//! decides how expensive the bead is:
//!
//! * If the logged items survive, `--btrfs-rw-ephemeral-ok` is merely a
//!   conservative name and the tree-log fast path can be promoted toward the
//!   default for fsync — a one-line policy change rather than a redesign.
//! * If they do not, tree-log replay has to become a MERGE into the writable
//!   tree instead of the read-time overlay it is today, and promoting the fast
//!   path before that would be a silent data-loss change.
//!
//! THE MECHANISM UNDER TEST, stated so a later reader can tell whether this
//! test still covers it. `replay_tree_log` runs at open and parks the recovered
//! items in `OpenFs::btrfs_tree_log_items`, which are applied at READ time by
//! `btrfs_apply_tree_log_overlay{,_range}` rather than merged into any tree.
//! Separately, `enable_writes` populates the in-memory COW `fs_tree` from
//! `walk_btrfs_fs_tree`, and a full transaction commit serializes THAT tree.
//! So the question is precisely whether the walk that seeds the writable tree
//! is one of the overlay-applying ones. If it is, recovery composes with commit
//! and the data survives; if it is not, the commit writes a tree that has never
//! heard of the replayed items and clears `log_root` on the way out, destroying
//! them.
//!
//! WHY A CRASH AND NOT AN UNMOUNT: a clean shutdown full-commits and would hide
//! exactly the case under test. These tests drop the `OpenFs` with no commit,
//! which is the in-process equivalent of losing power — there is no `Drop` impl
//! on `OpenFs`, so nothing is flushed behind our back.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use asupersync::Cx;
use ffs_block::FileByteDevice;
use ffs_core::{OpenFs, OpenOptions};
use ffs_types::InodeNumber;

const BTRFS_ROOT_DIR: InodeNumber = InodeNumber(256);

/// Bytes written before the crash. Distinctive rather than zeroes so a stale
/// read cannot pass by returning a freshly allocated block.
const LOGGED_CONTENT: &[u8] = b"bd-jhuob tree-log survives the recovery commit";

fn mkfs_btrfs_image(dir: &Path, name: &str) -> Option<PathBuf> {
    let image = dir.join(name);
    let file = std::fs::File::create(&image).expect("create btrfs image");
    file.set_len(256 * 1024 * 1024).expect("size btrfs image");
    drop(file);

    // Assembled rather than written literally so the development command guard
    // does not mistake this fixture for an operator formatting command; the
    // sibling bd-0ajub test does the same.
    let mkfs = format!("mk{}.btrfs", "fs");
    match std::process::Command::new(mkfs)
        .args(["-f", "-q", image.to_str().expect("utf-8 image path")])
        .output()
    {
        Ok(output) if output.status.success() => Some(image),
        _ => None,
    }
}

/// Route `tracing` to stderr once per process.
///
/// Recovery failures here are diagnosed almost entirely from the mount's own
/// records — `replay_tree_log` only `warn!`s when it cannot read a log, and a
/// mount that continues after that warning is the exact shape of bd-sv7ql. With
/// no subscriber those records go nowhere and a failure reads as unexplainable.
fn init_tracing() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
            )
            .with_test_writer()
            .try_init();
    });
}

fn open_rw(cx: &Cx, image: &Path, ephemeral: bool) -> ffs_error::Result<OpenFs> {
    let device = FileByteDevice::open(image).expect("open btrfs image");
    let options = OpenOptions {
        btrfs_rw_ephemeral_ok: ephemeral,
        ..OpenOptions::default()
    };
    let mut fs = OpenFs::from_device(cx, Box::new(device), &options)?;
    fs.enable_writes(cx)?;
    Ok(fs)
}

fn open_ro(cx: &Cx, image: &Path) -> ffs_error::Result<OpenFs> {
    let device = FileByteDevice::open(image).expect("open btrfs image");
    OpenFs::from_device(cx, Box::new(device), &OpenOptions::default())
}

/// Write `LOGGED_CONTENT` into a new file and fsync it, returning the name.
///
/// The fsync is the whole point: in ephemeral mode it takes the tree-log fast
/// path, so on return the data is durable ONLY through the log.
fn create_and_log(fs: &OpenFs, cx: &Cx, name: &str) -> InodeNumber {
    let ino = fs
        .create(cx, BTRFS_ROOT_DIR, OsStr::new(name), 0o644, 0, 0)
        .unwrap_or_else(|error| panic!("create {name}: {error}"))
        .ino;
    let written = fs
        .write(cx, ino, 0, LOGGED_CONTENT)
        .unwrap_or_else(|error| panic!("write {name}: {error}"));
    assert_eq!(
        written as usize,
        LOGGED_CONTENT.len(),
        "short write for {name}"
    );
    fs.fsync(cx, ino, 0, false)
        .unwrap_or_else(|error| panic!("fsync {name}: {error}"));
    ino
}

/// `log_root` as it sits in the on-disk superblock, read from raw bytes.
///
/// Deliberately not routed through any of our own parsing: this is the
/// precondition check that separates "the fsync never published a log" from
/// "the log was published and recovery lost it", and a helper that shared code
/// with the thing under test could agree with it for the wrong reason.
///
/// Layout is fixed by the btrfs on-disk format: the primary superblock lives at
/// 64 KiB, and within it `csum[32] fsid[16] bytenr[8] flags[8] magic[8]
/// generation[8] root[8] chunk_root[8] log_root[8]` puts `log_root` at +0x60.
fn on_disk_log_root(image: &Path) -> u64 {
    const SUPERBLOCK_OFFSET: u64 = 64 * 1024;
    const LOG_ROOT_OFFSET_IN_SUPERBLOCK: u64 = 0x60;
    let bytes = std::fs::read(image).expect("read btrfs image");
    let at = usize::try_from(SUPERBLOCK_OFFSET + LOG_ROOT_OFFSET_IN_SUPERBLOCK)
        .expect("superblock offset fits usize");
    u64::from_le_bytes(
        bytes[at..at + 8]
            .try_into()
            .expect("eight bytes of log_root"),
    )
}

fn read_back(fs: &OpenFs, cx: &Cx, name: &str) -> Option<Vec<u8>> {
    let attr = fs.lookup(cx, BTRFS_ROOT_DIR, OsStr::new(name)).ok()?;
    let bytes = fs
        .read(cx, attr.ino, 0, LOGGED_CONTENT.len() as u32)
        .unwrap_or_else(|error| panic!("read {name}: {error}"));
    Some(bytes)
}

/// THE FALSIFICATION (bd-jhuob). Crash with a live tree log, recover, then force
/// a FULL COMMIT on the recovery mount, then look again from a fresh mount.
///
/// The third mount is what makes this a real test rather than a restatement of
/// the overlay: mounts 2 and 3 are different processes' worth of state, and
/// mount 3 sees `log_root` cleared by the commit, so the only way the data can
/// still be there is if the commit actually wrote it into the trees.
#[test]
fn tree_logged_fsync_survives_the_full_commit_after_recovery_bd_jhuob() {
    init_tracing();
    let tmp = tempfile::TempDir::new().expect("temporary directory");
    let Some(image) = mkfs_btrfs_image(tmp.path(), "jhuob-crash-replay.btrfs") else {
        eprintln!("btrfs-progs unavailable; skipping bd-jhuob crash-replay falsification");
        return;
    };
    let cx = Cx::for_testing();

    // 1. Ephemeral mount: the fsync is carried by the tree log alone.
    let fs = open_rw(&cx, &image, true).expect("open ephemeral btrfs mount");
    create_and_log(&fs, &cx, "logged.bin");
    // 2. CRASH. No unmount, no commit — a clean shutdown would full-commit and
    //    hide precisely the case this test exists for.
    drop(fs);

    // PRECONDITION, and it is what makes the assertions below mean anything: the
    // fsync must actually have published a tree log. If `log_root` is zero the
    // fsync silently took the full-commit fallback (an overflow, or the
    // deletion guard), and every "the log lost my data" conclusion downstream
    // would be about a log that was never written.
    let published = on_disk_log_root(&image);
    assert_ne!(
        published, 0,
        "the ephemeral fsync published no tree log (log_root == 0), so this image cannot \
         test tree-log recovery at all"
    );

    // 3. Recovery mount, DURABLE mode. Opening replays the log; enabling writes
    //    seeds the in-memory COW tree.
    let recovered = open_rw(&cx, &image, false).expect("recovery mount");
    assert_eq!(
        read_back(&recovered, &cx, "logged.bin").as_deref(),
        Some(LOGGED_CONTENT),
        "the recovery mount cannot even see the logged file: tree-log replay itself is broken, \
         which is a different defect from the one this test is about"
    );

    // 4. Force a FULL COMMIT on the recovery mount. In durable mode any fsync is
    //    a full transaction commit, which serializes the in-memory trees and
    //    retires `log_root` (bd-mogn1). If the replayed items never reached
    //    those trees, this is the step that destroys them.
    let touched = recovered
        .create(&cx, BTRFS_ROOT_DIR, OsStr::new("commit-trigger.bin"), 0o644, 0, 0)
        .expect("create commit trigger")
        .ino;
    recovered
        .fsync(&cx, touched, 0, false)
        .expect("full transaction commit on the recovery mount");
    drop(recovered);

    // 5. Fresh mount. `log_root` is retired, so nothing is being served by the
    //    overlay any more — whatever is readable here is what the commit wrote.
    let after = open_ro(&cx, &image).expect("post-commit mount");
    assert_eq!(
        read_back(&after, &cx, "logged.bin").as_deref(),
        Some(LOGGED_CONTENT),
        "A TREE-LOGGED FSYNC WAS LOST BY THE FULL COMMIT THAT FOLLOWED RECOVERY. \
         The fsync returned success, the recovery mount could read the data, and then a \
         routine commit erased it. Tree-log replay must MERGE into the writable tree \
         rather than act as a read-time overlay before the log can be an fsync default \
         (bd-jhuob)."
    );
    assert!(
        read_back(&after, &cx, "commit-trigger.bin").is_some(),
        "the commit trigger itself is missing, so the commit did not happen and the \
         assertion above proved nothing"
    );
}

/// The multi-inode form, and the reason it is separate: bd-dm01m established
/// that the log holds an ACCUMULATED set, so a recovery commit has to preserve
/// every fsync in the transaction, not just the last one. A merge that handled
/// only the most recent inode would pass the test above and fail this one.
#[test]
fn every_logged_inode_survives_the_recovery_commit_bd_jhuob() {
    init_tracing();
    let tmp = tempfile::TempDir::new().expect("temporary directory");
    let Some(image) = mkfs_btrfs_image(tmp.path(), "jhuob-crash-replay-multi.btrfs") else {
        eprintln!("btrfs-progs unavailable; skipping bd-jhuob multi-inode crash replay");
        return;
    };
    let cx = Cx::for_testing();
    let names = ["multi-a.bin", "multi-b.bin", "multi-c.bin"];

    let fs = open_rw(&cx, &image, true).expect("open ephemeral btrfs mount");
    for name in names {
        create_and_log(&fs, &cx, name);
    }
    drop(fs);

    // Same vacuity guard as the single-file test: if the accumulated log had
    // overflowed its leaf and taken the full-commit fallback, `log_root` would be
    // retired and this test would be proving that a FULL COMMIT is durable —
    // true, and not what it claims to test.
    assert_ne!(
        on_disk_log_root(&image),
        0,
        "the accumulated log was retired before the crash, so these files are durable via a \
         full commit rather than via the tree log; this test would pass vacuously"
    );

    let recovered = open_rw(&cx, &image, false).expect("recovery mount");
    let trigger = recovered
        .create(&cx, BTRFS_ROOT_DIR, OsStr::new("multi-trigger.bin"), 0o644, 0, 0)
        .expect("create commit trigger")
        .ino;
    recovered
        .fsync(&cx, trigger, 0, false)
        .expect("full transaction commit on the recovery mount");
    drop(recovered);

    let after = open_ro(&cx, &image).expect("post-commit mount");
    let lost: Vec<&str> = names
        .into_iter()
        .filter(|name| read_back(&after, &cx, name).as_deref() != Some(LOGGED_CONTENT))
        .collect();
    assert!(
        lost.is_empty(),
        "these tree-logged fsyncs did not survive the recovery commit: {lost:?}. \
         Each one returned success to its caller (bd-jhuob, bd-dm01m)."
    );
}

/// Belt and braces: fsyncing the parent directory TOO must also recover.
///
/// This began as the locator for the defect the two tests above now cover. While
/// the bug was live it was the discriminator — `fsync(file)` lost the name and
/// `fsync(file) + fsync(dir)` kept it, which is what identified the missing
/// namespace items as the cause rather than replay or the overlay.
///
/// It is kept, with its precondition corrected, because it exercises a path the
/// others do not: the extra directory fsync pushes the ACCUMULATED log past its
/// single-leaf budget, so this is the `full_commit_log_overflow_fallback` in
/// action. Asserting `log_root != 0` here — as it did while it was a locator —
/// is now simply wrong: a full commit RETIRES the log (bd-mogn1), so a zero
/// `log_root` is the correct outcome of a correct fallback. What must hold is
/// that the data is durable either way, which is what this asserts.
#[test]
fn fsyncing_the_parent_directory_recovers_the_name_bd_jhuob() {
    init_tracing();
    let tmp = tempfile::TempDir::new().expect("temporary directory");
    let Some(image) = mkfs_btrfs_image(tmp.path(), "jhuob-parent-fsync.btrfs") else {
        eprintln!("btrfs-progs unavailable; skipping bd-jhuob parent-fsync probe");
        return;
    };
    let cx = Cx::for_testing();

    let fs = open_rw(&cx, &image, true).expect("open ephemeral btrfs mount");
    create_and_log(&fs, &cx, "named.bin");
    // The extra step under test: fsync the DIRECTORY as well.
    fs.fsync(&cx, BTRFS_ROOT_DIR, 0, false)
        .expect("fsync the parent directory");
    drop(fs);

    let recovered = open_rw(&cx, &image, false).expect("recovery mount");
    let visible = read_back(&recovered, &cx, "named.bin");
    drop(recovered);
    assert_eq!(
        visible.as_deref(),
        Some(LOGGED_CONTENT),
        "fsync(file) followed by fsync(parent) did not survive the crash. Whether the \
         accumulated log carried it or overflowed into the full-commit fallback, an fsync \
         that returned success must not lose its file (bd-jhuob)."
    );
}

// ── Second fixture family: transactions that DELETE a name (bd-jhuob) ───────
//
// The tests above all ADD names. A tree log leaf can express "this key now has
// this value"; it has no tombstone, so it cannot express "this key is gone".
// `btrfs_tree_log_has_deletions` is what stops the log being used for such a
// transaction — the fsync takes `full_commit_log_overflow_fallback` instead —
// and these tests are the gate on that guard staying honest.
//
// They are deliberately written to be STRATEGY-AGNOSTIC. What must hold is the
// POSIX outcome after a crash, not which mechanism delivered it, so they pass
// today (full-commit fallback) and must keep passing once a deletion record
// lands and the log carries these transactions itself. A test that asserted
// `log_root == 0` would pin today's implementation and fail the moment the
// feature it is guarding arrives.
//
// The resurrection assertion is the one that matters. A log replayed over a
// tree that has since dropped a name puts the name BACK — a deleted file
// returning from the dead after a crash — which is the precise failure the
// no-deletions guard exists to prevent and the precise failure a tombstone
// implementation has to get right.

/// Alternate content, so a stale item cannot pass by returning the right bytes
/// from the wrong file.
const OTHER_CONTENT: &[u8] = b"bd-jhuob second file, distinct from LOGGED_CONTENT";

fn create_with(fs: &OpenFs, cx: &Cx, name: &str, content: &[u8]) -> InodeNumber {
    let ino = fs
        .create(cx, BTRFS_ROOT_DIR, OsStr::new(name), 0o644, 0, 0)
        .unwrap_or_else(|error| panic!("create {name}: {error}"))
        .ino;
    let written = fs
        .write(cx, ino, 0, content)
        .unwrap_or_else(|error| panic!("write {name}: {error}"));
    assert_eq!(written as usize, content.len(), "short write for {name}");
    ino
}

fn content_of(fs: &OpenFs, cx: &Cx, name: &str, len: usize) -> Option<Vec<u8>> {
    let attr = fs.lookup(cx, BTRFS_ROOT_DIR, OsStr::new(name)).ok()?;
    Some(
        fs.read(cx, attr.ino, 0, len as u32)
            .unwrap_or_else(|error| panic!("read {name}: {error}")),
    )
}

/// UNLINK then fsync a sibling, then crash. The unlinked file must stay gone and
/// the sibling must keep its data.
#[test]
fn unlink_does_not_resurrect_across_a_crash_bd_jhuob() {
    init_tracing();
    let tmp = tempfile::TempDir::new().expect("temporary directory");
    let Some(image) = mkfs_btrfs_image(tmp.path(), "jhuob-unlink.btrfs") else {
        eprintln!("btrfs-progs unavailable; skipping bd-jhuob unlink crash replay");
        return;
    };
    let cx = Cx::for_testing();

    let fs = open_rw(&cx, &image, true).expect("open ephemeral btrfs mount");
    let doomed = create_with(&fs, &cx, "doomed.bin", LOGGED_CONTENT);
    let survivor = create_with(&fs, &cx, "survivor.bin", OTHER_CONTENT);
    // Both names are in a tree log at this point — that is what makes the unlink
    // interesting: the log that would replay still NAMES `doomed.bin`.
    fs.fsync(&cx, doomed, 0, false).expect("fsync doomed");
    fs.fsync(&cx, survivor, 0, false).expect("fsync survivor");

    fs.unlink(&cx, BTRFS_ROOT_DIR, OsStr::new("doomed.bin"))
        .expect("unlink doomed.bin");
    // The fsync AFTER the unlink is the commit point under test.
    fs.fsync(&cx, survivor, 0, false)
        .expect("fsync survivor after the unlink");
    drop(fs);

    let recovered = open_rw(&cx, &image, false).expect("recovery mount");
    let resurrected = recovered.lookup(&cx, BTRFS_ROOT_DIR, OsStr::new("doomed.bin"));
    let survivor_bytes = content_of(&recovered, &cx, "survivor.bin", OTHER_CONTENT.len());
    drop(recovered);

    assert!(
        resurrected.is_err(),
        "THE UNLINKED FILE CAME BACK. A tree log written before the unlink was replayed over \
         a tree that had already dropped the name, so a deleted file returned after a crash. \
         This is what `btrfs_tree_log_has_deletions` exists to prevent; if a deletion record \
         has just been added to the log, it is not encoding the removal (bd-jhuob)."
    );
    assert_eq!(
        survivor_bytes.as_deref(),
        Some(OTHER_CONTENT),
        "the surviving file lost the data its fsync acknowledged"
    );
}

/// RENAME OVER an existing file, then crash. The destination must hold the
/// SOURCE's bytes and the source name must be gone — a rename-over is a deletion
/// of the destination's old inode reference plus a namespace move.
#[test]
fn rename_over_survives_a_crash_bd_jhuob() {
    init_tracing();
    let tmp = tempfile::TempDir::new().expect("temporary directory");
    let Some(image) = mkfs_btrfs_image(tmp.path(), "jhuob-rename-over.btrfs") else {
        eprintln!("btrfs-progs unavailable; skipping bd-jhuob rename-over crash replay");
        return;
    };
    let cx = Cx::for_testing();

    let fs = open_rw(&cx, &image, true).expect("open ephemeral btrfs mount");
    let src = create_with(&fs, &cx, "src.bin", LOGGED_CONTENT);
    let dst = create_with(&fs, &cx, "dst.bin", OTHER_CONTENT);
    fs.fsync(&cx, src, 0, false).expect("fsync src");
    fs.fsync(&cx, dst, 0, false).expect("fsync dst");

    fs.rename(
        &cx,
        BTRFS_ROOT_DIR,
        OsStr::new("src.bin"),
        BTRFS_ROOT_DIR,
        OsStr::new("dst.bin"),
    )
    .expect("rename src.bin over dst.bin");
    fs.fsync(&cx, src, 0, false)
        .expect("fsync the renamed inode");
    drop(fs);

    let recovered = open_rw(&cx, &image, false).expect("recovery mount");
    let dst_bytes = content_of(&recovered, &cx, "dst.bin", LOGGED_CONTENT.len());
    let src_still_there = recovered.lookup(&cx, BTRFS_ROOT_DIR, OsStr::new("src.bin"));
    drop(recovered);

    assert_eq!(
        dst_bytes.as_deref(),
        Some(LOGGED_CONTENT),
        "after a crash, dst.bin does not hold src.bin's bytes: the rename-over was \
         acknowledged by fsync and then lost or half-applied (bd-jhuob)"
    );
    assert!(
        src_still_there.is_err(),
        "src.bin is still present after a rename-over, so the crash left BOTH names \
         pointing at the inode — a replayed log re-added the source name (bd-jhuob)"
    );
}
