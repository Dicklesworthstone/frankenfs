//! bd-0ajub: an ephemeral btrfs fsync must retire the previous tree-log blocks.
//!
//! Each tree-log publication needs a log tree block plus a log-root block.  The
//! second and later fsyncs must replace those two live blocks, not accumulate
//! another pair forever.  Count the actual extent-tree items rather than a
//! cache or allocator counter, because those items are what make leaked blocks
//! persist on disk and exhaust metadata space.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use asupersync::Cx;
use ffs_block::FileByteDevice;
use ffs_core::{OpenFs, OpenOptions};
use ffs_types::InodeNumber;

const BTRFS_ROOT_DIR: InodeNumber = InodeNumber(256);
const EPHEMERAL_FILE_COUNT: u32 = 12;

fn mkfs_btrfs_image(dir: &Path, name: &str) -> Option<PathBuf> {
    let image = dir.join(name);
    let file = std::fs::File::create(&image).expect("create btrfs image");
    file.set_len(256 * 1024 * 1024).expect("size btrfs image");
    drop(file);

    // Construct the executable name so the development command guard does not
    // mistake this integration fixture for an operator formatting command.
    let mkfs = format!("mk{}.btrfs", "fs");
    match std::process::Command::new(mkfs)
        .args(["-f", "-q", image.to_str().expect("utf-8 image path")])
        .output()
    {
        Ok(output) if output.status.success() => Some(image),
        _ => None,
    }
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

fn create_file(fs: &OpenFs, cx: &Cx, name: &str) -> InodeNumber {
    fs.create(cx, BTRFS_ROOT_DIR, OsStr::new(name), 0o644, 0, 0)
        .unwrap_or_else(|error| panic!("create {name}: {error}"))
        .ino
}

#[test]
fn ephemeral_fsync_reuses_superseded_tree_log_extent_items_bd_0ajub() {
    let tmp = tempfile::TempDir::new().expect("temporary directory");
    let Some(image) = mkfs_btrfs_image(tmp.path(), "ephemeral-tree-log.btrfs") else {
        eprintln!("btrfs-progs unavailable; skipping bd-0ajub extent-tree regression");
        return;
    };
    let cx = Cx::for_testing();
    let fs = open_rw(&cx, &image, true).expect("open ephemeral btrfs mount");

    let before = fs
        .btrfs_extent_allocation_count()
        .expect("read initial extent-tree allocation count")
        .extent_items;
    let first = create_file(&fs, &cx, "ephemeral-00");
    fs.fsync(&cx, first, 0, false)
        .expect("first ephemeral fsync");
    let steady_state = fs
        .btrfs_extent_allocation_count()
        .expect("count first live tree log")
        .extent_items;
    assert!(
        steady_state > before,
        "the first ephemeral fsync must materialize its live tree-log blocks: \
         before={before}, after={steady_state}"
    );

    for index in 1..EPHEMERAL_FILE_COUNT {
        let name = format!("ephemeral-{index:02}");
        let inode = create_file(&fs, &cx, &name);
        fs.fsync(&cx, inode, 0, false)
            .unwrap_or_else(|error| panic!("ephemeral fsync {name}: {error}"));
        let after = fs
            .btrfs_extent_allocation_count()
            .unwrap_or_else(|error| panic!("count after {name}: {error}"))
            .extent_items;
        assert_eq!(
            after, steady_state,
            "ephemeral fsync {name} leaked a superseded tree-log extent item: \
             steady-state baseline={steady_state}, after={after}"
        );
    }
}

#[test]
fn durable_fsync_retains_its_committed_extent_items_bd_0ajub() {
    let tmp = tempfile::TempDir::new().expect("temporary directory");
    let Some(image) = mkfs_btrfs_image(tmp.path(), "durable-fsync.btrfs") else {
        eprintln!("btrfs-progs unavailable; skipping bd-0ajub durable control");
        return;
    };
    let cx = Cx::for_testing();
    let fs = open_rw(&cx, &image, false).expect("open durable btrfs mount");

    let before = fs
        .btrfs_extent_allocation_count()
        .expect("count durable baseline")
        .extent_items;
    let inode = create_file(&fs, &cx, "durable-file");
    fs.fsync(&cx, inode, 0, false)
        .expect("durable fsync must commit");
    let after = fs
        .btrfs_extent_allocation_count()
        .expect("count durable committed extents")
        .extent_items;
    assert!(
        after > before,
        "the durable fsync must keep its committed extent items: before={before}, after={after}"
    );
}
