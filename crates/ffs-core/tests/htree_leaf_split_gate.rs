#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Anti-corruption gate for the incremental htree LEAF SPLIT (bd-gauub).
//!
//! The htree-dir insert fast path splits ONE full leaf (O(log N)) instead of
//! rebuilding the whole index (O(dir)). A split mis-places an entry on disk =
//! silent corruption, so this gate inserts enough files into ONE directory to
//! force htree conversion AND many leaf splits, then asserts:
//!   1. EVERY inserted name is findable via `lookup` (the htree descent).
//!   2. `readdir` enumerates EXACTLY the inserted set (no dupes, no losses).
//!   3. After a rename churn (rename each name to a new one), every new name is
//!      still findable and readdir still enumerates exactly the renamed set.
//!
//! Renames keep the directory at capacity (insert + remove, no net growth), so
//! every rename's insert hits a full leaf -> exercises the split path heavily.
//!
//! Requires `mkfs.ext4` (skips gracefully otherwise, like the harness tests).

use asupersync::Cx;
use ffs_core::{OpenFs, OpenOptions};
use ffs_types::InodeNumber;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn has_command(name: &str) -> bool {
    matches!(
        Command::new(name)
            .arg("-V")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
        Ok(status) if status.success()
    )
}

fn unique_path(tag: &str) -> PathBuf {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!("ffs_htree_split_{tag}_{pid}_{nanos}.ext4"))
}

/// Format a fresh ext4 image with dir_index (htree) enabled — the default — so
/// the directory converts to an htree once it outgrows a linear block. Modern
/// `mkfs.ext4` enables `metadata_csum` by default, so this also exercises the
/// checksum-stamping side of the split.
fn make_ext4_image(path: &Path, size_mib: u64) {
    let f = std::fs::File::create(path).expect("create image file");
    f.set_len(size_mib * 1024 * 1024).expect("set image length");
    drop(f);
    let st = Command::new("mkfs.ext4")
        .args(["-q", "-F", "-O", "^has_journal,dir_index", "-b", "4096"])
        .arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn mkfs.ext4");
    assert!(st.success(), "mkfs.ext4 failed");
}

fn open_writable(path: &Path) -> OpenFs {
    let cx = Cx::for_testing();
    let opts = OpenOptions::default();
    let mut fs = OpenFs::open_with_options(&cx, path, &opts).expect("open ext4 image");
    fs.enable_writes(&cx).expect("enable writes");
    fs
}

/// Page through `readdir` collecting every real entry name (skipping `.`/`..`).
fn collect_readdir_names(fs: &OpenFs, cx: &Cx, dir: InodeNumber) -> Vec<Vec<u8>> {
    let mut names: Vec<Vec<u8>> = Vec::new();
    let mut off = 0_u64;
    loop {
        let page = fs.readdir(cx, dir, off).expect("readdir");
        if page.is_empty() {
            break;
        }
        let mut max_off = off;
        for e in &page {
            max_off = max_off.max(e.offset);
            if e.name != b"." && e.name != b".." {
                names.push(e.name.clone());
            }
        }
        if max_off <= off {
            // No progress (defensive): avoid an infinite loop.
            break;
        }
        off = max_off;
    }
    names
}

#[test]
fn htree_leaf_split_inserts_renames_stay_consistent_bd_gauub() {
    const N: usize = 6000;
    if !has_command("mkfs.ext4") {
        eprintln!("skipping htree_leaf_split gate: mkfs.ext4 unavailable");
        return;
    }

    let img = unique_path("gate");
    // 64 MiB is comfortably large for several thousand zero-length files in one
    // directory plus the htree index blocks.
    make_ext4_image(&img, 64);

    let cx = Cx::for_testing();
    let fs = open_writable(&img);
    let root = InodeNumber(2); // ext4 root inode

    // Make a dedicated subdirectory so the root's reserved entries don't mix in.
    let dir_attr = fs
        .mkdir(&cx, root, OsStr::new("bigdir"), 0o755, 0, 0)
        .expect("mkdir bigdir");
    let dir = dir_attr.ino;

    // Insert enough files to force htree conversion AND many single-level leaf
    // splits. At 4 KiB blocks a leaf holds ~120 short names; ~6000 names => ~50
    // leaves, each created by a split off a full leaf after conversion.
    let mut expected: HashSet<Vec<u8>> = HashSet::new();
    for i in 0..N {
        let name = format!("file_{i:06}");
        fs.create(&cx, dir, OsStr::new(&name), 0o644, 0, 0)
            .unwrap_or_else(|e| panic!("create {name}: {e:?}"));
        expected.insert(name.into_bytes());
    }

    // GATE 1: every inserted name is findable via the htree descent.
    for name in &expected {
        let os = OsStr::new(std::str::from_utf8(name).unwrap());
        fs.lookup(&cx, dir, os)
            .unwrap_or_else(|e| panic!("post-insert lookup {os:?} failed: {e:?}"));
    }

    // GATE 2: readdir enumerates EXACTLY the inserted set (no dupes, no losses).
    let listed = collect_readdir_names(&fs, &cx, dir);
    assert_eq!(
        listed.len(),
        expected.len(),
        "readdir count {} != inserted {} (dupes or losses)",
        listed.len(),
        expected.len()
    );
    let listed_set: HashSet<Vec<u8>> = listed.iter().cloned().collect();
    assert_eq!(
        listed_set.len(),
        listed.len(),
        "readdir produced duplicate names"
    );
    assert_eq!(listed_set, expected, "readdir set != inserted set");

    // GATE 3: rename churn — rename each name to a new one in the same dir. The
    // dir stays at capacity so each rename's insert hits a full leaf, driving the
    // split path on the rename hot path specifically.
    let mut renamed: HashSet<Vec<u8>> = HashSet::new();
    for i in 0..N {
        let from = format!("file_{i:06}");
        let to = format!("renamed_{i:06}");
        fs.rename(&cx, dir, OsStr::new(&from), dir, OsStr::new(&to))
            .unwrap_or_else(|e| panic!("rename {from} -> {to}: {e:?}"));
        renamed.insert(to.into_bytes());
    }

    // Every renamed name findable; no old name lingers.
    for name in &renamed {
        let os = OsStr::new(std::str::from_utf8(name).unwrap());
        fs.lookup(&cx, dir, os)
            .unwrap_or_else(|e| panic!("post-rename lookup {os:?} failed: {e:?}"));
    }
    for i in 0..N {
        let from = format!("file_{i:06}");
        assert!(
            fs.lookup(&cx, dir, OsStr::new(&from)).is_err(),
            "old name {from} still resolves after rename"
        );
    }

    // readdir enumerates exactly the renamed set.
    let listed2 = collect_readdir_names(&fs, &cx, dir);
    assert_eq!(
        listed2.len(),
        renamed.len(),
        "post-rename readdir count {} != {}",
        listed2.len(),
        renamed.len()
    );
    let listed2_set: HashSet<Vec<u8>> = listed2.iter().cloned().collect();
    assert_eq!(
        listed2_set.len(),
        listed2.len(),
        "post-rename readdir produced duplicate names"
    );
    assert_eq!(
        listed2_set, renamed,
        "post-rename readdir set != renamed set"
    );

    // Persist so an external e2fsck / kernel mount can validate the on-disk index.
    fs.sync_all_to_device(&cx).expect("flush to image");
    eprintln!("htree_leaf_split gate image (persisted): {}", img.display());
    // Leave the image in /tmp for the optional kernel-consistency check; the
    // harness's temp dir is cleaned by the OS. Best-effort remove if present.
    let _ = std::fs::remove_file(&img);
}
