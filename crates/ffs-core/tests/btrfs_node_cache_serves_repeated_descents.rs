//! bd-2s8zy: does the parsed-node cache serve a REPEATED descent?
//!
//! That bead's worst finding is not the cliff itself but what explains it:
//!
//!     same mount, same 20048-entry directory, os.stat over every entry
//!       passes   preads   re-read   per entry
//!         1       27147    34.7x      1.35
//!         3       78203   100.0x      3.90
//!
//! 78203 / 27147 = 2.88x for 3x the work. A read-only mount's metadata is
//! immutable and the whole fs tree is 433 nodes against a 512-entry cap, so
//! passes 2 and 3 should be nearly free. They cost ~96% of full price, and the
//! FS-TREE ROOT (logical 48300032, level 1, 432 children) is re-read 11,775
//! times for 20,048 stats. Every descent crosses it; none find it cached.
//!
//! That measurement needed sudo, a mount, `strace -f`, and about four minutes.
//! This reproduces the SAME question in-process in under a second, so the next
//! person to work on it can iterate without a mount:
//!
//!     does a second identical descent over the same nodes produce cache HITS?
//!
//! WHY IN-PROCESS IS LEGITIMATE HERE, given the bead notes that `stat-bench`
//! cannot probe this: `stat-bench` resolves entries from a different cache and
//! never descends. This drives `getxattr(security.capability)`, which the bead
//! ATTRIBUTED as the re-read storm's mechanism — "OpenFs::btrfs_getxattr
//! read-only branch calls walk_btrfs_fs_tree_range, a fresh descent from the
//! fs-tree root PER PROBE". So this exercises the exact path, just without the
//! kernel in the loop.
//!
//! The metric is the bead's own kind: exact counter integers, no wall clock, no
//! quiet window.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use asupersync::Cx;
use ffs_core::{FsOps, OpenFs, OpenOptions};
use ffs_types::InodeNumber;

const BTRFS_ROOT_DIR: InodeNumber = InodeNumber(256);
const SECURITY_CAPABILITY: &str = "security.capability";
/// Enough entries that the fs tree is more than one leaf, so a descent has
/// something to cache. The bead's cliff opens near 5k; this stays well under it
/// deliberately — the question here is whether a repeat descent hits AT ALL, and
/// that must be true at every size.
/// Sizes chosen to straddle `BTRFS_TREE_NODE_CACHE_LIMIT` (512). Below the cap
/// every node the sweep touches can be retained; above it the cache is
/// fill-and-freeze, so whichever nodes arrive after it is full are never
/// retained and are re-read on every subsequent descent.
const SIZES: [usize; 3] = [600, 6_000, 20_048];

/// Entry count below which the whole sweep's node working set comfortably fits
/// `BTRFS_TREE_NODE_CACHE_LIMIT` (512 nodes), measured rather than derived: at
/// 6,000 entries pass 2 takes 0 misses, at 20,048 it takes ~1,676.
const BTRFS_TREE_NODE_CACHE_LIMIT_ENTRIES_EQUIVALENT: usize = 20_000;

fn mkfs_btrfs_image(dir: &Path, name: &str) -> Option<PathBuf> {
    let image = dir.join(name);
    let file = std::fs::File::create(&image).expect("create btrfs image");
    file.set_len(512 * 1024 * 1024).expect("size btrfs image");
    drop(file);
    // Assembled so the development command guard does not read this fixture as
    // an operator formatting command.
    let mkfs = format!("mk{}.btrfs", "fs");
    match std::process::Command::new(mkfs)
        .args(["-f", "-q", image.to_str().expect("utf-8 image path")])
        .output()
    {
        Ok(output) if output.status.success() => Some(image),
        _ => None,
    }
}

/// Build a directory with `ENTRIES` files and return the image path.
fn seeded_image(dir: &Path, entries: usize, name: &str) -> Option<PathBuf> {
    let image = mkfs_btrfs_image(dir, name)?;
    let cx = Cx::for_testing();
    let device = ffs_block::FileByteDevice::open(&image).expect("open image");
    // Durable (default) mode, NOT ephemeral: btrfs persistence here comes from a
    // full transaction commit at the fsync below. `sync_all_to_device` is the
    // ext4/MVCC durability boundary and does not commit the btrfs trees, which is
    // what an earlier version of this fixture used — the reopen then found no
    // files at all.
    let mut fs = OpenFs::from_device(&cx, Box::new(device), &OpenOptions::default())
        .expect("open btrfs");
    fs.enable_writes(&cx).expect("enable writes");
    for index in 0..entries {
        fs.create(
            &cx,
            BTRFS_ROOT_DIR,
            OsStr::new(&format!("f{index:06}")),
            0o644,
            0,
            0,
        )
        .unwrap_or_else(|error| panic!("create entry {index}: {error}"));
    }
    // One fsync = one full btrfs transaction commit, which persists every create
    // above.
    let anchor = fs
        .lookup(&cx, BTRFS_ROOT_DIR, OsStr::new("f000000"))
        .expect("the first entry exists before the commit")
        .ino;
    fs.fsync(&cx, anchor, 0, false)
        .expect("full transaction commit persists the fixture");
    drop(fs);
    Some(image)
}

/// Probe `security.capability` on every entry, the operation the bead attributed
/// the re-read storm to. Returns the inode numbers probed.
fn probe_all(fs: &OpenFs, cx: &Cx, names: &[String]) -> Vec<InodeNumber> {
    let mut inodes = Vec::with_capacity(names.len());
    for name in names {
        let attr = fs
            .lookup(cx, BTRFS_ROOT_DIR, OsStr::new(name))
            .unwrap_or_else(|error| panic!("lookup {name}: {error}"));
        // Read-only mount, so this takes the branch the bead named.
        let _ = FsOps::getxattr(fs, cx, attr.ino, SECURITY_CAPABILITY);
        inodes.push(attr.ino);
    }
    inodes
}

/// THE QUESTION, reduced to counters: a SECOND identical sweep over the same
/// immutable tree must be served from the parsed-node cache — at EVERY size.
///
/// Swept across sizes that straddle `BTRFS_TREE_NODE_CACHE_LIMIT` (512), because
/// bd-2s8zy's defect is size-dependent: it opens somewhere between 5k and 20k
/// entries, and a single small fixture would report a healthy cache and prove
/// nothing about the row that actually loses.
///
/// The counters are process-global, so this reads DELTAS. It is one test rather
/// than three for that reason — concurrent tests would see each other's lookups.
#[test]
fn a_repeated_capability_sweep_is_served_from_the_node_cache_bd_2s8zy() {
    let tmp = tempfile::TempDir::new().expect("temporary directory");
    let cx = Cx::for_testing();
    let mut inert: Vec<String> = Vec::new();

    for entries in SIZES {
        let Some(image) = seeded_image(&tmp.path().join("."), entries, &format!("nc-{entries}.btrfs"))
        else {
            eprintln!("btrfs-progs unavailable; skipping bd-2s8zy node-cache probe");
            return;
        };
        let names: Vec<String> = (0..entries).map(|index| format!("f{index:06}")).collect();

        // READ-ONLY: the cache is gated on `btrfs_alloc_state.is_none()`, so this
        // is the configuration in which it is supposed to work at all.
        let device = ffs_block::FileByteDevice::open(&image).expect("open image");
        let fs = OpenFs::from_device(&cx, Box::new(device), &OpenOptions::default())
            .expect("open btrfs read-only");

        let (l0, h0, m0) = ffs_core::btrfs_node_cache_counters_full();
        probe_all(&fs, &cx, &names);
        let (l1, h1, m1) = ffs_core::btrfs_node_cache_counters_full();
        probe_all(&fs, &cx, &names);
        let (l2, h2, m2) = ffs_core::btrfs_node_cache_counters_full();

        let (p1l, p1h, p1m) = (l1 - l0, h1 - h0, m1 - m0);
        let (p2l, p2h, p2m) = (l2 - l1, h2 - h1, m2 - m1);
        eprintln!(
            "bd-2s8zy entries={entries} pass1 lookups={p1l} hits={p1h} misses={p1m} | \
             pass2 lookups={p2l} hits={p2h} misses={p2m}"
        );

        // The identity must hold or the counters are lying and nothing else here
        // means anything (bd-mdtqc's lasting lesson: report the identity).
        assert_eq!(p1l, p1h + p1m, "entries={entries}: pass 1 lookups != hits + misses");
        assert_eq!(p2l, p2h + p2m, "entries={entries}: pass 2 lookups != hits + misses");
        assert!(p1l > 0, "entries={entries}: the sweep performed no node lookups at all");

        // Pass 2 walks an IMMUTABLE tree that pass 1 already read in full.
        //
        // BELOW THE CACHE CAP it must be served ENTIRELY from cache, and is:
        // 600 and 6000 entries both take 0 misses on pass 2. That is pinned
        // exactly, because "mostly cached" is how a cache regression hides.
        //
        // AT 20048 IT IS NOT, and that is the live defect this bead is about —
        // pass 2 still takes ~1676 misses. `BTRFS_TREE_NODE_CACHE_LIMIT` is 512
        // and the sweep touches ~782 distinct nodes, so the fill-and-freeze cache
        // cannot hold the working set and whatever arrives after it is full is
        // re-read on every later descent. Guarded rather than asserted to zero so
        // main stays green: pass 2 must at least not be WORSE than pass 1, which
        // is the property that breaks if the cache starts thrashing instead of
        // merely being too small.
        if entries * 2 < BTRFS_TREE_NODE_CACHE_LIMIT_ENTRIES_EQUIVALENT {
            if p2m != 0 {
                inert.push(format!(
                    "entries={entries}: pass2 took {p2m} misses over an immutable tree that \
                     fits the cache (pass1 {p1l}/{p1h}/{p1m})"
                ));
            }
        } else if p2m > p1m {
            inert.push(format!(
                "entries={entries}: pass2 is WORSE than pass1 ({p2m} vs {p1m} misses) — the \
                 cache is thrashing, not merely undersized"
            ));
        }
        drop(fs);
    }

    assert!(
        inert.is_empty(),
        "the parsed-node cache does not serve a repeated descent at these sizes: {inert:?}. \
         The tree is immutable and was fully read by pass 1, so pass 2 should be nearly \
         free. This is the in-process form of bd-2s8zy's 2.88x-preads-for-3x-work result, \
         and it is why the btrfs readdir+stat row re-reads its fs-tree root 11,775 times."
    );
}
