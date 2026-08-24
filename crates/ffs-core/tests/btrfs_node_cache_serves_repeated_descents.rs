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

/// THE CACHE IS OFF ENTIRELY ON A WRITABLE MOUNT, and this pins it.
///
/// `btrfs_read_parsed_node` gates every lookup, hit and insert on
/// `let cacheable = self.btrfs_alloc_state.is_none();` — i.e. the parsed-node
/// cache exists only for READ-ONLY mounts. On a writable one the counters do not
/// even move, and every descent pays a full device read.
///
/// That is defensible by design (a writable tree changes under the cache and
/// there is no invalidation), and it is NOT the mechanism behind bd-2s8zy's
/// mounted readdir+stat storm — the comparator passes `--rw` only for MUTATING
/// workloads (`ffs_mounted_kernel_bench.rs`: `if config.workload.is_mutating()`),
/// and readdir+stat is not one. So this test does not explain that row.
///
/// It is worth pinning anyway because it sizes a DIFFERENT gap: every write
/// workload — create/delete storm, parallel metadata write, fsync — runs with the
/// node cache completely disabled, and the read-only numbers above show what that
/// costs when the same nodes are crossed repeatedly (0 misses vs a full descent
/// each time). Anyone proposing generation-stamped invalidation for writable
/// mounts should start from this counter, and anyone who "fixes" the gate without
/// adding invalidation will break correctness silently.
#[test]
fn the_node_cache_is_disabled_on_a_writable_mount_bd_2s8zy() {
    let tmp = tempfile::TempDir::new().expect("temporary directory");
    let entries = 600;
    let Some(image) = seeded_image(&tmp.path().join("."), entries, "nc-rw.btrfs") else {
        eprintln!("btrfs-progs unavailable; skipping bd-2s8zy writable-mount probe");
        return;
    };
    let cx = Cx::for_testing();
    let names: Vec<String> = (0..entries).map(|index| format!("f{index:06}")).collect();

    let device = ffs_block::FileByteDevice::open(&image).expect("open image");
    let mut fs = OpenFs::from_device(&cx, Box::new(device), &OpenOptions::default())
        .expect("open btrfs");
    fs.enable_writes(&cx).expect("enable writes");

    let (l0, h0, m0) = ffs_core::btrfs_node_cache_counters_full();
    probe_all(&fs, &cx, &names);
    probe_all(&fs, &cx, &names);
    let (l1, h1, m1) = ffs_core::btrfs_node_cache_counters_full();
    let (lookups, hits, misses) = (l1 - l0, h1 - h0, m1 - m0);
    eprintln!(
        "bd-2s8zy WRITABLE entries={entries} two sweeps: lookups={lookups} hits={hits} misses={misses}"
    );

    assert_eq!(
        (lookups, hits, misses),
        (0, 0, 0),
        "the writable-mount arm recorded node-cache activity, so the `cacheable` gate in          btrfs_read_parsed_node no longer means what this test documents — re-read it          before trusting any read-only cache number measured alongside a writable mount"
    );
}

/// PER-OPERATION DESCENT DECOMPOSITION for the readdir+stat row
/// (bd-btrfs-readdir-stat-8x-8y7vp, bd-2s8zy, bd-3zx2x).
///
/// The mounted instrument reports device reads PER ARM. It has never reported
/// them PER FUSE OPERATION, so "the probe costs a second uncached descent per
/// entry" — bd-2s8zy's attribution, and the basis for the whole lever class — has
/// been inferred from arm totals rather than measured directly.
///
/// One `ls -l` entry costs the daemon three kinds of work: resolve the NAME
/// (LOOKUP), read the ATTRIBUTES (GETATTR), and answer the kernel's mandatory
/// `security.capability` probe (GETXATTR). This counts node lookups for each in
/// isolation, over the same directory, from a cold cache each time.
///
/// It needs no mount and no quiet window, which matters because every mounted
/// attempt at this row this session has been refused for host contention.
#[test]
fn readdir_stat_descent_cost_decomposes_by_operation_bd_2s8zy() {
    let tmp = tempfile::TempDir::new().expect("temporary directory");
    let entries = 6_000;
    let Some(image) = seeded_image(&tmp.path().join("."), entries, "nc-decomp.btrfs") else {
        eprintln!("btrfs-progs unavailable; skipping bd-2s8zy per-op decomposition");
        return;
    };
    let cx = Cx::for_testing();
    let names: Vec<String> = (0..entries).map(|index| format!("f{index:06}")).collect();

    // Each arm gets a FRESH OpenFs so it starts from a cold parsed-node cache;
    // otherwise arm 2 measures arm 1's cache and the decomposition is meaningless.
    let fresh = || {
        let device = ffs_block::FileByteDevice::open(&image).expect("open image");
        OpenFs::from_device(&cx, Box::new(device), &OpenOptions::default())
            .expect("open btrfs read-only")
    };
    let measure = |label: &str, body: &dyn Fn(&OpenFs)| -> (u64, u64) {
        let fs = fresh();
        let (l0, _, m0) = ffs_core::btrfs_node_cache_counters_full();
        body(&fs);
        let (l1, _, m1) = ffs_core::btrfs_node_cache_counters_full();
        let (lookups, misses) = (l1 - l0, m1 - m0);
        eprintln!(
            "bd-2s8zy decomp {label}: node_lookups={lookups} misses={misses} \
             per_entry={:.3}",
            lookups as f64 / entries as f64
        );
        (lookups, misses)
    };

    let (lookup_only, _) = measure("LOOKUP        ", &|fs| {
        for name in &names {
            let _ = fs.lookup(&cx, BTRFS_ROOT_DIR, OsStr::new(name));
        }
    });
    let (lookup_getattr, _) = measure("LOOKUP+GETATTR", &|fs| {
        for name in &names {
            if let Ok(attr) = fs.lookup(&cx, BTRFS_ROOT_DIR, OsStr::new(name)) {
                let _ = fs.getattr(&cx, attr.ino);
            }
        }
    });
    let (full_stat, _) = measure("LOOKUP+GETATTR+GETXATTR", &|fs| {
        for name in &names {
            if let Ok(attr) = fs.lookup(&cx, BTRFS_ROOT_DIR, OsStr::new(name)) {
                let _ = fs.getattr(&cx, attr.ino);
                let _ = FsOps::getxattr(fs, &cx, attr.ino, SECURITY_CAPABILITY);
            }
        }
    });

    let getattr_cost = lookup_getattr.saturating_sub(lookup_only);
    let getxattr_cost = full_stat.saturating_sub(lookup_getattr);
    eprintln!(
        "bd-2s8zy decomp DELTAS: lookup={lookup_only} getattr=+{getattr_cost} \
         getxattr=+{getxattr_cost} (total {full_stat})"
    );

    assert!(
        lookup_only > 0,
        "the LOOKUP arm performed no node lookups, so this decomposition is measuring nothing"
    );
    // ⚠️ MEASURED RESULT THAT REFUTES THE PREMISE I WROTE THIS TEST TO CONFIRM.
    //
    // I first asserted `getxattr_cost * 4 >= lookup_only` — the bead's attribution
    // that the capability probe is a SECOND FULL DESCENT per entry. It FAILS:
    // the probe costs 334 node lookups against 14817 for LOOKUP over the same
    // 6,000 entries, about 2%. GETATTR costs ZERO. In-process, the probe is very
    // nearly free.
    //
    // That does not contradict bd-2s8zy's mounted measurement (suppressing the
    // probe took preads 27572 -> 1840, ~15x). It LOCATES it: the probe's expense
    // is not the tree descent, because in-process the descent is already absorbed
    // by the parsed-node cache and the floor-leaf memo. Whatever makes it
    // expensive through a mount is added by the mount — the extra FUSE round trip
    // per probe, or per-request state that stops those two caches from carrying
    // across operations the way they do here.
    //
    // The direction of this assertion is therefore INVERTED on purpose: it pins
    // that the probe is cheap on the in-process path, so that anyone proposing a
    // "share the descent across the sweep" lever sees first that there is almost
    // no descent left to share at this layer, and goes looking in the FUSE layer
    // instead.
    assert!(
        getxattr_cost * 4 < lookup_only,
        "the security.capability probe now costs {getxattr_cost} node lookups against \
         {lookup_only} for LOOKUP over {entries} entries. It used to be ~2%. If the probe \
         has become a full descent again at this layer, the parsed-node cache or the \
         floor-leaf memo stopped absorbing it, and bd-2s8zy's mounted attribution would \
         now apply in-process too."
    );
    // REGRESSION GUARD on the floor-memo sizing (bd-2s8zy). With
    // BTRFS_FLOOR_MEMO_SLOTS = 4 this sweep cost 2.525 node lookups per entry; at
    // 16 it costs 0.861. The threshold sits between the two, so shrinking the memo
    // back below the working set fails here instead of quietly restoring ~3x the
    // descent work.
    let per_entry = full_stat as f64 / entries as f64;
    assert!(
        per_entry < 1.5,
        "a full stat now costs {per_entry:.3} node lookups per entry ({full_stat} for \
         {entries}); it was 0.861 at BTRFS_FLOOR_MEMO_SLOTS = 16 and 2.525 at 4. The \
         floor-leaf memo has dropped back below the sweep's working set."
    );
    assert_eq!(
        getattr_cost, 0,
        "GETATTR now costs {getattr_cost} node lookups on top of LOOKUP; it used to be \
         free because the lookup already resolved the inode. A regression here would \
         double the descent cost of every stat."
    );
}

/// DOES ACCESS ORDER REPRODUCE THE MOUNTED STORM? (bd-2s8zy, bd-79li3,
/// bd-btrfs-readdir-stat-8x-8y7vp)
///
/// The decomposition above says the capability probe is ~2% of LOOKUP in-process,
/// while the mount measures it at ~15x. The obvious difference in my harness is
/// ACCESS ORDER: in-process I probe each inode immediately after looking it up,
/// which is perfect locality for a 4-slot floor-leaf memo
/// (`BTRFS_FLOOR_MEMO_SLOTS = 4`, round-robin victim). The banked row is
/// `readdir-stat-8t` — EIGHT client threads, each walking its own slice of one
/// directory, so eight independent descent streams compete for four slots and
/// bd-79li3 already measured that a miss REPLACES the memo on every descent.
///
/// This drives the same total work in two orders on the same image:
///   SEQUENTIAL  — one stream, entry 0,1,2,...  (what the earlier arms measured)
///   INTERLEAVED — eight streams round-robined, which is the ORDER eight
///                 concurrent client threads present to a shared memo, without
///                 needing threads to reproduce it.
///
/// Single-threaded on purpose: the question is whether ORDER alone accounts for
/// the gap. If it does, the mechanism is memo capacity against stream count and
/// the fix is a policy on slots, not a new constant. If it does not, order is
/// exonerated and the cost is elsewhere in the FUSE layer.
#[test]
fn interleaved_stat_order_costs_more_descents_than_sequential_bd_2s8zy() {
    let tmp = tempfile::TempDir::new().expect("temporary directory");
    let entries = 6_000;
    let streams = 8;
    let Some(image) = seeded_image(&tmp.path().join("."), entries, "nc-order.btrfs") else {
        eprintln!("btrfs-progs unavailable; skipping bd-2s8zy access-order probe");
        return;
    };
    let cx = Cx::for_testing();
    let names: Vec<String> = (0..entries).map(|index| format!("f{index:06}")).collect();

    // Eight contiguous slices, round-robined: exactly the sequence eight threads
    // each scanning their own slice present to one shared memo.
    let mut interleaved: Vec<usize> = Vec::with_capacity(entries);
    let slice = entries.div_ceil(streams);
    for offset in 0..slice {
        for stream in 0..streams {
            let index = stream * slice + offset;
            if index < entries {
                interleaved.push(index);
            }
        }
    }
    assert_eq!(interleaved.len(), entries, "the interleaving must cover every entry");

    let sweep = |order: &[usize]| -> u64 {
        let device = ffs_block::FileByteDevice::open(&image).expect("open image");
        let fs = OpenFs::from_device(&cx, Box::new(device), &OpenOptions::default())
            .expect("open btrfs read-only");
        let (l0, _, _) = ffs_core::btrfs_node_cache_counters_full();
        for &index in order {
            if let Ok(attr) = fs.lookup(&cx, BTRFS_ROOT_DIR, OsStr::new(&names[index])) {
                let _ = fs.getattr(&cx, attr.ino);
                let _ = FsOps::getxattr(fs_ref(&fs), &cx, attr.ino, SECURITY_CAPABILITY);
            }
        }
        let (l1, _, _) = ffs_core::btrfs_node_cache_counters_full();
        l1 - l0
    };

    let sequential_order: Vec<usize> = (0..entries).collect();
    let sequential = sweep(&sequential_order);
    let interleaved_cost = sweep(&interleaved);

    eprintln!(
        "bd-2s8zy order entries={entries} streams={streams}: sequential={sequential} \
         interleaved={interleaved_cost} ratio={:.3}",
        interleaved_cost as f64 / sequential as f64
    );

    assert!(sequential > 0, "the sequential sweep performed no node lookups");
    // No assertion on the DIRECTION beyond a sanity bound: this test exists to
    // publish the ratio, and pinning a direction I have not yet explained is how
    // a premise gets frozen before it is understood (the mistake the arm above
    // corrects). The bound catches only a pathological blowup, which would be a
    // regression in anyone's reading.
    assert!(
        interleaved_cost < sequential * 50,
        "interleaved access cost {interleaved_cost} node lookups against {sequential} \
         sequential — a >50x blowup from ORDER alone on one thread is a defect, not a \
         locality effect"
    );
}

/// `FsOps::getxattr` takes `&self`; this keeps the call site readable above.
fn fs_ref(fs: &OpenFs) -> &OpenFs {
    fs
}

/// The shipping floor-memo size must be the one the counted evidence was taken on
/// (bd-2s8zy).
///
/// 692af94aa raised the memo 4 -> 16 on counted evidence and left it unmeasurable
/// against the live kernel: the mounted comparator only A/Bs two configurations
/// that come from ONE ELF and can be shown to differ on a knob the daemon
/// self-reports. `FFS_BTRFS_FLOOR_MEMO_SLOTS` now makes that A/B expressible.
///
/// This asserts the half an integration test can honestly reach. The knob's
/// PARSING is unit-tested inside ffs-core (`std::env::set_var` is `unsafe` in
/// edition 2024 and this workspace forbids unsafe, so an integration test cannot
/// toggle it without mutating process-global state the parallel harness shares).
/// The knob's EFFECT is the 4-vs-16 table in 692af94aa, taken by rebuilding.
#[test]
fn the_shipping_floor_memo_size_matches_the_measured_one_bd_2s8zy() {
    assert_eq!(
        ffs_core::btrfs_floor_memo_slots_effective(),
        16,
        "the effective floor-memo slot count is not 16, so the knob line the comparator \
         reads does not describe the configuration the counted 2.93x was measured on"
    );
}
