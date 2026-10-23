<div align="center">
  <img src="docs/assets/frankenfs_illustration.webp" alt="FrankenFS — Rust userspace filesystems: ext4, btrfs, FAT16, FAT32, NTFS and ZFS">
</div>

<h1 align="center">FrankenFS</h1>

<p align="center">
  <strong>Rust userspace filesystems: ext4 and btrfs, expanding to FAT16, FAT32, NTFS and ZFS</strong><br>
  <em>Block-level MVCC · RaptorQ repair · Explicit durability boundaries · Unsafe forbidden in first-party crates</em>
</p>

<p align="center">
  <a href="LICENSE">License</a> ·
  <a href="README_EXT4_BTRFS.md">Detailed ext4/btrfs guide</a> ·
  <a href="COMPREHENSIVE_PLAN_FOR_NTFS_FAT16_FAT32_AND_ZFS.md">Multi-format plan</a> ·
  <a href="FEATURE_PARITY.md">Feature and evidence accounting</a>
</p>

## What it is

FrankenFS reimplements native filesystem behavior in Rust and runs in userspace
through FUSE and offline-image tools. Its established development base is ext4
and btrfs, with experimental block-level multi-version concurrency control
(MVCC), RaptorQ repair symbols and explicit writeback/durability gates.

The expansion now includes **FAT16, FAT32, NTFS and ZFS companion tools**. These
are real native-image paths, not just format-signature recognizers, but their
capabilities differ substantially. A read profile is not a native writer, a
parser is not a mounted filesystem, and source code is not executed proof.

**All profiles remain experimental. Keep original images untouched and use
separate copies for mutation experiments.** The first-party unsafe-code ban
does not cover every dependency or the vendored FUSE transport, and it does not
prevent logical filesystem corruption.

The previous long-form README was preserved in full as the
[detailed ext4/btrfs guide](README_EXT4_BTRFS.md), which continues to receive
native implementation updates. It retains architecture, operational examples,
benchmark qualifications, recovery/writeback discussion and historical evidence.
The format matrix below is the front-page overview of the broader project;
per-format profiles define the actual admission rules.

## Current format surface

| Format | Entry point | Implemented surface | Important boundary |
|---|---|---|---|
| **ext4** | Main `ffs-cli` / `OpenFs` path | Native reads, experimental mounted writes, journal integration, MVCC and repair work | Writeback, recovery and release readiness remain evidence-gated; see the detailed guide and current parity ledger. |
| **btrfs** | Main `ffs-cli` / `OpenFs` path | Native reads and guarded experimental writes, transaction-commit and repair work | Native feature/topology admission and durability evidence still matter; not blanket kernel parity. |
| **FAT16** | `ffs-fat` | Native reads/catalog/extraction, experimental ordinary/protected writable FUSE, allocation checks, formatting/population, and ordered offline file/directory/range mutation | New long names use bounded UTF-16 with ASCII aliases. Subdirectories can grow; [offline resize can expand the fixed root](docs/FAT_ROOT_EXPANSION.md) into a new image. Native/mounted crash qualification remains open; ordered mutation is not a crash-atomic transaction. |
| **FAT32** | `ffs-fat` | The FAT16 companion surface plus root chains, selected-FAT handling, free-space hints and offline resize/relocation | Namespace and range operations retain ordered native publication and explicit dirty failure states. Complete native/mounted qualification remains open. |
| **NTFS** | `ffs-ntfs` | Read-only native namespace and file/stream access, sparse and admitted compressed/transformed data, metadata inspection, physical allocation checking and FUSE | The exact read profile controls admission. Restricted volatile `$LogFile` recovery exists; neither recovery nor allocation checking grants native write authority or a general Windows consistency claim. General NTFS mutation remains unfinished. |
| **ZFS** | `ffs-zfs` | Native dataset/snapshot reads, automatic read-only root selection, admitted compression/checksums, selected mirror/RAIDZ, explicit missing-member extraction and volatile ZIL recovery | Read-only root selection is not native writable pool ownership. Missing-member extraction is committed-view-only and forbids ZIL replay. Native allocation/TXG writing remains unfinished. |

The companion engines are reusable libraries: `ffs-fat`, `ffs-ntfs` and
`ffs-zfs`. Their binaries and the protected mount import the same implementation.
The `ffs` facade provides `open_read_only(cx, path, options)` for all six formats,
returning the detected format and a `Box<dyn FsOps>`. It uses bounded read-only
image handles, refuses ambiguous signatures and keeps native admission rules.
Options preserve volume bounds, FAT OEM selection, btrfs roots/devices and ZFS
pool/candidate/dataset/snapshot/device selection. ext4 recovery stays in memory.
Callers supply their own context and keep backing images offline and immutable.
Auxiliary ext4 journals, btrfs devices and ZFS members use `ImageSource` with
their own offset and length. Each receives the same regular-file, OS-read-only
and shared-lock admission as the primary image. The facade passes these handles
into the engines; ext4 replay and journal pairing share one descriptor, and
nested btrfs views retain the admitted member handles. Direct core consumers can
use `OpenFs::from_devices` for already-open auxiliary devices; it refuses mixed
path/handle auxiliary options.
The auxiliary-handle change passed 46 facade/example tests (one existing native
producer test remained ignored), nine selected btrfs seed/journal regressions,
workspace checking, strict Clippy and formatting on a single source cut. These regressions
use constructed images; native auxiliary-device qualification remains open.
For NTFS, `ReadOnlyFs::ntfs_volume()` borrows the same admitted volume for exact
UTF-16 named-stream selection, including streams stored in extension records.
Native stream access has executed through the standalone public consumer on
ntfs-3g-produced images, including streams held in extension records.

The standalone [`native_reader` example](crates/ffs/examples/native_reader.rs)
uses that public API for `stat`, NUL-delimited `list`, bounded `read` and an
explicit `refuse-write` scratch-image check. Its foreground `mount` subcommand
passes the same admitted filesystem to the shared FUSE transport with kernel
read-only enforcement. It owns its application runtime:

```bash
cargo run -p ffs --example native_reader -- image.img stat /
cargo run -p ffs --example native_reader -- image.img read /hello.txt --start 0 --bytes 4096
cargo run -p ffs --example native_reader -- ntfs.img read /hello.txt --stream note
cargo run -p ffs --example native_reader -- image.img mount /mnt/ffs
cargo run -p ffs --example native_reader -- ntfs.img --ntfs-indexed-lookup mount /mnt/ffs
cargo run -p ffs --example native_reader -- ext4.img --ext4-journal journal.img 8192 32768 stat /
cargo run -p ffs --example native_reader -- sprout.img --btrfs-device seed.img 0 rest mount /mnt/ffs
cargo run -p ffs --example native_reader -- sprout.img --btrfs-device seed.img 0 rest --btrfs-subvolume seed-nested read /payload
```

`--ext4-journal PATH OFFSET LENGTH` selects one external journal;
`--btrfs-device PATH OFFSET LENGTH` repeats for additional members. Each offset
and length is in bytes; a positive length bounds that member, while `rest`
selects the remainder of its file. These format selections conflict with each
other and with NTFS/ZFS selectors. They use the same admitted read-only handles
as the library API, including independent regular-file, lock and bounds checks.
An external journal can be a bare JBD2 region or a native `JOURNAL_DEV` image.
For a native image, the selected bounds include its device header: keep the
original device-relative ring addresses instead of slicing past that header.
`--btrfs-subvolume NAME` or `--btrfs-subvolume-id ID` selects the root for all
offline commands and foreground mounts, with or without additional members.
The selectors are mutually exclusive and retain every primary/member bound
and lock. Root IDs must be positive; native root existence and format admission
are still checked by the library. Selecting a subvolume does not grant writes.

Mounting requires working FUSE support and an existing empty directory which
does not hide any primary or auxiliary backing image. Keep all backing files offline and unchanged
until unmount; use `fusermount3 -u /mnt/ffs` on Linux to end the foreground
session. Volume bounds and explicit NTFS/ZFS view selections apply to mounts
as they do to offline reads. This consumer has no writable, `allow_other`,
device-node or set-ID mount switches. Kernel-mount qualification for this new
public-consumer path passed on retained native fixtures across all six formats:
20 mounts, 56 files, 236 full/range/EOF/sparse byte comparisons, 20 read-only
write-open refusals and 20 missing-path refusals. Every mount unmounted and its
daemon exited successfully; all 47 image/payload/tool/executable controls stayed
unchanged. This includes strict/indexed and compressed NTFS views and divergent
ZFS head/snapshot views. The mount-qualified source passed 45 facade/example tests
(one existing native-producer test remained ignored), workspace/all-target
checking, strict Clippy and formatting. Exact source
cuts, failed attempts and readback receipts are in `.beads/pending_tasks.md`.
These are kernel reads of retained native inputs and captured native payloads,
with kernel-clamped EOF checks; no writable, crash, performance or field claim.

At merged revision `ff3dca7ec`, workspace/all-target checking and strict Clippy
passed through RCH. Earlier executed engine suites passed FAT 452, NTFS 344,
ZFS 305 and facade 40 tests, plus both external FAT consumer tests. The merged
ZFS suite then passed all 315 unit tests and one compiled doctest. The explicit
native-producer facade test passed FAT16/FAT32/NTFS plain and bounded images.
On OpenZFS 2.4.1, the corrected ZFS companion and public consumer at `bd2fac9c4`
passed native ZPL 4/5 file and divergent head/snapshot profiles, including exact
bytes, metadata, names and unchanged backing hashes. These are offline reads
of natively produced images. The NTFS companion at `ff3dca7ec` also passed its
native ntfs-3g profile: all 203 commands, 32 named streams spanning extension
records and actual LZNT1 compression with 512-byte and 4 KiB clusters, including
bounded reads and unchanged image hashes. The public consumer at `c555bb45e`
then passed 120 commands over the retained NTFS inputs, including all 32
extension streams, both exact selectors and write refusal; a separate verifier
executed 58 public calls and fresh native comparisons. The same consumer also
passed FAT16/FAT32 plain/bounded reads and selected ZPL 4/5 file/snapshot reads.
At `c6c93513b`, the explicit native Rust selection passed through RCH with
freshly produced FAT16/FAT32/NTFS images, same-volume named-stream reads and
both unchanged FAT/NTFS companion profile wrappers. Its captured output and
source receipt are recorded in `.beads/pending_tasks.md`; this run predates the
indexed-lookup repair and the indexed FsOps constructor below.
A current RCH-built NTFS CLI subsequently passed four strict read-only kernel
FUSE mounts on retained native plain, bounded and compressed images: 24 mounted
byte comparisons and eight EROFS/ENOENT refusals, with successful unmounts and
unchanged backing hashes. An independent rerun passed. Those companion mounts
covered the strict NTFS adapter; the public-consumer qualification above adds
the named indexed and six-format mounted slice. The standalone public consumer
built from `990539073` plus
explicit overlays also passed 228 calls on retained native FAT16/FAT32, NTFS
and ZFS images, including nine expected semantic failures and unchanged backing
hashes. The full harness subsequently passed 2,652 tests, zero failures and 11
ignored, including one compiled doctest, with a valid source receipt. The same
public consumer then passed another 52 calls on freshly natively produced ext4
and btrfs images: plain/bounded windows, eight native payload readbacks, 28
payload comparisons, Unicode and empty files, ranged reads and four typed
missing-path failures. All source, image, tool and executable hashes remained
unchanged during verification. Together these refreshes executed 280 public
calls across ext4, btrfs, FAT16, FAT32, NTFS and ZFS.

The default harness benchmarks completed with 60 timing intervals. A later
frozen `08226b8cb` plus recorded overlays passed workspace/all-target checking,
strict Clippy and full formatting through RCH. Its full FAT/facade run passed
515 tests; all nine parent-repair tests passed again after equivalent test
iterator corrections. Exact source cuts and logs are in `FEATURE_PARITY.md`
and `.beads/pending_tasks.md`. The later FAT root-expansion feature is outside
those cuts. UBS still reports three test-only panic tripwires; their separate
review and publication remain open under `bd-native-image-library-s4tde`.
These bounded results do not constitute release acceptance.
Explicit native checks require their real producer tools:

```bash
cargo test -p ffs native_producer_interchange_reads_and_refuses_mutation_through_public_facade -- --ignored --nocapture
cargo test -p ffs-cli --test cli_e2e native_companion_read_profile -- --ignored --nocapture --test-threads=1
```

`OpenFs` itself still
dispatches ext4/btrfs, and their MVCC/RaptorQ integration must not be inferred to
apply automatically to new-format native writes.

The historical `97/97` parity figure describes rows in the original feature
table. It is not a six-format completeness percentage, a passing test count,
or a release-readiness score.

## FAT: create a file in an existing image

The offline writer can create a new file with a native short or long name,
including mixed case, spaces and non-ASCII characters. It reserves the complete
long-name/short-entry set, growing a cluster-backed parent when needed.

```sh
# Preflight only: no image mutation. The parent directory must already exist.
ffs-fat replace volume.img '/Release notes 🦀.txt' \
  --source payload.bin --create --offline-image --dry-run

# Explicit create-only publication. An existing name or alias is an error.
ffs-fat replace volume.img '/Release notes 🦀.txt' \
  --source payload.bin --create --offline-image

# Read back and check allocation through the native FAT reader.
ffs-fat cat volume.img '/Release notes 🦀.txt' > readback.bin
ffs-fat check volume.img

# Create an empty native directory under an existing parent.
ffs-fat mkdir volume.img '/Release Assets' --offline-image --dry-run
ffs-fat mkdir volume.img '/Release Assets' --offline-image
```

Without `--create`, `replace` retains its existing-file-only behavior. Source
files must remain immutable; the image must not be mounted or modified by
another program. Advisory locks do not enforce that against unrelated writers.
`--offset`, `--length` and `--oem-code-page` retain explicit volume/name selection.

Names must fit both 255 UTF-8 bytes and 255 UTF-16 units. Native forbidden
characters, trailing dots/spaces and DOS device names are refused. Long names
receive collision-checked ASCII short aliases; this conservative creation policy
is not a claim of Windows-version-exact Unicode collation or alias generation.
The native records preserve UTF-16 units, reverse ordinals, checksum binding,
terminators and padding. Existing files and aliases are not renamed.

Creation initializes disjoint payload allocation and preserves existing entries.
The successor directory terminator is synchronized before any old end marker
is consumed, including a marker inside a reusable run. Hidden slots become
durably harmless before long-name records are written, and the file's short
entry is published last. A parent can grow by up to two separately reserved,
zeroed and synchronized clusters to fit a complete maximum-length name. All new
FAT links are durable before the old tail points to them. Final native-reader
name/alias checks, SHA-256 readback and complete allocation checks precede clean
state publication. FAT32 inactive-copy and reserved-high-bit rules are retained.

This is **ordered offline mutation, not an atomic transaction**. Interruption
may leave a dirty image requiring native checking/recovery on another copy.
Explicit `mkdir` initializes one empty native directory under an existing parent,
including `.` and `..`, using the same parent-growth and publication protocol.
Offline unlink/rmdir/rename and experimental writable mounts are implemented.
Their mounted/native crash qualification remains open under `bd-uzt72`;
bounded offline recovery does not establish general native crash replay.
See the [creation and directory-growth contract](docs/FAT_CREATE_PROFILE.md).

### Evidence for this increment

Seventeen regressions have been authored for creation, directory growth and
long names: the nine earlier controls plus eight additions covering native name
records, Unicode and maximum-length readback, alias collisions, two-cluster
growth, contiguous-slot requirements, stale plans and publication ordering.
The fault cases retain separate pending/durable bytes and cover write/flush
failures, lost or retained pending data and torn prefixes. An interior-marker
control specifically requires durable hidden-slot initialization before the
old end marker is consumed.

**All 133 FAT Rust tests passed**, including the 17 creation/growth/name
regressions and three mkdir controls, in RCH job `j-30063538684821517`.
No tests failed, were ignored or were filtered out. Workspace/all-target check
and strict Clippy passed in `j-30063538684821519` and `j-30063538684821516`;
formatting also passed. The source is
base `eeef44fe3` plus overlay
`c58623d3232fa8c06bc8bdb3ca6de7d6da6b23952d887639b50a2e3280f36a81`.
The old FAT32 mkdir writer failed the unchanged checker's root-parent invariant
in `j-30063538684821514`; the fixed writer encodes `..` as cluster zero for root
children in both dialects. Nested children retain their actual parent cluster.
Earlier compiler-gate failures required equivalent verification-guard and
visibility fixes; no condition or case was removed. These are executed
native-image and storage-model unit controls. A separately built public
`ffs-fat` also passed root/nested mkdir, exact dot-entry readback, hash-preserving
dry-run/collision refusal and independent `fsck.fat -n` on fresh 64 MiB FAT16
and FAT32 images. Windows, writable-mount, crash-replay and hardware power-cut
qualification remain outstanding.

## NTFS: cross-check physical allocation

`ffs-ntfs check-allocation` scans each allocated MFT record once and reconciles
its nonresident mappings with the volume's `$Bitmap`. It reports cross-linked
claims with record/attribute witnesses, mapped-but-free clusters and allocated
space without an observed reference. Fragmented MFTs, extension records, sparse
holes, metadata streams and preallocation use the existing native parsers.

```sh
ffs-ntfs check-allocation volume.img --offline-image
ffs-ntfs check-allocation disk.img --offline-image \
  --offset 1048576 --length 67108864 --max-clusters 33554432
```

This is read-only accounting, not full `chkdsk`, journal validation or repair.
Incomplete record/mapping coverage suppresses unreferenced-allocation conclusions;
unexplained space is never declared reclaimable. Bitmap failures and cancellation
fail the operation. Discrepancies or limits print JSON and return nonzero.
The command refuses sidecars and recovery overlays before opening images.
The shared library exposes the same check without a serialization dependency.
Ten library and four CLI/report controls are authored but not executed in this
 environment; native interchange and the Rust gates remain unverified. See the
[NTFS allocation-check profile](docs/NTFS_ALLOCATION_CHECK.md) for exact scope,
resource limits and qualification requirements.

Add `--verify-record-ownership` to cross-check allocated MFT extensions against
validated base ATTRIBUTE_LIST catalogs. The separate metadata budget is set with
`--max-metadata-bytes`; free or stale catalog references fail, while incomplete
coverage leaves owner-absence conclusions unknown. This does not grant repair
or native write authority. Eight library and three CLI/report regressions are
authored but unexecuted here. See the [record ownership profile](docs/NTFS_RECORD_OWNERSHIP.md).

### Resolve a path through its native index branches

`read`, `readlink` and `ls` accept `--indexed-lookup` to locate a path without
opening every unrelated sibling's FILE record. The shared library exposes
`resolve_indexed` and `resolve_indexed_no_follow`. The existing strict resolver
remains the default; `ls` still validates all entries in the requested directory.

```sh
ffs-ntfs read volume.img /large-directory/report.bin --offline-image \
  --indexed-lookup --start 513 --bytes 1025
```

The search retains native UpCase matching, exact-spelling priority, ambiguity
rejection, child allocation/fixup checks and complete selected-target identity
validation. It examines every relevant equal-name branch before returning.
Every matching identity for a selected file reference must occur in that file's
catalog, including same-reference aliases in either index order.
`NtfsFs::new_indexed` also selects this behavior for inode-relative `FsOps::lookup`;
its `readdir` still validates and caches only complete directory enumerations.
Unvisited branches and sibling records are not certified: this is an explicit
lookup scope, not repair, whole-directory checking or a measured speedup.
The current remote run passed all 360 NTFS and 24 NTFS CLI tests, including the
nine constructed-image reader, seven FsOps and three CLI regressions. Current
native CLI checks also passed named/compressed reads and a separately produced
256-file index with 13 reachable nodes, 12 leaves and two child levels. These
functional results make no speed claim or indexed FsOps mount claim. See the
[indexed lookup profile](docs/NTFS_INDEXED_LOOKUP.md).

## ZFS: extract from surviving mirror disks

`--missing-mirror-member GUID` explicitly identifies every absent child of one
exported mirror. The surviving images must agree on the complete native
configuration and selected root; present and missing GUIDs must account for
all children exactly. The existing checked block pipeline serves committed
head and snapshot reads without inventing devices or weakening checksums.

```sh
# GUIDs and candidate numbers are placeholders, not automatic root selection.
ffs-zfs read survivor.img /important.bin --dataset data --offline-image \
  --pool-guid 123 --label 0 --slot 2 --missing-mirror-member 1002 > recovered.bin
```

This profile does not infer missing disks or choose the newest surviving TXG.
It refuses active pools, incomplete RAIDZ/striped topology, automatic import and
log recovery. It performs no backing writes or healing. One survivor remains a
mirror-owned view rather than being reinterpreted as a standalone leaf.
The ten new controls are authored, not runtime-qualified in this implementation
session. See the [missing-mirror extraction profile](docs/ZFS_MISSING_MIRROR_PROFILE.md)
for exact limits, examples, proof scope and required validation.

### RAIDZ1/2/3 with explicitly absent children

`--missing-raidz-member GUID` provides a separate committed-view extraction
profile for an exported ordinary RAIDZ group. It retains native stripe width,
child order, parity count and the full GUID sum, even when only one image
survives. Missing columns have no supplied handle. Existing reconstruction
accepts bytes only after the original checksum and transform validate; corrupt
parity and additional read failures share the native parity budget.

```sh
# Three-child RAIDZ1: two actual images plus one declared absent native GUID.
ffs-zfs read first.img /important.bin --member second.img --offline-image \
  --pool-guid 123 --label 0 --slot 2 --missing-raidz-member 1003 > recovered.bin
```

All absent GUIDs must be declared, and their count must fit native parity.
Automatic import, replay and mixed mirror/RAIDZ declarations are refused before
image opens; no pool healing or latest-state authority is implied. Thirteen
new native-image, CLI and head/snapshot controls are authored but not executed
in this implementation session. See the
[missing-RAIDZ extraction profile](docs/ZFS_MISSING_RAIDZ_PROFILE.md) for limits
and validation still required before relying on the feature.

### Multiple top-level mirrors and mixed leaf/mirror pools

Explicit candidate reads now retain complete replica groups for multiple
top-level mirrors, including mixtures with standalone file/disk vdevs. Supply
every physical image with `--member`; native labels, not image argument order,
define vdev IDs and mirror child order. The selected pool GUID, label and slot
must agree across the complete exported topology. Per-vdev capacities and sector
sizes are preserved, and usable capacity is counted once per top-level vdev.

```sh
ffs-zfs read first.img /important.bin --member second.img \
  --member third.img --member fourth.img --offline-image \
  --pool-guid 123 --label 0 --slot 2 --dataset data > recovered.bin
```

Ordinary blocks, gang headers/fragments, redundancy scrub and existing ZIL
storage planning share the retained replica routing. A different vdev is not
a fallback unless another declared DVA selects it. Missing children in these
multi-vdev pools, multiple RAIDZ groups and native write/import
authority remain outside this increment. Ten new Rust tests are authored but
unexecuted here; see the [striped-mirror profile](docs/ZFS_STRIPED_MIRRORS.md).

Complete mirror/leaf stripes also support `--auto-import`. Selection checks all
surviving valid configurations, scans independently located rings using each
member's sector geometry, and retains the complete replica routing for root,
dataset and redundancy-scrub reads. Bad-checksum labels may be bypassed; valid
configuration conflicts, missing children and equal-TXG root forks may not.
Explicit candidate selection remains strict. The inherited highest-readable-TXG
policy can return an older committed view when newer roots are unreadable; it
does not establish newest-state or writable-pool authority.

```sh
ffs-zfs read first.img /important.bin --member second.img \
  --member third.img --member fourth.img --offline-image \
  --auto-import --pool-guid 123 --dataset data > recovered.bin
```

Eight additional Rust controls and a revised explicit/automatic equivalence
control are authored but unexecuted in this implementation environment. See
the profile above for the retained limits and required validation.

### Check redundancy, not only readability

`ffs-zfs scrub --verify-redundancy` rereads physical copies in the selected
dataset's DMU graph, including bounded gang-header and fragment trees, and checks
RAIDZ P/Q/R parity against the actual checksum-valid data columns. A good
alternate copy or successful reconstruction
no longer conceals a damaged replica or parity sector in this explicit mode.
Normal `scrub` retains its existing readability-only contract.

```sh
ffs-zfs scrub first.img --member second.img --offline-image \
  --pool-guid 123 --label 0 --slot 2 --dataset data --snapshot before \
  --verify-redundancy --max-copy-bytes 1073741824
```

The independent work budget is reserved before extra audit I/O. Missing members,
unverified parity, divergent gang headers and exhausted limits cannot
produce a clean redundancy result. No writes, healing, resilvering or pool-wide
coverage are implied; enclosing object-set roots, labels and other datasets stay
outside this walk. The eleven earlier audit controls plus seven new gang-tree
controls are authored but not executed in this environment. Gang audit charges
include a conservative whole-tree allowance before manifest I/O; an incomplete
graph or saturated diagnostic ledger never becomes a clean audit. See the
[physical-copy audit profile](docs/ZFS_REDUNDANCY_SCRUB.md)
for precise coverage, counters and qualification requirements.

## Build and explore

Use the checked-in Rust toolchain and the platform/dependency instructions in the
[detailed guide](README_EXT4_BTRFS.md) and [AGENTS.md](AGENTS.md).

```sh
cargo build -p ffs-cli --bins

# Existing ext4/btrfs entry point.
cargo run -p ffs-cli -- inspect /path/to/fs.img --json

# Native FAT image tools; reads do not require a FUSE mount.
cargo run -p ffs-cli --bin ffs-fat -- inspect /path/to/fat.img
cargo run -p ffs-cli --bin ffs-fat -- ls /path/to/fat.img /

# Discover exact companion arguments before selecting a volume or ZFS pool.
cargo run -p ffs-cli --bin ffs-ntfs -- --help
cargo run -p ffs-cli --bin ffs-zfs -- --help
```

Read-only mount and native-image examples, supported feature masks, ownership
projection and rejection rules are in the corresponding profiles:

| Profile | Documentation |
|---|---|
| FAT reads, names, mounts, checking and fresh-image creation | [FAT profile](docs/FAT_READ_PROFILE.md) |
| Existing-image FAT creation and directory growth | [Create-only profile](docs/FAT_CREATE_PROFILE.md) |
| NTFS native reads and read-only mounts | [NTFS profile](docs/NTFS_READ_PROFILE.md) |
| Opt-in NTFS index-directed path lookup | [Indexed lookup profile](docs/NTFS_INDEXED_LOOKUP.md) |
| NTFS MFT physical mappings versus native allocation bitmaps | [Allocation-check profile](docs/NTFS_ALLOCATION_CHECK.md) |
| ZFS datasets, snapshots, topology and read-only mounts | [ZFS profile](docs/ZFS_READ_PROFILE.md) |
| ZFS committed-view extraction from explicitly incomplete mirrors | [Missing-mirror profile](docs/ZFS_MISSING_MIRROR_PROFILE.md) |
| ZFS committed-view extraction with missing RAIDZ1/2/3 children | [Missing-RAIDZ profile](docs/ZFS_MISSING_RAIDZ_PROFILE.md) |
| ZFS physical-copy and RAIDZ parity audit of selected DMU graphs | [Redundancy scrub profile](docs/ZFS_REDUNDANCY_SCRUB.md) |
| ZFS complete multi-vdev mirror/leaf extraction | [Striped-mirror profile](docs/ZFS_STRIPED_MIRRORS.md) |
| ext4/btrfs architecture, operation and evidence | [Detailed guide](README_EXT4_BTRFS.md), [current parity ledger](FEATURE_PARITY.md) |

## Architecture and remaining priorities

Native parsing belongs in `ffs-ondisk`; image and block I/O, transaction control,
filesystem operations, FUSE adaptation, repair and evidence have distinct
boundaries. The project uses `asupersync::Cx` for explicit budget/cancellation
propagation. Full context propagation and worker scoping remain work, not a
blanket property of every existing path.

The multi-format plan deliberately separates native compatibility from
FrankenFS-specific improvements. The remaining high-impact work includes FAT
directory creation, broader namespace operations and native naming/interchange
qualification; NTFS native recovery plus allocator/MFT/index mutation; ZFS
native allocation/TXG/ZIL and pool lifecycle; shared backend integration; and
executable native-interchange, crash/reopen and mounted-operation evidence for
each admitted profile.

The [comprehensive plan](COMPREHENSIVE_PLAN_FOR_NTFS_FAT16_FAT32_AND_ZFS.md),
[implementation workpackages](docs/NTFS_FAT_ZFS_IMPLEMENTATION_WORKPACKAGES.md),
and `.beads/` track these separately. Implemented symbols, authored tests,
executed tests and native interoperability are different evidence levels.

For contributors, use the repository's prescribed remote execution workflow
when available. The focused FAT checks are:

```sh
rch exec -- cargo test -p ffs-fat
rch exec -- cargo test -p ffs --lib native::tests
rch exec -- cargo check -p ffs-cli --bin ffs-fat
rch exec -- cargo clippy -p ffs-cli --bin ffs-fat --all-targets -- -D warnings
cargo fmt --check
```

Passing those is necessary, not sufficient for filesystem readiness. Existing
native-format compatibility, fault-injection, mounted and release gates remain
in force; none are waived by adding a format or a new command.

### Source inventory

The current source-derived test inventory contains 24 crates under `crates/`,
63 fuzz targets, 173 Rust benchmark files, 125 tracked E2E scripts and
226 tracked insta snapshots. The evidence schema declares 23 evidence-event types.
These are source counts, not executed-test or readiness results.
The [fuzz inventory](fuzz/fuzz_targets/) has the badge count
![63 fuzz targets](https://img.shields.io/badge/fuzz%20targets-63-brightgreen).
The detailed guide retains [Decision 10: 125 E2E gate scripts](README_EXT4_BTRFS.md#decision-10-125-e2e-gate-scripts).

The btrfs reader declares 23 command variants for send streams and item-type
constants (24 currently). MVCC exposes 4 executable same-block merge mechanisms
through the 5-outcome `MergeProofMechanism` enum; the remaining outcome refuses
same-block merging. Enum and file counts do not qualify native interchange,
durability or mounted behavior.

## License

See [LICENSE](LICENSE) for the project's MIT + OpenAI/Anthropic Rider terms.
