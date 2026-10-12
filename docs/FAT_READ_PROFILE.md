# Experimental FAT16/FAT32 read and new-image creation profile

`ffs-fat` is a native Rust companion binary in `ffs-cli`. It uses the shared
`ffs-ondisk::fat` parser and the existing `ffs-core::FsOps` / `ffs-fuse` adapter.
It implements reads and creation of new empty images without invoking another
filesystem driver or formatter. The ordinary
ext4/btrfs `ffs-cli` dispatch and `FsFlavor` are unchanged; this is not yet
integration into the generic `ffs mount` or `OpenFs` auto-detection path.

## Commands

Build `ffs-fat` with the repository's prescribed Cargo/RCH workflow:

```sh
rch exec -- cargo build -p ffs-cli --bin ffs-fat

# These paths must not already exist; format creates an empty volume image.
target/debug/ffs-fat format new-fat16.img --kind fat16 --size-mib 4 --label DATA
target/debug/ffs-fat format new-fat32.img --kind fat32 --size-mib 64 --serial 305441741
target/debug/ffs-fat format selected-clusters.img --kind fat32 --size-mib 128 --sectors-per-cluster 2 --serial 0x1234ABCD

target/debug/ffs-fat inspect volume.img
target/debug/ffs-fat check volume.img
target/debug/ffs-fat ls volume.img /nested
target/debug/ffs-fat cat volume.img '/Long native filename.txt' > extracted.bin

# Lossless native catalog; copy entry_slots from the returned JSON.
target/debug/ffs-fat catalog volume.img
# These offsets are examples; use the selector belonging to your immutable image.
target/debug/ffs-fat catalog volume.img --entry-slots 20992
target/debug/ffs-fat extract volume.img --entry-slots 20992,22592 > extracted.bin

# The directory must already exist and be empty. No other program may write
# the backing image for the lifetime of this mount.
target/debug/ffs-fat mount volume.img /mnt/fat --offline-image --uid 1000 --gid 1000
fusermount3 -u /mnt/fat

# Explicit byte-bounded volume inside a larger image, without partition discovery.
target/debug/ffs-fat cat disk.img --offset 1048576 --length 67108864 /FILE.BIN
target/debug/ffs-fat check disk.img --offset 1048576 --length 67108864
```

Commands that open existing images use read-only handles. The separate `format`
command exclusively creates a new file; it cannot overwrite or format an existing
image or device. Mutation, repair, recovery, resizing and protection initialization
of existing volumes remain separate work. Shared advisory locks do not exclude
kernel mounts or unrelated writers; image immutability is a caller requirement.
`cat` and `extract` validate allocation before output, but a later storage failure
may still leave a previously streamed prefix on stdout and exits unsuccessfully.

## New-image formatter

`ffs-fat format NEW_IMAGE --kind fat16|fat32 --size-mib N` creates a new empty
volume image at byte zero. Both dialect and exact logical size are required.
The output is a volume image, without a partition table or operating-system
bootloader. No overwrite, device-format, partition-offset or resize option is
provided.

Geometry uses 512-byte sectors, two mirrored FATs and a power-of-two cluster
size from 1..128 sectors (up to 64 KiB). The formatter chooses the smallest
cluster size satisfying the selected dialect and resource bounds, then finds
the smallest FAT that can represent every data cluster. Optional
`--sectors-per-cluster` selects an exact cluster size; an invalid power of two,
wrong count-derived dialect, or exceeded resource bound is refused before
creating the output. This preserves the original automatic geometry choices.

| Native field | FAT16 | FAT32 |
|---|---|---|
| Data-cluster range | 4,087..65,518 | 65,525..8,388,608 |
| Reserved sectors | 1 | 32 |
| Root directory | Fixed 512-entry region | Allocated cluster 2, terminated by EOC |
| Primary / backup boot record | Sector 0 / absent | Sectors 0..2 / 6..8 |
| FSInfo | Absent | Sector 1 and initial copy at sector 7 |
| FAT copies | Two matching complete copies | Two matching complete copies |
| Explicit 512-byte metadata writes | 4 | 9 |

The FAT16 range avoids ambiguous FAT12 thresholds and reserved cluster
identifiers. FAT32 stays within the allocation checker's 8,388,608-cluster
budget, so every successfully created image can receive complete allocation
verification. The complete BPB and last data-cluster address are independently
admitted by the ordinary native geometry parser before any output file is
opened. The admitted range retains the original formatter's compatibility
choices: it does not impose Microsoft's suggested 16-cluster separation from
dialect cutovers, and its optional 64 KiB clusters exceed the specification's
32 KiB application-compatibility recommendation. Native interchange evidence
applies to the exercised geometries, not automatically to every admitted size.

An optional `--label` accepts 1..11 legal printable ASCII FAT label bytes,
without leading or trailing space, uppercases them, and writes the same padded
name to the native boot label and root volume-label entry. With no label, the
boot field contains the native `NO NAME` default and the entire root is empty.
`--serial` accepts a 32-bit volume identifier in decimal or `0x`/`0X` hex;
the default is derived from the system clock and is not a uniqueness guarantee.
Supplying a serial makes the constructed image deterministic. Native label-entry
creation/access/modification dates use 1980-01-01; ordinary root slots remain zero.

All options and the completed BPB are checked before an atomic `create_new`
open with mode 0600, subject to the caller's umask. Existing regular files,
empty files, hardlinks, symlinks (including dangling links), directories and
device paths are refused. The destination parent's identity and pathname
resolution must remain stable until completion: the directory handle used for
its final sync is opened separately from exclusive file creation. The new file
is exclusively advisory-locked and extended from zero length, supplying logical
zeros for both complete allocation tables and their padding, reserved regions,
root slack and free space. Physical storage may be sparse; the command does
not reserve the image's entire logical size for future writes. Existing image
bytes are never read or copied during initialization.

Preparation writes clean native FAT headers, root metadata, both FAT32 FSInfo
sectors and the signed FAT32 boot-extension sectors 2 and 8, then synchronizes
the file. The initial FSInfo free count is exact and the next-free search hint
is cluster 3. Both primary and backup BPBs remain unpublished throughout this
stage. Cancellation from the request context or Ctrl+C is honored before
creation and at preparation boundaries, including immediately after that sync.

After the final preparation checkpoint, publication writes the FAT32 backup
BPB, then the primary BPB, synchronizes the file, and synchronizes the parent
directory entry. This sequence has at most two sector writes and two syncs,
with no cancellation checkpoint between them. A pending signal is delivered
to the actual shared request context, so it can still stop the subsequent
verification, including the checker's cached-allocation loops.

Verification reads back every explicitly written metadata sector, including
all six FAT32 boot-record sectors, and runs the existing allocation checker
through a read-only adapter over a clone of the same locked handle. It neither
reopens the target pathname nor reacquires its lock. Success requires complete
coverage, an empty namespace, expected free/allocated counts, agreeing FAT
copies and no allocation findings. Full readback is mandatory; the bounded
initialization phase is followed by verification that scales with the admitted
allocation count.

The JSON result preserves `operation: create_new_image`,
`created_new_image: true`, native geometry/label/serial fields and the embedded
read-only `verification` report. It adds `durability: file_and_parent_synced`.
No successful result is emitted before final synchronization and verification.

An error always retains any newly created destination, with its original cause
and the completed phase:

- Before boot publication, neither BPB has been published and the image is incomplete.
- A backup/primary write or final file-sync error states that publication started
  and file durability is uncertain; a partial prefix or valid boot copy may exist.
- A parent-sync error states that the image was initialized and file-synchronized,
  with uncertain directory-entry durability.
- An error or cancellation during readback states that the image was already
  initialized and file-and-parent synchronized, but verification did not complete.
- A stdout/reporting error states that initialization, synchronization and
  verification already succeeded.

The file is not silently removed or reused on a subsequent attempt. The lock
remains advisory; unrelated writers and kernel mounts are outside the contract.
This adds empty-image creation. Writable mounts, mutation/recovery of existing
FAT filesystems, partition formatting and MVCC/RaptorQ integration remain separate
native write-path work.

### Native format references

The layout was reviewed against Microsoft's *FAT Specification 1.03*
(`fatgen103.doc`), retrieved from the official
[WHDC Legacy Documents archive](https://www.microsoft.com/en-us/download/details.aspx?id=53426):
[original document](https://download.microsoft.com/download/1/6/1/161ba512-40e2-4cc9-843a-923143f3456c/fatgen103.doc).
The retrieved document is 222,720 bytes with SHA-256
`b17d66c796d9cd3070adf4ccbc00add5a8b6b6f5491fe8ea949df778fce60172`.
Its BPB tables, FAT type determination, reserved entries, root initialization,
FSInfo and three-sector backup description informed the encoder and independent
byte fixtures. The original document is not redistributed in the repository.
The existing native implementation reference is retained:
[dosfstools 4.2 formatter](https://github.com/dosfstools/dosfstools/blob/v4.2/src/mkfs.fat.c).

The host-file guarantees are documented in Rust's
[`OpenOptions::create_new`](https://doc.rust-lang.org/std/fs/struct.OpenOptions.html#method.create_new)
and [`File::set_len`](https://doc.rust-lang.org/std/fs/struct.File.html#method.set_len).
The host filesystem's file and directory sync semantics define durability;
process termination or power loss before completion may leave a retained partial
image. Native oracle tools validate interchange; the formatter never invokes them.

## Implemented read boundaries

FAT type comes from cluster count. Geometry, backing ranges, FAT capacity,
FAT16 fixed roots, FAT32 root chains, active FAT selection, clean-state headers,
and backup boot geometry are checked before use. Mirrored allocation entries
must agree. Reads handle fragmented chains, nested directories, allocated slack,
LFNs spanning sectors/clusters, ASCII short aliases, and exact EOF limits.
Free-space accounting scans admitted FAT copies instead of trusting FSInfo hints.

The FUSE adapter supplies inode lookup/attributes, directory cookies and parent
lookup, reads, read-only open admission, sync no-ops, statfs, and SEEK_DATA/HOLE.
File allocation accounting includes preallocation but read output excludes it.
Root and directory allocation chains are validated before both listing and
attribute reporting, including allocated tails beyond the first end-of-directory
marker. An unused tail is never decoded as additional names, but its links must
still be bounded, acyclic, valid and consistent across admitted FAT copies.
Mount-lifetime slot-based identities must not be reused as a writable-FAT or
NFS-export design. Registry and allocation-map caches have explicit limits.

The current profile accepts 512..4096-byte sectors, clusters up to 64 KiB,
and one or two FAT copies. Directory traversal is capped at 65,536 slots;
individual file allocation maps at 8,388,608 clusters; individual reads at
16 MiB. Mounted lookup registrations are capped at 131,072 nodes, retained
chain caches at 1,024 files and 32 MiB of cluster addresses. These are admission
and resource limits, not assertions of full FAT parity.

Path commands and mounts use lossless UTF-8 LFNs and ASCII short names;
non-ASCII OEM-only names, unpaired UTF-16 surrogates and names exceeding the
host's 255-byte limit have no admitted path spelling. The native catalog and
entry-slot extraction below can access those names without conversion.
Comparisons fold ASCII only, not Windows Unicode collation. Permissions/ownership
are explicit read-only Unix projections.
Native timestamps use a deterministic UTC projection of FAT wall-clock fields;
the format records no timezone, so this projection does not recover the original
instant. Creation preserves its native 10 ms precision (including odd seconds),
access preserves its native date precision, and modification preserves its native
two-second precision. Unavailable fields and the nonexistent native metadata-change
time remain epoch zero. Present dates/times must pass calendar and field bounds;
invalid fields report corruption at their directory record. Dirty volumes and
conflicting boot copies require offline native investigation; this reader never
repairs them automatically.

FAT12, exFAT, mutation/recovery of existing FAT images, full OEM/Unicode naming parity, integrated
MVCC/RaptorQ protection, and NTFS/ZFS implementation remain separate work.

## Lossless native catalog and extraction

`catalog` lists the root by default. Each live ordinary entry includes its raw
11-byte short name, optional assembled UTF-16 LFN, optional lossless display name
and display error, attributes, file size, first cluster, and an exact `entry_slots`
selector. Non-ASCII OEM bytes are retained without assuming a code page; the
native 0x05 short-name escape is retained. Unpaired UTF-16 units and names whose
UTF-8 representation exceeds the host limit remain accessible through selectors.

A selector is a comma-separated root-to-entry chain of decimal short-entry byte
offsets. Offsets are relative to the selected FAT volume, including when `--offset`
and `--length` select a volume inside a larger image. They are valid only for that
same immutable image; changing the image can change the identity at a slot.
`catalog --entry-slots ...` lists a selected directory, and
`extract --entry-slots ...` streams a selected regular file through the existing
allocation, EOF, read-size and cancellation checks.

Every selector component must occur in the complete parsed directory selected
by its preceding components. Arbitrary image offsets, deleted/LFN/volume-label
slots, native dot entries, records after the directory-end marker, non-directory
intermediates and ancestor cycles cannot select file contents. Native units are
checked for invalid path separators before any display conversion, so an unpaired
surrogate cannot hide another malformed name component. Existing structural
parser failures remain fatal; the normal reader's short-alias fallback for an
invalid LFN sequence remains unchanged. The checker continues to report those
LFN defects separately.

Selectors admit at most 256 components, each a 32-byte-aligned u64 offset, with a
5,375-byte input bound. Existing directory and allocation-map budgets still apply.
A requested slot does not stop validation early: damaged later entries or allocated
directory tails fail before file output. Cataloging does not certify file payloads
or perform the full allocation/namespace check described below.

## Read-only allocation check

`ffs-fat check` walks the admitted directory tree and every addressable allocation
entry, returning a JSON report. It identifies cross-linked file/directory chains,
live chain cycles, short file chains, allocated clusters unreachable from the
tree, contradictory native short names and ASCII aliases, invalid native
dot/parent links, nonzero directory sizes, misplaced dot entries, malformed or
orphaned LFN sets, reserved allocation values and invalid successors. FAT32
FSInfo signatures and known free-count/search hints are checked against the
admitted FAT geometry and scan. FSInfo remains advisory; no hint or allocation
is repaired. The normal reader may still use a short alias after malformed LFN
records; the checker retains that damage as an issue. Ownership traversal keeps
raw native names even when the reader's UTF-8/OEM display projection is unavailable.

The flat report retains `format`, `read_only`, `scope`, `clean`,
`namespace_complete`, `issues` (each with `kind`), `omitted_issues`, allocation
counts, file/directory counts, and `fs_info_free_hint`. It also reports explicit
`status`/`complete`, volume bounds, data-cluster coverage, and reserved,
conflicting and uniquely referenced cluster counts. Every cross-link retains
both volume-relative owner offsets when both are ordinary entries; a null
offset denotes the native root. No owner is selected as the rightful owner.

Reachable file preallocation, including an allocated empty file, is counted in
`preallocated_clusters` and never exposed as file contents or classified as
lost. Native bad-cluster markers are counted separately and become a live-chain
error only when a file or directory references them. Unknown FSInfo hints are
accepted. Its next-cluster value is a search hint that may already be allocated;
only its range is checked.

The `status` is `clean`, `issues_found`, or `incomplete`; only `clean` exits
successfully. Structural failures produce specific issues rather than a clean
report. Mirrored disagreement never selects a preferred FAT. If a directory
cannot be fully examined, required allocation evidence is ambiguous, or a
traversal budget is exhausted, `complete` and `namespace_complete` are false
and `lost_clusters` is null. Unvisited allocation is then not asserted to be
orphaned. Cancellation, physical I/O failure, allocation failure and unsupported
volume geometry return an error. The checker retains normal clean-volume
admission: it does not bypass dirty-state refusal, replay a journal, or accept
a concurrently writable image.

Checks are bounded to 8,388,608 data clusters and total visited chain entries
(including shared suffixes), 131,072 namespace objects, 256 directory levels,
128 MiB of total directory allocation and 1,024 retained issues. The existing
per-directory allocation limit also applies. Further issues are counted in
`omitted_issues` without turning truncation into a clean result. Two bounded
`u32` arrays retain FAT evidence and ownership, and shared chains also receive
cycle detection. These checks do not verify file-content integrity, full
OEM/Unicode collation, all native naming rules or complete `fsck.fat` behavior,
and do not provide a repair plan.

## Executable checks and evidence limits

```sh
rch exec -- cargo test -p ffs-ondisk fat
rch exec -- cargo test -p ffs-cli --bin ffs-fat

# Requires dosfstools and mtools; --mounted additionally requires usable FUSE.
python3 scripts/verify_fat_read.py --binary target/debug/ffs-fat
python3 scripts/verify_fat_read.py --binary target/debug/ffs-fat --mounted
```

The external runner exercises images created by both `mkfs.fat` and
`ffs-fat format`. It independently scans native BPB/FAT bytes, verifies fresh
FAT32 three-sector boot copies, seeds and reads files with mtools, and checks the
candidate's complete allocation report against known namespace/free counts.
It compares binary and optional mounted reads, requires EROFS for mounted
write-open, checks unchanged image hashes, and runs `fsck.fat -n`. Formatter
scenarios also require exact refusal statuses and unchanged bytes when trying
to format an existing path, and no destination for rejected partition options.
All images and command logs are retained; missing prerequisites fail the run.
The added Rust unit tests cover independent byte layouts, error/cancellation
propagation, malformed chains, partition bounds, LFN boundaries, FsOps and dates.
Additional checker regressions retain raw malformed/orphaned LFN records,
duplicate empty-file names, misplaced dot entries, incomplete namespace and FAT
coverage, both clusters of a shared suffix, and cycles inside shared suffixes.

**Initial delivery evidence:** Python syntax compilation and runner help were
executed in the authoring environment. Rust compilation/tests, native-image
execution, mounted verification and rustfmt/Clippy were not executed there:
Cargo, rustc and RCH were unavailable, and the connector-created commits had no
reported Actions runs at the time checked. The presence of these tests and this
runner is not a passing conformance or mounted-support certification.

**Directory-tail regression coverage:** the reader tests include both dialects,
FAT32 roots, invalid/free/bad/reserved/cyclic tail links, mirror disagreement,
allocation limits and cancellation after an early directory end marker. A positive
control rejects any physical read of unused tail data while preserving the visible
listing. These added tests have not been executed in this editing session: the
shared executor disconnected before compilation, and offline Cargo resolution
also lacked required dependencies. Source review is not native or mounted proof.

**Allocation-check regression coverage:** nine reader tests plus CLI argument
coverage exercise both dialects, clean counts without payload reads, preallocation,
bad/lost/shared clusters, directory aliases and ancestor cycles, parent/name/size
inconsistencies, FSInfo hints, cancelled/mismatched FAT scans, bounded issue output
and unchanged image/adjacent-volume bytes. These are authored, source-reviewed
tests, not executed evidence: the editing executor is offline, and the most recent
available Actions execution stopped at its action-owner policy before checkout.
Rust compilation, formatting, Clippy and native-image validation remain required.

**Native timestamp increment (2026-10-11):** the parser retains creation date,
time and 10 ms increments, access date, and modification date/time. Constructed
parser and FsOps regressions cover FAT16 and FAT32, leap years including the
2100 exception, the 1980/2107 endpoints, fractions and odd seconds, absent dates,
and invalid-field error locations. The calendar constants were independently
checked with JavaScript date conversion, and the source received a second review.
Rust tests, formatting, workspace checks, Clippy and UBS remain unexecuted because
the authoring executor is offline. No new native-image or mounted result is claimed.

**Native name access increment (2026-10-11):** three parser/CLI tests and seven
constructed image regressions cover FAT16 and FAT32, OEM bytes and the native
0x05 escape, unpaired surrogates, host-overlong UTF-8, nested selectors, nonmember
and deleted entries, label/LFN/dot/end-marker slack, ancestor links, raw separator
corruption, damaged allocation and directory tails, cancellation, and unchanged
images including adjacent volume bytes. Existing test assertions are preserved.
Independent source/fixture review and exact GitHub blob comparisons completed;
Rust compilation/tests, formatting, Clippy, UBS and native-image execution remain
unavailable while the executor is offline. These tests are not executed native
or mounted parity evidence.

**Native formatter increment (2026-10-11):** eleven new regressions cover CLI
requirements; independent geometry and FAT-capacity boundaries; new FAT16/FAT32
images with complete mirrors, roots and FSInfo backups; labels and serials;
no-overwrite behavior for existing files, directories, symlinks and devices;
invalid and pre-cancelled requests without output creation; every initialization
I/O failure and mid-I/O cancellation position; partial-write retention; boot-last
flush ordering; readback damage and unexpected allocation beyond the explicitly
written header; and bounded read-only verification.

Complete production, CLI and fixture blobs received independent review and
exact readback comparison. Independent arithmetic compared minimum FAT sizing
with a separate closed form across the integer-MiB size range and checked all
boundary fixtures. These are source and arithmetic checks, not execution of
the formatter. At that initial delivery, Rust compilation, the eleven
regressions, formatting, workspace checks, Clippy, UBS, native
`fsck.fat`/mtools validation and mounted interchange were unexecuted because its
authoring executor was offline. The runner then used only `mkfs.fat` inputs,
so that earlier runner did not qualify the native formatter.

**Formatter integration coverage (2026-10-11):** all eleven original formatter
test functions and their independent default-geometry, optional-label, timestamp,
readback and allocation assertions are preserved. Their fault and cancellation
loops now include every FAT32 backup write, primary write, final image sync and
parent sync, retained partial prefixes, withheld BPBs before publication, and
pending cancellation that stops later verification after durable initialization.
Eight additional native-layout tests cover raw BPB constants, root dates,
FSInfo/complete boot copies, finite independent FAT-capacity calculations,
cluster selection and label/serial bounds. Six additional creation tests cover
raw complete-FAT/free-space scans, existing hardlinks/inode preservation, explicit
cluster and hex-serial CLI admission, production request-context cancellation,
tampering in either boot-extension sector, and verification of the original
locked inode after a leaf-path replacement.

The combined formatter received independent source review. The updated native
oracle passed Python syntax compilation; it now includes formatter-created
images, native fsck/mtools interchange and retained command evidence. These
source-level checks do not establish execution of the combined Rust suite,
native interchange or mounted validation. Runtime results must identify the
candidate revision and the actual commands/tools exercised.

Final integration evidence (2026-10-11): the five changed Rust files passed
rustfmt parsing and formatting checks, and the delivered Python oracle passed
syntax compilation. Independent review covered the merged production code and
all 25 formatter tests. Earlier CLI checks/tests in this session, including a
one-compiler-thread attempt, received SIGKILL during `asupersync` compilation
under the shared memory limit. This merged formatter has no compiled or executed
result from those attempts. The installed UBS
launcher was not executable. Native dosfstools/mtools and mounted runs have not
executed. The separate 838-test on-disk parser run and on-disk Clippy pass do not
validate this CLI formatter or count as native interchange evidence.
