# Experimental FAT16/FAT32 read and new-image creation profile

`ffs-fat` is a native Rust companion binary in `ffs-cli`. It uses the shared
`ffs-ondisk::fat` parser and the existing `ffs-core::FsOps` / `ffs-fuse` adapter.
It implements reads and creation of new images, including native population
from a source directory, without invoking another filesystem driver or formatter.
The ordinary
ext4/btrfs `ffs-cli` dispatch and `FsFlavor` are unchanged; this is not yet
integration into the generic `ffs mount` or `OpenFs` auto-detection path.

## Commands

Build `ffs-fat` with the repository's prescribed Cargo/RCH workflow:

```sh
rch exec -- cargo build -p ffs-cli --bin ffs-fat

# These paths must not already exist; format creates a fresh volume image.
target/debug/ffs-fat format new-fat16.img --kind fat16 --size-mib 4 --label DATA
target/debug/ffs-fat format new-fat32.img --kind fat32 --size-mib 64 --serial 305441741
target/debug/ffs-fat format selected-clusters.img --kind fat32 --size-mib 128 --sectors-per-cluster 2 --serial 0x1234ABCD
# Source files and directories must remain immutable until this finishes.
target/debug/ffs-fat format populated-fat16.img --kind fat16 --size-mib 64 --source-dir ./release-tree
target/debug/ffs-fat format populated-fat32.img --kind fat32 --size-mib 128 --source-dir ./release-tree --label RELEASE --serial 0x1234ABCD

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

`ffs-fat format NEW_IMAGE --kind fat16|fat32 --size-mib N` creates a new
volume image at byte zero. Without `--source-dir`, it retains the original empty
image behavior. With that option, it copies an admitted source tree into real
native FAT files and directories before publishing either boot sector. Both
dialect and exact logical size are required.
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
| Root directory | Fixed 512-entry region | Chain starting at cluster 2, extended for populated entries |
| Primary / backup boot record | Sector 0 / absent | Sectors 0..2 / 6..8 |
| FSInfo | Absent | Sector 1 and initial copy at sector 7 |
| FAT copies | Two matching complete copies | Two matching complete copies |
| Empty-image explicit 512-byte metadata writes | 4 | 9 |

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
boot field contains the native `NO NAME` default and no root volume-label slot
is consumed. The root is otherwise empty unless a source tree is supplied.
`--serial` accepts a 32-bit volume identifier in decimal or `0x`/`0X` hex;
the default is derived from the system clock and is not a uniqueness guarantee.
Supplying a serial makes the constructed image deterministic for the same admitted
source tree and options. Native creation/access/modification dates use 1980-01-01;
unused slots and allocation slack remain zero. Source permissions, timestamps,
extended attributes and ownership are not imported.

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

Preparation writes any source payloads, the complete planned allocation links in
both FATs, native directories, both FAT32 FSInfo sectors and the signed FAT32
boot-extension sectors 2 and 8, then synchronizes the file. The initial FSInfo
free count is exact. Its next-free search hint is the first unused cluster,
cluster 3 for an empty image, or the native unknown value when allocation is full.
Both primary and backup BPBs remain unpublished throughout this
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
coverage, the exact planned file/directory and free/allocated counts, agreeing
FAT copies and no allocation findings. Populated images additionally enumerate
every native directory and read every file through `FatVolume`, checking exact
names/aliases, sizes, chains and SHA-256 payload digests. Full readback is mandatory;
verification scales with the admitted allocation count and total copied payload.

The JSON result preserves `operation: create_new_image`,
`created_new_image: true`, native geometry/label/serial fields and the embedded
read-only `verification` report. It adds `durability: file_and_parent_synced`,
`source_directory`, `copied_files`, `copied_directories` (including the root),
`copied_bytes` and `payload_verification`. For a source tree the last field is
`sha256_via_native_reader`; it is null without a source, as is `source_directory`.
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
This implements fresh empty and populated image creation. Writable mounts,
mutation/recovery of existing FAT filesystems, partition formatting and
MVCC/RaptorQ integration remain separate native write-path work.

### Populating a fresh image from a source directory

The source option is a bounded native creation operation: the existing geometry
planner allocates real FAT chains, writes ordinary file contents and encodes
native directory records. It does not store a tar archive, private object map,
host-path reference or sidecar inside the image. A completed populated image is
read through the same native FAT parser and allocation checker as an image
created by another FAT implementation.

Preflight completes before opening the output path. It enumerates and sorts the
source tree, reserves every sibling name and alias, computes all native directory
slots, allocates every chain, and hashes each source file. A FAT16 root can hold
exactly 512 slots, including a requested volume label and all LFN slots; an exact
full root is legal without an extra end marker. A name that needs an LFN occupies
its short entry plus up to 20 preceding long entries. FAT32 roots and ordinary
directories grow to complete cluster chains. Space and file-size failures return
the original ENOSPC or file-too-large cause while leaving no destination.

The first creation profile has the following explicit bounds:

| Source property | Admitted profile |
|---|---|
| Tree objects | At most 4,096, including the root |
| Retained regular-file handles | At most 1,024 |
| Relative depth | At most 64 components below the root |
| Individual component | Lossless UTF-8, at most 255 bytes and 255 UTF-16 units |
| Ordinary directory | At most 65,536 native 32-byte slots |
| File length | At most 4,294,967,295 bytes and enough image clusters |
| Payload copying/hash I/O | At most 64 KiB per checkpoint interval |
| Host entry types | Regular files and directories; no symlinks or special files |
| Destination | A new regular file outside the canonical source directory |

The caller must keep the entire source tree, its intermediate path components,
and the destination parent namespace stable until creation finishes. Source
regular files are opened read-only with final-component no-follow and nonblocking
flags, verified with their opened metadata, shared-advisory-locked and retained
through copying and native readback. Preflight and publication preparation
compare device/inode identity, size, nanosecond modification/change timestamps
and complete directory memberships. Access times are excluded because reads
can update them. This detects ordinary concurrent edits and path replacement;
it is not a host snapshot or protection against an adversarial writer bypassing
advisory locks or changing intermediate path resolutions.

SHA-256 is calculated from each retained source handle during preflight, again
while copying that handle into its reserved native chain, and finally from file
bytes returned by the native FAT reader on the locked output handle. A different
copy digest or source metadata/membership check aborts before either BPB.
Source hardlinks are copied as separate ordinary FAT files with separate chains.
Empty files have zero length and cluster zero. No source object is written,
renamed, removed or truncated.

Name creation preserves the exact accepted Unicode text without normalization.
It rejects invalid/control characters, the native U+FFFF LFN padding sentinel,
final spaces/periods, reserved DOS device names (including the documented
superscript COM/LPT variants), and non-UTF-8 host names. Sibling collisions use a conservative Unicode uppercase-then-lowercase
key; this deliberately refuses case-equivalent names such as README/readme or
É/é without claiming a particular Windows/OEM collation table.

ASCII 8.3 names use native uppercase short entries and lowercase part flags when
those flags reproduce the original spelling. Mixed-case and other long names
retain the exact UTF-16 LFN. Generated ASCII aliases use a finite deterministic
tilde-number search. Every existing natural short alias and every sibling long
name is reserved before generation, so a long name cannot steal a later sibling's
native name. LFN sets contain native descending ordinals, the last-entry bit,
the short-name checksum, and the required terminator/padding when the final
13-unit fragment is partial. Subdirectories begin with dot entries; a parent
link to the root uses cluster zero in both FAT16 and FAT32.

Each object receives its own contiguous initial chain. The allocator derives
space from the checked fresh-image geometry, never from FSInfo hints. Both FATs
receive identical links and EOC records. Every directory and file allocation
starts as logical zero; payload tail bytes, unwritten cluster slack, free
clusters, directory end slots and FAT padding remain zero. Only the payload
and metadata required by the plan are written, so memory does not scale with
the image's logical byte size. This deterministic initial allocation is not a
defragmentation or future in-place allocation policy.

The new source path adds preparation work; the existing bounded publication
sequence is unchanged. A failed source preflight creates nothing. A later copy,
source-stability, metadata or preparation-sync failure retains an incomplete
new file with both BPBs unpublished. Once BPB publication starts, existing
durability-phase reporting applies. An error during native directory or payload
readback explicitly reports that the file and parent were already synchronized;
it never turns a failed digest into success or silently removes the image.

### Native format references

The layout was reviewed against Microsoft's *FAT Specification 1.03*
(`fatgen103.doc`), retrieved from the official
[WHDC Legacy Documents archive](https://www.microsoft.com/en-us/download/details.aspx?id=53426):
[original document](https://download.microsoft.com/download/1/6/1/161ba512-40e2-4cc9-843a-923143f3456c/fatgen103.doc).
The retrieved document is 222,720 bytes with SHA-256
`b17d66c796d9cd3070adf4ccbc00add5a8b6b6f5491fe8ea949df778fce60172`.
Its BPB tables, FAT type determination, reserved entries, root initialization,
FSInfo, three-sector backup, short/long directory entries, alias checksums and
native dot/parent rules informed the encoder and independent byte fixtures.
The original document is not redistributed in the repository. The source-name
profile also follows Microsoft's [file naming rules](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file)
for invalid characters, trailing periods/spaces and reserved DOS device names.
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

Path commands and mounts use lossless UTF-8 LFNs and short names decoded with
the explicit `--oem-code-page ascii|437|850` option. The default `ascii` preserves
the conservative refusal of non-ASCII OEM-only names. FAT stores no OEM code-page
identifier, so the reader never infers it from the BPB, volume label, host locale,
or observed filenames. CP437 and CP850 decode all native bytes, restore the
first-byte `0x05` escape to `0xE5`, and honor independent base/extension lowercase
flags. The selected page remains fixed across a volume's cached directory entries.

```sh
ffs-fat ls disk.img --oem-code-page 850
ffs-fat cat disk.img --oem-code-page 850 /ÉCOLE.TXT
ffs-fat check disk.img --oem-code-page 437
ffs-fat mount disk.img /mnt/fat --offline-image --oem-code-page 850
```

Lookup, mounted directory collision checks, and checker alias/LFN collision
checks use ASCII case folding plus the selected page's representable native
case pairs. They do not expand sharp s to `SS`, remove accents, normalize Unicode,
or claim Windows' full Unicode LFN collation. Characters outside the selected
page compare exactly; CP850 includes the native one-way dotless-i-to-`I` mapping.
The byte mappings follow the Unicode Consortium's Microsoft
[CP437](https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/PC/CP437.TXT) and
[CP850](https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/PC/CP850.TXT) tables;
the native case pairs agree with Linux v6.19's corresponding NLS tables.

Unpaired UTF-16 surrogates and names exceeding the host's 255-byte limit still
have no admitted path spelling. The native catalog and entry-slot extraction
below access those entries without converting their identity. Permissions and
ownership remain explicit read-only Unix projections.
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
selector. All OEM bytes and the native `0x05` short-name escape remain unchanged
in `short_name_bytes`; `name` and `short_alias` use the selected page, reported as
`oem_code_page` in the catalog envelope. Unpaired UTF-16 units and names whose
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
tree, contradictory native short names and aliases under the selected code page, invalid native
dot/parent links, nonzero directory sizes, misplaced dot entries, malformed or
orphaned LFN sets, reserved allocation values and invalid successors. FAT32
FSInfo signatures and known free-count/search hints are checked against the
admitted FAT geometry and scan. FSInfo remains advisory; no hint or allocation
is repaired. The normal reader may still use a short alias after malformed LFN
records; the checker retains that damage as an issue. Ownership traversal keeps
raw native names even when the reader's UTF-8/OEM display projection is unavailable.

The flat report retains `format`, `read_only`, `oem_code_page`, `scope`, `clean`,
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


**Populated-image increment (2026-10-12):** the source-directory command adds
native file/directory creation to fresh images while preserving every original
empty-format regression. Fifteen new Rust test groups cover end-to-end copies
in both dialects; independently decoded FAT links, dots, zero slack and FSInfo;
short-name case flags; exact Unicode and 13/14/255-unit LFN boundaries; reserved
alias collisions; root and subdirectory growth; fixed-root/label/LFN capacity;
preflight ENOSPC and the native file-size limit; source type/name/depth refusal;
hardlink separation; source replacement and in-copy changes; payload and extra
metadata I/O failures/cancellation; and data corruption detectable only by native
payload readback. They also preserve verification on the created inode after
its destination pathname is replaced.

The extended external oracle includes populated images, native fsck and mtools
extraction/insertion, exact source-tree payload/name comparisons, allocation and
FSInfo counts, and optional mounted traversal. Authored tests and oracle coverage
are not executed interoperability evidence. Runtime and formatting results for
this increment must identify the actual revision and commands exercised; no
native or mounted success is inferred from the source implementation.

Final source integration evidence (2026-10-12): all five changed Rust source
files passed rustfmt parsing/formatting checks, the expanded external runner
passed Python syntax compilation, and independent production/API/fixture reviews
found no remaining concrete defect. CLI compilation again received SIGKILL while
building `asupersync` under the shared memory limit. The 15 new regression groups,
native fsck/mtools interchange and mounted cases remain unexecuted. Workspace
formatting reports existing differences in unchanged files; UBS could not execute
its installed launcher. The separately passing 850-test on-disk suite does not
validate this formatter or establish native interchange.
