# Experimental FAT16/FAT32 read profile

`ffs-fat` is a native Rust companion binary in `ffs-cli`. It uses the shared
`ffs-ondisk::fat` parser and the existing `ffs-core::FsOps` / `ffs-fuse` adapter.
It does not invoke another filesystem driver to implement reads. The ordinary
ext4/btrfs `ffs-cli` dispatch and `FsFlavor` are unchanged; this is not yet
integration into the generic `ffs mount` or `OpenFs` auto-detection path.

## Commands

Build `ffs-fat` with the repository's prescribed Cargo/RCH workflow:

```sh
rch exec -- cargo build -p ffs-cli --bin ffs-fat

target/debug/ffs-fat inspect volume.img
target/debug/ffs-fat check volume.img
target/debug/ffs-fat ls volume.img /nested
target/debug/ffs-fat cat volume.img '/Long native filename.txt' > extracted.bin

# The directory must already exist and be empty. No other program may write
# the backing image for the lifetime of this mount.
target/debug/ffs-fat mount volume.img /mnt/fat --offline-image --uid 1000 --gid 1000
fusermount3 -u /mnt/fat

# Explicit byte-bounded volume inside a larger image, without partition discovery.
target/debug/ffs-fat cat disk.img --offset 1048576 --length 67108864 /FILE.BIN
target/debug/ffs-fat check disk.img --offset 1048576 --length 67108864
```

All image opens are read-only. There is no write, repair, recovery, format,
resize, or protection-initialization path. Shared advisory locks do not exclude
kernel mounts or unrelated writers; image immutability is a caller requirement.
`cat` validates allocation before output, but a later storage failure may still
leave a previously streamed prefix on stdout and exits unsuccessfully.

## Implemented boundaries

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

Names use lossless UTF-8 LFNs and ASCII short names; non-ASCII OEM-only names,
unpaired UTF-16 surrogates and names exceeding the host's 255-byte limit are
refused rather than silently altered. Comparisons fold ASCII only, not Windows
Unicode collation. Permissions/ownership are explicit read-only Unix projections.
Native timestamps use a deterministic UTC projection of FAT wall-clock fields;
the format records no timezone, so this projection does not recover the original
instant. Creation preserves its native 10 ms precision (including odd seconds),
access preserves its native date precision, and modification preserves its native
two-second precision. Unavailable fields and the nonexistent native metadata-change
time remain epoch zero. Present dates/times must pass calendar and field bounds;
invalid fields report corruption at their directory record. Dirty volumes and
conflicting boot copies require offline native investigation; this reader never
repairs them automatically.

FAT12, exFAT, FAT writes/recovery, complete OEM/Unicode naming parity, integrated
MVCC/RaptorQ protection, and NTFS/ZFS implementation remain separate work.

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

The external runner creates real FAT16/FAT32 images with `mkfs.fat`, seeds and
reads them with mtools, checks the candidate's complete allocation report against
the known namespace and independently scanned free count, compares binary and
optional mounted reads, requires EROFS for mounted write-open, checks unchanged
image hashes, and runs
`fsck.fat -n`. It retains images and command logs and fails on missing prerequisites.
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
