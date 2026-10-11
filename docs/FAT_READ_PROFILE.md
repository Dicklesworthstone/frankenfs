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
Modification time is a deterministic UTC projection of native FAT wall-clock
fields; missing access/change/creation timestamps are epoch zero, not fabricated
native timestamps. Dirty volumes and conflicting boot copies require offline
native investigation; this reader never repairs them automatically.

FAT12, exFAT, FAT writes/recovery, complete OEM/Unicode naming parity, integrated
MVCC/RaptorQ protection, and NTFS/ZFS implementation remain separate work.

## Read-only allocation check

`ffs-fat check` walks the admitted directory tree and every addressable allocation
entry, returning a JSON report. It identifies cross-linked file/directory chains,
allocated clusters unreachable from the tree, contradictory ASCII names/aliases,
invalid native dot/parent links, nonzero directory sizes, reserved allocation
values and invalid successors. FAT32 FSInfo signatures and known free-count/search
hints are checked against the admitted FAT geometry and scan. FSInfo remains
advisory; no hint or allocation is repaired.

The report includes allocated/free/bad/preallocated cluster counts, files and
directories visited, and the volume-relative offsets of conflicting owners.
Reachable file preallocation is accounted for and never exposed as file contents
or classified as lost. Bad-cluster markers are counted, without treating the
marked media as available. If a shared directory cannot be traversed uniquely,
`namespace_complete` is false and `lost_clusters` is null, so an incomplete walk
cannot invent a definitive orphan count.

Exit status is zero only when all scoped checks complete without issues. A
completed scan with issues prints JSON with `clean: false` and exits unsuccessfully.
Malformed live chains, unsupported names/geometry, mirror conflicts, I/O errors,
cancellation and resource exhaustion return an error without a clean report.
The checker retains normal clean-volume admission: it does not bypass dirty-state
refusal, replay a journal, or accept a concurrently writable image.

Checks are bounded to 8,388,608 data clusters and total claimed chain entries,
131,072 namespace objects, 256 directory levels, 128 MiB of total directory
allocation and 1,024 retained issues. Further issues are counted explicitly.
These checks cover the reader's admitted namespace and allocation profile; they
do not verify file-content integrity, all native naming rules or complete
`fsck.fat` behavior, and do not provide a repair plan.

## Executable checks and evidence limits

```sh
rch exec -- cargo test -p ffs-ondisk fat
rch exec -- cargo test -p ffs-cli --bin ffs-fat

# Requires dosfstools and mtools; --mounted additionally requires usable FUSE.
python3 scripts/verify_fat_read.py --binary target/debug/ffs-fat
python3 scripts/verify_fat_read.py --binary target/debug/ffs-fat --mounted
```

The external runner creates real FAT16/FAT32 images with `mkfs.fat`, seeds and
reads them with mtools, compares binary and optional mounted reads, requires
EROFS for mounted write-open, checks unchanged image hashes, and runs
`fsck.fat -n`. It retains images and command logs and fails on missing prerequisites.
The added Rust unit tests cover independent byte layouts, error/cancellation
propagation, malformed chains, partition bounds, LFN boundaries, FsOps and dates.

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
