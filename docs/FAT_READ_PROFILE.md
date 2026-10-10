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
Root and directory allocation chains are also validated for attribute reporting.
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
