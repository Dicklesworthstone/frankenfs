# Experimental NTFS 3.1 MFT and stream read profile

`ffs-ntfs` implements native offline image reads using `ffs-ondisk::ntfs` and
`ffs-block::ByteDevice`. It does not delegate data reads to ntfs-3g, a kernel
filesystem or a mounted image. This is a companion binary, not yet an `OpenFs`
backend, FUSE mount, directory-index/path resolver, or writable filesystem.

## Commands

Use the repository's prescribed RCH build workflow:

```sh
rch exec -- cargo build -p ffs-cli --bin ffs-ntfs

ffs-ntfs inspect volume.img --offline-image
ffs-ntfs record volume.img 24 --offline-image
ffs-ntfs cat volume.img 24 --offline-image > extracted.bin
ffs-ntfs cat volume.img 24 --offline-image --stream note > alternate.bin
ffs-ntfs cat volume.img 24 --offline-image --sequence 7 --start 507 --bytes 1031
ffs-ntfs cat disk.img 24 --offline-image --offset 1048576 --length 67108864
```

Record numbers are MFT identities, not byte offsets. `record` reports each
attribute, its native UTF-16 name, and whether a DATA stream is admitted by this
profile. UTF-16 names that cannot be represented as UTF-8 retain their exact
code units in JSON rather than being silently replaced. `--stream` selects an
exact UTF-16 encoding of the supplied name; Windows case-insensitive collation
is not implemented. An optional sequence number detects stale file references.

## Implemented data path

Boot parsing checks sector/cluster geometry, both record-size encodings,
selected-volume bounds and primary/mirror bootstrap locations. MFT FILE records
have every 512-byte-stride update-sequence trailer checked before restoration.
Attribute parsing checks used-byte boundaries, names, resident values,
nonresident headers, unique instances and the terminating marker.

The reader bootstraps the unnamed MFT DATA stream, requires record-zero
agreement with MFTMirr, and reads subsequent records through the MFT runlist,
including a fragmented MFT. It checks file-reference identity, sequence and
in-use state and reads version/flags from VOLUME_INFORMATION.

Single-record resident and nonresident DATA streams support exact named-stream
selection, signed backward LCN deltas, fragmentation, sparse holes and
ValidDataLength zero tails. All mappings are validated before extraction;
logical EOF never exposes allocation slack. Reads coalesce within a physical
run, locate runs by binary search and cap each returned buffer at 16 MiB.
Invalid mappings, storage errors and cancellation are errors, not successful
short reads. Already streamed stdout prefixes may remain after later I/O errors.

## Admission limits and exclusions

Only immutable, offline regular files, NTFS 3.1, 512..4096-byte sectors,
clusters up to 64 KiB and FILE/index record sizes up to 64 KiB are admitted.
The MFT bootstrap record must fit in the initial physical run. MFT indices
above u32::MAX and records outside initialized MFT data are not exposed.
Mapping-pair decoding has a 65,536-run budget.

ATTRIBUTE_LIST assembly and extension records, compression, EFS encryption,
unknown attribute flags and nonzero volume flags are refused rather than
returning a partial or misinterpreted stream. Sparse-only attributes accept
zero or four as their frame-unit encoding; compressed data remains refused.
No writes, repairs, log replay, volume-flag changes or device flushes occur.

A zero volume-flags field and matching record-zero mirror are **not** proof of
a clean $LogFile, absence of hibernation, complete MFTMirr consistency, or global
allocation/index integrity. The caller must supply a quiescent image; shared
advisory locking does not exclude kernel mounts or unrelated writers. This is
not a recovery or filesystem-check tool. Directory indexes, $UpCase collation,
reparse traversal, mounted operations and NTFS mutation remain separate work.

## Validation

```sh
rch exec -- cargo test -p ffs-ondisk ntfs
rch exec -- cargo test -p ffs-cli --bin ffs-ntfs
python3 scripts/verify_ntfs_read.py --binary target/debug/ffs-ntfs
```

The Python runner creates a new scratch image with mkntfs, seeds it with ntfscp,
gets independent MFT identities with ntfsls, and compares bytes with ntfscat.
It covers small/large/empty files, a named stream, unaligned ranges and explicit
partition boundaries, checking unchanged image hashes and retaining command
logs. It does not require a privileged mount or modify an existing image.
Missing native tools and candidate failures are failures, never passing skips.

Delivery evidence: Python syntax compilation and runner `--help` were executed.
Rust compilation, Rust tests, rustfmt/Clippy and native-image execution were not
available in the authoring environment. Added tests and runner code are not a
passing conformance claim. The native runner does not manufacture sparse,
compressed, encrypted or extension-record images; the Rust fixtures separately
exercise sparse/uninitialized reads and unsupported/corrupt admission.
