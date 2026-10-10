# Experimental NTFS 3.1 MFT and stream read profile

`ffs-ntfs` implements native offline image reads using `ffs-ondisk::ntfs` and
`ffs-block::ByteDevice`. It does not delegate data reads to ntfs-3g, a kernel
filesystem or a mounted image. This is a companion binary, not yet an `OpenFs`
backend, FUSE mount, or writable filesystem. It traverses native directory
indexes and resolves paths using the image's own UpCase table.

## Commands

Use the repository's prescribed RCH build workflow:

```sh
rch exec -- cargo build -p ffs-cli --bin ffs-ntfs

ffs-ntfs inspect volume.img --offline-image
ffs-ntfs ls volume.img / --offline-image
ffs-ntfs ls volume.img /nested --offline-image
ffs-ntfs read volume.img /nested/file.txt --offline-image > extracted.bin
ffs-ntfs read volume.img /nested/file.txt --offline-image --stream note
ffs-ntfs record volume.img 24 --offline-image
ffs-ntfs cat volume.img 24 --offline-image > extracted.bin
ffs-ntfs cat volume.img 24 --offline-image --stream note > alternate.bin
ffs-ntfs cat volume.img 24 --offline-image --sequence 7 --start 507 --bytes 1031
ffs-ntfs cat disk.img 24 --offline-image --offset 1048576 --length 67108864
```

Record numbers are MFT identities, not byte offsets. `record` reports the
attributes physically contained in the selected FILE record, including native
UTF-16 names; it is not a flattened extension-catalog listing. Its DATA admission
checks and `cat`/`read` operate on the assembled base file. Select streams through
the base record, not an arbitrary extension record. UTF-16 names that cannot be
represented as UTF-8 retain their exact code units in JSON. `--stream` selects an
exact UTF-16 encoding of the supplied name; named-stream selection remains exact
rather than case-insensitive. An optional sequence number detects stale references.

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

Resident and nonresident DATA streams support exact named-stream selection,
signed backward LCN deltas, fragmentation, sparse holes and ValidDataLength zero
tails. All mappings are validated before extraction; logical EOF never exposes
allocation slack. Reads coalesce within a physical run, locate runs by binary
search and cap each returned buffer at 16 MiB. Invalid mappings, storage errors
and cancellation are errors, not successful short reads. Already streamed stdout
prefixes may remain after later I/O errors.

## ATTRIBUTE_LIST and extension records

A list can be resident or disk-backed; its complete mapping must be stored in the
base FILE record. The reader parses the entire initialized logical list, resolves
referenced records through the MFT, and checks the record/sequence, target instance,
attribute type, native name, and starting VCN. Every extension must point back to
the exact base record generation. Repeated resident attributes such as FILE_NAME
hard links remain separate instances, not one concatenated stream.

Catalog validation is bidirectional: each list entry must have its target, and
all attributes in the base and referenced extensions must be listed, except the
base's ATTRIBUTE_LIST itself. Unlisted attributes, missing instances, stale
references, foreign owners and recursive lists are refused. The list is never
used to redirect an extension into a different file.

Nonresident extents are assembled in VCN order. Gaps, overlaps, conflicting flags,
physical self-aliasing and incomplete coverage are rejected before publishing a
stream. Sizes come only from VCN zero; undefined continuation size fields cannot
change EOF or initialized length. Each extent restarts its relative LCN decoding.
Sparse and uninitialized ranges retain the same no-physical-read zero semantics.

MFT bootstrap uses a private, initially incomplete map. A referenced extension
record is read only when its entire initialized range is already mapped. The
reader repeatedly processes newly reachable extents, including dependencies that
are not in VCN order, until the complete DATA map can be validated through the
ordinary assembler. A no-progress dependency, stale record, torn fixup, logical
or physical alias, or exceeded work budget is an error; no physical address is
guessed from record number and no incomplete map is returned. The reconstructed
mapping must still reproduce the original record-zero bootstrap bytes.

These checks establish the admitted read-side relationships, not recovery,
allocation ownership across different files, or complete volume consistency.

## Native directories and path resolution

`ls` enumerates resident INDEX_ROOT and multi-level INDEX_ALLOCATION trees rather
than scanning the MFT for plausible parent references. Child VBNs, bitmap bits,
initialized allocation ranges, update-sequence protection and terminal records
are checked. Cycles, shared child nodes and unreachable allocated index blocks
are refused. Each directory key must match the target record's sequence and a
resident FILE_NAME identity, including its parent and namespace. FILE_NAME,
INDEX_ROOT, INDEX_ALLOCATION and BITMAP selection includes validated extensions.
Index ordering is not certified; enumeration visits the complete admitted tree
before lookup.

Path resolution starts at MFT record 5 and loads the native 65,536-entry UpCase
table from record 10, including ATTRIBUTE_LIST-backed DATA. Exact names are
preferred; Win32/DOS names fold through that table. POSIX names remain exact-only.
DOS aliases retain their native record identity. Conflicting folded matches are
refused. JSON listings retain separate native namespace entries, so a short alias
and long name may identify the same file. Unrepresentable UTF-16 names retain
raw code units; numeric inspection remains available. Reparse traversal is
refused even when the reparse attribute is stored in an extension record.

Each directory is limited to 65,536 keys, 16,384 allocation blocks and depth 32,
with at most 256 path components. The entire directory and referenced FILE_NAME
identities must be readable; a corrupt or unsupported target can cause the
listing/lookup to fail rather than publish a partially validated result. Index
block geometry must match the boot profile. Sub-cluster index blocks use 512-byte
VBN units even on a larger-sector volume. Parent traversal (`..`) is not admitted.

## Admission limits and exclusions

Only immutable, offline regular files, NTFS 3.1, 512..4096-byte sectors,
clusters up to 64 KiB and FILE/index record sizes up to 64 KiB are admitted.
The MFT bootstrap record must fit in the initial physical run. MFT indices
above u32::MAX and records outside initialized MFT data are not exposed.

Attribute lists are bounded to 4 MiB and 65,536 entries. Extension record storage
is bounded to 16 MiB per catalog. The assembled stream is limited to 65,536 runs,
not 65,536 runs per extension. MFT discovery admits at most 131,072 dependency
probes and 1,048,576 cumulative mapping-merge units. These are explicit resource
limits, not maximum sizes of the native NTFS format.

The list's own mapping cannot be recursively extended through other FILE records.
Compression, EFS encryption, unknown attribute flags and nonzero volume flags
remain refused. Sparse-only attributes accept zero or four as their frame-unit
encoding. No writes, repairs, log replay, volume-flag changes or device flushes
occur. A shared advisory lock does not exclude kernel mounts or unrelated writers.

A zero volume-flags field and matching record-zero mirror are **not** proof of
a clean $LogFile, absence of hibernation, complete MFTMirr consistency, or global
allocation/index integrity. The caller must supply a quiescent image. This is
not a recovery or filesystem-check tool. Reparse handling, compression, mounted
operations, native security projection and NTFS mutation remain separate work.

## Validation

```sh
rch exec -- cargo test -p ffs-ondisk ntfs
rch exec -- cargo test -p ffs-cli --bin ffs-ntfs
python3 scripts/verify_ntfs_read.py --binary target/debug/ffs-ntfs
```

The runner creates a new scratch image with mkntfs, seeds it with ntfscp, gets
independent MFT identities with ntfsls, and compares bytes with ntfscat. It covers
small/large/empty files, directory listings, namespace-aware path reads, named
streams, unaligned ranges and explicit partition boundaries, checking unchanged
image hashes and retaining command logs. It never modifies an existing image.

It also creates 32 additional named streams on one file. The ATTRIBUTE_LIST
returned independently by `ntfscat -a 0x20` must contain real extension-record
references for those streams. Merely creating many single-record names is not
accepted as coverage. All 32 streams are compared by numeric and path/ranged
reads, including an extension stream inside a selected partition. Missing tools,
a formatter that does not produce the requested layout, and candidate failures
are failures, not successful skips.

Delivery evidence: Python syntax compilation and runner `--help` were executed
for the extension-aware runner. Rust compilation/tests, rustfmt/Clippy and native
NTFS-image execution were unavailable in the authoring environment. Added code
and tests are not a passing conformance or Windows-interchange claim. The native
runner does not force fragmented MFT bootstrap, split mapping-pair continuations,
sparse/compressed/EFS images or directory-extension layouts; those mechanisms
have separate constructed Rust fixtures and still require native evidence.

The new Rust regressions cover resident/disk-backed lists, named/resident values
in extensions, split fragmented and sparse mappings, stale or mismatched catalogs,
physical aliases, partial coverage, cancellation, unchanged image bytes, MFT
out-of-order dependency resolution and refusal, extended indexes/FILE_NAMEs,
extended UpCase data and reparse attributes hidden in extensions. Existing boot,
stream, namespace, and read-only failure tests remain intact.
