# Experimental native ZFS block, DMU, ZPL and extraction mounts

`ffs-zfs` implements the restricted ZFS-01/ZFS-02 foundation and starts ZFS-03
from the comprehensive expansion plan. It inspects labels and explicit uberblock
candidates, extracts checked roots and MOS object ranges, inventories DSL head
datasets, reads files within an explicitly selected head or named snapshot, and
exposes that same committed view through a read-only FUSE extraction mount.
It does not import a pool. No ext4/btrfs/FAT/NTFS dispatch is changed.

## Commands

Build using the repository's prescribed toolchain/RCH workflow:

```sh
rch exec -- cargo build -p ffs-cli --bin ffs-zfs

ffs-zfs inspect leaf.img --offline-image

# Read the GUID, label index and candidate slot from inspect. Sample values
# are placeholders, not authorization to choose an authoritative TXG.
ffs-zfs root leaf.img --offline-image --pool-guid 123 --label 0 --slot 2 > mos-root.bin
ffs-zfs object leaf.img 1 --offline-image --pool-guid 123 --label 0 --slot 2
ffs-zfs zap leaf.img 1 --offline-image --pool-guid 123 --label 0 --slot 2
ffs-zfs datasets leaf.img --offline-image --pool-guid 123 --label 0 --slot 2

# Explicit raw DMU bytes, NOT a ZPL file read or inferred file EOF.
ffs-zfs object-read leaf.img 1 --start 0 --bytes 512 \
  --offline-image --pool-guid 123 --label 0 --slot 2 > object-range.bin

# Actual ZPL paths: --dataset is relative to the pool, defaulting to its root.
ffs-zfs ls leaf.img / --dataset data --offline-image --pool-guid 123 --label 0 --slot 2
ffs-zfs stat leaf.img /file.bin --dataset data --offline-image --pool-guid 123 --label 0 --slot 2
ffs-zfs read leaf.img /file.bin --dataset data --start 507 --bytes 8199 \
  --offline-image --pool-guid 123 --label 0 --slot 2 > file-range.bin
ffs-zfs readlink leaf.img /link --dataset data --offline-image --pool-guid 123 --label 0 --slot 2

# Mountpoints must already exist and be empty. UID/GID are synthetic host IDs.
ffs-zfs mount leaf.img /mnt/zfs-head --dataset data --uid 1000 --gid 1000 \
  --offline-image --pool-guid 123 --label 0 --slot 2
ffs-zfs mount leaf.img /mnt/zfs-before --dataset data --snapshot before \
  --uid 1000 --gid 1000 --offline-image --pool-guid 123 --label 0 --slot 2

# All native checksum verifiers and DVA addresses remain vdev-relative.
ffs-zfs inspect disk.img --offline-image --offset 1048576 --length 134217728
```

`inspect` inventories configurations and candidate slots. It reports rejected
labels and empty/invalid/unsupported slots, not a global integrity pass. It does
not select the highest TXG or certify root authority. Extraction requires the
explicit candidate. Raw object/root commands stage their requested output;
ZPL `read` streams bounded, checked chunks. A later storage or stdout failure
can leave an earlier prefix in a host output file, but cannot report success.

## Implemented native pipeline

The pure `ffs-ondisk::zfs` module validates label placement, 1..8 KiB uberblock
slots derived from ashift, native byte order, and offset-salted SHA256 embedded
checksums. Label verifiers use vdev-relative offsets, never the containing file's
partition base. The XDR nvlist parser checks pair spans, scalar/array counts,
terminators, nested bounds and duplicate names; encoded/decoded lengths never
become unchecked allocations. Unknown values remain typed opaque data, not
permission to interpret them as a required config field.

Regular block pointers retain native sizes, birth, object type, byte order and
DVAs. The physical reader checks vdev identity, allocation size, sector alignment,
all-copy bounds and boot/label exclusions before issuing data I/O. Physical bytes
are checked with Fletcher2, Fletcher4, SHA256 or SHA-512/256 before transformation.
Native LZJB, gzip-1 through gzip-9, ZLE and length-prefixed ZFS LZ4 decode to the
exact declared logical length; short output, invalid backreferences, overflow
and unsupported codecs fail.
Fletcher inputs use the block's payload byte order, independently of the host
and the block-pointer container. SHA256 keeps its historical big-endian numeric
checksum words. Native checksum 11 (`sha512`) uses SHA-512/256 and interprets
each standard digest word in the block's payload byte order. SHA-512/256 uses
its own initialization values.

Embedded DATA pointers carry up to 112 compressed bytes inside the pointer
itself. Their native payload consists of fourteen numeric words, excluding the
property word and logical birth word; bytes are extracted least-significant
first even when the pointer's containing block is big-endian. Logical and packed
lengths are byte counts, not sector counts. Only level-zero, unencrypted,
non-deduplicated DATA pointers are admitted, with no embedded DNODE/OBJSET
blocks, reserved subtype or redacted-data interpretation. Uncompressed, LZJB,
gzip-1 through gzip-9, ZLE and ZFS LZ4 payloads must reconstruct the exact bounded
logical size. The parent block's checksum protects these bytes; there is no fabricated child checksum
or physical DVA read. A reached embedded pointer requires the native
`com.delphix:embedded_data` label feature as well as the ordinary dnode
type/size/birth checks before decoded bytes may enter the view's cache.

Native ZLE (codec 14) uses literal runs of 1..64 bytes and zero runs of
1..192 bytes. Every complete run must fit the declared logical output, and a
short stream cannot invent missing bytes. Decoding stops at the logical block
end, as in OpenZFS; trailing physical padding is still covered by the block's
checksum. The same decoder serves physical and embedded blocks, so ordinary
files, snapshots and mounted reads inherit the admitted codec without another
path or a native library dependency.

Native gzip-1 through gzip-9 (codecs 5..13) use RFC 1950 zlib framing, with
DEFLATE and its Adler-32 trailer, rather than RFC 1952 gzip members. The existing
flate2/zlib-rs dependency decodes into a fixed buffer of exactly the admitted
logical size. Success requires the complete first zlib stream and exact output
length; missing or damaged trailers, dictionaries, overrun and short output
fail. Bytes after that stream are physical padding, still covered by the full
physical-block checksum; a second stream is never concatenated to fill LSIZE.
The shared decoder reaches ordinary file, snapshot and mounted reads for both
physical and embedded blocks. No label feature requirement is added.

A bad physical read, checksum or transform can try another declared copy on the
same leaf. Cancellation propagates immediately and cannot turn into a redundant
copy retry. No copy is repaired. The uberblock's native GUID sum must match the
single-leaf configuration, including the root/pool GUID. The selected root must
be a level-zero OBJSET pointer born no later than its uberblock and decode to a
META object set. The `root` command alone does not validate its descendants.

## DMU objects and DSL head inventory

`ffs-ondisk::zfs_dmu` parses object sets, allocated dnodes and micro-ZAP entries.
Dnodes preserve native bonus/spill bytes, pointer counts, allocation units and
endianness. Object lookup walks slot boundaries from the start of the containing
16 KiB dnode block: interior slots of large dnodes cannot impersonate objects.
Indirect routes use wide arithmetic rather than overflowing on high block IDs.

Each object view owns one selected root and its admitted leaf configuration.
Traversed block pointers must have the expected type, level and logical size,
and a birth no later than their containing parent and the selected TXG. These
checks occur before I/O and before cache hits. Every physical read reuses the
existing checksum/transform/copy pipeline. Each child block supplies its own
payload byte order. Sparse leaf or indirect subtrees yield context-sized zeroes
without physical reads; embedded pointers use their dedicated decoder and
encrypted pointers remain refused rather than taking the hole path.

A view retains up to 32 fully checked blocks and 16 MiB of block bytes, keyed by
the complete pointer. Views do not share caches across roots. In-flight output,
clones and bookkeeping are outside this retention limit. Requests check
cancellation on cached paths as well as physical reads. No performance number
is claimed without executed measurements.

`object` reports a dnode and raw bonus bytes. `object-read` requires an explicit
byte count of at most 16 MiB and rejects ranges beyond dn_maxblkid geometry.
It does not mistake allocation capacity or bonus data for a ZPL file's EOF.
`zap` enumerates complete, unnormalized micro/fat-ZAPs, preserving raw name bytes
and typed values. JSON reports `integer_bytes` and a `values` array; an empty
array is distinct from a scalar zero. DSL references require exactly one native
8-byte integer and never silently cast a byte string or array into an object ID.

`datasets` follows the pool directory's root_dataset, DSL child maps, directory
bonus records and head dataset bonus records. It checks parent/backreferences,
duplicate or cyclic directory/head identities, state flags, GUIDs and creation
TXGs, then verifies and parses every reported head's object-set root. Filesystem
and volume object-set kinds are reported, but neither is mounted by inventory.
Names are relative to the pool; the root has an empty name. Raw component arrays
accompany lossless UTF-8 names. Internal DSL directories are not silently
discarded. Snapshots and clone relationships are not enumerated.

The inventory is bounded to 4,096 DSL directories, depth 64 and 1 MiB cumulative
path bytes. A corrupt or unsupported reached map fails the entire inventory;
there is no partial-success list. DSL directory/dataset bonus layouts must be
256/320 bytes; extensified ZAP-typed dnodes are recognized, but their extra
properties and full feature obligations are not interpreted by this inventory.

## Native fat-ZAP traversal

The `ffs-ondisk::zfs_zap` parser handles embedded and external pointer tables,
leaf prefix intervals, hash buckets, entry chains, chunked names, typed values
and the free-chunk list. DMU traversal supplies checksum-verified blocks in each
block's own byte order. Integer-array payloads retain their native big-endian
encoding independent of the leaf header; widths 1, 2, 4 and 8 are supported.

Each leaf must own one contiguous, aligned power-of-two pointer-table interval.
Its prefix and every entry's salted CRC64 hash must match that routing. Both
28-bit and HASH64/48-bit string-key hashes are supported. Entries, name/value
arrays and free chunks cannot share chunks or form cycles. Counts and all chunk
ownership must agree; orphan chunks, duplicate keys, unterminated names and
missing metadata blocks are errors, never partially successful maps.

During incremental external-table growth the old table remains authoritative.
Every completed block pair in the growing copy is compared with the duplicated
old pointers. Uncopied reserved blocks are not treated as initialized data.
Leaf references cannot alias either pointer-table region. No table is changed,
finished or repaired by a read. Normalized and binary/pre-hashed key layouts
remain refused; string-key enumeration is not full naming-policy support.

Per-map bounds are 512..128 KiB power-of-two blocks, 1,048,576 table pointers,
4,096 leaves and 65,536 entries. Names are capped at 4 KiB including NUL; a value
array is capped at 64 KiB before widening its integers. Enumeration charges at
most 64 MiB of ZAP data-block work, including cached accesses; DMU indirect
reads are separate. Returned entries and duplicate-name payload accounting are
capped at 16 MiB. These are not total-process or physical-I/O memory limits:
temporary leaf/table buffers, allocator bookkeeping and view caches also exist.
The entire admitted map is validated before it is returned to CLI or DSL code.

## ZPL paths and system attributes

`ls`, `stat`, `read` and `readlink` select a head through the validated DSL
inventory. The selected filesystem gets its own object-set root and block cache,
separate from the MOS and other datasets. Its master node supplies ROOT, VERSION
and naming policies. Case-sensitive, unnormalized ZPL versions 1..5 are admitted;
UTF8-only policy is checked when present. Unsupported policies fail rather than
silently substituting host collation. An exact `--snapshot` selects a validated
historical filesystem as described in [ZFS_SNAPSHOT_READ_PROFILE.md](ZFS_SNAPSHOT_READ_PROFILE.md).
There is no zvol or recursive traversal into mounted child datasets.

Metadata can use legacy 264-byte znodes or native system attributes. Fixed
legacy attribute IDs remain fixed; other IDs come from the dataset's REGISTRY.
LAYOUTS supplies ordered uint16 attribute arrays. Each SA bonus/spill buffer
identifies its own byte order and layout, including variable-length fields and
eight-byte alignment. Spill blocks pass the same type/birth/checksum pipeline
as other metadata. Bounds are checked for unconsumed attributes too; duplicate
attributes, conflicting registrations and missing required fields are errors.
ACL/xattr bytes are not interpreted as access-control authorization.

Directory entries are decoded as low-48-bit objects plus native type tags.
Their target mode must agree. Directory parents and identities are validated;
ordinary file hard links retain one object identity even when their stored
parent differs. Enumeration returns no successful partial list if a later target
is corrupt. Names retain their native bytes, with lossless UTF-8 when possible.
No host path is opened from an image name. Parent traversal and symlink following
are refused. `readlink` returns a native target without resolving it.

File reads use ZPL_SIZE for EOF. Allocation slack is never returned; sparse
subtrees and the logical tail beyond the last allocated block return zeroes
without fabricated physical reads. Existing DMU transforms apply to allocated
blocks. Legacy inline/long symlinks and SA symlink attributes are read separately
from regular-file content. Reparse/offline providers and private xattr objects
remain refused. Metadata reports native mode, IDs, link count, creation
generation, allocation accounting and four timestamps, including signed seconds
and nanosecond precision. This is offline extraction, not host SID/FUID/ACL
mapping or permission enforcement, and no mode/owner mutation is offered.

ZPL requests are capped at 16 MiB; CLI extraction streams 1 MiB chunks. Paths
are capped at 64 KiB and 256 components, names at 255 bytes, symlink output at
64 KiB, directory result payloads at 32 MiB. SA registries/layouts are capped at
4,096 registered entries, 1,022 stored layouts, 65,536 layout items, and 128 KiB
per bonus/spill buffer. These are admission budgets, not format maxima or a
whole-process memory limit. Reads describe the selected committed root only:
there is no ZIL replay, recovery validation or claim that pending synchronous
intent has been incorporated into that root.

## Read-only extraction mounts

`mount` uses the same explicit pool GUID, label and uberblock slot as extraction.
It validates the selected head or snapshot, its root directory and the root's
children before starting FUSE. A missing or invalid snapshot cannot fall back to
the head. The mount owns its read-only image handle and selected object-set view;
its lifetime and checked-block cache do not depend on a temporary CLI reader.
Separate mounts retain separate roots, SA registries and caches even when a
head and a snapshot contain the same native object numbers.

Lookup, attributes, bounded directory enumeration, regular-file reads and
symlink targets come from the native ZPL graph. Hard links share one mounted
inode. Inode 1 is the selected filesystem root; native object numbers cannot
provide a second alias for it. Reached object generations, types and directory
parents are checked on every access. A directory's entire native listing is
validated before any part of it or its discovered identities becomes visible.
Directory cookies are stable within the immutable view and names remain exact
byte strings. Reads preserve native EOF, sparse zeroes, checksums, compression,
embedded payloads and cancellation errors.

Mounted ownership is the supplied synthetic UID/GID, with modes 0555 for
directories, 0444 for files and 0777 for symlinks. Native ZFS ACLs, FUID mapping
and permission enforcement are not projected; `stat` continues to expose the
native metadata separately. `allow_other` and writable mount options are not
offered. Writable opens and filesystem mutations return read-only errors.
`fsync` and `fsyncdir` validate the requested object without writing or flushing
the image. Native symlink targets are returned to the host kernel, which applies
normal mounted symlink semantics; this extraction mount is not a path sandbox.

Special files, xattrs/ACL access and pool free-space reporting (`statfs`) are
explicitly unsupported. A reached directory containing a special file fails
rather than fabricating a device number or successful partial listing.
`SEEK_DATA`/`SEEK_HOLE` use the permitted conservative projection of file data
through EOF; they do not claim an exact physical-allocation map. At most 131,072
object identities are retained per mount, with up to 32 cached directories and
8 MiB of retained directory data in addition to the existing DMU view cache.
These bounds do not represent a whole-process memory limit.

Constructed regression fixtures exercise mounted lookup/read/readdir behavior,
hard links, root identity, legacy and SA metadata, both byte orders, historical
cache isolation, write refusal, corrupt directories and cancellation. The test
devices reject every backing write or flush. These are unit-level fixtures;
they do not establish executed kernel FUSE or native OpenZFS interchange.

## Explicit admission limits

All input opens use read-only handles to regular offline files. The caller must
keep the image immutable; shared advisory locks do not exclude unrelated writers
or kernel mounts. There are no writes, flushes, label repairs, TXG publication,
log replay, implicit native imports or host paths taken from a label.

Extraction requires all four configurations to validate and agree on pool/leaf
identity, addressing, configuration generation and read features. The pool must
be exported and have one top-level file/disk leaf with ID zero and no removal,
special or log state. Versions 1..28 or 5000 are admitted. Version 5000 requires
no label read features beyond optional `org.illumos:lz4_compress` and
`com.delphix:embedded_data`, encoded as boolean-presence fields. Unknown features
and wrong value types still fail admission. This is not full MOS feature
negotiation or pool import.

The selected uberblock cannot predate label configuration. Fork/history
resolution, rewind, active/MMP ownership and multi-vdev import remain separate
work. Gang and encrypted/authenticated blocks remain unsupported;
context-sized holes are handled only in the DMU traversal, not root extraction.
RAIDZ/mirror topologies, indirect vdevs, normalized/binary ZAP keys, full ZPL/SA
feature coverage, full snapshot/clone semantics, security, native writes, maintenance and
MVCC/RaptorQ integration remain incomplete. Neither dataset inventory nor the
restricted ZPL reader is a full ZFS-support claim.

Other budgets: 16 MiB logical/physical blocks; 112 KiB label configurations;
8,192 nvlist items, depth 16 and 4 KiB config strings; 512..16,384-byte dnodes,
1..3 root pointers, at most 12 levels, 4..128 KiB indirect blocks; micro-ZAPs up
to 128 KiB. Ashift 9..16 is recognized with the native 8 KiB uberblock stride cap.
These are implementation bounds, not maximum sizes of the native filesystem.

## Validation and evidence

```sh
rch exec -- cargo test -p ffs-ondisk zfs
rch exec -- cargo test -p ffs-cli --bin ffs-zfs
python3 scripts/verify_zfs_root.py --binary target/debug/ffs-zfs --create-scratch-pool

# Separate opt-in: this new runner creates AND natively mounts fresh scratch pools.
python3 scripts/verify_zfs_files.py --binary target/debug/ffs-zfs --create-and-mount-scratch-pool
```

The original native runner creates only new random-named file pools without
force, import, destroy or dataset mounts. It exports them and retains images/logs.
It compares root bytes against zdb -R at ashift 9 and 12 and compares DSL head
names/GUIDs with native zfs list captured before export. Both are repeated inside
a bounded partition, with whole-image hashes checked. Candidate selection on
this fresh fixture is not a FrankenFS import algorithm. Missing tools, layout
refusal and disagreement fail instead of earning skipped-test credit.

The fat-ZAP workload adds 128 long-named children beneath `data`, alongside the
existing `nested` child. Native `zdb` must independently identify a fat-ZAP with
more than one leaf and exactly 129 child references. Candidate typed values and
name bytes must match every native reference, and the entire DSL names/GUIDs
comparison still runs. Both the child map and dataset inventory are repeated in
the bounded partition with the original root/hash checks retained. A small-map
substitute, unknown zdb output, missing tools or native disagreement fails.
This runner does not manufacture external/growing pointer tables, mixed endian
blocks or corrupt chains; those remain constructed Rust test coverage.

The new ZPL runner separately requires permission to create and natively mount
its fresh random-named file pools. It creates ZPL version 4/5 datasets with long
names, hard links, nested paths, a symlink, empty files and a multi-GiB sparse
tail; records native file bytes and stat metadata; then exports before invoking
the candidate. It compares listing/stat/read/ranged-read/readlink output on the
exported image and on a bounded partition, checks EOF and refusal to follow the
symlink, and requires unchanged hashes. It never imports or destroys an existing
pool, accepts an existing image, forces an operation or removes evidence.
This is an executable native comparison, not a claim that it has run here.

Initial block-pipeline evidence included fixed Python SHA256 vectors, independent
liblz4 vectors, and Python runner syntax/help checks, not Rust/native execution.
For this DMU increment, six parser, six graph/traversal and one CLI regression
functions were added. They cover mixed-endian trees, sparse subtrees, interior
slots, explicit range bounds, wrong-type/level/birth/vdev pointers, checksums,
cancellation, cache context and DSL identities. The graph tests deliberately
isolate DMU traversal from label admission; they are not native-image proof.

DMU authoring evidence: Python runner syntax/help and source whitespace checks
were executed. Rust/Cargo/RCH are absent, network toolchain download is unavailable,
and no ZFS kernel/tools are present here. Compilation, Rust tests, rustfmt/Clippy,
native comparisons and mounted behavior are NOT claimed. Existing test assertions
and root-verification gates are retained; new coverage is not a passing result.

Fat-ZAP authoring evidence: seven parser and five DMU regression functions were
added, including typed arrays, empty values, cross-chunk names, external/growing
tables, mixed-endian blocks, DSL consumption, corruption and cancellation. Fixed
hash vectors were calculated separately with Python. Runner syntax compilation,
`--help`, two positive and seventeen negative constructed Python helper checks,
and changed-file whitespace checks passed. Rust compilation/tests, rustfmt/Clippy
and native ZFS execution remain unexecuted here. Helper checks do not execute the
Rust parser or a filesystem and do not certify native interchange.

ZPL authoring evidence: eight parser, seven graph and two CLI/helper regression
functions added. Python syntax compilation, runner help, two positive/twelve
negative helper cases and source whitespace checks passed. Rust compilation,
Rust tests, rustfmt/Clippy and native ZFS execution remain unexecuted here.
Existing DMU and CLI source was retained byte-for-byte apart from module/command
registration; existing test assertions and native comparison gates are unchanged.

Additional embedded-data authoring evidence: three parser, two verified-parent
graph and one full-label regression functions were added. They cover fixed
numeric payload vectors, LZJB/LZ4 decoding, malformed LZ4 streams, fill-bearing
type refusal, mixed inline/hole/physical ranges, parent checksum failure, cancellation
and four-label feature agreement. These supplement the existing embedded runtime
and its tests. They were source-reviewed only: executor loss prevented Rust
compilation/tests and rustfmt/Clippy, and no native ZFS comparison was executed.
Native fill semantics were checked against pinned OpenZFS `dmu.h` and `zio.c`;
payload and feature layouts against `spa.h`, `blkptr.c` and `zfeature_common.c`.

Extraction-mount implementation validation (2026-10-11): before the shared
executor outage, the complete `ffs-ondisk` library suite passed 790 tests and
parser-library Clippy passed with warnings denied. Workspace formatting passed
at that point. CLI compilation was killed in `asupersync` under the shared
memory limit. The source was then recovered through immutable GitHub blobs;
the production embedded parser matched its pre-outage Git blob, while some
added fixtures were reconstructed. The final integrated tree, CLI regressions,
kernel FUSE mounts and native ZFS comparisons have not been executed. Source
review and restored bytes do not replace those runtime gates.

Reference: OpenZFS tag zfs-2.3.0, especially spa.h, vdev_impl.h,
uberblock_impl.h, dnode.h, dmu_objset.h, zap_impl.h, dsl_dir.h, dsl_dataset.h,
zap_leaf.h, zap_leaf.c, zap_micro.c, nvpair.c, zio_checksum.c, sha2_zfs.c,
lzjb.c, zle.c, zio_compress.c, lz4_zfs.c, sa_impl.h, sa.c, zfs_sa.c and zfs_znode.h.
Embedded layout and decoding contracts come from the same pinned tag's
[spa.h](https://github.com/openzfs/zfs/blob/zfs-2.3.0/include/sys/spa.h),
[blkptr.c](https://github.com/openzfs/zfs/blob/zfs-2.3.0/module/zfs/blkptr.c),
[zio.c](https://github.com/openzfs/zfs/blob/zfs-2.3.0/module/zfs/zio.c) and
[zfeature_common.c](https://github.com/openzfs/zfs/blob/zfs-2.3.0/module/zcommon/zfeature_common.c).

## Native ZLE validation

Six focused regressions cover all 256 token values, fixed mixed literal/zero
payloads, every truncated input prefix, output limits, physical checksum
verification including padding, and checksum-valid malformed streams. Physical
and embedded block dispatch are exercised in all four combinations of pointer
container and logical payload byte order. Existing embedded feature, historical
birth, image immutability and read-budget checks remain in their shared paths.

Delivery evidence (2026-10-11): independent source review against pinned OpenZFS
[`zle.c`](https://github.com/openzfs/zfs/blob/zfs-2.3.0/module/zfs/zle.c) and
[`zio_compress.c`](https://github.com/openzfs/zfs/blob/zfs-2.3.0/module/zfs/zio_compress.c),
complete blob comparisons, and JavaScript reference checks of the fixed payload,
embedded numeric words, token ranges and malformed fixture expectations. Rust
compilation/tests, formatting, workspace checks, Clippy, UBS and native ZFS
execution remain unavailable with the executor offline. The reference checks
do not execute the Rust decoder or establish native interoperability.

## Native SHA-512/256 validation

Six regressions use NIST short and 112-byte known answers in both native word
orders, preserve SHA256's historical representation, and exercise complete
physical-sector decoding across all four container/payload order combinations.
They also cover truncated or damaged payloads, damaged and swapped checksum
words, incorrect payload-order bits, unsupported checksum algorithms and the
existing input-size budget. This uses the existing sha2 dependency. Native
SHA512 is a dataset feature rather than a label MOS feature; checksum support
does not add a label feature requirement or relax the existing allowlist.

Delivery evidence (2026-10-11): complete blob comparisons, independent source
review, exact known-answer/message comparison and independent byte-order fixture
checks. Rust compilation/tests, formatting, workspace checks, Clippy, UBS and
native ZFS execution remain unavailable with the executor offline. Authored
regressions and reference checks are not passing Rust or interoperability results.

References: [NIST SHA-512/256 examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512_256.pdf),
and OpenZFS `zfs-2.3.0`
[`sha2_zfs.c`](https://github.com/openzfs/zfs/blob/zfs-2.3.0/module/zfs/sha2_zfs.c),
[`zio_checksum.c`](https://github.com/openzfs/zfs/blob/zfs-2.3.0/module/zfs/zio_checksum.c),
[`zfeature_common.c`](https://github.com/openzfs/zfs/blob/zfs-2.3.0/module/zcommon/zfeature_common.c)
and [`sha2_test.c`](https://github.com/openzfs/zfs/blob/zfs-2.3.0/tests/zfs-tests/cmd/checksum/sha2_test.c).

## Native GZIP validation

Seven regressions cover all nine native compression IDs with independently
specified fixed-Huffman, dynamic-Huffman and stored-block zlib vectors. They
exercise exact output length, every proper input prefix, Adler-32 failures,
dictionary requests, wrong framing, invalid DEFLATE, concatenated-stream tails,
input/output budgets, and physical/embedded dispatch in all four combinations
of pointer-container and payload byte order. Complete physical-sector checksums
remain mandatory, including padding bytes. Existing admission and tests are
retained.

Delivery evidence (2026-10-11): complete blob comparisons, independent source
review against the pinned implementations below, and separate JavaScript
DEFLATE/framing/Adler-32 fixture checks. Rust compilation/tests, formatting,
workspace checks, Clippy, UBS and native ZFS execution remain unavailable with
the executor offline. Reference checks and authored tests do not execute the
Rust decoder or establish native interoperability. The dependency version and
backend already exist in the workspace; only ffs-ondisk's dependency edge is new.

References: OpenZFS `zfs-2.3.0`
[gzip.c](https://github.com/openzfs/zfs/blob/zfs-2.3.0/module/zfs/gzip.c),
zlib `v1.3.1`
[uncompr.c](https://github.com/madler/zlib/blob/v1.3.1/uncompr.c) and
[infcover.c](https://github.com/madler/zlib/blob/v1.3.1/test/infcover.c),
and flate2 `1.1.9`
[mem.rs](https://github.com/rust-lang/flate2-rs/blob/1.1.9/src/mem.rs).
