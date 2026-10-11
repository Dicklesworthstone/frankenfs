# Experimental native ZFS block, DMU and ZPL reading

`ffs-zfs` implements the restricted ZFS-01/ZFS-02 foundation and starts ZFS-03
from the comprehensive expansion plan. It inspects labels and explicit uberblock
candidates, extracts checked roots and MOS object ranges, inventories DSL head
datasets, and reads files within an explicitly selected head. It is NOT a pool
importer or FUSE backend. No ext4/btrfs/FAT/NTFS dispatch is changed.

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
are checked with Fletcher2, Fletcher4 or SHA256 before transformation. Native
LZJB and length-prefixed ZFS LZ4 decode to the exact declared logical length;
short output, invalid backreferences, overflow and unsupported codecs fail.
SHA256 words and Fletcher input order follow the native format, independently
of the host and of the block-pointer container's byte order.

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
without physical reads; encrypted/embedded pointers cannot take that path.

Embedded DATA leaves require the declared `com.delphix:embedded_data` feature.
Their block pointers carry at most 112 encoded bytes within a verified parent
block. Existing raw/LZJB/LZ4 decoders enforce the 16 MiB logical-block bound;
no payload DVA is read. The native DNODE/OBJSET types cannot embed because they
require their fill counts. Nonleaf, reserved/redacted, protected and deduplicated
embedded forms are also refused. The same interpretation and cache checks apply.

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
silently substituting host collation. Only a head filesystem is selected: no
snapshot, zvol or recursive traversal into mounted child datasets is implied.

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

## Explicit admission limits

All input opens use read-only handles to regular offline files. The caller must
keep the image immutable; shared advisory locks do not exclude unrelated writers
or kernel mounts. There are no writes, flushes, label repairs, TXG publication,
log replay, implicit native imports or host paths taken from a label.

Extraction requires all four configurations to validate and agree on pool/leaf
identity, addressing, configuration generation and read features. The pool must
be exported and have one top-level file/disk leaf with ID zero and no removal,
special or log state. Versions 1..28 or 5000 are admitted. Version 5000 admits
only optional `org.illumos:lz4_compress` and `com.delphix:embedded_data` label
read features, each encoded as a native boolean-presence field. This is not full
MOS feature negotiation or pool import.

The selected uberblock cannot predate label configuration. Fork/history
resolution, rewind, active/MMP ownership and multi-vdev import remain separate
work. Gang and encrypted/authenticated blocks remain unsupported; embedded DATA
is limited to the leaf pipeline above. Context-sized holes are handled only in
the DMU traversal, not root extraction.
RAIDZ/mirror topologies, indirect vdevs, normalized/binary ZAP keys, full ZPL/SA
feature coverage, snapshot reads, security, native writes, maintenance and
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

Reference: OpenZFS tag zfs-2.3.0, especially spa.h, vdev_impl.h,
uberblock_impl.h, dnode.h, dmu_objset.h, zap_impl.h, dsl_dir.h, dsl_dataset.h,
zap_leaf.h, zap_leaf.c, zap_micro.c, nvpair.c, zio_checksum.c, sha2_zfs.c,
lzjb.c, lz4_zfs.c, sa_impl.h, sa.c, zfs_sa.c and zfs_znode.h.
