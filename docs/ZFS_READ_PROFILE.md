# Experimental native ZFS block, DMU, ZPL and extraction mounts

`ffs-zfs` implements the restricted ZFS-01/ZFS-02 foundation, selected ZFS-03
filesystem and snapshot reads, and bounded ZFS-04 mirror and ordinary RAIDZ1/2/3
profiles from the comprehensive expansion plan. It inspects labels and explicit uberblock
candidates, extracts checked roots and MOS object ranges, inventories DSL head
datasets, reads files within an explicitly selected head or named snapshot, and
exposes that same committed view through a read-only FUSE extraction mount.
Reads can use a single leaf or an explicitly supplied complete mirror or RAIDZ1/2/3 group.
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

# User xattrs share the selected dataset/snapshot and all explicit member options.
ffs-zfs listxattr leaf.img /file.bin --dataset data --snapshot before \
  --offline-image --pool-guid 123 --label 0 --slot 2
ffs-zfs getxattr leaf.img /file.bin user.comment --dataset data --snapshot before \
  --offline-image --pool-guid 123 --label 0 --slot 2 > comment.bin

# Mountpoints must already exist and be empty. UID/GID are synthetic host IDs.
ffs-zfs mount leaf.img /mnt/zfs-head --dataset data --uid 1000 --gid 1000 \
  --offline-image --pool-guid 123 --label 0 --slot 2
ffs-zfs mount leaf.img /mnt/zfs-before --dataset data --snapshot before \
  --uid 1000 --gid 1000 --offline-image --pool-guid 123 --label 0 --slot 2

# All native checksum verifiers and DVA addresses remain vdev-relative.
ffs-zfs inspect disk.img --offline-image --offset 1048576 --length 134217728

# Supply every configured mirror member explicitly; repeat --mirror-member
# for each member after the first. GUID/label/slot remain explicit selections.
ffs-zfs root mirror-a.img --mirror-member mirror-b.img \
  --offline-image --pool-guid 123 --label 0 --slot 2 > mirror-mos-root.bin
ffs-zfs read mirror-a.img /file.bin --mirror-member mirror-b.img \
  --dataset data --snapshot before --start 507 --bytes 8199 \
  --offline-image --pool-guid 123 --label 0 --slot 2 > mirror-file-range.bin
ffs-zfs mount mirror-a.img /mnt/zfs-mirror --mirror-member mirror-b.img \
  --dataset data --snapshot before --uid 1000 --gid 1000 \
  --offline-image --pool-guid 123 --label 0 --slot 2

# One ordinary RAIDZ group: every configured member is supplied explicitly.
# --member is repeatable; --mirror-member and --raidz-member are aliases.
ffs-zfs read raidz-a.img /file.bin --member raidz-b.img --member raidz-c.img \
  --dataset data --snapshot before --start 507 --bytes 8199 \
  --offline-image --pool-guid 123 --label 0 --slot 2 > raidz-file-range.bin
ffs-zfs mount raidz-a.img /mnt/zfs-raidz --member raidz-b.img --member raidz-c.img \
  --dataset data --snapshot before --uid 1000 --gid 1000 \
  --offline-image --pool-guid 123 --label 0 --slot 2
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
Native LZJB, gzip-1 through gzip-9, ZLE, length-prefixed ZFS LZ4 and native
Zstandard decode to the exact declared logical length; short output, invalid
backreferences, overflow and unsupported codecs fail.
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
gzip-1 through gzip-9, ZLE, ZFS LZ4 and native Zstandard payloads must reconstruct
the exact bounded logical size. The parent block's checksum protects these bytes; there is no fabricated child checksum
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

Native Zstandard (codec 16) reads the eight-byte big-endian OpenZFS wrapper and
its magicless frame. The compressed-length field bounds exactly one complete
frame. All four historical level/version byte layouts follow the native getter
rule; normal levels 1..19 and fast-level IDs 103..123 are admitted. The producer
version remains informational, as in OpenZFS.

The existing zstd dependency decodes into a fixed logical-size output slice
through its safe API. Before a decoder context is created, the frame's advertised
window is checked against the 16 MiB budget and any declared content size must
match LSIZE. The decoder also receives the 16 MiB window parameter. Truncated
frames, dictionaries that are actually required, reserved framing, extra frames
inside the declared native length, content-checksum failures and short or long
output fail. Padding outside that native length remains covered by the full
physical-block checksum. The same transform serves physical and embedded
ordinary-file, snapshot and mounted reads.

OpenZFS registers `org.freebsd:zstd_compress` as a per-dataset feature, not a MOS
label feature. This codec addition does not broaden the label
`features_for_read` allowlist or claim full MOS/dataset feature negotiation.

A bad physical read, checksum or transform can try another declared copy on the
same leaf, another explicitly supplied member of an admitted mirror, or the
bounded ordinary RAIDZ1/2/3 reconstruction path described below.
Cancellation propagates immediately and cannot turn into a redundant-copy
retry. No copy is repaired. The uberblock's native GUID sum must match the
complete admitted configuration, including the root/pool, top-level vdev and
all configured member GUIDs when present. The selected root must be a level-zero
OBJSET pointer born no later than its uberblock and decode to a META object set.
The `root` command alone does not validate its descendants.

## Native gang-tree reads

Gang-backed roots, DMU metadata and file data use the same selected leaf,
complete mirror or ordinary RAIDZ1/2/3 owner as contiguous blocks. Native
512-byte headers retain all three child slots and the embedded SHA256 verifier
derived from the first DVA's vdev/offset and physical birth. That identity is
unchanged when a later header copy or another mirror member supplies the bytes.
RAIDZ header recovery verifies the embedded header checksum; each ordinary
fragment and interior stream has its own physical checksum. Only the complete
leader stream is decompressed, so a compressed leader's PSIZE may differ from
LSIZE without treating its fragments as independent compressed blocks.

Every header is verified and retained before any fragment payload is read.
Admission validates all declared copies against every supplied member, claims
their actual native allocation intervals, and refuses repeated or overlapping
header, fragment and replica extents anywhere in the tree. Gang DVA ASIZE counts
scattered descendants by copy; only the header's own sector allocation must fit
at its offset. This permits a valid header in the final usable vdev sector.
Expansion consumes the retained header graph without rereading it, preserves
the native replica/parity paths, and returns bytes only after all fragment,
interior and leader checksums and the exact logical-length transform succeed.
Cancellation aborts both admission and expansion immediately.

The existing limits of 32 header levels, 65,536 visited nodes and 512 MiB of
summed physical-stream work remain. An additional 256 MiB allocation budget
counts all declared DVA copies and every supplied mirror member before header
I/O, independently of PSIZE and ashift. The 16 MiB block limit, DMU type/level/
birth checks, selected snapshot bounds and per-view cache rules still apply.
No fragment creates an independent DMU cache entry. Root address and RAIDZ
diagnostics identify the verified header; they do not describe a contiguous
extent containing all gang data. The reader performs no import or backing write.

Native contracts: OpenZFS `zfs-2.3.0`
[zio.h](https://github.com/openzfs/zfs/blob/zfs-2.3.0/include/sys/zio.h),
[spa.h](https://github.com/openzfs/zfs/blob/zfs-2.3.0/include/sys/spa.h),
[vdev.h](https://github.com/openzfs/zfs/blob/zfs-2.3.0/include/sys/vdev.h),
[zio.c](https://github.com/openzfs/zfs/blob/zfs-2.3.0/module/zfs/zio.c)
and [zio_checksum.c](https://github.com/openzfs/zfs/blob/zfs-2.3.0/module/zfs/zio_checksum.c).

## Explicit mirror members and replica reads

The mirror profile accepts exactly one top-level mirror, with native vdev ID
zero and two through eight ordinary file/disk children. Every configured member
must be supplied as a read-only offline image. `--member` is repeatable, with
`--mirror-member` retained as an alias; there are no inferred paths, automatic
device discovery, missing-member or
forced/degraded admission options. The supplied order need not match the native
child order: labels identify membership by GUID. Native path strings remain
configuration metadata and are never opened on the host.

All four label configurations on each supplied member must agree on its
identity, exported state, top-level addressing, configuration TXG and allowed
read features. Every member must describe the same complete mirror tree, with
distinct member GUIDs and the native child IDs. The selected label and slot
must contain the same semantic uberblock on every member: version, TXG, GUID
sum, timestamp and complete root pointer must agree. Different valid native
container byte orders are allowed. There is no majority vote, automatic newer
candidate, rewind, or head fallback for an invalid historical selection.
Offline, faulted, removing, rebuilding, spare, nested/replacing and allocation
class topologies remain refused.

`--offset` and `--length` apply to every supplied image. This CLI profile does
not express different partition bases for different members. Omitting length
uses each file's remaining selected span; unequal member lengths are admitted
only when the common configured top-level allocation range fits every member.
The mount guard checks all supplied backing paths, including canonical aliases,
so mounting cannot hide one of the images beneath the mountpoint.

Native mirror children use the same DVA offset. Physical I/O starts at the
selected partition base plus the native 4 MiB data prefix plus that offset.
The top-level mirror supplies ashift and allocation geometry; native child
label nodes normally omit ashift/asize. DVA allocation size is the physical
size rounded to the top-level sector size, without multiplication by mirror
width. Every declared DVA must fit the configured allocation range and every
member's selected usable span, excluding the boot/front-label region and the
two end labels. These checks run for all declared copies before a good first
copy can cause success.

For each DVA, reads try the supplied members in argument order. Physical I/O,
checksum or decompression failures can try the next member and then the next
DVA. The complete physical checksum and bounded transform must succeed before
bytes are returned or admitted to a DMU cache. Cancellation stops immediately,
including before cache eviction/publication; it cannot trigger another replica
read. An all-copy failure returns an error with bounded diagnostics. `root`
reports the successful native member GUID and DVA copy index on stderr.

MOS, head and snapshot views retain the immutable pool owner, including every
member handle. Each selected object set keeps its own checked-block cache and
historical birth limits. Root reads, indirect blocks, ZAPs, legacy/SA metadata,
ordinary and embedded file data, and extraction mounts all use this same
verified read path. A failed later file block is never cached as successful;
previously verified metadata or data may remain cached. This is a bounded
extraction profile, not DTL interpretation, scrub, healing, resilver, pool
import, native write support or proof of full mirror feature coverage.

Native contracts were checked against OpenZFS `zfs-2.3.0`
[`vdev_mirror.c`](https://github.com/openzfs/zfs/blob/zfs-2.3.0/module/zfs/vdev_mirror.c),
[`vdev.c`](https://github.com/openzfs/zfs/blob/zfs-2.3.0/module/zfs/vdev.c),
[`vdev_label.c`](https://github.com/openzfs/zfs/blob/zfs-2.3.0/module/zfs/vdev_label.c),
[`vdev_impl.h`](https://github.com/openzfs/zfs/blob/zfs-2.3.0/include/sys/vdev_impl.h)
and [`spa.h`](https://github.com/openzfs/zfs/blob/zfs-2.3.0/include/sys/spa.h).

## Ordinary RAIDZ read contract

The ordinary RAIDZ profile admits one exported top-level `raidz` group
with `nparity=1`, `2` or `3`, up to eight ordinary file/disk children, and at
least one data column beyond its parity count. Every member image is supplied
explicitly. The existing complete-label and explicit
uberblock agreement checks bind all member GUIDs to one selected immutable
root. Native child IDs, rather than host argument positions, determine columns.
Expanded RAIDZ (`raidz_expanding` or `raidz_expand_txgs`), dRAID, nested
replacement/spare layouts, unsupported active features and parity counts
outside one through three remain outside this profile.

For RAIDZ1 with sector size `S=2^ashift`, physical size `P` and width `N`, stripe
data contains `ceil(P/S)` sectors and P parity contains
`ceil(ceil(P/S)/(N-1))` sectors. The DVA allocation rounds their combined
sector count up to a multiple of two. Native variable-width columns keep long
columns before short columns; the data stream concatenates data columns in
that logical column order. DVA offset bit 20 swaps the physical addresses of
the parity and first data column. Allocated skip sectors do not contribute to
parity or output. Sub-sector PSIZE padding participates in stripe I/O and XOR,
then only the original PSIZE reaches the block checksum and decoder.

All declared DVA allocation spans and all mapped child allocation extents,
including skipped padding, are validated before any data I/O. The top-level
allocation region must fit the complete selected storage set. Data columns
are read first. A checksum-valid block can succeed without reading parity;
parity-only failure therefore does not make intact data unreadable. In RAIDZ1, one known
data-column I/O failure can be reconstructed from P parity and the remaining
data. If physical reads succeed but the checksum fails, each single data-column
erasure hypothesis is attempted within the admitted width. Every result must
pass the complete original-PSIZE checksum and transform. A missing/corrupt
second required column is beyond the RAIDZ1 recovery budget. Failure may try
another declared DVA, but never another root candidate or a newer TXG.

RAIDZ2 and RAIDZ3 use native P/Q and P/Q/R parity over GF(256), respectively,
with the corresponding native column allocation and skip-sector geometry.
Recovery considers bounded erasure hypotheses up to the configured parity
count, including corrupt-but-readable parity columns. It preserves intact
data-first reads and accepts a reconstructed candidate only after the original
physical checksum and bounded transform succeed.

Cancellation propagates before further reads or reconstruction candidates.
No unverified or cancelled result enters the DMU cache. Recovery is in memory;
the backend never writes parity, repairs a member, imports the pool or changes
labels. Dataset, snapshot and extraction-mount reads share this block path.

The mapping and reconstruction contract is extracted from pinned OpenZFS
`zfs-2.3.0`
[`vdev_raidz.c`](https://github.com/openzfs/zfs/blob/zfs-2.3.0/module/zfs/vdev_raidz.c),
with alignment and leaf-label translation from
[`zio.c`](https://github.com/openzfs/zfs/blob/zfs-2.3.0/module/zfs/zio.c)
and storage geometry from
[`vdev.c`](https://github.com/openzfs/zfs/blob/zfs-2.3.0/module/zfs/vdev.c).

`--offset` and `--length` apply to every explicitly supplied RAIDZ image, just
as for mirrors. A top-level RAIDZ allocation region must contain a whole
number of member stripes; its size divided by the native width must fit each
selected member after native label/boot reservations. Child label nodes need
not carry independent ashift/asize values. All configured members must open
and agree on their labels and selected candidate even when an individual
block subsequently needs parity recovery.

Root diagnostics identify the native DVA allocation, each column's child ID,
member GUID, relative physical offset and read span, whether parity was read,
and any reconstructed native child ID. A parity stripe is never presented as
a successful single-member replica. All supplied images, including aliases,
remain subject to the extraction mount's backing-path visibility guard.

## DMU objects and DSL head inventory

`ffs-ondisk::zfs_dmu` parses object sets, allocated dnodes and micro-ZAP entries.
Dnodes preserve native bonus/spill bytes, pointer counts, allocation units and
endianness. Object lookup walks slot boundaries from the start of the containing
16 KiB dnode block: interior slots of large dnodes cannot impersonate objects.
Indirect routes use wide arithmetic rather than overflowing on high block IDs.

Each object view owns one selected root, its admitted configuration and the
complete set of read-only pool member handles.
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

The MOS pool directory is a heterogeneous typed ZAP, not a map containing only
object references. OpenZFS 2.4.1 stores a 32-byte checksum salt and TXG-history
integer arrays beside `root_dataset`. Discovery structurally validates every reached map
entry and chunk, then requires exactly one 8-byte integer only for the selected
`root_dataset` key. An array, empty value or byte-width root reference still
fails, as does a malformed unrelated array; scalar-only DSL child maps retain
their existing contract. Native evidence on CSD exposed the prior whole-map
scalar conversion failure. See OpenZFS's
[MOS key definitions](https://github.com/openzfs/zfs/blob/zfs-2.4.1/include/sys/dmu.h)
and [checksum-salt storage](https://github.com/openzfs/zfs/blob/zfs-2.4.1/module/zfs/spa.c).
The correction's constructed and native qualification is pending.

An uninitialized DSL head, including native `$ORIGIN`, has an entirely zero
object-set block pointer. Inventory preserves that head with
`objectset_kind: null` and its native zero `root_birth`; it does not claim an
empty filesystem or discard the internal dataset. Referenced, compressed,
uncompressed and unique byte counters must all be zero. Every existing
directory/backreference, GUID, creation-TXG and state check still applies.
Initialized heads retain the complete physical-size, pointer, checksum and
object-set validation. ZPL, zvol and ZIL reads require an initialized object set.
OpenZFS's [origin creation](https://github.com/openzfs/zfs/blob/zfs-2.4.1/module/zfs/dsl_pool.c)
creates the head and origin snapshot without initializing data. Native
qualification of this newly modeled state remains pending.

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

`ls`, `stat`, `read`, `readlink`, `listxattr` and `getxattr` select a head through the validated DSL
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
from regular-file content. Reparse/offline providers remain refused. Private
xattr objects are accessible only through the owner-checked xattr traversal
below, never through ordinary lookup/stat/read. Metadata reports native mode, IDs, link count, creation
generation, allocation accounting and four timestamps, including signed seconds
and nanosecond precision. This is offline extraction, not host SID/FUID/ACL
mapping or permission enforcement, and no mode/owner mutation is offered.

ZPL requests are capped at 16 MiB; CLI extraction streams 1 MiB chunks. Paths
are capped at 64 KiB and 256 components, names at 255 bytes, symlink output at
64 KiB, directory result payloads at 32 MiB. SA registries/layouts are capped at
4,096 registered entries, 1,022 stored layouts, 65,536 layout items, and 128 KiB
per bonus/spill buffer. These are admission budgets, not format maxima or a
whole-process memory limit. Reads describe the selected committed root by
default. Explicit `--replay-zil` on a head dataset stages admitted intent-log
operations in a private in-memory ZPL view, including native hard links and
shared data after unlink or rename. Named snapshot reads retain their selected
committed root. See [ZIL recovery](ZFS_ZIL_TOPOLOGY_PROFILE.md#zpl-namespace-recovery-and-hard-links)
for record admission, failure behavior and the distinction from single-file
recovery. No recovery path here writes a pool or certifies native durable replay.

## Native user extended attributes

The same selected head or named snapshot now serves `listxattr` and `getxattr`
through the CLI and extraction mount. Directory storage follows the owner's
native `ZPL_XATTR` reference, checks the private directory's kind and owner,
then checks each private regular value file's type, flags, generation and parent.
Directory references retain the native low-48-bit object/type encoding. Value
bytes use the existing checked DMU reader, including sparse zeroes, compression,
historical birth ceilings, checksums, explicit redundant members and cancellation.

SA storage reads dataset-registered `ZPL_DXATTR` from bonus and checked spill
buffers. Its value must be exactly one XDR nvlist of native byte-array pairs.
Byte arrays use opaque bytes and four-byte padding, without the extra count
used by numeric arrays. Wrong value types, duplicate packed names, truncated
spans, nonzero XDR padding and trailing bytes fail. Labels retain their separate
allocation-padding rule.

Only user names are exposed. Native lookup priority is prefixed SA, prefixed
directory, unprefixed compatibility SA, then unprefixed compatibility directory.
An exact name present in both stores is valid and SA takes priority. Listing
returns sorted, unique host names; compatibility aliases are deduplicated.
`security.`, `system.`, `trusted.` and `freebsd:` attributes are not projected.
A reserved namespace inside a requested `user.` suffix is rejected, so a user
alias cannot retrieve a privileged native name.

Both catalogs are admitted before any successful list/get result. Names must
fit the lossless UTF-8 host interface and its 255-byte limit, including an added
compatibility prefix. There are at most 4,096 native names across both stores
and 64 KiB of returned names including terminators. A get returns at most
64 KiB, preserves binary and empty values, and distinguishes an empty value
from absence. Larger directory values can be listed but cannot be extracted by
this interface. CLI get stages the complete value before writing stdout; a bad
selected value never falls back to another spelling or the live head.

These are extraction semantics with the mount's existing synthetic ownership.
Native ACL/FUID enforcement, privileged namespace projection and xattr mutation
remain outside this profile.

## Read-only extraction mounts

`mount` uses the same explicit pool GUID, label and uberblock slot as extraction.
It validates the selected head or snapshot, its root directory and the root's
children before starting FUSE. A missing or invalid snapshot cannot fall back to
the head. The mount owns its read-only image handles and selected object-set view;
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

User xattr list/get use the shared native storage traversal above. Special
files, native ACL/privileged xattr projection and pool free-space reporting
(`statfs`) remain explicitly unsupported. A reached directory containing a special file fails
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

Extraction requires all four configurations on every supplied image to validate
and agree on pool/member identity, addressing, configuration generation and
read features. The pool must be exported and have one top-level file/disk leaf
or a complete two-to-eight-member mirror or ordinary RAIDZ1/2/3 group described
above, with native ID zero and no removal, special or log state. Versions 1..28 or 5000 are admitted.
Version 5000 requires
no label read features beyond optional `org.illumos:lz4_compress` and
`com.delphix:embedded_data`, encoded as boolean-presence fields. Unknown features
and wrong value types still fail admission. This is not full MOS feature
negotiation or pool import.

The selected uberblock cannot predate label configuration. Fork/history
resolution, rewind, active/MMP ownership and multi-vdev import remain separate
work. Encrypted/authenticated blocks remain unsupported;
context-sized holes are handled only in the DMU traversal, not root extraction.
Expanded RAIDZ, dRAID, nested/replacing or incomplete redundant groups,
indirect vdevs,
normalized/binary ZAP keys, full ZPL/SA feature coverage, full snapshot/clone
semantics, security, native writes, maintenance and
MVCC/RaptorQ integration remain incomplete. Neither dataset inventory nor the
restricted ZPL reader is a full ZFS-support claim.

Other budgets: 16 MiB logical/physical blocks; 112 KiB label configurations;
8,192 nvlist items, depth 16 and 4 KiB config strings; 512..16,384-byte dnodes,
1..3 root pointers, at most 12 levels, 4..128 KiB indirect blocks; micro-ZAPs up
to 128 KiB. Ashift 9..16 is recognized with the native 8 KiB uberblock stride cap.
These are implementation bounds, not maximum sizes of the native filesystem.

## Validation and evidence

On 2026-10-21, the file and snapshot profiles both passed on OpenZFS 2.4.1
using the companion and standalone public `ffs` consumer built from
`bd2fac9c4b1ec7e06bb39a7ff52922e4757e6b20`. Each covered ZPL 4 and 5 on a
plain exported leaf and a bounded partition. Native file bytes, stat fields,
directory names, head/before/after snapshot identities and contents, sparse
tails and unchanged backing hashes were checked. The public consumer also
required write refusal and missing-snapshot refusal; the file profile used a
real external host canary for symlink refusal. Snapshot invocations use separate
processes, and the example clamps EOF using metadata. No FrankenFS FUSE mount,
same-instance cache, striped-mirror native or field acceptance is implied.

Retained CSD roots are
`/data/ssd/tmp/ffs-native-verification-7CWV8iQw/ffs-zpl-native-5v585dlk` and
`/data/ssd/tmp/ffs-native-verification-7CWV8iQw/ffs-snapshots-native-wxggvr7a`.
Their `result.json` and per-command argv/stdout/stderr/status accompany every
native image and oracle. Companion SHA256 is
`1a6544a12f5dde8f14d0660e4a9875c3e5cce8ba04295ab64b0116160e9029f1`;
public consumer SHA256 is
`41e55bd78bae93298a3ecdd11a0784fa88b155c4f070848c64ffa21e316cf0f3`.
The native failures preceding these passes are retained separately: MOS maps
contain arrays beside `root_dataset`, and the native `$ORIGIN` head has no
initialized object set. Current selection validates all reached structure,
interprets only the required scalar reference and inventories an uninitialized
head without granting it data-read authority. At merged `ff3dca7ec`, the full
workspace/all-target check, strict Clippy, all 315 ZFS unit tests and one
compiled doctest passed. Historical authoring-only
evidence below describes the limits at the time of each earlier increment.

Engine tests have moved into the `ffs-zfs` library, with separate CLI tests;
these current verification commands do not imply a new execution result.

```sh
rch exec -- cargo test -p ffs-ondisk zfs
rch exec -- cargo test -p ffs-zfs
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

Mirror authoring evidence (2026-10-11): eleven constructed engine regression
functions cover widths two, three and eight; both byte orders; ashift 9, 12 and
16; raw/LZ4 roots; GUID membership independent of input order; unequal valid
member spans; all-label and selected-candidate disagreement; unsupported
states/topologies; all-member bounds; checksum and physical-I/O replica
fallback; all-copy failure; cancellation; and successful-copy diagnostics.
Complete label-to-MOS-to-ZPL fixtures exercise legacy and SA/spill metadata,
embedded and ordinary data, mounted reads, historical cache isolation and a
later historical block cancellation without another replica or head fallback.
Backing devices reject every write or flush. Companion CLI regressions cover
explicit member arguments, input limits and all-image mountpoint guards.
The complete new mirror source and fixtures were parsed and formatted by
rustfmt in an isolated checkout. CLI test attempts were killed while compiling
the asupersync dependency under the shared memory limit, including a
single-threaded retry. No mirror Rust execution, full CLI typecheck, kernel
FUSE mount or native OpenZFS mirror comparison is claimed. Source review and
formatting do not replace those runtime gates.

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

## Native Zstandard validation

Ten regressions cover published raw, compressed-sequence, literal-only and
multiblock RLE vectors; all native levels and four historical header layouts;
truncation, native lengths and exact LSIZE; content sizes and memory windows;
dictionary requests, wrong framing, reserved fields and trailing frames;
content-checksum damage; physical padding with all four admitted checksum
algorithms; and physical/embedded dispatch across both container and payload
byte orders. The GZIP unsupported-codec test uses neighboring unsupported ID 17
now that ID 16 has an implementation; its admission and failure assertions
remain intact.

Delivery evidence (2026-10-11): complete source blobs and their exact changes
received independent review. Fixture bytes match the pinned Go examples and
Zstandard binary goldens; their output layouts and the constructed mixed
compressed/RLE block were checked separately through a small read-only fixture
decoder. Those checks do not execute the Rust implementation or establish
native pool interoperability. Rust compilation, these ten tests, formatting,
workspace checks, Clippy, UBS and native-image execution remain unavailable
because the authoring executor is offline.

Native framing and feature references:
[OpenZFS Zstandard metadata](https://github.com/openzfs/zfs/blob/zfs-2.3.0/include/sys/zstd/zstd.h),
[OpenZFS codec](https://github.com/openzfs/zfs/blob/zfs-2.3.0/module/zstd/zfs_zstd.c),
[OpenZFS feature registration](https://github.com/openzfs/zfs/blob/zfs-2.3.0/module/zcommon/zfeature_common.c),
and [MOS label fields](https://github.com/openzfs/zfs/blob/zfs-2.3.0/module/zfs/vdev_label.c).
Independent vectors and format:
[Go Zstandard examples](https://github.com/golang/go/blob/go1.24.0/src/internal/zstd/zstd_test.go),
[Zstandard golden vectors](https://github.com/facebook/zstd/tree/v1.5.7/tests/golden-decompression),
and [Zstandard framing specification](https://github.com/facebook/zstd/blob/v1.5.7/doc/zstd_compression_format.md).
The implementation uses the existing pinned zstd 0.13.3 / zstd-safe 7.2.4 dependency;
no new package versions or experimental API features are introduced.

### Bounded Zstandard header execution validation

The decoder now reads the native frame's window and optional content size before
restoring magic bytes, copying the frame or constructing a libzstd context. This
preserves FrankenFS's 16 MiB budget even when a header exceeds libzstd's own
window limit. An explicitly stored 64-bit content size must match LSIZE; values
such as UINT64_MAX can no longer alias the library's "content size unknown"
status and bypass the declared-size comparison. Dictionary-ID field widths and
the native two-byte content-size bias are decoded before locating these fields.
The existing header, frame extent, dictionary, checksum and output checks remain.

The original ten Zstandard regressions are retained. An eleventh covers explicit
64-bit sizes in both frame forms, all zero dictionary-ID widths, valid output
and extreme values including both native sentinel values. The complete
`cargo test -p ffs-ondisk --lib --locked` run passed 838 tests, including all
eleven Zstandard and twelve NTFS security tests, with one compiler thread.
`cargo clippy -p ffs-ondisk --all-targets --locked -- -D warnings` also passed.
Changed Rust sources were parsed/formatted. The installed UBS launcher could
not execute (permission denied); no UBS result is credited. Integrated CLI and
native pool/mount execution remain unverified under the previously recorded
resource and tool limits. These parser results do not qualify mirror mounts.

## Ordinary RAIDZ1 validation

Six pure mapping/reconstruction regressions cover native child rotation,
variable-width short columns, parity address swapping, skip sectors, PSIZE
versus sector padding, geometry and overflow refusal, exact input spans and
single-column XOR recovery. Their expected address table contains twenty
captures from the unmodified OpenZFS `zfs-2.3.0` `vdev_raidz_map_alloc`
function compiled in an isolated C harness. The harness and captured output
executed successfully; the Rust mapper matches every captured tuple. This is
native-function evidence, not a pool imported or mounted by OpenZFS.

Twelve authored engine regression functions exercise labeled, bounded member
images: native GUID order independent of supplied order, two through eight
members, both byte orders, ashift 9/12/16, compressed PSIZE padding, data-first
reads, checksum and physical-I/O reconstruction, parity-only failure, two-column
failures, another declared DVA, immediate cancellation, expanded/unsupported
topology, capacity, later-DVA and label disagreement refusals. Constructed MOS,
DSL, legacy/SA/spill ZPL, embedded-data and historical snapshot graphs are
re-encoded bottom-up with native stripe placement and newly checksummed parent
pointers. FsOps reads preserve hardlinks, holes, unaligned EOF, snapshot names
and historical bytes; failed or cancelled blocks cannot become cache entries
or a successful partial request. Read-only test devices panic on writes or
flushes.

Execution evidence (2026-10-12): the full
`cargo test -p ffs-ondisk --lib --locked` suite passed 850 tests, including all
six RAIDZ tests and all twenty captured mapping cases. Integrated engine/CLI
typechecking and these twelve graph tests remain unexecuted: the complete
dependency graph is still blocked by `asupersync` compiler SIGKILL under the
shared memory limit. No CLI, kernel FUSE or native RAIDZ-pool execution is
claimed from the parser tests, mapping capture or source review.

Final integration evidence (2026-10-12):
`cargo clippy -p ffs-ondisk --all-targets --locked -- -D warnings` completed with
exit 0 on the combined XPRESS/RAIDZ sources. All changed Rust files passed
parsing/formatting checks; independent production and fixture/API reviews found
no remaining concrete defect. The generic-member CLI retains its existing count
and mountpoint guard assertions and adds one regression combining all three
option spellings in a single ordered member set. A fresh
`cargo check -p ffs-cli --all-targets --locked` retry still stopped in `asupersync`
with SIGKILL, before checking the integration code. Workspace formatting reports
pre-existing differences in 13 unchanged files. UBS could not execute its
installed launcher. The new engine and CLI tests remain source-reviewed only.

## Native user xattr validation

Eleven authored regression functions cover native XDR byte-array goldens,
zero/large binary values, strict packed-value bounds, arbitrary SA registration
IDs and independent bonus/spill byte orders. Constructed MOS/DSL/ZPL graphs
exercise directory and SA/bonus/spill storage in both byte orders, native name
precedence, hard links, private-object and parent validation, UTF-8/name budgets,
64 KiB value bounds, corruption and cancellation. A corrupt prefixed directory
value has a valid raw SA alternative and must still return an error. Historical
snapshot graphs reuse native object numbers while retaining distinct attribute
bytes through both direct ZPL and FsOps reads. Existing missing-xattr mount
assertions now require an empty list and absent value; privileged names still
require refusal.

Authoring evidence (2026-10-12): complete source and native semantics received
independent review. The shared executor disconnected while Cargo was compiling
dependencies, before any FrankenFS crate or new regression ran. These eleven
tests, final-tree compilation, rustfmt/Clippy, kernel FUSE and native pool
comparisons are unexecuted; the earlier parser-suite results above do not cover
this increment.

Native contracts: OpenZFS `zfs-2.3.0`
[zpl_xattr.c](https://github.com/openzfs/zfs/blob/zfs-2.3.0/module/os/linux/zfs/zpl_xattr.c),
[zfs_sa.c](https://github.com/openzfs/zfs/blob/zfs-2.3.0/module/zfs/zfs_sa.c),
[zfs_sa.h](https://github.com/openzfs/zfs/blob/zfs-2.3.0/include/sys/zfs_sa.h),
[zfs_dir.c](https://github.com/openzfs/zfs/blob/zfs-2.3.0/module/os/linux/zfs/zfs_dir.c),
[nvpair.c](https://github.com/openzfs/zfs/blob/zfs-2.3.0/module/nvpair/nvpair.c)
and [namespace prefixes](https://github.com/openzfs/zfs/blob/zfs-2.3.0/include/sys/fs/zfs.h).

## Gang admission and complete filesystem validation

The existing thirteen native header/parser and seventeen engine gang regression
functions are preserved. Five additional engine regressions cover checksummed
duplicate fragment allocations, partial/header/replica overlaps, malformed or
cancelled later nested headers before early payload I/O, allocation budgets
including ditto and mirror copies, and real trees at the 32/33-level boundary.
The positive boundary fixture also requires each retained header to be read
exactly once before any payload. Four new complete MOS/DSL/ZPL/FsOps graph
regressions cover both byte orders, RAIDZ1/2/3, legacy and SA/spill metadata,
gang-backed 1024-byte file blocks, hard links, holes, EOF, cache reuse, multiple
historical snapshots and independent historical cache/birth limits. A later
fragment failure or cancellation must return an error without a partial block
cache entry or substitution of head data.

Execution evidence (2026-10-12): all thirteen unchanged upstream gang-parser
tests passed in a bounded Rust harness using the exact production gang module,
its original parent ZFS functions and test source, and real `ffs-types`, `sha2`,
`flate2` and `zstd` dependencies. Unrelated nvlist/RAIDZ modules and other test
registrations were omitted from that harness; no model parser types replaced
production code. This verifies the parser cohort, not the physical reader.

Authoring evidence (2026-10-12): all eleven changed Rust files passed the pinned
nightly formatter and its check mode. The complete admission/expansion source
and native allocation/checksum contracts received independent review. Full CLI
and focused reader build attempts were killed in dependencies under the shared
memory limit, before checking this runtime increment. These nine new engine and
graph tests remain unexecuted; the fixtures do not establish native-pool
interoperability or kernel FUSE behavior.
