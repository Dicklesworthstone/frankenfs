# Experimental native ZFS block and DMU reading

`ffs-zfs` implements the restricted ZFS-01/ZFS-02 foundation and starts ZFS-03
from the comprehensive expansion plan. It inspects labels and explicit uberblock
candidates, extracts checked roots and MOS object ranges, and inventories DSL
head datasets through supported metadata layouts. It is NOT a pool importer,
ZPL file reader or FUSE backend. No ext4/btrfs/FAT/NTFS dispatch is changed.

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

# All native checksum verifiers and DVA addresses remain vdev-relative.
ffs-zfs inspect disk.img --offline-image --offset 1048576 --length 134217728
```

`inspect` inventories configurations and candidate slots. It reports rejected
labels and empty/invalid/unsupported slots, not a global integrity pass. It does
not select the highest TXG or certify root authority. All extraction commands
require the explicit candidate and stage the requested output before stdout.
A stdout error can still leave a partial host file; a storage/checksum failure
cannot produce a successful unchecked extraction.

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

A view retains up to 32 fully checked blocks and 16 MiB of block bytes, keyed by
the complete pointer. Views do not share caches across roots. In-flight output,
clones and bookkeeping are outside this retention limit. Requests check
cancellation on cached paths as well as physical reads. No performance number
is claimed without executed measurements.

`object` reports a dnode and raw bonus bytes. `object-read` requires an explicit
byte count of at most 16 MiB and rejects ranges beyond dn_maxblkid geometry.
It does not mistake allocation capacity or bonus data for a ZPL file's EOF.
`zap` enumerates complete, unnormalized micro-ZAPs, preserving raw name bytes;
fat-ZAPs, duplicate keys and unterminated names are errors, not empty maps.

`datasets` follows the pool directory's root_dataset, DSL child maps, directory
bonus records and head dataset bonus records. It checks parent/backreferences,
duplicate or cyclic directory/head identities, state flags, GUIDs and creation
TXGs, then verifies and parses every reported head's object-set root. Filesystem
and volume object-set kinds are reported, but neither is mounted or exposed as
a ZPL file or zvol. Names are relative to the pool; the root has an empty name.
Raw component arrays accompany lossless UTF-8 names. Internal DSL directories
are not silently discarded. Snapshots and clone relationships are not enumerated.

The inventory is bounded to 4,096 DSL directories, depth 64 and 1 MiB cumulative
path bytes. A corrupt or unsupported reached map fails the entire inventory;
there is no partial-success list. DSL directory/dataset bonus layouts must be
256/320 bytes; extensified ZAP-typed dnodes are recognized, but their extra
properties and full feature obligations are not interpreted by this inventory.

## Explicit admission limits

All input opens use read-only handles to regular offline files. The caller must
keep the image immutable; shared advisory locks do not exclude unrelated writers
or kernel mounts. There are no writes, flushes, label repairs, TXG publication,
log replay, implicit native imports or host paths taken from a label.

Extraction requires all four configurations to validate and agree on pool/leaf
identity, addressing, configuration generation and read features. The pool must
be exported and have one top-level file/disk leaf with ID zero and no removal,
special or log state. Versions 1..28 or 5000 are admitted. Version 5000 requires
no label read features beyond optional org.illumos:lz4_compress, encoded as a
boolean-presence field. This is not full MOS feature negotiation or pool import.

The selected uberblock cannot predate label configuration. Fork/history
resolution, rewind, active/MMP ownership and multi-vdev import remain separate
work. Gang, embedded and encrypted/authenticated blocks remain unsupported;
context-sized holes are handled only in the DMU traversal, not root extraction.
RAIDZ/mirror topologies, indirect vdevs, fat-ZAP, ZPL/SA file interpretation,
snapshot reads, security, native writes, maintenance and MVCC/RaptorQ integration
remain incomplete. Dataset inventory is not a full ZFS-support claim.

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
```

The native runner creates only new random-named file pools without force,
import, destroy or dataset mounts. It exports them and retains all images/logs.
It compares root bytes against zdb -R at ashift 9 and 12 and compares DSL head
names/GUIDs with native zfs list captured before export. Both are repeated inside
a bounded partition, with whole-image hashes checked. Candidate selection on
this fresh fixture is not a FrankenFS import algorithm. Missing tools, layout
refusal and disagreement fail instead of earning skipped-test credit.

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

Reference: OpenZFS tag zfs-2.3.0, especially spa.h, vdev_impl.h,
uberblock_impl.h, dnode.h, dmu_objset.h, zap_impl.h, dsl_dir.h, dsl_dataset.h,
nvpair.c, zio_checksum.c, sha2_zfs.c, lzjb.c and lz4_zfs.c.
