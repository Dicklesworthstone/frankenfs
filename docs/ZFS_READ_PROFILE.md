# Experimental native ZFS block-reading foundation

`ffs-zfs` starts the ZFS-01/ZFS-02 work in the comprehensive expansion plan.
It inspects native vdev labels and uberblocks and extracts an explicitly selected,
checksum-verified META object-set root from a restricted single-leaf image.
It is NOT a pool importer, ZPL filesystem, dataset reader or FUSE backend.
No existing ext4, btrfs, FAT or NTFS dispatch is changed.

## Commands

Build using the repository's prescribed toolchain/RCH workflow:

```sh
rch exec -- cargo build -p ffs-cli --bin ffs-zfs

ffs-zfs inspect leaf.img --offline-image

# Read the pool GUID, label index and candidate slot from inspect.
# These sample numbers are placeholders, not a request to choose a TXG for you.
ffs-zfs root leaf.img --offline-image --pool-guid 123 --label 0 --slot 2 > mos-root.bin

# Every offset, including native checksum verifiers, is relative to this vdev.
ffs-zfs inspect disk.img --offline-image --offset 1048576 --length 134217728
```

`inspect` inventories configurations and candidate slots. It reports rejected
labels and the number of empty/invalid/unsupported slots; this is not a global
integrity pass. It does not select the highest TXG or certify root authority.
`root` requires explicit pool GUID, label and slot, then stages the whole checked
root before writing stdout. A host stdout error can still leave a partial output
file. No read failure produces a successful unchecked root.

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
single-leaf configuration, including the root/pool GUID. The selected root must be a level-zero OBJSET
pointer born no later than its uberblock and decode to a META object set.
Checking this root does not validate its complete dnode/indirect/MOS descendants.

## Explicit admission limits

All input opens use read-only handles to regular offline files. The caller must
keep the image immutable; shared advisory locks do not exclude unrelated writers
or kernel mounts. There are no writes, flushes, label repairs, TXG publication,
log replay, implicit native imports or host paths taken from a label.

Root extraction currently requires all four label configurations to validate
and agree on pool/leaf identities, addressing, configuration generation and read
features. The pool must be marked exported and have one top-level file/disk leaf
with ID zero, no removal/special/log state, and supported feature requirements.
Version 1..28 or 5000 is admitted; version 5000 requires a label read-feature
catalog containing no requirements other than optional `org.illumos:lz4_compress`,
encoded as a native boolean-presence field, not an integer reference count.
This is a deliberately narrow root-inspection profile, not complete feature
negotiation. A later required feature in the MOS is not made safe by this check.

The selected uberblock cannot predate the label's configuration. Fork/history
resolution, rewind, active/MMP ownership and multi-vdev import remain separate
work. Gang, embedded, encrypted/authenticated and context-sized hole blocks are
not routed through the regular-block decoder. RAIDZ, mirrors as topologies,
indirect vdevs, dataset/snapshot/ZAP/ZPL traversal, ZFS security, pool maintenance,
native writes and MVCC/RaptorQ integration remain incomplete.

Read budgets: 16 MiB logical/physical blocks; 112 KiB label configurations;
8,192 nvlist items (including nested-list array work), depth 16 and 4 KiB config
strings. Ashift 9..16 is recognized with the native 8 KiB uberblock stride cap.
These are implementation limits, not the limits of the native filesystem.

## Validation and evidence

```sh
rch exec -- cargo test -p ffs-ondisk zfs
rch exec -- cargo test -p ffs-cli --bin ffs-zfs

# Requires usable native ZFS and explicit permission to create fresh scratch pools.
python3 scripts/verify_zfs_root.py --binary target/debug/ffs-zfs --create-scratch-pool
```

The runner creates only new random-named file pools, without force/import/destroy
or dataset mounts. It exports them, retains all images/logs, compares candidate
root bytes against native `zdb -R` output at ashift 9 and 12, repeats extraction
inside a bounded partition, and checks whole-image hashes. The runner's selection
of a candidate on its own fresh exported fixture is not an import-selection
algorithm in FrankenFS. Missing tools, layout refusal and native disagreement
are failures, never skipped passes. Native zdb decompression guessing must return
the exact expected logical byte count and match the candidate; no assertion or
native error is suppressed.

Initial authoring evidence: Python hashlib generated fixed offset-salted SHA256
vectors; the system liblz4 independently decoded two match vectors and generated
two compressed root fixtures. Python runner syntax and help were checked. These
checks do not execute the Rust parser, reader or a native ZFS pool. Rust/Cargo/RCH,
rustfmt/Clippy and native ZFS execution were unavailable here. The added Rust and
native-runner tests are not passing conformance claims.

Reference layout: OpenZFS tag `zfs-2.3.0`, especially `include/sys/spa.h`,
`vdev_impl.h`, `uberblock_impl.h`, `dmu_objset.h`, `module/nvpair/nvpair.c`,
`module/zfs/zio_checksum.c`, `sha2_zfs.c`, `lzjb.c` and `lz4_zfs.c`.
