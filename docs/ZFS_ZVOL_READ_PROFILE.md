# Native ZFS volume read profile

The ZFS reader exposes an immutable native volume dataset through `Zvol` and
`ffs_block::ByteDevice`, plus three CLI commands. This is not a ZPL file, a FUSE
regular-file emulation, a host `/dev/zvol` device, or a writable volume engine.
It reads committed object-set state only; pending ZIL intent is not replayed.

```sh
ffs-zfs zvol-info first.img --offline-image --auto-import --dataset vm/disk
ffs-zfs zvol-read first.img --offline-image --auto-import --dataset vm/disk \
  --snapshot before --start 510 --bytes 600
ffs-zfs zvol-seek first.img --offline-image --auto-import --dataset vm/disk \
  --snapshot before --start 4096 --kind data
```

Use existing `--pool-guid`, `--label`, `--slot`, `--member`, `--offset` and
`--length` options for explicit candidate, member and partition selection.
`--dataset` is required; it is relative to the selected pool, never a host path.
Snapshot names are exact native byte strings and use the same checked name-map,
predecessor-chain, origin and birth rules as filesystem snapshots. Missing or
unsupported snapshots never select the live head. Volume metadata includes both
pool and selected-view TXGs, dataset GUID, root birth, capacity and block size.

The pinned layout is OpenZFS `zfs-2.3.0`, `include/sys/zvol.h` and
`module/zfs/zvol.c`: data object 1 has type DMU_OT_ZVOL (23); property object 2
has type DMU_OT_ZVOL_PROP (24). Capacity is its scalar uint64 `size` property;
block size is the data dnode's block size. Require positive capacity divisible
by a power-of-two block size between 512 bytes and the existing 16 MiB limit.
Neither dn_maxblkid nor allocation accounting is EOF. Sparse tails remain zero
without invented physical reads; allocation beyond a shrunken capacity cannot
be read through this interface. Each selected snapshot supplies its own capacity.

Every reached pointer uses the existing DMU, native checksum/decompression,
embedded/gang/hole-birth and topology-validation pipeline. Volume allocation
queries share the sparse-seek implementation; they do not scrub data payloads.
They return ENXIO when no data exists, or when the start is at/past capacity.
The implicit terminal hole is at capacity. The byte API accepts unaligned
ranges; any future sector frontend must impose its own sector policy.

`Zvol::read` returns an exact range or an error. Scalar and vectored ByteDevice
reads stage at most 16 MiB per call and preserve all destination bytes on any
error, including later-block checksum failure and cancellation. No fallible
operation follows destination publication. Sequential reads reuse the pinned
view's cache; concurrent ByteDevice calls use fresh request-local caches sharing
only immutable pool handles. No blocking cache mutex or global history cache is
introduced. Writes return ReadOnly; sync checks cancellation without flushing
backing devices. Underlying images must remain immutable throughout use.

CLI extraction streams verified ranges in 1 MiB chunks to binary stdout, with
no newline or JSON mixed into the byte stream. An explicit range crossing capacity
is rejected, not silently truncated. Omitting `--bytes` reads the remaining
capacity. A later failure may leave an earlier verified prefix in stdout: discard
all output unless the command exits successfully. Output failures are errors.
Read-only volume commands refuse sidecar healing before opening any image.

Not implemented: host block-device registration, writable import, ZIL recovery,
creation, resizing, destruction, TRIM, volume property mutation, or native
write/flush durability. The ByteDevice adapter is a bounded internal frontend,
not a claim of complete ZFS-09 lifecycle or operating-system block-driver parity.

## Validation status

The two implementation commits add ten constructed-MOS engine regression
functions, three CLI/range/refusal tests, and three complete label/mirror/RAIDZ
volume tests. They exercise both byte orders, sparse capacity, independent head
and snapshot roots/sizes, embedded compressed data, damaged replicas, native
parity recovery, malformed metadata and terminal cancellation. These are authored
Rust tests, not executed proof of native-pool interoperability.

The authoring environment has no Cargo, rustc or rustfmt; the attempted Rust
command exits 127. Source hashes and targeted whitespace checks are verified,
but compilation, Rust test passage, Clippy and native OpenZFS validation are not.
Run the pinned workspace tests and compare read ranges, capacities and snapshots
against volumes created by the pinned OpenZFS version before claiming support:

Engine tests have moved into the `ffs-zfs` library, with separate CLI tests;
these current verification commands do not imply a new execution result.

```sh
rch exec -- cargo test -p ffs-zfs --lib -- zvol
rch exec -- cargo test -p ffs-cli --bin ffs-zfs
rch exec -- cargo check --workspace --all-targets
rch exec -- cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```
