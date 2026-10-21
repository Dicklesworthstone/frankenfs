# Experimental native ZFS snapshot reads

This extends `ZFS_READ_PROFILE.md` with explicitly selected historical roots.
The existing candidate-selection, single-leaf, immutable-image, checksum,
transform and ZPL policy limits still apply. This is neither a pool import nor
snapshot creation, destruction, rollback, replication, repair or log replay.

```sh
ffs-zfs snapshots leaf.img --offline-image --pool-guid 123 --label 0 --slot 2 --dataset data
ffs-zfs ls leaf.img / --offline-image --pool-guid 123 --label 0 --slot 2 --dataset data --snapshot before
ffs-zfs stat leaf.img /file.bin --offline-image --pool-guid 123 --label 0 --slot 2 --dataset data --snapshot before
ffs-zfs read leaf.img /file.bin --offline-image --pool-guid 123 --label 0 --slot 2 --dataset data --snapshot before
ffs-zfs readlink leaf.img /link --offline-image --pool-guid 123 --label 0 --slot 2 --dataset data --snapshot before
ffs-zfs mount leaf.img /mnt/zfs-before --offline-image --pool-guid 123 --label 0 --slot 2 --dataset data --snapshot before --uid 1000 --gid 1000
```

Sample identities are placeholders. `--dataset` remains a relative head name;
`--snapshot` is one exact stored component, not `dataset@snapshot`, a host path,
a bookmark or a request to select another pool TXG. Missing or corrupt snapshot
selection fails: it never falls back to live head bytes. Omitting the option
retains the original head-read behavior. Snapshot maps can contain distinct
case variants; selection is exact, not case folded.

`mount` exposes the exact selected historical root through the read-only
extraction backend documented in [ZFS_READ_PROFILE.md](ZFS_READ_PROFILE.md).
The mountpoint must already exist and be empty. Each mount owns its view and
cache, so mounting a head and a snapshot independently does not mix their
namespaces or data. Host ownership and modes are synthetic; pool import,
native ACL enforcement, xattrs and `statfs` are outside this mount's profile.

## Native identities and historical bounds

Enumeration reconciles the head's native name ZAP with its complete local
predecessor chain. Each named record must be a snapshot owned by the same DSL
directory, with a matching successor, creation TXG and unique GUID. Missing,
unlisted, cyclic, aliased and foreign records fail the inventory. Every reported
root passes the existing type/size/birth/checksum pipeline and object-set parser.
A root newer than its snapshot is invalid even if its physical checksum matches.

The walk stops at the directory's recorded origin, which can be the pool's
hidden origin or a clone origin. A non-primary branch must be present in the
native next-clones map with matching identity and child count. The origin is not
exposed as a locally named snapshot; clones, promotion and foreign snapshot
namespaces are not recursively enumerated. Old layouts without the required
branch catalog are refused rather than guessed. Deferred-destroy snapshots can
still be read when their named roots are retained and valid.

Each opened snapshot has its own object-set root, SA registry, naming policy
and bounded DMU cache. Its block-birth ceiling is its native creation TXG, not
the later pool candidate. Equal file-object numbers in head and snapshot views
therefore cannot select each other's cached bytes. File reads, metadata,
hard links, sparse EOF and symlink inspection reuse the existing ZPL reader.

JSON `txg` identifies the selected pool candidate. File `view_txg` identifies
the head candidate or the snapshot creation TXG; `dataset_guid` is the native
GUID of that selected head/snapshot record. `snapshot`/`snapshot_name_bytes`
identify the requested historical view. Snapshot inventory reports each native
record number, GUID, creation time/TXG, root birth and referenced-byte accounting.
These values are not writable allocation authority or current free-space counts.

## Naming and resource limits

OpenZFS snapshot-name ZAPs use TOUPPER normalization even on case-sensitive
filesystems. The explicitly enabled snapshot path supports unnormalized maps
and the ASCII subset of TOUPPER-only maps. Fat-ZAP hashes are recomputed from
uppercase ASCII while names keep their original bytes. Generic metadata/ZPL
parsers keep their existing unnormalized admission. Non-ASCII normalized names,
other Unicode normalization, binary keys and case-insensitive ZPL snapshots
remain refused. This is not full Unicode snapshot-name parity.

At most 4,096 snapshots and 1 MiB of snapshot-name bytes are inventoried per
head. Existing per-ZAP work/results and per-view block-cache limits remain;
these are not a total-process memory cap. A failed map or historical root does
not produce a partially successful inventory. The original image must remain
unchanged for the entire read session.

## Validation

Engine tests have moved into the `ffs-zfs` library, with separate CLI tests;
these current verification commands do not imply a new execution result.

```sh
rch exec -- cargo test -p ffs-zfs -p ffs-ondisk --lib
rch exec -- cargo test -p ffs-cli --bin ffs-zfs
python3 scripts/verify_zfs_snapshots.py --binary target/debug/ffs-zfs --create-and-mount-scratch-pool
```

The native runner creates only fresh random file pools, with ZPL versions 4 and
5. It records two native snapshots, overwrites the same hard-linked file in place,
renames a file out of the live namespace, and changes sparse EOF. It checks the
native historical bytes after the head diverges, exports, then compares candidate
snapshots/GUIDs/TXGs, listings, metadata, hard-linked contents, unaligned reads,
EOF and symlink targets. The workload repeats inside a bounded partition, requires
missing-snapshot failure without stdout data, and checks unchanged whole images.
No existing pool is accepted, imported, destroyed or force-exported. Evidence is
retained. Missing tools and unsupported layouts fail rather than count as skips.

Authoring evidence: independent Python CRC64 vectors, Python runner syntax/help,
constructed helper checks and source/blob consistency checks were executed.
Four normalization-parser, five snapshot-graph and one CLI regression functions
were added. Rust compilation/tests, rustfmt/Clippy and native ZFS execution were
not available in the authoring environment and are not claimed. Constructed
Rust fixtures and Python helper checks are not native filesystem conformance.

Integration validation on 2026-10-11 at source
`aa359b9c4a56d3738447e2e6a4b9a6afc38ad237` executed through RCH:

```sh
cargo test -j2 --config profile.dev.debug=0 --config profile.test.debug=0 \
  -p ffs-cli -p ffs-ondisk --lib --bin ffs-zfs -- \
  zfs_zap file_commands:: reader:: --nocapture --test-threads=2
```

All 33 selected CLI tests and 11 ZAP parser tests passed, with no failures or
ignored tests; two CLI and 769 other parser tests were filtered out. This covers
constructed snapshot lineage, historical cache isolation, cancellation, malformed
maps and normalized names. The native ZFS runner has not been executed as part of
this validation, so these results do not establish native filesystem conformance.

Reference behavior: OpenZFS `zfs-2.3.0` `dsl_dataset.c` snapshot creation and
origin branches, `dsl_dataset.h`, `dsl_dir.h`, `zap.c`, `zap_micro.c` and
`u8_textprep.h`. No OpenZFS implementation code is linked or executed by reads.
