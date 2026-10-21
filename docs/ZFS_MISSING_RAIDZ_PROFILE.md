# Explicit committed-view extraction with absent RAIDZ members

`ffs-zfs --missing-raidz-member GUID` connects explicit missing-device admission
to the existing native RAIDZ1/2/3 checksum-verified reconstruction pipeline.
It selects a committed view from one exported ordinary RAIDZ group, not the
latest state of a degraded pool. This is read-only extraction, not native
pool import, repair, resilvering, ZIL replay, or writable operation.

## Select the actual native identities

Supply every available immutable regular image, using `--member IMAGE` for
additional survivors. Repeat `--missing-raidz-member GUID` for every absent
child. The GUID is the decimal native child GUID, not a path, array position,
pool GUID or top-level vdev GUID. Do not create dummy images for missing disks.

The example numbers are placeholders. Use the actual retained configuration
and explicitly selected label/uberblock slot:

```sh
# Three-child RAIDZ1 with two survivors and one absent child.
ffs-zfs datasets first.img --member second.img --offline-image \
  --pool-guid 123 --label 0 --slot 2 --missing-raidz-member 1003

ffs-zfs read first.img /important.bin --dataset data --member second.img \
  --offline-image --pool-guid 123 --label 0 --slot 2 \
  --missing-raidz-member 1003 > recovered.bin

# Four-child RAIDZ2 with two explicitly absent children.
ffs-zfs mount first.img /mnt/recovery --dataset data --snapshot before \
  --member second.img --offline-image --pool-guid 123 --label 0 --slot 2 \
  --missing-raidz-member 1003 --missing-raidz-member 1004
```

The mountpoint must exist, be empty, and not hide any backing image. Explicit
`--offset` and `--length` retain their existing selected-volume meaning for all
supplied images. Streaming output can contain an earlier prefix if a later read
or stdout write fails; a nonzero exit must not be treated as complete recovery.

## Admission and reconstruction boundaries

The native configuration must contain one ordinary RAIDZ group, with one to
three parity columns, at least one data column and at most eight children.
There must be at least one survivor. The missing count cannot exceed native
parity. Every surviving image must have four valid, agreeing labels describing
the same exported configuration, and the same explicitly selected uberblock.
Present and missing GUIDs must form the exact disjoint configured child set.
Zero, duplicate, foreign, overlapping and unaccounted GUIDs are errors.
A supplied unreadable image is not silently reclassified as absent.

The native stripe width/order, parity count, allocation size, ashift and full
uberblock GUID sum are retained, including absent children. The reader does
not compact a stripe to the surviving-image count. Every declared DVA and
column allocation is bounded before payload reads. Absent routes own no Leaf
or file descriptor, and cannot alias a supplied handle or open a native path.

Intact checksum-valid data does not require parity reads. Missing data columns
use the existing parity equations and bounded recovery hypotheses. Additional
I/O failures and corrupt-but-readable data/parity must fit that same native
budget. Every accepted candidate must satisfy the original physical checksum
and transform; exhausting recovery returns an error, never unchecked bytes.
Cancellation is terminal rather than a reason to try another replica or DVA.

Per-column reports retain native child IDs and GUIDs, including reconstructed
children. The root's reported first-data-child identity may be an absent child
whose bytes were reconstructed; it is not a claim that that device was read.
Even one surviving image retains the full RAIDZ-aware pool owner. Dataset and
snapshot views keep their selected roots and independent caches after the
original pool handle is dropped. No backing image is written, flushed, healed,
or promoted to a new transaction group by this path.

## Explicit refusals

The new option conflicts with `--auto-import`, `--replay-zil` and
`--missing-mirror-member`. Direct argument construction checks the same
restrictions before image opens. `zil-inspect` and `zil-read` also refuse missing
RAIDZ requests before opening images. Active pools, expansion/dRAID, nested or
changing topology, missing special/log vdevs and native pool lifecycle remain
outside this profile. Existing feature/device-state exclusions remain intact.
Normal operation without a missing-member option still requires all members.

A surviving checksum cannot prove that absent disks have no newer or divergent
state. This mode neither discovers the newest authoritative TXG nor establishes
DTL/resilvering history. It does not claim native OpenZFS degraded-import parity.

## Evidence status

Thirteen new Rust tests are authored: eight native-image/route controls, three
CLI/pre-I/O controls and two head/snapshot filesystem controls. They cover
RAIDZ1/2/3, both byte orders, every admitted missing subset for selected widths,
512/4096/65536-byte sectors, compression, one survivor, exact native membership,
full GUID sums, contradictory labels, all-DVA bounds, corrupt parity, copy retry,
cancellation, root lifetime and later historical-read failure without live-head
fallback. Absent children have no supplied handle; existing fixture devices
panic on writes or flushes. The integration tests call FsOps on constructed
native images; they are not kernel FUSE or OpenZFS-generated-image evidence.

These tests have **not been executed in the implementation session**. Cargo,
rustc, rustfmt and RCH are unavailable; attempted test/check/Clippy/format commands
failed to start. Source/hash/diff checks do not substitute for compilation.
No gate, assertion, default admission rule or acceptance criterion is relaxed.
Required validation remains, including:

Engine tests have moved into the `ffs-zfs` library, with separate CLI tests;
these current verification commands do not imply a new execution result.

```sh
rch exec -- cargo test -p ffs-zfs --lib missing_raidz
rch exec -- cargo test -p ffs-zfs --lib raidz
rch exec -- cargo test -p ffs-cli --bin ffs-zfs
rch exec -- cargo check --workspace --all-targets
rch exec -- cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

Native OpenZFS interchange, actual read-only FUSE mounts and damaged-device
qualification remain outstanding. See also the [ZFS read profile](ZFS_READ_PROFILE.md)
and [explicit missing-mirror profile](ZFS_MISSING_MIRROR_PROFILE.md).
