# Explicit read-only extraction from a mirror with absent members

`ffs-zfs` now admits a bounded missing-member profile through the repeatable
`--missing-mirror-member GUID` option. This is **committed-view extraction from
an explicitly selected exported mirror**, not automatic degraded pool import,
latest-state selection, log recovery, resilvering or writable pool operation.
Keep every supplied image offline and immutable for the lifetime of the view.

## Selection

Supply at least one surviving regular image. Use `--member IMAGE` for additional
survivors and `--missing-mirror-member GUID` for **every** unavailable child.
GUIDs are decimal native child GUIDs, not paths, child indexes, the pool GUID,
or the top-level mirror GUID. Obtain them from the known native configuration;
do not guess them or use a made-up image to represent an absent disk.

The following numbers are placeholders. Select the actual pool GUID, label and
uberblock slot from the retained images and their native configuration:

```sh
ffs-zfs datasets survivor.img --offline-image \
  --pool-guid 123 --label 0 --slot 2 --missing-mirror-member 1002

ffs-zfs read survivor.img /important.bin --dataset data --offline-image \
  --pool-guid 123 --label 0 --slot 2 --missing-mirror-member 1002 > recovered.bin

ffs-zfs mount survivor.img /mnt/recovery --dataset data --snapshot before \
  --offline-image --pool-guid 123 --label 0 --slot 2 \
  --missing-mirror-member 1002

# Three-child mirror: two actual images plus one declared absent child.
ffs-zfs read first.img /important.bin --member second.img --offline-image \
  --pool-guid 123 --label 0 --slot 2 --missing-mirror-member 1003
```

The mountpoint must already exist and be empty, and cannot hide a backing
image. The existing `--offset` and `--length` bounds apply to all supplied
images. Raw MOS commands, dataset/snapshot selection and read-only filesystem
views use the same pool owner. A later I/O failure can leave a previously
streamed prefix on stdout; it does not turn partial extraction into success.

## Native admission and read behavior

The complete configuration must describe one ordinary mirror with two through
eight file/disk children. Every surviving member must have four valid, agreeing
labels identifying that same exported configuration. Repeated supplied GUIDs,
unknown missing GUIDs, overlapping present/missing sets, zero/duplicate GUIDs,
and an unaccounted child are refused. A supplied image with damaged metadata
is not silently relabeled as absent. Normal operation without the new option
continues to require the complete configured member set.

Each survivor must contain the same explicitly selected uberblock candidate.
Its native GUID sum continues to include **all configured children**, including
absent ones. Neither this option nor a surviving checksum proves that an absent
member has no newer or divergent state. There is no automatic rewind or
selection of a conveniently readable transaction group in this profile.

The existing block-pointer bounds, feature admission, checksums, transforms,
copy selection and cancellation handling remain in force. Reads try surviving
replicas and declared copies of the same block; they never synthesize an absent
device or return unverified bytes. Cancellation is terminal, not a reason to
try another copy. No member or label is rewritten, synchronized, healed or
replaced by this path.

Even one remaining mirror disk keeps the mirror-aware pool owner. It is not
reinterpreted as a standalone leaf. Head and named-snapshot readers retain
separate roots and caches, including after the original pool handle is dropped.
A successful read says nothing about the unread part of the pool or the ability
to restore native redundancy.

## Refused combinations

Missing-member selection is incompatible with `--auto-import`, `--replay-zil`,
active pool state, missing RAIDZ columns, striped top-level vdevs, nested or
changing topologies, missing log/special storage, and writable operation. The
separate `zil-inspect` and `zil-read` commands also refuse this option before
opening images. Existing feature, device-state and ownership exclusions are
not bypassed. This increment does not add native pool import/export or repair.

## Evidence

Ten authored Rust controls cover two/three/eight-child mirrors, either byte
order, one or multiple survivors, exact GUID membership and native GUID sums,
contradictory configurations/candidates, default missing-device refusal,
corrupt and I/O-failing copies, cancellation, CLI/pre-I/O guards, and independent
head/snapshot filesystem reads retained from one surviving member. The test
backing devices panic on any write or flush. The head/snapshot case uses
constructed embedded-payload metadata and calls `FsOps`; it is not a kernel
FUSE mount or an OpenZFS-generated-image oracle.

These new Rust controls have **not been executed in the implementation session**.
Local Cargo test/check/fmt/Clippy attempts exited 127 because Cargo is absent.
Source blobs were compared to the existing baseline and reviewed before upload;
Git whitespace checks passed. GitHub Actions were triggered by the direct
commit, but queued workflow state is not a passing build or test result.
No OpenZFS interchange, mounted kernel, hardware-failure or native recovery
qualification is claimed. Run the unchanged repository gates, including:

```sh
rch exec -- cargo test -p ffs-cli --bin ffs-zfs missing_mirror
rch exec -- cargo test -p ffs-cli --bin ffs-zfs mirror
rch exec -- cargo check --workspace --all-targets
rch exec -- cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

The broader feature and transform limits remain in
[the ZFS read profile](ZFS_READ_PROFILE.md). The new explicit exception applies
only to the mirror-member completeness requirement described here.
