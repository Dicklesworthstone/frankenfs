# Read-only views of striped ZFS mirrors

The shared `ffs-zfs` engine now admits a complete pool consisting of multiple
ordinary mirror top-level vdevs, including mixtures of mirrors and standalone
file/disk vdevs. Supply every physical image and either explicitly select the
pool GUID, label and uberblock slot or request automatic read-only selection.
Existing single-leaf, single-mirror, single-RAIDZ and plain-leaf stripe profiles
retain their admission rules.

```sh
# Placeholder identities: replace with the actual pool/candidate values.
# Image ordering does not assign native vdev IDs or mirror child order.
ffs-zfs read first.img /important.bin \
  --member second.img --member third.img --member fourth.img \
  --offline-image --pool-guid 123 --label 0 --slot 2 \
  --dataset data > recovered.bin

ffs-zfs scrub first.img \
  --member second.img --member third.img --member fourth.img \
  --offline-image --pool-guid 123 --label 0 --slot 2 \
  --dataset data --verify-redundancy --max-copy-bytes 1073741824
```

## Native topology admission

Each label describes its own top-level subtree. The engine joins these subtrees
by their native vdev IDs, not argument order. Two through eight top-level vdevs
and at most eight total physical members are admitted. Every mirror has two
through eight ordinary file/disk children; all configured children are required.

Explicit selection requires all four labels on each member to agree on its
entire subtree and physical identity. Automatic selection uses all surviving
checksum-valid labels as described below. Members of a mirror must agree on
their subtree. Top-level IDs must be
complete and contiguous; physical GUIDs and top-level GUIDs cannot alias another
native identity. Different top-level ashifts, capacities and configuration TXGs
are retained. Pool version, exported state and read-feature policy must agree,
and the selected candidate must not predate any admitted configuration.

Every member's allocation capacity is checked against its selected volume and
label exclusions before payload reads, including otherwise-unused replicas and
vdevs. The explicitly selected uberblock must agree across every supplied image
and carry the complete native GUID sum. Native path strings remain metadata;
only caller-supplied host paths are opened.

## Automatic read-only root selection

`--auto-import` now accepts the complete multi-mirror and mixed leaf/mirror
topologies above. `Pool::import_active` and `Pool::import_objects` use the same
shared topology admission as explicit selection; no second mapping algorithm
or filesystem adapter is introduced.

```sh
ffs-zfs read first.img /important.bin \
  --member second.img --member third.img --member fourth.img \
  --offline-image --auto-import --pool-guid 123 --dataset data > recovered.bin
```

Every physical member must have at least one valid configuration. Only label
I/O failures and checksum-invalid copies are disposable. Every checksum-valid
copy must parse and agree with its member's complete subtree; disagreement,
unsupported metadata and cancellation are not reasons to prefer a healthy copy.
All top-level IDs, GUID uniqueness, mirror child membership, capacities and
read-feature/state checks remain mandatory before root-data I/O. Automatic
selection uses the existing active/exported read-only state policy; offline
immutability is still required and no writable ownership is acquired.

Every ring on every supplied member is scanned with that member's admitted
slot geometry, including a ring beside a damaged configuration. Candidates
need the complete pool/top-level/child GUID sum and must not predate any admitted
configuration. Equal-TXG root conflicts are rejected before payload reads;
identical candidate roots are deduplicated before trying physical copies.
Mirror routing is installed before the MOS root read and reconstructed from
the same verified labels before later object-set, dataset and snapshot access.
A bad label zero cannot make a selected view lose its other mirror children.
Redundancy scrub continues to inspect every replica after automatic selection.

The pre-existing highest-readable-TXG policy is unchanged: an older candidate
can be returned when newer root copies fail verification. This is an immutable
committed-view reader, not a guarantee of newest or fully recovered state.
Full configuration-history resolution, explicit-rewind lifecycle policy, log
recovery and writable-pool admission remain separate roadmap obligations.
Explicit `--label`/`--slot` selection still requires all four configurations and
the same selected candidate on every member; it has no tolerant fallback.

## Reads and retained views

A DVA selects one top-level vdev. For a mirror it can read that vdev's physical
children in native child order, accepting only an independently verified copy.
Failure of every child is an error unless another declared DVA supplies a valid
copy. Equal-looking bytes on an unrelated vdev are never an implicit fallback.
Cancellation is terminal, not a reason to try another mirror or DVA.

The complete replica routing is retained by the pool owner attached to DMU views
before MOS feature admission. Cloned head/snapshot views keep the same immutable
owner and independent existing cache semantics after their originating handles
are dropped. Top-level usable capacity is counted once, not once per replica.
The shared object-set reader supplies dataset, file, snapshot and read-only
filesystem consumers; this increment does not add a second filesystem adapter.

Ordinary blocks, gang headers and cross-vdev gang fragments validate every DVA
against every owning replica before payload fallback. Existing whole-graph,
checksum, compression and allocation checks remain in force. Gang work admission
conservatively includes the largest retained mirror multiplicity.

`--verify-redundancy` reads every physical replica rather than only the first
usable one, charging its existing independent copy-work budget. Recoverable
bytes do not certify an intact mirror. Native ZIL storage planning also retains
all replicas and their actual member identities: the embedded log checksum,
not an ordinary data checksum, decides whether a copy is usable. All planned
log copies are charged before log I/O. Existing ZIL inspection/recovery scope
and limits are unchanged; no replay or backing mutation happens merely by
opening this topology.

## Explicit limits

Native writable import, pool ownership, DTL reconciliation, newest-state authority,
resilver/heal, device attach/replace, allocation/TXG writing and native replay
remain separate obligations. The images must remain offline and immutable.

Missing-member options remain limited to their existing single-group profiles;
this new topology requires the complete member set. Multiple RAIDZ groups,
mixtures involving RAIDZ, nested/replacing/spare vdevs, log/special allocation
classes, removed/indirect vdevs, expanded RAIDZ and dRAID remain unsupported.
A readable selected root is not permission to discard any of these components.

## Evidence and qualification

Ten new Rust regression tests are authored: eight native-layout/DMU/scrub tests
and two ZIL storage tests. They cover both byte orders, 512/4096/65536-byte sectors,
mixed leaves and mirrors, unequal mirror widths, reordered inputs, retained
owners, exact capacity, corruption/fallback/cancellation, incomplete/conflicting
members, foreign later DVAs, undersized otherwise-unused members, actual-copy
scrub, gang fragments on different vdevs, and pre-I/O work-budget refusal.
Fixture devices panic on backing writes and synchronization. The native
admission gates remain in force.

Automatic-selection coverage adds eight constructed-image tests and replaces
the former unsupported-topology assertion with explicit/automatic config and
payload equivalence plus a retained DMU read. The new controls cover mixed
widths and sector geometries, both byte orders, permuted images, independently
located ring candidates, damaged label zero, replica fallback, retained cold
views, all-copy redundancy scrub, complete membership, valid-but-conflicting
labels, missing label authority, GUID sums, configuration age, equal-TXG forks,
I/O versus cancellation and no unrelated-vdev fallback. The existing single-
group import tests and other explicit-topology test bodies are unchanged.

The automatic-selection tests are authored but unexecuted in this environment.
Source/hash and patch-application checks are not Rust execution or native
OpenZFS qualification; the historical results elsewhere do not qualify this
new path. No checker, release gate or canonical bead is relaxed or closed.

These tests have not run in this implementation environment. RCH/Cargo test,
workspace check, strict Clippy and format commands were attempted and could not
start because their executables are absent (exit 127). Baseline/upload hash and
patch checks are source evidence, not compiler/runtime, native OpenZFS-image,
kernel FUSE or hardware-fault qualification. Independent native interchange and
the repository's unchanged Rust gates remain required:

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-zfs striped_mirror
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-zfs auto_import
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p ffs-zfs
RCH_REQUIRE_REMOTE=1 rch exec -- cargo check --workspace --all-targets
RCH_REQUIRE_REMOTE=1 rch exec -- cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

Native configuration reference: OpenZFS `zfs-2.3.0`,
`module/zfs/vdev_label.c`. The implementation independently composes the existing
FrankenFS parsers and verified physical readers; no native driver code is reused.
