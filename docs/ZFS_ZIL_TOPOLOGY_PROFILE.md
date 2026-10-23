# ZIL reads through the admitted native storage set

The native ZIL inspector and existing memory-only copied-write/EOF-truncation
recovery path now retain the same complete storage owner as ordinary MOS/ZPL
reads: a single leaf, complete mirror, striped standalone top-level leaves, or
one complete ordinary RAIDZ1/2/3 group. The existing topology/feature admission
still decides which images constitute a pool. This does not admit missing
members, SLOG devices, nested groups, dRAID, or expanded RAIDZ.

`ffs-zfs zil-inspect` and `ffs-zfs zil-read` retain the existing `--member`
options and aliases. `--offset` and `--length` still select the same span on
each image. More than seven additional images and sidecar healing are refused
before opening storage. No on-disk log claim, replay-sequence update, TXG
publication, physical repair, write or flush is introduced.

Log blocks use their native ZILOG/ZILOG2 embedded checksum and chain identity,
not the ordinary DMU block-pointer checksum. Mirror replicas are tried without
changing that identity. RAIDZ uses the shared native mapping and reconstruction
algorithms, but verifies every assembled candidate with the log verifier. A
bad P equation may be excluded while Q/R reconstruct the data. Parity is read
only after the original data fails; this is not an all-copy/parity scrub.

Before data I/O, every declared DVA and member extent must satisfy sector,
allocation-size, vdev, partition and end-label bounds. Actual allocation
intervals, including skip sectors, are retained per supplied member across
the complete log chain. Distinct vdevs may reuse a numeric offset; overlapping
allocations on one member are refused.

`physical_work_bytes` counts admitted read bytes for every declared replica and
parity column, including copies that a successful earlier read makes unnecessary.
The existing 64 MiB cap remains. `reconstruction_work_bytes` separately charges
all native padded column bytes for each RAIDZ assembly attempt, with a 256 MiB
per-scan cap. These are cumulative work bounds, not whole-process memory limits.

Cancellation and exhausted budgets terminate immediately. If no verified copy
can be reconstructed, any physical I/O failure remains an error. Only fully
readable but checksum-invalid copies may form an unverified tail. Claimed log
boundaries still fail closed; extracting an unclaimed verified prefix still
requires explicit `--allow-unverified-tail` authorization. Such a tail can be
unwritten or damaged, so a prefix is not certification of complete recovery.

Pending namespace records, range-free records, native durable replay and
writable mounts remain outside the file-data recovery profile. Full-block
indirect writes are admitted as described below; partial indirect writes and
`TX_WRITE2` remain unsupported.

## Surviving bytes and indirect file data

Recovery now reads only committed bytes that survive every admitted write and
truncate. A completely overwritten block, or a tail retired by shrink/regrowth,
does not require its old payload to be readable. Every surviving old range still
passes the ordinary checked ZPL reader. A corrupt partially required block is
not converted into a successful result. The coverage mask is limited to 16 MiB,
marking work to 128 MiB, and the complete base-read plan to 4,096 ranges before
its first old-data read. These are in addition to the existing staged-output
and edit-copy bounds.

Native 192-byte `TX_WRITE` records may now supply a level-zero ordinary file-data
block pointer instead of inline bytes. This restricted increment requires the
logged length to equal the complete logical block size and its offset to be
aligned to that size. Encrypted, embedded, gang and hole pointers remain refused
on this path. The obsolete `lr_blkoff` field is retained but not interpreted.
Partial-block replay and `TX_WRITE2` need separate EOF and hidden-tail semantics;
they are not approximated by copying a subrange or extending EOF with zeros.

Every pending operation is admitted before target file payloads are loaded.
Indirect pointers are protected by the verified log, and their data goes through
the existing pool checksum/transform/replica pipeline. Their births may be newer
than the selected committed TXG. These bytes remain in the recovery staging
area; they never enter the committed object-set cache or weaken its birth checks.
Ordinary reads and metadata still describe the original committed filesystem.

Only the selected existing file's indirect payloads are materialized. Their
aggregate logical buffers and aggregate native allocation work, including
mirror replicas, each have a 64 MiB preflight limit. Existing per-block native
reconstruction limits still apply. The returned log work counters continue to
describe the log chain only, not these separately budgeted file-data reads.
A payload checksum/I/O failure is an error, not an unwritten tail or permission
to substitute committed bytes. Prefix-recovery consent remains mandatory.

## ZPL namespace recovery and hard links

The selected-head `Zpl::replay_zil` path, exposed by `ffs-zfs --replay-zil`,
also stages namespace operations in a private in-memory view. This is a
separate interface from the narrower, single-file `zil-read` recovery above.
Native `TX_LINK` records now join the existing plain create, mkdir, symlink,
unlink, rmdir, rename, write, truncate and setattr operations. The native
layout is a 48-byte header followed by one NUL-terminated name and alignment
padding, as defined by OpenZFS's
[`lr_link_t`](https://github.com/openzfs/zfs/blob/zfs-2.3.0/include/sys/zil.h).

A recovered hard link retains the target's object number, generation and data.
Aliases share later writes, survive removal of the original name, and update
the native link count and destination directory accounting. The parent field
follows OpenZFS's
[`zfs_link_create`](https://github.com/openzfs/zfs/blob/zfs-2.3.0/module/os/linux/zfs/zfs_dir.c)
semantics. Existing committed targets and objects created earlier in the same
log are admitted, including symlinks. Directories, deleted or missing targets,
invalid object identities, occupied names, invalid path components and link
count overflow are refused.

Every pending record must pass native framing and semantic checks before the
new view is published. A later failure discards earlier staged links and
preserves the previously visible view. Repeating replay rebuilds from the
committed root rather than incrementing link counts again. Backing images,
log claims and replay sequence fields are never written. Unknown flags,
including `TX_CI`, remain unsupported; this does not admit writable pools or
native durable replay.

Five added Rust regression functions cover both byte orders, legacy and slim
log checksums, claimed and unclaimed boundaries, cross-directory aliases,
newly created targets, symlinks, original-name removal, repeat replay, malformed
records and atomic refusal. Their native-layout fixtures are constructed;
they do not establish OpenZFS crash-image interoperability.

## Native atomic rename exchanges

The same selected-head namespace replay now admits exact native type 22,
`TX_RENAME_EXCHANGE`. OpenZFS zfs-2.3.0 stores the two directory object numbers
and two NUL-terminated names in `lr_rename_t`, then dispatches replay with
`RENAME_EXCHANGE`. Inspection retains a distinct exchange payload; it is never
decoded or applied as an ordinary rename that replaces and removes a target.

Both entries must exist. Exchanges preserve each object's identity, generation,
link count and contents, including symlinks and nonempty directories. A mixed
file/directory exchange transfers the child's parent-link contribution between
parents while preserving both directory entry counts. Both moved directories
are checked against their prospective ancestors before either parent changes.
Identical names or different hard-link aliases of one object are successful
no-ops. Missing targets, invalid directory identities, cycles, malformed names,
unknown type flags and unexplained record suffixes fail the complete replay.

The operation uses the existing private-overlay publication boundary. A later
failure leaves the previously visible view intact; replay starts from committed
state each time, so it does not swap an already recovered namespace twice.
Backing images, claim fields and replay-sequence fields remain unchanged.

Five authored regression functions cover both byte orders, ZILOG/ZILOG2 checksums,
claimed/unclaimed logs, shared hard-link writes, same-object no-ops, mixed and
nonempty directory exchanges, both cycle directions, repeated replay, exact
record framing and a later failure after a previously published recovery view.
Pinned-nightly formatting and whitespace checks passed. These constructed-image
Rust tests have not executed in this environment: dependency resolution is
blocked by an incomplete local Cargo cache and exhausted shared storage. Native
OpenZFS crash-image interchange is also unverified; the broad `bd-ofjn7` remains
open. Existing workspace CI runs on `main` and retains its compiler/test gates.

## Native SA user-xattr recovery

Selected-head namespace replay also admits native `TX_SETSAXATTR` (type 21)
for the existing user-xattr read profile. OpenZFS zfs-2.3.0 defines the record
in [`zil.h`](https://github.com/openzfs/zfs/blob/zfs-2.3.0/include/sys/zil.h)
and emits it in
[`zfs_log_setsaxattr`](https://github.com/openzfs/zfs/blob/zfs-2.3.0/module/zfs/zfs_log.c):
a 48-byte fixed header contains the object number and value length, followed
by one NUL-terminated native name, exactly that many value bytes, and ordinary
eight-byte alignment padding. Unknown flags, incomplete values and unexplained
suffixes remain errors. Binary values are retained unchanged.

The native
[`zfs_replay_setsaxattr`](https://github.com/openzfs/zfs/blob/zfs-2.3.0/module/zfs/zfs_replay.c)
contract treats a zero value length as removal of an existing SA nvpair, not
creation of an empty value. A missing SA key on a live owner fails recovery.
The outer
[`zil_replay_log_record`](https://github.com/openzfs/zfs/blob/zfs-2.3.0/module/zfs/zil.c)
dispatcher classifies this operation as out of order: an owner already proven
unallocated is skipped. Other owner lookup failures, corrupt metadata and
private xattr objects remain errors. Large-dnode interior slots retain the
existing reader refusal; arbitrary parse failures are never treated as absence.

Committed owners must use the native SA representation in an SA-capable dataset.
Recovered creations begin with empty xattr sources. Changes are keyed by object
identity, so hard links share them; the final unlink retires them, and reuse of
an object number cannot inherit its prior SA values or private xattr directory.
Replay initializes each map from the committed root, never from an earlier
published recovery view.

Recovered SA maps enter the existing public `listxattr` and `getxattr` paths
before name projection. Lookup order remains prefixed SA, prefixed directory,
unprefixed SA, then unprefixed directory. Removing only the SA nvpair can reveal
a directory fallback. Lists remain sorted and deduplicate compatibility aliases.
Reserved security, system, trusted and foreign namespaces are refused by this
replay increment; it does not add ACL or capability interpretation. Existing
UTF-8 and 255-byte host-name bounds remain.

The native value limit is 32 KiB; the packed XDR SA map must fit the native
65,535-byte attribute ceiling. The sum of pre-edit and post-edit map sizes has
a separate 64 MiB replay work limit. These bounds follow
[`zfs_sa.h`](https://github.com/openzfs/zfs/blob/zfs-2.3.0/include/sys/zfs_sa.h),
[`sa.h`](https://github.com/openzfs/zfs/blob/zfs-2.3.0/include/sys/sa.h), and the
existing bounded reader design.

Publication remains atomic across the complete pending log: a later framing,
owner, namespace, size or removal failure leaves the previous view intact.
Repeating replay rebuilds the same state without writing backing images,
claim fields or replay sequences. Constructed native-format regressions cover
both byte orders, both ZIL checksum variants, claimed/unclaimed boundaries,
binary replacement, SA/directory precedence, hard links, object reuse, skipped
unallocated owners and late failure. Pinned-nightly formatting, whitespace and
strict all-target Clippy checks pass, including type-checking the new tests.
The complete `ffs-ondisk` library suite passed all 955 tests. After the earlier
memory-limited attempts, the complete ZFS library suite executed successfully:
339 passed, zero failed or ignored, including all six new SA-xattr regressions.
The executed command was:

```bash
cargo test --locked -p ffs-zfs --lib \
  --features ffs-core/bhh0i_sharded_alloc -- --test-threads=2
```

These are constructed native-format fixtures. Native OpenZFS crash-image
interchange remains unverified.

## Earlier validation notes

Twelve new Rust regression functions cover topology transport and CLI admission,
including mixed checksum variants/byte orders, 512-byte through 64-KiB native
sectors, parity corruption, I/O erasures, cancellation, allocation aliases,
budget exhaustion, and the public Objects-to-ZPL recovered-read path. These are
constructed fixtures, not native OpenZFS import or interoperability evidence.

Rust/Cargo/RCH are unavailable in the authoring environment. Compilation,
Rust execution, rustfmt, Clippy and native OpenZFS comparisons remain unverified.
Independent Python finite models and patch-application/whitespace checks do not
substitute for those gates.

The surviving-range increment adds four regression functions; a separately
executed symbolic-origin/materialized-byte model passed 37,120 comparisons.
The indirect-write increment adds six constructed native regression functions
covering both container and payload byte orders, LZ4, malformed/partial records,
missing payloads, cancellation, preflight budgets, mirror fallback and the
complete MOS/ZPL recovered-read path with an unreadable superseded base block.
None of these authored Rust tests is claimed as executed here.
