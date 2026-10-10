# NTFS, FAT16/FAT32, and ZFS: Implementation Work Packages

> Proposed implementation companion, 2026-10-09.
>
> The governing design is
> [the comprehensive multi-format plan](../COMPREHENSIVE_PLAN_FOR_NTFS_FAT16_FAT32_AND_ZFS.md).
> Its repository baseline and source register apply here. Nothing below claims
> that a new driver, command, test, or benchmark has already been implemented.
> Proposed module/test names identify intended ownership, not existing files.
>
> `CORE-*`, `FAT-*`, `NTFS-*`, `ZFS-*`, and `PROTECT-*` are document-local work
> identifiers, **not real bead IDs**. Create or link actual beads only when
> implementation is claimed; do not mechanically import this document as dozens
> of administrative tasks.

## 1. Dependency graph and first useful deliverables

```text
CORE-01 bounded device/geometry ----+--> FAT-01 -> FAT-02 -> FAT-03 [mounted RO]
                                   |                       |
CORE-02 admission / CORE-03 FsOps ---+                       +-> FAT-04/05
                                   |                           [native RW]
                                   +--> NTFS-01 -> NTFS-02/03 [mounted RO]
                                   |                 |
                                   |                 +-> NTFS-04 -> NTFS-05
                                   |                    [recovery] [native RW]
                                   +--> ZFS-01 -> ZFS-02/03 [pool + dataset RO]
                                                     |
                                                     +-> ZFS-04/05/06
                                                         [topology + native RW]

CORE-04 native commit outcomes + CORE-05 faultable storage
  -> every native writer and recovery engine

native durable token + immutable/exclusive capture
  -> PROTECT-01 -> PROTECT-02 -> PROTECT-03

format-specific advanced features and lifecycle follow the corresponding writer;
they do not all block the first independently verified read-only vertical slice.
```

The first coding increment should be a bounded volume adapter, FAT BPB/chain
parsing, and an actual `OpenFs` read of a native-created file. The second should
complete directory/name behavior and mounted read-only operation for both FAT
dialects. Start mutation only when allocation, initialization, and fault injection
can be exercised together. A separate commit that only adds four enum variants
and empty crates is not a useful deliverable.

Do not serialize NTFS and ZFS research behind every FAT utility. Pure NTFS MFT
parsing and pure ZFS label/block-pointer parsing can proceed independently, with
integration waiting only on the concrete common seams they need.

## 2. Common engine work

### CORE-01: bounded volumes and explicit physical guarantees

**Own:** `ffs-block` device views; checked geometry types in `ffs-types` only where
shared; pure test devices under the owning crate's test support.

Implement a byte-device view with validated `base`, `length`, logical-sector
size, physical-write granularity where known, and flush capability. Construction
fails on a backing shorter than the view, zero/invalid sizes, arithmetic overflow,
or a required physical guarantee the backing cannot supply. Every read/write
checks `relative_offset + length` before translating to the backing offset.

A view must not permit writes to preceding/following partitions through an
alignment helper. For sub-sector metadata updates, the owner serializes a
read-modify-write against every other writer touching that physical sector.
A 4 KiB cache block does not authorize overwriting neighboring 512-byte sectors.

**Acceptance:** generated offsets near integer limits; final partial reads;
unaligned spans; adjacent-volume sentinels; truncated backings; cancelled calls;
short physical reads/writes; flush failure. Record physical writes to prove a
read-only open produces none. Re-run existing ext4/btrfs device tests.

### CORE-02: discovery is not admission

**Own:** `ffs-core` detector/admission modules and relevant CLI selection parsing.

Implement bounded probe results containing candidate format, geometry evidence,
feature state, identity, and rejection reasons. Explicit volume selection happens
before native bootstrap. For a pool, the selection identifies a storage set,
not one arbitrarily chosen filesystem root.

A magic match followed by invalid geometry is a malformed candidate, not support.
Two valid conflicting candidates require explicit selection or an ambiguity
error. The chosen filesystem option cannot override a failed native parser.
Unknown NTFS/FAT variants, exFAT, FAT12, and unsupported ZFS active features must
not fall through to another engine as if no signature existed.

Writable admission is a second step, dependent on native recovery, feature,
ownership, and topology checks. A requested writable open either yields the
requested admitted mode or fails explicitly; do not silently downgrade it and
make the caller discover the change on its first write.

**Acceptance:** malformed/ambiguous probes; wrong selected format; false-positive
magic inside data; feature/key/device refusal; existing ext4/btrfs behavior;
zero writes even on failure. Do not add a second support-report framework.

### CORE-03: root, names, object identity, and operations

**Own:** the existing `FsOps` contract, backend adapters, and `ffs-fuse` dispatch.

Introduce the smallest native-name and object-identity abstractions needed by
FAT, then extend them with NTFS streams/record sequences and ZFS dataset identity.
Do not let a user-visible UTF-8 string be the only representation of a native
name. Directory pages carry restartable cookies without assuming stable array
indexes under mutation.

Map FUSE node 1 to the admitted native root. Allocate mount-lifetime node IDs
without collisions across FAT aliases, NTFS hard links/streams, or ZFS datasets.
Preserve open handles across rename/unlink and reject stale reuse. FAT stable
identity across remounts is not part of transient node allocation.

Unsupported operations return the backend's exact policy error before mutation.
For example, native FAT hard links and native FAT xattrs are unsupported, not
successful no-ops. Format-specific ioctls must not be routed to ext4 methods
because that was the original default branch.

**Acceptance:** mounted lookup/read/readdir/getattr; invalid and non-ASCII names;
negative-cache invalidation; root translation; cross-dataset IDs; open-unlink;
rename-overwrite; unsupported syscall errors and unchanged-image hashes.

### CORE-04: explicit native commit results

**Own:** `ffs-core` integration, native engine transaction modules, and only the
shared MVCC interfaces actually required by a second concrete engine.

Use a typed result that distinguishes not committed, committed with a native
durable token, and outcome requiring recovery. A token binds storage identity,
view/epoch, and the native publication point. It is not just a global integer.

Keep allocation, recovery records, data initialization, namespace updates,
publication, and reclamation in the native engine. A shared write-plan executor
may honor dependencies/barriers; it must not infer those dependencies by sorting
block addresses. Preserve the current ext4/btrfs paths during extraction.

Cancellation after durable commitment must preserve the committed result for
reconciliation even when the request cannot receive its normal reply. Retries
must not duplicate an operation whose outcome is already known committed.

**Acceptance:** cancellation and I/O failure before/after each boundary; deferred
error reporting; file versus directory sync; commit-token/MVCC-view association;
no success on a failed required flush; existing native recovery regressions.

### CORE-05: deterministic storage failure model

**Own:** shared test infrastructure close to `ffs-block`; native scenario drivers
in each engine's integration tests.

Maintain separate pending and durable device state. Implement fault schedules
for short reads/writes, injected errors, supported torn-write granularity,
reordering before flush, loss of unflushed data, and explicit failed flushes.
Restart a new engine instance against the resulting durable image, not the old
instance's cache. Capture the acknowledged-operation prefix separately from
issued but unacknowledged operations.

A successful simulated flush makes its required earlier writes durable under
the declared model. Do not create impossible arbitrary post-flush loss and call
it a filesystem ordering bug; report a separate device-guarantee violation.
Model device sets independently for ZFS and cross-file ordering for sidecars.

**Acceptance:** self-tests proving the fault device itself loses pending data,
retains flushed data, exposes torn writes as configured, and cannot accidentally
reuse in-memory backend state after a simulated crash. Use this machinery to
exercise real native operations, not only artificial write-plan examples.

## 3. FAT implementation work

### FAT-01: BPB, dialect, and region arithmetic

**Own:** proposed `ffs-ondisk::fat` pure parsers and `ffs-fat` validated layout.
**Depends:** CORE-01; integrate detection through CORE-02.

Use checked arithmetic for the conventional layout calculation:

```text
root_dir_sectors = ceil(root_entry_count * 32 / bytes_per_sector)
fat_sectors      = validated dialect-appropriate FAT size field
first_data       = reserved_sectors + number_of_fats * fat_sectors
                   + root_dir_sectors
cluster_count    = (total_sectors - first_data) / sectors_per_cluster
cluster_sector(n)= first_data + (n - 2) * sectors_per_cluster
```

Validate every input before division/subtraction, then validate the selected
FAT16/FAT32 layout against the cluster-count classification described in the
main plan. Table capacity must cover the admitted cluster namespace and reserved
entries. A formula result alone does not prove that an upper-bound cluster value
is a legal data-cluster value under the dialect.

FAT16 root bytes occupy a fixed region; FAT32 root uses a validated cluster.
Validate reserved regions, backup references, active-FAT policy, and selected
volume bounds. Preserve diagnostic evidence for conflicting boot/FAT copies.

**Acceptance:** boundary counts around 4,085 and 65,525; deliberately inconsistent
label/layout; sector sizes and cluster sizes admitted by the profile; near-full
arithmetic; truncated FAT/root; backup conflict. Compare geometry with native
formatters rather than only a parser-generated fixture.

### FAT-02: bounded cluster and data reads

**Own:** `ffs-fat` table reader, chain cursor, and file read path.
**Depends:** FAT-01.

Represent FAT entries as typed states: data successor, end, bad, reserved, free,
or invalid. FAT32 lookup masks the value bits without losing the original word
needed by the future writer. Follow a file's chain lazily with cycle/work bounds;
cache sparse chain anchors for random reads without retaining the entire volume.

Check the relation between file size and required chain coverage. Do not read
slack as file data. A range straddling EOF, cluster boundaries, or a host cache
page must return exact bytes or a correctly scoped error. A failure after
reading an earlier cluster cannot turn the later malformed cluster into a
successful short file.

**Acceptance:** empty, one-cluster, fragmented, unaligned, and large files; free
entry inside a live chain; cycles; bad/reserved successors; overlong versus short
chains; repeated random seeks; cancellation during I/O; native file hashes.

### FAT-03: directories and mounted read-only support

**Own:** `ffs-fat` directory/name implementation, core adapter, and FUSE tests.
**Depends:** FAT-02 and CORE-03.

Parse the fixed root and cluster-backed directories through one bounded iterator.
Handle end/deleted entries, the special first-byte encoding in short names,
volume labels, case flags, and LFN sequence/checksum validation. A malformed LFN
must not attach to the following unrelated short entry. Preserve raw long and
short names and perform lookup under the configured native comparison policy.

Implement actual root lookup, nested path lookup, readdir pagination, getattr,
and data reads through the public mount path. Short aliases identify the same
native object where exposed; they do not allocate duplicate independent nodes.
For unsupported host representations, use the documented refusal/forensic policy
rather than lossy replacement-character collisions.

**Acceptance:** Windows/mtools-created aliases; maximal native names; malformed
LFN ordinal/checksum/terminator; Unicode and code-page collisions; full FAT16
root; FAT32 root fragmentation; nested directory reads; all read-only mount,
unmount, error, and scrub paths leave the image byte-for-byte unchanged.

This is the first release-worthy restricted FAT read-only profile. It is not the
completion of FAT write support or the entire expansion program.

### FAT-04: allocation, initialization, and file mutation

**Own:** `ffs-fat` allocator and native ordered-write engine.
**Depends:** FAT-03, CORE-04, CORE-05.

Implement bounded free-entry search, validation under lock, reservation, chain
extension, file growth, positioned overwrite, truncate, and free-space accounting.
Honor active-FAT/mirror policy and preserve FAT32 reserved high bits. Never allocate
from FSInfo alone. Detect no-space before a partially published operation where
possible; keep rollback/recovery accounting for reservations already changed.

Initialize every newly visible byte, including gaps and partial clusters. A
write exceeding the native file-size bound fails before changing the file.
Serialize overlapping physical-sector read-modify-writes. Growth publishes length
only after the data/chain state it exposes is safe. Shrink stops exposing data
before freeing/reusing removed clusters.

**Acceptance:** fill/ENOSPC and retry; two concurrent allocators; partial-cluster
extension; write beyond EOF; truncate-and-reallocate into another file; table
mirror faults; poisoned old allocation; dirty/clean state and failed final flush;
every relevant storage cut followed by independent native checking.

### FAT-05: directory mutation and native crash limits

**Own:** `ffs-fat` directory mutation and mount-lifetime orphan/handle management.
**Depends:** FAT-04.

Implement short-name generation/collision resolution, contiguous LFN/SFN slot
reservation, create/mkdir, rename within/across directories, replacement,
unlink/rmdir, and directory expansion. Update `..` on cross-parent movement where
required and prevent directory cycles. Define what an open deleted file retains
and when allocation can be reclaimed after the final handle closes.

Native FAT cannot generally make the multiple directory/table sectors of these
operations atomic across power loss. The implementation must document and test
the permitted native recovery outcomes rather than claiming a rollback protocol
that exists only in memory. A stronger external transaction profile is separate.

**Acceptance:** same-name/no-op rename; alias-only/case changes; occupied target;
open target replacement; full root/directory; subdirectory move into descendant;
crashes between target/source/parent/FAT updates; no stale-data disclosure; native
checker classifications match the declared interrupted-outcome contract.

### FAT-06: maintenance and native creation

**Own:** `ffs-fat` checker/formatter/offline-resize modules and existing CLI paths.
**Depends:** FAT-04/05 for mutation primitives; checker can start after FAT-03.

Build reachability and ownership accounting with bounded spill/storage strategy
for large images. Report cross-links, lost chains, length mismatches, malformed
directories, mirror divergence, and inaccurate hints independently. A checker
cannot select the rightful owner of a cross-linked cluster merely from order of
traversal. Repairs require a stated choice and preserve before/after evidence.

Format only explicitly authorized fresh volume ranges. Produce native FAT16 and
FAT32 structures and verify them with independent tools. Offline resize must
prove all live clusters fit before shrink, relocate safely, and update geometry
and backups in a recoverable sequence. No implicit partition-table rewrite.

**Acceptance:** non-mutating checker hash equality; ambiguous repair refusal;
lost-chain choices; native formatter/read/write/check interchange; FAT16 root
sizing; FAT32 backup/FSInfo correctness; adjacent partitions preserved; interrupted
resize recovery or explicit unsupported refusal before modification.

## 4. NTFS implementation work

### NTFS-01: safe VBR and MFT bootstrap

**Own:** proposed `ffs-ondisk::ntfs` and `ffs-ntfs` bootstrap modules.
**Depends:** CORE-01/02; pure parsers can begin independently.

Validate sector/cluster geometry, signed file-record/index-record size encodings,
volume bounds, initial MFT location, and backup metadata. Locate update-sequence
arrays using bounded header fields, validate the protected sector tails, then
parse the restored FILE/INDX content. A fixup mismatch is not a warning to ignore.

Bootstrap record zero's data mapping and expand fragmented MFT mappings through
validated attribute-list references. Check base/extension record identity,
sequence, VCN coverage, duplicate references, and work limits. Preserve the
native distinction between MFT mirror coverage and the rest of the MFT.

**Acceptance:** native-created clean volumes; records crossing read boundaries;
negative size encoding edge cases; torn sector tails; fragmented MFT; extension
cycles; stale sequence; malformed attribute offsets; no out-of-range reads or
writes during rejected bootstrap.

### NTFS-02: attributes, streams, and exact data reads

**Own:** `ffs-ntfs` attribute/runlist/stream modules.
**Depends:** NTFS-01.

For each nonresident mapping-pair entry, validate the encoded length/offset field
widths, decode the unsigned run length and signed LCN delta, and check cumulative
VCN/LCN arithmetic. Sparse runs are not physical cluster zero. Verify continuation
attributes belong to the same native stream and supply coherent VCN coverage.
Bound traversal even when the claimed stream length is enormous.

Maintain allocated, data, and initialized lengths separately. Zero-fill only
native sparse/uninitialized regions; a damaged runlist is an error, not an
opportunity to invent zeros. Resident content also obeys record and attribute
bounds. Cache by file sequence, stream name, and view, not file number alone.

Add bounded LZNT1 decoding with compression-unit tests; list unsupported EFS/WOF
states precisely until their providers are implemented. Enumerate alternate
streams through a real public API rather than discarding them from file counts.

**Acceptance:** Windows-produced resident/nonresident/fragmented streams;
continuation attributes; signed negative LCN deltas; sparse and initialized-length
boundaries; alternate names; compressed-unit boundaries; corrupt compressed data;
stream-specific reads and hashes compared against independent consumers.

### NTFS-03: native namespace and security-preserving presentation

**Own:** `ffs-ntfs` indexes/names/security/reparse modules; core/FUSE adapter.
**Depends:** NTFS-02 and CORE-03.

Implement `$I30` B-tree traversal using the volume collation table, correct child
bounds, and validated FILE references. Resolve hard-link aliases to one native
file identity. Keep security descriptor references and raw descriptors available
before attempting a POSIX projection. Record reparse tags and translate only
explicitly supported semantics.

Wire read-only mount operations, streams, metadata, and precise unsupported
operation errors. A permissions presentation that cannot faithfully represent a
native descriptor must not grant extra host access as a fallback.

**Acceptance:** Windows Unicode/case/alias corpus; large indexes; hard links;
stale record references; deny/inherit ACL cases; junction/symlink/unknown reparse
cases; nested file reads; mounted image hash unchanged. NTFS read-only support is
not gated on implementing every future writer, but its admitted read profile
must name every unsupported transform/provider.

### NTFS-04: native log recovery and dirty-volume admission

**Own:** `ffs-ntfs` native log/recovery modules; read-only overlay integration.
**Depends:** NTFS-01/02 plus CORE-04/05.

Implement restart-area selection and validation, LSN ordering/wrap, transaction
analysis, redo/undo/compensation handling, checkpoint rules, and replay identity.
Inventory native recovery operations with independently generated interrupted
images. Unsupported operations or inconsistent chains fail before backing
mutation; do not partially replay and then claim read-only refusal.

A memory/temporary recovery overlay can expose a recovered read view while the
source stays immutable. Keep its identity distinct from the unrecovered image.
Writable admission includes hibernation/Fast Startup and native ownership checks;
never introduce a silent dirty-bit clear or journal discard.

**Acceptance:** repeat replay produces the same state; competing restart pages;
log wrap; torn records; uncommitted transaction undo; committed redo; crash during
replay; unknown operation; hibernated images; native Windows recovery comparison.
Where native behavior is not established, retain a restricted profile rather
than guessing journal semantics.

### NTFS-05: metadata transaction writer and complete ordinary mutations

**Own:** `ffs-ntfs` native transaction, allocator, attribute writer, and index writer.
**Depends:** NTFS-03/04.

Implement `$Bitmap` and MFT allocation with resource reservation; journal every
required associated change under the admitted native recovery vocabulary.
Support resident/nonresident conversion, attribute-list growth, index split/merge,
stream growth/truncate, create/mkdir, hard link, rename/replacement, unlink/rmdir,
and safe allocation reuse. Maintain native record fixups, sequences, link counts,
covered mirror records, directory references, and volume state.

Updates to file size, initialized length, and allocation must not reveal old
clusters. An interrupted resident-to-nonresident transition must select a valid
old or recoverable new representation, not a mixed attribute body.

**Acceptance:** Windows reopens and modifies every clean result; Windows and
FrankenFS recover admitted crash cuts; MFT/index growth under ENOSPC; unlink/open
handles; fragmented writes; stale-sequence rejection; no double allocation or
unreachable data silently reported as clean.

### NTFS-06: advanced native semantics, not hidden exclusions

**Own:** `ffs-ntfs` compression/security/extended-metadata/provider modules.
**Depends:** the relevant NTFS-05 transaction primitives.

Deliver compressed writes, sparse allocation changes, full stream lifecycle,
security descriptor/ACL edits, and the active secondary metadata obligations:
`$UsnJrnl`, object-ID, quota, and reparse indexes. Each feature includes native
accounting, deletion, recovery, and interchange, not just its decoder.

Add EFS only with explicit key handling and authentic native fixtures; distinguish
raw-preservation, decrypted read, and writable encryption capabilities. Separate
WOF or external reparse-provider integration from ordinary compression. An active
feature whose indexes would be invalidated by mutation blocks that mutation or
writable profile until implemented.

**Acceptance:** native change-journal observations; quota/index consistency;
ACL round-trips preserving deny/inheritance; compressed rewrite and truncation;
alternate-stream rename/delete; missing-key refusal; native encrypted round-trip;
crashes during the corresponding metadata updates.

### NTFS-07: checker, formatter, and offline resize

**Own:** `ffs-ntfs` maintenance modules and existing CLI integration.
**Depends:** NTFS-05 plus the feature obligations of the target maintenance profile.

Cross-check records, references, links, cluster ownership, native indexes, and
metadata-file invariants without writing. Keep damage, unsupported state, and
missing external checker distinct. Implement bounded explicitly authorized repair
only when ownership and recovery intent are established.

A native formatter must initialize the metadata files, native log, allocation,
collation, security defaults, mirror coverage, and backup metadata required by the
profile. Offline resize needs valid relocation and metadata publication; it is
not a BPB total-sector edit. Native Windows checking/interchange is mandatory.

**Acceptance:** fresh formatted volume used and checked by Windows; structural
repair choices; readonly checker byte equality; offline grow/shrink; interrupted
relocation; ordinary data and metadata outside the resize scope preserved.

## 5. ZFS implementation work

### ZFS-01: labels, configurations, and read-only pool ownership

**Own:** proposed `ffs-ondisk::zfs` low-level parsing and `ffs-zfs` import modules.
**Depends:** CORE-01/02.

Parse labels/nvlists/uberblock candidates with independent size and depth limits.
Construct the vdev graph and match pool/vdev identities before following a MOS
root. Candidate selection validates its complete required root and configuration;
a later TXG on a stale/forked device is not automatically authoritative.

Identify feature states and distinguish required data/special/log components
from optional cache. Enforce explicit pool selection and read-only behavior.
Attach all dataset views to one shared pool owner. Reject unsupported topology,
active feature state, or unresolved ownership before writable import is possible.

**Acceptance:** exported native pools; endian variants in the declared profile;
conflicting labels; truncated labels/nvlists; duplicate GUIDs; incomplete device
sets; wrong pool member; unsupported active GUIDs; missing special/cache/log
components classified separately; no backing writes during discovery/import.

### ZFS-02: block pointers and verified single-leaf reads

**Own:** `ffs-zfs` block-pointer, checksum, transform, and physical-read pipeline.
**Depends:** ZFS-01.

Implement DVA translation and physical/logical size validation, birth identity,
holes/embedded/gang representations, native byte order, checksum selection, and
bounded transform decoding for the initial profile. A block must be fully
validated before parsed contents or decoded data enter shared caches.

Keep physical block identity distinct from logical DMU offsets. Verify the native
transform sequence against encrypted and unencrypted fixtures before expanding
admission. Refuse unimplemented checksum/compression/encryption methods instead
of treating data as uncompressed bytes.

**Acceptance:** OpenZFS-produced blocks; valid/corrupt embedded and gang cases;
truncated/oversized reads; decompression bombs; alternate-endian structures;
logical versus physical size mismatch; strict no-partial-success behavior.

### ZFS-03: MOS, DSL, DMU, ZAP, and mounted datasets

**Own:** `ffs-zfs` metadata stack and ZPL adapter; core/FUSE dataset views.
**Depends:** ZFS-02 and CORE-03.

Implement MOS traversal, DSL dataset discovery, DMU object sets/dnodes and indirect
blocks, bonus/spill/system attributes, micro/fat ZAP, then ZPL namespace/data.
Support the selected root, native properties, directories, links, metadata,
xattrs/ACL presentation, sparse content, and immutable snapshot roots.

Use a view identity that distinguishes pool, dataset, snapshot/transaction root,
object number, and generation. Do not let a cache entry for the live dataset
satisfy a historical snapshot lookup. Dataset enumeration and property queries
must work independently of a mounted ZPL path.

**Acceptance:** OpenZFS dataset/file/property comparison; large objects, directories,
dnodes, and spill data; snapshots with later live changes; multiple datasets
containing the same object numbers; mounted read-only data hashes; unsupported
feature refusal without mutating the pool.

### ZFS-04: redundant topology and native reconstruction

**Own:** `ffs-zfs` vdev mapping, mirror, RAIDZ, and later advanced-layout modules.
**Depends:** ZFS-02; integrate dataset evidence through ZFS-03.

Implement mirrors, RAIDZ1/2/3, mapping/asize/padding, checksum-aware alternative
reads, and correct erasure reconstruction. A successful physical read with a bad
checksum is an invalid copy, not a reason to suppress retries. Missing and
corrupt members count against the same actual recoverability budget.

Treat dRAID, expanded RAIDZ, indirect vdev mappings, and allocation classes as
separate work inside this package, with separate tests and admission capabilities.
Do not claim advanced support because a simple RAIDZ arithmetic test passes.

**Acceptance:** native mapping/reconstruction oracle; varying widths, block sizes,
sector alignment, and native layouts; every tolerated erasure combination;
combined missing/corrupt copies; all-copy failure; cache isolation after a failed
candidate; independent native import/read of any repaired test image.

### ZFS-05: allocation, TXGs, and ordinary native writes

**Own:** `ffs-zfs` metaslab/space-map, DMU dirtying, TXG, and ZPL mutation modules.
**Depends:** ZFS-03, CORE-04/05; initial writer may admit only proven simple topology.

Implement allocation reservation, COW data/metadata generation, dependent writes,
space-map and accounting updates, TXG synchronization, durable root publication,
and recovery selection. Reconcile native durable TXG tokens with MVCC visibility.
Do not free blocks still reachable by a live view, snapshot, clone, or incomplete
transaction. Reserve enough metadata/recovery capacity to fail safely under ENOSPC.

Implement create/write/truncate/rename/unlink/directories and metadata in this
engine, not as edits to serialized blocks from the reader. Full TXG commit per
fsync is an acceptable first correct implementation; mark its performance cost.
Writable topology expansion waits for the corresponding mapping/allocation and
failure tests, even if its read-only counterpart already works.

**Acceptance:** native OpenZFS import/read/write/check of clean results; every
TXG publication cut; all children durable before referenced publication;
ENOSPC/flush failure; root selection after restart; ordinary namespace semantics;
space accounting and allocation reuse without corruption or permanent leaks.

### ZFS-06: foreign ZIL replay and native synchronous intent

**Own:** `ffs-zfs` ZIL parser/replayer/writer, integrated with native TXGs.
**Depends:** ZFS-05 transaction primitives; log parsing starts earlier.

Read and replay admitted native synchronous intent records with idempotent
restart behavior. Distinguish already incorporated transactions from still-needed
log work. Enforce log-device and ownership rules. An unsupported replay record
cannot be ignored merely because the dataset can otherwise be read.

After full-TXG synchronous writes are correct, add a native ZIL writer when
measurements justify it. It must meet the same acknowledged durability contract
and remain recoverable by OpenZFS. Never set a discard/replay-disable shortcut as
a mount default or equate SLOG with a generic volatile write cache.

**Acceptance:** native-created pending synchronous operations; repeated replay;
crash during replay; lost required log device; TXG/log overlap; fsync acknowledgment
cuts; native recovery of FrankenFS-written intent records.

### ZFS-07: shared references and dataset lifecycle

**Own:** `ffs-zfs` DSL lifecycle, reference/deadlist/accounting, replication modules.
**Depends:** ZFS-05/06; feature-specific dependencies are explicit.

Implement snapshot/clone create/destroy, holds, bookmarks, rollback where admitted,
quota/reservation/property behavior, and correct shared-block reclamation. Add
DDT and BRT paths separately; read support for shared blocks does not authorize
freeing them. Handle resumable long-running destruction/receive work.

Implement send and receive as separate capabilities, including admitted
incremental, raw, and resume forms. Validate stream bounds, feature compatibility,
base snapshot identity, and target authorization. Received metadata must not
choose arbitrary host paths or devices.

**Acceptance:** native snapshots/clones/shared writes; destroy in different orders;
reclaimed-space accounting after restart; failed quota operations; DDT/BRT reference
changes; native incremental/raw interchange; wrong-base and hostile receive
refusal; resumable operation after crash.

### ZFS-08: transforms, keys, and advanced feature completeness

**Own:** `ffs-zfs` feature registry, transforms, native encryption, key lifecycle.
**Depends:** ZFS-02/05/07 as appropriate.

Implement every read/write/recovery obligation in the pinned target feature
manifest, including the chosen checksum/compression families, native encryption,
large/embedded metadata forms, and interactions with shared data. Keep property
settings separate from the on-disk features already active in a pool.

Define key-root behavior, authenticated native representations, key wrapping,
nonce uniqueness, secure key sources, load/unload, and raw versus plaintext
access. Protect ciphertext without requiring keys only where immutable identity
and checksum/provenance constraints hold.

**Acceptance:** native transform fixtures and round-trips; corrupted ciphertext and
metadata; missing/wrong keys; key unload under active handles; raw receive;
encryption-root inheritance; mixed transformed/shared data; no secret output in
logs, sidecars, or artifacts.

### ZFS-09: pool lifecycle, scrub/resilver, and zvol frontend

**Own:** `ffs-zfs` pool administration; explicit host block-volume frontend for zvols.
**Depends:** the native write/topology/feature packages used by each operation.

Implement create/import/export, attach/replace/detach, online/offline, spares,
scrub/resilver, TRIM, checkpoint/rewind, and admitted removal/expansion protocols.
Native multihost protection must be implemented before admitting that writable
profile. Persist long-running progress with correct recovery and cancellation.

A replacement/resilver operation copies the correct allocated native versions,
not every physical byte indiscriminately. A special vdev is not detachable like
a cache device. Device removal/RAIDZ expansion/dRAID require their actual native
mapping protocols and independent proof.

Implement zvols through a separately specified block-device transport and the
same pool engine, including size, snapshots, I/O, flush, error, and lifecycle
semantics. Do not claim a zvol by exposing a regular file under FUSE.

**Acceptance:** native import after every lifecycle cut; replace and resilver under
foreground writes; missing-device safety; resumed progress; checksum-guided repair;
no writes on read-only scrub; zvol block/flush/snapshot tests and native interchange.

## 6. Protection integration work

### PROTECT-01: identity-bound immutable captures

**Own:** existing `ffs-repair` sidecar/live infrastructure and engine attachments.
**Depends:** native read-view identity plus safe storage ownership/capture.

Extend existing attachment identity rather than creating another parity file
format. Bind volume or pool storage set, geometry, selected native generation,
and protected byte/view coverage. Define forward/backward compatibility before
changing a persisted sidecar version.

For a multi-device pool, one member's sidecar is not protection of the pool.
Immutable capture must cover a coherent set. FAT/NTFS native serial numbers and
file paths are insufficient identity/freshness checks. Refuse capture from an
uncontrolled concurrently writable image; a successful final reread is not a
proof of exclusive access.

**Acceptance:** cloned/renamed path; serial collision; wrong pool member; topology
change; native legitimate modification; truncated sidecar; stale generation;
read-only keyless ciphertext capture where supported; bounded group memory.

### PROTECT-02: dirty-before-native, seal-after-native protocol

**Own:** live sidecar state machine and native commit integration.
**Depends:** PROTECT-01 and the native writer's durable tokens.

Persist invalidation before the first native modification in affected coverage.
Publish native changes through their real engine. Generate symbols from the
selected stable committed view, persist them, then seal the protection generation.
If any stage fails, keep the coverage dirty/unknown rather than advertising old
symbols as current. Reuse existing pending-work preservation and cancellation
rules instead of bypassing them with a new callback path.

Document native-durable versus protected-durable acknowledgment. Protected-durable
success waits for its required generation seal; ordinary native-durable success
can expose a known protection lag, but cannot label it fully protected.

**Acceptance:** faults independently on native and sidecar devices; invalidation
flush failure; native commit success with refresh failure; crash during symbol
write/seal; cancelled refresh; wrong native token; protected acknowledgment never
precedes its required durable seal.

### PROTECT-03: verified repair and native handoff

**Own:** repair admission/coordinator and explicit maintenance CLI operations.
**Depends:** PROTECT-02 plus native recovery and any native redundancy paths.

Recover native logs first when needed, use valid native redundancy next, and use
external symbols only for their exact authorized version. Never patch a live ZFS
block using a sidecar from an earlier birth/TXG. Never classify all differences
from a saved FAT/NTFS snapshot as bit rot.

For external FAT transactions, implement checkpoint/recovery and a clean handoff
that removes the dependency on the external log before native use. When the
current generation cannot be proven, report uncertainty rather than make a
plausible destructive repair.

**Acceptance:** legitimate-write versus corruption cases; stale symbols; native
mirror preferred over old sidecar; interrupted recovery; native reopen after
repair/handoff; authenticated-provenance policy where required; no repair in a
strict read-only operation.

## 7. Crash cut matrix: concrete minimum campaigns

Each row requires a real native operation, a fresh restart against durable bytes,
and a native oracle where the claim depends on interchange. `ACK` means the
operation's promised durability acknowledgment, not its submission or buffered
write return. The matrix is a minimum, not an exhaustive crash proof.

### 7.1 FAT16/FAT32

| Cut or injected fault | Required observation |
|---|---|
| Data initialized, new chain not published | Old namespace remains valid; reserved/lost clusters are accounted for under the declared interrupted-operation contract. |
| Chain extended, larger length not published | Old logical EOF does not expose allocation slack; checker reports any permitted leak accurately. |
| Length publication attempted before required data flush | Test must detect the invalid ordering; this is not an allowed implementation. |
| Shrink length published, tail not yet freed | Removed bytes are no longer visible; possible unreclaimed tail is diagnosed without assigning it to another file. |
| Deleted directory entry, chain not yet freed | Name remains absent or follows the specified native interrupted outcome; allocation cannot be silently reused while still reachable. |
| One mirrored FAT updated and another write fails | Dirty state and disagreement are reported; no arbitrary clean success or majority-based ownership guess. |
| LFN slots written, short entry absent/torn | No fabricated long-name association with a neighboring file. |
| Target/source/`..` cuts during cross-directory rename | Exactly documented native outcomes, including fsck requirements; never claim general atomic rename from these writes. |
| FSInfo/backup hint stale after successful data mutation | Valid data/chain state remains authoritative; hints cannot double-allocate clusters. |
| ACK followed by simulated loss of only unflushed writes | Every obligation included in that acknowledgment survives; successful flush guarantees are honored by the model. |
| Final clean-state flush fails | Unmount/sync reports failure; next open cannot trust an unpersisted clean transition. |
| External recovery present, source opened by a native reader | Demonstrate and document the checkpoint/handoff boundary; native recovery cannot be credited with understanding the external log. |

Run every relevant row on both FAT variants and with physical-sector/cache-page
mismatches. Fill reused clusters with distinctive old contents to catch stale
exposure; all-zero fixtures hide this class of defect.

### 7.2 NTFS

| Cut or injected fault | Required observation |
|---|---|
| FILE/INDX update-sequence mismatch | Record rejected or recovered using an independently justified native path; never parsed as intact. |
| Log record durable, dependent metadata absent | Native replay selects and applies the required operation correctly. |
| Uncommitted metadata transaction interrupted | Native undo/compensation restores an allowed state; mere redo is insufficient. |
| Commit/restart/checkpoint torn | Restart selection and transaction outcome follow validated native semantics. |
| Crash during replay | Repeating recovery is safe and converges; already replayed changes are not applied twice incorrectly. |
| Resident-to-nonresident or attribute-list transition cut | Stream has one coherent recovered representation with correct initialized/data lengths. |
| MFT/index growth with allocation failure | No duplicate record/cluster ownership, invalid index references, or false successful create. |
| Rename/link update interrupted across parent indexes | Native reference/link/index invariants recover coherently. |
| Active secondary index maintenance interrupted | `$UsnJrnl`/object-ID/quota/reparse obligations remain recoverable, or writes were refused before mutation. |
| Hibernated/unsupported log state | Writable open fails without clearing flags, deleting hibernation content, or partially replaying. |
| ACK then restart in Windows | Native recovery preserves the exact promised file/namespace state for the admitted profile. |
| Missing EFS key or unsupported reparse provider | Data access fails precisely; no ciphertext-as-plaintext or invented empty content. |

Native recovery vocabulary must be derived from captured native behavior and
reviewed references. The matrix does not prescribe guessed `$LogFile` opcodes.

### 7.3 ZFS

| Cut or injected fault | Required observation |
|---|---|
| New child blocks written, parent/root not published | Previous committed tree remains selected; new unreachable allocations are accounted for/reclaimable. |
| Parent published before a required child is durable | Negative test identifies a protocol violation; this is never an allowed success. |
| Torn or inconsistent uberblock candidate | Selection validates coherent configuration/root state rather than highest TXG alone. |
| Independently faulted pool members | Native recovery selects a consistent supported pool state, not a mixture of incompatible generations. |
| Valid ZIL intent, TXG not yet incorporating it | Replay preserves acknowledged synchronous operations under native semantics. |
| TXG incorporates an intent, log reclamation interrupted | Replay does not duplicate already incorporated work incorrectly. |
| Missing required SLOG/special storage, optional cache absent | Correctly distinct admission decisions; no silent acknowledged-data loss disguised as cache removal. |
| Snapshot/clone references live while a file is rewritten/freed | No live or historical view loses shared blocks; accounting converges after deletion/restart. |
| Mirror/RAIDZ read succeeds physically but checksum fails | Alternate/reconstruction path validates content before publication; all-copy failure returns an error. |
| Replace/resilver/removal/expansion interrupted | Native progress and mappings recover correctly, or the unimplemented operation was refused before changes. |
| Unknown active feature or unresolved encryption key | Import/read/write follows exact profile restrictions; feature presence is not silently ignored. |
| ACK then native OpenZFS import | Promised synchronous contents survive native recovery, including the selected topology and transform profile. |

Read-only verification and automatic healing are different campaigns. A read-only
scrub that corrects one byte is a failed read-only test, even if the correction
was otherwise accurate.

### 7.4 Cross-device protection protocol

| Cut | Required observation |
|---|---|
| Invalidation not durable | Native mutation has not started. |
| Invalidation durable, native mutation not committed | Old symbols are not treated as current authority for an uncertain changed group. |
| Native commit durable, new parity absent | Native-durable state is retained; protection lag is explicit and repair refuses stale symbols. |
| New parity partly durable, seal absent | Incomplete generation is ignored/quarantined, not selected as newest merely by timestamp. |
| Seal durable, ACK not returned | Recovery recognizes the sealed generation; retry does not regress to the old one. |
| Wrong storage/view/token paired with a valid-looking sidecar | Attachment/repair is refused. |
| Native recovery changes the selected generation | Revalidate protection binding before using any saved symbols. |

## 8. Native oracle workloads and fixture construction

### 8.1 Shared operation corpus

Create native images, populate them with an independent producer, and perform a
fixed operation stream through FrankenFS: empty files, mixed-size files,
fragmentation, random positioned writes, growth/shrink, directory churn,
rename/replacement, open-unlink, allocation exhaustion, and repeated sync/reopen.
Use nontrivial deterministic content, not only zeros. Validate names, metadata,
allocation, and content separately.

Then reverse the direction: native systems consume and modify FrankenFS-written
images, which FrankenFS reopens. Neither direction may be skipped for a full
interchange claim. Take byte-identical fixture copies for independent runs; never
mount one backing writable in both systems to compare them.

### 8.2 FAT-specific fixture set

Include independently created FAT16/FAT32 volumes near classification boundaries,
small/full fixed roots, active-FAT versus mirrored FAT32, multiple admitted sector
sizes, fragmented directory/data chains, maximal long names, Unicode/code-page
aliases, deliberate table disagreement, and lies in FSInfo hints. Record the
actual formatter options and native resulting geometry, not only a intended size.

Windows and mtools naming disagreement is a compatibility question to resolve,
not permission to silently pick the easier oracle. Keep the normative layout
profile and explicitly admitted implementation quirks distinct.

### 8.3 NTFS-specific fixture set

Create fixtures with Windows versions/options recorded: resident and nonresident
streams, fragmented MFT and attribute lists, sparse/initialized-length edges,
normal compression, alternate streams, hard links, security descriptors,
reparse tags, active change/secondary indexes, encrypted content with controlled
test keys, and interrupted native transactions.

Maintain clean and dirty images as separate fixture classes. Read-only mount
success on a clean image provides no evidence about replay. NTFS3 and NTFS-3G
are additional native-format consumers/producers, not substitutes for Windows
interchange when that is the advertised contract.

### 8.4 ZFS-specific fixture set

Use a pinned OpenZFS version and explicit feature settings. Start with exported
single-leaf pools; expand to mirrors/RAIDZ widths, native checksum/compression
families, large metadata, snapshots/clones, DDT/BRT, encrypted datasets,
allocation classes, pending synchronous intent, and lifecycle-interrupted pools.

Do not rely on whatever features a host's current default `zpool create` happens
to enable. Record actual enabled/active GUIDs and the vdev graph from the created
image set. A source tag without the executed tool/kernel identity is incomplete
provenance. Key-bearing fixtures use nonproduction test material with explicit
handling, never personal or production pools.

### 8.5 Test lane boundaries

Pure parser/model tests can run without a mount. Core integration reads need
real images. FUSE tests need a real mount and syscalls. Native interchange and
storage-failure campaigns need their native tools or isolated VMs. Use the
repository-approved RCH execution route for heavy Cargo work; do not introduce
an unauthorized local fallback to obtain a green result.

Missing required native tools or mount capability means missing evidence. Local
optional smoke tests may explicitly skip, but cannot satisfy release acceptance.
Retain exact test counts and scope; a filter matching zero tests is not a pass.
No administrative schema test substitutes for the operation named by a gate.

## 9. Commit boundaries and non-goals for the implementation sessions

Use coherent direct-to-main increments containing implementation plus focused
regressions. A good FAT increment reads a real native directory/file through the
core; a good NTFS increment resolves a fragmented stream with native comparison;
a good ZFS increment imports a real pool root and reads a dataset object.

Before touching a shared source path, inspect current main and relevant beads so
ongoing ext4/btrfs work is preserved. Associate real implementation beads with
these work packages where useful, but do not bulk-rewrite the existing JSONL
tracker or close an implementation task because a plan or refusal test exists.

Do not add empty backend crates, fake successful format commands, constant
capability flags, globally permissive feature handling, assumed device ownership,
unsafe journal-discard options, or broad allowlists hiding native discrepancies.
Do not spend the first implementation session building a new report catalogue.

Completion of this companion means the implementation work is specified, not
performed. The next useful work is CORE-01 plus FAT-01/02's real vertical slice,
followed by FAT-03's mounted path and the first native allocation/crash campaign.
