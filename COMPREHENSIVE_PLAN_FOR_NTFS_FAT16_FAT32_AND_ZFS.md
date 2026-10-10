# Comprehensive Plan for Native NTFS, FAT16, FAT32, and ZFS Support

> Design baseline: 2026-10-09, repository commit `200ab6303996e50933ad3307e302ea54d98c98d8`.
>
> **Status: proposed implementation plan, not implemented filesystem support.**
> This document adds no capability claims to `FEATURE_PARITY.md`. Every API,
> command, crate, profile, and test marked proposed below is work to implement.
> Existing ext4/btrfs behavior remains authoritative until a tested migration.
>
> This extends, rather than replaces, `COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md`,
> `PLAN_TO_PORT_FRANKENFS_TO_RUST.md`, and `PROPOSED_ARCHITECTURE.md`.
> The implementation companion is
> [NTFS/FAT/ZFS implementation work packages](docs/NTFS_FAT_ZFS_IMPLEMENTATION_WORKPACKAGES.md).

## 1. Executive decision

Implement three additional native storage engines, exposing four filesystem
flavors: a shared **FAT16/FAT32 engine**, an **NTFS engine**, and a **ZFS pool and
dataset engine**. Preserve ext4 and btrfs as first-class backends throughout.

The highest-value change is not adding four signatures to a detector. It is
making the existing core correctly separate filesystem semantics, physical
geometry, native durability, and FrankenFS-specific protection. Without that
separation, a superficially working reader can become a corrupting writer.

The implementation order is:

1. Extract the minimum backend admission and native-commit seams needed for an
   end-to-end FAT reader; preserve ext4/btrfs through adapters and regression tests.
2. Deliver FAT16 and FAT32 together: complete mounted reads, native mutation,
   honest crash semantics, checking, formatting, and optional external protection.
3. Deliver NTFS reads and preservation first, then native recovery and mutation,
   followed by its advanced stream, security, compression, and encryption surface.
4. Develop ZFS in parallel after the common I/O seam stabilizes. Start with a
   clean single-leaf pool, but build a real pool engine: vdev topology, block
   pointers, MOS/DSL/DMU/ZPL, TXGs, intent-log recovery, and lifecycle operations.
5. Close each format's complete declared feature profile with native-system
   interchange, mounted operations, storage-fault recovery, and protection tests.

Do not wait for every historical ext4/btrfs bead to close before starting. A
specific shared durability or repair defect blocks the new path that uses it;
legacy documentation cleanup and unrelated performance work do not.

## 2. What was inspected and what it establishes

### 2.1 Repository sources

The baseline review covered the original comprehensive specification and porting
plan, `AGENTS.md`, `Cargo.toml`, `PROPOSED_ARCHITECTURE.md`, `FEATURE_PARITY.md`,
`.beads/issues.jsonl`, `.beads/pending_tasks.md`, the core format-selection and
`OpenFs` implementation, and the external repair-sidecar entry point.

| Existing surface | Useful foundation | Gap relevant to this expansion |
|---|---|---|
| `crates/ffs-core/src/lib.rs` | `FsFlavor`, detection, `OpenFs`, mount orchestration | The inspected flavor enum has ext4/btrfs, not these four formats; admission and dispatch must expand without treating all disks as ext4-like volumes. |
| `ffs-block` | Byte/block I/O, caching, cancellation-aware operations | Add bounded volume views and explicit geometry/address domains; reuse physical I/O, not filesystem-specific mapping assumptions. |
| `ffs-ondisk` | Checked ext4/btrfs parsing | New independent FAT, NTFS, and ZFS format grammars and hostile-input coverage are needed. |
| `ffs-alloc`, `ffs-dir`, `ffs-extent`, `ffs-journal` | Existing ext4-oriented algorithms and JBD2 integration | Buddy/Orlov allocation, htree layout, extents, and JBD2 are not interchangeable with FAT chains, NTFS attributes, or ZFS space maps/TXGs. |
| `ffs-btrfs` and attached-device routing | Device identity checks, bounded reads, checksum-verified alternatives | Reuse engineering patterns; do not copy btrfs chunk/RAID formulas into ZFS. |
| `ffs-fuse` / `FsOps` | A protocol adapter already separated from format engines | Audit format-specific ioctl, name, inode, permission, and root assumptions before new backends enter the dispatch path. |
| `ffs-mvcc` | Versioning, conflict detection, durability infrastructure | A committed MVCC sequence must be reconciled with each native engine's actual recovery/publication boundary. |
| `ffs-repair/src/sidecar.rs` and its `live` module | External RaptorQ protection already exists | Extend this implementation and its identity/freshness rules; do not invent a second incompatible sidecar format. |
| `ffs-harness` and parity execution | Exact contract-to-test mappings and external-image comparisons | Add genuine native-oracle and mounted coverage; parser tests alone must not grant filesystem support. |

This is a source/design review, not a fresh executed performance, crash, or
conformance result. The older pending-task summary is not a substitute for the
JSONL tracker or newer source changes.

### 2.2 Lessons from the beads that change this design

The inspected tracker and parity notes distinguish completed scaffolding from
completed behavior. In particular, `bd-0r0kc` closed by removing hollow gate5 and
gate7 wrappers: that restored truthful `not_implemented` reporting; it did not
supply the missing mounted gates. Similarly, the earlier filesystem-semantics
track `bd-29o` closed a read-only milestone while deferring writes.

`FEATURE_PARITY.md` identifies remaining execution binding under `bd-wh1xk` /
`bd-lc132`, and distinguishes the repair integration work from default repair,
reserved native storage, and mounted restart freshness under `bd-11a8t` /
`bd-j7a4e`. The latest reviewed commit concerns remaining btrfs count/seed
admission under `bd-hk5w3`; the architecture still states that multi-device btrfs
writes are unsupported.

These references are dependency leads, not a claim that every referenced bead
has been independently re-executed or that this is the complete live backlog.
Re-read their current rows before claiming implementation work. Do not bulk-edit
or close existing beads based on this plan. Plan-local work-package identifiers
in the companion are not newly created beads.

## 3. Define full support before choosing shortcuts

### 3.1 A complete declared profile, not a moving universal claim

A release must name its admitted filesystem revisions, on-disk feature set,
topologies, operations, geometry envelope, and host presentation policy. Full
support means all obligations of that profile are implemented and independently
validated. It must not mean 'magic recognized', 'can list a fixture', or 'ordinary
files work provided every advanced feature is absent'.

Initial restricted profiles are useful deliverables, but remain explicitly
restricted. The end-state feature obligations below stay on the roadmap rather
than disappearing from the denominator as inconvenient work.

| Dimension | Completion requirement |
|---|---|
| Discover and inspect | Correct type, revision, geometry, identity, feature inventory, and refusal reasons, including ambiguous/truncated images. |
| Read | Complete native namespace and data interpretation for the profile; no silent skipping of unsupported streams, transforms, or datasets. |
| Mutate | Create, write, truncate, rename, unlink, directories, metadata, allocation, and reclamation with native semantic fidelity. |
| Recover | Read foreign-system recovery state and recover FrankenFS-written interruptions according to the native format and declared durability contract. |
| Interchange | Native systems can read, modify, check, and reopen FrankenFS-written media, and vice versa, without an undocumented conversion step. |
| Operate | Real CLI/FUSE paths, precise errors, cancellation, resource limits, lifecycle handling, and useful diagnosis. |
| Maintain | Non-mutating consistency checks, explicitly authorized repairs, allocation accounting, and format-appropriate scrub behavior. |
| Create and evolve | Native formatting/creation and declared resize, pool, dataset, and device lifecycle operations. |
| Protect | MVCC and RaptorQ integration with explicit generation binding, storage ownership, and crash-safe freshness semantics. |

### 3.2 Native semantics are not universally POSIX semantics

FAT does not acquire native hard links, Unix owners, ACLs, sparse files, or
snapshots because the host API offers them. Unsupported operations must fail
precisely or use a clearly identified optional emulation profile. Emulated
metadata cannot be advertised as native interoperability.

Conversely, NTFS alternate streams and security descriptors, and ZFS datasets,
snapshots, encryption roots, and pool devices, must not disappear behind the
lowest common denominator of a POSIX directory tree.

### 3.3 Scope boundaries

The end target is native FAT16/FAT32, NTFS 3.x with 3.1 first, and an explicitly
pinned OpenZFS compatibility profile plus separately tested historical formats.
The design does not automatically admit every future feature GUID or every
historical implementation quirk.

FAT12 and exFAT are separate formats, not accidental extensions of this project.
Detect them accurately and refuse unsupported use. BitLocker is a volume
transformation outside NTFS; it needs a separate block-layer provider and key
policy. Proprietary Oracle ZFS extensions, Windows kernel/filter-driver ABI
emulation, network-filesystem protocols, and bootloader implementation are not
implied by filesystem-format support.

WOF/cloud reparse providers, Windows transactional APIs, and other external
services need named integration capabilities. Preserve their native metadata;
never turn an unsupported provider into an ordinary file containing misleading
bytes. Native NTFS EFS and OpenZFS encryption remain explicit advanced targets,
not capabilities silently counted as complete because metadata can be listed.

## 4. Non-negotiable invariants

- A strict read-only open performs **zero backing writes**: no atime, replay,
  dirty-bit clearing, pool-import bookkeeping, automatic healing, or sidecar
  attachment mutation. A separate writable recovery action is explicit.
- A native read-write open cannot succeed until all encountered metadata needed
  to mutate the admitted profile is understood. Unknown is not equivalent to
  harmless, and successful parsing is not write admission.
- The same native storage domain has one writer. File locks exclude cooperating
  processes only; they do not prove that a kernel mount or another host is absent.
- Acknowledged durability has a documented native recovery boundary. FUSE
  `flush`, `fsync`, `fdatasync`, directory synchronization, and unmount are not
  interchangeable events.
- Data is initialized before it becomes readable. Logical EOF and initialized
  length must not expose old contents from a reused cluster, block, or record.
- Cancellation before publication aborts or leaves recoverable work. After a
  durable commit point it cannot make a committed mutation appear rolled back.
- Read, recovery, allocation, checksum, decompression, and name parsing are
  bounded by explicit byte, depth, count, and work limits.
- A failed read never leaks partially validated data from a corrupt replica into
  the caller's successful output or the shared cache.
- Sidecar mismatch is not permission to restore an earlier legitimate generation.
  Native format recovery and native redundancy precede speculative repair.
- First-party Rust continues to forbid unsafe code and uses the existing
  asupersync/Cx conventions. This is not a claim that every third-party dependency
  or the vendored FUSE transport contains no unsafe implementation.

## 5. Architecture: reuse infrastructure, not incompatible semantics

### 5.1 Crate ownership

Proposed format engines are `ffs-fat`, `ffs-ntfs`, and `ffs-zfs`. Introduce a crate
only with a real parser/read path and tests, not an empty workspace placeholder.
FAT16 and FAT32 share an engine with a validated dialect enum.

Low-level pure format parsing should live under `ffs-ondisk::{fat,ntfs,zfs}` when
that preserves the existing dependency direction. ZFS-only higher-level metadata
interpretation belongs in `ffs-zfs`; do not create two copies of the same parser
for an artificial symmetry with ext4.

`ffs-core` owns admission, common mount policy, backend selection, request
lifecycle, and the mapping to `FsOps`. `ffs-fuse` remains the protocol adapter.
The public `ffs` facade should expose format-neutral file operations and explicit
format-specific administrative APIs without requiring callers to import private
backend internals.

Use the existing block, cache, observability, error, MVCC, repair, and harness
infrastructure where its contracts actually match. No dynamic plugin loader,
general-purpose storage framework, or wholesale core rewrite is a prerequisite.

### 5.2 A small backend seam

Initially, closed enum dispatch is adequate and makes unsupported combinations
visible to the compiler. Conceptually, an admitted backend contains:

```text
BackendDescriptor
  flavor / native_revision / feature_profile
  selected_storage_identity / geometry
  supported_operations / native_semantics
  admission_decision / refusal_reasons
  read_view / native_commit_engine / optional_protection_attachment
```

These are proposed responsibilities, not a required public Rust signature.
Separate immutable detection results from a writable admitted instance. A
boolean such as `is_supported` or `writable` cannot express read-only transforms,
unsupported recovery state, missing devices, key requirements, and durability.

The public flavor vocabulary should include `Ntfs`, `Fat16`, `Fat32`, and `Zfs`.
Do not serialize FAT dialects or feature-bit values into an unstable display
string that later becomes the only machine-readable interface.

### 5.3 Strangler migration, not a rewrite gate

First route the existing ext4 and btrfs opens through an admission result while
preserving their behavior and exact errors. Then add FAT's real read-only
vertical slice. Extract another common operation only when at least two concrete
backends need it.

Keep native transaction, mapping, and allocation implementations private to their
engines. Do not move a format-specific algorithm into a generic crate merely to
avoid an enum match. Preserve optimized hot paths until equivalent behavior and
cost are measured.

## 6. Devices, volumes, pools, and geometry

### 6.1 Bounded device views

A proposed `VolumeDevice` wraps a byte device with a checked base offset and
length. Validate every addition, multiplication, alignment conversion, and
read/write span against both the selected volume and the actual backing.
Logical sector size, physical write granularity, filesystem allocation unit,
cache page size, and repair-symbol block size are different quantities.

Explicit image/partition selection is mandatory when multiple plausible
filesystems exist. Support raw volume images first. Add MBR/GPT discovery using a
bounded parser with header/table checks, overlap detection, and explicit
selection; never silently choose a partition because one signature matched.
Formatting a selected volume must not overwrite the partition table or adjacent
volumes. Partition resizing is a separate authorized operation.

### 6.2 Address domains and identity

Do not overload one `BlockNumber` with all of these meanings:

| Engine | Important separate domains |
|---|---|
| FAT | Device byte, logical sector, FAT entry, data cluster, directory slot |
| NTFS | Device byte, cluster/LCN, attribute VCN, MFT record plus sequence, stream |
| ZFS | Pool GUID, vdev GUID and physical offset, block pointer/birth, objset, object |

Use checked newtypes or typed mapping structures at the boundaries. A cache key
must include the backing identity, view/generation, and the relevant address
domain; otherwise two datasets or volumes can alias one another.

A FAT serial number and length are not strong attachment identity. An NTFS
serial number is not sufficient evidence that an external writer has not changed
the volume. A ZFS pool GUID without topology and selected TXG is not enough to
bind a multi-device protection snapshot.

### 6.3 ZFS is not one more partition-sized filesystem

A pool owns a graph of vdevs, allocation, transaction groups, datasets, and
recovery state. Multiple dataset mounts share one pool owner and one writer
coordination domain. Never open each dataset as an independently writable pool.
A dataset export to FUSE is a view of the pool engine, not its replacement.

## 7. Namespace, metadata, and FUSE contracts

### 7.1 Lossless names

Audit `FsOps`, FUSE dispatch, lookup caches, directory cookies, CLI output, and
public structs for UTF-8-only assumptions. Unix filenames are byte strings;
NTFS names and FAT long names have UTF-16-based native representations, while
short FAT names have code-page rules. A display conversion must not become the
lookup key.

Define a native-name type and a collision-checked presentation policy. Preserve
raw code units for names that cannot be represented losslessly in the selected
host policy. Normal mode should reject creation of unrepresentable names rather
than substitute replacement characters. A reversible forensic encoding, when
provided, must reserve its escape syntax and detect collisions with real names.

NTFS comparison uses the volume's collation information, including `$UpCase`;
FAT short-name comparison follows its selected code page and case rules. ZFS
comparison is governed by the dataset's native case/normalization properties.
Do not apply the current host's generic Unicode casefold to all three.

### 7.2 Object and handle identity

Map the FUSE root node to each backend's native root. Do not assume native inode
2, NTFS record 5, a FAT synthetic root, and a ZFS dataset root are interchangeable.
Include NTFS record sequence and ZFS dataset/object generation in stale-handle
checks. FAT needs a mount-lifetime object table that survives directory-slot
relocation and rename; a directory-slot byte offset alone is not an inode.

Define open-unlink, rename-overwrite, hard-link aliasing where supported, lookup
reference release, directory pagination, and handle reuse before enabling writes.
FAT export-stable handles across remounts are a separate capability requiring
persistent identity; do not promise NFS-export semantics from transient IDs.

### 7.3 Metadata policy

Return native precision and representability limits for time, file size,
allocation, attributes, and ownership. FAT ownership/mode defaults are mount
policy, not persisted Unix metadata. NTFS security translation must preserve the
underlying descriptor, and ZFS ACL/property handling must respect the selected
ZPL profile. Never report successful chmod/chown while dropping meaningful ACLs.

Expose alternate streams through explicit stream APIs/commands. Large stream
content is not a POSIX xattr payload. A colon convention can be an opt-in
presentation, but must not ambiguously reinterpret a legitimate native name.

Unknown native attributes and reparse metadata must remain inspectable and
preserved where safe. A mutation that requires interpreting them is refused.
Symlink/reparse handling must not cause the engine itself to follow host paths
while resolving an image; return or translate targets only under an explicit
mount presentation policy.

### 7.4 Operations and errors

Publish capabilities for readlink, hard links, xattrs, ACLs, sparse allocation,
clone/reflink, direct I/O, flags, labels, snapshots, streams, and native ioctls.
Distinguish unsupported format behavior (`EOPNOTSUPP`), unknown ioctl (`ENOTTY`),
read-only state (`EROFS`), corruption/I/O failure, stale object, no space, name
collision, and invalid geometry. A generic `EIO` is not an admission policy.

## 8. Native durability and FrankenFS MVCC

### 8.1 Separate visibility from durable native publication

A version visible to FrankenFS is not automatically recoverable by a native
filesystem implementation. The backend must produce a native durable token
only after its required protocol reaches a recoverable commit boundary.
Associate that token with MVCC `CommitSeq` and view identity.

| Backend | Native mechanism to respect | Prohibited shortcut |
|---|---|---|
| Existing ext4 | Existing JBD2/data-ordering integration | Treat a buffered MVCC commit as a completed journal commit. |
| Existing btrfs | Its COW/tree-log/full-transaction protocols | Generalize single-device success to arbitrary multi-device writes. |
| FAT16/32 | Carefully ordered metadata/data writes; no native journal | Claim atomic multi-sector transactions from block sorting. |
| NTFS | `$LogFile` recovery and native metadata transaction ordering | Substitute `$UsnJrnl` or a FrankenFS-only WAL for native recovery. |
| ZFS | Pool-wide TXGs, block-tree publication, and synchronous intent semantics | Treat COW or an uberblock write alone as a complete durable commit. |

The existing sorted-buffer writer and journal interfaces must not become the
universal commit engine. Share dependency-ordered I/O primitives, not native
transaction rules.

### 8.2 Write intent and outcomes

Represent mutation intent sufficiently to preserve allocation, data
initialization, directory publication, recovery logging, and reclamation order.
Record whether an error occurred before a commit, after durable commitment, or
with an uncertain outcome requiring recovery. Do not blindly retry a committed
rename because cancellation arrived while forming the FUSE reply.

`fsync` must cover the file's recoverable data and required metadata. Directory
`fsync` covers namespace durability under the declared backend semantics.
`flush` may report deferred errors, but closing a file is not an implicit promise
that all prior data is power-loss durable. Full-pool/full-volume synchronization
is an acceptable early correct implementation when explicitly measured; optimize
only after correctness.

### 8.3 Optional external transaction protection

FAT can use an external redo/undo mechanism for stronger FrankenFS-managed
recovery, but that is an enhanced profile, not a new native FAT journal. A
foreign OS will not replay it. Before handoff, finish recovery, checkpoint all
native changes, flush, and cleanly detach the external transaction dependency.
A native system inspecting an interrupted enhanced mount must be warned that
FrankenFS recovery may still be required.

For NTFS and ZFS, an external WAL is not a replacement for the native protocols
required to exchange dirty or crash-interrupted media with their native systems.

## 9. FAT16 and FAT32: full implementation design

### 9.1 Geometry and recognition

Use the BPB's checked geometry to calculate data sectors and cluster count.
The conventional classification is FAT12 below 4,085 data clusters, FAT16 below
65,525, and FAT32 thereafter; also validate the corresponding layout, table
capacity, root rules, and reserved values. Do not classify from the textual
`FAT16`/`FAT32` label alone. Boundary compatibility quirks must be isolated by
native formatter/reader fixtures, not accepted by weakening all validation.
References: [F1], [F2], [F3].

Validate bytes per sector, sectors per cluster, reserved region, FAT count and
size, total sectors, root entries/root cluster, selected volume bounds, and the
capacity for all reachable FAT entries. A superfloppy and a partition-backed
volume share the validated engine after selection, not different arithmetic.

For FAT32, honor the active-FAT and mirroring policy. Mask the low 28 bits for
cluster interpretation and preserve reserved high bits on updates. Treat FSInfo
free-count/next-free values as hints requiring validation, not allocation truth.
Validate backup metadata; do not arbitrarily choose one disagreeing FAT or boot
record merely because it is first or in a numerical majority.

### 9.2 Read path

Implement FAT16's fixed root and FAT32's root cluster chain through a common
directory iterator. Follow cluster chains with legal-value checks, a work bound,
and cycle detection. Distinguish end-of-chain, free, reserved, bad, and
out-of-range entries. A file whose recorded size requires unavailable clusters
is not a successful short read.

Parse ordinary 32-byte directory entries, deleted/end markers, volume labels,
short names, long-name sequences, checksums, ordering, terminators, and UTF-16
code units. Long-name chains are bounded; malformed chains must not steal the
short name belonging to a different file. Preserve the native short alias and
case flags, and test alias collisions against an independent implementation.

Read only within logical EOF. Support fragmented files, empty files, full root
directories, deeply nested but bounded directory walks, and clusters that cross
host cache-page boundaries.

### 9.3 Mutation and allocation

Implement file/directory creation, positioned reads/writes, growth, truncation,
rename within/across directories, overwrite, deletion, directory extension,
timestamps, DOS attributes, labels, and clean unmount. Reserve enough directory
slots for the entire long-name/short-name set before publishing it.

Allocation is a FAT-chain allocator, not ext4 block allocation. Cache bounded
free-space search hints but validate the chosen entries and mirror policy under
the transaction lock. Prevent two files from allocating one cluster. Initialize
newly exposed bytes, including gaps on writes beyond EOF. The maximum native
file length is `2^32 - 1` bytes; reject overflow before changing disk state.

Open-unlink and rename-overwrite need a mount-lifetime orphan/handle strategy.
Delay reuse while a live handle can still reference content. Native FAT has no
persistent Unix orphan list; crash handling must account for leaked allocation
rather than pretending the in-memory table survives a restart.

### 9.4 Crash ordering

Growth must initialize data before publishing a reachable allocation/length.
Shrink must stop exposing removed bytes before freeing their clusters. Deletion
must sever namespace reachability before clusters can be reused. New directory
publication must not expose uninitialized `.`/`..` or a partially initialized
chain. Mirrored table updates, parent movement, directory slots, and FSInfo hints
have separately defined ordering and failure behavior.

**There is no general native FAT atomic rename or metadata transaction produced
by ordering alone.** Specify the allowed interrupted outcomes and the boundary
at which fsck may be required. A cleanly completed operation must be natively
consistent; an interrupted operation may leave repairable leaks, but must not
silently expose old unrelated data or report corrupt contents as correct.
Fault tests must preserve all previously acknowledged durable obligations.

Set and persist the native dirty/error state where the dialect supports it;
clear clean state only after all required data, metadata, and flushes succeed.
An error in the final clean-state flush is an error, not a successful unmount.
Offer stronger externally recoverable transactions only under Section 8.3.

### 9.5 Checking, repair, creation, and evolution

The checker computes reachability, chain ownership, cross-links, lost chains,
size/chain consistency, directory structure, mirror disagreements, and hint
accuracy without modifying the volume. Cross-link ownership is not generally
inferable from a bitmap; ambiguous repair needs an explicit operator choice.

Provide native FAT16/FAT32 formatting for fresh authorized targets using valid
geometry, reserved entries, root initialization, serial/label policy, FAT32
backup structures, and independently checked results. Start with offline resize;
validate relocation/accounting before reducing the last usable cluster. Any
partition-table change is outside a volume-only formatter's authority.

Native consistency checking cannot detect arbitrary file-content bit rot without
an independent checksum source. External RaptorQ protection adds that evidence;
it does not retroactively prove that every changed byte was corruption.

### 9.6 FAT completion gate

Both dialects must pass the same operation corpus, adjusted for native geometry
and root semantics, on independently formatted images. Required oracles include
dosfstools/mtools and Windows or another native system for naming and interchange.
Power-failure outcomes are evaluated against the declared native versus enhanced
profile; neither profile is allowed to masquerade as the other.

## 10. NTFS: full implementation design

### 10.1 Bootstrap and safe metadata parsing

Start with NTFS 3.1 and add 3.0 through an explicit profile. Validate volume boot
geometry and signed record-size encodings with checked arithmetic. Decode FILE
and INDX records only after validating their update-sequence protection and
record bounds. Sequence numbers participate in reference validity, not merely
in display output. References: [N1], [N2], [N3].

Bootstrap `$MFT` from its own initial record, then resolve fragmented MFT extents
and `$ATTRIBUTE_LIST` references without assuming the whole MFT is contiguous.
Bound reference expansion and detect cycles, repeated segments, inconsistent
attribute identities, and stale record references. `$MFTMirr` is limited mirror
coverage, not a complete duplicate MFT or an arbitrary repair authority.

The parser set must include resident/nonresident attribute headers, mapping
pairs, standard information, file names, index roots/allocation/bitmaps, security
references, volume information, object IDs, reparse data, and attribute lists.
Preserve unrecognized attributes for inspection and refuse mutations that would
require interpreting them.

### 10.2 Streams and data interpretation

Use a stream identity containing file record/sequence and native attribute name.
Validate VCN ranges, signed LCN deltas, run lengths, bounds, sparse runs,
continuation attributes, allocation size, data size, and initialized size. Bytes
between initialized length and data length read as zero, never stale allocation.
References: [N3], [N4].

Support unnamed and alternate data streams, resident-to-nonresident transition,
sparse data, normal compression units, and stream-aware cache invalidation.
Expose stream enumeration and direct stream access without squeezing content
into the host's small xattr limits.

For compression, implement bounded native LZNT1 reads and write/rewrite behavior
with valid compression-unit layout. WOF-backed content uses a distinct reparse
provider path, not the ordinary NTFS compressed-attribute decoder. For EFS,
separate metadata/raw preservation from actual authorized decryption and write
support; unsupported encrypted access must fail rather than return ciphertext
as if it were plaintext.

### 10.3 Namespace and metadata fidelity

Implement `$I30` index traversal, collation using `$UpCase`, short/long aliases,
hard links, file-reference validation, and directory index mutation. Keep parent
references and every relevant name/link count coherent across rename/unlink.
The NTFS root is selected from native metadata rather than a generic Unix inode
constant.

Implement `$Secure` descriptor storage and references, SID-aware identity policy,
raw descriptor access, and conservative POSIX projection. Changes through chmod,
chown, or ACL APIs must not silently discard deny ACEs, inheritance, or native
security meaning. Preserve all native timestamp/attribute fields even when the
host's `stat` surface displays only a subset.

Reparse tags need explicit dispatch and preservation. Symlinks and junctions are
not every possible tag, and a cloud placeholder is not an empty ordinary file.
Translate only supported semantics under a policy that does not make the image
reader chase arbitrary host paths. Reference: [N6].

### 10.4 Recovery is a write-path prerequisite

Implement `$LogFile` restart-page validation, log-page fixups, restart selection,
LSN ordering, wrap handling, transaction analysis, redo, undo, compensation,
and checkpoint/restart behavior for the admitted native profile. Replay must be
idempotent and reject unsupported recovery operations before partially mutating
the volume. `$UsnJrnl` is change tracking, not this recovery journal. References:
[N5], [N7].

Read-only policy must explicitly choose clean-only, a labeled unrecovered
committed view where meaningful, or a verified in-memory recovery overlay.
Never write the backing merely because the mount requested read-only recovery.

Before writable admission, detect dirty/inconsistent state, hibernation and Fast
Startup hazards, unsupported active attributes, and external-writer risk. Do not
silently clear dirty state, discard the journal, delete `hiberfil.sys`, or add a
force option that pretends a unsafe state is understood.

A FrankenFS-written crash image must be recoverable under the declared native
interchange contract, including Windows where that contract is claimed. A
FrankenFS-only WAL plus an unchanged native journal does not satisfy this.

### 10.5 Native mutation engine

Implement cluster `$Bitmap` and MFT record allocation, MFT growth, resident and
nonresident attribute edits, attribute-list expansion, directory index splits
and merges, stream growth/truncation, hard-link changes, and reclamation. Native
journal records and publication rules must cover every associated metadata
update. Reserve transaction resources before partially changing namespace state.

Update `$MFTMirr` for the records it covers, maintain volume state and native
metadata-file invariants, and preserve required alignment/fixups/checksums.
Do not reuse the ext4 sorted-buffer writer as the NTFS transaction protocol.

An active `$UsnJrnl`, `$ObjId`, `$Quota`, or `$Reparse` index brings additional
maintenance obligations. Implement those obligations or reject writes to the
affected profile; leaving a secondary index stale while ordinary file reads
still work is not full NTFS support. Windows transactional-file APIs are a
separate integration scope, not a synonym for native metadata recovery.

### 10.6 Advanced functionality and lifecycle

The complete NTFS roadmap includes large and alternate streams, sparse and
compressed writes, security/ACL fidelity, supported reparse providers, change
journal consistency, quota/object-ID maintenance, and explicit EFS key handling.
Encryption keys must not appear in diagnostic logs or fixture artifacts.

Implement a structural checker that distinguishes fixable damage from uncertain
ownership and unsupported metadata. Native Windows `chkdsk` remains an essential
independent oracle; `ntfsfix` must not be treated as equivalent complete checking.
Begin with externally formatted fixtures; later add a native formatter with the
required metadata files, journal, allocation, collation, and security defaults.
Offline resize precedes any online extension/shrink claim.

### 10.7 NTFS completion gate

Required evidence spans Microsoft-created volumes and files, Linux NTFS3 and
NTFS-3G comparisons where applicable, and Windows read/modify/check/reopen cycles.
A Windows-unavailable development lane can test implementation mechanics, but
cannot award a Windows-interchange release claim. Pin OS/tool versions, volume
options, generated-image hashes, and the precise interpretation disagreements.

## 11. ZFS: full pool and dataset engine design

### 11.1 Pool discovery and import

Parse vdev labels, bounded nvlists, configuration identities, and uberblock
candidates. Validate endian handling, offsets, checksums, geometry, pool/vdev
GUID relationships, and the candidate MOS root. Select a coherent recoverable
pool state, not simply the numerically largest TXG found on one device.
References: [Z1], [Z2], [Z3].

Build the complete vdev graph, distinguish required storage from optional cache,
and report unavailable components. A special allocation-class vdev is storage,
not disposable cache. A missing log device can affect acknowledged synchronous
writes and must never be silently ignored. References: [Z4], [Z5].

Rewind is an explicit recovery action with a stated possible loss of newer
transactions. Read-only import must not update pool state. Writable import must
respect ownership, export/import state, multihost protection when enabled,
unsupported feature dependencies, and topology sufficiency. No automatic force
import, MMP bypass, label rewriting, or discarded log to make a fixture mount.

### 11.2 Physical block pipeline

Implement native block pointers and DVAs, checksum selection, physical/logical
sizes, birth information, holes, embedded data, gang blocks, and redundant copies.
Honor per-structure byte order. Map through the selected vdev topology using its
native allocation/asize rules, including `ashift`; do not equate logical block
size with disk-sector size.

Validate the appropriate on-disk checksum/authentication boundaries for the
selected transform before exposing decoded bytes. Compression, encryption,
checksum, and byteswap ordering comes from the pinned native format, not a
universal pipeline guessed from unencrypted fixtures. Bound decompression and
indirect traversal independently of the claimed logical file size.

First deliver a single-leaf reader, then mirrors, RAIDZ1/2/3, and the advanced
layouts in the final profile. RAIDZ reconstruction and variable-stripe mapping
need an independent native oracle. dRAID, expanded RAIDZ layouts, and indirect
vdev mappings are separate algorithmic work, not boolean switches on RAIDZ.

### 11.3 Metadata stack and datasets

Implement MOS objects, DSL directories/datasets, DMU object sets and dnodes,
indirect blocks, bonus/spill data, system attributes, and micro/fat ZAP objects.
Build ZPL namespace operations on those layers, including object identity,
directories, links, xattrs/ACLs, file data, properties, and allocation reporting.
Do not skip large dnodes, spill metadata, or transformed data encountered in an
admitted feature profile.

Read snapshots at their selected immutable root. Enumerate datasets, properties,
clones, and snapshots independently of which dataset is mounted. Parent/child
dataset boundaries and mount policy cannot be inferred solely from a ZPL file
path. Dataset property inheritance is part of metadata semantics. Reference:
[Z6].

### 11.4 Feature flags are a compatibility protocol

Build an explicit feature registry keyed by native GUID, dependencies,
read-compatibility semantics, and the actual implemented operation set. Inspect
disabled, enabled, and active states separately. An unsupported active feature
may require total import refusal or may allow a documented read-only import;
that decision follows native compatibility semantics, not a generic 'ignore
unknown flags' rule. Reference: [Z1].

Do not automatically enable or upgrade a pool feature. An enabled setting does
not prove the corresponding disk structures are absent, and disabling a setting
does not erase structures already written. Writer admission must account for
both existing metadata and features the requested operation would activate.

Freeze an initial profile from a pinned OpenZFS reference revision. Maintain an
explicit delta for newer features rather than changing what 'full' means when
upstream publishes another release. Historical Sun/illumos interoperability is
a separate tested profile, not assumed from common ancestry.

### 11.5 TXG publication and synchronous writes

Implement the pool transaction lifecycle: allocation reservation, dirty DMU
state, data/metadata block generation, checksum construction, dependent writes,
space-map/accounting updates, synchronization, root publication, and uberblock
selection after restart. Children must be durable before the published parent
can depend on them, following the native protocol. Reclamation cannot race
snapshots, clones, readers, or incomplete transactions.

ZIL recovery of foreign-system synchronous operations is required before a
writable import can claim the corresponding dirty-pool profile. Do not disable
replay or discard the log to simplify import. A correct initial writer may use a
full TXG commit to satisfy every synchronous operation, provided native
interchange and fault tests establish its semantics. A subsequent native ZIL
writer can reduce latency without changing the durability contract. References:
[Z2], [Z3], [Z4].

Persist error/suspension behavior when required writes or flushes fail. An
acknowledgment cannot be based on a buffered uberblock whose children or log
records never reached the device. Native synchronous intent and a FrankenFS
MVCC WAL are distinct mechanisms with explicit reconciliation.

### 11.6 Space, snapshots, clones, and deduplication

Implement metaslab/space-map accounting, deferred frees, snapshot and clone
references, deadlists, quotas, reservations, and dataset accounting. Snapshot
creation without correct later deletion/reclamation is not complete support.
Pool exhaustion must preserve sufficient reserved recovery/metadata capacity or
fail before creating an unrecoverable transaction.

Deduplication requires the native DDT lookup, reference accounting, verification,
and free paths. Block cloning/BRT is a distinct feature with its own reference
semantics. A reader that can follow shared data does not demonstrate safe shared
block mutation or reclamation. References: [Z7], [Z8].

### 11.7 Native encryption and transformed data

Implement the profile's native compression/checksum algorithms with bounded
decoders and independent fixtures. Native encryption adds key roots, wrapped key
material, authenticated metadata/data rules, nonce uniqueness, key load/unload,
and raw versus decrypted access. Preserve ciphertext safely while keys are
absent; do not advertise data-read support from a metadata-only locked view.

Key management is a separate capability and threat surface. Require explicit
key sources, scoped secret lifetimes, redacted diagnostics, and no keys in
sidecars or test reports. RaptorQ can protect immutable ciphertext without
possessing decryption keys, but cannot substitute for authentication.

### 11.8 Pool and dataset lifecycle

The final declared OpenZFS profile must account for pool create/import/export,
dataset create/destroy/rename, property inheritance, snapshots/clones/bookmarks,
holds, send/receive including admitted incremental/raw/resumable forms, scrub,
resilver, attach/replace/detach, online/offline, spares, allocation classes,
TRIM, checkpoint/rewind, and admitted device removal/expansion operations.

These are substantial algorithms. Stage offline/restricted forms first and keep
unfinished features visible. Persist long-running operation progress and resume
correctly after restart. Sending a stream is not support for receiving one;
listing a snapshot is not support for safe rollback or destruction.

Zvol support needs a separate block-volume frontend and its lifecycle/testing,
not a claim that exporting a regular ZPL file already implements a zvol. Host
transport choices must preserve first-party safety and must not introduce an
unreviewed runtime dependency on libzfs or a kernel module as the native engine.

### 11.9 Scrub and repair

Use native checksums and redundancy first: verify a candidate copy, reconstruct
through the actual topology, and heal only the intended block/version under
pool transaction and ownership rules. A correct mirror or parity reconstruction
is preferable to restoring bytes from a stale external snapshot.

A scrub result must distinguish verified, repaired, unrecoverable, skipped due to
keys/features, and not covered. A read-only scrub verifies without writing.
Resilver is not merely a full-device byte copy; it follows native allocation and
birth/topology semantics.

## 12. RaptorQ protection without foreign-format corruption

### 12.1 Extend the existing sidecar implementation

`ffs-repair/src/sidecar.rs` already describes external snapshot protection,
bounded group memory, saved-generation identity, and the limits of advisory
locking. Its current `live` module is the starting point for writable integration.
Do not assume unused tails, reserved sectors, FAT slack, NTFS metadata-file slack,
or ZFS label padding are available for private parity storage.

Native compatibility mode keeps private state external. A future in-format
extension needs a separately identified format/profile, feature negotiation,
and migration plan; it must never be smuggled into the native profile.

### 12.2 Generation and ownership binding

Bind protection to the exact storage set, selected view, length/geometry,
protection generation, and native durable boundary. For a pool, include every
required vdev identity, topology, and selected TXG; a sidecar for only one member
is not whole-pool protection. For FAT/NTFS, supplement weak native serials with
trusted attachment identity and the existing content/snapshot verification.

An immutable snapshot or proved exclusive ownership is required during capture.
A final reread can detect some races but is not proof that no external writer
exists. Refuse unsafe capture instead of silently weakening the promise.

### 12.3 Commit and freshness protocol

The proposed live protocol must make these transitions crash-safe:

```text
old protected generation
  -> durable dirty/invalidation record for the affected coverage
  -> native transaction publication and durable native token
  -> symbol/checksum generation from that stable committed view
  -> durable new symbol generation and manifest
  -> sealed protection generation
```

Recovery may encounter every prefix of this sequence. A dirty or mismatched
coverage group is not repair authority. A native write and a sidecar write on
separate files/devices do not become atomic because both use `fsync`.

Decide acknowledgment policy explicitly. An ordinary native-durable mount can
acknowledge before parity refresh only while reporting the unprotected interval.
A profile promising protected durability at acknowledgment must wait for its
required seal. Measure this cost; do not describe both policies with one
'protected' boolean.

Preserve the existing sidecar's distinction between accidental-corruption
checksums and authenticated provenance. A hostile image plus a hostile manifest
can agree on fabricated checksums; trust requires an external trusted root.

### 12.4 What automatic repair may not do

Do not regenerate good-looking symbols from detected corruption. Do not heal a
new legitimate write back to a saved older version. Do not patch ZFS physical
blocks without validating birth/version/topology and transaction ownership. Do
not infer NTFS/FAT file-data correctness from structural consistency alone.
When evidence is insufficient, return a bounded diagnosis and recovery options.

## 13. Operational surface

The following is a proposed interface direction, not a list of commands that
exist in the baseline:

```text
ffs inspect <image-or-device> [explicit volume selection]
ffs info <image-or-device> --json
ffs mount <volume> <mountpoint> [native profile and recovery policy]
ffs fsck <volume> [non-mutating by default]
ffs repair <volume> [explicit scope and authorization]
ffs format <fresh-volume> --filesystem <fat16|fat32|ntfs>
ffs streams <ntfs-volume> <file> [list/read/write operations]
ffs pool <discover|import|export|create|status|scrub|...>
ffs dataset <list|create|snapshot|clone|send|receive|...>
```

Integrate with existing command conventions rather than adding a second parser.
Machine-readable output must separate detected format, admitted profile,
read/write/recovery capability, unavailable features, protection state, and
reasons. An unavailable native checker is not a clean bill of health.

Destructive actions require explicit target identity and scope, offline/ownership
preflight, and a dry-run plan where meaningful. Do not run native formatters,
force imports, destructive repairs, or partition edits merely to inspect a
user-supplied device. Test fixtures belong on disposable images or isolated VMs.

## 14. Differential and crash validation

### 14.1 Independent native oracles

| Format | Reference producers and consumers | Required evidence beyond self-round-trip |
|---|---|---|
| FAT16/FAT32 | dosfstools, mtools, native OS FAT implementations | Native names/aliases, geometry edges, allocation/repair findings, writes reopened outside FrankenFS. |
| NTFS | Windows formatting/file operations/checking; NTFS3 and NTFS-3G where applicable | MFT/attribute interpretation, streams/security/compression, Windows replay and interchange on interrupted images. |
| ZFS | Pinned OpenZFS tools and kernel in isolated reference environments | Pool import/checks, block mapping, datasets/properties, TXG/ZIL recovery, shared blocks, topology and lifecycle. |

Record the exact source revision, executable/OS version, options, image hashes,
operation sequence, and native findings. Differences between native oracles must
be investigated, not resolved by choosing whichever agrees with our parser.

A self-generated fixture read by its matching writer proves internal consistency,
not external compatibility. A parser fuzzer proves neither successful mounting
nor correct `fsync`. Retain both kinds of tests but label their scope precisely.

### 14.2 Fault model

Use a deterministic faultable byte device with pending versus durable state,
short I/O, errors, torn writes at declared granularity, reordered writes before
barriers, lost unflushed writes, and crashes at every publication stage. Also run
real mounted process-death tests and native recovery in isolated storage/VM
lanes. Killing the daemon alone does not simulate power loss from a device cache.

Honor the model's declared flush guarantees; separately test explicit flush
failure. Record the acknowledgment point and verify that recovered files and
namespace satisfy exactly the native/enhanced contract promised to the caller.

### 14.3 Required scenario families

Every format needs fragmented/large/empty data, full storage, allocation reuse,
open-unlink, rename-overwrite, directory pagination, invalid names, corruption,
unknown features, cancellation, stale handles, wrong-image attachment, and
read-only zero-write tests. Add native-specific cases:

- FAT: root-table exhaustion, LFN/SFN collision, FAT mirror divergence, high-bit
  preservation, cyclic chains, FSInfo lies, and every metadata-ordering cut.
- NTFS: torn FILE/INDX records, fragmented MFT bootstrap, split attributes,
  sparse/initialized-length boundaries, journal redo/undo cuts, hibernation,
  active secondary indexes, compressed streams, and locked encrypted content.
- ZFS: inconsistent label candidates, unsupported active GUIDs, missing storage
  versus cache/log, degraded topology, checksum-valid alternate copies, RAIDZ
  erasure combinations, TXG/ZIL cuts, snapshot/free interactions, and key absence.

### 14.4 Evidence must not inflate readiness

Add exact behavioral mappings to the existing parity mechanism. Distinguish
parser, core, dispatch, mounted, native-interchange, fault-model, and actual
storage-crash evidence. Required missing tools, zero selected tests, or skipped
mounts are missing evidence, not a pass. A negative test proving refusal does not
award positive support for the feature refused.

Do not raise legacy ext4/btrfs readiness as a side effect of adding new declared
rows. Keep the original feature denominators interpretable. Integrate new rows
when their implementation and exact behavioral tests exist, not merely because
this planning document names them.

## 15. Security, hostile media, and secret handling

Treat all volume metadata, recovery logs, receive streams, and sidecars as
untrusted input. Impose configurable hard budgets for expanded references,
allocation tables, tree depth, decompression output, journal scan length, path
components, native names, and diagnostic volume. Preflight cannot allocate memory
proportional to an unvalidated disk field.

All parsers use checked offset arithmetic and bounded slices. Recursion over
metadata references becomes a budgeted iterative traversal when depth is
attacker-controlled. Validate structures before cache insertion, and keep
negative cache entries scoped to the correct view and policy.

Do not follow image-controlled host paths, spawn commands named by filesystem
metadata, accept arbitrary native device paths from a received stream, or load
keys from a path supplied by untrusted on-disk properties without explicit
operator authorization. Bind destructive operations to already validated targets.

Use audited cryptographic/compression dependencies only after workspace policy,
license, resource behavior, and native compatibility review. No new Tokio-based
runtime, unsafe first-party decoder, or mandatory runtime FFI to another filesystem
implementation is an acceptable shortcut to the project's native Rust goal.

## 16. Performance architecture

Correctness comes before speculative optimization, but data structures must not
force a whole-volume scan for an ordinary lookup or read.

FAT needs bounded chain-window caches, free-space hints, and directory-name
indexes invalidated on mutation. NTFS needs MFT/attribute and index-node caches,
stream-run seeking, and bounded decompression-unit caching. ZFS needs a block
pipeline and cache keyed by immutable native identity, bounded ZAP/DMU lookup,
and topology-aware verified alternate reads.

Measure mounted sequential and random reads/writes, small-file namespace churn,
large directories, sparse/compressed data, 4 KiB synchronous writes, metadata
synchronization, import/replay time, memory use, and degraded-pool reads. Compare
cold and warm states, real durability contracts, and equivalent native features.
Do not claim a win from omitting verification, logging, compression, or fsync.

A full-volume/full-TXG sync implementation can be the first correct writer.
Replace it with finer-grained group commit or ZIL optimization only after
reproducible evidence identifies its cost. Avoid inventing numerical speedup
promises in the plan.

## 17. Delivery sequence and dependencies

| Milestone | Real functionality delivered | Prerequisite / exit condition |
|---|---|---|
| M0: admission seam | Existing backends preserved; explicit geometry/profile/read-only contract | ext4/btrfs regression evidence plus bounded new device views. |
| M1: FAT vertical reader | FAT16 and FAT32 inspect, lookup, readdir, read through core and FUSE | Native-created image comparisons, hostile-input bounds, strict zero writes. |
| M2: native FAT writer | Full ordinary namespace/data mutation and honest synchronization | Allocation/ordering cuts, independent native reopen/check, no fake atomicity. |
| M3: FAT complete profile | Formatter/checker/repair/resize plus external protection integration | Both dialects and native/enhanced profile distinctions pass the full corpus. |
| M4: NTFS reader | MFT/attributes/streams/indexes, correct metadata presentation | Windows-created images, sparse/compressed/fragmented cases, precise feature refusal. |
| M5: NTFS recovery/writer | Native log replay and journal-aware mutation | Dirty and interrupted images recover under the admitted native contract. |
| M6: NTFS full profile | Advanced streams/security/transforms/indexes and lifecycle | No unnamed advanced-feature exclusions; native Windows interchange demonstrated. |
| M7: ZFS reader | Clean pool import, metadata stack, dataset reads; then required topologies | Pinned OpenZFS images and explicit GUID/topology admission. |
| M8: ZFS writer | Native allocation, TXGs, foreign ZIL recovery, durable dataset mutation | Native import after every crash cut, correct space and shared-reference accounting. |
| M9: ZFS full profile | Advanced topology, transforms, lifecycle, replication, zvol frontend | Complete pinned feature/profile obligations, not only ordinary ZPL file operations. |
| M10: protected multi-format release | Native/MVCC/protection semantics reconciled for admitted profiles | Wrong-generation refusal, interrupted refresh recovery, mounted and native evidence. |

M4 and M7 can proceed in parallel with later FAT work after M0/M1 establish the
necessary seams. M5 does not depend on every FAT utility, and ZFS parser work does
not depend on NTFS security translation. Multi-format live protection depends on
the native commit token of each backend, not on a blanket claim that one WAL
works for everything.

The critical path is native recoverability and interchange, not the number of
new files or report schemas. Stop broad refactoring once the first concrete
backend can use the seam. Each implementation commit should deliver a coherent
behavior and its focused tests; do not spend a session creating empty crates,
renaming tracker rows, or claiming broad gates from unrelated test wrappers.

## 18. Decisions that require experiments rather than guesses

| Question | Initial decision | Experiment that can change it |
|---|---|---|
| Generic dispatch shape | Closed enum plus small internal interfaces | Measure real backend hot paths before introducing more indirection. |
| FAT stronger crash recovery | Native ordered profile plus optional external recovery | Enumerate crash cuts and native handoff behavior; never assume atomic multi-file commits. |
| NTFS native log coverage | Implement the admitted Windows recovery vocabulary before writes | Capture independently produced interrupted operations; unsupported opcode/state blocks that profile. |
| NTFS name/security projection | Preserve native values; conservative explicit host policy | Round-trip pathological names and ACLs through Windows and the proposed host APIs. |
| ZFS first synchronous writer | Full TXG commit is allowed as the first correct implementation | Native recovery and latency measurements decide when a ZIL writer is worthwhile. |
| Online RaptorQ attachment | Extend existing sidecar/live lifecycle with native durable tokens | Wrong-image, stale-generation, lost-invalidation, and interrupted-seal fault tests. |
| Historical/new feature support | Pinned profile with explicit per-feature deltas | Generate native images and prove all reachable metadata/operations before admission. |

These are bounded research tasks attached to implementation paths. They are not
an excuse to postpone the FAT vertical slice or to implement unsafe writers while
waiting for a complete universal format specification.

## 19. Release acceptance

A format/profile is complete only when its implementation satisfies every
claimed operation, all mandatory independent oracles run, its mounted path and
recovery boundary are tested, and all unsupported native features have precise
admission behavior. No storage-corrupting known defect can be hidden behind an
'experimental' success result.

An advanced feature is complete only when reading, writing where claimed,
recovery, preservation, accounting/reclamation, and native interoperability are
covered. A snapshot reader is not a snapshot lifecycle implementation. An NTFS
compression decoder is not compressed-write support. A ZFS RAIDZ reader is not
pool replacement/resilver support.

Keep release language scoped: 'FAT32 native read/write profile X', 'NTFS 3.1
read-only profile Y', or 'OpenZFS profile Z on these topologies'. Reserve an
unqualified full-support statement for a completed, published profile rather
than using it as a synonym for this roadmap.

## 20. Source and oracle reference register

Repository facts above are anchored to the baseline commit and these local files:

- [Original comprehensive specification](COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md)
- [Original porting plan](PLAN_TO_PORT_FRANKENFS_TO_RUST.md)
- [Architecture](PROPOSED_ARCHITECTURE.md)
- [Executed versus declared parity](FEATURE_PARITY.md)
- [Beads JSONL](.beads/issues.jsonl)
- [Core implementation](crates/ffs-core/src/lib.rs)
- [Existing external repair sidecar](crates/ffs-repair/src/sidecar.rs)

The public primary references below were consulted for native semantics and
implementation planning. Pin exact versions/source commits and fixture-producing
commands when implementing; a moving documentation URL is not a reproducible
oracle version. The algorithmic and architectural requirements in this document
are proposed engineering decisions, not claims that these references supply a
complete independently sufficient filesystem specification.

### FAT references

- **[F1]** [UEFI 2.10, media access and FAT filesystem sections](https://uefi.org/specs/UEFI/2.10/13_Protocols_Media_Access.html): firmware FAT layout and interoperability context. This does not cover every desktop FAT quirk.
- **[F2]** [Linux VFAT documentation](https://docs.kernel.org/filesystems/vfat.html): native mount/name/permission presentation and compatibility policies.
- **[F3]** [dosfstools `mkfs.fat.c`](https://github.com/dosfstools/dosfstools/blob/master/src/mkfs.fat.c): independent formatter behavior, cluster-count boundaries, and layout constraints.
- **[F4]** [GNU mtools `mformat`](https://www.gnu.org/software/mtools/manual/html_node/mformat.html): independent image creation and geometry controls.

The original Microsoft FAT specification should be acquired from a verifiable
source, license-reviewed, and content-hashed before detailed format conformance
is signed off. Its PDF was not successfully retrieved during this planning
review; do not cite it as reviewed evidence or substitute an unverified mirror.

### NTFS references

- **[N1]** [Microsoft: Master File Table](https://learn.microsoft.com/en-us/windows/win32/devnotes/master-file-table).
- **[N2]** [Microsoft: FILE_RECORD_SEGMENT_HEADER](https://learn.microsoft.com/en-us/windows/win32/devnotes/file-record-segment-header).
- **[N3]** [Microsoft: ATTRIBUTE_RECORD_HEADER](https://learn.microsoft.com/en-us/windows/win32/devnotes/attribute-record-header).
- **[N4]** [Microsoft: File streams](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams).
- **[N5]** [Microsoft: Change journals](https://learn.microsoft.com/en-us/windows/win32/fileio/change-journals).
- **[N6]** [Microsoft: Reparse points](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points).
- **[N7]** [Linux NTFS3 documentation](https://docs.kernel.org/filesystems/ntfs3.html).

Microsoft's public structure notes are not a complete `$LogFile`, EFS, or
Windows behavior specification. Native-generated fixtures, source study subject
to license constraints, and recovery experiments are necessary. Do not copy
licensed implementation code into first-party Rust without an explicit compatible
license decision; 'rewritten in Rust' does not by itself resolve licensing.

### ZFS references

- **[Z1]** [OpenZFS `zpool-features(7)`](https://openzfs.github.io/openzfs-docs/man/master/7/zpool-features.7.html).
- **[Z2]** [OpenZFS `zpool-import(8)`](https://openzfs.github.io/openzfs-docs/man/master/8/zpool-import.8.html).
- **[Z3]** [OpenZFS copy-on-write concepts](https://openzfs.github.io/openzfs-docs/Basic%20Concepts/Copy-on-write.html).
- **[Z4]** [OpenZFS caching and log-device concepts](https://openzfs.github.io/openzfs-docs/Basic%20Concepts/Pool%20Structure/Caching.html) and [missing-log-device diagnosis](https://openzfs.github.io/openzfs-docs/msg/ZFS-8000-K4/index.html).
- **[Z5]** [OpenZFS special vdev concepts](https://openzfs.github.io/openzfs-docs/Basic%20Concepts/Pool%20Structure/Special%20vdev.html).
- **[Z6]** [OpenZFS `zfsprops(7)`](https://openzfs.github.io/openzfs-docs/man/master/7/zfsprops.7.html).
- **[Z7]** [OpenZFS deduplication concepts](https://openzfs.github.io/openzfs-docs/Basic%20Concepts/Data%20Storage/Deduplication.html).
- **[Z8]** [OpenZFS block cloning concepts](https://openzfs.github.io/openzfs-docs/Basic%20Concepts/Data%20Storage/Block%20Cloning.html).
- **[Z9]** [OpenZFS 2.3 `raidz_test(1)`](https://openzfs.github.io/openzfs-docs/man/v2.3/1/raidz_test.1.html): a reference-tool direction for independently checking RAIDZ mapping/reconstruction; not a claim that all 2.3 features are implemented here.

OpenZFS is a behavioral/source reference and native oracle, not a proposed
mandatory runtime dependency. Review CDDL/GPL and other source/dependency
obligations before choosing any reuse strategy; this plan makes no legal
conclusion that translation, linking, or distribution is automatically allowed.

## 21. First implementation session: stop planning and ship behavior

The next implementation should take the narrow M0/M1 path: bounded volume reads,
explicit flavor admission, FAT16/FAT32 geometry and chain parsing, real namespace
and file reads through `OpenFs`/FUSE, and independent native-image tests. Keep the
writer unavailable until the allocation and native ordering work lands.

In parallel, isolate NTFS bootstrap/attribute parsing and ZFS label/block-pointer
parsing behind their own pure tests. Do not advertise either as a mounted backend
until its first full path resolves a native root, looks up a real file, reads its
bytes, and enforces its unsupported-state rules without writing the image.

Follow the implementation companion for concrete code boundaries, dependencies,
crash cut points, and acceptance workloads. The outcome to optimize is usable,
recoverable native filesystem functionality, not a larger collection of planning
artifacts or nominally green wrappers.
