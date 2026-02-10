# PLAN_TO_PORT_FRANKENFS_TO_RUST.md

> **FrankenFS** -- A memory-safe, FUSE-based Rust reimplementation of ext4 and
> btrfs with block-level MVCC and RaptorQ self-healing.
>
> This document is the **master porting plan** following the four-document
> methodology. It defines scope, exclusions, source metrics, phased delivery,
> cross-cutting concerns, risks, and success criteria.
>
> Companion documents:
> - `PROPOSED_ARCHITECTURE.md` -- crate topology, data-flow diagrams, trait contracts
> - `AGENTS.md` -- guardrails for agent changes in this repo
> - `EXISTING_EXT4_BTRFS_STRUCTURE.md` -- behavior extraction from the legacy C corpus
> - `FEATURE_PARITY.md` -- parity status tracking

---

## 0. Execution TODO (Canonical)

This is the **authoritative**, granular TODO checklist for the repo. It MUST be
updated whenever work is completed or new required sub-tasks are discovered.

Status legend: `[ ]` not started, `[~]` in progress, `[x]` complete.

### 0.1 Documentation and Consistency (Blocker Before Deep Implementation)

- [x] Canonicalize crate naming across all docs (no phantom crates like `ffs-ops`, `ffs-cache`, `ffs-io`, `ffs-async`)
- [x] Canonicalize all normative type definitions (single source for `TxnId`, `CommitSeq`, `Snapshot`, `BlockNumber`, `InodeNumber`, `BlockVersion`)
- [~] Canonicalize all normative trait definitions (single source for `BlockDevice`, MVCC interfaces, repair interfaces)
- [x] Reconcile doc claims vs workspace reality (21 workspace crates: 19 core + `ffs-ext4`/`ffs-btrfs` wrappers)
- [x] Reconcile ext4/btrfs scope statements (both formats are in-scope; btrfs phased)
- [x] Fix math/spec errors in Section 18 (probabilistic conflict model) to be dimensionally correct and assumption-explicit
- [x] Remove/repair any references to non-existent files (`ARCHITECTURE.md` -> `PROPOSED_ARCHITECTURE.md`, `CONVENTIONS.md` merged into `AGENTS.md`)
- [x] Ensure dependency lists match `Cargo.toml` (zerocopy/bytes references removed; fuser planned for Phase 7; Appendix C updated to match actual Cargo.toml)
- [x] Doc fix: `COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md` Section 18 “Sequential writes” row is inconsistent with the stated formula (make assumptions explicit or remove the row)
- [x] Doc fix: `COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md` Section 18 group/bitmap conflict math (`1/G` vs `(1/G)^2`) and version-chain length formula (dimensional correctness)
- [x] Doc fix: `COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md` ext4 block-size support statements (format allows 1K–64K, but FrankenFS v1 support must be stated consistently)
- [x] Doc fix: `COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md` Section 19.1 uses nonexistent `FfsError::*` variants (`InvalidMagic`, `UnsupportedBlockSize`, `IncompatibleFeature`, `InvalidGeometry`) — align with canonical `FfsError` or `ParseError`
- [x] Doc fix: `COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md` Section 23.8.2 references `zerocopy` and “panic on OOB” behavior — align with current `ffs-types` parsing helpers (`ensure_slice`, `read_le_u*`) and “return Err, never panic” fuzz doctrine
- [x] Doc fix: `PROPOSED_ARCHITECTURE.md` crate dependency descriptions must match actual `Cargo.toml` (e.g., `ffs-block` does not currently depend on `ffs-ondisk`)

### 0.2 `ffs-types` (Canonical Newtypes + Shared Parsing Primitives)

- [ ] Decide inode ID strategy:
  - ext4 on-disk inode is `u32`
  - btrfs objectid is `u64`
  - pick canonical `InodeNumber` representation and add per-format wrappers if needed
- [x] Add missing newtypes used by docs/spec: `BlockSize` (validated), `GroupNumber`, `Generation` (landed); `ByteOffset`/`DeviceId` deferred as not yet needed
- [x] Add helpers: `BlockSize::byte_to_block/block_to_byte/shift`, `BlockNumber::checked_add/sub`, `block_to_group`, `group_first_block`, `inode_to_group`, `inode_index_in_group`

### 0.3 `ffs-error` (Error Model + Errno Mapping)

- [x] Canonicalize `FfsError` variant set (no duplicates across docs)
- [x] Implement errno mapping (`impl From<&FfsError> for libc::c_int` or equivalent)
- [ ] Add `Unsupported`/`IncompatibleFeature`/`UnsupportedBlockSize` variants as required by mount validation

### 0.4 `ffs-ondisk` ext4 (Parsing + Validation)

- [x] Expand `Ext4Superblock` parsing toward full on-disk layout (~30 fields: geometry, identity, revision, features, state/errors, timestamps, journal, htree hash seed, flex BG, checksums)
- [x] Implement ext4 feature flag decoding (compat / ro_compat / incompat) — `has_compat`, `has_incompat`, `has_ro_compat`, `is_64bit`, `has_metadata_csum` landed
- [x] Implement superblock validation helpers — `validate_v1` (block size, features), `validate_geometry` (blocks_per_group, inodes_per_group, inode_size, first_data_block), `validate_checksum` (CRC32C), `csum_seed`
- [~] Implement group descriptor parsing (32/64 byte descriptors; 64-bit fields; checksum hooks) (descriptor parsing landed; checksum hooks pending)
- [x] Implement inode location math — `inode_to_group`, `inode_index_in_group` in ffs-types; `Ext4Superblock::inode_table_offset` and `group_desc_offset` in ffs-ondisk

### 0.5 `ffs-ondisk` btrfs (Parsing + Mapping + Tree Primitives)

- [~] Expand `BtrfsSuperblock` parsing (include `sys_chunk_array` bootstrap mapping)
- [ ] Implement logical->physical mapping for single-device images (sys_chunk only, initial scope)
- [ ] Implement node read/parse helpers (header + item table bounds checking)
- [ ] Implement initial tree-walk primitive for read-only discovery (root -> items iterator)

### 0.6 `ffs-block` (Image-Backed I/O + Cache)

- [x] Implement `ByteDevice` (read/write exact at byte offsets) with cancellation checkpoints
- [x] Implement `FileByteDevice` (Linux `FileExt` pread/pwrite) (read-write vs read-only behavior made explicit)
- [x] Implement `BlockDevice` (block-sized reads/writes over `ByteDevice`)
- [~] Implement an ARC-like metadata cache wrapper (start read-cache; add write-back later)
- [x] Provide safe helpers to read ext4/btrfs superblocks by fixed byte offsets
- [x] Fix cancellation mapping: `Cx::checkpoint()` errors must map to `FfsError::Cancelled` (not `FfsError::Format`)
- [x] Validate block geometry: `ByteBlockDevice::new` rejects non-block-aligned images (`len_bytes % block_size != 0`)

### 0.7 Integration (`ffs-core`, `ffs-cli`, `ffs-harness`)

- [x] Switch `ffs-cli inspect` to use `ffs-block` (no 128KB probe reads)
- [x] Add `ffs-core` helpers: detect/open image via `ffs-block`, returning parsed superblock + geometry
- [ ] Add harness vectors for new ext4/btrfs parsing functionality and update parity counts

### 0.8 Performance and Regression Gates

- [ ] Update `scripts/benchmark.sh` if commands change
- [ ] Add baseline entry for new parsing + I/O paths once stabilized
- [ ] Profile hotspots only after correctness fixtures exist (per optimization discipline)

### 0.9 Cleanup (Requires Explicit Permission)

- [ ] Delete leftover bootstrap temp files (e.g. `.spec_*.md`) ONLY after explicit user permission (Rule 1)

## 1. Scope

FrankenFS is a **userspace filesystem** that reads and writes real ext4 and
btrfs disk images through FUSE. On top of format compatibility it layers two
novel capabilities shared across both filesystems:

1. **Block-level MVCC** -- every block write produces a new version; readers see
   a consistent snapshot without holding locks.
2. **RaptorQ self-healing** -- fountain-code repair symbols are maintained per
   block group so that single- or multi-block corruption can be repaired
   automatically without external backups.

### 1.1 Deliverable Summary

| Deliverable | Description |
|---|---|
| 21-crate Cargo workspace (19 core + 2 legacy/reference wrappers) | Modular, independently testable crates |
| FUSE filesystem binary | Mounts ext4 images in Linux userspace via `fuser` (planned; Phase 7) |
| CLI (`ffs-cli`) | `mount`, `fsck`, `info`, `dump` commands |
| TUI (`ffs-tui`) | Live monitoring dashboard (cache, MVCC, repair stats) |
| Conformance harness | Automated comparison against Linux kernel ext4 driver |
| Public API facade (`ffs`) | Library crate for embedding FrankenFS in other programs |

### 1.2 Workspace Crate Map

| # | Crate | Purpose | Primary Phase |
|---|---|---|---|
| 1 | `ffs` | Public API facade, re-exports | 9 |
| 2 | `ffs-types` | Primitive newtypes (BlockNumber, InodeNumber, TxnId, CommitSeq, Snapshot) | 2 |
| 3 | `ffs-error` | `FfsError` enum, errno mapping | 2 |
| 4 | `ffs-ondisk` | ext4 on-disk struct parsing and serialization | 2 |
| 5 | `ffs-block` | BlockDevice trait, ARC cache, Cx-aware I/O | 3 |
| 6 | `ffs-btree` | B+tree operations (insert, delete, split, merge) | 4 |
| 7 | `ffs-extent` | Extent tree: logical-to-physical block mapping | 4 |
| 8 | `ffs-alloc` | Block and inode allocation (mballoc, Orlov) | 4 |
| 9 | `ffs-inode` | Inode lifecycle management | 5 |
| 10 | `ffs-dir` | Directory operations (linear, htree) | 5 |
| 11 | `ffs-xattr` | Extended attributes (inline + block) | 5 |
| 12 | `ffs-journal` | JBD2 replay + COW journal | 6 |
| 13 | `ffs-mvcc` | Block-level MVCC, SSI conflict detection | 6 |
| 14 | `ffs-fuse` | `fuser::Filesystem` implementation | 7 |
| 15 | `ffs-core` | Mount orchestration, superblock validation | 7 |
| 16 | `ffs-repair` | RaptorQ codec, scrub, self-healing | 8 |
| 17 | `ffs-cli` | Command-line interface | 9 |
| 18 | `ffs-tui` | Terminal UI (frankentui-based) | 9 |
| 19 | `ffs-harness` | Conformance test harness | 9 |
| 20 | `ffs-ext4` | Legacy/reference wrapper: re-exports `ffs-ondisk::ext4::*` | 1 |
| 21 | `ffs-btrfs` | Legacy/reference wrapper: re-exports `ffs-ondisk::btrfs::*` | 1 |

### 1.3 Target Platform

- **OS:** Linux (x86_64, aarch64)
- **Interface:** FUSE 7.x via the `fuser` crate (kernel FUSE module required)
- **Rust edition:** 2024
- **MSRV:** 1.85 (required by Edition 2024)

### 1.4 Key Dependencies

| Crate | Role | Version Pin |
|---|---|---|
| `asupersync` | Cx capability contexts, cooperative cancellation, RaptorQ codec, lab runtime for deterministic testing | workspace |
| `ftui` (frankentui) | TUI rendering framework | workspace (path = /dp/frankentui/crates/ftui) |
| `fuser` | FUSE protocol implementation | planned (Phase 7); not yet in workspace dependencies |
| `crc32c` | CRC32C checksums (ext4 metadata_csum) | ^0.6 |
| `blake3` | BLAKE3 checksums (native-mode integrity) | ^1 |
| `parking_lot` | Fast mutexes and RwLocks | ^0.12 |
| `bitflags` | Flag-set types for on-disk fields | ^2 |
| `serde` + `serde_json` | Serialization for fixtures, conformance, metadata reports | ^1 |
| `thiserror` | Derive macro for `FfsError` | ^2 |
| `clap` | CLI argument parsing | ^4 |
| `tracing` | Structured logging | ^0.1 |

---

## 2. Explicit Exclusions

The following features are **out of scope** for this porting effort. Each
exclusion is deliberate and documented to prevent scope creep.

| Exclusion | Rationale |
|---|---|
| **Kernel module** | FrankenFS is userspace-only via FUSE. Kernel module development introduces unsafe code, GPL licensing constraints, and kernel ABI stability concerns that conflict with our memory-safety goals. |
| **ext2/ext3 legacy format support** | We target ext4 exclusively. ext2/ext3 images can be mounted as ext4 by the kernel; we do not need backward compatibility with older superblock formats. |
| **fscrypt (encrypted filesystem support)** | Filesystem-level encryption adds significant complexity (key management, per-file policies, filename encryption). This can be layered on in a future phase or handled by dm-crypt at the block layer. |
| **Online resize (resize2fs equivalent)** | Resizing a mounted filesystem requires careful coordination with active I/O. Offline resize via `ffs-cli fsck --resize` may be added later. |
| **Quota subsystem** | Disk quotas (usrquota, grpquota, prjquota) are an administrative feature. Excluding them removes ~3K LOC of quota tracking code. |
| **btrfs advanced features** | Initial btrfs scope is single-device images + metadata parsing + read-only mount parity first. Multi-device/RAID profiles, send/receive, and transparent compression are phased later. |
| **NFS export support** | NFS export requires stable file handle generation across remounts. This is a protocol concern orthogonal to filesystem correctness. |
| **ext4 inline data** | The `EXT4_INLINE_DATA_FL` feature stores small files inside the inode itself. This optimization affects ~2% of files and can be added in a future phase. |
| **Multi-device support** | FrankenFS operates on a single block device (disk image). RAID, LVM, and multi-device btrfs topologies are excluded. |
| **DAX / direct access** | Persistent-memory (pmem) direct access mode is excluded. FUSE does not support DAX. |
| **ext4 encrypted directory indexes** | A sub-feature of fscrypt; excluded along with the parent feature. |
| **Verity (fs-verity)** | Read-only integrity verification via Merkle trees. Overlaps with our RaptorQ integrity story but uses a different mechanism. |

---

## 3. Source Metrics

### 3.1 Legacy ext4 Source

Source location: `/data/projects/frankenfs/legacy_ext4_and_btrfs_code/linux-fs/fs/ext4/`

| Category | Files | Approx. LOC | Notes |
|---|---|---|---|
| Core (super.c, inode.c, namei.c, file.c) | 4 | ~18,000 | Superblock, inode ops, name lookup, file ops |
| Extent tree (extents.c, extents_status.c) | 2 | ~7,500 | Extent mapping, status tree |
| Block allocation (mballoc.c, balloc.c, ialloc.c) | 3 | ~9,000 | Multi-block alloc, buddy system, inode alloc |
| Directory (dir.c, hash.c, namei.c) | 3 | ~5,500 | Linear dirs, htree, dx_hash |
| Journal (jbd2/) | ~8 | ~12,000 | JBD2 transaction manager |
| Extended attributes (xattr.c, xattr_*.c) | 5 | ~3,500 | xattr inline, block, security, trusted, user |
| Checksums (checksum.c) | 1 | ~500 | CRC32C for metadata |
| Miscellaneous (resize.c, migrate.c, move_extent.c, ioctl.c, sysfs.c, ...) | ~14 | ~9,000 | Features we exclude or partially reference |
| **Total** | **~40** | **~65,000** | |

### 3.2 Legacy btrfs Source

Source location: `/data/projects/frankenfs/legacy_ext4_and_btrfs_code/linux-fs/fs/btrfs/`

| Category | Files | Approx. LOC | Notes |
|---|---|---|---|
| B-tree (ctree.c, ctree.h) | 2 | ~8,000 | B+tree operations -- basis for btrfs compatibility and ffs-btree |
| COW semantics (transaction.c, tree-log.c) | 2 | ~9,000 | Copy-on-write transaction model -- basis for btrfs compatibility and ffs-mvcc |
| Extent allocation (extent-tree.c, block-group.c) | 2 | ~12,000 | Extent-based allocation -- informs ffs-alloc + btrfs extent accounting |
| Disk I/O (disk-io.c, volumes.c) | 2 | ~10,000 | Block I/O layer -- informs ffs-block + btrfs device/chunk mapping |
| Scrub/repair (scrub.c, check-integrity.c) | 2 | ~7,000 | Integrity checking -- informs ffs-repair scrub/scanning patterns |
| Remaining (inode.c, dir-item.c, file.c, ...) | ~60 | ~94,000 | Other btrfs internals |
| **Total** | **~70** | **~140,000** | |

### 3.3 Estimated Rust Output

| Phase | Crates | Est. LOC | Rationale |
|---|---|---|---|
| 1 -- Bootstrap | all stubs | 500 | Cargo.toml + empty lib.rs |
| 2 -- Types & On-Disk | ffs-types, ffs-error, ffs-ondisk | 5,000 | On-disk structs, parsing, validation |
| 3 -- Block I/O & Cache | ffs-block | 3,000 | ARC cache, BlockDevice trait, Cx I/O |
| 4 -- B-tree & Extent | ffs-btree, ffs-extent, ffs-alloc | 6,000 | Tree ops, extent mapping, mballoc |
| 5 -- Inode & Directory | ffs-inode, ffs-dir, ffs-xattr | 5,000 | Inode CRUD, htree, xattrs |
| 6 -- Journal & MVCC | ffs-journal, ffs-mvcc | 8,000 | JBD2 replay, COW journal, SSI |
| 7 -- FUSE Interface | ffs-fuse, ffs-core | 4,000 | fuser integration, mount orchestration |
| 8 -- RaptorQ Repair | ffs-repair | 4,000 | Fountain codes, scrub, self-healing |
| 9 -- CLI, TUI & Harness | ffs-cli, ffs-tui, ffs-harness, ffs | 5,000 | User-facing tools, conformance tests |
| **Total** | **21 crates (19 core + 2 legacy/reference wrappers)** | **~45,500** | **~22% of legacy C LOC** |

The reduction from ~205K C LOC to ~45.5K Rust LOC reflects:

- **Exclusions:** ~30% of legacy code covers excluded features (quota, resize,
  fscrypt, multi-device, NFS export, inline data).
- **No kernel boilerplate:** Kernel module registration, sysfs, procfs, ioctl
  handlers, memory allocation wrappers, and spinlock ceremony are eliminated.
- **Rust expressiveness:** Sum types (`enum`), `Result<T, E>`, iterators, trait
  dispatch, and the `?` operator replace thousands of lines of C error-handling
  boilerplate (goto chains, IS_ERR/PTR_ERR, manual cleanup).
- **Library reuse:** `fuser`, `crc32c`, `blake3`, `bitflags`,
  `parking_lot`, `serde` replace hand-rolled equivalents in the kernel.
- **Concept borrowing vs. translation:** We borrow btrfs *ideas* but don't
  translate its 140K LOC. Only the architectural patterns (COW B-tree, MVCC,
  scrub) inform our design.

---

## 4. Nine Phases

### Phase 1: Bootstrap (Current)

**Goal:** Establish the Cargo workspace, create all 21 crate stubs (19 core + 2 legacy/reference wrappers), write the
four specification documents, and verify the workspace compiles.

**Deliverables:**

| Artifact | Description |
|---|---|
| `Cargo.toml` (workspace root) | Workspace members, shared dependency versions, workspace lints |
| 21 crate `Cargo.toml` + `src/lib.rs` stubs | Empty crates with correct inter-crate dependencies declared |
| `PLAN_TO_PORT_FRANKENFS_TO_RUST.md` | This document |
| `PROPOSED_ARCHITECTURE.md` | Crate topology, data-flow, trait contracts |
| `AGENTS.md` | Agent assignments, coordination protocol, code conventions |
| `README.md` | Project overview, build instructions, quick start |

**Acceptance Criteria:**
- `cargo check --workspace` exits 0
- `cargo test --workspace` exits 0 (no tests yet, but no compilation errors)
- All four spec documents reviewed and merged
- CI pipeline configured (clippy, rustfmt, `cargo deny`)

**LOC Estimate:** ~500

**Risk:** None. This phase is pure scaffolding.

**Duration:** 1-2 days.

---

### Phase 2: Types & On-Disk Formats

**Goal:** Define all fundamental types and implement ext4 on-disk structure
parsing with round-trip fidelity.

**Deliverables:**

| Crate | Key Items |
|---|---|
| `ffs-types` | `BlockNumber(u64)`, `InodeNumber(u64)`, `TxnId(u64)`, `CommitSeq(u64)`, `Snapshot { high: CommitSeq }`, `ParseError` enum; binary read helpers (`read_le_u16/u32/u64`, `ensure_slice`, `trim_nul_padded`); ext4/btrfs magic constants |
| `ffs-error` | `FfsError` enum (18 variants: Io, Corruption, Format, Parse, UnsupportedFeature, InvalidGeometry, MvccConflict, Cancelled, NoSpace, NotFound, PermissionDenied, ReadOnly, NotDirectory, IsDirectory, NotEmpty, NameTooLong, Exists, RepairFailed); `Result<T>` alias. See canonical listing in `crates/ffs-error/src/lib.rs`. |
| `ffs-ondisk` | Parsing and serialization for all ext4 on-disk structures |

**Key On-Disk Structures:**

| Structure | C Source | Fields | Notes |
|---|---|---|---|
| `ext4_super_block` | `ext4.h` | 1345+ | 1024-byte superblock at offset 1024; includes compat/incompat/ro_compat feature flags |
| `ext4_inode` | `ext4.h` | 804+ | 128 or 256 bytes; contains mode, uid, gid, size, timestamps, extent tree root or block map |
| `ext4_extent_header` | `ext4_extents.h` | 5 | Magic (0xF30A), entries, max, depth, generation |
| `ext4_extent` | `ext4_extents.h` | 4 | Leaf: logical block, length, physical block (hi+lo) |
| `ext4_extent_idx` | `ext4_extents.h` | 4 | Internal: logical block, physical block (hi+lo), unused |
| `ext4_group_desc` | `ext4.h` | ~20 | 32 or 64 bytes; block/inode bitmaps, inode table, free counts, checksum |
| `ext4_dir_entry_2` | `ext4.h` | 5 | Variable-length: inode, rec_len, name_len, file_type, name |
| `ext4_dx_root` | `ext4.h` | ~10 | htree root: dot/dotdot entries, dx_root_info, dx_entries |
| `ext4_dx_entry` | `ext4.h` | 2 | Hash, block |
| `ext4_xattr_header` | `xattr.h` | 4 | Magic, refcount, blocks, hash |
| `ext4_xattr_entry` | `xattr.h` | 6 | name_len, name_index, value_offs, value_inum, value_size, hash |
| `jbd2_journal_superblock_s` | `jbd2.h` | ~30 | Journal superblock |
| `jbd2_journal_header_s` | `jbd2.h` | 3 | Block type, transaction ID |
| `journal_block_tag_s` | `jbd2.h` | 4 | Blocknr, checksum, flags |

**Parsing Strategy:**
- Manual byte-level parsing via `ffs-types` helpers (`read_le_u16`, `read_le_u32`,
  `read_le_u64`, `ensure_slice`) — no zerocopy dependency.
- Explicit `from_le_bytes` / `to_le_bytes` conversion methods for every field
  (ext4 is little-endian on disk regardless of host architecture).
- Validation methods that check magic numbers, checksum fields, and
  range-validity of all numeric fields.
- `Display` and `Debug` implementations for human-readable dumping.

**Acceptance Criteria:**
- Parse a real ext4 superblock from a test image and verify all 50+ commonly
  used fields match `dumpe2fs` output.
- Parse inodes, extent trees, group descriptors, and directory entries from the
  same test image.
- Round-trip: parse a structure, serialize it, compare byte-for-byte with the
  original.
- Property-based tests via `proptest` for parse/serialize round-trip on
  randomized inputs.

**LOC Estimate:** ~5,000

**Risk:**

| Risk | Severity | Mitigation |
|---|---|---|
| Field alignment mismatches between C packed structs and Rust repr | Medium | Manual byte-level parsing via `ffs-types` helpers (`read_le_u16/u32/u64`); never rely on Rust struct layout |
| Endianness bugs | Medium | Newtype wrappers (`Le16`, `Le32`, `Le64`) that enforce conversion at read/write boundaries |
| Superblock feature flag combinatorial explosion | Low | Parse all flags but gate behavior on supported subset; return `EOPNOTSUPP` for unsupported features |

**Duration:** 1-2 weeks.

---

### Phase 3: Block I/O & Cache

**Goal:** Implement the block device abstraction and an Adaptive Replacement
Cache (ARC) that mediates all disk access through Cx capability contexts.

**Deliverables:**

| Component | Description |
|---|---|
| `BlockDevice` trait | `fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf>` / `write_block` / `sync` / `block_size` / `block_count` |
| `FileBlockDevice` | `BlockDevice` implementation backed by `std::fs::File` (for disk images) |
| `ArcCache` | Adaptive Replacement Cache with T1 (recent), T2 (frequent), B1 (recent ghost), B2 (frequent ghost) lists |
| `BlockBuf` | Reference-counted block buffer with dirty tracking |
| `CachedBlockDevice` | Wraps any `BlockDevice` with `ArcCache`; transparent caching |
| `FlushDaemon` | Background task that writes dirty blocks to disk; configurable interval and dirty-page threshold |

**ARC Cache Design:**

The ARC algorithm (Megiddo & Modha, 2003) maintains four LRU lists:

```
T1: pages seen exactly once recently         (recency)
T2: pages seen at least twice recently        (frequency)
B1: ghost entries evicted from T1             (recency history)
B2: ghost entries evicted from T2             (frequency history)
```

A tuning parameter `p` (0 <= p <= cache_size) controls the split between T1 and
T2. On a B1 hit, `p` increases (favor recency); on a B2 hit, `p` decreases
(favor frequency). This self-tuning property makes ARC superior to plain LRU for
filesystem workloads that mix sequential scans with random access.

**Cx Integration:**

Every I/O operation accepts `&asupersync::Cx` as its first parameter. The Cx
context provides:

- **Cooperative cancellation:** Operations check `cx.is_cancelled()` at yield
  points (before/after disk I/O, during cache eviction scans). A cancelled Cx
  causes the operation to return `FfsError::Cancelled`.
- **Deadline propagation:** Cx carries an optional deadline; operations that
  exceed the deadline are treated as cancelled.
- **Lab runtime compatibility:** Under `asupersync`'s deterministic lab runtime,
  Cx enables controlled scheduling of concurrent operations for reproducible
  testing.

**Acceptance Criteria:**
- Read all blocks of an ext4 superblock + block group descriptors from a test
  image.
- Cache hit ratio > 90% when reading the same 1000 blocks twice.
- ARC self-tuning: sequential scan of N blocks followed by random access of M
  hot blocks; T2 retains hot blocks despite scan pressure.
- `FlushDaemon` writes dirty blocks within configured interval.
- All operations respect Cx cancellation: cancelling a Cx mid-read returns
  `FfsError::Cancelled` without corrupting cache state.
- Concurrent read stress test: 16 threads reading random blocks; no data races
  (verified by `--cfg miri` or thread sanitizer).

**LOC Estimate:** ~3,000

**Risk:**

| Risk | Severity | Mitigation |
|---|---|---|
| ARC implementation correctness (ghost list management, p-adaptation) | Medium | Port from the reference pseudocode; extensive property-based testing with workload traces |
| Cache coherency under concurrent writers | High | `parking_lot::RwLock` per cache entry; write lock held during block mutation; dirty flag is atomic |
| FlushDaemon crash leaving dirty blocks | Medium | Dirty blocks are journaled (Phase 6) before being written to their final location |

**Duration:** 1-2 weeks.

---

### Phase 4: B-tree & Extent Tree

**Goal:** Implement B+tree operations and the ext4 extent tree for
logical-to-physical block mapping, plus block and inode allocation.

**Deliverables:**

| Crate | Key Components |
|---|---|
| `ffs-btree` | Generic B+tree with configurable key/value types, insert, delete, search, range scan, split, merge, bulk load |
| `ffs-extent` | `ExtentTree` that wraps the B+tree for ext4 extent tree semantics: `lookup(logical_block) -> Option<PhysicalBlock>`, `insert_extent`, `remove_extent`, `split_extent`, `merge_adjacent` |
| `ffs-alloc` | `BlockAllocator` (mballoc-style), `InodeAllocator` (Orlov-style) |

**Extent Tree Internals:**

The ext4 extent tree is a B+tree embedded in the inode's `i_block` field (60
bytes = 1 header + 4 extents at the root level). Deeper trees use additional
blocks.

```
Root (in inode i_block):
  ext4_extent_header { magic=0xF30A, entries, max=4, depth }
  If depth == 0:
    ext4_extent[entries]        -- leaf: logical -> physical mapping
  If depth > 0:
    ext4_extent_idx[entries]    -- internal: logical -> child block
```

**Key Algorithms:**

| Algorithm | Source Reference | Description |
|---|---|---|
| Extent lookup | `ext4_ext_find_extent()` in extents.c | Walk from root to leaf following extent_idx entries |
| Extent insert | `ext4_ext_insert_extent()` | Insert a new extent; may cause leaf split |
| Extent split | `ext4_ext_split()` | Split a full node; propagate split up to root; may grow tree depth |
| Extent merge | `ext4_ext_try_to_merge()` | Merge adjacent extents with contiguous physical blocks |
| mballoc | `ext4_mb_new_blocks()` in mballoc.c | Multi-block allocation: best-fit search, buddy system fallback, locality group pre-allocation |
| Orlov allocation | `ext4_find_inode_goal()` in ialloc.c | Spread directories across groups; co-locate files with parent directory |

**mballoc Strategy:**

The multi-block allocator attempts allocation in this priority order:

1. **Goal block** -- if the file already has extents, try to extend the last
   extent by allocating blocks immediately after it.
2. **Pre-allocation** -- check locality group pre-allocated blocks (per-CPU
   pools of pre-allocated blocks for small files).
3. **Best-fit search** -- scan the group's buddy bitmap for the smallest free
   chunk that satisfies the request.
4. **Buddy fallback** -- if best-fit fails in the preferred group, scan other
   groups using buddy-system order.
5. **Any free block** -- last resort; scan all groups for any free block.

**Acceptance Criteria:**
- Resolve the block mapping for every file in a real ext4 test image and verify
  against `debugfs` output.
- Insert extents into an empty inode, trigger leaf splits, and verify the
  resulting tree structure.
- Allocate blocks using mballoc and verify they come from appropriate groups.
- Orlov allocator spreads new directories across groups (measure group
  distribution in test).
- Deallocate blocks and verify they are returned to the free pool.
- Stress test: allocate/deallocate 100K blocks in random order; verify no leaks
  (free count matches expected).

**LOC Estimate:** ~6,000

**Risk:**

| Risk | Severity | Mitigation |
|---|---|---|
| Extent tree split edge cases (root growth, depth increase) | High | Exhaustive test matrix: 1-extent, 2-extent, full-leaf, 2-level, 3-level, 4-level trees |
| mballoc fragmentation | Medium | Reproduce kernel's buddy-system bitmap; test with fragmented images |
| Off-by-one in physical block addressing (hi/lo 48-bit split) | Medium | Newtype `PhysBlockNr` that encapsulates hi/lo assembly; unit tests for boundary values |

**Duration:** 2-3 weeks.

---

### Phase 5: Inode & Directory

**Goal:** Implement inode lifecycle management, directory operations (both
linear and htree), and extended attribute support.

**Deliverables:**

| Crate | Key Components |
|---|---|
| `ffs-inode` | `Inode` struct (in-memory representation), `InodeTable` (read/write inodes from disk), `InodeCache` (LRU cache of hot inodes), permission checks (`can_read`, `can_write`, `can_exec`), timestamp management (atime/mtime/ctime/crtime), link count management |
| `ffs-dir` | `DirEntry` (in-memory), `LinearDir` (brute-force scan), `HtreeDir` (hashed B-tree lookup), `dx_hash` computation (half-MD4, TEA, legacy), `DirIterator` (readdir streaming), `DirBuilder` (create/link/unlink/rename entries) |
| `ffs-xattr` | `Xattr` struct, inline xattr storage (in inode body after i_extra_isize), block xattr storage (dedicated xattr blocks), namespace routing (user, trusted, system, security) |

**Directory Internals:**

ext4 supports two directory formats:

1. **Linear directory:** Unsorted list of `ext4_dir_entry_2` records. Each
   record is variable-length (8-byte header + name, padded to 4-byte alignment
   via `rec_len`). Lookup is O(n). Used for directories with < ~1000 entries
   (before htree is enabled).

2. **htree (hashed B-tree) directory:** A B-tree indexed by the hash of the
   filename. The root block contains `dx_root` (with dot/dotdot entries +
   `dx_root_info` + `dx_entry` array). Internal nodes contain `dx_entry` arrays.
   Leaf blocks are linear directory blocks. Lookup is O(log n).

**dx_hash Algorithms:**

| Algorithm | ID | Notes |
|---|---|---|
| Legacy | 0 | Unsigned sum of bytes -- terrible distribution, only for ancient filesystems |
| Half-MD4 | 1 | Default for most ext4 filesystems; good distribution |
| TEA | 2 | Tiny Encryption Algorithm; alternative hash |
| Legacy unsigned | 3 | Like legacy but explicit unsigned |
| Half-MD4 unsigned | 4 | Half-MD4 with unsigned folding |
| TEA unsigned | 5 | TEA with unsigned folding |
| siphash | 6 | Modern hash; used with ext4 casefold |

The hash algorithm is stored in `dx_root_info.hash_version`. The hash seed is
stored in `s_hash_seed[4]` in the superblock (16 bytes, initialized at mkfs
time).

**Acceptance Criteria:**
- Read all inodes from a real ext4 test image; verify mode, uid, gid, size,
  timestamps against `stat` output.
- List all directory entries in `/`, `/home`, and a large directory (>1000
  entries) from the test image.
- Perform htree lookup for known filenames; verify O(log n) block reads.
- Compute `dx_hash` for test filenames and verify against kernel-computed values
  (using `debugfs` or a reference C implementation).
- Create a new file: allocate inode, insert directory entry, set permissions,
  write inode to disk, verify with `fsck.ext4`.
- Delete a file: remove directory entry, decrement link count, free inode and
  blocks if link count reaches zero.
- Rename a file: remove from source directory, insert into target directory,
  handle cross-directory rename.
- Read and write extended attributes; verify with `getfattr`/`setfattr`.

**LOC Estimate:** ~5,000

**Risk:**

| Risk | Severity | Mitigation |
|---|---|---|
| htree hash compatibility | High | Byte-for-byte test vectors extracted from kernel; test with half-MD4, TEA, and siphash seeds |
| Directory entry alignment (rec_len padding) | Medium | Fuzz test: random-length names, verify rec_len is always 4-byte aligned and covers the entry |
| Inode extra_isize variability | Low | Parse extra_isize from superblock; handle both 128-byte and 256-byte inodes |
| Race conditions in inode cache | Medium | parking_lot::RwLock per inode slot; test under concurrent load |

**Duration:** 2-3 weeks.

---

### Phase 6: Journal & MVCC

**Goal:** Implement JBD2 journal replay for ext4 compatibility and a novel
COW-based journal with block-level MVCC and Serializable Snapshot Isolation.

This is the **highest-risk phase** and the core innovation of FrankenFS.

**Deliverables:**

| Crate | Key Components |
|---|---|
| `ffs-journal` | `Jbd2Journal` (replay-only for ext4 compat), `CowJournal` (native FrankenFS journal), `Transaction` (atomic unit of work), `TxnHandle` (RAII handle for active transaction), `CheckpointManager` (advance journal tail) |
| `ffs-mvcc` | `MvccStore` (block → version chain), `BlockVersion { block, commit_seq, writer, bytes }`, `Transaction` (active txn with staged writes), `CommitError` (conflict reporting), `Snapshot { high: CommitSeq }` (read-consistent view); first-committer-wins conflict detection; `prune_versions_older_than()` GC |

**JBD2 Replay (ext4 Compatibility):**

When mounting a real ext4 image that was not cleanly unmounted, the journal may
contain uncommitted transactions that must be replayed. JBD2 uses a
write-ahead log with these block types:

| Block Type | Tag | Purpose |
|---|---|---|
| Descriptor | `JBD2_DESCRIPTOR_BLOCK` (1) | Lists the filesystem blocks in this transaction |
| Data | (no tag -- follows descriptor) | Copies of the filesystem blocks |
| Commit | `JBD2_COMMIT_BLOCK` (2) | Marks transaction as committed |
| Revoke | `JBD2_REVOKE_BLOCK` (5) | Blocks that should NOT be replayed from earlier transactions |
| Superblock v1/v2 | `JBD2_SUPERBLOCK_V1/V2` (3/4) | Journal metadata |

Replay algorithm:
1. Read journal superblock; find `s_start` (first transaction) and `s_sequence`
   (expected sequence number).
2. **Pass 1 (SCAN):** Walk the journal from `s_start`, collecting committed
   transactions and building the revoke table.
3. **Pass 2 (REVOKE):** Mark blocks that appear in revoke records.
4. **Pass 3 (REPLAY):** For each committed transaction (in order), replay
   non-revoked blocks to their filesystem locations.
5. Clear the journal (write `s_start = 0`).

**COW Journal (Native Mode):**

In native mode, FrankenFS uses copy-on-write journaling:

- **No write-ahead log.** Instead of writing blocks to the journal first and
  then to their final location, COW writes to a *new* location every time.
- **Version chain.** Each block has a linked list of versions, ordered by LSN.
  The current version is at the head.
- **Atomic commit.** A transaction commits by atomically updating the version
  pointers (a single metadata write).
- **Instant recovery.** No replay needed; the version store always points to the
  last committed state.

**Block-Level MVCC:**

| Concept | Implementation |
|---|---|
| Version chain | `BTreeMap<BlockNumber, Vec<BlockVersion>>` where `BlockVersion { block: BlockNumber, commit_seq: CommitSeq, writer: TxnId, bytes: Vec<u8> }` |
| Snapshot | `Snapshot { high: CommitSeq }` — reading block N returns the latest version with `commit_seq <= snapshot.high` |
| Write | `Transaction::stage_write()` buffers in the transaction's `BTreeMap<BlockNumber, Vec<u8>>`; not visible to other transactions |
| Commit | `MvccStore::commit()` validates first-committer-wins (no concurrent write to same block), appends `BlockVersion` entries, returns `Result<CommitSeq, CommitError>` |
| Abort | Transaction is dropped; staged writes are never applied |
| Garbage collection | `prune_versions_older_than(watermark)` removes versions superseded by newer versions that also predate the watermark; at least one version per block is always retained |

**Serializable Snapshot Isolation (SSI):**

SSI detects write-write and write-read conflicts that would violate
serializability. FrankenFS implements SSI using the Cahill-Rohm-Fekete algorithm:

1. **Read tracking:** Each transaction records the set of blocks it read and the
   version (LSN) it observed.
2. **Write tracking:** Each transaction records the set of blocks it wrote.
3. **Conflict detection at commit time:**
   - **RW conflict (dangerous structure):** Transaction T1 read block B at
     version V1; transaction T2 wrote block B creating version V2 where
     V1 < V2 <= T1.commit_lsn. If T2 committed before T1, this is a
     *rw-antidependency* from T1 to T2.
   - **Dangerous structure:** If two rw-antidependencies form a cycle
     (T1 -rw-> T2 -rw-> T3 -rw-> T1 or T1 -rw-> T2 -rw-> T1), one
     transaction must abort.
4. **Abort policy:** The transaction that has done the least work (fewest writes)
   is aborted. Ties are broken by transaction age (younger aborts).

**Acceptance Criteria:**
- Replay the JBD2 journal from a real ext4 image that was force-unmounted (kill
  -9 during write); verify filesystem integrity with `fsck.ext4`.
- Open two concurrent snapshots; write to the same file from snapshot A; read
  from snapshot B; verify B sees the old version.
- Commit A; open snapshot C; verify C sees A's writes.
- SSI conflict detection: two transactions that read/write overlapping blocks;
  verify one is aborted.
- SSI false positive rate: run a workload with non-conflicting transactions;
  verify zero false aborts (this is SSI's theoretical guarantee for non-cyclic
  dependency graphs).
- Garbage collector: create 1000 versions of a block, advance the oldest
  snapshot, verify old versions are reclaimed.
- All of the above tested under `asupersync` lab runtime for deterministic
  concurrency.

**LOC Estimate:** ~8,000

**Risk:**

| Risk | Severity | Mitigation |
|---|---|---|
| JBD2 replay correctness | Critical | Test with real unclean ext4 images generated by the conformance harness; bit-for-bit comparison with kernel replay |
| MVCC garbage collection correctness (premature reclamation) | Critical | Formal invariant: never reclaim a version if any active snapshot could observe it; tested with model checking under lab runtime |
| SSI false positive rate under high contention | High | Benchmark with TPC-C-style workload; tune conflict detection granularity (block-level vs. range-level) |
| Version store memory consumption | High | Bounded version chain length per block; spill old versions to disk when memory pressure exceeds threshold |
| Interaction between JBD2 compat mode and native COW mode | Medium | Separate code paths; JBD2 mode is read-only replay at mount time; all runtime writes use COW journal |

**Duration:** 3-5 weeks.

---

### Phase 7: FUSE Interface

**Goal:** Implement the `fuser::Filesystem` trait and mount orchestration so
that FrankenFS can be mounted as a real filesystem.

**Deliverables:**

| Crate | Key Components |
|---|---|
| `ffs-fuse` | Implementation of `fuser::Filesystem` with all required operations |
| `ffs-core` | `MountManager` (validates superblock, initializes caches, starts daemons), `Superblock` (in-memory superblock with feature flag checking), `FsContext` (shared state: block device, caches, allocators, journal, MVCC store) |

**FUSE Operations:**

| Operation | FUSE Method | Description |
|---|---|---|
| Mount | `init()` | Validate superblock, replay journal if needed, initialize caches |
| Unmount | `destroy()` | Flush dirty blocks, commit pending transactions, sync to disk |
| Lookup | `lookup()` | Directory entry lookup by name; returns inode attributes + generation |
| Getattr | `getattr()` | Return file/directory attributes (stat) |
| Setattr | `setattr()` | Change mode, uid, gid, size (truncate), timestamps |
| Read | `read()` | Read file data; extent tree lookup, cache fetch, copy to userspace buffer |
| Write | `write()` | Write file data; allocate blocks if needed, update extent tree, dirty cache |
| Readdir | `readdir()` | Stream directory entries; support both linear and htree directories |
| Readdirplus | `readdirplus()` | Like readdir but also returns inode attributes (reduces subsequent getattr calls) |
| Create | `create()` | Allocate inode, insert dir entry, return file handle |
| Mkdir | `mkdir()` | Allocate inode (directory type), insert dir entry, create dot/dotdot entries |
| Unlink | `unlink()` | Remove dir entry, decrement link count, free inode+blocks if link count == 0 |
| Rmdir | `rmdir()` | Like unlink but verify directory is empty first |
| Rename | `rename()` | Atomic rename: remove from source dir, insert into target dir |
| Link | `link()` | Create hard link: insert dir entry, increment link count |
| Symlink | `symlink()` | Create symbolic link: allocate inode, store target path in extent data or inline |
| Readlink | `readlink()` | Read symbolic link target |
| Statfs | `statfs()` | Return filesystem statistics (total/free blocks, total/free inodes) |
| Fsync | `fsync()` | Flush dirty blocks for this inode; optionally datasync (skip metadata) |
| Fallocate | `fallocate()` | Pre-allocate blocks without writing data; supports KEEP_SIZE and PUNCH_HOLE |
| Open | `open()` | Validate access permissions, return file handle |
| Release | `release()` | Close file handle, flush if needed |
| Opendir | `opendir()` | Validate directory access permissions |
| Releasedir | `releasedir()` | Close directory handle |
| Access | `access()` | Check access permissions (used by access(2) syscall) |
| Getxattr | `getxattr()` | Read extended attribute value |
| Setxattr | `setxattr()` | Write extended attribute value |
| Listxattr | `listxattr()` | List extended attribute names |
| Removexattr | `removexattr()` | Remove extended attribute |

**Error Code Mapping:**

Every `FfsError` variant maps to a POSIX errno for FUSE:

| FfsError Variant | errno | Typical Cause |
|---|---|---|
| `Io` | `EIO` | I/O error |
| `Corruption` | `EIO` | On-disk corruption detected |
| `Format` | `EINVAL` | Invalid on-disk format |
| `Parse` | `EINVAL` | Parse-layer error surfaced to user |
| `UnsupportedFeature` | `EOPNOTSUPP` | Feature not supported by this build |
| `InvalidGeometry` | `EINVAL` | Block size or geometry out of range |
| `MvccConflict` | `EAGAIN` | SSI conflict; retry transaction |
| `Cancelled` | `EINTR` | Cx cancellation |
| `NoSpace` | `ENOSPC` | No free blocks or inodes |
| `NotFound` | `ENOENT` | File or directory not found |
| `PermissionDenied` | `EACCES` | Insufficient permissions |
| `ReadOnly` | `EROFS` | Write attempted on read-only mount |
| `NotDirectory` | `ENOTDIR` | Path component is not a directory |
| `IsDirectory` | `EISDIR` | Attempted file operation on a directory |
| `NotEmpty` | `ENOTEMPTY` | rmdir on non-empty directory |
| `NameTooLong` | `ENAMETOOLONG` | Filename exceeds limit |
| `Exists` | `EEXIST` | File already exists in create/mkdir |
| `RepairFailed` | `EIO` | RaptorQ repair could not recover data |

> **Note:** These are the canonical 18 FfsError variants. See `crates/ffs-error/src/lib.rs` for the normative definition and mapping policy documentation.

**Acceptance Criteria:**
- Mount a real ext4 test image via FUSE.
- `ls -la /mnt/frankenfs/` returns correct directory listing.
- `cat /mnt/frankenfs/testfile` returns correct file contents.
- `cp /tmp/newfile /mnt/frankenfs/newfile` creates the file; `diff` confirms
  contents match.
- `rm /mnt/frankenfs/newfile` removes the file.
- `mkdir`, `rmdir`, `ln`, `ln -s`, `mv` all work correctly.
- `bonnie++` basic benchmark passes without errors.
- `fsck.ext4 -n` on the unmounted image reports no errors after a write session.
- Concurrent access: two processes reading/writing different files simultaneously
  without corruption.

**LOC Estimate:** ~4,000

**Risk:**

| Risk | Severity | Mitigation |
|---|---|---|
| FUSE protocol edge cases (generation numbers, node IDs, timeouts) | Medium | Study fuser documentation and libfuse test suite; test with FUSE debug logging |
| Error code mapping gaps | Low | Exhaustive match on FfsError; no wildcard arms |
| Read-ahead / write-behind buffering strategy | Medium | Start with simple synchronous I/O; add buffering in optimization pass |
| inode generation number management | Medium | Store generation in ext4_inode.i_generation; increment on reuse for NFS-like stale handle detection |

**Duration:** 2-3 weeks.

---

### Phase 8: RaptorQ Repair

**Goal:** Implement RaptorQ fountain-code self-healing that detects and repairs
block-level corruption automatically.

**Deliverables:**

| Component | Description |
|---|---|
| `RepairCodec` | RaptorQ encoder/decoder using `asupersync`'s GF(256) codec |
| `RepairSymbolStore` | Storage for repair symbols (dedicated blocks at end of each block group) |
| `ScrubDaemon` | Background task that scans block groups, verifies checksums, triggers repair |
| `CorruptionDetector` | Checksum verification (CRC32C for ext4-compat metadata, BLAKE3 for data blocks in native mode) |
| `RepairManager` | Orchestrates detection, symbol retrieval, decoding, and block rewrite |

**RaptorQ Design:**

RaptorQ (RFC 6330) is a fountain code that can recover K source symbols from any
K + epsilon received symbols (where epsilon is typically 0-2). We use it as
follows:

| Parameter | Value | Rationale |
|---|---|---|
| Source symbols per group | K = blocks_per_group (e.g., 32768) | One repair set per block group |
| Symbol size | block_size (e.g., 4096 bytes) | Each source symbol is one block |
| Repair symbols | R = ceil(K * repair_ratio) | Configurable; default 5% overhead |
| Repair ratio | 0.05 (5%) | Recovers up to ~5% of blocks per group |
| Encoding | Systematic | Source symbols are the original blocks; repair symbols are the parity |

**Storage Layout:**

Repair symbols are stored in reserved blocks at the end of each block group.
The number of reserved blocks is `ceil(blocks_per_group * repair_ratio)`. These
blocks are marked as used in the block bitmap but are not part of the regular
allocation pool.

**Repair Flow:**

```
ScrubDaemon
  |
  v
For each block_group:
  1. Read all blocks in the group
  2. Verify checksum of each block
  3. If all checksums pass -> skip to next group
  4. If corrupted blocks found:
     a. Count corrupted blocks (C)
     b. If C <= R (repair symbols available):
        i.  Read R repair symbols for this group
        ii. Feed K-C good source symbols + R repair symbols to RaptorQ decoder
        iii. Recover C missing source symbols
        iv. Verify recovered blocks (checksum)
        v.  Write recovered blocks back to disk
        vi. Log repair event
     c. If C > R:
        i.  Log unrecoverable corruption
        ii. Return EIO for affected files
```

**Repair Symbol Refresh:**

When a block is written, its repair symbols become stale. The `RepairManager`
must re-encode the affected block group's repair symbols. This is done
lazily:

1. Mark the block group's repair symbols as stale (set a flag in the group
   descriptor or a dedicated bitmap).
2. On the next scrub pass, re-encode stale groups.
3. Optionally, re-encode immediately if `fsync` is called (for critical data).

**Acceptance Criteria:**
- Generate repair symbols for a block group; verify symbol count matches
  configuration.
- Inject single-block corruption (flip bytes in one block); verify `ScrubDaemon`
  detects and automatically recovers the block.
- Inject multi-block corruption (up to repair_ratio of blocks); verify recovery.
- Inject corruption exceeding repair_ratio; verify graceful failure (EIO, not
  panic or silent data corruption).
- Measure repair symbol storage overhead; verify it matches configured ratio
  (5% default).
- Benchmark RaptorQ encode/decode performance; verify scrub of a 1GB image
  completes in < 60 seconds on commodity hardware.
- Verify repair interacts correctly with MVCC: repairing a block restores the
  correct version (latest committed).

**LOC Estimate:** ~4,000

**Risk:**

| Risk | Severity | Mitigation |
|---|---|---|
| Repair symbol storage overhead | Medium | Configurable ratio; default 5%; document trade-off (more symbols = more recovery but less usable space) |
| GF(256) codec performance | Medium | Use asupersync's SIMD-accelerated codec; benchmark early; fall back to scalar if SIMD unavailable |
| Interaction with MVCC version chains | High | Repair always targets the latest committed version; old versions in the chain are not repaired (they will be GC'd) |
| Stale repair symbols after writes | Medium | Lazy re-encoding with scrub daemon; critical writes can force immediate re-encoding |
| Repair during active writes (torn repair) | Medium | Repair takes a snapshot (MVCC) of the block group; writes to a new location (COW); atomically update pointers |

**Duration:** 2-3 weeks.

---

### Phase 9: CLI, TUI & Conformance Harness

**Goal:** Deliver the user-facing tools and a comprehensive conformance test
suite that validates FrankenFS against the Linux kernel ext4 driver.

**Deliverables:**

| Crate | Key Components |
|---|---|
| `ffs-cli` | `mount` (FUSE mount with options), `umount` (clean unmount), `fsck` (offline integrity check + repair), `info` (dump superblock, group descriptors, inode info), `dump` (raw block/inode hex dump), `mkfs` (create new FrankenFS image -- future) |
| `ffs-tui` | Live dashboard built on `ftui` (frankentui): cache hit/miss rates, MVCC active snapshots + version counts, repair symbol status per group, block allocation heatmap, journal transaction rate |
| `ffs-harness` | Automated conformance tests comparing FrankenFS behavior against real kernel ext4 |
| `ffs` | Public API facade crate; re-exports key types and functions for library consumers |

**CLI Commands:**

```
ffs mount <image> <mountpoint> [options]
  --read-only         Mount read-only
  --cache-size <MB>   ARC cache size (default: 256MB)
  --repair-ratio <F>  RaptorQ repair symbol ratio (default: 0.05)
  --no-journal        Skip JBD2 journal replay
  --debug             Enable FUSE debug logging

ffs umount <mountpoint>
  --force             Force unmount (may lose unflushed data)

ffs fsck <image>
  --repair            Attempt automatic repair
  --scrub             Run RaptorQ scrub
  --verbose           Detailed output

ffs info <image>
  --superblock        Dump superblock fields
  --groups            Dump group descriptors
  --inode <N>         Dump inode N
  --extent-tree <N>   Dump extent tree for inode N

ffs dump <image> --block <N> [--hex]
  Raw block dump (hex or binary)
```

**TUI Dashboard Layout:**

```
+--------------------------------------------------+
|  FrankenFS v0.1.0    /dev/loop0 -> /mnt/frankenfs |
+--------------------------------------------------+
| Cache          | MVCC           | Repair          |
| Hit: 94.2%     | Snapshots: 3   | Clean: 98.7%    |
| Miss: 5.8%     | Versions: 12K  | Stale: 1.3%     |
| Dirty: 128     | Commits/s: 45  | Repairs: 2      |
| Size: 256MB    | Oldest: 3.2s   | Errors: 0       |
+--------------------------------------------------+
| Block Allocation Heatmap (groups 0-127)           |
| [##########....######...####....####...####..#..] |
+--------------------------------------------------+
| Journal     | Transactions: 1,234  | Tail: 0x4000  |
+--------------------------------------------------+
| Log (last 10 events)                              |
| 14:23:01 REPAIR group 42 block 1374832 recovered  |
| 14:23:00 WRITE  /home/user/data.bin 4096 bytes    |
| 14:22:58 COMMIT txn 1234 (12 blocks, 0.3ms)       |
+--------------------------------------------------+
```

**Conformance Harness Design:**

The harness creates test ext4 images, performs operations using both FrankenFS
(via FUSE) and the kernel ext4 driver (via loopback mount), and compares
results.

| Test Category | Test Count (Est.) | Description |
|---|---|---|
| Superblock parsing | 15 | Compare all superblock fields against `dumpe2fs` |
| Inode attributes | 25 | stat() comparison for various file types |
| Directory listing | 20 | readdir comparison for small, medium, large, htree directories |
| File read | 30 | Read comparison for various file sizes (0, 1 byte, 4095, 4096, 1MB, 1GB) |
| File write | 25 | Write + read-back comparison; verify on-disk format with fsck |
| Extent tree | 20 | Block mapping comparison for fragmented/non-fragmented files |
| Hard links | 10 | Create, read, unlink hard links; verify link count |
| Symbolic links | 10 | Create, readlink, dangling links, long targets |
| Permissions | 15 | chmod, chown, access checks |
| Timestamps | 10 | atime, mtime, ctime, crtime; nanosecond precision |
| Extended attrs | 15 | Set, get, list, remove xattrs; all namespaces |
| Rename | 15 | Same-dir, cross-dir, overwrite, atomic rename |
| Truncate | 10 | Grow, shrink, punch hole |
| Fsync | 10 | Write + fsync + kill + remount; verify data persisted |
| Edge cases | 20 | ENOSPC, ENOENT, ENAMETOOLONG, concurrent ops, etc. |
| **Total** | **~250** | **Target: 95%+ pass rate** |

**Acceptance Criteria:**
- `ffs mount` mounts a test image; standard Unix tools work.
- `ffs fsck` detects and reports corruption.
- `ffs info --superblock` matches `dumpe2fs` output for all supported fields.
- TUI displays live statistics; updates at >= 10 Hz.
- TUI does not consume > 1% CPU when idle.
- Conformance harness passes >= 95% of test vectors (237+ of 250).
- Failing tests are documented with root cause and phase for future fix.

**LOC Estimate:** ~5,000

**Risk:**

| Risk | Severity | Mitigation |
|---|---|---|
| Conformance test coverage gaps | Medium | Prioritize tests that cover real-world usage patterns; add tests as bugs are found |
| TUI performance overhead (polling stats) | Low | Use atomic counters for stats; TUI reads atomics without locking |
| CLI argument parsing edge cases | Low | Use `clap` derive macros; comprehensive integration tests |
| Public API stability | Medium | Mark `ffs` crate as `0.1.0`; document instability; use `#[doc(hidden)]` for internal APIs |

**Duration:** 2-3 weeks.

---

## 5. Cross-Cutting Concerns

### 5.1 Cancellation via Cx

Every function that performs I/O or long-running computation takes a
`&asupersync::Cx` parameter as its first argument. The Cx capability context
provides cooperative cancellation:

```rust
pub async fn read_block(cx: &Cx, dev: &dyn BlockDevice, nr: BlockNr) -> Result<BlockBuf> {
    cx.check_cancelled()?;       // Early exit if already cancelled
    let buf = dev.read(cx, nr).await?;
    cx.check_cancelled()?;       // Check again after I/O
    Ok(buf)
}
```

**Rules:**
- All public APIs in every crate accept `&Cx` as the first parameter.
- Cx is checked at every yield point (before/after I/O, at loop iteration
  boundaries, before expensive computations).
- A cancelled Cx causes `FfsError::Cancelled` to propagate up the call stack.
- The FUSE layer translates `FfsError::Cancelled` to `EINTR`.

### 5.2 Deterministic Testing

The `asupersync` lab runtime provides deterministic scheduling of concurrent
operations. This is critical for testing MVCC and SSI:

- **Controlled scheduling:** The lab runtime executes async tasks in a
  deterministic order, controlled by a seed. Replaying the same seed reproduces
  the same interleaving.
- **Fault injection:** The lab runtime can inject I/O failures, delays, and
  cancellations at specific points.
- **Model checking:** For critical invariants (e.g., MVCC version chain
  consistency, SSI conflict detection completeness), the lab runtime can
  enumerate all possible interleavings up to a bound.

### 5.3 Checksums

| Checksum | Use | Algorithm | Notes |
|---|---|---|---|
| Metadata checksum | ext4 superblock, group descriptors, inodes, directory blocks | CRC32C | ext4 `metadata_csum` feature; seed is `s_checksum_seed` (CRC32C of filesystem UUID) |
| Journal checksum | JBD2 commit blocks | CRC32C | `JBD2_FEATURE_INCOMPAT_CSUM_V3` |
| Data integrity (native) | Block-level integrity in native mode | BLAKE3 | Faster than SHA-256; keyed mode available for authenticated integrity |
| Repair symbol integrity | RaptorQ repair symbol blocks | BLAKE3 | Detect repair symbol corruption before using them for recovery |

### 5.4 No Unsafe Code

Every crate root contains:

```rust
#![forbid(unsafe_code)]
```

The workspace `Cargo.toml` includes:

```toml
[workspace.lints.rust]
unsafe_code = "forbid"
```

This is a hard constraint. If a third-party crate requires `unsafe`, it must be:
1. Audited via `cargo vet` or `cargo crev`.
2. Isolated behind a safe abstraction boundary.
3. Documented in `PROPOSED_ARCHITECTURE.md` with justification.

Third-party crates like `crc32c`, `blake3`, and `parking_lot` use `unsafe`
internally but expose safe APIs. This is acceptable because they are widely
audited and their safety invariants are well-understood.

### 5.5 Error Handling

All fallible operations return `Result<T, FfsError>`. The `FfsError` enum is
defined in `ffs-error` and has **14 canonical variants** — see `ffs-error/src/lib.rs`
and PROPOSED_ARCHITECTURE.md Section 7 for the single normative listing.

The 14 variants are: `Io`, `Corruption`, `Format`, `MvccConflict`, `Cancelled`,
`NoSpace`, `NotFound`, `PermissionDenied`, `NotDirectory`, `IsDirectory`,
`NotEmpty`, `NameTooLong`, `Exists`, `RepairFailed`.

> **Important:** Earlier revisions of this document listed 19 variants with names
> like `AlreadyExists`, `ReadOnly`, `InvalidArgument`, `TooLarge`, `Journal`,
> `Unsupported`, `Range`. Those are **non-normative** — the implemented 14-variant
> enum in `ffs-error/src/lib.rs` is the source of truth.

### 5.6 Logging and Tracing

All crates use the `tracing` framework for structured logging:

- `tracing::error!` for unrecoverable errors (corruption, I/O failure).
- `tracing::warn!` for recoverable issues (SSI conflict, repair triggered).
- `tracing::info!` for significant events (mount, unmount, journal replay).
- `tracing::debug!` for detailed operation traces (block read/write, cache
  hit/miss).
- `tracing::trace!` for verbose internals (MVCC version chain operations, ARC
  list movements).

The FUSE binary initializes a `tracing-subscriber` that writes to stderr and
optionally to a log file. The TUI integrates with `tracing` to display recent
events.

### 5.7 Testing Strategy

| Level | Framework | Scope |
|---|---|---|
| Unit tests | `#[cfg(test)]` + `proptest` | Individual functions, struct parsing, algorithm correctness |
| Integration tests | `tests/` directory per crate | Cross-function workflows within a crate |
| System tests | `ffs-harness` | End-to-end FUSE mount, file operations, conformance |
| Deterministic concurrency tests | `asupersync` lab runtime | MVCC, SSI, concurrent cache access, journal replay |
| Fuzz tests | `cargo-fuzz` / `libfuzzer` | On-disk struct parsing, directory entry parsing, extent tree operations |
| Benchmark tests | `criterion` | ARC cache throughput, RaptorQ encode/decode, FUSE operation latency |

---

## 6. Risk Summary Table

| # | Risk | Phase | Severity | Likelihood | Impact | Mitigation |
|---|---|---|---|---|---|---|
| R1 | JBD2 replay correctness | 6 | Critical | Medium | Data loss on mount of unclean image | Test with real unclean images; bit-for-bit comparison with kernel replay; fuzz journal parsing |
| R2 | MVCC GC premature reclamation | 6 | Critical | Low | Silent data corruption (reader sees wrong version) | Formal invariant: version >= oldest_active_snapshot_lsn is never reclaimed; lab runtime model checking |
| R3 | SSI false positive rate | 6 | High | Medium | Unnecessary transaction aborts degrade throughput | Benchmark with realistic workloads; tune conflict detection granularity; consider predicate-level tracking |
| R4 | Extent tree split edge cases | 4 | High | Medium | Filesystem corruption on deep extent trees | Exhaustive test matrix covering all tree depths (0-4); fuzz extent insertion sequences |
| R5 | htree hash compatibility | 5 | High | Medium | Directory lookup fails for existing ext4 images | Byte-for-byte test vectors from kernel; test all hash algorithms (half-MD4, TEA, siphash) |
| R6 | ARC cache coherency | 3 | High | Low | Stale reads or lost writes under concurrent access | RwLock per cache entry; concurrent stress test with thread sanitizer |
| R7 | FUSE protocol edge cases | 7 | Medium | Medium | Spurious errors or hangs for corner-case operations | Study libfuse test suite; enable FUSE debug logging in CI |
| R8 | RaptorQ + MVCC interaction | 8 | High | Low | Repair restores wrong version of a block | Repair always targets latest committed version from MVCC store; never repairs uncommitted versions |
| R9 | Version store memory | 6 | High | Medium | OOM under sustained write workload | Bounded version chains; disk-spill for old versions; configurable memory limit |
| R10 | Endianness bugs | 2 | Medium | Medium | Incorrect parsing of on-disk structures | Le16/Le32/Le64 newtypes; zero raw integer reads; property-based round-trip tests |
| R11 | Repair symbol storage overhead | 8 | Medium | Low | Reduced usable space beyond user expectation | Configurable ratio with clear documentation; default 5% |
| R12 | Conformance test coverage | 9 | Medium | Medium | Undiscovered incompatibilities with kernel ext4 | Start testing early (Phase 5+); add tests as bugs surface; target 95% pass rate |
| R13 | mballoc fragmentation pathology | 4 | Medium | Low | Poor allocation performance on fragmented images | Buddy-system fallback; test with pre-fragmented images |
| R14 | Directory entry alignment | 5 | Medium | Medium | Corrupted directory blocks | Fuzz variable-length name insertion; verify rec_len invariants |
| R15 | Stale repair symbols after writes | 8 | Medium | Medium | Repair fails because symbols are outdated | Lazy re-encoding via scrub daemon; optional eager re-encoding on fsync |

---

## 7. Dependencies Between Phases

```
Phase 1: Bootstrap
    |
    v
Phase 2: Types & On-Disk Formats
    |
    +-----------------------------+
    |                             |
    v                             v
Phase 3: Block I/O & Cache     (provides Cx-aware I/O to all downstream)
    |
    +------------------+
    |                  |
    v                  v
Phase 4: B-tree      Phase 6: Journal & MVCC
& Extent Tree            |
    |                    |
    v                    |
Phase 5: Inode           |
& Directory              |
    |                    |
    +-------+    +-------+
            |    |
            v    v
        Phase 7: FUSE Interface
              |
              v
        Phase 8: RaptorQ Repair
              |
              v
        Phase 9: CLI, TUI & Conformance Harness
```

**Critical Path:** 1 -> 2 -> 3 -> 4 -> 5 -> 7 -> 8 -> 9

**Parallel Opportunities:**
- Phase 6 (Journal & MVCC) can proceed in parallel with Phases 4 and 5, since
  it depends only on Phase 3 (Block I/O).
- Phase 9 CLI/TUI work can begin as soon as Phase 7 is functional; the
  conformance harness requires Phase 7 completion.

**Dependency Details:**

| From | To | What is Needed |
|---|---|---|
| Phase 1 | Phase 2 | Workspace structure, crate stubs |
| Phase 2 | Phase 3 | `BlockNumber`, `TxnId`, `CommitSeq`, `FfsError`, on-disk types |
| Phase 2 | Phase 4 | `ext4_extent_header`, `ext4_extent`, `ext4_extent_idx` on-disk types |
| Phase 2 | Phase 5 | `ext4_inode`, `ext4_dir_entry_2`, `ext4_dx_root` on-disk types |
| Phase 2 | Phase 6 | `jbd2_journal_superblock_s`, JBD2 block types, `TxnId`, `CommitSeq` |
| Phase 3 | Phase 4 | `BlockDevice` trait, `BlockBuf`, Cx-aware I/O |
| Phase 3 | Phase 5 | Cached block reads for inode table, directory blocks |
| Phase 3 | Phase 6 | Block reads/writes for journal and MVCC version store |
| Phase 4 | Phase 5 | Extent tree lookup for inode data blocks |
| Phase 4 | Phase 7 | Block allocation for write operations |
| Phase 5 | Phase 7 | Inode and directory operations for FUSE callbacks |
| Phase 6 | Phase 7 | Journal replay at mount, MVCC for concurrent access |
| Phase 7 | Phase 8 | Mounted filesystem context for scrub daemon integration |
| Phase 7 | Phase 9 | Functional FUSE mount for CLI and conformance testing |
| Phase 8 | Phase 9 | Repair status reporting for TUI; repair testing for harness |

---

## 8. Total LOC Estimate

| Phase | Crates | LOC | Cumulative |
|---|---|---|---|
| 1 - Bootstrap | (all stubs) | 500 | 500 |
| 2 - Types & On-Disk | ffs-types, ffs-error, ffs-ondisk | 5,000 | 5,500 |
| 3 - Block I/O & Cache | ffs-block | 3,000 | 8,500 |
| 4 - B-tree & Extent | ffs-btree, ffs-extent, ffs-alloc | 6,000 | 14,500 |
| 5 - Inode & Directory | ffs-inode, ffs-dir, ffs-xattr | 5,000 | 19,500 |
| 6 - Journal & MVCC | ffs-journal, ffs-mvcc | 8,000 | 27,500 |
| 7 - FUSE Interface | ffs-fuse, ffs-core | 4,000 | 31,500 |
| 8 - RaptorQ Repair | ffs-repair | 4,000 | 35,500 |
| 9 - CLI, TUI & Harness | ffs-cli, ffs-tui, ffs-harness, ffs | 5,000 | 40,500 |
| **Tests (all phases)** | | **~5,000** | **45,500** |

**Comparison with Legacy Source:**

| Metric | Legacy (C) | FrankenFS (Rust) | Ratio |
|---|---|---|---|
| ext4 source | ~65,000 LOC | ~40,500 LOC (impl) | 62% |
| btrfs source (reference) | ~140,000 LOC | ~0 LOC (concepts only) | 0% |
| Total legacy | ~205,000 LOC | ~45,500 LOC (total) | 22% |
| Test code | ~0 (kernel selftests separate) | ~5,000 LOC (integrated) | N/A |
| Unsafe code | 100% (C is all unsafe) | 0% (`#![forbid(unsafe_code)]`) | 0% |

---

## 9. Success Criteria

The FrankenFS porting effort is considered successful when all of the following
criteria are met:

### 9.1 Functional Correctness

| Criterion | Verification Method |
|---|---|
| Mount real ext4 images created by `mkfs.ext4` | Manual test + conformance harness |
| Read files of all sizes (0 bytes to multi-GB) | Conformance harness: byte-for-byte comparison with kernel ext4 |
| Write files and verify persistence across unmount/remount | Write via FUSE, unmount, verify with `fsck.ext4 -n`, remount, read back |
| Directory operations (create, list, delete, rename) | Conformance harness |
| Hard links and symbolic links | Conformance harness |
| Extended attributes (user, trusted, system namespaces) | Conformance harness: compare with `getfattr`/`setfattr` |
| Permission enforcement (mode, uid, gid) | Conformance harness: compare with `stat` and access checks |
| JBD2 journal replay for unclean images | Force-kill during write; remount; verify no data loss beyond last committed transaction |

### 9.2 Concurrency & MVCC

| Criterion | Verification Method |
|---|---|
| Concurrent readers + writers without corruption | Stress test: N writer threads + M reader threads for 60 seconds; verify no EIO or data corruption |
| Snapshot isolation: readers see consistent state | Open snapshot, perform writes in another thread, verify snapshot sees original data |
| SSI conflict detection | Construct known-conflicting transaction pairs; verify one aborts |
| No deadlocks under concurrent access | Thread sanitizer + lab runtime model checking |
| MVCC garbage collection does not reclaim active versions | Lab runtime: hold snapshot, create 10K versions, trigger GC, verify snapshot still reads correctly |

### 9.3 Self-Healing

| Criterion | Verification Method |
|---|---|
| Single-block corruption auto-recovery | Inject corruption (flip bytes); wait for scrub; verify block restored |
| Multi-block corruption within repair budget | Inject corruption in N blocks (N <= R); verify all recovered |
| Corruption exceeding repair budget fails gracefully | Inject corruption in N blocks (N > R); verify EIO (not panic or silent corruption) |
| Scrub detects and repairs without data loss | Full scrub of a healthy image completes without errors; scrub of a corrupted image repairs without losing uncorrupted data |

### 9.4 Code Quality

| Criterion | Verification Method |
|---|---|
| `cargo test --workspace` passes (all tests green) | CI pipeline |
| `cargo clippy --workspace -- -D warnings` passes | CI pipeline |
| `cargo fmt --check` passes | CI pipeline |
| `#![forbid(unsafe_code)]` in every crate | CI pipeline (workspace lint) |
| No `unwrap()` or `expect()` in library crates (except tests) | Clippy custom lint + code review |
| Conformance harness >= 95% pass rate (237+ of 250 tests) | Conformance harness CI job |
| Documentation coverage: all public items have doc comments | `#![warn(missing_docs)]` in every crate |

### 9.5 Performance Baselines

These are not hard requirements but targets for acceptable performance:

| Metric | Target | Measurement |
|---|---|---|
| Sequential read throughput | >= 200 MB/s (FUSE overhead ~2x vs kernel) | `fio` sequential read benchmark |
| Random read IOPS (4K blocks) | >= 50K IOPS (cached) | `fio` random read benchmark |
| ARC cache hit ratio | >= 90% for repeated access patterns | Internal instrumentation |
| FUSE latency (getattr) | < 100 us p99 | `fio` or custom benchmark |
| RaptorQ encode (per block group) | < 100 ms for 128MB group | Internal benchmark |
| RaptorQ decode (single block recovery) | < 10 ms | Internal benchmark |
| TUI refresh overhead | < 1% CPU when idle | `perf` profiling |

---

## Appendix A: Glossary

| Term | Definition |
|---|---|
| **ARC** | Adaptive Replacement Cache -- self-tuning cache that balances recency and frequency |
| **B+tree** | Balanced tree where all values are in leaf nodes; internal nodes contain only keys |
| **Block group** | ext4 divides the disk into block groups (~128MB each); each has its own bitmaps and inode table |
| **COW** | Copy-on-Write -- writing creates a new copy rather than overwriting in place |
| **Cx** | Capability context from `asupersync`; carries cancellation tokens and deadlines |
| **dx_hash** | Directory index hash function used in ext4 htree directories |
| **Extent** | Contiguous range of physical blocks mapped to a range of logical blocks |
| **FUSE** | Filesystem in Userspace -- Linux kernel module that delegates filesystem operations to a userspace process |
| **GF(256)** | Galois Field with 256 elements -- the finite field used in RaptorQ encoding |
| **htree** | Hashed B-tree -- ext4's indexed directory format for fast filename lookup |
| **JBD2** | Journaling Block Device v2 -- ext4's write-ahead logging subsystem |
| **LSN** | Log Sequence Number -- monotonically increasing identifier for journal entries |
| **mballoc** | Multi-block allocator -- ext4's block allocation subsystem |
| **MVCC** | Multi-Version Concurrency Control -- concurrent access via versioned data |
| **Orlov allocator** | Inode allocation strategy that spreads directories and co-locates files |
| **RaptorQ** | Fountain code (RFC 6330) for forward error correction |
| **SSI** | Serializable Snapshot Isolation -- concurrency control that detects serializability violations |

## Appendix B: Reference Materials

| Resource | Relevance |
|---|---|
| `legacy_ext4_and_btrfs_code/linux-fs/fs/ext4/` | Primary source for ext4 on-disk format and algorithms |
| `legacy_ext4_and_btrfs_code/linux-fs/fs/btrfs/` | Reference for COW B-tree, MVCC, and scrub concepts |
| ext4 wiki: https://ext4.wiki.kernel.org/ | On-disk format documentation |
| `man 5 ext4` | ext4 filesystem format specification |
| Megiddo & Modha, "ARC: A Self-Tuning, Low Overhead Replacement Cache" (2003) | ARC algorithm reference |
| Cahill, Rohm & Fekete, "Serializable Isolation for Snapshot Databases" (2008) | SSI algorithm reference |
| RFC 6330: RaptorQ Forward Error Correction Scheme | RaptorQ codec specification |
| `fuser` crate documentation | FUSE protocol implementation in Rust |
| `serde` + `serde_json` documentation | Serialization for fixtures, conformance, metadata |

## Appendix C: 21-Crate Dependency Graph (matches Cargo.toml)

```
ffs-types ──── depends on ─── serde, thiserror
ffs-error ──── depends on ─── thiserror

ffs-ondisk ─── depends on ─── ffs-types, ffs-error, crc32c, serde

ffs-block ──── depends on ─── ffs-types, ffs-error, ffs-ondisk,
               asupersync, parking_lot

ffs-btree ──── depends on ─── ffs-types, ffs-error, ffs-block, ffs-ondisk
ffs-alloc ──── depends on ─── ffs-types, ffs-error, ffs-block, ffs-ondisk
ffs-inode ──── depends on ─── ffs-types, ffs-error, ffs-block, ffs-ondisk
ffs-xattr ──── depends on ─── ffs-types, ffs-error, ffs-block, ffs-ondisk

ffs-dir ────── depends on ─── ffs-types, ffs-error, ffs-inode
ffs-extent ─── depends on ─── ffs-types, ffs-error, ffs-btree, ffs-alloc

ffs-journal ── depends on ─── ffs-types, ffs-error, ffs-block
ffs-repair ─── depends on ─── ffs-types, ffs-error, ffs-block, asupersync

ffs-mvcc ───── depends on ─── ffs-types, serde, thiserror
               (standalone — will gain ffs-block, ffs-journal later)

ffs-core ───── depends on ─── ffs-types, ffs-ondisk, ffs-mvcc,
               asupersync, serde, thiserror
               (will gain domain crate deps as implementation progresses)

ffs-fuse ───── depends on ─── ffs-core, ffs-types, asupersync,
               serde, thiserror

ffs ────────── depends on ─── ffs-core (re-exports)

ffs-cli ────── depends on ─── ffs-core, anyhow, serde, serde_json, ftui
ffs-tui ────── depends on ─── ffs, ftui
ffs-harness ── depends on ─── ffs-core, ffs-ondisk, ffs-types,
               anyhow, hex, serde, serde_json; dev: criterion

Legacy wrappers (reference only):
ffs-ext4 ───── depends on ─── ffs-ondisk
ffs-btrfs ──── depends on ─── ffs-ondisk
```

---

*This document is the authoritative porting plan for FrankenFS. All phase
deliverables, acceptance criteria, and risk mitigations are binding. Changes
require review and approval documented in a commit message referencing this
file.*
