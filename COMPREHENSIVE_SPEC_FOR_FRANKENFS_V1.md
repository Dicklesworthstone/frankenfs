# COMPREHENSIVE SPECIFICATION FOR FRANKENFS V1

> A memory-safe, FUSE-based Rust reimplementation of ext4 with block-level MVCC
> (replacing JBD2's global journal lock) and RaptorQ self-healing (fountain-coded
> corruption recovery per block group).

> **Version:** 1.0 | **Date:** 2026-02-09 | **Status:** Normative Draft

---

# COMPREHENSIVE SPECIFICATION FOR FRANKENFS -- Sections 0, 1, 2

> Canonical specification for FrankenFS v1. Normative unless explicitly marked informative.

---

## 0. How to Read This Document

This is the single authoritative specification for FrankenFS. It supersedes and consolidates `PROPOSED_ARCHITECTURE.md`, `PLAN_TO_PORT_FRANKENFS_TO_RUST.md`, `EXISTING_EXT4_BTRFS_STRUCTURE.md`, and `EXISTING_LEGACY_FS_STRUCTURE.md`. Those documents remain for reference; where they conflict, this document wins.

**Audience:** AI coding agents, human reviewers, and any collaborator who needs the full picture of what FrankenFS is, why it exists, and exactly how to build it.

### 0.1 Non-Negotiable Scope Doctrine

This specification describes the **complete target system**. There is no "V1 scope" escape hatch. Every feature, protocol, trait, on-disk structure, and subsystem described here is in scope. If something is genuinely excluded, it appears in the Exclusions section with a technical rationale. Everything else MUST be built.

Implementation is phased for sequencing, not scope reduction. A feature in Phase 9 is not optional -- it depends on Phase 8. A feature in Phase 2 that has not been implemented is implementation debt, not a spec omission. Agents MUST NOT treat codebase omissions as evidence that a specified feature is out of scope.

### 0.1.1 Current Errata (Doc-vs-Code Drift)

This section records *current* (not historical) drift between this spec and the codebase. It exists to prevent agents from "implementing to the wrong contract."

- **ParseError -> FfsError context drift:** The crate boundary is now explicit: `ffs-ondisk` returns `ParseError` (pure parsing + checksum verification), while user-facing layers return `FfsError` and convert at the orchestration boundary (`ffs-core`). However, the conversion still lacks a structured context object (structure + offsets + inode/group) for actionable diagnostics. Track: `bd-2fy`.
- **Missing normative traits (integration points):** Spec §8/§9/§14 define normative traits (repair manager, scrub progress, semantics ops) that are not yet present in code (`crates/ffs-repair` is currently stub-only, `crates/ffs-fuse` is scaffolding). Resolution: introduce the traits in the owning crates without creating dependency cycles, then migrate scaffolding to those contracts. Tracks: `bd-2l4`, `bd-3bf`, `bd-hv6`.

### 0.1.2 Audit Checklist (Mechanical)

Run these from the repo root to re-audit for drift:

```bash
# Workspace membership + crate count sanity.
cargo metadata --no-deps --format-version 1 | jq '.workspace_members | length'
ls crates | wc -l

# Crate map / count wording drift.
rg -n "19[- ]crate|19 crates|21[- ]crate|21 crates" -S *.md

# fuser planned vs required drift.
rg -n "\\bfuser\\b" -S Cargo.toml crates/ffs-fuse/Cargo.toml *.md

# Top-level normative contract presence in code.
rg -n "pub struct (GroupNumber|BlockSize|ByteOffset)\\b" -S crates/ffs-types
rg -n "enum (ParseError|FfsError)\\b" -S crates
rg -n "trait (RepairManager|BlockEventSink|FfsOperations|FuseBackend)\\b" -S crates

# Forbidden runtime creep.
rg -n "\\btokio\\b" Cargo.lock
```

### 0.2 Normative Language

Per RFC 2119 / RFC 8174:

- **MUST** / **MUST NOT**: Absolute requirement or prohibition. Violation is a spec-conformance bug.
- **SHOULD** / **SHOULD NOT**: Strong recommendation. Deviation requires documented justification citing the section.
- **MAY**: Truly optional.

Type definitions and trait signatures in code blocks are normative unless labeled "illustrative."

### 0.3 Glossary

| Term | Definition |
|------|-----------|
| **MVCC** | Multi-Version Concurrency Control. Readers see a consistent snapshot; writers create new block versions. No reader blocks a writer; no writer blocks a reader. |
| **SSI** | Serializable Snapshot Isolation. Extends SI to detect write-skew via rw-antidependency tracking (Cahill-Rohm-Fekete). Applied at block granularity. |
| **TxnId** | `TxnId(u64)`. Monotonically increasing transaction begin-order identifier. `TxnId(0)` reserved. |
| **CommitSeq** | `CommitSeq(u64)`. Monotonically increasing commit sequence number -- the global commit clock. `CommitSeq(0)` = before any commit. |
| **Snapshot** | `Snapshot { high: CommitSeq }`. Immutable read boundary. Version V visible iff `V.commit_seq <= S.high` and V is newest such version for its block. |
| **FCW** | First-Committer-Wins. If target block has committed version with `commit_seq > writer.snapshot.high`, commit MUST fail. |
| **ARC** | Adaptive Replacement Cache (Megiddo & Modha, 2003). Self-tuning T1/T2/B1/B2 cache with dynamic partition `p`. |
| **BlockNumber** | `BlockNumber(u64)`. Physical block identifier, zero-indexed. |
| **InodeNumber** | `InodeNumber(u64)`. Inode identifier. 0=reserved, 1=bad blocks, 2=root directory. |
| **GroupNumber** | `GroupNumber(u32)`. Block group identifier. At 4 KiB blocks: 32768 blocks/group (~128 MiB). |
| **Cx** | `asupersync::Cx`. Capability context for cooperative cancellation, deadline propagation, structured concurrency. Every I/O operation MUST accept `&Cx`. |
| **Budget** | Asupersync resource budget: `{ deadline, poll_quota, cost_quota, priority }`. Combined component-wise: deadline/poll/cost use `min`; priority uses `max`. |
| **Region** | Asupersync structured concurrency scope. Close implies quiescence. Used for scrub, GC, flush daemons. |
| **Lab** | Asupersync deterministic test runtime. Seed-controlled scheduling for reproducible interleaving enumeration. |
| **RaptorQ** | RFC 6330 fountain code. K source symbols -> unlimited encoding symbols; any ~K received suffice for decoding. Systematic encoding: source symbols = original blocks. |
| **OTI** | Object Transmission Information. RaptorQ decode metadata: `(F, Al, T, Z, N)`. Stored per block group. |
| **ECS** | Erasure-Coded Storage. Block data + repair symbols as RaptorQ symbol sets. Each block group maintains an ECS repair pool. |
| **BlockBuf** | `Vec<u8>` of exactly `block_size` bytes. Reference-counted in ARC; carries dirty tracking. |
| **FfsError** | Unified error enum (`ffs-error`). Every variant maps to a POSIX errno via `to_errno()`. |
| **MountConfig** | Mount-time configuration: device, mountpoint, read_only, cache_size, mvcc_enabled, repair_enabled, repair_overhead, scrub_interval, fuse_options. |
| **ext4 superblock magic** | `0xEF53`. 16-bit at superblock offset 0x38. Superblock at device byte offset 1024. |
| **extent magic** | `0xF30A`. 16-bit `eh_magic` in `ext4_extent_header`. All extent tree nodes begin with this. |
| **htree** | Hashed B-tree. ext4 indexed directory: `dx_root` (hash algo, depth, `dx_entry` arrays), leaf blocks are linear dir blocks. O(log n) lookup. |
| **mballoc** | Multi-block allocator. Buddy-system bitmaps, best-fit search, locality-group pre-allocation, goal-directed allocation. |
| **Orlov allocator** | Spreads directories across groups; co-locates files with parent directory group. |
| **JBD2** | Journaling Block Device v2. ext4 WAL with descriptor/data/commit/revoke blocks. FrankenFS replays at mount, then switches to native COW. |
| **COW** | Copy-on-Write. Every block write produces a new version; old version remains for active snapshots. |
| **FUSE** | Filesystem in Userspace. `/dev/fuse` kernel module delegates VFS ops to userspace. `fuser` crate for Rust bindings. |
| **CRC32C** | Castagnoli CRC-32 (`0x1EDC6F41`). ext4 metadata checksums + JBD2 journal checksums. Seed = `CRC32C(filesystem_uuid)`. |
| **BLAKE3** | Cryptographic hash. Native-mode block integrity + repair symbol integrity. Keyed mode for authenticated integrity. |
| **xxhash3** | Non-cryptographic 64-bit hash. In-memory hash tables and bloom filters only. NOT for on-disk integrity. |
| **blocking_pool** | Asupersync sync I/O offload facility. Prevents blocking disk I/O from starving cooperative scheduler. |

### 0.4 What "RaptorQ Everywhere" Means

RaptorQ is not optional. It is the **default substrate for block durability**:

1. **Per-block-group repair symbols.** Every block group reserves `ceil(blocks_per_group * repair_ratio)` blocks (default 5%) for systematic RaptorQ parity. Marked allocated in bitmap, excluded from regular allocation.

2. **Automatic corruption detection.** Background scrub reads all blocks, verifies checksums (CRC32C for ext4-compat metadata, BLAKE3 for native data), flags mismatches.

3. **Automatic recovery.** When corrupted count C <= repair budget R: feed K-C good symbols + R repair symbols to RaptorQ decoder, recover C blocks, verify checksums, write back.

4. **Repair symbol refresh.** Block writes mark the group stale. Re-encoded lazily on next scrub, or eagerly on `fsync`.

5. **Scrub is always running.** Region-scoped background task cycling through groups. Respects Cx cancellation and Budget.

A block write that never triggers repair symbol refresh for its group is a spec-conformance bug.

### 0.5 Table of Contents

| Section | Title |
|---------|-------|
| 0 | How to Read This Document |
| 1 | Project Identity |
| 2 | Why Block-Level MVCC |
| 3 | RaptorQ: The Information-Theoretic Foundation |
| 4 | Asupersync Deep Integration |
| 5 | MVCC Formal Model |
| 6 | Buffer Pool: ARC Cache |
| 7 | Checksums and Integrity |
| 8 | Architecture: Crate Map and Dependencies |
| 9 | Trait Hierarchy |
| 10 | On-Disk Format: ext4 Structures |
| 11 | Block Allocation and Extent Trees |
| 12 | Inode and Directory Operations |
| 13 | Journal Layer (JBD2 Replay + Native COW) |
| 14 | FUSE Integration |
| 15 | Exclusions (What We Are NOT Building) |
| 16 | Implementation Phases |
| 17 | Testing Strategy |
| 18 | Performance Model and Mechanical Sympathy |
| 19 | Security and Memory Safety |
| 20 | CLI and TUI |
| 21 | Conformance and Parity |
| 22 | Risk Register and Open Questions |
| 23 | Summary: What Makes FrankenFS Alien |

---

## 1. Project Identity

### 1.1 What It Is

FrankenFS is a **Rust 2024 workspace** (core 19 crates + optional legacy/reference crates) that:

1. **Parses the ext4 and btrfs on-disk formats** safely and completely (within declared scope):
   ext4 superblock, group descriptors, inodes, extent trees, directory entries (linear + htree),
   extended attributes, JBD2 journal structures, block/inode bitmaps; and btrfs superblock,
   node headers, keys/items, and initial tree walking primitives needed for mount-compatible behavior.

2. **Implements a FUSE filesystem mount** for real ext4 and btrfs disk images in Linux userspace. Supports: lookup, getattr, setattr, read, write, readdir, create, mkdir, unlink, rmdir, rename, link, symlink, readlink, statfs, fsync, fallocate, open, release, getxattr, setxattr, listxattr, removexattr (phased by filesystem and feature parity).

3. **Provides MVCC concurrent access** at block granularity with version chains, snapshot isolation, FCW conflict detection, and SSI write-skew detection.

4. **Implements RaptorQ self-healing** with per-block-group fountain-code repair symbols, checksum verification, automatic block recovery, and background scrub.

### 1.2 What It Is NOT

| Non-Goal | Rationale |
|----------|-----------|
| Kernel module | Userspace-only via FUSE. Kernel modules require `unsafe`, GPL, kernel ABI stability. |
| Line-by-line C translation | We extract behavior, then reimplement idiomatically in Rust. No `goto` transliteration. |
| btrfs complete parity on day 1 | FrankenFS targets ext4 and btrfs images, but btrfs support is phased (metadata parse → read-only mount → write-path). Multi-device/RAID profiles and other advanced features are out of scope initially. |
| Distributed filesystem | Single block device. No multi-device, RAID, replication. |
| Compatibility shim pile | No technical debt wrapping. ext4 behavior is re-derived from first principles. |

### 1.3 Two Core Innovations

**Innovation 1: Block-Level MVCC with Version Chains.** Every block has a version chain. Writes create new versions; readers see consistent snapshots. Enables concurrent readers that never block writers, concurrent disjoint-block writers without coordination, zero-cost snapshots, and SSI conflict detection.

```rust
// Core MVCC types (normative, defined in ffs-types / ffs-mvcc)
pub struct TxnId(pub u64);
pub struct CommitSeq(pub u64);
pub struct Snapshot { pub high: CommitSeq }

pub struct BlockVersion {
    pub block: BlockNumber,
    pub commit_seq: CommitSeq,
    pub writer: TxnId,
    pub bytes: Vec<u8>,  // exactly block_size bytes
}
```

**Innovation 2: RaptorQ Self-Healing Per Block Group.** Every block group maintains RaptorQ repair symbols (default 5% overhead). Background scrub detects corruption and triggers automatic recovery. No external backups or RAID required.

### 1.4 External Dependencies (Normative)

| Dependency | Path | Components | Purpose |
|-----------|------|------------|---------|
| **asupersync** | `/dp/asupersync` | Cx, Budget, Region, Lab, RaptorQ codec, blocking_pool | Concurrency, cancellation, deterministic testing, fountain codes |
| **frankentui** | `/dp/frankentui` (`ftui`) | Theme, widgets, event loop | TUI rendering for `ffs-tui` |
| **fuser** | crates.io | `Filesystem` trait, `MountOption`, `Session` | FUSE protocol bindings (planned; introduced in Phase 7) |

**Hard constraints:**

- MUST NOT introduce `tokio`, `async-std`, `smol`, or any general-purpose async runtime. All concurrency flows through `asupersync`.
- Third-party crates with transitive `tokio` dependency MUST NOT be added unless the tokio feature can be disabled.

### 1.5 Workspace Crates

| # | Crate | Role |
|---|-------|------|
| 1 | `ffs-types` | Newtypes (`BlockNumber`, `InodeNumber`, `TxnId`, `CommitSeq`, `Snapshot`), parse helpers, constants |
| 2 | `ffs-error` | `FfsError` enum, `Result<T>` alias, errno mappings |
| 3 | `ffs-ondisk` | ext4 on-disk parsing: superblock, group desc, inodes, extents, dirs, JBD2 |
| 4 | `ffs-block` | `BlockDevice` trait, ARC cache, `BlockBuf`, Cx-aware I/O, dirty tracking |
| 5 | `ffs-journal` | JBD2 replay + native COW journal |
| 6 | `ffs-mvcc` | `MvccStore`, version chains, snapshot visibility, FCW, SSI, GC |
| 7 | `ffs-btree` | Extent B+tree: search, insert, split, merge, walk |
| 8 | `ffs-alloc` | mballoc + Orlov inode allocator |
| 9 | `ffs-inode` | Inode CRUD, permissions, timestamps, cache |
| 10 | `ffs-dir` | Linear scan, htree lookup, `dx_hash`, dir entry CRUD |
| 11 | `ffs-extent` | Logical-to-physical mapping, extent allocation, holes |
| 12 | `ffs-xattr` | Inline + block xattrs, namespace routing |
| 13 | `ffs-fuse` | FUSE adapter scaffolding; `FuseBackend` + mount wiring now, `fuser::Filesystem` integration in Phase 7 |
| 14 | `ffs-repair` | RaptorQ: generate/store repair symbols, scrub, recovery |
| 15 | `ffs-core` | Mount orchestration, superblock validation, config, lifecycle |
| 16 | `ffs` | Public API facade, re-exports |
| 17 | `ffs-cli` | CLI: mount, fsck, info, dump, repair |
| 18 | `ffs-tui` | Live dashboard: cache, MVCC, repair, I/O stats |
| 19 | `ffs-harness` | Conformance tests, proptest, golden fixtures, benchmarks |
| 20 | `ffs-ext4` | *Legacy reference.* ext4 parser for conformance comparison. |
| 21 | `ffs-btrfs` | *Legacy reference.* btrfs parser for concept extraction. |

### 1.6 Constraints

```toml
[workspace.package]
edition = "2024"
rust-version = "1.85"

[workspace.lints.rust]
unsafe_code = "forbid"

[workspace.lints.clippy]
pedantic = { level = "deny", priority = -1 }
nursery  = { level = "deny", priority = -1 }
```

| Constraint | Enforcement | Rationale |
|-----------|-------------|-----------|
| `#![forbid(unsafe_code)]` | Workspace lint + crate-root attribute | Memory safety non-negotiable. Third-party `unsafe` (e.g., `crc32c`) acceptable if audited + safe API. |
| Edition 2024 | `[workspace.package]` | Latest language features. |
| Nightly toolchain | `rust-toolchain.toml`: `channel = "nightly"` | Required for Edition 2024 + dependency features. |
| `rust-version = "1.85"` | `[workspace.package]` | Minimum nightly version. |
| Clippy pedantic+nursery deny | Workspace lints | Idiomatic Rust, catch common bugs. |
| No tokio | Dependency audit | See Section 1.4. |
| `panic = "abort"` in release | `[profile.release]` | No unwinding; smaller binary; no catch_unwind misuse. |

### 1.7 Mechanical Sympathy

| FUSE Characteristic | Impact | Mitigation |
|---------------------|--------|------------|
| **Round-trip overhead (~5-10 us/op)** | Every VFS op crosses kernel/userspace boundary twice | ARC cache critical: hits avoid disk I/O. Batch ops (readdir, readahead) amortize overhead. |
| **No mmap support** | `MAP_SHARED` writes not reflected in FS | Document limitation. Applications MUST use read/write. Fundamental FUSE constraint. |
| **No zero-copy I/O** | Data copied across kernel/userspace | Minimize userspace copies: `BlockBuf` refcounting, vectored I/O where supported. |
| **Default single-thread dispatch** | `fuser` single-thread by default | MUST use multi-threaded dispatch. All `Filesystem` state MUST be `Send + Sync`. `parking_lot` locks for concurrency. |
| **Context switching cost** | >= 2 context switches per op | Never block FUSE dispatch thread on raw I/O. Offload to `asupersync::blocking_pool`. |

---

## 2. Why Block-Level MVCC

### 2.1 The Problem: JBD2 Serializes All Writers

ext4 uses JBD2 for crash consistency via a write-ahead log with a **single global transaction** serializing all metadata writers:

```
Writer A ──┐
Writer B ──┼──> Global Transaction T ──> Journal (WAL)
Writer C ──┘       (serialized)
```

Consequences:

1. **Metadata serialization.** All metadata mods (inode updates, dir entries, extent changes, bitmaps) funnel through one JBD2 handle. Unrelated file modifications batch into the same transaction.

2. **Commit latency coupling.** `fsync` on file A forces a JBD2 commit including metadata from writers B and C.

3. **Writeback mode does not help.** `data=writeback` lets data bypass the journal but metadata still serializes through JBD2. Metadata dominates the journal for typical workloads.

4. **Journal contention.** `j_state_lock`, `j_list_lock`, `j_checkpoint_lock` serialize journal access. Significant contention under concurrent metadata writes.

5. **No snapshot isolation.** Readers overlapping with writers may see partial state. ext4 VFS locking prevents most observable inconsistencies, but the fundamental guarantee is ordering, not isolation.

### 2.2 The Solution: Version Chains Per Block

FrankenFS replaces JBD2's global transaction with per-block version chains:

```
Block 100: V1(cs=1) -> V2(cs=3) -> V3(cs=7)
Block 101: V1(cs=1) -> V2(cs=5)
Block 102: V1(cs=2) -> V2(cs=4) -> V3(cs=6)

Writer A (snapshot cs=5):
  writes Block 100 -> V4(uncommitted) -> commit -> cs=8

Reader B (snapshot cs=5):
  Block 100 -> V2(cs=3)   [newest with cs <= 5]
  Block 101 -> V2(cs=5)   [exact match]
  Block 102 -> V2(cs=4)   [V3 cs=6 > 5, skip]
```

Each block has an ordered sequence of `BlockVersion` entries tagged with `CommitSeq` and `TxnId`. The version chain is the fundamental concurrency data structure.

### 2.3 How It Differs From Database MVCC

| Dimension | Database MVCC (PostgreSQL) | FrankenFS Block MVCC |
|-----------|--------------------------|---------------------|
| **Unit** | Row / tuple | Block (4096 bytes) |
| **Chain structure** | Per-row `xmin`/`xmax` or undo log | `BTreeMap<BlockNumber, Vec<BlockVersion>>` |
| **Version size** | Variable (row payload) | Fixed (`block_size` bytes) |
| **Visibility** | `xmin <= snapshot` and `xmax > snapshot` | Newest `commit_seq <= snapshot.high` |
| **Conflict granularity** | Row or predicate | Block: `committed.commit_seq > writer.snapshot.high` |
| **GC** | VACUUM / undo purge | `prune_versions_older_than(watermark)`, retain >= 1 per block |
| **Index interaction** | HOT, visibility map | None; indices above MVCC see versioned blocks |
| **Snapshot cost** | Cheap (capture xid) | Free (read `CommitSeq`) |
| **Write amplification** | Row-level | Block-level (full block per version). Mitigated by COW + GC. |

Block granularity is deliberate: filesystem metadata (extent nodes, directory blocks, inode table blocks) is not decomposable into independent rows. Versioning at block level captures modifications atomically without structure-aware diff/merge.

### 2.4 The FCW Conflict Rule

```rust
/// FCW check (normative, ffs-mvcc)
/// For each block B in write_set:
///   if store.latest_commit_seq(B) > txn.snapshot.high:
///       return Err(CommitError::Conflict { block: B, ... })
/// No conflicts: assign CommitSeq, publish all versions atomically.
/// Any conflict: entire transaction fails. No partial commits.
```

**Semantics:**

1. T begins with snapshot S.
2. T reads/writes blocks. Writes buffered in private write set.
3. At commit: for each write-set block B, check if any commit since S touched B.
4. Conflict -> `CommitError::Conflict`. Caller SHOULD retry with fresh snapshot.
5. No conflict -> new `CommitSeq` assigned, buffered writes become committed.

FCW validation + `CommitSeq` assignment MUST be atomic. `MvccStore` is the serialization point for commits only, not reads.

### 2.5 SSI: Detecting Write-Skew

FCW detects only write-write conflicts. Write skew (two transactions read overlapping blocks, write disjoint blocks) requires SSI:

```
T1: reads A, writes B    T2: reads B, writes A
Both commit under pure SI -> non-serializable.
SSI detects: T1 -rw-> T2 -rw-> T1 (cycle). One MUST abort.
```

**SSI requirements:**

1. **Read tracking.** `read_set: BTreeMap<BlockNumber, CommitSeq>` per transaction.
2. **Write tracking.** `write_set: BTreeSet<BlockNumber>` per transaction.
3. **Commit-time check.** Beyond FCW, detect rw-antidependency cycles:
   - For read-set block B: did any concurrent committed T' write B?
   - For write-set block B: did any concurrent T' (with earlier snapshot) read B?
   - If consecutive rw-antidependencies form a "dangerous structure," one MUST abort.
4. **Abort policy.** Abort the transaction with fewest writes. Ties: younger aborts.

### 2.6 Benefits

| Benefit | Detail |
|---------|--------|
| **Reads never block writes** | Readers hold a `CommitSeq` snapshot, acquire no locks. |
| **Disjoint writes proceed without coordination** | No shared locks or journal handles. Serialized only at `CommitSeq` assignment. |
| **Snapshots are free** | Single read of `current_commit_seq`. No copies, locks, or refcounts. |
| **Deterministic conflict resolution** | FCW + SSI decisions are replayable under `Lab` runtime. No probabilistic retry. |
| **Clean crash recovery** | Version chain contains last committed state. No replay needed for native writes. Uncommitted versions simply absent. |
| **GC independent of foreground** | Background Region task. Driven by oldest active snapshot watermark. Retains >= 1 version per block. |

### 2.7 JBD2 Compatibility

FrankenFS MUST support mounting ext4 images with unclean journals:

1. **Mount-time replay.** Read JBD2 superblock. If `s_start != 0` (dirty journal), three-pass replay:
   - **SCAN:** Walk from `s_start` at `s_sequence`, collect committed txns, build revoke table.
   - **REVOKE:** Mark blocks in revoke records.
   - **REPLAY:** Write non-revoked blocks to filesystem locations.
   - Clear journal (`s_start = 0`).

2. **Switch to native COW.** After replay, all new writes use MVCC/COW. JBD2 area not reused.

3. **Clean fast path.** `s_start == 0` -> skip replay, initialize native mode directly.

4. **Read-only fallback.** Unrecoverable journal error (checksum mismatch, unsupported feature) -> mount read-only + report error. MUST NOT silently skip.

```rust
// JBD2 block types (normative, ffs-journal)
#[repr(u32)]
pub enum Jbd2BlockType {
    DescriptorBlock = 1,
    CommitBlock     = 2,
    SuperblockV1    = 3,
    SuperblockV2    = 4,
    RevokeBlock     = 5,
}

pub enum JournalReplayPhase { Scan, Revoke, Replay, Done }
```

### 2.8 Version Chain Lifecycle

```
1. begin:     snapshot = current_commit_seq; read_set = {}; write_set = {}
2. read(B):   version = read_visible(B, snapshot); read_set[B] = version.commit_seq
3. write(B):  write_set[B] = new_bytes  (buffered, not in store)
4. commit:
   Phase 1 - FCW: for B in write_set { assert latest_commit_seq(B) <= snapshot.high }
   Phase 2 - SSI: check rw-antidependency cycles (see Section 5)
   Phase 3 - Publish: cs = next_commit_seq(); append versions with cs
5. GC (background):
   watermark = oldest_active_snapshot.high
   for each block: prune versions with commit_seq < watermark (keep >= 1)
```

### 2.9 Write Amplification and Mitigation

Block-level MVCC versions entire blocks per write (same amplification as JBD2 journaling and btrfs COW).

| Strategy | Priority | Description |
|----------|----------|-------------|
| **COW allocation** | MUST | New versions at new locations. Old version remains for active snapshots. |
| **GC space reclamation** | MUST | Freed blocks returned to allocator when no snapshot references them. |
| **Bounded version chains** | SHOULD | Cap at `max_versions_per_block` (default 64). Spill or aggressive GC beyond cap. |
| **Lazy repair refresh** | SHOULD | Mark groups stale on write; re-encode on next scrub. Amortizes RaptorQ cost. |

---
## 3. RaptorQ Foundation

### 3.1 Overview and Standards Basis

FrankenFS employs RaptorQ forward error correction as defined in **RFC 6330** to provide self-healing durability at the block group level. RaptorQ is a fountain code: given K source symbols, the encoder produces an unbounded stream of encoding symbols. A decoder MUST recover the original K source symbols from any set of K' received symbols, where K' is approximately K (typically K' <= K + 2 with high probability).

### 3.2 Galois Field GF(256) Arithmetic

All RaptorQ operations are performed over **GF(2^8)** using the irreducible polynomial `p(x) = x^8 + x^4 + x^3 + x^2 + 1` (reduction mask `0x1D`). The implementation in `asupersync::raptorq::gf256` MUST satisfy:

1. **Addition**: XOR of byte representations (`a + b = a ^ b`).
2. **Multiplication**: Precomputed log/exp tables with primitive element g = 0x02. The EXP table is extended to 512 entries for mod-free lookup.
3. **Determinism**: All GF(256) operations MUST be deterministic and platform-independent. Tables MUST be `const`-evaluated.

The `ffs-repair` crate MUST NOT reimplement GF(256) arithmetic; it MUST delegate to `asupersync::raptorq::gf256`.

### 3.3 Systematic Encoding Model

RaptorQ uses a **systematic** encoding scheme. For K source symbols:

1. A **precode matrix A** is constructed from LDPC, HDPC, and LT constraints.
2. The encoder solves for **L = K + S + H intermediate symbols** (S = LDPC count, H = HDPC count).
3. Source symbols pass through unchanged (the systematic property).
4. Repair symbols are generated by LT-encoding intermediate symbols using ESIs beyond the source range.

Key derived parameters (RFC 6330 Section 5.3):

```rust
pub struct SystematicParams {
    pub k: usize,           // source symbols
    pub s: usize,           // LDPC symbols
    pub h: usize,           // HDPC symbols
    pub l: usize,           // L = K + S + H total intermediate
    pub w: usize,           // W = K + S (LT symbols)
    pub p: usize,           // P = H (PI symbols)
    pub b: usize,           // B = K (non-LDPC LT symbols)
    pub symbol_size: usize,
}
```

`ffs-repair` MUST use `asupersync::raptorq::systematic` for parameter derivation. S and H values MUST NOT be hard-coded; they MUST be computed from K via RFC 6330 lookup tables.

### 3.4 Object Transmission Information (OTI)

The decoder requires OTI metadata to reconstruct encoding parameters:

| Field | Type | Meaning |
|-------|------|---------|
| F | `u64` | Transfer length (total source data bytes) |
| Al | `u8` | Symbol alignment (MUST be 4 for FrankenFS) |
| T | `u16` | Symbol size in bytes |
| Z | `u32` | Number of source blocks |
| N | `u16` | Number of sub-blocks |

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairOti {
    pub transfer_length: u64,
    pub alignment: u8,
    pub symbol_size: u16,
    pub source_block_count: u32,
    pub sub_block_count: u16,
}
```

OTI MUST be persisted in the group descriptor extension (Section 3.7). Because decoding is impossible without OTI, it MUST be redundantly stored in both the group descriptor and the first repair block's header.

### 3.5 Integration Points

#### 3.5.1 `ffs-repair` -- Primary Home

`ffs-repair` owns all RaptorQ logic within FrankenFS and MUST provide:

```rust
pub trait RepairManager: Send + Sync {
    fn generate_symbols(&self, cx: &Cx, group: GroupNumber) -> Result<RepairSymbolSet>;
    fn recover_block(&self, cx: &Cx, block: BlockNumber) -> Result<RecoveryResult>;
    fn scrub(&self, cx: &Cx, progress: &dyn ScrubProgress) -> Result<ScrubReport>;
    fn refresh_symbols(&self, cx: &Cx, block: BlockNumber) -> Result<()>;
}
```

Encoding and decoding delegate to `asupersync::raptorq::{RaptorQSender, RaptorQReceiver}`. All codec entry points MUST call `cx.checkpoint()?` before initiating work.

#### 3.5.2 `ffs-block` -- Checksum Verification

`ffs-block` MUST verify block integrity on every read and notify the repair layer on writes:

| Mode | Checksum | Storage |
|------|----------|---------|
| Compatibility (ext4) | CRC32C | ext4 `metadata_csum` fields |
| Native | BLAKE3 (256-bit) | Dedicated checksum block per block group |

```rust
pub enum ChecksumResult {
    Valid,
    Mismatch { block: BlockNumber, expected: [u8; 32], actual: [u8; 32] },
    Unavailable,
}

pub trait BlockEventSink: Send + Sync {
    fn on_checksum_mismatch(&self, cx: &Cx, block: BlockNumber, result: &ChecksumResult);
    fn on_block_dirty(&self, cx: &Cx, block: BlockNumber);
}
```

On checksum mismatch during read, `ffs-block` MUST: (1) invoke `BlockEventSink::on_checksum_mismatch()`, (2) attempt transparent recovery via `RepairManager::recover_block()` if enabled, (3) return corrected data and rewrite the block on success, (4) return `FfsError::Corruption` on failure.

#### 3.5.3 `ffs-core` -- Scrub Scheduling and Policy

`ffs-core` manages the scrub lifecycle and repair policy:

```rust
pub struct ScrubConfig {
    pub enabled: bool,
    pub interval: Duration,
    pub bandwidth_limit: Option<u64>, // bytes/sec; None = unlimited
    pub priority: u8,
}

pub struct RepairPolicy {
    pub overhead_ratio: f64,             // range [1.01, 1.10], default 1.05
    pub eager_refresh: bool,             // refresh symbols on every write?
    pub autopilot: Option<DurabilityAutopilot>,
}
```

The scrub process MUST run inside an `asupersync::Region` owned by the mount lifecycle Region and MUST respect Cx cancellation.

### 3.6 RaptorQ Permeation Map

| Crate | Role | Interface |
|-------|------|-----------|
| `ffs-repair` | Primary: encode, store, decode, scrub | `asupersync::raptorq::{RaptorQSender, RaptorQReceiver, SystematicParams}` |
| `ffs-block` | Consumer: checksum triggers repair; dirty notifications | `ffs-block::BlockEventSink` (implemented by `ffs-repair`) |
| `ffs-core` | Orchestrator: scrub scheduling, policy, DurabilityAutopilot | `ffs-repair::RepairManager`, `asupersync::RaptorQConfig` |
| `ffs-harness` | Testing: inject corruption, verify recovery | `ffs-repair::RepairManager` via `ffs` facade |
| `ffs-tui` | Display: scrub progress, repair stats | `ffs-repair::ScrubReport` (read-only) |
| `ffs-cli` | Commands: `ffs repair`, `ffs scrub` | `ffs-repair::RepairManager` via `ffs` facade |

All other crates MUST NOT depend on `ffs-repair` or import RaptorQ types.

### 3.7 Repair Symbol Storage

#### 3.7.1 On-Disk Layout

Repair symbols occupy **dedicated blocks at the end of each block group**:

```
repair_block_count = ceil(data_block_count * (overhead_ratio - 1.0))
```

For 5% overhead on a 32,768-block group (128 MiB at 4K): `ceil(32768 * 0.05) = 1639 blocks (~6.4 MiB)`. These blocks MUST be reserved in the block bitmap and MUST NOT be allocatable for file data.

#### 3.7.2 Group Descriptor Extension

```rust
#[repr(C)]
pub struct RepairGroupDescExt {
    pub magic: u32,                   // 0x52515246 ("RQRF")
    pub oti_transfer_length: u64,
    pub oti_alignment: u8,
    pub oti_symbol_size: u16,
    pub oti_source_block_count: u32,
    pub oti_sub_block_count: u16,
    pub repair_start_block: u32,      // first repair block in this group
    pub repair_block_count: u32,
    pub repair_generation: u64,       // incremented on full symbol refresh
    pub ext_checksum: u32,            // CRC32C of preceding fields
}
```

If `repair_generation` does not match the stored repair symbols, the set is stale and MUST be regenerated before use.

#### 3.7.3 Repair Block Format

```rust
#[repr(C)]
pub struct RepairBlockHeader {
    pub magic: u32,            // 0x52515342 ("RQSB")
    pub first_esi: u32,        // first Encoding Symbol Identifier
    pub symbol_count: u16,
    pub symbol_size: u16,
    pub block_group: u32,
    pub generation: u64,       // must match group descriptor
    pub checksum: u32,         // CRC32C of header + payload
}
```

### 3.8 Overhead Budget

The overhead ratio MUST be configurable at mount time in the range **[1.01, 1.10]**. Default: **1.05** (5%).

| Overhead | Extra per 128 MiB Group | Recovery Capability |
|----------|------------------------|---------------------|
| 1% | ~1.3 MiB | Marginal; single-block with high probability |
| 5% (default) | ~6.4 MiB | Good; up to ~5% simultaneous corruption per group |
| 10% | ~12.8 MiB | High; tolerates ~10% simultaneous corruption |

When `RepairPolicy::autopilot` is `Some`, the autopilot's `choose_overhead()` SHOULD override the static ratio at each scrub cycle.

### 3.9 Recovery Semantics

#### 3.9.1 Single Block Corruption

The repair layer loads K-1 intact source symbols plus repair symbols. Since K-1 + repair_count >= K', single-block recovery MUST succeed with probability >= 0.99 for overhead >= 1.01. On success, the corrected block MUST be written back and repair symbols refreshed.

#### 3.9.2 Multi-Block Corruption

For N corrupted blocks: recovery is possible iff available symbols (K-N intact + repair) >= K'. For N <= `repair_block_count`, recovery SHOULD succeed. For N > `repair_block_count`, recovery MUST fail gracefully with per-block reporting.

#### 3.9.3 Failure Reporting

```rust
pub enum RecoveryResult {
    Recovered { block: BlockNumber, data: BlockBuf },
    Unrecoverable {
        block: BlockNumber,
        missing_blocks: Vec<BlockNumber>,
        available_symbols: usize,
        required_symbols: usize,
    },
}

pub struct ScrubReport {
    pub groups_scanned: u32,
    pub groups_clean: u32,
    pub groups_repaired: u32,
    pub groups_degraded: u32,
    pub group_details: Vec<ScrubGroupDetail>,
    pub duration: Duration,
    pub blocks_read: u64,
    pub blocks_corrected: u64,
}
```

### 3.10 Symbol Refresh Protocol

Written blocks make repair symbols **stale**. Two modes:

1. **Eager** (`eager_refresh = true`): Re-encode immediately after write commit. Continuous consistency but higher write amplification.
2. **Lazy** (`eager_refresh = false`): Mark group dirty; refresh during next scrub. Between write and refresh, the repair set MUST NOT be used for recovery of affected source block partitions.

The `repair_generation` counter MUST be incremented only after a **full** symbol refresh of the group completes. Partial refreshes MUST NOT increment the counter.

### 3.11 Durability Autopilot (Bayesian Expected-Loss)

When `RepairPolicy::autopilot` is `Some`, `ffs-core` SHOULD choose `overhead_ratio` at the start of each scrub cycle (and MAY adjust it mid-scrub if evidence shifts materially).

The autopilot exists to prevent two failure modes:

1. **Under-redundancy:** too little repair overhead leads to unrecoverable multi-block corruption.
2. **Over-redundancy:** too much repair overhead wastes space and increases write amplification.

#### 3.11.1 Posterior Model

The autopilot maintains a conjugate **Beta posterior** over per-block corruption probability `p` for a scrub interval:

- Prior: `p ~ Beta(alpha=1, beta=1)` (uniform).
- Observation: a scrub reports `(scanned_blocks, corrupted_blocks)`.
- Update: `alpha += corrupted_blocks`, `beta += (scanned_blocks - corrupted_blocks)`.

Posterior mean and variance:

```
E[p] = alpha / (alpha + beta)
Var[p] = alpha*beta / ((alpha+beta)^2 * (alpha+beta+1))
```

The autopilot MUST use a conservative upper estimate:

```
p_hi = clamp(E[p] + z * sqrt(Var[p]), 0, 1)
```

Default: `z = 3.0` (intentionally conservative).

#### 3.11.2 Unrecoverable Tail-Risk Bound

Let:

- `r` be a candidate overhead ratio in `[1.01, 1.10]`
- `rho = r - 1.0` be the repair budget fraction (repair blocks / source blocks)
- `K` be the number of source blocks per group (use filesystem geometry when available; default 32,768)

Model the next interval's corruptions as `N ~ Binomial(K, p)`. Recovery is feasible when `N <= rho*K`.

The autopilot MUST use a conservative Chernoff-style bound on unrecoverable risk:

1. If `rho <= p_hi`, then `risk_bound = 1.0` (we cannot even cover the conservative rate).
2. Else:

```
risk_bound = exp(-K * D(rho || p_hi))
D(q||p) = q*ln(q/p) + (1-q)*ln((1-q)/(1-p))
```

This is a bound, not an exact probability; it is chosen for speed, monotonicity, and explainability.

#### 3.11.3 Expected-Loss Selection

Given candidate ratios `{r_i}`, the autopilot chooses:

```
L(r) = redundancy_cost * (r - 1) + corruption_cost * risk_bound(r)
r* = argmin_r L(r)
```

`redundancy_cost` and `corruption_cost` are mount-configurable loss scalars with conservative defaults (high cost for unrecoverable outcomes).

#### 3.11.4 Explainability Contract

The autopilot MUST produce an evidence-carrying decision record:

```rust
pub struct RedundancyDecision {
    pub repair_overhead: f64,
    pub expected_loss: f64,
    pub posterior_mean_corruption_rate: f64,
    pub posterior_hi_corruption_rate: f64,
    pub unrecoverable_risk_bound: f64,
    pub redundancy_loss: f64,
    pub corruption_loss: f64,
}
```

---

## 4. Asupersync Deep Integration

### 4.1 Cx (Capability Context)

#### 4.1.1 Contract

`asupersync::Cx` is the capability token threaded through ALL effectful operations in FrankenFS. Every operation that performs I/O, may block, or runs a potentially long computation MUST accept `&Cx` and MUST periodically checkpoint for cancellation.

```rust
pub struct Cx<Caps = cap::All> {
    inner: Arc<RwLock<CxInner>>,
    blocking_pool: Option<BlockingPoolHandle>,
    // ... I/O driver, timer driver, entropy, tracing handles
}
```

`Cx` is `Send + Sync` and cheaply clonable. Clones share state; cancellation signals and budget updates are visible to all clones.

#### 4.1.2 Checkpoint Protocol

`cx.checkpoint()` performs three actions atomically: (1) records a progress checkpoint, (2) checks cancellation flag, (3) checks budget exhaustion. Returns `Err(asupersync::Error::Cancelled { reason })` if any condition triggers.

```rust
impl Cx {
    pub fn checkpoint(&self) -> Result<(), asupersync::Error>;
    pub fn checkpoint_with(&self, msg: impl Into<String>) -> Result<(), asupersync::Error>;
    pub fn is_cancel_requested(&self) -> bool;
    pub fn budget(&self) -> Budget;
}
```

**Checkpoint placement rules:**

| Context | Frequency | Rationale |
|---------|-----------|-----------|
| Block group iteration (scrub/repair) | Every block | 32K blocks per group |
| B+tree traversal | Every level descent | 3-5 levels typical |
| Directory hash-tree walk | Every entry batch | Directories may be huge |
| MVCC version chain walk | Every version | Long chains under write load |
| Block I/O | Before each syscall | May block on degraded storage |
| Journal replay | Every transaction record | Thousands of records possible |

#### 4.1.3 Polling vs Checkpoint

SHOULD prefer `cx.checkpoint()?` over `cx.is_cancel_requested()`. The former checks all cancellation conditions including budget exhaustion and propagates errors via `?`. The latter checks only the explicit cancel flag; use it only when observing cancellation without yielding (e.g., hot inner loops that checkpoint at the outer level).

#### 4.1.4 Cx Threading Rules

Every public I/O or iteration function in `ffs-block`, `ffs-repair`, `ffs-mvcc`, `ffs-journal`, `ffs-core`, and `ffs-fuse` MUST accept `&Cx` as its first parameter after `&self`/`&mut self`. Example:

```rust
// ffs-block
impl CachedBlockDevice {
    pub fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        cx.checkpoint()?;
        // cache lookup, fallback to BlockDevice::read_block(cx, block)
    }
}

// ffs-repair
impl DefaultRepairManager {
    pub fn scrub(&self, cx: &Cx, progress: &dyn ScrubProgress) -> Result<ScrubReport> {
        for group in 0..self.group_count {
            cx.checkpoint_with(format!("scrub group {group}/{}", self.group_count))?;
            self.scrub_group(cx, GroupNumber(group))?;
        }
        // ...
    }
}
```

Pure parsing functions in `ffs-ondisk` and `ffs-types` that operate on in-memory slices SHOULD NOT require `&Cx`.

### 4.2 Budget

#### 4.2.1 Structure

```rust
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    pub deadline: Option<Time>,     // absolute deadline
    pub poll_quota: u32,            // max poll operations
    pub cost_quota: Option<u64>,    // abstract cost units
    pub priority: u8,               // 0=lowest, 255=highest
}
```

| Constant | Deadline | Poll | Cost | Priority | Purpose |
|----------|----------|------|------|----------|---------|
| `INFINITE` | None | `u32::MAX` | None | 128 | Default; no constraints |
| `ZERO` | `Time::ZERO` | 0 | `Some(0)` | 0 | Immediately exhausted |
| `MINIMAL` | None | 100 | None | 128 | Cleanup/finalizer phase |

#### 4.2.2 Budget Combining (Product Semiring)

Nested scopes combine budgets via the **meet** operation:

| Field | Rule | Semantic |
|-------|------|----------|
| `deadline` | `min(a, b)` | Tighter timeout wins |
| `poll_quota` | `min(a, b)` | Tighter quota wins |
| `cost_quota` | `min(a, b)`, None = unlimited | Tighter quota wins |
| `priority` | `max(a, b)` | Higher priority wins |

This forms a bounded semilattice. FrankenFS MUST NOT manually combine budgets; the runtime propagates budgets automatically through the Region tree.

#### 4.2.3 Recommended Task Budgets

| Task | Deadline | Priority |
|------|----------|----------|
| FUSE request handler | 30s (configurable) | 200 (high) |
| Background scrub | None | 50 (low) |
| GC (version garbage collection) | None | 80 (medium-low) |
| Journal flush | 5s (configurable) | 180 (high) |
| Repair symbol refresh (eager) | 10s | 150 (medium-high) |

### 4.3 Region (Structured Concurrency)

#### 4.3.1 Overview

`asupersync::Region` enforces structured concurrency: a Region owns tasks and child Regions in a tree. **Region close implies quiescence**: all children are cancelled, drained, and finalized before the Region itself completes.

Lifecycle state machine:

```
Open --> Closing --> Draining --> Finalizing --> Closed
```

| State | Can Spawn? | Description |
|-------|------------|-------------|
| Open | Yes | Accepting work |
| Closing | No | Body done; initiating shutdown |
| Draining | No | Cancel issued; waiting for children |
| Finalizing | No | Running finalizers (LIFO) |
| Closed | No | Terminal; outcome available |

#### 4.3.2 FrankenFS Region Tree

```
MountRegion (root)
+-- FuseRegion
|   +-- RequestHandler[0..N] (per-request tasks)
+-- ScrubRegion
|   +-- ScrubTask
+-- GcRegion
|   +-- GcTask
+-- FlushRegion
|   +-- FlushTask
+-- RepairRefreshRegion (if eager_refresh)
    +-- RefreshTask
```

**Unmount sequence**: MountRegion closes -> all child Regions receive cancellation -> each transitions Closing -> Draining -> Finalizing -> Closed. Finalizer order:

1. **FuseRegion**: drain in-flight requests (`Budget::MINIMAL` each).
2. **FlushRegion**: final dirty page flush.
3. **ScrubRegion**: checkpoint scrub progress for resume.
4. **GcRegion**: commit pending GC.
5. **MountRegion** (self): superblock update, device sync.

This guarantees no background work outlives the mount, no orphan tasks leak, and finalizers run deterministically.

#### 4.3.3 Transaction Scope

Individual transactions MAY use short-lived Regions:

```rust
impl FrankenFsEngine {
    pub fn execute_write(&self, cx: &Cx, ino: InodeNumber, offset: u64, data: &[u8]) -> Result<u32> {
        let tx = self.mvcc.begin_tx(cx)?;
        // ... writes ...
        match self.mvcc.commit(cx, tx) {
            Ok(_) => {
                for block in dirty_blocks { self.repair.on_block_dirty(cx, block); }
                Ok(bytes_written)
            }
            Err(CommitError::Conflict { .. }) => {
                self.mvcc.abort(cx, tx)?;
                Err(FfsError::MvccConflict { .. })
            }
        }
    }
}
```

### 4.4 Lab (Deterministic Runtime for Testing)

#### 4.4.1 Overview

`asupersync::Lab` replaces the production runtime with deterministic alternatives:

| Capability | Production | Lab |
|-----------|-----------|-----|
| Time | `WallClock` | `VirtualClock` (explicit advancement) |
| Scheduling | OS threads | Seed-driven deterministic scheduler |
| I/O | Real disk | Injected stubs with configurable failure |
| Entropy | `OsEntropy` | `DetEntropy` / `DetRng` |

FrankenFS MUST use Lab for testing all concurrency-critical paths.

#### 4.4.2 MVCC Concurrency Testing

```rust
#[test]
fn mvcc_fcw_deterministic() {
    let lab = Lab::builder().seed(42).build();
    lab.run(|cx| async move {
        let store = MvccStore::new();
        let block = BlockNumber(100);
        let tx1 = store.begin_tx(&cx)?;
        let tx2 = store.begin_tx(&cx)?;
        store.write_versioned(&cx, &tx1, block, b"A")?;
        store.write_versioned(&cx, &tx2, block, b"B")?;
        assert!(store.commit(&cx, tx1).is_ok());
        assert!(matches!(store.commit(&cx, tx2), Err(CommitError::Conflict { .. })));
        Ok(())
    });
}
```

Varying the seed explores different scheduling orders; conflict detection MUST be invariant.

#### 4.4.3 Disk Failure Simulation

Lab chaos injection (`asupersync::lab::chaos`) MUST be used to test repair:

```rust
#[test]
fn repair_single_block() {
    let lab = Lab::builder().seed(123).build();
    lab.run(|cx| async move {
        let engine = setup_test_engine(&cx, RepairPolicy { overhead_ratio: 1.05, .. })?;
        engine.write_block(&cx, BlockNumber(42), b"known")?;
        engine.repair.generate_symbols(&cx, GroupNumber(0))?;
        engine.raw_corrupt_block(BlockNumber(42), b"bad")?;
        let result = engine.repair.recover_block(&cx, BlockNumber(42))?;
        assert!(matches!(result, RecoveryResult::Recovered { .. }));
        Ok(())
    });
}
```

#### 4.4.4 Time Control

Virtual clock tests deadline behavior without wall-clock waits:

```rust
#[test]
fn budget_deadline_fires() {
    let lab = Lab::builder().seed(0).build();
    lab.run(|cx| async move {
        let cx = cx.with_budget(Budget::new().with_deadline(Time::from_secs(5)));
        lab.advance_time(Duration::from_secs(10));
        assert!(cx.checkpoint().is_err());
        Ok(())
    });
}
```

### 4.5 RaptorQ Codec

#### 4.5.1 Delegation Model

`ffs-repair` MUST NOT implement RaptorQ encoding/decoding. All codec work delegates to `asupersync::raptorq`:

| Operation | asupersync API | FrankenFS Caller |
|-----------|---------------|-----------------|
| Encode | `RaptorQSender::builder().build()` | `ffs-repair::generate_symbols()` |
| Decode | `RaptorQReceiver::builder().oti(...).build()` | `ffs-repair::recover_block()` |
| GF(256) | `asupersync::raptorq::gf256` | Transitive |
| Parameters | `SystematicParams::from_k()` | `ffs-repair` (symbol count derivation) |

#### 4.5.2 Configuration Mapping

```rust
impl RedundancyDecision {
    pub fn to_raptorq_config(self, block_size: u32) -> RaptorQConfig {
        let mut cfg = RaptorQConfig::default();
        cfg.encoding.repair_overhead = self.repair_overhead;
        cfg.encoding.max_block_size = usize::try_from(block_size).unwrap_or(4096);
        cfg.encoding.symbol_size = u16::try_from(block_size.clamp(64, 1024)).unwrap_or(256);
        cfg
    }
}
```

| FrankenFS Config | asupersync Target | Default |
|-----------------|-------------------|---------|
| `overhead_ratio` | `EncodingConfig::repair_overhead` | 1.05 |
| Block size (superblock) | `EncodingConfig::max_block_size` | 4096 |
| Symbol size | `EncodingConfig::symbol_size` | 256 |

#### 4.5.3 Symbol Size Selection

Symbol size T MUST satisfy: (1) `block_size % T == 0`, (2) T in [64, 1024], (3) T is a multiple of Al=4. For 4096-byte blocks, valid sizes: 64, 128, 256, 512, 1024. Default SHOULD be **256** bytes (K=16 per block).

### 4.6 Blocking Pool

#### 4.6.1 Rationale

The asupersync cooperative scheduler MUST NOT be blocked by synchronous disk I/O. All `pread`/`pwrite` syscalls MUST be offloaded to the blocking pool.

#### 4.6.2 Integration

```rust
pub struct FileBlockDevice {
    file: Arc<std::fs::File>,
    block_size: u32,
}

impl BlockDevice for FileBlockDevice {
    fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        cx.checkpoint()?;
        let file = Arc::clone(&self.file);
        let bs = self.block_size;
        let off = u64::from(block.0) * u64::from(bs);
        let data = cx.spawn_blocking(move |_| {
            let mut buf = vec![0u8; bs as usize];
            use std::os::unix::fs::FileExt;
            file.read_exact_at(&mut buf, off)?;
            Ok::<_, std::io::Error>(buf)
        }).await??;
        Ok(BlockBuf::from(data))
    }

    fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
        cx.checkpoint()?;
        let file = Arc::clone(&self.file);
        let off = u64::from(block.0) * u64::from(self.block_size);
        let data = data.to_vec();
        cx.spawn_blocking(move |_| {
            use std::os::unix::fs::FileExt;
            file.write_all_at(&data, off)
        }).await??;
        Ok(())
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        cx.checkpoint()?;
        let file = Arc::clone(&self.file);
        cx.spawn_blocking(move |_| file.sync_all()).await??;
        Ok(())
    }
}
```

#### 4.6.3 Pool Sizing and Cancellation

Pool size is controlled by asupersync runtime config (default: `num_cpus * 4`). FrankenFS SHOULD NOT override this.

**Cancellation safety**: blocking operations continue to completion on pool threads (soft cancellation). After `spawn_blocking().await`, code MUST call `cx.checkpoint()?` before using the result, as cancellation may have been requested during the I/O.

### 4.7 Forbidden Patterns

The following MUST NOT appear in any FrankenFS crate:

1. **Detached tasks**: All tasks MUST be spawned within a Region. No fire-and-forget.
2. **Direct `std::thread::spawn` for I/O**: Use the blocking pool. Direct threads bypass budget and cancellation.
3. **`tokio::spawn` / `tokio::runtime`**: FrankenFS MUST NOT depend on tokio. Use asupersync runtime.
4. **Unbounded loops without checkpoint**: Any loop over disk-derived data MUST include `cx.checkpoint()`.
5. **Swallowed checkpoint errors**: `cx.checkpoint()` errors MUST be propagated via `?` or explicit match.
6. **`cx.checkpoint().ok()`**: MUST NOT appear except in terminal finalizer cleanup paths.

---
## 5. MVCC Formal Model

This spec is split into phases:

- **Phase A (implemented)**: snapshot visibility + FCW (first-committer-wins) write-write conflict detection. This is **normative** and MUST match `crates/ffs-mvcc/src/lib.rs`.
- **Phase B (planned)**: SSI (rw-antidependency tracking), read-set bookkeeping, active transaction registry, and GC watermarking. This is **informative** until implemented (APIs MAY change).

Implementation home: `ffs-mvcc` crate; shared types: `ffs-types`.

---

### 5.0 Phase Plan (FCW -> SSI)

**Phase A (implemented now):**

- Snapshot isolation at block granularity via version chains and `Snapshot { high: CommitSeq }`.
- FCW (first-committer-wins) write-write conflict detection at commit time.
- No read-set tracking (so no SSI write-skew detection yet).
- Aborting is implicit: drop the `Transaction` without committing.

**Phase B (planned):**

- Add read-set bookkeeping and rw-antidependency tracking for SSI.
- Add an explicit `abort(tx)` API (needed once there is active-tx bookkeeping).
- Add GC watermark computation from active snapshots (safe version reclamation).
- Potentially evolve `ffs-mvcc` toward the `MvccBlockManager` trait in `PROPOSED_ARCHITECTURE.md` (which takes `&Cx`).

### 5.0.1 Phase A Public API (ffs-mvcc)

```rust
// Implemented in `crates/ffs-mvcc/src/lib.rs` (Phase A).

pub struct MvccStore { /* ... */ }
pub struct Transaction { pub id: TxnId, pub snapshot: Snapshot, /* ... */ }

impl MvccStore {
    pub fn new() -> Self;
    pub fn current_snapshot(&self) -> Snapshot;
    pub fn begin(&mut self) -> Transaction;
    pub fn commit(&mut self, txn: Transaction) -> Result<CommitSeq, CommitError>;
    pub fn latest_commit_seq(&self, block: BlockNumber) -> CommitSeq;
    pub fn read_visible(&self, block: BlockNumber, snapshot: Snapshot) -> Option<&[u8]>;
    pub fn prune_versions_older_than(&mut self, watermark: CommitSeq);
}

impl Transaction {
    pub fn stage_write(&mut self, block: BlockNumber, bytes: Vec<u8>);
    pub fn staged_write(&self, block: BlockNumber) -> Option<&[u8]>;
    pub fn pending_writes(&self) -> usize;
}
```

### 5.1 Core Types

```rust
/// Monotonically increasing transaction identifier.
/// INVARIANT: Valid IDs start at 1. Allocators MUST NOT issue TxnId(0).
pub struct TxnId(pub u64);       // canonical — see ffs-types/src/lib.rs

/// Monotonically increasing commit sequence number.
/// CommitSeq(0) = "no version exists".
/// INVARIANT: if C1 happens-before C2, then C1.0 < C2.0.
pub struct CommitSeq(pub u64);

/// Immutable read boundary. Captures commit frontier when a transaction begins.
pub struct Snapshot { pub high: CommitSeq }
```

**Implementation note:** The canonical `TxnId` is `TxnId(pub u64)`, not `NonZeroU64`. The `MvccStore` (in `ffs-mvcc`) starts its allocator at 1, so `TxnId(0)` is never issued in practice. The earlier plan to migrate to `NonZeroU64` has been deferred indefinitely — `u64` is simpler and the zero-sentinel invariant is enforced by the allocator, not by the type system.

The `TxHandle` struct shown in earlier revisions (with `HashSet<BlockNumber>` read/write sets) is an aspirational SSI design. The current implementation uses `Transaction` (in `ffs-mvcc`), which has `BTreeMap<BlockNumber, Vec<u8>>` for staged writes and uses first-committer-wins conflict detection (not full SSI with read-set tracking).

#### 5.1.1 Sentinel Values

| Type | Sentinel | Meaning |
|------|----------|---------|
| `TxnId` | `TxnId(0)` / `None` | No transaction |
| `CommitSeq` | `CommitSeq(0)` | No committed version for block |
| `CommitSeq` | `CommitSeq(u64::MAX)` (reserved) | Phase B only: sentinel if uncommitted versions are represented in-chain. Phase A keeps uncommitted bytes in `Transaction.writes` (private), not in the store. |

#### 5.1.2 Ordering

Both types MUST implement `Ord` with natural integer ordering. Start order (`txn_id`) and commit order (`commit_seq`) MAY differ -- a transaction started earlier may commit later.

---

### 5.2 Version Chain

Each block maintains a version chain: a sequence of `BlockVersion` entries, newest at head.

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockVersion {
    pub block: BlockNumber,
    pub commit_seq: CommitSeq,   // Phase A: always committed. Phase B: may use an UNCOMMITTED sentinel until commit.
    pub writer: TxnId,
    pub bytes: Vec<u8>,          // length MUST == block_size
}
```

**Chain**: `VersionChain(B) = [V_n, V_{n-1}, ..., V_0]` where V_n is newest, V_0 oldest. For committed versions i > j: `V_i.commit_seq > V_j.commit_seq`. At most one uncommitted version per active transaction per block.

**Storage** (current implementation):

```rust
pub struct MvccStore {
    next_txn: u64,
    next_commit: u64,
    versions: BTreeMap<BlockNumber, Vec<BlockVersion>>,  // oldest at idx 0
}
```

**Chain length bound (steady state):** `|VersionChain(B)| <= active_snapshots + 1` after GC completes.

---

### 5.3 Visibility Rule

**Definition.** Version V in `VersionChain(B)` is *visible* to snapshot S iff:

1. `V.commit_seq <= S.high`, AND
2. No other committed V' exists with `V'.commit_seq <= S.high` AND `V'.commit_seq > V.commit_seq`.

**Phase B note:** If uncommitted versions are ever represented in-chain, the visibility rule MUST additionally exclude them.

```rust
fn read_visible(chain: &[BlockVersion], snapshot: Snapshot) -> Option<&[u8]> {
    chain.iter().rev()
        .find(|v| v.commit_seq <= snapshot.high)
        .map(|v| v.bytes.as_slice())
}
```

#### 5.3.1 Required Properties

| ID | Property | Statement |
|----|----------|-----------|
| **P1** | Snapshot Consistency | Repeated reads of B within T return the same version (unless T wrote B in between). |
| **P2** | Monotonic Reads | If V visible to S1 and S1.high < S2.high, then V or a newer version is visible to S2. |
| **P3** | Isolation | Uncommitted versions of T1 are never visible to T2 (T1 != T2). |
| **P4** | Read-Your-Own-Writes | T reading B after writing B sees its own staged value. |

#### 5.3.2 Read-Your-Own-Writes Path

```rust
// Phase A (implemented): the MVCC layer exposes `Transaction` for staging writes.
// Higher layers MUST implement "read-your-writes" by overlaying staged writes on top
// of snapshot reads.
fn read_tx_overlay(store: &MvccStore, tx: &Transaction, block: BlockNumber) -> Option<&[u8]> {
    if let Some(staged) = tx.staged_write(block) {
        return Some(staged);
    }
    store.read_visible(block, tx.snapshot)
}
```

---

### 5.4 Write Protocol

#### 5.4.1 Phase 1 -- Staging

Writes are buffered locally. No chain modification occurs until commit.

```rust
// Phase A (implemented): `Transaction` stores staged writes as a per-block map.
// The last write to a block wins.
impl Transaction {
    pub fn stage_write(&mut self, block: BlockNumber, bytes: Vec<u8>) {
        self.writes.insert(block, bytes);
    }
}
```

#### 5.4.2 Phase 2 -- Commit (atomic critical section)

```
PROCEDURE commit(T):
    // 1. FCW validation
    FOR EACH block B in keys(T.staged_writes):
        IF store.latest_commit_seq(B) > T.snapshot.high THEN
            RETURN Err(CommitError::Conflict { block: B, ... })
    // 2. Allocate CommitSeq (strictly monotonic)
    LET seq = next_commit_seq()
    // 3. Install versions into chains
    FOR EACH (block, data) in T.staged_writes:
        append_to_chain(block, BlockVersion { block, commit_seq: seq, writer: T.txn_id, bytes: data })
    RETURN Ok(seq)
```

**FCW correctness sketch (Phase A):**

- If two transactions `T1` and `T2` both write the same block `B`, at most one can commit: the first committer publishes `B@cs=k`; the other must see `latest_commit_seq(B)=k > snapshot.high` and abort.
- Snapshot reads are consistent because visibility is defined as “newest `commit_seq <= snapshot.high`”, and `commit_seq` is a total order over committed versions.
- FCW alone does **not** prevent write-skew across *different* blocks; SSI (Phase B) is the roadmap for serializability.

Steps 1-3 MUST execute as a single critical section.

**Phase B note:** SSI validation is applied at commit time after FCW validation and before `CommitSeq` assignment.

#### 5.4.3 Phase 3 -- Abort

Phase A (implemented): dropping a `Transaction` without calling `commit()` discards staged writes. No chain entries exist for aborted transactions because Phase A does not publish uncommitted versions.

Phase B (planned): if the MVCC layer tracks active transactions for GC watermarking and SSI bookkeeping, an explicit `abort(tx)` API is REQUIRED to remove active bookkeeping deterministically.

#### 5.4.4 CommitSeq Guarantees

1. **Monotonicity:** strictly increasing.
2. **Gap-freedom:** SHOULD be consecutive; MAY skip on pre-validation reserve/release.
3. **Durability:** commit durable after next successful buffer pool `flush()`.

---

### 5.5 Conflict Detection: Serializable Snapshot Isolation (SSI)

SSI extends Snapshot Isolation to full serializability by detecting dangerous structures in the dependency graph.

#### 5.5.1 Dependency Types

| Edge | Notation | Meaning |
|------|----------|---------|
| ww (write-write) | T1 --ww--> T2 | T2 overwrites T1's version |
| wr (write-read) | T1 --wr--> T2 | T2 reads T1's version |
| rw (antidependency) | T1 --rw--> T2 | T1 reads a version that T2 overwrites |

#### 5.5.2 FCW Rule

```rust
fn check_fcw(store: &MvccStore, txn: &TxHandle) -> Result<(), CommitError> {
    for &block in &txn.write_set {
        let latest = store.latest_commit_seq(block);
        if latest > txn.snapshot.high {
            return Err(CommitError::Conflict { block, snapshot: txn.snapshot.high, observed: latest });
        }
    }
    Ok(())
}
```

T MUST abort if any block in `T.write_set` has a committed version with `commit_seq > T.snapshot.high`.

#### 5.5.3 Dangerous Structure Detection

A dangerous structure: `T1 --rw--> T2 --rw--> T3` where T1 and T3 are concurrent.

```
PROCEDURE ssi_dangerous_structure_detected(T):
    // T plays role of T2 (the committing transaction)

    LET inbound_rw = { T1 : exists B in T.write_set such that
                              T1 read B AND T1 concurrent with T }

    LET outbound_rw = { T3 : exists B in T.read_set such that
                               T3 wrote B AND T3.commit_seq > T.snapshot.high }

    RETURN inbound_rw non-empty AND outbound_rw non-empty
```

#### 5.5.4 SSI Bookkeeping

```rust
struct SsiTxnInfo {
    in_conflict: HashSet<TxnId>,     // inbound rw-antideps (they read, we write)
    out_conflict: HashSet<TxnId>,    // outbound rw-antideps (we read, they write)
    committed: bool,
    commit_seq: Option<CommitSeq>,
}
```

Lifecycle: created at `begin()`, updated on overlap detection, checked at `commit()`, cleaned up when no active snapshot can reference it.

#### 5.5.5 False Positives

SSI MAY produce false positives (abort serializable transactions). It MUST NOT produce false negatives (permit non-serializable executions).

---

### 5.6 Garbage Collection Protocol

#### 5.6.1 Watermark

```rust
fn compute_gc_watermark(active: &[TxHandle]) -> CommitSeq {
    active.iter().map(|t| t.snapshot.high).min()
        .unwrap_or(CommitSeq(u64::MAX))
}
```

#### 5.6.2 Per-Block Pruning

```
PROCEDURE prune_block(chain, watermark):
    LET keeper = newest version with commit_seq <= watermark
    IF keeper exists: remove all versions older than keeper
```

Current implementation:

```rust
pub fn prune_versions_older_than(&mut self, watermark: CommitSeq) {
    for versions in self.versions.values_mut() {
        if versions.len() <= 1 { continue; }
        let mut keep_from = 0usize;
        while keep_from + 1 < versions.len() {
            if versions[keep_from + 1].commit_seq <= watermark {
                keep_from += 1;
            } else { break; }
        }
        if keep_from > 0 { versions.drain(0..keep_from); }
    }
}
```

#### 5.6.3 Scheduling

1. **Trigger:** `total_versions > 2 * total_blocks` or timer (default 30s).
2. **Granularity:** one Region at a time.
3. **Cancellation:** MUST respect `&Cx`. Each block prune is a checkpoint.
4. **Concurrency:** read-lock for watermark, write-lock per chain prune.

```rust
async fn gc_region(cx: &Cx, store: &RwLock<MvccStore>, region: RegionId) -> Result<GcStats> {
    let watermark = { store.read().compute_gc_watermark() };
    let mut pruned = 0u64;
    for block in region.block_range() {
        cx.checkpoint()?;
        pruned += store.write().prune_single_block(block, watermark);
    }
    Ok(GcStats { region, pruned, watermark })
}
```

#### 5.6.4 GC Safety

**INVARIANT (GC-SAFE):** GC MUST NOT remove any version V visible to any active snapshot. The watermark = min(active snapshots); the keeper = newest version <= watermark; all older versions are superseded for every active snapshot.

---

### 5.7 Invariants Summary

| ID | Invariant | Where Enforced |
|----|-----------|----------------|
| **M1** | TxnId strictly monotonic, never reused | `begin()` |
| **M2** | CommitSeq strictly monotonic, never reused | `commit()` |
| **M3** | No committed version removed while visible to any active snapshot | `prune_versions_older_than()` |
| **M4** | Conflict checks deterministic and replayable | `commit()` |
| **M5** | Write set complete: every written block in `write_set` | `stage_write()` |
| **M6** | Read set sound: every chain-read block in `read_set` | `TxHandle::read()` |
| **M7** | At most one committed version per (block, CommitSeq) | `commit()` |
| **M8** | Snapshot.high immutable after creation | Type system |

---

### 5.8 Journal Interaction

1. **Pre-commit:** journal MUST have a running descriptor listing all write-set blocks before MVCC commit.
2. **Ordering:** journal commit record on stable storage before CommitSeq considered durable.
3. **Replay:** only transactions with complete journal commit records are restored; incomplete ones discarded.
4. **Native COW mode:** journal is redo log for MVCC metadata (chain pointers, counters) not block data (COW, never overwritten in place).

---

## 6. Buffer Pool: ARC Cache

Implementation: `ffs-block` crate.

---

### 6.1 Overview

FrankenFS uses an Adaptive Replacement Cache (ARC) as its buffer pool. ARC self-tunes to balance recency and frequency without manual configuration, providing scan resistance (sequential reads do not evict hot metadata) and recency sensitivity (interactive workloads keep recent blocks cached).

---

### 6.2 Data Structures

#### 6.2.1 Four Lists

```rust
pub struct ArcCache {
    /// T1: recently accessed once (recency). Contains data.
    t1: LinkedHashMap<BlockNumber, CacheEntry>,
    /// T2: accessed 2+ times (frequency). Contains data.
    t2: LinkedHashMap<BlockNumber, CacheEntry>,
    /// B1: ghost entries evicted from T1. No data.
    b1: LinkedHashSet<BlockNumber>,
    /// B2: ghost entries evicted from T2. No data.
    b2: LinkedHashSet<BlockNumber>,
    /// Adaptive target size for T1. Range: [0, c].
    p: usize,
    /// c = max blocks in T1 + T2.
    max_cached_blocks: usize,
    block_size: usize,
}

pub struct CacheEntry {
    pub buf: BlockBuf,
    pub dirty: bool,
    pub commit_seq: CommitSeq,
}
```

| List | Data? | Purpose | Max Size |
|------|-------|---------|----------|
| T1 | Yes | Recent (seen once) | target `p` |
| T2 | Yes | Frequent (seen 2+) | target `c - p` |
| B1 | No | Ghost history from T1 | `c - p` |
| B2 | No | Ghost history from T2 | `p` |

**Size constraints (MUST hold):**

```
|T1| + |T2| <= c
|T1| + |B1| <= c
|T2| + |B2| <= c
|T1| + |T2| + |B1| + |B2| <= 2c
```

#### 6.2.2 BlockBuf

```rust
#[derive(Clone, PartialEq, Eq)]
pub struct BlockBuf { data: Vec<u8> }  // length MUST == block_size

impl BlockBuf {
    pub fn zeroed(block_size: usize) -> Self { Self { data: vec![0u8; block_size] } }
    pub fn from_vec(data: Vec<u8>) -> Self { Self { data } }
    pub fn as_slice(&self) -> &[u8] { &self.data }
    pub fn as_mut_slice(&mut self) -> &mut [u8] { &mut self.data }
    pub fn len(&self) -> usize { self.data.len() }
    pub fn is_empty(&self) -> bool { self.data.is_empty() }
}
```

---

### 6.3 Adaptive Parameter `p`

Initial value: `p = 0` (favors frequency). Adapts on ghost hits:

**B1 hit** -- recency would have helped, increase p:

```rust
fn adapt_on_b1_hit(&mut self) {
    let delta = if self.b1.len() >= self.b2.len() { 1 }
                else { (self.b2.len() / self.b1.len()).max(1) };
    self.p = (self.p + delta).min(self.max_cached_blocks);
}
```

**B2 hit** -- frequency would have helped, decrease p:

```rust
fn adapt_on_b2_hit(&mut self) {
    let delta = if self.b2.len() >= self.b1.len() { 1 }
                else { (self.b1.len() / self.b2.len()).max(1) };
    self.p = self.p.saturating_sub(delta);
}
```

The ratio scaling gives scan resistance: a sequential scan fills B1 but never triggers B1 *hits*, so p stays low.

---

### 6.4 Cache Operations

#### 6.4.1 `get(block) -> Option<BlockBuf>`

```
PROCEDURE get(block):
    IF block IN T1:
        move entry from T1 to MRU of T2 (promote)
        RETURN Some(entry.buf)
    IF block IN T2:
        move to MRU of T2 (refresh)
        RETURN Some(entry.buf)
    IF block IN B1:
        adapt_on_b1_hit(); B1.remove(block)
    ELSE IF block IN B2:
        adapt_on_b2_hit(); B2.remove(block)
    RETURN None   // caller fetches from disk, calls put()
```

#### 6.4.2 `put(block, data) -> Option<EvictedEntry>`

```
PROCEDURE put(block, data):
    IF |T1| + |T2| == c:
        evicted = replace()
    IF block was ghost-hit from B1:
        T2.insert_mru(block, CacheEntry { buf: data, dirty: false })
    ELSE:
        T1.insert_mru(block, CacheEntry { buf: data, dirty: false })
    RETURN evicted   // caller MUST write-back if evicted.dirty
```

#### 6.4.3 `dirty(block)`

```rust
pub fn dirty(&mut self, block: BlockNumber) -> Result<(), CacheError> {
    if let Some(e) = self.t1.get_mut(&block) { e.dirty = true; return Ok(()); }
    if let Some(e) = self.t2.get_mut(&block) { e.dirty = true; return Ok(()); }
    Err(CacheError::NotCached(block))
}
```

MUST only be called on blocks currently in T1 or T2.

#### 6.4.4 `flush(device) -> Result<FlushStats>`

Writes all dirty blocks in T1 and T2 to device, clears dirty flags. MUST call `fdatasync()` or equivalent before returning `Ok`. Partial failures return `FlushError { partial_count, failures }`.

#### 6.4.5 `replace()` (internal eviction)

```
PROCEDURE replace():
    IF |T1| > 0 AND (|T1| > p OR (|T1| == p AND request_from_b2)):
        (block, entry) = T1.pop_lru()
        B1.insert(block); trim B1 to <= c - p
    ELSE IF |T2| > 0:
        (block, entry) = T2.pop_lru()
        B2.insert(block); trim B2 to <= p
    RETURN evicted entry (caller writes back if dirty)
```

---

### 6.5 MVCC Integration

#### 6.5.1 Layer Diagram

```
  +------------------------------------------+
  |           FUSE / VFS Layer               |
  +------------------------------------------+
  |        ffs-core (FrankenFsEngine)        |
  +------+------------------------------+---+
         |                              |
  +------v------+            +---------v--------+
  |  ffs-mvcc   |            |    ffs-block      |
  |  (versions, |            | (ARC + BlockDev)  |
  |   SSI, GC)  |            +--------+----------+
  +-------------+                     |
                              +-------v--------+
                              | Physical Device |
                              +----------------+
```

#### 6.5.2 What the Cache Stores

The cache holds the **current committed version** of each cached block (`CacheEntry.commit_seq` records which). Version chain history lives exclusively in `ffs-mvcc` memory. Cache eviction MUST NOT affect version chain integrity.

#### 6.5.3 Read Path

```
PROCEDURE mvcc_read_block(block, snapshot):
    LET cached = arc_cache.get(block)
    IF cached.commit_seq is correct version for snapshot: RETURN cached.buf
    // Fall through to version chain for historical reads
    LET data = mvcc_store.read_visible(block, snapshot)
    IF data: RETURN data
    // Never written: read from device, insert into cache
    LET disk = device.read_block(block)
    arc_cache.put(block, disk)
    RETURN disk
```

#### 6.5.4 Write Path

```
PROCEDURE on_mvcc_commit(writes: &[(BlockNumber, Vec<u8>)], seq: CommitSeq):
    FOR EACH (block, data) IN writes:
        IF cached: update in-place, mark dirty
        ELSE: put into cache as dirty
```

---

### 6.6 Write-Back vs. Write-Through

#### 6.6.1 CachePolicy Trait

```rust
pub trait CachePolicy: Send + Sync + 'static {
    fn should_write_immediately(&self, block: BlockNumber) -> bool;
    fn select_for_flush(&self, dirty: &[BlockNumber], elapsed: Duration) -> Vec<BlockNumber>;
    fn flush_interval(&self) -> Duration;
}
```

#### 6.6.2 Write-Back (Default)

Dirty blocks flushed: (a) periodically by daemon (default 5s), (b) on `fsync()`, (c) on dirty eviction, (d) on unmount.

```rust
pub struct WriteBackPolicy {
    pub max_dirty_age: Duration,      // default 30s
    pub max_dirty_blocks: usize,      // default 1024
    pub flush_interval: Duration,     // default 5s
}
```

#### 6.6.3 Write-Through

Every write goes to disk immediately. `should_write_immediately()` always returns `true`.

```rust
pub struct WriteThroughPolicy;
impl CachePolicy for WriteThroughPolicy {
    fn should_write_immediately(&self, _: BlockNumber) -> bool { true }
    fn select_for_flush(&self, _: &[BlockNumber], _: Duration) -> Vec<BlockNumber> { vec![] }
    fn flush_interval(&self) -> Duration { Duration::from_secs(u64::MAX) }
}
```

#### 6.6.4 Selection

```rust
pub enum CachePolicyKind { WriteBack(WriteBackPolicy), WriteThrough }
pub struct MountOptions {
    pub cache_policy: CachePolicyKind,
    pub max_cached_blocks: usize,
}
```

Policy MUST NOT change while mounted.

---

### 6.7 Cache Sizing and Metrics

#### 6.7.1 Constructor

```rust
impl ArcCache {
    pub fn new(max_cached_blocks: usize, block_size: usize) -> Self {
        assert!(max_cached_blocks > 0);
        Self { t1: .., t2: .., b1: .., b2: .., p: 0, max_cached_blocks, block_size }
    }
}
```

#### 6.7.2 Memory Bound

```
data    = max_cached_blocks * block_size            (T1+T2 payloads)
ghosts  = max_cached_blocks * size_of::<BlockNumber>()  (B1+B2 keys)
total  ~= data + ghosts + overhead
```

Example: 16,384 blocks * 4,096 B = 64 MiB data + ~128 KiB ghosts.

#### 6.7.3 TUI Metrics (`ffs-tui`)

```rust
#[derive(Debug, Clone, Serialize)]
pub struct ArcCacheStats {
    pub t1_size: usize, pub t2_size: usize,
    pub b1_size: usize, pub b2_size: usize,
    pub p: usize, pub max_cached_blocks: usize, pub block_size: usize,
    pub hit_count: u64, pub miss_count: u64,
    pub dirty_count: usize, pub eviction_count: u64, pub flush_count: u64,
}
impl ArcCacheStats {
    pub fn hit_rate(&self) -> f64 {
        let t = self.hit_count + self.miss_count;
        if t == 0 { 0.0 } else { self.hit_count as f64 / t as f64 }
    }
    pub fn memory_bytes(&self) -> usize {
        (self.t1_size + self.t2_size) * self.block_size
            + (self.b1_size + self.b2_size) * std::mem::size_of::<BlockNumber>()
    }
}
```

MUST be exposed in the TUI dashboard: `arc.{t1,t2,b1,b2}.size`, `arc.p`, `arc.hit_rate`, `arc.dirty_count`, `arc.memory_bytes`, `arc.evictions`, `arc.flushes`.

---

### 6.8 Concurrency

v1 uses a single `RwLock<ArcCache>`:

- T2 hit (no list move): read lock.
- T1-to-T2 promotion, `put`, `dirty`, `flush`: write lock.

Background flush daemon respects `&Cx` cancellation:

```rust
async fn flush_daemon(cx: &Cx, cache: &RwLock<ArcCache>,
                      device: &dyn BlockDevice, policy: &dyn CachePolicy) -> Result<()> {
    loop {
        cx.checkpoint()?;
        cx.sleep(policy.flush_interval()).await?;
        let dirty = { cache.read().dirty_block_list() };
        let batch = policy.select_for_flush(&dirty, policy.flush_interval());
        if !batch.is_empty() {
            let mut w = cache.write();
            for b in &batch {
                if let Some(e) = w.get_entry_mut(*b) {
                    if e.dirty { device.write_block(*b, e.buf.as_slice())?; e.dirty = false; }
                }
            }
        }
    }
}
```

**Future (informative):** shard by `BlockNumber % N` for reduced contention in v2.

---

### 6.9 BlockDevice Trait

```rust
pub trait BlockDevice: Send + Sync {
    fn read_block(&self, block: BlockNumber) -> Result<Vec<u8>, FfsError>;
    fn write_block(&self, block: BlockNumber, data: &[u8]) -> Result<(), FfsError>;
    fn sync(&self) -> Result<(), FfsError>;
    fn block_count(&self) -> u64;
    fn block_size(&self) -> usize;
}
```

Implementations: `FileBlockDevice` (file-backed), `RawBlockDevice` (`/dev/sdX`), `MemoryBlockDevice` (tests/fuzz).

---

### 6.10 Invariants Summary

| ID | Invariant | Where |
|----|-----------|-------|
| **C1** | `|T1| + |T2| <= max_cached_blocks` | `put()`, `replace()` |
| **C2** | Block appears in at most one of {T1, T2, B1, B2} | All ops |
| **C3** | `0 <= p <= max_cached_blocks` | adapt functions |
| **C4** | Ghost lists hold no block data | Construction |
| **C5** | Dirty flag only set via `dirty()` | `dirty()` |
| **C6** | After `flush()` Ok, no dirty blocks remain | `flush()` |
| **C7** | Eviction does not affect MVCC version chains | Layering |
| **C8** | CachePolicy immutable for mount lifetime | `MountOptions` |

---
## 7. Checksums and Integrity

FrankenFS employs three checksum algorithms, each serving a distinct role
in the integrity stack.

### 7.1 Algorithm Selection

| Algorithm | Crate | Digest | Crypto | Primary Use |
|-----------|-------|--------|--------|-------------|
| **CRC32C** | `crc32c ^0.6` | 4 B | No | ext4 `metadata_csum` compatibility |
| **BLAKE3** | `blake3 ^1` | 32 B | Yes | Native-mode block integrity, MVCC version verification, repair symbol integrity |
| **XXH3** | `xxhash-rust ^0.8` | 8 B | No | ARC cache lookup, hash table probing, htree directory hashing, page lock sharding |

### 7.2 CRC32C: ext4 Compatibility

CRC32C is mandatory for ext4 on-disk structures when `metadata_csum`
(`RO_COMPAT_METADATA_CSUM`, bit 0x0400) is set. Polynomial: Castagnoli
`0x1EDC6F41`.

**Metadata checksum seed (`csum_seed`):**
- If `INCOMPAT_CSUM_SEED` is set: `csum_seed = s_checksum_seed`.
- Else: `csum_seed = crc32c_append(0xFFFF_FFFF, s_uuid)` (i.e., kernel `crc32c(~0, uuid, 16)`).

> **Note:** The **superblock** checksum uses seed `0xFFFF_FFFF` over bytes `0x000..0x3FB`.
> Other metadata structures use `csum_seed` as their base seed.

| Structure | Field | Scope |
|-----------|-------|-------|
| Superblock | `s_checksum` (0x3FC) | All preceding bytes, seed `0xFFFFFFFF` |
| Group desc | `bg_checksum` (0x1E) | Seed + group# LE + desc bytes (csum zeroed) |
| Inode | `i_checksum_lo/hi` (0x7C/0x82) | Seed + ino# LE + gen LE + inode bytes (csum zeroed) |
| Extent node | `eh_checksum` (tail) | Seed + ino# + gen + extent block bytes |
| Dir leaf | `de_checksum` (tail) | Seed + ino# + gen + dir block bytes |
| htree node | `dx_checksum` (tail) | Seed + ino# + gen + dx node bytes |
| Journal desc | `t_checksum` | CRC32C over descriptor tags |
| Journal commit | `h_chksum[0]` | CRC32C over commit header |
| Journal revoke | `r_checksum` | CRC32C over revoke block |

All CRC32C verification lives in `ffs-ondisk` as **pure** functions/methods (no I/O),
returning `ffs-types::ParseError`. User-facing layers (CLI/FUSE/mount) map `ParseError`
to `ffs-error::FfsError` at the orchestration boundary (`ffs-core`).

```rust
use crc32c;
use ffs_types::ParseError;

pub fn verify_superblock_csum(raw_region: &[u8]) -> Result<(), ParseError> {
    if raw_region.len() < 1024 {
        return Err(ParseError::InsufficientData {
            needed: 1024,
            offset: 0,
            actual: raw_region.len(),
        });
    }

    let stored = u32::from_le_bytes(raw_region[0x3FC..0x400].try_into().unwrap());
    let computed = crc32c::crc32c_append(0xFFFF_FFFF, &raw_region[..0x3FC]);
    if stored != computed {
        return Err(ParseError::InvalidField {
            field: "s_checksum",
            reason: "superblock CRC32C mismatch",
        });
    }
    Ok(())
}
```

### 7.3 BLAKE3: Native-Mode Integrity

In native MVCC mode, BLAKE3 augments CRC32C with 256-bit cryptographic
checksums (collision resistance ~2^-256, pre-image resistance, optional
keyed mode via `blake3::keyed_hash()`). Used for: block-level integrity
(verified every `read_versioned()`), MVCC version verification, and
repair symbol integrity (verified before RaptorQ decoding).

```rust
pub struct BlockVersion {
    pub block_nr: BlockNumber,
    pub commit_seq: CommitSeq,
    pub writer: TxnId,
    pub data: BlockBuf,
    pub crc32c: u32,                    // always present
    pub blake3: Option<[u8; 32]>,       // None in JBD2-compat mode
}
```

BLAKE3 is NOT stored in ext4 on-disk structures -- only in FrankenFS's
version chain entries and repair symbol headers, preserving ext4 tool
compatibility.

### 7.4 XXH3: Fast Non-Cryptographic Hashing

Used for: ARC cache lookup (`ffs-block`), hash table probing (custom
`BuildHasher`), page lock sharding (`XXH3(block_nr) % shard_count`),
version chain index (`ffs-mvcc`), and htree directory hashing in native
mode. ext4 htree compatibility: versions 0-5 (legacy/half-MD4/TEA) MUST
be implemented; version 6+ MAY use XXH3 for native-created directories.

```rust
pub fn dx_hash(name: &[u8], hash_version: u8, hash_seed: &[u32; 4]) -> (u32, u32) {
    match hash_version {
        0 | 3 => dx_hash_legacy(name),
        1 | 4 => dx_hash_half_md4(name, hash_seed),
        2 | 5 => dx_hash_tea(name, hash_seed),
        _ => {
            let seed = u64::from(hash_seed[0]) | (u64::from(hash_seed[1]) << 32);
            let h = xxhash_rust::xxh3::xxh3_64_with_seed(name, seed);
            ((h >> 1) as u32, (h >> 33) as u32)
        }
    }
}
```

### 7.5 Integrity Verification Chain

**Read path:** Every `read_block` MUST verify checksum before returning.
ARC cache hit returns immediately (verified on insertion). Cache miss reads
from device, verifies CRC32C (and BLAKE3 in native mode), inserts into
cache. Mismatch returns `FfsError::Corruption` and triggers repair. No
unverified data is ever returned. Metadata blocks additionally undergo
type-specific verification (superblock, group desc, inode, extent, dir,
journal).

**Write path:** Every `write_block` computes CRC32C (+ BLAKE3 in native
mode) over final bytes, stores in version metadata, writes to device,
then notifies `ffs-repair::mark_stale(group)`. Checksum MUST be computed
over exact bytes that will be durably written -- no modification between
checksum and `pwrite64`.

### 7.6 Error Handling

1. Mismatch detected -> `FfsError::Corruption { block, detail }`
2. Attempt `ffs-repair::recover_block(cx, block_nr)`
3. Success -> return corrected block (caller never sees corruption)
4. Failure -> return `FfsError::Corruption` -> FUSE maps to `EIO`

Every mismatch MUST emit `tracing::warn!` regardless of repair outcome.

### 7.7 Performance

Per-4K-block overhead: CRC32C ~130 ns, BLAKE3 ~700 ns, XXH3 ~100 ns.
Combined native-mode read overhead under 1 us/block, negligible vs. NVMe
latency (~10 us).

---

## 8. Architecture: Crate Map

### 8.1 Workspace Overview

19 crates under `crates/`, plus two legacy reference crates (`ffs-ext4`,
`ffs-btrfs`). All share: Edition 2024, `#![forbid(unsafe_code)]`, Clippy
pedantic+nursery at deny, common versions via `[workspace.dependencies]`.

### 8.2 Crate Table

| # | Crate | Role | Key Deps |
|---|-------|------|----------|
| 1 | `ffs-types` | Newtypes (`BlockNumber`, `InodeNumber`, `TxnId`, `CommitSeq`, `Snapshot`), parse helpers, ext4/btrfs magic constants | `serde`, `thiserror` |
| 2 | `ffs-error` | `FfsError` (14 variants), `Result<T>`, errno mapping (`to_errno()`) | `libc`, `thiserror` |
| 3 | `ffs-ondisk` | Pure ext4 + btrfs parsing (superblocks, extents, leaf items); no I/O | `ffs-types`, `ffs-error`, `crc32c`, `serde` |
| 4 | `ffs-block` | Block I/O: `ByteDevice`, `BlockDevice`, ARC cache; Cx-aware I/O | `ffs-types`, `ffs-error`, `asupersync`, `parking_lot` |
| 5 | `ffs-journal` | JBD2-compatible journal replay scaffolding (phased) | `ffs-types`, `ffs-error`, `ffs-block` |
| 6 | `ffs-mvcc` | MVCC core (currently in-memory FCW; SSI phased) | `ffs-types`, `serde`, `thiserror` |
| 7 | `ffs-btree` | Tree ops used by ext4 (extents/htree) and btrfs (metadata trees) | `ffs-types`, `ffs-error`, `ffs-block`, `ffs-ondisk` |
| 8 | `ffs-alloc` | Allocation scaffolding (mballoc/Orlov phased) | `ffs-types`, `ffs-error`, `ffs-block`, `ffs-ondisk` |
| 9 | `ffs-inode` | Inode lifecycle scaffolding | `ffs-types`, `ffs-error`, `ffs-block`, `ffs-ondisk` |
| 10 | `ffs-dir` | Directory ops scaffolding | `ffs-types`, `ffs-error`, `ffs-inode` |
| 11 | `ffs-extent` | Extent mapping scaffolding | `ffs-types`, `ffs-error`, `ffs-btree`, `ffs-alloc` |
| 12 | `ffs-xattr` | Xattr scaffolding | `ffs-types`, `ffs-error`, `ffs-block`, `ffs-ondisk` |
| 13 | `ffs-fuse` | FUSE adapter scaffolding; delegates to `ffs-core` (fuser integration phased) | `asupersync`, `ffs-core`, `ffs-types`, `serde`, `thiserror` |
| 14 | `ffs-repair` | Repair scaffolding (RaptorQ integration phased) | `ffs-types`, `ffs-error`, `ffs-block`, `asupersync` |
| 15 | `ffs-core` | Engine integration: detect/inspect, MVCC wrapper, autopilot | `asupersync`, `ffs-block`, `ffs-error`, `ffs-mvcc`, `ffs-ondisk`, `ffs-types`, `serde`, `thiserror` |
| 16 | `ffs` | Public facade; re-exports `ffs-core` | `ffs-core` |
| 17 | `ffs-cli` | CLI: `inspect` (current), mount/fsck/info phased | `anyhow`, `asupersync`, `ffs-core`, `serde`, `serde_json`, `ftui` |
| 18 | `ffs-tui` | TUI monitoring | `ffs`, `ftui` |
| 19 | `ffs-harness` | Fixture conformance + benches | `anyhow`, `ffs-core`, `ffs-ondisk`, `ffs-types`, `hex`, `serde`, `serde_json` (+dev: `criterion`) |

All crates implicitly depend on `ffs-types` and `ffs-error`.

### 8.3 Dependency Graph

```
                         ┌───────────┐  ┌───────────┐
                         │ ffs-types │  │ ffs-error  │
                         └─────┬─────┘  └─────┬─────┘
                               └──────┬───────┘
                               ┌──────▼──────┐
                               │  ffs-ondisk  │   (pure; no I/O)
                               └──────┬──────┘
            ┌─────────────────────────┼──────────────────────────┐
            │                         │                          │
     ┌──────▼──────┐          ┌──────▼──────┐           ┌──────▼──────┐
     │  ffs-block   │          │  ffs-btree  │           │  ffs-xattr  │
     │  (ARC cache) │          └──────┬──────┘           └──────┬──────┘
     └──┬──┬──┬──┬──┘                │                         │
        │  │  │  │           ┌───────▼───────┐                 │
        │  │  │  │           │   ffs-alloc   │                 │
        │  │  │  │           └───────┬───────┘                 │
        │  │  │  └───────────────────┼─────────────────────────┘
   ┌────▼┐ │  ┌▼───────┐     ┌──────▼──────┐   ┌──────────┐
   │ffs- │ │  │ffs-    │     │ ffs-extent  │   │ffs-inode │
   │jour.│ │  │repair  │     └──────┬──────┘   └────┬─────┘
   └──┬──┘ │  └────────┘            │               │
      │    │                        │        ┌──────▼──────┐
   ┌──▼────▼───┐                    │        │   ffs-dir   │
   │  ffs-mvcc  │                    │        └──────┬──────┘
   └─────┬─────┘                    │               │
         └──────────┬───────────────┴───────────────┘
             ┌──────▼──────┐
             │   ffs-fuse   │
             └──────┬──────┘
             ┌──────▼──────┐
             │   ffs-core   │
             └──────┬──────┘
             ┌──────▼──────┐
             │     ffs      │   (facade)
             └──┬───┬───┬──┘
        ┌───────┘   │   └────────┐
 ┌──────▼──┐ ┌─────▼─────┐ ┌───▼──────────┐
 │ ffs-cli  │ │  ffs-tui   │ │ ffs-harness   │
 └─────────┘ └───────────┘ └──────────────┘
```

### 8.4 Layering Rules

1. **Parser crates are pure.** `ffs-ondisk` does no I/O. MUST NOT depend on `ffs-block` or `asupersync`.
2. **MVCC is transport-agnostic.** `ffs-mvcc` knows nothing about FUSE, files, or inodes.
3. **FUSE adapter delegates.** `ffs-fuse` maps callbacks to `FfsOperations`; zero FS logic.
4. **Repair is orthogonal.** `ffs-repair` operates on blocks, not files.
5. **Harness depends on everything.** No production crate (1-18) depends on `ffs-harness`.
6. **No cycles.** Strict DAG; enforced by `cargo` and CI.
7. **Cx everywhere.** Any I/O operation takes `&Cx` as first parameter. Pure functions do not.

### 8.5 Per-Crate Detailed Descriptions

> **Note:** The crate *boundaries* described here are normative, but the
> internal file/module layout is expected to evolve. Early prototypes may keep
> more code in `src/lib.rs` before splitting into modules.

**`ffs-types`** (~2,000 LOC estimated)

The foundational types crate with minimal dependencies (currently `serde` and
`thiserror`). Every other workspace crate depends on
this. All types are `#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]`
where semantically valid.

Key types and modules:
- `block.rs`: `BlockNumber(u64)` -- physical block address, zero-indexed. `BlockCount(u64)` for block ranges. `BlockSize(u32)` validated to power-of-two in 1024..=65536. `BlockBuf` -- owned block-aligned byte buffer, exactly `block_size` bytes. `BlockRef<'a>` -- borrowed reference to cached block data in ARC.
- `inode.rs`: `InodeNumber(u64)` -- 1-indexed inode number. `InodeNumber::ROOT = InodeNumber(2)`. `InodeNumber::JOURNAL = InodeNumber(8)`. `InodeSize(u16)` validated to 128 or 256.
- `group.rs`: `GroupNumber(u32)` -- block group index. `GroupDescSize(u16)` validated to 32 or 64.
- `txn.rs`: `TxnId(u64)` -- monotonically increasing transaction identifier, `TxnId(0)` reserved (no transaction). `CommitSeq(u64)` -- global commit clock, `CommitSeq(0)` = before first commit. `Snapshot { high: CommitSeq }` -- immutable read boundary.
- `time.rs`: `Timestamp { secs: i64, nsec: u32 }` -- ext4-compatible timestamp with nanosecond precision (34-bit seconds via epoch extension, 30-bit nanoseconds). Conversion from/to ext4 `i_xtime + i_xtime_extra` format. `UTIME_NOW` and `UTIME_OMIT` sentinel values.
- `mode.rs`: `FileMode(u16)` -- type (upper 4 bits) + permissions (lower 12 bits). Constants: `S_IFREG`, `S_IFDIR`, `S_IFLNK`, `S_IFCHR`, `S_IFBLK`, `S_IFIFO`, `S_IFSOCK`. Methods: `is_dir()`, `is_regular()`, `is_symlink()`, `permissions()`, `file_type()`.
- `flags.rs`: `InodeFlags(u32)` bitflags (SYNC, IMMUTABLE, APPEND, NOATIME, EXTENTS, HUGE_FILE, EA_INODE). `FeatureCompat(u32)`, `FeatureIncompat(u32)`, `FeatureRoCompat(u32)` bitflags for superblock feature detection. `MountFlags(u32)` for runtime mount options.
- `offset.rs`: `Offset(u64)` -- byte offset within a file. `LogicalBlock(u64)` -- file-relative block number (offset / block_size).
- `hash.rs`: `DxHashVersion(u8)` enum (Legacy, HalfMd4, Tea, UnsignedLegacy, UnsignedHalfMd4, UnsignedTea). `DxHash { major: u32, minor: u32 }`.
- `le.rs`: `read_le_u16(data, offset)`, `read_le_u32(data, offset)`, `read_le_u64(data, offset)` -- little-endian parse helpers that read from byte slices at a given offset. `ensure_slice(data, offset, len)` for bounds-checked subslice extraction. `read_fixed::<N>(data, offset)` for fixed-size arrays. `trim_nul_padded(bytes)` for NUL-terminated strings. Used pervasively in `ffs-ondisk`.
> **[CORRECTION]** The spec originally described `Le16(u16)`, `Le32(u32)`, `Le64(u64)` wrapper types. The actual implementation uses free functions (`read_le_u16`, etc.) rather than newtype wrappers.

Public API surface: ~60 types, all `#[derive(Debug, Clone)]`, most `Copy`.
`Cx` is currently imported from `asupersync` directly by crates that need it;
we may introduce a re-export via `ffs-types` later if API-stability concerns
justify it.

**`ffs-error`** (~600 LOC estimated)

Error types using `thiserror` derive. This crate defines the canonical
workspace error enum `FfsError` (14 variants), a `Result<T>` alias, and
`FfsError::to_errno()` for POSIX/FUSE integration.

Canonical source of truth: `crates/ffs-error/src/lib.rs`.

**`ffs-ondisk`** (~5,000 LOC estimated)

Pure ext4 + btrfs on-disk format parsing. Zero I/O -- operates exclusively on
byte slices passed in. MUST NOT depend on `ffs-block`, `asupersync`, or any I/O
crate. Parsing uses explicit, bounds-checking decode helpers from `ffs-types`
(`ensure_slice`, `read_le_u16/u32/u64`, `read_fixed`) and returns `ParseError`
on malformed metadata. No pointer casts, no unsafe code.

Current modules (in-repo):
- `ext4.rs`: `Ext4Superblock`, `Ext4Inode`, extent tree parsing.
- `btrfs.rs`: `BtrfsSuperblock`, node header + leaf item parsing.

Dependency rationale: depends on `ffs-types` for newtypes/constants and parse
helpers; depends on `ffs-error` for `Result`. Uses `crc32c` for checksum
computation and `serde` for fixtures/metadata reports.

**`ffs-block`** (~4,000 LOC estimated)

Block I/O layer and cache scaffolding. This is the central I/O hub: every block
read/write in the filesystem passes through `ffs-block`.

Current functionality (in-repo):
- `ByteDevice` trait: fixed-offset read/write (pread/pwrite semantics) with `&Cx`
  checkpoints for cooperative cancellation.
- `FileByteDevice`: file-backed `ByteDevice` using `std::os::unix::fs::FileExt`.
- `BlockDevice` trait and `ByteBlockDevice` adapter: block-sized I/O over a
  `ByteDevice`.
- `ArcCache`: ARC-like cache wrapper (currently read-cache + write-through;
  full ARC + write-back is phased).

Dependency rationale: depends on `ffs-types`/`ffs-error` for newtypes and error
model; depends on `asupersync` for `Cx`; uses `parking_lot` for internal
synchronization.

**`ffs-journal`** (~3,000 LOC estimated)

JBD2-compatible journal replay and native COW journal. Supports two modes
that share the same trait interface (`JournalManager`, Section 9.7).

Modules:
- `replay.rs`: JBD2 journal replay engine. Implements the four-phase algorithm from Section 11.6.4: (1) SCAN from `s_start` following `s_sequence`, matching magic and sequence numbers, parsing DESCRIPTOR/COMMIT/REVOKE blocks, stopping on mismatch or wrap; (2) REVOKE set construction (`HashMap<BlockNumber, u32>` mapping block to highest revoking sequence); (3) REPLAY oldest-first, skipping revoked blocks, writing data to target locations, restoring escaped magic bytes; (4) CLEANUP: set `s_start=0`, write journal superblock. Handles circular wrap via `next(pos) = s_first + ((pos - s_first + 1) % (s_maxlen - s_first))`.
- `jbd2.rs`: JBD2-compatible transaction lifecycle for write operations (active only in JBD2-compat mode). `JournalTransaction`: reserve blocks, write descriptor tags, copy data blocks to journal area, write revoke blocks, write commit block. Compound transactions: multiple FS operations batched within a single journal transaction (commit interval 5s or when journal space below 25%). Checkpoint: write committed journal data to final locations, advance journal head.
- `cow.rs`: Native COW journal (active in MVCC-native mode). Journal replay is still supported (for mounting dirty ext4 images), but write-path journaling is a no-op -- MVCC version chains provide crash consistency. The `begin_transaction`, `journal_block`, `commit_transaction`, and `checkpoint` methods are stubs returning `Ok(())`.
- `structs.rs`: `JournalSuperblock`, `JournalBlockHeader`, `DescriptorTag`, `RevokeHeader`, `CommitHeader` parsing from `ffs-ondisk` journal types. Checksum validation for v3 tags (CRC32C per tag).

Dependency rationale: depends on `ffs-block` for `BlockDevice` trait
(reading/writing journal blocks and target blocks). Does NOT depend on
`ffs-mvcc` (avoids cycle; the mode switch is configured at mount time
in `ffs-core`).

**`ffs-mvcc`** (~4,500 LOC estimated)

Block-level MVCC engine -- the core concurrency innovation. Provides
Serializable Snapshot Isolation (SSI) at block granularity using the
Cahill-Rohm-Fekete algorithm adapted from database theory (Section 5).

Modules:
- `version_store.rs`: Arena-backed version chain storage. Each `BlockVersion { data: BlockBuf, commit_seq: CommitSeq, committed: bool, prev: Option<VersionIdx> }`. Chains ordered by `commit_seq` descending. `resolve(block, snapshot) -> BlockRef`: walk chain, return newest version with `commit_seq <= snapshot.high`, fall through to `BlockDevice` if no MVCC version exists. Lock-free readers via atomic `committed` flag.
- `transaction.rs`: `Transaction` struct. Fields: `id: TxnId`, `snapshot: Snapshot`, `read_set: HashSet<BlockNumber>` (blocks read), `write_set: HashMap<BlockNumber, VersionIdx>` (blocks written), `rw_antideps: Vec<(TxnId, BlockNumber)>` (SSI dependency tracking). Lifecycle: `Active -> Validating -> Committed | Aborted`.
- `sequencer.rs`: Global commit sequencer. Single `AtomicU64` for `CommitSeq` allocation. Serializes the commit critical section: (1) acquire sequencer lock (parking_lot Mutex, held <1us), (2) FCW check (target block committed version with `commit_seq > writer.snapshot.high` => abort), (3) SSI validation (check for dangerous rw-antidependency structures: if T1 reads X, T2 writes X, T2 committed after T1's snapshot => potential anomaly), (4) assign `CommitSeq`, (5) flip all write-set versions to `committed=true`, (6) release lock.
- `conflict.rs`: SSI conflict detection. Tracks `in_conflict(tx) -> bool` by maintaining rw-antidependency graph edges. A transaction T aborts if there exist T1, T2 such that T1 ->rw T ->rw T2 and both T1 and T2 are concurrent with T (the "dangerous structure" from Cahill-Rohm-Fekete). False positive rate ~2-5% under typical filesystem workloads (most conflicts are genuine write-write on same block).
- `gc.rs`: Garbage collection of old versions. Computes `gc_horizon = min(active_snapshot.high for all active transactions)`. Prunes version chain entries with `commit_seq < gc_horizon` EXCEPT the newest below horizon (MUST keep at least one committed version per block -- violation = data loss). GC is incremental: processes N blocks per invocation (default 1000), cooperative via `cx.checkpoint()`. Tracks: `versions_pruned`, `chains_compacted`, `blocks_freed`.
- `manager.rs`: `MvccBlockManager` trait implementation. `MvccEngine` struct tying together version store, sequencer, GC, and conflict detector. Statistics: `commit_count`, `abort_count`, `gc_runs`, `max_chain_depth`, `avg_chain_depth`.

Dependency rationale: depends on `ffs-block` for `BlockDevice` (reading
base versions of blocks not yet in version store); depends on `ffs-journal`
for mode coordination (journal must be replayed before MVCC begins);
`parking_lot` for internal synchronization (sequencer mutex, version store
RwLock).

**`ffs-btree`** (~2,500 LOC estimated)

ext4 extent B+tree operations. The extent tree maps logical file blocks to
physical device blocks via a B+tree rooted in the inode's `i_block[0..14]`
(60 bytes).

Modules:
- `search.rs`: Binary search within a B+tree node. For leaf nodes (depth==0): find extent containing target logical block or determine it falls in a hole. For index nodes (depth>0): find largest `ei_block <= target`, descend. Full tree traversal from root to leaf: O(depth) block reads, depth 0-2 typical (depth 0: <= 4 extents, depth 1: <= ~1360 extents at 4K blocks, depth 2: <= ~462,400 extents).
- `insert.rs`: Insert new extent into tree. If leaf has space (`eh_entries < eh_max`): insert in sorted order. If leaf full: split leaf (allocate new block, redistribute entries, insert index entry in parent). If parent full: split parent recursively up to root. If root full: grow tree (allocate new root, old root becomes child, increment depth). After insert: update `eh_entries` at each modified node, recompute extent tail checksums.
- `split.rs`: Node split logic. Leaf split: choose median, left half stays, right half to new block. Index split: similar. Root split: allocate two new blocks, move entries, root gets single index entry pointing to two children. Balances with neighbor nodes before splitting when possible (borrow 1-2 entries from sibling).
- `delete.rs`: Remove extent or range. Find extent covering target. If exact match: remove entry, shift remaining left. If partial overlap: truncate extent (adjust `ee_block`/`ee_len`/`ee_start`). If split required (hole punch in middle): split into two extents. After removal: if node underfull, merge with sibling or borrow from sibling. If tree depth > 0 and root has single child, shrink tree.
- `walk.rs`: Full tree iteration for fsck and dump. Depth-first traversal yielding all extents in logical order. Validates at each node: magic `0xF30A`, `eh_entries <= eh_max`, monotonically increasing logical blocks, no overlapping ranges, child block numbers within filesystem bounds.

Dependency rationale: depends on `ffs-block` for reading/writing extent tree
node blocks; depends on `ffs-ondisk` for `Ext4ExtentHeader`, `Ext4Extent`,
`Ext4ExtentIdx`, `Ext4ExtentTail` parsing.

**`ffs-alloc`** (~3,500 LOC estimated)

Block and inode allocation using mballoc-style multi-block allocator (buddy
system) and Orlov inode allocation strategy.

Modules:
- `buddy.rs`: Buddy allocator per block group. Maintains order-0 through order-13 free lists (order N = contiguous 2^N blocks). Allocation: find smallest order >= requested size, split down. Free: coalesce with buddy if free, promote to higher order. Bitmap-backed: each order level is a bitmap over aligned chunks. Lazy initialization from on-disk block bitmap on first access per group.
- `mballoc.rs`: Multi-block allocator coordinating across groups. Allocation strategy: (1) try goal group/block (from `AllocHint`), (2) if goal fails, try groups near goal (locality), (3) if locality fails, scan all groups for best fit (fewest fragments), (4) for large allocations (>8 blocks): prefer higher-order buddy entries for contiguity. Pre-allocation window: regular files get `prealloc_window` blocks (default 8) beyond requested; reclaimed on file close if unused.
- `orlov.rs`: Orlov inode allocator for directories and files. Directory creation: spread across groups (choose group with above-average free inodes AND free blocks, fewest directories -- reduces inter-group dependencies). File creation: co-locate with parent directory's group (maximize locality for files in same directory). Flex group awareness: when `FLEX_BG` enabled, allocation considers flex group boundaries (typically 16 groups). Returns `InodeAllocResult { ino, group }`.
- `bitmap.rs`: Block and inode bitmap management. `BlockBitmapManager`: read on-disk bitmap, allocate (set bit), free (clear bit), count free. `InodeBitmapManager`: same for inodes. Bitmap modifications are journaled (JBD2-compat) or versioned (MVCC-native). Lazy initialization: `BLOCK_UNINIT`/`INODE_UNINIT` group flags mean bitmap is all-zeros (all free); initialized on first allocation in group.
- `group_stats.rs`: Per-group free count tracking. Caches `free_blocks_count` and `free_inodes_count` in memory (loaded from group descriptors at mount). Updated on allocate/free. Periodically flushed to on-disk group descriptors. Used by mballoc and Orlov for group selection decisions.

Dependency rationale: depends on `ffs-block` for reading/writing bitmap
blocks and group descriptors; depends on `ffs-ondisk` for bitmap parsing
and group descriptor layout.

**`ffs-inode`** (~2,500 LOC estimated)

Inode management: CRUD operations, permission checks, timestamp updates,
inode flag handling.

Modules:
- `read.rs`: `read_inode(cx, ino) -> Ext4Inode`. Computes group and table offset from inode number (Section 11.3). Reads inode table block from ARC cache. Parses `Ext4Inode` via `ffs-ondisk`. Validates checksum if `METADATA_CSUM` enabled.
- `write.rs`: `write_inode(cx, ino, inode) -> Result<()>`. Serializes `Ext4Inode` to bytes, computes checksum, writes to inode table block. Block is marked dirty in ARC. MVCC: creates new version of inode table block.
- `create.rs`: `create_inode(cx, mode, uid, gid, parent_group) -> InodeNumber`. Allocates inode via `ffs-alloc` Orlov allocator. Initializes all fields: mode, uid/gid (with high extensions), links_count=1 (2 for dirs), timestamps to now, extent tree root (empty header with magic `0xF30A`, entries=0, max=4, depth=0). Writes to inode table.
- `delete.rs`: `delete_inode(cx, ino) -> Result<()>`. Zeroes inode on disk, frees inode number in bitmap via `ffs-alloc`. For files with data: extent tree walk to free all data blocks. For xattrs: free external xattr block.
- `permissions.rs`: POSIX permission checking. `check_access(inode, uid, gid, groups, requested) -> Result<()>`. Algorithm: root bypasses (except execute without any x bit), match owner/group/other, check requested bits. Sticky bit enforcement for directories. Setuid/setgid clearing on chown.
- `timestamps.rs`: Timestamp update helpers. `touch_atime(inode)` (respecting relatime/noatime), `touch_mtime_ctime(inode)`, `touch_ctime(inode)`. Nanosecond precision using `clock_gettime(CLOCK_REALTIME)`. Ext4 extra field encoding/decoding (34-bit seconds, 30-bit nanoseconds).

Dependency rationale: depends on `ffs-block` for reading/writing inode
table blocks via ARC cache; depends on `ffs-ondisk` for `Ext4Inode`
parsing and serialization.

**`ffs-dir`** (~3,000 LOC estimated)

Directory operations: entry lookup, creation, deletion, and htree (hashed
B-tree) indexing for large directories.

Modules:
- `linear.rs`: Linear (non-indexed) directory scan. Iterates `ext4_dir_entry_2` entries within directory data blocks. `lookup_linear(cx, dir_ino, name) -> Option<(InodeNumber, FileType)>`: scan all blocks until match. `iterate_linear(cx, dir_ino) -> Vec<DirEntry>`: collect all entries. Used for small directories (< ~10 entries) and as fallback.
- `htree.rs`: Hashed B-tree directory index (Section 11.5.2). `lookup_htree(cx, dir_ino, name) -> Option<(InodeNumber, FileType)>`: compute `dx_hash(name)`, binary search dx_entries in root/node blocks, read target leaf block, linear scan within leaf. `insert_htree(cx, dir_ino, entry)`: compute hash, find target leaf, insert entry; if leaf full, split leaf and insert new dx_entry in parent; if root full, convert to two-level htree. `delete_htree(cx, dir_ino, name)`: find and remove entry from leaf; merge empty leaves.
- `hash.rs`: dx_hash implementations per Section 11.5.2. `half_md4_hash(name, seed) -> DxHash`: MD4 compression function operating on 32-byte chunks, 3 rounds. `tea_hash(name, seed) -> DxHash`: Tiny Encryption Algorithm on 16-byte chunks, 16 rounds, delta `0x9E3779B9`. Both produce `(major & ~1, minor)` pair. Signed vs unsigned variants: signed treats bytes as `i8` with sign extension; unsigned as `u8`. Selection via `s_def_hash_version` superblock field.
- `entry.rs`: Directory entry CRUD. `add_entry(cx, dir_ino, name, target_ino, file_type)`: find block with space (scan existing blocks for gap in `rec_len`), or allocate new block. 4-byte alignment. `remove_entry(cx, dir_ino, name)`: merge `rec_len` with predecessor (or set `inode=0` if first entry). `ext4_dir_entry_2` checksum tail management.
- `init.rs`: Directory initialization for `mkdir`. Creates first block with `.` entry (pointing to self) and `..` entry (pointing to parent). If htree enabled and parent is indexed, initialize dx_root structure with hash_version from superblock `s_def_hash_version`, indirect_levels=0, initial dx_entry.

Dependency rationale: depends on `ffs-inode` for reading directory inode
metadata (size, block count); uses `xxhash-rust` as an internal fast hash
for cache keys (NOT for dx_hash -- dx_hash uses half_md4/tea per ext4 spec).

**`ffs-extent`** (~2,000 LOC estimated)

Logical-to-physical block mapping and extent-level allocation. Bridges
`ffs-btree` (tree operations) and `ffs-alloc` (block allocation).

Modules:
- `map.rs`: `map_logical_to_physical(cx, inode, logical_block, count) -> Vec<ExtentMapping>`. Each `ExtentMapping { logical_start, physical_start, count, unwritten }`. Walks extent B+tree via `ffs-btree::search`. Holes (unmapped ranges) reported as `ExtentMapping` with `physical_start = 0` and `count` = hole size.
- `allocate.rs`: `allocate_extent(cx, inode, logical_start, count) -> ExtentMapping`. Allocates `count` physical blocks via `ffs-alloc` with `AllocHint` goal set to physical block after inode's last extent (contiguity). Inserts extent into B+tree via `ffs-btree::insert`. Returns mapping. For pre-allocation: allocates extra blocks per `prealloc_window` but inserts extent only for requested range.
- `truncate.rs`: `truncate_extents(cx, inode, new_logical_end)`. Walks extent tree, removes extents beyond `new_logical_end`. Partial overlap: split extent at boundary, free blocks beyond split. Full overlap: remove entire extent, free all blocks. Updates inode `i_blocks`. Freed blocks returned to `ffs-alloc`.
- `punch.rs`: `punch_hole(cx, inode, logical_start, count)`. Removes block mappings in range without changing file size. Handles three cases: (1) extent fully within hole -- remove and free, (2) extent partially overlaps start -- truncate extent end, (3) extent partially overlaps end -- adjust extent start. May split one extent into two (hole in middle).
- `unwritten.rs`: Unwritten (uninitialized) extent handling. `mark_written(cx, inode, logical_start, count)`: clears the unwritten flag (bit 15 of `ee_len`) on extents in range. May require splitting extents at boundaries. Used by `fallocate` (mode=0 allocates unwritten) and first write to preallocated region.

Dependency rationale: depends on `ffs-btree` for extent tree operations;
depends on `ffs-alloc` for block allocation and deallocation.

**`ffs-xattr`** (~1,500 LOC estimated)

Extended attribute storage: inline (in inode extra space) and external
(in separate xattr block).

Modules:
- `inline.rs`: Inline xattr storage in inode body after core 128-byte fields, within `i_extra_isize` space. Packed header format: `{ name_index: u8, name_len: u8, value_offset: u16, value_size: u32 }`. Name indices: 1=user, 2=system.posix_acl_access, 3=system.posix_acl_default, 4=trusted, 6=security, 7=system. `get_inline(inode_bytes, name)`, `set_inline(inode_bytes, name, value)`, `list_inline(inode_bytes) -> Vec<XattrName>`, `remove_inline(inode_bytes, name)`.
- `external.rs`: External xattr block at `i_file_acl`. Single block per inode (shared via refcount). Header: `{ magic: 0xEA020000, refcount: u32, blocks: u32, hash: u32 }`. Entries similar to inline but at block granularity. `get_external(cx, block)`, `set_external(cx, block, name, value)`. Refcount management: decrement on unlink, free block when refcount reaches 0.
- `namespace.rs`: Namespace routing. `parse_xattr_name(full_name) -> (Namespace, &str)`. Permission checks per namespace: `user.*` requires file owner or CAP_FOWNER; `trusted.*` requires CAP_SYS_ADMIN; `security.*` requires CAP_SYS_ADMIN for write, policy-dependent for read; `system.*` kernel-managed.
- `limits.rs`: Size limits: max value size 65536 bytes; total inline capacity = `s_inode_size - 128 - i_extra_isize`; total external = block_size - header. `ENOSPC` if combined inline + external capacity exceeded. `ERANGE` if value exceeds max.

Dependency rationale: depends on `ffs-block` for reading/writing external
xattr blocks; depends on `ffs-ondisk` for xattr header and entry parsing.

**`ffs-fuse`** (~2,000 LOC estimated)

FUSE interface adapter. Implements `fuser::Filesystem` trait by delegating
to `FfsOperations` (Section 9.4). Contains zero filesystem logic -- pure
translation between FUSE protocol types and FrankenFS types.

Modules:
- `adapter.rs`: `FrankenFuseAdapter<T: FfsOperations>` struct. Implements all `fuser::Filesystem` callbacks: `lookup`, `getattr`, `setattr`, `read`, `write`, `readdir`, `readdirplus`, `create`, `mkdir`, `rmdir`, `unlink`, `rename`, `link`, `symlink`, `readlink`, `open`, `release`, `flush`, `fsync`, `statfs`, `mknod`, `fallocate`, `getxattr`, `setxattr`, `listxattr`, `removexattr`, `access`, `destroy`, `lseek`. Each callback: (1) creates `Cx` from FUSE request context (uid, gid, pid), (2) translates FUSE types to FrankenFS types, (3) calls corresponding `FfsOperations` method, (4) translates result to FUSE reply (including `FfsError -> errno` conversion via `ffs-error`).
- `handles.rs`: File handle table. Maps `u64` FUSE file handles to internal state: `HandleInfo { ino: InodeNumber, flags: OpenFlags, snapshot: Snapshot, tx: Option<TxHandle> }`. Handle allocation is atomic counter. Release frees the handle entry.
- `mount.rs`: Mount point setup. `mount(device_path, mount_point, options) -> Result<Session>`. Parses FUSE mount options (allow_other, default_permissions, auto_unmount, max_write=131072). Creates `fuser::Session` with `AutoUnmount` flag. Enter event loop (blocking; spawned in asupersync `Region`).
- `reply.rs`: Helper functions for FUSE reply construction. `inode_attr_to_fuse(attr: InodeAttr) -> fuser::FileAttr`. `file_type_to_fuse(ft: FileType) -> fuser::FileType`. TTL constants: attribute TTL = 1s (stale ok), entry TTL = 1s.

Dependency rationale: depends on `ffs-inode`, `ffs-dir`, `ffs-extent`,
`ffs-xattr` indirectly via `FfsOperations` trait; depends on `fuser`
for FUSE protocol handling. Does NOT directly depend on `ffs-block` or
`ffs-mvcc` -- all I/O is abstracted behind `FfsOperations`.

**`ffs-repair`** (~2,500 LOC estimated)

RaptorQ self-healing: per-block-group repair symbol generation, corruption
detection, and recovery.

Modules:
- `encoder.rs`: RaptorQ encoding via `asupersync`'s codec. `encode_group(cx, group) -> RepairSymbolSet`. Collects K source blocks from group's data region (excluding metadata), encodes R = ceil(K * overhead_ratio) repair symbols. Default overhead 5% (configurable at mount). Stores symbols in reserved blocks within the group (allocated from end of data region, tracked in per-group metadata).
- `decoder.rs`: RaptorQ decoding for recovery. `decode_block(cx, block, symbols) -> Result<BlockBuf>`. Given K' received blocks (intact) + R repair symbols, reconstructs erased blocks. Succeeds if K' + R >= K (with high probability per RFC 6330). After recovery: re-verify BLAKE3 hash of recovered block.
- `scrub.rs`: Background scrub engine. `scrub_all(cx, progress) -> ScrubReport`. Iterates all blocks across all groups. Per block: read, verify checksum (BLAKE3 native / CRC32C metadata). On failure: attempt RaptorQ recovery. On recovery: write back corrected block. On unrecoverable: log and report. Cooperative: `cx.checkpoint()` per block group, respects cancellation.
- `stale.rs`: Stale symbol tracking. `mark_stale(group)`: called by write path when any block in group is modified. `stale_groups() -> Vec<GroupNumber>`. Background re-encoding task processes stale groups during idle time. `is_current(group) -> bool`: checks BLAKE3 hash of group data matches stored hash in `RepairSymbolSet`.
- `storage.rs`: Repair symbol persistence. Symbols stored in reserved blocks at end of each block group. Per-group metadata: `{ source_block_count: u32, repair_symbol_count: u32, source_hash: [u8; 32], encoded_at: Timestamp, symbol_offsets: Vec<BlockNumber> }`. Metadata block has its own CRC32C checksum.

Dependency rationale: depends on `ffs-block` for reading/writing blocks;
depends on `asupersync` for RaptorQ codec (`Encoder`, `Decoder` types);
depends on `blake3` for content hashing.

**`ffs-core`** (~3,500 LOC estimated)

Engine integration: mount orchestration, format detection, configuration,
lifecycle management. Coordinates all internal crates into a coherent
filesystem engine.

Modules:
- `engine.rs`: `FrankenFsEngine` struct implementing `FfsOperations`. Holds references to all subsystem managers: `BlockDevice`, `ArcCache`, `MvccBlockManager`, `JournalManager`, `AllocPolicy`, `RepairManager`. Each `FfsOperations` method: (1) begin MVCC transaction, (2) perform operation using subsystem crates, (3) commit transaction, (4) on SSI conflict: retry with backoff (up to 3 attempts). Read-only operations skip transaction machinery.
- `mount.rs`: Mount sequence orchestration (Section 10.1 ten-step process). `mount(config: MountConfig) -> Result<FrankenFsEngine>`. Opens device, reads superblock, validates features, reads group descriptors, initializes ARC cache, replays JBD2 journal, initializes MVCC engine, initializes repair manager, starts background tasks, registers FUSE session.
- `unmount.rs`: `unmount(engine: FrankenFsEngine) -> Result<()>`. FUSE `destroy()` callback triggers: cancel background `Region` tasks, flush ARC dirty blocks, MVCC final GC (JBD2-compat: checkpoint), update superblock (`s_mnt_count++`, `s_wtime`), sync device, close.
- `config.rs`: `MountConfig` struct. Fields: `device_path: PathBuf`, `mount_point: PathBuf`, `read_only: bool`, `cache_size: usize` (bytes, default `min(RAM/4, 256MB)`), `journal_mode: JournalMode` (JBD2Compat, MvccNative, AutoDetect), `repair_overhead: f64` (0.0 to 0.5, default 0.05), `flush_interval: Duration`, `gc_interval: Duration`, `scrub_interval: Duration`, `atime_mode: AtimeMode` (Relatime, Noatime, Strictatime).
- `background.rs`: Background task management via asupersync `Region`-scoped tasks. Three tasks: (1) Scrub (default: 1 full pass per hour), (2) GC (default: every 30s), (3) Flush (default: every 5s or when dirty count exceeds 25% high watermark). Each task: loop with `cx.checkpoint()` + sleep.
- `format.rs`: Format detection. `detect_format(device) -> FormatInfo`. Reads bytes at offset 1024, checks ext4 magic `0xEF53`. Validates feature flags. Returns `FormatInfo { block_size, total_blocks, total_inodes, has_journal, is_64bit, features }`. Used by `ffs info` and mount validation.

Dependency rationale: depends on all `ffs-*` crates (orchestrates them);
depends on `asupersync` for `Region`, `Cx`, and `blocking_pool`.

**`ffs`** (~200 LOC estimated)

Public API facade. A thin crate that re-exports `ffs-core` types and
functions. Exists to provide a stable external interface: downstream
consumers (CLI, TUI, harness) depend on `ffs`, not individual internal
crates. This insulates them from internal refactoring.

Re-exports: `ffs_core::FrankenFsEngine`, `ffs_core::MountConfig`,
`ffs_core::mount`, `ffs_core::unmount`, `ffs_types::*` (all public types),
`ffs_error::{FfsError, Result}`.

**`ffs-cli`** (~1,500 LOC estimated)

CLI binary using `clap` derive. Subcommands:

- `ffs mount <device> <mountpoint> [OPTIONS]`: Mount filesystem. Options: `--ro`, `--cache-size`, `--journal-mode`, `--repair-overhead`, `--atime`, `--foreground`.
- `ffs fsck <device> [OPTIONS]`: Filesystem check (Section 14.1). Options: `--repair`, `--force`, `--verbose`, `--block-group`, `--json`.
- `ffs info <device> [OPTIONS]`: Filesystem information (Section 14.2). Options: `--groups`, `--mvcc`, `--repair`, `--journal`.
- `ffs repair <device> [OPTIONS]`: Manual repair trigger (Section 14.3). Options: `--full-scrub`, `--block-group`, `--rebuild-symbols`, `--verify-only`, `--max-threads`.
- `ffs dump <subcommand> <device>`: Low-level metadata dump (Section 14.4). Subcommands: `superblock`, `group`, `inode`, `extents`, `dir`. Options: `--json`, `--hex`.

Structured output: all subcommands support `--json` for machine-readable
output (via `serde_json`). Exit codes: 0=success, 1=error, 2=corruption-found
(fsck), 4=corruption-repaired (fsck --repair).

**`ffs-tui`** (~2,000 LOC estimated)

Terminal UI for live filesystem monitoring using `ftui` (frankentui). Four
dashboard panels:

- **Cache panel:** ARC hit/miss rates, T1/T2/B1/B2 list sizes, dirty block count, flush rate, eviction rate. Real-time bar chart of hit ratio over time.
- **MVCC panel:** Current `CommitSeq`, active transaction count, version chain statistics (total versioned blocks, max/avg depth), commit/abort rates, SSI conflict percentage.
- **Repair panel:** Coverage (groups with valid symbols / total), stale groups pending re-encode, last scrub timestamp, corruption detected/repaired/unrecoverable lifetime counts. Per-group status heat map.
- **I/O panel:** Read/write IOPS, throughput (MB/s), latency histogram (p50/p90/p99), outstanding I/O count. Breakdown by metadata vs data.

Refresh rate: 100ms. Keybindings: tab=switch panel, q=quit, s=force-scrub,
g=force-gc, f=force-flush.

**`ffs-harness`** (~3,000 LOC estimated)

Conformance testing and benchmarking harness.

Modules:
- `conformance.rs`: Compare FrankenFS behavior against reference ext4 images. Create ext4 image with `mkfs.ext4`, perform operations with kernel ext4, dump state. Mount same image with FrankenFS, perform same operations, compare results. Tests: file CRUD, directory operations, symlinks, hard links, xattrs, permissions, timestamps, large files, sparse files.
- `proptest.rs`: Property-based testing generators. `arb_inode()`, `arb_extent()`, `arb_dir_entry()`, `arb_superblock()` -- generate arbitrary valid on-disk structures. `arb_fs_operation()` -- generate random filesystem operation sequences. Shrinking support for minimal failure reproduction.
- `insta.rs`: Snapshot testing via `insta`. Golden fixtures for: `ffs dump superblock`, `ffs dump inode`, `ffs dump extents`, `ffs dump dir`. Ensures parser output stability across refactoring.
- `bench.rs`: Criterion benchmarks. Micro: single block read/write, ARC lookup, extent tree search, dx_hash computation, CRC32C/BLAKE3 per block. Macro: sequential 4K reads (throughput), random 4K writes (IOPS), metadata-heavy create/delete cycles, large file copy. Comparison against kernel ext4 via `fio` baselines.

Dependency rationale: depends on `ffs` (public facade) for all filesystem
operations; depends on `proptest`, `insta`, `tempfile`, `criterion` for
testing infrastructure. No production crate depends on `ffs-harness`.

---

## 9. Trait Hierarchy

All trait methods performing I/O accept `&Cx` for cancellation and budget
propagation. Types: `BlockNumber`, `InodeNumber`, `GroupNumber`, `TxnId`,
`CommitSeq`, `Snapshot`, `FileMode`, `Timestamp` from `ffs-types`; `Cx`
from `asupersync`; `Result<T>` is `ffs_error::Result<T>`.

### 9.1 BlockDevice (ffs-block)

```rust
pub struct BlockBuf { /* block-aligned, exactly block_size bytes */ }

pub trait BlockDevice: Send + Sync {
    fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf>;
    fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()>;
    fn block_size(&self) -> u32;
    fn block_count(&self) -> u64;
    fn sync(&self, cx: &Cx) -> Result<()>;

    fn read_blocks(&self, cx: &Cx, start: BlockNumber, count: u32) -> Result<Vec<BlockBuf>> {
        let mut bufs = Vec::with_capacity(count as usize);
        for i in 0..u64::from(count) {
            cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
            bufs.push(self.read_block(cx, BlockNumber(start.0 + i))?);
        }
        Ok(bufs)
    }

    fn write_blocks(&self, cx: &Cx, start: BlockNumber, data: &[&[u8]]) -> Result<()> {
        for (i, d) in data.iter().enumerate() {
            cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
            self.write_block(cx, BlockNumber(start.0 + i as u64), d)?;
        }
        Ok(())
    }

    fn discard(&self, _cx: &Cx, _start: BlockNumber, _count: u64) -> Result<()> { Ok(()) }
}
```

- `read_block` MUST verify CRC32C before returning; returns `FfsError::Corruption` on mismatch.
- `write_block` computes CRC32C (and BLAKE3 in native mode) before writing. `data` MUST be `block_size()` bytes.
- `read_blocks`/`write_blocks` default to loops; implementations SHOULD override for `preadv2`.
- `sync` flushes to stable storage (`fdatasync` equivalent).
- `discard` issues TRIM; no-op by default.

### 9.2 CachePolicy (ffs-block)

```rust
pub trait CachePolicy: Send + Sync {
    fn max_cached_blocks(&self) -> usize;             // default 16384 (64MB@4K)
    fn write_back(&self) -> bool;                     // true=async flush, false=write-through
    fn flush_interval(&self) -> Duration;             // default 5s
    fn dirty_high_watermark(&self) -> usize { self.max_cached_blocks() / 4 }
    fn read_ahead_enabled(&self) -> bool { true }
    fn read_ahead_window(&self) -> u32 { 32 }         // blocks
}
```

### 9.3 MvccBlockManager (ffs-mvcc)

```rust
pub struct GcStats {
    pub versions_pruned: u64,
    pub chains_compacted: u64,
    pub oldest_active_snapshot: CommitSeq,
    pub elapsed: Duration,
}

pub struct TxHandle {
    pub id: TxnId,
    pub snapshot: Snapshot,
    // internal: read_set, write_set, rw_antideps for SSI
}

pub trait MvccBlockManager: Send + Sync {
    fn begin_tx(&self, cx: &Cx) -> Result<TxHandle>;
    fn read_versioned(&self, cx: &Cx, tx: &TxHandle, block: BlockNumber) -> Result<BlockBuf>;
    fn write_versioned(&self, cx: &Cx, tx: &TxHandle, block: BlockNumber, data: &[u8]) -> Result<()>;
    fn commit(&self, cx: &Cx, tx: TxHandle) -> Result<CommitSeq>;
    fn abort(&self, cx: &Cx, tx: TxHandle) -> Result<()>;
    fn gc(&self, cx: &Cx) -> Result<GcStats>;
    fn current_commit_seq(&self) -> CommitSeq;
    fn active_transaction_count(&self) -> usize;
}
```

- `begin_tx`: allocate `TxnId`, snapshot at current `CommitSeq`.
- `read_versioned`: walk version chain, return newest with `commit_seq <= snapshot.high`. Falls through to `BlockDevice` if no MVCC version. Records in read set for SSI.
- `write_versioned`: create uncommitted version (visible only to this tx). Returns `MvccConflict` on write-write conflict.
- `commit`: (1) acquire sequencer, (2) FCW check, (3) SSI validation, (4) assign `CommitSeq` + set `committed=true`, or abort with `MvccConflict`.
- `abort`: discard uncommitted versions, release write locks.
- `gc`: prune below `min(active snapshot.high)`. MUST keep >= 1 version per block. Violation = silent corruption.

### 9.4 FfsOperations (ffs-core, called by ffs-fuse)

```rust
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

pub struct InodeAttr {
    pub ino: InodeNumber, pub size: u64, pub blocks: u64,
    pub atime: Timestamp, pub mtime: Timestamp, pub ctime: Timestamp, pub crtime: Timestamp,
    pub mode: FileMode, pub nlink: u32, pub uid: u32, pub gid: u32,
    pub rdev: u32, pub flags: u32, pub blksize: u32,
}
pub struct SetAttrRequest {
    pub mode: Option<FileMode>, pub uid: Option<u32>, pub gid: Option<u32>,
    pub size: Option<u64>, pub atime: Option<Timestamp>,
    pub mtime: Option<Timestamp>, pub flags: Option<u32>,
}
pub struct CreateReply { pub attr: InodeAttr, pub generation: u64, pub fh: u64, pub flags: u32 }
pub struct DirEntry { pub ino: InodeNumber, pub offset: u64, pub kind: FileType, pub name: Vec<u8> }
pub struct StatFs {
    pub blocks: u64, pub bfree: u64, pub bavail: u64,
    pub files: u64, pub ffree: u64, pub bsize: u32, pub namelen: u32, pub frsize: u32,
}
pub enum FileType { RegularFile, Directory, Symlink, CharDevice, BlockDevice, Fifo, Socket }

/// Implemented by FrankenFsEngine. Mutating ops wrapped in MVCC transactions.
pub trait FfsOperations: Send + Sync {
    fn lookup(&self, cx: &Cx, parent: InodeNumber, name: &OsStr) -> Result<InodeAttr>;
    fn getattr(&self, cx: &Cx, ino: InodeNumber) -> Result<InodeAttr>;
    fn setattr(&self, cx: &Cx, ino: InodeNumber, attrs: SetAttrRequest) -> Result<InodeAttr>;
    fn read(&self, cx: &Cx, ino: InodeNumber, offset: u64, size: u32) -> Result<Vec<u8>>;
    fn write(&self, cx: &Cx, ino: InodeNumber, offset: u64, data: &[u8]) -> Result<u32>;
    fn readdir(&self, cx: &Cx, ino: InodeNumber, offset: u64) -> Result<Vec<DirEntry>>;
    fn create(&self, cx: &Cx, parent: InodeNumber, name: &OsStr, mode: FileMode) -> Result<CreateReply>;
    fn mkdir(&self, cx: &Cx, parent: InodeNumber, name: &OsStr, mode: FileMode) -> Result<InodeAttr>;
    fn unlink(&self, cx: &Cx, parent: InodeNumber, name: &OsStr) -> Result<()>;
    fn rmdir(&self, cx: &Cx, parent: InodeNumber, name: &OsStr) -> Result<()>;
    fn rename(&self, cx: &Cx, parent: InodeNumber, name: &OsStr,
              new_parent: InodeNumber, new_name: &OsStr) -> Result<()>;
    fn link(&self, cx: &Cx, ino: InodeNumber, new_parent: InodeNumber, new_name: &OsStr) -> Result<InodeAttr>;
    fn symlink(&self, cx: &Cx, parent: InodeNumber, name: &OsStr, target: &Path) -> Result<InodeAttr>;
    fn readlink(&self, cx: &Cx, ino: InodeNumber) -> Result<PathBuf>;
    fn statfs(&self, cx: &Cx) -> Result<StatFs>;
    fn fsync(&self, cx: &Cx, ino: InodeNumber, datasync: bool) -> Result<()>;
    fn fallocate(&self, cx: &Cx, ino: InodeNumber, offset: u64, length: u64, mode: u32) -> Result<()>;
    fn getxattr(&self, cx: &Cx, ino: InodeNumber, name: &OsStr) -> Result<Vec<u8>>;
    fn setxattr(&self, cx: &Cx, ino: InodeNumber, name: &OsStr, value: &[u8], flags: u32) -> Result<()>;
    fn listxattr(&self, cx: &Cx, ino: InodeNumber) -> Result<Vec<Vec<u8>>>;
    fn removexattr(&self, cx: &Cx, ino: InodeNumber, name: &OsStr) -> Result<()>;
}
```

Semantics: `read` returns zeroes for holes. `write` extends file, returns bytes written. `create` allocates inode + dir entry. `mkdir` initializes `.`/`..`. `unlink` frees when nlink=0. `rmdir` returns `NotEmpty` if non-trivial. `rename` atomically replaces target. `link` returns `IsDirectory` for dirs. `symlink` inlines target <= 60B. `fallocate` creates unwritten extents.

### 9.5 RepairManager (ffs-repair)

```rust
pub struct RepairSymbolSet {
    pub group: GroupNumber,
    pub source_block_count: u32,
    pub repair_symbol_count: u32,
    pub symbols: Vec<u8>,
    pub source_hash: [u8; 32],
    pub encoded_at: Timestamp,
}

pub enum RecoveryResult {
    Recovered { block: BlockNumber, recovered_hash: [u8; 32] },
    NotCorrupt { block: BlockNumber },
    Failed { block: BlockNumber, reason: String },
}

pub trait ScrubProgress: Send + Sync {
    fn on_group_complete(&self, group: GroupNumber, corruptions_found: u32);
    fn on_block_repaired(&self, block: BlockNumber);
    fn on_block_repair_failed(&self, block: BlockNumber, reason: &str);
}

pub struct ScrubReport {
    pub groups_scrubbed: u32, pub blocks_verified: u64,
    pub corruptions_detected: u32, pub corruptions_repaired: u32,
    pub corruptions_unrecoverable: u32, pub symbols_refreshed: u32,
    pub elapsed: Duration,
}

pub trait RepairManager: Send + Sync {
    fn generate_symbols(&self, cx: &Cx, group: GroupNumber) -> Result<RepairSymbolSet>;
    fn recover_block(&self, cx: &Cx, block: BlockNumber) -> Result<RecoveryResult>;
    fn scrub(&self, cx: &Cx, progress: &dyn ScrubProgress) -> Result<ScrubReport>;
    fn refresh_symbols(&self, cx: &Cx, block: BlockNumber) -> Result<()>;
    fn stale_group_count(&self) -> u32;
    fn is_group_current(&self, group: GroupNumber) -> bool;
}
```

- `generate_symbols`: encode K source blocks via RaptorQ, store R repair symbols. Overhead R/K configured at mount (default 5%). Idempotent (no-op if `source_hash` matches).
- `recover_block`: verify bad checksum, load symbols, verify BLAKE3 integrity, decode if K'+R >= K, verify recovered checksum, write back.
- `scrub`: verify all blocks across all groups, repair corruptions, re-encode stale symbols. Cooperative via `cx.checkpoint()`.
- `refresh_symbols`: mark group stale after write. MUST be O(1) -- on write critical path, MUST NOT encode.

### 9.6 AllocPolicy (ffs-alloc)

```rust
pub struct AllocHint {
    pub goal_group: Option<GroupNumber>, pub goal_block: Option<BlockNumber>,
    pub prealloc: bool, pub prealloc_window: u32,
}
pub struct AllocResult { pub start: BlockNumber, pub count: u32, pub group: GroupNumber }
pub struct InodeAllocResult { pub ino: InodeNumber, pub group: GroupNumber }

pub trait AllocPolicy: Send + Sync {
    fn allocate_blocks(&self, cx: &Cx, count: u32, hint: &AllocHint) -> Result<AllocResult>;
    fn free_blocks(&self, cx: &Cx, start: BlockNumber, count: u32) -> Result<()>;
    fn allocate_inode(&self, cx: &Cx, parent_group: GroupNumber, is_dir: bool) -> Result<InodeAllocResult>;
    fn free_inode(&self, cx: &Cx, ino: InodeNumber) -> Result<()>;
    fn free_block_count(&self) -> u64;
    fn free_inode_count(&self) -> u64;
    fn group_free_blocks(&self, group: GroupNumber) -> u32;
    fn group_free_inodes(&self, group: GroupNumber) -> u32;
}
```

- `allocate_blocks`: mballoc buddy system. MAY return fewer than requested. Returns `NoSpace` if full.
- `allocate_inode`: Orlov -- directories spread across groups, files co-locate with parent.
- `free_blocks`/`free_inode`: clear bitmaps, update group descriptors, merge buddies.

### 9.7 JournalManager (ffs-journal)

```rust
pub struct JournalTxHandle { pub sequence: u32, pub reserved_blocks: u32, pub used_blocks: u32 }
pub struct ReplayReport {
    pub transactions_found: u32, pub transactions_replayed: u32,
    pub blocks_recovered: u64, pub blocks_revoked: u64, pub was_clean: bool,
}
pub struct CheckpointReport {
    pub transactions_checkpointed: u32, pub blocks_written: u64, pub space_reclaimed: u32,
}

pub trait JournalManager: Send + Sync {
    fn replay(&self, cx: &Cx) -> Result<ReplayReport>;
    fn begin_transaction(&self, cx: &Cx, reserved_blocks: u32) -> Result<JournalTxHandle>;
    fn journal_block(&self, cx: &Cx, tx: &JournalTxHandle, block: BlockNumber, data: &[u8]) -> Result<()>;
    fn revoke_block(&self, cx: &Cx, tx: &JournalTxHandle, block: BlockNumber) -> Result<()>;
    fn commit_transaction(&self, cx: &Cx, tx: JournalTxHandle) -> Result<()>;
    fn checkpoint(&self, cx: &Cx) -> Result<CheckpointReport>;
    fn journal_sequence(&self) -> u32;
    fn journal_free_blocks(&self) -> u32;
    fn needs_replay(&self) -> bool;
}
```

Supports two modes: **JBD2-compat** (full journal lifecycle) and **native COW** (replay only; `begin_transaction`/`journal_block`/`commit_transaction`/`checkpoint` are no-ops since MVCC handles consistency).

- `replay`: MUST be called before any FS operations on mount. No-op if clean (`s_start == 0`). Scans descriptor+commit pairs, replays in sequence order, tracks revoked blocks.
- `journal_block`: copies block data into journal area (JBD2-compat) for crash replay.
- `revoke_block`: marks freed block; skipped during replay even if in earlier transactions.
- `checkpoint`: flush committed journal entries to final on-disk locations, reclaim space.

### 9.8 Trait Dependency Summary

```
  FfsOperations  (filesystem semantics)
       │ uses
  ┌────┼────────────┐
  │    │            │
AllocPolicy  MvccBlockMgr  JournalMgr
  └────┼────────────┘
       │
  BlockDevice + CachePolicy  (raw I/O)
       │
  RepairManager  (orthogonal; notified by write path)
```

`RepairManager` is outside the main call chain -- it reads/writes blocks
and is notified by the write path, but does not participate in filesystem
operations. This ensures repair can be tested, disabled, or reconfigured
without affecting correctness.
## 10. Filesystem Operations Pipeline

### 10.1 Mount Sequence

Each phase MUST complete before the next begins; failure is fatal.

1. **Open device** (`ffs-block`): `O_RDWR` (or `O_RDONLY` if `--ro`). Validate alignment to 512.
2. **Read superblock** (`ffs-ondisk`): 1024 bytes at offset 1024. Verify magic `0xEF53`. Compute `block_size = 1024 << s_log_block_size`.
3. **Validate features** (`ffs-ext4`): Parse compat/incompat/ro_compat flags. Reject unsupported INCOMPAT. Read-only if unknown RO_COMPAT.
4. **Read group descriptors** (`ffs-ondisk`): `ceil(blocks_count/blocks_per_group)` descriptors, 32 or 64 bytes. Verify checksums.
5. **Init ARC cache** (`ffs-block`): Four-list ARC (T1/T2/B1/B2). Default capacity: `min(RAM/4, 256MB)`. Pre-warm SB + GDT + root inode.
6. **Replay JBD2** (`ffs-journal`): If `COMPAT_HAS_JOURNAL` and dirty (`s_start != 0`): scan, apply, revoke, mark clean. See 11.6.
7. **Init MVCC** (`ffs-mvcc`): `CommitSeq(1)`, `TxnId(1)`. Native `--mvcc`: per-block version chains. JBD2-compat: single-writer mutex.
8. **Init repair** (`ffs-repair`): Scan per-group reserved blocks for RaptorQ metadata. Mark missing groups for re-encoding.
9. **Background tasks** (`ffs-core`): Three `Region`-scoped: Scrub (1 pass/hr), GC (30s), Flush (5s or 25% dirty).
10. **Register FUSE** (`ffs-fuse`): `fuser::Session` with `AutoUnmount`, `DefaultPermissions`. `max_write=128KiB`. Enter event loop.

**Unmount:** destroy() -> cancel Regions -> flush ARC -> MVCC: final GC / JBD2: checkpoint -> update superblock (s_mnt_count++, s_wtime) -> sync + close.

```rust
/// Mount sequence pseudocode (illustrative, not normative).
pub fn mount(cx: &Cx, config: MountConfig) -> Result<FrankenFsEngine> {
    // 1. Open device
    let device = FileBlockDevice::open(cx, &config.device_path, config.read_only)?;

    // 2. Read and validate superblock
    let sb_block = device.read_block(cx, BlockNumber(0))?; // block 0 at 4K, or offset 1024
    let sb_bytes: &[u8; 1024] = &sb_block.as_ref()[1024..2048].try_into()?;
    let sb = Ext4Superblock::parse(sb_bytes)?;
    sb.validate()?; // magic 0xEF53, checksum, geometry
    let block_size = 1024u32 << sb.s_log_block_size.get();

    // 3. Feature validation
    let features = FeatureSet::from_superblock(&sb);
    features.reject_unsupported_incompat()?;
    let read_only = config.read_only || features.has_unknown_ro_compat();

    // 4. Read group descriptors
    let group_count = sb.groups_count();
    let gdt_blocks = (group_count as u64 * u64::from(sb.desc_size()) + u64::from(block_size) - 1)
        / u64::from(block_size);
    let gdt_start = if block_size == 1024 { BlockNumber(2) } else { BlockNumber(1) };
    let gdt = device.read_blocks(cx, gdt_start, gdt_blocks as u32)?;
    let groups = Ext4GroupDesc::parse_all(&gdt, sb.desc_size(), group_count)?;
    for (i, g) in groups.iter().enumerate() {
        g.validate_checksum(sb.checksum_seed(), i as u32)?;
    }

    // 5. Initialize ARC cache
    let cache_capacity = config.cache_size.unwrap_or_else(|| {
        std::cmp::min(system_ram() / 4, 256 * 1024 * 1024)
    });
    let arc = ArcCache::new(cache_capacity / block_size as usize, block_size);

    // 6. Replay JBD2 if needed
    let journal = if features.has_journal() {
        let jm = Jbd2JournalManager::new(&device, &sb);
        if jm.needs_replay() {
            let report = jm.replay(cx)?;
            tracing::info!(txns = report.transactions_replayed, "journal replayed");
        }
        Some(jm)
    } else { None };

    // 7. Initialize MVCC
    let mvcc = match config.journal_mode {
        JournalMode::MvccNative => MvccEngine::new_native(&device, &arc),
        JournalMode::Jbd2Compat => MvccEngine::new_jbd2_compat(&device, &arc, journal.as_ref()),
        JournalMode::AutoDetect => MvccEngine::new_auto(&device, &arc, journal.as_ref()),
    };

    // 8. Initialize repair
    let repair = RepairEngine::new(cx, &device, &groups, config.repair_overhead)?;

    // 9. Background tasks (asupersync Region-scoped)
    let region = Region::new();
    region.spawn("scrub", |cx| loop { repair.scrub(&cx)?; cx.sleep(config.scrub_interval)?; });
    region.spawn("gc", |cx| loop { mvcc.gc(&cx)?; cx.sleep(config.gc_interval)?; });
    region.spawn("flush", |cx| loop { arc.flush_dirty(&cx)?; cx.sleep(config.flush_interval)?; });

    // 10. Assemble engine
    Ok(FrankenFsEngine { device, sb, groups, arc, journal, mvcc, repair, region, read_only })
}
```

### 10.2 Read Path

MUST be lock-free for readers, allocation-free on cache hit, bounded latency.

```
FUSE read(ino, offset, size)
  --> ffs-fuse: validate, translate ino
  --> ffs-mvcc: begin_read_txn() -> Snapshot { high: current_commit_seq }
  --> ffs-inode: resolve_inode(ino, snapshot)
        ARC lookup for inode table block, parse Ext4Inode, permission check
  --> ffs-extent: map_logical_to_physical(inode, offset, size)
        Walk extent B+tree (depth 0: binary search leaves; depth>0: descend)
        Return [(phys_block, offset_in_block, bytes)]; holes -> zeroes
  --> ffs-block: read_blocks(phys_blocks, snapshot)
        Per block: ARC probe -> HIT: return ref; MISS: pread64 via blocking_pool,
        verify checksum (CRC32C/BLAKE3), on fail: RaptorQ recover, insert ARC T1
        MVCC mode: resolve version chain per snapshot
  --> ffs-fuse: assemble, truncate to min(size, file_size - offset), return to FUSE
```

| Property | Requirement |
|----------|------------|
| Lock contention | Zero (snapshot is a `CommitSeq` copy) |
| Allocations (cache hit) | Zero (ref to ARC block) |
| Extent tree descent | O(depth) reads; depth 0-2 typical |
| Prefetch | If extent spans consecutive blocks, readahead next N |

**atime:** `relatime` default (update only if `atime < mtime` or `atime < ctime` or >24h old). `noatime`: no update. `strictatime`: write txn for every read.

### 10.3 Write Path

Every write MUST be in an MVCC transaction with COW semantics (native mode).

```
FUSE write(ino, offset, data)
  --> ffs-fuse: validate, translate ino
  --> ffs-mvcc: begin_write_txn() -> Transaction { id, snapshot }
        JBD2-compat: acquire global write mutex first
  --> ffs-inode: resolve_inode(ino, snapshot), check write permission
  --> ffs-extent: map_logical_to_physical(inode, offset, len)
  --> ffs-alloc: allocate_blocks(needed) [if new blocks needed]
        mballoc: prealloc -> goal -> best-fit. Update bitmap + group desc.
  --> ffs-mvcc + ffs-block: write_blocks_cow(blocks, data)
        MVCC: new phys location, BlockVersion(committed=false). JBD2: in-place.
        Compute checksum. Dirty in ARC. Track in write set.
  --> ffs-btree: update_extent_tree() [if new extents; split on overflow, COW]
  --> ffs-inode: update i_size/i_mtime/i_ctime/i_blocks
  --> ffs-mvcc: commit_transaction()
        FCW: latest_commit > snapshot.high -> ABORT
        SSI: incoming+outgoing rw-antidep -> ABORT
        Assign CommitSeq, set committed=true, publish to chain heads
  --> ffs-repair: mark_groups_stale(affected groups)
  --> Return bytes_written
```

```rust
/// Write path pseudocode (illustrative, not normative).
fn write_impl(engine: &FrankenFsEngine, cx: &Cx, ino: InodeNumber,
              offset: u64, data: &[u8]) -> Result<u32> {
    let block_size = engine.sb.block_size() as u64;
    let mut retries = 0;
    loop {
        let tx = engine.mvcc.begin_tx(cx)?;
        let inode = engine.read_inode_versioned(cx, &tx, ino)?;
        inode.check_write_permission(cx)?;

        // Map logical blocks needed for this write
        let first_logical = offset / block_size;
        let last_logical = (offset + data.len() as u64 - 1) / block_size;
        let mut bytes_written = 0u32;

        for logical in first_logical..=last_logical {
            cx.checkpoint().map_err(|_| FfsError::Cancelled)?;

            // Determine byte range within this block
            let blk_start = if logical == first_logical { (offset % block_size) as usize } else { 0 };
            let blk_end = if logical == last_logical {
                ((offset + data.len() as u64 - 1) % block_size) as usize + 1
            } else { block_size as usize };

            // Map logical to physical (may return hole)
            let mapping = engine.extent_map(cx, &tx, &inode, logical)?;
            let phys_block = if mapping.is_hole() {
                // Allocate new block
                let hint = AllocHint {
                    goal_group: Some(inode.group()),
                    goal_block: inode.last_extent_end(),
                    prealloc: true, prealloc_window: 8,
                };
                let alloc = engine.alloc.allocate_blocks(cx, 1, &hint)?;
                engine.btree_insert_extent(cx, &tx, &inode, logical, alloc.start, 1)?;
                alloc.start
            } else { mapping.physical_start };

            // Read-modify-write for partial blocks
            let mut block_data = if blk_start > 0 || blk_end < block_size as usize {
                engine.mvcc.read_versioned(cx, &tx, phys_block)?.to_vec()
            } else {
                vec![0u8; block_size as usize]
            };

            // Copy user data into block
            let data_offset = (logical - first_logical) as usize * block_size as usize
                + blk_start - (offset % block_size) as usize;
            let copy_len = blk_end - blk_start;
            block_data[blk_start..blk_end]
                .copy_from_slice(&data[data_offset..data_offset + copy_len]);
            bytes_written += copy_len as u32;

            // Write versioned block (COW)
            engine.mvcc.write_versioned(cx, &tx, phys_block, &block_data)?;
        }

        // Update inode metadata
        let new_size = std::cmp::max(inode.size(), offset + data.len() as u64);
        engine.update_inode_size_and_timestamps(cx, &tx, ino, new_size)?;

        // Commit
        match engine.mvcc.commit(cx, tx) {
            Ok(commit_seq) => {
                // Mark affected groups stale for RaptorQ re-encoding
                engine.repair.mark_groups_stale_for_range(first_logical, last_logical);
                return Ok(bytes_written);
            }
            Err(FfsError::MvccConflict { .. }) if retries < 3 => {
                retries += 1;
                let backoff = [Duration::ZERO, Duration::from_micros(100),
                               Duration::from_millis(1)];
                std::thread::sleep(backoff[retries - 1]);
                continue;
            }
            Err(e) => return Err(e),
        }
    }
}
```

**Abort/retry:** Discard versions, return blocks. Retry 3x (backoff: 0, 100us, 1ms). `EAGAIN` on exhaustion.

**fsync:** Flush dirty ARC pages for inode to disk. `fdatasync()/fsync()`. `--eager-repair`: blocking RaptorQ re-encode.

### 10.4 Directory Operations

All wrapped in write transactions. Htree index updated for large directories.

**create(parent, name, mode):** Write txn -> `allocate_inode()` (Orlov: same group as parent) -> `initialize_inode()` (mode, timestamps, empty extent header: `eh_magic=0xF30A, entries=0, max=4, depth=0`) -> `add_directory_entry()` (linear: gap/append; htree: hash, insert, split) -> update parent mtime/ctime -> commit.

**mkdir:** Like create + `S_IFDIR` mode, `links_count=2`, parent `links++`, init `.`/`..`, alloc one data block.

**unlink:** Write txn -> lookup -> verify not dir -> remove entry (inode=0, merge rec_len) -> decrement links (if 0: free blocks + inode) -> commit.

**rmdir:** Like unlink + verify empty, decrement parent links. `ENOTEMPTY` if non-empty.

**rename:** Write txn -> lookup old -> if new exists: validate types, remove -> remove old, add new -> if dir: update `..`, adjust links -> commit. `RENAME_NOREPLACE`: `EEXIST`. `RENAME_EXCHANGE`: atomic swap.

### 10.5 Metadata Operations

**getattr:** Read txn. Resolve inode. Map to `fuser::FileAttr`.

**setattr:** Write txn. Apply mode/uid/gid/size/atime/mtime. Truncate: free blocks. Always update ctime. Commit.

**statfs:** No txn. Cached superblock: bsize, blocks, bfree, bavail=free-reserved, files, ffree, namemax=255.

### 10.6 Symlink, Readlink, Link

**symlink:** Write txn. Alloc inode. If `target.len() <= 60`: store in `i_block[]` (fast symlink). Else: alloc data block + extent. Add dir entry. Commit.

**readlink:** Read txn. If `i_blocks==0 && i_size<=60`: read `i_block[]`. Else: extent tree.

**link:** Write txn. Verify not dir. Increment `links_count`, update `ctime`. Add dir entry. Commit.

### 10.7 Error Mapping

| FfsError (canonical) | errno | Condition |
|----------|-------|-----------|
| `Io` | `EIO` | Device I/O error |
| `Corruption` | `EIO` | Checksum mismatch / metadata corruption |
| `Format` | `EINVAL` | Invalid on-disk format |
| `MvccConflict` | `EAGAIN` | FCW/SSI conflict (retries exhausted) |
| `Cancelled` | `EINTR` | Cx cancellation |
| `NoSpace` | `ENOSPC` | Allocation failed |
| `NotFound` | `ENOENT` | Inode/entry missing |
| `PermissionDenied` | `EACCES` | Insufficient permission |
| `NotDirectory` | `ENOTDIR` | Expected dir |
| `IsDirectory` | `EISDIR` | File op on dir |
| `NotEmpty` | `ENOTEMPTY` | rmdir non-empty |
| `NameTooLong` | `ENAMETOOLONG` | Name > 255 bytes |
| `Exists` | `EEXIST` | Entry exists (O_EXCL) |
| `RepairFailed` | `EIO` | RaptorQ recovery failed |

> **Note:** This is the canonical 14-variant FfsError. Earlier revisions listed
> non-existent variants (`AlreadyExists`, `DirectoryNotEmpty`, `ReadOnly`,
> `TooManyLinks`, `SsiConflict`, `IoError`). See `ffs-error/src/lib.rs` for the
> normative definition.

---

## 11. On-Disk Format Compatibility

All multi-byte fields are **little-endian**. Offsets relative to structure start unless noted.

### 11.1 ext4 Superblock

Located at byte offset 1024 from device start, length 1024 bytes. Fixed location regardless of block size.

#### 11.1.1 Field Table

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| `0x000` | 4 | `s_inodes_count` | Total inode count |
| `0x004` | 4 | `s_blocks_count_lo` | Total blocks (low 32) |
| `0x008` | 4 | `s_r_blocks_count_lo` | Reserved blocks (low 32) |
| `0x00C` | 4 | `s_free_blocks_count_lo` | Free blocks (low 32) |
| `0x010` | 4 | `s_free_inodes_count` | Free inodes |
| `0x014` | 4 | `s_first_data_block` | First data block (0 for 4K, 1 for 1K) |
| `0x018` | 4 | `s_log_block_size` | Block size = `1024 << value` |
| `0x01C` | 4 | `s_log_cluster_size` | Cluster size (bigalloc) |
| `0x020` | 4 | `s_blocks_per_group` | Blocks per group |
| `0x024` | 4 | `s_clusters_per_group` | Clusters per group |
| `0x028` | 4 | `s_inodes_per_group` | Inodes per group |
| `0x02C` | 4 | `s_mtime` | Last mount time |
| `0x030` | 4 | `s_wtime` | Last write time |
| `0x034` | 2 | `s_mnt_count` | Mount count since fsck |
| `0x036` | 2 | `s_max_mnt_count` | Max mounts before fsck |
| `0x038` | 2 | `s_magic` | **`0xEF53`** |
| `0x03A` | 2 | `s_state` | 1=clean, 2=errors, 4=orphans |
| `0x03C` | 2 | `s_errors` | 1=continue, 2=ro, 3=panic |
| `0x03E` | 2 | `s_minor_rev_level` | Minor revision |
| `0x040` | 4 | `s_lastcheck` | Last fsck time |
| `0x044` | 4 | `s_checkinterval` | Max time between fscks |
| `0x048` | 4 | `s_creator_os` | Creator OS (0=Linux) |
| `0x04C` | 4 | `s_rev_level` | 0=original, 1=dynamic |
| `0x050` | 2 | `s_def_resuid` | Default reserved UID |
| `0x052` | 2 | `s_def_resgid` | Default reserved GID |
| `0x054` | 4 | `s_first_ino` | First non-reserved inode (typically 11) |
| `0x058` | 2 | `s_inode_size` | Inode size (128 or 256) |
| `0x05A` | 2 | `s_block_group_nr` | Block group of this SB copy |
| `0x05C` | 4 | `s_feature_compat` | Compatible features |
| `0x060` | 4 | `s_feature_incompat` | Incompatible features |
| `0x064` | 4 | `s_feature_ro_compat` | Read-only compatible features |
| `0x068` | 16 | `s_uuid` | 128-bit UUID |
| `0x078` | 16 | `s_volume_name` | Volume label (NUL-padded) |
| `0x088` | 64 | `s_last_mounted` | Last mount path |
| `0x0C8`-`0x0CD` | 6 | `s_algorithm_usage_bitmap`, `s_prealloc_*` | Compression (unused), file/dir prealloc blocks |
| `0x0CE` | 2 | `s_reserved_gdt_blocks` | Reserved GDT blocks for resize |
| `0x0D0` | 16 | `s_journal_uuid` | Journal UUID |
| `0x0E0` | 4 | `s_journal_inum` | Journal inode (typically 8) |
| `0x0E4` | 4 | `s_journal_dev` | Journal device (0=internal) |
| `0x0E8` | 4 | `s_last_orphan` | Head of orphan list |
| `0x0EC` | 16 | `s_hash_seed` | htree hash seed (4 x u32) |
| `0x0FC` | 1 | `s_def_hash_version` | 0=legacy, 1=half_md4, 2=tea, 3-5=unsigned |
| `0x0FE` | 2 | `s_desc_size` | Group desc size (32 or 64) |
| `0x100` | 4 | `s_default_mount_opts` | Default mount options |
| `0x104` | 4 | `s_first_meta_bg` | First meta block group |
| `0x108` | 4 | `s_mkfs_time` | Creation time |
| `0x10C` | 68 | `s_jnl_blocks` | Journal inode backup (17 x u32) |
| `0x150` | 4 | `s_blocks_count_hi` | Total blocks (high 32; `INCOMPAT_64BIT`) |
| `0x154` | 4 | `s_r_blocks_count_hi` | Reserved blocks (high 32) |
| `0x158` | 4 | `s_free_blocks_count_hi` | Free blocks (high 32) |
| `0x15C` | 2+2 | `s_min_extra_isize`, `s_want_extra_isize` | Min/desired extra inode size |
| `0x160` | 4 | `s_flags` | Misc flags |
| `0x164`-`0x16F` | 12 | `s_raid_stride`, `s_mmp_*` | RAID stride, MMP interval + block |
| `0x170` | 4 | `s_raid_stripe_width` | RAID stripe width |
| `0x174` | 1 | `s_log_groups_per_flex` | Flex group size = `2^value` |
| `0x175` | 1 | `s_checksum_type` | 1=crc32c |
| `0x178` | 8 | `s_kbytes_written` | Lifetime KB written |
| `0x180`-`0x193` | 20 | `s_snapshot_*` | Snapshot inode, ID, reserved blocks, list head |
| `0x194` | 4 | `s_error_count` | Error count |
| `0x198`-`0x1FF` | 104 | `s_first_error_*`, `s_last_error_*` | Error tracking: time, inode, block, func, line (first + last) |
| `0x200` | 64 | `s_mount_opts` | Mount options string |
| `0x240` | 4 | `s_usr_quota_inum` | User quota inode |
| `0x244` | 4 | `s_grp_quota_inum` | Group quota inode |
| `0x248` | 4 | `s_overhead_blocks` | Overhead blocks |
| `0x24C` | 8 | `s_backup_bgs` | Backup SB groups (sparse_super2) |
| `0x254`-`0x267` | 20 | `s_encrypt_*` | Encryption algorithms + salt |
| `0x268` | 4 | `s_lpf_ino` | lost+found inode |
| `0x26C` | 4 | `s_prj_quota_inum` | Project quota inode |
| `0x270` | 4 | `s_checksum_seed` | CRC32C seed (CRC32C of UUID if `INCOMPAT_CSUM_SEED`) |
| `0x274`-`0x27B` | 8 | `s_*_hi`, pad | High 8 bits of timestamps (wtime, mtime, mkfs, lastcheck, errors) + padding |
| `0x27C` | 4 | `s_encoding` | Filename encoding (casefold) |
| `0x280` | 4 | `s_encoding_flags`/`s_orphan_file_inum` | Encoding flags (2) + orphan inode (2) |
| `0x284` | 376 | `s_reserved` | Zero-filled |
| `0x3FC` | 4 | `s_checksum` | Superblock CRC32C |

**Total: 1024 bytes (0x400).**

**Checksum:** CRC32C of bytes `0x000..0x3FB` with `s_checksum_seed` as initial value (set `s_checksum=0` before computing).

**Backup locations:** First block of groups that are powers of 3, 5, or 7 (groups 1, 3, 5, 7, 9, 25, 27, ...) when `SPARSE_SUPER` enabled.

#### 11.1.2 Block Size

`block_size = 1024 << s_log_block_size`. The ext4 on-disk format allows 0 (1K)
through 6 (64K). **FrankenFS v1 support is currently 0..=2 (1K, 2K, 4K)**;
larger values are treated as unsupported until explicitly implemented.

#### 11.1.3 Feature Flags

**Incompatible (`s_feature_incompat` at `0x60`) -- unknown = mount MUST fail:**

REQUIRED: `FILETYPE`(0x0002), `EXTENTS`(0x0040).
Supported: `RECOVER`(0x0004), `META_BG`(0x0010), `64BIT`(0x0080), `FLEX_BG`(0x0200), `EA_INODE`(0x0400), `CSUM_SEED`(0x2000), `LARGEDIR`(0x4000).
Ignored: `MMP`(0x0100, warn), `DIRDATA`(0x1000).
REJECTED: `COMPRESSION`(0x0001), `JOURNAL_DEV`(0x0008), `INLINE_DATA`(0x8000), `ENCRYPT`(0x10000), `CASEFOLD`(0x20000).

**Compatible (`s_feature_compat` at `0x5C`) -- advisory, safe to ignore:**

Supported: `HAS_JOURNAL`(0x0004), `EXT_ATTR`(0x0008), `DIR_INDEX`(0x0020), `SPARSE_SUPER2`(0x0200), `ORPHAN_FILE`(0x1000).

**Read-only compatible (`s_feature_ro_compat` at `0x64`) -- unknown = mount read-only:**

Supported: `SPARSE_SUPER`(0x0001), `LARGE_FILE`(0x0002), `HUGE_FILE`(0x0008), `GDT_CSUM`(0x0010), `DIR_NLINK`(0x0020), `EXTRA_ISIZE`(0x0040), `METADATA_CSUM`(0x0400), `READONLY`(0x1000), `ORPHAN_PRESENT`(0x8000).

#### 11.1.4 64-bit Mode

If `INCOMPAT_64BIT`: `s_desc_size >= 64`, block counts combine lo|hi<<32, group descriptors are 64 bytes. Otherwise: 32-byte descriptors, 32-bit counts, max 16 TB at 4K.

### 11.2 Group Descriptors

Located at the block after the superblock block. Count = `ceil(s_blocks_count / s_blocks_per_group)`.

#### 11.2.1 Standard (32 bytes)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| `0x00` | 4 | `bg_block_bitmap_lo` | Block bitmap block |
| `0x04` | 4 | `bg_inode_bitmap_lo` | Inode bitmap block |
| `0x08` | 4 | `bg_inode_table_lo` | Inode table start |
| `0x0C` | 2 | `bg_free_blocks_count_lo` | Free blocks |
| `0x0E` | 2 | `bg_free_inodes_count_lo` | Free inodes |
| `0x10` | 2 | `bg_used_dirs_count_lo` | Directory count |
| `0x12` | 2 | `bg_flags` | `INODE_UNINIT`(0x1), `BLOCK_UNINIT`(0x2), `INODE_ZEROED`(0x4) |
| `0x14` | 4 | `bg_exclude_bitmap_lo` | Exclude bitmap |
| `0x18` | 2 | `bg_block_bitmap_csum_lo` | Block bitmap checksum |
| `0x1A` | 2 | `bg_inode_bitmap_csum_lo` | Inode bitmap checksum |
| `0x1C` | 2 | `bg_itable_unused_lo` | Unused inodes |
| `0x1E` | 2 | `bg_checksum` | Descriptor checksum |

#### 11.2.2 Extended (64 bytes, `INCOMPAT_64BIT`)

Bytes 0x00-0x1F identical to standard. Additional at 0x20:

| Offset | Size | Field |
|--------|------|-------|
| `0x20` | 4 | `bg_block_bitmap_hi` |
| `0x24` | 4 | `bg_inode_bitmap_hi` |
| `0x28` | 4 | `bg_inode_table_hi` |
| `0x2C` | 2 | `bg_free_blocks_count_hi` |
| `0x2E` | 2 | `bg_free_inodes_count_hi` |
| `0x30` | 2 | `bg_used_dirs_count_hi` |
| `0x32` | 2 | `bg_itable_unused_hi` |
| `0x34` | 4 | `bg_exclude_bitmap_hi` |
| `0x38` | 2 | `bg_block_bitmap_csum_hi` |
| `0x3A` | 2 | `bg_inode_bitmap_csum_hi` |
| `0x3C` | 4 | Reserved |

#### 11.2.3 Checksum

**CRC16** (if `GDT_CSUM`, not `METADATA_CSUM`): `crc16(~0, s_uuid || group_nr(le32) || desc_bytes_with_bg_checksum_zeroed)`.

**CRC32C** (if `METADATA_CSUM`): `bg_checksum = lower16(crc32c(s_checksum_seed, group_nr(le32) || desc_bytes_up_to_checksum))`.

### 11.3 Inode Format

Size = `s_inode_size` (128 min, 256 typical). Per block = `block_size / s_inode_size` (16 typical).

**Location:** `group = (ino-1) / inodes_per_group`, `index = (ino-1) % inodes_per_group`, `block = bg_inode_table[group] + (index * inode_size) / block_size`, `off = (index * inode_size) % block_size`.

#### 11.3.1 Core Fields (128 bytes)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| `0x00` | 2 | `i_mode` | Type (upper 4 bits: 0x4=dir, 0x8=reg, 0xA=symlink) + permissions (lower 12) |
| `0x02` | 2 | `i_uid` | Owner UID (low 16) |
| `0x04` | 4 | `i_size_lo` | Size (low 32) |
| `0x08` | 4 | `i_atime` | Access time (seconds) |
| `0x0C` | 4 | `i_ctime` | Change time (seconds) |
| `0x10` | 4 | `i_mtime` | Modification time (seconds) |
| `0x14` | 4 | `i_dtime` | Deletion time |
| `0x18` | 2 | `i_gid` | Group GID (low 16) |
| `0x1A` | 2 | `i_links_count` | Hard link count |
| `0x1C` | 4 | `i_blocks_lo` | Blocks (512-byte sectors; fs-blocks if HUGE_FILE) |
| `0x20` | 4 | `i_flags` | Inode flags |
| `0x24` | 4 | `i_osd1` | Linux: `l_i_version` |
| `0x28` | 60 | `i_block[15]` | Extent tree root (see 11.4) |
| `0x64` | 4 | `i_generation` | File version (NFS) |
| `0x68` | 4 | `i_file_acl_lo` | Xattr block (low 32) |
| `0x6C` | 4 | `i_size_high` | Size (high 32; for regular files) |
| `0x70` | 4 | `i_obso_faddr` | Obsolete |
| `0x74` | 2 | `l_i_blocks_high` | Blocks (high 16) |
| `0x76` | 2 | `l_i_file_acl_high` | Xattr block (high 16) |
| `0x78` | 2 | `l_i_uid_high` | UID (high 16) |
| `0x7A` | 2 | `l_i_gid_high` | GID (high 16) |
| `0x7C` | 2 | `l_i_checksum_lo` | Inode checksum (low 16) |
| `0x7E` | 2 | Reserved | |

#### 11.3.2 Extended Fields (offset 0x80+, if `s_inode_size > 128`)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| `0x80` | 2 | `i_extra_isize` | Extra fields size |
| `0x82` | 2 | `i_checksum_hi` | Inode checksum (high 16) |
| `0x84` | 4 | `i_ctime_extra` | bits 0-1: epoch extension, bits 2-31: nanoseconds |
| `0x88` | 4 | `i_mtime_extra` | Same format |
| `0x8C` | 4 | `i_atime_extra` | Same format |
| `0x90` | 4 | `i_crtime` | Creation time (seconds) |
| `0x94` | 4 | `i_crtime_extra` | Creation time extra |
| `0x98` | 4 | `i_version_hi` | Version (high 32) |
| `0x9C` | 4 | `i_projid` | Project ID |

**Timestamp format:** `seconds = i_xtime | (epoch_bits << 32)` (34-bit, range 1901-2446). `nanoseconds = bits[2..31]`.

#### 11.3.3 Key Inode Flags (`i_flags`)

| Flag | Value | Meaning |
|------|-------|---------|
| `EXT4_SYNC_FL` | `0x00000008` | Synchronous updates |
| `EXT4_IMMUTABLE_FL` | `0x00000010` | Immutable |
| `EXT4_APPEND_FL` | `0x00000020` | Append-only |
| `EXT4_NOATIME_FL` | `0x00000080` | No atime |
| `EXT4_EXTENTS_FL` | `0x00080000` | Uses extents (MUST be set) |
| `EXT4_HUGE_FILE_FL` | `0x00040000` | Blocks in fs-block units |
| `EXT4_EA_INODE_FL` | `0x00200000` | Large xattr in inode |
| `EXT4_INLINE_DATA_FL` | `0x10000000` | Inline data (rejected) |

#### 11.3.4 Inode Checksum (`METADATA_CSUM`)

```
crc = crc32c(s_checksum_seed, ino(le32) || generation(le32) || inode_bytes_with_csum_zeroed)
l_i_checksum_lo = low16(crc)    // offset 0x7C
i_checksum_hi   = high16(crc)   // offset 0x82 (if inode_size > 128)
```

### 11.4 Extent Tree

B+tree: logical-to-physical block mapping. Root in `i_block[15]` (60 bytes). External nodes in allocated blocks.

#### 11.4.1 Header (12 bytes, every node)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| `0x00` | 2 | `eh_magic` | **`0xF30A`** |
| `0x02` | 2 | `eh_entries` | Valid entry count |
| `0x04` | 2 | `eh_max` | Max entries: root=4 (60-12=48, /12), external=`(block_size-12-4)/12` (340 for 4K) |
| `0x06` | 2 | `eh_depth` | 0=leaf, >0=internal |
| `0x08` | 4 | `eh_generation` | Tree version |

#### 11.4.2 Leaf Entry (`ext4_extent`, 12 bytes, depth==0)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| `0x00` | 4 | `ee_block` | First logical block |
| `0x04` | 2 | `ee_len` | Length. Bit 15 set = unwritten. Actual len = `ee_len & 0x7FFF`. Max 32768. |
| `0x06` | 2 | `ee_start_hi` | Physical block (high 16) |
| `0x08` | 4 | `ee_start_lo` | Physical block (low 32) |

Physical block: `ee_start_lo | (ee_start_hi << 32)` (48-bit address).

#### 11.4.3 Index Entry (`ext4_extent_idx`, 12 bytes, depth>0)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| `0x00` | 4 | `ei_block` | Logical block of subtree |
| `0x04` | 4 | `ei_leaf_lo` | Child block (low 32) |
| `0x08` | 2 | `ei_leaf_hi` | Child block (high 16) |
| `0x0A` | 2 | Reserved | |

**Traversal:** At each level, binary search for largest `ei_block <= target`. Descend. At leaf, binary search for extent covering target. Unmapped = hole (zeroes).

#### 11.4.4 Tail Checksum (external nodes only, `METADATA_CSUM`)

4 bytes at `block_end - 4`: `crc32c(s_checksum_seed, ino(le32) || generation(le32) || block_data_excl_tail)`.

### 11.5 Directory Entries

Directories are files whose data blocks contain variable-length entries.

#### 11.5.1 `ext4_dir_entry_2`

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| `0x00` | 4 | `inode` | Target inode (0 = deleted) |
| `0x04` | 2 | `rec_len` | Total entry size (4-byte aligned, min 12). Last entry extends to block end. |
| `0x06` | 1 | `name_len` | Name length |
| `0x07` | 1 | `file_type` | 1=reg, 2=dir, 3=chrdev, 4=blkdev, 5=fifo, 6=sock, 7=symlink |
| `0x08` | N | `name` | Filename (NOT NUL-terminated; length from `name_len`) |

**Checksum tail** (`METADATA_CSUM`): Last 12 bytes: `{ 0(4), rec_len=12(2), 0(1), 0xDE(1), crc32c(4) }`. CRC: `crc32c(seed, ino || generation || block_excl_tail)`.

#### 11.5.2 Htree Index (`COMPAT_DIR_INDEX`)

First dir block = `dx_root`: `.` entry (12B) + `..` entry (12B) + `dx_root_info` at 0x18 (reserved(4), hash_version(1), info_len=8(1), indirect_levels(1), unused(1)) + `dx_root` at 0x20 (limit(2), count(2), block(4)) + `dx_entry[]` at 0x28 (hash(4) + block(4) each).

**Lookup:** `dx_hash(name)` with `s_def_hash_version` + `s_hash_seed` -> binary search dx_entries -> read leaf -> linear scan.

**Hash algorithms:** HALF_MD4 (v1/4): MD4 compression in 32B chunks, 3 rounds. TEA (v2/5): 16B chunks, 16 rounds, delta `0x9E3779B9`. Both return `(major & ~1, minor)`. Unsigned variants (3/4/5): bytes as `u8`. Signed (0/1/2): `i8` sign-extended.

### 11.6 JBD2 Journal

Internal file at `s_journal_inum` (typically inode 8). Circular log of block-level transactions.

#### 11.6.1 Journal Superblock (block 0 of journal)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| `0x000` | 4 | `h_magic` | **`0xC03B3998`** |
| `0x004` | 4 | `h_blocktype` | 3=SB v1, 4=SB v2 |
| `0x008` | 4 | `h_sequence` | First valid txn sequence |
| `0x00C` | 4 | `s_blocksize` | Journal block size (= fs block size) |
| `0x010` | 4 | `s_maxlen` | Total journal blocks |
| `0x014` | 4 | `s_first` | First usable block |
| `0x018` | 4 | `s_sequence` | Seq of first uncommitted txn |
| `0x01C` | 4 | `s_start` | Block of first uncommitted txn (0 = clean) |
| `0x020` | 4 | `s_errno` | FS error code |
| `0x028` | 4 | `s_feature_incompat` | bit0=revoke, bit1=64bit, bit2=async_commit, bit4=csum_v2, bit5=csum_v3 |
| `0x030` | 16 | `s_uuid` | Journal UUID |
| `0x050` | 1 | `s_checksum_type` | 1=CRC32C |
| `0x0FC` | 4 | `s_checksum` | Journal SB CRC32C |

**Clean journal:** `s_start == 0`.

#### 11.6.2 Block Types

All blocks start with 12-byte header: `{ h_magic: 0xC03B3998, h_blocktype, h_sequence }`.

| Type | Value | Purpose |
|------|-------|---------|
| `DESCRIPTOR` | 1 | Lists target blocks for following data blocks |
| `COMMIT` | 2 | Transaction complete marker |
| `SB_V1` | 3 | Journal superblock v1 |
| `SB_V2` | 4 | Journal superblock v2 |
| `REVOKE` | 5 | Blocks to skip during replay |

#### 11.6.3 Descriptor Tag (v3, `CSUM_V3`)

| Offset | Size | Field |
|--------|------|-------|
| `0x00` | 4 | `t_blocknr` (low 32) |
| `0x04` | 4 | `t_flags`: bit0=ESCAPE, bit1=SAME_UUID, bit2=DELETED, bit3=LAST_TAG |
| `0x08` | 4 | `t_blocknr_high` (high 32) |
| `0x0C` | 4 | `t_checksum` (CRC32C of data block) |

16 bytes per tag. If `!SAME_UUID`: 16-byte UUID follows.

#### 11.6.4 Replay Algorithm

1. **SCAN:** From `s_start`, seq=`s_sequence`. Match magic+seq. Parse DESCRIPTOR/COMMIT/REVOKE. Stop on mismatch.
2. **REVOKE:** Build `(block_nr, txn_seq)` set.
3. **REPLAY:** Oldest first: skip if later revoked. Write data to target. ESCAPE flag: restore `0xC03B3998` at offset 0.
4. **CLEANUP:** `s_start=0`, write journal superblock.

Circular: `next(pos) = s_first + ((pos - s_first + 1) % (s_maxlen - s_first))`.

### 11.7 Bitmaps

**Block bitmap:** 1 block/group. Bit per block. Set = allocated. `allocated = (bitmap[idx/8] >> (idx%8)) & 1`.

**Inode bitmap:** 1 block/group. Bit per inode. Set = allocated.

**Checksum** (`METADATA_CSUM`): `crc = crc32c(s_checksum_seed, bitmap_data)`. Low 16 stored in `bg_*_bitmap_csum_lo`, high 16 in `bg_*_bitmap_csum_hi` (64-bit descriptors only).

### 11.8 Special Inodes

| Inode | Purpose |
|-------|---------|
| 0 | Invalid |
| 1 | Bad blocks |
| 2 | **Root directory** |
| 3-4 | User/group quota |
| 5 | Boot loader |
| 6 | Undelete directory |
| 7 | Reserved GDT |
| 8 | **Journal** |
| 9-10 | Exclude/replica |
| 11+ | First user inode (`s_first_ino`) |

### 11.9 Layout Diagram

```
+--------+-----------+-----+--------+--------+--------+--------+
|Boot pad| Superblock| GDT | Blk bm | Ino bm | Ino tbl| Data   |
|1024 B  | 1024 B    |N blk| 1 blk  | 1 blk  | M blks |remainder|
+--------+-----------+-----+--------+--------+--------+--------+
|<--------------------- Block Group 0 ----------------------->|
```

4K blocks, 32768 blks/group: inode table ~512 blocks, data ~31744 blocks (~124 MB/group).
## 12. POSIX Coverage

FrankenFS targets the POSIX filesystem interface through the `fuser::Filesystem`
trait in `ffs-fuse` (fuser integration is phased; current code is scaffolding).
Each FUSE callback delegates to `ffs-core` (engine orchestration), which
coordinates with `ffs-mvcc` (transactions), `ffs-extent` (block mapping),
`ffs-alloc` (allocation), and `ffs-block` (ARC buffer pool).

> **Note:** Earlier revisions of this document referenced phantom crate names
> `ffs-ops` and `ffs-cache`. These do not exist in the workspace. The correct
> crates are `ffs-core` (orchestration) and `ffs-block` (block I/O + ARC cache).

### 12.1 File Operations

#### 12.1.1 open / create

- `open` resolves the inode, performs permission checks, and allocates a file
  handle (`u64`). The handle is associated with a `Snapshot` (for reads) or
  a lazily-allocated `Transaction` (for writes).
- `create` atomically creates a directory entry and inode in a single MVCC
  transaction touching: parent directory data block(s), inode allocation
  bitmap, inode table block, and parent inode (timestamps, link count).
- `O_TRUNC` triggers implicit `truncate(0)` within the open transaction.
- `O_APPEND` sets a per-handle flag; writes atomically append at current EOF.
- `O_CREAT | O_EXCL` MUST fail `EEXIST` if name exists. Existence check and
  creation MUST be atomic (single MVCC transaction).
- `direct_io` reply flag: set when caller requests `O_DIRECT`.
- `keep_cache` reply flag: set for files unchanged since last open.

```rust
/// create pseudocode (illustrative, not normative).
fn create_impl(engine: &FrankenFsEngine, cx: &Cx, parent: InodeNumber,
               name: &OsStr, mode: FileMode, flags: u32) -> Result<CreateReply> {
    let tx = engine.mvcc.begin_tx(cx)?;

    // 1. Read parent inode, verify is directory and write permission
    let parent_inode = engine.read_inode_versioned(cx, &tx, parent)?;
    if !parent_inode.mode().is_dir() { return Err(FfsError::NotDirectory); }
    parent_inode.check_write_permission(cx)?;

    // 2. Check name does not already exist
    if engine.dir_lookup(cx, &tx, parent, name)?.is_some() {
        return Err(FfsError::Exists);
    }

    // 3. Allocate inode via Orlov (co-locate with parent group)
    let alloc_result = engine.alloc.allocate_inode(cx, parent_inode.group(), false)?;
    let new_ino = alloc_result.ino;

    // 4. Initialize inode
    let now = Timestamp::now();
    let new_inode = Ext4Inode::new_regular(mode, cx.uid(), cx.gid(), now);
    // Initialize empty extent header: magic=0xF30A, entries=0, max=4, depth=0
    engine.write_inode_versioned(cx, &tx, new_ino, &new_inode)?;

    // 5. Add directory entry in parent
    let file_type = mode.to_dir_entry_type(); // DT_REG, DT_DIR, etc.
    engine.dir_add_entry(cx, &tx, parent, name, new_ino, file_type)?;

    // 6. Update parent timestamps
    engine.touch_mtime_ctime(cx, &tx, parent, now)?;

    // 7. Handle O_TRUNC (no-op for new file, already size 0)
    // 8. Commit transaction
    let commit_seq = engine.mvcc.commit(cx, tx)?;

    // 9. Allocate file handle
    let fh = engine.handles.allocate(new_ino, flags, Snapshot { high: commit_seq });
    let attr = engine.inode_to_attr(&new_inode, new_ino);

    Ok(CreateReply { attr, generation: new_inode.generation(), fh, flags: 0 })
}
```

#### 12.1.2 read

- Reads `size` bytes at `offset` using the file handle's snapshot. All blocks
  resolved via `resolve(block_nr, snapshot)` for point-in-time consistency.
- Extent tree traversal maps logical offset to physical block(s). Each block
  fetched from ARC cache (which calls `resolve()` on miss).
- Sparse regions (holes) return zero-filled data without block allocation.
- Reads beyond `i_size` return empty. Partial-block reads fetch the full
  block from cache and return the requested sub-range.
- `Cx` budget: each block fetch decrements cost quota. Budget exhaustion
  returns a short count (valid POSIX).
- Sequential reads benefit from ARC T2 list. Extent tree prefetch issues
  ahead-of-time cache loads for child blocks.

#### 12.1.3 write

- Each FUSE `write` is a single MVCC transaction providing **atomic write**
  semantics at FUSE request granularity.
- COW write path: (1) map logical offset via extent tree, (2) for each block:
  read current version (partial writes), create new `BlockVersion` with
  `committed=false`, write data, (3) extend `i_size` if needed, (4) allocate
  new blocks via `ffs-alloc` and insert extents via `ffs-extent` if needed,
  (5) commit: assign `CommitSeq`, flip `committed=true`, run SSI validation.
- `O_APPEND`: offset determined atomically within the transaction.
- Partial block writes: read-modify-write on full block.
- RaptorQ: after commit, modified blocks' groups marked for stale repair
  symbols. Re-encoding is asynchronous.
- SSI conflict at commit: write returns `EAGAIN`; `ffs-fuse` retries with
  exponential backoff (up to 3 retries). `ENOSPC` on allocation failure.
  `EFBIG` if extent tree at max depth.

#### 12.1.4 release (close)

- Called when last fd for a handle closes. Commits pending transactions,
  flushes dirty blocks if `flush=true`, releases handle resources.
- If `i_links_count == 0` (unlinked while open), frees inode and data blocks
  at release time (POSIX "delete on last close").

#### 12.1.5 lseek

- `SEEK_SET`, `SEEK_CUR`, `SEEK_END`: standard offset computation.
- `SEEK_DATA`: find next allocated region at/after offset by walking extent tree.
- `SEEK_HOLE`: find next gap between extents. Both MUST be supported
  (FUSE 7.24+); essential for `cp`, `rsync`, `tar` sparse file handling.

```rust
/// lseek SEEK_DATA/SEEK_HOLE pseudocode (illustrative, not normative).
fn lseek_impl(engine: &FrankenFsEngine, cx: &Cx, ino: InodeNumber,
              offset: u64, whence: u32) -> Result<u64> {
    let snapshot = engine.mvcc.current_snapshot();
    let inode = engine.read_inode_versioned(cx, &snapshot, ino)?;
    let file_size = inode.size();
    let block_size = engine.sb.block_size() as u64;

    match whence {
        libc::SEEK_DATA => {
            if offset >= file_size { return Err(FfsError::Format("ENXIO".into())); }
            let logical = offset / block_size;
            // Walk extent tree from logical block forward
            let extents = engine.extent_map_range(cx, &snapshot, &inode, logical, u64::MAX)?;
            for ext in &extents {
                if ext.is_hole() {
                    continue; // skip holes, look for data
                }
                let ext_start_byte = ext.logical_start * block_size;
                if ext_start_byte >= offset {
                    return Ok(ext_start_byte); // first data at/after offset
                }
                let ext_end_byte = ext_start_byte + ext.count as u64 * block_size;
                if ext_end_byte > offset {
                    return Ok(offset); // offset is within this data extent
                }
            }
            Err(FfsError::Format("ENXIO: no data after offset".into()))
        }
        libc::SEEK_HOLE => {
            if offset >= file_size { return Err(FfsError::Format("ENXIO".into())); }
            let logical = offset / block_size;
            let extents = engine.extent_map_range(cx, &snapshot, &inode, logical, u64::MAX)?;
            for ext in &extents {
                if ext.is_hole() {
                    let hole_start = ext.logical_start * block_size;
                    if hole_start >= offset { return Ok(hole_start); }
                    return Ok(offset); // offset is within this hole
                }
                let ext_end_byte = (ext.logical_start + ext.count as u64) * block_size;
                if ext_end_byte > offset && ext_end_byte < file_size {
                    // Check if next region is a hole
                    continue;
                }
            }
            Ok(file_size) // virtual hole at EOF
        }
        _ => unreachable!("SEEK_SET/CUR/END handled by FUSE layer"),
    }
}
```

#### 12.1.6 truncate (via setattr)

- **Shrink:** deallocate extents beyond new size, zero partial tail block,
  update `i_size`/`i_blocks`/extent tree. Single MVCC transaction.
- **Extend:** update `i_size` only (no allocation; extended region is a hole).
- Updates `mtime` and `ctime`. Deallocated blocks' groups get stale RaptorQ markers.

#### 12.1.7 fallocate

See Section 13.3.

### 12.2 Directory Operations

#### 12.2.1 opendir / readdir / readdirplus / releasedir

- `opendir` captures a snapshot for the directory handle. All `readdir` calls
  see a consistent view even under concurrent modifications.
- `readdir` returns entries from the given offset cookie in on-disk order
  (not alphabetical, matching kernel ext4). For htree directories, walks
  leaf blocks ignoring hash index.
- `readdirplus` also returns full inode attributes per entry (reduces stat calls).
- `.` and `..` MUST appear first with correct inode numbers.

#### 12.2.2 mkdir

Single MVCC transaction: (1) allocate inode via Orlov allocator, (2) initialize
with `S_IFDIR | (mode & ~umask)`, `i_links_count=2`, (3) allocate initial
directory block with `.` and `..`, (4) insert entry in parent (htree insert
if indexed), (5) increment parent's `i_links_count`, (6) update parent
timestamps, (7) commit.

Errors: `EEXIST` (name exists), `ENOSPC` (no inode/block), `EMLINK` (parent
link count overflow -- ext4 `dir_nlink` feature sets `i_links_count=1` for
directories exceeding 65000 subdirectories; FrankenFS MUST support this).

#### 12.2.3 rmdir

Single MVCC transaction: (1) look up name, verify is directory, (2) verify
empty (only `.` and `..`), (3) remove entry from parent, (4) decrement parent
`i_links_count`, (5) set target `i_links_count=0` and mark for deallocation,
(6) update parent timestamps, (7) commit.

Errors: `ENOENT`, `ENOTDIR`, `ENOTEMPTY`.

#### 12.2.4 rename

The most complex POSIX operation. All variants wrapped in a single MVCC
transaction for atomicity.

**Same-directory:** Remove old entry, insert new. If `newname` exists: unlink
target (file->file or empty-dir->empty-dir replacement; type mismatch returns
`EISDIR`/`ENOTDIR`).

**Cross-directory:** Same plus: cycle detection (walk `newparent`'s `..` chain
to verify source is not an ancestor; `EINVAL` on cycle), update `..` entry in
source directory, adjust link counts in both parents.

**RENAME_NOREPLACE:** Fail `EEXIST` if target exists.

**RENAME_EXCHANGE:** Both names MUST exist. Atomically swap entries, updating
`..` and link counts for directories.

MVCC scope touches: both parent directory blocks, inode table blocks for
source/target, `..` entry block for directory renames. SSI conflict detection
applies. Orlov allocator's cross-group inode spreading reduces false conflicts.

```rust
/// rename pseudocode (illustrative, not normative).
/// Handles same-dir, cross-dir, NOREPLACE, and EXCHANGE variants.
fn rename_impl(engine: &FrankenFsEngine, cx: &Cx,
               old_parent: InodeNumber, old_name: &OsStr,
               new_parent: InodeNumber, new_name: &OsStr,
               flags: u32) -> Result<()> {
    let tx = engine.mvcc.begin_tx(cx)?;

    // 1. Look up source entry
    let (src_ino, src_type) = engine.dir_lookup(cx, &tx, old_parent, old_name)?
        .ok_or(FfsError::NotFound(format!("{old_name:?}")))?;

    // 2. Look up target entry (may or may not exist)
    let target = engine.dir_lookup(cx, &tx, new_parent, new_name)?;

    // 3. RENAME_NOREPLACE: fail if target exists
    if flags & libc::RENAME_NOREPLACE != 0 && target.is_some() {
        return Err(FfsError::Exists);
    }

    // 4. RENAME_EXCHANGE: both must exist
    if flags & libc::RENAME_EXCHANGE != 0 {
        let (tgt_ino, _) = target.ok_or(FfsError::NotFound(
            format!("{new_name:?}")
        ))?;
        // Swap entries atomically
        engine.dir_update_entry(cx, &tx, old_parent, old_name, tgt_ino)?;
        engine.dir_update_entry(cx, &tx, new_parent, new_name, src_ino)?;
        // Update .. entries if either is a directory
        if src_type.is_dir() { engine.dir_update_dotdot(cx, &tx, src_ino, new_parent)?; }
        if engine.read_inode_versioned(cx, &tx, tgt_ino)?.mode().is_dir() {
            engine.dir_update_dotdot(cx, &tx, tgt_ino, old_parent)?;
        }
    } else {
        // 5. Standard rename
        // If target exists, unlink it first
        if let Some((tgt_ino, tgt_type)) = target {
            // Type compatibility check
            if src_type.is_dir() && !tgt_type.is_dir() {
                return Err(FfsError::NotDirectory);
            }
            if !src_type.is_dir() && tgt_type.is_dir() {
                return Err(FfsError::IsDirectory);
            }
            if tgt_type.is_dir() {
                // Verify target directory is empty
                engine.verify_dir_empty(cx, &tx, tgt_ino)?;
                engine.dec_links(cx, &tx, new_parent)?; // parent loses child
            }
            engine.dir_remove_entry(cx, &tx, new_parent, new_name)?;
            engine.dec_links_and_maybe_free(cx, &tx, tgt_ino)?;
        }

        // 6. Cross-directory cycle detection
        if old_parent != new_parent && src_type.is_dir() {
            // Walk new_parent's .. chain to verify source is not an ancestor
            let mut cursor = new_parent;
            while cursor != InodeNumber::ROOT {
                if cursor == src_ino { return Err(FfsError::Format(
                    "rename would create directory cycle".into()
                )); }
                cursor = engine.dir_lookup_dotdot(cx, &tx, cursor)?;
            }
        }

        // 7. Remove old entry, insert new
        engine.dir_remove_entry(cx, &tx, old_parent, old_name)?;
        engine.dir_add_entry(cx, &tx, new_parent, new_name, src_ino, src_type)?;

        // 8. Update .. for directory renames across parents
        if old_parent != new_parent && src_type.is_dir() {
            engine.dir_update_dotdot(cx, &tx, src_ino, new_parent)?;
            engine.dec_links(cx, &tx, old_parent)?;  // old parent loses child
            engine.inc_links(cx, &tx, new_parent)?;  // new parent gains child
        }
    }

    // 9. Update timestamps
    let now = Timestamp::now();
    engine.touch_mtime_ctime(cx, &tx, old_parent, now)?;
    if old_parent != new_parent {
        engine.touch_mtime_ctime(cx, &tx, new_parent, now)?;
    }
    engine.touch_ctime(cx, &tx, src_ino, now)?;

    engine.mvcc.commit(cx, tx)?;
    Ok(())
}
```

### 12.3 Link Operations

#### 12.3.1 link (hard link)

Single MVCC transaction: verify source is not directory (`EPERM`), verify
`newname` absent (`EEXIST`), increment `i_links_count`, insert entry in parent,
update timestamps. Link count overflow at `u16` max returns `EMLINK`.

#### 12.3.2 symlink

Single MVCC transaction: allocate inode (`S_IFLNK | 0777`), store target as
**fast symlink** (inline in `i_block[0..14]`, up to 60 bytes) or **slow symlink**
(extent-mapped data block), insert entry in parent.

#### 12.3.3 readlink

Read target from `i_block` (fast) or first extent data block (slow). MUST NOT
include trailing null (POSIX requirement).

#### 12.3.4 unlink

Single MVCC transaction: remove entry from parent, decrement `i_links_count`.
If count reaches 0: free inode and blocks immediately (no open handles) or
defer to release (POSIX "unlink while open" via orphan list). Update timestamps.

### 12.4 Attribute Operations

#### 12.4.1 getattr (stat)

Reads inode under caller's snapshot. Maps to `struct stat`: `st_mode` from
`i_mode`, `st_nlink` from `i_links_count`, `st_uid`/`st_gid` (with hi16
extensions for 32-bit UIDs), `st_size` (lo|hi<<32), `st_blocks` (512-byte
units), timestamps with nanosecond precision (ext4 extra epoch+nsec fields),
`st_blksize` from superblock, `st_rdev` from `i_block[0]`/`i_block[1]` for
device nodes.

#### 12.4.2 setattr (chmod, chown, utimes)

Single MVCC transaction per attribute set. **chmod:** update `i_mode`
preserving type bits; owner or root only. **chown:** update `i_uid`/`i_gid`;
root only (`_POSIX_CHOWN_RESTRICTED`); clears setuid/setgid. **utimes:**
nanosecond precision; `UTIME_NOW`/`UTIME_OMIT` supported. All changes
update `ctime`.

### 12.5 Permission Model

Traditional UNIX: 9 permission bits (rwx x owner/group/other) in `i_mode`.
Special bits: setuid, setgid, sticky. Root (UID 0) bypasses all checks
except execute (requires at least one x bit). Group membership checked
against supplementary group list from FUSE request context. Sticky bit on
directories: only file owner, directory owner, or root may delete/rename.

`access()`: permission check using real UID/GID (not effective). Returns
`EACCES` on failure.

### 12.6 Extended Attributes

Namespace routing:

| Namespace | Access | Usage |
|-----------|--------|-------|
| `user.` | Owner/root, requires r/w permission | Application metadata |
| `security.` | Root for set; policy-dependent read | SELinux labels, capabilities |
| `system.` | Kernel-managed | POSIX ACLs |
| `trusted.` | CAP_SYS_ADMIN only | Filesystem internals |

Storage: **Inline xattrs** in inode extra space (packed `{name_index, name_len,
value_offset, value_size}` headers). **External xattr block** via `i_file_acl`
when inline space exhausted (shared across inodes via refcount). Limits:
65536 bytes per value, one block total for external xattrs plus inline space.

MVCC: xattr modifications are transactions touching inode table block (inline)
or xattr block (external). Standard versioning/SSI rules apply.

### 12.7 File Locking

POSIX advisory locks (`fcntl F_SETLK/F_SETLKW/F_GETLK`) and `flock(2)` are
handled by the kernel's FUSE VFS layer. FrankenFS does not implement locking
logic. The `lock_owner` in FUSE callbacks is informational only.

### 12.8 mmap

**NOT SUPPORTED** (FUSE limitation). `MAP_SHARED` writes eventually arrive
as FUSE `write` callbacks but timing is kernel-controlled (not by `msync`).
FrankenFS cannot guarantee MVCC transaction semantics for mmap'd writes.
Applications requiring strong consistency MUST use `read()`/`write()`.

### 12.9 Special File Types

| Type | `i_mode` | On-Disk Storage |
|------|----------|-----------------|
| Regular | `S_IFREG` | Extent-mapped data blocks |
| Directory | `S_IFDIR` | Linear or htree-indexed entry blocks |
| Symlink | `S_IFLNK` | Inline (fast, `i_block`) or extent-mapped (slow) |
| Char device | `S_IFCHR` | `i_block[0]` (old) + `i_block[1]` (new: `major<<20\|minor`) |
| Block device | `S_IFBLK` | Same as char device |
| FIFO | `S_IFIFO` | No data blocks; inode only |
| Socket | `S_IFSOCK` | No data blocks; inode only |

Device nodes: `mknod()` creates char/block nodes. FrankenFS MUST write both
old and new device number encodings for compatibility. FIFOs and sockets are
inode-only; kernel handles actual I/O in memory.

---

## 13. Built-in Operations

### 13.1 statfs

Returns filesystem statistics from superblock and aggregated group descriptors.

| `statvfs` Field | Source |
|----------------|--------|
| `f_bsize` | `1024 << s_log_block_size` |
| `f_blocks` | `s_blocks_count_lo/hi` |
| `f_bfree` | `s_free_blocks_count_lo/hi` |
| `f_bavail` | `f_bfree - s_r_blocks_count` (minus reserved-for-root) |
| `f_files` | `s_inodes_count` |
| `f_ffree` | `s_free_inodes_count` |
| `f_namemax` | 255 |

MVCC note: free counts read under a snapshot may be slightly stale; POSIX
does not require `statfs` linearizability. Free block counts MUST exclude
blocks consumed by MVCC version chains (not yet GC'd) and RaptorQ repair
symbol blocks.

### 13.2 fsync / fdatasync

**datasync=true:** Flush dirty data blocks for this inode to device via
`pwrite64`, issue `fdatasync()` on underlying fd. Do NOT flush metadata
unless it affects data retrieval (size change, new extent).

**datasync=false:** Flush dirty data blocks + inode block + modified extent
tree blocks + xattr blocks. Issue `fsync()` on underlying fd.

**MVCC interaction:** `fsync` MUST commit any uncommitted transaction for
this file handle (assigns `CommitSeq`, makes versions visible). Then flush
committed dirty blocks to device. Does NOT wait for RaptorQ re-encoding.

**JBD2-compatible mode:** `fsync` forces a journal commit if the current
compound transaction contains dirty blocks for this file (matches kernel
ext4 behavior).

### 13.3 fallocate

**mode=0 (default):** Allocate and zero blocks for `[offset, offset+length)`.
Use `ffs-alloc` (mballoc) with goal-oriented contiguous allocation. Insert
extents via `ffs-extent`. Update `i_size` if extended. Single MVCC transaction.

**FALLOC_FL_KEEP_SIZE:** Same as mode=0 but do NOT update `i_size`.
Preallocated blocks return zeroes on read; file size unchanged.

**FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE:** Deallocate blocks in range.
Full extents: remove from tree and free blocks. Partial overlap: split extent
at boundary, deallocate inner blocks, zero partial boundary blocks. Update
`i_blocks`. Mark affected block groups for RaptorQ re-encoding.

**FALLOC_FL_COLLAPSE_RANGE:** Remove range and shift subsequent data down.
Rewrites extent tree mappings. Range MUST be block-aligned (`EINVAL`).

**FALLOC_FL_ZERO_RANGE:** Zero range without deallocation. Allocated blocks
get zeroes written. Unallocated blocks marked as uninitialized extents.

**FALLOC_FL_INSERT_RANGE:** Insert hole at offset, shift data up. Inverse of
collapse. Range MUST be block-aligned.

Block allocation strategy: goal set to physical block after file's last
extent for contiguity. Large allocations (>8 MB) use buddy allocator
higher-order entries for contiguous free space.

### 13.4 access

Permission check using request's real UID/GID. Algorithm: (1) `F_OK`: check
inode exists, (2) root: grant R_OK/W_OK unconditionally, X_OK requires at
least one execute bit, (3) select owner/group/other bits based on uid/gid
match, (4) check requested permissions, (5) `EACCES` on failure.

### 13.5 flush

Called on every `close()` of a file descriptor (may be called multiple times
per handle, unlike `release` which is called once). Flushes dirty data from
ARC cache to device and commits any uncommitted MVCC transaction. Does NOT
deallocate the file handle.

---

## 14. Filesystem Utilities

FrankenFS ships a CLI tool `ffs` (in `ffs-cli` using `clap` derive) for
offline diagnostics and repair. These operate directly on the block device
or disk image without FUSE mounting.

### 14.1 ffs fsck (Filesystem Check)

```
ffs fsck [OPTIONS] <device>
  --repair / -r     Attempt repair (default: read-only)
  --force / -f      Check even if marked clean
  --verbose / -v    Detailed progress
  --block-group <N> Check single group
  --json            JSON output
```

**Phase 1: Superblock Validation.** Read primary superblock at offset 1024.
Verify magic (`0xEF53`), CRC32C checksum (seed `s_checksum_seed`), feature
flags (unknown `incompat_features` are fatal), geometry consistency
(`s_blocks_count * block_size <= device_size`, etc.). With `--repair`:
restore from backup superblocks (groups at powers of 3, 5, 7) if primary
is corrupt.

**Phase 2: Block Group Descriptors.** Read all group descriptors. Per
descriptor: verify CRC32C checksum, validate `bg_block_bitmap` /
`bg_inode_bitmap` / `bg_inode_table` point to valid blocks, verify free
counts <= total. With `--repair`: recalculate checksums.

**Phase 3: Inode Table Walk.** For each allocated inode (per inode bitmap):
verify inode CRC32C, valid `i_mode` type, `i_links_count > 0`, `i_size`
consistent with `i_blocks`, plausible timestamps. Build inode->expected_link_count
map from directory entry references.

**Phase 4: Extent Tree Integrity.** For each extent-mapped inode: verify
extent header magic (`0xF30A`), valid depth/entry count, child blocks within
filesystem bounds, monotonically increasing non-overlapping logical ranges,
no cross-inode block sharing, leaf extent lengths <= 32768 blocks. Build
global physical block reference bitmap.

**Phase 5: Block Bitmap Consistency.** Compare computed bitmap (Phase 4
references + metadata blocks) with on-disk bitmap per group. Report:
orphaned blocks (marked used, unreferenced = leaked space), bitmap
undercounts (referenced but marked free = dangerous double-allocation risk).
With `--repair`: update on-disk bitmap.

**Phase 6: Inode Bitmap and Link Count.** Compare computed inode allocation
with on-disk bitmap. Report orphan inodes (allocated but no directory entry).
Compare expected vs actual `i_links_count`. With `--repair`: fix counts,
clear orphans, update bitmap.

**Phase 7: Directory Consistency.** Per directory: verify `.` (self) and
`..` (parent) entries exist with correct inode numbers, all entries reference
valid allocated inodes, no duplicate names, htree structure validity (hash
tree root, internal nodes, leaf ordering). Verify full tree connectivity from
root (inode 2). With `--repair`: reconnect orphan directories to `/lost+found`.

**Phase 8: RaptorQ Repair Symbols.** Per block group with repair symbols:
verify symbol block checksums, verify encoding parameters (K, R), optionally
trial-decode uncorrupted blocks to validate symbol consistency. Report groups
with missing/corrupt symbols. With `--repair`: re-encode invalid groups.

```rust
/// fsck output structure (illustrative, not normative).
pub struct FsckReport {
    pub superblock: SuperblockStatus,      // ok | repaired | corrupt
    pub group_descriptors: Vec<GroupStatus>,
    pub inodes: InodeCheckResult {
        pub checked: u64, pub valid: u64, pub invalid: u64,
        pub link_count_mismatches: Vec<(InodeNumber, u16 /* expected */, u16 /* actual */)>,
        pub orphaned: Vec<InodeNumber>,
    },
    pub extents: ExtentCheckResult {
        pub trees_checked: u64, pub valid: u64, pub corrupt: u64,
        pub double_referenced_blocks: Vec<(BlockNumber, Vec<InodeNumber>)>,
    },
    pub block_bitmap: BitmapCheckResult {
        pub groups_checked: u32, pub mismatches: u32,
        pub leaked_blocks: u64,        // marked used but unreferenced
        pub undercount_blocks: u64,    // referenced but marked free (dangerous)
    },
    pub inode_bitmap: BitmapCheckResult,
    pub directories: DirCheckResult {
        pub checked: u64, pub valid: u64,
        pub missing_dot: Vec<InodeNumber>,
        pub missing_dotdot: Vec<InodeNumber>,
        pub disconnected: Vec<InodeNumber>,   // not reachable from root
        pub duplicate_names: Vec<(InodeNumber, Vec<u8>)>,
    },
    pub repair_symbols: RepairCheckResult {
        pub groups_with_symbols: u32, pub valid: u32,
        pub corrupt: u32, pub missing: u32,
    },
    pub repaired: bool,                    // true if --repair made changes
    pub elapsed: Duration,
}
```

**Exit codes:** 0 = filesystem clean, 1 = errors found (not repaired), 2 = errors found and repaired, 4 = operational error (cannot open device, etc.). Exit codes can be combined (e.g., 3 = some repaired + some remaining).

### 14.2 ffs info (Filesystem Information)

```
ffs info [OPTIONS] <device>
  --groups    Block group table
  --mvcc      MVCC engine status (native mode)
  --repair    RaptorQ repair status
  --journal   JBD2 journal status
```

**Superblock summary:** UUID, label, block size, block/inode counts (total/free/reserved),
blocks per group, mount count, timestamps, feature flags, checksum type and seed.

**Block group summary (`--groups`):** Per-group: block range, free blocks,
inode range, free inodes, flags.

**MVCC status (`--mvcc`):** Current `CommitSeq`, active transaction count,
oldest active snapshot, version chain statistics (total versioned blocks,
max/avg chain depth, blocks pending GC), lifetime SSI conflict/abort counts.

**Repair status (`--repair`):** Configured symbol overhead percentage,
coverage (groups with valid symbols / total groups), groups with stale
symbols, last scrub time and duration, lifetime corruption detected/repaired/unrecoverable counts.

**Journal status (`--journal`):** Journal size, current/first-valid sequence
numbers, head/start blocks, committed/running transaction counts, checkpoint status.

### 14.3 ffs repair (Manual Repair Trigger)

```
ffs repair [OPTIONS] <device>
  --full-scrub        Scrub all groups (default: stale only)
  --block-group <N>   Repair single group
  --rebuild-symbols   Force re-encode all repair symbols
  --verify-only       Verify without repairing
  --max-threads <N>   Limit parallelism
```

**Workflow:**

1. **Scrub phase:** Read every block in scope. Verify checksums (BLAKE3 for
   native mode, CRC32C for metadata in JBD2-compatible mode). Record blocks
   with failures.

2. **Recovery phase:** Per group with corrupted blocks: load RaptorQ repair
   symbols, verify symbol integrity, construct decoding matrix (corrupted
   blocks = erased, intact blocks + valid symbols = received), attempt
   RaptorQ decode (succeeds if K' >= K received symbols), write recovered
   blocks, re-verify checksums.

3. **Re-encoding phase:** Re-encode repair symbols for all groups with
   recovered or modified blocks.

**Failure modes:** If corrupted blocks exceed repair symbols for a group,
recovery fails. Report unrecoverable blocks and their inode associations.
If repair symbol blocks themselves are corrupt, group cannot be RaptorQ-repaired;
suggest `--rebuild-symbols` after manual restoration.

### 14.4 ffs dump (Low-Level Metadata Dump)

```
ffs dump superblock <device>      Raw superblock fields
ffs dump group <N> <device>       Group descriptor fields
ffs dump inode <ino> <device>     All inode fields
ffs dump extents <ino> <device>   Full extent tree (all levels)
ffs dump dir <ino> <device>       Directory entries + htree structure
```

All subcommands support `--json` (machine-readable) and `--hex` (raw
hexadecimal block dump). Default is human-readable formatted output.

**superblock:** All `s_*` fields with numeric values and annotations
(e.g., `s_log_block_size: 2  # 1024 << 2 = 4096`).

**group:** All `bg_*` fields including bitmap/table locations, free counts, flags.

**inode:** All `i_*` fields including mode, uid/gid, size, timestamps,
blocks, flags, extent tree root (header + entries), extra isize, checksums.

**extents:** Full tree dump showing each level: root index entries with child
blocks, internal nodes with index entries, leaf nodes with extent entries
(logical range, physical range, initialized/uninitialized flag).

**dir:** Directory entries (offset, inode, type, name) plus htree structure
if indexed (hash algorithm, seed, indirect levels, index entries with hash
ranges and block pointers).

---

## 15. Exclusions

Features explicitly out of scope. Each exclusion is deliberate. If a feature
is not listed here and not specified elsewhere, its status SHOULD be raised
for clarification.

### 15.1 Kernel Module

**Excluded.** FrankenFS is userspace-only via FUSE.

- `#![forbid(unsafe_code)]` is incompatible with kernel module C API bindings.
- GPL licensing constraints conflict with dependency freedom.
- No stable kernel ABI; recompilation required per kernel version.
- Kernel development cycle (reboot-to-test, crash = system crash) vs. normal
  userspace development. FUSE context-switch overhead (2-5x for metadata-heavy
  workloads) is accepted for safety and velocity.

### 15.2 ext2/ext3 Legacy Format

**Excluded.** Target ext4 only.

- ext2/ext3 images mountable as ext4 by kernel. Users should use kernel driver
  or `tune2fs` conversion.
- Avoiding legacy code paths: indirect block addressing, 32-bit block counts,
  JBD v1 journal format, unjournaled metadata.

### 15.3 fscrypt (Filesystem Encryption)

**Excluded.**

- Key management complexity: kernel keyring, per-file policies, AES-256-XTS/CTS-CBC
  derivation, policy inheritance (~4K kernel LOC).
- MVCC interaction: encrypted versions with potentially different keys across
  the version chain; snapshot reads need historical keys.
- RaptorQ interaction: repair symbols over ciphertext works but complicates
  the repair/verify pipeline.
- Alternative: dm-crypt/LUKS at block device layer.

### 15.4 Online Resize

**Excluded.**

- Requires coordinating active I/O with metadata relocation (new block groups,
  superblock updates, group descriptor relocation).
- Shrinking requires relocating data/inodes from removed range.
- Interacts with MVCC (relocation must be transactional), RaptorQ (re-encode
  relocated groups), ARC cache (invalidate moved blocks).
- Future: offline resize via `ffs fsck --resize` after unmount.

### 15.5 Quota Subsystem

**Excluded.** Administrative policy feature (~3K LOC: quota file parsing,
in-memory tracking, enforcement hooks, `quotactl` handling). Can be layered
on later via well-defined hooks at allocation and ownership-change points.

### 15.6 btrfs On-Disk Format

**In scope (phased).** FrankenFS targets mount-compatible behavior for both
ext4 and btrfs images, using shared MVCC + self-healing internals.

Initial btrfs scope (explicit):

- single-device images only
- metadata parsing + validation
- read-only mount surface parity first, then write-path parity

Excluded initially (btrfs-specific):

- multi-device/chunk profiles (RAID*, DUP), device replace, balance
- send/receive
- transparent compression / fscrypt

### 15.7 NFS Export

**Excluded.** Requires stable file handles surviving reboots (filesystem ID +
inode number + generation). FUSE does not expose `export_operations`. Protocol
concern orthogonal to filesystem correctness.

### 15.8 ext4 Inline Data

**Excluded.** `EXT4_INLINE_DATA_FL` stores small files in inode body (~60 bytes
in `i_block` + extended attribute area). Benefits ~2% of files. Adds
complexity to every read/write path (inline vs extent-mapped check, transition
handling). Future optimization after core stabilization.

### 15.9 Multi-Device

**Excluded.** Single block device only. ext4 is inherently single-device;
multi-device would break format compatibility. Users can layer md-raid/LVM
beneath. RaptorQ already provides per-group redundancy; multi-device RAID
is an orthogonal layer.

### 15.10 DAX / Persistent Memory

**Excluded.** FUSE does not support DAX. Even with hypothetical FUSE DAX
support, direct memory-mapped writes would bypass MVCC transaction machinery.

### 15.11 fs-verity

**Excluded.** Read-only per-file Merkle tree (SHA-256). Overlaps with but is
weaker than RaptorQ: fs-verity detects corruption (returns EIO), RaptorQ
detects AND repairs. Different design goals (fs-verity: content authentication
for immutable files; RaptorQ: recovery for all files). Alternative: dm-verity
at block layer.

### 15.12 Encrypted Directory Indexes

**Excluded.** Sub-feature of fscrypt (Section 15.3). Encrypted filenames in
directory entries + keyed SipHash for htree. No use case without the broader
fscrypt infrastructure; excluded by implication.

### 15.13 Direct Block Pointers (Legacy Indirect Addressing)

**Excluded.** Pre-extents block mapping via 12 direct + 1 indirect + 1 double-
indirect + 1 triple-indirect pointers in `i_block[0..14]`. FrankenFS requires
`INCOMPAT_EXTENTS` -- all inodes MUST use extent trees. Images without extents
must be converted (`tune2fs -O extents`) before mounting. Rationale: extent
trees are strictly superior (contiguous ranges, O(log N) vs O(N) lookup for
large files, simpler COW semantics). Supporting both code paths would double
the block-mapping complexity for zero practical benefit (all modern ext4
images use extents by default since Linux 2.6.28).

### 15.14 Casefold (Case-Insensitive Directories)

**Excluded.** `INCOMPAT_CASEFOLD` (0x20000). Requires per-directory casefold
flag, Unicode NFD normalization for lookups, modified htree hash computation
(hash the normalized name, not the stored name), and full Unicode casefolding
tables (~100 KB). Used primarily for Windows/macOS interoperability (Samba,
case-insensitive Chromium filesystem). Adds complexity to every directory
lookup and modifies the htree hash contract. Alternative: application-layer
case-insensitive lookup via `readdir + casefold compare`.

### 15.15 Fast Commit

**Excluded.** `COMPAT_FAST_COMMIT` (0x0400). Lightweight journal extension
that logs logical operations (create inode, add to directory, extend file)
rather than physical blocks, reducing journal write amplification by 2-3x
for metadata-heavy workloads. Adds a parallel log stream alongside JBD2 with
its own replay logic (~3K LOC in kernel). Interacts with MVCC (fast commit
entries must be reconciled with version chains). FrankenFS's MVCC-native mode
already eliminates journal write amplification by using COW version chains
instead of journaling. JBD2-compat mode uses traditional physical journaling
for simplicity and correctness.

### 15.16 Bigalloc (Cluster-Based Allocation)

**Excluded.** `INCOMPAT_BIGALLOC`. Allocates in clusters (multiple blocks)
rather than individual blocks. Cluster size = `1024 << s_log_cluster_size`.
Reduces bitmap overhead for large filesystems but complicates extent
management (extent lengths in clusters, not blocks), allocation (minimum
allocation unit is a cluster), and compatibility (older tools may not
understand cluster-based extents). Limited real-world adoption. Standard
block-based allocation is sufficient for target workloads.

### 15.17 MMP (Multi-Mount Protection)

**Excluded.** `INCOMPAT_MMP` (0x0100). Prevents simultaneous mounting of a
filesystem on multiple hosts (shared storage). Uses a magic block
(`s_mmp_block`) updated every `s_mmp_interval` seconds with hostname and
timestamp. Requires active polling and network-aware timeout logic (~1K LOC).
FrankenFS is a single-host FUSE filesystem; shared storage protection is
handled by the storage layer (SAN locking, cluster manager). The
`INCOMPAT_MMP` flag is ignored with a warning at mount time (flag is set but
check is not enforced).

### 15.18 Compression

**Excluded.** `INCOMPAT_COMPRESSION` (0x0001). An early, largely unfinished
ext2 extension for per-file transparent compression. Never completed or widely
deployed in ext4. The flag is rejected at mount time. Block-level compression
is incompatible with FrankenFS's per-block MVCC versioning (compressed block
boundaries do not align with logical block boundaries). Alternative: file-level
compression via user-space tools or btrfs-style transparent compression
(which would require fundamental architecture changes).

---
## 16. Implementation Phases

FrankenFS is delivered in nine sequential phases. Each phase builds on all
prior phases. A phase is complete when every acceptance criterion passes in CI.
Phases MUST NOT be reordered; the dependency chain is strict.

**Total estimated Rust LOC: ~45,500** (40,500 production + ~5,000 test/bench/fixtures)

### 16.1 Phase Summary

| Phase | Name | Crates | Est. LOC | Cumul. | Status |
|-------|------|--------|----------|--------|--------|
| 1 | Bootstrap | all (stubs) | 500 | 500 | DONE |
| 2 | Types & On-Disk | ffs-types, ffs-error, ffs-ondisk | 5,000 | 5,500 | -- |
| 3 | Block I/O | ffs-block | 3,000 | 8,500 | -- |
| 4 | B-tree, Extent, Alloc | ffs-btree, ffs-extent, ffs-alloc | 6,000 | 14,500 | -- |
| 5 | Inode, Dir, Xattr | ffs-inode, ffs-dir, ffs-xattr | 5,000 | 19,500 | -- |
| 6 | Journal & MVCC | ffs-journal, ffs-mvcc | 8,000 | 27,500 | -- |
| 7 | FUSE | ffs-fuse, ffs-core | 4,000 | 31,500 | -- |
| 8 | Repair | ffs-repair | 4,000 | 35,500 | -- |
| 9 | CLI/TUI/Harness | ffs-cli, ffs-tui, ffs-harness, ffs | 5,000 | 40,500 | -- |

### 16.2 Phase 1: Bootstrap (DONE)

**Goal:** Workspace scaffolding, specs, empty stubs.

**Acceptance:** `cargo check --workspace` passes. All 21 crates present (19 core + 2 legacy/reference wrappers) with `#![forbid(unsafe_code)]`. Clippy and rustfmt clean.

### 16.3 Phase 2: Types & On-Disk (5,000 LOC)

**Goal:** Foundational type system and ext4 on-disk structure parsing. Parse real ext4 superblock, group descriptors, inodes, extents, and directory entries.

**ffs-types:** Newtypes `BlockNumber(u64)`, `InodeNumber(u64)`, `TxnId(u64)`, `CommitSeq(u64)`, `Snapshot { high: CommitSeq }`, `ParseError` enum. Binary read helpers (`read_le_u16/u32/u64`, `ensure_slice`, `trim_nul_padded`). ext4/btrfs magic constants. Additional planned newtypes: `GroupNumber(u32)`, `LogicalBlock(u64)`, `FileMode` (bitflags), `Timestamp { seconds: i64, nanoseconds: u32 }`, `BlockBuf`.

> **Note:** `InodeNumber` is `u64` (not `u32`) to support both ext4 32-bit inodes and btrfs 64-bit objectids. The ext4 on-disk format stores 32-bit inode numbers; conversion happens at the parsing boundary.

**ffs-error:** `FfsError` enum (**14 variants** — canonical definition in `ffs-error/src/lib.rs` and PROPOSED_ARCHITECTURE.md Section 7): `Io` -> `EIO`, `Corruption` -> `EIO`, `Format` -> `EINVAL`, `MvccConflict` -> `EAGAIN`, `Cancelled` -> `EINTR`, `NoSpace` -> `ENOSPC`, `NotFound` -> `ENOENT`, `PermissionDenied` -> `EACCES`, `NotDirectory` -> `ENOTDIR`, `IsDirectory` -> `EISDIR`, `NotEmpty` -> `ENOTEMPTY`, `NameTooLong` -> `ENAMETOOLONG`, `Exists` -> `EEXIST`, `RepairFailed` -> `EIO`.

**ffs-ondisk:** On-disk parsers are **pure** (no I/O, no ambient authority) and return
`Result<T, ParseError>`. User-facing layers (mount/CLI/FUSE) return `FfsError` and MUST
convert `ParseError -> FfsError` at the orchestration boundary (`ffs-core`), adding
context (structure, offset, group/inode) without dumping large byte buffers.

| Structure | Size | Checksum |
|-----------|------|----------|
| `Superblock` | 1024 B | CRC32C (last 4 bytes = `s_checksum`) |
| `GroupDesc` | 32/64 B | CRC32C seeded with group number |
| `Inode` | 128/256 B | CRC32C of inode_nr + generation + inode bytes |
| `ExtentHeader` | 12 B | Covered by parent block checksum |
| `ExtentIndex` / `Extent` | 12 B each | Covered by parent block checksum |
| `DirEntry2` | 8+name | Covered by `DirEntryTail` CRC32C |
| `DxRoot` / `DxEntry` | variable / 8 B | Covered by directory block checksum |
| `JournalSuperblock` | 1024 B | CRC32C (JBD2 v3) |

All parsers MUST: validate magic numbers first, verify CRC32C when `metadata_csum` is enabled,
return `ParseError` for invalid input, never panic on malformed input.

**Acceptance Criteria:**
1. Parse real ext4 image superblock; verify `s_magic == 0xEF53`, block size, UUID match `dumpe2fs`
2. Round-trip all structures: `parse(serialize(x)) == x`
3. CRC32C verification: pass on valid data; on mismatch return `ParseError::InvalidField` with a stable reason string (e.g., `"superblock CRC32C mismatch"`)
4. Proptest round-trip for Superblock, Inode, Extent, DirEntry2, GroupDesc (10,000 iterations each)
5. Fuzz all parsers for 60s with no panics
6. Golden fixtures from 3 real ext4 images (64MB, 1GB, 10GB)
7. Parse all group descriptors; verify count and free counts match `dumpe2fs`

### 16.4 Phase 3: Block I/O (3,000 LOC)

**Goal:** Block device abstraction and ARC cache with Cx integration.

**Deliverables:** `BlockDevice` trait (read/write/sync with `&Cx`), `FileBlockDevice` (file-backed via `pread64`/`pwrite64` through asupersync `blocking_pool`), `ArcCache` (Megiddo & Modha 2003: T1/T2/B1/B2 ghost lists, self-tuning `p`), `CacheMetrics`, `DirtyTracker` (write-back flush), `PageLockTable` (sharded, `available_parallelism * 4` shards).

**ARC defaults:** capacity=8192 blocks (32MB), write-back, flush 5s. Adaptation: B1 hit -> `p += max(1, |B2|/|B1|)`; B2 hit -> `p -= max(1, |B1|/|B2|)`.

**Acceptance Criteria:**
1. Read block through cache matches direct `pread64`
2. Write-through-cache round-trip verified
3. Cache hit on second read (verified via metrics)
4. Eviction at capacity (verified via metrics and ARC policy)
5. ARC adaptation: `p` decreases during frequency-dominated workload
6. Dirty write-back after flush interval
7. Cancellation via `Cx` returns `FfsError::Cancelled`, cache state consistent
8. 16-thread concurrent reads succeed under Lab runtime
9. PageLockTable sharding: different-shard blocks accessed concurrently
10. Metrics counters exactly match known operation sequence

### 16.5 Phase 4: B-tree, Extent, Alloc (6,000 LOC)

**Goal:** Extent B+tree operations, logical-to-physical mapping, mballoc allocator, Orlov inode allocator.

**ffs-btree:** `search` O(log N), `insert` with split, `delete`, `split_node`, `merge_nodes`, `walk`.

**ffs-extent:** `resolve(ino, logical_block) -> Option<PhysicalBlock>`, `resolve_range`, `allocate_extent`, `truncate`, `hole_detection`.

**ffs-alloc:** mballoc (buddy-system bitmaps, best-fit, goal-oriented, pre-alloc). Orlov inode allocator. API: `allocate_blocks`, `free_blocks`, `allocate_inode`, `free_inode`.

**Acceptance Criteria:**
1. Resolve all extents in real ext4 image; physical block totals match `stat --format=%b`
2. Extent tree search correctness for every extent in real image
3. Insert 1000 random non-overlapping extents; walk verifies sorted, no overlaps
4. Node split produces valid children and parent index
5. Allocate/free 1000 blocks; bitmaps and free counts consistent
6. 100 contiguous blocks allocated are physically contiguous
7. 100 directories distributed across >= 5 block groups (Orlov)
8. Proptest: arbitrary insert/delete preserves tree invariants (10,000 iterations)
9. Proptest: arbitrary allocate/free maintains `free_count == initial - net_allocated`
10. Sparse file hole detection correct

### 16.6 Phase 5: Inode, Dir, Xattr (5,000 LOC)

**Goal:** Inode CRUD, directory linear scan + htree, extended attributes.

**ffs-inode:** `read_inode`, `write_inode`, `create_inode`, `delete_inode`, `update_timestamps`, `inc/dec_link_count`.

**ffs-dir:** `lookup` (htree-aware), `add_entry`, `remove_entry`, `list_entries`, `dx_hash` (half-MD4/TEA/SipHash, kernel-compatible), `create_htree`. `dx_hash` MUST match Linux `ext4_dx_hash` exactly.

**ffs-xattr:** `get/set/remove/list_xattr`. Namespaces: user(1), trusted(4), security(6), system(7). Inline when space permits; external block otherwise.

**Acceptance Criteria:**
1. List all files in real ext4 root directory; names, inodes, types match kernel mount
2. Recursive tree walk; total file count matches `find | wc -l`
3. `dx_hash` for 1000 filenames matches kernel golden values (all hash versions)
4. htree lookup in 10,000-entry directory finds all entries
5. Inode parse-write-reparse round-trip preserves all fields
6. Create and delete inode; inode number allocation/deallocation correct
7. Add/remove directory entry; listing reflects change
8. Xattr `user.test=hello` round-trip
9. Small xattr inline, large xattr external block -- both round-trip
10. Inode timestamp nanosecond precision; ctime updates on mtime change

### 16.7 Phase 6: Journal & MVCC (8,000 LOC)

**Goal:** JBD2 replay, COW journal, MVCC version chains, snapshot isolation, SSI, GC. Core innovation phase.

**ffs-journal:** JBD2 3-pass replay (SCAN, REVOKE, REPLAY), transaction log parser, revoke table, COW journal (native mode), recovery sequencer. JBD2 replay: read journal super (magic 0xC03B3998), collect descriptors and revokes, replay committed transactions skipping revoked blocks, clear journal.

**ffs-mvcc:** `VersionChain` (per-block, newest-first), `VersionStore` (sharded), `TxManager`, `Sequencer` (atomic CommitSeq), `SnapshotManager`, `SSI Detector`, `GarbageCollector`.

**SSI (Cahill-Rohm-Fekete):** Per-tx `in_conflict`/`out_conflict` booleans. On read: set `in_conflict` if block written by post-snapshot commit. On commit: for each written block, set `in_conflict` on active readers, `out_conflict` on self. Abort if both flags set.

**GC:** Keep newest version + one version <= oldest active snapshot. Do not prune versions backing current repair symbols.

**Acceptance Criteria:**
1. JBD2 replay: crash-simulated ext4 image replayed correctly, files intact
2. JBD2 revoke handling: revoked blocks skipped during replay
3. MVCC begin/read/write/commit lifecycle correct
4. Snapshot isolation: T1 sees pre-T2 version after T2 commits
5. First-Committer-Wins: second writer gets `MvccConflict`
6. SSI detects write-skew (quota scenario from Section 2.5)
7. SSI false positive rate: 0 false aborts in 10,000 non-conflicting pairs
8. GC preserves versions visible to active snapshots
9. Lab deterministic test: all interleavings of 3 concurrent 2-block transactions satisfy visibility invariant
10. Stress: 8 threads, 1000 transactions each (10 writes), no corruption, conflict rate within model bounds (Section 18)

### 16.8 Phase 7: FUSE (4,000 LOC)

**Goal:** `fuser::Filesystem` implementation and mount orchestration. Read-only and read-write mount of real ext4 images.

**ffs-fuse:** Implements `fuser::Filesystem`. Maps FUSE ops to internal crates: `lookup`/`readdir` -> ffs-dir, `getattr`/`setattr` -> ffs-inode, `read`/`write` -> ffs-extent + ffs-block (via MVCC), `create`/`mkdir`/`unlink`/`rmdir`/`rename`/`link` -> ffs-dir + ffs-inode, `symlink`/`readlink`, `statfs`, `fsync` -> flush + repair refresh.

**ffs-core:** `MountOrchestrator`, `FormatDetector`, `ConfigResolver`, `ShutdownSequencer`.

**Acceptance Criteria:**
1. Mount ext4 image; mountpoint accessible
2. `ls /mnt/ffs/` returns correct entries
3. `cat` known file returns expected content
4. `stat` output matches kernel mount
5. Read-only mount rejects writes with EROFS
6. Write: create file, unmount, remount, content persists
7. Write: mkdir with `.` and `..` entries
8. Write: rm frees inode and blocks
9. Write: rename preserves inode number
10. `fio` 4-thread random read/write; `fsck.ext4 -f` clean after unmount

### 16.9 Phase 8: Repair (4,000 LOC)

**Goal:** RaptorQ self-healing: repair symbol generation/storage, corruption detection, block recovery, scrub daemon.

**Deliverables:** `RepairSymbolEncoder`, `RepairSymbolStore` (reserved blocks at group end), `CorruptionDetector`, `BlockRecoverer` (RaptorQ decode), `ScrubDaemon` (background Region task), `StaleTracker`, `ScrubReport`.

**Repair budget:** At 5% default overhead: 1,638 repair symbols per 32,768-block group, recovering up to 1,638 corrupted blocks (6.4 MB per 128 MB group).

**Acceptance Criteria:**
1. Generate symbols; count matches overhead ratio
2. Single-block recovery: corrupt one block, recover, verify byte-exact
3. Multi-block recovery: corrupt 5 blocks, recover all
4. Over-budget: corrupt beyond budget, `RepairFailed` with report
5. Checksum detection: single bit flip detected with correct block number
6. Full scrub on clean image: all scanned, zero corruptions
7. Scrub with corruption: 3 blocks across 2 groups recovered
8. Stale tracking: write marks group stale, re-encode clears
9. Repair + MVCC: corrupted committed version recovered, chain consistent
10. Scrub daemon starts, runs periodically, shuts down cleanly via Region

### 16.10 Phase 9: CLI/TUI/Harness (5,000 LOC)

**Goal:** User-facing tools and conformance testing harness.

**ffs-cli:** `mount`, `unmount`, `info`, `fsck`, `repair`, `scrub`, `dump --inode/--block`, `bench`.

**ffs-tui:** 5 panels -- Cache (ARC stats), MVCC (tx/conflict/GC), I/O (IOPS/throughput/latency), Repair (scrub/recovery), Filesystem (usage/options).

**ffs-harness:** 240 conformance tests comparing FrankenFS against kernel ext4: readdir (50), read (40), stat (30), write (30), mkdir/rmdir (20), link/unlink (20), rename (15), xattr (15), permissions (10), timestamps (10). Golden JSON fixtures. Test images: 64MB (CI), 256MB (integration), 1GB (stress), 10GB (perf).

**ffs facade:** Re-exports `ffs::mount()`, `ffs::FsInfo`, `ffs::FsConfig`.

**Acceptance Criteria:**
1. `ffs mount` / `ffs unmount` lifecycle works
2. `ffs info` matches `dumpe2fs` for key fields
3. `ffs fsck` reports clean on good image, specific errors on corrupt
4. TUI renders all 5 panels, metrics update live, Ctrl+C clean exit
5. Conformance: 100% file listing match across 3 test image sizes
6. Conformance: 100% byte-exact file content match
7. Conformance: all `stat` fields match
8. After 10,000 file create/delete/rename via FrankenFS, `fsck.ext4 -f` clean
9. Benchmarks: seq read >= 500 MB/s, random read >= 50K IOPS on NVMe
10. Results recorded in `baselines/`

### 16.11 Phase Dependency Graph

```
Phase 1 (DONE) -> Phase 2 -> Phase 3 -> Phase 4 -> Phase 5
                                    \                  |
                                     +-> Phase 6 <----+
                                            |
                                         Phase 7
                                          /    \
                                    Phase 8   Phase 9 (depends on 7+8)
```

**Critical path:** 1 -> 2 -> 3 -> 6 -> 7 -> 9. **Parallel opportunities:** Phases 4 and 6 can start concurrently after Phase 3; Phase 8 core codec can start after Phase 3 (full integration needs Phase 7).

---

## 17. Testing Strategy

FrankenFS employs six complementary testing approaches because filesystem bugs manifest as silent data corruption.

### 17.1 Unit Tests (per-crate, minimum 680 total)

| Crate | Focus | Min Tests |
|-------|-------|-----------|
| ffs-types | Newtype arithmetic, overflow, Display | 30 |
| ffs-error | errno mapping, Display, From conversions | 20 |
| ffs-ondisk | Parse/serialize round-trip with golden fixtures | 80 |
| ffs-block | Mock BlockDevice, ARC cache behavior | 50 |
| ffs-btree | Tree invariants under insert/delete/split/merge | 60 |
| ffs-extent | Logical-to-physical mapping correctness | 40 |
| ffs-alloc | Bitmap correctness, free count maintenance | 50 |
| ffs-inode | Field encoding, timestamp nanoseconds, checksums | 40 |
| ffs-dir | htree hash compatibility with kernel dx_hash | 50 |
| ffs-xattr | Inline vs external routing, namespace encoding | 30 |
| ffs-journal | JBD2 descriptor/commit/revoke block parsing | 40 |
| ffs-mvcc | Lab runtime deterministic concurrency | 70 |
| ffs-fuse | FUSE request/response marshaling | 40 |
| ffs-repair | RaptorQ encode/decode round-trip | 50 |
| ffs-core | Mount sequence state transitions | 30 |

### 17.2 Integration Tests (cross-crate workflows)

| # | Scenario | Description |
|---|----------|-------------|
| I-1 | Mount and list | Mount real ext4 image, readdir root, verify matches kernel |
| I-2 | Read file | Open file, read all bytes, compare against known content |
| I-3 | Write and persist | Write file, unmount, remount, verify persistence |
| I-4 | Directory tree | mkdir -p a/b/c/d/e, verify all intermediates |
| I-5 | Delete reclaim | Create 1000 files, delete all, verify free counts restored |
| I-6 | Concurrent txs | 4 threads writing different files; no corruption |
| I-7 | MVCC snapshot | Reader sees pre-modification version during concurrent write |
| I-8 | Journal replay | Simulate crash, remount, verify journal replay and consistency |
| I-9 | Repair recovery | Generate symbols, corrupt block, mount, verify auto-recovery |
| I-10 | Full lifecycle | Create, write, read, delete, repair, unmount, fsck |

Test images via `mkfs.ext4`: sizes 64MB/256MB/1GB/10GB, configurable block size, inode size, features, file count, directory depth, sparse files.

### 17.3 Property Tests (proptest, 10K iterations CI / 100K nightly)

| # | Property | Invariant |
|---|----------|-----------|
| P-1..P-5 | On-disk round-trips | `parse(serialize(x)) == x` for Superblock, Inode, Extent, DirEntry2, GroupDesc |
| P-6..P-8 | Extent tree ops | Insert/delete/split/merge preserve: balanced depth, sorted keys, no overlaps, fill bounds |
| P-9 | Allocator | `free_count == initial - net_allocated` always |
| P-10 | MVCC visibility | `resolve(block, snapshot)` returns correct version per rules |
| P-11 | MVCC GC | No active snapshot sees a pruned version |
| P-12 | SSI soundness | Never produces non-serializable committed history |
| P-13 | ARC consistency | Cache never returns stale data; dirty blocks flushed before eviction |
| P-14 | Allocation uniqueness | No two allocations return same block |
| P-15 | Bitmap consistency | Bit states and free counts always agree |

### 17.4 Fuzz Tests (cargo-fuzz / libFuzzer)

| Target | Crate | Input | Duration: CI / Nightly / Weekly |
|--------|-------|-------|---------------------------------|
| fuzz_superblock | ffs-ondisk | `[u8; 1024]` | 60s / 10m / 1h |
| fuzz_group_desc | ffs-ondisk | `[u8; 64]` | 60s / 10m / 1h |
| fuzz_inode | ffs-ondisk | `[u8; 256]` | 60s / 10m / 1h |
| fuzz_extent_header | ffs-ondisk | `[u8; 12]` | 60s / 10m / 1h |
| fuzz_dir_entry | ffs-ondisk | `[u8; 263]` | 60s / 10m / 1h |
| fuzz_journal_header | ffs-ondisk | `[u8; 1024]` | 60s / 10m / 1h |
| fuzz_extent_tree | ffs-btree | op sequence | 60s / 10m / 1h |
| fuzz_mvcc_schedule | ffs-mvcc | tx op stream | 60s / 10m / 1h |

All targets MUST return `Err`, never panic. Corpus seeds from real ext4 images stored in `crates/<crate>/fuzz/corpus/<target>/`.

### 17.5 Conformance Harness (ffs-harness)

Workflow: `mkfs.ext4` -> populate with kernel driver -> mount with FrankenFS -> compare against golden fixtures (JSON).

**240 tests:** readdir (50), read (40), stat (30), write (30), mkdir/rmdir (20), link/unlink (20), rename (15), xattr (15), permissions (10), timestamps (10). Golden fixture schema:
```json
{ "fixture_version": 1, "image_params": { "size_mb": 256, "block_size": 4096 },
  "test_cases": [{ "id": "readdir_root", "operation": "readdir", "path": "/",
    "expected": { "entries": [{"name":".", "inode":2, "file_type":"directory"}] } }] }
```

### 17.6 Corruption Tests

| # | Scenario | Method | Expected |
|---|----------|--------|----------|
| C-1 | Superblock (no repair) | Flip bit in magic | `Format` error at mount |
| C-2 | Superblock (with repair) | Flip bit in magic | Auto-repair, mount succeeds |
| C-3 | Group descriptor | Zero out GD | Checksum mismatch, repair if available |
| C-4 | Inode table | Randomize one inode | `Corruption` on read |
| C-5 | Extent tree | Corrupt extent header magic | Tree walk error |
| C-6 | Data block | Zero one block | Checksum mismatch, repair or error |
| C-7 | Multi-block (in budget) | Corrupt 5 blocks/group | RaptorQ recovers all |
| C-8 | Multi-block (over budget) | Corrupt 2000 blocks/group | Partial recovery, report |
| C-9 | Journal | Corrupt journal super | Skip replay, `JournalCorrupt` |
| C-10 | Bitmap | Flip bitmap bits | Free count mismatch detected |

Injection methods: `flip_bit(block, offset, bit)`, `zero_block(block)`, `randomize_block(block)`, `swap_blocks(a, b)`.

### 17.7 Benchmarks (criterion, release-perf profile)

| # | Benchmark | Metric | Target |
|---|-----------|--------|--------|
| B-1 | Sequential read 1GB | MB/s | >= 500 |
| B-2 | Sequential write 1GB | MB/s | >= 300 |
| B-3 | Random read 4K | IOPS | >= 50K |
| B-4 | Random write 4K (MVCC) | IOPS | >= 20K |
| B-5 | ARC hit rate (zipfian) | % | >= 80% at 10% cache ratio |
| B-6 | Extent tree traversal (10K extents) | ns/op | <= 500 |
| B-7 | htree lookup (100K entries) | ns/op | <= 2,000 |
| B-8 | MVCC version chain walk (100 versions) | ns/op | <= 1,000 |
| B-9 | RaptorQ encode (32K blocks, 5%) | ms | <= 500 |
| B-10 | RaptorQ decode (5 missing) | ms | <= 100 |
| B-11 | MVCC commit (1 block) | us | <= 10 |
| B-12 | GC (10K versions) | ms | <= 50 |
| B-13 | Metadata create (10K files) | files/s | >= 5,000 |
| B-14 | Concurrent read scaling (1-16 threads) | factor | >= 0.8x linear at 8 |

Results recorded in `baselines/baseline-YYYYMMDD.md`. CI flags regressions > 10%.

### 17.8 Extreme Software Optimization Loop (Mandatory)

FrankenFS performance work MUST follow a strict optimize-with-proof loop:

1. **Baseline:** measure before changes (`hyperfine` against `ffs-harness` and relevant microbenches).
2. **Profile:** identify hotspots (Rust: `cargo flamegraph`; allocation: `heaptrack`; syscalls: `strace -c`).
3. **Prove behavior unchanged:** conformance fixtures + parity report MUST match, and any golden outputs MUST be checksum-verified.
4. **One lever at a time:** each commit changes exactly one performance lever (data structure, algorithm, batching, caching).
5. **Re-measure:** record deltas in `baselines/` and re-profile (hotspots shift).

For every optimization PR/patch, include an "isomorphism proof" note with:

- Ordering preserved: yes/no + why
- Tie-breaking unchanged: yes/no + why
- Floating-point identical: identical/N/A
- RNG seeds unchanged: unchanged/N/A
- Fixture parity: `ffs-harness -- check-fixtures` matches
- Parity report: `ffs-harness -- parity` unchanged (or updated intentionally)

---

## 18. Probabilistic Block Conflict Model

Formal analysis of write-write conflicts under block-level MVCC.

### 18.1 Model Parameters

| Symbol | Name | Typical Range |
|--------|------|---------------|
| N | Concurrent transactions | 1 -- 64 |
| B | Total blocks | 10^4 -- 10^8 |
| W | Blocks written per tx | 1 -- 1,000 |
| R | Blocks read per tx | 1 -- 10,000 |
| K | Hot metadata blocks | 1 -- 10,000 |

### 18.2 Uniform Random Write Conflict Probability

Each transaction writes W blocks uniformly at random from B total.

**P(T1 conflicts with at least one of N-1 others):**

```
P(conflict) = 1 - (1 - W/B)^(W * (N-1))
```

Poisson approximation for small W/B:

```
P(conflict) ≈ 1 - exp(-W^2 * (N-1) / B)
```

Expected conflicting pairs among N transactions:

```
E[conflicts] = C(N,2) * (1 - (1 - W/B)^W)
```

### 18.3 Numerical Results

| Profile | N | B | W | P(conflict/tx) | Aborts/1000 tx |
|---------|---|---|---|-----------------|----------------|
| Light desktop | 4 | 10^6 | 5 | 7.5 x 10^-5 | 0.075 |
| Moderate server | 8 | 10^6 | 10 | 7.0 x 10^-4 | 0.70 |
| Heavy OLTP | 16 | 10^6 | 50 | 3.7 x 10^-2 | 36.6 |
| Extreme stress | 64 | 10^6 | 100 | 4.7 x 10^-1 | 468 |
| Sequential writes | 8 | 10^6 | 1000 | N/A (model inapplicable) | N/A |

> **Note on "Sequential writes":** The uniform random model does NOT apply to sequential writes. Under the formula, W=1000 with B=10^6 gives P ≈ 1 - exp(-1000² × 7 / 10^6) = 1 - exp(-7000) ≈ 1.0, not ~0. Sequential writes avoid conflict because they target *disjoint* regions by construction — the random model's assumptions are violated. This row shows that locality-aware allocation (each writer gets its own region) eliminates conflicts regardless of W.

Under typical workloads (Light/Moderate), conflicts are fewer than 1 per 1000 transactions.

### 18.4 Metadata Hot-Block Analysis

Real workloads are not uniform. Hot blocks:

| Block Type | Count (1M-block FS) | Contention Pattern |
|-----------|---------------------|-------------------|
| Block/inode bitmaps | 8 each | Written on every alloc/free in group |
| Inode table blocks | ~4,096 | Written on every inode modify |
| Group descriptors | 8-16 | Written on alloc/free (free counts) |
| Superblock | 1 | Written on mount count, free count updates |

**Inode table (birthday problem):** 16 inodes per 4K block, 512 table blocks per group:

```
P(two new inodes in same block | same group) = 1/512 ≈ 0.002
```

For N concurrent creates in same group (birthday approximation):

```
P(any inode table conflict) ≈ 1 - exp(-N*(N-1) / (2*512))
```

| N (same group) | P(inode table conflict) |
|----------------|------------------------|
| 2 | 0.002 |
| 4 | 0.012 |
| 8 | 0.053 |
| 16 | 0.197 |
| 32 | 0.577 |

**Bitmap:** Two transactions allocating in the same group -> P(conflict) = 1.0 (single bitmap block).

### 18.5 Mitigation Strategies

| Hot Block | Mitigation | Effect |
|-----------|------------|--------|
| Bitmaps | Orlov spreads creates across G groups | Reduces to P(same group) = 1/G |
| Inode table | Orlov + random inode selection | Reduces by factor of G * T/N |
| Group descriptor | Per-group allocation | P(same group) = 1/G |
| Superblock | Batched deferred writes | Reduces frequency ~100x |
| Directory blocks | htree distributes across multiple blocks | Reduces by factor of block count |

**With 8 groups (Moderate):** The pairwise probability that two allocating transactions target the same group is `1/G = 1/8 = 12.5%`. Given same-group means bitmap conflict is 100%, the effective pairwise bitmap conflict rate is `1/G = 12.5%`. Inode table conflict (given same group) is `1/512 ≈ 0.2%`, so the unconditional pairwise inode table conflict rate is `1/(G × 512) = 1/4096 ≈ 0.024%`.

> **Correction:** Earlier text stated `(1/8)^2 = 1.6%` for bitmap conflict. This is wrong — `(1/G)^2` would be the probability that two independent events *each* pick a specific group, not the same group. The correct pairwise same-group probability is `1/G`.

### 18.6 SSI Overhead

**Memory:** `8*R + 8*W + 2` bytes/tx. For R=100, W=10: 882 bytes. N=8: ~7 KB total.

**Commit check:** O(W * N * avg(R)) lookups. W=10, N=8, R=100: ~8,000 lookups, ~80 us. Dwarfed by NVMe I/O (~100 us/write).

### 18.7 Version Chain Memory

Per `BlockVersion`: 48 bytes header + 4,096 bytes data (or 8 bytes Arc pointer).

| Scenario | N | W | Uncommitted Versions | Header | Data |
|----------|---|---|---------------------|--------|------|
| Light | 4 | 5 | 20 | 960 B | 80 KB |
| Moderate | 8 | 10 | 80 | 3.8 KB | 320 KB |
| Heavy | 16 | 50 | 800 | 38 KB | 3.2 MB |
| Extreme | 64 | 100 | 6,400 | 300 KB | 25.6 MB |

**Steady-state chain length (average per block):** `1 + (N × W × tx_duration) / B`, where `tx_duration` is the average time a transaction's versions remain before GC. For Moderate (N=8, W=10, tx_duration ~0.8s assuming GC every 5s and N concurrent txns, B=10^6): `1 + (8 × 10 × 0.8) / 10^6 ≈ 1.000064`. Most blocks have exactly 1 version. GC runs every 100 commits or 5s.

> **Note:** The earlier formula `1 + N * W * N * tx_rate / B` is dimensionally incorrect (it mixes transaction count with rate). The corrected formula above computes the expected extra version depth as (concurrent writes in flight) / (total blocks).

### 18.8 Worst Cases

| Scenario | Conflict Rate | Mitigation |
|----------|--------------|------------|
| N transactions, same directory | ~100% | htree distributes across blocks |
| N transactions allocate same group | ~100% on bitmaps | Orlov distributes across groups |
| Long snapshot + heavy writes | 0% conflicts but memory grows | GC warns at 10% RAM threshold |
| Superblock free count update | ~100% | Batched deferred writes |

**Worst-case memory (long snapshot):** 1GB FS (262K blocks), 1-hour snapshot, 100 writes/s -> up to 1 GB version data. GC SHOULD warn when version memory exceeds configurable threshold (default 10% RAM).

### 18.9 Summary

Block-level MVCC provides significant concurrency benefits for real workloads: fewer than 1 in 1,000 transactions conflict under typical operation. Hot-block contention is mitigated by Orlov allocation and htree indexing. SSI overhead is bounded and small relative to I/O costs, confirming SERIALIZABLE isolation without meaningful performance penalty.
## 19. C ext4/btrfs Behavioral Reference

This section summarizes key behavioral patterns extracted from the Linux
kernel C source code (v6.19, `legacy_ext4_and_btrfs_code/linux-fs/fs/ext4/`
and `.../btrfs/`) that FrankenFS MUST replicate faithfully for compatibility
or MUST explicitly diverge from with documented rationale. Each subsection
references the canonical C function, describes the behavioral contract, and
specifies FrankenFS's conformance posture.

### 19.1 Superblock Validation Sequence

**C Reference:** `ext4_load_super()` and `__ext4_fill_super()` in `super.c`
(lines 5080-5180 and 5292-5490 respectively).

The kernel validates the superblock in a strict sequential pipeline. FrankenFS
MUST replicate this sequence in `ffs-core::mount::validate_superblock()`:

1. **Read raw superblock bytes.** The superblock is always at byte offset 1024
   from the start of the device, regardless of block size. For block sizes
   larger than 1024, the superblock is embedded at offset 1024 within block 0.
   For 1K block size, the superblock occupies block 1 entirely. The initial
   read uses the minimum block size (1024) for the first pass.

2. **Check magic number.** `es->s_magic` MUST equal `EXT4_SUPER_MAGIC`
   (0xEF53, stored as little-endian `le16`). The kernel performs
   `le16_to_cpu(es->s_magic) != EXT4_SUPER_MAGIC`. FrankenFS MUST return
   `ParseError::InvalidMagic` (from `ffs-types`) on mismatch. This is the
   first validation and MUST precede all other field reads.

3. **Validate log block size.** `es->s_log_block_size` MUST satisfy
   `s_log_block_size <= (EXT4_MAX_BLOCK_LOG_SIZE - EXT4_MIN_BLOCK_LOG_SIZE)`.
   `EXT4_MIN_BLOCK_LOG_SIZE` is 10 (1024 bytes), `EXT4_MAX_BLOCK_LOG_SIZE`
   is 16 (65536 bytes). The actual block size is computed as
   `1024 << s_log_block_size`. FrankenFS supports only block sizes 1024, 2048,
   and 4096 (log values 0, 1, 2). Log values 3-6 are rejected with
   `ParseError::InvalidField` (field="s_log_block_size", reason="unsupported block size").

4. **Re-read at correct block size.** If the computed block size differs from
   the initial 1K read, the superblock is re-read at the correct block size
   and the magic number is validated a second time (`super.c` lines 5155-5178).
   FrankenFS MUST perform this re-read.

5. **Initialize metadata checksum.** `ext4_init_metadata_csum()` validates
   the `metadata_csum` feature flag and computes the checksum seed
   (`s_checksum_seed = crc32c(~0, s_uuid)`). FrankenFS MUST compute the seed
   identically and verify the superblock checksum field
   `es->s_checksum` using CRC32C of the entire superblock structure (excluding
   the checksum field itself).

6. **Check feature compatibility.** `ext4_check_feature_compatibility()`
   (line 4665) examines three feature flag sets:
   - `s_feature_compat`: Compatible features. Unknown flags are ignored.
   - `s_feature_ro_compat`: Read-only compatible features. Unknown flags
     require mounting read-only.
   - `s_feature_incompat`: Incompatible features. Unknown flags MUST cause
     mount failure with `FfsError::Format("unknown incompatible feature flags")`.

   FrankenFS MUST refuse to mount (not just warn) if any unknown incompatible
   feature flag is set. Known incompatible features that FrankenFS supports:
   `filetype`, `extents`, `64bit`, `flex_bg`, `huge_file`, `dir_nlink`,
   `extra_isize`, `metadata_csum`, `mmp` (read-only awareness).

7. **Validate block group geometry.** `ext4_check_geometry()` (line 4769)
   validates:
   - `s_first_data_block < s_blocks_count`
   - For 1K block size with cluster ratio 1: `s_first_data_block != 0`
   - Total block groups = `ceil((s_blocks_count - s_first_data_block) /
     s_blocks_per_group)`. Result stored as `sbi->s_groups_count`.
   - `s_inodes_count == s_groups_count * s_inodes_per_group`
   - Device size (in blocks) >= `s_blocks_count`
   - Reserved GDT blocks <= `blocksize / 4`

   FrankenFS MUST replicate all of these checks. Failure at any step MUST
   return `FfsError::Format` with a diagnostic message identifying which
   geometry check failed (e.g., `FfsError::Format("invalid geometry: s_first_data_block >= s_blocks_count")`).

8. **Initialize group descriptors.** `ext4_group_desc_init()` reads and
   validates all group descriptor blocks. Each descriptor is verified with
   CRC16 or CRC32C depending on the `metadata_csum` feature. FrankenFS MUST
   verify group descriptor checksums during mount and report
   `FfsError::Corruption` for mismatches (triggering RaptorQ repair if
   repair symbols are available).

9. **Load journal.** `ext4_load_and_init_journal()` loads the JBD2 journal
   inode, reads the journal superblock, and replays if needed. See Section
   19.6 for JBD2 replay details.

**FrankenFS Divergence:** Steps 1-8 are replicated exactly. Step 9 (journal
load) applies only in JBD2-compatible mode. In native MVCC mode, the journal
is replayed (if dirty) and then the MVCC version store is initialized.

### 19.2 Extent Tree Traversal

**C Reference:** `ext4_find_extent()` in `extents.c` (line 887).

The extent tree is a B+tree rooted in the inode's `i_block[0..14]` field
(60 bytes), which contains an `ext4_extent_header` followed by extent entries
or index entries depending on depth. FrankenFS MUST replicate this traversal
in `ffs-btree::extent_tree::find_extent()`:

1. **Read extent header from inode.** The header at depth 0 is in-line in the
   inode body. Validate: `eh_magic == 0xF30A`, `eh_depth >= 0`,
   `eh_depth <= EXT4_MAX_EXTENT_DEPTH` (5), `eh_entries <= eh_max`.

2. **Determine tree depth.** `depth = eh_depth` from the root header. A depth
   of 0 means the root contains leaf extents directly. A depth of N means
   there are N levels of index nodes before the leaf level.

3. **Walk internal levels (depth > 0).** At each internal level:
   a. **Binary search** the `ext4_extent_idx` entries for the target logical
      block. The search finds the largest `ei_block <= target`. The kernel
      implementation (`ext4_ext_binsearch_idx`, not shown) uses standard
      binary search: `p = entries + 1`, `q = entries + count - 1`, splitting
      on `m = p + (q - p) / 2`, comparing `le32_to_cpu(m->ei_block)` against
      the target.
   b. **Read child block.** The physical block number of the child node is
      `ei_leaf_lo | (ei_leaf_hi << 32)`. Read the block and verify its
      extent header: `eh_magic == 0xF30A`, `eh_depth == expected_depth - 1`.
   c. **Verify checksum.** If `metadata_csum` is enabled, the extent block
      has a 4-byte `ext4_extent_tail` at the end containing a CRC32C checksum.
      The checksum covers the extent header and all entries, using the inode's
      checksum seed.

4. **Search leaf level.** At the leaf level, binary search the
   `ext4_extent` entries for the largest `ee_block <= target`. The kernel
   function `ext4_ext_binsearch()` performs this search.

5. **Compute physical block.** If a matching extent is found with
   `ee_block <= target < ee_block + ee_len`, the physical block is:
   ```
   physical = (ee_start_lo | (ee_start_hi << 16)) + (target - ee_block)
   ```
   If no extent covers the target, the block is a hole (returns zero-filled
   data for reads; triggers allocation for writes).

6. **Extent cache.** At depth 0, the kernel caches all extents in an
   in-memory extent status tree (`ext4_cache_extents()`). FrankenFS SHOULD
   implement an analogous cache in `ffs-extent::ExtentCache` to avoid
   repeated inode reads for sequential access.

**FrankenFS Divergence:** The traversal algorithm is identical. FrankenFS adds
MVCC version resolution at each block read: when reading an extent tree node
block, the block is resolved through `mvcc.resolve(block_nr, snapshot)` to
get the version visible to the current transaction. This is transparent to
the traversal algorithm.

### 19.3 Multi-Block Allocator (mballoc)

**C Reference:** `ext4_mb_new_blocks()` in `mballoc.c` (line 6236) and
`ext4_mb_regular_allocator()` (line 2985).

The mballoc allocator uses a multi-criteria search strategy defined by the
`enum criteria` in `ext4.h` (line 137). FrankenFS MUST replicate this
strategy in `ffs-alloc::mballoc::allocate_blocks()`:

**Allocation Flow:**

1. **Check preallocation.** Before entering the regular allocator, check if
   the inode has preallocated space (`ext4_mb_use_preallocated()`). If a
   preallocation covers the requested logical block range, consume it directly
   (no disk I/O needed). FrankenFS MUST support per-inode preallocation lists.

2. **Normalize request.** `ext4_mb_normalize_request()` adjusts the
   allocation request to request more blocks than immediately needed
   (preallocation). For small files (< `s_mb_stream_request` blocks, default
   16), use group preallocation (locality groups). For larger files, use
   per-inode preallocation. FrankenFS MUST replicate this normalization.

3. **Regular allocator criteria cascade.** `ext4_mb_regular_allocator()`
   tries criteria in order, escalating on failure:

   | Criteria | Name | Behavior | FrankenFS Crate |
   |----------|------|----------|-----------------|
   | `CR_POWER2_ALIGNED` | Power-of-2 aligned | For requests whose length is a power of 2: find a group with a buddy of exactly this order. No disk I/O (uses in-memory buddy order lists). Fastest path. | `ffs-alloc` |
   | `CR_GOAL_LEN_FAST` | Goal-length fast | Find a group whose average free fragment size >= requested length. Uses in-memory fragment lists indexed by average fragment size. No disk I/O. | `ffs-alloc` |
   | `CR_BEST_AVAIL_LEN` | Best available | Same as GOAL_LEN_FAST but proactively trims the goal length to the best available fragment length. Tries to find usable space before falling to the slow path. | `ffs-alloc` |
   | `CR_GOAL_LEN_SLOW` | Goal-length slow | Sequentially scans all block groups, reading buddy bitmaps from disk if not cached. Tries to allocate the full requested length but may trim. | `ffs-alloc` |
   | `CR_ANY_FREE` | Any free | Last resort. Allocates any available free block(s). Used only when all other criteria fail. Scans all groups for any free space. | `ffs-alloc` |

4. **Buddy bitmap system.** Each block group has a buddy bitmap that tracks
   free block runs at power-of-2 granularities. The buddy bitmap is a
   hierarchical structure: level 0 tracks individual blocks, level 1 tracks
   pairs, level 2 tracks quads, etc. up to the full group size. FrankenFS
   MUST implement buddy bitmaps for efficient free-space search.

5. **Goal-directed allocation.** The allocator uses a "goal" block as a
   starting hint. For file data, the goal is typically the physical block
   following the file's last extent (for contiguity). For metadata, the goal
   is the block group's metadata area. FrankenFS MUST pass extent-derived
   goals to the allocator.

6. **Mark disk space used.** On successful allocation,
   `ext4_mb_mark_diskspace_used()` updates the block bitmap, buddy bitmap,
   group descriptor free count, and superblock free count atomically within
   a JBD2 transaction. In FrankenFS native mode, these updates are performed
   as MVCC block writes to the bitmap, buddy, and descriptor blocks.

**FrankenFS Divergence:** The allocation strategy (criteria cascade, buddy
bitmaps, preallocation) is replicated. The key difference is that bitmap and
descriptor updates use MVCC block writes instead of JBD2 transactions. This
means concurrent allocations in different block groups proceed without
contention (different bitmap blocks), while concurrent allocations in the same
group are serialized by block-level FCW on the shared bitmap block.

### 19.4 Htree Directory Lookup

**C Reference:** `dx_probe()` in `namei.c` (line 778).

ext4 uses a hashed B-tree (htree) for O(log n) directory lookup in large
directories. FrankenFS MUST replicate this in `ffs-dir::htree::lookup()`:

1. **Read dx_root (block 0 of directory inode).** The first directory block
   contains a `dx_root` structure with:
   - `info.hash_version`: hash algorithm selector
     - `DX_HASH_LEGACY` (0): unsigned legacy hash
     - `DX_HASH_HALF_MD4` (1): half-MD4 hash
     - `DX_HASH_TEA` (2): TEA (Tiny Encryption Algorithm) hash
     - `DX_HASH_SIPHASH` (4): SipHash for encrypted+casefolded dirs
   - `info.indirect_levels`: htree depth (0 = one level of dx_entries, 1 =
     two levels, etc.). MUST be < `ext4_dir_htree_level()` (2 without
     `large_dir` feature, 3 with it).
   - `info.info_length`: offset to dx_entry array from start of info struct.
   - `info.unused_flags`: MUST be 0 (bit 0 set indicates unimplemented flags).

2. **Compute target hash.** Using the hash algorithm specified by
   `hash_version` and the hash seed from `s_hash_seed` (4 x `__u32` in the
   superblock), compute the hash of the target filename via
   `ext4fs_dirhash()` (`hash.c`). FrankenFS MUST implement all three hash
   algorithms:

   - **half_md4:** A cut-down MD4 transform producing a 32-bit hash. Uses
     three rounds (F, G, H) with constants K1=0, K2=013240474631,
     K3=015666365641 (octal). The hash seed initializes the 4-word state.
   - **TEA:** Tiny Encryption Algorithm. 16 rounds of TEA transform with
     delta=0x9E3779B9. The hash seed provides the key.
   - **SipHash:** Used only with encrypted+casefolded directories. FrankenFS
     excludes casefolded directories (Section 1.8), so SipHash is implemented
     but not exercised in normal operation.

   FrankenFS MUST also handle the `s_hash_unsigned` flag: if set, character
   values are treated as unsigned during hashing (DX_HASH_HALF_MD4 becomes
   DX_HASH_HALF_MD4_UNSIGNED, etc.).

3. **Binary search at each tree level.** Starting from the dx_entry array
   following dx_root (or at each internal node for deeper trees):
   a. Read `count` from `dx_get_count(entries)`. Validate
      `count > 0 && count <= limit`.
   b. Binary search entries `[1..count-1]` (entry 0 is the sentinel with
      hash=0). Find the last entry whose hash <= target hash:
      ```
      p = entries + 1; q = entries + count - 1;
      while (p <= q) {
          m = p + (q - p) / 2;
          if (hash(m) > target) q = m - 1;
          else p = m + 1;
      }
      at = p - 1;  // this is the matching entry
      ```
   c. The block number from `dx_get_block(at)` points to either the next
      level of dx_entries or a leaf directory block.

4. **Read leaf block.** At the leaf level, the target block contains standard
   `ext4_dir_entry_2` records. Perform a linear scan for the exact filename
   match. Each entry has: `inode` (4 bytes), `rec_len` (2 bytes), `name_len`
   (1 byte), `file_type` (1 byte), `name` (variable).

5. **Checksum verification.** If `metadata_csum` is enabled, each directory
   block has a fake directory entry at the end with `inode == 0` and
   `name_len == 0`, whose remaining space holds a `dx_tail` structure
   containing a CRC32C checksum. FrankenFS MUST verify these checksums.

**FrankenFS Divergence:** The htree lookup algorithm is replicated exactly.
Each directory block read is resolved through MVCC, ensuring that concurrent
directory modifications (in MVCC mode) do not produce inconsistent views.

**Conformance Requirement:** FrankenFS MUST produce identical hash values for
identical filenames given identical seed and algorithm as the kernel. This is
verified by the conformance test suite (Gate 3): hash FrankenFS output against
`debugfs -R 'htree /path' image.img` output for test images.

### 19.5 Btrfs COW Semantics (Reference for MVCC Design)

**C Reference:** `btrfs_cow_block()` in `ctree.c` (line 660) and
`btrfs_force_cow_block()` (line 478).

FrankenFS does not implement btrfs on-disk format, but its MVCC engine is
directly inspired by btrfs COW semantics. The following behavioral patterns
from btrfs inform FrankenFS's design:

1. **should_cow_block guard.** Before COWing, btrfs checks
   `should_cow_block()` (line 616):
   - If the block was already written in this transaction (`header_generation
     == trans->transid`) AND is not marked `WRITTEN` AND root is not
     `FORCE_COW`: skip COW, return existing buffer.
   - **FrankenFS equivalent:** Transaction-local writes check
     `version_chain.has_uncommitted_version(tx_id)`. If the current
     transaction already wrote this block, the existing uncommitted
     `BlockVersion` is returned for in-place update (no new version created).

2. **Allocate new block.** `btrfs_alloc_tree_block()` allocates a new physical
   location. Search starts near the original block (`round_down(buf->start,
   SZ_1G)`) for locality.
   - **FrankenFS equivalent:** COW allocation uses `ffs-alloc` with a goal
     hint of the original block number for spatial locality.

3. **Copy old content.** `copy_extent_buffer_full(cow, buf)` copies the
   entire old block content to the new block.
   - **FrankenFS equivalent:** `BlockVersion::new_cow(old_version.data.clone())`
     creates the new version with a copy of the old data.

4. **Update parent pointer.** `btrfs_set_node_blockptr(parent, parent_slot,
   cow->start)` updates the parent tree node to point to the new location.
   Parent is also COWed (recursively up the tree) if needed.
   - **FrankenFS equivalent:** In MVCC mode, the parent extent tree node or
     directory index node is also written (creating a new version), and its
     entry is updated to point to the new block. This cascading COW is
     bounded by tree depth (maximum 5 for extent trees, 3 for htrees).

5. **Free old block.** `btrfs_free_tree_block()` marks the old block for
   deferred freeing (added to the delayed-ref system, freed at transaction
   commit).
   - **FrankenFS equivalent:** The old `BlockVersion` is not freed immediately.
     It remains in the version chain, visible to older snapshots. The GC
     daemon prunes it when no active snapshot references it.

6. **Transaction ID stamping.** The new block header gets
   `generation = trans->transid` and the `WRITTEN` flag is cleared.
   - **FrankenFS equivalent:** The new `BlockVersion` gets
     `commit_seq = 0, committed = false` until commit, at which point it gets
     the assigned `CommitSeq` and `committed = true`.

**Key Behavioral Difference:** Btrfs COW is tree-oriented (COW propagates up
the B-tree from leaf to root). FrankenFS COW is block-oriented (each block
is independently versioned). In btrfs, a single metadata write causes O(depth)
block allocations. In FrankenFS, a single metadata write creates one new
`BlockVersion` per modified block, but the version chain management is O(1)
per block. FrankenFS avoids the cascading-COW cost for metadata trees by
versioning blocks independently; the tree structure is implicit in the
content of each versioned block.

### 19.6 JBD2 Journal Replay

**C Reference:** `jbd2_journal_recover()` in `fs/jbd2/recovery.c` (not in
sparse checkout, but behavior is well-documented in the kernel and the JBD2
journal format is defined in `ext4_jbd2.h`).

FrankenFS MUST implement JBD2 journal replay for mounting ext4 images that
were not cleanly unmounted. This is required even in native MVCC mode (the
journal is replayed first, then MVCC takes over). Implementation resides in
`ffs-journal::replay`:

1. **Read journal superblock.** The journal occupies a dedicated inode
   (typically inode 8, stored in `s_journal_inum`). The journal superblock is
   in block 0 of the journal inode and contains:
   - `s_header.h_magic`: MUST equal `JBD2_MAGIC_NUMBER` (0xC03B3998)
   - `s_header.h_blocktype`: MUST equal `JBD2_SUPERBLOCK_V1` (3) or
     `JBD2_SUPERBLOCK_V2` (4)
   - `s_blocksize`: MUST match filesystem block size
   - `s_maxlen`: journal length in blocks
   - `s_first`: first block of log information (after superblock)
   - `s_sequence`: expected next transaction sequence number
   - `s_start`: block number of start of log (0 = clean, no replay needed)

   If `s_start == 0`, the journal is clean and no replay is needed. FrankenFS
   MUST check this first and skip replay for clean journals.

2. **Scan pass (PASS_SCAN).** Starting from `s_start`, scan forward through
   the journal looking for valid descriptor and commit blocks:
   - **Descriptor block** (`h_blocktype == JBD2_DESCRIPTOR_BLOCK`): contains
     `journal_block_tag_t` entries mapping journal blocks to their filesystem
     target locations. Each tag has `t_blocknr` (target block low 32 bits),
     `t_blocknr_high` (upper 32 bits for 64-bit filesystems), and `t_flags`
     (escape flag, same-UUID, last-tag, checksum flags).
   - **Commit block** (`h_blocktype == JBD2_COMMIT_BLOCK`): marks the end of
     a complete transaction. Contains a checksum covering all descriptor and
     data blocks in the transaction.
   - **Revoke block** (`h_blocktype == JBD2_REVOKE_BLOCK`): contains a list
     of block numbers that should NOT be replayed from earlier transactions
     (they have been superseded).

   The scan builds a list of complete transactions (those with both descriptor
   and commit blocks) and a revocation table.

3. **Revoke pass (PASS_REVOKE).** Process all revoke blocks to build the
   complete revocation hash table. Any filesystem block in this table was
   written by a later transaction and should not be overwritten by replay of
   an earlier transaction.

4. **Replay pass (PASS_REPLAY).** For each complete transaction (in order):
   - For each data block referenced by a descriptor tag:
     - Check if the target block number is in the revocation table with a
       sequence number >= this transaction's sequence. If so, skip.
     - Read the journal data block.
     - If the tag has `JBD2_FLAG_ESCAPE`, restore the magic number
       (0xC03B3998) in the first 4 bytes (it was escaped to prevent the
       journal scanner from misinterpreting the data block as a journal
       header).
     - Write the data block to its target filesystem location.

5. **Update journal superblock.** Set `s_start = 0` (marking journal clean)
   and update `s_sequence` to the next expected sequence number. Write the
   journal superblock.

**FrankenFS Conformance:** Replay correctness is verified by Gate 5: create
ext4 images, perform operations, simulate crash (do not unmount), mount with
FrankenFS, verify all data is consistent. Test images include edge cases:
wrapped journal (transactions that cross the end-of-journal boundary), escaped
blocks, revoke records that cancel earlier writes.

**FrankenFS Divergence:** After journal replay completes in MVCC mode, the
journal is marked clean and MVCC version chains are initialized from the
replayed state. No further JBD2 writes occur in MVCC mode.

### 19.7 Inode Read Path

**C Reference:** `ext4_iget()` / `__ext4_iget()` in `inode.c`,
`ext4_get_inode_loc()` for locating the inode on disk.

The inode read path computes the physical location of an inode from its inode
number and reads it from the inode table:

1. **Compute block group.** `group = (ino - 1) / s_inodes_per_group`.
2. **Compute offset within group.** `offset = (ino - 1) % s_inodes_per_group`.
3. **Read group descriptor.** Get `bg_inode_table` from the group descriptor
   for this block group (the physical block number of the start of the inode
   table for this group).
4. **Compute block within inode table.**
   `block = bg_inode_table + (offset * s_inode_size) / blocksize`.
5. **Compute byte offset within block.**
   `byte_offset = (offset * s_inode_size) % blocksize`.
6. **Read the block.** Read the inode table block from disk.
7. **Parse inode.** Extract the `ext4_inode` structure starting at
   `byte_offset`. Validate the inode checksum if `metadata_csum` is enabled.

FrankenFS MUST replicate this computation exactly in
`ffs-inode::InodeReader::read_inode()`. The inode block read goes through
MVCC resolution in native mode.

### 19.8 Inode Allocation (Orlov Algorithm)

**C Reference:** `find_group_orlov()` in `ialloc.c` (line 422),
`__ext4_new_inode()` (line 925).

The Orlov allocator distributes directory inodes across block groups to avoid
clustering while co-locating file inodes near their parent directory:

1. **Directory allocation:** Find a block group with above-average free inodes
   and below-average directory count. If the filesystem has flex_bg enabled,
   Orlov operates at flex_bg granularity. The algorithm selects a group that
   balances:
   - Free inode count (higher is better)
   - Free block count (higher is better for future file data)
   - Directory count (lower is better to spread directories)

2. **File allocation:** Allocate the inode in the same block group (or flex_bg
   group) as the parent directory. This co-locates file data with its parent
   directory for locality. If the parent group is full, fall back to the Orlov
   spread strategy.

FrankenFS MUST replicate the Orlov allocator in `ffs-alloc::ialloc`. The Orlov
statistics (`struct orlov_stats`: `free_inodes`, `free_clusters`, `used_dirs`)
are computed per flex_bg group and used identically to the kernel's algorithm.

---

## 20. Key Reference Files

This section provides a comprehensive mapping from Linux kernel C source files
to FrankenFS Rust crates, identifying the key data structures and functions in
each file and which crate is responsible for their Rust reimplementation.

### 20.1 ext4 Header Files

| C Source File | Key Structures / Constants | FrankenFS Crate | Notes |
|---|---|---|---|
| `ext4.h` | `ext4_super_block` (disk superblock layout, 1024 bytes), `ext4_inode` (on-disk inode, 128/256 bytes), `ext4_group_desc` (group descriptor, 32/64 bytes), `EXT4_SUPER_MAGIC` (0xEF53), feature flag constants (`EXT4_FEATURE_INCOMPAT_*`, `EXT4_FEATURE_RO_COMPAT_*`, `EXT4_FEATURE_COMPAT_*`), `enum criteria` (mballoc criteria: `CR_POWER2_ALIGNED` through `CR_ANY_FREE`) | `ffs-ondisk` (structures), `ffs-alloc` (criteria enum) | Primary header; ~3400 lines. All on-disk format definitions originate here. |
| `ext4_extents.h` | `ext4_extent_header` (`eh_magic`, `eh_entries`, `eh_max`, `eh_depth`, `eh_generation`), `ext4_extent` (`ee_block`, `ee_len`, `ee_start_hi`, `ee_start_lo`), `ext4_extent_idx` (`ei_block`, `ei_leaf_lo`, `ei_leaf_hi`, `ei_unused`), `ext4_extent_tail` (checksum) | `ffs-ondisk` (layout), `ffs-btree` (traversal) | Extent tree node structures. |
| `ext4_jbd2.h` | `ext4_journal_cb_entry`, transaction credit constants (`EXT4_DATA_TRANS_BLOCKS`, `EXT4_META_TRANS_BLOCKS`), `ext4_journal_get_write_access()`, `ext4_handle_dirty_metadata()` | `ffs-journal` | JBD2 integration layer for ext4. |
| `mballoc.h` | `ext4_allocation_context`, `ext4_allocation_request`, `ext4_buddy` (buddy bitmap), `ext4_prealloc_space`, per-CPU locality groups | `ffs-alloc` | Multi-block allocator internal types. |
| `xattr.h` | `ext4_xattr_entry` (name_index, name_len, value_offs, value_block, value_size), `ext4_xattr_ibody_header`, `ext4_xattr_header`, `XATTR_MAGIC` (0xEA020000) | `ffs-xattr` | Extended attribute format definitions. |
| `extents_status.h` | `extent_status` (in-memory extent cache), `ES_WRITTEN`, `ES_UNWRITTEN`, `ES_DELAYED`, `ES_HOLE` | `ffs-extent` | Extent status tree for caching. |

### 20.2 ext4 Implementation Files

| C Source File | Key Functions | FrankenFS Crate | Notes |
|---|---|---|---|
| `super.c` | `ext4_load_super()` (magic check, block size validation, re-read), `__ext4_fill_super()` (full mount pipeline: feature check, geometry, group desc, journal), `ext4_check_feature_compatibility()`, `ext4_check_geometry()`, `ext4_commit_super()`, `ext4_statfs()` | `ffs-core` | Mount/unmount orchestration. ~6200 lines. |
| `inode.c` | `ext4_iget()` / `__ext4_iget()` (read inode from disk), `ext4_get_inode_loc()` (compute inode block/offset), `ext4_do_update_inode()` (write inode), `ext4_setattr()`, `ext4_write_begin()` / `ext4_write_end()` | `ffs-inode` | Inode read/write path. ~6000 lines. |
| `extents.c` | `ext4_find_extent()` (B+tree traversal), `ext4_ext_insert_extent()` (add new extent), `ext4_ext_binsearch()` / `ext4_ext_binsearch_idx()` (binary search), `ext4_ext_map_blocks()` (high-level extent mapping), `ext4_split_extent_at()` (split for partial writes) | `ffs-btree`, `ffs-extent` | Extent tree operations. ~5800 lines. |
| `mballoc.c` | `ext4_mb_new_blocks()` (top-level allocation entry), `ext4_mb_regular_allocator()` (criteria cascade), `ext4_mb_find_by_goal()` (CR0 goal match), `ext4_mb_scan_groups()` (iterate groups), `ext4_mb_mark_diskspace_used()` (commit allocation), `ext4_mb_use_preallocated()`, `ext4_mb_normalize_request()` | `ffs-alloc` | Block allocator. ~6500 lines, largest single file. |
| `ialloc.c` | `__ext4_new_inode()` (inode allocation orchestration), `find_group_orlov()` (directory inode spreading), `ext4_free_inode()`, `ext4_count_free_inodes()` | `ffs-alloc` | Inode allocation. ~1600 lines. |
| `namei.c` | `dx_probe()` (htree traversal), `ext4_find_entry()` (directory lookup), `ext4_add_entry()` (add dir entry), `ext4_delete_entry()`, `ext4_rename()`, `ext4_mkdir()`, `ext4_rmdir()` | `ffs-dir` | Directory operations. ~4200 lines. |
| `hash.c` | `ext4fs_dirhash()` (dispatcher), `half_md4_transform()`, `TEA_transform()` | `ffs-dir` | Directory hash computation. ~290 lines. Must be bit-exact. |
| `dir.c` | `ext4_readdir()` (iterate directory entries), `ext4_check_dir_entry()` (validate entry), `ext4_htree_store_dirent()` | `ffs-dir` | Directory reading. ~750 lines. |
| `xattr.c` | `ext4_xattr_get()`, `ext4_xattr_set()`, `ext4_xattr_ibody_find()` (in-inode xattrs), `ext4_xattr_block_find()` (external xattr block) | `ffs-xattr` | Extended attribute implementation. ~2800 lines. |
| `balloc.c` | `ext4_count_free_clusters()`, `ext4_has_free_clusters()`, `ext4_read_block_bitmap_nowait()`, `ext4_validate_block_bitmap()` | `ffs-alloc` | Block bitmap operations. ~800 lines. |
| `fsync.c` | `ext4_sync_file()` (fsync implementation) | `ffs-fuse` | Fsync path. ~250 lines. |

### 20.3 btrfs Reference Files

These files are reference material for btrfs compatibility (on-disk format +
algorithms) and for FrankenFS design concepts reused across both filesystems.

| C Source File | Key Structures/Functions | FrankenFS Conceptual Target | Borrowed Concept |
|---|---|---|---|
| `ctree.h` | `btrfs_path`, `btrfs_key`, `btrfs_header` (per-block generation tracking) | `ffs-mvcc` | Generation-based versioning: `btrfs_header.generation` maps to `BlockVersion.commit_seq` |
| `ctree.c` | `btrfs_cow_block()` / `btrfs_force_cow_block()` (COW semantics), `should_cow_block()` (idempotent COW guard), `btrfs_search_slot()` (B-tree lookup with COW) | `ffs-mvcc` | Block COW protocol: check-before-COW, allocate-copy-repoint-free, transaction ID stamping |
| `transaction.h` / `transaction.c` | `btrfs_transaction` (transaction lifecycle), `btrfs_start_transaction()`, `btrfs_commit_transaction()`, `TRANS_STATE_*` | `ffs-mvcc` | Transaction state machine: RUNNING -> COMMIT_START -> COMMIT_DOING -> UNBLOCKED -> COMPLETED |
| `scrub.c` | `struct scrub_ctx` (scrub context), `scrub_stripe` (per-stripe scrub state), `scrub_bio` (I/O submission for scrub), error detection and reporting | `ffs-repair` | Background integrity verification pattern: systematic device scan, checksum verify, report/repair |
| `block-group.c` | `btrfs_read_block_groups()`, `btrfs_make_block_group()`, free space tracking | `ffs-alloc` | Block group lifecycle management and free space accounting |
| `delayed-ref.c` | Deferred block freeing: reference count updates batched and applied at commit | `ffs-mvcc` (GC) | Deferred freeing aligns with MVCC GC: old versions are freed only when no snapshot references them |

### 20.4 JBD2 Reference Files

| C Source File | Key Functions | FrankenFS Crate | Notes |
|---|---|---|---|
| `jbd2/recovery.c` | `jbd2_journal_recover()`, `do_one_pass()` (SCAN/REVOKE/REPLAY passes), `scan_revoke_records()` | `ffs-journal` | Journal replay. FrankenFS must replicate the three-pass algorithm exactly. |
| `jbd2/journal.c` | `jbd2_journal_init_inode()`, `jbd2_journal_load()`, `jbd2_journal_destroy()` | `ffs-journal` | Journal lifecycle. |
| `jbd2/transaction.c` | `jbd2_journal_start()`, `jbd2_journal_stop()`, `jbd2__journal_start()` (the `j_state_lock` bottleneck) | `ffs-journal` (compat mode) | Transaction management. In compat mode, FrankenFS uses a single `Mutex` to emulate. |
| `jbd2/commit.c` | `jbd2_journal_commit_transaction()` | `ffs-journal` | Commit protocol: write descriptor, write data, write commit block. |

---

## 21. Risk Register and Open Questions

### 21.1 Risk Register

Each risk is assigned an ID, severity (CRITICAL / HIGH / MEDIUM / LOW),
likelihood (CERTAIN / LIKELY / POSSIBLE / UNLIKELY), and a mitigation
strategy with owner crate.

#### R1: FUSE Performance Overhead

- **Severity:** HIGH
- **Likelihood:** CERTAIN
- **Description:** FUSE introduces a minimum ~5-10 microseconds per filesystem
  operation due to kernel/userspace context switches (two for each operation:
  kernel -> userspace for the request, userspace -> kernel for the response).
  For metadata-heavy workloads (e.g., `find`, `ls -laR`, `git status`), this
  overhead dominates because each `getattr`, `lookup`, and `readdir` call
  incurs the full round-trip cost. Under heavy load, the FUSE daemon's
  `/dev/fuse` read queue can become a bottleneck.
- **Mitigation:**
  1. **ARC cache (ffs-block):** Keep hot metadata blocks in memory. Cache hit
     avoids disk I/O, reducing per-operation time to the FUSE overhead itself.
  2. **Readahead (ffs-extent):** For sequential reads, prefetch upcoming
     extent tree nodes and data blocks into the cache before they are needed.
  3. **FUSE splice mode:** Use `FUSE_SPLICE_READ` and `FUSE_SPLICE_WRITE` to
     avoid data copies between kernel and userspace for large read/write
     operations.
  4. **Multi-threaded FUSE (ffs-fuse):** Configure `fuser` with multiple
     threads to handle concurrent operations. Default:
     `min(available_parallelism(), 16)`.
  5. **Negative dentry cache (ffs-dir):** Cache failed lookups to avoid
     repeated htree traversals for non-existent files.
  6. **Entry/attribute timeout (ffs-fuse):** Set FUSE `entry_valid` and
     `attr_valid` timeouts to reduce kernel-to-FUSE round-trips for repeated
     stat operations on the same file.
- **Acceptance Criterion:** FrankenFS achieves >= 50% of kernel ext4
  throughput on the `fio` random-read benchmark at 4K block size, queue
  depth 32.

#### R2: MVCC Memory Overhead for Long-Running Transactions

- **Severity:** HIGH
- **Likelihood:** LIKELY
- **Description:** Each active snapshot prevents the GC from pruning old
  `BlockVersion` entries. A long-running read transaction (e.g., a backup
  process reading the entire filesystem) holds its snapshot open indefinitely,
  causing version chains to grow without bound. At 4096 bytes per block
  version data plus ~64 bytes of chain metadata, a filesystem with 1M blocks
  and 10 concurrent versions per block would consume ~40 GB of version data.
- **Mitigation:**
  1. **Configurable max version chain length (ffs-mvcc):** Default 64 versions
     per block. When exceeded, the oldest snapshot is forcibly expired (the
     transaction receives an error on next block read, as the snapshot is no longer valid).
> **[CORRECTION]** `FfsError::SnapshotExpired` does not exist. The actual mechanism would use `FfsError::MvccConflict` or a new variant when snapshot expiry is implemented.
  2. **GC aggressiveness tuning (ffs-mvcc):** Three GC modes: `lazy` (GC
     runs only when memory pressure is detected), `normal` (periodic GC every
     N commits), `aggressive` (GC after every commit). Default: `normal` with
     GC every 128 commits.
  3. **Version data spilling (ffs-mvcc):** When in-memory version data exceeds
     a configurable threshold (default: 25% of available RAM), old versions
     are spilled to a temporary file on disk. This trades I/O for memory.
  4. **Snapshot timeout (ffs-mvcc):** Snapshots older than a configurable age
     (default: 5 minutes) are automatically expired. Long-running operations
     must periodically refresh their snapshot.
- **Acceptance Criterion:** Under a workload of 8 concurrent writers + 1
  long-running reader, memory usage remains below 2x the ARC cache size.

#### R3: RaptorQ Symbol Storage Overhead

- **Severity:** MEDIUM
- **Likelihood:** CERTAIN
- **Description:** RaptorQ repair symbols consume usable storage space. At the
  default 5% overhead ratio, a 1 TB filesystem loses 50 GB to repair symbols.
  Users may be surprised by the reduced usable capacity compared to standard
  ext4.
- **Mitigation:**
  1. **Configurable overhead ratio (ffs-repair):** Range 1%-10%, set at
     `mkfs` time via `--repair-overhead` or at mount time via
     `--repair-overhead-pct`. Default: 5%.
  2. **Reserved area in block group (ffs-ondisk):** Repair symbols are stored
     in reserved blocks at the end of each block group. The reserved block
     count is `ceil(s_blocks_per_group * overhead_ratio)`.
  3. **Transparent reporting (ffs-cli, ffs-tui):** `ffs-cli info` and the TUI
     dashboard show both total capacity and usable capacity after repair
     overhead.
  4. **Lazy encoding (ffs-repair):** Repair symbols are not pre-computed for
     all block groups at mkfs time. They are generated lazily as blocks are
     written, reducing initial format time.
- **Acceptance Criterion:** `df` output correctly reports usable capacity
  after deducting repair overhead.

#### R4: Htree Hash Compatibility

- **Severity:** HIGH
- **Likelihood:** POSSIBLE
- **Description:** The directory hash computation (half_md4, TEA) must produce
  bit-identical results to the Linux kernel for FrankenFS to correctly read
  ext4 htree directories. Subtle differences in byte signedness, hash seed
  handling, or string padding would cause silent lookup failures (files
  exist but cannot be found via htree).
- **Mitigation:**
  1. **Conformance test suite (ffs-dir tests):** Extract hash values from real
     ext4 images using `debugfs -R 'htree /dir' image.img` and compare with
     FrankenFS-computed hashes for the same filenames and seeds.
  2. **Property-based testing (proptest):** Generate random filenames and
     seeds, compute hashes with both FrankenFS and a C reference
     implementation linked via FFI (test-only dependency, not shipped).
  3. **Unsigned handling (ffs-dir):** Explicitly handle `s_hash_unsigned`
     flag. When set, cast each filename byte to `u8` before hashing (rather
     than `i8` which is C's default `char` signedness on x86).
  4. **Byte-for-byte implementation (ffs-dir):** The Rust hash
     implementations are literal translations of the C code in `hash.c`,
     preserving all arithmetic wrapping and bit operations.
- **Acceptance Criterion:** Hash conformance tests pass against 10 real ext4
  images created by different kernel versions (4.x, 5.x, 6.x) on both x86
  and ARM.

#### R5: JBD2 Journal Replay Correctness

- **Severity:** CRITICAL
- **Likelihood:** POSSIBLE
- **Description:** Incorrect journal replay can cause data loss or filesystem
  corruption. The three-pass replay algorithm (SCAN, REVOKE, REPLAY) has
  subtle edge cases: wrapped journals (transactions crossing the circular
  buffer boundary), escaped blocks (data blocks whose first 4 bytes match the
  journal magic number), and revoke records that cancel earlier writes.
- **Mitigation:**
  1. **Crash-replay test suite (ffs-journal tests):** Create ext4 images,
     perform operations under a controlled environment, simulate crash at
     various points (mid-transaction, mid-commit, between transactions), mount
     with FrankenFS, verify filesystem consistency.
  2. **Golden-file tests (insta):** Capture `debugfs` output of filesystem
     state before crash and after kernel replay; compare with FrankenFS
     replay result.
  3. **Fuzz testing:** Fuzz the journal data (random valid/invalid descriptor
     blocks, commit blocks, revoke blocks) and verify FrankenFS does not
     panic and correctly rejects malformed journals.
  4. **Conservative replay (ffs-journal):** When in doubt, FrankenFS prefers
     not replaying a questionable transaction over risking corruption. Invalid
     commit block checksums cause the transaction and all subsequent
     transactions to be skipped.
- **Acceptance Criterion:** FrankenFS produces identical filesystem state as
  kernel ext4 after replaying journals from 50 crash scenarios.

#### R6: Extent Tree Modifications During Concurrent Writes

- **Severity:** HIGH
- **Likelihood:** LIKELY
- **Description:** Two transactions concurrently modifying the same file's
  extent tree (e.g., appending data at different offsets) could corrupt the
  tree if not properly serialized. Extent tree modifications involve splitting
  nodes, inserting entries, and updating parent pointers -- all of which
  modify multiple blocks.
- **Mitigation:**
  1. **MVCC version isolation (ffs-mvcc):** Each transaction sees its own
     snapshot of extent tree blocks. Modifications create new versions of the
     modified blocks. At commit time, FCW detects if any of the modified
     blocks were also modified by another committed transaction.
  2. **Per-inode write serialization (ffs-inode):** For extent tree
     modifications that span multiple blocks (split, merge), acquire a
     per-inode write lock (`RwLock<()>` per inode in the inode cache) to
     serialize tree structure changes to the same inode. This is strictly
     more restrictive than necessary but avoids complex multi-block conflict
     resolution.
  3. **SSI detection (ffs-mvcc):** If two transactions read overlapping
     extent tree nodes and write different nodes, SSI detects the
     rw-antidependency and aborts one transaction.
- **Acceptance Criterion:** Lab-deterministic test with 8 threads appending
  to the same file passes 10,000 iterations without extent tree corruption.

#### R7: Asupersync API Stability

- **Severity:** MEDIUM
- **Likelihood:** POSSIBLE
- **Description:** Asupersync is a pre-1.0 dependency under active
  development. API changes (especially to `Cx`, `Budget`, `Region`, or the
  `Lab` testing runtime) could require widespread FrankenFS changes.
- **Mitigation:**
  1. **Thin wrapper layer (ffs-types):** All asupersync types used across
     crate boundaries are re-exported through `ffs-types` with thin
     newtypes or type aliases. If asupersync changes, only `ffs-types` needs
     updating.
  2. **Pin dependency version (Cargo.toml):** Use exact version pinning
     (`=x.y.z`) for asupersync in `Cargo.toml` rather than semver ranges.
  3. **Abstraction traits (ffs-types):** Define traits (`CxExt`,
     `BudgetExt`) that wrap the asupersync-specific API surface. Crates
     depend on the traits, not the concrete asupersync types.
- **Acceptance Criterion:** An asupersync minor version bump requires changes
  to at most 2 crates (`ffs-types` and the crate that directly wraps asupersync APIs).

> **Note:** `ffs-async` does not exist as a workspace crate. The asupersync dependency
> is declared directly by crates that need it (`ffs-block`, `ffs-core`, `ffs-fuse`,
> `ffs-repair`).

#### R8: Bitmap Update Races in MVCC Mode

- **Severity:** HIGH
- **Likelihood:** LIKELY
- **Description:** Block and inode bitmaps are shared resources. In MVCC mode,
  two transactions allocating blocks in the same block group will write to the
  same bitmap block. FCW resolves this by aborting one transaction, but high
  contention on popular block groups (e.g., the root directory's group) could
  cause frequent aborts and retries.
- **Mitigation:**
  1. **Orlov spreading (ffs-alloc):** Distribute allocations across block
     groups to minimize bitmap contention.
  2. **Retry with backoff (ffs-mvcc):** Aborted transactions retry with
     exponential backoff (1ms, 2ms, 4ms, ..., capped at 100ms).
  3. **Sub-block bitmap resolution (future):** Future optimization to track
     which bits within a bitmap block were modified, allowing non-overlapping
     bit changes to merge rather than conflict.
- **Acceptance Criterion:** Under 8-thread parallel file creation, bitmap
  conflict rate < 5% when files are in different directories.

### 21.2 Open Questions

These questions are unresolved design decisions that require further
investigation or user input before implementation can proceed. Each question
has a tentative resolution and a phase by which it must be finalized.

#### OQ1: Native-Mode On-Disk Format Boundaries

**Question:** When running in native MVCC mode, which ext4 on-disk structures
are preserved verbatim and which are extended or replaced?

**Tentative Resolution:** All ext4 structures (superblock, group descriptors,
inodes, extents, directory blocks) are preserved in their standard layout.
MVCC version chains and repair symbols are stored in separate reserved areas
(reserved blocks at the end of each block group for repair symbols, a
dedicated "version store" inode for MVCC metadata). This allows fallback to
JBD2 mode by discarding the version store.

**Must Resolve By:** Phase 4 (before first write path implementation).

#### OQ2: Conflict Resolution Beyond FCW

**Question:** FCW (First-Committer-Wins) handles the simple case of two
transactions writing the same block. But what about "safe merge" scenarios
where both transactions' changes could be applied? For example, two
transactions each setting different bits in a bitmap block.

**Tentative Resolution:** V1 uses strict FCW only. "Safe merge" (also called
"write-write conflict resolution") requires semantic knowledge of block
contents (bitmap, directory block, etc.) and dramatically increases
complexity. Safe merge MAY be added in a post-V1 release.

**Must Resolve By:** Phase 6 (MVCC implementation).

#### OQ3: Repair Symbol Invalidation During Heavy Writes

**Question:** During write-heavy workloads, repair symbols become stale
immediately after each write. If the scrub daemon cannot keep up with
re-encoding, there is a window where corrupted blocks cannot be repaired.
How large is this window acceptable to be?

**Tentative Resolution:** The staleness window is acceptable as long as it is
bounded. The scrub daemon processes stale groups in priority order (groups
with the most stale symbols first). A configurable "max staleness" threshold
(default: 30 seconds or 1000 stale blocks, whichever is reached first)
triggers synchronous re-encoding on the next `fsync`.

**Must Resolve By:** Phase 8 (repair implementation).

#### OQ4: FUSE Writeback Mode Interaction with MVCC Dirty Tracking

**Question:** FUSE writeback mode (`-o writeback`) allows the kernel to
coalesce and reorder writes before sending them to the FUSE daemon. This
means the FUSE daemon sees writes in a different order than the application
issued them. How does this interact with MVCC transaction boundaries?

**Tentative Resolution:** FrankenFS uses `direct_io` mode for data writes in
MVCC mode, bypassing kernel writeback caching. This ensures each write
creates a deterministic MVCC version. For metadata operations (which are
always synchronous in FUSE), this is not an issue.

**Must Resolve By:** Phase 7 (FUSE integration).

#### OQ5: Multi-Host Repair Scope

**Question:** Should RaptorQ repair symbols be designed to support repair
coordination across multiple hosts (e.g., a network-attached storage scenario
where multiple hosts have partial copies of the filesystem)?

**Tentative Resolution:** V1 is single-host only. Repair symbols are stored
on the same device as the data they protect. Multi-host repair would require
a distributed protocol for symbol exchange and is out of scope for V1.

**Must Resolve By:** Not required for V1. Documented as future work.

#### OQ6: Inode Generation Number Handling

**Question:** ext4 uses `i_generation` (a 32-bit random number assigned at
inode creation) for NFS file handle stability. FUSE also uses generation
numbers in the `lookup` response. How should FrankenFS handle generation
numbers, especially across unmount/remount cycles?

**Tentative Resolution:** FrankenFS reads and preserves `i_generation` from
the ext4 inode. On inode allocation, a new generation number is assigned
using a CSPRNG. The FUSE `lookup` response includes the generation number.
NFS export is out of scope (Section 1.8), but correct generation handling
ensures FUSE protocol correctness.

**Must Resolve By:** Phase 5 (inode operations).

#### OQ7: Version Store Persistence Format

**Question:** In native MVCC mode, how is the MVCC version store persisted
across unmount/remount? Options include: (a) a dedicated journal-like area,
(b) a hidden inode with COW-allocated blocks, (c) an entirely separate file
alongside the filesystem image.

**Tentative Resolution:** Option (b): a hidden inode (inode number in a
reserved range, e.g., inode 12) stores version chain metadata in a structured
format. On clean unmount, the version store is compacted (all uncommitted
versions discarded, all committed versions with `commit_seq` older than the
oldest possible snapshot are pruned). On mount, the version store is loaded
and the MVCC engine is initialized from it.

**Must Resolve By:** Phase 6 (MVCC persistence).

---

## 22. Verification Gates

FrankenFS development proceeds through 9 phases (as defined in
`PLAN_TO_PORT_FRANKENFS_TO_RUST.md`). Each gate is a hard checkpoint: it
MUST pass before the next phase may begin. Gates are not aspirational
quality targets; they are binary pass/fail criteria.

### 22.1 Gate Definitions

#### Gate 1: On-Disk Format Parsing (Phase 2 Complete)

**Objective:** Prove that `ffs-ondisk` correctly parses all ext4 on-disk
structures from real filesystem images.

**Criteria:**

1. Parse 10 real ext4 images covering:
   - Block sizes: 1024, 2048, 4096
   - Feature combinations: `metadata_csum` on/off, `64bit` on/off,
     `flex_bg` on/off, `extents` on/off (indirect blocks), `dir_index` on/off
   - Image sizes: 1 MB (minimal), 100 MB (small), 1 GB (medium), 10 GB (large)
   - Source kernels: at least 3 different kernel versions (4.x, 5.x, 6.x)
2. For each image, round-trip test: parse all superblock fields, serialize
   back to bytes, compare byte-for-byte with original. Any mismatch is a
   failure.
3. Parse all group descriptors (32-byte and 64-byte variants), verify
   checksums match.
4. Parse all inodes in all groups, verify inode checksums match.
5. Zero panics, zero `unwrap()` failures on any malformed test input
   (fuzz-tested with 10,000 random mutations of valid images).

**Test Command:** `cargo test -p ffs-ondisk -- --include-ignored gate1`

#### Gate 2: Extent Resolution (Phase 4 Complete)

**Objective:** Prove that `ffs-btree` and `ffs-extent` correctly resolve
all extent mappings in real ext4 images.

**Criteria:**

1. For each of the 10 Gate 1 test images, resolve every extent for every
   regular file inode.
2. Compare physical block mappings with `debugfs -R 'blocks <ino>' image.img`
   output. Every physical block number MUST match exactly.
3. Verify hole detection: files with sparse regions (unallocated logical
   blocks) correctly return no mapping for hole regions.
4. Verify extent tree depth handling: test images include files with
   depth-0 (inline extents), depth-1 (single level of index nodes), and
   depth-2 (two levels) extent trees.
5. Performance: extent resolution for a file with 10,000 extents completes
   in < 100ms.

**Test Command:** `cargo test -p ffs-btree -p ffs-extent -- --include-ignored gate2`

#### Gate 3: Directory Listing (Phase 5 Complete)

**Objective:** Prove that `ffs-dir` correctly lists all files and directories,
matching kernel ext4 behavior exactly.

**Criteria:**

1. For each test image, mount with kernel ext4, run `ls -laR /mnt > expected`,
   mount with FrankenFS, run `ls -laR /mnt > actual`, diff MUST be empty
   (modulo mount timestamp differences).
2. Hash conformance: for each htree directory in test images, verify
   FrankenFS-computed hashes match `debugfs -R 'htree /dir'` output.
3. Linear directory scan: non-htree directories (small directories without
   `dir_index` feature or with < 2 blocks) correctly list all entries.
4. Special entries: `.` and `..` are present and correct in every directory.
5. File type field: `d_type` in `readdir` responses matches inode mode for
   all entries (regular file, directory, symlink, etc.).
6. Directory checksum verification: all directory block checksums validate.

**Test Command:** `cargo test -p ffs-dir -- --include-ignored gate3`

#### Gate 4: MVCC Concurrency (Phase 6 Complete)

**Objective:** Prove that the MVCC engine provides correct Serializable
Snapshot Isolation under concurrent access.

**Criteria:**

1. **Visibility correctness:** Under the Lab deterministic runtime, enumerate
   all possible interleavings (up to a bounded state space) of 4 transactions
   reading and writing 8 blocks. For each interleaving, verify:
   - Every read returns the correct version per the snapshot
   - No uncommitted version is ever visible to another transaction
   - FCW correctly aborts the second committer on write-write conflicts
2. **SSI correctness:** Create known write-skew scenarios (like the quota
   example in Section 2.5). Verify SSI detects and aborts one transaction.
   Test with at least 10 distinct write-skew patterns.
3. **GC safety:** With 3 concurrent snapshots at different `CommitSeq` values,
   verify GC never prunes a version visible to any active snapshot.
4. **Stress test:** 8 threads, 10,000 transactions each, random read/write
   mix on 1,000 blocks. Zero assertion failures, zero data races (run under
   `--cfg sanitize="thread"`).
5. **Performance:** Single-thread MVCC read (cache hit) < 500ns.
   Single-thread MVCC write (version creation) < 2us.

**Test Command:** `cargo test -p ffs-mvcc -- --include-ignored gate4`

#### Gate 5: FUSE Mount and POSIX Operations (Phase 7 Complete)

**Objective:** Prove that FrankenFS can mount real ext4 images and serve
basic POSIX filesystem operations correctly.

**Criteria:**

1. Mount each Gate 1 test image via FUSE (JBD2-compatible mode).
2. Run a POSIX test suite covering:
   - `open` / `close` (O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_EXCL, O_TRUNC)
   - `read` / `write` (sequential, random, partial block, multi-block)
   - `lseek` (SEEK_SET, SEEK_CUR, SEEK_END)
   - `stat` / `fstat` (all metadata fields)
   - `mkdir` / `rmdir`
   - `rename` (same directory, cross-directory)
   - `unlink`
   - `symlink` / `readlink`
   - `chmod` / `chown` / `utimes`
   - `readdir` (full directory listing)
   - `fsync` / `fdatasync`
   - `truncate` / `ftruncate`
3. JBD2 replay: create an image, write data, simulate crash (kill FrankenFS
   without unmount), remount, verify all fsync'd data is present.
4. All operations return correct errno values on error conditions.
5. No data loss: write a known pattern, unmount cleanly, remount with kernel
   ext4, verify pattern is intact.

**Test Command:** `cargo test -p ffs-fuse -- --include-ignored gate5`

#### Gate 6: RaptorQ Self-Healing (Phase 8 Complete)

**Objective:** Prove that the repair subsystem can detect and recover from
block corruption.

**Criteria:**

1. Create a test image, write known data, compute and store repair symbols
   for all block groups.
2. Inject 1% random block corruption (flip random bytes in randomly selected
   blocks, up to the repair overhead ratio).
3. Mount with FrankenFS, trigger scrub (or wait for automatic scrub).
4. Verify 100% recovery: all corrupted blocks are repaired to their original
   content (verified by comparing with a known-good copy).
5. Verify no false positives: uncorrupted blocks are not modified by repair.
6. Verify repair symbol freshness: after writing new data, verify that
   updated repair symbols correctly protect the new data.
7. Edge case: corrupt a repair symbol block itself. Verify that the
   systematic encoding property allows recovery (the first K encoding symbols
   are the source data; only the R additional symbols are repair symbols).
8. Performance: repair of a 128 MB block group with 5% corruption completes
   in < 5 seconds.

**Test Command:** `cargo test -p ffs-repair -- --include-ignored gate6`

#### Gate 7: Full Conformance and User-Facing Tools (Phase 9 Complete)

**Objective:** Prove end-to-end system readiness including CLI, TUI, and
documentation.

**Criteria:**

1. **Full conformance harness:** All gates 1-6 pass in a single CI run.
2. **CLI workflow:** The following sequence completes without error:
   ```
   ffs mount image.ext4 /mnt/ffs
   # perform file operations
   ffs info /mnt/ffs           # shows filesystem stats
   ffs scrub /mnt/ffs          # triggers manual scrub
   ffs umount /mnt/ffs         # clean unmount
   ffs fsck image.ext4         # offline consistency check
   ```
3. **TUI dashboard:** `ffs tui /mnt/ffs` launches and shows:
   - ARC cache hit rate (T1/T2/B1/B2 sizes, hit/miss counters)
   - MVCC version chain statistics (active snapshots, avg chain length,
     GC prune count)
   - Repair status (per-group: clean/stale/repairing, total symbols,
     corruption events)
   - I/O throughput (reads/writes per second, bytes per second)
   - Live updates (at least 1 Hz refresh rate)
4. **Error handling:** All user-facing error messages are actionable (include
   what went wrong, what the user should do, and relevant block/inode
   numbers).
5. **Clean shutdown:** `ffs umount` completes within 5 seconds (flushes
   dirty cache, writes final superblock, closes FUSE session).
6. **No resource leaks:** Mount for 1 hour under continuous load, verify no
   FD leaks, no monotonic memory growth beyond expected cache size.

**Test Command:** `cargo test --workspace -- --include-ignored gate7`

### 22.2 Gate Enforcement

- Each gate is implemented as a `#[test]` function with the `#[ignore]`
  attribute (run only when explicitly requested via `--include-ignored`).
- CI pipeline runs all gates on every merge to `main`.
- A gate failure on `main` is a P0 blocking issue.
- Gates are cumulative: Gate N implicitly requires all gates < N to pass.
- Gate test functions are in the crate that owns the primary functionality
  being tested. Cross-crate gate tests (e.g., Gate 5 which tests FUSE +
  journal + inodes + directories) live in `ffs-fuse/tests/gates/`.

### 22.3 Test Image Corpus

The 10 test images for Gate 1 (used by all subsequent gates) are:

| Image | Block Size | Size | Features | Source Kernel | Notes |
|-------|-----------|------|----------|---------------|-------|
| `img01_minimal.ext4` | 4096 | 1 MB | extents, filetype | 6.x | Minimal: root dir + 1 file |
| `img02_1k_blocks.ext4` | 1024 | 10 MB | extents, filetype, dir_index | 6.x | 1K blocks, first_data_block=1 |
| `img03_2k_blocks.ext4` | 2048 | 10 MB | extents, filetype | 6.x | 2K blocks |
| `img04_metadata_csum.ext4` | 4096 | 100 MB | extents, filetype, metadata_csum, 64bit | 6.x | Full checksums enabled |
| `img05_flex_bg.ext4` | 4096 | 100 MB | extents, filetype, flex_bg, metadata_csum | 6.x | Flex block groups |
| `img06_no_extents.ext4` | 4096 | 10 MB | filetype | 4.x | Indirect blocks only (no extents feature) |
| `img07_large_dirs.ext4` | 4096 | 1 GB | extents, filetype, dir_index, dir_nlink, large_dir | 6.x | 100K+ files in single directory |
| `img08_deep_tree.ext4` | 4096 | 1 GB | extents, filetype, huge_file | 6.x | Files with depth-2+ extent trees |
| `img09_sparse.ext4` | 4096 | 100 MB | extents, filetype | 5.x | Sparse files with holes |
| `img10_xattrs.ext4` | 4096 | 100 MB | extents, filetype, extra_isize, metadata_csum | 6.x | Files with extended attributes (user, security) |

Images are generated by CI scripts using `mkfs.ext4` with explicit feature
flags and populated with deterministic content using a seed-based generator.

---

## 23. Summary: What Makes FrankenFS Alien

FrankenFS is not an incremental improvement on existing filesystems. It
combines properties that have never existed together in a single system.
This section summarizes the key differentiators and explains why each matters.

### 23.1 A Filesystem That Does Not Need fsck

Traditional filesystems treat block corruption as a fatal condition requiring
offline repair tools (`fsck.ext4`, `btrfs check`). The repair process is
slow (hours for large filesystems), requires exclusive access (unmounted or
read-only), and can itself cause data loss if the corruption is severe.

FrankenFS eliminates the need for offline fsck through RaptorQ self-healing:

- **Every block group carries its own repair symbols.** At the default 5%
  overhead, each 128 MB block group (at 4K block size) reserves ~6.4 MB of
  repair symbols that can reconstruct up to ~1,600 corrupted blocks within
  that group.
- **Corruption is detected automatically.** The scrub daemon continuously
  verifies BLAKE3 checksums for every block. Corrupted blocks are detected
  within one full scrub cycle (configurable interval, default: 24 hours for a
  full sweep, with high-priority metadata groups scrubbed every hour).
- **Repair is transparent and online.** When corruption is detected, RaptorQ
  decoding reconstructs the original block content from the surviving source
  symbols and repair symbols. The repaired block is written back to its
  original location. No unmount, no user intervention, no data loss.
- **Repair symbols are self-protecting.** Because RaptorQ is a systematic
  code, the first K encoding symbols ARE the source data. The R additional
  repair symbols are stored separately. Even if some repair symbols are
  themselves corrupted, the remaining symbols (source + repair) can still
  recover the original data, as long as the total number of valid symbols
  >= K.

### 23.2 A Filesystem with Database-Grade Concurrency

ext4 provides SERIALIZABLE isolation trivially: all metadata updates go
through a single global journal lock (`j_state_lock`), so every execution
is equivalent to some serial ordering. But this is SERIALIZABLE by
strangulation -- you get correctness by destroying parallelism.

FrankenFS provides SERIALIZABLE isolation via SSI (Serializable Snapshot
Isolation) while allowing genuine parallel execution:

- **Multiple concurrent writers.** Two transactions modifying files in
  different directories proceed in full parallel -- their extent tree writes,
  directory entry insertions, bitmap updates, and inode modifications never
  contend because they touch different blocks.
- **Lock-free readers.** Readers never block and never hold locks. They read
  a consistent snapshot of the filesystem without interfering with concurrent
  writers. There is no "journal checkpoint pause" that freezes readers while
  metadata is flushed.
- **Write skew prevention.** SSI detects rw-antidependency cycles (the
  signature of write skew anomalies) and aborts one transaction before it can
  commit incorrect results. This is the same isolation guarantee that
  PostgreSQL provides at its SERIALIZABLE level.
- **First-Committer-Wins.** Write-write conflicts are resolved simply: the
  first transaction to commit wins; the second transaction detects the
  conflict at commit time and retries with a fresh snapshot.

### 23.3 A Filesystem Written in 100% Safe Rust

FrankenFS enforces `#![forbid(unsafe_code)]` at the workspace level. Every
crate in the workspace carries this attribute (including legacy/reference crates). There are zero
`unsafe` blocks in FrankenFS source code.

**What this means:**

- **No undefined behavior.** The Rust compiler guarantees that FrankenFS
  cannot exhibit undefined behavior: no use-after-free, no double-free, no
  buffer overflows, no data races, no null pointer dereferences, no
  uninitialized memory reads.
- **No memory corruption.** On-disk structure parsing uses explicit,
  bounds-checking decode helpers (no pointer casts, no `transmute`, no raw
  pointer arithmetic).
- **Auditable safety boundary.** Third-party crates that use `unsafe`
  internally (e.g., `parking_lot`, `libc`) are acceptable because they expose
  safe APIs, are widely audited, and their `unsafe` is encapsulated.
  FrankenFS's own code is provably free of memory safety bugs.

**What this does NOT mean:**

- FrankenFS is not free of logic bugs. Safe Rust prevents memory corruption
  but cannot prevent incorrect extent tree traversal or wrong checksum
  computation.
- FrankenFS relies on the correctness of `unsafe` code in dependencies.
  This is an acceptable tradeoff shared by every Rust application.

### 23.4 A Filesystem That Reads Real ext4 Images

FrankenFS is not a toy filesystem or a research prototype. It reads and writes
real ext4 disk images created by `mkfs.ext4`:

- **Mount compatibility.** An ext4 image created by the Linux kernel can be
  mounted by FrankenFS without conversion. FrankenFS reads the superblock,
  group descriptors, inode tables, extent trees, directory blocks, and
  extended attributes in their native ext4 format.
- **Write compatibility (JBD2 mode).** In JBD2-compatible mode, writes
  produce output that the Linux kernel can read on the next mount. The JBD2
  journal, metadata checksums, and all on-disk structures are maintained in
  kernel-compatible format.
- **Tool compatibility.** `dumpe2fs`, `debugfs`, `tune2fs`, and `fsck.ext4`
  work on FrankenFS-written images. `mkfs.ext4` creates images that FrankenFS
  can mount.
- **Conformance testing.** Every release is tested against the 10-image
  corpus (Section 22.3), comparing FrankenFS behavior byte-for-byte with
  kernel ext4 behavior.

### 23.5 A Filesystem Observable in Real-Time

Filesystem internals are traditionally opaque. Administrators have limited
visibility into cache behavior, I/O patterns, and internal data structure
health. FrankenFS exposes its internals through a live TUI dashboard
(`ffs tui`):

- **ARC cache state.** T1/T2/B1/B2 list sizes, hit/miss rates, eviction
  counts, adaptation parameter (p) showing the cache's current
  recency-vs-frequency balance.
- **MVCC version chains.** Active snapshot count, average and maximum version
  chain length, GC prune rate, conflict/abort rate, commit throughput
  (commits per second).
- **Repair status.** Per-block-group repair state (clean, stale, repairing,
  failed), total corruption events detected, blocks repaired, repair symbol
  freshness percentage across the filesystem.
- **I/O throughput.** Reads and writes per second, bytes per second, FUSE
  operation latency histogram (p50, p95, p99), ARC cache bypass rate.

All metrics are updated at >= 1 Hz refresh rate and are implemented via
lock-free atomic counters to avoid perturbing the measured workload.

### 23.6 A Filesystem That Expects Corruption

Traditional filesystems treat corruption as exceptional. Error handling for
corrupt metadata is an afterthought -- often a `BUG_ON()` crash or a terse
`EIO` with no recovery path.

FrankenFS treats corruption as expected and routine:

- **Every block group has repair symbols.** Not as an optional feature, not
  as a RAID mode, not as a configuration choice. Every block group, always.
- **Checksum verification is ubiquitous.** Every metadata read verifies its
  checksum. Every data read can optionally verify its BLAKE3 integrity hash.
  Verification failures trigger the repair path, not an error return.
- **Corruption metrics are first-class.** The TUI shows corruption events
  per block group, cumulative blocks repaired, and current repair symbol
  freshness. Operators can see filesystem health at a glance.
- **Graceful degradation.** If corruption exceeds the repair capacity
  (more blocks corrupted than repair symbols can recover), FrankenFS returns
  `EIO` for the affected blocks but continues serving uncorrupted blocks.
  The filesystem does not crash or force-unmount.

### 23.7 Structured Concurrency: No Fire-and-Forget Tasks

FrankenFS uses asupersync's structured concurrency primitives (`Cx`, `Region`,
`Budget`) to ensure that all background tasks are bounded, cancellable, and
deterministically testable:

- **Cx (Capability Context):** Every I/O operation takes a `&Cx` as its
  first parameter. The `Cx` carries a cancellation token, a deadline, and a
  resource budget. Operations check `cx.checkpoint()` at yield points and
  stop work if cancelled or budget-exhausted.
- **Region (Structured Scope):** Background tasks (scrub daemon, GC daemon,
  flush daemon, repair encoder) are spawned within a `Region`. When the
  `Region` is dropped (at unmount), all tasks within it are cancelled and
  joined. There are no orphan tasks, no leaked goroutines, no fire-and-forget
  `tokio::spawn` calls.
- **Budget (Resource Limits):** Each operation carries a `Budget` with
  `{ deadline, poll_quota, cost_quota, priority }`. Budgets compose via
  component-wise rules: deadlines use `min` (tighter wins), quotas use `min`,
  priority uses `max`. This ensures that a scrub daemon with low priority
  does not starve user I/O.
- **Lab (Deterministic Testing):** All concurrent code paths are testable
  under asupersync's `Lab` runtime, which provides deterministic scheduling
  (controlled by a seed), virtual time, and fault injection. MVCC visibility
  rules, SSI conflict detection, and GC safety invariants are verified under
  exhaustive interleaving enumeration.

### 23.8 Three Things Impossible in C

The following properties are achievable in FrankenFS specifically because it is
written in Rust. They are not merely "harder in C" -- they are structurally
impossible to guarantee in C at compile time.

#### 23.8.1 Fearless MVCC Concurrency Without Data Races

In C, concurrent access to version chains requires careful manual
synchronization. A missing lock acquisition, a lock ordering violation, or
a read of a partially-updated pointer can cause silent data corruption. Data
races in C are undefined behavior, meaning the compiler can (and does) optimize
code in ways that break concurrent correctness.

In Rust:

- `BlockVersion` is stored in an `Arc<parking_lot::RwLock<VersionChainInner>>`.
  The type system enforces that readers hold a read lock and writers hold a
  write lock.
- `Send` and `Sync` bounds on MVCC types ensure that version chains can be
  safely shared across threads. A type that is not `Sync` cannot be placed
  in a shared context -- the compiler rejects the code.
- There is no equivalent of a "data race" in safe Rust. The ownership system
  ensures exclusive mutable access OR shared immutable access, never both.

#### 23.8.2 Zero Undefined Behavior in Metadata Parsing

In C, parsing ext4 on-disk structures involves pointer arithmetic, type
casting (`(struct ext4_super_block *)(bh->b_data + offset)`), and manual
bounds checking. A single off-by-one in the offset calculation, a missing
endianness conversion, or reading past the end of a buffer is undefined
behavior.

In Rust:

- Parsing code never casts pointers. It uses explicit, bounds-checking decode
  helpers (`ffs-types::{ensure_slice, read_le_u16, read_le_u32, read_le_u64, read_fixed}`)
  that return `Result<_, ParseError>` instead of invoking undefined behavior.
- All field accesses on on-disk structures use explicit endianness conversion
  (`u32::from_le_bytes()`, `u64::from_le_bytes()`, etc).
- Out-of-bounds is handled as a parse failure (`ParseError::InsufficientData`),
  not a panic. The fuzz doctrine in this repo is: **return `Err`, never panic**
  on malformed metadata.

#### 23.8.3 Compile-Time Module Encapsulation of Raw Block Access

In C, any code file can call `pread64()` to read a raw block from disk. There
is no compile-time mechanism to enforce that all block reads go through the
ARC cache layer. Code review is the only defense, and it is fallible.

In Rust, the FrankenFS crate architecture enforces access discipline:

- The `BlockDevice` trait (planned for `ffs-block`) is the only way to read/write
  raw blocks.
- `ffs-block` will provide an ARC cache wrapper (`ArcCache`) around `BlockDevice`.
  All higher-level crates depend on the cached interface, not the raw device.
- The raw `BlockDevice` implementation is `pub(crate)` within `ffs-block`. No
  other crate can even name the concrete type, let alone call it directly.
- Trait bounds on generic parameters (`T: CachedBlockDevice`) enforce at
  compile time that only cached block access is possible. Attempting to pass

> **Note:** Earlier revisions referenced phantom crates `ffs-io` and `ffs-cache`.
> These do not exist. The correct crate for all block I/O and caching is `ffs-block`.
  a raw `BlockDevice` where a `CachedBlockDevice` is expected is a type
  error.

This is not a convention or a code review rule. It is enforced by the Rust
compiler. Every build, every time, on every platform.

---

*End of Sections 19-23.*
