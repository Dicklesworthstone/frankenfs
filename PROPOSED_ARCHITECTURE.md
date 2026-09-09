# PROPOSED_ARCHITECTURE.md — FrankenFS (ffs)

> 22-member Cargo workspace architecture (21 members under `crates/`, plus `tools/ffs-ops`) for a FUSE-based Rust reimplementation of ext4 and btrfs with block-level MVCC and RaptorQ self-healing.

> **Source check (2026-09-08):** Cargo.toml declares Rust 1.95 minimum, asupersync 0.3.9, and vendored fuser 0.17.0 with ABI 7.42 enabled. First-party crates forbid unsafe Rust; `vendor/fuser` is excluded from the workspace and contains unsafe transport code. Implemented CLI paths attach the ext4 JBD2 writer before enabling writes, selected ext4 writes stage merge proofs, and per-core FUSE dispatch calls vendored workers. These source connections do not substitute for fresh mounted/crash/performance evidence. Default mounted repair and fully region-scoped background work remain incomplete against the canonical specification.

> **Status note (2026-05-01):** The architecture map describes the implemented
> crate topology and target boundaries. Current reality-check bridge work outside
> the tracked parity denominator is recorded in `bd-rchk1` through `bd-rchk7`.
> Mounted self-healing now has an explicit repair-enabled read-only mount mode
> (`--background-repair --background-scrub-ledger <jsonl>`); read-write mounted
> automatic repair remains scoped out until repair writeback is serialized with
> client write traffic.

---

## 1. Crate Map

| # | Crate | Role | Key Dependencies | Primary Phase |
|---|-------|------|-----------------|--------------|
| 1 | `ffs-types` | Newtypes: BlockNumber, BlockSize, ByteOffset, InodeNumber, TxnId, CommitSeq, Snapshot, GroupNumber, DeviceId, Generation, ParseError; binary read helpers (read_le_u16/u32/u64); ext4/btrfs magic constants | `serde`, `thiserror` | 2 |
| 2 | `ffs-error` | FfsError enum, Result<T> alias, errno mappings (ENOENT, EIO, ENOSPC, ...) | `thiserror` | 2 |
| 3 | `ffs-ondisk` | ext4 + btrfs on-disk format parsing: superblocks, headers, keys/items, ext4 group desc/inodes/extents/dirs, JBD2 structures | `ffs-types`, `ffs-error`, `crc32c`, `serde` | 2 |
| 4 | `ffs-block` | Block I/O layer: BlockDevice trait, ARC (Adaptive Replacement Cache), read/write with Cx, dirty page tracking | `ffs-types`, `ffs-error`, `asupersync`, `parking_lot` | 3 |
| 5 | `ffs-journal` | JBD2-compatible journal replay + native COW journal: transaction lifecycle, descriptor/commit/revoke blocks | `ffs-types`, `ffs-error`, `ffs-block` | 6 |
| 6 | `ffs-mvcc` | Block-level MVCC: version chains (BlockVersion), snapshot isolation, first-committer-wins conflict detection, GC of old versions; planned: durable version store overlay (bd-1u7) | `ffs-types`, `ffs-error`, `ffs-block`, `asupersync`, `parking_lot`, `serde`, `thiserror` | 6 |
| 7 | `ffs-btree` | B-tree operations used by ext4 (extents/htree) and btrfs (metadata trees): search, insert, split, merge, tree walk | `ffs-types`, `ffs-error`, `ffs-block`, `ffs-ondisk` | 4 |
| 8 | `ffs-alloc` | Block/inode allocation: mballoc-style multi-block allocator (buddy system, best-fit, prealloc), Orlov inode allocator | `ffs-types`, `ffs-error`, `ffs-block`, `ffs-ondisk` | 4 |
| 9 | `ffs-inode` | Inode management: read/write/create/delete, permissions, timestamps, flags | `ffs-types`, `ffs-error`, `ffs-block`, `ffs-ondisk` | 5 |
| 10 | `ffs-dir` | Directory operations: linear scan, htree (hashed B-tree) lookup, dx_hash, create/delete entries | `ffs-types`, `ffs-error`, `ffs-inode` | 5 |
| 11 | `ffs-extent` | Extent mapping: logical→physical block resolution, extent allocation, hole detection | `ffs-types`, `ffs-error`, `ffs-btree`, `ffs-alloc` | 4 |
| 12 | `ffs-xattr` | Extended attributes: inline (after inode extra fields), external block, namespace routing (user/system/security/trusted) | `ffs-types`, `ffs-error`, `ffs-block`, `ffs-ondisk` | 5 |
| 13 | `ffs-fuse` | FUSE interface: FuseBackend trait, MountOptions, FrankenFuseMount — delegates to `ffs-core::FsOps` implementations (currently `OpenFs`) and does not depend on domain crates directly | `ffs-core`, `ffs-types`, `ffs-error`, `asupersync`, `fuser`, `libc`, `serde`, `thiserror`, `tracing` | 7 |
| 14 | `ffs-repair` | RaptorQ self-healing: generate/store repair symbols per block group, detect corruption via checksum, recover blocks, background scrub | `ffs-types`, `ffs-error`, `ffs-block`, `asupersync`, `blake3`, `crc32c` | 8 |
| 15 | `ffs-core` | Engine integration: format detection (`FsFlavor`), `OpenFs` (`FsOps` implementation for ext4/btrfs dispatch), `FrankenFsEngine` MVCC utility APIs, DurabilityAutopilot (Bayesian redundancy), mount orchestration | `ffs-types`, `ffs-error`, `ffs-ondisk`, `ffs-block`, `ffs-mvcc`, `ffs-btrfs`, `asupersync`, `serde`, `thiserror` | 7 |
| 16 | `ffs` | Public API facade: re-exports core functionality, stable external interface | `ffs-core` | 9 |
| 17 | `ffs-cli` | CLI binary: `ffs inspect`, `ffs info`, `ffs dump`, `ffs fsck`, `ffs repair`, `ffs mount`, `ffs scrub`, `ffs parity` | `ffs-core`, `ffs-block`, `ffs-fuse`, `ffs-harness`, `ffs-ondisk`, `ffs-repair`, `ffs-types`, `anyhow`, `asupersync`, `clap`, `serde`, `serde_json` | 9 |
| 18 | `ffs-tui` | TUI monitoring: live cache stats, MVCC version counts, repair status, I/O throughput | `ffs`, `ftui` | 9 |
| 19 | `ffs-harness` | Conformance testing harness: parity reports, sparse JSON fixtures, compare FrankenFS behavior against real ext4/btrfs images | `ffs-core`, `ffs-ondisk`, `ffs-types`, `anyhow`, `hex`, `serde`, `serde_json`; dev: `criterion` | 9 |
| 20 | `ffs-ext4` | Legacy/reference wrapper for ext4 parsing APIs (re-exports `ffs-ondisk::ext4::*`) | `ffs-ondisk` | 1 |
| 21 | `ffs-btrfs` | Btrfs tree walking and mutation layer: root/inode/dir/extent-data helpers, chunk/device tree discovery, COW tree updates, delayed refs, snapshot/subvolume metadata, MVCC-backed transaction manifests, **metadata writeback serialization (CoW node → on-disk bytes)**, extent tree allocation for new nodes with `METADATA_ITEM`/`TREE_BLOCK_REF` accounting, data orphan reclamation after interrupted writeback, atomic superblock commit with generation bump; re-exports low-level `ffs-ondisk::btrfs::*` primitives | `ffs-ondisk`, `ffs-types`, `ffs-mvcc`, `asupersync`, `thiserror`, `tracing` | 4-7 |

---

The 22nd member, `ffs-ops` in `tools/ffs-ops`, provides operational validation commands and depends on `ffs-harness`, `anyhow`, and `serde_json`.

## 2. Dependency Graph

```
                    ┌──────────┐  ┌──────────┐
                    │ ffs-types│  │ ffs-error │
                    └────┬─────┘  └─────┬─────┘
                         │              │
                         └──────┬───────┘
                                │
                    ┌───────────┼───────────┐
                    │           │           │
             ┌──────▼──────┐   │    ┌──────▼──────┐
             │  ffs-ondisk  │   │    │  ffs-block   │
             └──────┬──────┘   │    │  (+ ARC)     │
                    │          │    └──┬──┬──┬──┬──┘
     ┌──────────────┼──────┐   │       │  │  │  │
     │              │      │   │       │  │  │  └──────────┐
     │       ┌──────▼────┐ │   │       │  │  │      ┌──────▼──────┐
     │       │ ffs-btree  │ │   │       │  │  │      │  ffs-mvcc   │
     │       └──────┬────┘ │   │       │  │  │      │  (ffs-block) │
     │              │      │   │       │  │  │      └─────────────┘
     │       ┌──────▼────┐ │   │       │  │  │
     │       │ ffs-alloc  │ │   │       │  │  │
     │       └──────┬────┘ │   │       │  │  │
     │              │      │   │       │  │  │
  ┌──▼──────────┐  ┌▼─────▼┐  │  ┌────▼┐ │ ┌▼──────┐  ┌────────────┐
  │  ffs-xattr  │  │extent │  │  │jrnl │ │ │repair │  │ ffs-inode  │
  └─────────────┘  └───────┘  │  └─────┘ │ └───────┘  └──────┬─────┘
                              │           │                   │
                              │           │            ┌──────▼──────┐
                              │           │            │   ffs-dir   │
                              │           │            └─────────────┘
                              │           │
       ┌──────────────────────▼───────────┘
       │   ffs-core  (orchestrates mvcc, ondisk, block, btrfs)
       └──┬───────┬───┘
          │       │
   ┌──────▼────┐  │  ┌────────────┐
   │  ffs-fuse  │  │  │    ffs     │  (public facade)
   │ (ffs-core) │  │  │ (ffs-core) │
   └────────────┘  │  └──┬───┬────┘
                   │     │   │
           ┌───────┘     │   └────────┐
           │             │            │
    ┌──────▼──┐  ┌──────▼─────┐ ┌───▼────────┐
    │ ffs-cli  │  │  ffs-tui   │ │ ffs-harness │
    └─────────┘  └────────────┘ └────────────┘
```

> **Note:** `ffs-fuse` depends on `ffs-core` (which orchestrates domain crates), NOT on domain crates directly. This is the canonical layering — ffs-core is the integration point, ffs-fuse is a thin FUSE protocol adapter. `ffs-mvcc` now depends on `ffs-block` for versioned block storage (MvccBlockDevice wraps a BlockDevice to provide snapshot-isolated reads/writes). As MVCC persistence lands (bd-1u7), `ffs-mvcc` will additionally use `ByteDevice` (via `ffs-block`) to implement an append-only durable overlay log for versioned blocks (see COMPREHENSIVE_SPEC §5.9). `ffs-core` depends on `ffs-btrfs` for btrfs root tree walking during format detection and multi-format support.

`ffs-ondisk::BtrfsStripeMapping` bounds each mapping with a contiguous byte
length. `ffs-btrfs::BtrfsDeviceSet` assembles longer reads segment by segment,
requiring exact physical read lengths and retrying alternate mirrors on read
failure. Readers receive the caller's `Cx`; checkpoints before and after physical
I/O prevent cancellation from returning bytes or triggering another mirror.
`BtrfsDeviceError` distinguishes cancellation, I/O, mapping, missing devices and
incorrect lengths. Registration rejects zero IDs and duplicate IDs without
replacing an existing reader. `OpenOptions::btrfs_device_paths` (CLI: repeatable
`--btrfs-device`) attaches additional backings before bootstrap. Core validates
superblock checksums, filesystem generation/roots/geometry, device IDs/UUIDs and
capacity, then checks identities against the committed CHUNK_TREE inventory and
stripe references. Bootstrap, parsed metadata and file-data reads use the device
set. Kernel-written RAID0 and RAID1 images are covered through the core API and
FUSE with each primary-device choice. Metadata reads validate each complete
mirror's checksum, logical address and structure before caching it, retrying
another copy on invalid content. Kernel-written RAID1/RAID10/C3/C4 tests corrupt
chunk-tree, root-tree and fs-tree copies independently: all but the final mirror
can be corrupt and still recover through FUSE; corrupting every copy fails.
Checksummed file reads validate whole sectors
and retry mirrors both during the existing pre-output extent check and when
filling read/decompression buffers, so the bytes returned come from the validated
copy. Recovery uses sector-sized buffers rather than retaining whole extents.
Kernel-written RAID1/RAID10/C3/C4 ordinary/zstd data recovery, unaligned reads, all-copy
refusal, verification opt-out and NODATASUM behavior are covered through core
and FUSE tests. Metadata whole-tree, range, floor and node-address walks check
the caller's cancellation before cache access and after traversal, before
converting parser errors. A cancelled operation returns `FfsError::Cancelled`,
including empty ranges and cached results; cancellation observed during I/O
must not publish a parsed node or floor memo. Parser error types remain about
format interpretation, with runtime cancellation handled at the operation boundary.
Clean multi-device images use this routing even with no extra
paths: a lone RAID1 survivor is admitted only after every committed chunk has
device coverage. RAID1/C3/C4 need a surviving copy; RAID10 needs one survivor in each
adjacent `sub_stripes` mirror group, after validating stripe geometry. Other
chunk profiles require all stripe devices. A four-device kernel RAID10 fixture
checks all 14 nonempty proper attachment subsets, with full and stripe-crossing
ordinary data reads plus cold FUSE mounts for supported subsets and refusal
when an entire group is missing. C3/C4 validate mirror-profile geometry before
admitting a survivor. Kernel-written three/four-device images cover every
nonempty proper subset (6 C3 and 14 C4), plus each complete-set primary, through
ordinary core and cold FUSE reads. Separate corruption tests use full attachments;
the complete corruption/missing-device/checksum-codec matrix remains unverified.
Clean three-device RAID5 and four-device RAID6 kernel images pass
full-file, stripe-boundary and cold FUSE reads with each primary. Their mapper
rotates ordered data slots forward per physical row, matching Linux; it does
not reconstruct parity, and admission still requires every stripe device.
Unused missing devices
remain in the authoritative inventory. Kernel-image tests mount each RAID1
survivor alone and reject a missing RAID0 data device despite readable mirrored
metadata. No sibling images are discovered implicitly. Multi-device mounts require a clean
tree log and no MVCC WAL; dirty-image recovery,
the remaining degraded/profile coverage and parity reconstruction remain open. There is no
multi-device mutation support.
`OpenFs::enable_writes` refuses any device count other than one and any known
chunk profile other than Single/DUP before loading mutable allocation state.
Skipping read validation does not bypass this write-admission check.
`OpenFs::current_btrfs_device_items` reads the backing superblock through the request's
`Cx`, verifies its checksum, parses the embedded device item, and checks its
filesystem UUID. Writable mounts enumerate live CHUNK_TREE DEV_ITEM records
under the allocator's read lock; read-only mounts use checksum-verified range
descent over the committed device-item keyspace. Both include unused devices
and maximum IDs, require IDs to match their keys, reject duplicate IDs/UUIDs
and foreign filesystem UUIDs, and verify the backing device's identity.
Partial live tree loads return an unsupported error; missing, malformed or
count-inconsistent inventories return corruption errors. Unlike Linux's
mount-time count repair, FrankenFS currently refuses a superblock/DEV_ITEM
count mismatch. This inventory does not open or validate additional backing
files, and does not enable cross-device reads. Seed-device inventories with
different filesystem UUIDs are not yet supported. The allocator lock stabilizes writable accounting,
but full commit releases it before superblock publication; serializing that
publication with device-info reads remains open (`bd-hk5w3`).
Mount initialization preserves DATA, METADATA, and SYSTEM block-group types.
Chunk-tree COW allocates from SYSTEM space so the superblock's bootstrap map
can resolve the new root. When growth dirties CHUNK_TREE and DEV_TREE, full
commit retires their old extent records before allocating replacement nodes;
the existing pin mechanism protects those old blocks until publication.
`FS_INFO` derives `max_id` from the complete validated inventory. `DEV_INFO`
looks up any inventory device by exact ID and optional UUID, with current
per-device accounting. Neither ioctl infers device IDs from chunk stripes.

---

## 3. Trait Hierarchy

### 3.1 Storage Traits

```rust
/// Byte-addressed device for fixed-offset I/O (pread/pwrite semantics).
pub trait ByteDevice: Send + Sync {
    /// Total length in bytes.
    fn len_bytes(&self) -> u64;

    /// Read exactly `buf.len()` bytes from `offset` into `buf`.
    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()>;

    /// Write all bytes in `buf` to `offset`.
    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()>;

    /// Flush pending writes to stable storage.
    fn sync(&self, cx: &Cx) -> Result<()>;
}

/// Low-level block device abstraction.
pub trait BlockDevice: Send + Sync {
    /// Read a single block. Returns owned block data.
    fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf>;

    /// Write a single block.
    fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()>;

    /// Block size in bytes (typically 1024, 2048, or 4096).
    fn block_size(&self) -> u32;

    /// Total number of blocks.
    fn block_count(&self) -> u64;

    /// Flush pending writes to stable storage.
    fn sync(&self, cx: &Cx) -> Result<()>;
}

/// Cache policy for the ARC buffer pool.
pub trait CachePolicy: Send + Sync {
    /// Maximum number of cached blocks.
    fn max_cached_blocks(&self) -> usize;

    /// Whether to use write-back (true) or write-through (false).
    fn write_back(&self) -> bool;

    /// Background flush interval.
    fn flush_interval(&self) -> Duration;
}
```

### 3.2 MVCC Traits

**Phase note:** `ffs-mvcc` currently ships a Phase A API (`MvccStore` + `Transaction`) that implements snapshot visibility + FCW conflict detection. The trait below is the Phase B+ target once we add SSI/read-set tracking, active transaction bookkeeping, and thread-safe sharing (and once MVCC needs `&Cx` cancellation plumbing).

```rust
/// Block-level MVCC manager.
pub trait MvccBlockManager: Send + Sync {
    /// Begin a new transaction, returning a snapshot view.
    fn begin_tx(&self, cx: &Cx) -> Result<TxHandle>;

    /// Read a block at the version visible to this transaction.
    fn read_versioned(&self, cx: &Cx, tx: &TxHandle, block: BlockNumber) -> Result<BlockBuf>;

    /// Write a block, creating a new version in the chain.
    fn write_versioned(
        &self, cx: &Cx, tx: &TxHandle, block: BlockNumber, data: &[u8],
    ) -> Result<()>;

    /// Commit transaction. Returns the CommitSeq on success, or Err if conflict detected.
    fn commit(&self, cx: &Cx, tx: TxHandle) -> Result<CommitSeq>;

    /// Abort transaction, discarding all writes.
    fn abort(&self, cx: &Cx, tx: TxHandle) -> Result<()>;

    /// Garbage-collect versions no longer visible to any active transaction.
    fn gc(&self, cx: &Cx) -> Result<GcStats>;

    /// Current global commit sequence (used to form snapshots).
    fn current_commit_seq(&self) -> CommitSeq;

    /// Number of active transactions (used for observability/backpressure).
    fn active_transaction_count(&self) -> usize;
}
```

#### 3.2.1 MVCC Persistence (VersionStore overlay; planned — bd-1u7)

MVCC durability is provided by an **append-only commit log**:

- One durable record per commit (`record_len`, `record_type`, `commit_seq`, `txn_id`, `num_writes`, write entries, trailing CRC32C).
- Commit records are canonicalized before encode (single write per block, ascending block order).
- Replay is strictly monotonic on `commit_seq`; malformed/truncated tail is discarded and truncated at last valid byte.
- Crash-safe durability requires append + sync before returning commit success.

The durable region is `ByteDevice`-backed and placement-agnostic (sidecar file, hidden inode, or equivalent). Canonical wire format and replay invariants live in `COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md` §5.9, including scenario IDs `MVCC_DURABLE_WAL_001..006` and required durable-path log fields (`operation_id`, `scenario_id`, `commit_seq`, `txn_id`, `outcome`, `error_class`).

### 3.3 Filesystem Operations Trait (planned — lives in `ffs-core`)

```rust
/// High-level filesystem operations (defined in ffs-core, consumed by ffs-fuse).
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
    fn rename(&self, cx: &Cx, parent: InodeNumber, name: &OsStr, new_parent: InodeNumber, new_name: &OsStr) -> Result<()>;
    fn link(&self, cx: &Cx, ino: InodeNumber, new_parent: InodeNumber, new_name: &OsStr) -> Result<InodeAttr>;
    fn symlink(&self, cx: &Cx, parent: InodeNumber, name: &OsStr, target: &Path) -> Result<InodeAttr>;
    fn readlink(&self, cx: &Cx, ino: InodeNumber) -> Result<PathBuf>;
    fn statfs(&self, cx: &Cx) -> Result<StatFs>;
    fn fsync(&self, cx: &Cx, ino: InodeNumber, datasync: bool) -> Result<()>;
}
```

Current `ffs-core::FsOps` also exposes filesystem-specific ioctl helper
methods consumed by `ffs-fuse`. For btrfs, `BTRFS_IOC_INO_LOOKUP` stays at
this boundary: `ffs-fuse` decodes the 4096-byte ioctl struct, while `ffs-core`
resolves `treeid=0` to the mounted subvolume, locates explicit tree ids via
the ROOT_TREE, and walks `INODE_REF` chains inside the selected fs tree.

### 3.4 Repair Traits

```rust
/// Self-healing repair interface.
pub trait RepairManager: Send + Sync {
    /// Generate repair symbols for a block group.
    fn generate_symbols(&self, cx: &Cx, group: GroupNumber) -> Result<RepairSymbolSet>;

    /// Attempt to recover a corrupted block using repair symbols.
    fn recover_block(&self, cx: &Cx, block: BlockNumber) -> Result<RecoveryResult>;

    /// Run background scrub over all block groups.
    fn scrub(&self, cx: &Cx, progress: &dyn ScrubProgress) -> Result<ScrubReport>;

    /// Refresh repair symbols after a block has been written.
    fn refresh_symbols(&self, cx: &Cx, block: BlockNumber) -> Result<()>;
}
```

---

## 4. Layering Rules

1. **Parser crates are pure.** `ffs-ondisk` performs no I/O — it parses byte slices into typed structures.
2. **MVCC is transport-agnostic.** `ffs-mvcc` operates on blocks, not files or directories. It depends on `ffs-block` for versioned block storage but has no knowledge of FUSE, inodes, or directory entries.
3. **FUSE adapter delegates to ffs-core.** `ffs-fuse` maps FUSE protocol to the `ffs-core::FsOps` trait (runtime path currently uses `OpenFs`) — it contains no filesystem logic and does not depend on domain crates directly.
4. **Repair is orthogonal.** `ffs-repair` operates on blocks, not files. It doesn't know about inodes or directories.
5. **Harness dependency boundary.** `ffs-harness` consumes internal crates for validation; `ffs-cli` and `ffs-ops` also depend on it for operator-facing validation commands. Core filesystem crates must remain independent of the harness.
6. **No cycles.** The dependency graph is a DAG. If crate A depends on B, B must not depend on A.
7. **Explicit Cx is required by the target design.** Context-aware filesystem operations accept `&Cx`; current repair-flush notification still has a `Cx::current()` path, and CLI/FUSE workers use standard threads. Completing explicit propagation and region ownership remains required work. Absence of a `Cx` argument does not prohibit Rust standard-library I/O.

---

## 5. Integration with External Dependencies

### 5.1 asupersync

| Feature | Usage |
|---------|-------|
| `Cx` (capability context) | Passed through context-aware filesystem I/O; ambient and standard-thread paths remain to be integrated |
| `Budget` | Resource budgeting for block cache memory, open file descriptors, repair symbol storage |
| `Region` | Required target ownership for background tasks; current CLI scrub and FUSE workers also use standard threads |
| `Lab` | Deterministic runtime for testing concurrent MVCC operations |
| `RaptorQ codec` | Encoding/decoding repair symbols in `ffs-repair` |
| `blocking_pool` | Offload synchronous disk I/O from async context |

### 5.2 ftui (frankentui)

| Feature | Usage |
|---------|-------|
| Theme/style | Consistent terminal styling for `ffs-tui` and `ffs-cli` output |
| Widget library | Live dashboard widgets for cache stats, MVCC metrics, repair status |
| Event loop | TUI refresh loop integrated with filesystem event notifications |

### 5.3 fuser

| Feature | Usage |
|---------|-------|
| `Filesystem` trait | `ffs-fuse` implements this trait to serve FUSE requests |
| `MountOption` | Mount configuration (read-only, allow_other, auto_unmount) |
| `Session` | FUSE session lifecycle management |

> **Status:** vendored `fuser` is a patched dependency, excluded from first-party workspace lint enforcement. `ffs-fuse` implements `fuser::Filesystem`; mounts reach ext4 and btrfs paths, including a wired per-core dispatcher. Default mount is read-only; read-write behavior remains experimental, and complete V1 acceptance requires execution evidence beyond this architecture map.

---

## 6. Data Flow Examples

### 6.1 Read Path

```
userspace read(fd, buf, count)
  → kernel FUSE → fuser → ffs-fuse::read()
    → ffs-core: begin read transaction
      → ffs-mvcc: get snapshot, read versioned blocks
        → ffs-extent: resolve logical offset → physical blocks
          → ffs-btree: walk extent B+tree
        → ffs-block: read blocks through ARC cache
          → BlockDevice::read_block()
    → ffs-core: assemble response, end transaction
  → fuser → kernel → userspace
```

### 6.2 Write Path

```
userspace write(fd, buf, count)
  → kernel FUSE → fuser → ffs-fuse::write()
    → ffs-core: begin write transaction
      → ffs-mvcc: create new block versions (COW)
        → ffs-extent: resolve/allocate physical blocks
          → ffs-alloc: mballoc allocation
          → ffs-btree: update extent tree
        → ffs-block: write blocks through cache
          → BlockDevice::write_block()
      → ffs-journal: record transaction in COW journal
      → ffs-repair: refresh repair symbols for modified blocks
      → ffs-mvcc: commit (SSI validation)
    → ffs-core: return bytes written
  → fuser → kernel → userspace
```

### 6.3 Corruption Recovery Path

```
ffs-repair::scrub() [background]
  → ffs-block: read all blocks in group
    → checksum verification (crc32c or BLAKE3)
    → MISMATCH detected for block N
      → ffs-repair: load repair symbols for block group
        → asupersync RaptorQ codec: decode
        → recovered block data
      → ffs-block: write corrected block
      → ffs-repair: refresh repair symbols
      → report: { block: N, status: recovered }
```

---

## 7. Error Strategy

All errors flow through `FfsError` (defined in `ffs-error`):

```rust
/// 18 variants — this is the canonical definition. See ffs-error/src/lib.rs.
#[derive(Debug, thiserror::Error)]
pub enum FfsError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("corrupt metadata at block {block}: {detail}")]
    Corruption { block: u64, detail: String },

    #[error("invalid on-disk format: {0}")]
    Format(String),

    #[error("parse error: {0}")]
    Parse(String),

    #[error("unsupported feature: {0}")]
    UnsupportedFeature(String),

    #[error("invalid geometry: {0}")]
    InvalidGeometry(String),

    #[error("MVCC conflict: transaction {tx} conflicts on block {block}")]
    MvccConflict { tx: u64, block: u64 },

    #[error("operation cancelled")]
    Cancelled,

    #[error("no space left on device")]
    NoSpace,

    #[error("not found: {0}")]
    NotFound(String),

    #[error("permission denied")]
    PermissionDenied,

    #[error("read-only filesystem")]
    ReadOnly,

    #[error("not a directory")]
    NotDirectory,

    #[error("is a directory")]
    IsDirectory,

    #[error("directory not empty")]
    NotEmpty,

    #[error("name too long")]
    NameTooLong,

    #[error("file exists")]
    Exists,

    #[error("repair failed: {0}")]
    RepairFailed(String),
}
```

> This error listing is an architectural sketch, not the complete current API. `crates/ffs-error/src/lib.rs` is authoritative for variants and errno mappings.

---

## 8. Configuration

Current library callers open images with synchronous `OpenFs::open(&cx, path)` or `OpenFs::open_with_options(&cx, path, &OpenOptions)`. FUSE configuration is in `ffs_fuse::MountOptions` and `ffs_fuse::MountConfig`. The following historical combined configuration sketch is not an exported `ffs_core::MountConfig`:

```rust
pub struct MountConfig {
    /// Path to the ext4 image or block device.
    pub device: PathBuf,

    /// Mount point.
    pub mountpoint: PathBuf,

    /// Read-only mount.
    pub read_only: bool,

    /// ARC cache size (number of blocks).
    pub cache_size: usize,

    /// Enable MVCC (native mode) or JBD2-compat (legacy mode).
    pub mvcc_enabled: bool,

    /// Optional MVCC overlay path for durable versioned blocks (append-only log).
    /// When None, MVCC is in-memory only (dev/testing).
    pub mvcc_overlay_path: Option<PathBuf>,

    /// Enable RaptorQ self-healing.
    pub repair_enabled: bool,

    /// Repair symbol overhead ratio (e.g., 0.05 = 5% extra storage).
    pub repair_overhead: f64,

    /// Background scrub interval.
    pub scrub_interval: Duration,

    /// FUSE mount options.
    pub fuse_options: Vec<MountOption>,
}
```

---

## 9. Testing Architecture

| Layer | Strategy | Crate |
|-------|----------|-------|
| On-disk parsing | Round-trip golden tests against real ext4 metadata | `ffs-harness` |
| Block I/O | Mock BlockDevice, verify cache behavior | `ffs-block` (unit) |
| MVCC | Lab runtime deterministic concurrency tests | `ffs-mvcc` (unit) |
| Extent tree | Property tests (proptest) for tree invariants | `ffs-btree`, `ffs-extent` |
| Directory ops | htree hash compatibility tests against kernel dx_hash | `ffs-dir` (unit) |
| FUSE integration | Mount image, run standard filesystem operations | `ffs-harness` |
| Repair | Inject corruption, verify recovery | `ffs-harness` |
| Performance | Criterion benchmarks for hot paths | `ffs-harness` |
| Fuzz | Fuzz on-disk parsers with arbitrary bytes | `ffs-ondisk` (fuzz) |

---

## 10. Upgrade Path

_This section tracks original implementation sequencing, not current parity status._

1. **Phase 1:** Workspace scaffolding, specs, empty stubs
2. **Phase 2:** On-disk parsing (ext4 + btrfs metadata ingestion)
3. **Phase 3:** Block I/O with ARC cache
4. **Phase 4:** Extent tree traversal and block allocation
5. **Phase 5:** Inode and directory operations (initial mount path)
6. **Phase 6:** Journal replay and MVCC (read-write mount)
7. **Phase 7:** Full FUSE interface
8. **Phase 8:** RaptorQ self-healing
9. **Phase 9:** CLI, TUI, and conformance harness maturity
