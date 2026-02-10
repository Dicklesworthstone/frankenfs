# PROPOSED_ARCHITECTURE.md — FrankenFS (ffs)

> 21-crate Cargo workspace architecture (19 core crates + 2 legacy/reference wrappers) for a memory-safe, FUSE-based Rust reimplementation of ext4 and btrfs with block-level MVCC and RaptorQ self-healing.

---

## 1. Crate Map

| # | Crate | Role | Key Dependencies | Primary Phase |
|---|-------|------|-----------------|--------------|
| 1 | `ffs-types` | Newtypes: BlockNumber, InodeNumber, TxnId, CommitSeq, Snapshot, ParseError; binary read helpers (read_le_u16/u32/u64); ext4/btrfs magic constants | `serde`, `thiserror` | 2 |
| 2 | `ffs-error` | FfsError enum, Result<T> alias, errno mappings (ENOENT, EIO, ENOSPC, ...) | `thiserror` | 2 |
| 3 | `ffs-ondisk` | ext4 + btrfs on-disk format parsing: superblocks, headers, keys/items, ext4 group desc/inodes/extents/dirs, JBD2 structures | `ffs-types`, `ffs-error`, `crc32c`, `serde` | 2 |
| 4 | `ffs-block` | Block I/O layer: BlockDevice trait, ARC (Adaptive Replacement Cache), read/write with Cx, dirty page tracking | `ffs-types`, `ffs-error`, `asupersync`, `parking_lot` | 3 |
| 5 | `ffs-journal` | JBD2-compatible journal replay + native COW journal: transaction lifecycle, descriptor/commit/revoke blocks | `ffs-types`, `ffs-error`, `ffs-block` | 6 |
| 6 | `ffs-mvcc` | Block-level MVCC: version chains (BlockVersion), snapshot isolation, first-committer-wins conflict detection, GC of old versions | `ffs-types`, `serde`, `thiserror` | 6 |
| 7 | `ffs-btree` | B-tree operations used by ext4 (extents/htree) and btrfs (metadata trees): search, insert, split, merge, tree walk | `ffs-types`, `ffs-error`, `ffs-block`, `ffs-ondisk` | 4 |
| 8 | `ffs-alloc` | Block/inode allocation: mballoc-style multi-block allocator (buddy system, best-fit, prealloc), Orlov inode allocator | `ffs-types`, `ffs-error`, `ffs-block`, `ffs-ondisk` | 4 |
| 9 | `ffs-inode` | Inode management: read/write/create/delete, permissions, timestamps, flags | `ffs-types`, `ffs-error`, `ffs-block`, `ffs-ondisk` | 5 |
| 10 | `ffs-dir` | Directory operations: linear scan, htree (hashed B-tree) lookup, dx_hash, create/delete entries | `ffs-types`, `ffs-error`, `ffs-inode` | 5 |
| 11 | `ffs-extent` | Extent mapping: logical→physical block resolution, extent allocation, hole detection | `ffs-types`, `ffs-error`, `ffs-btree`, `ffs-alloc` | 4 |
| 12 | `ffs-xattr` | Extended attributes: inline (after inode extra fields), external block, namespace routing (user/system/security/trusted) | `ffs-types`, `ffs-error`, `ffs-block`, `ffs-ondisk` | 5 |
| 13 | `ffs-fuse` | FUSE interface: FuseBackend trait, MountOptions, FrankenFuseMount — delegates to ffs-core engine (not domain crates directly) | `ffs-core`, `ffs-types`, `asupersync`, `serde`, `thiserror` | 7 |
| 14 | `ffs-repair` | RaptorQ self-healing: generate/store repair symbols per block group, detect corruption via checksum, recover blocks, background scrub | `ffs-types`, `ffs-error`, `ffs-block`, `asupersync` | 8 |
| 15 | `ffs-core` | Engine integration: format detection (FsFlavor), FrankenFsEngine (MVCC wrapper), DurabilityAutopilot (Bayesian redundancy), mount orchestration | `ffs-types`, `ffs-ondisk`, `ffs-mvcc`, `asupersync`, `serde`, `thiserror` | 7 |
| 16 | `ffs` | Public API facade: re-exports core functionality, stable external interface | `ffs-core` | 9 |
| 17 | `ffs-cli` | CLI binary: `ffs inspect` (currently), planned: `ffs mount`, `ffs fsck`, `ffs info`, `ffs repair` | `ffs-core`, `anyhow`, `serde`, `serde_json`, `ftui` | 9 |
| 18 | `ffs-tui` | TUI monitoring: live cache stats, MVCC version counts, repair status, I/O throughput | `ffs`, `ftui` | 9 |
| 19 | `ffs-harness` | Conformance testing harness: parity reports, sparse JSON fixtures, compare FrankenFS behavior against real ext4/btrfs images | `ffs-core`, `ffs-ondisk`, `ffs-types`, `anyhow`, `hex`, `serde`, `serde_json`; dev: `criterion` | 9 |
| 20 | `ffs-ext4` | Legacy/reference wrapper for ext4 parsing APIs (re-exports `ffs-ondisk::ext4::*`) | `ffs-ondisk` | 1 |
| 21 | `ffs-btrfs` | Legacy/reference wrapper for btrfs parsing APIs (re-exports `ffs-ondisk::btrfs::*`) | `ffs-ondisk` | 1 |

---

## 2. Dependency Graph

```
                    ┌──────────┐  ┌──────────┐
                    │ ffs-types│  │ ffs-error │
                    └────┬─────┘  └─────┬─────┘
                         │              │
                         └──────┬───────┘
                                │
                         ┌──────▼──────┐
                         │  ffs-ondisk  │       ┌──────────┐
                         └──────┬──────┘       │ ffs-mvcc  │
                                │              │(ffs-types,│
              ┌─────────────────┼──────────┐   │serde,     │
              │                 │          │   │thiserror) │
       ┌──────▼──────┐  ┌──────▼──────┐  ┌▼───┴──────────┐
       │  ffs-block   │  │  ffs-btree  │  │   ffs-xattr   │
       │  (+ ARC)     │  └──────┬──────┘  └───────────────┘
       └──┬───┬───┬───┘        │
          │   │   │      ┌─────▼─────┐
          │   │   │      │ ffs-alloc  │
          │   │   │      └─────┬─────┘
          │   │   │            │
   ┌──────▼┐  │  ┌▼──────┐  ┌─▼────────┐  ┌──────────────┐
   │ffs-   │  │  │ffs-   │  │ffs-extent│  │  ffs-inode   │
   │journal│  │  │repair │  └──────────┘  └──────┬───────┘
   └───────┘  │  └───────┘                       │
              │                           ┌──────▼──────┐
              │                           │   ffs-dir   │
              │                           └─────────────┘
              │
       ┌──────▼──────┐  (orchestrates ffs-mvcc, ffs-ondisk, ffs-types)
       │   ffs-core   │
       └──┬───────┬───┘
          │       │
   ┌──────▼────┐  │  ┌────────────┐
   │  ffs-fuse  │  │  │    ffs     │  (public facade)
   │(ffs-core)  │  │  │ (ffs-core) │
   └────────────┘  │  └──┬───┬────┘
                   │     │   │
           ┌───────┘     │   └────────┐
           │             │            │
    ┌──────▼──┐  ┌──────▼─────┐ ┌───▼────────┐
    │ ffs-cli  │  │  ffs-tui   │ │ ffs-harness │
    └─────────┘  └────────────┘ └────────────┘
```

> **Note:** `ffs-fuse` depends on `ffs-core` (which orchestrates domain crates), NOT on domain crates directly. This is the canonical layering — ffs-core is the integration point, ffs-fuse is a thin FUSE protocol adapter. `ffs-mvcc` is currently standalone (depends only on `ffs-types`, `serde`, `thiserror`) — it will gain `ffs-block` and `ffs-journal` dependencies as block-backed versioning is implemented.

---

## 3. Trait Hierarchy

### 3.1 Storage Traits

```rust
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
}
```

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
2. **MVCC is transport-agnostic.** `ffs-mvcc` knows nothing about FUSE, files, or directories.
3. **FUSE adapter delegates to ffs-core.** `ffs-fuse` maps FUSE protocol to `ffs-core::FrankenFsEngine` — it contains no filesystem logic and does not depend on domain crates directly.
4. **Repair is orthogonal.** `ffs-repair` operates on blocks, not files. It doesn't know about inodes or directories.
5. **Harness depends on everything.** `ffs-harness` may use any internal crate. No production crate depends on harness.
6. **No cycles.** The dependency graph is a DAG. If crate A depends on B, B must not depend on A.
7. **Cx everywhere.** Any operation that performs I/O or may block takes `&Cx` as its first parameter.

---

## 5. Integration with External Dependencies

### 5.1 asupersync

| Feature | Usage |
|---------|-------|
| `Cx` (capability context) | Threaded through all I/O operations for cooperative cancellation and deadline propagation |
| `Budget` | Resource budgeting for block cache memory, open file descriptors, repair symbol storage |
| `Region` | Structured concurrency scopes for background tasks (scrub, GC, flush) |
| `Lab` | Deterministic runtime for testing concurrent MVCC operations |
| `RaptorQ codec` | Encoding/decoding repair symbols in `ffs-repair` |
| `blocking_pool` | Offload synchronous disk I/O from async context |

### 5.2 ftui (frankentui)

| Feature | Usage |
|---------|-------|
| Theme/style | Consistent terminal styling for `ffs-tui` and `ffs-cli` output |
| Widget library | Live dashboard widgets for cache stats, MVCC metrics, repair status |
| Event loop | TUI refresh loop integrated with filesystem event notifications |

### 5.3 fuser (planned — not yet in workspace dependencies)

| Feature | Usage |
|---------|-------|
| `Filesystem` trait | `ffs-fuse` will implement this trait to serve FUSE requests (Phase 7) |
| `MountOption` | Mount configuration (read-only, allow_other, direct_io) |
| `Session` | FUSE session lifecycle management in `ffs-core` |

> **Status:** `fuser` is not yet listed in `Cargo.toml` workspace dependencies. It will be added when `ffs-fuse` progresses past scaffolding (Phase 7). Currently, `ffs-fuse` defines its own `FuseBackend` trait and `FrankenFuseMount` that returns `NotImplemented`.

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
/// 14 variants — this is the canonical definition. See ffs-error/src/lib.rs.
#[derive(Debug, thiserror::Error)]
pub enum FfsError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("corrupt metadata at block {block}: {detail}")]
    Corruption { block: u64, detail: String },

    #[error("invalid on-disk format: {0}")]
    Format(String),

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

> **Canonical variant count: 14.** Other sections of the spec that reference FfsError with different counts or variant names (e.g., `AlreadyExists` for `Exists`, `DirectoryNotEmpty` for `NotEmpty`) are non-normative — this listing and `ffs-error/src/lib.rs` are the single source of truth.

---

## 8. Configuration

Mount-time configuration lives in `ffs-core`:

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

1. **Phase 1 (current):** Workspace scaffolding, specs, empty stubs
2. **Phase 2:** On-disk parsing (read-only ext4 image access)
3. **Phase 3:** Block I/O with ARC cache
4. **Phase 4:** Extent tree traversal and block allocation
5. **Phase 5:** Inode and directory operations (read-only mount)
6. **Phase 6:** Journal replay and MVCC (read-write mount)
7. **Phase 7:** Full FUSE interface
8. **Phase 8:** RaptorQ self-healing
9. **Phase 9:** CLI, TUI, and conformance harness maturity
