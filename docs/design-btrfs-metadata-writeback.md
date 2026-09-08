# Design: btrfs Metadata Writeback

> **Status:** Spec-first design document per AGENTS.md doctrine.
> **Beads:** bd-xuo95.37 (A-design), prerequisite for bd-xuo95.2 (A1), bd-xuo95.3 (A2), bd-xuo95.4 (A3), bd-xuo95.5 (A4).
> **Last updated:** 2026-05-21

---

## 1. Problem Statement

FrankenFS btrfs mutations (`create`, `mkdir`, `unlink`, `write`, etc.) execute against
an in-memory `InMemoryCowBtrfsTree` (`ffs-btrfs/src/lib.rs:1483`) that is **never
serialized back to disk**. The `btrfs_sync_with_logging` function (`ffs-core/src/lib.rs:13493`)
logs `outcome="applied"` while flushing only the ext4 MVCC store (empty for btrfs).
btrfs RW changes evaporate on unmount.

This design specifies how to make btrfs metadata durable:
1. Serialize in-memory CoW nodes to on-disk format (A1)
2. Allocate physical blocks for new nodes (A2)
3. Commit the tree root atomically via superblock (A3)
4. Ensure crash consistency via write ordering (A4)

---

## 2. On-Disk Node Format Obligations

### 2.1 Node Header (`btrfs_header`)

Every tree node (leaf or internal) begins with a 101-byte header:

```
Offset  Size  Field              Description
------  ----  -----              -----------
0x00    32    csum               CRC32C over bytes [32..nodesize)
0x20    16    fsid               Filesystem UUID
0x30    8     bytenr             Byte offset of this node on disk
0x38    8     flags              BTRFS_HEADER_FLAG_* bits
0x40    16    chunk_tree_uuid    Chunk tree UUID
0x50    8     generation         Transaction ID that last modified this node
0x58    8     owner              Tree ID that owns this node (root objectid)
0x60    4     nritems            Number of items (leaves) or key-pointers (internal)
0x64    1     level              Tree level (0 = leaf)
```

**Serialization contract:**
- `csum` is computed **after** all other fields are written, over `[32..nodesize)`.
- `bytenr` **must** match the physical location where the node is written.
- `generation` **must** be the current transaction ID.
- `fsid` **must** match the superblock's `fsid`.

### 2.2 Leaf Node Layout (level = 0)

```
[header (101 bytes)] [item[0]..item[N-1]] ... [gap] ... [data[N-1]..data[0]]
```

Each `btrfs_item` (25 bytes):
```
Offset  Size  Field    Description
------  ----  -----    -----------
0x00    17    key      (objectid: u64, type: u8, offset: u64) little-endian
0x11    4     offset   Offset of item data from end of header
0x15    4     size     Size of item data in bytes
```

Item data grows **backward** from `nodesize` toward the item array. The `offset` field
gives the data position relative to `BTRFS_LEAF_DATA_OFFSET` (byte 101, end of header).

**Serialization contract:**
- Items must be sorted by key (lexicographic: objectid, type, offset).
- No overlap between item array and item data region.
- `nritems` in header must match actual item count.

### 2.3 Internal Node Layout (level > 0)

```
[header (101 bytes)] [key_ptr[0]..key_ptr[N-1]]
```

Each `btrfs_key_ptr` (33 bytes):
```
Offset  Size  Field       Description
------  ----  -----       -----------
0x00    17    key         First key in the child subtree
0x11    8     blockptr    Byte offset of child node
0x19    8     generation  Generation of child node
```

**Serialization contract:**
- Key-pointers must be sorted by key.
- `blockptr` must point to a valid allocated node.
- `generation` must match the child's header generation.

### 2.4 Nodesize

The nodesize is stored in the superblock (`nodesize` field, default 16384 = 16 KiB).
**Do NOT assume 4 KiB** — the serializer must respect the superblock's declared nodesize.

Maximum items per leaf: `(nodesize - 101) / 25 - 1` (leaving room for data).
Maximum key-pointers per internal: `(nodesize - 101) / 33 = 493` for 16 KiB.

---

## 3. Block Group Model for Metadata Allocation

### 3.1 Chunk Tree Structure

btrfs maps logical addresses to physical devices via chunks. Each chunk belongs to a
block group with a type:

| Type Flag | Profile | Purpose |
|-----------|---------|---------|
| `BTRFS_BLOCK_GROUP_DATA` | Data extents |
| `BTRFS_BLOCK_GROUP_METADATA` | Tree nodes |
| `BTRFS_BLOCK_GROUP_SYSTEM` | Chunk/dev trees |

Metadata nodes **must** be allocated from chunks with the `METADATA` flag (or `MIXED`).

### 3.2 MIXED_BLOCK_GROUPS (Small Images)

For small filesystems (< 1 GiB by default), btrfs uses `MIXED_BLOCK_GROUPS` mode where
data and metadata share the same chunks. This is indicated by:
- `BTRFS_FEATURE_INCOMPAT_MIXED_GROUPS` in superblock `incompat_flags`
- Block groups have both `DATA` and `METADATA` flags set

**Implementation requirement:** When `MIXED_GROUPS` is set, allocate metadata from any
`DATA|METADATA` block group. When not set, allocate only from pure `METADATA` groups.

### 3.3 Extent Tree Accounting

Every allocated metadata block requires:
1. An `EXTENT_ITEM` (key type 0xA8) or `METADATA_ITEM` (key type 0xA9) in the extent tree
2. A `TREE_BLOCK_REF` (key type 0xB0) back-reference
3. Free-space update in the free-space tree (or cache)

The allocation path:
```
1. Find a metadata block group with free space
2. Allocate logical bytes from the block group
3. Insert EXTENT_ITEM/METADATA_ITEM into extent tree
4. Insert TREE_BLOCK_REF back-reference
5. Update block group free space accounting
```

**Invariant:** No node may be written to a location not marked allocated in the extent tree.

FrankenFS models the allocation range and its back-references as distinct extent-tree
items. Gap scans and largest-free calculations count only `EXTENT_ITEM` and
`METADATA_ITEM` keys as occupied byte ranges; `TREE_BLOCK_REF` keys prove ownership but
do not consume additional address space.

---

## 4. Write-Dependency DAG

### 4.1 Definition

The write-dependency DAG captures the ordering constraint: **a child node must be
durable before any parent that references it**.

Nodes in the DAG:
- Every dirty (modified or new) tree node
- The root tree (contains ROOT_ITEM for each tree)
- The superblock (generation bump commits everything)

Edges (A → B means "A must be durable before B"):
- Leaf → parent internal node
- Internal node → its parent
- Tree root node → ROOT_ITEM in root tree
- ROOT_ITEM → root tree root node
- Root tree root → superblock

### 4.2 Topological Sort

Flush nodes in **reverse topological order** of the DAG:
1. All leaf nodes (level 0) with no dirty children
2. Internal nodes (level 1..7) whose children are all durable
3. Tree roots (after all their subtrees)
4. Root tree (after all ROOT_ITEMs updated)
5. Superblock (last, the linearization point)

### 4.3 fsync Barrier

Before serializing the transaction's metadata, drain committed MVCC file-data
blocks to the underlying device while holding the btrfs allocator lock. That
lock excludes new btrfs writes from the metadata snapshot being committed.
Publishing extent references and checksums without this drain can acknowledge
an fsync whose file data disappears after reopening. A drain failure must return
before advancing the generation or mutating commit publication state.

Before writing the superblock:
1. Issue `fsync()` on the underlying device
2. This ensures all prior file-data and node writes are durable
3. Only then write the superblock

The barrier makes the superblock write the single atomic commit point.
If there are no metadata nodes to publish but the drain wrote file-data blocks,
issue the device sync before returning success.

---

## 5. Crash Consistency Invariants

### 5.1 WB-I1: Prefix-Closed Durability

> At every crash point, the set of durable nodes is **prefix-closed** under references:
> no durable internal node points at a non-durable child.

**Why this holds:** Reverse-topological flush order ensures children are durable before
parents. If a crash interrupts writeback:
- Nodes flushed before the crash are durable
- Their parent pointers were not yet updated (parents flush later)
- The old superblock still points at the old tree

**Executable oracle:** After a simulated crash, traverse from the superblock. Every
`blockptr` in a durable internal node must point to a durable child (verified by
checking the child's checksum and generation).

### 5.2 WB-I2: Atomic Generation Transition

> A reader after crash observes generation `g` (pre-writeback) or `g+1` (post),
> never a torn mixture.

**Why this holds:** The superblock write is the single linearization point. Before
the superblock is durable at generation `g+1`:
- The old superblock at generation `g` remains valid
- Old tree roots are intact (COW means they weren't overwritten)

After the superblock is durable:
- New tree roots are referenced
- New nodes are reachable
- Old nodes become orphans (reclaimable)

**Executable oracle:** Mount after crash, read superblock generation. Traverse the
entire tree structure. Every reachable node's generation must be ≤ superblock generation.
No node with generation > superblock.generation is reachable.

### 5.3 No Tree-Log Required for Correctness

btrfs's tree-log is an **optimization** for fast `fsync()` — it allows a single file's
durability without a full transaction commit. For correctness, a full transaction
commit (all dirty nodes + superblock) is sufficient.

This design implements full-transaction commit only. Tree-log is **explicitly deferred**
(see Section 9) because:
1. Full commit is correct (all mutations durable)
2. Tree-log adds complexity (must replay on mount)
3. The read/replay path already exists; write path is the gap

---

## 6. Atomic Root Commit Sequence

### 6.1 ROOT_ITEM Update

Each tree's current root location is stored as a `ROOT_ITEM` in the root tree
(tree objectid 1):
```
Key: (tree_objectid, BTRFS_ROOT_ITEM_KEY, 0)
Value: btrfs_root_item {
    bytenr: u64,      // Root node location
    generation: u64,  // Generation of root node
    ...
}
```

After flushing a tree's nodes, update its ROOT_ITEM:
1. Read the current ROOT_ITEM
2. Update `bytenr` to the new root node location
3. Update `generation` to the current transaction ID
4. Write the updated ROOT_ITEM (this dirties the root tree)

### 6.2 Superblock Commit

The superblock stores:
- `root` / `root_level`: Root tree location
- `chunk_root` / `chunk_root_level`: Chunk tree location
- `generation`: Transaction ID

Commit sequence:
1. Flush all dirty tree nodes (reverse-topological)
2. Update all ROOT_ITEMs in root tree
3. Flush root tree nodes
4. `fsync()` barrier
5. Write superblock with `generation = g + 1`
6. Update backup root ring (generations g-3, g-2, g-1, g)
7. Write superblock to all mirror locations:
   - Primary: 64 KiB (0x10000)
   - Mirror 1: 64 MiB (0x4000000)
   - Mirror 2: 256 GiB (0x4000000000) — if device is large enough

### 6.3 Backup Root Ring

The superblock contains a backup root ring (`super_roots[4]`) preserving the last
4 root tree locations. On commit:
```
super_roots[3] = super_roots[2]  // g-3
super_roots[2] = super_roots[1]  // g-2
super_roots[1] = super_roots[0]  // g-1
super_roots[0] = current_root    // g
```

This enables recovery from a corrupted/torn superblock by falling back to an older
root tree state.

---

## 7. Orphan Data-Extent Reclamation

### 7.1 The Problem

When `btrfs_write_logical` writes file data directly to disk, it allocates a data
extent and inserts an `EXTENT_DATA` item in the inode's tree. If a crash interrupts
writeback after the data extent is allocated but before the `EXTENT_DATA` item is
committed:
- The data extent is allocated (in extent tree)
- The `EXTENT_DATA` item is not durable
- Result: allocated-but-unreachable leak

### 7.2 Solution: Transactional Commit and Recovery Cleanup

**Transactional path:** Ensure both allocation and metadata commit atomically:
- Do not expose data extents as durable until the referencing metadata commits
- Use delayed allocation: reserve space, write data, then allocate+commit together

**Recovery path:** On mount or replay cleanup, scan for orphan extents:
- Extents in extent tree with no referencing EXTENT_DATA item
- Free them during mount-time cleanup

The initial A2 implementation provides the allocator-side cleanup primitive:
`BtrfsExtentAllocator::reclaim_unreferenced_data_extents` scans data block groups for
allocated `EXTENT_ITEM`s and frees any extent absent from the caller's durable
`EXTENT_DATA` reference set. Later writeback/replay phases provide that reference set
from the persisted inode trees.

### 7.3 Metadata-Only Orphans

Metadata nodes that were allocated but whose parent reference didn't commit are
automatically handled: the old superblock doesn't reference them, so they're not
reachable and can be reclaimed by the free-space accounting during the next mount
or balance operation.

---

## 8. Serialization API

### 8.1 Node Serializer Interface

```rust
pub trait BtrfsNodeSerializer {
    /// Serialize a leaf node to on-disk bytes.
    ///
    /// # Arguments
    /// * `items` - Sorted (key, data) pairs
    /// * `nodesize` - Node size from superblock
    /// * `generation` - Current transaction ID
    /// * `bytenr` - Physical byte offset where this node will be written
    /// * `owner` - Tree ID that owns this node
    /// * `fsid` - Filesystem UUID
    ///
    /// # Returns
    /// `nodesize` bytes ready for disk write, with valid CRC32C.
    fn serialize_leaf(
        &self,
        items: &[(BtrfsKey, &[u8])],
        nodesize: u32,
        generation: u64,
        bytenr: u64,
        owner: u64,
        fsid: &[u8; 16],
    ) -> Result<Vec<u8>, BtrfsSerializeError>;

    /// Serialize an internal node to on-disk bytes.
    fn serialize_internal(
        &self,
        key_ptrs: &[(BtrfsKey, u64, u64)], // (key, child_bytenr, child_gen)
        level: u8,
        nodesize: u32,
        generation: u64,
        bytenr: u64,
        owner: u64,
        fsid: &[u8; 16],
    ) -> Result<Vec<u8>, BtrfsSerializeError>;
}
```

### 8.2 Round-Trip Property

**Invariant:** `parse(serialize(tree)) ≡ tree`

Property test:
1. Generate arbitrary `InMemoryCowBtrfsTree`
2. Serialize each node
3. Parse with existing `ffs-ondisk` btrfs parser
4. Compare parsed structure equals original

---

## 9. Tree-Log Deferral (V1.x)

The btrfs tree-log provides fast per-file `fsync()` without a full transaction commit.
It works by:
1. Recording pending changes for a file in a separate tree-log tree
2. On `fsync(file)`, flush only the tree-log
3. On mount, replay the tree-log to recover pending changes

**Why deferred:**
1. Full-transaction commit is **correct** — every `fsync()` durably commits all changes
2. Tree-log is an **optimization** for latency, not correctness
3. The read/replay path already exists (`ffs_btrfs::replay_tree_log`)
4. Write path adds complexity without correctness benefit

**Tracked as:** bd-xuo95.39 (A-deferred), priority P3

---

## 10. Implementation Phases

### Phase A1: CoW Node Serializer (bd-xuo95.2)

- Implement `serialize_leaf()` and `serialize_internal()`
- Parameterize by superblock nodesize
- CRC32C computation over `[32..nodesize)`
- Property test: `parse(serialize(tree)) ≡ tree`
- Fuzz target: `fuzz_btrfs_cow_node_roundtrip`

### Phase A2: Metadata Block Allocation (bd-xuo95.3)

- Allocate from metadata (or mixed) block groups
- Insert EXTENT_ITEM/METADATA_ITEM + TREE_BLOCK_REF
- Update free-space accounting
- Handle ENOSPC
- Orphan-extent reclamation on recovery

Implemented allocator slice:
- `alloc_metadata_for_tree(num_bytes, root, level)` records `METADATA_ITEM` plus
  `TREE_BLOCK_REF` and queues a matching delayed tree-block reference.
- Exhausted matching block groups return `BtrfsMutationError::NoSpace`.
- `reclaim_unreferenced_data_extents(referenced)` frees allocated data extents that
  lack durable `EXTENT_DATA` references while leaving metadata extents intact.

### Phase A3: Atomic Root Commit (bd-xuo95.4)

- ROOT_ITEM update per tree
- Backup root ring rotation
- Superblock generation bump
- Multi-mirror superblock write
- WB-I2 oracle

### Phase A4: Crash Consistency (bd-xuo95.5)

- Write-dependency DAG construction
- Reverse-topological flush
- fsync barrier before superblock
- DPOR-enumerated crash points via LabRuntime
- WB-I1 oracle at every crash point

---

## 11. Test Strategy

### 11.1 Unit Tests

- Node serialization round-trip (leaf, internal, empty, full, max-fanout)
- Block allocation (normal, ENOSPC, mixed-groups, tree-block backrefs)
- Data orphan reclamation (reclaims unreferenced data, preserves metadata)
- ROOT_ITEM update
- Backup root ring rotation

### 11.2 Integration Tests

- Mount RW → mutate → unmount → remount → verify mutations
- Metamorphic: `reparse(writeback(mutate(parse(img)))) ≡ model(mutate(parse(img)))`

### 11.3 Crash Matrix (LabRuntime DPOR)

For each crash point enumerated by DPOR:
1. Simulate crash (drop pending writes)
2. Remount from crashed state
3. Assert WB-I1: traversal finds no dangling references
4. Assert WB-I2: superblock generation is `g` or `g+1`
5. Assert filesystem is consistent (`btrfs check` clean)

### 11.4 Differential Validation

After writeback, run:
- `btrfs check --readonly <image>` — no errors
- `btrfs inspect-internal dump-tree <image>` — structure matches in-memory model

---

## 12. Updates to Other Documents

### 12.1 PROPOSED_ARCHITECTURE.md

Add to ffs-btrfs description:
> Btrfs tree walking and mutation layer: ... **metadata writeback serialization
> (CoW node → on-disk bytes)**, extent tree allocation for new nodes, atomic
> superblock commit with generation bump.

### 12.2 FEATURE_PARITY.md

Update btrfs rows:
- "btrfs metadata writeback" — `in_progress` → `implemented` when A1-A4 complete
- "btrfs crash consistency" — new row, `implemented` with cited tests
- "btrfs RW durability" — new row, `implemented` with e2e script

---

*End of design document.*
