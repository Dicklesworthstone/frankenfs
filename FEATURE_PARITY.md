# FEATURE_PARITY

> Quantitative feature coverage tracking for FrankenFS.

## 1. Coverage Summary (Current)

| Domain | Implemented | Total Tracked | Coverage |
|--------|-------------|---------------|----------|
| ext4 metadata parsing | 10 | 19 | 52.6% |
| btrfs metadata parsing | 8 | 20 | 40.0% |
| MVCC/COW core | 5 | 14 | 35.7% |
| FUSE surface | 6 | 12 | 50.0% |
| self-healing durability policy | 5 | 10 | 50.0% |
| **Overall** | **34** | **75** | **45.3%** |

> **Canonical source:** The `ParityReport::current()` function in `ffs-harness` is the
> authoritative source for implemented/total counts. This table MUST match those
> values at all times. A CI test (`parity_report_matches_feature_parity_md`)
> enforces this invariant.

## 2. Tracked Capability Matrix

| Capability | Legacy Reference | Status | Notes |
|------------|------------------|--------|-------|
| ext4 superblock decode | `fs/ext4/ext4.h` | ✅ | Implemented in `ffs-ext4` |
| ext4 inode core decode | `fs/ext4/ext4.h` | ✅ | Implemented in `ffs-ext4` |
| ext4 extent header decode | `fs/ext4/ext4_extents.h` | ✅ | Implemented in `ffs-ext4` |
| ext4 extent entry decode | `fs/ext4/ext4_extents.h` | ✅ | Implemented in `ffs-ext4` |
| ext4 feature flag validation | `fs/ext4/super.c` | ✅ | Basic checks implemented |
| ext4 group descriptor decode | `fs/ext4/ext4.h` | ✅ | Implemented in `ffs-ondisk` (`Ext4GroupDesc`) |
| ext4 directory entry parsing | `fs/ext4/dir.c` | ✅ | Implemented in `ffs-ondisk` |
| ext4 inode device read | `fs/ext4/inode.c` | ✅ | `OpenFs::read_inode` via `ByteDevice` |
| ext4 path resolution | `fs/ext4/namei.c` | ✅ | `OpenFs::resolve_path` |
| ext4 bitmap free space reading | `fs/ext4/balloc.c` | ✅ | `OpenFs::free_space_summary`, bitmap-derived free block/inode counts |
| ext4 journal replay parity | `fs/ext4/ext4_jbd2.c` | 🟡 | Replay + write-side implemented in `ffs-journal` (`replay_jbd2`, `Jbd2Writer` with descriptor/data/revoke/commit blocks, self-replayability verified). `OpenFs::commit_transaction_journaled` integration boundary in `ffs-core`. Checkpoint/space management pending. |
| ext4 allocator parity | `fs/ext4/mballoc.c` | 🟡 | Phase A: correctness-first contiguous alloc with reserved-block exclusion, on-disk GDT persistence, double-free detection. `alloc_blocks_persist` / `free_blocks_persist` in `ffs-alloc`. Buddy-style search and preallocation pending. |
| ext4 orphan recovery parity | `fs/ext4/orphan.c` | 🟡 | Read-only orphan-list detection/traversal implemented (`OpenFs::read_ext4_orphan_list` + CLI inspect diagnostics); mutating orphan cleanup still pending |
| btrfs superblock decode | `fs/btrfs/disk-io.c` | ✅ | Implemented in `ffs-ondisk` |
| btrfs btree header decode | `fs/btrfs/ctree.c` | ✅ | Implemented in `ffs-ondisk` |
| btrfs leaf item metadata decode | `fs/btrfs/ctree.c` | ✅ | Implemented in `ffs-ondisk` |
| btrfs internal node parsing | `fs/btrfs/ctree.c` | ✅ | `parse_internal_items` in `ffs-ondisk` |
| btrfs sys_chunk mapping | `fs/btrfs/volumes.c` | ✅ | `map_logical_to_physical` in `ffs-ondisk` |
| btrfs read-only tree walk | `fs/btrfs/ctree.c` | ✅ | `walk_tree` in `ffs-btrfs` |
| btrfs item payload decode (ROOT/INODE/DIR/EXTENT_DATA) | `fs/btrfs/ctree.c` | ✅ | Implemented in `ffs-btrfs` (`parse_root_item`, `parse_inode_item`, `parse_dir_items`, `parse_extent_data`) |
| btrfs open/validate pipeline | `fs/btrfs/disk-io.c` | ✅ | `BtrfsContext` in `ffs-core` |
| btrfs transaction parity | `fs/btrfs/transaction.c` | ❌ | Not yet implemented |
| btrfs delayed refs parity | `fs/btrfs/delayed-ref.c` | ❌ | Not yet implemented |
| btrfs scrub parity | `fs/btrfs/scrub.c` | ❌ | Not yet implemented |
| MVCC snapshot visibility | FrankenFS spec §3 | ✅ | Implemented in `ffs-mvcc` |
| MVCC commit sequencing | FrankenFS spec §3 | ✅ | Implemented in `ffs-mvcc` |
| FCW conflict detection | FrankenFS spec §3 | ✅ | Implemented in `ffs-mvcc` |
| version retention policy | FrankenFS spec §3 | ✅ | In-memory retention with `VersionData::Identical` dedup (zero-copy for unchanged blocks), configurable `CompressionPolicy` (dedup + max chain length cap), watermark-safe pruning, chain-pressure handling (oldest-snapshot force-advance + `CommitError::ChainBackpressure`), and crossbeam-epoch deferred reclamation counters/collection (`ebr_stats`, `ebr_collect`) in `ffs-mvcc` |
| COW block rewrite path | FrankenFS spec §3 | ✅ | Allocation-backed COW rewrite path implemented in `ffs-mvcc` (`write_cow`, logical→physical mapping visibility, deferred-free + watermark GC integration) |
| durability policy model | FrankenFS spec §4 | ✅ | Bayesian expected-loss selector |
| asupersync config mapping | FrankenFS spec §4 | ✅ | `RaptorQConfig` mapping implemented |
| format-aware scrub superblock validation | FrankenFS spec §4 | ✅ | `Ext4SuperblockValidator` + `BtrfsSuperblockValidator` in `ffs-repair`, wired into `ffs-cli scrub` |
| repair symbol storage I/O (dual-slot generation commit) | FrankenFS spec §4 | ✅ | `RepairGroupStorage` in `ffs-repair::storage` with symbol-block validation + torn-generation fallback |
| corruption recovery orchestrator + evidence ledger | FrankenFS spec §4 | ✅ | `GroupRecoveryOrchestrator` in `ffs-repair::recovery` (decode + writeback + post-verify + JSON evidence) |
| FUSE getattr | FrankenFS spec §9 | ✅ | `FsOps::getattr` via `OpenFs` |
| FUSE lookup | FrankenFS spec §9 | ✅ | `FsOps::lookup` via `OpenFs` |
| FUSE readdir | FrankenFS spec §9 | ✅ | `FsOps::readdir` via `OpenFs` |
| FUSE read | FrankenFS spec §9 | ✅ | `FsOps::read` via `OpenFs` |
| FUSE readlink | FrankenFS spec §9 | ✅ | `FsOps::readlink` via `OpenFs` |
| FUSE mount runtime | FrankenFS spec §9 | ❌ | Interface scaffold only |
| CLI inspect command | FrankenFS spec §6 | ✅ | Implemented in `ffs-cli` |
| fixture conformance harness | FrankenFS spec §7 | ✅ | Implemented in `ffs-harness` |
| benchmark harness | FrankenFS spec §8 | ✅ | Criterion benchmark added |

Legend: `✅` implemented, `🟡` partial, `❌` not implemented.

## 3. Blocking Gaps to 100%

1. ext4 journal and allocator mutation behavior parity
2. btrfs transaction/delayed-ref/scrub parity
3. production FUSE mount path
4. full compatibility-mode write-path equivalence

## 4. Update Rule

Any change touching compatibility behavior MUST update this file in the same patch.
