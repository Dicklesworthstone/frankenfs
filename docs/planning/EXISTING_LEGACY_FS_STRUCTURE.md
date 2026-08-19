# EXISTING_LEGACY_FS_STRUCTURE

> Extracted structure overview from Linux kernel v6.19 (`git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git`).
> The original source is gitignored locally due to size; this document captures the extracted behavioral contracts.

## 1. Legacy Corpus Inventory

### ext4

Path: Linux v6.19 `fs/ext4/`

- File count: 52
- Key files:
  - `super.c`
  - `inode.c`
  - `extents.c`
  - `ext4.h`
  - `ext4_extents.h`
  - `xattr.c`
  - `mballoc.c`

### btrfs

Path: Linux v6.19 `fs/btrfs/`

- File count: 130
- Key files:
  - `super.c`
  - `ctree.c`
  - `extent-tree.c`
  - `transaction.c`
  - `disk-io.c`
  - `accessors.h`
  - `fs.h`

## 2. ext4 On-Disk Structures Used in Current Port

### `struct ext4_super_block`

Source: Linux v6.19 `fs/ext4/ext4.h`

Current parser extracts:

- inode/block counters
- block size factors
- group sizes
- feature flags
- UUID
- volume label
- checksum type

### `struct ext4_inode`

Source: Linux v6.19 `fs/ext4/ext4.h`

Current parser extracts:

- mode/uid/gid
- size
- timestamps
- links
- blocks
- flags
- extent payload bytes from `i_block`

### Extent structs

Source: Linux v6.19 `fs/ext4/ext4_extents.h`

- `ext4_extent_header`
- `ext4_extent`
- `ext4_extent_idx`

Current parser supports header + inline entry decoding.

## 3. btrfs On-Disk Structures Used in Current Port

Legacy btrfs C code references packed structures from `linux/btrfs_tree.h` and in-tree accessors.

Current parser implements:

- superblock (offset 64 KiB, size 4096)
- btree block header
- leaf item metadata

Field naming and layout are aligned with kernel/uapi naming.

## 4. Behavioral Areas Not Yet Ported (Tracked)

1. ext4 journaling replay and fast-commit behavior
2. ext4 allocator and block group mutation semantics
3. btrfs delayed refs and relocation internals
4. btrfs scrub/raid56/advanced repair paths
5. full fsync and transaction replay parity

All missing areas are tracked in `FEATURE_PARITY.md`.
