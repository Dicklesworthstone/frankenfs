# Behavioral Extraction Spec: ext4 and btrfs On-Disk Structures

> Extracted from the Linux kernel v6.19 source tree (`fs/ext4/` and `fs/btrfs/`).
> Source: `git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git` (tag v6.19).
> The original corpus is gitignored locally due to size; this document captures
> all byte offsets, sizes, magic numbers, flag values, and algorithmic behaviors.

---

# Part I: ext4 On-Disk Format and Behavior

The ext4 filesystem is a mature, widely-deployed journaling filesystem
descended from ext2/ext3. Its on-disk format is built around the concept of
**block groups**: the filesystem is divided into fixed-size groups, each
containing a copy (or partial copy) of metadata plus the actual data blocks.
The structures below are defined primarily in `ext4.h`, `ext4_extents.h`,
`mballoc.h`, `xattr.h`, `ext4_jbd2.h`, and the corresponding `.c` files.

---

## 1. Superblock (`struct ext4_super_block`)

**Source:** `ext4.h` lines 1345-1476

The superblock is the master metadata structure of an ext4 filesystem.
It resides at byte offset **1024** from the beginning of the device (always,
regardless of block size). For a 4096-byte block size filesystem, the
superblock occupies bytes 1024-2047 within block 0. The total on-disk size
of `struct ext4_super_block` fills from offset 0x00 to the end of one
block, with reserved padding at the end.

### 1.1 Complete Field Layout

```
Offset  Size  Field                        Description
------  ----  -----                        -----------
0x000   4     s_inodes_count               Total number of inodes in the filesystem
0x004   4     s_blocks_count_lo            Total number of blocks (low 32 bits)
0x008   4     s_r_blocks_count_lo          Reserved blocks for superuser (low 32 bits)
0x00C   4     s_free_blocks_count_lo       Free blocks count (low 32 bits)
0x010   4     s_free_inodes_count          Free inodes count
0x014   4     s_first_data_block           First data block (0 for blocksize > 1024, else 1)
0x018   4     s_log_block_size             Block size shift: actual_size = 1024 << s_log_block_size
0x01C   4     s_log_cluster_size           Cluster size shift (for bigalloc)
0x020   4     s_blocks_per_group           Number of blocks per block group
0x024   4     s_clusters_per_group         Number of clusters per block group
0x028   4     s_inodes_per_group           Number of inodes per block group
0x02C   4     s_mtime                      Last mount time (UNIX epoch, seconds)
0x030   4     s_wtime                      Last write time
0x034   2     s_mnt_count                  Mount count since last fsck
0x036   2     s_max_mnt_count              Max mounts before forced fsck
0x038   2     s_magic                      Magic signature: 0xEF53
0x03A   2     s_state                      Filesystem state (0x0001=clean, 0x0002=errors, 0x0004=orphans)
0x03C   2     s_errors                     Error behavior (1=continue, 2=remount-ro, 3=panic)
0x03E   2     s_minor_rev_level            Minor revision level
0x040   4     s_lastcheck                  Time of last fsck
0x044   4     s_checkinterval              Max interval between checks
0x048   4     s_creator_os                 OS (0=Linux, 1=Hurd, 2=Masix, 3=FreeBSD, 4=Lites)
0x04C   4     s_rev_level                  Revision level (0=GOOD_OLD_REV, 1=DYNAMIC_REV)
0x050   2     s_def_resuid                 Default uid for reserved blocks (low 16 bits)
0x052   2     s_def_resgid                 Default gid for reserved blocks (low 16 bits)

--- EXT4_DYNAMIC_REV fields only (s_rev_level >= 1) ---

0x054   4     s_first_ino                  First non-reserved inode (default 11)
0x058   2     s_inode_size                 Size of inode structure (128, 256, 512, etc.)
0x05A   2     s_block_group_nr             Block group number of this superblock copy
0x05C   4     s_feature_compat             Compatible feature set (bitmask)
0x060   4     s_feature_incompat           Incompatible feature set (bitmask)
0x064   4     s_feature_ro_compat          Read-only compatible feature set (bitmask)
0x068   16    s_uuid[16]                   128-bit UUID for volume
0x078   16    s_volume_name[16]            Volume name (null-terminated, max 16 chars)
0x088   64    s_last_mounted[64]           Directory where last mounted
0x0C8   4     s_algorithm_usage_bitmap     Compression algorithm bitmap
0x0CC   1     s_prealloc_blocks            Blocks to preallocate for regular files
0x0CD   1     s_prealloc_dir_blocks        Blocks to preallocate for directories
0x0CE   2     s_reserved_gdt_blocks        Reserved GDT blocks for online growth
0x0D0   16    s_journal_uuid[16]           UUID of journal superblock
0x0E0   4     s_journal_inum               Inode number of journal file (default 8)
0x0E4   4     s_journal_dev                Device number of external journal
0x0E8   4     s_last_orphan                Start of orphan inode linked list
0x0EC   16    s_hash_seed[4]               Four 32-bit values for htree hash seed
0x0FC   1     s_def_hash_version           Default hash version for directory indexing
0x0FD   1     s_jnl_backup_type            Journal backup type
0x0FE   2     s_desc_size                  Size of group descriptors (32 or 64 bytes)
0x100   4     s_default_mount_opts         Default mount options bitmask
0x104   4     s_first_meta_bg              First metablock block group
0x108   4     s_mkfs_time                  When the filesystem was created
0x10C   68    s_jnl_blocks[17]             Backup copy of journal inode i_block[] + i_size

--- 64-bit support (EXT4_FEATURE_INCOMPAT_64BIT) ---

0x150   4     s_blocks_count_hi            Blocks count (high 32 bits)
0x154   4     s_r_blocks_count_hi          Reserved blocks count (high 32 bits)
0x158   4     s_free_blocks_count_hi       Free blocks count (high 32 bits)
0x15C   2     s_min_extra_isize            All inodes have at least this many extra bytes
0x15E   2     s_want_extra_isize           New inodes should reserve this many extra bytes
0x160   4     s_flags                      Miscellaneous flags
0x164   2     s_raid_stride                RAID stride in blocks
0x166   2     s_mmp_update_interval        MMP check interval (seconds)
0x168   8     s_mmp_block                  Block number for multi-mount protection
0x170   4     s_raid_stripe_width          blocks on all data disks (N * stride)
0x174   1     s_log_groups_per_flex        Flex BG group size (power of 2)
0x175   1     s_checksum_type              Metadata checksum algorithm (1 = crc32c)
0x176   1     s_encryption_level           Encryption versioning level
0x177   1     s_reserved_pad               Padding
0x178   8     s_kbytes_written             Lifetime kilobytes written
0x180   4     s_snapshot_inum              Active snapshot inode number
0x184   4     s_snapshot_id                Active snapshot sequential ID
0x188   8     s_snapshot_r_blocks_count    Reserved blocks for active snapshot
0x190   4     s_snapshot_list              Head of on-disk snapshot list
0x194   4     s_error_count                Number of filesystem errors
0x198   4     s_first_error_time           Time of first error
0x19C   4     s_first_error_ino            Inode involved in first error
0x1A0   8     s_first_error_block          Block involved in first error
0x1A8   32    s_first_error_func[32]       Function name where first error happened
0x1C8   4     s_first_error_line           Line number of first error
0x1CC   4     s_last_error_time            Time of most recent error
0x1D0   4     s_last_error_ino             Inode involved in last error
0x1D4   4     s_last_error_line            Line number of last error
0x1D8   8     s_last_error_block           Block involved in last error
0x1E0   32    s_last_error_func[32]        Function name where last error happened
0x200   64    s_mount_opts[64]             Mount options string
0x240   4     s_usr_quota_inum             Inode for user quota tracking
0x244   4     s_grp_quota_inum             Inode for group quota tracking
0x248   4     s_overhead_clusters          Overhead blocks/clusters in filesystem
0x24C   8     s_backup_bgs[2]              Block groups with sparse_super2 superblocks
0x254   4     s_encrypt_algos[4]           Encryption algorithms in use
0x258   16    s_encrypt_pw_salt[16]        Salt for string2key algorithm
0x268   4     s_lpf_ino                    lost+found inode number
0x26C   4     s_prj_quota_inum             Inode for project quota tracking
0x270   4     s_checksum_seed              crc32c(uuid) if INCOMPAT_CSUM_SEED set
0x274   1     s_wtime_hi                   High bits of write time
0x275   1     s_mtime_hi                   High bits of mount time
0x276   1     s_mkfs_time_hi               High bits of mkfs time
0x277   1     s_lastcheck_hi               High bits of last check time
0x278   1     s_first_error_time_hi        High bits of first error time
0x279   1     s_last_error_time_hi         High bits of last error time
0x27A   1     s_first_error_errcode        Error code of first error
0x27B   1     s_last_error_errcode         Error code of last error
0x27C   2     s_encoding                   Filename charset encoding
0x27E   2     s_encoding_flags             Filename charset encoding flags
0x280   4     s_orphan_file_inum           Inode for orphan file tracking
0x284   2     s_def_resuid_hi              Default uid for reserved blocks (high 16 bits)
0x286   2     s_def_resgid_hi              Default gid for reserved blocks (high 16 bits)
0x288   372   s_reserved[93]               Padding to end of block
0x3FC   4     s_checksum                   crc32c of entire superblock
```

**Total struct size:** 1024 bytes (0x400).

### 1.2 Magic Number

The magic number **0xEF53** is stored at byte offset **0x38** within the
superblock (which is at absolute byte offset 1024 + 0x38 = 0x438 on disk).
This value is stored in little-endian format as bytes `53 EF`.

### 1.3 Block Size Calculation

```c
block_size = 1024 << s_log_block_size;
```

Common values:
- `s_log_block_size = 0` -> 1024 bytes
- `s_log_block_size = 1` -> 2048 bytes
- `s_log_block_size = 2` -> 4096 bytes (most common)
- `s_log_block_size = 4` -> 16384 bytes
- `s_log_block_size = 6` -> 65536 bytes (maximum: `EXT4_MAX_BLOCK_SIZE`)

Minimum block size: `EXT4_MIN_BLOCK_SIZE = 1024`
Maximum block size: `EXT4_MAX_BLOCK_SIZE = 65536`
Minimum block log size: `EXT4_MIN_BLOCK_LOG_SIZE = 10`
Maximum block log size: `EXT4_MAX_BLOCK_LOG_SIZE = 16`

### 1.4 Feature Flags

#### Compatible Features (`s_feature_compat` at offset 0x05C)

The kernel can mount a filesystem even if it does not recognize compatible
features. These are informational or performance-related.

```
Bit     Value    Name                    Description
---     -----    ----                    -----------
0       0x0001   DIR_PREALLOC            Directory preallocation
1       0x0002   IMAGIC_INODES           AFS server inodes exist
2       0x0004   HAS_JOURNAL             Has a journal (ext3/ext4)
3       0x0008   EXT_ATTR                Extended attributes supported
4       0x0010   RESIZE_INODE            Reserved GDT blocks for online growth
5       0x0020   DIR_INDEX               Directory indexing (htree) enabled
9       0x0200   SPARSE_SUPER2           Sparse superblock v2
10      0x0400   FAST_COMMIT             Fast commit journal feature
11      0x0800   STABLE_INODES           Stable inode numbers (for encryption)
12      0x1000   ORPHAN_FILE             Orphan file exists
```

#### Incompatible Features (`s_feature_incompat` at offset 0x060)

The kernel **must** refuse to mount if it does not recognize any set
incompatible feature bits.

```
Bit     Value    Name                    Description
---     -----    ----                    -----------
0       0x0001   COMPRESSION             Filesystem uses compression
1       0x0002   FILETYPE                Directory entries have file type byte
2       0x0004   RECOVER                 Filesystem needs recovery (journal replay)
3       0x0008   JOURNAL_DEV             Filesystem has separate journal device
4       0x0010   META_BG                 Meta block groups
6       0x0040   EXTENTS                 Extents support (critical for ext4)
7       0x0080   64BIT                   64-bit block numbers (>= 16TB support)
8       0x0100   MMP                     Multi-mount protection
9       0x0200   FLEX_BG                 Flexible block groups
10      0x0400   EA_INODE                Extended attributes in dedicated inodes
12      0x1000   DIRDATA                 Data in directory entries
13      0x2000   CSUM_SEED               Checksum seed in superblock
14      0x4000   LARGEDIR                Directories > 2GB or 3-level htree
15      0x8000   INLINE_DATA             Data stored directly in inode
16      0x10000  ENCRYPT                 Encryption support
17      0x20000  CASEFOLD                Case-insensitive directory lookups
```

#### Read-Only Compatible Features (`s_feature_ro_compat` at offset 0x064)

The kernel can mount read-only if it does not recognize these features, but
must not mount read-write.

```
Bit     Value    Name                    Description
---     -----    ----                    -----------
0       0x0001   SPARSE_SUPER            Sparse superblock (copies only in certain groups)
1       0x0002   LARGE_FILE              Files > 2GB exist
2       0x0004   BTREE_DIR               Not used in ext4 (ext3 compat)
3       0x0008   HUGE_FILE               File sizes in units of fs blocks
4       0x0010   GDT_CSUM                Group descriptors have checksums
5       0x0020   DIR_NLINK               Directory link count > 65000
6       0x0040   EXTRA_ISIZE             Large inodes (> 128 bytes)
8       0x0100   QUOTA                   Quota support
9       0x0200   BIGALLOC                Cluster-based allocation
10      0x0400   METADATA_CSUM           Metadata checksumming (crc32c)
12      0x1000   READONLY                Filesystem is read-only (image)
13      0x2000   PROJECT                 Project quotas
15      0x8000   VERITY                  Verity (fs-verity) protected files exist
16      0x10000  ORPHAN_PRESENT          Orphan file may have valid entries
```

### 1.5 Superblock Copies and Backup Locations

The primary superblock is always at offset 1024 (byte). Backup copies exist
in block groups whose group numbers are 0, 1, and powers of 3, 5, and 7
(when the `SPARSE_SUPER` feature is enabled -- almost always). With
`SPARSE_SUPER2`, only the groups specified in `s_backup_bgs[2]` contain
superblock copies.

### 1.6 Filesystem State Tracking

The `s_state` field tracks whether the filesystem was cleanly unmounted:
- `0x0001` (EXT4_VALID_FS): Clean
- `0x0002` (EXT4_ERROR_FS): Errors detected
- `0x0004` (EXT4_ORPHAN_FS): Orphan inodes being recovered

### 1.7 Special Inode Numbers

```c
#define EXT4_BAD_INO             1   /* Bad blocks inode */
#define EXT4_ROOT_INO            2   /* Root directory inode */
#define EXT4_USR_QUOTA_INO       3   /* User quota inode */
#define EXT4_GRP_QUOTA_INO       4   /* Group quota inode */
#define EXT4_BOOT_LOADER_INO     5   /* Boot loader inode */
#define EXT4_UNDEL_DIR_INO       6   /* Undelete directory inode */
#define EXT4_RESIZE_INO          7   /* Reserved group descriptors inode */
#define EXT4_JOURNAL_INO         8   /* Journal inode */
#define EXT4_GOOD_OLD_FIRST_INO  11  /* First non-reserved inode */
```

---

## 2. Block Groups (`struct ext4_group_desc`)

**Source:** `ext4.h` lines 403-428

The filesystem is divided into block groups, each containing
`s_blocks_per_group` blocks (typically 32768 blocks for 4K blocksize =
128MB per group). Block groups allow locality of reference and limit
bitmap scanning.

### 2.1 Group Descriptor Layout

Each block group is described by a group descriptor. Descriptors for all
groups are stored sequentially in the blocks immediately following the
superblock (and its copies in backup groups).

The descriptor size is either **32 bytes** (traditional) or **64 bytes**
(when `EXT4_FEATURE_INCOMPAT_64BIT` is set and `s_desc_size >= 64`).

```
Offset  Size  Field                        Description
------  ----  -----                        -----------
0x00    4     bg_block_bitmap_lo           Block bitmap block number (low 32 bits)
0x04    4     bg_inode_bitmap_lo           Inode bitmap block number (low 32 bits)
0x08    4     bg_inode_table_lo            Inode table start block (low 32 bits)
0x0C    2     bg_free_blocks_count_lo      Free blocks count (low 16 bits)
0x0E    2     bg_free_inodes_count_lo      Free inodes count (low 16 bits)
0x10    2     bg_used_dirs_count_lo        Directory count (low 16 bits)
0x12    2     bg_flags                     Block group flags (see below)
0x14    4     bg_exclude_bitmap_lo         Exclude bitmap for snapshots (low 32 bits)
0x18    2     bg_block_bitmap_csum_lo      crc32c(s_uuid+grp_num+block_bitmap) low 16 bits
0x1A    2     bg_inode_bitmap_csum_lo      crc32c(s_uuid+grp_num+inode_bitmap) low 16 bits
0x1C    2     bg_itable_unused_lo          Unused inodes count (low 16 bits)
0x1E    2     bg_checksum                  crc16(sb_uuid+group+desc) or crc32c

--- 64-byte descriptor (s_desc_size >= 64, INCOMPAT_64BIT) ---

0x20    4     bg_block_bitmap_hi           Block bitmap block number (high 32 bits)
0x24    4     bg_inode_bitmap_hi           Inode bitmap block number (high 32 bits)
0x28    4     bg_inode_table_hi            Inode table start block (high 32 bits)
0x2C    2     bg_free_blocks_count_hi      Free blocks count (high 16 bits)
0x2E    2     bg_free_inodes_count_hi      Free inodes count (high 16 bits)
0x30    2     bg_used_dirs_count_hi        Directory count (high 16 bits)
0x32    2     bg_itable_unused_hi          Unused inodes count (high 16 bits)
0x34    4     bg_exclude_bitmap_hi         Exclude bitmap (high 32 bits)
0x38    2     bg_block_bitmap_csum_hi      Block bitmap checksum (high 16 bits)
0x3A    2     bg_inode_bitmap_csum_hi      Inode bitmap checksum (high 16 bits)
0x3C    4     bg_reserved                  Padding
```

**32-byte descriptor size:** `EXT4_MIN_DESC_SIZE = 32`
**64-byte descriptor size:** `EXT4_MIN_DESC_SIZE_64BIT = 64`
**Maximum descriptor size:** `EXT4_MAX_DESC_SIZE = EXT4_MIN_BLOCK_SIZE = 1024`

### 2.2 Block Group Flags

```
Value   Name                Description
-----   ----                -----------
0x0001  EXT4_BG_INODE_UNINIT   Inode table and bitmap not initialized
0x0002  EXT4_BG_BLOCK_UNINIT   Block bitmap not initialized
0x0004  EXT4_BG_INODE_ZEROED   On-disk inode table initialized to zero
```

The `INODE_UNINIT` and `BLOCK_UNINIT` flags are used for lazy initialization.
When a group with `INODE_UNINIT` is first needed, the kernel initializes the
inode bitmap and inode table. This avoids the long mkfs time for large
filesystems. The `INODE_ZEROED` flag indicates the inode table blocks have
been filled with zeroes on disk.

### 2.3 Block and Inode Bitmaps

Each block group has two bitmaps:

- **Block bitmap**: One bit per block (or cluster in bigalloc mode) in the
  group. A set bit means the block is allocated. Located at
  `bg_block_bitmap_lo|hi`.

- **Inode bitmap**: One bit per inode slot in the group. A set bit means
  the inode is allocated. Located at `bg_inode_bitmap_lo|hi`.

For a standard 4096-byte block size with 32768 blocks per group, the block
bitmap is exactly one block (4096 bytes = 32768 bits = 32768 blocks tracked).

### 2.4 Inode Table

The inode table is a contiguous array of on-disk `ext4_inode` structures.
It starts at block `bg_inode_table_lo|hi` and spans
`ceil(s_inodes_per_group * s_inode_size / block_size)` blocks.

For a filesystem with 256-byte inodes, 8192 inodes per group, and 4K
blocks, the inode table is `8192 * 256 / 4096 = 512` blocks per group.

### 2.5 Flex Block Groups

When `EXT4_FEATURE_INCOMPAT_FLEX_BG` is set, multiple adjacent block groups
are treated as a single "flex group." The metadata (bitmaps and inode
tables) for all groups in a flex group are packed into the first group of
the flex group. The flex group size is `2^s_log_groups_per_flex`.

The `flex_groups` in-memory structure tracks aggregated stats:

```c
struct flex_groups {
    atomic64_t  free_clusters;
    atomic_t    free_inodes;
    atomic_t    used_dirs;
};
```

This allows fast decisions about which flex group has the most free space.
Typical flex group sizes are 16 (default in most distro mkfs configs).

### 2.6 Descriptors Per Block

```c
EXT4_DESC_PER_BLOCK(s) = EXT4_BLOCK_SIZE(s) / EXT4_DESC_SIZE(s)
```

For 4K blocks with 64-byte descriptors: 4096/64 = 64 descriptors per block.
For 4K blocks with 32-byte descriptors: 4096/32 = 128 descriptors per block.

---

## 3. Inodes (`struct ext4_inode`)

**Source:** `ext4.h` lines 804-863

The inode is the fundamental metadata structure describing a file, directory,
symlink, device node, or other filesystem object.

For unencrypted ext4 symlinks, Linux v6.19 passes the filesystem block size to
`fscrypt_prepare_symlink`, which includes the trailing NUL in its size check.
Creation therefore rejects a target length greater than or equal to the block
size with `ENAMETOOLONG`, before allocating an inode. Up to 59 target bytes fit
in the 60-byte `i_block` area; 60 bytes require a data block. `i_size` excludes
the NUL. Inode allocation, target initialization and directory publication belong
to the same namespace operation; a rejected creation must not leak allocations.
Sources: [ext4 namei.c](https://raw.githubusercontent.com/torvalds/linux/v6.19/fs/ext4/namei.c)
(`ext4_symlink`, `ext4_init_symlink_block`) and
[fscrypt.h](https://raw.githubusercontent.com/torvalds/linux/v6.19/include/linux/fscrypt.h)
(`fscrypt_prepare_symlink`, non-encrypted implementation).

### 3.1 Standard Inode Fields (First 128 Bytes)

The first 128 bytes (`EXT4_GOOD_OLD_INODE_SIZE = 128`) constitute the
"classic" inode layout compatible with ext2/ext3:

```
Offset  Size  Field                   Description
------  ----  -----                   -----------
0x00    2     i_mode                  File mode (type + permissions, same as POSIX)
0x02    2     i_uid                   Owner UID (low 16 bits)
0x04    4     i_size_lo               File size in bytes (low 32 bits)
0x08    4     i_atime                 Access time (UNIX epoch, seconds, low 32 bits)
0x0C    4     i_ctime                 Inode change time (low 32 bits)
0x10    4     i_mtime                 Modification time (low 32 bits)
0x14    4     i_dtime                 Deletion time
0x18    2     i_gid                   Group ID (low 16 bits)
0x1A    2     i_links_count           Hard link count
0x1C    4     i_blocks_lo             Block count (512-byte units, or fs blocks if HUGE_FILE)
0x20    4     i_flags                 Inode flags (see 3.3)
0x24    4     osd1.linux1.l_i_version Inode version (for NFS)
0x28    60    i_block[EXT4_N_BLOCKS]  Block map / extent tree root (15 x 4 bytes = 60 bytes)
0x64    4     i_generation            File version (NFS generation number)
0x68    4     i_file_acl_lo           Extended attribute block (low 32 bits)
0x6C    4     i_size_high             File size (high 32 bits, for files > 4GB)
0x70    4     i_obso_faddr            Obsoleted fragment address
0x74    2     l_i_blocks_high         Blocks count (high 16 bits) (Linux)
0x76    2     l_i_file_acl_high       Extended attribute block (high 16 bits) (Linux)
0x78    2     l_i_uid_high            Owner UID (high 16 bits) (Linux)
0x7A    2     l_i_gid_high            Group ID (high 16 bits) (Linux)
0x7C    2     l_i_checksum_lo         crc32c(uuid+inum+inode) (low 16 bits)
0x7E    2     l_i_reserved            Reserved
```

**Constants:**
```c
#define EXT4_NDIR_BLOCKS    12     /* Direct block pointers */
#define EXT4_IND_BLOCK      12     /* Indirect block pointer */
#define EXT4_DIND_BLOCK     13     /* Double indirect block pointer */
#define EXT4_TIND_BLOCK     14     /* Triple indirect block pointer */
#define EXT4_N_BLOCKS       15     /* Total block pointer slots */
```

The `i_block[]` array is 60 bytes (15 x 4 bytes). For extent-based files
(which is the default for ext4), this space is reused as the root of the
extent tree rather than holding block pointers.

### 3.2 Extended Inode Fields (Bytes 128+)

When `s_inode_size > 128` (commonly 256 bytes), additional fields are
available. The extended area starts at offset 0x80 and its usable size is
indicated by `i_extra_isize`.

```
Offset  Size  Field                   Description
------  ----  -----                   -----------
0x80    2     i_extra_isize           Size of extra inode fields (bytes after offset 0x80)
0x82    2     i_checksum_hi           crc32c(uuid+inum+inode) (high 16 bits)
0x84    4     i_ctime_extra           Extra change time (nanoseconds << 2 | epoch bits)
0x88    4     i_mtime_extra           Extra modification time (nanoseconds << 2 | epoch bits)
0x8C    4     i_atime_extra           Extra access time (nanoseconds << 2 | epoch bits)
0x90    4     i_crtime                File creation time (seconds, low 32 bits)
0x94    4     i_crtime_extra          Extra creation time (nanoseconds << 2 | epoch bits)
0x98    4     i_version_hi            High 32 bits for 64-bit inode version
0x9C    4     i_projid                Project ID
```

#### Timestamp Extended Encoding

The `*_extra` timestamp fields encode both nanosecond precision and extended
epoch bits to extend the timestamp range beyond 2038:

```c
#define EXT4_EPOCH_BITS  2
#define EXT4_EPOCH_MASK  ((1 << EXT4_EPOCH_BITS) - 1)  /* = 0x3 */
#define EXT4_NSEC_MASK   (~0UL << EXT4_EPOCH_BITS)

/* extra field layout: [31..2] = nanoseconds, [1..0] = epoch bits */
```

The epoch bits extend the 32-bit signed seconds field to 34 bits unsigned,
covering dates from 1901-12-13 through 2446-05-10.

#### The `EXT4_FITS_IN_INODE` Check

```c
#define EXT4_FITS_IN_INODE(ext4_inode, einode, field) \
    ((offsetof(typeof(*ext4_inode), field) + sizeof((ext4_inode)->field)) \
    <= (EXT4_GOOD_OLD_INODE_SIZE + (einode)->i_extra_isize))
```

This macro checks whether a given extended field is available in the
current inode. The kernel uses this before accessing any extended field.

### 3.3 Inode Flags (`i_flags`)

```
Value       Name                    Description
-----       ----                    -----------
0x00000001  EXT4_SECRM_FL           Secure deletion (not implemented)
0x00000002  EXT4_UNRM_FL            Undelete (not implemented)
0x00000004  EXT4_COMPR_FL           Compressed file (not implemented)
0x00000008  EXT4_SYNC_FL            Synchronous updates
0x00000010  EXT4_IMMUTABLE_FL       Immutable file
0x00000020  EXT4_APPEND_FL          Append only
0x00000040  EXT4_NODUMP_FL          Do not dump (backup) file
0x00000080  EXT4_NOATIME_FL         Do not update access time
0x00000100  EXT4_DIRTY_FL           Dirty (compression)
0x00000200  EXT4_COMPRBLK_FL        Compressed clusters
0x00000400  EXT4_NOCOMPR_FL         Access raw compressed data
0x00000800  EXT4_ENCRYPT_FL         Encrypted inode
0x00001000  EXT4_INDEX_FL           Hash-indexed directory
0x00002000  EXT4_IMAGIC_FL          AFS directory
0x00004000  EXT4_JOURNAL_DATA_FL    File data journaled
0x00008000  EXT4_NOTAIL_FL          Do not merge tail
0x00010000  EXT4_DIRSYNC_FL         Directory operations are synchronous
0x00020000  EXT4_TOPDIR_FL          Top of directory hierarchy
0x00040000  EXT4_HUGE_FILE_FL       File uses fs-block units for i_blocks
0x00080000  EXT4_EXTENTS_FL         Inode uses extent tree (critical)
0x00100000  EXT4_VERITY_FL          Verity protected inode
0x00200000  EXT4_EA_INODE_FL        Inode used for large extended attributes
0x02000000  EXT4_DAX_FL             DAX (direct access, bypass page cache)
0x10000000  EXT4_INLINE_DATA_FL     Data stored inline in inode body
0x20000000  EXT4_PROJINHERIT_FL     Children inherit project ID
0x40000000  EXT4_CASEFOLD_FL        Case-insensitive directory
0x80000000  EXT4_RESERVED_FL        Reserved for ext4 library
```

**Key flag for FrankenFS:** `EXT4_EXTENTS_FL = 0x00080000` indicates the
inode uses the extent tree format (Section 4) rather than the legacy
indirect block mapping.

### 3.4 File Size Computation

Total file size in bytes:

```c
i_size = ((__u64)i_size_high << 32) | i_size_lo;
```

### 3.5 Block Count Computation

When `EXT4_HUGE_FILE_FL` is NOT set:
```c
i_blocks = ((__u64)l_i_blocks_high << 32) | i_blocks_lo;
/* i_blocks is in 512-byte units */
```

When `EXT4_HUGE_FILE_FL` IS set:
```c
i_blocks = ((__u64)l_i_blocks_high << 32) | i_blocks_lo;
/* i_blocks is in filesystem block units */
```

### 3.6 UID/GID 32-bit Computation

```c
uid = ((__u32)l_i_uid_high << 16) | i_uid;
gid = ((__u32)l_i_gid_high << 16) | i_gid;
```

### 3.7 Inline Data

When `EXT4_INLINE_DATA_FL` is set, small file data is stored directly in
the inode body, using the `i_block[]` area (60 bytes) and potentially the
extended attribute space. This eliminates the need for separate data blocks
for very small files (up to roughly 60 bytes in `i_block[]` plus more in
the xattr area).

---

## 4. Extent Tree

**Source:** `ext4_extents.h` lines 1-267

ext4 uses an extent tree to map logical file blocks to physical disk blocks.
This is far more efficient than indirect block mapping for large and
contiguous files. The extent tree is rooted in the inode's `i_block[]` array.

### 4.1 Extent Header (`struct ext4_extent_header`)

Every extent tree node (including the root in the inode) begins with a
12-byte header:

```
Offset  Size  Field          Description
------  ----  -----          -----------
0x00    2     eh_magic       Magic number: 0xF30A
0x02    2     eh_entries     Number of valid entries following this header
0x04    2     eh_max         Maximum entries that can be stored
0x06    2     eh_depth       Tree depth below this node (0 = leaf level)
0x08    4     eh_generation  Generation of the tree (for preallocation)
```

**Total header size:** 12 bytes.

**Magic number:** `EXT4_EXT_MAGIC = 0xF30A` (stored little-endian as `0A F3`).

**Maximum tree depth:** `EXT4_MAX_EXTENT_DEPTH = 5`

### 4.2 Extent Entry (`struct ext4_extent`) -- Leaf Level

At depth 0 (leaf nodes), the header is followed by extent entries:

```
Offset  Size  Field          Description
------  ----  -----          -----------
0x00    4     ee_block       First logical block this extent covers
0x04    2     ee_len         Number of blocks covered (see unwritten flag below)
0x06    2     ee_start_hi    Physical block number (high 16 bits)
0x08    4     ee_start_lo    Physical block number (low 32 bits)
```

**Total entry size:** 12 bytes.

**Physical block computation:**
```c
static inline ext4_fsblk_t ext4_ext_pblock(struct ext4_extent *ex)
{
    ext4_fsblk_t block;
    block = le32_to_cpu(ex->ee_start_lo);
    block |= ((ext4_fsblk_t) le16_to_cpu(ex->ee_start_hi) << 31) << 1;
    return block;
}
```

This yields a 48-bit physical block address.

### 4.3 Unwritten (Preallocated) Extents

The `ee_len` field uses its MSB (bit 15) as an "unwritten" flag:

- If `ee_len <= 0x8000` (32768): the extent is **initialized** and
  `ee_len` is the actual block count. Maximum initialized length is
  `EXT_INIT_MAX_LEN = 2^15 = 32768` blocks.

- If `ee_len > 0x8000`: the extent is **unwritten** (preallocated, reads
  return zeroes). The actual length is `ee_len - 0x8000`. Maximum
  unwritten length is `EXT_UNWRITTEN_MAX_LEN = 32767` blocks.

- Special case: `ee_len == 0x8000` is treated as an initialized extent of
  length 32768. An unwritten extent of length 0 would be nonsensical.

```c
#define EXT_INIT_MAX_LEN       (1UL << 15)        /* 32768 */
#define EXT_UNWRITTEN_MAX_LEN  (EXT_INIT_MAX_LEN - 1)  /* 32767 */

static inline int ext4_ext_is_unwritten(struct ext4_extent *ext)
{
    return (le16_to_cpu(ext->ee_len) > EXT_INIT_MAX_LEN);
}

static inline int ext4_ext_get_actual_len(struct ext4_extent *ext)
{
    return (le16_to_cpu(ext->ee_len) <= EXT_INIT_MAX_LEN ?
            le16_to_cpu(ext->ee_len) :
            (le16_to_cpu(ext->ee_len) - EXT_INIT_MAX_LEN));
}
```

### 4.4 Index Entry (`struct ext4_extent_idx`) -- Internal Levels

At depth > 0 (internal nodes), the header is followed by index entries:

```
Offset  Size  Field          Description
------  ----  -----          -----------
0x00    4     ei_block       Logical block number this index covers from
0x04    4     ei_leaf_lo     Physical block of next-level node (low 32 bits)
0x08    2     ei_leaf_hi     Physical block of next-level node (high 16 bits)
0x0A    2     ei_unused      Reserved/unused
```

**Total entry size:** 12 bytes (same as ext4_extent).

**Physical block of child node:**
```c
static inline ext4_fsblk_t ext4_idx_pblock(struct ext4_extent_idx *ix)
{
    ext4_fsblk_t block;
    block = le32_to_cpu(ix->ei_leaf_lo);
    block |= ((ext4_fsblk_t) le16_to_cpu(ix->ei_leaf_hi) << 31) << 1;
    return block;
}
```

### 4.5 Extent Tail (`struct ext4_extent_tail`)

For non-inode extent blocks (i.e., extent tree blocks allocated on disk,
not the root stored in the inode), a checksum tail is appended after the
maximum number of entries:

```
Offset  Size  Field          Description
------  ----  -----          -----------
0x00    4     et_checksum    crc32c(uuid + inum + extent_block)
```

The tail is located at:
```c
#define EXT4_EXTENT_TAIL_OFFSET(hdr) \
    (sizeof(struct ext4_extent_header) + \
     (sizeof(struct ext4_extent) * le16_to_cpu((hdr)->eh_max)))
```

Since `sizeof(ext4_extent_header) = 12`, `sizeof(ext4_extent) = 12`, and
`block_size % 12 >= 4` for all valid block sizes, the 4-byte tail always
fits.

### 4.6 Tree Structure

**Root node:** The extent tree root resides in the inode's `i_block[0..14]`
field, which is 60 bytes. Subtracting the 12-byte header leaves room for
`(60 - 12) / 12 = 4` extent entries (or index entries) in the root.

**Depth interpretation:**
- `eh_depth == 0`: This node contains `ext4_extent` leaf entries. The
  logical-to-physical block mapping is directly available.
- `eh_depth > 0`: This node contains `ext4_extent_idx` entries pointing
  to child nodes at depth `eh_depth - 1`.

**Maximum entries per non-root node:**
```
max_entries = (block_size - sizeof(ext4_extent_header) - sizeof(ext4_extent_tail))
              / sizeof(ext4_extent)
```
For 4096-byte blocks: `(4096 - 12 - 4) / 12 = 340` entries per block.

**Capacity for a 2-level tree (depth=1) with 4K blocks:**
- Root: 4 index entries
- Each index points to a leaf block with 340 extents
- Each extent covers up to 32768 blocks = 128MB
- Total: `4 * 340 * 32768 * 4096 bytes = ~167 TB`

### 4.7 Path Traversal

The kernel uses `struct ext4_ext_path` to record the traversal path:

```c
struct ext4_ext_path {
    ext4_fsblk_t            p_block;     /* physical block of this node */
    __u16                   p_depth;     /* depth of this node */
    __u16                   p_maxdepth;  /* max depth of the tree */
    struct ext4_extent      *p_ext;      /* pointer to current extent */
    struct ext4_extent_idx  *p_idx;      /* pointer to current index */
    struct ext4_extent_header *p_hdr;    /* pointer to node header */
    struct buffer_head      *p_bh;       /* buffer head for this node */
};
```

Binary search is used within each node to find the correct entry for a
given logical block number.

### 4.8 Extent Tree Navigation Macros

```c
#define EXT_FIRST_EXTENT(__hdr__) \
    ((struct ext4_extent *)(((char *)(__hdr__)) + sizeof(struct ext4_extent_header)))

#define EXT_FIRST_INDEX(__hdr__) \
    ((struct ext4_extent_idx *)(((char *)(__hdr__)) + sizeof(struct ext4_extent_header)))

#define EXT_LAST_EXTENT(__hdr__) \
    (EXT_FIRST_EXTENT((__hdr__)) + le16_to_cpu((__hdr__)->eh_entries) - 1)

#define EXT_LAST_INDEX(__hdr__) \
    (EXT_FIRST_INDEX((__hdr__)) + le16_to_cpu((__hdr__)->eh_entries) - 1)
```

---

## 5. Directory Format

**Source:** `ext4.h` lines 2392-2472, `namei.c` lines 235-291

ext4 supports two directory formats: linear (small directories) and hash
tree / htree (large directories). All directories start as linear and may
be converted to htree when they grow.

### 5.1 Linear Directory Entries (`struct ext4_dir_entry_2`)

The "version 2" directory entry is the standard format:

```
Offset  Size  Field       Description
------  ----  -----       -----------
0x00    4     inode       Inode number of the referenced file
0x04    2     rec_len     Total size of this directory entry (including padding)
0x06    1     name_len    Length of the file name
0x07    1     file_type   File type code (see below)
0x08    var   name[]      File name (up to 255 bytes, NOT null-terminated)
```

**Minimum entry size:** 8 bytes (header) + 1 byte (name) = 9, rounded up
to a multiple of 4 = 12 bytes.

**Maximum entry size:** 8 + 255 = 263, rounded up to 264 bytes.

**`rec_len` behavior:** The `rec_len` field specifies the distance from the
start of this entry to the start of the next entry. The last entry in a
block has its `rec_len` extended to reach the end of the block. This allows
the entry list to function as a linked list within each block.

For block sizes > 65535, `rec_len` uses a special encoding:
```c
static inline unsigned int
ext4_rec_len_from_disk(__le16 dlen, unsigned blocksize)
{
    unsigned len = le16_to_cpu(dlen);
    if (len == EXT4_MAX_REC_LEN || len == 0)
        return blocksize;
    return (len & 65532) | ((len & 3) << 16);
}
```

### 5.2 File Type Codes

```c
#define EXT4_FT_UNKNOWN    0
#define EXT4_FT_REG_FILE   1   /* Regular file */
#define EXT4_FT_DIR        2   /* Directory */
#define EXT4_FT_CHRDEV     3   /* Character device */
#define EXT4_FT_BLKDEV     4   /* Block device */
#define EXT4_FT_FIFO       5   /* FIFO (named pipe) */
#define EXT4_FT_SOCK       6   /* Socket */
#define EXT4_FT_SYMLINK    7   /* Symbolic link */
#define EXT4_FT_MAX        8
#define EXT4_FT_DIR_CSUM   0xDE  /* Fake type for checksum entry */
```

### 5.3 Directory Entry Tail (Checksum)

When metadata checksumming is enabled, each directory leaf block ends with
a checksum entry:

```c
struct ext4_dir_entry_tail {
    __le32  det_reserved_zero1;  /* Pretend to be unused (inode = 0) */
    __le16  det_rec_len;         /* Always 12 */
    __u8    det_reserved_zero2;  /* Zero name length */
    __u8    det_reserved_ft;     /* 0xDE (fake file type) */
    __le32  det_checksum;        /* crc32c(uuid+inum+dirblock) */
};
```

Located at `block_end - sizeof(struct ext4_dir_entry_tail)` = last 12 bytes
of the directory block.

### 5.4 Hash Tree (htree) Directory Format

For directories with many entries, ext4 uses a hash tree (htree) structure.
The first block of the directory contains a special root structure.

#### dx_root Structure

```c
struct dx_root {
    struct fake_dirent dot;        /* "." entry: inode(4) + rec_len(2) + name_len(1) + type(1) */
    char dot_name[4];              /* ".\0\0\0" */
    struct fake_dirent dotdot;     /* ".." entry */
    char dotdot_name[4];           /* "..\0\0" */
    struct dx_root_info {
        __le32 reserved_zero;      /* Must be zero */
        u8 hash_version;           /* Hash algorithm version */
        u8 info_length;            /* Always 8 (sizeof dx_root_info) */
        u8 indirect_levels;        /* Tree depth (0 = single level of dx_nodes) */
        u8 unused_flags;           /* Reserved */
    } info;
    struct dx_entry entries[];     /* Variable-length array of hash entries */
};
```

The root block layout is thus:
- Bytes 0-11: "." directory entry (12 bytes)
- Bytes 12-23: ".." directory entry (12 bytes)
- Bytes 24-31: `dx_root_info` (8 bytes)
- Bytes 32+: Array of `dx_entry` structures

#### dx_entry Structure

```c
struct dx_entry {
    __le32 hash;    /* Hash value */
    __le32 block;   /* Block number within the directory file */
};
```

Each `dx_entry` is 8 bytes. The first entry in the root is special: its
`hash` field is unused (set to 0), and its `block` field contains the
**count** of entries (in the low 16 bits) and the **limit** (maximum
entries, in the high 16 bits). This is the `dx_countlimit` structure.

#### dx_node Structure (Internal Hash Tree Nodes)

```c
struct dx_node {
    struct fake_dirent fake;    /* fake directory entry header (8 bytes) */
    struct dx_entry entries[];  /* Hash entries */
};
```

#### dx_tail Structure (Checksum)

```c
struct dx_tail {
    u32 dt_reserved;
    __le32 dt_checksum;  /* crc32c(uuid+inum+dirblock) */
};
```

### 5.5 Hash Algorithms

The `hash_version` field in `dx_root_info` selects the hash function:

```c
#define DX_HASH_LEGACY              0  /* Original hash (broken for some locales) */
#define DX_HASH_HALF_MD4            1  /* Half-MD4 hash */
#define DX_HASH_TEA                 2  /* TEA (Tiny Encryption Algorithm) hash */
#define DX_HASH_LEGACY_UNSIGNED     3  /* Legacy with unsigned char comparison */
#define DX_HASH_HALF_MD4_UNSIGNED   4  /* Half-MD4 with unsigned char */
#define DX_HASH_TEA_UNSIGNED        5  /* TEA with unsigned char */
#define DX_HASH_SIPHASH             6  /* SipHash (for casefolded+encrypted dirs) */
```

The "unsigned" variants were introduced to fix locale-dependent sorting
issues with the original algorithms.

**Half-MD4 hash** (`hash.c`): Uses a cut-down MD4 transform that processes
the filename in 32-byte chunks through 3 rounds of 8 operations each.
Returns only the lower 32 bits.

**TEA hash** (`hash.c`): Uses the Tiny Encryption Algorithm with 16
Feistel rounds per block. The TEA constant `DELTA = 0x9E3779B9`.

**SipHash**: Used for case-insensitive encrypted directories. Provides
better collision resistance.

The hash seed is stored in `s_hash_seed[4]` in the superblock (4 x 32-bit
values = 128 bits).

### 5.6 Htree Lookup Algorithm

1. Read block 0 of the directory; verify `dx_root_info`.
2. Hash the target filename using the configured hash function and seed.
3. Binary search the `dx_entry` array in the root for the hash range
   containing our hash.
4. If `indirect_levels > 0`, follow the block pointer to a `dx_node` and
   repeat the binary search.
5. Read the target leaf block (a regular directory block with linear entries)
   and scan linearly for the exact name match.

---

## 6. Block Allocation (mballoc)

**Source:** `mballoc.h`, `mballoc.c`, `ext4.h` lines 130-230

ext4 uses a multi-block allocator (mballoc) that attempts to allocate
contiguous runs of blocks. The allocator uses a tiered strategy with
multiple "criteria" levels, falling back to less optimal strategies.

### 6.1 Allocation Criteria

The allocation criteria enum (`ext4.h` lines 137-177) defines the strategy
tiers:

```c
enum criteria {
    CR_POWER2_ALIGNED,   /* Power-of-2 aligned, fastest, no disk IO */
    CR_GOAL_LEN_FAST,    /* In-memory lookup for best group */
    CR_BEST_AVAIL_LEN,   /* May reduce goal length for faster alloc */
    CR_GOAL_LEN_SLOW,    /* Sequential group scan, may do disk IO */
    CR_ANY_FREE,          /* First free blocks found (last resort) */
    EXT4_MB_NUM_CRS       /* Count of criteria */
};
```

**CR_POWER2_ALIGNED:** Used when the request length is a power of 2. Uses
buddy bitmaps to find an appropriately aligned free chunk with no disk I/O
(except block prefetch). This is the fastest path.

**CR_GOAL_LEN_FAST:** Looks up in-memory data structures to find the best
group matching the goal request. No disk I/O beyond block prefetch.

**CR_BEST_AVAIL_LEN:** Same as CR_GOAL_LEN_FAST but is allowed to reduce
the goal length to the best available length for faster allocation. The
maximum trim amount is controlled by `MB_DEFAULT_BEST_AVAIL_TRIM_ORDER = 3`
(can trim at most 3 orders from the request).

**CR_GOAL_LEN_SLOW:** Reads each block group sequentially (may trigger
disk I/O to read block bitmaps) to find a suitable group. Tries to
allocate the goal length but may trim the request if nothing is found.

**CR_ANY_FREE:** Finds the first set of free blocks and allocates those.
Used only when all other criteria fail.

### 6.2 Allocation Hints (Flags)

```c
#define EXT4_MB_HINT_MERGE          0x0001  /* Prefer goal, merge with adjacent */
#define EXT4_MB_HINT_FIRST          0x0008  /* First blocks in file */
#define EXT4_MB_HINT_DATA           0x0020  /* Data blocks being allocated */
#define EXT4_MB_HINT_NOPREALLOC     0x0040  /* Don't preallocate (for tails) */
#define EXT4_MB_HINT_GROUP_ALLOC    0x0080  /* Locality group allocation */
#define EXT4_MB_HINT_GOAL_ONLY      0x0100  /* Goal blocks or nothing */
#define EXT4_MB_HINT_TRY_GOAL       0x0200  /* Goal is meaningful */
#define EXT4_MB_DELALLOC_RESERVED   0x0400  /* Delayed allocation reserved */
#define EXT4_MB_STREAM_ALLOC        0x0800  /* Stream allocation mode */
#define EXT4_MB_USE_ROOT_BLOCKS     0x1000  /* May use reserved root blocks */
#define EXT4_MB_USE_RESERVED        0x2000  /* May use reserved pool */
#define EXT4_MB_STRICT_CHECK        0x4000  /* Strict free block check on retry */
```

### 6.3 Allocation Request Structure

```c
struct ext4_allocation_request {
    struct inode *inode;       /* Target inode */
    unsigned int len;          /* Number of blocks requested */
    ext4_lblk_t logical;       /* Logical block number in target inode */
    ext4_lblk_t lleft;         /* Closest allocated logical block to the left */
    ext4_lblk_t lright;        /* Closest allocated logical block to the right */
    ext4_fsblk_t goal;         /* Physical block goal (hint) */
    ext4_fsblk_t pleft;        /* Physical block of closest left neighbor */
    ext4_fsblk_t pright;       /* Physical block of closest right neighbor */
    unsigned int flags;        /* Hint flags (EXT4_MB_HINT_*) */
};
```

### 6.4 Buddy Bitmap System

The mballoc allocator maintains **buddy bitmaps** for each block group.
These are dual bitmaps:

1. **Block bitmap**: Standard per-group bitmap (one bit per block/cluster).
2. **Buddy bitmap**: Hierarchical free-space tracking at multiple orders.

The buddy bitmap for order N tracks free chunks of size 2^N blocks. The
number of valid buddy orders is:

```c
#define MB_NUM_ORDERS(sb)  ((sb)->s_blocksize_bits + 2)
```

For 4K blocks: `12 + 2 = 14` orders (tracking free chunks from 1 block up
to 2^13 = 8192 blocks).

The `ext4_buddy` structure holds references to both bitmaps:

```c
struct ext4_buddy {
    struct folio *bd_buddy_folio;
    void *bd_buddy;
    struct folio *bd_bitmap_folio;
    void *bd_bitmap;
    struct ext4_group_info *bd_info;
    struct super_block *bd_sb;
    __u16 bd_blkbits;
    ext4_group_t bd_group;
};
```

### 6.5 Preallocation

mballoc maintains two types of preallocation to reduce fragmentation:

#### Per-Inode Preallocation (PA)

```c
struct ext4_prealloc_space {
    /* ... */
    ext4_fsblk_t    pa_pstart;   /* Physical start block */
    ext4_lblk_t     pa_lstart;   /* Logical start block */
    ext4_grpblk_t   pa_len;      /* Length of preallocated chunk */
    ext4_grpblk_t   pa_free;     /* Remaining free blocks in the PA */
    unsigned short  pa_type;     /* MB_INODE_PA or MB_GROUP_PA */
};
```

Per-inode PAs are stored in an rbtree per inode. When a file allocates
blocks, any unused preallocated space is checked first. The preallocation
size is normalized based on file size by `ext4_mb_normalize_request()`.

#### Per-Locality-Group Preallocation

```c
struct ext4_locality_group {
    struct mutex        lg_mutex;
    struct list_head    lg_prealloc_list[PREALLOC_TB_SIZE];
    spinlock_t          lg_prealloc_lock;
};
```

`PREALLOC_TB_SIZE = 10`. Each CPU has a locality group that maintains
preallocated space for "stream" allocations (small writes to multiple
files). The default group prealloc size is `MB_DEFAULT_GROUP_PREALLOC = 512`
blocks.

### 6.6 The Regular Allocator (`ext4_mb_regular_allocator`)

The main allocation function (`mballoc.c` line 2985) proceeds as follows:

1. **Try the goal**: Call `ext4_mb_find_by_goal()` to check if blocks near
   the requested goal are free.

2. **Iterate through criteria**: For each criterion from the starting
   criterion to `CR_ANY_FREE`:
   a. Scan block groups (with prefetching).
   b. For each group, load the buddy bitmap and try to find a suitable
      free extent.
   c. If a sufficiently good match is found, stop.

3. **Use preallocation**: If the allocation succeeds, update (or create)
   preallocation structures.

### 6.7 Allocation Context

```c
struct ext4_allocation_context {
    struct ext4_free_extent ac_o_ex;  /* Original request */
    struct ext4_free_extent ac_g_ex;  /* Goal (normalized) request */
    struct ext4_free_extent ac_b_ex;  /* Best extent found */
    struct ext4_free_extent ac_f_ex;  /* Best before preallocation */
    ext4_grpblk_t  ac_orig_goal_len;  /* Original goal length */
    __u32 ac_flags;                    /* Allocation hints */
    __u16 ac_groups_scanned;           /* Groups examined */
    __u16 ac_found;                    /* Extents found */
    __u8  ac_status;                   /* CONTINUE / FOUND / BREAK */
    __u8  ac_criteria;                 /* Current criterion */
    __u8  ac_2order;                   /* log2 of request if power-of-2, else 0 */
};
```

### 6.8 Tuning Parameters

```c
#define MB_DEFAULT_MAX_TO_SCAN           200  /* Max extents to examine */
#define MB_DEFAULT_MIN_TO_SCAN           10   /* Min extents to examine */
#define MB_DEFAULT_STREAM_THRESHOLD      16   /* 16 blocks = 64KB for stream alloc */
#define MB_DEFAULT_ORDER2_REQS           2    /* Min requests for order-2 search */
#define MB_DEFAULT_GROUP_PREALLOC        512  /* Default group prealloc blocks */
#define MB_DEFAULT_LINEAR_LIMIT          4    /* Groups before scan optimization */
#define MB_DEFAULT_LINEAR_SCAN_THRESHOLD 16   /* Min groups for scan optimization */
#define MB_DEFAULT_BEST_AVAIL_TRIM_ORDER 3    /* Max trim for best-avail */
```

---

## 7. Inode Allocation (Orlov Allocator)

**Source:** `ialloc.c` lines 364-560

The Orlov allocator is the primary algorithm for choosing which block group
should host a new inode. It implements a heuristic that spreads top-level
directories across block groups while clustering subdirectories and files
near their parent directory.

### 7.1 Orlov Statistics

```c
struct orlov_stats {
    __u64 free_clusters;
    __u32 free_inodes;
    __u32 used_dirs;
};
```

These statistics are gathered per block group (or per flex group if flex_bg
is enabled) via `get_orlov_stats()`.

### 7.2 The `find_group_orlov()` Algorithm

```c
static int find_group_orlov(struct super_block *sb, struct inode *parent,
                            ext4_group_t *group, umode_t mode,
                            const struct qstr *qstr)
```

**Input:**
- `parent`: The parent directory inode
- `mode`: File type being created
- `qstr`: Name of the new entry (used for hash-based distribution)

**Algorithm:**

#### Phase 1: Top-Level Directory Spreading

When creating a **directory** whose parent is the root directory or has the
`EXT4_INODE_TOPDIR` flag:

1. Compute a starting group:
   - If a name is provided, hash it with `DX_HASH_HALF_MD4` using the
     filesystem's hash seed, then `parent_group = hash % ngroups`.
   - Otherwise, choose a random group.

2. Scan all groups starting from the computed starting point.

3. Select the group with the fewest used directories (`best_ndir`) that
   also satisfies:
   - `stats.free_inodes > 0`
   - `stats.used_dirs < best_ndir` (better than current best)
   - `stats.free_inodes >= avefreei` (average free inodes)
   - `stats.free_clusters >= avefreec` (average free clusters)

This spreads top-level directories evenly across the filesystem.

#### Phase 2: Subdirectory and File Clustering

For files and subdirectories (not top-level):

1. Compute thresholds:
   ```c
   max_dirs = ndirs / ngroups + inodes_per_group * flex_size / 16;
   min_inodes = avefreei - inodes_per_group * flex_size / 4;
   min_clusters = avefreec - EXT4_CLUSTERS_PER_GROUP(sb) * flex_size / 4;
   ```

2. Start scanning from the parent's last allocation group
   (`i_last_alloc_group`) if set, otherwise from the parent's block group.

3. Select the first group that satisfies all three constraints:
   - `stats.used_dirs < max_dirs`
   - `stats.free_inodes >= min_inodes`
   - `stats.free_clusters >= min_clusters`

This clusters related inodes together for locality.

#### Phase 3: Fallback

If no group satisfies the constraints:
1. Fall back to scanning all groups for any group with free inodes above
   the filesystem average.
2. If that fails, halve the `avefreei` threshold and retry.
3. As a last resort, accept any group with free inodes.

#### Flex Group Adjustment

When flex_bg is enabled, the algorithm works in terms of flex groups
(groups of block groups). Once a flex group is chosen, the actual block
group is selected by finding the first constituent group with free inodes,
preferring groups near the beginning of the flex group (for inode table
locality).

### 7.3 File Allocation Strategy

For non-directory files, `find_group_other()` is used instead. It first
offsets the parent group by the parent's inode number (`group = (group +
parent->i_ino) % ngroups`), then scans forward using a power-of-two step
pattern (`for (i = 1; i < ngroups; i <<= 1) { *group += i; ...}`). This
gives increments of +1, +2, +4, +8, +16, ..., producing cumulative offsets
of +1, +3, +7, +15, +31, ... The kernel comments call this "quadratic hash"
but the iteration doubles `i` each step rather than squaring it. If no
suitable group is found, it falls back to a linear scan.

The decision between Orlov and `find_group_other` is made in
`__ext4_new_inode()` (line 1018):
```c
if (S_ISDIR(mode))
    ret2 = find_group_orlov(sb, dir, &group, mode, qstr);
else
    ret2 = find_group_other(sb, dir, &group, mode);
```

---

## 8. JBD2 Journaling

**Source:** `ext4_jbd2.h`, `ext4_jbd2.c`

ext4 uses the JBD2 (Journaling Block Device 2) layer for crash consistency.
The journal is typically stored in inode 8 (`EXT4_JOURNAL_INO`) and
operates as a circular log of metadata (and optionally data) changes.

### 8.1 Journal Structure (On-Disk)

The journal occupies the logical block range of the journal inode (typically
inode 8). Physical storage may be one extent or multiple non-contiguous
extents. Replay semantics are defined by journal logical block order, not by
physical contiguity, so recovery must iterate across extent boundaries in
logical sequence. The journal contains:

1. **Journal superblock**: Describes journal size, block size, sequence
   numbers, and feature flags. Located at the first block of the journal.

2. **Descriptor blocks**: List the filesystem blocks that are included in
   the following data blocks. Each descriptor block has a header with magic
   number `0xC03B3998` and block type tag.

3. **Data blocks**: Copies of the filesystem metadata blocks as they
   appeared at commit time. These are the "journal copies" that will be
   replayed during recovery.

4. **Commit blocks**: Mark the end of a transaction. A commit block
   includes a checksum of all the data in the transaction.

5. **Revoke blocks**: List filesystem blocks whose journal entries should
   be ignored during replay (because the blocks have been freed or
   reallocated since those journal entries were written).

### 8.2 Transaction Lifecycle

```
running -> committing -> committed -> checkpointed
```

1. **Running**: The current active transaction. New operations join this
   transaction via `jbd2_journal_start()`.

2. **Committing**: The transaction is being written to the journal.
   No new operations can join. The JBD2 commit thread handles this.

3. **Committed**: The transaction has been written to the journal but the
   actual filesystem blocks haven't been written to their final locations
   yet.

4. **Checkpointed**: All filesystem blocks from this transaction have been
   written to their final on-disk locations. The journal space used by
   this transaction can be reclaimed.

### 8.3 Journal Handles and Credits

```c
handle_t *__ext4_journal_start_sb(struct inode *inode, struct super_block *sb,
                                  unsigned int line, int type, int blocks,
                                  int rsv_blocks, int revoke_creds);
```

A **handle** represents a single filesystem operation's participation in a
transaction. Each handle must declare the maximum number of **credits**
(buffer modifications) it will need:

```c
#define EXT4_SINGLEDATA_TRANS_BLOCKS(sb) \
    (ext4_has_feature_extents(sb) ? 20U : 8U)

#define EXT4_XATTR_TRANS_BLOCKS    6U

#define EXT4_DATA_TRANS_BLOCKS(sb) \
    (EXT4_SINGLEDATA_TRANS_BLOCKS(sb) + EXT4_XATTR_TRANS_BLOCKS - 2 + \
     EXT4_MAXQUOTAS_TRANS_BLOCKS(sb))
```

For extent-based filesystems, a single data modification may need up to 20
buffer credits (for the inode, up to 5 levels of extent tree nodes, bitmap
blocks, group descriptor blocks, and the superblock).

### 8.4 Handle Operation Types

```c
#define EXT4_HT_MISC             0
#define EXT4_HT_INODE            1
#define EXT4_HT_WRITE_PAGE       2
#define EXT4_HT_MAP_BLOCKS       3
#define EXT4_HT_DIR              4
#define EXT4_HT_TRUNCATE         5
#define EXT4_HT_QUOTA            6
#define EXT4_HT_RESIZE           7
#define EXT4_HT_MIGRATE          8
#define EXT4_HT_MOVE_EXTENTS     9
#define EXT4_HT_XATTR           10
#define EXT4_HT_EXT_CONVERT     11
#define EXT4_HT_MAX             12
```

### 8.5 Data Journaling Modes

```c
#define EXT4_INODE_JOURNAL_DATA_MODE   0x01  /* journal data mode */
#define EXT4_INODE_ORDERED_DATA_MODE   0x02  /* ordered data mode */
#define EXT4_INODE_WRITEBACK_DATA_MODE 0x04  /* writeback data mode */
```

**Journal mode** (`data=journal`): Both metadata and file data are written
to the journal before being committed to their final locations. Maximum
safety, lowest performance.

**Ordered mode** (`data=ordered`): Only metadata is journaled, but file
data is forced to disk before the corresponding metadata transaction is
committed. This is the default mode. Ensures that after a crash, file
data won't contain stale or garbage data from previous file operations.

**Writeback mode** (`data=writeback`): Only metadata is journaled. File
data may be written to disk at any time relative to the metadata
transaction. Fastest but data might be stale after a crash.

### 8.6 Key JBD2 Wrapper Functions

```c
ext4_journal_start(inode, type, nblocks)
    /* Start a new handle with nblocks credits */

ext4_journal_stop(handle)
    /* Stop (complete) a handle */

ext4_journal_get_write_access(handle, sb, bh, trigger_type)
    /* Get write access to a buffer within a transaction */

ext4_handle_dirty_metadata(handle, inode, bh)
    /* Mark a buffer as dirty metadata within the transaction */

ext4_journal_ensure_credits(handle, credits, revoke_creds)
    /* Ensure handle has enough credits, extending or restarting if needed */

ext4_journal_extend(handle, nblocks, revoke)
    /* Try to extend the current handle's credit allocation */

ext4_journal_restart(handle, nblocks, revoke)
    /* Restart the handle in a new transaction */
```

### 8.7 Fast Commit

When the `FAST_COMMIT` feature is enabled, ext4 can perform lightweight
commits for common operations (file appends, inode updates) without a
full JBD2 transaction commit. The fast commit log is appended after the
main journal and uses a separate replay path.

---

## 9. Extended Attributes (xattr)

**Source:** `xattr.h` lines 1-237, `xattr.c`

Extended attributes store name-value pairs associated with inodes. ext4
supports two storage locations: inline (in the inode body) and block-based
(in a separate block).

### 9.1 Xattr Namespaces

```c
#define EXT4_XATTR_INDEX_USER               1
#define EXT4_XATTR_INDEX_POSIX_ACL_ACCESS   2
#define EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT  3
#define EXT4_XATTR_INDEX_TRUSTED            4
#define EXT4_XATTR_INDEX_LUSTRE             5
#define EXT4_XATTR_INDEX_SECURITY           6
#define EXT4_XATTR_INDEX_SYSTEM             7
#define EXT4_XATTR_INDEX_RICHACL            8
#define EXT4_XATTR_INDEX_ENCRYPTION         9
#define EXT4_XATTR_INDEX_HURD              10
```

### 9.2 Inline Xattrs (In-Inode)

When the inode size is larger than 128 bytes and `i_extra_isize` allows
room, extended attributes are stored directly in the inode body after the
standard and extra fields.

The inline xattr area starts with a 4-byte header:

```c
struct ext4_xattr_ibody_header {
    __le32  h_magic;  /* Magic number: 0xEA020000 */
};
```

The header is located at:
```c
#define IHDR(inode, raw_inode) \
    ((struct ext4_xattr_ibody_header *) \
        ((void *)raw_inode + EXT4_GOOD_OLD_INODE_SIZE + \
         EXT4_I(inode)->i_extra_isize))
```

For a 256-byte inode with `i_extra_isize = 32`:
- Standard fields: bytes 0-127
- Extra fields: bytes 128-159
- Xattr ibody header: byte 160
- Xattr entries: bytes 164-255 (remaining inode space)

The end of the inline xattr area is:
```c
#define ITAIL(inode, raw_inode) \
    ((void *)(raw_inode) + EXT4_SB((inode)->i_sb)->s_inode_size)
```

### 9.3 Block-Based Xattrs

When xattrs don't fit in the inode, they are stored in a separate block
pointed to by `i_file_acl_lo|hi`. The block starts with a header:

```c
struct ext4_xattr_header {
    __le32  h_magic;      /* Magic: 0xEA020000 */
    __le32  h_refcount;   /* Reference count (blocks can be shared) */
    __le32  h_blocks;     /* Number of disk blocks used */
    __le32  h_hash;       /* Hash value of all attributes */
    __le32  h_checksum;   /* crc32c(uuid+blknum+xattrblock) */
    __u32   h_reserved[3]; /* Zero, reserved */
};
```

**Total header size:** 32 bytes.

**Magic number:** `EXT4_XATTR_MAGIC = 0xEA020000`

**Maximum reference count:** `EXT4_XATTR_REFCOUNT_MAX = 1024`

### 9.4 Xattr Entry Format

Both inline and block-based xattrs use the same entry format:

```c
struct ext4_xattr_entry {
    __u8    e_name_len;     /* Length of attribute name */
    __u8    e_name_index;   /* Attribute namespace index (see 9.1) */
    __le16  e_value_offs;   /* Offset in disk block of value data */
    __le32  e_value_inum;   /* Inode for value (if stored in a separate inode) */
    __le32  e_value_size;   /* Size of attribute value */
    __le32  e_hash;         /* Hash of name and value */
    char    e_name[];       /* Attribute name (variable length) */
};
```

**Entry size (minimum):** 16 bytes (header) + name_len, rounded up to 4-byte
boundary:

```c
#define EXT4_XATTR_PAD_BITS  2
#define EXT4_XATTR_PAD       (1 << EXT4_XATTR_PAD_BITS)  /* = 4 */
#define EXT4_XATTR_ROUND     (EXT4_XATTR_PAD - 1)        /* = 3 */
#define EXT4_XATTR_LEN(name_len) \
    (((name_len) + EXT4_XATTR_ROUND + sizeof(struct ext4_xattr_entry)) & \
     ~EXT4_XATTR_ROUND)
```

### 9.5 Xattr Entry Traversal

Entries are stored sequentially. The end of the entry list is marked by a
4-byte zero value:

```c
#define IS_LAST_ENTRY(entry)  (*(__u32 *)(entry) == 0)
```

The next entry is found by:
```c
#define EXT4_XATTR_NEXT(entry) \
    ((struct ext4_xattr_entry *)(((char *)(entry)) + \
     EXT4_XATTR_LEN((entry)->e_name_len)))
```

### 9.6 Value Storage

Values are stored at the **end** of the xattr block (or inode space),
growing toward the entries from the opposite direction. The `e_value_offs`
field gives the offset from the start of the block/inode-body to the
value data. Values are also padded to 4-byte boundaries:

```c
#define EXT4_XATTR_SIZE(size)  (((size) + EXT4_XATTR_ROUND) & ~EXT4_XATTR_ROUND)
```

### 9.7 Large Xattr Values (EA Inode)

When `EXT4_FEATURE_INCOMPAT_EA_INODE` is set and a value is too large for
the xattr block, it can be stored in a separate inode. The `e_value_inum`
field contains the inode number, and `e_value_size` contains the value size.

The minimum size for external storage:
```c
#define EXT4_XATTR_MIN_LARGE_EA_SIZE(b) \
    ((b) - EXT4_XATTR_LEN(3) - sizeof(struct ext4_xattr_header) - 4)
```

Maximum xattr value size: `EXT4_XATTR_SIZE_MAX = 1 << 24 = 16 MB`
(the practical limit is `XATTR_SIZE_MAX = 64KB`).

---

## 10. Checksums

**Source:** `ext4.h` lines 2545-2548

ext4 uses **crc32c** for all metadata checksumming when the
`RO_COMPAT_METADATA_CSUM` feature is enabled.

### 10.1 Core Checksum Function

```c
static inline u32 ext4_chksum(u32 crc, const void *address, unsigned int length)
{
    return crc32c(crc, address, length);
}
```

This is a thin wrapper around the kernel's `crc32c()` function.

### 10.2 Superblock Checksum

The superblock checksum is stored in `s_checksum` (offset 0x3FC, last 4
bytes). It is computed as `crc32c` of the entire superblock with the
checksum field itself set to zero.

The checksum seed can be pre-computed from the UUID:
- If `INCOMPAT_CSUM_SEED` is set: `seed = s_checksum_seed`
- Otherwise: `seed = crc32c(~0, s_uuid, 16)`

### 10.3 Group Descriptor Checksum

The group descriptor checksum is stored in `bg_checksum` (offset 0x1E).
When `METADATA_CSUM` is enabled, it is `crc32c(seed, group_number, desc)`.
When only `GDT_CSUM` is enabled (legacy), it is `crc16(seed, group, desc)`.

### 10.4 Inode Checksum

Inodes have a split checksum:
- `l_i_checksum_lo` (offset 0x7C in inode): Low 16 bits
- `i_checksum_hi` (offset 0x82 in inode): High 16 bits (only in extended
  inodes)

Computed as `crc32c(seed, inode_number, inode_data)`.

### 10.5 Extent Tree Checksum

Non-root extent tree blocks have `ext4_extent_tail.et_checksum`:
`crc32c(seed + inode_number, extent_block_data)`.

### 10.6 Directory Block Checksum

Directory leaf blocks end with `ext4_dir_entry_tail.det_checksum`:
`crc32c(seed + inode_number, dir_block_data)`.

Htree (dx) blocks end with `dx_tail.dt_checksum`:
`crc32c(seed, dir_entries)`.

### 10.7 Xattr Block Checksum

The xattr block header contains `h_checksum`:
`crc32c(seed + block_number, xattr_block_data)`.

### 10.8 Bitmap Checksums

Block and inode bitmaps have checksums in the group descriptor:
- `bg_block_bitmap_csum_lo|hi`: `crc32c(seed + group_number, block_bitmap)`
- `bg_inode_bitmap_csum_lo|hi`: `crc32c(seed + group_number, inode_bitmap)`

---

# Part II: btrfs Concepts Relevant to FrankenFS

btrfs is a copy-on-write (COW) B-tree filesystem that stores all metadata
and data references in B-trees. Unlike ext4's fixed block group structure,
btrfs uses a flexible tree-based approach where all metadata is stored as
items in B-trees indexed by `(objectid, type, offset)` keys.

---

## 11. B-tree (ctree)

**Source:** `ctree.h`, `ctree.c`, `accessors.h`

The btrfs B-tree is the fundamental data structure. All filesystem metadata
(inodes, directory entries, extent references, checksums, etc.) is stored as
items in B-trees. Each tree is identified by a root and uses COW semantics.

### 11.1 btrfs_key

The key is the universal index for all items in all trees:

```c
struct btrfs_key {
    __le64  objectid;   /* Object identifier (e.g., inode number) */
    __u8    type;       /* Item type code */
    __le64  offset;     /* Type-dependent offset value */
};
```

**Total size:** 17 bytes on disk (8 + 1 + 8).

**Comparison order:** Keys are compared lexicographically:
1. First by `objectid` (ascending)
2. Then by `type` (ascending)
3. Then by `offset` (ascending)

```c
int __pure btrfs_comp_cpu_keys(const struct btrfs_key *k1,
                               const struct btrfs_key *k2)
{
    if (k1->objectid > k2->objectid) return 1;
    if (k1->objectid < k2->objectid) return -1;
    if (k1->type > k2->type) return 1;
    if (k1->type < k2->type) return -1;
    if (k1->offset > k2->offset) return 1;
    if (k1->offset < k2->offset) return -1;
    return 0;
}
```

#### Common Key Types

The `type` field identifies the kind of item. Common types include:

```
Type  Value  Name                        Meaning
----  -----  ----                        -------
1     0x01   BTRFS_INODE_ITEM_KEY        Inode metadata
12    0x0C   BTRFS_INODE_REF_KEY         Inode back-reference (name + parent)
13    0x0D   BTRFS_INODE_EXTREF_KEY      Extended inode reference (for hardlinks)
24    0x18   BTRFS_XATTR_ITEM_KEY        Extended attribute
36    0x24   BTRFS_ORPHAN_ITEM_KEY       Orphan inode entry
48    0x30   BTRFS_DIR_LOG_ITEM_KEY      Directory log item (for tree-log)
60    0x3C   BTRFS_DIR_ITEM_KEY          Directory entry (hashed name)
84    0x54   BTRFS_DIR_INDEX_KEY         Directory entry (sequence number)
96    0x60   BTRFS_EXTENT_DATA_KEY       File data extent reference
108   0x6C   BTRFS_EXTENT_CSUM_KEY       Data checksums
128   0x80   BTRFS_ROOT_ITEM_KEY         Subvolume/tree root descriptor
132   0x84   BTRFS_ROOT_BACKREF_KEY      Subvolume parent reference
144   0x90   BTRFS_ROOT_REF_KEY          Subvolume child reference
168   0xA8   BTRFS_EXTENT_ITEM_KEY       Extent allocation record
169   0xA9   BTRFS_METADATA_ITEM_KEY     Metadata extent record
176   0xB0   BTRFS_TREE_BLOCK_REF_KEY    Tree block back-reference
178   0xB2   BTRFS_SHARED_BLOCK_REF_KEY  Shared tree block reference
180   0xB4   BTRFS_EXTENT_DATA_REF_KEY   Extent data back-reference
182   0xB6   BTRFS_SHARED_DATA_REF_KEY   Shared extent data reference
192   0xC0   BTRFS_BLOCK_GROUP_ITEM_KEY  Block group descriptor
196   0xC4   BTRFS_FREE_SPACE_INFO_KEY   Free space info
198   0xC6   BTRFS_FREE_SPACE_EXTENT_KEY Free space extent
200   0xC8   BTRFS_FREE_SPACE_BITMAP_KEY Free space bitmap
204   0xCC   BTRFS_DEV_EXTENT_KEY        Device extent allocation
216   0xD8   BTRFS_DEV_ITEM_KEY          Device descriptor
228   0xE4   BTRFS_CHUNK_ITEM_KEY        Chunk (logical -> physical) mapping
230   0xE6   BTRFS_QGROUP_STATUS_KEY     Quota group status
```

### 11.2 Node Header (`struct btrfs_header`)

Every tree node (leaf or internal) starts with a header. The header fields
are accessed through `BTRFS_SETGET_HEADER_FUNCS` macros:

```
Offset  Size  Field                Description
------  ----  -----                -----------
0x00    32    csum                 Checksum of everything after this field
0x20    16    fsid                 Filesystem UUID
0x30    8     bytenr               Byte offset of this node on disk
0x38    8     flags                Node flags (WRITTEN, RELOC, etc.)
0x40    16    chunk_tree_uuid      Chunk tree UUID (device-level identifier)
0x50    8     generation           Transaction ID when this node was last COWed
0x58    8     owner                Tree ID that owns this node (root objectid)
0x60    4     nritems              Number of items (leaves) or key-pointers (nodes)
0x64    1     level                Level in the tree (0 = leaf)
```

**Total header size:** 101 bytes (0x65).

**Accessor macros from `accessors.h`:**
```c
BTRFS_SETGET_HEADER_FUNCS(header_bytenr, struct btrfs_header, bytenr, 64);
BTRFS_SETGET_HEADER_FUNCS(header_generation, struct btrfs_header, generation, 64);
BTRFS_SETGET_HEADER_FUNCS(header_owner, struct btrfs_header, owner, 64);
BTRFS_SETGET_HEADER_FUNCS(header_nritems, struct btrfs_header, nritems, 32);
BTRFS_SETGET_HEADER_FUNCS(header_flags, struct btrfs_header, flags, 64);
BTRFS_SETGET_HEADER_FUNCS(header_level, struct btrfs_header, level, 8);
```

### 11.3 Internal Node Layout

For `level > 0`, after the header, internal nodes contain an array of
`btrfs_key_ptr` structures:

```
struct btrfs_key_ptr {
    struct btrfs_disk_key key;   /* 17 bytes: the first key in the child */
    __le64 blockptr;             /* 8 bytes: byte offset of child node */
    __le64 generation;           /* 8 bytes: generation of child node */
};
```

**Total per key-pointer:** 33 bytes (17 + 8 + 8).

Number of key-pointers per node:
```
max_key_ptrs = (nodesize - sizeof(btrfs_header)) / sizeof(btrfs_key_ptr)
```
For default 16KB nodesize: `(16384 - 101) / 33 = 493` key-pointers.

### 11.4 Leaf Node Layout

For `level == 0`, after the header, leaves contain an array of
`btrfs_item` structures followed by item data growing from the end of the
node toward the items:

```
struct btrfs_item {
    struct btrfs_disk_key key;   /* 17 bytes: item key */
    __le32 offset;               /* 4 bytes: offset of data relative to BTRFS_LEAF_DATA_OFFSET (end of header) */
    __le32 size;                 /* 4 bytes: size of item data */
};
```

**Total per item header:** 25 bytes (17 + 4 + 4).

The leaf layout is:

```
[header (101 bytes)] [item[0]..item[N-1] (25 bytes each)] ... [gap] ... [data[N-1]..data[0]]
```

Item data grows from the end of the node backward (toward the item array).
`btrfs_item.offset` gives the data offset relative to `BTRFS_LEAF_DATA_OFFSET`
(which is the end of the header).

The leaf data end (start of free space) is calculated by:
```c
static unsigned int leaf_data_end(const struct extent_buffer *leaf)
{
    u32 nr = btrfs_header_nritems(leaf);
    if (nr == 0)
        return BTRFS_LEAF_DATA_SIZE(leaf->fs_info);
    return btrfs_item_offset(leaf, nr - 1);
}
```

### 11.5 btrfs_path

The path structure tracks the traversal from root to leaf:

```c
struct btrfs_path {
    struct extent_buffer *nodes[BTRFS_MAX_LEVEL];  /* Node at each level */
    int slots[BTRFS_MAX_LEVEL];                     /* Item/key index at each level */
    u8 locks[BTRFS_MAX_LEVEL];                      /* Lock state at each level */
    u8 reada;          /* Readahead mode: NONE, BACK, FORWARD, FORWARD_ALWAYS */
    u8 lowest_level;   /* Stop descending at this level */
    /* Bit flags */
    bool search_for_split:1;
    bool keep_locks:1;
    bool skip_locking:1;
    bool search_commit_root:1;
    bool need_commit_sem:1;
    bool skip_release_on_error:1;
    bool search_for_extension:1;
    bool nowait:1;
};
```

**BTRFS_MAX_LEVEL = 8** (defined in `uapi/linux/btrfs_tree.h`). This
limits the tree to 8 levels, which provides enormous capacity:
- For 16KB nodes with ~493 key-pointers per internal node:
  493^7 * leaf_items per node > 10^18 items

### 11.6 Tree Roots

btrfs maintains multiple independent B-trees, each with its own root:

```
Root objectid  Name               Purpose
-----------    ----               -------
1              ROOT_TREE          Contains root items for all other trees
2              EXTENT_TREE        Tracks extent allocation and references
3              CHUNK_TREE         Maps logical addresses to physical devices
4              DEV_TREE           Device allocation information
5              FS_TREE            Default subvolume (root filesystem)
6              ROOT_DIR           Root directory objectid
7              CSUM_TREE          Data checksum storage
8              QUOTA_TREE         Quota group information
9              UUID_TREE          Maps subvolume UUIDs to root IDs
10             FREE_SPACE_TREE    Free space tracking (v2)
-5             TREE_LOG           Per-subvolume tree log for fast fsync
-7             TREE_RELOC         Temporary tree used during balance
-8             DATA_RELOC_TREE    Data relocation tree
```

### 11.6.1 `BTRFS_IOC_INO_LOOKUP` Path Lookup Contract

Linux `fs/btrfs/ioctl.c` handles `BTRFS_IOC_INO_LOOKUP` with
`struct btrfs_ioctl_ino_lookup_args`:

```
Field     Type    Meaning
-----     ----    -------
treeid    u64     Subvolume tree objectid, or 0 for the mounted root
objectid  u64     Inode objectid to resolve
name      bytes   NUL-terminated path buffer written by the filesystem
```

Behavioral contract:

1. If `treeid == 0`, resolve it to the currently mounted btrfs root id and
   write that resolved tree id back to the reply.
2. If `objectid == BTRFS_FIRST_FREE_OBJECTID` (256), return the resolved
   tree id with an empty NUL-terminated path.
3. Otherwise, locate the requested tree's `ROOT_ITEM`, walk that fs tree, and
   resolve `INODE_REF` back-references from `objectid` to the subvolume root.
4. The returned path is relative to the selected subvolume root and is
   NUL-terminated.

### 11.7 Search Algorithm

`btrfs_search_slot()` (ctree.c) implements the core B-tree search:

1. Start at the root node (`root->node`).
2. At each internal level:
   a. Binary search for the key.
   b. If `ins_len > 0` (insert mode), COW the node.
   c. Descend to the appropriate child via the block pointer.
3. At the leaf level:
   a. Binary search for the exact key or insertion point.
   b. If the key is found, `path->slots[0]` points to it.
   c. If not found, return 1 with `slots[0]` at the insertion point.

### 11.8 Node Split and Merge

When a leaf or internal node overflows during insertion:

- **split_leaf()**: Splits a leaf into two halves, distributing items
  between them and inserting a new key-pointer in the parent.

- **split_node()**: Splits an internal node similarly.

- **push_node_left() / balance_node_right()**: Attempt to rebalance items
  between sibling nodes before resorting to a split.

These operations maintain the B-tree invariant that all leaves are at the
same level.

---

## 12. COW Semantics

**Source:** `ctree.c` lines 470-714

Copy-on-Write (COW) is btrfs's core mechanism for transactional updates.
When any tree node needs modification, a new copy is allocated, the old
content is copied to it, the modification is applied to the copy, and the
parent pointer is updated to reference the new copy.

### 12.1 `btrfs_force_cow_block()`

This is the main COW implementation (ctree.c lines 478-614):

```c
int btrfs_force_cow_block(struct btrfs_trans_handle *trans,
                          struct btrfs_root *root,
                          struct extent_buffer *buf,
                          struct extent_buffer *parent,
                          int parent_slot,
                          struct extent_buffer **cow_ret,
                          u64 search_start, u64 empty_size,
                          enum btrfs_lock_nesting nest)
```

**Algorithm:**

1. **Allocate a new tree block:**
   ```c
   cow = btrfs_alloc_tree_block(trans, root, parent_start,
                                btrfs_root_id(root), &disk_key, level,
                                search_start, empty_size, reloc_src_root, nest);
   ```

2. **Copy the old block's content to the new block:**
   ```c
   copy_extent_buffer_full(cow, buf);
   ```

3. **Update the new block's header:**
   ```c
   btrfs_set_header_bytenr(cow, cow->start);
   btrfs_set_header_generation(cow, trans->transid);
   btrfs_set_header_backref_rev(cow, BTRFS_MIXED_BACKREF_REV);
   btrfs_clear_header_flag(cow, BTRFS_HEADER_FLAG_WRITTEN |
                                BTRFS_HEADER_FLAG_RELOC);
   ```

4. **Update extent reference counts:**
   ```c
   ret = update_ref_for_cow(trans, root, buf, cow, &last_ref);
   ```

5. **Update the parent pointer:**
   - If `buf == root->node` (COWing the root):
     ```c
     rcu_assign_pointer(root->node, cow);
     ```
   - Otherwise (COWing a non-root node):
     ```c
     btrfs_set_node_blockptr(parent, parent_slot, cow->start);
     btrfs_set_node_ptr_generation(parent, parent_slot, trans->transid);
     btrfs_mark_buffer_dirty(trans, parent);
     ```

6. **Free the old block:**
   ```c
   ret = btrfs_free_tree_block(trans, btrfs_root_id(root), buf,
                               parent_start, last_ref);
   ```

7. **Handle relocation trees:**
   If the root is shareable (subvolume trees), relocation must be tracked:
   ```c
   if (test_bit(BTRFS_ROOT_SHAREABLE, &root->state)) {
       ret = btrfs_reloc_cow_block(trans, root, buf, cow);
   }
   ```

### 12.2 `should_cow_block()`

An optimization to avoid unnecessary COW operations:

```c
static inline bool should_cow_block(const struct btrfs_trans_handle *trans,
                                    const struct btrfs_root *root,
                                    const struct extent_buffer *buf)
{
    if (btrfs_is_testing(root->fs_info))
        return false;
    /* Skip COW if:
     * 1) Block was not created/changed in this transaction
     * 2) Block does not belong to TREE_RELOC tree
     * 3) Block was already COWed for this transaction
     */
    /* ... checks based on generation, root type, etc. ... */
}
```

A block does not need to be COWed if:
- It was already allocated and modified in the current transaction
  (its `generation` matches `trans->transid`)
- It does not belong to a reloc tree
- The root is not in a force-COW state

### 12.3 `btrfs_cow_block()`

The public wrapper that checks `should_cow_block()` first:

```c
int btrfs_cow_block(struct btrfs_trans_handle *trans,
                    struct btrfs_root *root,
                    struct extent_buffer *buf,
                    struct extent_buffer *parent,
                    int parent_slot,
                    struct extent_buffer **cow_ret,
                    enum btrfs_lock_nesting nest)
{
    /* ... validation checks ... */
    if (!should_cow_block(trans, root, buf)) {
        *cow_ret = buf;
        return 0;
    }
    search_start = round_down(buf->start, SZ_1G);
    /* ... subtree trace for qgroup ... */
    return btrfs_force_cow_block(trans, root, buf, parent, parent_slot,
                                  cow_ret, search_start, 0, nest);
}
```

The `search_start` is rounded down to a 1GB boundary to encourage locality
in allocations.

### 12.4 Transaction Model

**Source:** `transaction.h`, `transaction.c`

btrfs transactions group multiple filesystem operations into atomic units:

```c
enum btrfs_trans_state {
    TRANS_STATE_RUNNING,          /* Active, accepting operations */
    TRANS_STATE_COMMIT_PREP,      /* Preparing to commit */
    TRANS_STATE_COMMIT_START,     /* Starting commit */
    TRANS_STATE_COMMIT_DOING,     /* Actively committing */
    TRANS_STATE_UNBLOCKED,        /* New transaction can start */
    TRANS_STATE_SUPER_COMMITTED,  /* Superblock written */
    TRANS_STATE_COMPLETED,        /* Fully complete */
};
```

#### Transaction Structure

```c
struct btrfs_transaction {
    u64 transid;                          /* Transaction ID */
    atomic_t num_extwriters;              /* External writers count */
    atomic_t num_writers;                 /* Total writers count */
    refcount_t use_count;
    enum btrfs_trans_state state;
    int aborted;
    struct list_head list;
    struct extent_io_tree dirty_pages;
    time64_t start_time;
    wait_queue_head_t writer_wait;
    wait_queue_head_t commit_wait;
    struct list_head pending_snapshots;
    struct list_head dev_update_list;
    struct list_head dirty_bgs;
    struct list_head io_bgs;
    struct list_head dropped_roots;
    struct extent_io_tree pinned_extents;
    struct btrfs_delayed_ref_root delayed_refs;
    struct btrfs_fs_info *fs_info;
    atomic_t pending_ordered;
    wait_queue_head_t pending_wait;
};
```

#### Transaction Handle

```c
struct btrfs_trans_handle {
    u64 transid;                          /* Transaction ID */
    u64 bytes_reserved;                   /* Space reserved for this handle */
    u64 delayed_refs_bytes_reserved;
    u64 chunk_bytes_reserved;
    unsigned long delayed_ref_updates;
    unsigned long delayed_ref_csum_deletions;
    struct btrfs_transaction *transaction;
    struct btrfs_block_rsv *block_rsv;
    struct btrfs_block_rsv *orig_rsv;
    struct btrfs_pending_snapshot *pending_snapshot;
    refcount_t use_count;
    /* ... flags ... */
};
```

#### Starting and Committing Transactions

```c
/* Join types */
#define TRANS_START        (__TRANS_START | __TRANS_FREEZABLE)
#define TRANS_ATTACH       (__TRANS_ATTACH)
#define TRANS_JOIN         (__TRANS_JOIN | __TRANS_FREEZABLE)
#define TRANS_JOIN_NOLOCK  (__TRANS_JOIN_NOLOCK)
#define TRANS_JOIN_NOSTART (__TRANS_JOIN_NOSTART)
```

- **TRANS_START**: Starts a new transaction or joins the current one.
  Blocks if the filesystem is frozen.
- **TRANS_ATTACH**: Attaches to the current running transaction without
  starting a new one.
- **TRANS_JOIN**: Joins the current transaction, blocking if frozen.
- **TRANS_JOIN_NOLOCK**: Joins without taking the filesystem lock.
- **TRANS_JOIN_NOSTART**: Joins if a transaction is running but does not
  start a new one.

### 12.5 COW Implications for Snapshots

Because COW never overwrites existing data, old versions of tree blocks
remain on disk until their reference counts drop to zero. This is the basis
for btrfs snapshots:

1. A snapshot creates a new root item pointing to the same tree root as the
   source subvolume.
2. Both the snapshot and the source share all tree blocks.
3. When either modifies a block, COW creates a new copy, and the two trees
   diverge at that point.
4. Reference counting in the extent tree tracks how many trees reference
   each block.

---

## 13. Scrub and Repair

**Source:** `scrub.c` lines 1-250, `scrub.h`

The btrfs scrub subsystem reads all data and metadata on a device, verifies
checksums, and attempts to repair corrupted data using redundant copies
(from other mirrors in RAID configurations or from other devices).

### 13.1 Scrub Architecture

The scrub operates in units of **stripes**, where each stripe represents a
contiguous `BTRFS_STRIPE_LEN`-sized region of a device. Stripes are
processed in groups for I/O efficiency.

```c
#define SCRUB_STRIPES_PER_GROUP   8    /* 512KB per group */
#define SCRUB_GROUPS_PER_SCTX     16   /* 8MB total per device */
#define SCRUB_TOTAL_STRIPES       (SCRUB_GROUPS_PER_SCTX * SCRUB_STRIPES_PER_GROUP)
                                       /* = 128 stripes */
```

### 13.2 Sector Verification

Each sector within a stripe has associated verification metadata:

```c
struct scrub_sector_verification {
    union {
        u8 *csum;          /* For data: pointer to expected checksum */
        u64 generation;    /* For metadata: expected generation number */
    };
};
```

For data sectors, the `csum` pointer references the expected checksum from
the checksum tree. For metadata sectors, the `generation` field contains
the expected generation for the tree block header.

### 13.3 Scrub Stripe Structure

```c
struct scrub_stripe {
    struct scrub_ctx *sctx;
    struct btrfs_block_group *bg;
    struct folio *folios[SCRUB_STRIPE_MAX_FOLIOS];
    struct scrub_sector_verification *sectors;
    struct btrfs_device *dev;
    u64 logical;        /* Logical address */
    u64 physical;       /* Physical address on device */
    u16 mirror_num;     /* Mirror number (for RAID) */
    u16 nr_sectors;     /* BTRFS_STRIPE_LEN / sectorsize */
    u16 nr_data_extents;
    u16 nr_meta_extents;
    atomic_t pending_io;
    wait_queue_head_t io_wait;
    wait_queue_head_t repair_wait;
    unsigned long state;  /* scrub_stripe_flags bits */

    /* Packed sub-bitmaps for error tracking */
    unsigned long bitmaps[BITS_TO_LONGS(
        scrub_bitmap_nr_last * (BTRFS_STRIPE_LEN / BTRFS_MIN_BLOCKSIZE))];

    unsigned long write_error_bitmap;
    spinlock_t write_error_lock;

    u8 *csums;           /* Checksum data for the entire stripe */
    struct work_struct work;
};
```

**Maximum folios per stripe:** `SCRUB_STRIPE_MAX_FOLIOS = BTRFS_STRIPE_LEN / PAGE_SIZE`

**Maximum sectors per block:** `SCRUB_MAX_SECTORS_PER_BLOCK = BTRFS_MAX_METADATA_BLOCKSIZE / SZ_4K`

### 13.4 Bitmap-Based Error Tracking

The scrub uses a packed bitmap system to efficiently track the state of
each sector within a stripe. Multiple sub-bitmaps are packed into a single
large bitmap:

```c
enum {
    scrub_bitmap_nr_has_extent = 0,    /* Sector is covered by an extent */
    scrub_bitmap_nr_is_metadata,       /* Sector belongs to metadata */
    scrub_bitmap_nr_error,             /* Any error (OR of all error types) */
    scrub_bitmap_nr_io_error,          /* I/O read error */
    scrub_bitmap_nr_csum_error,        /* Checksum mismatch */
    scrub_bitmap_nr_meta_error,        /* Metadata validation error */
    scrub_bitmap_nr_meta_gen_error,    /* Metadata generation mismatch */
    scrub_bitmap_nr_last,              /* Total number of sub-bitmaps */
};
```

Each sub-bitmap has `nr_sectors` bits. The starting bit for sub-bitmap
`name` at block `block_nr` is:

```c
#define scrub_calc_start_bit(stripe, name, block_nr) \
    (scrub_bitmap_nr_##name * stripe->nr_sectors + block_nr)
```

The bitmap operations are generated by macros:

```c
IMPLEMENT_SCRUB_BITMAP_OPS(has_extent)
IMPLEMENT_SCRUB_BITMAP_OPS(is_metadata)
IMPLEMENT_SCRUB_BITMAP_OPS(error)
IMPLEMENT_SCRUB_BITMAP_OPS(io_error)
IMPLEMENT_SCRUB_BITMAP_OPS(csum_error)
IMPLEMENT_SCRUB_BITMAP_OPS(meta_error)
IMPLEMENT_SCRUB_BITMAP_OPS(meta_gen_error)
```

Each `IMPLEMENT_SCRUB_BITMAP_OPS(name)` generates:
- `scrub_bitmap_set_##name(stripe, block_nr, nr_blocks)`
- `scrub_bitmap_clear_##name(stripe, block_nr, nr_blocks)`
- `scrub_bitmap_test_##name(stripe, block_nr)` (returns bool)

### 13.5 Stripe Flags

```c
enum scrub_stripe_flags {
    SCRUB_STRIPE_FLAG_INITIALIZED,  /* Metadata fields are set */
    SCRUB_STRIPE_FLAG_REPAIR_DONE,  /* Read-repair completed */
    SCRUB_STRIPE_FLAG_NO_REPORT,    /* Don't report errors (P/Q triggered) */
};
```

### 13.6 Scrub Context

```c
struct scrub_ctx {
    struct scrub_stripe   stripes[SCRUB_TOTAL_STRIPES];
    struct scrub_stripe   *raid56_data_stripes;
    struct btrfs_fs_info  *fs_info;
    struct btrfs_path     extent_path;
    struct btrfs_path     csum_path;
    int                   first_free;
    int                   cur_stripe;
    atomic_t              cancel_req;
    int                   readonly;

    /* I/O throttling */
    ktime_t               throttle_deadline;
    u64                   throttle_sent;

    bool                  is_dev_replace;
    u64                   write_pointer;

    struct mutex          wr_lock;
    struct btrfs_device   *wr_tgtdev;

    /* Statistics */
    struct btrfs_scrub_progress stat;
    spinlock_t            stat_lock;

    refcount_t            refs;
};
```

### 13.7 Scrub Algorithm

The scrub process for each device works as follows:

1. **Iterate over all block groups** assigned to the device.

2. **For each stripe in the block group:**
   a. Look up extent items in the extent tree to determine which sectors
      are data and which are metadata (`has_extent` and `is_metadata`
      bitmaps).
   b. For data sectors, look up expected checksums from the csum tree.
   c. For metadata sectors, determine the expected generation.

3. **Read the stripe** from the device.

4. **Verify each sector:**
   - For data: compute the checksum and compare with the expected value.
     Set `csum_error` bitmap on mismatch.
   - For metadata: verify the header checksum, fsid, bytenr, and
     generation. Set `meta_error` or `meta_gen_error` on failure.
   - Set `io_error` if the read itself failed.
   - Set the `error` bitmap as the OR of all error bitmaps.

5. **Repair (if possible):**
   - For RAID1/RAID10/RAID5/RAID6: read the sector from another mirror.
   - If a good copy is found, write it back to the corrupted location.
   - Update the `write_error_bitmap` if the repair write fails.

6. **Report statistics** via `btrfs_scrub_progress`.

### 13.8 Verification Details

For data sectors, the checksum algorithm depends on the filesystem's
configured checksum type (stored in the superblock). Common algorithms:
- **crc32c** (default, type 1)
- **xxhash** (type 2)
- **sha256** (type 3)
- **blake2b** (type 4)

For metadata blocks, verification includes:
1. Checksum of the entire block (after the checksum field) matches.
2. The `fsid` in the header matches the filesystem's UUID.
3. The `bytenr` in the header matches the block's actual position on disk.
4. The `generation` does not exceed the filesystem's current generation.

---

## 14. Summary of Key Constants and Magic Numbers

### ext4

| Constant | Value | Location |
|----------|-------|----------|
| Superblock offset | 1024 bytes | Always |
| Superblock magic | 0xEF53 | Offset 0x038 |
| Extent magic | 0xF30A | Extent header |
| Xattr magic | 0xEA020000 | Xattr header |
| Orphan block magic | 0x0B10CA04 | Orphan tail |
| Dir entry checksum type | 0xDE | dir_entry_tail |
| Good old inode size | 128 bytes | `EXT4_GOOD_OLD_INODE_SIZE` |
| Max block size | 65536 | `EXT4_MAX_BLOCK_SIZE` |
| Min block size | 1024 | `EXT4_MIN_BLOCK_SIZE` |
| Max extent depth | 5 | `EXT4_MAX_EXTENT_DEPTH` |
| Max link count | 65000 | `EXT4_LINK_MAX` |
| First non-reserved inode | 11 | `EXT4_GOOD_OLD_FIRST_INO` |
| Root inode | 2 | `EXT4_ROOT_INO` |
| Journal inode | 8 | `EXT4_JOURNAL_INO` |
| Extent init max len | 32768 | `EXT_INIT_MAX_LEN` |
| Extent unwritten max len | 32767 | `EXT_UNWRITTEN_MAX_LEN` |
| Group desc min size | 32 bytes | `EXT4_MIN_DESC_SIZE` |
| Group desc 64-bit min | 64 bytes | `EXT4_MIN_DESC_SIZE_64BIT` |
| Max N_BLOCKS | 15 | `EXT4_N_BLOCKS` |

### btrfs

| Constant | Value | Location |
|----------|-------|----------|
| Superblock offset | 65536 (0x10000) | `BTRFS_SUPER_INFO_OFFSET` |
| Max tree level | 8 | `BTRFS_MAX_LEVEL` |
| Key size | 17 bytes | `btrfs_key` |
| Header size | 101 bytes | `btrfs_header` |
| Item header size | 25 bytes | `btrfs_item` |
| Key-pointer size | 33 bytes | `btrfs_key_ptr` |
| Super mirror max | 3 | `BTRFS_SUPER_MIRROR_MAX` |
| Super mirror shift | 12 | `BTRFS_SUPER_MIRROR_SHIFT` |
| Stripe length | 65536 (64KB) | `BTRFS_STRIPE_LEN` |
| Default nodesize | 16384 (16KB) | Typical |
| Default sectorsize | 4096 | Typical |

---

## 15. Cross-Reference: Structural Comparison

### Metadata Organization

| Aspect | ext4 | btrfs |
|--------|------|-------|
| Allocation unit | Block group (fixed) | Chunk/block group (dynamic) |
| Index structure | Extent tree (per-inode) | B-tree (per-tree) |
| Free space tracking | Bitmaps + buddy | Free space tree or cache |
| Checksum algorithm | crc32c only | crc32c, xxhash, sha256, blake2b |
| Journal/COW | JBD2 journal | Copy-on-write |
| Snapshot support | None | Native (via COW) |
| Inode storage | Fixed table per group | B-tree items |
| Directory format | Linear + htree | B-tree items |

### Update Semantics

| Aspect | ext4 | btrfs |
|--------|------|-------|
| Write model | Journal-then-write | Copy-on-write |
| Atomicity scope | Transaction (handle) | Transaction |
| Crash recovery | Journal replay | Tree root rollback |
| Data integrity | Ordered/journal/writeback | COW + checksums |
| In-place update | Yes (journaled) | Never (COW) |
| Reference counting | None (fixed locations) | Extent backrefs |

### Addressing

| Aspect | ext4 | btrfs |
|--------|------|-------|
| Block addressing | 48-bit (16-bit + 32-bit split) | 64-bit logical |
| Inode addressing | Group + offset in table | B-tree key lookup |
| Max filesystem size | 1 EB (64-bit blocks) | 16 EB |
| Max file size | 16 TB (32-bit logical blocks) | 16 EB |

---

## 16. Behavioral Notes for FrankenFS Implementation

### 16.1 ext4 On-Disk Layout Invariants

1. The superblock is always at byte offset 1024, regardless of block size.
2. Block group 0 always contains the superblock, group descriptors, and
   (potentially) the journal.
3. Group descriptors immediately follow the superblock block.
4. Inode 0 is never used; inode 1 is bad blocks; inode 2 is root.
5. The extent tree root always occupies exactly 60 bytes in the inode.
6. Extent tree entries and index entries are both exactly 12 bytes.
7. The extent header magic 0xF30A must be present at the start of every
   extent tree node.
8. Directory entries must be 4-byte aligned (rec_len is always multiple of 4).
9. The last directory entry in a block has rec_len extending to block end.
10. All checksums use crc32c with a seed derived from the filesystem UUID.

### 16.2 btrfs Behavioral Invariants

1. No block is ever modified in place; all updates go through COW.
2. The generation number in tree node headers must match the transaction
   that last modified the node.
3. The `bytenr` in a tree node header must match the node's actual
   position on disk.
4. All tree operations (search, insert, delete) start with the root and
   traverse downward, COWing as needed.
5. Leaf data grows from the end of the node backward; item headers grow
   from after the node header forward.
6. Key comparison is strictly lexicographic on (objectid, type, offset).
7. The superblock has copies at offsets 0x10000, 0x4000000, and
   0x4000000000 (64KB, 64MB, 256GB).
8. Tree block checksums cover everything after the checksum field itself.
9. Each subvolume is an independent B-tree sharing blocks with other
   subvolumes via reference counting.
10. Scrub verifies all allocated extents against their checksums and can
    repair from redundant copies in RAID configurations.
11. A logical read must be split at chunk boundaries and, for striped
    profiles, stripe boundaries. A physical mapping describes only the
    contiguous bytes before the next such boundary, not the entire request.
    Each segment must return exactly its requested length; a short mirror
    read is a failed attempt and may fall back to another copy of that segment.
    RAID5/6 parity is not a readable mirror and requires separate reconstruction.

### 16.3 Key Implementation Patterns

#### ext4 Block Address Reconstruction

The split 48-bit addressing pattern (16-bit high + 32-bit low) appears in:
- Extent entries: `ee_start_hi` (16) + `ee_start_lo` (32)
- Index entries: `ei_leaf_hi` (16) + `ei_leaf_lo` (32)
- Group descriptors: `bg_*_hi` (32) + `bg_*_lo` (32) for 64-bit addressing
- Superblock: `s_blocks_count_hi` (32) + `s_blocks_count_lo` (32)

```c
/* Generic pattern for 48-bit block address reconstruction */
block = lo_32bit | (((ext4_fsblk_t) hi_16bit << 31) << 1);
```

The `<< 31 << 1` pattern (instead of `<< 32`) avoids undefined behavior
in C when shifting a 16-bit value by 32 bits.

#### btrfs Accessor Pattern

All on-disk structure fields in btrfs are accessed through generated
accessor functions that handle endianness and cross-page reads:

```c
/* For fields in extent buffers (tree nodes) */
BTRFS_SETGET_FUNCS(name, type, member, bits)

/* For header fields (first page only, fast path) */
BTRFS_SETGET_HEADER_FUNCS(name, type, member, bits)

/* For stack-allocated structures */
BTRFS_SETGET_STACK_FUNCS(name, type, member, bits)
```

This pattern ensures correct access regardless of the structure's alignment
within the extent buffer and handles the case where a field spans two
memory pages.

---

*End of Behavioral Extraction Spec*
