#![forbid(unsafe_code)]
//! On-disk format parsing for ext4 and btrfs structures.
//!
//! Pure parsing crate — no I/O, no side effects. Parses byte slices into
//! typed Rust structures representing ext4 superblocks, group descriptors,
//! inodes, extent trees, directory entries, and ext4 journal-related
//! superblock fields, plus btrfs superblocks, headers, leaf item tables,
//! and internal node key-pointers.

pub mod btrfs;
pub mod crc_incremental;
pub mod ext4;

pub use btrfs::{
    BTRFS_CSUM_FIELD_SIZE, BtrfsChunkEntry, BtrfsCompatRoFeatures, BtrfsDevItem, BtrfsHeader,
    BtrfsIncompatFeatures, BtrfsItem, BtrfsKey, BtrfsKeyPtr, BtrfsPhysicalMapping,
    BtrfsRaidProfile, BtrfsStripe, BtrfsStripeMapping, BtrfsSuperblock, btrfs_csum,
    btrfs_csum_size, chunk_type_flags, map_logical_to_physical, map_logical_to_stripes,
    parse_dev_item, parse_internal_items, parse_leaf_items, parse_sys_chunk_array,
    verify_superblock_checksum as verify_btrfs_superblock_checksum,
    verify_tree_block_checksum as verify_btrfs_tree_block_checksum,
};
pub use ext4::{
    DX_NODE_COUNT_OFFSET, DX_ROOT_COUNT_OFFSET, DirBlockIter, EXT_INIT_MAX_LEN, EXT4_BAD_INO,
    EXT4_BG_BLOCK_UNINIT, EXT4_BG_INODE_UNINIT, EXT4_BG_INODE_ZEROED, EXT4_BOOT_LOADER_INO,
    EXT4_DYNAMIC_REV, EXT4_ERROR_FS, EXT4_EXCLUDE_INO, EXT4_FT_BLKDEV, EXT4_FT_CHRDEV, EXT4_FT_DIR,
    EXT4_FT_DIR_CSUM, EXT4_FT_FIFO, EXT4_FT_MAX, EXT4_FT_REG_FILE, EXT4_FT_SOCK, EXT4_FT_SYMLINK,
    EXT4_FT_UNKNOWN, EXT4_GOOD_OLD_FIRST_INO, EXT4_GOOD_OLD_INODE_SIZE, EXT4_GOOD_OLD_REV,
    EXT4_GRP_QUOTA_INO, EXT4_JOURNAL_INO, EXT4_MAX_NAME_BYTES, EXT4_ORPHAN_FS, EXT4_PRJ_QUOTA_INO,
    EXT4_REPLICA_INO, EXT4_RESIZE_INO, EXT4_ROOT_INO, EXT4_UNDEL_DIR_INO, EXT4_USR_QUOTA_INO,
    EXT4_VALID_FS, Ext4CasefoldEncoding, Ext4CasefoldNameDiagnostics, Ext4CompatFeatures,
    Ext4DirEntry, Ext4DirEntryRef, Ext4DirEntryTail, Ext4DxEntry, Ext4DxRoot, Ext4Extent,
    Ext4ExtentHeader, Ext4ExtentIndex, Ext4FileType, Ext4GroupDesc, Ext4GroupDescChecksumKind,
    Ext4ImageReader, Ext4IncompatFeatures, Ext4Inode, Ext4MmpBlock, Ext4MmpStatus,
    Ext4RoCompatFeatures, Ext4Superblock, Ext4Xattr, ExtentTree, FeatureDiagnostics,
    HtreeFindResult, HtreeLeafSplit, HtreeSplitFallback, InodeLocation, build_htree_directory,
    build_htree_directory_for_rebuild, build_htree_directory_stamped,
    build_htree_directory_stamped_with_large_dir,
    build_htree_directory_stamped_with_large_dir_casefold, build_htree_directory_with_large_dir,
    build_htree_directory_with_large_dir_casefold, choose_htree_leaf_split, dir_entry_rec_len,
    dx_hash, dx_root_entry_limit, ext4_casefold_key, ext4_casefold_name_diagnostics,
    ext4_casefold_names_collide, ext4_chksum, ext4_dx_block_csum, ext4_xattr_block_csum,
    find_ibody_xattr_by_index_name, find_ibody_xattr_by_name, find_xattr_block_value_by_index_name,
    find_xattr_block_value_by_name, htree_find_entry, htree_find_entry_casefold,
    htree_leaf_logical_blocks, htree_target_leaf_block, htree_target_leaf_block_casefold,
    is_reserved_inode, iter_dir_block, lookup_in_dir_block, lookup_in_dir_block_casefold,
    pack_dir_block_entries, parse_dir_block, parse_dx_root, parse_extent_tree,
    parse_ibody_xattr_names, parse_ibody_xattrs, parse_ibody_xattrs_with_inum,
    parse_inode_extent_tree, parse_xattr_block, parse_xattr_block_names,
    parse_xattr_block_with_inum, split_htree_leaf, stamp_block_bitmap_checksum,
    stamp_dir_block_checksum, stamp_dx_block_checksum, stamp_extent_block_checksum,
    stamp_group_desc_checksum, stamp_inode_bitmap_checksum, stamp_xattr_block_checksum,
    verify_block_bitmap_checksum, verify_dir_block_checksum, verify_dx_block_checksum,
    verify_extent_block_checksum, verify_group_desc_checksum, verify_inode_bitmap_checksum,
    verify_inode_checksum, verify_xattr_block_checksum, write_dx_root,
};
