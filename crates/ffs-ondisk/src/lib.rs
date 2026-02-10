#![forbid(unsafe_code)]
//! On-disk format parsing for ext4 and btrfs structures.
//!
//! Pure parsing crate — no I/O, no side effects. Parses byte slices into
//! typed Rust structures representing ext4 superblocks, group descriptors,
//! inodes, extent trees, directory entries, JBD2 journal structures, and
//! btrfs superblocks, headers, and leaf item tables.

pub mod btrfs;
pub mod ext4;

pub use btrfs::{BtrfsHeader, BtrfsItem, BtrfsKey, BtrfsSuperblock, parse_leaf_items};
pub use ext4::{
    Ext4CompatFeatures, Ext4DirEntry, Ext4DirEntryTail, Ext4Extent, Ext4ExtentHeader,
    Ext4ExtentIndex, Ext4FileType, Ext4GroupDesc, Ext4ImageReader, Ext4IncompatFeatures, Ext4Inode,
    Ext4RoCompatFeatures, Ext4Superblock, ExtentTree, lookup_in_dir_block, parse_dir_block,
    parse_extent_tree, parse_inode_extent_tree, verify_group_desc_checksum, verify_inode_checksum,
};
