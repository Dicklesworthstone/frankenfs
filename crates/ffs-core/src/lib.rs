#![forbid(unsafe_code)]

use asupersync::{Cx, RaptorQConfig};
use ffs_block::{
    ByteDevice, FileByteDevice, read_btrfs_superblock_region, read_ext4_superblock_region,
};
use ffs_btrfs::{BtrfsLeafEntry, walk_tree};
use ffs_error::FfsError;
use ffs_mvcc::{CommitError, MvccStore, Transaction};
use ffs_ondisk::{
    BtrfsChunkEntry, BtrfsSuperblock, Ext4DirEntry, Ext4Extent, Ext4FileType, Ext4GroupDesc,
    Ext4ImageReader, Ext4Inode, Ext4Superblock, Ext4Xattr, ExtentTree, lookup_in_dir_block,
    parse_dir_block, parse_extent_tree, parse_inode_extent_tree, parse_sys_chunk_array,
};
use ffs_types::{
    BlockNumber, ByteOffset, CommitSeq, GroupNumber, InodeNumber, ParseError, Snapshot, TxnId,
};
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::path::Path;
use std::time::SystemTime;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FsFlavor {
    Ext4(Ext4Superblock),
    Btrfs(BtrfsSuperblock),
}

#[derive(Debug, Error)]
pub enum DetectionError {
    #[error("image does not decode as supported ext4/btrfs superblock")]
    UnsupportedImage,
    #[error("I/O error while probing image: {0}")]
    Io(#[from] FfsError),
}

pub fn detect_filesystem(image: &[u8]) -> Result<FsFlavor, DetectionError> {
    if let Ok(ext4) = Ext4Superblock::parse_from_image(image) {
        return Ok(FsFlavor::Ext4(ext4));
    }

    if let Ok(btrfs) = BtrfsSuperblock::parse_from_image(image) {
        return Ok(FsFlavor::Btrfs(btrfs));
    }

    Err(DetectionError::UnsupportedImage)
}

pub fn detect_filesystem_on_device(
    cx: &Cx,
    dev: &dyn ByteDevice,
) -> Result<FsFlavor, DetectionError> {
    let len = dev.len_bytes();

    let ext4_end =
        u64::try_from(ffs_types::EXT4_SUPERBLOCK_OFFSET + ffs_types::EXT4_SUPERBLOCK_SIZE)
            .map_err(|_| FfsError::Format("ext4 superblock end offset overflows u64".to_owned()))?;
    if len >= ext4_end {
        let ext4_region = read_ext4_superblock_region(cx, dev)?;
        if let Ok(sb) = Ext4Superblock::parse_superblock_region(&ext4_region) {
            return Ok(FsFlavor::Ext4(sb));
        }
    }

    let btrfs_end =
        u64::try_from(ffs_types::BTRFS_SUPER_INFO_OFFSET + ffs_types::BTRFS_SUPER_INFO_SIZE)
            .map_err(|_| {
                FfsError::Format("btrfs superblock end offset overflows u64".to_owned())
            })?;
    if len >= btrfs_end {
        let btrfs_region = read_btrfs_superblock_region(cx, dev)?;
        if let Ok(sb) = BtrfsSuperblock::parse_superblock_region(&btrfs_region) {
            return Ok(FsFlavor::Btrfs(sb));
        }
    }

    Err(DetectionError::UnsupportedImage)
}

pub fn detect_filesystem_at_path(
    cx: &Cx,
    path: impl AsRef<Path>,
) -> Result<FsFlavor, DetectionError> {
    let dev = FileByteDevice::open(path)?;
    detect_filesystem_on_device(cx, &dev)
}

// ── OpenFs API ──────────────────────────────────────────────────────────────

/// Options controlling how a filesystem image is opened.
///
/// By default, mount-time validation is enabled. Disable it only for
/// recovery or diagnostic workflows where reading a partially-corrupt
/// image is intentional.
#[derive(Debug, Clone)]
pub struct OpenOptions {
    /// Skip mount-time validation (geometry, features, checksums).
    ///
    /// When `true`, the superblock is parsed but not validated via
    /// `validate_v1()`. Use for recovery or diagnostics only.
    pub skip_validation: bool,
}

#[allow(clippy::derivable_impls)]
impl Default for OpenOptions {
    fn default() -> Self {
        Self {
            skip_validation: false,
        }
    }
}

/// Pre-computed ext4 geometry derived from the superblock.
///
/// These values are computed once at open time and cached so that
/// downstream code does not re-derive them on every operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ext4Geometry {
    /// Block size in bytes (1024, 2048, or 4096 for v1).
    pub block_size: u32,
    /// Total number of inodes.
    pub inodes_count: u32,
    /// Number of inodes per block group.
    pub inodes_per_group: u32,
    /// First non-reserved inode number.
    pub first_ino: u32,
    /// On-disk inode structure size in bytes.
    pub inode_size: u16,
    /// Number of block groups.
    pub groups_count: u32,
    /// Size of each group descriptor (32 or 64 bytes).
    pub group_desc_size: u16,
    /// Checksum seed for metadata_csum verification.
    pub csum_seed: u32,
    /// Whether the filesystem uses 64-bit block addressing.
    pub is_64bit: bool,
    /// Whether metadata_csum is enabled.
    pub has_metadata_csum: bool,
}

/// Pre-computed btrfs context derived from the superblock.
///
/// Contains the parsed sys_chunk logical-to-physical mapping and the node
/// size, computed once at open time so that tree-walk operations do not
/// re-parse the chunk array on every call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BtrfsContext {
    /// Parsed sys_chunk logical-to-physical mapping entries.
    pub chunks: Vec<BtrfsChunkEntry>,
    /// Tree node size in bytes.
    pub nodesize: u32,
}

/// An opened filesystem image, ready for VFS operations.
///
/// `OpenFs` bundles a validated superblock, pre-computed geometry, and the
/// block device handle into a single context. The constructor validates by
/// default so callers cannot accidentally operate on unvalidated metadata.
///
/// # Opening a filesystem
///
/// ```ignore
/// let cx = Cx::for_request();
/// let fs = OpenFs::open(&cx, "/path/to/image.ext4")?;
/// println!("block_size = {}", fs.block_size());
/// ```
pub struct OpenFs {
    /// Detected filesystem type with parsed superblock.
    pub flavor: FsFlavor,
    /// Pre-computed ext4 geometry (None for btrfs).
    pub ext4_geometry: Option<Ext4Geometry>,
    /// Pre-computed btrfs context (None for ext4).
    pub btrfs_context: Option<BtrfsContext>,
    /// Block device for I/O operations.
    dev: Box<dyn ByteDevice>,
}

impl std::fmt::Debug for OpenFs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenFs")
            .field("flavor", &self.flavor)
            .field("ext4_geometry", &self.ext4_geometry)
            .field("btrfs_context", &self.btrfs_context)
            .field("dev_len", &self.dev.len_bytes())
            .finish()
    }
}

impl OpenFs {
    /// Open a filesystem image at `path` with default options (validation enabled).
    pub fn open(cx: &Cx, path: impl AsRef<Path>) -> Result<Self, FfsError> {
        Self::open_with_options(cx, path, &OpenOptions::default())
    }

    /// Open a filesystem image with custom options.
    pub fn open_with_options(
        cx: &Cx,
        path: impl AsRef<Path>,
        options: &OpenOptions,
    ) -> Result<Self, FfsError> {
        let dev = FileByteDevice::open(path.as_ref())?;
        Self::from_device(cx, Box::new(dev), options)
    }

    /// Open a filesystem from an already-opened device.
    pub fn from_device(
        cx: &Cx,
        dev: Box<dyn ByteDevice>,
        options: &OpenOptions,
    ) -> Result<Self, FfsError> {
        let flavor = detect_filesystem_on_device(cx, &*dev).map_err(|e| match e {
            DetectionError::UnsupportedImage => {
                FfsError::Format("image is not a recognized ext4 or btrfs filesystem".into())
            }
            DetectionError::Io(ffs_err) => ffs_err,
        })?;

        let (ext4_geometry, btrfs_context) = match &flavor {
            FsFlavor::Ext4(sb) => {
                if !options.skip_validation {
                    sb.validate_v1().map_err(|e| parse_error_to_ffs(&e))?;
                }
                let geom = Ext4Geometry {
                    block_size: sb.block_size,
                    inodes_count: sb.inodes_count,
                    inodes_per_group: sb.inodes_per_group,
                    first_ino: sb.first_ino,
                    inode_size: sb.inode_size,
                    groups_count: sb.groups_count(),
                    group_desc_size: sb.group_desc_size(),
                    csum_seed: sb.csum_seed(),
                    is_64bit: sb.is_64bit(),
                    has_metadata_csum: sb.has_metadata_csum(),
                };
                (Some(geom), None)
            }
            FsFlavor::Btrfs(sb) => {
                if !options.skip_validation {
                    validate_btrfs_superblock(sb)?;
                }
                let chunks = parse_sys_chunk_array(&sb.sys_chunk_array)
                    .map_err(|e| parse_to_ffs_error(&e))?;
                let ctx = BtrfsContext {
                    chunks,
                    nodesize: sb.nodesize,
                };
                (None, Some(ctx))
            }
        };

        Ok(Self {
            flavor,
            ext4_geometry,
            btrfs_context,
            dev,
        })
    }

    /// The block device backing this filesystem.
    #[must_use]
    pub fn device(&self) -> &dyn ByteDevice {
        &*self.dev
    }

    /// Block size in bytes.
    #[must_use]
    pub fn block_size(&self) -> u32 {
        match &self.flavor {
            FsFlavor::Ext4(sb) => sb.block_size,
            FsFlavor::Btrfs(sb) => sb.sectorsize,
        }
    }

    /// Whether this is an ext4 filesystem.
    #[must_use]
    pub fn is_ext4(&self) -> bool {
        matches!(self.flavor, FsFlavor::Ext4(_))
    }

    /// Whether this is a btrfs filesystem.
    #[must_use]
    pub fn is_btrfs(&self) -> bool {
        matches!(self.flavor, FsFlavor::Btrfs(_))
    }

    /// Device length in bytes.
    #[must_use]
    pub fn device_len(&self) -> u64 {
        self.dev.len_bytes()
    }

    /// Return the ext4 superblock, or `None` if this is not ext4.
    #[must_use]
    pub fn ext4_superblock(&self) -> Option<&Ext4Superblock> {
        match &self.flavor {
            FsFlavor::Ext4(sb) => Some(sb),
            FsFlavor::Btrfs(_) => None,
        }
    }

    /// Return the btrfs superblock, or `None` if this is not btrfs.
    #[must_use]
    pub fn btrfs_superblock(&self) -> Option<&BtrfsSuperblock> {
        match &self.flavor {
            FsFlavor::Btrfs(sb) => Some(sb),
            FsFlavor::Ext4(_) => None,
        }
    }

    /// Return the btrfs context (chunk mapping + nodesize), or `None` if not btrfs.
    #[must_use]
    pub fn btrfs_context(&self) -> Option<&BtrfsContext> {
        self.btrfs_context.as_ref()
    }

    // ── Btrfs tree-walk via device ───────────────────────────────────

    /// Walk a btrfs tree from the given logical root, reading nodes via the device.
    ///
    /// Uses the sys_chunk logical-to-physical mapping to translate addresses,
    /// then reads each node from the block device. Returns all leaf items in
    /// key order (left-to-right DFS).
    ///
    /// Returns `FfsError::Format` if this is not a btrfs filesystem.
    pub fn walk_btrfs_tree(
        &self,
        cx: &Cx,
        root_logical: u64,
    ) -> Result<Vec<BtrfsLeafEntry>, FfsError> {
        let ctx = self
            .btrfs_context()
            .ok_or_else(|| FfsError::Format("not a btrfs filesystem".into()))?;

        let nodesize = ctx.nodesize;
        let ns =
            usize::try_from(nodesize).map_err(|_| FfsError::Format("nodesize overflow".into()))?;

        let mut read_fn = |phys: u64| -> Result<Vec<u8>, ParseError> {
            let mut buf = vec![0_u8; ns];
            self.dev
                .read_exact_at(cx, ByteOffset(phys), &mut buf)
                .map_err(|_| ParseError::InsufficientData {
                    needed: ns,
                    offset: 0,
                    actual: 0,
                })?;
            Ok(buf)
        };

        walk_tree(&mut read_fn, &ctx.chunks, root_logical, nodesize)
            .map_err(|e| parse_to_ffs_error(&e))
    }

    /// Walk the btrfs root tree, returning all leaf items.
    ///
    /// Convenience wrapper around [`walk_btrfs_tree`](Self::walk_btrfs_tree)
    /// that uses the superblock's `root` address.
    pub fn walk_btrfs_root_tree(&self, cx: &Cx) -> Result<Vec<BtrfsLeafEntry>, FfsError> {
        let sb = self
            .btrfs_superblock()
            .ok_or_else(|| FfsError::Format("not a btrfs filesystem".into()))?;
        self.walk_btrfs_tree(cx, sb.root)
    }

    /// Read a group descriptor via the device.
    ///
    /// Returns `FfsError::Format` if this is not an ext4 filesystem.
    pub fn read_group_desc(&self, cx: &Cx, group: GroupNumber) -> Result<Ext4GroupDesc, FfsError> {
        let sb = self
            .ext4_superblock()
            .ok_or_else(|| FfsError::Format("not an ext4 filesystem".into()))?;
        let desc_size = sb.group_desc_size();
        let offset = sb
            .group_desc_offset(group)
            .ok_or_else(|| FfsError::InvalidGeometry("group desc offset overflow".into()))?;

        let mut buf = vec![0_u8; usize::from(desc_size)];
        self.dev.read_exact_at(cx, ByteOffset(offset), &mut buf)?;
        Ext4GroupDesc::parse_from_bytes(&buf, desc_size).map_err(|e| parse_to_ffs_error(&e))
    }

    /// Read an ext4 inode by number via the device.
    ///
    /// Uses [`Ext4Superblock::locate_inode`] and [`Ext4Superblock::inode_device_offset`]
    /// to compute the on-disk position, reads the group descriptor for the
    /// inode table pointer, then reads and parses the inode.
    pub fn read_inode(&self, cx: &Cx, ino: InodeNumber) -> Result<Ext4Inode, FfsError> {
        let sb = self
            .ext4_superblock()
            .ok_or_else(|| FfsError::Format("not an ext4 filesystem".into()))?;

        let loc = sb.locate_inode(ino).map_err(|e| parse_to_ffs_error(&e))?;
        let gd = self.read_group_desc(cx, loc.group)?;
        let abs_offset = sb
            .inode_device_offset(&loc, gd.inode_table)
            .map_err(|e| parse_to_ffs_error(&e))?;

        let inode_size = usize::from(sb.inode_size);
        let mut buf = vec![0_u8; inode_size];
        self.dev
            .read_exact_at(cx, ByteOffset(abs_offset), &mut buf)?;
        Ext4Inode::parse_from_bytes(&buf).map_err(|e| parse_to_ffs_error(&e))
    }

    /// Read an ext4 inode and return its VFS attributes.
    pub fn read_inode_attr(&self, cx: &Cx, ino: InodeNumber) -> Result<InodeAttr, FfsError> {
        let sb = self
            .ext4_superblock()
            .ok_or_else(|| FfsError::Format("not an ext4 filesystem".into()))?;
        let inode = self.read_inode(cx, ino)?;
        Ok(inode_to_attr(sb, ino, &inode))
    }

    // ── Extent mapping via device ─────────────────────────────────────

    /// Maximum extent tree depth (ext4 kernel limit).
    const MAX_EXTENT_DEPTH: u16 = 5;

    /// Read a full filesystem block from the device.
    #[allow(clippy::cast_possible_truncation)] // block_size is u32, always fits usize
    fn read_block_vec(&self, cx: &Cx, block: BlockNumber) -> Result<Vec<u8>, FfsError> {
        let bs = u64::from(self.block_size());
        let offset = block
            .0
            .checked_mul(bs)
            .ok_or_else(|| FfsError::Corruption {
                block: block.0,
                detail: "block offset overflow".into(),
            })?;
        let mut buf = vec![0_u8; self.block_size() as usize];
        self.dev.read_exact_at(cx, ByteOffset(offset), &mut buf)?;
        Ok(buf)
    }

    /// Resolve a logical file block to a physical block number via the inode's
    /// extent tree, reading index blocks from the device as needed.
    ///
    /// Returns `Ok(None)` if the logical block falls in a hole (no mapping).
    pub fn resolve_extent(
        &self,
        cx: &Cx,
        inode: &Ext4Inode,
        logical_block: u32,
    ) -> Result<Option<u64>, FfsError> {
        let (header, tree) = parse_inode_extent_tree(inode).map_err(|e| parse_to_ffs_error(&e))?;
        self.walk_extent_tree(cx, &tree, logical_block, header.depth)
    }

    fn walk_extent_tree(
        &self,
        cx: &Cx,
        tree: &ExtentTree,
        logical_block: u32,
        remaining_depth: u16,
    ) -> Result<Option<u64>, FfsError> {
        if remaining_depth > Self::MAX_EXTENT_DEPTH {
            return Err(FfsError::Corruption {
                block: 0,
                detail: "extent tree depth exceeds maximum".into(),
            });
        }

        match tree {
            ExtentTree::Leaf(extents) => {
                for ext in extents {
                    let start = ext.logical_block;
                    let len = u32::from(ext.actual_len());
                    if logical_block >= start && logical_block < start.saturating_add(len) {
                        let offset_within = u64::from(logical_block - start);
                        return Ok(Some(ext.physical_start + offset_within));
                    }
                }
                Ok(None)
            }
            ExtentTree::Index(indexes) => {
                if remaining_depth == 0 {
                    return Err(FfsError::Corruption {
                        block: 0,
                        detail: "extent index at depth 0".into(),
                    });
                }
                let mut chosen: Option<usize> = None;
                for (i, idx) in indexes.iter().enumerate() {
                    if idx.logical_block <= logical_block {
                        chosen = Some(i);
                    } else {
                        break;
                    }
                }
                let Some(i) = chosen else {
                    return Ok(None);
                };
                let idx = &indexes[i];

                let child_data = self.read_block_vec(cx, BlockNumber(idx.leaf_block))?;
                let (child_header, child_tree) =
                    parse_extent_tree(&child_data).map_err(|e| parse_to_ffs_error(&e))?;

                if child_header.depth + 1 != remaining_depth {
                    return Err(FfsError::Corruption {
                        block: idx.leaf_block,
                        detail: "child extent tree depth inconsistency".into(),
                    });
                }

                self.walk_extent_tree(cx, &child_tree, logical_block, remaining_depth - 1)
            }
        }
    }

    /// Collect all leaf extents for an inode, flattening multi-level trees.
    ///
    /// Returns extents in tree-traversal order (sorted by logical block).
    pub fn collect_extents(&self, cx: &Cx, inode: &Ext4Inode) -> Result<Vec<Ext4Extent>, FfsError> {
        let (header, tree) = parse_inode_extent_tree(inode).map_err(|e| parse_to_ffs_error(&e))?;
        let mut result = Vec::new();
        self.collect_extents_recursive(cx, &tree, header.depth, &mut result)?;
        Ok(result)
    }

    fn collect_extents_recursive(
        &self,
        cx: &Cx,
        tree: &ExtentTree,
        remaining_depth: u16,
        result: &mut Vec<Ext4Extent>,
    ) -> Result<(), FfsError> {
        if remaining_depth > Self::MAX_EXTENT_DEPTH {
            return Err(FfsError::Corruption {
                block: 0,
                detail: "extent tree depth exceeds maximum".into(),
            });
        }

        match tree {
            ExtentTree::Leaf(extents) => {
                result.extend_from_slice(extents);
                Ok(())
            }
            ExtentTree::Index(indexes) => {
                if remaining_depth == 0 {
                    return Err(FfsError::Corruption {
                        block: 0,
                        detail: "extent index at depth 0".into(),
                    });
                }
                for idx in indexes {
                    let child_data = self.read_block_vec(cx, BlockNumber(idx.leaf_block))?;
                    let (child_header, child_tree) =
                        parse_extent_tree(&child_data).map_err(|e| parse_to_ffs_error(&e))?;
                    if child_header.depth + 1 != remaining_depth {
                        return Err(FfsError::Corruption {
                            block: idx.leaf_block,
                            detail: "child extent tree depth inconsistency".into(),
                        });
                    }
                    self.collect_extents_recursive(cx, &child_tree, remaining_depth - 1, result)?;
                }
                Ok(())
            }
        }
    }

    /// Read file data using extent mapping via the device.
    ///
    /// Resolves each logical block through the extent tree and reads the
    /// corresponding physical blocks from the device. Holes are filled
    /// with zeroes. Returns the number of bytes actually read.
    #[allow(clippy::cast_possible_truncation)]
    pub fn read_file_data(
        &self,
        cx: &Cx,
        inode: &Ext4Inode,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, FfsError> {
        let file_size = inode.size;
        if offset >= file_size {
            return Ok(0);
        }

        let available = file_size - offset;
        let to_read = usize::try_from(available.min(buf.len() as u64)).unwrap_or(buf.len());

        let bs = u64::from(self.block_size());
        let bs_usize = self.block_size() as usize;
        let mut bytes_read = 0_usize;

        while bytes_read < to_read {
            let current_offset = offset + bytes_read as u64;
            let logical_block =
                u32::try_from(current_offset / bs).map_err(|_| FfsError::Corruption {
                    block: 0,
                    detail: "logical block number overflow".into(),
                })?;
            let offset_in_block = (current_offset % bs) as usize;
            let remaining_in_block = bs_usize - offset_in_block;
            let chunk_size = remaining_in_block.min(to_read - bytes_read);

            match self.resolve_extent(cx, inode, logical_block)? {
                Some(phys_block) => {
                    let block_data = self.read_block_vec(cx, BlockNumber(phys_block))?;
                    buf[bytes_read..bytes_read + chunk_size].copy_from_slice(
                        &block_data[offset_in_block..offset_in_block + chunk_size],
                    );
                }
                None => {
                    buf[bytes_read..bytes_read + chunk_size].fill(0);
                }
            }

            bytes_read += chunk_size;
        }

        Ok(bytes_read)
    }

    // ── Directory operations via device ───────────────────────────────

    /// Read all directory entries from a directory inode via the device.
    ///
    /// Iterates over the inode's data blocks via extent mapping, reading
    /// each block from the device and parsing directory entries.
    pub fn read_dir(&self, cx: &Cx, inode: &Ext4Inode) -> Result<Vec<Ext4DirEntry>, FfsError> {
        let bs = u64::from(self.block_size());
        let num_blocks = dir_logical_block_count(inode.size, bs)?;

        let mut all_entries = Vec::new();

        for lb in 0..num_blocks {
            if let Some(phys) = self.resolve_extent(cx, inode, lb)? {
                let block_data = self.read_block_vec(cx, BlockNumber(phys))?;
                let (entries, _tail) = parse_dir_block(&block_data, self.block_size())
                    .map_err(|e| parse_to_ffs_error(&e))?;
                all_entries.extend(entries);
            }
        }

        Ok(all_entries)
    }

    /// Look up a single name in a directory inode via the device.
    ///
    /// Returns the matching `Ext4DirEntry` if found, `None` otherwise.
    pub fn lookup_name(
        &self,
        cx: &Cx,
        dir_inode: &Ext4Inode,
        name: &[u8],
    ) -> Result<Option<Ext4DirEntry>, FfsError> {
        let bs = u64::from(self.block_size());
        let num_blocks = dir_logical_block_count(dir_inode.size, bs)?;

        for lb in 0..num_blocks {
            if let Some(phys) = self.resolve_extent(cx, dir_inode, lb)? {
                let block_data = self.read_block_vec(cx, BlockNumber(phys))?;
                if let Some(entry) = lookup_in_dir_block(&block_data, self.block_size(), name) {
                    return Ok(Some(entry));
                }
            }
        }

        Ok(None)
    }

    // ── High-level file read ──────────────────────────────────────────

    /// Read file data by inode number via the device.
    ///
    /// Reads the inode, validates it is a regular file, then reads up to
    /// `size` bytes starting at `offset` using extent mapping. Returns
    /// `FfsError::IsDirectory` if the inode is a directory.
    pub fn read_file(
        &self,
        cx: &Cx,
        ino: InodeNumber,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, FfsError> {
        let inode = self.read_inode(cx, ino)?;
        if inode.is_dir() {
            return Err(FfsError::IsDirectory);
        }
        let mut buf = vec![0_u8; size as usize];
        let n = self.read_file_data(cx, &inode, offset, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    // ── Path resolution ───────────────────────────────────────────────

    /// Resolve an absolute path to an inode number and parsed inode.
    ///
    /// Walks the directory tree from root (inode 2), looking up each path
    /// component via [`lookup_name`](Self::lookup_name). The path must
    /// start with `/`.
    ///
    /// Returns `FfsError::NotFound` if a component does not exist, or
    /// `FfsError::NotDirectory` if an intermediate component is not a
    /// directory.
    pub fn resolve_path(&self, cx: &Cx, path: &str) -> Result<(InodeNumber, Ext4Inode), FfsError> {
        if !path.starts_with('/') {
            return Err(FfsError::Format(
                "path must be absolute (start with /)".into(),
            ));
        }

        let mut current_ino = InodeNumber::ROOT;
        let mut current_inode = self.read_inode(cx, current_ino)?;

        for component in path.split('/').filter(|c| !c.is_empty()) {
            if !current_inode.is_dir() {
                return Err(FfsError::NotDirectory);
            }

            let entry = self
                .lookup_name(cx, &current_inode, component.as_bytes())?
                .ok_or_else(|| FfsError::NotFound(component.to_owned()))?;

            current_ino = InodeNumber(u64::from(entry.inode));
            current_inode = self.read_inode(cx, current_ino)?;
        }

        Ok((current_ino, current_inode))
    }

    // ── Symlink reading ───────────────────────────────────────────────

    /// Read the target of a symbolic link via the device.
    ///
    /// Fast symlinks (target <= 60 bytes) are stored inline in the inode's
    /// block area. Slow symlinks read their target from data blocks via
    /// extent mapping.
    pub fn read_symlink(&self, cx: &Cx, inode: &Ext4Inode) -> Result<Vec<u8>, FfsError> {
        if !inode.is_symlink() {
            return Err(FfsError::Format("not a symlink".into()));
        }
        // Fast symlink: target stored inline in extent_bytes
        if let Some(target) = inode.fast_symlink_target() {
            return Ok(target.to_vec());
        }
        // Slow symlink: read from data blocks
        let len = usize::try_from(inode.size).map_err(|_| FfsError::Corruption {
            block: 0,
            detail: "symlink size overflow".into(),
        })?;
        let mut buf = vec![0_u8; len];
        self.read_file_data(cx, inode, 0, &mut buf)?;
        // Trim trailing NUL
        if let Some(pos) = buf.iter().position(|&b| b == 0) {
            buf.truncate(pos);
        }
        Ok(buf)
    }
}

/// Compute the number of logical blocks in a directory, as a u32.
fn dir_logical_block_count(file_size: u64, block_size: u64) -> Result<u32, FfsError> {
    let num = file_size.div_ceil(block_size);
    u32::try_from(num).map_err(|_| FfsError::Corruption {
        block: 0,
        detail: "directory block count overflow".into(),
    })
}

/// Validate btrfs superblock fields at mount time.
///
/// Checks that `sectorsize` and `nodesize` are within the range accepted
/// by the kernel and are consistent with each other.
fn validate_btrfs_superblock(sb: &BtrfsSuperblock) -> Result<(), FfsError> {
    // sectorsize: power of 2, [512, 4096]
    if sb.sectorsize < 512 || sb.sectorsize > 4096 {
        return Err(FfsError::InvalidGeometry(format!(
            "btrfs sectorsize {} out of range [512, 4096]",
            sb.sectorsize
        )));
    }
    // nodesize: power of 2, [sectorsize, 65536]
    if sb.nodesize < sb.sectorsize || sb.nodesize > 65536 {
        return Err(FfsError::InvalidGeometry(format!(
            "btrfs nodesize {} out of range [{}, 65536]",
            sb.nodesize, sb.sectorsize
        )));
    }
    Ok(())
}

/// Convert a mount-time `ParseError` into the appropriate `FfsError` variant.
///
/// This is the crate-boundary conversion described in the `ffs-error` error
/// taxonomy. During mount-time validation, `ParseError::InvalidField` is
/// mapped based on the field name to distinguish unsupported features from
/// geometry errors from format errors.
fn parse_error_to_ffs(e: &ParseError) -> FfsError {
    match e {
        ParseError::InvalidField { field, reason } => {
            // Feature validation failures → UnsupportedFeature
            if field.contains("feature") || reason.contains("unsupported") {
                FfsError::UnsupportedFeature(format!("{field}: {reason}"))
            }
            // Geometry failures → InvalidGeometry
            else if field.contains("block_size")
                || field.contains("blocks_per_group")
                || field.contains("inodes_per_group")
                || field.contains("inode_size")
                || field.contains("desc_size")
                || field.contains("first_data_block")
                || field.contains("blocks_count")
                || field.contains("inodes_count")
            {
                FfsError::InvalidGeometry(format!("{field}: {reason}"))
            }
            // Everything else → Format
            else {
                FfsError::Format(e.to_string())
            }
        }
        ParseError::InvalidMagic { .. } => FfsError::Format(e.to_string()),
        ParseError::InsufficientData { .. } | ParseError::IntegerConversion { .. } => {
            FfsError::Corruption {
                block: 0,
                detail: e.to_string(),
            }
        }
    }
}

// ── VFS semantics layer ─────────────────────────────────────────────────────

/// Filesystem-agnostic file type for VFS operations.
///
/// This is the semantics-level file type used by [`FsOps`] methods. It unifies
/// ext4's `Ext4FileType` and btrfs's inode type into a single enum that
/// higher layers (FUSE, harness) consume without filesystem-specific knowledge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileType {
    RegularFile,
    Directory,
    Symlink,
    BlockDevice,
    CharDevice,
    Fifo,
    Socket,
}

/// Inode attributes returned by [`FsOps::getattr`] and [`FsOps::lookup`].
///
/// This is the semantics-level stat structure, analogous to POSIX `struct stat`.
/// Format-specific crates (ffs-ext4, ffs-btrfs) convert their on-disk inode
/// representations into `InodeAttr` at the crate boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InodeAttr {
    /// Inode number.
    pub ino: InodeNumber,
    /// File size in bytes.
    pub size: u64,
    /// Number of 512-byte blocks allocated.
    pub blocks: u64,
    /// Last access time.
    pub atime: SystemTime,
    /// Last modification time.
    pub mtime: SystemTime,
    /// Last status change time.
    pub ctime: SystemTime,
    /// Creation time (if available).
    pub crtime: SystemTime,
    /// File type.
    pub kind: FileType,
    /// POSIX permission bits (lower 12 bits of mode).
    pub perm: u16,
    /// Number of hard links.
    pub nlink: u32,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// Device ID (for block/char devices).
    pub rdev: u32,
    /// Preferred I/O block size.
    pub blksize: u32,
}

/// A directory entry returned by [`FsOps::readdir`].
///
/// Each entry represents one name in a directory listing. The `offset` field
/// is an opaque cookie for resuming iteration — FUSE passes it back on
/// subsequent `readdir` calls so the implementation can skip already-returned
/// entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirEntry {
    /// Inode number of the target.
    pub ino: InodeNumber,
    /// Opaque offset cookie for readdir continuation.
    pub offset: u64,
    /// File type of the target.
    pub kind: FileType,
    /// Entry name (filename component, not a full path).
    pub name: Vec<u8>,
}

impl DirEntry {
    /// Return the name as a UTF-8 string (lossy).
    #[must_use]
    pub fn name_str(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }
}

/// FUSE/VFS operation kind used for MVCC request-scope hooks.
///
/// These operation tags let `FsOps` implementations choose an MVCC policy per
/// request (for example: read-snapshot only vs. begin write transaction).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RequestOp {
    Getattr,
    Lookup,
    Open,
    Opendir,
    Read,
    Readdir,
    Readlink,
}

/// MVCC scope acquired for a single VFS request.
///
/// Current read-only implementations can return an empty scope. Future write
/// implementations may attach a transaction id and snapshot captured at request
/// start so that begin/end hooks can manage commit/abort semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RequestScope {
    pub snapshot: Option<Snapshot>,
    pub tx: Option<TxnId>,
}

impl RequestScope {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            snapshot: None,
            tx: None,
        }
    }
}

/// Minimal VFS operations trait for read-only filesystem access.
///
/// This is the internal interface that FUSE and the test harness call.
/// Format-specific implementations (ext4, btrfs) live behind this trait so
/// that higher layers are filesystem-agnostic.
///
/// # Design Notes
///
/// - All methods take `&Cx` for cooperative cancellation and deadline
///   propagation via the asupersync runtime.
/// - Errors are returned as `ffs_error::FfsError`, which maps to POSIX
///   errnos via [`FfsError::to_errno()`].
/// - The trait is `Send + Sync` so that FUSE can call it from multiple
///   threads concurrently.
/// - Only read-only operations are included in this initial version.
///   Write operations (create, write, mkdir, unlink, etc.) will be added
///   in a future bead once the MVCC write path is ready.
/// - `begin_request_scope`/`end_request_scope` provide a policy hook for
///   per-request MVCC snapshot/transaction management.
pub trait FsOps: Send + Sync {
    /// Get file attributes by inode number.
    ///
    /// Returns the attributes for the given inode. Returns
    /// `FfsError::NotFound` if the inode does not exist.
    fn getattr(&self, cx: &Cx, ino: InodeNumber) -> ffs_error::Result<InodeAttr>;

    /// Look up a directory entry by name.
    ///
    /// Returns the attributes of the child inode named `name` within the
    /// directory `parent`. Returns `FfsError::NotFound` if the name does
    /// not exist, or `FfsError::NotDirectory` if `parent` is not a directory.
    fn lookup(&self, cx: &Cx, parent: InodeNumber, name: &OsStr) -> ffs_error::Result<InodeAttr>;

    /// List directory entries starting from `offset`.
    ///
    /// Returns a batch of entries from the directory identified by `ino`.
    /// The `offset` parameter is an opaque cookie from a previous call's
    /// `DirEntry::offset` field (use 0 for the first call). An empty
    /// result indicates the end of the directory.
    ///
    /// Returns `FfsError::NotDirectory` if `ino` is not a directory.
    fn readdir(&self, cx: &Cx, ino: InodeNumber, offset: u64) -> ffs_error::Result<Vec<DirEntry>>;

    /// Read file data.
    ///
    /// Returns up to `size` bytes starting at byte `offset` within the
    /// file identified by `ino`. Returns fewer bytes at EOF. Returns
    /// `FfsError::IsDirectory` if `ino` is a directory.
    fn read(&self, cx: &Cx, ino: InodeNumber, offset: u64, size: u32)
    -> ffs_error::Result<Vec<u8>>;

    /// Read the target of a symbolic link.
    ///
    /// Returns the raw bytes of the symlink target. Returns
    /// `FfsError::Format` if `ino` is not a symlink.
    fn readlink(&self, cx: &Cx, ino: InodeNumber) -> ffs_error::Result<Vec<u8>>;

    /// List extended attribute names for an inode.
    ///
    /// Returns the full attribute names (including namespace prefix, e.g.
    /// `"user.myattr"`, `"security.selinux"`). Returns an empty list if the
    /// inode has no xattrs or the filesystem does not support them.
    fn listxattr(&self, cx: &Cx, ino: InodeNumber) -> ffs_error::Result<Vec<String>> {
        let _ = (cx, ino);
        Ok(Vec::new())
    }

    /// Get the value of an extended attribute by full name.
    ///
    /// The `name` parameter is the full attribute name including namespace
    /// prefix (e.g. `"user.myattr"`). Returns `None` if the attribute does
    /// not exist.
    fn getxattr(&self, cx: &Cx, ino: InodeNumber, name: &str) -> ffs_error::Result<Option<Vec<u8>>> {
        let _ = (cx, ino, name);
        Ok(None)
    }

    /// Acquire request scope before executing a VFS operation.
    ///
    /// Default behavior is a no-op for read-only backends.
    fn begin_request_scope(&self, _cx: &Cx, _op: RequestOp) -> ffs_error::Result<RequestScope> {
        Ok(RequestScope::empty())
    }

    /// Release request scope after executing a VFS operation.
    ///
    /// Called even when the operation body fails. Default behavior is a no-op.
    fn end_request_scope(
        &self,
        _cx: &Cx,
        _op: RequestOp,
        _scope: RequestScope,
    ) -> ffs_error::Result<()> {
        Ok(())
    }
}

// ── Ext4FsOps: bridge from Ext4ImageReader to FsOps ───────────────────────

/// Read-only ext4 filesystem operations backed by an in-memory image.
///
/// This is the bridge layer that connects the pure-parsing `Ext4ImageReader`
/// (which operates on `&[u8]` slices) to the VFS-level `FsOps` trait (which
/// the FUSE adapter and test harness consume).
///
/// # Design
///
/// The image is stored as `Arc<Vec<u8>>` so that `Ext4FsOps` is `Send + Sync`
/// without copying. The `Ext4ImageReader` holds only the parsed superblock
/// and pre-computed geometry — no mutable state — so concurrent reads are safe.
pub struct Ext4FsOps {
    reader: Ext4ImageReader,
    image: std::sync::Arc<Vec<u8>>,
}

impl std::fmt::Debug for Ext4FsOps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ext4FsOps")
            .field("block_size", &self.reader.sb.block_size)
            .field("image_len", &self.image.len())
            .finish()
    }
}

impl Ext4FsOps {
    /// Create from an in-memory ext4 image.
    ///
    /// Parses the superblock and validates geometry. The image is wrapped
    /// in `Arc` for zero-copy sharing.
    pub fn new(image: Vec<u8>) -> Result<Self, FfsError> {
        let reader = Ext4ImageReader::new(&image).map_err(|e| parse_to_ffs_error(&e))?;
        Ok(Self {
            reader,
            image: std::sync::Arc::new(image),
        })
    }

    /// Create from an already-shared image.
    pub fn from_arc(image: std::sync::Arc<Vec<u8>>) -> Result<Self, FfsError> {
        let reader = Ext4ImageReader::new(&image).map_err(|e| parse_to_ffs_error(&e))?;
        Ok(Self { reader, image })
    }

    /// Access the underlying `Ext4ImageReader`.
    #[must_use]
    pub fn reader(&self) -> &Ext4ImageReader {
        &self.reader
    }

    /// Access the raw image bytes.
    #[must_use]
    pub fn image(&self) -> &[u8] {
        &self.image
    }

    /// Read and convert an inode to `InodeAttr`.
    fn inode_to_attr(&self, ino: InodeNumber, inode: &Ext4Inode) -> InodeAttr {
        inode_to_attr(&self.reader.sb, ino, inode)
    }
}

/// Convert `ParseError` to `FfsError` for runtime operations (not mount-time).
fn parse_to_ffs_error(e: &ParseError) -> FfsError {
    match e {
        ParseError::InvalidField { field, reason } => {
            if reason.contains("not found") || reason.contains("component not found") {
                FfsError::NotFound(format!("{field}: {reason}"))
            } else if reason.contains("not a directory") {
                FfsError::NotDirectory
            } else {
                FfsError::Format(e.to_string())
            }
        }
        ParseError::InvalidMagic { .. } => FfsError::Format(e.to_string()),
        ParseError::InsufficientData { .. } | ParseError::IntegerConversion { .. } => {
            FfsError::Corruption {
                block: 0,
                detail: e.to_string(),
            }
        }
    }
}

/// Convert an ext4 inode into VFS `InodeAttr` using the superblock for context.
fn inode_to_attr(sb: &Ext4Superblock, ino: InodeNumber, inode: &Ext4Inode) -> InodeAttr {
    let kind = inode_file_type(inode);
    let blocks_512 = if (inode.flags & ffs_types::EXT4_HUGE_FILE_FL) != 0 {
        inode.blocks.saturating_mul(u64::from(sb.block_size / 512))
    } else {
        inode.blocks
    };

    InodeAttr {
        ino,
        size: inode.size,
        blocks: blocks_512,
        atime: inode.atime_system_time(),
        mtime: inode.mtime_system_time(),
        ctime: inode.ctime_system_time(),
        crtime: inode.crtime_system_time(),
        kind,
        perm: inode.permission_bits(),
        nlink: u32::from(inode.links_count),
        uid: inode.uid,
        gid: inode.gid,
        rdev: inode.device_number(),
        blksize: sb.block_size,
    }
}

/// Map ext4 inode mode to VFS `FileType`.
fn inode_file_type(inode: &Ext4Inode) -> FileType {
    if inode.is_regular() {
        FileType::RegularFile
    } else if inode.is_dir() {
        FileType::Directory
    } else if inode.is_symlink() {
        FileType::Symlink
    } else if inode.is_blkdev() {
        FileType::BlockDevice
    } else if inode.is_chrdev() {
        FileType::CharDevice
    } else if inode.is_fifo() {
        FileType::Fifo
    } else if inode.is_socket() {
        FileType::Socket
    } else {
        FileType::RegularFile // fallback for unknown types
    }
}

/// Map ext4 directory entry file type to VFS `FileType`.
fn dir_entry_file_type(ft: Ext4FileType) -> FileType {
    match ft {
        Ext4FileType::Dir => FileType::Directory,
        Ext4FileType::Symlink => FileType::Symlink,
        Ext4FileType::Blkdev => FileType::BlockDevice,
        Ext4FileType::Chrdev => FileType::CharDevice,
        Ext4FileType::Fifo => FileType::Fifo,
        Ext4FileType::Sock => FileType::Socket,
        Ext4FileType::RegFile | Ext4FileType::Unknown => FileType::RegularFile,
    }
}

impl FsOps for Ext4FsOps {
    fn getattr(&self, _cx: &Cx, ino: InodeNumber) -> ffs_error::Result<InodeAttr> {
        let inode = self
            .reader
            .read_inode(&self.image, ino)
            .map_err(|e| parse_to_ffs_error(&e))?;
        Ok(self.inode_to_attr(ino, &inode))
    }

    fn lookup(&self, _cx: &Cx, parent: InodeNumber, name: &OsStr) -> ffs_error::Result<InodeAttr> {
        let parent_inode = self
            .reader
            .read_inode(&self.image, parent)
            .map_err(|e| parse_to_ffs_error(&e))?;

        if !parent_inode.is_dir() {
            return Err(FfsError::NotDirectory);
        }

        let name_bytes = name.as_encoded_bytes();
        let entry = self
            .reader
            .lookup(&self.image, &parent_inode, name_bytes)
            .map_err(|e| parse_to_ffs_error(&e))?
            .ok_or_else(|| FfsError::NotFound(name.to_string_lossy().into_owned()))?;

        let child_ino = InodeNumber(u64::from(entry.inode));
        let child_inode = self
            .reader
            .read_inode(&self.image, child_ino)
            .map_err(|e| parse_to_ffs_error(&e))?;
        Ok(self.inode_to_attr(child_ino, &child_inode))
    }

    fn readdir(&self, _cx: &Cx, ino: InodeNumber, offset: u64) -> ffs_error::Result<Vec<DirEntry>> {
        let inode = self
            .reader
            .read_inode(&self.image, ino)
            .map_err(|e| parse_to_ffs_error(&e))?;

        if !inode.is_dir() {
            return Err(FfsError::NotDirectory);
        }

        let raw_entries = self
            .reader
            .read_dir(&self.image, &inode)
            .map_err(|e| parse_to_ffs_error(&e))?;

        // Convert to VFS DirEntry with offset cookies.
        // Offset is 1-indexed position in the entry list.
        let entries: Vec<DirEntry> = raw_entries
            .into_iter()
            .enumerate()
            .filter(|(idx, _)| (*idx as u64) >= offset)
            .map(|(idx, e)| DirEntry {
                ino: InodeNumber(u64::from(e.inode)),
                offset: (idx as u64) + 1,
                kind: dir_entry_file_type(e.file_type),
                name: e.name,
            })
            .collect();

        Ok(entries)
    }

    fn read(
        &self,
        _cx: &Cx,
        ino: InodeNumber,
        offset: u64,
        size: u32,
    ) -> ffs_error::Result<Vec<u8>> {
        let inode = self
            .reader
            .read_inode(&self.image, ino)
            .map_err(|e| parse_to_ffs_error(&e))?;

        if inode.is_dir() {
            return Err(FfsError::IsDirectory);
        }

        let mut buf = vec![0_u8; size as usize];
        let n = self
            .reader
            .read_inode_data(&self.image, &inode, offset, &mut buf)
            .map_err(|e| parse_to_ffs_error(&e))?;
        buf.truncate(n);
        Ok(buf)
    }

    fn readlink(&self, _cx: &Cx, ino: InodeNumber) -> ffs_error::Result<Vec<u8>> {
        let inode = self
            .reader
            .read_inode(&self.image, ino)
            .map_err(|e| parse_to_ffs_error(&e))?;

        if !inode.is_symlink() {
            return Err(FfsError::Format("not a symlink".into()));
        }

        self.reader
            .read_symlink(&self.image, &inode)
            .map_err(|e| parse_to_ffs_error(&e))
    }

    fn listxattr(&self, _cx: &Cx, ino: InodeNumber) -> ffs_error::Result<Vec<String>> {
        let inode = self
            .reader
            .read_inode(&self.image, ino)
            .map_err(|e| parse_to_ffs_error(&e))?;
        let xattrs = self
            .reader
            .list_xattrs(&self.image, &inode)
            .map_err(|e| parse_to_ffs_error(&e))?;
        Ok(xattrs.iter().map(Ext4Xattr::full_name).collect())
    }

    fn getxattr(
        &self,
        _cx: &Cx,
        ino: InodeNumber,
        name: &str,
    ) -> ffs_error::Result<Option<Vec<u8>>> {
        let inode = self
            .reader
            .read_inode(&self.image, ino)
            .map_err(|e| parse_to_ffs_error(&e))?;
        let xattrs = self
            .reader
            .list_xattrs(&self.image, &inode)
            .map_err(|e| parse_to_ffs_error(&e))?;
        Ok(xattrs.into_iter().find(|x| x.full_name() == name).map(|x| x.value))
    }
}

// ── FsOps for OpenFs (device-based ext4 adapter) ──────────────────────────

impl FsOps for OpenFs {
    fn getattr(&self, cx: &Cx, ino: InodeNumber) -> ffs_error::Result<InodeAttr> {
        self.read_inode_attr(cx, ino)
    }

    fn lookup(&self, cx: &Cx, parent: InodeNumber, name: &OsStr) -> ffs_error::Result<InodeAttr> {
        let parent_inode = self.read_inode(cx, parent)?;
        if !parent_inode.is_dir() {
            return Err(FfsError::NotDirectory);
        }

        let name_bytes = name.as_encoded_bytes();
        let entry = self
            .lookup_name(cx, &parent_inode, name_bytes)?
            .ok_or_else(|| FfsError::NotFound(name.to_string_lossy().into_owned()))?;

        let child_ino = InodeNumber(u64::from(entry.inode));
        self.read_inode_attr(cx, child_ino)
    }

    fn readdir(&self, cx: &Cx, ino: InodeNumber, offset: u64) -> ffs_error::Result<Vec<DirEntry>> {
        let inode = self.read_inode(cx, ino)?;
        if !inode.is_dir() {
            return Err(FfsError::NotDirectory);
        }

        let raw_entries = self.read_dir(cx, &inode)?;
        let entries: Vec<DirEntry> = raw_entries
            .into_iter()
            .enumerate()
            .filter(|(idx, _)| (*idx as u64) >= offset)
            .map(|(idx, e)| DirEntry {
                ino: InodeNumber(u64::from(e.inode)),
                offset: (idx as u64) + 1,
                kind: dir_entry_file_type(e.file_type),
                name: e.name,
            })
            .collect();

        Ok(entries)
    }

    fn read(
        &self,
        cx: &Cx,
        ino: InodeNumber,
        offset: u64,
        size: u32,
    ) -> ffs_error::Result<Vec<u8>> {
        self.read_file(cx, ino, offset, size)
    }

    fn readlink(&self, cx: &Cx, ino: InodeNumber) -> ffs_error::Result<Vec<u8>> {
        let inode = self.read_inode(cx, ino)?;
        self.read_symlink(cx, &inode)
    }

    fn listxattr(&self, cx: &Cx, ino: InodeNumber) -> ffs_error::Result<Vec<String>> {
        let inode = self.read_inode(cx, ino)?;
        let mut xattrs =
            ffs_ondisk::parse_ibody_xattrs(&inode).map_err(|e| parse_to_ffs_error(&e))?;
        if inode.file_acl != 0 {
            let block_data = self.read_block_vec(cx, BlockNumber(inode.file_acl))?;
            let block_xattrs = ffs_ondisk::parse_xattr_block(&block_data)
                .map_err(|e| parse_to_ffs_error(&e))?;
            xattrs.extend(block_xattrs);
        }
        Ok(xattrs.iter().map(Ext4Xattr::full_name).collect())
    }

    fn getxattr(
        &self,
        cx: &Cx,
        ino: InodeNumber,
        name: &str,
    ) -> ffs_error::Result<Option<Vec<u8>>> {
        let inode = self.read_inode(cx, ino)?;
        let mut xattrs =
            ffs_ondisk::parse_ibody_xattrs(&inode).map_err(|e| parse_to_ffs_error(&e))?;
        if inode.file_acl != 0 {
            let block_data = self.read_block_vec(cx, BlockNumber(inode.file_acl))?;
            let block_xattrs = ffs_ondisk::parse_xattr_block(&block_data)
                .map_err(|e| parse_to_ffs_error(&e))?;
            xattrs.extend(block_xattrs);
        }
        Ok(xattrs.into_iter().find(|x| x.full_name() == name).map(|x| x.value))
    }
}

// ── Bayesian Filesystem Integrity Scanner ──────────────────────────────────
//
// Alien-artifact quality: cascading checksum verification with a formal
// evidence ledger. Each verification step contributes a log-likelihood
// observation to a Beta-Binomial posterior over the corruption rate.
//
// The posterior P(healthy|evidence) is computed via conjugate update:
//   α += corrupted_count, β += clean_count
// where clean = verified_ok and corrupted = checksum_mismatch.
//
// Decision theory: the expected corruption rate E[p] = α/(α+β) and the
// upper credible bound p_hi = E[p] + z·√Var[p] provide actionable thresholds.

/// Verdict for a single integrity check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckVerdict {
    /// What was checked (e.g., "superblock", "group_desc[3]", "inode[142]").
    pub component: String,
    /// Whether the check passed.
    pub passed: bool,
    /// Human-readable detail (empty on success).
    pub detail: String,
}

/// The complete evidence ledger from an integrity scan.
///
/// # Bayesian Model
///
/// We model each metadata object as a Bernoulli trial: P(corrupt) = p.
/// Using a Beta(α, β) conjugate prior (default: uninformative Beta(1,1)),
/// after observing n_clean clean objects and n_corrupt corrupted objects:
///
/// ```text
/// Posterior: Beta(α + n_corrupt, β + n_clean)
/// E[p] = α / (α + β)                           — expected corruption rate
/// Var[p] = αβ / ((α+β)²(α+β+1))                — posterior variance
/// p_hi = E[p] + z·√Var[p]                       — upper credible bound
/// ```
///
/// A filesystem is "healthy" when p_hi < threshold (default 0.01).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityReport {
    /// Per-component verdicts (evidence ledger).
    pub verdicts: Vec<CheckVerdict>,
    /// Number of checks that passed.
    pub passed: u64,
    /// Number of checks that failed.
    pub failed: u64,
    /// Posterior α (prior + observed corruptions).
    pub posterior_alpha: f64,
    /// Posterior β (prior + observed clean).
    pub posterior_beta: f64,
    /// E[p] = expected corruption rate.
    pub expected_corruption_rate: f64,
    /// Upper credible bound on corruption rate (z=3 by default).
    pub upper_bound_corruption_rate: f64,
    /// Overall health verdict: true if upper_bound < 0.01.
    pub healthy: bool,
}

impl IntegrityReport {
    /// Posterior probability that corruption rate < threshold.
    ///
    /// Uses the regularized incomplete beta function approximation:
    /// for large sample sizes, the Beta posterior is approximately Normal,
    /// so P(p < t) ≈ Φ((t - μ) / σ) where μ = E[p], σ = √Var[p].
    #[must_use]
    pub fn prob_healthy(&self, threshold: f64) -> f64 {
        let a = self.posterior_alpha;
        let b = self.posterior_beta;
        let mean = a / (a + b);
        let var = (a * b) / ((a + b).powi(2) * (a + b + 1.0));
        let std = var.sqrt();
        if std < 1e-15 {
            return if mean < threshold { 1.0 } else { 0.0 };
        }
        // Normal CDF approximation: Φ(x) ≈ 0.5 * erfc(-x/√2)
        let z = (threshold - mean) / std;
        0.5 * erfc_approx(-z / std::f64::consts::SQRT_2)
    }

    /// Log Bayes factor: ln(P(evidence|healthy) / P(evidence|corrupt)).
    ///
    /// Positive values favor health; negative values favor corruption.
    /// Uses the ratio of Beta-Binomial marginal likelihoods:
    ///   - H₀ (healthy): p ~ Beta(1, 99) (expect ~1% corruption)
    ///   - H₁ (corrupt): p ~ Beta(1, 1) (uniform prior)
    #[must_use]
    pub fn log_bayes_factor(&self) -> f64 {
        // ln B(α₀ + f, β₀ + p) - ln B(α₀, β₀) - ln B(α₁ + f, β₁ + p) + ln B(α₁, β₁)
        // where f = failed, p = passed, and B is the beta function
        let f = self.failed as f64;
        let p = self.passed as f64;

        // H₀: healthy prior Beta(1, 99)
        let a0 = 1.0_f64;
        let b0 = 99.0_f64;
        // H₁: corrupt prior Beta(1, 1)
        let a1 = 1.0_f64;
        let b1 = 1.0_f64;

        ln_beta(a0 + f, b0 + p) - ln_beta(a0, b0) - ln_beta(a1 + f, b1 + p) + ln_beta(a1, b1)
    }
}

/// Approximate complementary error function erfc(x) for Normal CDF.
fn erfc_approx(x: f64) -> f64 {
    // Abramowitz & Stegun approximation (7.1.26), max error < 1.5e-7
    let t = 1.0 / 0.327_591_1_f64.mul_add(x.abs(), 1.0);
    let poly = t
        * (0.254_829_592
            + t * (-0.284_496_736
                + t * (1.421_413_741 + t * (-1.453_152_027 + t * 1.061_405_429))));
    let result = poly * (-x * x).exp();
    if x >= 0.0 { result } else { 2.0 - result }
}

/// ln(Beta(a, b)) = ln(Γ(a)) + ln(Γ(b)) - ln(Γ(a+b))
fn ln_beta(a: f64, b: f64) -> f64 {
    ln_gamma(a) + ln_gamma(b) - ln_gamma(a + b)
}

/// Lanczos approximation for ln(Γ(x)), accurate for x > 0.
#[allow(clippy::excessive_precision)]
fn ln_gamma(x: f64) -> f64 {
    const COEFFS: [f64; 9] = [
        0.999_999_999_999_809_9,
        676.520_368_121_885_1,
        -1_259.139_216_722_403,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];

    if x <= 0.0 {
        return f64::INFINITY;
    }
    let g = 7.0_f64;
    if x < 0.5 {
        let pi = std::f64::consts::PI;
        return (pi / (pi * x).sin()).ln() - ln_gamma(1.0 - x);
    }
    let z = x - 1.0;
    let mut sum = COEFFS[0];
    for (i, &c) in COEFFS.iter().enumerate().skip(1) {
        sum += c / (z + i as f64);
    }
    let t = z + g + 0.5;
    0.5_f64.mul_add(
        (2.0 * std::f64::consts::PI).ln(),
        (z + 0.5).mul_add(t.ln(), -t),
    ) + sum.ln()
}

/// Run a comprehensive integrity scan of an ext4 filesystem image.
///
/// Cascades through verification levels:
/// 1. **Superblock checksum** (if metadata_csum enabled)
/// 2. **Group descriptor checksums** (all groups)
/// 3. **Inode checksums** (sampled or exhaustive)
/// 4. **Directory block checksums** (for sampled directory inodes)
///
/// Returns an `IntegrityReport` with per-component verdicts and a
/// Bayesian posterior over the corruption rate.
///
/// # Arguments
/// * `image` - raw filesystem image bytes
/// * `max_inodes` - maximum number of inodes to verify (0 = all)
#[allow(clippy::too_many_lines)]
pub fn verify_ext4_integrity(image: &[u8], max_inodes: u32) -> Result<IntegrityReport, FfsError> {
    let reader = Ext4ImageReader::new(image).map_err(|e| parse_to_ffs_error(&e))?;
    let sb = &reader.sb;

    let mut verdicts = Vec::new();
    let mut passed = 0_u64;
    let mut failed = 0_u64;
    let mut sb_passed = false;

    // ── Level 1: Superblock checksum ───────────────────────────────────
    if sb.has_metadata_csum() {
        let sb_region = &image[ffs_types::EXT4_SUPERBLOCK_OFFSET
            ..ffs_types::EXT4_SUPERBLOCK_OFFSET + ffs_types::EXT4_SUPERBLOCK_SIZE];
        match sb.validate_checksum(sb_region) {
            Ok(()) => {
                verdicts.push(CheckVerdict {
                    component: "superblock".into(),
                    passed: true,
                    detail: String::new(),
                });
                passed += 1;
                sb_passed = true;
            }
            Err(e) => {
                verdicts.push(CheckVerdict {
                    component: "superblock".into(),
                    passed: false,
                    detail: e.to_string(),
                });
                failed += 1;
            }
        }
    }

    // ── Level 2: Group descriptor checksums ────────────────────────────
    let csum_seed = sb.csum_seed();
    let groups_count = sb.groups_count();
    let desc_size = sb.group_desc_size();

    for g in 0..groups_count {
        let group = ffs_types::GroupNumber(g);
        let gd_result = reader.read_group_desc(image, group);
        match gd_result {
            Ok(_gd) => {
                // Read raw GD bytes for checksum verification
                if let Some(gd_off) = sb.group_desc_offset(group) {
                    let ds = usize::from(desc_size);
                    let offset = usize::try_from(gd_off).unwrap_or(usize::MAX);
                    if offset.saturating_add(ds) <= image.len() {
                        let raw_gd = &image[offset..offset + ds];
                        match ffs_ondisk::verify_group_desc_checksum(
                            raw_gd, csum_seed, g, desc_size,
                        ) {
                            Ok(()) => {
                                passed += 1;
                            }
                            Err(e) => {
                                verdicts.push(CheckVerdict {
                                    component: format!("group_desc[{g}]"),
                                    passed: false,
                                    detail: e.to_string(),
                                });
                                failed += 1;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                verdicts.push(CheckVerdict {
                    component: format!("group_desc[{g}]"),
                    passed: false,
                    detail: e.to_string(),
                });
                failed += 1;
            }
        }
    }
    // Single success verdict for all clean group descs
    if failed == 0 || passed > 0 {
        let clean_gd = passed - u64::from(sb_passed); // subtract superblock if it was counted
        if clean_gd > 0 {
            verdicts.push(CheckVerdict {
                component: format!("group_descs ({clean_gd}/{groups_count} verified)"),
                passed: true,
                detail: String::new(),
            });
        }
    }

    // ── Level 3: Inode checksums (sampled) ─────────────────────────────
    let inodes_count = sb.inodes_count;
    let first_ino = sb.first_ino;
    let inode_size = usize::from(sb.inode_size);

    // Always check root inode (2) and first non-reserved inode
    let check_limit = if max_inodes == 0 {
        inodes_count
    } else {
        max_inodes.min(inodes_count)
    };

    let mut inodes_checked = 0_u64;
    let mut inodes_clean = 0_u64;
    let mut inodes_corrupt = 0_u64;

    // Check inodes: root (2), then first_ino..first_ino+check_limit
    let ino_list: Vec<u32> = {
        let mut v = vec![2_u32]; // root inode
        let start = first_ino.max(2);
        let end = start
            .saturating_add(check_limit)
            .min(inodes_count.saturating_add(1));
        for i in start..end {
            if i != 2 {
                v.push(i);
            }
        }
        v
    };

    for &ino in &ino_list {
        if inodes_checked >= u64::from(check_limit) {
            break;
        }

        // Read raw inode bytes for checksum verification
        let ino_num = ffs_types::InodeNumber(u64::from(ino));
        match reader.read_inode(image, ino_num) {
            Ok(inode) => {
                // Verify inode checksum using raw bytes
                let group = ffs_types::GroupNumber((ino - 1) / sb.inodes_per_group);
                if let Ok(gd) = reader.read_group_desc(image, group) {
                    let local = (ino - 1) % sb.inodes_per_group;
                    let itable_off = gd.inode_table * u64::from(sb.block_size);
                    let inode_off = itable_off + u64::from(local) * inode_size as u64;
                    let off = usize::try_from(inode_off).unwrap_or(usize::MAX);
                    if off.saturating_add(inode_size) <= image.len() {
                        let raw = &image[off..off + inode_size];
                        match ffs_ondisk::verify_inode_checksum(
                            raw,
                            csum_seed,
                            ino,
                            u16::try_from(inode_size).unwrap_or(256),
                        ) {
                            Ok(()) => {
                                inodes_clean += 1;
                                passed += 1;
                            }
                            Err(e) => {
                                verdicts.push(CheckVerdict {
                                    component: format!("inode[{ino}]"),
                                    passed: false,
                                    detail: e.to_string(),
                                });
                                inodes_corrupt += 1;
                                failed += 1;
                            }
                        }
                    }
                }

                // ── Level 4: Directory block checksums ─────────────────
                if inode.is_dir() && inode.uses_extents() {
                    let dir_blocks = inode.size / u64::from(sb.block_size);
                    let scan_blocks = u32::try_from(dir_blocks.min(16)).unwrap_or(16);
                    for lb in 0..scan_blocks {
                        if let Ok(Some(phys)) = reader.resolve_extent(image, &inode, lb) {
                            let blk_off = usize::try_from(phys * u64::from(sb.block_size))
                                .unwrap_or(usize::MAX);
                            let bs = sb.block_size as usize;
                            if blk_off.saturating_add(bs) <= image.len() {
                                let block_data = &image[blk_off..blk_off + bs];
                                // Check if block has a checksum tail
                                // (last entry has inode=0 and file_type=0xDE)
                                if bs >= 12 {
                                    let tail_ino = u32::from_le_bytes([
                                        block_data[bs - 12],
                                        block_data[bs - 11],
                                        block_data[bs - 10],
                                        block_data[bs - 9],
                                    ]);
                                    let tail_ft = block_data[bs - 5];
                                    if tail_ino == 0 && tail_ft == 0xDE {
                                        match ffs_ondisk::verify_dir_block_checksum(
                                            block_data,
                                            csum_seed,
                                            ino,
                                            inode.generation,
                                        ) {
                                            Ok(()) => {
                                                passed += 1;
                                            }
                                            Err(e) => {
                                                verdicts.push(CheckVerdict {
                                                    component: format!(
                                                        "dir_block[ino={ino},lb={lb}]"
                                                    ),
                                                    passed: false,
                                                    detail: e.to_string(),
                                                });
                                                failed += 1;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                inodes_checked += 1;
            }
            Err(_) => {
                // Inode unreadable — skip silently (might be unallocated)
                inodes_checked += 1;
            }
        }
    }

    if inodes_clean > 0 {
        verdicts.push(CheckVerdict {
            component: format!(
                "inodes ({inodes_clean}/{inodes_checked} verified, {inodes_corrupt} corrupt)"
            ),
            passed: inodes_corrupt == 0,
            detail: String::new(),
        });
    }

    // ── Compute Bayesian posterior ──────────────────────────────────────
    // Prior: Beta(1, 1) — uninformative
    let alpha = 1.0 + failed as f64;
    let beta_param = 1.0 + passed as f64;
    let mean = alpha / (alpha + beta_param);
    let var = (alpha * beta_param) / ((alpha + beta_param).powi(2) * (alpha + beta_param + 1.0));
    let z = 3.0_f64; // 99.7% credible interval
    let upper = z.mul_add(var.sqrt(), mean).clamp(0.0, 1.0);

    Ok(IntegrityReport {
        verdicts,
        passed,
        failed,
        posterior_alpha: alpha,
        posterior_beta: beta_param,
        expected_corruption_rate: mean,
        upper_bound_corruption_rate: upper,
        healthy: upper < 0.01,
    })
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DurabilityPosterior {
    pub alpha: f64,
    pub beta: f64,
}

impl Default for DurabilityPosterior {
    fn default() -> Self {
        Self {
            alpha: 1.0,
            beta: 1.0,
        }
    }
}

impl DurabilityPosterior {
    /// Observe a single Bernoulli event ("did we see any corruption?").
    ///
    /// This is intentionally coarse; prefer `observe_blocks()` when scrub can
    /// report counts.
    pub fn observe_event(&mut self, corruption_event: bool) {
        self.observe_blocks(1, u64::from(corruption_event));
    }

    /// Observe scrub results as counts of scanned vs corrupted blocks.
    ///
    /// Uses a Beta-Binomial conjugate update where `alpha` counts "corrupt"
    /// and `beta` counts "clean".
    pub fn observe_blocks(&mut self, scanned_blocks: u64, corrupted_blocks: u64) {
        let scanned = scanned_blocks as f64;
        let corrupted = (corrupted_blocks.min(scanned_blocks)) as f64;
        let clean = (scanned - corrupted).max(0.0);
        self.alpha += corrupted;
        self.beta += clean;
    }

    #[must_use]
    pub fn expected_corruption_rate(&self) -> f64 {
        self.alpha / (self.alpha + self.beta)
    }

    #[must_use]
    pub fn variance(&self) -> f64 {
        let a = self.alpha;
        let b = self.beta;
        let denom = (a + b).powi(2) * (a + b + 1.0);
        if denom <= 0.0 {
            return 0.0;
        }
        (a * b) / denom
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DurabilityLossModel {
    pub corruption_cost: f64,
    pub redundancy_cost: f64,
    pub z_score: f64,
}

impl Default for DurabilityLossModel {
    fn default() -> Self {
        Self {
            corruption_cost: 10_000.0,
            redundancy_cost: 25.0,
            z_score: 3.0,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RedundancyDecision {
    pub repair_overhead: f64,
    pub expected_loss: f64,
    pub posterior_mean_corruption_rate: f64,
    pub posterior_hi_corruption_rate: f64,
    pub unrecoverable_risk_bound: f64,
    pub redundancy_loss: f64,
    pub corruption_loss: f64,
}

impl RedundancyDecision {
    #[must_use]
    pub fn to_raptorq_config(self, block_size: u32) -> RaptorQConfig {
        let mut cfg = RaptorQConfig::default();
        cfg.encoding.repair_overhead = self.repair_overhead;
        cfg.encoding.max_block_size = usize::try_from(block_size).unwrap_or(4096);
        cfg.encoding.symbol_size = u16::try_from(block_size.clamp(64, 1024)).unwrap_or(256);
        cfg
    }
}

#[derive(Debug, Clone, Default)]
pub struct DurabilityAutopilot {
    posterior: DurabilityPosterior,
    loss: DurabilityLossModel,
}

impl DurabilityAutopilot {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe_event(&mut self, corruption_event: bool) {
        self.posterior.observe_event(corruption_event);
    }

    pub fn observe_scrub(&mut self, scanned_blocks: u64, corrupted_blocks: u64) {
        self.posterior
            .observe_blocks(scanned_blocks, corrupted_blocks);
    }

    #[must_use]
    pub fn choose_overhead(&self, candidates: &[f64]) -> RedundancyDecision {
        self.choose_overhead_for_group(candidates, 32_768)
    }

    #[must_use]
    pub fn choose_overhead_for_group(
        &self,
        candidates: &[f64],
        source_block_count: u32,
    ) -> RedundancyDecision {
        const MIN_OVERHEAD: f64 = 1.01;
        const MAX_OVERHEAD: f64 = 1.10;
        const DEFAULT_OVERHEAD: f64 = 1.05;

        let p_mean = self.posterior.expected_corruption_rate();
        let p_hi = self
            .loss
            .z_score
            .mul_add(self.posterior.variance().sqrt(), p_mean)
            .clamp(0.0, 1.0);

        let mut best = RedundancyDecision {
            repair_overhead: DEFAULT_OVERHEAD,
            expected_loss: f64::INFINITY,
            posterior_mean_corruption_rate: p_mean,
            posterior_hi_corruption_rate: p_hi,
            unrecoverable_risk_bound: 1.0,
            redundancy_loss: 0.0,
            corruption_loss: f64::INFINITY,
        };

        let k = f64::from(source_block_count.max(1));
        let mut considered_any = false;

        for candidate in candidates {
            if !candidate.is_finite() || *candidate < MIN_OVERHEAD || *candidate > MAX_OVERHEAD {
                continue;
            }
            considered_any = true;

            // Repair budget fraction relative to source blocks.
            let rho = (candidate - 1.0).clamp(0.0, 1.0);

            // Conservative tail-risk estimate (Chernoff bound) for:
            //   P(N >= rho*K) where N ~ Binomial(K, p) and p is conservatively taken as p_hi.
            let risk_bound = if p_hi <= 0.0 {
                0.0
            } else if rho <= p_hi {
                1.0
            } else {
                let eps = 1e-12;
                let q = rho.clamp(eps, 1.0 - eps);
                let p = p_hi.clamp(eps, 1.0 - eps);
                let kl = q * (q / p).ln() + (1.0 - q) * ((1.0 - q) / (1.0 - p)).ln();
                (-k * kl.max(0.0)).exp()
            };

            let redundancy_loss = self.loss.redundancy_cost * rho;
            let corruption_loss = self.loss.corruption_cost * risk_bound;
            let expected_loss = redundancy_loss + corruption_loss;

            if expected_loss < best.expected_loss {
                best = RedundancyDecision {
                    repair_overhead: *candidate,
                    expected_loss,
                    posterior_mean_corruption_rate: p_mean,
                    posterior_hi_corruption_rate: p_hi,
                    unrecoverable_risk_bound: risk_bound,
                    redundancy_loss,
                    corruption_loss,
                };
            }
        }

        if !considered_any {
            best.repair_overhead = DEFAULT_OVERHEAD;
            best.redundancy_loss = self.loss.redundancy_cost * (DEFAULT_OVERHEAD - 1.0);
            best.corruption_loss = self.loss.corruption_cost;
            best.expected_loss = best.redundancy_loss + best.corruption_loss;
        }

        best
    }
}

// ── Repair Policy ────────────────────────────────────────────────────────────

/// Mount-configurable repair policy governing overhead ratio and autopilot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairPolicy {
    /// Static overhead ratio, range `[1.01, 1.10]`, default `1.05`.
    pub overhead_ratio: f64,
    /// Refresh repair symbols eagerly on every write?
    pub eager_refresh: bool,
    /// When present, the autopilot's `choose_overhead()` overrides the static
    /// ratio at each scrub cycle.
    #[serde(skip)]
    pub autopilot: Option<DurabilityAutopilot>,
}

impl Default for RepairPolicy {
    fn default() -> Self {
        Self {
            overhead_ratio: 1.05,
            eager_refresh: false,
            autopilot: None,
        }
    }
}

impl RepairPolicy {
    /// Return the effective overhead ratio.  When autopilot is engaged, query
    /// it with the standard candidate set; otherwise return the static ratio.
    #[must_use]
    pub fn effective_overhead(&self) -> f64 {
        self.effective_overhead_for_group(32_768)
    }

    /// Return the effective overhead ratio for a specific group size.
    #[must_use]
    pub fn effective_overhead_for_group(&self, source_block_count: u32) -> f64 {
        self.autopilot.as_ref().map_or(self.overhead_ratio, |ap| {
            let candidates: Vec<f64> = (1..=10).map(|i| f64::from(i).mul_add(0.01, 1.0)).collect();
            ap.choose_overhead_for_group(&candidates, source_block_count)
                .repair_overhead
        })
    }

    /// Return the full `RedundancyDecision` when autopilot is engaged, or
    /// `None` when using static overhead.
    #[must_use]
    pub fn autopilot_decision(&self) -> Option<RedundancyDecision> {
        self.autopilot_decision_for_group(32_768)
    }

    /// Return the full `RedundancyDecision` for a given group size.
    #[must_use]
    pub fn autopilot_decision_for_group(
        &self,
        source_block_count: u32,
    ) -> Option<RedundancyDecision> {
        let ap = self.autopilot.as_ref()?;
        let candidates: Vec<f64> = (1..=10).map(|i| f64::from(i).mul_add(0.01, 1.0)).collect();
        Some(ap.choose_overhead_for_group(&candidates, source_block_count))
    }
}

#[derive(Debug, Default)]
pub struct FrankenFsEngine {
    store: MvccStore,
}

impl FrankenFsEngine {
    #[must_use]
    pub fn new() -> Self {
        Self {
            store: MvccStore::new(),
        }
    }

    pub fn begin(&mut self) -> Transaction {
        self.store.begin()
    }

    pub fn commit(&mut self, txn: Transaction) -> Result<CommitSeq, CommitError> {
        self.store.commit(txn)
    }

    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        self.store.current_snapshot()
    }

    #[must_use]
    pub fn read(&self, block: BlockNumber, snapshot: Snapshot) -> Option<&[u8]> {
        self.store.read_visible(block, snapshot)
    }

    pub fn checkpoint(cx: &Cx) -> Result<(), Box<asupersync::Error>> {
        cx.checkpoint().map_err(Box::new)
    }

    pub fn inspect_image(image: &[u8]) -> Result<FsFlavor, DetectionError> {
        detect_filesystem(image)
    }

    pub fn parse_ext4(image: &[u8]) -> Result<Ext4Superblock, ParseError> {
        Ext4Superblock::parse_from_image(image)
    }

    pub fn parse_btrfs(image: &[u8]) -> Result<BtrfsSuperblock, ParseError> {
        BtrfsSuperblock::parse_from_image(image)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffs_types::{
        BTRFS_MAGIC, BTRFS_SUPER_INFO_OFFSET, BTRFS_SUPER_INFO_SIZE, ByteOffset, EXT4_SUPER_MAGIC,
        EXT4_SUPERBLOCK_OFFSET, EXT4_SUPERBLOCK_SIZE,
    };
    use std::sync::Mutex;

    /// In-memory ByteDevice for testing (no file I/O).
    #[derive(Debug)]
    struct TestDevice {
        data: Mutex<Vec<u8>>,
    }

    impl TestDevice {
        fn from_vec(v: Vec<u8>) -> Self {
            Self {
                data: Mutex::new(v),
            }
        }
    }

    impl ByteDevice for TestDevice {
        fn len_bytes(&self) -> u64 {
            self.data.lock().unwrap().len() as u64
        }

        #[allow(clippy::cast_possible_truncation)]
        fn read_exact_at(
            &self,
            _cx: &Cx,
            offset: ByteOffset,
            buf: &mut [u8],
        ) -> ffs_error::Result<()> {
            let off = offset.0 as usize;
            let data = self.data.lock().unwrap();
            let end = off + buf.len();
            if end > data.len() {
                return Err(FfsError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "read past end",
                )));
            }
            buf.copy_from_slice(&data[off..end]);
            drop(data);
            Ok(())
        }

        #[allow(clippy::cast_possible_truncation)]
        fn write_all_at(&self, _cx: &Cx, offset: ByteOffset, buf: &[u8]) -> ffs_error::Result<()> {
            let off = offset.0 as usize;
            let mut data = self.data.lock().unwrap();
            let end = off + buf.len();
            if end > data.len() {
                return Err(FfsError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "write past end",
                )));
            }
            data[off..end].copy_from_slice(buf);
            drop(data);
            Ok(())
        }

        fn sync(&self, _cx: &Cx) -> ffs_error::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn detect_ext4_and_btrfs_images() {
        let mut ext4_img = vec![0_u8; EXT4_SUPERBLOCK_OFFSET + EXT4_SUPERBLOCK_SIZE];
        let sb = EXT4_SUPERBLOCK_OFFSET;
        ext4_img[sb + 0x38..sb + 0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
        ext4_img[sb + 0x18..sb + 0x1C].copy_from_slice(&0_u32.to_le_bytes());
        let ext4 = detect_filesystem(&ext4_img).expect("detect ext4");
        assert!(matches!(ext4, FsFlavor::Ext4(_)));

        let mut btrfs_img = vec![0_u8; BTRFS_SUPER_INFO_OFFSET + BTRFS_SUPER_INFO_SIZE];
        let sb2 = BTRFS_SUPER_INFO_OFFSET;
        btrfs_img[sb2 + 0x40..sb2 + 0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        btrfs_img[sb2 + 0x90..sb2 + 0x94].copy_from_slice(&4096_u32.to_le_bytes());
        btrfs_img[sb2 + 0x94..sb2 + 0x98].copy_from_slice(&4096_u32.to_le_bytes());
        let btrfs = detect_filesystem(&btrfs_img).expect("detect btrfs");
        assert!(matches!(btrfs, FsFlavor::Btrfs(_)));
    }

    // ── FsOps VFS trait tests ─────────────────────────────────────────

    /// A stub FsOps implementation for testing that the trait is object-safe
    /// and can be used as a trait object behind `dyn`.
    struct StubFs;

    impl FsOps for StubFs {
        fn getattr(&self, _cx: &Cx, ino: InodeNumber) -> ffs_error::Result<InodeAttr> {
            if ino == InodeNumber(1) {
                Ok(InodeAttr {
                    ino,
                    size: 4096,
                    blocks: 8,
                    atime: SystemTime::UNIX_EPOCH,
                    mtime: SystemTime::UNIX_EPOCH,
                    ctime: SystemTime::UNIX_EPOCH,
                    crtime: SystemTime::UNIX_EPOCH,
                    kind: FileType::Directory,
                    perm: 0o755,
                    nlink: 2,
                    uid: 0,
                    gid: 0,
                    rdev: 0,
                    blksize: 4096,
                })
            } else {
                Err(FfsError::NotFound(format!("inode {ino}")))
            }
        }

        fn lookup(
            &self,
            _cx: &Cx,
            _parent: InodeNumber,
            name: &OsStr,
        ) -> ffs_error::Result<InodeAttr> {
            if name == "hello.txt" {
                Ok(InodeAttr {
                    ino: InodeNumber(11),
                    size: 13,
                    blocks: 8,
                    atime: SystemTime::UNIX_EPOCH,
                    mtime: SystemTime::UNIX_EPOCH,
                    ctime: SystemTime::UNIX_EPOCH,
                    crtime: SystemTime::UNIX_EPOCH,
                    kind: FileType::RegularFile,
                    perm: 0o644,
                    nlink: 1,
                    uid: 1000,
                    gid: 1000,
                    rdev: 0,
                    blksize: 4096,
                })
            } else {
                Err(FfsError::NotFound(name.to_string_lossy().into_owned()))
            }
        }

        fn readdir(
            &self,
            _cx: &Cx,
            ino: InodeNumber,
            offset: u64,
        ) -> ffs_error::Result<Vec<DirEntry>> {
            if ino != InodeNumber(1) {
                return Err(FfsError::NotDirectory);
            }
            let all = vec![
                DirEntry {
                    ino: InodeNumber(1),
                    offset: 1,
                    kind: FileType::Directory,
                    name: b".".to_vec(),
                },
                DirEntry {
                    ino: InodeNumber(1),
                    offset: 2,
                    kind: FileType::Directory,
                    name: b"..".to_vec(),
                },
                DirEntry {
                    ino: InodeNumber(11),
                    offset: 3,
                    kind: FileType::RegularFile,
                    name: b"hello.txt".to_vec(),
                },
            ];
            Ok(all.into_iter().filter(|e| e.offset > offset).collect())
        }

        fn read(
            &self,
            _cx: &Cx,
            ino: InodeNumber,
            offset: u64,
            size: u32,
        ) -> ffs_error::Result<Vec<u8>> {
            if ino == InodeNumber(1) {
                return Err(FfsError::IsDirectory);
            }
            let data = b"Hello, world!";
            let start = usize::try_from(offset)
                .unwrap_or(usize::MAX)
                .min(data.len());
            let end = (start + size as usize).min(data.len());
            Ok(data[start..end].to_vec())
        }

        fn readlink(&self, _cx: &Cx, _ino: InodeNumber) -> ffs_error::Result<Vec<u8>> {
            Err(FfsError::Format("not a symlink".into()))
        }
    }

    #[test]
    fn fsops_getattr_root() {
        let fs = StubFs;
        let cx = Cx::for_testing();
        let attr = fs.getattr(&cx, InodeNumber(1)).unwrap();
        assert_eq!(attr.ino, InodeNumber(1));
        assert_eq!(attr.kind, FileType::Directory);
        assert_eq!(attr.perm, 0o755);
        assert_eq!(attr.nlink, 2);
    }

    #[test]
    fn fsops_getattr_not_found() {
        let fs = StubFs;
        let cx = Cx::for_testing();
        let err = fs.getattr(&cx, InodeNumber(999)).unwrap_err();
        assert_eq!(err.to_errno(), libc::ENOENT);
    }

    #[test]
    fn fsops_lookup_found() {
        let fs = StubFs;
        let cx = Cx::for_testing();
        let attr = fs
            .lookup(&cx, InodeNumber(1), OsStr::new("hello.txt"))
            .unwrap();
        assert_eq!(attr.ino, InodeNumber(11));
        assert_eq!(attr.kind, FileType::RegularFile);
    }

    #[test]
    fn fsops_lookup_not_found() {
        let fs = StubFs;
        let cx = Cx::for_testing();
        let err = fs
            .lookup(&cx, InodeNumber(1), OsStr::new("missing"))
            .unwrap_err();
        assert_eq!(err.to_errno(), libc::ENOENT);
    }

    #[test]
    fn fsops_readdir_with_offset() {
        let fs = StubFs;
        let cx = Cx::for_testing();

        // Full listing from offset 0
        let entries = fs.readdir(&cx, InodeNumber(1), 0).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].name_str(), ".");
        assert_eq!(entries[2].name_str(), "hello.txt");

        // Resume from offset 2 (skip . and ..)
        let entries = fs.readdir(&cx, InodeNumber(1), 2).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name_str(), "hello.txt");
    }

    #[test]
    fn fsops_readdir_not_directory() {
        let fs = StubFs;
        let cx = Cx::for_testing();
        let err = fs.readdir(&cx, InodeNumber(11), 0).unwrap_err();
        assert_eq!(err.to_errno(), libc::ENOTDIR);
    }

    #[test]
    fn fsops_read_file() {
        let fs = StubFs;
        let cx = Cx::for_testing();
        let data = fs.read(&cx, InodeNumber(11), 0, 5).unwrap();
        assert_eq!(&data, b"Hello");

        // Read from offset
        let data = fs.read(&cx, InodeNumber(11), 7, 100).unwrap();
        assert_eq!(&data, b"world!");
    }

    #[test]
    fn fsops_read_directory_returns_is_directory() {
        let fs = StubFs;
        let cx = Cx::for_testing();
        let err = fs.read(&cx, InodeNumber(1), 0, 4096).unwrap_err();
        assert_eq!(err.to_errno(), libc::EISDIR);
    }

    #[test]
    fn fsops_trait_is_object_safe() {
        // Verify FsOps can be used as dyn trait object
        let fs: Box<dyn FsOps> = Box::new(StubFs);
        let cx = Cx::for_testing();
        let attr = fs.getattr(&cx, InodeNumber(1)).unwrap();
        assert_eq!(attr.kind, FileType::Directory);
    }

    #[test]
    fn dir_entry_name_str() {
        let entry = DirEntry {
            ino: InodeNumber(5),
            offset: 1,
            kind: FileType::RegularFile,
            name: b"test.txt".to_vec(),
        };
        assert_eq!(entry.name_str(), "test.txt");
    }

    #[test]
    fn file_type_variants_are_distinct() {
        let types = [
            FileType::RegularFile,
            FileType::Directory,
            FileType::Symlink,
            FileType::BlockDevice,
            FileType::CharDevice,
            FileType::Fifo,
            FileType::Socket,
        ];
        for (i, a) in types.iter().enumerate() {
            for (j, b) in types.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    // ── inode_to_attr tests ───────────────────────────────────────────────

    /// Build a minimal Ext4Superblock for unit tests.
    fn make_test_superblock() -> Ext4Superblock {
        let mut sb_buf = vec![0_u8; EXT4_SUPERBLOCK_SIZE];
        sb_buf[0x38..0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
        sb_buf[0x18..0x1C].copy_from_slice(&2_u32.to_le_bytes()); // log_block_size=2 → 4K
        sb_buf[0x00..0x04].copy_from_slice(&1024_u32.to_le_bytes()); // inodes_count
        sb_buf[0x04..0x08].copy_from_slice(&4096_u32.to_le_bytes()); // blocks_count
        sb_buf[0x20..0x24].copy_from_slice(&4096_u32.to_le_bytes()); // blocks_per_group
        sb_buf[0x28..0x2C].copy_from_slice(&1024_u32.to_le_bytes()); // inodes_per_group
        sb_buf[0x58..0x5A].copy_from_slice(&256_u16.to_le_bytes()); // inode_size
        Ext4Superblock::parse_superblock_region(&sb_buf).expect("test superblock")
    }

    /// Build a minimal inode buffer with mode and device encoding in i_block.
    fn make_test_inode(mode: u16, block0: u32, block1: u32) -> Ext4Inode {
        let mut buf = [0_u8; 128];
        buf[0x00..0x02].copy_from_slice(&mode.to_le_bytes());
        buf[0x28..0x2C].copy_from_slice(&block0.to_le_bytes());
        buf[0x2C..0x30].copy_from_slice(&block1.to_le_bytes());
        Ext4Inode::parse_from_bytes(&buf).expect("test inode")
    }

    #[test]
    fn inode_to_attr_block_device_rdev() {
        use ffs_types::{S_IFBLK, S_IFCHR};

        let sb = make_test_superblock();

        // Block device: major=8, minor=1 → /dev/sda1 (new format in i_block[1])
        let inode = make_test_inode(S_IFBLK | 0o660, 0, 0x0801);
        let attr = inode_to_attr(&sb, InodeNumber(100), &inode);
        assert_eq!(attr.kind, FileType::BlockDevice);
        assert_eq!(attr.rdev, 0x0801);
        assert_eq!(attr.perm, 0o660);

        // Char device: major=1, minor=3 → /dev/null (old format in i_block[0])
        let inode = make_test_inode(S_IFCHR | 0o666, 0x0103, 0);
        let attr = inode_to_attr(&sb, InodeNumber(101), &inode);
        assert_eq!(attr.kind, FileType::CharDevice);
        assert_eq!(attr.rdev, 0x0103);
        assert_eq!(attr.perm, 0o666);
    }

    #[test]
    fn inode_to_attr_regular_file_rdev_zero() {
        use ffs_types::S_IFREG;

        let sb = make_test_superblock();
        let inode = make_test_inode(S_IFREG | 0o644, 0, 0);
        let attr = inode_to_attr(&sb, InodeNumber(11), &inode);
        assert_eq!(attr.kind, FileType::RegularFile);
        assert_eq!(attr.rdev, 0);
        assert_eq!(attr.perm, 0o644);
        assert_eq!(attr.uid, 0);
        assert_eq!(attr.gid, 0);
    }

    // ── listxattr/getxattr via FsOps defaults ────────────────────────────

    #[test]
    fn fsops_listxattr_default_returns_empty() {
        let fs = StubFs;
        let cx = Cx::for_testing();
        let names = fs.listxattr(&cx, InodeNumber(1)).unwrap();
        assert!(names.is_empty());
    }

    #[test]
    fn fsops_getxattr_default_returns_none() {
        let fs = StubFs;
        let cx = Cx::for_testing();
        let val = fs.getxattr(&cx, InodeNumber(1), "user.test").unwrap();
        assert!(val.is_none());
    }

    // ── OpenFs tests ─────────────────────────────────────────────────────

    /// Build a minimal synthetic ext4 image for OpenFs testing.
    #[allow(clippy::cast_possible_truncation)]
    fn build_ext4_image(block_size_log: u32) -> Vec<u8> {
        let block_size = 1024_u32 << block_size_log;
        let image_size: u32 = 128 * 1024; // 128K
        let mut image = vec![0_u8; image_size as usize];
        let sb_off = EXT4_SUPERBLOCK_OFFSET;

        // magic
        image[sb_off + 0x38..sb_off + 0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
        // log_block_size
        image[sb_off + 0x18..sb_off + 0x1C].copy_from_slice(&block_size_log.to_le_bytes());
        // blocks_count_lo
        let blocks_count = image_size / block_size;
        image[sb_off + 0x04..sb_off + 0x08].copy_from_slice(&blocks_count.to_le_bytes());
        // inodes_count
        image[sb_off..sb_off + 0x04].copy_from_slice(&128_u32.to_le_bytes());
        // first_data_block
        let first_data = u32::from(block_size == 1024);
        image[sb_off + 0x14..sb_off + 0x18].copy_from_slice(&first_data.to_le_bytes());
        // blocks_per_group
        image[sb_off + 0x20..sb_off + 0x24].copy_from_slice(&blocks_count.to_le_bytes());
        // inodes_per_group
        image[sb_off + 0x28..sb_off + 0x2C].copy_from_slice(&128_u32.to_le_bytes());
        // inode_size = 256
        image[sb_off + 0x58..sb_off + 0x5A].copy_from_slice(&256_u16.to_le_bytes());
        // rev_level = 1 (dynamic)
        image[sb_off + 0x4C..sb_off + 0x50].copy_from_slice(&1_u32.to_le_bytes());
        // feature_incompat = FILETYPE | EXTENTS
        let filetype: u32 = 0x0002;
        let extents: u32 = 0x0040;
        image[sb_off + 0x60..sb_off + 0x64].copy_from_slice(&(filetype | extents).to_le_bytes());
        // first_ino
        image[sb_off + 0x54..sb_off + 0x58].copy_from_slice(&11_u32.to_le_bytes());

        image
    }

    #[test]
    fn open_options_default_enables_validation() {
        let opts = OpenOptions::default();
        assert!(!opts.skip_validation);
    }

    #[test]
    fn open_fs_from_ext4_image() {
        let image = build_ext4_image(2); // 4K blocks
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();

        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();
        assert!(fs.is_ext4());
        assert!(!fs.is_btrfs());
        assert_eq!(fs.block_size(), 4096);
        assert!(fs.ext4_geometry.is_some());

        let geom = fs.ext4_geometry.as_ref().unwrap();
        assert!(geom.groups_count > 0);
        assert!(geom.group_desc_size == 32 || geom.group_desc_size == 64);
    }

    #[test]
    fn open_fs_debug_format() {
        let image = build_ext4_image(2);
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();

        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();
        let debug = format!("{fs:?}");
        assert!(debug.contains("OpenFs"));
        assert!(debug.contains("dev_len"));
    }

    #[test]
    fn open_fs_rejects_garbage() {
        let garbage = vec![0xAB_u8; 1024 * 128];
        let dev = TestDevice::from_vec(garbage);
        let cx = Cx::for_testing();

        let err = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap_err();
        assert_eq!(err.to_errno(), libc::EINVAL); // Format error
    }

    #[test]
    fn open_fs_skip_validation() {
        // Build an image with bad features (should fail validation but pass with skip)
        let mut image = build_ext4_image(2);
        let sb_off = EXT4_SUPERBLOCK_OFFSET;
        // Set unsupported incompat feature (COMPRESSION = 0x0001)
        let bad_incompat: u32 = 0x0002 | 0x0040 | 0x0001; // FILETYPE | EXTENTS | COMPRESSION
        image[sb_off + 0x60..sb_off + 0x64].copy_from_slice(&bad_incompat.to_le_bytes());

        let dev = TestDevice::from_vec(image.clone());
        let cx = Cx::for_testing();

        // Should fail with default options
        let err = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap_err();
        assert!(
            matches!(err, FfsError::UnsupportedFeature(_) | FfsError::Format(_)),
            "expected feature/format error, got {err:?}",
        );

        // Should succeed with skip_validation
        let dev2 = TestDevice::from_vec(image);
        let opts = OpenOptions {
            skip_validation: true,
        };
        let fs = OpenFs::from_device(&cx, Box::new(dev2), &opts).unwrap();
        assert!(fs.is_ext4());
    }

    #[test]
    fn parse_error_to_ffs_mapping() {
        // Feature error
        let e = parse_error_to_ffs(&ParseError::InvalidField {
            field: "feature_incompat",
            reason: "unsupported flags",
        });
        assert!(matches!(e, FfsError::UnsupportedFeature(_)));

        // Geometry error
        let e = parse_error_to_ffs(&ParseError::InvalidField {
            field: "block_size",
            reason: "out of range",
        });
        assert!(matches!(e, FfsError::InvalidGeometry(_)));

        // Generic format error
        let e = parse_error_to_ffs(&ParseError::InvalidField {
            field: "magic",
            reason: "wrong value",
        });
        assert!(matches!(e, FfsError::Format(_)));

        // Magic error
        let e = parse_error_to_ffs(&ParseError::InvalidMagic {
            expected: 0xEF53,
            actual: 0x0000,
        });
        assert!(matches!(e, FfsError::Format(_)));

        // Truncation error
        let e = parse_error_to_ffs(&ParseError::InsufficientData {
            needed: 100,
            offset: 0,
            actual: 50,
        });
        assert!(matches!(e, FfsError::Corruption { .. }));
    }

    #[test]
    fn parse_error_to_ffs_new_geometry_fields() {
        // desc_size → InvalidGeometry
        let e = parse_error_to_ffs(&ParseError::InvalidField {
            field: "s_desc_size",
            reason: "must be >= 32 when non-zero",
        });
        assert!(
            matches!(e, FfsError::InvalidGeometry(_)),
            "desc_size should map to InvalidGeometry, got: {e:?}",
        );

        // first_data_block → InvalidGeometry
        let e = parse_error_to_ffs(&ParseError::InvalidField {
            field: "s_first_data_block",
            reason: "must be 1 for 1K block size",
        });
        assert!(
            matches!(e, FfsError::InvalidGeometry(_)),
            "first_data_block should map to InvalidGeometry, got: {e:?}",
        );

        // blocks_count → InvalidGeometry
        let e = parse_error_to_ffs(&ParseError::InvalidField {
            field: "s_blocks_count",
            reason: "group descriptor table extends beyond device",
        });
        assert!(
            matches!(e, FfsError::InvalidGeometry(_)),
            "blocks_count should map to InvalidGeometry, got: {e:?}",
        );

        // inodes_count → InvalidGeometry
        let e = parse_error_to_ffs(&ParseError::InvalidField {
            field: "s_inodes_count",
            reason: "inodes_count exceeds groups * inodes_per_group",
        });
        assert!(
            matches!(e, FfsError::InvalidGeometry(_)),
            "inodes_count should map to InvalidGeometry, got: {e:?}",
        );
    }

    #[test]
    fn ext4_geometry_has_all_fields() {
        let image = build_ext4_image(2); // 4K blocks
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();

        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();
        let geom = fs.ext4_geometry.as_ref().unwrap();

        assert_eq!(geom.block_size, 4096);
        assert_eq!(geom.inodes_count, 128);
        assert_eq!(geom.inodes_per_group, 128);
        assert_eq!(geom.first_ino, 11);
        assert_eq!(geom.inode_size, 256);
        assert!(geom.groups_count > 0);
        assert!(geom.group_desc_size == 32 || geom.group_desc_size == 64);
        // 32-bit fs (no 64BIT flag set)
        assert!(!geom.is_64bit);
        // No metadata_csum flag set
        assert!(!geom.has_metadata_csum);
    }

    #[test]
    fn ext4_geometry_1k_blocks() {
        let image = build_ext4_image(0); // 1K blocks
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();

        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();
        let geom = fs.ext4_geometry.as_ref().unwrap();
        assert_eq!(geom.block_size, 1024);
    }

    #[test]
    fn ext4_geometry_serializes() {
        let geom = Ext4Geometry {
            block_size: 4096,
            inodes_count: 8192,
            inodes_per_group: 8192,
            first_ino: 11,
            inode_size: 256,
            groups_count: 1,
            group_desc_size: 32,
            csum_seed: 0,
            is_64bit: false,
            has_metadata_csum: false,
        };
        let json = serde_json::to_string(&geom).unwrap();
        let deser: Ext4Geometry = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.block_size, 4096);
        assert_eq!(deser.inodes_count, 8192);
        assert_eq!(deser.groups_count, 1);
    }

    // ── Device-based inode read tests ──────────────────────────────────

    /// Build an ext4 image with a valid group descriptor and a root inode.
    #[allow(clippy::cast_possible_truncation)]
    fn build_ext4_image_with_inode() -> Vec<u8> {
        let block_size: u32 = 4096;
        let image_size: u32 = 256 * 1024; // 256K = 64 blocks
        let mut image = vec![0_u8; image_size as usize];
        let sb_off = EXT4_SUPERBLOCK_OFFSET;

        // ── Superblock ──
        image[sb_off + 0x38..sb_off + 0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
        image[sb_off + 0x18..sb_off + 0x1C].copy_from_slice(&2_u32.to_le_bytes()); // log=2 → 4K
        let blocks_count = image_size / block_size;
        image[sb_off + 0x04..sb_off + 0x08].copy_from_slice(&blocks_count.to_le_bytes());
        image[sb_off..sb_off + 0x04].copy_from_slice(&128_u32.to_le_bytes()); // inodes_count
        image[sb_off + 0x14..sb_off + 0x18].copy_from_slice(&0_u32.to_le_bytes()); // first_data_block
        image[sb_off + 0x20..sb_off + 0x24].copy_from_slice(&blocks_count.to_le_bytes()); // blocks_per_group
        image[sb_off + 0x28..sb_off + 0x2C].copy_from_slice(&128_u32.to_le_bytes()); // inodes_per_group
        image[sb_off + 0x58..sb_off + 0x5A].copy_from_slice(&256_u16.to_le_bytes()); // inode_size
        image[sb_off + 0x4C..sb_off + 0x50].copy_from_slice(&1_u32.to_le_bytes()); // rev_level=DYNAMIC
        let incompat: u32 = 0x0002 | 0x0040; // FILETYPE | EXTENTS
        image[sb_off + 0x60..sb_off + 0x64].copy_from_slice(&incompat.to_le_bytes());
        image[sb_off + 0x54..sb_off + 0x58].copy_from_slice(&11_u32.to_le_bytes()); // first_ino

        // ── Group descriptor at block 1 (offset 4096) ──
        // 32-byte group descriptor (no 64BIT feature).
        let gd_off: usize = 4096;
        // bg_block_bitmap = block 2
        image[gd_off..gd_off + 4].copy_from_slice(&2_u32.to_le_bytes());
        // bg_inode_bitmap = block 3
        image[gd_off + 4..gd_off + 8].copy_from_slice(&3_u32.to_le_bytes());
        // bg_inode_table = block 4 (offset 16384)
        image[gd_off + 8..gd_off + 12].copy_from_slice(&4_u32.to_le_bytes());

        // ── Root inode (#2) in the inode table ──
        // Inode 2 is at index 1 (0-based) in the table.
        // offset = 16384 + 1 * 256 = 16640
        let ino_off: usize = 16384 + 256;
        // mode = S_IFDIR | 0o755
        let mode: u16 = 0o040_755;
        image[ino_off..ino_off + 2].copy_from_slice(&mode.to_le_bytes());
        // uid_lo = 0
        image[ino_off + 2..ino_off + 4].copy_from_slice(&0_u16.to_le_bytes());
        // size = 4096
        image[ino_off + 4..ino_off + 8].copy_from_slice(&4096_u32.to_le_bytes());
        // links_count = 2
        image[ino_off + 0x1A..ino_off + 0x1C].copy_from_slice(&2_u16.to_le_bytes());
        // i_extra_isize = 32 (for 256-byte inodes, extra area starts at 128)
        image[ino_off + 0x80..ino_off + 0x82].copy_from_slice(&32_u16.to_le_bytes());

        image
    }

    #[test]
    fn read_inode_via_device() {
        let image = build_ext4_image_with_inode();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();

        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();
        let inode = fs.read_inode(&cx, InodeNumber(2)).unwrap();

        assert!(inode.is_dir());
        assert_eq!(inode.size, 4096);
        assert_eq!(inode.links_count, 2);
        assert_eq!(inode.permission_bits(), 0o755);
    }

    #[test]
    fn read_inode_attr_via_device() {
        let image = build_ext4_image_with_inode();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();

        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();
        let attr = fs.read_inode_attr(&cx, InodeNumber(2)).unwrap();

        assert_eq!(attr.ino, InodeNumber(2));
        assert_eq!(attr.kind, FileType::Directory);
        assert_eq!(attr.perm, 0o755);
        assert_eq!(attr.nlink, 2);
        assert_eq!(attr.size, 4096);
        assert_eq!(attr.blksize, 4096);
    }

    #[test]
    fn read_inode_zero_fails() {
        let image = build_ext4_image_with_inode();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();

        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();
        let err = fs.read_inode(&cx, InodeNumber(0)).unwrap_err();
        // inode 0 is invalid → should produce an error
        assert!(
            !matches!(err, FfsError::Io(_)),
            "expected parse/format error, got I/O: {err:?}",
        );
    }

    #[test]
    fn read_inode_out_of_bounds_fails() {
        let image = build_ext4_image_with_inode();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();

        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();
        // Image has 128 inodes; 129 is out of range.
        let err = fs.read_inode(&cx, InodeNumber(129)).unwrap_err();
        assert!(
            !matches!(err, FfsError::Io(_)),
            "expected parse/format error, got I/O: {err:?}",
        );
    }

    #[test]
    fn read_group_desc_via_device() {
        let image = build_ext4_image_with_inode();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();

        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();
        let gd = fs.read_group_desc(&cx, GroupNumber(0)).unwrap();
        assert_eq!(gd.block_bitmap, 2);
        assert_eq!(gd.inode_bitmap, 3);
        assert_eq!(gd.inode_table, 4);
    }

    // ── Device-based extent mapping tests ─────────────────────────────

    /// Build an ext4 image with file inodes that have extent trees.
    ///
    /// Layout (4K block size, 256K image = 64 blocks):
    /// - Block 0: superblock at offset 1024
    /// - Block 1: group descriptor table
    /// - Block 4+: inode table
    /// - Block 10: data for inode #11 (leaf extent)
    /// - Block 11: extent leaf block for inode #12 (index extent)
    /// - Block 12: data for inode #12
    #[allow(clippy::cast_possible_truncation)]
    fn build_ext4_image_with_extents() -> Vec<u8> {
        let block_size: u32 = 4096;
        let image_size: u32 = 256 * 1024;
        let mut image = vec![0_u8; image_size as usize];
        let sb_off = EXT4_SUPERBLOCK_OFFSET;

        // ── Superblock ──
        image[sb_off + 0x38..sb_off + 0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
        image[sb_off + 0x18..sb_off + 0x1C].copy_from_slice(&2_u32.to_le_bytes()); // log=2 → 4K
        let blocks_count = image_size / block_size;
        image[sb_off + 0x04..sb_off + 0x08].copy_from_slice(&blocks_count.to_le_bytes());
        image[sb_off..sb_off + 0x04].copy_from_slice(&128_u32.to_le_bytes()); // inodes_count
        image[sb_off + 0x14..sb_off + 0x18].copy_from_slice(&0_u32.to_le_bytes()); // first_data_block=0
        image[sb_off + 0x20..sb_off + 0x24].copy_from_slice(&blocks_count.to_le_bytes());
        image[sb_off + 0x28..sb_off + 0x2C].copy_from_slice(&128_u32.to_le_bytes());
        image[sb_off + 0x58..sb_off + 0x5A].copy_from_slice(&256_u16.to_le_bytes()); // inode_size
        image[sb_off + 0x4C..sb_off + 0x50].copy_from_slice(&1_u32.to_le_bytes()); // rev_level=DYNAMIC
        let incompat: u32 = 0x0002 | 0x0040; // FILETYPE | EXTENTS
        image[sb_off + 0x60..sb_off + 0x64].copy_from_slice(&incompat.to_le_bytes());
        image[sb_off + 0x54..sb_off + 0x58].copy_from_slice(&11_u32.to_le_bytes()); // first_ino

        // ── Group descriptor at block 1 ──
        let gd_off: usize = 4096;
        image[gd_off..gd_off + 4].copy_from_slice(&2_u32.to_le_bytes()); // block_bitmap
        image[gd_off + 4..gd_off + 8].copy_from_slice(&3_u32.to_le_bytes()); // inode_bitmap
        image[gd_off + 8..gd_off + 12].copy_from_slice(&4_u32.to_le_bytes()); // inode_table

        // ── Inode #11 (index 10): regular file with leaf extent ──
        let ino11_off: usize = 4 * 4096 + 10 * 256;
        image[ino11_off..ino11_off + 2].copy_from_slice(&0o100_644_u16.to_le_bytes()); // S_IFREG|0644
        image[ino11_off + 4..ino11_off + 8].copy_from_slice(&14_u32.to_le_bytes()); // size=14
        image[ino11_off + 0x1A..ino11_off + 0x1C].copy_from_slice(&1_u16.to_le_bytes()); // links
        image[ino11_off + 0x20..ino11_off + 0x24].copy_from_slice(&0x0008_0000_u32.to_le_bytes()); // EXT4_EXTENTS_FL
        image[ino11_off + 0x80..ino11_off + 0x82].copy_from_slice(&32_u16.to_le_bytes()); // extra

        // Extent tree (depth=0, 1 leaf extent: logical 0 → physical 10)
        let e = ino11_off + 0x28;
        image[e..e + 2].copy_from_slice(&0xF30A_u16.to_le_bytes()); // magic
        image[e + 2..e + 4].copy_from_slice(&1_u16.to_le_bytes()); // entries
        image[e + 4..e + 6].copy_from_slice(&4_u16.to_le_bytes()); // max
        image[e + 6..e + 8].copy_from_slice(&0_u16.to_le_bytes()); // depth=0
        image[e + 12..e + 16].copy_from_slice(&0_u32.to_le_bytes()); // logical_block=0
        image[e + 16..e + 18].copy_from_slice(&1_u16.to_le_bytes()); // raw_len=1
        image[e + 18..e + 20].copy_from_slice(&0_u16.to_le_bytes()); // start_hi=0
        image[e + 20..e + 24].copy_from_slice(&10_u32.to_le_bytes()); // start_lo=10

        // Data at block 10
        let d = 10 * 4096;
        image[d..d + 14].copy_from_slice(b"Hello, extent!");

        // ── Inode #12 (index 11): regular file with index extent (depth=1) ──
        let ino12_off: usize = 4 * 4096 + 11 * 256;
        image[ino12_off..ino12_off + 2].copy_from_slice(&0o100_644_u16.to_le_bytes());
        image[ino12_off + 4..ino12_off + 8].copy_from_slice(&14_u32.to_le_bytes()); // size=14
        image[ino12_off + 0x1A..ino12_off + 0x1C].copy_from_slice(&1_u16.to_le_bytes());
        image[ino12_off + 0x20..ino12_off + 0x24].copy_from_slice(&0x0008_0000_u32.to_le_bytes()); // EXT4_EXTENTS_FL
        image[ino12_off + 0x80..ino12_off + 0x82].copy_from_slice(&32_u16.to_le_bytes());

        // Extent tree (depth=1, 1 index entry pointing to block 11)
        let e = ino12_off + 0x28;
        image[e..e + 2].copy_from_slice(&0xF30A_u16.to_le_bytes()); // magic
        image[e + 2..e + 4].copy_from_slice(&1_u16.to_le_bytes()); // entries
        image[e + 4..e + 6].copy_from_slice(&4_u16.to_le_bytes()); // max
        image[e + 6..e + 8].copy_from_slice(&1_u16.to_le_bytes()); // depth=1
        image[e + 12..e + 16].copy_from_slice(&0_u32.to_le_bytes()); // logical_block=0
        image[e + 16..e + 20].copy_from_slice(&11_u32.to_le_bytes()); // leaf_lo=11
        image[e + 20..e + 22].copy_from_slice(&0_u16.to_le_bytes()); // leaf_hi=0

        // Block 11: leaf extent block (depth=0, 1 extent: logical 0 → physical 12)
        let l = 11 * 4096;
        image[l..l + 2].copy_from_slice(&0xF30A_u16.to_le_bytes()); // magic
        image[l + 2..l + 4].copy_from_slice(&1_u16.to_le_bytes()); // entries
        image[l + 4..l + 6].copy_from_slice(&340_u16.to_le_bytes()); // max (4K block)
        image[l + 6..l + 8].copy_from_slice(&0_u16.to_le_bytes()); // depth=0
        image[l + 12..l + 16].copy_from_slice(&0_u32.to_le_bytes()); // logical_block=0
        image[l + 16..l + 18].copy_from_slice(&1_u16.to_le_bytes()); // raw_len=1
        image[l + 18..l + 20].copy_from_slice(&0_u16.to_le_bytes()); // start_hi=0
        image[l + 20..l + 24].copy_from_slice(&12_u32.to_le_bytes()); // start_lo=12

        // Data at block 12
        let d = 12 * 4096;
        image[d..d + 14].copy_from_slice(b"Index extent!\n");

        image
    }

    #[test]
    fn resolve_extent_leaf_only() {
        let image = build_ext4_image_with_extents();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();
        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();

        let inode = fs.read_inode(&cx, InodeNumber(11)).unwrap();
        let phys = fs.resolve_extent(&cx, &inode, 0).unwrap();
        assert_eq!(phys, Some(10));
    }

    #[test]
    fn resolve_extent_hole() {
        let image = build_ext4_image_with_extents();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();
        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();

        let inode = fs.read_inode(&cx, InodeNumber(11)).unwrap();
        // Logical block 1 is not mapped — should be a hole.
        let phys = fs.resolve_extent(&cx, &inode, 1).unwrap();
        assert_eq!(phys, None);
    }

    #[test]
    fn resolve_extent_index() {
        let image = build_ext4_image_with_extents();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();
        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();

        let inode = fs.read_inode(&cx, InodeNumber(12)).unwrap();
        let phys = fs.resolve_extent(&cx, &inode, 0).unwrap();
        assert_eq!(phys, Some(12));
    }

    #[test]
    fn collect_extents_leaf() {
        let image = build_ext4_image_with_extents();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();
        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();

        let inode = fs.read_inode(&cx, InodeNumber(11)).unwrap();
        let extents = fs.collect_extents(&cx, &inode).unwrap();
        assert_eq!(extents.len(), 1);
        assert_eq!(extents[0].logical_block, 0);
        assert_eq!(extents[0].physical_start, 10);
        assert_eq!(extents[0].actual_len(), 1);
        assert!(!extents[0].is_unwritten());
    }

    #[test]
    fn collect_extents_index() {
        let image = build_ext4_image_with_extents();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();
        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();

        let inode = fs.read_inode(&cx, InodeNumber(12)).unwrap();
        let extents = fs.collect_extents(&cx, &inode).unwrap();
        assert_eq!(extents.len(), 1);
        assert_eq!(extents[0].logical_block, 0);
        assert_eq!(extents[0].physical_start, 12);
        assert_eq!(extents[0].actual_len(), 1);
    }

    #[test]
    fn read_file_data_leaf() {
        let image = build_ext4_image_with_extents();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();
        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();

        let inode = fs.read_inode(&cx, InodeNumber(11)).unwrap();
        let mut buf = vec![0_u8; 14];
        let n = fs.read_file_data(&cx, &inode, 0, &mut buf).unwrap();
        assert_eq!(n, 14);
        assert_eq!(&buf[..n], b"Hello, extent!");
    }

    #[test]
    fn read_file_data_index() {
        let image = build_ext4_image_with_extents();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();
        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();

        let inode = fs.read_inode(&cx, InodeNumber(12)).unwrap();
        let mut buf = vec![0_u8; 14];
        let n = fs.read_file_data(&cx, &inode, 0, &mut buf).unwrap();
        assert_eq!(n, 14);
        assert_eq!(&buf[..n], b"Index extent!\n");
    }

    #[test]
    fn read_file_data_partial() {
        let image = build_ext4_image_with_extents();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();
        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();

        let inode = fs.read_inode(&cx, InodeNumber(11)).unwrap();
        let mut buf = vec![0_u8; 100];
        let n = fs.read_file_data(&cx, &inode, 7, &mut buf).unwrap();
        assert_eq!(n, 7); // 14 - 7 = 7 bytes remaining
        assert_eq!(&buf[..n], b"extent!");
    }

    #[test]
    fn read_file_data_past_eof() {
        let image = build_ext4_image_with_extents();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();
        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();

        let inode = fs.read_inode(&cx, InodeNumber(11)).unwrap();
        let mut buf = vec![0_u8; 10];
        let n = fs.read_file_data(&cx, &inode, 100, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    // ── Device-based directory tests ──────────────────────────────────

    /// Build an ext4 image with a directory inode containing entries.
    ///
    /// Layout (4K blocks, 256K image):
    /// - Block 0: superblock at offset 1024
    /// - Block 1: group descriptor table
    /// - Block 4+: inode table
    ///   - Inode #2 (root): directory, size=4096, extent: logical 0 → physical 10
    ///   - Inode #11: regular file stub
    /// - Block 10: directory data block with ".", "..", "hello.txt"
    #[allow(clippy::cast_possible_truncation)]
    fn build_ext4_image_with_dir() -> Vec<u8> {
        let block_size: u32 = 4096;
        let image_size: u32 = 256 * 1024;
        let mut image = vec![0_u8; image_size as usize];
        let sb_off = EXT4_SUPERBLOCK_OFFSET;

        // ── Superblock ──
        image[sb_off + 0x38..sb_off + 0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
        image[sb_off + 0x18..sb_off + 0x1C].copy_from_slice(&2_u32.to_le_bytes());
        let blocks_count = image_size / block_size;
        image[sb_off + 0x04..sb_off + 0x08].copy_from_slice(&blocks_count.to_le_bytes());
        image[sb_off..sb_off + 0x04].copy_from_slice(&128_u32.to_le_bytes());
        image[sb_off + 0x14..sb_off + 0x18].copy_from_slice(&0_u32.to_le_bytes());
        image[sb_off + 0x20..sb_off + 0x24].copy_from_slice(&blocks_count.to_le_bytes());
        image[sb_off + 0x28..sb_off + 0x2C].copy_from_slice(&128_u32.to_le_bytes());
        image[sb_off + 0x58..sb_off + 0x5A].copy_from_slice(&256_u16.to_le_bytes());
        image[sb_off + 0x4C..sb_off + 0x50].copy_from_slice(&1_u32.to_le_bytes());
        let incompat: u32 = 0x0002 | 0x0040;
        image[sb_off + 0x60..sb_off + 0x64].copy_from_slice(&incompat.to_le_bytes());
        image[sb_off + 0x54..sb_off + 0x58].copy_from_slice(&11_u32.to_le_bytes());

        // ── Group descriptor at block 1 ──
        let gd_off: usize = 4096;
        image[gd_off..gd_off + 4].copy_from_slice(&2_u32.to_le_bytes());
        image[gd_off + 4..gd_off + 8].copy_from_slice(&3_u32.to_le_bytes());
        image[gd_off + 8..gd_off + 12].copy_from_slice(&4_u32.to_le_bytes());

        // ── Inode #2 (root dir, index 1) ──
        let ino2 = 4 * 4096 + 256; // inode #2 = index 1
        image[ino2..ino2 + 2].copy_from_slice(&0o040_755_u16.to_le_bytes()); // S_IFDIR|0755
        image[ino2 + 4..ino2 + 8].copy_from_slice(&4096_u32.to_le_bytes()); // size = 1 block
        image[ino2 + 0x1A..ino2 + 0x1C].copy_from_slice(&3_u16.to_le_bytes()); // links=3
        image[ino2 + 0x20..ino2 + 0x24].copy_from_slice(&0x0008_0000_u32.to_le_bytes());
        image[ino2 + 0x80..ino2 + 0x82].copy_from_slice(&32_u16.to_le_bytes());

        // Extent tree: depth=0, 1 extent: logical 0 → physical 10
        let e = ino2 + 0x28;
        image[e..e + 2].copy_from_slice(&0xF30A_u16.to_le_bytes());
        image[e + 2..e + 4].copy_from_slice(&1_u16.to_le_bytes());
        image[e + 4..e + 6].copy_from_slice(&4_u16.to_le_bytes());
        image[e + 6..e + 8].copy_from_slice(&0_u16.to_le_bytes());
        image[e + 12..e + 16].copy_from_slice(&0_u32.to_le_bytes());
        image[e + 16..e + 18].copy_from_slice(&1_u16.to_le_bytes());
        image[e + 18..e + 20].copy_from_slice(&0_u16.to_le_bytes());
        image[e + 20..e + 24].copy_from_slice(&10_u32.to_le_bytes());

        // ── Inode #11 (file, index 10) ──
        let ino11 = 4 * 4096 + 10 * 256;
        image[ino11..ino11 + 2].copy_from_slice(&0o100_644_u16.to_le_bytes());
        image[ino11 + 4..ino11 + 8].copy_from_slice(&5_u32.to_le_bytes());
        image[ino11 + 0x1A..ino11 + 0x1C].copy_from_slice(&1_u16.to_le_bytes());
        image[ino11 + 0x80..ino11 + 0x82].copy_from_slice(&32_u16.to_le_bytes());

        // ── Block 10: directory data ──
        // Entry "." → inode 2, type=DIR(2)
        let d = 10 * 4096;
        image[d..d + 4].copy_from_slice(&2_u32.to_le_bytes()); // inode
        image[d + 4..d + 6].copy_from_slice(&12_u16.to_le_bytes()); // rec_len
        image[d + 6] = 1; // name_len
        image[d + 7] = 2; // file_type = DIR
        image[d + 8] = b'.';

        // Entry ".." → inode 2, type=DIR(2)
        let d = d + 12;
        image[d..d + 4].copy_from_slice(&2_u32.to_le_bytes());
        image[d + 4..d + 6].copy_from_slice(&12_u16.to_le_bytes());
        image[d + 6] = 2;
        image[d + 7] = 2;
        image[d + 8] = b'.';
        image[d + 9] = b'.';

        // Entry "hello.txt" → inode 11, type=REG(1)
        let d = d + 12;
        image[d..d + 4].copy_from_slice(&11_u32.to_le_bytes());
        image[d + 4..d + 6].copy_from_slice(&4072_u16.to_le_bytes()); // rest of block
        image[d + 6] = 9;
        image[d + 7] = 1;
        image[d + 8..d + 17].copy_from_slice(b"hello.txt");

        image
    }

    #[test]
    fn read_dir_via_device() {
        let image = build_ext4_image_with_dir();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();
        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();

        let inode = fs.read_inode(&cx, InodeNumber(2)).unwrap();
        assert!(inode.is_dir());

        let entries = fs.read_dir(&cx, &inode).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].name, b".");
        assert_eq!(entries[0].inode, 2);
        assert_eq!(entries[1].name, b"..");
        assert_eq!(entries[1].inode, 2);
        assert_eq!(entries[2].name, b"hello.txt");
        assert_eq!(entries[2].inode, 11);
    }

    #[test]
    fn lookup_name_found() {
        let image = build_ext4_image_with_dir();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();
        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();

        let inode = fs.read_inode(&cx, InodeNumber(2)).unwrap();
        let entry = fs.lookup_name(&cx, &inode, b"hello.txt").unwrap();
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.inode, 11);
        assert_eq!(entry.name, b"hello.txt");
    }

    #[test]
    fn lookup_name_not_found() {
        let image = build_ext4_image_with_dir();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();
        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();

        let inode = fs.read_inode(&cx, InodeNumber(2)).unwrap();
        let entry = fs.lookup_name(&cx, &inode, b"missing.txt").unwrap();
        assert!(entry.is_none());
    }

    // ── High-level file read tests ────────────────────────────────────

    #[test]
    fn read_file_returns_data() {
        let image = build_ext4_image_with_extents();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();
        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();

        let data = fs.read_file(&cx, InodeNumber(11), 0, 100).unwrap();
        assert_eq!(&data, b"Hello, extent!");
    }

    #[test]
    fn read_file_partial() {
        let image = build_ext4_image_with_extents();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();
        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();

        let data = fs.read_file(&cx, InodeNumber(11), 7, 100).unwrap();
        assert_eq!(&data, b"extent!");
    }

    #[test]
    fn read_file_rejects_directory() {
        let image = build_ext4_image_with_dir();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();
        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();

        let err = fs.read_file(&cx, InodeNumber(2), 0, 4096).unwrap_err();
        assert_eq!(err.to_errno(), libc::EISDIR);
    }

    // ── Path resolution tests ─────────────────────────────────────────

    #[test]
    fn resolve_path_root() {
        let image = build_ext4_image_with_dir();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();
        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();

        let (ino, inode) = fs.resolve_path(&cx, "/").unwrap();
        assert_eq!(ino, InodeNumber(2));
        assert!(inode.is_dir());
    }

    #[test]
    fn resolve_path_file() {
        let image = build_ext4_image_with_dir();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();
        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();

        let (ino, inode) = fs.resolve_path(&cx, "/hello.txt").unwrap();
        assert_eq!(ino, InodeNumber(11));
        assert!(inode.is_regular());
    }

    #[test]
    fn resolve_path_not_found() {
        let image = build_ext4_image_with_dir();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();
        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();

        let err = fs.resolve_path(&cx, "/missing").unwrap_err();
        assert_eq!(err.to_errno(), libc::ENOENT);
    }

    #[test]
    fn resolve_path_not_directory() {
        let image = build_ext4_image_with_dir();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();
        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();

        // hello.txt is a regular file, not a directory — traversal through it fails.
        let err = fs.resolve_path(&cx, "/hello.txt/child").unwrap_err();
        assert_eq!(err.to_errno(), libc::ENOTDIR);
    }

    #[test]
    fn resolve_path_relative_rejected() {
        let image = build_ext4_image_with_dir();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();
        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();

        let err = fs.resolve_path(&cx, "hello.txt").unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    // ── FsOps for OpenFs tests ────────────────────────────────────────

    #[test]
    fn open_fs_fsops_getattr() {
        let image = build_ext4_image_with_dir();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();
        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();

        // Use via dyn FsOps to verify trait impl works
        let ops: &dyn FsOps = &fs;
        let attr = ops.getattr(&cx, InodeNumber(2)).unwrap();
        assert_eq!(attr.kind, FileType::Directory);
        assert_eq!(attr.perm, 0o755);
    }

    #[test]
    fn open_fs_fsops_lookup() {
        let image = build_ext4_image_with_dir();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();
        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();

        let ops: &dyn FsOps = &fs;
        let attr = ops
            .lookup(&cx, InodeNumber(2), OsStr::new("hello.txt"))
            .unwrap();
        assert_eq!(attr.ino, InodeNumber(11));
        assert_eq!(attr.kind, FileType::RegularFile);
    }

    #[test]
    fn open_fs_fsops_lookup_not_found() {
        let image = build_ext4_image_with_dir();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();
        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();

        let ops: &dyn FsOps = &fs;
        let err = ops
            .lookup(&cx, InodeNumber(2), OsStr::new("missing"))
            .unwrap_err();
        assert_eq!(err.to_errno(), libc::ENOENT);
    }

    #[test]
    fn open_fs_fsops_readdir() {
        let image = build_ext4_image_with_dir();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();
        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();

        let ops: &dyn FsOps = &fs;
        let entries = ops.readdir(&cx, InodeNumber(2), 0).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].name, b".");
        assert_eq!(entries[2].name, b"hello.txt");

        // Offset-based pagination
        let entries = ops.readdir(&cx, InodeNumber(2), 2).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, b"hello.txt");
    }

    #[test]
    fn open_fs_fsops_read() {
        let image = build_ext4_image_with_extents();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();
        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();

        let ops: &dyn FsOps = &fs;
        let data = ops.read(&cx, InodeNumber(11), 0, 100).unwrap();
        assert_eq!(&data, b"Hello, extent!");
    }

    #[test]
    fn open_fs_fsops_read_directory_rejected() {
        let image = build_ext4_image_with_dir();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();
        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();

        let ops: &dyn FsOps = &fs;
        let err = ops.read(&cx, InodeNumber(2), 0, 4096).unwrap_err();
        assert_eq!(err.to_errno(), libc::EISDIR);
    }

    #[test]
    fn durability_autopilot_prefers_more_redundancy_when_failures_observed() {
        let candidates = [1.02, 1.05, 1.10];

        let mut clean = DurabilityAutopilot::new();
        clean.observe_scrub(10_000, 0);
        let clean_decision = clean.choose_overhead(&candidates);
        assert!((clean_decision.repair_overhead - 1.02).abs() < 1e-12);

        let mut dirty = DurabilityAutopilot::new();
        dirty.observe_scrub(10_000, 300);
        let dirty_decision = dirty.choose_overhead(&candidates);
        assert!(dirty_decision.repair_overhead >= 1.05);
    }

    // ── Math helper tests ───────────────────────────────────────────────

    #[test]
    fn erfc_approx_known_values() {
        // erfc(0) = 1.0
        let val = erfc_approx(0.0);
        assert!((val - 1.0).abs() < 1e-6, "erfc(0) = {val}, expected 1.0");

        // erfc(large) → 0
        let val = erfc_approx(5.0);
        assert!(val < 1e-6, "erfc(5) = {val}, expected ~0");

        // erfc(-large) → 2
        let val = erfc_approx(-5.0);
        assert!((val - 2.0).abs() < 1e-6, "erfc(-5) = {val}, expected ~2");

        // erfc(1) ≈ 0.1573 (known value)
        let val = erfc_approx(1.0);
        assert!(
            (val - 0.1573).abs() < 0.001,
            "erfc(1) = {val}, expected ~0.1573",
        );
    }

    #[test]
    fn ln_gamma_known_values() {
        // Γ(1) = 1, ln(1) = 0
        let val = ln_gamma(1.0);
        assert!(val.abs() < 1e-10, "ln_gamma(1) = {val}, expected 0");

        // Γ(2) = 1, ln(1) = 0
        let val = ln_gamma(2.0);
        assert!(val.abs() < 1e-10, "ln_gamma(2) = {val}, expected 0");

        // Γ(5) = 24, ln(24) ≈ 3.1781
        let val = ln_gamma(5.0);
        let expected = 24.0_f64.ln();
        assert!(
            (val - expected).abs() < 1e-8,
            "ln_gamma(5) = {val}, expected {expected}",
        );

        // Γ(0.5) = √π ≈ 1.7725, ln(√π) ≈ 0.5724
        let val = ln_gamma(0.5);
        let expected = std::f64::consts::PI.sqrt().ln();
        assert!(
            (val - expected).abs() < 1e-6,
            "ln_gamma(0.5) = {val}, expected {expected}",
        );

        // Γ(10) = 9! = 362880
        let val = ln_gamma(10.0);
        let expected = 362_880.0_f64.ln();
        assert!(
            (val - expected).abs() < 1e-6,
            "ln_gamma(10) = {val}, expected {expected}",
        );
    }

    #[test]
    fn ln_gamma_zero_and_negative() {
        assert!(ln_gamma(0.0).is_infinite());
        assert!(ln_gamma(-1.0).is_infinite());
    }

    #[test]
    fn ln_beta_known_values() {
        // B(1,1) = 1, ln(1) = 0
        let val = ln_beta(1.0, 1.0);
        assert!(val.abs() < 1e-10, "ln_beta(1,1) = {val}, expected 0");

        // B(1,2) = 1/2, ln(1/2) ≈ -0.6931
        let val = ln_beta(1.0, 2.0);
        let expected = 0.5_f64.ln();
        assert!(
            (val - expected).abs() < 1e-8,
            "ln_beta(1,2) = {val}, expected {expected}",
        );

        // B(2,2) = 1/6, ln(1/6) ≈ -1.7918
        let val = ln_beta(2.0, 2.0);
        let expected = (1.0 / 6.0_f64).ln();
        assert!(
            (val - expected).abs() < 1e-8,
            "ln_beta(2,2) = {val}, expected {expected}",
        );
    }

    // ── IntegrityReport tests ───────────────────────────────────────────

    #[test]
    fn integrity_report_all_clean() {
        let report = IntegrityReport {
            verdicts: vec![],
            passed: 100,
            failed: 0,
            posterior_alpha: 1.0,
            posterior_beta: 101.0,
            expected_corruption_rate: 1.0 / 102.0,
            upper_bound_corruption_rate: 0.005,
            healthy: true,
        };

        let p = report.prob_healthy(0.05);
        assert!(p > 0.9, "prob_healthy = {p}, expected > 0.9");

        let lbf = report.log_bayes_factor();
        assert!(
            lbf > 0.0,
            "log_bayes_factor = {lbf}, expected > 0 (favors health)"
        );
    }

    #[test]
    fn integrity_report_heavily_corrupted() {
        let report = IntegrityReport {
            verdicts: vec![],
            passed: 10,
            failed: 90,
            posterior_alpha: 91.0,
            posterior_beta: 11.0,
            expected_corruption_rate: 91.0 / 102.0,
            upper_bound_corruption_rate: 0.95,
            healthy: false,
        };

        let p = report.prob_healthy(0.01);
        assert!(p < 0.01, "prob_healthy = {p}, expected < 0.01");

        let lbf = report.log_bayes_factor();
        assert!(
            lbf < 0.0,
            "log_bayes_factor = {lbf}, expected < 0 (favors corruption)"
        );
    }

    #[test]
    fn integrity_report_bayes_factor_is_finite() {
        let report = IntegrityReport {
            verdicts: vec![],
            passed: 50,
            failed: 50,
            posterior_alpha: 51.0,
            posterior_beta: 51.0,
            expected_corruption_rate: 0.5,
            upper_bound_corruption_rate: 0.55,
            healthy: false,
        };
        let lbf = report.log_bayes_factor();
        assert!(lbf.is_finite(), "log_bayes_factor should be finite");
    }

    // ── Ext4FsOps helper tests ──────────────────────────────────────────

    #[test]
    fn dir_entry_file_type_mapping() {
        assert_eq!(dir_entry_file_type(Ext4FileType::Dir), FileType::Directory);
        assert_eq!(
            dir_entry_file_type(Ext4FileType::Symlink),
            FileType::Symlink
        );
        assert_eq!(
            dir_entry_file_type(Ext4FileType::Blkdev),
            FileType::BlockDevice
        );
        assert_eq!(
            dir_entry_file_type(Ext4FileType::Chrdev),
            FileType::CharDevice
        );
        assert_eq!(dir_entry_file_type(Ext4FileType::Fifo), FileType::Fifo);
        assert_eq!(dir_entry_file_type(Ext4FileType::Sock), FileType::Socket);
        assert_eq!(
            dir_entry_file_type(Ext4FileType::RegFile),
            FileType::RegularFile
        );
        assert_eq!(
            dir_entry_file_type(Ext4FileType::Unknown),
            FileType::RegularFile
        );
    }

    #[test]
    fn parse_to_ffs_error_runtime_mappings() {
        let e = parse_to_ffs_error(&ParseError::InvalidField {
            field: "dir_entry",
            reason: "component not found in directory",
        });
        assert!(matches!(e, FfsError::NotFound(_)));

        let e = parse_to_ffs_error(&ParseError::InvalidField {
            field: "path",
            reason: "not a directory",
        });
        assert!(matches!(e, FfsError::NotDirectory));

        let e = parse_to_ffs_error(&ParseError::InvalidField {
            field: "extent",
            reason: "corrupt extent header",
        });
        assert!(matches!(e, FfsError::Format(_)));

        let e = parse_to_ffs_error(&ParseError::InsufficientData {
            needed: 256,
            offset: 0,
            actual: 128,
        });
        assert!(matches!(e, FfsError::Corruption { .. }));
    }

    #[test]
    fn check_verdict_serializes() {
        let v = CheckVerdict {
            component: "superblock".into(),
            passed: true,
            detail: String::new(),
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("superblock"));
        assert!(json.contains("true"));
    }

    #[test]
    fn integrity_report_serializes() {
        let report = IntegrityReport {
            verdicts: vec![CheckVerdict {
                component: "test".into(),
                passed: true,
                detail: String::new(),
            }],
            passed: 1,
            failed: 0,
            posterior_alpha: 1.0,
            posterior_beta: 2.0,
            expected_corruption_rate: 0.333,
            upper_bound_corruption_rate: 0.5,
            healthy: true,
        };
        let json = serde_json::to_string(&report).unwrap();
        let deser: IntegrityReport = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.passed, 1);
        assert_eq!(deser.failed, 0);
        assert!(deser.healthy);
    }

    // ── Btrfs OpenFs tests ──────────────────────────────────────────────

    /// Build a minimal synthetic btrfs image with a sys_chunk_array and a leaf
    /// node at the root tree address.
    #[allow(clippy::cast_possible_truncation)]
    fn build_btrfs_image() -> Vec<u8> {
        let image_size: usize = 256 * 1024; // 256 KB
        let mut image = vec![0_u8; image_size];
        let sb_off = BTRFS_SUPER_INFO_OFFSET;

        // magic
        image[sb_off + 0x40..sb_off + 0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        // generation
        image[sb_off + 0x48..sb_off + 0x50].copy_from_slice(&1_u64.to_le_bytes());
        // root (logical address of root tree leaf)
        let root_logical = 0x4000_u64;
        image[sb_off + 0x50..sb_off + 0x58].copy_from_slice(&root_logical.to_le_bytes());
        // chunk_root (set to 0 — we only use sys_chunk_array)
        image[sb_off + 0x58..sb_off + 0x60].copy_from_slice(&0_u64.to_le_bytes());
        // total_bytes
        image[sb_off + 0x70..sb_off + 0x78].copy_from_slice(&(image_size as u64).to_le_bytes());
        // root_dir_objectid
        image[sb_off + 0x80..sb_off + 0x88].copy_from_slice(&256_u64.to_le_bytes());
        // num_devices
        image[sb_off + 0x88..sb_off + 0x90].copy_from_slice(&1_u64.to_le_bytes());
        // sectorsize = 4096
        image[sb_off + 0x90..sb_off + 0x94].copy_from_slice(&4096_u32.to_le_bytes());
        // nodesize = 4096
        image[sb_off + 0x94..sb_off + 0x98].copy_from_slice(&4096_u32.to_le_bytes());
        // stripesize = 4096
        image[sb_off + 0x9C..sb_off + 0xA0].copy_from_slice(&4096_u32.to_le_bytes());

        // Build sys_chunk_array: one chunk, identity mapping [0, 256K) → [0, 256K)
        let mut chunk_array = Vec::new();
        // disk_key: objectid=256, type=228, offset=0
        chunk_array.extend_from_slice(&256_u64.to_le_bytes());
        chunk_array.push(228_u8);
        chunk_array.extend_from_slice(&0_u64.to_le_bytes());
        // chunk: length, owner, stripe_len, type
        chunk_array.extend_from_slice(&(image_size as u64).to_le_bytes());
        chunk_array.extend_from_slice(&2_u64.to_le_bytes());
        chunk_array.extend_from_slice(&0x1_0000_u64.to_le_bytes());
        chunk_array.extend_from_slice(&2_u64.to_le_bytes());
        // io_align, io_width, sector_size
        chunk_array.extend_from_slice(&4096_u32.to_le_bytes());
        chunk_array.extend_from_slice(&4096_u32.to_le_bytes());
        chunk_array.extend_from_slice(&4096_u32.to_le_bytes());
        // num_stripes=1, sub_stripes=0
        chunk_array.extend_from_slice(&1_u16.to_le_bytes());
        chunk_array.extend_from_slice(&0_u16.to_le_bytes());
        // stripe: devid=1, offset=0 (identity), dev_uuid=[0;16]
        chunk_array.extend_from_slice(&1_u64.to_le_bytes());
        chunk_array.extend_from_slice(&0_u64.to_le_bytes());
        chunk_array.extend_from_slice(&[0_u8; 16]);

        // sys_chunk_array_size
        let array_size = chunk_array.len() as u32;
        image[sb_off + 0xA0..sb_off + 0xA4].copy_from_slice(&array_size.to_le_bytes());
        // sys_chunk_array data (at offset 0x32B from sb region start)
        let array_start = sb_off + 0x32B;
        image[array_start..array_start + chunk_array.len()].copy_from_slice(&chunk_array);
        // root_level = 0 (leaf)
        image[sb_off + 0xC6] = 0;

        // Write a leaf node at physical 0x4000 (= root_logical via identity map)
        let leaf_off = root_logical as usize;
        // btrfs header: bytenr
        image[leaf_off + 0x30..leaf_off + 0x38].copy_from_slice(&root_logical.to_le_bytes());
        // generation
        image[leaf_off + 0x50..leaf_off + 0x58].copy_from_slice(&1_u64.to_le_bytes());
        // owner (ROOT_TREE = 1)
        image[leaf_off + 0x58..leaf_off + 0x60].copy_from_slice(&1_u64.to_le_bytes());
        // nritems = 1
        image[leaf_off + 0x60..leaf_off + 0x64].copy_from_slice(&1_u32.to_le_bytes());
        // level = 0 (leaf)
        image[leaf_off + 0x64] = 0;

        // Leaf item 0 at header_size=101
        let item_off = leaf_off + 101;
        // key: objectid=256, type=132 (ROOT_ITEM), offset=0
        image[item_off..item_off + 8].copy_from_slice(&256_u64.to_le_bytes());
        image[item_off + 8] = 132;
        image[item_off + 9..item_off + 17].copy_from_slice(&0_u64.to_le_bytes());
        // data_offset=200, data_size=8
        image[item_off + 17..item_off + 21].copy_from_slice(&200_u32.to_le_bytes());
        image[item_off + 21..item_off + 25].copy_from_slice(&8_u32.to_le_bytes());
        // Actual data at leaf_off + 200
        image[leaf_off + 200..leaf_off + 208]
            .copy_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF]);

        image
    }

    #[test]
    fn open_fs_from_btrfs_image() {
        let image = build_btrfs_image();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();

        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();
        assert!(fs.is_btrfs());
        assert!(!fs.is_ext4());
        assert_eq!(fs.block_size(), 4096);
        assert!(fs.ext4_geometry.is_none());
        assert!(fs.btrfs_context.is_some());

        let ctx = fs.btrfs_context().unwrap();
        assert_eq!(ctx.nodesize, 4096);
        assert_eq!(ctx.chunks.len(), 1);
    }

    #[test]
    fn open_fs_btrfs_debug_format() {
        let image = build_btrfs_image();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();

        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();
        let debug = format!("{fs:?}");
        assert!(debug.contains("OpenFs"));
        assert!(debug.contains("btrfs_context"));
    }

    #[test]
    fn open_fs_btrfs_superblock_accessor() {
        let image = build_btrfs_image();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();

        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();
        let sb = fs.btrfs_superblock().expect("btrfs superblock");
        assert_eq!(sb.magic, BTRFS_MAGIC);
        assert_eq!(sb.sectorsize, 4096);
        assert_eq!(sb.nodesize, 4096);
    }

    #[test]
    fn open_fs_btrfs_walk_root_tree() {
        let image = build_btrfs_image();
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();

        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();
        let items = fs.walk_btrfs_root_tree(&cx).expect("walk root tree");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].key.objectid, 256);
        assert_eq!(items[0].key.item_type, 132);
        assert_eq!(
            items[0].data,
            vec![0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF]
        );
    }

    #[test]
    fn open_fs_btrfs_walk_on_ext4_errors() {
        let image = build_ext4_image(2);
        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();

        let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap();
        let err = fs.walk_btrfs_root_tree(&cx).unwrap_err();
        assert_eq!(err.to_errno(), libc::EINVAL);
    }

    #[test]
    fn validate_btrfs_rejects_bad_nodesize() {
        let mut image = build_btrfs_image();
        let sb_off = BTRFS_SUPER_INFO_OFFSET;
        // Set nodesize to 128K (too large for our validation)
        image[sb_off + 0x94..sb_off + 0x98].copy_from_slice(&(128 * 1024_u32).to_le_bytes());

        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();
        let err = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default()).unwrap_err();
        assert!(
            matches!(err, FfsError::InvalidGeometry(_)),
            "expected InvalidGeometry, got: {err:?}"
        );
    }

    #[test]
    fn validate_btrfs_skip_validation() {
        let mut image = build_btrfs_image();
        let sb_off = BTRFS_SUPER_INFO_OFFSET;
        // Set nodesize to 128K (too large)
        image[sb_off + 0x94..sb_off + 0x98].copy_from_slice(&(128 * 1024_u32).to_le_bytes());

        let dev = TestDevice::from_vec(image);
        let cx = Cx::for_testing();
        let opts = OpenOptions {
            skip_validation: true,
        };
        let fs = OpenFs::from_device(&cx, Box::new(dev), &opts).unwrap();
        assert!(fs.is_btrfs());
        assert!(fs.btrfs_context.is_some());
    }

    // ── DurabilityAutopilot tests ────────────────────────────────────────

    /// Standard candidate set: 1% to 10% overhead.
    fn standard_candidates() -> Vec<f64> {
        (1..=10).map(|i| f64::from(i).mul_add(0.01, 1.0)).collect()
    }

    #[test]
    fn posterior_uniform_prior() {
        let p = DurabilityPosterior::default();
        assert!((p.alpha - 1.0).abs() < f64::EPSILON);
        assert!((p.beta - 1.0).abs() < f64::EPSILON);
        assert!((p.expected_corruption_rate() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn posterior_observe_blocks_updates_correctly() {
        let mut p = DurabilityPosterior::default();
        // Scrub 1000 blocks, find 10 corrupt.
        p.observe_blocks(1000, 10);
        // alpha = 1 + 10 = 11, beta = 1 + 990 = 991
        assert!((p.alpha - 11.0).abs() < f64::EPSILON);
        assert!((p.beta - 991.0).abs() < f64::EPSILON);
        let rate = p.expected_corruption_rate();
        assert!((rate - 11.0 / 1002.0).abs() < 1e-10);
    }

    #[test]
    fn posterior_converges_to_empirical_rate() {
        let mut p = DurabilityPosterior::default();
        // Many observations at 2% corruption rate.
        for _ in 0..100 {
            p.observe_blocks(10_000, 200);
        }
        let rate = p.expected_corruption_rate();
        assert!((rate - 0.02).abs() < 0.001, "expected ~0.02, got {rate}");
    }

    #[test]
    fn posterior_variance_decreases_with_observations() {
        let mut p = DurabilityPosterior::default();
        let var_before = p.variance();
        p.observe_blocks(10_000, 100);
        let var_after = p.variance();
        assert!(
            var_after < var_before,
            "variance should decrease: {var_before} -> {var_after}"
        );
    }

    #[test]
    fn autopilot_fresh_picks_lowest_overhead() {
        // With no observations (uniform prior), p_hi clamps to 1.0.
        // All candidates have risk_bound=1.0 (rho <= p_hi), so the
        // corruption_loss is identical.  Tiebreaker is redundancy_loss,
        // which is minimized at the lowest candidate.
        let ap = DurabilityAutopilot::new();
        let d = ap.choose_overhead(&standard_candidates());
        assert!(
            (d.repair_overhead - 1.01).abs() < f64::EPSILON,
            "fresh autopilot should pick lowest overhead (risk equal), got {}",
            d.repair_overhead
        );
        assert!(d.expected_loss.is_finite());
        assert!(d.posterior_mean_corruption_rate > 0.0);
        // All candidates have same risk, so corruption_loss is maximal.
        assert!((d.unrecoverable_risk_bound - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn autopilot_low_corruption_picks_low_overhead() {
        let mut ap = DurabilityAutopilot::new();
        // 10 clean scrubs of 100K blocks each, zero corruption.
        for _ in 0..10 {
            ap.observe_scrub(100_000, 0);
        }
        let d = ap.choose_overhead(&standard_candidates());
        // With ~1M clean blocks observed, posterior p is very low.
        // The autopilot should pick a low overhead since risk is negligible.
        assert!(
            d.repair_overhead <= 1.03,
            "low corruption should yield low overhead, got {}",
            d.repair_overhead
        );
        assert!(d.unrecoverable_risk_bound < 1e-10);
        assert!(d.corruption_loss < d.redundancy_loss);
    }

    #[test]
    fn autopilot_high_corruption_picks_high_overhead() {
        let mut ap = DurabilityAutopilot::new();
        // Heavy corruption: 5% of blocks corrupt per scrub.
        for _ in 0..5 {
            ap.observe_scrub(10_000, 500);
        }
        let d = ap.choose_overhead(&standard_candidates());
        // p is around 5%, so overhead should be high to cover.
        assert!(
            d.repair_overhead >= 1.06,
            "high corruption should yield high overhead, got {}",
            d.repair_overhead
        );
        assert!(d.posterior_mean_corruption_rate > 0.04);
    }

    #[test]
    fn autopilot_reacts_to_corruption_increase() {
        // Use a modest clean history so corruption isn't swamped.
        let mut ap = DurabilityAutopilot::new();
        ap.observe_scrub(10_000, 0);
        let d_clean = ap.choose_overhead(&standard_candidates());

        // Observe heavy corruption: 5% of blocks corrupt, enough data to
        // push the posterior mean above 1% so overhead must increase.
        for _ in 0..20 {
            ap.observe_scrub(10_000, 500);
        }
        let d_corrupt = ap.choose_overhead(&standard_candidates());

        assert!(
            d_corrupt.repair_overhead > d_clean.repair_overhead,
            "overhead should increase after corruption: {} -> {}",
            d_clean.repair_overhead,
            d_corrupt.repair_overhead,
        );
        assert!(d_corrupt.posterior_mean_corruption_rate > d_clean.posterior_mean_corruption_rate);
    }

    #[test]
    fn decision_contains_explainable_fields() {
        let mut ap = DurabilityAutopilot::new();
        ap.observe_scrub(50_000, 25);
        let d = ap.choose_overhead(&standard_candidates());

        // All evidence fields must be populated and finite.
        assert!(d.repair_overhead.is_finite());
        assert!(d.expected_loss.is_finite());
        assert!(d.posterior_mean_corruption_rate.is_finite());
        assert!(d.posterior_hi_corruption_rate.is_finite());
        assert!(d.unrecoverable_risk_bound.is_finite());
        assert!(d.redundancy_loss.is_finite());
        assert!(d.corruption_loss.is_finite());

        // Consistency: expected_loss = redundancy_loss + corruption_loss.
        let sum = d.redundancy_loss + d.corruption_loss;
        assert!(
            (d.expected_loss - sum).abs() < 1e-10,
            "loss should decompose: {} != {} + {}",
            d.expected_loss,
            d.redundancy_loss,
            d.corruption_loss,
        );

        // p_hi >= p_mean (upper bound).
        assert!(d.posterior_hi_corruption_rate >= d.posterior_mean_corruption_rate);

        // Overhead is in valid range.
        assert!(d.repair_overhead >= 1.01);
        assert!(d.repair_overhead <= 1.10);
    }

    #[test]
    fn risk_bound_monotonically_decreases_with_overhead() {
        let mut ap = DurabilityAutopilot::new();
        ap.observe_scrub(100_000, 50);
        let candidates = standard_candidates();

        let mut prev_risk = f64::INFINITY;
        for &c in &candidates {
            let d = ap.choose_overhead_for_group(&[c], 32_768);
            assert!(
                d.unrecoverable_risk_bound <= prev_risk + f64::EPSILON,
                "risk should decrease: at overhead {c}, risk {} > prev {prev_risk}",
                d.unrecoverable_risk_bound,
            );
            prev_risk = d.unrecoverable_risk_bound;
        }
    }

    #[test]
    fn autopilot_no_valid_candidates_uses_default() {
        let ap = DurabilityAutopilot::new();
        // Pass only out-of-range candidates.
        let d = ap.choose_overhead(&[0.5, 2.0, f64::NAN, f64::INFINITY]);
        assert!((d.repair_overhead - 1.05).abs() < f64::EPSILON);
    }

    #[test]
    fn autopilot_empty_candidates_uses_default() {
        let ap = DurabilityAutopilot::new();
        let d = ap.choose_overhead(&[]);
        assert!((d.repair_overhead - 1.05).abs() < f64::EPSILON);
    }

    #[test]
    fn autopilot_group_size_affects_risk() {
        let mut ap = DurabilityAutopilot::new();
        ap.observe_scrub(100_000, 50);

        // Large group: more blocks = tighter concentration = lower risk.
        let d_large = ap.choose_overhead_for_group(&standard_candidates(), 32_768);
        // Small group: fewer blocks = wider variance = higher risk.
        let d_small = ap.choose_overhead_for_group(&standard_candidates(), 100);

        // Small groups should pick higher (or equal) overhead.
        assert!(
            d_small.repair_overhead >= d_large.repair_overhead,
            "small group ({}) should need >= overhead than large group ({})",
            d_small.repair_overhead,
            d_large.repair_overhead,
        );
    }

    #[test]
    fn loss_model_custom_costs() {
        let mut ap = DurabilityAutopilot {
            posterior: DurabilityPosterior::default(),
            loss: DurabilityLossModel {
                corruption_cost: 1.0,
                redundancy_cost: 1_000_000.0,
                z_score: 3.0,
            },
        };
        // When redundancy is extremely expensive, should pick lowest overhead.
        ap.observe_scrub(100_000, 10);
        let d = ap.choose_overhead(&standard_candidates());
        assert!(
            (d.repair_overhead - 1.01).abs() < f64::EPSILON,
            "high redundancy cost should pick 1.01, got {}",
            d.repair_overhead,
        );
    }

    #[test]
    fn decision_serializes_to_json() {
        let mut ap = DurabilityAutopilot::new();
        ap.observe_scrub(10_000, 5);
        let d = ap.choose_overhead(&standard_candidates());
        let json = serde_json::to_string(&d).expect("serialize");
        let d2: RedundancyDecision = serde_json::from_str(&json).expect("deserialize");
        assert!((d.repair_overhead - d2.repair_overhead).abs() < f64::EPSILON);
        assert!((d.expected_loss - d2.expected_loss).abs() < 1e-10);
    }

    // ── RepairPolicy tests ───────────────────────────────────────────────

    #[test]
    fn repair_policy_default_is_static_5pct() {
        let p = RepairPolicy::default();
        assert!((p.overhead_ratio - 1.05).abs() < f64::EPSILON);
        assert!(!p.eager_refresh);
        assert!(p.autopilot.is_none());
        assert!((p.effective_overhead() - 1.05).abs() < f64::EPSILON);
        assert!(p.autopilot_decision().is_none());
    }

    #[test]
    fn repair_policy_with_autopilot_delegates() {
        let mut ap = DurabilityAutopilot::new();
        for _ in 0..10 {
            ap.observe_scrub(100_000, 0);
        }
        let policy = RepairPolicy {
            overhead_ratio: 1.05,
            eager_refresh: false,
            autopilot: Some(ap),
        };
        let overhead = policy.effective_overhead();
        // Should come from autopilot, not static ratio.
        assert!((1.01..=1.10).contains(&overhead));

        let decision = policy.autopilot_decision().expect("should have decision");
        assert!((decision.repair_overhead - overhead).abs() < f64::EPSILON);
    }
}
