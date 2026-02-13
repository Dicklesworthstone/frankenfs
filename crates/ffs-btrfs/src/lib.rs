#![forbid(unsafe_code)]
//! Higher-level btrfs operations: tree traversal, item enumeration.
//!
//! Builds on `ffs_ondisk::btrfs` parsing primitives. I/O-agnostic —
//! callers provide a read callback for physical byte access.

pub use ffs_ondisk::btrfs::*;
use ffs_types::ParseError;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashSet};
use tracing::{debug, trace};

/// A single leaf item yielded by tree traversal: key + raw payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtrfsLeafEntry {
    pub key: BtrfsKey,
    pub data: Vec<u8>,
}

/// btrfs objectid for the root tree.
pub const BTRFS_ROOT_TREE_OBJECTID: u64 = 1;
/// btrfs objectid for the default filesystem tree.
pub const BTRFS_FS_TREE_OBJECTID: u64 = 5;

/// btrfs item type constants used by the read-only VFS path.
pub const BTRFS_ITEM_INODE_ITEM: u8 = 1;
pub const BTRFS_ITEM_DIR_ITEM: u8 = 84;
pub const BTRFS_ITEM_DIR_INDEX: u8 = 96;
pub const BTRFS_ITEM_EXTENT_DATA: u8 = 108;
pub const BTRFS_ITEM_ROOT_ITEM: u8 = 132;

/// Directory entry type values stored in btrfs dir items.
pub const BTRFS_FT_UNKNOWN: u8 = 0;
pub const BTRFS_FT_REG_FILE: u8 = 1;
pub const BTRFS_FT_DIR: u8 = 2;
pub const BTRFS_FT_CHRDEV: u8 = 3;
pub const BTRFS_FT_BLKDEV: u8 = 4;
pub const BTRFS_FT_FIFO: u8 = 5;
pub const BTRFS_FT_SOCK: u8 = 6;
pub const BTRFS_FT_SYMLINK: u8 = 7;

/// File extent type values in EXTENT_DATA payloads.
pub const BTRFS_FILE_EXTENT_INLINE: u8 = 0;
pub const BTRFS_FILE_EXTENT_REG: u8 = 1;
pub const BTRFS_FILE_EXTENT_PREALLOC: u8 = 2;

/// Parsed subset of `btrfs_root_item` needed for tree bootstrapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtrfsRootItem {
    /// Logical address of the tree root block (`bytenr`).
    pub bytenr: u64,
    /// Root tree level (`0` for leaf roots).
    pub level: u8,
}

/// Parsed subset of `btrfs_inode_item` needed for read-only VFS operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtrfsInodeItem {
    pub size: u64,
    pub nbytes: u64,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub rdev: u64,
    pub atime_sec: u64,
    pub atime_nsec: u32,
    pub ctime_sec: u64,
    pub ctime_nsec: u32,
    pub mtime_sec: u64,
    pub mtime_nsec: u32,
    pub otime_sec: u64,
    pub otime_nsec: u32,
}

/// One decoded directory entry from DIR_ITEM / DIR_INDEX payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtrfsDirItem {
    pub child_objectid: u64,
    pub child_key_type: u8,
    pub child_key_offset: u64,
    pub file_type: u8,
    pub name: Vec<u8>,
}

/// Parsed EXTENT_DATA payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BtrfsExtentData {
    /// Inline extent payload bytes.
    Inline { compression: u8, data: Vec<u8> },
    /// Regular or preallocated extent that references on-disk bytes.
    ///
    /// `disk_bytenr` is a logical bytenr in btrfs address space.
    Regular {
        extent_type: u8,
        compression: u8,
        disk_bytenr: u64,
        disk_num_bytes: u64,
        extent_offset: u64,
        num_bytes: u64,
    },
}

fn read_exact<const N: usize>(
    data: &[u8],
    off: usize,
    field: &'static str,
) -> Result<[u8; N], ParseError> {
    let end = off.checked_add(N).ok_or(ParseError::InvalidField {
        field,
        reason: "offset overflow",
    })?;
    let Some(slice) = data.get(off..end) else {
        return Err(ParseError::InsufficientData {
            needed: end,
            offset: off,
            actual: data.len(),
        });
    };
    let mut out = [0_u8; N];
    out.copy_from_slice(slice);
    Ok(out)
}

fn read_u16(data: &[u8], off: usize, field: &'static str) -> Result<u16, ParseError> {
    Ok(u16::from_le_bytes(read_exact::<2>(data, off, field)?))
}

fn read_u32(data: &[u8], off: usize, field: &'static str) -> Result<u32, ParseError> {
    Ok(u32::from_le_bytes(read_exact::<4>(data, off, field)?))
}

fn read_u64(data: &[u8], off: usize, field: &'static str) -> Result<u64, ParseError> {
    Ok(u64::from_le_bytes(read_exact::<8>(data, off, field)?))
}

/// Parse the subset of `btrfs_root_item` needed to find the FS tree root.
///
/// Layout assumption (stable for the supported on-disk variants):
/// - `bytenr` at offset 176
/// - `level` in the final byte of the item payload
pub fn parse_root_item(data: &[u8]) -> Result<BtrfsRootItem, ParseError> {
    if data.len() < 184 {
        return Err(ParseError::InsufficientData {
            needed: 184,
            offset: 0,
            actual: data.len(),
        });
    }

    let bytenr = read_u64(data, 176, "root_item.bytenr")?;
    let level = *data.last().ok_or(ParseError::InsufficientData {
        needed: 1,
        offset: 0,
        actual: data.len(),
    })?;

    if bytenr == 0 {
        return Err(ParseError::InvalidField {
            field: "root_item.bytenr",
            reason: "must be non-zero",
        });
    }

    Ok(BtrfsRootItem { bytenr, level })
}

/// Parse the subset of `btrfs_inode_item` needed for read-only VFS operations.
pub fn parse_inode_item(data: &[u8]) -> Result<BtrfsInodeItem, ParseError> {
    if data.len() < 160 {
        return Err(ParseError::InsufficientData {
            needed: 160,
            offset: 0,
            actual: data.len(),
        });
    }

    Ok(BtrfsInodeItem {
        size: read_u64(data, 16, "inode_item.size")?,
        nbytes: read_u64(data, 24, "inode_item.nbytes")?,
        nlink: read_u32(data, 40, "inode_item.nlink")?,
        uid: read_u32(data, 44, "inode_item.uid")?,
        gid: read_u32(data, 48, "inode_item.gid")?,
        mode: read_u32(data, 52, "inode_item.mode")?,
        rdev: read_u64(data, 56, "inode_item.rdev")?,
        atime_sec: read_u64(data, 112, "inode_item.atime_sec")?,
        atime_nsec: read_u32(data, 120, "inode_item.atime_nsec")?,
        ctime_sec: read_u64(data, 124, "inode_item.ctime_sec")?,
        ctime_nsec: read_u32(data, 132, "inode_item.ctime_nsec")?,
        mtime_sec: read_u64(data, 136, "inode_item.mtime_sec")?,
        mtime_nsec: read_u32(data, 144, "inode_item.mtime_nsec")?,
        otime_sec: read_u64(data, 148, "inode_item.otime_sec")?,
        otime_nsec: read_u32(data, 156, "inode_item.otime_nsec")?,
    })
}

/// Parse one or more directory entries from a DIR_ITEM or DIR_INDEX payload.
pub fn parse_dir_items(data: &[u8]) -> Result<Vec<BtrfsDirItem>, ParseError> {
    const HEADER: usize = 30; // disk_key(17) + transid(8) + data_len(2) + name_len(2) + type(1)

    let mut out = Vec::new();
    let mut cur = 0_usize;
    while cur < data.len() {
        if cur + HEADER > data.len() {
            return Err(ParseError::InsufficientData {
                needed: HEADER,
                offset: cur,
                actual: data.len() - cur,
            });
        }

        let child_objectid = read_u64(data, cur, "dir_item.location.objectid")?;
        let child_key_type = data[cur + 8];
        let child_key_offset = read_u64(data, cur + 9, "dir_item.location.offset")?;
        // transid at +17..+25 (currently unused in VFS path)
        let _transid = read_u64(data, cur + 17, "dir_item.transid")?;
        let data_len = usize::from(read_u16(data, cur + 25, "dir_item.data_len")?);
        let name_len = usize::from(read_u16(data, cur + 27, "dir_item.name_len")?);
        let file_type = data[cur + 29];

        let name_start = cur + HEADER;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or(ParseError::InvalidField {
                field: "dir_item.name_len",
                reason: "overflow",
            })?;
        let payload_end = name_end
            .checked_add(data_len)
            .ok_or(ParseError::InvalidField {
                field: "dir_item.data_len",
                reason: "overflow",
            })?;

        if payload_end > data.len() {
            return Err(ParseError::InsufficientData {
                needed: payload_end,
                offset: cur,
                actual: data.len(),
            });
        }

        out.push(BtrfsDirItem {
            child_objectid,
            child_key_type,
            child_key_offset,
            file_type,
            name: data[name_start..name_end].to_vec(),
        });

        cur = payload_end;
    }

    Ok(out)
}

/// Parse an EXTENT_DATA payload for regular or inline extents.
pub fn parse_extent_data(data: &[u8]) -> Result<BtrfsExtentData, ParseError> {
    const FIXED: usize = 21; // generation(8) + ram_bytes(8) + compression(1) + encryption(1) + other_encoding(2) + type(1)

    if data.len() < FIXED {
        return Err(ParseError::InsufficientData {
            needed: FIXED,
            offset: 0,
            actual: data.len(),
        });
    }

    let compression = data[16];
    let extent_type = data[20];
    match extent_type {
        BTRFS_FILE_EXTENT_INLINE => Ok(BtrfsExtentData::Inline {
            compression,
            data: data[FIXED..].to_vec(),
        }),
        BTRFS_FILE_EXTENT_REG | BTRFS_FILE_EXTENT_PREALLOC => {
            // disk_bytenr + disk_num_bytes + extent_offset + num_bytes
            if data.len() < FIXED + 32 {
                return Err(ParseError::InsufficientData {
                    needed: FIXED + 32,
                    offset: 0,
                    actual: data.len(),
                });
            }
            Ok(BtrfsExtentData::Regular {
                extent_type,
                compression,
                disk_bytenr: read_u64(data, 21, "extent_data.disk_bytenr")?,
                disk_num_bytes: read_u64(data, 29, "extent_data.disk_num_bytes")?,
                extent_offset: read_u64(data, 37, "extent_data.offset")?,
                num_bytes: read_u64(data, 45, "extent_data.num_bytes")?,
            })
        }
        _ => Err(ParseError::InvalidField {
            field: "extent_data.type",
            reason: "unsupported extent type",
        }),
    }
}

/// Walk a btrfs tree from `root_logical` down to all leaves, collecting items.
///
/// `read_physical` reads `nodesize` bytes at the given physical byte offset.
/// `chunks` provides the logical→physical address mapping.
///
/// Returns all leaf items in key order (left-to-right DFS).
/// The traversal is bounded: it rejects levels > 7 and validates nritems
/// against block capacity at each node.
pub fn walk_tree(
    read_physical: &mut dyn FnMut(u64) -> Result<Vec<u8>, ParseError>,
    chunks: &[BtrfsChunkEntry],
    root_logical: u64,
    nodesize: u32,
) -> Result<Vec<BtrfsLeafEntry>, ParseError> {
    let mut results = Vec::new();
    let mut active_path = HashSet::new();
    let mut visited_nodes = HashSet::new();
    walk_node(
        read_physical,
        chunks,
        root_logical,
        nodesize,
        &mut results,
        &mut active_path,
        &mut visited_nodes,
    )?;
    Ok(results)
}

fn walk_node(
    read_physical: &mut dyn FnMut(u64) -> Result<Vec<u8>, ParseError>,
    chunks: &[BtrfsChunkEntry],
    logical: u64,
    nodesize: u32,
    out: &mut Vec<BtrfsLeafEntry>,
    active_path: &mut HashSet<u64>,
    visited_nodes: &mut HashSet<u64>,
) -> Result<(), ParseError> {
    if !active_path.insert(logical) {
        return Err(ParseError::InvalidField {
            field: "logical_address",
            reason: "cycle detected in btrfs tree pointers",
        });
    }
    if !visited_nodes.insert(logical) {
        return Err(ParseError::InvalidField {
            field: "logical_address",
            reason: "duplicate node reference in btrfs tree pointers",
        });
    }

    let mapping = map_logical_to_physical(chunks, logical)?.ok_or(ParseError::InvalidField {
        field: "logical_address",
        reason: "not covered by any chunk",
    })?;

    let block = read_physical(mapping.physical)?;
    let ns = usize::try_from(nodesize)
        .map_err(|_| ParseError::IntegerConversion { field: "nodesize" })?;
    if block.len() != ns {
        return Err(ParseError::InsufficientData {
            needed: ns,
            offset: 0,
            actual: block.len(),
        });
    }

    let header = BtrfsHeader::parse_from_block(&block)?;
    header.validate(block.len(), Some(logical))?;

    if header.level == 0 {
        collect_leaf_items(&block, out)?;
    } else {
        let (_, ptrs) = parse_internal_items(&block)?;
        for kp in &ptrs {
            walk_node(
                read_physical,
                chunks,
                kp.blockptr,
                nodesize,
                out,
                active_path,
                visited_nodes,
            )?;
        }
    }

    active_path.remove(&logical);
    Ok(())
}

fn collect_leaf_items(block: &[u8], out: &mut Vec<BtrfsLeafEntry>) -> Result<(), ParseError> {
    let (_, items) = parse_leaf_items(block)?;
    for item in &items {
        let off = usize::try_from(item.data_offset).map_err(|_| ParseError::IntegerConversion {
            field: "data_offset",
        })?;
        let sz = usize::try_from(item.data_size)
            .map_err(|_| ParseError::IntegerConversion { field: "data_size" })?;
        let end = off.checked_add(sz).ok_or(ParseError::InvalidField {
            field: "data_offset",
            reason: "overflow",
        })?;
        if end > block.len() {
            return Err(ParseError::InvalidField {
                field: "data_offset",
                reason: "item data extends past block",
            });
        }
        out.push(BtrfsLeafEntry {
            key: item.key,
            data: block[off..end].to_vec(),
        });
    }
    Ok(())
}

fn key_cmp(lhs: &BtrfsKey, rhs: &BtrfsKey) -> Ordering {
    lhs.objectid
        .cmp(&rhs.objectid)
        .then_with(|| lhs.item_type.cmp(&rhs.item_type))
        .then_with(|| lhs.offset.cmp(&rhs.offset))
}

/// Errors returned by in-memory btrfs COW tree mutation APIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BtrfsMutationError {
    InvalidConfig(&'static str),
    InvalidRange,
    KeyAlreadyExists,
    KeyNotFound,
    MissingNode(u64),
    BrokenInvariant(&'static str),
    AddressOverflow,
}

/// Key/value payload stored in leaf nodes for the in-memory COW model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtrfsTreeItem {
    pub key: BtrfsKey,
    pub data: Vec<u8>,
}

/// In-memory btrfs B-tree node model used for mutation planning and testing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BtrfsCowNode {
    Leaf {
        items: Vec<BtrfsTreeItem>,
    },
    Internal {
        keys: Vec<BtrfsKey>,
        children: Vec<u64>,
    },
}

/// COW B-tree mutation interface used by write-path planning code.
pub trait BtrfsBTree {
    fn insert(&mut self, key: BtrfsKey, item: &[u8]) -> Result<u64, BtrfsMutationError>;
    fn delete(&mut self, key: &BtrfsKey) -> Result<u64, BtrfsMutationError>;
    fn update(&mut self, key: &BtrfsKey, item: &[u8]) -> Result<u64, BtrfsMutationError>;
    fn range(
        &self,
        start: &BtrfsKey,
        end: &BtrfsKey,
    ) -> Result<Vec<(BtrfsKey, Vec<u8>)>, BtrfsMutationError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InsertResult {
    node_id: u64,
    split: Option<(BtrfsKey, u64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeleteResult {
    node_id: u64,
    deleted: bool,
}

/// In-memory COW btrfs B-tree. Every mutation allocates new nodes and advances
/// the root pointer, keeping previously-addressed nodes immutable.
#[derive(Debug, Clone)]
pub struct InMemoryCowBtrfsTree {
    max_items: usize,
    min_items: usize,
    root: u64,
    next_block: u64,
    nodes: BTreeMap<u64, BtrfsCowNode>,
}

impl InMemoryCowBtrfsTree {
    /// Create a COW B-tree with the requested maximum keys/items per node.
    ///
    /// `max_items` must be >= 3 to allow split/merge behavior.
    pub fn new(max_items: usize) -> Result<Self, BtrfsMutationError> {
        if max_items < 3 {
            return Err(BtrfsMutationError::InvalidConfig("max_items must be >= 3"));
        }
        let root = 1_u64;
        let mut nodes = BTreeMap::new();
        nodes.insert(root, BtrfsCowNode::Leaf { items: Vec::new() });
        Ok(Self {
            max_items,
            min_items: max_items / 2,
            root,
            next_block: 2,
            nodes,
        })
    }

    /// Current root block identifier.
    #[must_use]
    pub fn root_block(&self) -> u64 {
        self.root
    }

    /// Snapshot a node by block number.
    pub fn node_snapshot(&self, block: u64) -> Result<BtrfsCowNode, BtrfsMutationError> {
        self.nodes
            .get(&block)
            .cloned()
            .ok_or(BtrfsMutationError::MissingNode(block))
    }

    /// Return tree height (`1` for a leaf root).
    pub fn height(&self) -> Result<usize, BtrfsMutationError> {
        self.height_of(self.root)
    }

    /// Validate structure invariants:
    /// - key ordering
    /// - child count relationships
    /// - balanced depth
    /// - node occupancy for non-root nodes
    pub fn validate_invariants(&self) -> Result<(), BtrfsMutationError> {
        let mut leaf_depth = None;
        self.validate_node(self.root, None, None, 1, &mut leaf_depth, true)?;
        Ok(())
    }

    fn node_ref(&self, block: u64) -> Result<&BtrfsCowNode, BtrfsMutationError> {
        self.nodes
            .get(&block)
            .ok_or(BtrfsMutationError::MissingNode(block))
    }

    fn alloc_node(&mut self, node: BtrfsCowNode) -> Result<u64, BtrfsMutationError> {
        let block = self.next_block;
        self.next_block = self
            .next_block
            .checked_add(1)
            .ok_or(BtrfsMutationError::AddressOverflow)?;
        self.nodes.insert(block, node);
        Ok(block)
    }

    fn child_slot(keys: &[BtrfsKey], key: &BtrfsKey) -> usize {
        keys.iter()
            .position(|sep| key_cmp(key, sep) == Ordering::Less)
            .unwrap_or(keys.len())
    }

    fn insert_entry(
        &mut self,
        entry: BtrfsTreeItem,
        allow_replace: bool,
    ) -> Result<u64, BtrfsMutationError> {
        let old_root = self.root;
        trace!(
            root = old_root,
            objectid = entry.key.objectid,
            item_type = entry.key.item_type,
            offset = entry.key.offset,
            allow_replace,
            "btrfs_cow_insert_start"
        );
        let result = self.insert_into(self.root, entry, allow_replace)?;
        self.root = result.node_id;
        if let Some((separator, right_id)) = result.split {
            debug!(
                old_root,
                left_root = self.root,
                right_root = right_id,
                separator_objectid = separator.objectid,
                separator_type = separator.item_type,
                separator_offset = separator.offset,
                "btrfs_cow_root_split"
            );
            let new_root = self.alloc_node(BtrfsCowNode::Internal {
                keys: vec![separator],
                children: vec![self.root, right_id],
            })?;
            self.root = new_root;
        }
        trace!(old_root, new_root = self.root, "btrfs_cow_insert_complete");
        Ok(self.root)
    }

    fn insert_into(
        &mut self,
        node_id: u64,
        entry: BtrfsTreeItem,
        allow_replace: bool,
    ) -> Result<InsertResult, BtrfsMutationError> {
        let node = self.node_ref(node_id)?.clone();
        match node {
            BtrfsCowNode::Leaf { items } => self.insert_into_leaf(items, entry, allow_replace),
            BtrfsCowNode::Internal { keys, children } => {
                self.insert_into_internal(keys, children, entry, allow_replace)
            }
        }
    }

    fn insert_into_leaf(
        &mut self,
        mut items: Vec<BtrfsTreeItem>,
        entry: BtrfsTreeItem,
        allow_replace: bool,
    ) -> Result<InsertResult, BtrfsMutationError> {
        let idx = items.partition_point(|existing| key_cmp(&existing.key, &entry.key).is_lt());
        if let Some(existing) = items.get_mut(idx)
            && key_cmp(&existing.key, &entry.key) == Ordering::Equal
        {
            if allow_replace {
                trace!(
                    objectid = entry.key.objectid,
                    item_type = entry.key.item_type,
                    offset = entry.key.offset,
                    "btrfs_cow_update_leaf"
                );
                existing.data = entry.data;
                let new_id = self.alloc_node(BtrfsCowNode::Leaf { items })?;
                return Ok(InsertResult {
                    node_id: new_id,
                    split: None,
                });
            }
            return Err(BtrfsMutationError::KeyAlreadyExists);
        }

        items.insert(idx, entry);
        if items.len() <= self.max_items {
            let new_id = self.alloc_node(BtrfsCowNode::Leaf { items })?;
            return Ok(InsertResult {
                node_id: new_id,
                split: None,
            });
        }

        let mid = items.len() / 2;
        let right_items = items.split_off(mid);
        let separator =
            right_items
                .first()
                .map(|item| item.key)
                .ok_or(BtrfsMutationError::BrokenInvariant(
                    "right split leaf must not be empty",
                ))?;
        debug!(
            separator_objectid = separator.objectid,
            separator_type = separator.item_type,
            separator_offset = separator.offset,
            left_items = items.len(),
            right_items = right_items.len(),
            "btrfs_cow_leaf_split"
        );
        let left_id = self.alloc_node(BtrfsCowNode::Leaf { items })?;
        let right_id = self.alloc_node(BtrfsCowNode::Leaf { items: right_items })?;
        Ok(InsertResult {
            node_id: left_id,
            split: Some((separator, right_id)),
        })
    }

    fn insert_into_internal(
        &mut self,
        mut keys: Vec<BtrfsKey>,
        mut children: Vec<u64>,
        entry: BtrfsTreeItem,
        allow_replace: bool,
    ) -> Result<InsertResult, BtrfsMutationError> {
        if children.len() != keys.len().saturating_add(1) {
            return Err(BtrfsMutationError::BrokenInvariant(
                "internal node child count mismatch",
            ));
        }

        let idx = Self::child_slot(&keys, &entry.key);
        let child_result = self.insert_into(children[idx], entry, allow_replace)?;
        children[idx] = child_result.node_id;
        if let Some((separator, right_child)) = child_result.split {
            keys.insert(idx, separator);
            children.insert(idx + 1, right_child);
        }

        if keys.len() <= self.max_items {
            let new_id = self.alloc_node(BtrfsCowNode::Internal { keys, children })?;
            return Ok(InsertResult {
                node_id: new_id,
                split: None,
            });
        }

        let mid = keys.len() / 2;
        let separator = keys[mid];
        let right_keys = keys.split_off(mid + 1);
        let removed = keys.pop();
        if removed.is_none() {
            return Err(BtrfsMutationError::BrokenInvariant(
                "internal split separator missing",
            ));
        }
        let right_children = children.split_off(mid + 1);
        debug!(
            separator_objectid = separator.objectid,
            separator_type = separator.item_type,
            separator_offset = separator.offset,
            left_keys = keys.len(),
            right_keys = right_keys.len(),
            "btrfs_cow_internal_split"
        );
        let left_id = self.alloc_node(BtrfsCowNode::Internal { keys, children })?;
        let right_id = self.alloc_node(BtrfsCowNode::Internal {
            keys: right_keys,
            children: right_children,
        })?;
        Ok(InsertResult {
            node_id: left_id,
            split: Some((separator, right_id)),
        })
    }

    fn first_key(&self, node_id: u64) -> Result<Option<BtrfsKey>, BtrfsMutationError> {
        match self.node_ref(node_id)? {
            BtrfsCowNode::Leaf { items } => Ok(items.first().map(|item| item.key)),
            BtrfsCowNode::Internal { children, .. } => {
                let Some(first_child) = children.first() else {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "internal node must have children",
                    ));
                };
                self.first_key(*first_child)
            }
        }
    }

    fn compute_internal_keys(&self, children: &[u64]) -> Result<Vec<BtrfsKey>, BtrfsMutationError> {
        if children.is_empty() {
            return Err(BtrfsMutationError::BrokenInvariant(
                "internal node must have children",
            ));
        }
        let mut keys = Vec::with_capacity(children.len().saturating_sub(1));
        for child in children.iter().skip(1) {
            let Some(separator) = self.first_key(*child)? else {
                return Err(BtrfsMutationError::BrokenInvariant(
                    "internal separator child must contain a key",
                ));
            };
            keys.push(separator);
        }
        Ok(keys)
    }

    fn alloc_internal_node(&mut self, children: Vec<u64>) -> Result<u64, BtrfsMutationError> {
        let keys = self.compute_internal_keys(&children)?;
        self.alloc_node(BtrfsCowNode::Internal { keys, children })
    }

    fn node_key_count(&self, node_id: u64) -> Result<usize, BtrfsMutationError> {
        match self.node_ref(node_id)? {
            BtrfsCowNode::Leaf { items } => Ok(items.len()),
            BtrfsCowNode::Internal { keys, .. } => Ok(keys.len()),
        }
    }

    fn rotate_from_left(
        &mut self,
        left_id: u64,
        right_id: u64,
    ) -> Result<(u64, u64), BtrfsMutationError> {
        let left_node = self.node_ref(left_id)?.clone();
        let right_node = self.node_ref(right_id)?.clone();
        match (left_node, right_node) {
            (
                BtrfsCowNode::Leaf {
                    items: mut left_items,
                },
                BtrfsCowNode::Leaf {
                    items: mut right_items,
                },
            ) => {
                let moved = left_items.pop().ok_or(BtrfsMutationError::BrokenInvariant(
                    "cannot borrow from empty left leaf",
                ))?;
                right_items.insert(0, moved);
                let new_left = self.alloc_node(BtrfsCowNode::Leaf { items: left_items })?;
                let new_right = self.alloc_node(BtrfsCowNode::Leaf { items: right_items })?;
                Ok((new_left, new_right))
            }
            (
                BtrfsCowNode::Internal {
                    children: mut left_children,
                    ..
                },
                BtrfsCowNode::Internal {
                    children: mut right_children,
                    ..
                },
            ) => {
                let moved = left_children
                    .pop()
                    .ok_or(BtrfsMutationError::BrokenInvariant(
                        "cannot borrow from empty left internal",
                    ))?;
                right_children.insert(0, moved);
                let new_left = self.alloc_internal_node(left_children)?;
                let new_right = self.alloc_internal_node(right_children)?;
                Ok((new_left, new_right))
            }
            _ => Err(BtrfsMutationError::BrokenInvariant(
                "sibling node type mismatch",
            )),
        }
    }

    fn rotate_from_right(
        &mut self,
        left_id: u64,
        right_id: u64,
    ) -> Result<(u64, u64), BtrfsMutationError> {
        let left_node = self.node_ref(left_id)?.clone();
        let right_node = self.node_ref(right_id)?.clone();
        match (left_node, right_node) {
            (
                BtrfsCowNode::Leaf {
                    items: mut left_items,
                },
                BtrfsCowNode::Leaf {
                    items: mut right_items,
                },
            ) => {
                if right_items.is_empty() {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "cannot borrow from empty right leaf",
                    ));
                }
                right_items.rotate_left(1);
                let moved = right_items
                    .pop()
                    .ok_or(BtrfsMutationError::BrokenInvariant(
                        "cannot borrow from empty right leaf",
                    ))?;
                left_items.push(moved);
                let new_left = self.alloc_node(BtrfsCowNode::Leaf { items: left_items })?;
                let new_right = self.alloc_node(BtrfsCowNode::Leaf { items: right_items })?;
                Ok((new_left, new_right))
            }
            (
                BtrfsCowNode::Internal {
                    children: mut left_children,
                    ..
                },
                BtrfsCowNode::Internal {
                    children: mut right_children,
                    ..
                },
            ) => {
                if right_children.is_empty() {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "cannot borrow from empty right internal",
                    ));
                }
                right_children.rotate_left(1);
                let moved = right_children
                    .pop()
                    .ok_or(BtrfsMutationError::BrokenInvariant(
                        "cannot borrow from empty right internal",
                    ))?;
                left_children.push(moved);
                let new_left = self.alloc_internal_node(left_children)?;
                let new_right = self.alloc_internal_node(right_children)?;
                Ok((new_left, new_right))
            }
            _ => Err(BtrfsMutationError::BrokenInvariant(
                "sibling node type mismatch",
            )),
        }
    }

    fn merge_adjacent_nodes(
        &mut self,
        left_id: u64,
        right_id: u64,
    ) -> Result<u64, BtrfsMutationError> {
        let left_node = self.node_ref(left_id)?.clone();
        let right_node = self.node_ref(right_id)?.clone();
        match (left_node, right_node) {
            (
                BtrfsCowNode::Leaf {
                    items: mut left_items,
                },
                BtrfsCowNode::Leaf { items: right_items },
            ) => {
                left_items.extend(right_items);
                self.alloc_node(BtrfsCowNode::Leaf { items: left_items })
            }
            (
                BtrfsCowNode::Internal {
                    children: mut left_children,
                    ..
                },
                BtrfsCowNode::Internal {
                    children: right_children,
                    ..
                },
            ) => {
                left_children.extend(right_children);
                self.alloc_internal_node(left_children)
            }
            _ => Err(BtrfsMutationError::BrokenInvariant(
                "cannot merge different node types",
            )),
        }
    }

    fn rebalance_child(
        &mut self,
        children: &mut Vec<u64>,
        child_idx: usize,
    ) -> Result<(), BtrfsMutationError> {
        if child_idx >= children.len() {
            return Err(BtrfsMutationError::BrokenInvariant(
                "child index out of bounds",
            ));
        }
        if children.len() <= 1 {
            return Ok(());
        }

        let child_keys = self.node_key_count(children[child_idx])?;
        if child_keys >= self.min_items {
            return Ok(());
        }

        if child_idx > 0 {
            let left_keys = self.node_key_count(children[child_idx - 1])?;
            if left_keys > self.min_items {
                let (new_left, new_child) =
                    self.rotate_from_left(children[child_idx - 1], children[child_idx])?;
                children[child_idx - 1] = new_left;
                children[child_idx] = new_child;
                debug!(
                    child_idx,
                    left_keys, child_keys, "btrfs_cow_delete_borrow_left"
                );
                return Ok(());
            }
        }

        if child_idx + 1 < children.len() {
            let right_keys = self.node_key_count(children[child_idx + 1])?;
            if right_keys > self.min_items {
                let (new_child, new_right) =
                    self.rotate_from_right(children[child_idx], children[child_idx + 1])?;
                children[child_idx] = new_child;
                children[child_idx + 1] = new_right;
                debug!(
                    child_idx,
                    right_keys, child_keys, "btrfs_cow_delete_borrow_right"
                );
                return Ok(());
            }
        }

        if child_idx > 0 {
            let merged = self.merge_adjacent_nodes(children[child_idx - 1], children[child_idx])?;
            children[child_idx - 1] = merged;
            children.remove(child_idx);
            debug!(merged_child = child_idx - 1, "btrfs_cow_delete_merge_left");
        } else {
            let merged = self.merge_adjacent_nodes(children[child_idx], children[child_idx + 1])?;
            children[child_idx] = merged;
            children.remove(child_idx + 1);
            debug!(merged_child = child_idx, "btrfs_cow_delete_merge_right");
        }
        Ok(())
    }

    fn delete_from(
        &mut self,
        node_id: u64,
        key: &BtrfsKey,
    ) -> Result<DeleteResult, BtrfsMutationError> {
        let node = self.node_ref(node_id)?.clone();
        match node {
            BtrfsCowNode::Leaf { mut items } => {
                let idx = items.partition_point(|existing| key_cmp(&existing.key, key).is_lt());
                let Some(existing) = items.get(idx) else {
                    return Ok(DeleteResult {
                        node_id,
                        deleted: false,
                    });
                };
                if key_cmp(&existing.key, key) != Ordering::Equal {
                    return Ok(DeleteResult {
                        node_id,
                        deleted: false,
                    });
                }
                items.remove(idx);
                let new_id = self.alloc_node(BtrfsCowNode::Leaf { items })?;
                Ok(DeleteResult {
                    node_id: new_id,
                    deleted: true,
                })
            }
            BtrfsCowNode::Internal { keys, mut children } => {
                if children.len() != keys.len().saturating_add(1) {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "internal node child count mismatch",
                    ));
                }
                let idx = Self::child_slot(&keys, key);
                let child_result = self.delete_from(children[idx], key)?;
                if !child_result.deleted {
                    return Ok(DeleteResult {
                        node_id,
                        deleted: false,
                    });
                }
                children[idx] = child_result.node_id;
                self.rebalance_child(&mut children, idx)?;
                let new_id = self.alloc_internal_node(children)?;
                Ok(DeleteResult {
                    node_id: new_id,
                    deleted: true,
                })
            }
        }
    }

    fn normalize_root_after_delete(&mut self) -> Result<(), BtrfsMutationError> {
        loop {
            let root_node = self.node_ref(self.root)?.clone();
            let BtrfsCowNode::Internal { children, .. } = root_node else {
                break;
            };
            if children.len() != 1 {
                break;
            }
            let Some(child) = children.first() else {
                return Err(BtrfsMutationError::BrokenInvariant(
                    "internal node must have children",
                ));
            };
            self.root = *child;
        }
        Ok(())
    }

    fn find(&self, key: &BtrfsKey) -> Result<Option<Vec<u8>>, BtrfsMutationError> {
        self.find_in(self.root, key)
    }

    fn find_in(&self, node_id: u64, key: &BtrfsKey) -> Result<Option<Vec<u8>>, BtrfsMutationError> {
        match self.node_ref(node_id)? {
            BtrfsCowNode::Leaf { items } => Ok(items
                .iter()
                .find(|item| key_cmp(&item.key, key) == Ordering::Equal)
                .map(|item| item.data.clone())),
            BtrfsCowNode::Internal { keys, children } => {
                if children.len() != keys.len().saturating_add(1) {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "internal node child count mismatch",
                    ));
                }
                let idx = Self::child_slot(keys, key);
                self.find_in(children[idx], key)
            }
        }
    }

    fn collect_all_items(&self) -> Result<Vec<BtrfsTreeItem>, BtrfsMutationError> {
        let mut out = Vec::new();
        self.collect_from(self.root, &mut out)?;
        Ok(out)
    }

    fn collect_from(
        &self,
        node_id: u64,
        out: &mut Vec<BtrfsTreeItem>,
    ) -> Result<(), BtrfsMutationError> {
        match self.node_ref(node_id)? {
            BtrfsCowNode::Leaf { items } => {
                out.extend(items.iter().cloned());
            }
            BtrfsCowNode::Internal { children, .. } => {
                for child in children {
                    self.collect_from(*child, out)?;
                }
            }
        }
        Ok(())
    }

    fn height_of(&self, node_id: u64) -> Result<usize, BtrfsMutationError> {
        match self.node_ref(node_id)? {
            BtrfsCowNode::Leaf { .. } => Ok(1),
            BtrfsCowNode::Internal { children, .. } => {
                let mut child_heights = children
                    .iter()
                    .map(|child| self.height_of(*child))
                    .collect::<Result<Vec<_>, _>>()?;
                let first = child_heights
                    .pop()
                    .ok_or(BtrfsMutationError::BrokenInvariant(
                        "internal node must have children",
                    ))?;
                if child_heights.iter().any(|height| *height != first) {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "tree is not height-balanced",
                    ));
                }
                Ok(first + 1)
            }
        }
    }

    fn validate_node(
        &self,
        node_id: u64,
        lower: Option<BtrfsKey>,
        upper: Option<BtrfsKey>,
        depth: usize,
        leaf_depth: &mut Option<usize>,
        is_root: bool,
    ) -> Result<(), BtrfsMutationError> {
        match self.node_ref(node_id)? {
            BtrfsCowNode::Leaf { items } => {
                if !is_root && items.len() < self.min_items {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "non-root leaf underflow",
                    ));
                }
                for window in items.windows(2) {
                    if key_cmp(&window[0].key, &window[1].key) != Ordering::Less {
                        return Err(BtrfsMutationError::BrokenInvariant(
                            "leaf keys must be strictly increasing",
                        ));
                    }
                }
                for item in items {
                    if let Some(min_key) = lower
                        && key_cmp(&item.key, &min_key) == Ordering::Less
                    {
                        return Err(BtrfsMutationError::BrokenInvariant(
                            "leaf key below lower bound",
                        ));
                    }
                    if let Some(max_key) = upper
                        && key_cmp(&item.key, &max_key) != Ordering::Less
                    {
                        return Err(BtrfsMutationError::BrokenInvariant(
                            "leaf key above upper bound",
                        ));
                    }
                }
                if let Some(expected_depth) = *leaf_depth {
                    if expected_depth != depth {
                        return Err(BtrfsMutationError::BrokenInvariant(
                            "leaves must have uniform depth",
                        ));
                    }
                } else {
                    *leaf_depth = Some(depth);
                }
                Ok(())
            }
            BtrfsCowNode::Internal { keys, children } => {
                if children.len() != keys.len().saturating_add(1) {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "internal node child count mismatch",
                    ));
                }
                if !is_root && keys.len() < self.min_items {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "non-root internal underflow",
                    ));
                }
                for window in keys.windows(2) {
                    if key_cmp(&window[0], &window[1]) != Ordering::Less {
                        return Err(BtrfsMutationError::BrokenInvariant(
                            "internal separators must be strictly increasing",
                        ));
                    }
                }
                for (idx, separator) in keys.iter().enumerate() {
                    let Some(expected) = self.first_key(children[idx + 1])? else {
                        return Err(BtrfsMutationError::BrokenInvariant(
                            "separator child must contain a key",
                        ));
                    };
                    if key_cmp(separator, &expected) != Ordering::Equal {
                        return Err(BtrfsMutationError::BrokenInvariant(
                            "internal separator mismatch",
                        ));
                    }
                }
                for (idx, child) in children.iter().enumerate() {
                    let child_lower = if idx == 0 { lower } else { Some(keys[idx - 1]) };
                    let child_upper = if idx == keys.len() {
                        upper
                    } else {
                        Some(keys[idx])
                    };
                    self.validate_node(
                        *child,
                        child_lower,
                        child_upper,
                        depth + 1,
                        leaf_depth,
                        false,
                    )?;
                }
                Ok(())
            }
        }
    }
}

impl BtrfsBTree for InMemoryCowBtrfsTree {
    fn insert(&mut self, key: BtrfsKey, item: &[u8]) -> Result<u64, BtrfsMutationError> {
        self.insert_entry(
            BtrfsTreeItem {
                key,
                data: item.to_vec(),
            },
            false,
        )
    }

    fn delete(&mut self, key: &BtrfsKey) -> Result<u64, BtrfsMutationError> {
        let old_root = self.root;
        trace!(
            root = old_root,
            objectid = key.objectid,
            item_type = key.item_type,
            offset = key.offset,
            "btrfs_cow_delete_start"
        );
        let deleted = self.delete_from(self.root, key)?;
        if !deleted.deleted {
            return Err(BtrfsMutationError::KeyNotFound);
        }
        self.root = deleted.node_id;
        self.normalize_root_after_delete()?;
        trace!(old_root, new_root = self.root, "btrfs_cow_delete_complete");
        Ok(self.root)
    }

    fn update(&mut self, key: &BtrfsKey, item: &[u8]) -> Result<u64, BtrfsMutationError> {
        if self.find(key)?.is_none() {
            return Err(BtrfsMutationError::KeyNotFound);
        }
        self.insert_entry(
            BtrfsTreeItem {
                key: *key,
                data: item.to_vec(),
            },
            true,
        )
    }

    fn range(
        &self,
        start: &BtrfsKey,
        end: &BtrfsKey,
    ) -> Result<Vec<(BtrfsKey, Vec<u8>)>, BtrfsMutationError> {
        if key_cmp(start, end) == Ordering::Greater {
            return Err(BtrfsMutationError::InvalidRange);
        }
        Ok(self
            .collect_all_items()?
            .into_iter()
            .filter(|item| {
                key_cmp(&item.key, start) != Ordering::Less
                    && key_cmp(&item.key, end) != Ordering::Greater
            })
            .map(|item| (item.key, item.data))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffs_ondisk::BtrfsStripe;
    use std::collections::{BTreeMap, HashMap};

    const NODESIZE: u32 = 4096;
    const HEADER_SIZE: usize = 101;
    const ITEM_SIZE: usize = 25;
    const KEY_PTR_SIZE: usize = 33;

    fn test_key(objectid: u64) -> BtrfsKey {
        BtrfsKey {
            objectid,
            item_type: BTRFS_ITEM_INODE_ITEM,
            offset: 0,
        }
    }

    fn test_payload(objectid: u64) -> [u8; 1] {
        [u8::try_from(objectid).expect("test objectid should fit in u8")]
    }

    /// Build a btrfs header in a block buffer.
    fn write_header(
        block: &mut [u8],
        bytenr: u64,
        nritems: u32,
        level: u8,
        owner: u64,
        generation: u64,
    ) {
        block[0x30..0x38].copy_from_slice(&bytenr.to_le_bytes());
        block[0x50..0x58].copy_from_slice(&generation.to_le_bytes());
        block[0x58..0x60].copy_from_slice(&owner.to_le_bytes());
        block[0x60..0x64].copy_from_slice(&nritems.to_le_bytes());
        block[0x64] = level;
    }

    /// Write a leaf item entry at the given index.
    fn write_leaf_item(
        block: &mut [u8],
        idx: usize,
        objectid: u64,
        item_type: u8,
        data_off: u32,
        data_sz: u32,
    ) {
        let base = HEADER_SIZE + idx * ITEM_SIZE;
        block[base..base + 8].copy_from_slice(&objectid.to_le_bytes());
        block[base + 8] = item_type;
        block[base + 9..base + 17].copy_from_slice(&0_u64.to_le_bytes());
        block[base + 17..base + 21].copy_from_slice(&data_off.to_le_bytes());
        block[base + 21..base + 25].copy_from_slice(&data_sz.to_le_bytes());
    }

    /// Write an internal key-pointer entry at the given index.
    fn write_key_ptr(
        block: &mut [u8],
        idx: usize,
        objectid: u64,
        item_type: u8,
        blockptr: u64,
        generation: u64,
    ) {
        let base = HEADER_SIZE + idx * KEY_PTR_SIZE;
        block[base..base + 8].copy_from_slice(&objectid.to_le_bytes());
        block[base + 8] = item_type;
        block[base + 9..base + 17].copy_from_slice(&0_u64.to_le_bytes());
        block[base + 17..base + 25].copy_from_slice(&blockptr.to_le_bytes());
        block[base + 25..base + 33].copy_from_slice(&generation.to_le_bytes());
    }

    /// Identity chunk: logical == physical for the range [0, 1GiB).
    fn identity_chunks() -> Vec<BtrfsChunkEntry> {
        vec![BtrfsChunkEntry {
            key: BtrfsKey {
                objectid: 256,
                item_type: 228,
                offset: 0,
            },
            length: 0x4000_0000, // 1 GiB
            owner: 2,
            stripe_len: 0x1_0000,
            chunk_type: 2,
            io_align: 4096,
            io_width: 4096,
            sector_size: 4096,
            num_stripes: 1,
            sub_stripes: 0,
            stripes: vec![BtrfsStripe {
                devid: 1,
                offset: 0, // identity mapping
                dev_uuid: [0; 16],
            }],
        }]
    }

    #[test]
    fn walk_single_leaf() {
        let logical = 0x4000_u64;
        let chunks = identity_chunks();

        let mut leaf = vec![0_u8; NODESIZE as usize];
        write_header(&mut leaf, logical, 2, 0, 5, 10);
        // Item 0: key=(256,1,0), data at [3000..3010]
        write_leaf_item(&mut leaf, 0, 256, 1, 3000, 10);
        leaf[3000..3010].copy_from_slice(&[0xAA; 10]);
        // Item 1: key=(257,1,0), data at [3010..3025]
        write_leaf_item(&mut leaf, 1, 257, 1, 3010, 15);
        leaf[3010..3025].copy_from_slice(&[0xBB; 15]);

        let blocks: HashMap<u64, Vec<u8>> = [(logical, leaf)].into();
        let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
            blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                field: "physical",
                reason: "block not in test image",
            })
        };

        let entries = walk_tree(&mut read, &chunks, logical, NODESIZE).expect("walk");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key.objectid, 256);
        assert_eq!(entries[0].data, vec![0xAA; 10]);
        assert_eq!(entries[1].key.objectid, 257);
        assert_eq!(entries[1].data, vec![0xBB; 15]);
    }

    #[test]
    fn walk_internal_plus_leaves() {
        let root_logical = 0x1_0000_u64;
        let left_logical = 0x2_0000_u64;
        let right_logical = 0x3_0000_u64;
        let chunks = identity_chunks();

        // Root: internal node (level=1) with 2 children
        let mut root = vec![0_u8; NODESIZE as usize];
        write_header(&mut root, root_logical, 2, 1, 1, 10);
        write_key_ptr(&mut root, 0, 256, 1, left_logical, 10);
        write_key_ptr(&mut root, 1, 512, 1, right_logical, 10);

        // Leaf A: 1 item
        let mut left_leaf = vec![0_u8; NODESIZE as usize];
        write_header(&mut left_leaf, left_logical, 1, 0, 5, 10);
        write_leaf_item(&mut left_leaf, 0, 256, 1, 2000, 4);
        left_leaf[2000..2004].copy_from_slice(&[1, 2, 3, 4]);

        // Leaf B: 1 item
        let mut right_leaf = vec![0_u8; NODESIZE as usize];
        write_header(&mut right_leaf, right_logical, 1, 0, 5, 10);
        write_leaf_item(&mut right_leaf, 0, 512, 1, 2000, 4);
        right_leaf[2000..2004].copy_from_slice(&[5, 6, 7, 8]);

        let blocks: HashMap<u64, Vec<u8>> = [
            (root_logical, root),
            (left_logical, left_leaf),
            (right_logical, right_leaf),
        ]
        .into();
        let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
            blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                field: "physical",
                reason: "block not in test image",
            })
        };

        let entries = walk_tree(&mut read, &chunks, root_logical, NODESIZE).expect("walk");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key.objectid, 256);
        assert_eq!(entries[0].data, vec![1, 2, 3, 4]);
        assert_eq!(entries[1].key.objectid, 512);
        assert_eq!(entries[1].data, vec![5, 6, 7, 8]);
    }

    #[test]
    fn walk_unmapped_address_fails() {
        let chunks = identity_chunks();
        // Address beyond the 1GiB chunk range
        let far_logical = 0x8000_0000_u64;
        let mut read = |_phys: u64| -> Result<Vec<u8>, ParseError> {
            panic!("should not be called");
        };
        let err = walk_tree(&mut read, &chunks, far_logical, NODESIZE).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "logical_address",
                    ..
                }
            ),
            "expected unmapped error, got: {err:?}"
        );
    }

    #[test]
    fn walk_empty_leaf() {
        let logical = 0x4000_u64;
        let chunks = identity_chunks();

        let mut leaf = vec![0_u8; NODESIZE as usize];
        write_header(&mut leaf, logical, 0, 0, 5, 10);

        let blocks: HashMap<u64, Vec<u8>> = [(logical, leaf)].into();
        let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
            blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                field: "physical",
                reason: "block not in test image",
            })
        };

        let entries = walk_tree(&mut read, &chunks, logical, NODESIZE).expect("walk");
        assert!(entries.is_empty());
    }

    #[test]
    fn walk_self_cycle_fails_fast() {
        let root_logical = 0x1_0000_u64;
        let chunks = identity_chunks();

        let mut root = vec![0_u8; NODESIZE as usize];
        write_header(&mut root, root_logical, 1, 1, 1, 10);
        write_key_ptr(&mut root, 0, 256, 1, root_logical, 10);

        let blocks: HashMap<u64, Vec<u8>> = [(root_logical, root)].into();
        let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
            blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                field: "physical",
                reason: "block not in test image",
            })
        };

        let err = walk_tree(&mut read, &chunks, root_logical, NODESIZE).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "logical_address",
                reason: "cycle detected in btrfs tree pointers",
            }
        ));
    }

    #[test]
    fn walk_two_node_cycle_fails_fast() {
        let a_logical = 0x1_0000_u64;
        let b_logical = 0x2_0000_u64;
        let chunks = identity_chunks();

        let mut a = vec![0_u8; NODESIZE as usize];
        write_header(&mut a, a_logical, 1, 1, 1, 10);
        write_key_ptr(&mut a, 0, 256, 1, b_logical, 10);

        let mut b = vec![0_u8; NODESIZE as usize];
        write_header(&mut b, b_logical, 1, 1, 1, 10);
        write_key_ptr(&mut b, 0, 256, 1, a_logical, 10);

        let blocks: HashMap<u64, Vec<u8>> = [(a_logical, a), (b_logical, b)].into();
        let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
            blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                field: "physical",
                reason: "block not in test image",
            })
        };

        let err = walk_tree(&mut read, &chunks, a_logical, NODESIZE).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "logical_address",
                reason: "cycle detected in btrfs tree pointers",
            }
        ));
    }

    #[test]
    fn walk_duplicate_child_reference_fails_fast() {
        let root_logical = 0x1_0000_u64;
        let leaf_logical = 0x2_0000_u64;
        let chunks = identity_chunks();

        let mut root = vec![0_u8; NODESIZE as usize];
        write_header(&mut root, root_logical, 2, 1, 1, 10);
        write_key_ptr(&mut root, 0, 256, 1, leaf_logical, 10);
        write_key_ptr(&mut root, 1, 512, 1, leaf_logical, 10);

        let mut leaf = vec![0_u8; NODESIZE as usize];
        write_header(&mut leaf, leaf_logical, 0, 0, 5, 10);

        let blocks: HashMap<u64, Vec<u8>> = [(root_logical, root), (leaf_logical, leaf)].into();
        let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
            blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                field: "physical",
                reason: "block not in test image",
            })
        };

        let err = walk_tree(&mut read, &chunks, root_logical, NODESIZE).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "logical_address",
                reason: "duplicate node reference in btrfs tree pointers",
            }
        ));
    }

    #[test]
    fn cow_insert_preserves_previous_root_node() {
        let mut tree = InMemoryCowBtrfsTree::new(3).expect("tree");
        tree.insert(test_key(10), b"a").expect("insert first");
        let root_before = tree.root_block();
        let snapshot = tree.node_snapshot(root_before).expect("snapshot");

        tree.insert(test_key(20), b"b").expect("insert second");
        let root_after = tree.root_block();
        assert_ne!(root_before, root_after);
        assert_eq!(
            tree.node_snapshot(root_before).expect("snapshot old root"),
            snapshot
        );
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn insert_split_creates_internal_root() {
        let mut tree = InMemoryCowBtrfsTree::new(3).expect("tree");
        for objectid in [10_u64, 20, 30, 40] {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("insert");
        }

        assert!(matches!(
            tree.node_snapshot(tree.root_block())
                .expect("root snapshot"),
            BtrfsCowNode::Internal { .. }
        ));
        let entries = tree
            .range(&test_key(0), &test_key(100))
            .expect("range query");
        let keys = entries
            .iter()
            .map(|(key, _)| key.objectid)
            .collect::<Vec<_>>();
        assert_eq!(keys, vec![10, 20, 30, 40]);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn delete_shrinks_to_leaf_root() {
        let mut tree = InMemoryCowBtrfsTree::new(3).expect("tree");
        for objectid in 1_u64..=8 {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("insert");
        }
        let height_before = tree.height().expect("height before");

        for objectid in 2_u64..=8 {
            tree.delete(&test_key(objectid)).expect("delete");
        }

        let height_after = tree.height().expect("height after");
        assert!(height_after <= height_before);
        assert!(matches!(
            tree.node_snapshot(tree.root_block())
                .expect("root snapshot"),
            BtrfsCowNode::Leaf { .. }
        ));
        let entries = tree
            .range(&test_key(0), &test_key(100))
            .expect("range query");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0.objectid, 1);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn delete_underflow_borrows_from_right_sibling() {
        let mut tree = InMemoryCowBtrfsTree::new(4).expect("tree");
        for objectid in 1_u64..=5 {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("insert");
        }

        tree.delete(&test_key(1)).expect("delete");
        let keys = tree
            .range(&test_key(0), &test_key(10))
            .expect("range query")
            .iter()
            .map(|(key, _)| key.objectid)
            .collect::<Vec<_>>();
        assert_eq!(keys, vec![2, 3, 4, 5]);
        assert_eq!(tree.height().expect("height"), 2);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn delete_underflow_merges_and_shrinks_root() {
        let mut tree = InMemoryCowBtrfsTree::new(4).expect("tree");
        for objectid in 1_u64..=5 {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("insert");
        }

        tree.delete(&test_key(5)).expect("delete first");
        tree.delete(&test_key(4)).expect("delete second");
        let keys = tree
            .range(&test_key(0), &test_key(10))
            .expect("range query")
            .iter()
            .map(|(key, _)| key.objectid)
            .collect::<Vec<_>>();
        assert_eq!(keys, vec![1, 2, 3]);
        assert_eq!(tree.height().expect("height"), 1);
        assert!(matches!(
            tree.node_snapshot(tree.root_block())
                .expect("root snapshot"),
            BtrfsCowNode::Leaf { .. }
        ));
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn delete_missing_key_returns_error() {
        let mut tree = InMemoryCowBtrfsTree::new(3).expect("tree");
        tree.insert(test_key(1), b"a").expect("insert");
        let err = tree.delete(&test_key(999)).expect_err("delete should fail");
        assert_eq!(err, BtrfsMutationError::KeyNotFound);
    }

    #[test]
    fn update_replaces_existing_value() {
        let mut tree = InMemoryCowBtrfsTree::new(5).expect("tree");
        let key = test_key(9);
        tree.insert(key, b"old").expect("insert");
        tree.update(&key, b"new").expect("update");
        let entries = tree.range(&key, &key).expect("point range");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1, b"new");
    }

    #[test]
    fn range_returns_inclusive_sorted_window() {
        let mut tree = InMemoryCowBtrfsTree::new(5).expect("tree");
        for objectid in 1_u64..=6 {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("insert");
        }

        let entries = tree.range(&test_key(2), &test_key(4)).expect("range query");
        let keys = entries
            .iter()
            .map(|(key, _)| key.objectid)
            .collect::<Vec<_>>();
        assert_eq!(keys, vec![2, 3, 4]);
    }

    #[test]
    fn random_mutations_preserve_invariants_and_ordering() {
        let mut tree = InMemoryCowBtrfsTree::new(5).expect("tree");
        let mut model = BTreeMap::<u64, u8>::new();
        let mut state = 0xD1CE_D00D_CAFE_BABEu64;

        for _ in 0..1000 {
            // LCG for deterministic pseudo-random operations without extra deps.
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let objectid = (state % 128) + 1;
            let op = state % 3;
            let payload = [u8::try_from(objectid).expect("objectid should fit u8")];
            let key = test_key(objectid);

            match op {
                0 => {
                    if tree.insert(key, &payload).is_ok() {
                        model.insert(objectid, payload[0]);
                    }
                }
                1 => {
                    if tree.update(&key, &payload).is_ok() {
                        model.insert(objectid, payload[0]);
                    }
                }
                _ => {
                    if tree.delete(&key).is_ok() {
                        model.remove(&objectid);
                    }
                }
            }

            tree.validate_invariants().expect("invariants after op");
            let observed = tree
                .range(&test_key(0), &test_key(u64::MAX))
                .expect("full range");
            let observed_keys = observed
                .iter()
                .map(|(entry_key, _)| entry_key.objectid)
                .collect::<Vec<_>>();
            let model_keys = model.keys().copied().collect::<Vec<_>>();
            assert_eq!(observed_keys, model_keys);
        }
    }

    #[test]
    fn parse_root_item_smoke() {
        let mut root = vec![0_u8; 239];
        root[176..184].copy_from_slice(&0x1234_0000_u64.to_le_bytes());
        root[238] = 0;
        let parsed = parse_root_item(&root).expect("parse root item");
        assert_eq!(parsed.bytenr, 0x1234_0000);
        assert_eq!(parsed.level, 0);
    }

    #[test]
    fn parse_inode_item_smoke() {
        let mut inode = [0_u8; 160];
        inode[16..24].copy_from_slice(&4096_u64.to_le_bytes());
        inode[24..32].copy_from_slice(&4096_u64.to_le_bytes());
        inode[40..44].copy_from_slice(&2_u32.to_le_bytes());
        inode[44..48].copy_from_slice(&1000_u32.to_le_bytes());
        inode[48..52].copy_from_slice(&1000_u32.to_le_bytes());
        inode[52..56].copy_from_slice(&0o040_755_u32.to_le_bytes());
        inode[112..120].copy_from_slice(&10_u64.to_le_bytes());
        inode[124..132].copy_from_slice(&11_u64.to_le_bytes());
        inode[136..144].copy_from_slice(&12_u64.to_le_bytes());
        inode[148..156].copy_from_slice(&13_u64.to_le_bytes());
        let parsed = parse_inode_item(&inode).expect("parse inode item");
        assert_eq!(parsed.size, 4096);
        assert_eq!(parsed.mode, 0o040_755);
        assert_eq!(parsed.nlink, 2);
        assert_eq!(parsed.mtime_sec, 12);
    }

    #[test]
    fn parse_dir_items_smoke() {
        let name = b"hello.txt";
        let mut data = vec![0_u8; 30 + name.len()];
        data[0..8].copy_from_slice(&257_u64.to_le_bytes());
        data[8] = BTRFS_ITEM_INODE_ITEM;
        data[17..25].copy_from_slice(&1_u64.to_le_bytes()); // transid
        data[25..27].copy_from_slice(&0_u16.to_le_bytes()); // data_len
        let name_len = u16::try_from(name.len()).expect("test name length should fit u16");
        data[27..29].copy_from_slice(&name_len.to_le_bytes());
        data[29] = BTRFS_FT_REG_FILE;
        data[30..30 + name.len()].copy_from_slice(name);

        let parsed = parse_dir_items(&data).expect("parse dir items");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].child_objectid, 257);
        assert_eq!(parsed[0].file_type, BTRFS_FT_REG_FILE);
        assert_eq!(parsed[0].name, name);
    }

    #[test]
    fn parse_extent_data_regular_smoke() {
        let mut data = [0_u8; 53];
        data[20] = BTRFS_FILE_EXTENT_REG;
        data[21..29].copy_from_slice(&0x8_000_u64.to_le_bytes());
        data[29..37].copy_from_slice(&4096_u64.to_le_bytes());
        data[45..53].copy_from_slice(&128_u64.to_le_bytes());

        let parsed = parse_extent_data(&data).expect("parse extent");
        match parsed {
            BtrfsExtentData::Regular {
                extent_type,
                compression,
                disk_bytenr,
                num_bytes,
                ..
            } => {
                assert_eq!(extent_type, BTRFS_FILE_EXTENT_REG);
                assert_eq!(compression, 0);
                assert_eq!(disk_bytenr, 0x8_000);
                assert_eq!(num_bytes, 128);
            }
            BtrfsExtentData::Inline { .. } => panic!("expected regular extent"),
        }
    }
}
