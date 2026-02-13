#![forbid(unsafe_code)]
//! Higher-level btrfs operations: tree traversal, item enumeration.
//!
//! Builds on `ffs_ondisk::btrfs` parsing primitives. I/O-agnostic —
//! callers provide a read callback for physical byte access.

pub use ffs_ondisk::btrfs::*;
use ffs_types::ParseError;
use std::collections::HashSet;

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
    Inline {
        data: Vec<u8>,
    },
    /// Regular or preallocated extent that references on-disk bytes.
    ///
    /// `disk_bytenr` is a logical bytenr in btrfs address space.
    Regular {
        extent_type: u8,
        disk_bytenr: u64,
        disk_num_bytes: u64,
        extent_offset: u64,
        num_bytes: u64,
    },
}

fn read_exact<const N: usize>(data: &[u8], off: usize, field: &'static str) -> Result<[u8; N], ParseError> {
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

    let extent_type = data[20];
    match extent_type {
        BTRFS_FILE_EXTENT_INLINE => Ok(BtrfsExtentData::Inline {
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

#[cfg(test)]
mod tests {
    use super::*;
    use ffs_ondisk::BtrfsStripe;
    use std::collections::HashMap;

    const NODESIZE: u32 = 4096;
    const HEADER_SIZE: usize = 101;
    const ITEM_SIZE: usize = 25;
    const KEY_PTR_SIZE: usize = 33;

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
        inode[52..56].copy_from_slice(&0o040755_u32.to_le_bytes());
        inode[112..120].copy_from_slice(&10_u64.to_le_bytes());
        inode[124..132].copy_from_slice(&11_u64.to_le_bytes());
        inode[136..144].copy_from_slice(&12_u64.to_le_bytes());
        inode[148..156].copy_from_slice(&13_u64.to_le_bytes());
        let parsed = parse_inode_item(&inode).expect("parse inode item");
        assert_eq!(parsed.size, 4096);
        assert_eq!(parsed.mode, 0o040755);
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
        data[27..29].copy_from_slice(&(name.len() as u16).to_le_bytes());
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
                disk_bytenr,
                num_bytes,
                ..
            } => {
                assert_eq!(extent_type, BTRFS_FILE_EXTENT_REG);
                assert_eq!(disk_bytenr, 0x8_000);
                assert_eq!(num_bytes, 128);
            }
            BtrfsExtentData::Inline { .. } => panic!("expected regular extent"),
        }
    }
}
