#![forbid(unsafe_code)]
//! Higher-level btrfs operations: tree traversal, item enumeration.
//!
//! Builds on `ffs_ondisk::btrfs` parsing primitives. I/O-agnostic —
//! callers provide a read callback for physical byte access.

pub use ffs_ondisk::btrfs::*;
use ffs_types::ParseError;

/// A single leaf item yielded by tree traversal: key + raw payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtrfsLeafEntry {
    pub key: BtrfsKey,
    pub data: Vec<u8>,
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
    walk_node(read_physical, chunks, root_logical, nodesize, &mut results)?;
    Ok(results)
}

fn walk_node(
    read_physical: &mut dyn FnMut(u64) -> Result<Vec<u8>, ParseError>,
    chunks: &[BtrfsChunkEntry],
    logical: u64,
    nodesize: u32,
    out: &mut Vec<BtrfsLeafEntry>,
) -> Result<(), ParseError> {
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
            walk_node(read_physical, chunks, kp.blockptr, nodesize, out)?;
        }
    }

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
}
