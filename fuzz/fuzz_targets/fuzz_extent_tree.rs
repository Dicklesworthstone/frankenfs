#![no_main]
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, OnceLock};

use asupersync::Cx;
use ffs_alloc::{AllocHint, FsGeometry, GroupStats, PersistCtx};
use ffs_block::{BlockBuf, BlockDevice};
use ffs_error::{FfsError, Result};
use ffs_extent::{
    allocate_extent, allocate_unwritten_extent, collapse_range, insert_range,
    map_logical_to_physical, mark_written, punch_hole, truncate_extents, ExtentMapping,
    ExtentOwner,
};
use ffs_ondisk::{Ext4DxRoot, Ext4ExtentHeader, Ext4ExtentIndex, Ext4Inode, ExtentTree};
use ffs_types::{BlockNumber, GroupNumber, ParseError};
use libfuzzer_sys::fuzz_target;

const EXT4_EXTENT_MAGIC: u16 = 0xF30A;
const EXTENT_HEADER_BYTES: usize = 12;
const EXTENT_ENTRY_BYTES: usize = 12;
const EXTENT_ROOT_BYTES: usize = 60;
const INODE_BYTES: usize = 256;
const INODE_EXTENT_OFFSET: usize = 0x28;
const DX_ROOT_MIN_BYTES: usize = 0x28;
const DX_COUNTLIMIT_OFFSET: usize = 0x20;

const MAX_INPUT_BYTES: usize = 2048;
const MAX_OPS: usize = 96;
const LOW_LOGICAL_DOMAIN: u32 = 512;
const MAX_OP_COUNT: u32 = 16;

fuzz_target!(|data: &[u8]| {
    assert_extent_tree_parser_contracts(data);
    assert_inode_extent_tree_contracts(data);
    assert_dx_root_parser_contracts(data);
    assert_synthetic_ext4_parser_cases(data);

    fuzz_stateful_extent_edits(data);
});

#[derive(Debug, Clone, PartialEq, Eq)]
struct DxRootSig {
    hash_version: u8,
    indirect_levels: u8,
    entries: Vec<(u32, u32)>,
}

fn assert_extent_tree_parser_contracts(data: &[u8]) {
    let first = ffs_ondisk::parse_extent_tree(data);
    let second = ffs_ondisk::parse_extent_tree(data);
    assert_eq!(first, second, "extent tree parse must be deterministic");

    if data.len() < EXTENT_HEADER_BYTES {
        assert_eq!(
            first,
            Err(ParseError::InsufficientData {
                needed: EXTENT_HEADER_BYTES,
                offset: 0,
                actual: data.len(),
            }),
            "short extent tree input must report the header size"
        );
        return;
    }

    let magic = read_u16(data, 0);
    if magic != EXT4_EXTENT_MAGIC {
        assert_eq!(
            first,
            Err(ParseError::InvalidMagic {
                expected: u64::from(EXT4_EXTENT_MAGIC),
                actual: u64::from(magic),
            }),
            "extent tree must reject the header magic before entry parsing"
        );
        return;
    }

    if let Ok((header, tree)) = first {
        assert_extent_tree_shape(&header, &tree);
    }
}

fn assert_extent_tree_shape(header: &Ext4ExtentHeader, tree: &ExtentTree) {
    if header.magic != EXT4_EXTENT_MAGIC {
        invariant_failure("parsed extent header must preserve the ext4 magic".to_owned());
    }
    if header.entries > header.max_entries {
        invariant_failure("parsed extent header entries must not exceed max_entries".to_owned());
    }

    match tree {
        ExtentTree::Leaf(extents) => {
            if header.depth != 0 {
                invariant_failure("leaf extent tree must have depth zero".to_owned());
            }
            if extents.len() != usize::from(header.entries) {
                invariant_failure("leaf extent count must match eh_entries".to_owned());
            }
            let mut previous_end = 0_u64;
            let mut saw_previous = false;
            for extent in extents {
                let actual_len = extent.actual_len();
                if actual_len == 0 {
                    invariant_failure("leaf extents must have non-zero length".to_owned());
                }
                if saw_previous && u64::from(extent.logical_block) < previous_end {
                    invariant_failure(
                        "leaf extents must be ordered and non-overlapping".to_owned(),
                    );
                }
                previous_end = u64::from(extent.logical_block) + u64::from(actual_len);
                saw_previous = true;
            }
        }
        ExtentTree::Index(indexes) => {
            if header.depth == 0 {
                invariant_failure("index extent tree must have non-zero depth".to_owned());
            }
            if indexes.len() != usize::from(header.entries) {
                invariant_failure("index extent count must match eh_entries".to_owned());
            }
            let mut previous_logical = None;
            for index in indexes {
                if let Some(previous) = previous_logical {
                    if index.logical_block <= previous {
                        invariant_failure(
                            "index extents must be strictly ordered by logical block".to_owned(),
                        );
                    }
                }
                previous_logical = Some(index.logical_block);
            }
        }
    }
}

fn assert_inode_extent_tree_contracts(data: &[u8]) {
    if let Ok(inode) = Ext4Inode::parse_from_bytes(data) {
        assert_eq!(
            ffs_ondisk::parse_inode_extent_tree(&inode),
            ffs_ondisk::parse_extent_tree(&inode.extent_bytes),
            "inode extent parser must delegate to the raw i_block extent bytes"
        );
    }
}

fn assert_dx_root_parser_contracts(data: &[u8]) {
    let first = dx_root_sig(ffs_ondisk::parse_dx_root(data));
    let second = dx_root_sig(ffs_ondisk::parse_dx_root(data));
    assert_eq!(first, second, "dx root parse must be deterministic");

    if data.len() < DX_ROOT_MIN_BYTES {
        assert_eq!(
            first,
            Err(ParseError::InsufficientData {
                needed: DX_ROOT_MIN_BYTES,
                offset: 0,
                actual: data.len(),
            }),
            "short dx root input must report the minimum root size"
        );
        return;
    }

    let reserved_zero = read_u32(data, 0x18);
    if reserved_zero != 0 {
        assert_eq!(
            first,
            Err(ParseError::InvalidField {
                field: "dx_reserved_zero",
                reason: "expected 0",
            }),
            "dx root must reject non-zero reserved root info first"
        );
        return;
    }

    let info_length = data[0x1D];
    if info_length != 8 {
        assert_eq!(
            first,
            Err(ParseError::InvalidField {
                field: "dx_root_info_length",
                reason: "expected 8",
            }),
            "dx root must reject malformed root info length before entries"
        );
        return;
    }

    let indirect_levels = data[0x1E];
    if indirect_levels > 2 {
        assert_eq!(
            first,
            Err(ParseError::InvalidField {
                field: "dx_indirect_levels",
                reason: "exceeds maximum (2) without LARGEDIR",
            }),
            "plain dx root parsing must enforce the non-LARGEDIR depth limit"
        );
        return;
    }

    let unused_flags = data[0x1F];
    if unused_flags != 0 {
        assert_eq!(
            first,
            Err(ParseError::InvalidField {
                field: "dx_unused_flags",
                reason: "expected 0",
            }),
            "dx root must reject non-zero unused flags before entries"
        );
        return;
    }

    if let Ok(root) = first {
        assert_dx_root_shape(&root, data);
    }
}

fn assert_dx_root_shape(root: &DxRootSig, data: &[u8]) {
    if root.indirect_levels > 2 {
        invariant_failure("plain dx root parse must not accept level > 2".to_owned());
    }

    let count = usize::from(read_u16(data, DX_COUNTLIMIT_OFFSET + 2));
    if count == 0 {
        if !root.entries.is_empty() {
            invariant_failure("zero dx entry count must produce no entries".to_owned());
        }
        return;
    }

    if root.entries.is_empty() {
        invariant_failure("non-zero dx entry count must include the sentinel entry".to_owned());
    }
    if root.entries[0].0 != 0 {
        invariant_failure("first dx entry hash must be the implicit zero sentinel".to_owned());
    }
    if root.entries.len() > count {
        invariant_failure("dx parser must not emit more entries than dx_count".to_owned());
    }

    let available_following_entries = data.len().saturating_sub(DX_COUNTLIMIT_OFFSET + 8) / 8;
    if root.entries.len() > 1 + available_following_entries {
        invariant_failure("dx parser emitted entries beyond the available bytes".to_owned());
    }
}

fn assert_synthetic_ext4_parser_cases(data: &[u8]) {
    let leaf = synthetic_leaf_extent_root(data);
    let (leaf_header, leaf_tree) =
        ffs_ondisk::parse_extent_tree(&leaf).expect("synthetic leaf root must parse");
    assert_extent_tree_shape(&leaf_header, &leaf_tree);
    assert_inode_wrapper_matches_raw_extent_root(&leaf);

    let mut leaf_with_tail = leaf;
    leaf_with_tail.extend_from_slice(&[0xA5, 0x5A, seed_u8(data, 40)]);
    let reparsed_leaf = ffs_ondisk::parse_extent_tree(&leaf_with_tail)
        .expect("synthetic leaf root with tail must parse");
    assert_eq!(
        (leaf_header, leaf_tree),
        reparsed_leaf,
        "extent parser must ignore bytes beyond eh_entries"
    );

    let index_root = synthetic_index_extent_root(data);
    let (index_header, index_tree) =
        ffs_ondisk::parse_extent_tree(&index_root).expect("synthetic index root must parse");
    assert_extent_tree_shape(&index_header, &index_tree);
    assert_inode_wrapper_matches_raw_extent_root(&index_root);

    assert_extent_parser_rejects(
        zero_length_leaf_root(),
        ParseError::InvalidField {
            field: "extent_entries.ee_len",
            reason: "extent length must be non-zero",
        },
    );
    assert_extent_parser_rejects(
        overlapping_leaf_root(),
        ParseError::InvalidField {
            field: "extent_entries",
            reason: "extents not sorted by logical_block or overlap",
        },
    );
    assert_extent_parser_rejects(
        duplicate_index_root(),
        ParseError::InvalidField {
            field: "extent_indexes",
            reason: "index entries not strictly sorted by logical_block",
        },
    );
    assert_extent_parser_rejects(
        entries_exceed_max_root(),
        ParseError::InvalidField {
            field: "eh_entries",
            reason: "entries exceed max",
        },
    );
    assert_extent_parser_rejects(
        truncated_extent_root(),
        ParseError::InsufficientData {
            needed: EXTENT_HEADER_BYTES + EXTENT_ENTRY_BYTES,
            offset: EXTENT_HEADER_BYTES,
            actual: 0,
        },
    );

    let dx_root = synthetic_dx_root(data);
    let parsed_dx_root =
        dx_root_sig(ffs_ondisk::parse_dx_root(&dx_root)).expect("synthetic dx root must parse");
    assert_dx_root_shape(&parsed_dx_root, &dx_root);
    assert_dx_parser_rejects(
        nonzero_reserved_dx_root(),
        ParseError::InvalidField {
            field: "dx_reserved_zero",
            reason: "expected 0",
        },
    );
    assert_dx_parser_rejects(
        invalid_info_len_dx_root(),
        ParseError::InvalidField {
            field: "dx_root_info_length",
            reason: "expected 8",
        },
    );
    assert_dx_parser_rejects(
        level_three_dx_root(),
        ParseError::InvalidField {
            field: "dx_indirect_levels",
            reason: "exceeds maximum (2) without LARGEDIR",
        },
    );
    assert_dx_parser_rejects(
        nonzero_flags_dx_root(),
        ParseError::InvalidField {
            field: "dx_unused_flags",
            reason: "expected 0",
        },
    );
    assert_dx_parser_rejects(
        count_exceeds_limit_dx_root(),
        ParseError::InvalidField {
            field: "dx_count",
            reason: "count exceeds limit",
        },
    );
}

fn assert_inode_wrapper_matches_raw_extent_root(root: &[u8]) {
    let mut inode_bytes = [0_u8; INODE_BYTES];
    inode_bytes[INODE_EXTENT_OFFSET..INODE_EXTENT_OFFSET + EXTENT_ROOT_BYTES]
        .copy_from_slice(&root[..EXTENT_ROOT_BYTES]);
    let inode = Ext4Inode::parse_from_bytes(&inode_bytes).expect("synthetic inode must parse");
    assert_eq!(
        ffs_ondisk::parse_inode_extent_tree(&inode),
        ffs_ondisk::parse_extent_tree(&root[..EXTENT_ROOT_BYTES]),
        "inode extent parser must preserve synthetic i_block bytes"
    );
}

fn assert_extent_parser_rejects(bytes: Vec<u8>, expected: ParseError) {
    let actual = ffs_ondisk::parse_extent_tree(&bytes).expect_err("extent root must reject");
    assert_eq!(actual, expected);
}

fn assert_dx_parser_rejects(bytes: Vec<u8>, expected: ParseError) {
    let actual = ffs_ondisk::parse_dx_root(&bytes).expect_err("dx root must reject");
    assert_eq!(actual, expected);
}

fn dx_root_sig(
    result: std::result::Result<Ext4DxRoot, ParseError>,
) -> std::result::Result<DxRootSig, ParseError> {
    result.map(|root| DxRootSig {
        hash_version: root.hash_version,
        indirect_levels: root.indirect_levels,
        entries: root
            .entries
            .into_iter()
            .map(|entry| (entry.hash, entry.block))
            .collect(),
    })
}

fn synthetic_leaf_extent_root(data: &[u8]) -> Vec<u8> {
    let first_len = u16::from(seed_u8(data, 0) % 16) + 1;
    let second_len = u16::from(seed_u8(data, 1) % 16) + 1;
    let first_logical = seed_u32(data, 2) % 128;
    let second_logical = first_logical + u32::from(first_len) + u32::from(seed_u8(data, 6) % 8);
    let first_physical = bounded_physical(seed_u64(data, 8)).max(1);
    let second_physical = bounded_physical(seed_u64(data, 16)).max(first_physical + 1);

    let mut bytes = extent_root_header(2, 4, 0, seed_u32(data, 24));
    write_extent_entry(&mut bytes, 0, first_logical, first_len, first_physical);
    write_extent_entry(
        &mut bytes,
        1,
        second_logical,
        ffs_ondisk::EXT_INIT_MAX_LEN | second_len,
        second_physical,
    );
    bytes.resize(EXTENT_ROOT_BYTES, 0);
    bytes
}

fn synthetic_index_extent_root(data: &[u8]) -> Vec<u8> {
    let first_logical = seed_u32(data, 28) % 128;
    let second_logical = first_logical + u32::from(seed_u8(data, 32) % 8) + 1;
    let first_leaf = bounded_physical(seed_u64(data, 33)).max(1);
    let second_leaf = bounded_physical(seed_u64(data, 41)).max(first_leaf + 1);

    let mut bytes = extent_root_header(2, 4, 1, seed_u32(data, 49));
    write_extent_index(&mut bytes, 0, first_logical, first_leaf);
    write_extent_index(&mut bytes, 1, second_logical, second_leaf);
    bytes.resize(EXTENT_ROOT_BYTES, 0);
    bytes
}

fn zero_length_leaf_root() -> Vec<u8> {
    let mut bytes = extent_root_header(1, 1, 0, 0);
    write_extent_entry(&mut bytes, 0, 7, 0, 42);
    bytes
}

fn overlapping_leaf_root() -> Vec<u8> {
    let mut bytes = extent_root_header(2, 2, 0, 0);
    write_extent_entry(&mut bytes, 0, 10, 4, 100);
    write_extent_entry(&mut bytes, 1, 13, 2, 200);
    bytes
}

fn duplicate_index_root() -> Vec<u8> {
    let mut bytes = extent_root_header(2, 2, 1, 0);
    write_extent_index(&mut bytes, 0, 5, 100);
    write_extent_index(&mut bytes, 1, 5, 200);
    bytes
}

fn entries_exceed_max_root() -> Vec<u8> {
    extent_root_header(2, 1, 0, 0)
}

fn truncated_extent_root() -> Vec<u8> {
    extent_root_header(1, 1, 0, 0)
        .into_iter()
        .take(EXTENT_HEADER_BYTES)
        .collect()
}

fn extent_root_header(entries: u16, max_entries: u16, depth: u16, generation: u32) -> Vec<u8> {
    let mut bytes = vec![0_u8; EXTENT_HEADER_BYTES + usize::from(entries) * EXTENT_ENTRY_BYTES];
    write_u16(&mut bytes, 0, EXT4_EXTENT_MAGIC);
    write_u16(&mut bytes, 2, entries);
    write_u16(&mut bytes, 4, max_entries);
    write_u16(&mut bytes, 6, depth);
    write_u32(&mut bytes, 8, generation);
    bytes
}

fn write_extent_entry(
    bytes: &mut [u8],
    entry_index: usize,
    logical_block: u32,
    raw_len: u16,
    physical_start: u64,
) {
    let base = EXTENT_HEADER_BYTES + entry_index * EXTENT_ENTRY_BYTES;
    let physical_start = bounded_physical(physical_start);
    write_u32(bytes, base, logical_block);
    write_u16(bytes, base + 4, raw_len);
    write_u16(bytes, base + 6, (physical_start >> 32) as u16);
    write_u32(bytes, base + 8, physical_start as u32);
}

fn write_extent_index(bytes: &mut [u8], entry_index: usize, logical_block: u32, leaf_block: u64) {
    let index = Ext4ExtentIndex {
        logical_block,
        leaf_block: bounded_physical(leaf_block),
    };
    let base = EXTENT_HEADER_BYTES + entry_index * EXTENT_ENTRY_BYTES;
    write_u32(bytes, base, index.logical_block);
    write_u32(bytes, base + 4, index.leaf_block as u32);
    write_u16(bytes, base + 8, (index.leaf_block >> 32) as u16);
}

fn synthetic_dx_root(data: &[u8]) -> Vec<u8> {
    let mut bytes = dx_root_header(3, 3);
    bytes[0x1C] = seed_u8(data, 57);
    bytes[0x1D] = 8;
    bytes[0x1E] = seed_u8(data, 58) % 3;
    bytes[0x1F] = 0;
    write_u32(&mut bytes, 0x24, (seed_u32(data, 59) % 1024) + 1);
    write_u32(&mut bytes, 0x28, 0x1000);
    write_u32(&mut bytes, 0x2C, (seed_u32(data, 63) % 1024) + 2);
    write_u32(&mut bytes, 0x30, 0x8000);
    write_u32(&mut bytes, 0x34, (seed_u32(data, 67) % 1024) + 3);
    bytes
}

fn nonzero_reserved_dx_root() -> Vec<u8> {
    let mut bytes = dx_root_header(1, 1);
    write_u32(&mut bytes, 0x18, 1);
    bytes
}

fn invalid_info_len_dx_root() -> Vec<u8> {
    let mut bytes = dx_root_header(1, 1);
    bytes[0x1D] = 7;
    bytes
}

fn level_three_dx_root() -> Vec<u8> {
    let mut bytes = dx_root_header(1, 1);
    bytes[0x1E] = 3;
    bytes
}

fn nonzero_flags_dx_root() -> Vec<u8> {
    let mut bytes = dx_root_header(1, 1);
    bytes[0x1F] = 1;
    bytes
}

fn count_exceeds_limit_dx_root() -> Vec<u8> {
    dx_root_header(2, 1)
}

fn dx_root_header(count: u16, limit: u16) -> Vec<u8> {
    let mut bytes = vec![0_u8; DX_ROOT_MIN_BYTES + usize::from(count.saturating_sub(1)) * 8];
    bytes[0x1D] = 8;
    write_u16(&mut bytes, DX_COUNTLIMIT_OFFSET, limit);
    write_u16(&mut bytes, DX_COUNTLIMIT_OFFSET + 2, count);
    bytes
}

fn seed_u8(data: &[u8], offset: usize) -> u8 {
    data.get(offset).copied().unwrap_or(0)
}

fn seed_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        seed_u8(data, offset),
        seed_u8(data, offset + 1),
        seed_u8(data, offset + 2),
        seed_u8(data, offset + 3),
    ])
}

fn seed_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        seed_u8(data, offset),
        seed_u8(data, offset + 1),
        seed_u8(data, offset + 2),
        seed_u8(data, offset + 3),
        seed_u8(data, offset + 4),
        seed_u8(data, offset + 5),
        seed_u8(data, offset + 6),
        seed_u8(data, offset + 7),
    ])
}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn bounded_physical(value: u64) -> u64 {
    value & 0x0000_FFFF_FFFF_FFFF
}

struct ByteCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn next_u8(&mut self) -> u8 {
        let b = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.saturating_add(1);
        b
    }

    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes([
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
        ])
    }
}

struct MemBlockDevice {
    block_size: u32,
    block_count: u64,
    blocks: Mutex<HashMap<u64, Vec<u8>>>,
}

impl MemBlockDevice {
    fn new(block_size: u32, block_count: u64) -> Self {
        Self {
            block_size,
            block_count,
            blocks: Mutex::new(HashMap::new()),
        }
    }

    fn lock_blocks(&self) -> MutexGuard<'_, HashMap<u64, Vec<u8>>> {
        match self.blocks.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn block_len(&self) -> Result<usize> {
        usize::try_from(self.block_size)
            .map_err(|_| FfsError::InvalidGeometry("block size does not fit usize".to_owned()))
    }
}

impl BlockDevice for MemBlockDevice {
    fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        if block.0 >= self.block_count {
            return Err(FfsError::InvalidGeometry(format!(
                "read block {} beyond device block count {}",
                block.0, self.block_count
            )));
        }
        let blocks = self.lock_blocks();
        blocks.get(&block.0).map_or_else(
            || Ok(BlockBuf::new(vec![0u8; self.block_len()?])),
            |data| Ok(BlockBuf::new(data.clone())),
        )
    }

    fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
        if block.0 >= self.block_count {
            return Err(FfsError::InvalidGeometry(format!(
                "write block {} beyond device block count {}",
                block.0, self.block_count
            )));
        }
        let block_len = self.block_len()?;
        if data.len() != block_len {
            return Err(FfsError::Format(format!(
                "write_block length mismatch: got {}, expected {block_len}",
                data.len()
            )));
        }
        self.lock_blocks().insert(block.0, data.to_vec());
        Ok(())
    }

    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn block_count(&self) -> u64 {
        self.block_count
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        Ok(())
    }
}

fn fuzz_stateful_extent_edits(data: &[u8]) {
    if data.len() < 8 || data.len() > MAX_INPUT_BYTES {
        return;
    }

    let cx = Cx::for_testing();
    let dev = MemBlockDevice::new(4096, 1_000_000);
    let geo = make_geometry();
    let mut groups = make_groups(&geo);
    let pctx = make_pctx(&geo);
    let mut root = empty_root();
    let mut cursor = ByteCursor::new(data);
    let mut interesting_ranges = Vec::new();

    assert_failed_insert_preserves_boundary_tail(&cx, &dev, &geo, &mut groups, &pctx);

    let op_limit = usize::from(cursor.next_u8() % (MAX_OPS as u8));
    for _ in 0..op_limit {
        let op = cursor.next_u8() % 8;
        let count = next_count(&mut cursor);
        let logical_start = next_logical_start(&mut cursor, count);

        match op {
            0 => {
                if range_is_sparse(&cx, &dev, &root, logical_start, count) {
                    let _ = allocate_extent(
                        &cx,
                        &dev,
                        &mut root,
                        &geo,
                        &mut groups,
                        logical_start,
                        count,
                        &AllocHint::default(),
                        &pctx,
                        ExtentOwner::default(),
                    );
                    interesting_ranges.push((logical_start, count));
                }
            }
            1 => {
                if range_is_sparse(&cx, &dev, &root, logical_start, count) {
                    let _ = allocate_unwritten_extent(
                        &cx,
                        &dev,
                        &mut root,
                        &geo,
                        &mut groups,
                        logical_start,
                        count,
                        &AllocHint::default(),
                        &pctx,
                        ExtentOwner::default(),
                    );
                    interesting_ranges.push((logical_start, count));
                }
            }
            2 => {
                let _ = punch_hole(
                    &cx,
                    &dev,
                    &mut root,
                    &geo,
                    &mut groups,
                    logical_start,
                    u64::from(count),
                    &pctx,
                    ExtentOwner::default(),
                );
            }
            3 => {
                let _ = collapse_range(
                    &cx,
                    &dev,
                    &mut root,
                    &geo,
                    &mut groups,
                    logical_start,
                    count,
                    &pctx,
                    ExtentOwner::default(),
                );
            }
            4 => {
                let _ = insert_range(
                    &cx,
                    &dev,
                    &mut root,
                    &geo,
                    &mut groups,
                    logical_start,
                    count,
                    &pctx,
                    ExtentOwner::default(),
                );
            }
            5 => {
                let _ = mark_written(
                    &cx,
                    &dev,
                    &mut root,
                    &geo,
                    &mut groups,
                    logical_start,
                    count,
                    &pctx,
                    ExtentOwner::default(),
                );
            }
            6 => {
                // bd-dqsb1 — truncate_extents shrinks the tree by
                // removing all mappings beyond new_logical_end and
                // freeing the underlying physical blocks. Use the
                // fuzz `logical_start` as the new end-of-file boundary.
                let _ = truncate_extents(
                    &cx,
                    &dev,
                    &mut root,
                    &geo,
                    &mut groups,
                    logical_start,
                    &pctx,
                    ExtentOwner::default(),
                );
                // Drop any interesting_ranges that now lie beyond
                // the truncation boundary so post-op asserts don't
                // probe a removed region.
                interesting_ranges.retain(|&(start, _)| start < logical_start);
            }
            _ => assert_covering_mappings(&cx, &dev, &root, logical_start, u64::from(count)),
        }

        assert_covering_mappings(&cx, &dev, &root, logical_start, u64::from(count));
        if let Some(&(probe_start, probe_count)) = interesting_ranges.last() {
            assert_covering_mappings(&cx, &dev, &root, probe_start, u64::from(probe_count));
        }
        if interesting_ranges.len() > 32 {
            interesting_ranges.remove(0);
        }
    }
}

fn assert_failed_insert_preserves_boundary_tail(
    cx: &Cx,
    dev: &dyn BlockDevice,
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    pctx: &PersistCtx,
) {
    let mut root = empty_root();
    let logical_start = u32::MAX;
    let mapping = allocate_extent(
        cx,
        dev,
        &mut root,
        geo,
        groups,
        logical_start,
        1,
        &AllocHint::default(),
        pctx,
        ExtentOwner::default(),
    );
    if mapping.is_err() {
        return;
    }

    let before = match map_logical_to_physical(cx, dev, &root, logical_start, 1) {
        Ok(mappings) => mappings,
        Err(err) => invariant_failure(format!(
            "boundary tail mapping must be readable before insert_range: {err}"
        )),
    };
    assert_physical_mapping(&before, logical_start, 1);

    let result = insert_range(
        cx,
        dev,
        &mut root,
        geo,
        groups,
        0,
        1,
        pctx,
        ExtentOwner::default(),
    );
    if result.is_ok() {
        invariant_failure(
            "insert_range must reject shifting the final logical block beyond ext4 space"
                .to_owned(),
        );
    }

    let after = match map_logical_to_physical(cx, dev, &root, logical_start, 1) {
        Ok(mappings) => mappings,
        Err(err) => invariant_failure(format!(
            "failed insert_range must leave boundary tail readable: {err}"
        )),
    };
    if before != after {
        invariant_failure(
            "failed insert_range must not mutate the boundary tail mapping".to_owned(),
        );
    }
}

fn range_is_sparse(
    cx: &Cx,
    dev: &dyn BlockDevice,
    root: &[u8; 60],
    logical_start: u32,
    count: u32,
) -> bool {
    map_logical_to_physical(cx, dev, root, logical_start, u64::from(count))
        .map(|mappings| mappings.iter().all(|mapping| mapping.physical_start == 0))
        .unwrap_or(false)
}

fn assert_covering_mappings(
    cx: &Cx,
    dev: &dyn BlockDevice,
    root: &[u8; 60],
    logical_start: u32,
    count: u64,
) {
    let mappings = match map_logical_to_physical(cx, dev, root, logical_start, count) {
        Ok(mappings) => mappings,
        Err(err) => invariant_failure(format!(
            "extent tree must remain mappable after stateful op: {err}"
        )),
    };
    let mut expected_start = u64::from(logical_start);
    let expected_end = expected_start + count;
    for mapping in mappings {
        if u64::from(mapping.logical_start) != expected_start {
            invariant_failure("mappings must be contiguous and ordered".to_owned());
        }
        if mapping.count == 0 {
            invariant_failure("mapping count must be positive".to_owned());
        }
        let mapping_end = u64::from(mapping.logical_start) + u64::from(mapping.count);
        if mapping_end > expected_end {
            invariant_failure(format!(
                "mapping end {mapping_end} must not exceed requested end {expected_end}"
            ));
        }
        if mapping.physical_start != 0 {
            assert_physical_mapping(&[mapping], mapping.logical_start, mapping.count);
        }
        expected_start = mapping_end;
    }
    if expected_start != expected_end {
        invariant_failure("mappings must cover the full requested range".to_owned());
    }
}

fn assert_physical_mapping(mappings: &[ExtentMapping], logical_start: u32, count: u32) {
    if !mappings.iter().any(|mapping| {
        mapping.logical_start == logical_start
            && mapping.count == count
            && mapping.physical_start != 0
    }) {
        invariant_failure(format!(
            "expected physical mapping at logical range [{logical_start}, {})",
            u64::from(logical_start) + u64::from(count)
        ));
    }
}

fn next_count(cursor: &mut ByteCursor<'_>) -> u32 {
    u32::from(cursor.next_u8() % (MAX_OP_COUNT as u8)).saturating_add(1)
}

fn next_logical_start(cursor: &mut ByteCursor<'_>, count: u32) -> u32 {
    let raw = cursor.next_u32();
    let max_start = u64::from(u32::MAX) + 1 - u64::from(count);
    let candidate = match cursor.next_u8() % 4 {
        0 => u64::from(raw % LOW_LOGICAL_DOMAIN),
        1 => max_start.saturating_sub(u64::from(raw % 64)),
        2 => u64::from(LOW_LOGICAL_DOMAIN) + u64::from(raw % 4096),
        _ => u64::from(raw).min(max_start),
    };
    u32::try_from(candidate.min(max_start)).unwrap_or(u32::MAX)
}

fn invariant_failure(message: String) -> ! {
    std::panic::panic_any(message);
}

fn empty_root() -> [u8; 60] {
    let mut root = [0u8; 60];
    root[0] = 0x0A;
    root[1] = 0xF3;
    root[4] = 4;
    root
}

fn make_geometry() -> FsGeometry {
    FsGeometry {
        blocks_per_group: 8192,
        inodes_per_group: 2048,
        block_size: 4096,
        total_blocks: 32768,
        total_inodes: 8192,
        first_data_block: 0,
        group_count: 4,
        inode_size: 256,
        desc_size: 32,
        reserved_gdt_blocks: 0,
        first_meta_bg: 0,
        feature_compat: ffs_ondisk::Ext4CompatFeatures(0),
        feature_incompat: ffs_ondisk::Ext4IncompatFeatures(0),
        feature_ro_compat: ffs_ondisk::Ext4RoCompatFeatures(0),
        log_groups_per_flex: 0,
        backup_bgs: [0, 0],
        first_inode: 11,
        cluster_ratio: 1,
    }
}

fn make_groups(geo: &FsGeometry) -> Vec<GroupStats> {
    (0..geo.group_count)
        .map(|g| GroupStats {
            group: GroupNumber(g),
            free_blocks: geo.blocks_per_group,
            block_largest_free_run: None,
            free_inodes: geo.inodes_per_group,
            inode_search_start: 0,
            used_dirs: 0,
            block_bitmap_block: BlockNumber(u64::from(g) * 100 + 1),
            inode_bitmap_block: BlockNumber(u64::from(g) * 100 + 2),
            inode_table_block: BlockNumber(u64::from(g) * 100 + 3),
            flags: 0,
            block_bitmap_csum: 0,
            inode_bitmap_csum: 0,
            reserved_cache: OnceLock::new(),
            reserved_confirmed: OnceLock::new(),
        })
        .collect()
}

fn make_pctx(geo: &FsGeometry) -> PersistCtx {
    PersistCtx {
        gdt_block: BlockNumber(50),
        gdt_blocks: None,
        desc_size: geo.desc_size,
        has_metadata_csum: false,
        csum_seed: 0,
        uuid: [0; 16],
        group_desc_checksum_kind: ffs_ondisk::ext4::Ext4GroupDescChecksumKind::None,
        blocks_per_group: geo.blocks_per_group,
        inodes_per_group: geo.inodes_per_group,
    }
}
