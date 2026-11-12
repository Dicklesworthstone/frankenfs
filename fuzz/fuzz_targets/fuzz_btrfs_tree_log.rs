#![no_main]

use ffs_btrfs::{
    replay_tree_log, BtrfsChunkEntry, BtrfsKey, BtrfsLeafEntry, BtrfsStripe, BtrfsSuperblock,
    TreeLogReplayResult, BTRFS_ITEM_DIR_ITEM, BTRFS_ITEM_EXTENT_DATA, BTRFS_ITEM_INODE_ITEM,
    BTRFS_ITEM_XATTR_ITEM,
};
use ffs_types::{crc32c, ParseError, BTRFS_CSUM_TYPE_CRC32C};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

const NODESIZE: usize = 4096;
const HEADER_SIZE: usize = 101;
const ITEM_SIZE: usize = 25;
const KEY_PTR_SIZE: usize = 33;
const ROOT_LOGICAL: u64 = 0x10_000;
const LEFT_LOGICAL: u64 = 0x20_000;
const RIGHT_LOGICAL: u64 = 0x30_000;
const OWNER: u64 = 5;
const GENERATION: u64 = 77;
const PHYSICAL_SHIFT: u64 = 0x80_000;
const MAX_INPUT_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Topology {
    Absent,
    SingleLeaf,
    InternalTwoLeaf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CorruptionMode {
    None,
    BadChecksum,
    Structural,
    UncoveredRoot,
    UnsupportedChecksum,
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
        let byte = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.saturating_add(1);
        byte
    }

    fn take_vec(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_u8()).collect()
    }
}

struct TreeImage {
    superblock: BtrfsSuperblock,
    identity_chunks: Vec<BtrfsChunkEntry>,
    shifted_chunks: Vec<BtrfsChunkEntry>,
    identity_blocks: BTreeMap<u64, Vec<u8>>,
    shifted_blocks: BTreeMap<u64, Vec<u8>>,
    expected_items: Vec<BtrfsLeafEntry>,
    topology: Topology,
    corruption: CorruptionMode,
}

fn build_superblock(log_root: u64, log_root_level: u8, csum_type: u16) -> BtrfsSuperblock {
    BtrfsSuperblock {
        csum: [0; 32],
        fsid: [0; 16],
        bytenr: 0,
        flags: 0,
        magic: 0,
        generation: GENERATION,
        root: 0,
        chunk_root: 0,
        chunk_root_generation: GENERATION,
        log_root,
        total_bytes: 0,
        bytes_used: 0,
        root_dir_objectid: 0,
        num_devices: 1,
        sectorsize: u32::try_from(NODESIZE).expect("nodesize fits in u32"),
        nodesize: u32::try_from(NODESIZE).expect("nodesize fits in u32"),
        stripesize: 0,
        compat_flags: 0,
        compat_ro_flags: 0,
        incompat_flags: 0,
        csum_type,
        root_level: 0,
        chunk_root_level: 0,
        log_root_level,
        label: String::new(),
        sys_chunk_array_size: 0,
        sys_chunk_array: Vec::new(),
    }
}

fn build_single_stripe_chunk(
    logical_start: u64,
    length: u64,
    physical_start: u64,
) -> BtrfsChunkEntry {
    BtrfsChunkEntry {
        key: BtrfsKey {
            objectid: 256,
            item_type: 228,
            offset: logical_start,
        },
        length,
        owner: 2,
        stripe_len: u64::try_from(NODESIZE).expect("nodesize fits in u64"),
        chunk_type: 1,
        io_align: u32::try_from(NODESIZE).expect("nodesize fits in u32"),
        io_width: u32::try_from(NODESIZE).expect("nodesize fits in u32"),
        sector_size: u32::try_from(NODESIZE).expect("nodesize fits in u32"),
        num_stripes: 1,
        sub_stripes: 0,
        stripes: vec![BtrfsStripe {
            devid: 1,
            offset: physical_start,
            dev_uuid: [0; 16],
        }],
    }
}

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

fn write_leaf_item(block: &mut [u8], idx: usize, key: &BtrfsKey, data_off: u32, data_size: u32) {
    let base = HEADER_SIZE + idx * ITEM_SIZE;
    let header_size = u32::try_from(HEADER_SIZE).expect("header size fits in u32");
    let encoded_data_off = data_off
        .checked_sub(header_size)
        .expect("payload should live after the header");
    block[base..base + 8].copy_from_slice(&key.objectid.to_le_bytes());
    block[base + 8] = key.item_type;
    block[base + 9..base + 17].copy_from_slice(&key.offset.to_le_bytes());
    block[base + 17..base + 21].copy_from_slice(&encoded_data_off.to_le_bytes());
    block[base + 21..base + 25].copy_from_slice(&data_size.to_le_bytes());
}

fn write_key_ptr(block: &mut [u8], idx: usize, key: &BtrfsKey, blockptr: u64, generation: u64) {
    let base = HEADER_SIZE + idx * KEY_PTR_SIZE;
    block[base..base + 8].copy_from_slice(&key.objectid.to_le_bytes());
    block[base + 8] = key.item_type;
    block[base + 9..base + 17].copy_from_slice(&key.offset.to_le_bytes());
    block[base + 17..base + 25].copy_from_slice(&blockptr.to_le_bytes());
    block[base + 25..base + 33].copy_from_slice(&generation.to_le_bytes());
}

fn stamp_tree_block_checksum(block: &mut [u8]) {
    block[..0x20].fill(0);
    let checksum = crc32c(&block[0x20..]);
    block[..4].copy_from_slice(&checksum.to_le_bytes());
}

fn key_order_tuple(key: &BtrfsKey) -> (u64, u8, u64) {
    (key.objectid, key.item_type, key.offset)
}

fn fallback_key(base_objectid: u64) -> BtrfsKey {
    BtrfsKey {
        objectid: base_objectid,
        item_type: BTRFS_ITEM_INODE_ITEM,
        offset: 0,
    }
}

fn build_leaf_entries(
    cursor: &mut ByteCursor<'_>,
    count: usize,
    base_objectid: u64,
) -> Vec<BtrfsLeafEntry> {
    let mut entries = Vec::with_capacity(count);
    for idx in 0..count {
        let item_type = match cursor.next_u8() % 4 {
            0 => BTRFS_ITEM_INODE_ITEM,
            1 => BTRFS_ITEM_DIR_ITEM,
            2 => BTRFS_ITEM_EXTENT_DATA,
            _ => BTRFS_ITEM_XATTR_ITEM,
        };
        let key = BtrfsKey {
            objectid: base_objectid
                + u64::try_from(idx).expect("index fits in u64") * 17
                + u64::from(cursor.next_u8()),
            item_type,
            offset: (u64::try_from(idx).expect("index fits in u64") << 16)
                | u64::from(cursor.next_u8())
                | (u64::from(cursor.next_u8()) << 8),
        };
        let payload_len = usize::from(cursor.next_u8() % 48);
        entries.push(BtrfsLeafEntry {
            key,
            data: cursor.take_vec(payload_len),
        });
    }
    entries.sort_by_key(|entry| key_order_tuple(&entry.key));
    entries
}

fn build_leaf_block(
    logical: u64,
    owner: u64,
    generation: u64,
    entries: &[BtrfsLeafEntry],
) -> Vec<u8> {
    let mut block = vec![0_u8; NODESIZE];
    write_header(
        &mut block,
        logical,
        u32::try_from(entries.len()).expect("entry count fits in u32"),
        0,
        owner,
        generation,
    );
    let mut data_end = NODESIZE;
    for (idx, entry) in entries.iter().enumerate() {
        data_end = data_end.saturating_sub(entry.data.len());
        if !entry.data.is_empty() {
            block[data_end..data_end + entry.data.len()].copy_from_slice(&entry.data);
        }
        write_leaf_item(
            &mut block,
            idx,
            &entry.key,
            u32::try_from(data_end).expect("payload offset fits in u32"),
            u32::try_from(entry.data.len()).expect("payload length fits in u32"),
        );
    }
    stamp_tree_block_checksum(&mut block);
    block
}

fn build_internal_block(
    logical: u64,
    owner: u64,
    generation: u64,
    ptrs: &[(BtrfsKey, u64)],
) -> Vec<u8> {
    let mut block = vec![0_u8; NODESIZE];
    write_header(
        &mut block,
        logical,
        u32::try_from(ptrs.len()).expect("pointer count fits in u32"),
        1,
        owner,
        generation,
    );
    for (idx, (key, blockptr)) in ptrs.iter().enumerate() {
        write_key_ptr(&mut block, idx, key, *blockptr, generation);
    }
    stamp_tree_block_checksum(&mut block);
    block
}

fn build_tree_image(data: &[u8]) -> TreeImage {
    let mut cursor = ByteCursor::new(data);
    let topology = match cursor.next_u8() % 3 {
        0 => Topology::Absent,
        1 => Topology::SingleLeaf,
        _ => Topology::InternalTwoLeaf,
    };
    let corruption = match cursor.next_u8() % 8 {
        0..=4 => CorruptionMode::None,
        5 => CorruptionMode::BadChecksum,
        6 => CorruptionMode::Structural,
        7 => CorruptionMode::UncoveredRoot,
        _ => CorruptionMode::UnsupportedChecksum,
    };
    let corruption = if cursor.next_u8() == u8::MAX {
        CorruptionMode::UnsupportedChecksum
    } else {
        corruption
    };

    let mut logical_blocks = BTreeMap::new();
    let mut expected_items = Vec::new();
    let mut log_root = 0_u64;
    let mut log_root_level = 0_u8;
    let max_logical = match topology {
        Topology::Absent => ROOT_LOGICAL,
        Topology::SingleLeaf => ROOT_LOGICAL,
        Topology::InternalTwoLeaf => RIGHT_LOGICAL,
    };

    match topology {
        Topology::Absent => {}
        Topology::SingleLeaf => {
            let count = usize::from(cursor.next_u8() % 7);
            let entries = build_leaf_entries(&mut cursor, count, 256);
            logical_blocks.insert(
                ROOT_LOGICAL,
                build_leaf_block(ROOT_LOGICAL, OWNER, GENERATION, &entries),
            );
            expected_items = entries;
            log_root = ROOT_LOGICAL;
        }
        Topology::InternalTwoLeaf => {
            let left_count = usize::from(cursor.next_u8() % 4);
            let right_count = usize::from(cursor.next_u8() % 4);
            let left_entries = build_leaf_entries(&mut cursor, left_count, 256);
            let right_entries = build_leaf_entries(&mut cursor, right_count, 4096);

            logical_blocks.insert(
                LEFT_LOGICAL,
                build_leaf_block(LEFT_LOGICAL, OWNER, GENERATION, &left_entries),
            );
            logical_blocks.insert(
                RIGHT_LOGICAL,
                build_leaf_block(RIGHT_LOGICAL, OWNER, GENERATION, &right_entries),
            );

            let mut ptrs = vec![
                (
                    left_entries
                        .first()
                        .map(|entry| entry.key)
                        .unwrap_or_else(|| fallback_key(256)),
                    LEFT_LOGICAL,
                ),
                (
                    right_entries
                        .first()
                        .map(|entry| entry.key)
                        .unwrap_or_else(|| fallback_key(4096)),
                    RIGHT_LOGICAL,
                ),
            ];
            if corruption == CorruptionMode::Structural {
                ptrs[0].1 = ROOT_LOGICAL;
            }
            logical_blocks.insert(
                ROOT_LOGICAL,
                build_internal_block(ROOT_LOGICAL, OWNER, GENERATION, &ptrs),
            );

            expected_items.extend(left_entries);
            expected_items.extend(right_entries);
            log_root = ROOT_LOGICAL;
            log_root_level = 1;
        }
    }

    if topology == Topology::SingleLeaf && corruption == CorruptionMode::Structural && log_root != 0
    {
        log_root = log_root.saturating_add(1);
    }

    if corruption == CorruptionMode::BadChecksum && log_root != 0 {
        if let Some(block) = logical_blocks.get_mut(&ROOT_LOGICAL) {
            block[0] ^= 0xFF;
        }
    }

    let csum_type = if corruption == CorruptionMode::UnsupportedChecksum && log_root != 0 {
        BTRFS_CSUM_TYPE_CRC32C.saturating_add(1)
    } else {
        BTRFS_CSUM_TYPE_CRC32C
    };

    let chunk_start = if corruption == CorruptionMode::UncoveredRoot && log_root != 0 {
        ROOT_LOGICAL.saturating_add(u64::try_from(NODESIZE).expect("nodesize fits in u64"))
    } else {
        ROOT_LOGICAL
    };
    let chunk_length = max_logical
        .saturating_add(u64::try_from(NODESIZE).expect("nodesize fits in u64"))
        .saturating_sub(ROOT_LOGICAL)
        .max(u64::try_from(NODESIZE).expect("nodesize fits in u64"));

    let identity_chunks = vec![build_single_stripe_chunk(
        chunk_start,
        chunk_length,
        ROOT_LOGICAL,
    )];
    let shifted_chunks = vec![build_single_stripe_chunk(
        chunk_start,
        chunk_length,
        ROOT_LOGICAL.saturating_add(PHYSICAL_SHIFT),
    )];

    let identity_blocks = logical_blocks.clone();
    let shifted_blocks = logical_blocks
        .into_iter()
        .map(|(logical, block)| (logical.saturating_add(PHYSICAL_SHIFT), block))
        .collect();

    TreeImage {
        superblock: build_superblock(log_root, log_root_level, csum_type),
        identity_chunks,
        shifted_chunks,
        identity_blocks,
        shifted_blocks,
        expected_items,
        topology,
        corruption,
    }
}

fn run_replay(
    blocks: &BTreeMap<u64, Vec<u8>>,
    sb: &BtrfsSuperblock,
    chunks: &[BtrfsChunkEntry],
) -> (
    std::result::Result<TreeLogReplayResult, ParseError>,
    Vec<u64>,
) {
    let mut reads = Vec::new();
    let mut read = |physical: u64| -> std::result::Result<Vec<u8>, ParseError> {
        reads.push(physical);
        blocks
            .get(&physical)
            .cloned()
            .ok_or(ParseError::InvalidField {
                field: "physical",
                reason: "block not in fuzz image",
            })
    };
    (replay_tree_log(&mut read, sb, chunks, OWNER), reads)
}

fn assert_result_invariants(result: &TreeLogReplayResult, sb: &BtrfsSuperblock) {
    assert_eq!(
        result.items_count,
        result.items.len(),
        "tree-log replay item count should match the returned item vector"
    );
    assert_eq!(
        result.replayed,
        sb.log_root != 0,
        "tree-log replayed flag should track whether log_root was present"
    );
    if !result.replayed {
        assert!(
            result.items.is_empty(),
            "tree-log replay without log_root should not return items"
        );
    }
    for pair in result.items.windows(2) {
        assert!(
            key_order_tuple(&pair[0].key) <= key_order_tuple(&pair[1].key),
            "tree-log replay items should stay in key order"
        );
    }
}

fn assert_results_match(
    left: &std::result::Result<TreeLogReplayResult, ParseError>,
    right: &std::result::Result<TreeLogReplayResult, ParseError>,
    context: &str,
) {
    match (left, right) {
        (Ok(left), Ok(right)) => {
            assert_eq!(
                left.replayed, right.replayed,
                "{context} should keep replay mode stable"
            );
            assert_eq!(
                left.items_count, right.items_count,
                "{context} should keep replay counts stable"
            );
            assert_eq!(
                left.items, right.items,
                "{context} should keep replayed items stable"
            );
        }
        (Err(left), Err(right)) => {
            assert_eq!(
                left.to_string(),
                right.to_string(),
                "{context} should reject malformed tree-logs deterministically"
            );
        }
        (left, right) => {
            assert_eq!(
                left.is_ok(),
                right.is_ok(),
                "{context} changed success/failure mode: left={left:?} right={right:?}"
            );
        }
    }
}

fn assert_shifted_reads_match(identity_reads: &[u64], shifted_reads: &[u64]) {
    assert_eq!(
        identity_reads.len(),
        shifted_reads.len(),
        "equivalent chunk mappings should issue the same number of physical reads"
    );
    for (identity, shifted) in identity_reads.iter().zip(shifted_reads) {
        assert_eq!(
            *identity + PHYSICAL_SHIFT,
            *shifted,
            "shifted chunk mapping should translate each physical read by PHYSICAL_SHIFT"
        );
    }
}

fn assert_corruption_contract(
    image: &TreeImage,
    result: &std::result::Result<TreeLogReplayResult, ParseError>,
) {
    if image.topology != Topology::Absent && image.corruption != CorruptionMode::None {
        assert!(
            result.is_err(),
            "modeled non-absent corrupted tree-log was accepted: topology={:?} corruption={:?} result={:?}",
            image.topology,
            image.corruption,
            result
        );
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let image = build_tree_image(data);

    let (first_identity, first_reads) = run_replay(
        &image.identity_blocks,
        &image.superblock,
        &image.identity_chunks,
    );
    let (second_identity, second_reads) = run_replay(
        &image.identity_blocks,
        &image.superblock,
        &image.identity_chunks,
    );
    assert_results_match(
        &first_identity,
        &second_identity,
        "re-running tree-log replay on the same image",
    );
    assert_eq!(
        first_reads, second_reads,
        "tree-log replay should read the same physical blocks deterministically"
    );

    let (shifted_result, shifted_reads) = run_replay(
        &image.shifted_blocks,
        &image.superblock,
        &image.shifted_chunks,
    );
    assert_results_match(
        &first_identity,
        &shifted_result,
        "equivalent chunk mappings for the same tree-log image",
    );
    assert_shifted_reads_match(&first_reads, &shifted_reads);
    assert_corruption_contract(&image, &first_identity);

    if image.topology == Topology::Absent {
        if let Ok(result) = &first_identity {
            assert_result_invariants(result, &image.superblock);
        }
        assert!(
            first_reads.is_empty() && shifted_reads.is_empty(),
            "absent tree-log should not issue physical reads"
        );
    }

    if image.corruption == CorruptionMode::None {
        if let Ok(result) = &first_identity {
            assert_result_invariants(result, &image.superblock);
            if image.topology != Topology::Absent {
                assert_eq!(
                    result.items, image.expected_items,
                    "valid synthesized tree-log should replay the modeled leaf items exactly"
                );
            }
        }
    } else if let Ok(result) = &first_identity {
        assert_result_invariants(result, &image.superblock);
    }
});
