#![forbid(unsafe_code)]

use ffs_ondisk::ext4::{
    EXT4_MMP_MAGIC, EXT4_MMP_SEQ_CLEAN, EXT4_MMP_SEQ_FSCK, Ext4GroupDescChecksumKind,
    Ext4RoCompatFeatures, stamp_group_desc_checksum,
};
use ffs_ondisk::{
    BtrfsHeader, BtrfsSuperblock, Ext4GroupDesc, Ext4ImageReader, Ext4Inode, Ext4MmpBlock,
    Ext4MmpStatus, Ext4Superblock, ExtentTree, ext4_chksum, iter_dir_block,
    map_logical_to_physical, parse_dev_item, parse_dir_block, parse_dx_root, parse_extent_tree,
    parse_ibody_xattrs, parse_internal_items, parse_leaf_items, parse_sys_chunk_array,
    parse_xattr_block, stamp_dir_block_checksum, stamp_extent_block_checksum,
    verify_btrfs_superblock_checksum, verify_btrfs_tree_block_checksum, verify_dir_block_checksum,
    verify_extent_block_checksum, verify_group_desc_checksum, verify_inode_checksum,
};
use ffs_types::{
    BTRFS_CSUM_TYPE_CRC32C, BTRFS_MAGIC, BTRFS_SUPER_INFO_OFFSET, BTRFS_SUPER_INFO_SIZE,
    EXT4_SB_CHECKSUM_OFFSET, EXT4_SUPER_MAGIC, EXT4_SUPERBLOCK_OFFSET, EXT4_SUPERBLOCK_SIZE,
    ParseError,
};
use proptest::prelude::*;
use std::collections::BTreeMap;
use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;

#[derive(Debug, Default)]
struct ErrorCoverage {
    insufficient_data: u32,
    invalid_magic: u32,
    invalid_field: u32,
    integer_conversion: u32,
}

impl ErrorCoverage {
    fn observe(&mut self, err: &ParseError) {
        match err {
            ParseError::InsufficientData { .. } => self.insufficient_data += 1,
            ParseError::InvalidMagic { .. } => self.invalid_magic += 1,
            ParseError::InvalidField { .. } => self.invalid_field += 1,
            ParseError::IntegerConversion { .. } => self.integer_conversion += 1,
        }
    }
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root")
        .join("tests/fuzz_corpus")
}

fn manifest_fuzz_targets(workspace_root: &std::path::Path) -> Vec<String> {
    let fuzz_manifest = workspace_root.join("fuzz").join("Cargo.toml");
    let manifest_contents =
        fs::read_to_string(&fuzz_manifest).expect("failed to read fuzz manifest");

    let mut targets = manifest_contents
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let name = trimmed.strip_prefix("name = \"")?.strip_suffix('"')?;
            name.starts_with("fuzz_").then(|| name.to_owned())
        })
        .collect::<Vec<_>>();
    targets.sort();
    targets.dedup();
    targets
}

fn load_corpus_samples() -> Vec<(String, Vec<u8>)> {
    let dir = corpus_dir();
    let mut entries = fs::read_dir(&dir)
        .expect("failed to read corpus dir")
        .collect::<Result<Vec<_>, _>>()
        .expect("failed to iterate corpus dir");
    entries.sort_by_key(std::fs::DirEntry::file_name);

    let mut out = inline_data_adversarial_samples();
    out.extend(inode_checksum_adversarial_samples());
    out.extend(xattr_block_adversarial_samples());
    out.extend(dir_block_adversarial_samples());
    out.extend(dx_root_adversarial_samples());
    out.extend(ext4_superblock_adversarial_samples());
    out.extend(extent_tree_adversarial_samples());
    out.extend(group_desc_adversarial_samples());
    out.extend(mmp_block_adversarial_samples());
    out.extend(btrfs_tree_adversarial_samples());
    out.extend(btrfs_sys_chunk_adversarial_samples());
    out.extend(btrfs_dev_item_adversarial_samples());
    out.extend(btrfs_superblock_adversarial_samples());
    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("bin") {
            continue;
        }
        let data = fs::read(&path).expect("failed to read corpus sample");
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .map_or_else(|| path.display().to_string(), str::to_owned);
        out.push((name, data));
    }

    assert!(
        out.len() >= 50,
        "expected at least 50 adversarial samples, found {}",
        out.len()
    );
    out
}

fn base_inline_data_inode() -> Vec<u8> {
    let mut inode = vec![0_u8; 256];
    inode[0x00..0x02].copy_from_slice(&(ffs_types::S_IFREG | 0o644).to_le_bytes());
    inode[0x1A..0x1C].copy_from_slice(&1_u16.to_le_bytes());
    inode[0x20..0x24].copy_from_slice(&ffs_types::EXT4_INLINE_DATA_FL.to_le_bytes());
    inode[0x80..0x82].copy_from_slice(&32_u16.to_le_bytes());
    inode
}

fn inline_data_adversarial_samples() -> Vec<(String, Vec<u8>)> {
    let mut samples = Vec::new();

    let mut huge_inline_size = base_inline_data_inode();
    huge_inline_size[0x04..0x08].copy_from_slice(&u32::MAX.to_le_bytes());
    huge_inline_size[0x6C..0x70].copy_from_slice(&u32::MAX.to_le_bytes());
    huge_inline_size[0x28..0x28 + 60].copy_from_slice(&[0xA5; 60]);
    samples.push((
        "synthetic_ext4_inline_data_huge_size.bin".to_owned(),
        huge_inline_size,
    ));

    let mut extra_isize_overflow = base_inline_data_inode();
    extra_isize_overflow[0x80..0x82].copy_from_slice(&129_u16.to_le_bytes());
    samples.push((
        "synthetic_ext4_inline_data_extra_isize_overflow.bin".to_owned(),
        extra_isize_overflow,
    ));

    let mut magic_only_ibody = base_inline_data_inode();
    let ibody_start = 128 + 32;
    magic_only_ibody[ibody_start..ibody_start + 4]
        .copy_from_slice(&ffs_types::EXT4_XATTR_MAGIC.to_le_bytes());
    samples.push((
        "synthetic_ext4_inline_data_ibody_magic_only.bin".to_owned(),
        magic_only_ibody,
    ));

    let mut name_overflow = base_inline_data_inode();
    name_overflow[ibody_start..ibody_start + 4]
        .copy_from_slice(&ffs_types::EXT4_XATTR_MAGIC.to_le_bytes());
    let entry_start = ibody_start + 4;
    name_overflow[entry_start] = 96;
    name_overflow[entry_start + 1] = ffs_types::EXT4_XATTR_INDEX_USER;
    samples.push((
        "synthetic_ext4_inline_data_ibody_name_overflow.bin".to_owned(),
        name_overflow,
    ));

    let mut value_overflow = base_inline_data_inode();
    value_overflow[ibody_start..ibody_start + 4]
        .copy_from_slice(&ffs_types::EXT4_XATTR_MAGIC.to_le_bytes());
    value_overflow[entry_start] = 4;
    value_overflow[entry_start + 1] = ffs_types::EXT4_XATTR_INDEX_USER;
    value_overflow[entry_start + 2..entry_start + 4].copy_from_slice(&94_u16.to_le_bytes());
    value_overflow[entry_start + 8..entry_start + 12].copy_from_slice(&4_u32.to_le_bytes());
    value_overflow[entry_start + 16..entry_start + 20].copy_from_slice(b"boom");
    samples.push((
        "synthetic_ext4_inline_data_ibody_value_overflow.bin".to_owned(),
        value_overflow,
    ));

    let mut valid_ibody_xattr = base_inline_data_inode();
    valid_ibody_xattr[ibody_start..ibody_start + 4]
        .copy_from_slice(&ffs_types::EXT4_XATTR_MAGIC.to_le_bytes());
    valid_ibody_xattr[entry_start] = 4;
    valid_ibody_xattr[entry_start + 1] = ffs_types::EXT4_XATTR_INDEX_USER;
    valid_ibody_xattr[entry_start + 2..entry_start + 4].copy_from_slice(&80_u16.to_le_bytes());
    valid_ibody_xattr[entry_start + 8..entry_start + 12].copy_from_slice(&5_u32.to_le_bytes());
    valid_ibody_xattr[entry_start + 16..entry_start + 20].copy_from_slice(b"seed");
    let value_start = entry_start + 80;
    valid_ibody_xattr[value_start..value_start + 5].copy_from_slice(b"fuzz!");
    samples.push((
        "synthetic_ext4_inline_data_ibody_valid_xattr.bin".to_owned(),
        valid_ibody_xattr,
    ));

    samples
}

fn base_inode_for_checksum(inode_size: usize, extra_isize: u16) -> Vec<u8> {
    let mut inode = vec![0_u8; inode_size];
    inode[0x00..0x02].copy_from_slice(&(ffs_types::S_IFREG | 0o644).to_le_bytes());
    inode[0x04..0x08].copy_from_slice(&12_345_u32.to_le_bytes());
    inode[0x1A..0x1C].copy_from_slice(&1_u16.to_le_bytes());
    inode[0x20..0x24].copy_from_slice(&ffs_types::EXT4_EXTENTS_FL.to_le_bytes());
    inode[0x64..0x68].copy_from_slice(&42_u32.to_le_bytes());
    if inode_size >= EXT4_TEST_INODE_CHECKSUM_HI_OFFSET {
        inode[0x80..0x82].copy_from_slice(&extra_isize.to_le_bytes());
    }
    inode
}

fn ext4_inode_checksum_hi_is_present(raw_inode: &[u8], inode_size: usize) -> bool {
    if inode_size < EXT4_TEST_INODE_CHECKSUM_HI_OFFSET + 2
        || raw_inode.len() < EXT4_TEST_INODE_CHECKSUM_HI_OFFSET + 2
    {
        return false;
    }
    let extra_isize = u16::from_le_bytes([raw_inode[0x80], raw_inode[0x81]]);
    128 + usize::from(extra_isize) >= EXT4_TEST_INODE_CHECKSUM_HI_OFFSET + 2
}

fn compute_ext4_inode_checksum(raw_inode: &[u8], csum_seed: u32, ino: u32, inode_size: u16) -> u32 {
    let inode_size = usize::from(inode_size);
    let generation = u32::from_le_bytes([
        raw_inode[0x64],
        raw_inode[0x65],
        raw_inode[0x66],
        raw_inode[0x67],
    ]);
    let ino_seed = ext4_chksum(csum_seed, &ino.to_le_bytes());
    let ino_seed = ext4_chksum(ino_seed, &generation.to_le_bytes());

    let mut csum = ext4_chksum(ino_seed, &raw_inode[..EXT4_TEST_INODE_CHECKSUM_LO_OFFSET]);
    csum = ext4_chksum(csum, &[0, 0]);
    csum = ext4_chksum(
        csum,
        &raw_inode[EXT4_TEST_INODE_CHECKSUM_LO_OFFSET + 2..128],
    );

    if inode_size > 128 {
        let hi_bound = EXT4_TEST_INODE_CHECKSUM_HI_OFFSET.min(inode_size);
        csum = ext4_chksum(csum, &raw_inode[128..hi_bound]);

        if inode_size >= EXT4_TEST_INODE_CHECKSUM_HI_OFFSET + 2 {
            if ext4_inode_checksum_hi_is_present(raw_inode, inode_size) {
                csum = ext4_chksum(csum, &[0, 0]);
                let after_hi = EXT4_TEST_INODE_CHECKSUM_HI_OFFSET + 2;
                if after_hi < inode_size {
                    csum = ext4_chksum(csum, &raw_inode[after_hi..inode_size]);
                }
            } else {
                csum = ext4_chksum(
                    csum,
                    &raw_inode[EXT4_TEST_INODE_CHECKSUM_HI_OFFSET..inode_size],
                );
            }
        } else if hi_bound < inode_size {
            csum = ext4_chksum(csum, &raw_inode[hi_bound..inode_size]);
        }
    }

    csum
}

fn stamp_ext4_inode_checksum(raw_inode: &mut [u8], csum_seed: u32, ino: u32, inode_size: u16) {
    let inode_size_usize = usize::from(inode_size);
    raw_inode[EXT4_TEST_INODE_CHECKSUM_LO_OFFSET..EXT4_TEST_INODE_CHECKSUM_LO_OFFSET + 2].fill(0);
    if ext4_inode_checksum_hi_is_present(raw_inode, inode_size_usize) {
        raw_inode[EXT4_TEST_INODE_CHECKSUM_HI_OFFSET..EXT4_TEST_INODE_CHECKSUM_HI_OFFSET + 2]
            .fill(0);
    }

    let csum = compute_ext4_inode_checksum(raw_inode, csum_seed, ino, inode_size);
    raw_inode[EXT4_TEST_INODE_CHECKSUM_LO_OFFSET..EXT4_TEST_INODE_CHECKSUM_LO_OFFSET + 2]
        .copy_from_slice(&(csum & 0xFFFF).to_le_bytes()[..2]);

    if ext4_inode_checksum_hi_is_present(raw_inode, inode_size_usize) {
        raw_inode[EXT4_TEST_INODE_CHECKSUM_HI_OFFSET..EXT4_TEST_INODE_CHECKSUM_HI_OFFSET + 2]
            .copy_from_slice(&(csum >> 16).to_le_bytes()[..2]);
    }
}

fn inode_checksum_adversarial_samples() -> Vec<(String, Vec<u8>)> {
    let mut valid132 = base_inode_for_checksum(132, 4);
    stamp_ext4_inode_checksum(
        &mut valid132,
        EXT4_TEST_INODE_CSUM_SEED,
        EXT4_TEST_INODE_NUMBER,
        132,
    );

    let mut valid256 = base_inode_for_checksum(256, 32);
    valid256[0x84..0x88].copy_from_slice(&500_000_000_u32.to_le_bytes());
    valid256[0x98..0x9C].copy_from_slice(&0x0102_0304_u32.to_le_bytes());
    stamp_ext4_inode_checksum(
        &mut valid256,
        EXT4_TEST_INODE_CSUM_SEED,
        EXT4_TEST_INODE_NUMBER,
        256,
    );

    let mut bad_checksum = valid256.clone();
    bad_checksum[EXT4_TEST_INODE_CHECKSUM_LO_OFFSET] ^= 0x80;

    let mut covered_byte_corrupt = valid256.clone();
    covered_byte_corrupt[0x10] ^= 0x01;

    let mut short256 = valid256.clone();
    short256.truncate(255);

    vec![
        (
            "synthetic_ext4_inode_checksum_valid_132.bin".to_owned(),
            valid132,
        ),
        (
            "synthetic_ext4_inode_checksum_valid_256.bin".to_owned(),
            valid256,
        ),
        (
            "synthetic_ext4_inode_checksum_bad_checksum.bin".to_owned(),
            bad_checksum,
        ),
        (
            "synthetic_ext4_inode_checksum_covered_byte_corrupt.bin".to_owned(),
            covered_byte_corrupt,
        ),
        (
            "synthetic_ext4_inode_checksum_short_256.bin".to_owned(),
            short256,
        ),
        (
            "synthetic_ext4_inode_checksum_inode_size_too_small.bin".to_owned(),
            base_inode_for_checksum(128, 0),
        ),
    ]
}

fn base_xattr_block(size: usize) -> Vec<u8> {
    let mut block = vec![0_u8; size];
    block[0..4].copy_from_slice(&ffs_types::EXT4_XATTR_MAGIC.to_le_bytes());
    block
}

fn xattr_block_adversarial_samples() -> Vec<(String, Vec<u8>)> {
    let mut samples = Vec::new();

    samples.push((
        "synthetic_ext4_xattr_block_bad_magic.bin".to_owned(),
        vec![0x5A; 64],
    ));

    samples.push((
        "synthetic_ext4_xattr_block_header_only.bin".to_owned(),
        base_xattr_block(32),
    ));

    let mut name_overflow = base_xattr_block(64);
    let entry_start = 32;
    name_overflow[entry_start] = 48;
    name_overflow[entry_start + 1] = ffs_types::EXT4_XATTR_INDEX_USER;
    samples.push((
        "synthetic_ext4_xattr_block_name_overflow.bin".to_owned(),
        name_overflow,
    ));

    let mut value_overflow = base_xattr_block(96);
    value_overflow[entry_start] = 4;
    value_overflow[entry_start + 1] = ffs_types::EXT4_XATTR_INDEX_USER;
    value_overflow[entry_start + 2..entry_start + 4].copy_from_slice(&94_u16.to_le_bytes());
    value_overflow[entry_start + 8..entry_start + 12].copy_from_slice(&4_u32.to_le_bytes());
    value_overflow[entry_start + 16..entry_start + 20].copy_from_slice(b"boom");
    samples.push((
        "synthetic_ext4_xattr_block_value_overflow.bin".to_owned(),
        value_overflow,
    ));

    let mut valid_block = base_xattr_block(128);
    valid_block[entry_start] = 4;
    valid_block[entry_start + 1] = ffs_types::EXT4_XATTR_INDEX_USER;
    valid_block[entry_start + 2..entry_start + 4].copy_from_slice(&80_u16.to_le_bytes());
    valid_block[entry_start + 8..entry_start + 12].copy_from_slice(&5_u32.to_le_bytes());
    valid_block[entry_start + 16..entry_start + 20].copy_from_slice(b"seed");
    valid_block[80..85].copy_from_slice(b"block");
    samples.push((
        "synthetic_ext4_xattr_block_valid_user_attr.bin".to_owned(),
        valid_block,
    ));

    samples
}

fn write_dir_header(
    block: &mut [u8],
    offset: usize,
    inode: u32,
    rec_len: u16,
    name_len: u8,
    file_type: u8,
) {
    block[offset..offset + 4].copy_from_slice(&inode.to_le_bytes());
    block[offset + 4..offset + 6].copy_from_slice(&rec_len.to_le_bytes());
    block[offset + 6] = name_len;
    block[offset + 7] = file_type;
}

fn dir_block_adversarial_samples() -> Vec<(String, Vec<u8>)> {
    let mut samples = Vec::new();
    let checksum_seed = EXT4_TEST_DIR_CSUM_SEED;
    let dir_ino = EXT4_TEST_DIR_INODE;
    let dir_generation = EXT4_TEST_DIR_GENERATION;

    let valid = synth_valid_dir_block(
        &[
            (2, 2, b".".to_vec()),
            (2, 2, b"..".to_vec()),
            (12, 1, b"file".to_vec()),
        ],
        true,
        0xA5A5_5A5A,
    );
    samples.push(("synthetic_ext4_dir_block_valid_tail.bin".to_owned(), valid));

    let mut valid_checksum = synth_valid_dir_block(
        &[
            (2, 2, b".".to_vec()),
            (2, 2, b"..".to_vec()),
            (12, 1, b"file".to_vec()),
        ],
        true,
        0,
    );
    stamp_dir_block_checksum(&mut valid_checksum, checksum_seed, dir_ino, dir_generation);

    let mut checksum_corrupt = valid_checksum.clone();
    checksum_corrupt[EXT4_TEST_DIR_BLOCK_SIZE - 1] ^= 0x80;

    let mut covered_byte_corrupt = valid_checksum.clone();
    covered_byte_corrupt[8] ^= 0x01;

    let mut malformed_tail = valid_checksum.clone();
    malformed_tail[EXT4_TEST_DIR_BLOCK_SIZE - 5] = 0xDF;

    let too_small_for_tail = vec![0_u8; 11];

    samples.push((
        "synthetic_ext4_dir_block_checksum_valid.bin".to_owned(),
        valid_checksum,
    ));
    samples.push((
        "synthetic_ext4_dir_block_checksum_corrupt.bin".to_owned(),
        checksum_corrupt,
    ));
    samples.push((
        "synthetic_ext4_dir_block_checksum_covered_byte_corrupt.bin".to_owned(),
        covered_byte_corrupt,
    ));
    samples.push((
        "synthetic_ext4_dir_block_checksum_malformed_tail.bin".to_owned(),
        malformed_tail,
    ));
    samples.push((
        "synthetic_ext4_dir_block_checksum_too_small.bin".to_owned(),
        too_small_for_tail,
    ));

    let mut rec_len_too_small = vec![0_u8; EXT4_TEST_DIR_BLOCK_SIZE];
    write_dir_header(&mut rec_len_too_small, 0, 12, 8, 1, 1);
    rec_len_too_small[8] = b'x';
    samples.push((
        "synthetic_ext4_dir_block_rec_len_too_small.bin".to_owned(),
        rec_len_too_small,
    ));

    let mut rec_len_unaligned = vec![0_u8; EXT4_TEST_DIR_BLOCK_SIZE];
    write_dir_header(&mut rec_len_unaligned, 0, 12, 14, 1, 1);
    rec_len_unaligned[8] = b'x';
    samples.push((
        "synthetic_ext4_dir_block_rec_len_unaligned.bin".to_owned(),
        rec_len_unaligned,
    ));

    let mut rec_len_past_end = vec![0_u8; 32];
    write_dir_header(&mut rec_len_past_end, 0, 12, 4096, 1, 1);
    rec_len_past_end[8] = b'x';
    samples.push((
        "synthetic_ext4_dir_block_rec_len_past_end.bin".to_owned(),
        rec_len_past_end,
    ));

    let mut name_overflow = vec![0_u8; 12];
    write_dir_header(&mut name_overflow, 0, 12, 12, 5, 1);
    name_overflow[8..12].copy_from_slice(b"abcd");
    samples.push((
        "synthetic_ext4_dir_block_name_overflow.bin".to_owned(),
        name_overflow,
    ));

    let mut tail_nonzero_padding = vec![0_u8; 16];
    write_dir_header(&mut tail_nonzero_padding, 0, 0, 12, 0, 0xDE);
    tail_nonzero_padding[8..12].copy_from_slice(&0xCAFE_BABEu32.to_le_bytes());
    tail_nonzero_padding[12] = 1;
    samples.push((
        "synthetic_ext4_dir_block_tail_nonzero_padding.bin".to_owned(),
        tail_nonzero_padding,
    ));

    samples
}

fn make_dx_root_block(hash_version: u8, indirect_levels: u8, limit: u16, count: u16) -> Vec<u8> {
    let mut block = vec![0_u8; EXT4_TEST_DIR_BLOCK_SIZE];

    write_dir_header(&mut block, 0, 2, 12, 1, 2);
    block[8] = b'.';
    write_dir_header(&mut block, 12, 2, 12, 2, 2);
    block[20..22].copy_from_slice(b"..");

    block[0x1C] = hash_version;
    block[0x1D] = 8;
    block[0x1E] = indirect_levels;
    block[0x1F] = 0;
    block[0x20..0x22].copy_from_slice(&limit.to_le_bytes());
    block[0x22..0x24].copy_from_slice(&count.to_le_bytes());
    block[0x24..0x28].copy_from_slice(&1_u32.to_le_bytes());
    block[0x28..0x2C].copy_from_slice(&0x1000_u32.to_le_bytes());
    block[0x2C..0x30].copy_from_slice(&2_u32.to_le_bytes());
    block[0x30..0x34].copy_from_slice(&0x8000_u32.to_le_bytes());
    block[0x34..0x38].copy_from_slice(&3_u32.to_le_bytes());

    block
}

fn dx_root_adversarial_samples() -> Vec<(String, Vec<u8>)> {
    let valid = make_dx_root_block(1, 0, 100, 3);
    let unknown_hash_version = make_dx_root_block(0xFF, 0, 100, 3);
    let zero_count = make_dx_root_block(1, 0, 100, 0);

    let mut nonzero_reserved = valid.clone();
    nonzero_reserved[0x18..0x1C].copy_from_slice(&1_u32.to_le_bytes());

    let mut bad_info_length = valid.clone();
    bad_info_length[0x1D] = 7;

    let mut excessive_indirect_levels = valid.clone();
    excessive_indirect_levels[0x1E] = 3;

    let mut nonzero_unused_flags = valid.clone();
    nonzero_unused_flags[0x1F] = 1;

    let mut count_exceeds_limit = make_dx_root_block(1, 0, 2, 3);
    count_exceeds_limit[0x20..0x22].copy_from_slice(&2_u16.to_le_bytes());
    count_exceeds_limit[0x22..0x24].copy_from_slice(&3_u16.to_le_bytes());

    let mut too_short = valid.clone();
    too_short.truncate(0x27);

    vec![
        ("synthetic_ext4_dx_root_valid.bin".to_owned(), valid),
        (
            "synthetic_ext4_dx_root_unknown_hash_version.bin".to_owned(),
            unknown_hash_version,
        ),
        (
            "synthetic_ext4_dx_root_zero_count.bin".to_owned(),
            zero_count,
        ),
        (
            "synthetic_ext4_dx_root_nonzero_reserved.bin".to_owned(),
            nonzero_reserved,
        ),
        (
            "synthetic_ext4_dx_root_bad_info_length.bin".to_owned(),
            bad_info_length,
        ),
        (
            "synthetic_ext4_dx_root_excessive_indirect_levels.bin".to_owned(),
            excessive_indirect_levels,
        ),
        (
            "synthetic_ext4_dx_root_nonzero_unused_flags.bin".to_owned(),
            nonzero_unused_flags,
        ),
        (
            "synthetic_ext4_dx_root_count_exceeds_limit.bin".to_owned(),
            count_exceeds_limit,
        ),
        ("synthetic_ext4_dx_root_too_short.bin".to_owned(), too_short),
    ]
}

fn write_extent_header(
    block: &mut [u8],
    entries: u16,
    max_entries: u16,
    depth: u16,
    generation: u32,
) {
    block[0..2].copy_from_slice(&0xF30A_u16.to_le_bytes());
    block[2..4].copy_from_slice(&entries.to_le_bytes());
    block[4..6].copy_from_slice(&max_entries.to_le_bytes());
    block[6..8].copy_from_slice(&depth.to_le_bytes());
    block[8..12].copy_from_slice(&generation.to_le_bytes());
}

fn write_extent_leaf_entry(
    block: &mut [u8],
    idx: usize,
    logical_block: u32,
    raw_len: u16,
    physical_start: u64,
) {
    let base = 12 + idx * 12;
    let start_hi = u16::try_from((physical_start >> 32) & 0xFFFF).expect("physical high bits fit");
    let start_lo = u32::try_from(physical_start & 0xFFFF_FFFF).expect("physical low bits fit");
    block[base..base + 4].copy_from_slice(&logical_block.to_le_bytes());
    block[base + 4..base + 6].copy_from_slice(&raw_len.to_le_bytes());
    block[base + 6..base + 8].copy_from_slice(&start_hi.to_le_bytes());
    block[base + 8..base + 12].copy_from_slice(&start_lo.to_le_bytes());
}

fn write_extent_index_entry(block: &mut [u8], idx: usize, logical_block: u32, leaf_block: u64) {
    let base = 12 + idx * 12;
    let leaf_lo = u32::try_from(leaf_block & 0xFFFF_FFFF).expect("leaf low bits fit");
    let leaf_hi = u16::try_from((leaf_block >> 32) & 0xFFFF).expect("leaf high bits fit");
    block[base..base + 4].copy_from_slice(&logical_block.to_le_bytes());
    block[base + 4..base + 8].copy_from_slice(&leaf_lo.to_le_bytes());
    block[base + 8..base + 10].copy_from_slice(&leaf_hi.to_le_bytes());
}

fn extent_tree_adversarial_samples() -> Vec<(String, Vec<u8>)> {
    let mut samples = Vec::new();

    let mut valid_leaf = vec![0_u8; 36];
    write_extent_header(&mut valid_leaf, 2, 4, 0, 0x1010_2020);
    write_extent_leaf_entry(&mut valid_leaf, 0, 0, 4, 0x0001_0000_0010);
    write_extent_leaf_entry(&mut valid_leaf, 1, 8, 0x8003, 0x0001_0000_0040);
    samples.push((
        "synthetic_ext4_extent_tree_valid_leaf.bin".to_owned(),
        valid_leaf,
    ));

    let mut valid_index = vec![0_u8; 36];
    write_extent_header(&mut valid_index, 2, 4, 1, 0x3030_4040);
    write_extent_index_entry(&mut valid_index, 0, 0, 0x0002_0000_0100);
    write_extent_index_entry(&mut valid_index, 1, 64, 0x0002_0000_0200);
    samples.push((
        "synthetic_ext4_extent_tree_valid_index.bin".to_owned(),
        valid_index,
    ));

    let mut bad_magic = vec![0_u8; 12];
    bad_magic[0..2].copy_from_slice(&0xCAFE_u16.to_le_bytes());
    bad_magic[2..4].copy_from_slice(&0_u16.to_le_bytes());
    bad_magic[4..6].copy_from_slice(&4_u16.to_le_bytes());
    samples.push((
        "synthetic_ext4_extent_tree_bad_magic.bin".to_owned(),
        bad_magic,
    ));

    let mut entries_gt_max = vec![0_u8; 36];
    write_extent_header(&mut entries_gt_max, 2, 1, 0, 0);
    samples.push((
        "synthetic_ext4_extent_tree_entries_gt_max.bin".to_owned(),
        entries_gt_max,
    ));

    let mut truncated_entries = vec![0_u8; 24];
    write_extent_header(&mut truncated_entries, 2, 4, 0, 0);
    write_extent_leaf_entry(&mut truncated_entries, 0, 0, 1, 20);
    samples.push((
        "synthetic_ext4_extent_tree_truncated_entries.bin".to_owned(),
        truncated_entries,
    ));

    let mut leaf_overlap = vec![0_u8; 36];
    write_extent_header(&mut leaf_overlap, 2, 4, 0, 0);
    write_extent_leaf_entry(&mut leaf_overlap, 0, 10, 5, 30);
    write_extent_leaf_entry(&mut leaf_overlap, 1, 12, 1, 40);
    samples.push((
        "synthetic_ext4_extent_tree_leaf_overlap.bin".to_owned(),
        leaf_overlap,
    ));

    let mut index_unsorted = vec![0_u8; 36];
    write_extent_header(&mut index_unsorted, 2, 4, 1, 0);
    write_extent_index_entry(&mut index_unsorted, 0, 20, 100);
    write_extent_index_entry(&mut index_unsorted, 1, 20, 200);
    samples.push((
        "synthetic_ext4_extent_tree_index_unsorted.bin".to_owned(),
        index_unsorted,
    ));

    let mut valid_checksum_block = vec![0_u8; 64];
    write_extent_header(&mut valid_checksum_block, 1, 2, 0, 0);
    write_extent_leaf_entry(&mut valid_checksum_block, 0, 0, 1, 50);
    stamp_extent_block_checksum(&mut valid_checksum_block, 0x1234_5678, 42, 7);
    samples.push((
        "synthetic_ext4_extent_block_valid_checksum.bin".to_owned(),
        valid_checksum_block,
    ));

    samples
}

fn write_ext4_group_desc_low_fields(desc: &mut [u8]) {
    desc[0x00..0x04].copy_from_slice(&0x0000_0100_u32.to_le_bytes());
    desc[0x04..0x08].copy_from_slice(&0x0000_0200_u32.to_le_bytes());
    desc[0x08..0x0C].copy_from_slice(&0x0000_0300_u32.to_le_bytes());
    desc[0x0C..0x0E].copy_from_slice(&0x0040_u16.to_le_bytes());
    desc[0x0E..0x10].copy_from_slice(&0x0020_u16.to_le_bytes());
    desc[0x10..0x12].copy_from_slice(&0x0003_u16.to_le_bytes());
    desc[0x12..0x14].copy_from_slice(&0x0005_u16.to_le_bytes());
    desc[0x18..0x1A].copy_from_slice(&0x1357_u16.to_le_bytes());
    desc[0x1A..0x1C].copy_from_slice(&0x2468_u16.to_le_bytes());
    desc[0x1C..0x1E].copy_from_slice(&0x0010_u16.to_le_bytes());
}

fn make_ext4_group_desc_32() -> Vec<u8> {
    let mut desc = vec![0_u8; 32];
    write_ext4_group_desc_low_fields(&mut desc);
    desc
}

fn make_ext4_group_desc_64() -> Vec<u8> {
    let mut desc = vec![0_u8; 64];
    write_ext4_group_desc_low_fields(&mut desc);
    desc[0x20..0x24].copy_from_slice(&0x0000_0001_u32.to_le_bytes());
    desc[0x24..0x28].copy_from_slice(&0x0000_0002_u32.to_le_bytes());
    desc[0x28..0x2C].copy_from_slice(&0x0000_0003_u32.to_le_bytes());
    desc[0x2C..0x2E].copy_from_slice(&0x0001_u16.to_le_bytes());
    desc[0x2E..0x30].copy_from_slice(&0x0002_u16.to_le_bytes());
    desc[0x30..0x32].copy_from_slice(&0x0003_u16.to_le_bytes());
    desc[0x32..0x34].copy_from_slice(&0x0004_u16.to_le_bytes());
    desc[0x38..0x3A].copy_from_slice(&0xAAAA_u16.to_le_bytes());
    desc[0x3A..0x3C].copy_from_slice(&0xBBBB_u16.to_le_bytes());
    desc
}

fn group_desc_adversarial_samples() -> Vec<(String, Vec<u8>)> {
    let mut valid32 = make_ext4_group_desc_32();
    stamp_group_desc_checksum(
        &mut valid32,
        &EXT4_TEST_GROUP_DESC_UUID,
        EXT4_TEST_GROUP_DESC_CSUM_SEED,
        EXT4_TEST_GROUP_DESC_NUMBER,
        32,
        Ext4GroupDescChecksumKind::MetadataCsum,
    );

    let mut valid64 = make_ext4_group_desc_64();
    stamp_group_desc_checksum(
        &mut valid64,
        &EXT4_TEST_GROUP_DESC_UUID,
        EXT4_TEST_GROUP_DESC_CSUM_SEED,
        EXT4_TEST_GROUP_DESC_NUMBER,
        64,
        Ext4GroupDescChecksumKind::MetadataCsum,
    );

    let mut bad_checksum = valid32.clone();
    bad_checksum[0x1E] ^= 0xFF;

    let mut short32 = valid32.clone();
    short32.truncate(31);

    let mut short64 = valid64.clone();
    short64.truncate(63);

    vec![
        (
            "synthetic_ext4_group_desc_valid_32.bin".to_owned(),
            valid32.clone(),
        ),
        ("synthetic_ext4_group_desc_valid_64.bin".to_owned(), valid64),
        (
            "synthetic_ext4_group_desc_bad_checksum.bin".to_owned(),
            bad_checksum,
        ),
        ("synthetic_ext4_group_desc_short_32.bin".to_owned(), short32),
        ("synthetic_ext4_group_desc_short_64.bin".to_owned(), short64),
        (
            "synthetic_ext4_group_desc_desc_size_too_small.bin".to_owned(),
            valid32,
        ),
    ]
}

fn make_ext4_mmp_block(seq: u32, checksum_seed: u32) -> Vec<u8> {
    let mut block = vec![0_u8; EXT4_SUPERBLOCK_SIZE];
    block[0x00..0x04].copy_from_slice(&EXT4_MMP_MAGIC.to_le_bytes());
    block[0x04..0x08].copy_from_slice(&seq.to_le_bytes());
    block[0x08..0x10].copy_from_slice(&0x0000_0001_0000_007B_u64.to_le_bytes());
    block[0x10..0x1A].copy_from_slice(b"ffs-node-a");
    block[0x50..0x58].copy_from_slice(b"/dev/vda");
    block[0x70..0x72].copy_from_slice(&5_u16.to_le_bytes());

    let checksum = ext4_chksum(checksum_seed, &block[..EXT4_TEST_MMP_CHECKSUM_OFFSET]);
    block[EXT4_TEST_MMP_CHECKSUM_OFFSET..EXT4_TEST_MMP_CHECKSUM_OFFSET + 4]
        .copy_from_slice(&checksum.to_le_bytes());
    block
}

fn mmp_block_adversarial_samples() -> Vec<(String, Vec<u8>)> {
    let checksum_seed = 0xAABB_CCDD;
    let mut samples = vec![
        (
            "synthetic_ext4_mmp_clean_valid.bin".to_owned(),
            make_ext4_mmp_block(EXT4_MMP_SEQ_CLEAN, checksum_seed),
        ),
        (
            "synthetic_ext4_mmp_fsck_valid.bin".to_owned(),
            make_ext4_mmp_block(EXT4_MMP_SEQ_FSCK, checksum_seed),
        ),
        (
            "synthetic_ext4_mmp_active_valid.bin".to_owned(),
            make_ext4_mmp_block(42, checksum_seed),
        ),
        (
            "synthetic_ext4_mmp_unknown_seq.bin".to_owned(),
            make_ext4_mmp_block(u32::MAX, checksum_seed),
        ),
    ];

    let mut bad_magic = make_ext4_mmp_block(EXT4_MMP_SEQ_CLEAN, checksum_seed);
    bad_magic[0x00..0x04].copy_from_slice(&0xCAFE_BABEu32.to_le_bytes());
    samples.push(("synthetic_ext4_mmp_bad_magic.bin".to_owned(), bad_magic));

    let mut checksum_corrupt = make_ext4_mmp_block(EXT4_MMP_SEQ_CLEAN, checksum_seed);
    checksum_corrupt[EXT4_TEST_MMP_CHECKSUM_OFFSET] ^= 0xFF;
    samples.push((
        "synthetic_ext4_mmp_checksum_corrupt.bin".to_owned(),
        checksum_corrupt,
    ));

    let mut short_block = make_ext4_mmp_block(EXT4_MMP_SEQ_CLEAN, checksum_seed);
    short_block.truncate(EXT4_SUPERBLOCK_SIZE - 1);
    samples.push(("synthetic_ext4_mmp_short.bin".to_owned(), short_block));

    samples
}

fn write_btrfs_header(block: &mut [u8], nritems: u32, level: u8) {
    block[0x30..0x38].copy_from_slice(&0x1000_u64.to_le_bytes());
    block[0x50..0x58].copy_from_slice(&1_u64.to_le_bytes());
    block[0x58..0x60].copy_from_slice(&5_u64.to_le_bytes());
    block[0x60..0x64].copy_from_slice(&nritems.to_le_bytes());
    block[0x64] = level;
}

fn write_btrfs_leaf_item(
    block: &mut [u8],
    idx: usize,
    objectid: u64,
    item_type: u8,
    key_offset: u64,
    absolute_data_offset: u32,
    data_size: u32,
) {
    let base = BTRFS_TEST_HEADER_SIZE + idx * BTRFS_TEST_ITEM_SIZE;
    let header_size = u32::try_from(BTRFS_TEST_HEADER_SIZE).expect("header size fits");
    let relative_offset = absolute_data_offset
        .checked_sub(header_size)
        .expect("payload offset is after header");
    block[base..base + 8].copy_from_slice(&objectid.to_le_bytes());
    block[base + 8] = item_type;
    block[base + 9..base + 17].copy_from_slice(&key_offset.to_le_bytes());
    block[base + 17..base + 21].copy_from_slice(&relative_offset.to_le_bytes());
    block[base + 21..base + 25].copy_from_slice(&data_size.to_le_bytes());
}

fn write_btrfs_key_ptr(
    block: &mut [u8],
    idx: usize,
    objectid: u64,
    item_type: u8,
    key_offset: u64,
    blockptr: u64,
    generation: u64,
) {
    let base = BTRFS_TEST_HEADER_SIZE + idx * BTRFS_TEST_KEY_PTR_SIZE;
    block[base..base + 8].copy_from_slice(&objectid.to_le_bytes());
    block[base + 8] = item_type;
    block[base + 9..base + 17].copy_from_slice(&key_offset.to_le_bytes());
    block[base + 17..base + 25].copy_from_slice(&blockptr.to_le_bytes());
    block[base + 25..base + 33].copy_from_slice(&generation.to_le_bytes());
}

fn stamp_btrfs_tree_checksum(block: &mut [u8]) {
    let checksum = ffs_types::crc32c(&block[0x20..]);
    block[0..4].copy_from_slice(&checksum.to_le_bytes());
}

fn btrfs_tree_adversarial_samples() -> Vec<(String, Vec<u8>)> {
    let mut samples = Vec::new();

    let mut valid_leaf = vec![0_u8; 512];
    write_btrfs_header(&mut valid_leaf, 1, 0);
    write_btrfs_leaf_item(&mut valid_leaf, 0, 256, 1, 0, 400, 4);
    valid_leaf[400..404].copy_from_slice(b"leaf");
    stamp_btrfs_tree_checksum(&mut valid_leaf);
    samples.push(("synthetic_btrfs_tree_valid_leaf.bin".to_owned(), valid_leaf));

    let mut level_too_deep = vec![0_u8; BTRFS_TEST_HEADER_SIZE];
    write_btrfs_header(&mut level_too_deep, 0, 8);
    samples.push((
        "synthetic_btrfs_tree_level_too_deep.bin".to_owned(),
        level_too_deep,
    ));

    let mut leaf_item_table_overlap = vec![0_u8; 512];
    write_btrfs_header(&mut leaf_item_table_overlap, 1, 0);
    write_btrfs_leaf_item(&mut leaf_item_table_overlap, 0, 256, 1, 0, 125, 4);
    samples.push((
        "synthetic_btrfs_leaf_item_table_overlap.bin".to_owned(),
        leaf_item_table_overlap,
    ));

    let mut leaf_payload_outside = vec![0_u8; 512];
    write_btrfs_header(&mut leaf_payload_outside, 1, 0);
    write_btrfs_leaf_item(&mut leaf_payload_outside, 0, 256, 1, 0, 500, 16);
    samples.push((
        "synthetic_btrfs_leaf_payload_outside.bin".to_owned(),
        leaf_payload_outside,
    ));

    let mut leaf_payload_overlap = vec![0_u8; 512];
    write_btrfs_header(&mut leaf_payload_overlap, 2, 0);
    write_btrfs_leaf_item(&mut leaf_payload_overlap, 0, 256, 1, 0, 400, 40);
    write_btrfs_leaf_item(&mut leaf_payload_overlap, 1, 257, 1, 0, 420, 40);
    samples.push((
        "synthetic_btrfs_leaf_payload_overlap.bin".to_owned(),
        leaf_payload_overlap,
    ));

    let mut valid_internal = vec![0_u8; 512];
    write_btrfs_header(&mut valid_internal, 1, 1);
    write_btrfs_key_ptr(&mut valid_internal, 0, 256, 132, 0, 0x4000, 7);
    samples.push((
        "synthetic_btrfs_tree_valid_internal.bin".to_owned(),
        valid_internal,
    ));

    let mut zero_blockptr = vec![0_u8; 512];
    write_btrfs_header(&mut zero_blockptr, 1, 1);
    write_btrfs_key_ptr(&mut zero_blockptr, 0, 256, 132, 0, 0, 7);
    samples.push((
        "synthetic_btrfs_tree_zero_blockptr.bin".to_owned(),
        zero_blockptr,
    ));

    samples
}

fn write_btrfs_sys_chunk_key(data: &mut [u8], objectid: u64, item_type: u8, offset: u64) {
    data[0..8].copy_from_slice(&objectid.to_le_bytes());
    data[8] = item_type;
    data[9..17].copy_from_slice(&offset.to_le_bytes());
}

fn write_btrfs_chunk_header(
    data: &mut [u8],
    length: u64,
    stripe_len: u64,
    chunk_type: u64,
    num_stripes: u16,
) {
    let base = BTRFS_TEST_DISK_KEY_SIZE;
    data[base..base + 8].copy_from_slice(&length.to_le_bytes());
    data[base + 8..base + 16].copy_from_slice(&2_u64.to_le_bytes());
    data[base + 16..base + 24].copy_from_slice(&stripe_len.to_le_bytes());
    data[base + 24..base + 32].copy_from_slice(&chunk_type.to_le_bytes());
    data[base + 32..base + 36].copy_from_slice(&4096_u32.to_le_bytes());
    data[base + 36..base + 40].copy_from_slice(&4096_u32.to_le_bytes());
    data[base + 40..base + 44].copy_from_slice(&4096_u32.to_le_bytes());
    data[base + 44..base + 46].copy_from_slice(&num_stripes.to_le_bytes());
    data[base + 46..base + 48].copy_from_slice(&0_u16.to_le_bytes());
}

fn write_btrfs_chunk_stripe(data: &mut [u8], idx: usize, devid: u64, offset: u64) {
    let base =
        BTRFS_TEST_DISK_KEY_SIZE + BTRFS_TEST_CHUNK_FIXED_SIZE + idx * BTRFS_TEST_STRIPE_SIZE;
    data[base..base + 8].copy_from_slice(&devid.to_le_bytes());
    data[base + 8..base + 16].copy_from_slice(&offset.to_le_bytes());
    data[base + 16..base + 32].copy_from_slice(&[0xA5; 16]);
}

fn make_btrfs_sys_chunk(
    length: u64,
    stripe_len: u64,
    chunk_type: u64,
    num_stripes: u16,
) -> Vec<u8> {
    let stripe_bytes = usize::from(num_stripes) * BTRFS_TEST_STRIPE_SIZE;
    let mut data =
        vec![0_u8; BTRFS_TEST_DISK_KEY_SIZE + BTRFS_TEST_CHUNK_FIXED_SIZE + stripe_bytes];
    write_btrfs_sys_chunk_key(
        &mut data,
        BTRFS_TEST_CHUNK_TREE_OBJECTID,
        BTRFS_TEST_CHUNK_ITEM_KEY,
        0x1000,
    );
    write_btrfs_chunk_header(&mut data, length, stripe_len, chunk_type, num_stripes);
    for idx in 0..usize::from(num_stripes) {
        write_btrfs_chunk_stripe(&mut data, idx, 1, 0x2000);
    }
    data
}

fn btrfs_sys_chunk_adversarial_samples() -> Vec<(String, Vec<u8>)> {
    let mut samples = Vec::new();

    samples.push((
        "synthetic_btrfs_sys_chunk_valid_single.bin".to_owned(),
        make_btrfs_sys_chunk(
            BTRFS_TEST_CHUNK_LENGTH,
            4096,
            BTRFS_TEST_BLOCK_GROUP_SYSTEM,
            1,
        ),
    ));

    let mut bad_key_type = make_btrfs_sys_chunk(
        BTRFS_TEST_CHUNK_LENGTH,
        4096,
        BTRFS_TEST_BLOCK_GROUP_SYSTEM,
        1,
    );
    bad_key_type[8] = BTRFS_TEST_CHUNK_ITEM_KEY.wrapping_add(1);
    samples.push((
        "synthetic_btrfs_sys_chunk_bad_key_type.bin".to_owned(),
        bad_key_type,
    ));

    let mut bad_objectid = make_btrfs_sys_chunk(
        BTRFS_TEST_CHUNK_LENGTH,
        4096,
        BTRFS_TEST_BLOCK_GROUP_SYSTEM,
        1,
    );
    bad_objectid[0..8].copy_from_slice(&255_u64.to_le_bytes());
    samples.push((
        "synthetic_btrfs_sys_chunk_bad_objectid.bin".to_owned(),
        bad_objectid,
    ));

    samples.push((
        "synthetic_btrfs_sys_chunk_zero_length.bin".to_owned(),
        make_btrfs_sys_chunk(0, 4096, BTRFS_TEST_BLOCK_GROUP_SYSTEM, 1),
    ));

    samples.push((
        "synthetic_btrfs_sys_chunk_zero_stripe_len.bin".to_owned(),
        make_btrfs_sys_chunk(BTRFS_TEST_CHUNK_LENGTH, 0, BTRFS_TEST_BLOCK_GROUP_SYSTEM, 1),
    ));

    samples.push((
        "synthetic_btrfs_sys_chunk_zero_stripes.bin".to_owned(),
        make_btrfs_sys_chunk(
            BTRFS_TEST_CHUNK_LENGTH,
            4096,
            BTRFS_TEST_BLOCK_GROUP_SYSTEM,
            0,
        ),
    ));

    let mut zero_stripe_devid = make_btrfs_sys_chunk(
        BTRFS_TEST_CHUNK_LENGTH,
        4096,
        BTRFS_TEST_BLOCK_GROUP_SYSTEM,
        1,
    );
    write_btrfs_chunk_stripe(&mut zero_stripe_devid, 0, 0, 0x2000);
    samples.push((
        "synthetic_btrfs_sys_chunk_zero_stripe_devid.bin".to_owned(),
        zero_stripe_devid,
    ));

    samples.push((
        "synthetic_btrfs_sys_chunk_multiple_raid_profiles.bin".to_owned(),
        make_btrfs_sys_chunk(
            BTRFS_TEST_CHUNK_LENGTH,
            4096,
            BTRFS_TEST_BLOCK_GROUP_SYSTEM
                | BTRFS_TEST_BLOCK_GROUP_RAID0
                | BTRFS_TEST_BLOCK_GROUP_RAID1,
            1,
        ),
    ));

    let mut truncated_stripe = make_btrfs_sys_chunk(
        BTRFS_TEST_CHUNK_LENGTH,
        4096,
        BTRFS_TEST_BLOCK_GROUP_SYSTEM,
        1,
    );
    truncated_stripe.truncate(BTRFS_TEST_DISK_KEY_SIZE + BTRFS_TEST_CHUNK_FIXED_SIZE + 8);
    samples.push((
        "synthetic_btrfs_sys_chunk_truncated_stripe.bin".to_owned(),
        truncated_stripe,
    ));

    samples
}

#[derive(Clone, Copy)]
struct BtrfsDevItemSeed {
    devid: u64,
    total_bytes: u64,
    bytes_used: u64,
    io_align: u32,
    io_width: u32,
    sector_size: u32,
    dev_type: u64,
    generation: u64,
    start_offset: u64,
    dev_group: u32,
    seek_speed: u8,
    bandwidth: u8,
    uuid: [u8; 16],
    fsid: [u8; 16],
}

impl BtrfsDevItemSeed {
    fn valid() -> Self {
        Self {
            devid: 7,
            total_bytes: BTRFS_TEST_DEV_TOTAL_BYTES,
            bytes_used: BTRFS_TEST_DEV_BYTES_USED,
            io_align: 4096,
            io_width: 8192,
            sector_size: 4096,
            dev_type: 0,
            generation: 42,
            start_offset: 1 << 20,
            dev_group: 3,
            seek_speed: 11,
            bandwidth: 22,
            uuid: [0x11; 16],
            fsid: [0x22; 16],
        }
    }

    fn max_values() -> Self {
        Self {
            devid: u64::MAX,
            total_bytes: u64::MAX,
            bytes_used: u64::MAX,
            io_align: u32::MAX,
            io_width: u32::MAX,
            sector_size: u32::MAX,
            dev_type: u64::MAX,
            generation: u64::MAX,
            start_offset: u64::MAX,
            dev_group: u32::MAX,
            seek_speed: u8::MAX,
            bandwidth: u8::MAX,
            uuid: [0xAA; 16],
            fsid: [0x55; 16],
        }
    }
}

fn make_btrfs_dev_item(seed: BtrfsDevItemSeed) -> Vec<u8> {
    let mut data = vec![0_u8; BTRFS_TEST_DEV_ITEM_SIZE];
    data[0..8].copy_from_slice(&seed.devid.to_le_bytes());
    data[8..16].copy_from_slice(&seed.total_bytes.to_le_bytes());
    data[16..24].copy_from_slice(&seed.bytes_used.to_le_bytes());
    data[24..28].copy_from_slice(&seed.io_align.to_le_bytes());
    data[28..32].copy_from_slice(&seed.io_width.to_le_bytes());
    data[32..36].copy_from_slice(&seed.sector_size.to_le_bytes());
    data[36..44].copy_from_slice(&seed.dev_type.to_le_bytes());
    data[44..52].copy_from_slice(&seed.generation.to_le_bytes());
    data[52..60].copy_from_slice(&seed.start_offset.to_le_bytes());
    data[60..64].copy_from_slice(&seed.dev_group.to_le_bytes());
    data[64] = seed.seek_speed;
    data[65] = seed.bandwidth;
    data[66..82].copy_from_slice(&seed.uuid);
    data[82..98].copy_from_slice(&seed.fsid);
    data
}

fn btrfs_dev_item_adversarial_samples() -> Vec<(String, Vec<u8>)> {
    let mut samples = Vec::new();

    let valid = make_btrfs_dev_item(BtrfsDevItemSeed::valid());
    samples.push(("synthetic_btrfs_dev_item_valid_full.bin".to_owned(), valid));

    samples.push((
        "synthetic_btrfs_dev_item_max_values.bin".to_owned(),
        make_btrfs_dev_item(BtrfsDevItemSeed::max_values()),
    ));

    let mut extra_tail = make_btrfs_dev_item(BtrfsDevItemSeed::valid());
    extra_tail.extend_from_slice(&[0x5A; 16]);
    samples.push((
        "synthetic_btrfs_dev_item_extra_tail.bin".to_owned(),
        extra_tail,
    ));

    let mut zero_devid = make_btrfs_dev_item(BtrfsDevItemSeed::valid());
    zero_devid[0..8].copy_from_slice(&0_u64.to_le_bytes());
    samples.push((
        "synthetic_btrfs_dev_item_zero_devid.bin".to_owned(),
        zero_devid,
    ));

    let mut zero_total = make_btrfs_dev_item(BtrfsDevItemSeed::valid());
    zero_total[8..16].copy_from_slice(&0_u64.to_le_bytes());
    zero_total[16..24].copy_from_slice(&0_u64.to_le_bytes());
    samples.push((
        "synthetic_btrfs_dev_item_zero_total_bytes.bin".to_owned(),
        zero_total,
    ));

    let mut overused = make_btrfs_dev_item(BtrfsDevItemSeed::valid());
    overused[16..24].copy_from_slice(&(BTRFS_TEST_DEV_TOTAL_BYTES + 1).to_le_bytes());
    samples.push((
        "synthetic_btrfs_dev_item_bytes_used_exceeds_total.bin".to_owned(),
        overused,
    ));

    let mut truncated = make_btrfs_dev_item(BtrfsDevItemSeed::valid());
    truncated.truncate(BTRFS_TEST_DEV_ITEM_SIZE - 1);
    samples.push((
        "synthetic_btrfs_dev_item_truncated_tail.bin".to_owned(),
        truncated,
    ));

    samples
}

fn minimal_valid_btrfs_superblock_region(sys_chunk_array: &[u8]) -> Vec<u8> {
    let mut region = vec![0_u8; BTRFS_SUPER_INFO_SIZE];
    let sys_chunk_array_size =
        u32::try_from(sys_chunk_array.len()).expect("sys_chunk_array length fits in u32");
    let sys_chunk_array_offset = 0x32B;
    let sys_chunk_array_end = sys_chunk_array_offset + sys_chunk_array.len();

    region[0x20..0x30].copy_from_slice(&[0x33; 16]);
    let superblock_bytenr =
        u64::try_from(BTRFS_SUPER_INFO_OFFSET).expect("btrfs superblock offset fits in u64");
    region[0x30..0x38].copy_from_slice(&superblock_bytenr.to_le_bytes());
    region[0x38..0x40].copy_from_slice(&0_u64.to_le_bytes());
    region[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
    region[0x48..0x50].copy_from_slice(&7_u64.to_le_bytes());
    region[0x50..0x58].copy_from_slice(&0x4000_u64.to_le_bytes());
    region[0x58..0x60].copy_from_slice(&0x8000_u64.to_le_bytes());
    region[0x60..0x68].copy_from_slice(&0_u64.to_le_bytes());
    region[0x70..0x78].copy_from_slice(&BTRFS_TEST_DEV_TOTAL_BYTES.to_le_bytes());
    region[0x78..0x80].copy_from_slice(&BTRFS_TEST_DEV_BYTES_USED.to_le_bytes());
    region[0x80..0x88].copy_from_slice(&5_u64.to_le_bytes());
    region[0x88..0x90].copy_from_slice(&1_u64.to_le_bytes());
    region[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
    region[0x94..0x98].copy_from_slice(&16_384_u32.to_le_bytes());
    region[0x9C..0xA0].copy_from_slice(&4096_u32.to_le_bytes());
    region[0xA0..0xA4].copy_from_slice(&sys_chunk_array_size.to_le_bytes());
    region[0xC4..0xC6].copy_from_slice(&BTRFS_CSUM_TYPE_CRC32C.to_le_bytes());
    region[0xC6] = 0;
    region[0xC7] = 0;
    region[0xC8] = 0;
    region[0x12B..0x13A].copy_from_slice(b"ffs-adversarial");
    region[sys_chunk_array_offset..sys_chunk_array_end].copy_from_slice(sys_chunk_array);

    region
}

fn minimal_valid_btrfs_image(superblock_region: &[u8]) -> Vec<u8> {
    let mut image = vec![0_u8; BTRFS_TEST_MAX_SAMPLE_SIZE];
    let end = BTRFS_SUPER_INFO_OFFSET + BTRFS_SUPER_INFO_SIZE;
    image[BTRFS_SUPER_INFO_OFFSET..end].copy_from_slice(superblock_region);
    image
}

fn btrfs_superblock_adversarial_samples() -> Vec<(String, Vec<u8>)> {
    let sys_chunk_array = make_btrfs_sys_chunk(
        BTRFS_TEST_CHUNK_LENGTH,
        4096,
        BTRFS_TEST_BLOCK_GROUP_SYSTEM,
        1,
    );
    let valid_region = minimal_valid_btrfs_superblock_region(&sys_chunk_array);
    let mut samples = Vec::new();

    samples.push((
        "synthetic_btrfs_superblock_valid_region.bin".to_owned(),
        valid_region.clone(),
    ));

    let mut bad_magic = valid_region.clone();
    bad_magic[0x40..0x48].copy_from_slice(&0xFEED_FACE_CAFE_BEEFu64.to_le_bytes());
    samples.push((
        "synthetic_btrfs_superblock_bad_magic.bin".to_owned(),
        bad_magic,
    ));

    let mut zero_sectorsize = valid_region.clone();
    zero_sectorsize[0x90..0x94].copy_from_slice(&0_u32.to_le_bytes());
    samples.push((
        "synthetic_btrfs_superblock_zero_sectorsize.bin".to_owned(),
        zero_sectorsize,
    ));

    let mut non_power_nodesize = valid_region.clone();
    non_power_nodesize[0x94..0x98].copy_from_slice(&12_288_u32.to_le_bytes());
    samples.push((
        "synthetic_btrfs_superblock_non_power_nodesize.bin".to_owned(),
        non_power_nodesize,
    ));

    let mut bad_stripesize = valid_region.clone();
    bad_stripesize[0x9C..0xA0].copy_from_slice(&12_288_u32.to_le_bytes());
    samples.push((
        "synthetic_btrfs_superblock_bad_stripesize.bin".to_owned(),
        bad_stripesize,
    ));

    let mut zero_total_bytes = valid_region.clone();
    zero_total_bytes[0x70..0x78].copy_from_slice(&0_u64.to_le_bytes());
    zero_total_bytes[0x78..0x80].copy_from_slice(&0_u64.to_le_bytes());
    samples.push((
        "synthetic_btrfs_superblock_zero_total_bytes.bin".to_owned(),
        zero_total_bytes,
    ));

    let mut overused = valid_region.clone();
    overused[0x78..0x80].copy_from_slice(&(BTRFS_TEST_DEV_TOTAL_BYTES + 1).to_le_bytes());
    samples.push((
        "synthetic_btrfs_superblock_bytes_used_exceeds_total.bin".to_owned(),
        overused,
    ));

    let mut zero_devices = valid_region.clone();
    zero_devices[0x88..0x90].copy_from_slice(&0_u64.to_le_bytes());
    samples.push((
        "synthetic_btrfs_superblock_zero_num_devices.bin".to_owned(),
        zero_devices,
    ));

    let mut oversized_sys_chunk_array = valid_region.clone();
    oversized_sys_chunk_array[0xA0..0xA4].copy_from_slice(&2049_u32.to_le_bytes());
    samples.push((
        "synthetic_btrfs_superblock_oversized_sys_chunk_array.bin".to_owned(),
        oversized_sys_chunk_array,
    ));

    let mut short_region = valid_region.clone();
    short_region.truncate(BTRFS_SUPER_INFO_SIZE - 1);
    samples.push((
        "synthetic_btrfs_superblock_short_region.bin".to_owned(),
        short_region,
    ));

    samples.push((
        "synthetic_btrfs_superblock_valid_image.bin".to_owned(),
        minimal_valid_btrfs_image(&valid_region),
    ));

    let mut short_image = minimal_valid_btrfs_image(&valid_region);
    short_image.truncate(BTRFS_TEST_MAX_SAMPLE_SIZE - 1);
    samples.push((
        "synthetic_btrfs_superblock_short_image.bin".to_owned(),
        short_image,
    ));

    samples
}

fn run_parser<T, F>(
    _sample_name: &str,
    parser_name: &'static str,
    parser_hits: &mut BTreeMap<&'static str, u32>,
    coverage: &mut ErrorCoverage,
    parser: F,
) -> bool
where
    F: FnOnce() -> Result<T, ParseError>,
{
    *parser_hits.entry(parser_name).or_default() += 1;
    match catch_unwind(AssertUnwindSafe(parser)) {
        Ok(Ok(_)) => false,
        Ok(Err(err)) => {
            coverage.observe(&err);
            true
        }
        Err(panic_payload) => {
            std::panic::resume_unwind(panic_payload);
        }
    }
}

fn run_dir_iter(block: &[u8], block_size: u32) -> Result<(), ParseError> {
    let mut iter = iter_dir_block(block, block_size);
    for _ in 0..64 {
        match iter.next() {
            Some(Ok(_)) => {}
            Some(Err(err)) => return Err(err),
            None => return Ok(()),
        }
    }
    Ok(())
}

fn minimal_valid_ext4_superblock() -> Ext4Superblock {
    let sb = minimal_valid_ext4_superblock_bytes();
    Ext4Superblock::parse_superblock_region(&sb).expect("valid ext4 superblock")
}

fn minimal_valid_ext4_superblock_bytes() -> [u8; EXT4_SUPERBLOCK_SIZE] {
    let mut sb = [0_u8; EXT4_SUPERBLOCK_SIZE];
    sb[0x38..0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
    sb[0x18..0x1C].copy_from_slice(&2_u32.to_le_bytes()); // log_block_size=2 -> 4K
    sb[0x1C..0x20].copy_from_slice(&2_u32.to_le_bytes()); // log_cluster_size=2 -> 4K
    sb[0x00..0x04].copy_from_slice(&8192_u32.to_le_bytes()); // inodes_count
    sb[0x04..0x08].copy_from_slice(&32768_u32.to_le_bytes()); // blocks_count_lo
    sb[0x14..0x18].copy_from_slice(&0_u32.to_le_bytes()); // first_data_block
    sb[0x20..0x24].copy_from_slice(&32768_u32.to_le_bytes()); // blocks_per_group
    sb[0x24..0x28].copy_from_slice(&32768_u32.to_le_bytes()); // clusters_per_group
    sb[0x28..0x2C].copy_from_slice(&8192_u32.to_le_bytes()); // inodes_per_group
    sb[0x58..0x5A].copy_from_slice(&256_u16.to_le_bytes()); // inode_size
    sb
}

fn stamp_ext4_superblock_checksum(sb: &mut [u8; EXT4_SUPERBLOCK_SIZE]) {
    let ro_compat = Ext4RoCompatFeatures::METADATA_CSUM.0.to_le_bytes();
    sb[0x64..0x68].copy_from_slice(&ro_compat);
    let checksum = ext4_chksum(!0_u32, &sb[..EXT4_SB_CHECKSUM_OFFSET]);
    sb[EXT4_SB_CHECKSUM_OFFSET..EXT4_SB_CHECKSUM_OFFSET + 4]
        .copy_from_slice(&checksum.to_le_bytes());
}

fn ext4_superblock_image(region: &[u8; EXT4_SUPERBLOCK_SIZE]) -> Vec<u8> {
    let mut image = vec![0_u8; EXT4_SUPERBLOCK_OFFSET];
    image.extend_from_slice(region);
    image
}

fn ext4_superblock_adversarial_samples() -> Vec<(String, Vec<u8>)> {
    let mut valid_region = minimal_valid_ext4_superblock_bytes();
    valid_region[0x78..0x83].copy_from_slice(b"ffs-ext4-sb");
    valid_region[0xEC..0xF0].copy_from_slice(&0x0123_4567_u32.to_le_bytes());
    valid_region[0xF0..0xF4].copy_from_slice(&0x89AB_CDEF_u32.to_le_bytes());
    stamp_ext4_superblock_checksum(&mut valid_region);

    let valid_image = ext4_superblock_image(&valid_region);

    let mut bad_magic = valid_region;
    bad_magic[0x38..0x3A].copy_from_slice(&0x1234_u16.to_le_bytes());

    let mut unsupported_block_size = valid_region;
    unsupported_block_size[0x18..0x1C].copy_from_slice(&3_u32.to_le_bytes());
    stamp_ext4_superblock_checksum(&mut unsupported_block_size);

    let mut invalid_cluster_shift = valid_region;
    invalid_cluster_shift[0x1C..0x20].copy_from_slice(&22_u32.to_le_bytes());
    stamp_ext4_superblock_checksum(&mut invalid_cluster_shift);

    let mut checksum_corrupt = valid_region;
    checksum_corrupt[EXT4_SB_CHECKSUM_OFFSET] ^= 0x80;

    let mut zero_blocks_per_group = valid_region;
    zero_blocks_per_group[0x20..0x24].copy_from_slice(&0_u32.to_le_bytes());
    stamp_ext4_superblock_checksum(&mut zero_blocks_per_group);

    let mut inode_size_not_power_two = valid_region;
    inode_size_not_power_two[0x58..0x5A].copy_from_slice(&192_u16.to_le_bytes());
    stamp_ext4_superblock_checksum(&mut inode_size_not_power_two);

    let mut wrong_first_data_block_1k = valid_region;
    wrong_first_data_block_1k[0x18..0x1C].copy_from_slice(&0_u32.to_le_bytes());
    wrong_first_data_block_1k[0x1C..0x20].copy_from_slice(&0_u32.to_le_bytes());
    wrong_first_data_block_1k[0x04..0x08].copy_from_slice(&16_384_u32.to_le_bytes());
    wrong_first_data_block_1k[0x20..0x24].copy_from_slice(&8192_u32.to_le_bytes());
    wrong_first_data_block_1k[0x24..0x28].copy_from_slice(&8192_u32.to_le_bytes());
    wrong_first_data_block_1k[0x14..0x18].copy_from_slice(&0_u32.to_le_bytes());
    stamp_ext4_superblock_checksum(&mut wrong_first_data_block_1k);

    let short_region = valid_region[..EXT4_SUPERBLOCK_SIZE - 1].to_vec();
    let short_image = ext4_superblock_image(&valid_region)
        [..EXT4_SUPERBLOCK_OFFSET + EXT4_SUPERBLOCK_SIZE - 1]
        .to_vec();

    vec![
        (
            "synthetic_ext4_superblock_valid_region.bin".to_owned(),
            valid_region.to_vec(),
        ),
        (
            "synthetic_ext4_superblock_valid_image.bin".to_owned(),
            valid_image,
        ),
        (
            "synthetic_ext4_superblock_bad_magic.bin".to_owned(),
            bad_magic.to_vec(),
        ),
        (
            "synthetic_ext4_superblock_unsupported_block_size.bin".to_owned(),
            unsupported_block_size.to_vec(),
        ),
        (
            "synthetic_ext4_superblock_invalid_cluster_shift.bin".to_owned(),
            invalid_cluster_shift.to_vec(),
        ),
        (
            "synthetic_ext4_superblock_checksum_corrupt.bin".to_owned(),
            checksum_corrupt.to_vec(),
        ),
        (
            "synthetic_ext4_superblock_zero_blocks_per_group.bin".to_owned(),
            zero_blocks_per_group.to_vec(),
        ),
        (
            "synthetic_ext4_superblock_inode_size_not_power_two.bin".to_owned(),
            inode_size_not_power_two.to_vec(),
        ),
        (
            "synthetic_ext4_superblock_wrong_first_data_block_1k.bin".to_owned(),
            wrong_first_data_block_1k.to_vec(),
        ),
        (
            "synthetic_ext4_superblock_short_region.bin".to_owned(),
            short_region,
        ),
        (
            "synthetic_ext4_superblock_short_image.bin".to_owned(),
            short_image,
        ),
    ]
}

const EXT4_TEST_DIR_BLOCK_SIZE: usize = 4096;
const EXT4_TEST_DIR_CSUM_SEED: u32 = 0xC0DE_CAFE;
const EXT4_TEST_DIR_GENERATION: u32 = 0x0102_0304;
const EXT4_TEST_DIR_INODE: u32 = 2;
const EXT4_TEST_GROUP_DESC_CSUM_SEED: u32 = 0xAABB_CCDD;
const EXT4_TEST_GROUP_DESC_NUMBER: u32 = 7;
const EXT4_TEST_GROUP_DESC_UUID: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
const EXT4_TEST_INODE_CHECKSUM_LO_OFFSET: usize = 0x7C;
const EXT4_TEST_INODE_CHECKSUM_HI_OFFSET: usize = 0x82;
const EXT4_TEST_INODE_CSUM_SEED: u32 = 0x3141_5926;
const EXT4_TEST_INODE_NUMBER: u32 = 11;
const EXT4_TEST_MMP_CHECKSUM_OFFSET: usize = 0x3FC;
const BTRFS_TEST_HEADER_SIZE: usize = 101;
const BTRFS_TEST_ITEM_SIZE: usize = 25;
const BTRFS_TEST_KEY_PTR_SIZE: usize = 33;
const BTRFS_TEST_DISK_KEY_SIZE: usize = 17;
const BTRFS_TEST_CHUNK_FIXED_SIZE: usize = 48;
const BTRFS_TEST_STRIPE_SIZE: usize = 32;
const BTRFS_TEST_DEV_ITEM_SIZE: usize = 98;
const BTRFS_TEST_CHUNK_TREE_OBJECTID: u64 = 256;
const BTRFS_TEST_CHUNK_ITEM_KEY: u8 = 228;
const BTRFS_TEST_CHUNK_LENGTH: u64 = 0x0010_0000;
const BTRFS_TEST_BLOCK_GROUP_SYSTEM: u64 = 1 << 1;
const BTRFS_TEST_BLOCK_GROUP_RAID0: u64 = 1 << 3;
const BTRFS_TEST_BLOCK_GROUP_RAID1: u64 = 1 << 4;
const BTRFS_TEST_DEV_TOTAL_BYTES: u64 = 1 << 40;
const BTRFS_TEST_DEV_BYTES_USED: u64 = 1 << 39;
const BTRFS_TEST_MAX_SAMPLE_SIZE: usize = BTRFS_SUPER_INFO_OFFSET + BTRFS_SUPER_INFO_SIZE;

fn align4(len: usize) -> usize {
    (len + 3) & !3
}

fn synth_valid_dir_block(
    seed_entries: &[(u32, u8, Vec<u8>)],
    include_tail: bool,
    tail_checksum: u32,
) -> Vec<u8> {
    let tail_len = if include_tail { 12 } else { 0 };
    let body_len = EXT4_TEST_DIR_BLOCK_SIZE - tail_len;

    let mut entries: Vec<(u32, u8, Vec<u8>, usize)> = Vec::new();
    let mut used = 0_usize;
    for (inode, file_type, raw_name) in seed_entries {
        let name = if raw_name.is_empty() {
            vec![b'x']
        } else {
            raw_name.clone()
        };
        let min_rec_len = align4(8 + name.len());
        if used + min_rec_len > body_len {
            break;
        }
        entries.push((*inode, *file_type, name, min_rec_len));
        used += min_rec_len;
    }

    if entries.is_empty() {
        entries.push((1, 1, vec![b'x'], body_len));
        used = body_len;
    } else if used < body_len {
        let slack = body_len - used;
        if let Some(last) = entries.last_mut() {
            last.3 += slack;
        }
        used = body_len;
    }

    debug_assert_eq!(used, body_len);

    let mut block = vec![0_u8; EXT4_TEST_DIR_BLOCK_SIZE];
    let mut offset = 0_usize;
    for (inode, file_type, name, rec_len) in &entries {
        let rec_len_u16 = u16::try_from(*rec_len).expect("dir rec_len fits in u16");
        let name_len_u8 = u8::try_from(name.len()).expect("name length is bounded");
        block[offset..offset + 4].copy_from_slice(&inode.to_le_bytes());
        block[offset + 4..offset + 6].copy_from_slice(&rec_len_u16.to_le_bytes());
        block[offset + 6] = name_len_u8;
        block[offset + 7] = *file_type;
        let name_end = offset + 8 + usize::from(name_len_u8);
        block[offset + 8..name_end].copy_from_slice(name);
        offset += usize::from(rec_len_u16);
    }

    if include_tail {
        block[offset..offset + 4].copy_from_slice(&0_u32.to_le_bytes());
        block[offset + 4..offset + 6].copy_from_slice(&12_u16.to_le_bytes());
        block[offset + 6] = 0;
        block[offset + 7] = 0xDE;
        block[offset + 8..offset + 12].copy_from_slice(&tail_checksum.to_le_bytes());
    }

    block
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn ext4_proptest_parse_from_image_matches_region_parse_for_valid_superblocks(
        log_block_size in 0_u32..=2,
        inodes_count in 1_u32..=500_000,
        blocks_count in 1_u32..=4_000_000,
        blocks_per_group in 1_u32..=131_072,
        inodes_per_group in 1_u32..=65_536,
        inode_size in prop_oneof![Just(128_u16), Just(256_u16), Just(512_u16)],
        volume_name in proptest::collection::vec(any::<u8>(), 0..=16),
        prefix in proptest::collection::vec(any::<u8>(), 1024..=1024),
        suffix in proptest::collection::vec(any::<u8>(), 0..=4096),
    ) {
        let mut sb = minimal_valid_ext4_superblock_bytes();
        sb[0x00..0x04].copy_from_slice(&inodes_count.to_le_bytes());
        sb[0x04..0x08].copy_from_slice(&blocks_count.to_le_bytes());
        sb[0x18..0x1C].copy_from_slice(&log_block_size.to_le_bytes());
        sb[0x1C..0x20].copy_from_slice(&log_block_size.to_le_bytes());
        sb[0x20..0x24].copy_from_slice(&blocks_per_group.to_le_bytes());
        sb[0x24..0x28].copy_from_slice(&blocks_per_group.to_le_bytes());
        sb[0x28..0x2C].copy_from_slice(&inodes_per_group.to_le_bytes());
        sb[0x58..0x5A].copy_from_slice(&inode_size.to_le_bytes());
        sb[0x78..0x88].fill(0);
        let volume_name_len = volume_name.len();
        sb[0x78..0x78 + volume_name_len].copy_from_slice(&volume_name);

        let from_region = Ext4Superblock::parse_superblock_region(&sb)
            .expect("structured superblock should parse");

        let mut image = prefix;
        image.extend_from_slice(&sb);
        image.extend_from_slice(&suffix);
        let from_image = Ext4Superblock::parse_from_image(&image)
            .expect("structured image should parse");

        prop_assert_eq!(from_image, from_region);
    }

    #[test]
    fn ext4_proptest_parse_dir_block_matches_iter_dir_block_on_synthesized_valid_blocks(
        seed_entries in proptest::collection::vec(
            (
                any::<u32>(),
                any::<u8>(),
                proptest::collection::vec(any::<u8>(), 0..=32),
            ),
            0..=64
        ),
        include_tail in any::<bool>(),
        tail_checksum in any::<u32>(),
    ) {
        let block = synth_valid_dir_block(&seed_entries, include_tail, tail_checksum);
        let (parsed_entries, parsed_tail) = parse_dir_block(
            &block,
            u32::try_from(EXT4_TEST_DIR_BLOCK_SIZE).expect("fixed block size fits in u32")
        ).expect("synthesized directory block should parse");

        let mut iter = iter_dir_block(
            &block,
            u32::try_from(EXT4_TEST_DIR_BLOCK_SIZE).expect("fixed block size fits in u32")
        );
        let iter_entries = iter
            .by_ref()
            .collect::<Result<Vec<_>, ParseError>>()
            .expect("iterator should parse synthesized block")
            .into_iter()
            .map(|entry| entry.to_owned())
            .collect::<Vec<_>>();
        let iter_tail = iter.checksum_tail();

        prop_assert_eq!(iter_entries, parsed_entries);
        prop_assert_eq!(iter_tail, parsed_tail);
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn adversarial_corpus_is_panic_free_and_exercises_parse_error_variants() {
    let samples = load_corpus_samples();
    let mut parser_hits = BTreeMap::new();
    let mut coverage = ErrorCoverage::default();

    for (name, bytes) in &samples {
        assert!(
            bytes.len() <= BTRFS_TEST_MAX_SAMPLE_SIZE,
            "sample `{name}` exceeds btrfs superblock image-size limit"
        );

        let mut sample_had_error = false;

        sample_had_error |= run_parser(
            name,
            "ext4_parse_superblock_region",
            &mut parser_hits,
            &mut coverage,
            || Ext4Superblock::parse_superblock_region(bytes),
        );
        sample_had_error |= run_parser(
            name,
            "ext4_parse_from_image",
            &mut parser_hits,
            &mut coverage,
            || Ext4Superblock::parse_from_image(bytes),
        );
        sample_had_error |= run_parser(
            name,
            "ext4_group_desc_parse",
            &mut parser_hits,
            &mut coverage,
            || Ext4GroupDesc::parse_from_bytes(bytes, 32),
        );
        sample_had_error |= run_parser(
            name,
            "ext4_inode_parse",
            &mut parser_hits,
            &mut coverage,
            || Ext4Inode::parse_from_bytes(bytes),
        );
        sample_had_error |= run_parser(
            name,
            "ext4_parse_ibody_xattrs",
            &mut parser_hits,
            &mut coverage,
            || {
                let inode = Ext4Inode::parse_from_bytes(bytes)?;
                parse_ibody_xattrs(&inode)
            },
        );
        sample_had_error |= run_parser(
            name,
            "ext4_parse_extent_tree",
            &mut parser_hits,
            &mut coverage,
            || parse_extent_tree(bytes),
        );
        sample_had_error |= run_parser(
            name,
            "ext4_parse_dir_block",
            &mut parser_hits,
            &mut coverage,
            || parse_dir_block(bytes, 4096),
        );
        sample_had_error |= run_parser(
            name,
            "ext4_iter_dir_block",
            &mut parser_hits,
            &mut coverage,
            || run_dir_iter(bytes, 4096),
        );
        sample_had_error |= run_parser(
            name,
            "ext4_parse_dx_root",
            &mut parser_hits,
            &mut coverage,
            || parse_dx_root(bytes),
        );
        sample_had_error |= run_parser(
            name,
            "ext4_parse_xattr_block",
            &mut parser_hits,
            &mut coverage,
            || parse_xattr_block(bytes),
        );
        sample_had_error |= run_parser(
            name,
            "ext4_parse_mmp_block",
            &mut parser_hits,
            &mut coverage,
            || Ext4MmpBlock::parse_from_bytes(bytes),
        );
        sample_had_error |= run_parser(
            name,
            "ext4_verify_group_desc_checksum",
            &mut parser_hits,
            &mut coverage,
            || {
                verify_group_desc_checksum(
                    bytes,
                    &EXT4_TEST_GROUP_DESC_UUID,
                    0,
                    0,
                    32,
                    Ext4GroupDescChecksumKind::MetadataCsum,
                )
            },
        );
        sample_had_error |= run_parser(
            name,
            "ext4_verify_inode_checksum",
            &mut parser_hits,
            &mut coverage,
            || verify_inode_checksum(bytes, 0, 2, 256),
        );
        sample_had_error |= run_parser(
            name,
            "ext4_verify_dir_block_checksum",
            &mut parser_hits,
            &mut coverage,
            || verify_dir_block_checksum(bytes, 0, 2, 0),
        );
        sample_had_error |= run_parser(
            name,
            "ext4_verify_extent_block_checksum",
            &mut parser_hits,
            &mut coverage,
            || verify_extent_block_checksum(bytes, 0, 2, 0),
        );

        sample_had_error |= run_parser(
            name,
            "btrfs_parse_superblock_region",
            &mut parser_hits,
            &mut coverage,
            || BtrfsSuperblock::parse_superblock_region(bytes),
        );
        sample_had_error |= run_parser(
            name,
            "btrfs_parse_from_image",
            &mut parser_hits,
            &mut coverage,
            || BtrfsSuperblock::parse_from_image(bytes),
        );
        sample_had_error |= run_parser(
            name,
            "btrfs_parse_sys_chunk_array",
            &mut parser_hits,
            &mut coverage,
            || parse_sys_chunk_array(bytes),
        );
        sample_had_error |= run_parser(
            name,
            "btrfs_map_logical_to_physical",
            &mut parser_hits,
            &mut coverage,
            || {
                let chunks = parse_sys_chunk_array(bytes)?;
                let _ = map_logical_to_physical(&chunks, u64::MAX)?;
                Ok(())
            },
        );
        sample_had_error |= run_parser(
            name,
            "btrfs_header_parse",
            &mut parser_hits,
            &mut coverage,
            || BtrfsHeader::parse_from_block(bytes),
        );
        sample_had_error |= run_parser(
            name,
            "btrfs_header_validate",
            &mut parser_hits,
            &mut coverage,
            || {
                let header = BtrfsHeader::parse_from_block(bytes)?;
                header.validate(bytes.len(), Some(0))
            },
        );
        sample_had_error |= run_parser(
            name,
            "btrfs_parse_leaf_items",
            &mut parser_hits,
            &mut coverage,
            || parse_leaf_items(bytes),
        );
        sample_had_error |= run_parser(
            name,
            "btrfs_parse_internal_items",
            &mut parser_hits,
            &mut coverage,
            || parse_internal_items(bytes),
        );
        sample_had_error |= run_parser(
            name,
            "btrfs_parse_dev_item",
            &mut parser_hits,
            &mut coverage,
            || parse_dev_item(bytes),
        );
        sample_had_error |= run_parser(
            name,
            "btrfs_verify_superblock_checksum",
            &mut parser_hits,
            &mut coverage,
            || verify_btrfs_superblock_checksum(bytes),
        );
        sample_had_error |= run_parser(
            name,
            "btrfs_verify_tree_block_checksum_crc32c",
            &mut parser_hits,
            &mut coverage,
            || verify_btrfs_tree_block_checksum(bytes, BTRFS_CSUM_TYPE_CRC32C),
        );
        sample_had_error |= run_parser(
            name,
            "btrfs_verify_tree_block_checksum_bad_type",
            &mut parser_hits,
            &mut coverage,
            || verify_btrfs_tree_block_checksum(bytes, 999),
        );

        assert!(
            sample_had_error,
            "sample `{name}` produced no parser errors across the adversarial harness"
        );
    }

    // Explicitly force IntegerConversion coverage through read_inode_data's
    // logical block cast (u64 -> u32).
    let mut inode = Ext4Inode::parse_from_bytes(&[0_u8; 128]).expect("minimal inode parses");
    let reader = Ext4ImageReader {
        sb: minimal_valid_ext4_superblock(),
    };
    let overflow_offset = (u64::from(u32::MAX) + 1) * u64::from(reader.sb.block_size);
    inode.size = overflow_offset + 1;
    let mut one_byte = [0_u8; 1];
    let err = reader
        .read_inode_data(&[], &inode, overflow_offset, &mut one_byte)
        .expect_err("forced logical_block conversion should fail");
    coverage.observe(&err);
    assert!(matches!(
        err,
        ParseError::IntegerConversion {
            field: "logical_block"
        }
    ));

    assert!(
        coverage.insufficient_data > 0,
        "expected InsufficientData coverage from adversarial corpus"
    );
    assert!(
        coverage.invalid_magic > 0,
        "expected InvalidMagic coverage from adversarial corpus"
    );
    assert!(
        coverage.invalid_field > 0,
        "expected InvalidField coverage from adversarial corpus"
    );
    assert!(
        coverage.integer_conversion > 0,
        "expected IntegerConversion coverage"
    );

    assert!(
        parser_hits.len() >= 20,
        "expected broad parser coverage, got only {} parser entry points",
        parser_hits.len()
    );
}

#[test]
fn ext4_inline_data_adversarial_samples_exercise_ibody_boundaries() {
    let samples = inline_data_adversarial_samples()
        .into_iter()
        .collect::<BTreeMap<_, _>>();

    let extra_isize_overflow = Ext4Inode::parse_from_bytes(
        &samples["synthetic_ext4_inline_data_extra_isize_overflow.bin"],
    )
    .expect_err("oversized i_extra_isize must be rejected");
    assert!(matches!(
        extra_isize_overflow,
        ParseError::InvalidField {
            field: "i_extra_isize",
            ..
        }
    ));

    let name_overflow =
        Ext4Inode::parse_from_bytes(&samples["synthetic_ext4_inline_data_ibody_name_overflow.bin"])
            .expect("inode with malformed ibody entry still parses");
    let name_err =
        parse_ibody_xattrs(&name_overflow).expect_err("xattr name overflow must be rejected");
    assert!(matches!(
        name_err,
        ParseError::InvalidField {
            field: "xattr_name",
            ..
        }
    ));

    let value_overflow = Ext4Inode::parse_from_bytes(
        &samples["synthetic_ext4_inline_data_ibody_value_overflow.bin"],
    )
    .expect("inode with malformed ibody value still parses");
    let value_err =
        parse_ibody_xattrs(&value_overflow).expect_err("xattr value overflow must be rejected");
    assert!(matches!(
        value_err,
        ParseError::InvalidField {
            field: "xattr_value",
            ..
        }
    ));

    let magic_only =
        Ext4Inode::parse_from_bytes(&samples["synthetic_ext4_inline_data_ibody_magic_only.bin"])
            .expect("magic-only ibody inode parses");
    assert_eq!(
        parse_ibody_xattrs(&magic_only)
            .expect("magic-only ibody xattr area is empty"), [] as [ffs_ondisk::Ext4Xattr; 0]
    );

    let valid_ibody =
        Ext4Inode::parse_from_bytes(&samples["synthetic_ext4_inline_data_ibody_valid_xattr.bin"])
            .expect("valid ibody xattr inode parses");
    let xattrs = parse_ibody_xattrs(&valid_ibody).expect("valid ibody xattr parses");
    assert_eq!(xattrs.len(), 1);
    assert_eq!(xattrs[0].full_name(), "user.seed");
    assert_eq!(xattrs[0].value, b"fuzz!");
}

#[test]
fn ext4_inode_checksum_adversarial_samples_exercise_boundaries() {
    let samples = inode_checksum_adversarial_samples()
        .into_iter()
        .collect::<BTreeMap<_, _>>();

    assert_valid_ext4_inode_checksum_samples(&samples);
    assert_invalid_ext4_inode_checksum_samples(&samples);
}

fn assert_valid_ext4_inode_checksum_samples(samples: &BTreeMap<String, Vec<u8>>) {
    let valid132 = &samples["synthetic_ext4_inode_checksum_valid_132.bin"];
    verify_inode_checksum(
        valid132,
        EXT4_TEST_INODE_CSUM_SEED,
        EXT4_TEST_INODE_NUMBER,
        132,
    )
    .expect("132-byte inode checksum with high half verifies");

    let inode132 =
        Ext4Inode::parse_from_bytes(valid132).expect("valid 132-byte checksum inode parses");
    assert_eq!(inode132.generation, 42);
    assert_eq!(inode132.extra_isize, 4);

    let valid256 = &samples["synthetic_ext4_inode_checksum_valid_256.bin"];
    verify_inode_checksum(
        valid256,
        EXT4_TEST_INODE_CSUM_SEED,
        EXT4_TEST_INODE_NUMBER,
        256,
    )
    .expect("256-byte inode checksum with high half verifies");

    let inode256 =
        Ext4Inode::parse_from_bytes(valid256).expect("valid 256-byte checksum inode parses");
    assert_eq!(inode256.generation, 42);
    assert_eq!(inode256.extra_isize, 32);
    assert_ne!(inode256.checksum, 0);
    assert_eq!(inode256.version_hi, 0x0102_0304);
}

fn assert_invalid_ext4_inode_checksum_samples(samples: &BTreeMap<String, Vec<u8>>) {
    let bad_checksum = verify_inode_checksum(
        &samples["synthetic_ext4_inode_checksum_bad_checksum.bin"],
        EXT4_TEST_INODE_CSUM_SEED,
        EXT4_TEST_INODE_NUMBER,
        256,
    )
    .expect_err("inode checksum field corruption must be rejected");
    assert!(matches!(
        bad_checksum,
        ParseError::InvalidField {
            field: "i_checksum",
            ..
        }
    ));

    let covered_byte = verify_inode_checksum(
        &samples["synthetic_ext4_inode_checksum_covered_byte_corrupt.bin"],
        EXT4_TEST_INODE_CSUM_SEED,
        EXT4_TEST_INODE_NUMBER,
        256,
    )
    .expect_err("covered inode byte corruption must be rejected");
    assert!(matches!(
        covered_byte,
        ParseError::InvalidField {
            field: "i_checksum",
            ..
        }
    ));

    let wrong_ino = verify_inode_checksum(
        &samples["synthetic_ext4_inode_checksum_valid_256.bin"],
        EXT4_TEST_INODE_CSUM_SEED,
        EXT4_TEST_INODE_NUMBER + 1,
        256,
    )
    .expect_err("wrong inode-number checksum seed must be rejected");
    assert!(matches!(
        wrong_ino,
        ParseError::InvalidField {
            field: "i_checksum",
            ..
        }
    ));

    let short256 = verify_inode_checksum(
        &samples["synthetic_ext4_inode_checksum_short_256.bin"],
        EXT4_TEST_INODE_CSUM_SEED,
        EXT4_TEST_INODE_NUMBER,
        256,
    )
    .expect_err("short inode checksum buffer must be rejected");
    assert!(matches!(
        short256,
        ParseError::InsufficientData {
            needed: 256,
            offset: 0,
            actual: 255,
        }
    ));

    let size_too_small = verify_inode_checksum(
        &samples["synthetic_ext4_inode_checksum_inode_size_too_small.bin"],
        EXT4_TEST_INODE_CSUM_SEED,
        EXT4_TEST_INODE_NUMBER,
        64,
    )
    .expect_err("inode sizes below the 128-byte minimum must be rejected");
    assert!(matches!(
        size_too_small,
        ParseError::InsufficientData {
            needed: 128,
            offset: 0,
            actual: 128,
        }
    ));
}

#[test]
fn ext4_xattr_block_adversarial_samples_exercise_boundaries() {
    let samples = xattr_block_adversarial_samples()
        .into_iter()
        .collect::<BTreeMap<_, _>>();

    let bad_magic = parse_xattr_block(&samples["synthetic_ext4_xattr_block_bad_magic.bin"])
        .expect_err("bad xattr block magic must be rejected");
    assert!(matches!(bad_magic, ParseError::InvalidMagic { .. }));

    let header_only = parse_xattr_block(&samples["synthetic_ext4_xattr_block_header_only.bin"])
        .expect("header-only xattr block parses as empty");
    assert_eq!(header_only, [] as [ffs_ondisk::Ext4Xattr; 0]);

    let name_err = parse_xattr_block(&samples["synthetic_ext4_xattr_block_name_overflow.bin"])
        .expect_err("xattr block name overflow must be rejected");
    assert!(matches!(
        name_err,
        ParseError::InvalidField {
            field: "xattr_name",
            ..
        }
    ));

    let value_err = parse_xattr_block(&samples["synthetic_ext4_xattr_block_value_overflow.bin"])
        .expect_err("xattr block value overflow must be rejected");
    assert!(matches!(
        value_err,
        ParseError::InvalidField {
            field: "xattr_value",
            ..
        }
    ));

    let xattrs = parse_xattr_block(&samples["synthetic_ext4_xattr_block_valid_user_attr.bin"])
        .expect("valid xattr block parses");
    assert_eq!(xattrs.len(), 1);
    assert_eq!(xattrs[0].full_name(), "user.seed");
    assert_eq!(xattrs[0].value, b"block");
}

#[test]
fn ext4_dir_block_adversarial_samples_exercise_boundaries() {
    let samples = dir_block_adversarial_samples()
        .into_iter()
        .collect::<BTreeMap<_, _>>();

    let valid = &samples["synthetic_ext4_dir_block_valid_tail.bin"];
    let (entries, tail) = parse_dir_block(
        valid,
        u32::try_from(EXT4_TEST_DIR_BLOCK_SIZE).expect("fixed block size fits in u32"),
    )
    .expect("valid synthetic dir block parses");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].name, b".");
    assert_eq!(entries[1].name, b"..");
    assert_eq!(entries[2].name, b"file");
    assert_eq!(
        tail.expect("valid synthetic dir block carries a checksum tail")
            .checksum,
        0xA5A5_5A5A
    );

    let mut iter = iter_dir_block(
        valid,
        u32::try_from(EXT4_TEST_DIR_BLOCK_SIZE).expect("fixed block size fits in u32"),
    );
    let iter_entries = iter
        .by_ref()
        .collect::<Result<Vec<_>, ParseError>>()
        .expect("iterator parses valid synthetic dir block")
        .into_iter()
        .map(|entry| entry.to_owned())
        .collect::<Vec<_>>();
    assert_eq!(iter_entries, entries);
    assert_eq!(
        iter.checksum_tail()
            .expect("iterator captures checksum tail")
            .checksum,
        0xA5A5_5A5A
    );

    assert_valid_ext4_dir_checksum_samples(&samples);
    assert_invalid_ext4_dir_checksum_samples(&samples);

    let rec_len_too_small = parse_dir_block(
        &samples["synthetic_ext4_dir_block_rec_len_too_small.bin"],
        4096,
    )
    .expect_err("short rec_len must be rejected");
    assert!(matches!(
        rec_len_too_small,
        ParseError::InvalidField {
            field: "de_rec_len",
            ..
        }
    ));

    let rec_len_unaligned = parse_dir_block(
        &samples["synthetic_ext4_dir_block_rec_len_unaligned.bin"],
        4096,
    )
    .expect_err("unaligned rec_len must be rejected");
    assert!(matches!(
        rec_len_unaligned,
        ParseError::InvalidField {
            field: "de_rec_len",
            ..
        }
    ));

    let rec_len_past_end = parse_dir_block(
        &samples["synthetic_ext4_dir_block_rec_len_past_end.bin"],
        4096,
    )
    .expect_err("rec_len past block end must be rejected");
    assert!(matches!(
        rec_len_past_end,
        ParseError::InvalidField {
            field: "de_rec_len",
            ..
        }
    ));

    let name_overflow =
        parse_dir_block(&samples["synthetic_ext4_dir_block_name_overflow.bin"], 4096)
            .expect_err("name past rec_len must be rejected");
    assert!(matches!(
        name_overflow,
        ParseError::InvalidField {
            field: "de_name_len",
            ..
        }
    ));

    let tail_padding = parse_dir_block(
        &samples["synthetic_ext4_dir_block_tail_nonzero_padding.bin"],
        4096,
    )
    .expect_err("nonzero bytes after checksum tail must be rejected");
    assert!(matches!(
        tail_padding,
        ParseError::InvalidField {
            field: "dir_block_tail",
            ..
        }
    ));
}

fn assert_valid_ext4_dir_checksum_samples(samples: &BTreeMap<String, Vec<u8>>) {
    let valid = &samples["synthetic_ext4_dir_block_checksum_valid.bin"];
    verify_dir_block_checksum(
        valid,
        EXT4_TEST_DIR_CSUM_SEED,
        EXT4_TEST_DIR_INODE,
        EXT4_TEST_DIR_GENERATION,
    )
    .expect("stamped directory block checksum verifies");

    let (entries, tail) = parse_dir_block(
        valid,
        u32::try_from(EXT4_TEST_DIR_BLOCK_SIZE).expect("fixed block size fits in u32"),
    )
    .expect("checksum-valid synthetic dir block parses");
    assert_eq!(entries.len(), 3);
    let tail = tail.expect("checksum-valid synthetic dir block carries a tail");
    assert_ne!(tail.checksum, 0);
}

fn assert_invalid_ext4_dir_checksum_samples(samples: &BTreeMap<String, Vec<u8>>) {
    let checksum_corrupt = verify_dir_block_checksum(
        &samples["synthetic_ext4_dir_block_checksum_corrupt.bin"],
        EXT4_TEST_DIR_CSUM_SEED,
        EXT4_TEST_DIR_INODE,
        EXT4_TEST_DIR_GENERATION,
    )
    .expect_err("directory checksum field corruption must be rejected");
    assert!(matches!(
        checksum_corrupt,
        ParseError::InvalidField {
            field: "dir_checksum",
            ..
        }
    ));

    let covered_byte_corrupt = verify_dir_block_checksum(
        &samples["synthetic_ext4_dir_block_checksum_covered_byte_corrupt.bin"],
        EXT4_TEST_DIR_CSUM_SEED,
        EXT4_TEST_DIR_INODE,
        EXT4_TEST_DIR_GENERATION,
    )
    .expect_err("covered directory-entry byte corruption must be rejected");
    assert!(matches!(
        covered_byte_corrupt,
        ParseError::InvalidField {
            field: "dir_checksum",
            ..
        }
    ));

    let wrong_ino = verify_dir_block_checksum(
        &samples["synthetic_ext4_dir_block_checksum_valid.bin"],
        EXT4_TEST_DIR_CSUM_SEED,
        EXT4_TEST_DIR_INODE + 1,
        EXT4_TEST_DIR_GENERATION,
    )
    .expect_err("wrong directory inode checksum seed must be rejected");
    assert!(matches!(
        wrong_ino,
        ParseError::InvalidField {
            field: "dir_checksum",
            ..
        }
    ));

    let wrong_generation = verify_dir_block_checksum(
        &samples["synthetic_ext4_dir_block_checksum_valid.bin"],
        EXT4_TEST_DIR_CSUM_SEED,
        EXT4_TEST_DIR_INODE,
        EXT4_TEST_DIR_GENERATION + 1,
    )
    .expect_err("wrong directory generation checksum seed must be rejected");
    assert!(matches!(
        wrong_generation,
        ParseError::InvalidField {
            field: "dir_checksum",
            ..
        }
    ));

    let malformed_tail = verify_dir_block_checksum(
        &samples["synthetic_ext4_dir_block_checksum_malformed_tail.bin"],
        EXT4_TEST_DIR_CSUM_SEED,
        EXT4_TEST_DIR_INODE,
        EXT4_TEST_DIR_GENERATION,
    )
    .expect_err("malformed checksum tail must be rejected before CRC comparison");
    assert!(matches!(
        malformed_tail,
        ParseError::InvalidField {
            field: "dir_block_tail",
            ..
        }
    ));

    let too_small = verify_dir_block_checksum(
        &samples["synthetic_ext4_dir_block_checksum_too_small.bin"],
        EXT4_TEST_DIR_CSUM_SEED,
        EXT4_TEST_DIR_INODE,
        EXT4_TEST_DIR_GENERATION,
    )
    .expect_err("directory checksum blocks shorter than a tail must be rejected");
    assert!(matches!(
        too_small,
        ParseError::InsufficientData {
            needed: 12,
            offset: 0,
            actual: 11,
        }
    ));
}

#[test]
fn ext4_dx_root_adversarial_samples_exercise_boundaries() {
    let samples = dx_root_adversarial_samples()
        .into_iter()
        .collect::<BTreeMap<_, _>>();

    assert_valid_ext4_dx_root_samples(&samples);
    assert_invalid_ext4_dx_root_samples(&samples);
}

fn assert_valid_ext4_dx_root_samples(samples: &BTreeMap<String, Vec<u8>>) {
    let valid = parse_dx_root(&samples["synthetic_ext4_dx_root_valid.bin"])
        .expect("valid synthetic dx root parses");
    assert_eq!(valid.hash_version, 1);
    assert_eq!(valid.indirect_levels, 0);
    assert_eq!(valid.entries.len(), 3);
    assert_eq!(valid.entries[0].hash, 0);
    assert_eq!(valid.entries[0].block, 1);
    assert_eq!(valid.entries[1].hash, 0x1000);
    assert_eq!(valid.entries[1].block, 2);
    assert_eq!(valid.entries[2].hash, 0x8000);
    assert_eq!(valid.entries[2].block, 3);

    let unknown_hash = parse_dx_root(&samples["synthetic_ext4_dx_root_unknown_hash_version.bin"])
        .expect("unknown hash versions are preserved for dx_hash fallback handling");
    assert_eq!(unknown_hash.hash_version, 0xFF);
    assert_eq!(unknown_hash.entries.len(), 3);

    let zero_count = parse_dx_root(&samples["synthetic_ext4_dx_root_zero_count.bin"])
        .expect("zero-count dx root parses as an empty entry set");
    assert_eq!(zero_count.entries, [] as [ffs_ondisk::Ext4DxEntry; 0]);
}

fn assert_invalid_ext4_dx_root_samples(samples: &BTreeMap<String, Vec<u8>>) {
    let nonzero_reserved = parse_dx_root(&samples["synthetic_ext4_dx_root_nonzero_reserved.bin"])
        .expect_err("nonzero dx reserved field must be rejected");
    assert!(matches!(
        nonzero_reserved,
        ParseError::InvalidField {
            field: "dx_reserved_zero",
            ..
        }
    ));

    let bad_info_length = parse_dx_root(&samples["synthetic_ext4_dx_root_bad_info_length.bin"])
        .expect_err("bad dx root info length must be rejected");
    assert!(matches!(
        bad_info_length,
        ParseError::InvalidField {
            field: "dx_root_info_length",
            ..
        }
    ));

    let excessive_indirect_levels =
        parse_dx_root(&samples["synthetic_ext4_dx_root_excessive_indirect_levels.bin"])
            .expect_err("too many dx indirect levels must be rejected");
    assert!(matches!(
        excessive_indirect_levels,
        ParseError::InvalidField {
            field: "dx_indirect_levels",
            ..
        }
    ));

    let nonzero_unused_flags =
        parse_dx_root(&samples["synthetic_ext4_dx_root_nonzero_unused_flags.bin"])
            .expect_err("nonzero dx unused flags must be rejected");
    assert!(matches!(
        nonzero_unused_flags,
        ParseError::InvalidField {
            field: "dx_unused_flags",
            ..
        }
    ));

    let count_exceeds_limit =
        parse_dx_root(&samples["synthetic_ext4_dx_root_count_exceeds_limit.bin"])
            .expect_err("dx entry count exceeding limit must be rejected");
    assert!(matches!(
        count_exceeds_limit,
        ParseError::InvalidField {
            field: "dx_count",
            ..
        }
    ));

    let too_short = parse_dx_root(&samples["synthetic_ext4_dx_root_too_short.bin"])
        .expect_err("short dx root blocks must be rejected");
    assert!(matches!(
        too_short,
        ParseError::InsufficientData {
            needed: 0x28,
            offset: 0,
            actual: 0x27,
        }
    ));
}

#[test]
fn ext4_superblock_adversarial_samples_exercise_boundaries() {
    let samples = ext4_superblock_adversarial_samples()
        .into_iter()
        .collect::<BTreeMap<_, _>>();

    assert_valid_ext4_superblock_samples(&samples);
    assert_invalid_ext4_superblock_samples(&samples);
}

fn assert_valid_ext4_superblock_samples(samples: &BTreeMap<String, Vec<u8>>) -> Ext4Superblock {
    let valid = Ext4Superblock::parse_superblock_region(
        &samples["synthetic_ext4_superblock_valid_region.bin"],
    )
    .expect("valid synthetic ext4 superblock region parses");
    assert_eq!(valid.magic, EXT4_SUPER_MAGIC);
    assert_eq!(valid.block_size, 4096);
    assert_eq!(valid.cluster_size, 4096);
    assert_eq!(valid.inodes_count, 8192);
    assert_eq!(valid.blocks_count, 32768);
    assert_eq!(valid.blocks_per_group, 32768);
    assert_eq!(valid.inodes_per_group, 8192);
    assert_eq!(valid.inode_size, 256);
    assert_eq!(valid.volume_name, "ffs-ext4-sb");
    assert!(valid.has_metadata_csum());
    valid
        .validate_geometry()
        .expect("valid synthetic ext4 superblock geometry is accepted");
    valid
        .validate_checksum(&samples["synthetic_ext4_superblock_valid_region.bin"])
        .expect("stamped synthetic ext4 superblock checksum verifies");

    let from_image =
        Ext4Superblock::parse_from_image(&samples["synthetic_ext4_superblock_valid_image.bin"])
            .expect("valid synthetic ext4 image parses at the canonical offset");
    assert_eq!(from_image, valid);

    valid
}

fn assert_invalid_ext4_superblock_samples(samples: &BTreeMap<String, Vec<u8>>) {
    assert_invalid_ext4_superblock_parse_samples(samples);
    assert_invalid_ext4_superblock_checksum_samples(samples);
    assert_invalid_ext4_superblock_geometry_samples(samples);
    assert_short_ext4_superblock_samples(samples);
}

fn assert_invalid_ext4_superblock_parse_samples(samples: &BTreeMap<String, Vec<u8>>) {
    let bad_magic = Ext4Superblock::parse_superblock_region(
        &samples["synthetic_ext4_superblock_bad_magic.bin"],
    )
    .expect_err("bad ext4 superblock magic must be rejected");
    assert!(matches!(
        bad_magic,
        ParseError::InvalidMagic { expected, actual }
            if expected == u64::from(EXT4_SUPER_MAGIC) && actual == u64::from(0x1234_u16)
    ));

    let unsupported_block_size = Ext4Superblock::parse_superblock_region(
        &samples["synthetic_ext4_superblock_unsupported_block_size.bin"],
    )
    .expect_err("unsupported ext4 block sizes must be rejected");
    assert!(matches!(
        unsupported_block_size,
        ParseError::InvalidField {
            field: "s_log_block_size",
            reason: "unsupported block size",
        }
    ));

    let invalid_cluster_shift = Ext4Superblock::parse_superblock_region(
        &samples["synthetic_ext4_superblock_invalid_cluster_shift.bin"],
    )
    .expect_err("overflowing ext4 cluster-size shifts must be rejected");
    assert!(matches!(
        invalid_cluster_shift,
        ParseError::InvalidField {
            field: "s_log_cluster_size",
            reason: "invalid shift",
        }
    ));
}

fn assert_invalid_ext4_superblock_checksum_samples(samples: &BTreeMap<String, Vec<u8>>) {
    let checksum_corrupt = Ext4Superblock::parse_superblock_region(
        &samples["synthetic_ext4_superblock_checksum_corrupt.bin"],
    )
    .expect("checksum-corrupt ext4 superblock still parses before checksum validation");
    let checksum_err = checksum_corrupt
        .validate_checksum(&samples["synthetic_ext4_superblock_checksum_corrupt.bin"])
        .expect_err("corrupt ext4 superblock checksum must be rejected");
    assert!(matches!(
        checksum_err,
        ParseError::InvalidField {
            field: "s_checksum",
            ..
        }
    ));
}

fn assert_invalid_ext4_superblock_geometry_samples(samples: &BTreeMap<String, Vec<u8>>) {
    let zero_blocks = Ext4Superblock::parse_superblock_region(
        &samples["synthetic_ext4_superblock_zero_blocks_per_group.bin"],
    )
    .expect("zero blocks_per_group parses before geometry validation");
    let zero_blocks_err = zero_blocks
        .validate_geometry()
        .expect_err("zero blocks_per_group must be rejected by geometry validation");
    assert!(matches!(
        zero_blocks_err,
        ParseError::InvalidField {
            field: "s_blocks_per_group",
            ..
        }
    ));

    let inode_size = Ext4Superblock::parse_superblock_region(
        &samples["synthetic_ext4_superblock_inode_size_not_power_two.bin"],
    )
    .expect("non-power-of-two inode_size parses before geometry validation");
    let inode_size_err = inode_size
        .validate_geometry()
        .expect_err("non-power-of-two inode_size must be rejected by geometry validation");
    assert!(matches!(
        inode_size_err,
        ParseError::InvalidField {
            field: "s_inode_size",
            reason: "must be a power of two",
        }
    ));

    let wrong_first_data = Ext4Superblock::parse_superblock_region(
        &samples["synthetic_ext4_superblock_wrong_first_data_block_1k.bin"],
    )
    .expect("wrong 1K first_data_block parses before geometry validation");
    let wrong_first_data_err = wrong_first_data
        .validate_geometry()
        .expect_err("1K ext4 superblocks require first_data_block = 1");
    assert!(matches!(
        wrong_first_data_err,
        ParseError::InvalidField {
            field: "s_first_data_block",
            reason: "must be 1 for 1K block size",
        }
    ));
}

fn assert_short_ext4_superblock_samples(samples: &BTreeMap<String, Vec<u8>>) {
    let short_region = Ext4Superblock::parse_superblock_region(
        &samples["synthetic_ext4_superblock_short_region.bin"],
    )
    .expect_err("short ext4 superblock regions must be rejected");
    assert!(matches!(
        short_region,
        ParseError::InsufficientData {
            needed: EXT4_SUPERBLOCK_SIZE,
            offset: 0,
            actual,
        } if actual == EXT4_SUPERBLOCK_SIZE - 1
    ));

    let short_image =
        Ext4Superblock::parse_from_image(&samples["synthetic_ext4_superblock_short_image.bin"])
            .expect_err("short ext4 images must be rejected before slicing the superblock region");
    assert!(matches!(
        short_image,
        ParseError::InsufficientData {
            needed: EXT4_SUPERBLOCK_SIZE,
            offset: EXT4_SUPERBLOCK_OFFSET,
            actual,
        } if actual == EXT4_SUPERBLOCK_SIZE - 1
    ));
}

#[test]
fn ext4_extent_tree_adversarial_samples_exercise_boundaries() {
    let samples = extent_tree_adversarial_samples()
        .into_iter()
        .collect::<BTreeMap<_, _>>();

    let (leaf_header, leaf_tree) =
        parse_extent_tree(&samples["synthetic_ext4_extent_tree_valid_leaf.bin"])
            .expect("valid synthetic leaf extent tree parses");
    assert_eq!(leaf_header.entries, 2);
    assert_eq!(leaf_header.max_entries, 4);
    assert_eq!(leaf_header.depth, 0);
    assert_eq!(leaf_header.generation, 0x1010_2020);
    let ExtentTree::Leaf(extents) = leaf_tree else {
        std::panic::resume_unwind(Box::new("valid leaf sample must decode as a leaf tree"));
    };
    assert_eq!(extents.len(), 2);
    assert_eq!(extents[0].logical_block, 0);
    assert_eq!(extents[0].actual_len(), 4);
    assert!(!extents[0].is_unwritten());
    assert_eq!(extents[0].physical_start, 0x0001_0000_0010);
    assert_eq!(extents[1].logical_block, 8);
    assert_eq!(extents[1].actual_len(), 3);
    assert!(extents[1].is_unwritten());
    assert_eq!(extents[1].physical_start, 0x0001_0000_0040);

    let (index_header, index_tree) =
        parse_extent_tree(&samples["synthetic_ext4_extent_tree_valid_index.bin"])
            .expect("valid synthetic index extent tree parses");
    assert_eq!(index_header.entries, 2);
    assert_eq!(index_header.depth, 1);
    let ExtentTree::Index(indexes) = index_tree else {
        std::panic::resume_unwind(Box::new("valid index sample must decode as an index tree"));
    };
    assert_eq!(indexes.len(), 2);
    assert_eq!(indexes[0].logical_block, 0);
    assert_eq!(indexes[0].leaf_block, 0x0002_0000_0100);
    assert_eq!(indexes[1].logical_block, 64);
    assert_eq!(indexes[1].leaf_block, 0x0002_0000_0200);

    let bad_magic = parse_extent_tree(&samples["synthetic_ext4_extent_tree_bad_magic.bin"])
        .expect_err("bad extent magic must be rejected");
    assert!(matches!(bad_magic, ParseError::InvalidMagic { .. }));

    let entries_gt_max =
        parse_extent_tree(&samples["synthetic_ext4_extent_tree_entries_gt_max.bin"])
            .expect_err("extent entries greater than max must be rejected");
    assert!(matches!(
        entries_gt_max,
        ParseError::InvalidField {
            field: "eh_entries",
            ..
        }
    ));

    let truncated = parse_extent_tree(&samples["synthetic_ext4_extent_tree_truncated_entries.bin"])
        .expect_err("truncated extent entries must be rejected");
    assert!(matches!(truncated, ParseError::InsufficientData { .. }));

    let leaf_overlap = parse_extent_tree(&samples["synthetic_ext4_extent_tree_leaf_overlap.bin"])
        .expect_err("overlapping leaf extents must be rejected");
    assert!(matches!(
        leaf_overlap,
        ParseError::InvalidField {
            field: "extent_entries",
            ..
        }
    ));

    let index_unsorted =
        parse_extent_tree(&samples["synthetic_ext4_extent_tree_index_unsorted.bin"])
            .expect_err("unsorted index entries must be rejected");
    assert!(matches!(
        index_unsorted,
        ParseError::InvalidField {
            field: "extent_indexes",
            ..
        }
    ));

    let checksum_block = &samples["synthetic_ext4_extent_block_valid_checksum.bin"];
    verify_extent_block_checksum(checksum_block, 0x1234_5678, 42, 7)
        .expect("stamped extent block checksum verifies");

    let mut corrupted_checksum = checksum_block.clone();
    corrupted_checksum[20] ^= 0x80;
    let checksum_err = verify_extent_block_checksum(&corrupted_checksum, 0x1234_5678, 42, 7)
        .expect_err("extent checksum must reject covered-byte corruption");
    assert!(matches!(
        checksum_err,
        ParseError::InvalidField {
            field: "extent_checksum",
            ..
        }
    ));
}

#[test]
fn ext4_group_desc_adversarial_samples_exercise_boundaries() {
    let samples = group_desc_adversarial_samples()
        .into_iter()
        .collect::<BTreeMap<_, _>>();

    assert_valid_ext4_group_desc_samples(&samples);
    assert_invalid_ext4_group_desc_samples(&samples);
}

fn assert_valid_ext4_group_desc_samples(samples: &BTreeMap<String, Vec<u8>>) {
    let valid32 = &samples["synthetic_ext4_group_desc_valid_32.bin"];
    let desc32 =
        Ext4GroupDesc::parse_from_bytes(valid32, 32).expect("valid 32-byte group desc parses");
    assert_eq!(desc32.block_bitmap, 0x0000_0100);
    assert_eq!(desc32.inode_bitmap, 0x0000_0200);
    assert_eq!(desc32.inode_table, 0x0000_0300);
    assert_eq!(desc32.free_blocks_count, 0x0040);
    assert_eq!(desc32.free_inodes_count, 0x0020);
    assert_eq!(desc32.used_dirs_count, 0x0003);
    assert_eq!(desc32.itable_unused, 0x0010);
    assert_eq!(desc32.flags, 0x0005);
    assert_eq!(desc32.block_bitmap_csum, 0x1357);
    assert_eq!(desc32.inode_bitmap_csum, 0x2468);
    verify_group_desc_checksum(
        valid32,
        &EXT4_TEST_GROUP_DESC_UUID,
        EXT4_TEST_GROUP_DESC_CSUM_SEED,
        EXT4_TEST_GROUP_DESC_NUMBER,
        32,
        Ext4GroupDescChecksumKind::MetadataCsum,
    )
    .expect("stamped 32-byte group desc checksum verifies");

    let valid64 = &samples["synthetic_ext4_group_desc_valid_64.bin"];
    let desc64 =
        Ext4GroupDesc::parse_from_bytes(valid64, 64).expect("valid 64-byte group desc parses");
    assert_eq!(desc64.block_bitmap, 0x0000_0001_0000_0100);
    assert_eq!(desc64.inode_bitmap, 0x0000_0002_0000_0200);
    assert_eq!(desc64.inode_table, 0x0000_0003_0000_0300);
    assert_eq!(desc64.free_blocks_count, 0x0001_0040);
    assert_eq!(desc64.free_inodes_count, 0x0002_0020);
    assert_eq!(desc64.used_dirs_count, 0x0003_0003);
    assert_eq!(desc64.itable_unused, 0x0004_0010);
    assert_eq!(desc64.block_bitmap_csum, 0xAAAA_1357);
    assert_eq!(desc64.inode_bitmap_csum, 0xBBBB_2468);
    verify_group_desc_checksum(
        valid64,
        &EXT4_TEST_GROUP_DESC_UUID,
        EXT4_TEST_GROUP_DESC_CSUM_SEED,
        EXT4_TEST_GROUP_DESC_NUMBER,
        64,
        Ext4GroupDescChecksumKind::MetadataCsum,
    )
    .expect("stamped 64-byte group desc checksum verifies");
}

fn assert_invalid_ext4_group_desc_samples(samples: &BTreeMap<String, Vec<u8>>) {
    let bad_checksum = verify_group_desc_checksum(
        &samples["synthetic_ext4_group_desc_bad_checksum.bin"],
        &EXT4_TEST_GROUP_DESC_UUID,
        EXT4_TEST_GROUP_DESC_CSUM_SEED,
        EXT4_TEST_GROUP_DESC_NUMBER,
        32,
        Ext4GroupDescChecksumKind::MetadataCsum,
    )
    .expect_err("group desc checksum corruption must be rejected");
    assert!(matches!(
        bad_checksum,
        ParseError::InvalidField {
            field: "bg_checksum",
            ..
        }
    ));

    let desc_size_too_small = Ext4GroupDesc::parse_from_bytes(
        &samples["synthetic_ext4_group_desc_desc_size_too_small.bin"],
        31,
    )
    .expect_err("group desc sizes below 32 bytes must be rejected");
    assert!(matches!(
        desc_size_too_small,
        ParseError::InvalidField {
            field: "s_desc_size",
            ..
        }
    ));

    let short32 =
        Ext4GroupDesc::parse_from_bytes(&samples["synthetic_ext4_group_desc_short_32.bin"], 32)
            .expect_err("short 32-byte group desc must be rejected");
    assert!(matches!(
        short32,
        ParseError::InsufficientData {
            needed: 32,
            offset: 0,
            actual: 31,
        }
    ));

    let short64 =
        Ext4GroupDesc::parse_from_bytes(&samples["synthetic_ext4_group_desc_short_64.bin"], 64)
            .expect_err("short 64-byte group desc must be rejected");
    assert!(matches!(
        short64,
        ParseError::InsufficientData {
            needed: 64,
            offset: 0,
            actual: 63,
        }
    ));

    let checksum_short64 = verify_group_desc_checksum(
        &samples["synthetic_ext4_group_desc_short_64.bin"],
        &EXT4_TEST_GROUP_DESC_UUID,
        EXT4_TEST_GROUP_DESC_CSUM_SEED,
        EXT4_TEST_GROUP_DESC_NUMBER,
        64,
        Ext4GroupDescChecksumKind::MetadataCsum,
    )
    .expect_err("short group desc checksum input must be rejected");
    assert!(matches!(
        checksum_short64,
        ParseError::InsufficientData { .. }
    ));
}

#[test]
fn ext4_mmp_block_adversarial_samples_exercise_boundaries() {
    let samples = mmp_block_adversarial_samples()
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let checksum_seed = 0xAABB_CCDD;

    let clean = Ext4MmpBlock::parse_from_bytes(&samples["synthetic_ext4_mmp_clean_valid.bin"])
        .expect("valid clean MMP block parses");
    assert_eq!(clean.status(), Ext4MmpStatus::Clean);
    assert_eq!(clean.time, 0x0000_0001_0000_007B);
    assert_eq!(clean.nodename, "ffs-node-a");
    assert_eq!(clean.bdevname, "/dev/vda");
    assert_eq!(clean.check_interval, 5);
    clean
        .validate_checksum(
            &samples["synthetic_ext4_mmp_clean_valid.bin"],
            checksum_seed,
        )
        .expect("valid MMP checksum verifies");

    let fsck = Ext4MmpBlock::parse_from_bytes(&samples["synthetic_ext4_mmp_fsck_valid.bin"])
        .expect("valid fsck MMP block parses");
    assert_eq!(fsck.status(), Ext4MmpStatus::Fsck);

    let active = Ext4MmpBlock::parse_from_bytes(&samples["synthetic_ext4_mmp_active_valid.bin"])
        .expect("valid active MMP block parses");
    assert_eq!(active.status(), Ext4MmpStatus::Active(42));

    let unknown = Ext4MmpBlock::parse_from_bytes(&samples["synthetic_ext4_mmp_unknown_seq.bin"])
        .expect("unknown but well-formed MMP sequence parses");
    assert_eq!(unknown.status(), Ext4MmpStatus::UnsafeUnknown(u32::MAX));

    let bad_magic = Ext4MmpBlock::parse_from_bytes(&samples["synthetic_ext4_mmp_bad_magic.bin"])
        .expect_err("bad MMP magic must be rejected");
    assert!(matches!(
        bad_magic,
        ParseError::InvalidField {
            field: "mmp_magic",
            ..
        }
    ));

    let corrupt =
        Ext4MmpBlock::parse_from_bytes(&samples["synthetic_ext4_mmp_checksum_corrupt.bin"])
            .expect("checksum-corrupt MMP block still parses before validation");
    let checksum_err = corrupt
        .validate_checksum(
            &samples["synthetic_ext4_mmp_checksum_corrupt.bin"],
            checksum_seed,
        )
        .expect_err("corrupt MMP checksum must be rejected");
    assert!(matches!(
        checksum_err,
        ParseError::InvalidField {
            field: "mmp_checksum",
            ..
        }
    ));

    let short = Ext4MmpBlock::parse_from_bytes(&samples["synthetic_ext4_mmp_short.bin"])
        .expect_err("short MMP blocks must be rejected");
    assert!(matches!(
        short,
        ParseError::InsufficientData {
            needed: EXT4_SUPERBLOCK_SIZE,
            offset: 0,
            actual,
        } if actual == EXT4_SUPERBLOCK_SIZE - 1
    ));
}

#[test]
fn btrfs_tree_block_adversarial_samples_exercise_boundaries() {
    let samples = btrfs_tree_adversarial_samples()
        .into_iter()
        .collect::<BTreeMap<_, _>>();

    let valid_leaf = &samples["synthetic_btrfs_tree_valid_leaf.bin"];
    let (leaf_header, leaf_items) =
        parse_leaf_items(valid_leaf).expect("valid synthetic btrfs leaf parses");
    assert_eq!(leaf_header.level, 0);
    assert_eq!(leaf_header.nritems, 1);
    assert_eq!(leaf_items.len(), 1);
    assert_eq!(leaf_items[0].key.objectid, 256);
    assert_eq!(leaf_items[0].key.item_type, 1);
    assert_eq!(leaf_items[0].data_offset, 400);
    assert_eq!(leaf_items[0].data_size, 4);
    verify_btrfs_tree_block_checksum(valid_leaf, BTRFS_CSUM_TYPE_CRC32C)
        .expect("stamped btrfs tree checksum verifies");

    let mut corrupted_leaf = valid_leaf.clone();
    corrupted_leaf[400] ^= 0x80;
    let checksum_err = verify_btrfs_tree_block_checksum(&corrupted_leaf, BTRFS_CSUM_TYPE_CRC32C)
        .expect_err("covered-byte corruption must fail tree checksum");
    assert!(matches!(
        checksum_err,
        ParseError::InvalidField {
            field: "tree_block_csum",
            ..
        }
    ));

    let deep_header =
        BtrfsHeader::parse_from_block(&samples["synthetic_btrfs_tree_level_too_deep.bin"])
            .expect("header with excessive level still parses");
    let deep_err = deep_header
        .validate(BTRFS_TEST_HEADER_SIZE, None)
        .expect_err("level beyond btrfs max depth must be rejected");
    assert!(matches!(
        deep_err,
        ParseError::InvalidField { field: "level", .. }
    ));

    let table_overlap = parse_leaf_items(&samples["synthetic_btrfs_leaf_item_table_overlap.bin"])
        .expect_err("leaf item payload must not overlap item table");
    assert!(matches!(
        table_overlap,
        ParseError::InvalidField {
            field: "item_offset",
            ..
        }
    ));

    let payload_outside = parse_leaf_items(&samples["synthetic_btrfs_leaf_payload_outside.bin"])
        .expect_err("leaf item payload must not point outside block");
    assert!(matches!(
        payload_outside,
        ParseError::InvalidField {
            field: "item_offset",
            ..
        }
    ));

    let payload_overlap = parse_leaf_items(&samples["synthetic_btrfs_leaf_payload_overlap.bin"])
        .expect_err("leaf payload ranges must not overlap each other");
    assert!(matches!(
        payload_overlap,
        ParseError::InvalidField {
            field: "item_offset",
            ..
        }
    ));

    let (internal_header, ptrs) =
        parse_internal_items(&samples["synthetic_btrfs_tree_valid_internal.bin"])
            .expect("valid synthetic btrfs internal node parses");
    assert_eq!(internal_header.level, 1);
    assert_eq!(ptrs.len(), 1);
    assert_eq!(ptrs[0].key.objectid, 256);
    assert_eq!(ptrs[0].blockptr, 0x4000);
    assert_eq!(ptrs[0].generation, 7);

    let zero_blockptr = parse_internal_items(&samples["synthetic_btrfs_tree_zero_blockptr.bin"])
        .expect_err("zero child block pointer must be rejected");
    assert!(matches!(
        zero_blockptr,
        ParseError::InvalidField {
            field: "blockptr",
            ..
        }
    ));
}

#[test]
fn btrfs_sys_chunk_adversarial_samples_exercise_boundaries() {
    let samples = btrfs_sys_chunk_adversarial_samples()
        .into_iter()
        .collect::<BTreeMap<_, _>>();

    let valid = parse_sys_chunk_array(&samples["synthetic_btrfs_sys_chunk_valid_single.bin"])
        .expect("valid synthetic btrfs sys_chunk_array parses");
    assert_eq!(valid.len(), 1);
    assert_eq!(valid[0].key.objectid, BTRFS_TEST_CHUNK_TREE_OBJECTID);
    assert_eq!(valid[0].key.item_type, BTRFS_TEST_CHUNK_ITEM_KEY);
    assert_eq!(valid[0].key.offset, 0x1000);
    assert_eq!(valid[0].length, BTRFS_TEST_CHUNK_LENGTH);
    assert_eq!(valid[0].stripe_len, 4096);
    assert_eq!(valid[0].chunk_type, BTRFS_TEST_BLOCK_GROUP_SYSTEM);
    assert_eq!(valid[0].num_stripes, 1);
    assert_eq!(valid[0].stripes.len(), 1);
    assert_eq!(valid[0].stripes[0].devid, 1);
    assert_eq!(valid[0].stripes[0].offset, 0x2000);

    let mapping = map_logical_to_physical(&valid, 0x1010)
        .expect("valid sys chunk maps")
        .expect("logical address is covered");
    assert_eq!(mapping.devid, 1);
    assert_eq!(mapping.physical, 0x2010);

    let miss = map_logical_to_physical(&valid, 0x1000 + BTRFS_TEST_CHUNK_LENGTH)
        .expect("valid miss is ok");
    assert_eq!(miss, None);

    let bad_key_type =
        parse_sys_chunk_array(&samples["synthetic_btrfs_sys_chunk_bad_key_type.bin"])
            .expect_err("sys_chunk_array must reject non-chunk item keys");
    assert!(matches!(
        bad_key_type,
        ParseError::InvalidField {
            field: "sys_chunk_key_type",
            ..
        }
    ));

    let bad_objectid =
        parse_sys_chunk_array(&samples["synthetic_btrfs_sys_chunk_bad_objectid.bin"])
            .expect_err("sys_chunk_array must reject unexpected objectids");
    assert!(matches!(
        bad_objectid,
        ParseError::InvalidField {
            field: "sys_chunk_key_objectid",
            ..
        }
    ));

    let zero_length = parse_sys_chunk_array(&samples["synthetic_btrfs_sys_chunk_zero_length.bin"])
        .expect_err("zero-length chunks must be rejected");
    assert!(matches!(
        zero_length,
        ParseError::InvalidField {
            field: "chunk_length",
            ..
        }
    ));

    let zero_stripe_len =
        parse_sys_chunk_array(&samples["synthetic_btrfs_sys_chunk_zero_stripe_len.bin"])
            .expect_err("zero stripe length must be rejected");
    assert!(matches!(
        zero_stripe_len,
        ParseError::InvalidField {
            field: "stripe_len",
            ..
        }
    ));

    let zero_stripes =
        parse_sys_chunk_array(&samples["synthetic_btrfs_sys_chunk_zero_stripes.bin"])
            .expect_err("zero stripes must be rejected");
    assert!(matches!(
        zero_stripes,
        ParseError::InvalidField {
            field: "num_stripes",
            ..
        }
    ));

    let zero_stripe_devid =
        parse_sys_chunk_array(&samples["synthetic_btrfs_sys_chunk_zero_stripe_devid.bin"])
            .expect_err("zero stripe device IDs must be rejected");
    assert!(matches!(
        zero_stripe_devid,
        ParseError::InvalidField {
            field: "stripe_devid",
            ..
        }
    ));

    let multiple_raid_profiles =
        parse_sys_chunk_array(&samples["synthetic_btrfs_sys_chunk_multiple_raid_profiles.bin"])
            .expect_err("multiple raid profile bits must be rejected");
    assert!(matches!(
        multiple_raid_profiles,
        ParseError::InvalidField {
            field: "chunk_type",
            ..
        }
    ));

    let truncated_stripe =
        parse_sys_chunk_array(&samples["synthetic_btrfs_sys_chunk_truncated_stripe.bin"])
            .expect_err("truncated stripe records must be rejected");
    assert!(matches!(
        truncated_stripe,
        ParseError::InsufficientData { .. }
    ));
}

#[test]
fn btrfs_superblock_adversarial_samples_exercise_boundaries() {
    let samples = btrfs_superblock_adversarial_samples()
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    assert_valid_btrfs_superblock_samples(&samples);
    assert_invalid_btrfs_superblock_samples(&samples);
}

fn assert_valid_btrfs_superblock_samples(samples: &BTreeMap<String, Vec<u8>>) -> BtrfsSuperblock {
    let valid = BtrfsSuperblock::parse_superblock_region(
        &samples["synthetic_btrfs_superblock_valid_region.bin"],
    )
    .expect("valid synthetic btrfs superblock region parses");
    assert_eq!(valid.magic, BTRFS_MAGIC);
    assert_eq!(
        valid.bytenr,
        u64::try_from(BTRFS_SUPER_INFO_OFFSET).expect("btrfs superblock offset fits in u64")
    );
    assert_eq!(valid.generation, 7);
    assert_eq!(valid.root, 0x4000);
    assert_eq!(valid.chunk_root, 0x8000);
    assert_eq!(valid.total_bytes, BTRFS_TEST_DEV_TOTAL_BYTES);
    assert_eq!(valid.bytes_used, BTRFS_TEST_DEV_BYTES_USED);
    assert_eq!(valid.root_dir_objectid, 5);
    assert_eq!(valid.num_devices, 1);
    assert_eq!(valid.sectorsize, 4096);
    assert_eq!(valid.nodesize, 16_384);
    assert_eq!(valid.stripesize, 4096);
    assert_eq!(valid.csum_type, BTRFS_CSUM_TYPE_CRC32C);
    assert_eq!(valid.label, "ffs-adversarial");

    let chunks =
        parse_sys_chunk_array(&valid.sys_chunk_array).expect("superblock sys_chunk_array parses");
    assert_eq!(chunks.len(), 1);
    let mapping = map_logical_to_physical(&chunks, 0x1010)
        .expect("valid sys chunk mapping is checked")
        .expect("logical address is covered");
    assert_eq!(mapping.devid, 1);
    assert_eq!(mapping.physical, 0x2010);

    let from_image =
        BtrfsSuperblock::parse_from_image(&samples["synthetic_btrfs_superblock_valid_image.bin"])
            .expect("valid synthetic btrfs image parses at the canonical offset");
    assert_eq!(from_image, valid);

    valid
}

fn assert_invalid_btrfs_superblock_samples(samples: &BTreeMap<String, Vec<u8>>) {
    assert_invalid_btrfs_superblock_shape_samples(samples);
    assert_invalid_btrfs_superblock_accounting_samples(samples);
}

fn assert_invalid_btrfs_superblock_shape_samples(samples: &BTreeMap<String, Vec<u8>>) {
    let short_image =
        BtrfsSuperblock::parse_from_image(&samples["synthetic_btrfs_superblock_short_image.bin"])
            .expect_err("short images must be rejected before slicing the superblock region");
    assert!(matches!(
        short_image,
        ParseError::InsufficientData {
            needed: BTRFS_SUPER_INFO_SIZE,
            offset: BTRFS_SUPER_INFO_OFFSET,
            actual,
        } if actual == BTRFS_SUPER_INFO_SIZE - 1
    ));

    let short_region = BtrfsSuperblock::parse_superblock_region(
        &samples["synthetic_btrfs_superblock_short_region.bin"],
    )
    .expect_err("one-byte-short superblock regions must be rejected");
    assert!(matches!(
        short_region,
        ParseError::InsufficientData {
            needed: BTRFS_SUPER_INFO_SIZE,
            offset: 0,
            actual,
        } if actual == BTRFS_SUPER_INFO_SIZE - 1
    ));

    let bad_magic = BtrfsSuperblock::parse_superblock_region(
        &samples["synthetic_btrfs_superblock_bad_magic.bin"],
    )
    .expect_err("bad btrfs magic must be rejected");
    assert!(matches!(bad_magic, ParseError::InvalidMagic { .. }));

    let zero_sectorsize = BtrfsSuperblock::parse_superblock_region(
        &samples["synthetic_btrfs_superblock_zero_sectorsize.bin"],
    )
    .expect_err("zero sector sizes must be rejected");
    assert!(matches!(
        zero_sectorsize,
        ParseError::InvalidField {
            field: "sectorsize",
            ..
        }
    ));

    let non_power_nodesize = BtrfsSuperblock::parse_superblock_region(
        &samples["synthetic_btrfs_superblock_non_power_nodesize.bin"],
    )
    .expect_err("non-power-of-two node sizes must be rejected");
    assert!(matches!(
        non_power_nodesize,
        ParseError::InvalidField {
            field: "nodesize",
            ..
        }
    ));

    let bad_stripesize = BtrfsSuperblock::parse_superblock_region(
        &samples["synthetic_btrfs_superblock_bad_stripesize.bin"],
    )
    .expect_err("non-power-of-two stripe sizes must be rejected");
    assert!(matches!(
        bad_stripesize,
        ParseError::InvalidField {
            field: "stripesize",
            ..
        }
    ));

    let oversized_sys_chunk_array = BtrfsSuperblock::parse_superblock_region(
        &samples["synthetic_btrfs_superblock_oversized_sys_chunk_array.bin"],
    )
    .expect_err("oversized sys_chunk_array declarations must be rejected");
    assert!(matches!(
        oversized_sys_chunk_array,
        ParseError::InvalidField {
            field: "sys_chunk_array_size",
            ..
        }
    ));
}

fn assert_invalid_btrfs_superblock_accounting_samples(samples: &BTreeMap<String, Vec<u8>>) {
    let zero_total = BtrfsSuperblock::parse_superblock_region(
        &samples["synthetic_btrfs_superblock_zero_total_bytes.bin"],
    )
    .expect_err("zero total_bytes superblocks must be rejected");
    assert!(matches!(
        zero_total,
        ParseError::InvalidField {
            field: "total_bytes",
            reason: "must be non-zero",
        }
    ));

    let overused = BtrfsSuperblock::parse_superblock_region(
        &samples["synthetic_btrfs_superblock_bytes_used_exceeds_total.bin"],
    )
    .expect_err("superblock bytes_used above total_bytes must be rejected");
    assert!(matches!(
        overused,
        ParseError::InvalidField {
            field: "bytes_used",
            reason: "exceeds total_bytes",
        }
    ));

    let zero_devices = BtrfsSuperblock::parse_superblock_region(
        &samples["synthetic_btrfs_superblock_zero_num_devices.bin"],
    )
    .expect_err("zero-device superblocks must be rejected");
    assert!(matches!(
        zero_devices,
        ParseError::InvalidField {
            field: "num_devices",
            reason: "must be non-zero",
        }
    ));
}

#[test]
fn btrfs_dev_item_adversarial_samples_exercise_boundaries() {
    let samples = btrfs_dev_item_adversarial_samples()
        .into_iter()
        .collect::<BTreeMap<_, _>>();

    let valid = parse_dev_item(&samples["synthetic_btrfs_dev_item_valid_full.bin"])
        .expect("valid synthetic btrfs dev item parses");
    assert_eq!(valid.devid, 7);
    assert_eq!(valid.total_bytes, BTRFS_TEST_DEV_TOTAL_BYTES);
    assert_eq!(valid.bytes_used, BTRFS_TEST_DEV_BYTES_USED);
    assert_eq!(valid.io_align, 4096);
    assert_eq!(valid.io_width, 8192);
    assert_eq!(valid.sector_size, 4096);
    assert_eq!(valid.dev_type, 0);
    assert_eq!(valid.generation, 42);
    assert_eq!(valid.start_offset, 1 << 20);
    assert_eq!(valid.dev_group, 3);
    assert_eq!(valid.seek_speed, 11);
    assert_eq!(valid.bandwidth, 22);
    assert_eq!(valid.uuid, [0x11; 16]);
    assert_eq!(valid.fsid, [0x22; 16]);

    let max_values = parse_dev_item(&samples["synthetic_btrfs_dev_item_max_values.bin"])
        .expect("max-value btrfs dev item parses");
    assert_eq!(max_values.devid, u64::MAX);
    assert_eq!(max_values.total_bytes, u64::MAX);
    assert_eq!(max_values.bytes_used, u64::MAX);
    assert_eq!(max_values.io_align, u32::MAX);
    assert_eq!(max_values.io_width, u32::MAX);
    assert_eq!(max_values.sector_size, u32::MAX);
    assert_eq!(max_values.dev_type, u64::MAX);
    assert_eq!(max_values.generation, u64::MAX);
    assert_eq!(max_values.start_offset, u64::MAX);
    assert_eq!(max_values.dev_group, u32::MAX);
    assert_eq!(max_values.seek_speed, u8::MAX);
    assert_eq!(max_values.bandwidth, u8::MAX);
    assert_eq!(max_values.uuid, [0xAA; 16]);
    assert_eq!(max_values.fsid, [0x55; 16]);

    let extra_tail = parse_dev_item(&samples["synthetic_btrfs_dev_item_extra_tail.bin"])
        .expect("fixed-size dev item parser ignores trailing leaf payload bytes");
    assert_eq!(extra_tail, valid);

    let zero_devid = parse_dev_item(&samples["synthetic_btrfs_dev_item_zero_devid.bin"])
        .expect_err("zero device IDs must be rejected");
    assert!(matches!(
        zero_devid,
        ParseError::InvalidField {
            field: "devid",
            reason: "must be non-zero",
        }
    ));

    let zero_total = parse_dev_item(&samples["synthetic_btrfs_dev_item_zero_total_bytes.bin"])
        .expect_err("zero-capacity dev item must be rejected");
    assert!(matches!(
        zero_total,
        ParseError::InvalidField {
            field: "total_bytes",
            reason: "must be non-zero",
        }
    ));

    let overused =
        parse_dev_item(&samples["synthetic_btrfs_dev_item_bytes_used_exceeds_total.bin"])
            .expect_err("dev item bytes_used above total_bytes must be rejected");
    assert!(matches!(
        overused,
        ParseError::InvalidField {
            field: "bytes_used",
            reason: "exceeds total_bytes",
        }
    ));

    let truncated = parse_dev_item(&samples["synthetic_btrfs_dev_item_truncated_tail.bin"])
        .expect_err("one-byte-short dev item must be rejected");
    assert!(matches!(
        truncated,
        ParseError::InsufficientData {
            needed: BTRFS_TEST_DEV_ITEM_SIZE,
            offset: 0,
            actual,
        } if actual == BTRFS_TEST_DEV_ITEM_SIZE - 1
    ));
}

// ── Fuzz infrastructure validation ──────────────────────────────────────────

#[test]
fn fuzz_workspace_structure_is_valid() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root")
        .to_path_buf();
    let fuzz_dir = workspace_root.join("fuzz");

    // Fuzz Cargo.toml must exist
    let fuzz_manifest = fuzz_dir.join("Cargo.toml");
    assert!(
        fuzz_manifest.exists(),
        "fuzz/Cargo.toml must exist for cargo-fuzz"
    );

    // Read and validate manifest references ffs-ondisk
    let manifest_contents =
        fs::read_to_string(&fuzz_manifest).expect("failed to read fuzz/Cargo.toml");
    assert!(
        manifest_contents.contains("ffs-ondisk"),
        "fuzz/Cargo.toml must depend on ffs-ondisk"
    );
    assert!(
        manifest_contents.contains("libfuzzer-sys"),
        "fuzz/Cargo.toml must depend on libfuzzer-sys"
    );

    let manifest_targets = manifest_fuzz_targets(&workspace_root);
    assert!(
        !manifest_targets.is_empty(),
        "fuzz/Cargo.toml must register at least one fuzz target"
    );

    // fuzz_targets/ directory must exist and match the manifest target count
    let targets_dir = fuzz_dir.join("fuzz_targets");
    assert!(
        targets_dir.is_dir(),
        "fuzz/fuzz_targets/ directory must exist"
    );
    let target_files: Vec<_> = fs::read_dir(&targets_dir)
        .expect("failed to read fuzz/fuzz_targets/")
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "rs"))
        .collect();
    assert!(
        target_files.len() == manifest_targets.len(),
        "fuzz/fuzz_targets count ({}) must match manifest target count ({})",
        target_files.len(),
        manifest_targets.len()
    );

    // Each target must contain fuzz_target! macro
    for entry in &target_files {
        let content = fs::read_to_string(entry.path()).expect("failed to read fuzz target");
        assert!(
            content.contains("fuzz_target!"),
            "fuzz target {} must contain fuzz_target! macro",
            entry.path().display()
        );
    }

    // Corpus directories must exist with seeds
    let corpus_dir = fuzz_dir.join("corpus");
    assert!(
        corpus_dir.is_dir(),
        "fuzz/corpus/ directory must exist for seed inputs"
    );
}

#[test]
fn fuzz_dictionaries_exist_and_are_well_formed() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root")
        .to_path_buf();

    let dict_dir = workspace_root.join("fuzz").join("dictionaries");
    assert!(dict_dir.is_dir(), "fuzz/dictionaries/ must exist");

    let expected_dicts = ["ext4.dict", "btrfs.dict"];
    for dict_name in &expected_dicts {
        let dict_path = dict_dir.join(dict_name);
        assert!(
            dict_path.exists(),
            "dictionary {dict_name} must exist in fuzz/dictionaries/"
        );

        let content = fs::read_to_string(&dict_path).expect("failed to read fuzz dictionary");

        // Must contain at least one quoted token entry
        let token_lines = content
            .lines()
            .filter(|l| {
                let trimmed = l.trim();
                trimmed.starts_with('"') || trimmed.contains("=\"")
            })
            .count();
        assert!(
            token_lines >= 5,
            "{dict_name} should have at least 5 dictionary entries, found {token_lines}"
        );
    }
}

#[test]
fn fuzz_seed_generation_script_exists() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root")
        .to_path_buf();

    let gen_script = workspace_root
        .join("fuzz")
        .join("scripts")
        .join("generate_seeds.sh");
    assert!(
        gen_script.exists(),
        "fuzz/scripts/generate_seeds.sh must exist"
    );

    let run_script = workspace_root
        .join("fuzz")
        .join("scripts")
        .join("run_fuzz.sh");
    assert!(run_script.exists(), "fuzz/scripts/run_fuzz.sh must exist");
}

#[test]
fn fuzz_nightly_campaign_script_exists() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root")
        .to_path_buf();

    let nightly_script = workspace_root
        .join("fuzz")
        .join("scripts")
        .join("nightly_fuzz.sh");
    assert!(
        nightly_script.exists(),
        "fuzz/scripts/nightly_fuzz.sh must exist for automated campaigns"
    );

    // Verify it's executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::metadata(&nightly_script)
            .expect("read nightly script metadata")
            .permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "nightly_fuzz.sh must be executable"
        );
    }

    // Verify minimize script exists
    let minimize_script = workspace_root
        .join("fuzz")
        .join("scripts")
        .join("minimize_corpus.sh");
    assert!(
        minimize_script.exists(),
        "fuzz/scripts/minimize_corpus.sh must exist"
    );
}

#[test]
fn fuzz_seed_corpus_covers_all_targets() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root")
        .to_path_buf();

    let expected_targets = manifest_fuzz_targets(&workspace_root);

    for target in &expected_targets {
        let corpus_path = workspace_root.join("fuzz").join("corpus").join(target);
        assert!(
            corpus_path.is_dir(),
            "corpus directory must exist for target: {target}"
        );
        let sample_count = fs::read_dir(&corpus_path)
            .expect("failed to read fuzz corpus dir")
            .filter_map(Result::ok)
            .filter(|e| e.path().is_file())
            .count();
        assert!(
            sample_count > 0,
            "corpus for {target} must contain at least one seed sample, found {sample_count}"
        );
    }
}
