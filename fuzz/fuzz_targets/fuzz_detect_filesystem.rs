#![no_main]

use ffs_core::{detect_filesystem, DetectionError, FrankenFsEngine, FsFlavor};
use ffs_ondisk::{EXT4_ORPHAN_FS, EXT4_VALID_FS};
use ffs_types::{
    crc32c, BTRFS_CSUM_TYPE_CRC32C, BTRFS_MAGIC, BTRFS_SUPER_INFO_OFFSET, EXT4_SUPERBLOCK_OFFSET,
    EXT4_SUPERBLOCK_SIZE, EXT4_SUPER_MAGIC,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 512;
const MAX_RAW_BYTES: usize = 4 * 1024;
const EXT4_SUPERBLOCK_END: usize = EXT4_SUPERBLOCK_OFFSET + EXT4_SUPERBLOCK_SIZE;

const EXT4_IMAGE_SIZE: usize = 128 * 1024;
const EXT4_BLOCK_SIZE_LOG: u32 = 2;
const EXT4_STATE_OFFSET: usize = EXT4_SUPERBLOCK_OFFSET + 0x3A;
const EXT4_LAST_ORPHAN_OFFSET: usize = EXT4_SUPERBLOCK_OFFSET + 0xE8;
const EXT4_INTERESTING_OFFSETS: [usize; 7] = [
    EXT4_SUPERBLOCK_OFFSET,
    EXT4_SUPERBLOCK_OFFSET + 0x04,
    EXT4_SUPERBLOCK_OFFSET + 0x18,
    EXT4_SUPERBLOCK_OFFSET + 0x38,
    EXT4_STATE_OFFSET,
    EXT4_SUPERBLOCK_OFFSET + 0x58,
    EXT4_LAST_ORPHAN_OFFSET,
];

const BTRFS_IMAGE_SIZE: usize = 256 * 1024;
const BTRFS_ROOT_LOGICAL: usize = 0x4_000;
const BTRFS_NODESIZE: usize = 4_096;
const BTRFS_LOG_ROOT_OFFSET: usize = BTRFS_SUPER_INFO_OFFSET + 0x60;
const BTRFS_INTERESTING_OFFSETS: [usize; 10] = [
    BTRFS_SUPER_INFO_OFFSET + 0x30,
    BTRFS_SUPER_INFO_OFFSET + 0x40,
    BTRFS_SUPER_INFO_OFFSET + 0x48,
    BTRFS_SUPER_INFO_OFFSET + 0x50,
    BTRFS_LOG_ROOT_OFFSET,
    BTRFS_SUPER_INFO_OFFSET + 0x90,
    BTRFS_SUPER_INFO_OFFSET + 0x94,
    BTRFS_SUPER_INFO_OFFSET + 0xC4,
    BTRFS_ROOT_LOGICAL + 0x30,
    BTRFS_ROOT_LOGICAL + 0x60,
];

#[derive(Clone, Copy, Debug)]
enum SeedImage {
    Ext4Clean,
    Ext4Dirty,
    BtrfsClean,
    Zeroes,
    Raw,
    Truncated,
}

impl SeedImage {
    fn from_selector(selector: u8) -> Self {
        match selector % 6 {
            0 => Self::Ext4Clean,
            1 => Self::Ext4Dirty,
            2 => Self::BtrfsClean,
            3 => Self::Zeroes,
            4 => Self::Raw,
            _ => Self::Truncated,
        }
    }

    fn must_reject_as_short_image(self) -> bool {
        matches!(self, Self::Zeroes | Self::Raw | Self::Truncated)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutcomeClass {
    Ext4,
    Btrfs,
    Unsupported,
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

    fn next_u16(&mut self) -> u16 {
        u16::from_le_bytes([self.next_u8(), self.next_u8()])
    }

    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes([
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
        ])
    }

    fn next_index(&mut self, len: usize) -> usize {
        if len == 0 {
            0
        } else {
            usize::from(self.next_u16()) % len
        }
    }

    fn remainder(&self) -> &'a [u8] {
        self.data.get(self.pos..).unwrap_or(&[])
    }
}

fn build_ext4_image(block_size_log: u32) -> Vec<u8> {
    let block_size = 1024_u32 << block_size_log;
    let mut image = vec![0_u8; EXT4_IMAGE_SIZE];
    let sb_off = EXT4_SUPERBLOCK_OFFSET;

    image[sb_off + 0x38..sb_off + 0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
    image[sb_off + 0x18..sb_off + 0x1C].copy_from_slice(&block_size_log.to_le_bytes());

    let blocks_count = u32::try_from(EXT4_IMAGE_SIZE / usize::try_from(block_size).unwrap_or(1))
        .unwrap_or(u32::MAX);
    image[sb_off + 0x04..sb_off + 0x08].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off..sb_off + 0x04].copy_from_slice(&128_u32.to_le_bytes());

    let first_data = u32::from(block_size == 1024);
    image[sb_off + 0x14..sb_off + 0x18].copy_from_slice(&first_data.to_le_bytes());
    image[sb_off + 0x20..sb_off + 0x24].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off + 0x28..sb_off + 0x2C].copy_from_slice(&128_u32.to_le_bytes());
    image[sb_off + 0x58..sb_off + 0x5A].copy_from_slice(&256_u16.to_le_bytes());
    image[sb_off + 0x4C..sb_off + 0x50].copy_from_slice(&1_u32.to_le_bytes());
    image[sb_off + 0x54..sb_off + 0x58].copy_from_slice(&11_u32.to_le_bytes());
    image[sb_off + 0x60..sb_off + 0x64].copy_from_slice(&(0x0002_u32 | 0x0040_u32).to_le_bytes());
    image[sb_off + 0x3A..sb_off + 0x3C].copy_from_slice(&EXT4_VALID_FS.to_le_bytes());

    image
}

fn build_ext4_dirty_image() -> Vec<u8> {
    let mut image = build_ext4_image(EXT4_BLOCK_SIZE_LOG);
    image[EXT4_STATE_OFFSET..EXT4_STATE_OFFSET + 2]
        .copy_from_slice(&(EXT4_VALID_FS | EXT4_ORPHAN_FS).to_le_bytes());
    image[EXT4_LAST_ORPHAN_OFFSET..EXT4_LAST_ORPHAN_OFFSET + 4]
        .copy_from_slice(&2_u32.to_le_bytes());
    image
}

fn build_btrfs_image() -> Vec<u8> {
    let mut image = vec![0_u8; BTRFS_IMAGE_SIZE];
    let sb_off = BTRFS_SUPER_INFO_OFFSET;

    image[sb_off + 0x30..sb_off + 0x38]
        .copy_from_slice(&(BTRFS_SUPER_INFO_OFFSET as u64).to_le_bytes());
    image[sb_off + 0x40..sb_off + 0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
    image[sb_off + 0x48..sb_off + 0x50].copy_from_slice(&1_u64.to_le_bytes());
    image[sb_off + 0x50..sb_off + 0x58].copy_from_slice(&(BTRFS_ROOT_LOGICAL as u64).to_le_bytes());
    image[sb_off + 0x58..sb_off + 0x60].copy_from_slice(&0_u64.to_le_bytes());
    image[sb_off + 0x70..sb_off + 0x78].copy_from_slice(&(BTRFS_IMAGE_SIZE as u64).to_le_bytes());
    image[sb_off + 0x80..sb_off + 0x88].copy_from_slice(&256_u64.to_le_bytes());
    image[sb_off + 0x88..sb_off + 0x90].copy_from_slice(&1_u64.to_le_bytes());
    image[sb_off + 0x90..sb_off + 0x94].copy_from_slice(&4096_u32.to_le_bytes());
    image[sb_off + 0x94..sb_off + 0x98].copy_from_slice(&4096_u32.to_le_bytes());
    image[sb_off + 0x9C..sb_off + 0xA0].copy_from_slice(&4096_u32.to_le_bytes());
    image[sb_off + 0xC4..sb_off + 0xC6].copy_from_slice(&BTRFS_CSUM_TYPE_CRC32C.to_le_bytes());
    image[sb_off + 0xC6] = 0;

    let mut chunk_array = Vec::new();
    chunk_array.extend_from_slice(&256_u64.to_le_bytes());
    chunk_array.push(228_u8);
    chunk_array.extend_from_slice(&0_u64.to_le_bytes());
    chunk_array.extend_from_slice(&(BTRFS_IMAGE_SIZE as u64).to_le_bytes());
    chunk_array.extend_from_slice(&2_u64.to_le_bytes());
    chunk_array.extend_from_slice(&0x1_0000_u64.to_le_bytes());
    chunk_array.extend_from_slice(&2_u64.to_le_bytes());
    chunk_array.extend_from_slice(&4096_u32.to_le_bytes());
    chunk_array.extend_from_slice(&4096_u32.to_le_bytes());
    chunk_array.extend_from_slice(&4096_u32.to_le_bytes());
    chunk_array.extend_from_slice(&1_u16.to_le_bytes());
    chunk_array.extend_from_slice(&0_u16.to_le_bytes());
    chunk_array.extend_from_slice(&1_u64.to_le_bytes());
    chunk_array.extend_from_slice(&0_u64.to_le_bytes());
    chunk_array.extend_from_slice(&[0_u8; 16]);

    let array_size = u32::try_from(chunk_array.len()).unwrap_or(u32::MAX);
    image[sb_off + 0xA0..sb_off + 0xA4].copy_from_slice(&array_size.to_le_bytes());
    let array_start = sb_off + 0x32B;
    image[array_start..array_start + chunk_array.len()].copy_from_slice(&chunk_array);

    let leaf_off = BTRFS_ROOT_LOGICAL;
    image[leaf_off + 0x30..leaf_off + 0x38]
        .copy_from_slice(&(BTRFS_ROOT_LOGICAL as u64).to_le_bytes());
    image[leaf_off + 0x50..leaf_off + 0x58].copy_from_slice(&1_u64.to_le_bytes());
    image[leaf_off + 0x58..leaf_off + 0x60].copy_from_slice(&1_u64.to_le_bytes());
    image[leaf_off + 0x60..leaf_off + 0x64].copy_from_slice(&1_u32.to_le_bytes());
    image[leaf_off + 0x64] = 0;
    stamp_btrfs_tree_block_checksum(&mut image, BTRFS_ROOT_LOGICAL);

    image
}

fn stamp_btrfs_tree_block_checksum(image: &mut [u8], logical: usize) {
    let block = &mut image[logical..logical + BTRFS_NODESIZE];
    block[..0x20].fill(0);
    let checksum = crc32c(&block[0x20..]);
    block[..4].copy_from_slice(&checksum.to_le_bytes());
}

fn mutate_byte(image: &mut [u8], offset: usize, value: u8) {
    if let Some(slot) = image.get_mut(offset) {
        *slot = value;
    }
}

fn xor_byte(image: &mut [u8], offset: usize, value: u8) {
    if let Some(slot) = image.get_mut(offset) {
        *slot ^= value;
    }
}

fn write_u16_le(image: &mut [u8], offset: usize, value: u16) {
    let end = offset.saturating_add(2);
    if end <= image.len() {
        image[offset..end].copy_from_slice(&value.to_le_bytes());
    }
}

fn write_u32_le(image: &mut [u8], offset: usize, value: u32) {
    let end = offset.saturating_add(4);
    if end <= image.len() {
        image[offset..end].copy_from_slice(&value.to_le_bytes());
    }
}

fn overwrite_range(image: &mut [u8], offset: usize, len: usize, cursor: &mut ByteCursor<'_>) {
    let start = offset.min(image.len());
    let end = start.saturating_add(len).min(image.len());
    for byte in &mut image[start..end] {
        *byte = cursor.next_u8();
    }
}

fn mutate_bytes(image: &mut [u8], cursor: &mut ByteCursor<'_>, offsets: &[usize]) {
    let focused_rounds = usize::from(cursor.next_u8() % 16);
    for _ in 0..focused_rounds {
        let base = offsets[cursor.next_index(offsets.len())];
        match cursor.next_u8() % 5 {
            0 => mutate_byte(image, base, cursor.next_u8()),
            1 => xor_byte(image, base, cursor.next_u8()),
            2 => write_u16_le(image, base, cursor.next_u16()),
            3 => write_u32_le(image, base, cursor.next_u32()),
            _ => overwrite_range(image, base, 1 + usize::from(cursor.next_u8() % 32), cursor),
        }
    }
}

fn build_image(seed: SeedImage, cursor: &mut ByteCursor<'_>) -> Vec<u8> {
    match seed {
        SeedImage::Raw => {
            cursor.remainder()[..cursor.remainder().len().min(MAX_RAW_BYTES)].to_vec()
        }
        SeedImage::Zeroes => vec![0_u8; 1024],
        SeedImage::Truncated => {
            let mut image = build_ext4_image(EXT4_BLOCK_SIZE_LOG);
            mutate_bytes(&mut image, cursor, &EXT4_INTERESTING_OFFSETS);
            let len = usize::from(cursor.next_u16()) % 2048;
            image.truncate(len);
            image
        }
        SeedImage::Ext4Clean => {
            let mut image = build_ext4_image(EXT4_BLOCK_SIZE_LOG);
            mutate_bytes(&mut image, cursor, &EXT4_INTERESTING_OFFSETS);
            image
        }
        SeedImage::Ext4Dirty => {
            let mut image = build_ext4_dirty_image();
            mutate_bytes(&mut image, cursor, &EXT4_INTERESTING_OFFSETS);
            image[EXT4_STATE_OFFSET..EXT4_STATE_OFFSET + 2]
                .copy_from_slice(&(EXT4_VALID_FS | EXT4_ORPHAN_FS).to_le_bytes());
            image
        }
        SeedImage::BtrfsClean => {
            let mut image = build_btrfs_image();
            mutate_bytes(&mut image, cursor, &BTRFS_INTERESTING_OFFSETS);
            if cursor.next_u8() & 1 == 0 {
                stamp_btrfs_tree_block_checksum(&mut image, BTRFS_ROOT_LOGICAL);
            }
            image
        }
    }
}

fn normalize(result: Result<FsFlavor, DetectionError>) -> OutcomeClass {
    match result {
        Ok(FsFlavor::Ext4(_)) => OutcomeClass::Ext4,
        Ok(FsFlavor::Btrfs(_)) => OutcomeClass::Btrfs,
        Err(_) => OutcomeClass::Unsupported,
    }
}

fn normalize_ref(result: &Result<FsFlavor, DetectionError>) -> OutcomeClass {
    match result {
        Ok(FsFlavor::Ext4(_)) => OutcomeClass::Ext4,
        Ok(FsFlavor::Btrfs(_)) => OutcomeClass::Btrfs,
        Err(_) => OutcomeClass::Unsupported,
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let mut cursor = ByteCursor::new(data);
    let seed = SeedImage::from_selector(cursor.next_u8());
    let image = build_image(seed, &mut cursor);

    let first = normalize(detect_filesystem(&image));
    let second = normalize(detect_filesystem(&image));
    let wrapped_result = FrankenFsEngine::inspect_image(&image);
    let wrapped = normalize_ref(&wrapped_result);
    let ext4_first = FrankenFsEngine::parse_ext4(&image);
    let ext4_second = FrankenFsEngine::parse_ext4(&image);
    let btrfs_first = FrankenFsEngine::parse_btrfs(&image);
    let btrfs_second = FrankenFsEngine::parse_btrfs(&image);

    assert_eq!(
        first, second,
        "detect_filesystem classification must be deterministic for identical inputs"
    );
    assert_eq!(
        first, wrapped,
        "FrankenFsEngine::inspect_image must match detect_filesystem on identical inputs"
    );
    assert_eq!(
        ext4_first, ext4_second,
        "FrankenFsEngine::parse_ext4 must be deterministic for identical inputs"
    );
    assert_eq!(
        btrfs_first, btrfs_second,
        "FrankenFsEngine::parse_btrfs must be deterministic for identical inputs"
    );

    if seed.must_reject_as_short_image() {
        assert!(
            image.len() < EXT4_SUPERBLOCK_END,
            "{seed:?} seed must stay shorter than the ext4 superblock span"
        );
        assert_eq!(
            first,
            OutcomeClass::Unsupported,
            "{seed:?} short image must not be classified as ext4 or btrfs"
        );
        assert!(
            wrapped_result.is_err(),
            "{seed:?} short image must be rejected by inspect_image"
        );
        assert!(
            ext4_first.is_err(),
            "{seed:?} short image must be rejected by parse_ext4"
        );
        assert!(
            btrfs_first.is_err(),
            "{seed:?} short image must be rejected by parse_btrfs"
        );
        return;
    }

    match wrapped_result {
        Ok(FsFlavor::Ext4(superblock)) => {
            assert_eq!(
                ext4_first.as_ref(),
                Ok(&*superblock),
                "inspect_image ext4 classifications must carry the same superblock as parse_ext4"
            );
        }
        Ok(FsFlavor::Btrfs(superblock)) => {
            assert!(
                ext4_first.is_err(),
                "btrfs classifications must only happen after ext4 parsing rejects the image"
            );
            assert_eq!(
                btrfs_first.as_ref(),
                Ok(&*superblock),
                "inspect_image btrfs classifications must carry the same superblock as parse_btrfs"
            );
        }
        Err(_) => {}
    }
});
