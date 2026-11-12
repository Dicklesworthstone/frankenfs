#![no_main]

use ffs_ondisk::Ext4ImageReader;
use ffs_types::{BlockNumber, GroupNumber, InodeNumber, EXT4_SUPERBLOCK_OFFSET, EXT4_SUPER_MAGIC};
use libfuzzer_sys::fuzz_target;

const BLOCK_SIZE: usize = 4096;
const IMAGE_BLOCKS: usize = 16;
const IMAGE_SIZE: usize = BLOCK_SIZE * IMAGE_BLOCKS;
const INODE_SIZE: usize = 256;
const INODE_TABLE_BLOCK: u32 = 2;
const ROOT_DIR_BLOCK: u32 = 4;
const FILE_DATA_BLOCK: u32 = 5;
const LONG_LINK_BLOCK: u32 = 6;
const ROOT_INO: u32 = 2;
const FILE_INO: u32 = 11;
const FAST_LINK_INO: u32 = 12;
const LONG_LINK_INO: u32 = 13;
const MAX_MUTATIONS: usize = 32;
const INTERESTING_OFFSETS: [usize; 12] = [
    EXT4_SUPERBLOCK_OFFSET + 0x18,
    EXT4_SUPERBLOCK_OFFSET + 0x38,
    EXT4_SUPERBLOCK_OFFSET + 0x58,
    BLOCK_SIZE + 0x08,
    BLOCK_SIZE + 0x09,
    BLOCK_SIZE * 2,
    BLOCK_SIZE * 2 + 0x80,
    BLOCK_SIZE * 2 + 0x100,
    BLOCK_SIZE * 4,
    BLOCK_SIZE * 4 + 0x18,
    BLOCK_SIZE * 5,
    BLOCK_SIZE * 6,
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReaderOutcome {
    group0_ok: bool,
    root_mode: Option<u16>,
    file_mode: Option<u16>,
    file_read_len: Option<usize>,
    file_read_prefix: Option<Vec<u8>>,
    file_xattr_count: Option<usize>,
    root_dir_count: Option<usize>,
    root_dir_has_file: Option<bool>,
    lookup_file_inode: Option<u32>,
    fast_link_target: Option<Vec<u8>>,
    long_link_target: Option<Vec<u8>>,
    root_block_ok: bool,
    file_block_ok: bool,
    resolve_file_ino: Option<u64>,
    follow_fast_link_ino: Option<u64>,
    follow_long_link_ino: Option<u64>,
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

    fn next_index(&mut self, len: usize) -> usize {
        if len == 0 {
            0
        } else {
            usize::from(self.next_u8()) % len
        }
    }

    fn remainder(&self) -> &'a [u8] {
        self.data.get(self.pos..).unwrap_or(&[])
    }
}

fn inode_offset(ino: u32) -> usize {
    usize::try_from(INODE_TABLE_BLOCK).unwrap_or(0) * BLOCK_SIZE
        + usize::try_from(ino.saturating_sub(1)).unwrap_or(0) * INODE_SIZE
}

fn write_dir_entry(
    buf: &mut [u8],
    offset: usize,
    inode: u32,
    file_type: u8,
    name: &[u8],
    rec_len: u16,
) {
    buf[offset..offset + 4].copy_from_slice(&inode.to_le_bytes());
    buf[offset + 4..offset + 6].copy_from_slice(&rec_len.to_le_bytes());
    buf[offset + 6] = u8::try_from(name.len()).unwrap_or(u8::MAX);
    buf[offset + 7] = file_type;
    buf[offset + 8..offset + 8 + name.len()].copy_from_slice(name);
}

fn write_extent_inode(
    image: &mut [u8],
    ino: u32,
    mode: u16,
    size: u64,
    links: u16,
    extent_block: u32,
    extent_len: u16,
) {
    let off = inode_offset(ino);
    image[off..off + 2].copy_from_slice(&mode.to_le_bytes());
    image[off + 0x04..off + 0x08].copy_from_slice(&(size as u32).to_le_bytes());
    image[off + 0x1A..off + 0x1C].copy_from_slice(&links.to_le_bytes());
    image[off + 0x20..off + 0x24].copy_from_slice(&0x0008_0000_u32.to_le_bytes());
    image[off + 0x64..off + 0x68].copy_from_slice(&1_u32.to_le_bytes());
    image[off + 0x6C..off + 0x70].copy_from_slice(&((size >> 32) as u32).to_le_bytes());

    let header = off + 0x28;
    image[header..header + 2].copy_from_slice(&0xF30A_u16.to_le_bytes());
    image[header + 2..header + 4].copy_from_slice(&1_u16.to_le_bytes());
    image[header + 4..header + 6].copy_from_slice(&4_u16.to_le_bytes());
    image[header + 6..header + 8].copy_from_slice(&0_u16.to_le_bytes());

    let extent = header + 12;
    image[extent..extent + 4].copy_from_slice(&0_u32.to_le_bytes());
    image[extent + 4..extent + 6].copy_from_slice(&extent_len.to_le_bytes());
    image[extent + 6..extent + 8].copy_from_slice(&0_u16.to_le_bytes());
    image[extent + 8..extent + 12].copy_from_slice(&extent_block.to_le_bytes());
}

fn write_fast_symlink_inode(image: &mut [u8], ino: u32, target: &[u8]) {
    let off = inode_offset(ino);
    image[off..off + 2].copy_from_slice(&0o120_777_u16.to_le_bytes());
    image[off + 0x04..off + 0x08]
        .copy_from_slice(&(u32::try_from(target.len()).unwrap_or(u32::MAX)).to_le_bytes());
    image[off + 0x1A..off + 0x1C].copy_from_slice(&1_u16.to_le_bytes());
    image[off + 0x28..off + 0x28 + target.len()].copy_from_slice(target);
}

fn build_clean_image() -> Vec<u8> {
    let mut image = vec![0_u8; IMAGE_SIZE];
    let sb = EXT4_SUPERBLOCK_OFFSET;
    image[sb + 0x38..sb + 0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
    image[sb + 0x18..sb + 0x1C].copy_from_slice(&2_u32.to_le_bytes());
    image[sb..sb + 0x04].copy_from_slice(&8192_u32.to_le_bytes());
    image[sb + 0x04..sb + 0x08].copy_from_slice(&(IMAGE_BLOCKS as u32).to_le_bytes());
    image[sb + 0x20..sb + 0x24].copy_from_slice(&(IMAGE_BLOCKS as u32).to_le_bytes());
    image[sb + 0x28..sb + 0x2C].copy_from_slice(&8192_u32.to_le_bytes());
    image[sb + 0x54..sb + 0x58].copy_from_slice(&11_u32.to_le_bytes());
    image[sb + 0x58..sb + 0x5A].copy_from_slice(&(INODE_SIZE as u16).to_le_bytes());

    image[BLOCK_SIZE + 0x08..BLOCK_SIZE + 0x0C].copy_from_slice(&INODE_TABLE_BLOCK.to_le_bytes());

    write_extent_inode(
        &mut image,
        ROOT_INO,
        0o040_755,
        BLOCK_SIZE as u64,
        2,
        ROOT_DIR_BLOCK,
        1,
    );
    write_extent_inode(&mut image, FILE_INO, 0o100_644, 27, 1, FILE_DATA_BLOCK, 1);
    write_fast_symlink_inode(&mut image, FAST_LINK_INO, b"file");
    write_extent_inode(
        &mut image,
        LONG_LINK_INO,
        0o120_777,
        4,
        1,
        LONG_LINK_BLOCK,
        1,
    );

    let root = ROOT_DIR_BLOCK as usize * BLOCK_SIZE;
    write_dir_entry(&mut image, root, ROOT_INO, 2, b".", 12);
    write_dir_entry(&mut image, root + 12, ROOT_INO, 2, b"..", 12);
    write_dir_entry(&mut image, root + 24, FILE_INO, 1, b"file", 12);
    write_dir_entry(&mut image, root + 36, FAST_LINK_INO, 7, b"link", 12);
    write_dir_entry(
        &mut image,
        root + 48,
        LONG_LINK_INO,
        7,
        b"longlink",
        (BLOCK_SIZE - 48) as u16,
    );

    image[FILE_DATA_BLOCK as usize * BLOCK_SIZE..FILE_DATA_BLOCK as usize * BLOCK_SIZE + 27]
        .copy_from_slice(b"FrankenFS ext4 reader fuzz\n");
    image[LONG_LINK_BLOCK as usize * BLOCK_SIZE..LONG_LINK_BLOCK as usize * BLOCK_SIZE + 4]
        .copy_from_slice(b"file");
    image
}

fn apply_mutations(image: &mut [u8], cursor: &mut ByteCursor<'_>) {
    let mutation_count = cursor.next_index(MAX_MUTATIONS + 1);
    for _ in 0..mutation_count {
        let offset = if cursor.next_u8() & 1 == 0 {
            INTERESTING_OFFSETS[cursor.next_index(INTERESTING_OFFSETS.len())]
        } else {
            cursor.next_index(image.len())
        };
        if let Some(slot) = image.get_mut(offset) {
            *slot ^= cursor.next_u8();
        }
    }
}

fn build_input(data: &[u8]) -> Vec<u8> {
    let mut cursor = ByteCursor::new(data);
    match cursor.next_u8() % 4 {
        0 => build_clean_image(),
        1 => {
            let mut image = build_clean_image();
            apply_mutations(&mut image, &mut cursor);
            image
        }
        2 => {
            let mut image = build_clean_image();
            image.truncate(cursor.next_index(image.len() + 1));
            image
        }
        _ => cursor
            .remainder()
            .iter()
            .copied()
            .take(IMAGE_SIZE)
            .collect(),
    }
}

fn input_selects_clean_image(data: &[u8]) -> bool {
    data.first().copied().unwrap_or(0) % 4 == 0
}

fn run_reader_workflow(image: &[u8]) -> Option<ReaderOutcome> {
    let reader = Ext4ImageReader::new(image).ok()?;
    let root_inode = reader
        .read_inode(image, InodeNumber(u64::from(ROOT_INO)))
        .ok();
    let file_inode = reader
        .read_inode(image, InodeNumber(u64::from(FILE_INO)))
        .ok();
    let fast_link_inode = reader
        .read_inode(image, InodeNumber(u64::from(FAST_LINK_INO)))
        .ok();
    let long_link_inode = reader
        .read_inode(image, InodeNumber(u64::from(LONG_LINK_INO)))
        .ok();

    let (file_read_len, file_read_prefix) = if let Some(inode) = file_inode.as_ref() {
        let mut buf = [0_u8; 32];
        match reader.read_inode_data(image, inode, 0, &mut buf) {
            Ok(len) => {
                let prefix_len = len.min(buf.len());
                (Some(len), Some(buf[..prefix_len].to_vec()))
            }
            Err(_) => (None, None),
        }
    } else {
        (None, None)
    };

    let file_xattr_count = file_inode
        .as_ref()
        .and_then(|inode| reader.read_xattrs_ibody(inode).ok())
        .map(|xattrs| xattrs.len());

    let root_dir_entries = root_inode
        .as_ref()
        .and_then(|inode| reader.read_dir(image, inode).ok());
    let root_dir_count = root_dir_entries.as_ref().map(Vec::len);
    let root_dir_has_file = root_dir_entries
        .as_ref()
        .map(|entries| entries.iter().any(|entry| entry.name == b"file"));

    let lookup_file_inode = root_inode
        .as_ref()
        .and_then(|inode| reader.lookup(image, inode, b"file").ok())
        .flatten()
        .map(|entry| entry.inode);

    Some(ReaderOutcome {
        group0_ok: reader.read_group_desc(image, GroupNumber(0)).is_ok(),
        root_mode: root_inode.as_ref().map(|inode| inode.mode),
        file_mode: file_inode.as_ref().map(|inode| inode.mode),
        file_read_len,
        file_read_prefix,
        file_xattr_count,
        root_dir_count,
        root_dir_has_file,
        lookup_file_inode,
        fast_link_target: fast_link_inode
            .as_ref()
            .and_then(|inode| reader.read_symlink(image, inode).ok()),
        long_link_target: long_link_inode
            .as_ref()
            .and_then(|inode| reader.read_symlink(image, inode).ok()),
        root_block_ok: reader
            .read_block(image, BlockNumber(u64::from(ROOT_DIR_BLOCK)))
            .is_ok(),
        file_block_ok: reader
            .read_block(image, BlockNumber(u64::from(FILE_DATA_BLOCK)))
            .is_ok(),
        resolve_file_ino: reader
            .resolve_path(image, "/file")
            .ok()
            .map(|(ino, _)| ino.0),
        follow_fast_link_ino: reader
            .resolve_path_follow(image, "/link")
            .ok()
            .map(|(ino, _)| ino.0),
        follow_long_link_ino: reader
            .resolve_path_follow(image, "/longlink")
            .ok()
            .map(|(ino, _)| ino.0),
    })
}

fn assert_clean_image_outcome(outcome: &ReaderOutcome) {
    assert!(outcome.group0_ok);
    assert_eq!(outcome.root_mode, Some(0o040_755));
    assert_eq!(outcome.file_mode, Some(0o100_644));
    assert_eq!(outcome.file_read_len, Some(27));
    assert_eq!(
        outcome.file_read_prefix.as_deref(),
        Some(b"FrankenFS ext4 reader fuzz\n".as_slice())
    );
    assert_eq!(outcome.file_xattr_count, Some(0));
    assert_eq!(outcome.root_dir_count, Some(5));
    assert_eq!(outcome.root_dir_has_file, Some(true));
    assert_eq!(outcome.lookup_file_inode, Some(FILE_INO));
    assert_eq!(
        outcome.fast_link_target.as_deref(),
        Some(b"file".as_slice())
    );
    assert_eq!(
        outcome.long_link_target.as_deref(),
        Some(b"file".as_slice())
    );
    assert!(outcome.root_block_ok);
    assert!(outcome.file_block_ok);
    assert_eq!(outcome.resolve_file_ino, Some(u64::from(FILE_INO)));
    assert_eq!(outcome.follow_fast_link_ino, Some(u64::from(FILE_INO)));
    assert_eq!(outcome.follow_long_link_ino, Some(u64::from(FILE_INO)));
}

fuzz_target!(|data: &[u8]| {
    let image = build_input(data);
    let first = run_reader_workflow(&image);
    let second = run_reader_workflow(&image);
    assert_eq!(
        first, second,
        "ext4 image reader workflow should be deterministic for identical images"
    );
    if input_selects_clean_image(data) {
        assert_clean_image_outcome(first.as_ref().expect("clean synthetic image must mount"));
    }
});
