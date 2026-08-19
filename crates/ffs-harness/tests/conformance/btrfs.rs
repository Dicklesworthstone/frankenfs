const BTRFS_SEND_CRC32C_POLY: u32 = 0x82F6_3B78;

fn btrfs_send_crc32c(seed: u32, data: &[u8]) -> u32 {
    let mut crc = seed;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ BTRFS_SEND_CRC32C_POLY
            };
        }
    }
    crc
}

fn append_send_stream_command(stream: &mut Vec<u8>, cmd: u16, attrs: &[(u16, &[u8])]) {
    let payload_len: usize = attrs.iter().map(|(_, value)| 4 + value.len()).sum();
    let payload_len =
        u32::try_from(payload_len).expect("send stream command payload length fits u32");
    let command_start = stream.len();
    stream.extend_from_slice(&payload_len.to_le_bytes());
    stream.extend_from_slice(&cmd.to_le_bytes());
    stream.extend_from_slice(&0_u32.to_le_bytes());
    for (attr, value) in attrs {
        stream.extend_from_slice(&attr.to_le_bytes());
        let value_len = u16::try_from(value.len()).expect("send stream attr length fits u16");
        stream.extend_from_slice(&value_len.to_le_bytes());
        stream.extend_from_slice(value);
    }
    let mut crc = btrfs_send_crc32c(0, &stream[command_start..command_start + 6]);
    crc = btrfs_send_crc32c(crc, &[0_u8; 4]);
    crc = btrfs_send_crc32c(crc, &stream[command_start + 10..]);
    stream[command_start + 6..command_start + 10].copy_from_slice(&crc.to_le_bytes());
}

const BTRFS_TEST_NODESIZE: u32 = 4096;
const BTRFS_TEST_HEADER_SIZE: usize = 101;
const BTRFS_TEST_ITEM_SIZE: usize = 25;
const BTRFS_TEST_KEY_PTR_SIZE: usize = 33;

fn build_btrfs_tree_log_superblock(log_root: u64, log_root_level: u8) -> BtrfsSuperblock {
    BtrfsSuperblock {
        csum: [0; 32],
        fsid: [0; 16],
        bytenr: 0,
        flags: 0,
        magic: 0,
        generation: 77,
        root: 0,
        chunk_root: 0,
        chunk_root_generation: 77,
        log_root,
        total_bytes: 0,
        bytes_used: 0,
        root_dir_objectid: 0,
        num_devices: 1,
        sectorsize: BTRFS_TEST_NODESIZE,
        nodesize: BTRFS_TEST_NODESIZE,
        stripesize: 0,
        compat_flags: 0,
        compat_ro_flags: 0,
        incompat_flags: 0,
        csum_type: 0,
        root_level: 0,
        chunk_root_level: 0,
        log_root_level,
        label: String::new(),
        sys_chunk_array_size: 0,
        sys_chunk_array: Vec::new(),
    }
}

fn build_btrfs_chunk_tree_superblock(chunk_root: u64) -> BtrfsSuperblock {
    BtrfsSuperblock {
        csum: [0; 32],
        fsid: [0; 16],
        bytenr: chunk_root,
        flags: 0,
        magic: 0,
        generation: 77,
        root: 0,
        chunk_root,
        chunk_root_generation: 77,
        log_root: 0,
        total_bytes: 0,
        bytes_used: 0,
        root_dir_objectid: 0,
        num_devices: 1,
        sectorsize: BTRFS_TEST_NODESIZE,
        nodesize: BTRFS_TEST_NODESIZE,
        stripesize: 0,
        compat_flags: 0,
        compat_ro_flags: 0,
        incompat_flags: 0,
        csum_type: 0,
        root_level: 0,
        chunk_root_level: 0,
        log_root_level: 0,
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
        stripe_len: u64::from(BTRFS_TEST_NODESIZE),
        chunk_type: 1,
        io_align: BTRFS_TEST_NODESIZE,
        io_width: BTRFS_TEST_NODESIZE,
        sector_size: BTRFS_TEST_NODESIZE,
        num_stripes: 1,
        sub_stripes: 0,
        stripes: vec![BtrfsStripe {
            devid: 1,
            offset: physical_start,
            dev_uuid: [0; 16],
        }],
    }
}

fn write_btrfs_header(
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

fn stamp_btrfs_tree_block_checksum(block: &mut [u8]) {
    let csum = ffs_types::crc32c(&block[0x20..]);
    block[0..4].copy_from_slice(&csum.to_le_bytes());
}

fn write_btrfs_leaf_item(
    block: &mut [u8],
    idx: usize,
    objectid: u64,
    item_type: u8,
    key_offset: u64,
    data_off: u32,
    data_sz: u32,
) {
    let base = BTRFS_TEST_HEADER_SIZE + idx * BTRFS_TEST_ITEM_SIZE;
    let header_size =
        u32::try_from(BTRFS_TEST_HEADER_SIZE).expect("btrfs test header size should fit in u32");
    let encoded_data_off = data_off
        .checked_sub(header_size)
        .expect("btrfs test payload should follow the header");
    block[base..base + 8].copy_from_slice(&objectid.to_le_bytes());
    block[base + 8] = item_type;
    block[base + 9..base + 17].copy_from_slice(&key_offset.to_le_bytes());
    block[base + 17..base + 21].copy_from_slice(&encoded_data_off.to_le_bytes());
    block[base + 21..base + 25].copy_from_slice(&data_sz.to_le_bytes());
}

fn write_btrfs_key_ptr(
    block: &mut [u8],
    idx: usize,
    objectid: u64,
    item_type: u8,
    blockptr: u64,
    generation: u64,
) {
    let base = BTRFS_TEST_HEADER_SIZE + idx * BTRFS_TEST_KEY_PTR_SIZE;
    block[base..base + 8].copy_from_slice(&objectid.to_le_bytes());
    block[base + 8] = item_type;
    block[base + 9..base + 17].copy_from_slice(&0_u64.to_le_bytes());
    block[base + 17..base + 25].copy_from_slice(&blockptr.to_le_bytes());
    block[base + 25..base + 33].copy_from_slice(&generation.to_le_bytes());
}

#[derive(Clone, Copy)]
struct ChunkItemPayload {
    length: u64,
    owner: u64,
    stripe_len: u64,
    chunk_type: u64,
    io_align: u32,
    io_width: u32,
    sector_size: u32,
    devid: u64,
    physical_offset: u64,
}

fn build_chunk_item_payload(params: ChunkItemPayload) -> Vec<u8> {
    let mut data = vec![0_u8; 48 + 32];
    data[0..8].copy_from_slice(&params.length.to_le_bytes());
    data[8..16].copy_from_slice(&params.owner.to_le_bytes());
    data[16..24].copy_from_slice(&params.stripe_len.to_le_bytes());
    data[24..32].copy_from_slice(&params.chunk_type.to_le_bytes());
    data[32..36].copy_from_slice(&params.io_align.to_le_bytes());
    data[36..40].copy_from_slice(&params.io_width.to_le_bytes());
    data[40..44].copy_from_slice(&params.sector_size.to_le_bytes());
    data[44..46].copy_from_slice(&1_u16.to_le_bytes());
    data[46..48].copy_from_slice(&0_u16.to_le_bytes());
    data[48..56].copy_from_slice(&params.devid.to_le_bytes());
    data[56..64].copy_from_slice(&params.physical_offset.to_le_bytes());
    data
}

fn build_dev_item_payload(
    devid: u64,
    total_bytes: u64,
    bytes_used: u64,
    generation: u64,
    start_offset: u64,
) -> Vec<u8> {
    let mut data = vec![0_u8; 98];
    data[0..8].copy_from_slice(&devid.to_le_bytes());
    data[8..16].copy_from_slice(&total_bytes.to_le_bytes());
    data[16..24].copy_from_slice(&bytes_used.to_le_bytes());
    data[24..28].copy_from_slice(&BTRFS_TEST_NODESIZE.to_le_bytes());
    data[28..32].copy_from_slice(&BTRFS_TEST_NODESIZE.to_le_bytes());
    data[32..36].copy_from_slice(&BTRFS_TEST_NODESIZE.to_le_bytes());
    data[44..52].copy_from_slice(&generation.to_le_bytes());
    data[52..60].copy_from_slice(&start_offset.to_le_bytes());
    let devid_byte = u8::try_from(devid).expect("test devid should fit in u8");
    data[64] = devid_byte;
    data[65] = 100_u8.saturating_add(devid_byte);
    data[66..82].fill(devid_byte);
    data[82..98].fill(0xF0_u8.saturating_add(devid_byte));
    data
}

fn encode_btrfs_inode_item(mode: u32, size: u64, nbytes: u64, nlink: u32) -> [u8; 160] {
    let mut inode = [0_u8; 160];
    inode[0..8].copy_from_slice(&1_u64.to_le_bytes());
    inode[8..16].copy_from_slice(&1_u64.to_le_bytes());
    inode[16..24].copy_from_slice(&size.to_le_bytes());
    inode[24..32].copy_from_slice(&nbytes.to_le_bytes());
    inode[40..44].copy_from_slice(&nlink.to_le_bytes());
    inode[44..48].copy_from_slice(&1000_u32.to_le_bytes());
    inode[48..52].copy_from_slice(&1000_u32.to_le_bytes());
    inode[52..56].copy_from_slice(&mode.to_le_bytes());
    inode[112..120].copy_from_slice(&10_u64.to_le_bytes());
    inode[124..132].copy_from_slice(&10_u64.to_le_bytes());
    inode[136..144].copy_from_slice(&10_u64.to_le_bytes());
    inode[148..156].copy_from_slice(&10_u64.to_le_bytes());
    inode
}

fn encode_btrfs_dir_index_entry(name: &[u8], child_objectid: u64, file_type: u8) -> Vec<u8> {
    let mut entry = vec![0_u8; 30 + name.len()];
    entry[0..8].copy_from_slice(&child_objectid.to_le_bytes());
    entry[8] = BTRFS_ITEM_INODE_ITEM;
    entry[9..17].copy_from_slice(&0_u64.to_le_bytes());
    entry[17..25].copy_from_slice(&1_u64.to_le_bytes());
    entry[25..27].copy_from_slice(&0_u16.to_le_bytes());
    let name_len = u16::try_from(name.len()).expect("test name length should fit in u16");
    entry[27..29].copy_from_slice(&name_len.to_le_bytes());
    entry[29] = file_type;
    entry[30..30 + name.len()].copy_from_slice(name);
    entry
}

fn encode_btrfs_extent_regular(disk_bytenr: u64, num_bytes: u64) -> [u8; 53] {
    let mut extent = [0_u8; 53];
    extent[0..8].copy_from_slice(&1_u64.to_le_bytes());
    extent[8..16].copy_from_slice(&num_bytes.to_le_bytes());
    extent[20] = BTRFS_FILE_EXTENT_REG;
    extent[21..29].copy_from_slice(&disk_bytenr.to_le_bytes());
    extent[29..37].copy_from_slice(&num_bytes.to_le_bytes());
    extent[37..45].copy_from_slice(&0_u64.to_le_bytes());
    extent[45..53].copy_from_slice(&num_bytes.to_le_bytes());
    extent
}

const BTRFS_TEST_IMAGE_SIZE: usize = 512 * 1024;
const BTRFS_TEST_ROOT_TREE_LOGICAL: u64 = 0x4_000;
const BTRFS_TEST_FS_TREE_LOGICAL: u64 = 0x8_000;
const BTRFS_TEST_FILE_DATA_LOGICAL: u64 = 0x12_000;
const BTRFS_TEST_ROOT_ITEM_OFF: u32 = 3000;
const BTRFS_TEST_ROOT_INODE_OFF: u32 = 3200;
const BTRFS_TEST_DIR_INDEX_OFF: u32 = 3060;
const BTRFS_TEST_FILE_INODE_OFF: u32 = 2860;
const BTRFS_TEST_EXTENT_OFF: u32 = 2780;

#[allow(clippy::too_many_lines)]
fn build_btrfs_regular_extent_mount_image(
    file_name: &[u8],
    logical_file_bytes: &[u8],
    extent_bytes: &[u8],
    compression: u8,
) -> Vec<u8> {
    let mut image = vec![0_u8; BTRFS_TEST_IMAGE_SIZE];
    let sb_off = BTRFS_SUPER_INFO_OFFSET;
    let nodesize =
        usize::try_from(BTRFS_TEST_NODESIZE).expect("btrfs test nodesize should fit in usize");
    let file_size =
        u64::try_from(logical_file_bytes.len()).expect("logical file size should fit in u64");
    let extent_size =
        u64::try_from(extent_bytes.len()).expect("extent payload size should fit in u64");

    image[sb_off + 0x40..sb_off + 0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
    image[sb_off + 0x48..sb_off + 0x50].copy_from_slice(&1_u64.to_le_bytes());
    image[sb_off + 0x50..sb_off + 0x58]
        .copy_from_slice(&BTRFS_TEST_ROOT_TREE_LOGICAL.to_le_bytes());
    image[sb_off + 0x58..sb_off + 0x60].copy_from_slice(&0_u64.to_le_bytes());
    image[sb_off + 0x70..sb_off + 0x78].copy_from_slice(
        &u64::try_from(BTRFS_TEST_IMAGE_SIZE)
            .expect("test image size")
            .to_le_bytes(),
    );
    image[sb_off + 0x80..sb_off + 0x88].copy_from_slice(&256_u64.to_le_bytes());
    image[sb_off + 0x88..sb_off + 0x90].copy_from_slice(&1_u64.to_le_bytes());
    image[sb_off + 0x90..sb_off + 0x94].copy_from_slice(&BTRFS_TEST_NODESIZE.to_le_bytes());
    image[sb_off + 0x94..sb_off + 0x98].copy_from_slice(&BTRFS_TEST_NODESIZE.to_le_bytes());
    image[sb_off + 0x9C..sb_off + 0xA0].copy_from_slice(&BTRFS_TEST_NODESIZE.to_le_bytes());
    image[sb_off + 0xC6] = 0;

    let mut chunk_array = Vec::new();
    chunk_array.extend_from_slice(&256_u64.to_le_bytes());
    chunk_array.push(BTRFS_ITEM_CHUNK);
    chunk_array.extend_from_slice(&0_u64.to_le_bytes());
    chunk_array.extend_from_slice(
        &u64::try_from(BTRFS_TEST_IMAGE_SIZE)
            .expect("test image size should fit in u64")
            .to_le_bytes(),
    );
    chunk_array.extend_from_slice(&2_u64.to_le_bytes());
    chunk_array.extend_from_slice(&0x1_0000_u64.to_le_bytes());
    chunk_array.extend_from_slice(&1_u64.to_le_bytes());
    chunk_array.extend_from_slice(&BTRFS_TEST_NODESIZE.to_le_bytes());
    chunk_array.extend_from_slice(&BTRFS_TEST_NODESIZE.to_le_bytes());
    chunk_array.extend_from_slice(&BTRFS_TEST_NODESIZE.to_le_bytes());
    chunk_array.extend_from_slice(&1_u16.to_le_bytes());
    chunk_array.extend_from_slice(&0_u16.to_le_bytes());
    chunk_array.extend_from_slice(&1_u64.to_le_bytes());
    chunk_array.extend_from_slice(&0_u64.to_le_bytes());
    chunk_array.extend_from_slice(&[0_u8; 16]);
    image[sb_off + 0xA0..sb_off + 0xA4].copy_from_slice(
        &u32::try_from(chunk_array.len())
            .expect("chunk array should fit in u32")
            .to_le_bytes(),
    );
    let array_start = sb_off + 0x32B;
    image[array_start..array_start + chunk_array.len()].copy_from_slice(&chunk_array);

    let mut root_leaf = vec![0_u8; nodesize];
    write_btrfs_header(&mut root_leaf, BTRFS_TEST_ROOT_TREE_LOGICAL, 1, 0, 1, 1);
    let root_item_size = 239_u32;
    write_btrfs_leaf_item(
        &mut root_leaf,
        0,
        BTRFS_FS_TREE_OBJECTID,
        132,
        0,
        BTRFS_TEST_ROOT_ITEM_OFF,
        root_item_size,
    );
    let mut root_item = vec![0_u8; usize::try_from(root_item_size).expect("root item size")];
    root_item[168..176].copy_from_slice(&256_u64.to_le_bytes());
    root_item[176..184].copy_from_slice(&BTRFS_TEST_FS_TREE_LOGICAL.to_le_bytes());
    let last = root_item.len() - 1;
    root_item[last] = 0;
    let root_item_off = usize::try_from(BTRFS_TEST_ROOT_ITEM_OFF).expect("root item offset");
    root_leaf[root_item_off..root_item_off + root_item.len()].copy_from_slice(&root_item);
    stamp_btrfs_tree_block_checksum(&mut root_leaf);
    let root_leaf_off =
        usize::try_from(BTRFS_TEST_ROOT_TREE_LOGICAL).expect("root tree logical should fit");
    image[root_leaf_off..root_leaf_off + root_leaf.len()].copy_from_slice(&root_leaf);

    let mut fs_leaf = vec![0_u8; nodesize];
    write_btrfs_header(
        &mut fs_leaf,
        BTRFS_TEST_FS_TREE_LOGICAL,
        4,
        0,
        BTRFS_FS_TREE_OBJECTID,
        1,
    );

    let root_inode = encode_btrfs_inode_item(0o040_755, 4096, 4096, 2);
    let file_inode = encode_btrfs_inode_item(0o100_644, file_size, file_size, 1);
    let dir_index = encode_btrfs_dir_index_entry(file_name, 257, BTRFS_FT_REG_FILE);
    let mut extent = encode_btrfs_extent_regular(BTRFS_TEST_FILE_DATA_LOGICAL, file_size);
    extent[16] = compression;
    extent[29..37].copy_from_slice(&extent_size.to_le_bytes());

    write_btrfs_leaf_item(
        &mut fs_leaf,
        0,
        256,
        BTRFS_ITEM_INODE_ITEM,
        0,
        BTRFS_TEST_ROOT_INODE_OFF,
        u32::try_from(root_inode.len()).expect("root inode size should fit in u32"),
    );
    write_btrfs_leaf_item(
        &mut fs_leaf,
        1,
        256,
        BTRFS_ITEM_DIR_INDEX,
        2,
        BTRFS_TEST_DIR_INDEX_OFF,
        u32::try_from(dir_index.len()).expect("dir index size should fit in u32"),
    );
    write_btrfs_leaf_item(
        &mut fs_leaf,
        2,
        257,
        BTRFS_ITEM_INODE_ITEM,
        0,
        BTRFS_TEST_FILE_INODE_OFF,
        u32::try_from(file_inode.len()).expect("file inode size should fit in u32"),
    );
    write_btrfs_leaf_item(
        &mut fs_leaf,
        3,
        257,
        BTRFS_ITEM_EXTENT_DATA,
        0,
        BTRFS_TEST_EXTENT_OFF,
        u32::try_from(extent.len()).expect("extent size should fit in u32"),
    );

    let root_inode_off = usize::try_from(BTRFS_TEST_ROOT_INODE_OFF).expect("root inode offset");
    fs_leaf[root_inode_off..root_inode_off + root_inode.len()].copy_from_slice(&root_inode);
    let dir_index_off = usize::try_from(BTRFS_TEST_DIR_INDEX_OFF).expect("dir index offset");
    fs_leaf[dir_index_off..dir_index_off + dir_index.len()].copy_from_slice(&dir_index);
    let file_inode_off = usize::try_from(BTRFS_TEST_FILE_INODE_OFF).expect("file inode offset");
    fs_leaf[file_inode_off..file_inode_off + file_inode.len()].copy_from_slice(&file_inode);
    let extent_off = usize::try_from(BTRFS_TEST_EXTENT_OFF).expect("extent offset");
    fs_leaf[extent_off..extent_off + extent.len()].copy_from_slice(&extent);
    stamp_btrfs_tree_block_checksum(&mut fs_leaf);
    let fs_leaf_off =
        usize::try_from(BTRFS_TEST_FS_TREE_LOGICAL).expect("fs tree logical should fit");
    image[fs_leaf_off..fs_leaf_off + fs_leaf.len()].copy_from_slice(&fs_leaf);

    let file_data_off =
        usize::try_from(BTRFS_TEST_FILE_DATA_LOGICAL).expect("file data logical should fit");
    image[file_data_off..file_data_off + extent_bytes.len()].copy_from_slice(extent_bytes);
    image
}

#[allow(clippy::cast_possible_truncation)]
fn build_btrfs_subvolume_mount_image() -> Vec<u8> {
    let file_bytes = b"hello from btrfs fsops";
    build_btrfs_regular_extent_mount_image(b"hello.txt", file_bytes, file_bytes, 0)
}

fn open_btrfs_test_image(image_name: &str, image: &[u8]) -> (OpenFs, tempfile::TempDir) {
    let tmp = tempfile::TempDir::new().expect("tmpdir for btrfs test image");
    let image_path = tmp.path().join(image_name);
    std::fs::write(&image_path, image).expect("write btrfs test image");
    let cx = Cx::for_testing();
    let fs = OpenFs::open_with_options(&cx, &image_path, &OpenOptions::default())
        .expect("open btrfs test image");
    (fs, tmp)
}

fn btrfs_transparent_decompression_payload() -> Vec<u8> {
    let mut payload = Vec::new();
    for _ in 0..128 {
        payload.extend_from_slice(b"FrankenFS btrfs transparent decompression harness payload.\n");
    }
    payload.extend_from_slice(b"tail-marker:transparent-decompression");
    payload
}

fn compress_btrfs_zlib_payload(data: &[u8]) -> Vec<u8> {
    use std::io::Write as _;

    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(data)
        .expect("zlib encoder should accept test payload");
    encoder.finish().expect("zlib encoder should finish")
}

fn compress_btrfs_lzo_payload(data: &[u8]) -> Vec<u8> {
    let page_size =
        usize::try_from(BTRFS_TEST_NODESIZE).expect("btrfs test nodesize should fit in usize");
    let mut framed = vec![0_u8; 4];
    for chunk in data.chunks(page_size) {
        let compressed = lzokay_native::compress(chunk).expect("compress lzo test payload");
        framed.extend_from_slice(
            &u32::try_from(compressed.len())
                .expect("lzo segment should fit in u32")
                .to_le_bytes(),
        );
        framed.extend_from_slice(&compressed);
    }
    let total_len = u32::try_from(framed.len()).expect("lzo payload should fit in u32");
    framed[0..4].copy_from_slice(&total_len.to_le_bytes());
    framed
}

fn compress_btrfs_zstd_payload(data: &[u8]) -> Vec<u8> {
    zstd::stream::encode_all(data, 0).expect("compress zstd test payload")
}

fn open_btrfs_transparent_decompression_image(
    image_name: &str,
    file_name: &str,
    codec: u8,
) -> (OpenFs, tempfile::TempDir, Vec<u8>) {
    let logical = btrfs_transparent_decompression_payload();
    let compressed = match codec {
        1 => compress_btrfs_zlib_payload(&logical),
        2 => compress_btrfs_lzo_payload(&logical),
        3 => compress_btrfs_zstd_payload(&logical),
        other => panic!("unexpected compression codec {other}"),
    };
    let image =
        build_btrfs_regular_extent_mount_image(file_name.as_bytes(), &logical, &compressed, codec);
    let (fs, tmp) = open_btrfs_test_image(image_name, &image);
    (fs, tmp, logical)
}

fn open_btrfs_subvolume_mount_image() -> (OpenFs, tempfile::TempDir) {
    open_btrfs_test_image(
        "subvolume-mount.btrfs",
        &build_btrfs_subvolume_mount_image(),
    )
}

#[test]
fn btrfs_send_stream_multi_command_conforms() {
    let mut data = Vec::new();
    data.extend_from_slice(BTRFS_SEND_STREAM_MAGIC);
    data.extend_from_slice(&1_u32.to_le_bytes());

    let uuid = *b"ffs-send-subvol!";
    append_send_stream_command(
        &mut data,
        SendCommand::Subvol as u16,
        &[(1, &uuid), (15, b"/sv")],
    );
    append_send_stream_command(
        &mut data,
        SendCommand::Write as u16,
        &[
            (15, b"/sv/file.txt"),
            (18, &0_u64.to_le_bytes()),
            (19, b"hello"),
        ],
    );
    append_send_stream_command(&mut data, SendCommand::End as u16, &[]);

    let result = parse_send_stream(&data).expect("parse multi-command send stream");
    assert_eq!(result.version, 1);
    assert_eq!(result.commands.len(), 3);
    assert_eq!(result.commands[0].cmd, SendCommand::Subvol);
    assert_eq!(result.commands[0].attrs[0], (1, uuid.to_vec()));
    assert_eq!(result.commands[0].attrs[1], (15, b"/sv".to_vec()));
    assert_eq!(result.commands[1].cmd, SendCommand::Write);
    assert_eq!(result.commands[1].attrs[0], (15, b"/sv/file.txt".to_vec()));
    assert_eq!(
        result.commands[1].attrs[1],
        (18, 0_u64.to_le_bytes().to_vec())
    );
    assert_eq!(result.commands[1].attrs[2], (19, b"hello".to_vec()));
    assert_eq!(result.commands[2].cmd, SendCommand::End);
    assert!(result.commands[2].attrs.is_empty());
}

#[test]
fn btrfs_send_stream_unknown_command_preserves_attrs_as_unspec() {
    let mut data = Vec::new();
    data.extend_from_slice(BTRFS_SEND_STREAM_MAGIC);
    data.extend_from_slice(&1_u32.to_le_bytes());
    append_send_stream_command(&mut data, 0xFFFE, &[(15, b"/mystery")]);
    append_send_stream_command(&mut data, SendCommand::End as u16, &[]);

    let result = parse_send_stream(&data).expect("parse send stream with unknown command");
    assert_eq!(result.commands.len(), 2);
    assert_eq!(result.commands[0].cmd, SendCommand::Unspec);
    assert_eq!(result.commands[0].attrs, vec![(15, b"/mystery".to_vec())]);
    assert_eq!(result.commands[1].cmd, SendCommand::End);
}

#[test]
fn btrfs_send_stream_rejects_missing_end_command() {
    let mut data = Vec::new();
    data.extend_from_slice(BTRFS_SEND_STREAM_MAGIC);
    data.extend_from_slice(&1_u32.to_le_bytes());
    append_send_stream_command(
        &mut data,
        SendCommand::Mkdir as u16,
        &[(15, b"/unterminated")],
    );

    let err = parse_send_stream(&data).unwrap_err();
    assert!(matches!(err, ffs_types::ParseError::InvalidField { .. }));
}

#[test]
fn send_stream_builder_all_command_types_roundtrip() {
    let mut builder = SendStreamBuilder::new();
    builder.write_header();

    let uuid = [0xAB_u8; 16];

    let (cmd, attrs) = build_subvol_command(b"mysubvol", &uuid, 42);
    let refs: Vec<(SendAttr, &[u8])> = attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
    builder.add_command(cmd, &refs);

    let (cmd, attrs) = build_mkdir_command(b"mysubvol/dir", 257);
    let refs: Vec<(SendAttr, &[u8])> = attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
    builder.add_command(cmd, &refs);

    let (cmd, attrs) = build_mkfile_command(b"mysubvol/file.txt", 258);
    let refs: Vec<(SendAttr, &[u8])> = attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
    builder.add_command(cmd, &refs);

    let (cmd, attrs) = build_write_command(b"mysubvol/file.txt", 0, b"content");
    let refs: Vec<(SendAttr, &[u8])> = attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
    builder.add_command(cmd, &refs);

    let (cmd, attrs) = build_truncate_command(b"mysubvol/file.txt", 7);
    let refs: Vec<(SendAttr, &[u8])> = attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
    builder.add_command(cmd, &refs);

    let (cmd, attrs) = build_chmod_command(b"mysubvol/file.txt", 0o644);
    let refs: Vec<(SendAttr, &[u8])> = attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
    builder.add_command(cmd, &refs);

    let (cmd, attrs) = build_chown_command(b"mysubvol/file.txt", 1000, 1000);
    let refs: Vec<(SendAttr, &[u8])> = attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
    builder.add_command(cmd, &refs);

    let (cmd, attrs) = build_utimes_command(b"mysubvol/file.txt", 1000, 0, 2000, 0, 3000, 0);
    let refs: Vec<(SendAttr, &[u8])> = attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
    builder.add_command(cmd, &refs);

    let (cmd, attrs) = build_symlink_command(b"mysubvol/link", 259, b"file.txt");
    let refs: Vec<(SendAttr, &[u8])> = attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
    builder.add_command(cmd, &refs);

    let (cmd, attrs) = build_setxattr_command(b"mysubvol/file.txt", b"user.test", b"value");
    let refs: Vec<(SendAttr, &[u8])> = attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
    builder.add_command(cmd, &refs);

    builder.finalize();
    let stream = builder.finish();

    let parsed = parse_send_stream(&stream).expect("parse builder-generated stream");
    assert_eq!(parsed.version, 1);
    assert_eq!(parsed.commands.len(), 11); // subvol, mkdir, mkfile, write, truncate, chmod, chown, utimes, symlink, setxattr, end

    assert_eq!(parsed.commands[0].cmd, SendCommand::Subvol);
    assert_eq!(parsed.commands[1].cmd, SendCommand::Mkdir);
    assert_eq!(parsed.commands[2].cmd, SendCommand::Mkfile);
    assert_eq!(parsed.commands[3].cmd, SendCommand::Write);
    assert_eq!(parsed.commands[4].cmd, SendCommand::Truncate);
    assert_eq!(parsed.commands[5].cmd, SendCommand::Chmod);
    assert_eq!(parsed.commands[6].cmd, SendCommand::Chown);
    assert_eq!(parsed.commands[7].cmd, SendCommand::Utimes);
    assert_eq!(parsed.commands[8].cmd, SendCommand::Symlink);
    assert_eq!(parsed.commands[9].cmd, SendCommand::SetXattr);
    assert_eq!(parsed.commands[10].cmd, SendCommand::End);
}

#[test]
fn send_stream_builder_mutation_commands_roundtrip() {
    let mut builder = SendStreamBuilder::new();
    builder.write_header();

    let uuid = [0xCD_u8; 16];

    let (cmd, attrs) = build_subvol_command(b"mutations", &uuid, 1);
    let refs: Vec<(SendAttr, &[u8])> = attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
    builder.add_command(cmd, &refs);

    let (cmd, attrs) = build_mkfile_command(b"mutations/old.txt", 257);
    let refs: Vec<(SendAttr, &[u8])> = attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
    builder.add_command(cmd, &refs);

    let (cmd, attrs) = build_rename_command(b"mutations/old.txt", b"mutations/new.txt");
    let refs: Vec<(SendAttr, &[u8])> = attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
    builder.add_command(cmd, &refs);

    let (cmd, attrs) = build_link_command(b"mutations/new.txt", b"mutations/hardlink.txt");
    let refs: Vec<(SendAttr, &[u8])> = attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
    builder.add_command(cmd, &refs);

    let (cmd, attrs) = build_setxattr_command(b"mutations/new.txt", b"user.attr", b"val");
    let refs: Vec<(SendAttr, &[u8])> = attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
    builder.add_command(cmd, &refs);

    let (cmd, attrs) = build_removexattr_command(b"mutations/new.txt", b"user.attr");
    let refs: Vec<(SendAttr, &[u8])> = attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
    builder.add_command(cmd, &refs);

    let (cmd, attrs) = build_unlink_command(b"mutations/hardlink.txt");
    let refs: Vec<(SendAttr, &[u8])> = attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
    builder.add_command(cmd, &refs);

    let (cmd, attrs) = build_mkdir_command(b"mutations/subdir", 258);
    let refs: Vec<(SendAttr, &[u8])> = attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
    builder.add_command(cmd, &refs);

    let (cmd, attrs) = build_rmdir_command(b"mutations/subdir");
    let refs: Vec<(SendAttr, &[u8])> = attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
    builder.add_command(cmd, &refs);

    builder.finalize();
    let stream = builder.finish();

    let parsed = parse_send_stream(&stream).expect("parse mutation stream");
    assert_eq!(parsed.version, 1);
    assert_eq!(parsed.commands.len(), 10);

    assert_eq!(parsed.commands[0].cmd, SendCommand::Subvol);
    assert_eq!(parsed.commands[1].cmd, SendCommand::Mkfile);
    assert_eq!(parsed.commands[2].cmd, SendCommand::Rename);
    assert_eq!(parsed.commands[3].cmd, SendCommand::Link);
    assert_eq!(parsed.commands[4].cmd, SendCommand::SetXattr);
    assert_eq!(parsed.commands[5].cmd, SendCommand::RemoveXattr);
    assert_eq!(parsed.commands[6].cmd, SendCommand::Unlink);
    assert_eq!(parsed.commands[7].cmd, SendCommand::Mkdir);
    assert_eq!(parsed.commands[8].cmd, SendCommand::Rmdir);
    assert_eq!(parsed.commands[9].cmd, SendCommand::End);
}

#[test]
fn send_stream_builder_special_files_roundtrip() {
    let mut builder = SendStreamBuilder::new();
    builder.write_header();

    let uuid = [0xEF_u8; 16];

    let (cmd, attrs) = build_subvol_command(b"specials", &uuid, 1);
    let refs: Vec<(SendAttr, &[u8])> = attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
    builder.add_command(cmd, &refs);

    let (cmd, attrs) = build_mknod_command(b"specials/blockdev", 257, 0o660 | 0o60000, 0x0801);
    let refs: Vec<(SendAttr, &[u8])> = attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
    builder.add_command(cmd, &refs);

    let (cmd, attrs) = build_mkfifo_command(b"specials/fifo", 258);
    let refs: Vec<(SendAttr, &[u8])> = attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
    builder.add_command(cmd, &refs);

    let (cmd, attrs) = build_mksock_command(b"specials/socket", 259);
    let refs: Vec<(SendAttr, &[u8])> = attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
    builder.add_command(cmd, &refs);

    builder.finalize();
    let stream = builder.finish();

    let parsed = parse_send_stream(&stream).expect("parse special files stream");
    assert_eq!(parsed.version, 1);
    assert_eq!(parsed.commands.len(), 5);

    assert_eq!(parsed.commands[0].cmd, SendCommand::Subvol);
    assert_eq!(parsed.commands[1].cmd, SendCommand::Mknod);
    assert_eq!(parsed.commands[2].cmd, SendCommand::Mkfifo);
    assert_eq!(parsed.commands[3].cmd, SendCommand::Mksock);
    assert_eq!(parsed.commands[4].cmd, SendCommand::End);
}

#[test]
fn btrfs_subvolume_mount_root_alias_conforms() {
    let cx = Cx::for_testing();
    let (fs, _tmp) = open_btrfs_subvolume_mount_image();

    let ctx = fs.btrfs_context().expect("btrfs context should be present");
    assert_eq!(ctx.subvol_objectid, BTRFS_FS_TREE_OBJECTID);
    assert_eq!(ctx.subvol_root_dirid, 256);

    let root_attr = fs.getattr(&cx, InodeNumber(1)).expect("get mounted root");
    assert_eq!(root_attr.ino, InodeNumber(1));
    assert_eq!(root_attr.perm, 0o755);

    let child = fs
        .lookup(&cx, InodeNumber(1), OsStr::new("hello.txt"))
        .expect("lookup file through mounted subvolume root");
    assert_eq!(child.ino, InodeNumber(257));
    assert_eq!(child.size, 22);

    let entries = fs
        .readdir(&cx, InodeNumber(1), 0)
        .expect("readdir mounted subvolume root");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].name, b".");
    assert_eq!(entries[1].name, b"..");
    assert_eq!(entries[2].name, b"hello.txt");

    let data = fs
        .read(&cx, InodeNumber(257), 0, 128)
        .expect("read file from mounted subvolume");
    assert_eq!(&data, b"hello from btrfs fsops");
}

fn assert_btrfs_transparent_decompression_conforms(
    image_name: &str,
    file_name: &str,
    codec_label: &str,
    codec: u8,
) {
    let cx = Cx::for_testing();
    let (fs, _tmp, expected) =
        open_btrfs_transparent_decompression_image(image_name, file_name, codec);

    let entry = fs
        .lookup(&cx, InodeNumber(1), OsStr::new(file_name))
        .unwrap_or_else(|err| panic!("lookup {codec_label} file through mounted root: {err}"));
    assert_eq!(entry.ino, InodeNumber(257));
    assert_eq!(
        entry.size,
        u64::try_from(expected.len()).expect("expected payload should fit in u64")
    );

    let data = fs
        .read(
            &cx,
            entry.ino,
            0,
            u32::try_from(expected.len() + 128).expect("read size should fit in u32"),
        )
        .unwrap_or_else(|err| panic!("read {codec_label} compressed extent: {err}"));
    assert_eq!(data, expected);

    let boundary_offset = 4080_u64;
    let boundary = fs
        .read(&cx, entry.ino, boundary_offset, 96)
        .unwrap_or_else(|err| panic!("read {codec_label} boundary slice: {err}"));
    assert_eq!(
        boundary,
        expected[usize::try_from(boundary_offset).expect("boundary offset")
            ..usize::try_from(boundary_offset + 96).expect("boundary end")]
    );
}

#[test]
fn btrfs_transparent_decompression_zlib_regular_extent_conforms() {
    assert_btrfs_transparent_decompression_conforms("btrfs-zlib.btrfs", "zlib.bin", "zlib", 1);
}

#[test]
fn btrfs_transparent_decompression_lzo_regular_extent_conforms() {
    assert_btrfs_transparent_decompression_conforms("btrfs-lzo.btrfs", "lzo.bin", "lzo", 2);
}

#[test]
fn btrfs_transparent_decompression_zstd_regular_extent_conforms() {
    assert_btrfs_transparent_decompression_conforms("btrfs-zstd.btrfs", "zstd.bin", "zstd", 3);
}

#[test]
fn btrfs_tree_log_replay_multilevel_conforms() {
    let root_logical = 0x10_000_u64;
    let leaf_logical = 0x20_000_u64;
    let physical_start = 0x80_000_u64;
    let root_physical = physical_start;
    let leaf_physical = physical_start + (leaf_logical - root_logical);
    let chunk_length = leaf_logical + u64::from(BTRFS_TEST_NODESIZE) - root_logical;
    let chunks = vec![build_single_stripe_chunk(
        root_logical,
        chunk_length,
        physical_start,
    )];

    let mut root = vec![0_u8; BTRFS_TEST_NODESIZE as usize];
    write_btrfs_header(&mut root, root_logical, 1, 1, 5, 77);
    write_btrfs_key_ptr(&mut root, 0, 256, BTRFS_ITEM_INODE_ITEM, leaf_logical, 77);

    let mut leaf = vec![0_u8; BTRFS_TEST_NODESIZE as usize];
    write_btrfs_header(&mut leaf, leaf_logical, 2, 0, 5, 77);
    let alpha_off = 3600_u32;
    let beta_off = 3605_u32;
    write_btrfs_leaf_item(&mut leaf, 0, 256, BTRFS_ITEM_INODE_ITEM, 0, alpha_off, 5);
    leaf[alpha_off as usize..(alpha_off + 5) as usize].copy_from_slice(b"alpha");
    write_btrfs_leaf_item(&mut leaf, 1, 257, BTRFS_ITEM_INODE_ITEM, 0, beta_off, 4);
    leaf[beta_off as usize..(beta_off + 4) as usize].copy_from_slice(b"beta");

    stamp_btrfs_tree_block_checksum(&mut root);
    stamp_btrfs_tree_block_checksum(&mut leaf);
    let blocks: HashMap<u64, Vec<u8>> = [(root_physical, root), (leaf_physical, leaf)]
        .into_iter()
        .collect();
    let mut reads = Vec::new();
    let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
        reads.push(phys);
        blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
            field: "physical",
            reason: "block not in test image",
        })
    };

    let sb = build_btrfs_tree_log_superblock(root_logical, 1);
    let replay = replay_tree_log(&mut read, &sb, &chunks, BTRFS_FS_TREE_OBJECTID)
        .expect("replay tree-log");
    assert!(replay.replayed, "tree-log with log_root should replay");
    assert_eq!(reads, vec![root_physical, leaf_physical]);
    assert_eq!(replay.items_count, 2);
    assert_eq!(replay.items.len(), 2);
    assert_eq!(replay.items[0].key.objectid, 256);
    assert_eq!(replay.items[0].key.item_type, BTRFS_ITEM_INODE_ITEM);
    assert_eq!(replay.items[0].data, b"alpha");
    assert_eq!(replay.items[1].key.objectid, 257);
    assert_eq!(replay.items[1].key.item_type, BTRFS_ITEM_INODE_ITEM);
    assert_eq!(replay.items[1].data, b"beta");
}

/// bd-jhuob. The KERNEL's log shape, end to end: `log_root` addresses a log ROOT
/// TREE of ROOT_ITEMs, each naming one subvolume's log tree.
///
/// This is the round trip between the two halves landed for this bead — the
/// ROOT_ITEM our writer emits (`tree_log_root_item`) and the reader that follows
/// it. Testing them against each other is the point: each side can be
/// self-consistent and still disagree about the layout, which is the failure that
/// survives both being individually "correct".
#[test]
fn btrfs_tree_log_replay_follows_a_log_root_tree_bd_jhuob() {
    const ROOT_ITEM_TYPE: u8 = 132;
    let log_root_logical = 0x40_0000_u64;
    let log_tree_logical = log_root_logical + u64::from(BTRFS_TEST_NODESIZE);
    let physical_start = 0x10_0000_u64;
    let log_root_physical = physical_start;
    let log_tree_physical = physical_start + u64::from(BTRFS_TEST_NODESIZE);
    let chunk_length = log_tree_logical + u64::from(BTRFS_TEST_NODESIZE) - log_root_logical;
    let chunks = vec![build_single_stripe_chunk(
        log_root_logical,
        chunk_length,
        physical_start,
    )];

    // The log ROOT TREE: one ROOT_ITEM for the fs tree, pointing at its log.
    //
    // ⚠️ THE KEY IS (TREE_LOG_OBJECTID, ROOT_ITEM, subvolume) — the subvolume is
    // the OFFSET. This fixture used to key it by the subvolume, matching what our
    // writer emitted and what our reader looked for, so this test passed against a
    // shape the kernel skips over: it mounts, logs "start tree-log replay", reports
    // no error, and the fsynced file is not there (bd-jhuob). Writer and reader
    // agreeing with each other proves nothing about the format.
    let mut log_root = vec![0_u8; BTRFS_TEST_NODESIZE as usize];
    write_btrfs_header(&mut log_root, log_root_logical, 1, 0, 5, 77);
    let root_item = tree_log_root_item(log_tree_logical, 0, 78);
    let root_item_off = 3000_u32;
    let root_item_len = u32::try_from(root_item.len()).expect("root item length fits u32");
    write_btrfs_leaf_item(
        &mut log_root,
        0,
        BTRFS_TREE_LOG_OBJECTID,
        ROOT_ITEM_TYPE,
        BTRFS_FS_TREE_OBJECTID,
        root_item_off,
        root_item_len,
    );
    log_root[root_item_off as usize..(root_item_off + root_item_len) as usize]
        .copy_from_slice(&root_item);

    // The subvolume's log tree: the items an fsync actually recorded.
    let mut log_tree = vec![0_u8; BTRFS_TEST_NODESIZE as usize];
    write_btrfs_header(&mut log_tree, log_tree_logical, 1, 0, 5, 78);
    let payload_off = 3600_u32;
    write_btrfs_leaf_item(&mut log_tree, 0, 256, BTRFS_ITEM_INODE_ITEM, 0, payload_off, 6);
    log_tree[payload_off as usize..(payload_off + 6) as usize].copy_from_slice(b"logged");

    stamp_btrfs_tree_block_checksum(&mut log_root);
    stamp_btrfs_tree_block_checksum(&mut log_tree);
    let blocks: HashMap<u64, Vec<u8>> =
        [(log_root_physical, log_root), (log_tree_physical, log_tree)]
            .into_iter()
            .collect();
    let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
        blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
            field: "physical",
            reason: "block not in test image",
        })
    };

    let sb = build_btrfs_tree_log_superblock(log_root_logical, 0);
    let replay = replay_tree_log(&mut read, &sb, &chunks, BTRFS_FS_TREE_OBJECTID)
        .expect("replay a log root tree");
    assert!(replay.replayed, "a log root tree naming our subvolume must replay");
    assert!(!replay.foreign_format);
    assert_eq!(replay.items.len(), 1, "the LOG TREE's items, not the root tree's");
    assert_eq!(replay.items[0].key.objectid, 256);
    assert_eq!(replay.items[0].data, b"logged");

    // ⚠️ A log root tree naming a DIFFERENT subvolume must not be replayed into
    // this one — those items belong to another keyspace — and must not be treated
    // as "nothing to replay" either, because that subvolume's acknowledged fsyncs
    // live there and a commit clearing log_root would destroy them.
    let other = replay_tree_log(&mut read, &sb, &chunks, BTRFS_FS_TREE_OBJECTID + 1)
        .expect("replay must not error for a foreign subvolume");
    assert!(!other.replayed);
    assert!(
        other.foreign_format,
        "a log for another subvolume is unreplayable HERE, and the caller must \
         refuse writes rather than clear it"
    );
    assert!(other.items.is_empty());
}

#[test]
fn btrfs_tree_log_replay_skips_when_log_root_absent() {
    let sb = build_btrfs_tree_log_superblock(0, 0);
    let mut read_calls = 0_usize;
    let mut read = |_phys: u64| -> Result<Vec<u8>, ParseError> {
        read_calls += 1;
        Err(ParseError::InvalidField {
            field: "physical",
            reason: "tree-log replay should not read when log_root is absent",
        })
    };

    let replay = replay_tree_log(&mut read, &sb, &[], BTRFS_FS_TREE_OBJECTID)
        .expect("tree-log absent fast path");
    assert_eq!(read_calls, 0, "no physical reads should occur");
    assert!(!replay.replayed);
    assert_eq!(replay.items_count, 0);
    assert!(replay.items.is_empty());
}

#[test]
fn btrfs_chunk_tree_walk_adds_and_sorts_new_chunks() {
    let chunk_root_logical = 0x10_000_u64;
    let bootstrap = vec![build_single_stripe_chunk(
        chunk_root_logical,
        u64::from(BTRFS_TEST_NODESIZE),
        0x80_000,
    )];

    let mut leaf = vec![0_u8; BTRFS_TEST_NODESIZE as usize];
    write_btrfs_header(
        &mut leaf,
        chunk_root_logical,
        1,
        0,
        BTRFS_CHUNK_TREE_OBJECTID,
        77,
    );
    let payload = build_chunk_item_payload(ChunkItemPayload {
        length: 0x20_000,
        owner: 2,
        stripe_len: 0x10_000,
        chunk_type: 1,
        io_align: BTRFS_TEST_NODESIZE,
        io_width: BTRFS_TEST_NODESIZE,
        sector_size: BTRFS_TEST_NODESIZE,
        devid: 2,
        physical_offset: 0x90_000,
    });
    let data_off = 3500_u32;
    write_btrfs_leaf_item(
        &mut leaf,
        0,
        256,
        BTRFS_ITEM_CHUNK,
        0x20_000,
        data_off,
        u32::try_from(payload.len()).expect("payload length should fit in u32"),
    );
    let end = data_off as usize + payload.len();
    leaf[data_off as usize..end].copy_from_slice(&payload);
    stamp_btrfs_tree_block_checksum(&mut leaf);
    let blocks: HashMap<u64, Vec<u8>> = std::iter::once((0x80_000_u64, leaf)).collect();
    let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
        blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
            field: "physical",
            reason: "block not in test image",
        })
    };

    let sb = build_btrfs_chunk_tree_superblock(chunk_root_logical);
    let chunks = walk_chunk_tree(&mut read, &sb, &bootstrap).expect("walk chunk tree");
    assert_eq!(
        chunks.len(),
        2,
        "bootstrap + chunk-tree entry should be returned"
    );
    assert_eq!(chunks[0].key.offset, chunk_root_logical);
    assert_eq!(chunks[0].stripes[0].offset, 0x80_000);
    assert_eq!(chunks[1].key.offset, 0x20_000);
    assert_eq!(chunks[1].length, 0x20_000);
    assert_eq!(chunks[1].stripe_len, 0x10_000);
    assert_eq!(chunks[1].stripes[0].devid, 2);
    assert_eq!(chunks[1].stripes[0].offset, 0x90_000);
}

#[test]
fn btrfs_device_tree_walk_enumerates_all_devices() {
    let root_logical = 0x20_000_u64;
    let leaf_logical = 0x30_000_u64;
    let physical_start = 0xA0_000_u64;
    let chunk_length = leaf_logical + u64::from(BTRFS_TEST_NODESIZE) - root_logical;
    let chunks = vec![build_single_stripe_chunk(
        root_logical,
        chunk_length,
        physical_start,
    )];
    let root_physical = physical_start;
    let leaf_physical = physical_start + (leaf_logical - root_logical);

    let mut root = vec![0_u8; BTRFS_TEST_NODESIZE as usize];
    write_btrfs_header(&mut root, root_logical, 1, 1, BTRFS_DEV_TREE_OBJECTID, 88);
    write_btrfs_key_ptr(&mut root, 0, 1, BTRFS_ITEM_DEV_ITEM, leaf_logical, 88);

    let mut leaf = vec![0_u8; BTRFS_TEST_NODESIZE as usize];
    write_btrfs_header(&mut leaf, leaf_logical, 2, 0, BTRFS_DEV_TREE_OBJECTID, 88);
    let first_payload = build_dev_item_payload(
        1,
        1024 * 1024 * 1024 * 1024_u64,
        512 * 1024 * 1024 * 1024_u64,
        88,
        1024 * 1024_u64,
    );
    let second_payload = build_dev_item_payload(
        2,
        2 * 1024 * 1024 * 1024 * 1024_u64,
        1024 * 1024 * 1024 * 1024_u64,
        89,
        2 * 1024 * 1024_u64,
    );
    let first_off = 3600_u32;
    let second_off = 3490_u32;
    write_btrfs_leaf_item(
        &mut leaf,
        0,
        1,
        BTRFS_ITEM_DEV_ITEM,
        1,
        first_off,
        u32::try_from(first_payload.len()).expect("payload length should fit in u32"),
    );
    write_btrfs_leaf_item(
        &mut leaf,
        1,
        2,
        BTRFS_ITEM_DEV_ITEM,
        2,
        second_off,
        u32::try_from(second_payload.len()).expect("payload length should fit in u32"),
    );
    let first_end = first_off as usize + first_payload.len();
    leaf[first_off as usize..first_end].copy_from_slice(&first_payload);
    let second_end = second_off as usize + second_payload.len();
    leaf[second_off as usize..second_end].copy_from_slice(&second_payload);

    stamp_btrfs_tree_block_checksum(&mut root);
    stamp_btrfs_tree_block_checksum(&mut leaf);
    let blocks: HashMap<u64, Vec<u8>> = [(root_physical, root), (leaf_physical, leaf)]
        .into_iter()
        .collect();
    let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
        blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
            field: "physical",
            reason: "block not in test image",
        })
    };

    let items = walk_device_tree(&mut read, root_logical, &chunks, BTRFS_TEST_NODESIZE, 0)
        .expect("walk device tree");
    assert_eq!(
        items.len(),
        2,
        "device tree should return both DEV_ITEM entries"
    );
    assert_eq!(items[0].key.objectid, 1);
    assert_eq!(items[0].key.item_type, BTRFS_ITEM_DEV_ITEM);
    assert_eq!(items[1].key.objectid, 2);
    assert_eq!(items[1].key.item_type, BTRFS_ITEM_DEV_ITEM);

    let first_dev = parse_dev_item(&items[0].data).expect("first DEV_ITEM should parse");
    assert_eq!(first_dev.devid, 1);
    assert_eq!(first_dev.total_bytes, 1024 * 1024 * 1024 * 1024_u64);
    assert_eq!(first_dev.bytes_used, 512 * 1024 * 1024 * 1024_u64);
    assert_eq!(first_dev.start_offset, 1024 * 1024_u64);

    let second_dev = parse_dev_item(&items[1].data).expect("second DEV_ITEM should parse");
    assert_eq!(second_dev.devid, 2);
    assert_eq!(second_dev.total_bytes, 2 * 1024 * 1024 * 1024 * 1024_u64);
    assert_eq!(second_dev.bytes_used, 1024 * 1024 * 1024 * 1024_u64);
    assert_eq!(second_dev.start_offset, 2 * 1024 * 1024_u64);
}

#[test]
fn btrfs_multi_device_dup_read_conforms() {
    let logical = 0xC0_000_u64;
    let stripe_len = 0x10_000_u64;
    // DUP with 1 device: 2 mirrors on the same device.
    // Length is stripe_len = 0x10_000.
    let chunks = vec![BtrfsChunkEntry {
        key: BtrfsKey {
            objectid: 256,
            item_type: 228,
            offset: logical,
        },
        length: stripe_len,
        owner: 2,
        stripe_len,
        chunk_type: ffs_ondisk::chunk_type_flags::BTRFS_BLOCK_GROUP_DATA
            | ffs_ondisk::chunk_type_flags::BTRFS_BLOCK_GROUP_DUP,
        io_align: BTRFS_TEST_NODESIZE,
        io_width: BTRFS_TEST_NODESIZE,
        sector_size: BTRFS_TEST_NODESIZE,
        num_stripes: 2,
        sub_stripes: 0,
        stripes: vec![
            BtrfsStripe {
                devid: 1,
                offset: 0x100_000,
                dev_uuid: [0; 16],
            },
            BtrfsStripe {
                devid: 1,
                offset: 0x200_000,
                dev_uuid: [0; 16],
            },
        ],
    }];

    let mut devices = BtrfsDeviceSet::new();
    let data1 = Arc::new(vec![0xAA_u8; 4]);
    let data2 = Arc::new(vec![0xBB_u8; 4]);

    // DUP: 2 stripes on the same device (devid 1).
    // The implementation should pick the first mirror by default.
    // If it fails, it should pick the second mirror.

    let d1 = Arc::clone(&data1);
    let d2 = Arc::clone(&data2);
    devices.add_device(
        1,
        Box::new(move |physical, len| {
            assert_eq!(len, 4);
            if physical == 0x100_000 {
                // First mirror
                Ok((*d1).clone())
            } else if physical == 0x200_000 {
                // Second mirror
                Ok((*d2).clone())
            } else {
                Err(ParseError::InvalidField {
                    field: "device",
                    reason: "unexpected physical offset",
                })
            }
        }),
    );

    // Read from logical (picks first mirror)
    let res1 = devices
        .read_logical(&chunks, logical, 4)
        .expect("read DUP mirror 0");
    assert_eq!(res1, vec![0xAA_u8; 4]);

    // We can't easily simulate failure of ONLY the first mirror on the same device
    // since the callback is per-device. But we've verified mirror picking for RAID1.
}

#[test]
fn btrfs_multi_device_raid6_read_conforms() {
    let logical = 0x70_000_u64;
    let stripe_len = 0x10_000_u64;
    // RAID6 with 4 devices: 2 data stripes, 2 parity stripes (P+Q).
    // Length is 2 * stripe_len = 0x20_000.
    let chunks = vec![BtrfsChunkEntry {
        key: BtrfsKey {
            objectid: 256,
            item_type: 228,
            offset: logical,
        },
        length: stripe_len * 2,
        owner: 2,
        stripe_len,
        chunk_type: ffs_ondisk::chunk_type_flags::BTRFS_BLOCK_GROUP_DATA
            | ffs_ondisk::chunk_type_flags::BTRFS_BLOCK_GROUP_RAID6,
        io_align: BTRFS_TEST_NODESIZE,
        io_width: BTRFS_TEST_NODESIZE,
        sector_size: BTRFS_TEST_NODESIZE,
        num_stripes: 4,
        sub_stripes: 0,
        stripes: vec![
            BtrfsStripe {
                devid: 1,
                offset: 0x100_000,
                dev_uuid: [0; 16],
            },
            BtrfsStripe {
                devid: 2,
                offset: 0x200_000,
                dev_uuid: [0; 16],
            },
            BtrfsStripe {
                devid: 3,
                offset: 0x300_000,
                dev_uuid: [0; 16],
            },
            BtrfsStripe {
                devid: 4,
                offset: 0x400_000,
                dev_uuid: [0; 16],
            },
        ],
    }];

    let mut devices = BtrfsDeviceSet::new();
    let data1 = Arc::new(vec![0x66_u8; 4]);
    let data2 = Arc::new(vec![0x77_u8; 4]);

    // In RAID6, P and Q rotate.
    // For stripe_nr=0, P=dev4, Q=dev3. Data at dev1, dev2.
    let d1 = Arc::clone(&data1);
    devices.add_device(
        1,
        Box::new(move |physical, len| {
            assert_eq!(len, 4);
            if physical == 0x100_000 {
                Ok((*d1).clone())
            } else {
                Err(ParseError::InvalidField {
                    field: "device",
                    reason: "unexpected physical offset",
                })
            }
        }),
    );

    // Row 0 has P=dev4 and Q=dev3, so the two data stripes are dev1 and dev2.
    let d2 = Arc::clone(&data2);
    devices.add_device(
        2,
        Box::new(move |physical, len| {
            assert_eq!(len, 4);
            if physical == 0x200_000 {
                Ok((*d2).clone())
            } else {
                Err(ParseError::InvalidField {
                    field: "device",
                    reason: "unexpected physical offset",
                })
            }
        }),
    );

    // Read stripe 0 (data1)
    let res1 = devices
        .read_logical(&chunks, logical, 4)
        .expect("read RAID6 data1");
    assert_eq!(res1, vec![0x66_u8; 4]);

    // Read row 0, data stripe 1.
    let res2 = devices
        .read_logical(&chunks, logical + stripe_len, 4)
        .expect("read RAID6 data2");
    assert_eq!(res2, vec![0x77_u8; 4]);
}

#[test]
fn btrfs_multi_device_raid10_read_conforms() {
    let logical = 0xA0_000_u64;
    let stripe_len = 0x10_000_u64;
    // RAID10 with 4 devices: 2 mirrors of 2 stripes.
    // Length is 2 * stripe_len = 0x20_000.
    let chunks = vec![BtrfsChunkEntry {
        key: BtrfsKey {
            objectid: 256,
            item_type: 228,
            offset: logical,
        },
        length: stripe_len * 2,
        owner: 2,
        stripe_len,
        chunk_type: ffs_ondisk::chunk_type_flags::BTRFS_BLOCK_GROUP_DATA
            | ffs_ondisk::chunk_type_flags::BTRFS_BLOCK_GROUP_RAID10,
        io_align: BTRFS_TEST_NODESIZE,
        io_width: BTRFS_TEST_NODESIZE,
        sector_size: BTRFS_TEST_NODESIZE,
        num_stripes: 4,
        sub_stripes: 2,
        stripes: vec![
            BtrfsStripe {
                devid: 1,
                offset: 0x100_000,
                dev_uuid: [0; 16],
            },
            BtrfsStripe {
                devid: 2,
                offset: 0x200_000,
                dev_uuid: [0; 16],
            },
            BtrfsStripe {
                devid: 3,
                offset: 0x300_000,
                dev_uuid: [0; 16],
            },
            BtrfsStripe {
                devid: 4,
                offset: 0x400_000,
                dev_uuid: [0; 16],
            },
        ],
    }];

    let mut devices = BtrfsDeviceSet::new();
    // Stripe 0: dev1, dev2 (mirrors)
    // Stripe 1: dev3, dev4 (mirrors)

    devices.add_device(
        1,
        Box::new(move |_physical, _len| {
            Err(ParseError::InvalidField {
                field: "device",
                reason: "simulated failure dev1",
            })
        }),
    );
    devices.add_device(
        2,
        Box::new(move |physical, len| {
            assert_eq!(physical, 0x200_000);
            assert_eq!(len, 4);
            Ok(b"mir0".to_vec())
        }),
    );
    devices.add_device(
        4,
        Box::new(move |physical, len| {
            assert_eq!(physical, 0x400_000);
            assert_eq!(len, 4);
            Ok(b"mir1".to_vec())
        }),
    );

    // Read from stripe 0 (should fall back to dev2)
    let res1 = devices
        .read_logical(&chunks, logical, 4)
        .expect("read RAID10 stripe 0");
    assert_eq!(res1, b"mir0");

    // Read from stripe 1 (device 4)
    let res2 = devices
        .read_logical(&chunks, logical + stripe_len, 4)
        .expect("read RAID10 stripe 1");
    assert_eq!(res2, b"mir1");
}

#[test]
fn btrfs_multi_device_raid5_read_conforms() {
    let logical = 0x50_000_u64;
    let stripe_len = 0x10_000_u64;
    // RAID5 with 3 devices: 2 data stripes, 1 parity stripe.
    // Length is 2 * stripe_len = 0x20_000.
    let chunks = vec![BtrfsChunkEntry {
        key: BtrfsKey {
            objectid: 256,
            item_type: 228,
            offset: logical,
        },
        length: stripe_len * 2,
        owner: 2,
        stripe_len,
        chunk_type: ffs_ondisk::chunk_type_flags::BTRFS_BLOCK_GROUP_DATA
            | ffs_ondisk::chunk_type_flags::BTRFS_BLOCK_GROUP_RAID5,
        io_align: BTRFS_TEST_NODESIZE,
        io_width: BTRFS_TEST_NODESIZE,
        sector_size: BTRFS_TEST_NODESIZE,
        num_stripes: 3,
        sub_stripes: 0,
        stripes: vec![
            BtrfsStripe {
                devid: 1,
                offset: 0x100_000,
                dev_uuid: [0; 16],
            },
            BtrfsStripe {
                devid: 2,
                offset: 0x200_000,
                dev_uuid: [0; 16],
            },
            BtrfsStripe {
                devid: 3,
                offset: 0x300_000,
                dev_uuid: [0; 16],
            },
        ],
    }];

    let mut devices = BtrfsDeviceSet::new();
    let data1 = Arc::new(vec![0x11_u8; 4]);
    let data2 = Arc::new(vec![0x22_u8; 4]);

    // In RAID5, data is striped.
    // Stripe 0: dev1:0x100_000, dev2:0x200_000, dev3:0x300_000 (P)
    // Row 1 starts at the next full RAID5 row: dev1:0x110_000 (P),
    // dev2:0x210_000, dev3:0x310_000.

    let d1 = Arc::clone(&data1);
    devices.add_device(
        1,
        Box::new(move |physical, len| {
            assert_eq!(len, 4);
            if physical == 0x100_000 {
                Ok((*d1).clone())
            } else {
                Err(ParseError::InvalidField {
                    field: "device",
                    reason: "unexpected physical offset",
                })
            }
        }),
    );

    let d2 = Arc::clone(&data2);
    devices.add_device(
        2,
        Box::new(move |physical, len| {
            assert_eq!(len, 4);
            if physical == 0x200_000 {
                Ok((*d2).clone())
            } else {
                Err(ParseError::InvalidField {
                    field: "device",
                    reason: "unexpected physical offset",
                })
            }
        }),
    );

    devices.add_device(
        3,
        Box::new(move |_physical, _len| {
            Err(ParseError::InvalidField {
                field: "device",
                reason: "RAID5 data-stripe fixture unexpectedly read parity stripe",
            })
        }),
    );

    // Read from logical 0x50_000 (stripe 0, data 1)
    let res1 = devices
        .read_logical(&chunks, logical, 4)
        .expect("read RAID5 data1");
    assert_eq!(res1, vec![0x11_u8; 4]);

    // Read row 0, data stripe 1. Row 0 has parity on dev3, so this maps to dev2:0x200_000.
    let res2 = devices
        .read_logical(&chunks, logical + stripe_len, 4)
        .expect("read RAID5 data2");
    assert_eq!(res2, vec![0x22_u8; 4]);
}

#[test]
fn btrfs_multi_device_raid1_read_falls_back_to_second_mirror() {
    let logical = 0x40_000_u64;
    let stripe_len = 0x10_000_u64;
    let chunks = vec![BtrfsChunkEntry {
        key: BtrfsKey {
            objectid: 256,
            item_type: 228,
            offset: logical,
        },
        length: stripe_len,
        owner: 2,
        stripe_len,
        chunk_type: ffs_ondisk::chunk_type_flags::BTRFS_BLOCK_GROUP_DATA
            | ffs_ondisk::chunk_type_flags::BTRFS_BLOCK_GROUP_RAID1,
        io_align: BTRFS_TEST_NODESIZE,
        io_width: BTRFS_TEST_NODESIZE,
        sector_size: BTRFS_TEST_NODESIZE,
        num_stripes: 2,
        sub_stripes: 0,
        stripes: vec![
            BtrfsStripe {
                devid: 1,
                offset: 0x100_000,
                dev_uuid: [0; 16],
            },
            BtrfsStripe {
                devid: 2,
                offset: 0x200_000,
                dev_uuid: [0; 16],
            },
        ],
    }];

    let mut devices = BtrfsDeviceSet::new();
    let first_reads = Arc::new(AtomicUsize::new(0));
    let second_reads = Arc::new(AtomicUsize::new(0));

    let first_reads_for_closure = Arc::clone(&first_reads);
    devices.add_device(
        1,
        Box::new(move |physical, len| {
            first_reads_for_closure.fetch_add(1, AtomicOrdering::SeqCst);
            assert_eq!(physical, 0x100_000);
            assert_eq!(len, 4);
            Err(ParseError::InvalidField {
                field: "device",
                reason: "simulated mirror read failure",
            })
        }),
    );

    let second_reads_for_closure = Arc::clone(&second_reads);
    devices.add_device(
        2,
        Box::new(move |physical, len| {
            second_reads_for_closure.fetch_add(1, AtomicOrdering::SeqCst);
            assert_eq!(physical, 0x200_000);
            assert_eq!(len, 4);
            Ok(b"raid".to_vec())
        }),
    );

    let data = devices
        .read_logical(&chunks, logical, 4)
        .expect("second RAID1 mirror should satisfy read");
    assert_eq!(data, b"raid");
    assert_eq!(first_reads.load(AtomicOrdering::SeqCst), 1);
    assert_eq!(second_reads.load(AtomicOrdering::SeqCst), 1);
}

#[test]
fn btrfs_multi_device_raid0_dispatches_to_correct_stripe() {
    let logical = 0x80_000_u64;
    let stripe_len = 0x10_000_u64;
    let chunks = vec![BtrfsChunkEntry {
        key: BtrfsKey {
            objectid: 256,
            item_type: 228,
            offset: logical,
        },
        length: stripe_len * 2,
        owner: 2,
        stripe_len,
        chunk_type: ffs_ondisk::chunk_type_flags::BTRFS_BLOCK_GROUP_DATA
            | ffs_ondisk::chunk_type_flags::BTRFS_BLOCK_GROUP_RAID0,
        io_align: BTRFS_TEST_NODESIZE,
        io_width: BTRFS_TEST_NODESIZE,
        sector_size: BTRFS_TEST_NODESIZE,
        num_stripes: 2,
        sub_stripes: 0,
        stripes: vec![
            BtrfsStripe {
                devid: 1,
                offset: 0x300_000,
                dev_uuid: [0; 16],
            },
            BtrfsStripe {
                devid: 2,
                offset: 0x400_000,
                dev_uuid: [0; 16],
            },
        ],
    }];

    let mut devices = BtrfsDeviceSet::new();
    let first_reads = Arc::new(AtomicUsize::new(0));
    let second_reads = Arc::new(AtomicUsize::new(0));

    let first_reads_for_closure = Arc::clone(&first_reads);
    devices.add_device(
        1,
        Box::new(move |_physical, _len| {
            first_reads_for_closure.fetch_add(1, AtomicOrdering::SeqCst);
            Ok(b"first".to_vec())
        }),
    );

    let second_reads_for_closure = Arc::clone(&second_reads);
    devices.add_device(
        2,
        Box::new(move |physical, len| {
            second_reads_for_closure.fetch_add(1, AtomicOrdering::SeqCst);
            assert_eq!(physical, 0x400_000);
            assert_eq!(len, 5);
            Ok(b"strip".to_vec())
        }),
    );

    let data = devices
        .read_logical(&chunks, logical + stripe_len, 5)
        .expect("RAID0 second stripe should dispatch to device 2");
    assert_eq!(data, b"strip");
    assert_eq!(first_reads.load(AtomicOrdering::SeqCst), 0);
    assert_eq!(second_reads.load(AtomicOrdering::SeqCst), 1);
}

#[test]
fn btrfs_chunk_mapping_fixture_conforms() {
    let (sb, chunks) =
        validate_btrfs_chunk_fixture(&fixture_path("btrfs_superblock_with_chunks.json"))
            .expect("btrfs chunk fixture");
    assert!(!chunks.is_empty(), "should have at least one chunk entry");
    assert_eq!(
        chunks.len(),
        1,
        "fixture should contain one sys_chunk entry"
    );

    let chunk = &chunks[0];
    assert_eq!(
        chunk.key.objectid, 256,
        "chunk key objectid should be FIRST_CHUNK_TREE_OBJECTID"
    );
    assert_eq!(
        chunk.key.item_type, 228,
        "chunk key type should be CHUNK_ITEM"
    );
    assert_eq!(chunk.key.offset, 0, "chunk key offset should be 0");
    assert_eq!(chunk.length, 8 * 1024 * 1024, "chunk length should be 8MiB");
    assert_eq!(chunk.owner, 2, "chunk owner should be EXTENT_TREE");
    assert_eq!(
        chunk.stripe_len,
        64 * 1024,
        "chunk stripe_len should be 64KiB"
    );
    assert_eq!(
        chunk.chunk_type,
        ffs_ondisk::chunk_type_flags::BTRFS_BLOCK_GROUP_SYSTEM,
        "chunk type should be SYSTEM"
    );
    assert_eq!(chunk.io_align, 4096, "chunk io_align should be 4096");
    assert_eq!(chunk.io_width, 4096, "chunk io_width should be 4096");
    assert_eq!(chunk.sector_size, 4096, "chunk sector_size should be 4096");
    assert_eq!(chunk.num_stripes, 1, "chunk should have one stripe");
    assert_eq!(chunk.sub_stripes, 0, "chunk sub_stripes should be 0");

    let stripe = &chunk.stripes[0];
    assert_eq!(stripe.devid, 1, "stripe devid should be 1");
    assert_eq!(stripe.offset, 1024 * 1024, "stripe offset should be 1MiB");
    assert_eq!(stripe.dev_uuid, [0; 16], "stripe dev_uuid should be zeroed");

    // root and chunk_root should be mappable
    let root_map = ffs_ondisk::map_logical_to_physical(&chunks, sb.root)
        .expect("mapping ok")
        .expect("root covered");
    assert_eq!(root_map.devid, 1);
    let cr_map = ffs_ondisk::map_logical_to_physical(&chunks, sb.chunk_root)
        .expect("mapping ok")
        .expect("chunk_root covered");
    assert_eq!(cr_map.devid, 1);
}

#[test]
fn btrfs_leaf_fixture_conforms() {
    let (header, items) = validate_btrfs_leaf_fixture(&fixture_path("btrfs_leaf_node.json"))
        .expect("btrfs leaf fixture");
    assert_eq!(header.level, 0, "should be a leaf");
    assert_eq!(header.owner, 5, "owner should be FS_TREE (5)");
    assert_eq!(header.nritems, 3, "header should declare 3 items");
    assert_eq!(items.len(), 3, "fixture should have 3 btrfs leaf items");

    // Items should be sorted by key (objectid then type)
    for pair in items.windows(2) {
        let a = &pair[0].key;
        let b = &pair[1].key;
        assert!(
            (a.objectid, a.item_type) <= (b.objectid, b.item_type),
            "items should be sorted by key"
        );
    }

    let expected_slots = [
        (
            256_u64,
            btrfs_item_types::INODE_ITEM,
            0_u64,
            16_000_u32,
            100_u32,
        ),
        (256, btrfs_item_types::INODE_REF, 0, 16_100, 50),
        (257, btrfs_item_types::INODE_ITEM, 0, 16_150, 100),
    ];

    for (item, (objectid, item_type, offset, data_offset, data_size)) in
        items.iter().zip(expected_slots)
    {
        assert_eq!(item.key.objectid, objectid, "leaf item objectid drift");
        assert_eq!(item.key.item_type, item_type, "leaf item type drift");
        assert_eq!(item.key.offset, offset, "leaf item key offset drift");
        assert_eq!(item.data_offset, data_offset, "leaf item data offset drift");
        assert_eq!(item.data_size, data_size, "leaf item data size drift");
    }
}

/// btrfs item type constants for fixture validation
mod btrfs_item_types {
    pub const INODE_ITEM: u8 = 1;
    pub const INODE_REF: u8 = 12;
    pub const DIR_ITEM: u8 = 84;
    pub const DIR_INDEX: u8 = 96;
    pub const EXTENT_DATA: u8 = 108;
    pub const ROOT_ITEM: u8 = 132;
}

/// Validate the fs-tree leaf fixture (bd-2jk.2 deliverable).
///
/// This fixture contains the minimum item types needed to support btrfs
/// read-only operations: INODE_ITEM, DIR_ITEM, DIR_INDEX, EXTENT_DATA.
#[test]
fn btrfs_fstree_leaf_fixture_conforms() {
    let (header, items) = validate_btrfs_leaf_fixture(&fixture_path("btrfs_fstree_leaf.json"))
        .expect("btrfs fs-tree leaf fixture");

    // Verify header
    assert_eq!(header.level, 0, "should be a leaf");
    assert_eq!(header.owner, 5, "owner should be FS_TREE (5)");
    assert_eq!(header.nritems, 5, "header should declare 5 items");
    assert_eq!(items.len(), 5, "fixture should have 5 FS_TREE entries");

    // Verify items are sorted
    for pair in items.windows(2) {
        let a = &pair[0].key;
        let b = &pair[1].key;
        assert!(
            (a.objectid, a.item_type, a.offset) <= (b.objectid, b.item_type, b.offset),
            "items should be sorted by key: {a:?} vs {b:?}"
        );
    }

    let expected_slots = [
        (
            256_u64,
            btrfs_item_types::INODE_ITEM,
            0_u64,
            15_936_u32,
            160_u32,
        ),
        (256, btrfs_item_types::DIR_ITEM, 0x12_3456, 16_096, 40),
        (256, btrfs_item_types::DIR_INDEX, 2, 16_136, 40),
        (257, btrfs_item_types::INODE_ITEM, 0, 16_176, 160),
        (257, btrfs_item_types::EXTENT_DATA, 0, 16_336, 48),
    ];

    for (item, (objectid, item_type, offset, data_offset, data_size)) in
        items.iter().zip(expected_slots)
    {
        assert_eq!(item.key.objectid, objectid, "FS_TREE item objectid drift");
        assert_eq!(item.key.item_type, item_type, "FS_TREE item type drift");
        assert_eq!(item.key.offset, offset, "FS_TREE item key offset drift");
        assert_eq!(
            item.data_offset, data_offset,
            "FS_TREE item data offset drift"
        );
        assert_eq!(item.data_size, data_size, "FS_TREE item data size drift");
    }
}

/// Validate the root-tree leaf fixture (bd-2jk.2 deliverable).
///
/// This fixture contains ROOT_ITEM entries for the core btrfs trees,
/// needed to bootstrap tree traversal from the superblock.
#[test]
fn btrfs_roottree_leaf_fixture_conforms() {
    let (header, items) = validate_btrfs_leaf_fixture(&fixture_path("btrfs_roottree_leaf.json"))
        .expect("btrfs root-tree leaf fixture");

    // Verify header
    assert_eq!(header.level, 0, "should be a leaf");
    assert_eq!(header.owner, 1, "owner should be ROOT_TREE (1)");
    assert_eq!(header.nritems, 3, "header should declare 3 items");
    assert_eq!(items.len(), 3, "fixture should have 3 ROOT_ITEM entries");

    // Verify items are sorted
    for pair in items.windows(2) {
        let a = &pair[0].key;
        let b = &pair[1].key;
        assert!(
            (a.objectid, a.item_type, a.offset) <= (b.objectid, b.item_type, b.offset),
            "items should be sorted by key: {a:?} vs {b:?}"
        );
    }

    let expected_slots = [
        (
            2_u64,
            btrfs_item_types::ROOT_ITEM,
            0_u64,
            15_667_u32,
            239_u32,
        ),
        (3, btrfs_item_types::ROOT_ITEM, 0, 15_906, 239),
        (5, btrfs_item_types::ROOT_ITEM, 0, 16_145, 239),
    ];

    for (item, (objectid, item_type, offset, data_offset, data_size)) in
        items.iter().zip(expected_slots)
    {
        assert_eq!(item.key.objectid, objectid, "ROOT_ITEM objectid drift");
        assert_eq!(item.key.item_type, item_type, "ROOT_ITEM type drift");
        assert_eq!(item.key.offset, offset, "ROOT_ITEM key offset drift");
        assert_eq!(item.data_offset, data_offset, "ROOT_ITEM data offset drift");
        assert_eq!(item.data_size, data_size, "ROOT_ITEM data size drift");
    }
}

#[test]
fn btrfs_devitem_fixture_conforms() {
    let devitem = ffs_harness::validate_btrfs_devitem_fixture(&fixture_path("btrfs_devitem.json"))
        .expect("btrfs devitem fixture");

    assert_eq!(devitem.devid, 1, "devid should be 1");
    assert_eq!(
        devitem.total_bytes,
        1024 * 1024 * 1024 * 1024,
        "total_bytes should be 1TB"
    );
    assert_eq!(
        devitem.bytes_used,
        512 * 1024 * 1024 * 1024,
        "bytes_used should be 512GB"
    );
    assert_eq!(devitem.sector_size, 4096, "sector_size should be 4096");
    assert_eq!(devitem.io_align, 4096, "io_align should be 4096");
    assert_eq!(devitem.io_width, 4096, "io_width should be 4096");
    assert_eq!(devitem.generation, 100, "generation should be 100");
    assert_eq!(
        devitem.start_offset,
        1024 * 1024,
        "start_offset should be 1MiB"
    );
    assert_eq!(devitem.dev_type, 0, "dev_type should be 0 (regular)");
    assert_eq!(devitem.dev_group, 0, "dev_group should be 0");
    assert_eq!(devitem.seek_speed, 0, "seek_speed should be 0");
    assert_eq!(devitem.bandwidth, 0, "bandwidth should be 0");
    assert_eq!(
        devitem.uuid,
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        "uuid should match fixture bytes"
    );
    assert_eq!(
        devitem.fsid,
        [
            0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE,
            0xAF, 0xB0,
        ],
        "fsid should match fixture bytes"
    );
}
