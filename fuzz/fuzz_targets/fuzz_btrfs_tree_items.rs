#![no_main]

use ffs_btrfs::{
    parse_dir_items, parse_extent_data, parse_inode_item, parse_root_item, parse_root_ref,
    parse_xattr_items, BtrfsDirItem, BtrfsExtentData, BtrfsInodeItem, BtrfsRootItem, BtrfsRootRef,
    BtrfsXattrItem, BTRFS_COMPRESS_LZO, BTRFS_COMPRESS_NONE, BTRFS_COMPRESS_ZLIB,
    BTRFS_COMPRESS_ZSTD, BTRFS_FILE_EXTENT_INLINE, BTRFS_FILE_EXTENT_PREALLOC,
    BTRFS_FILE_EXTENT_REG,
};
use ffs_types::ParseError;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 4096;
const MAX_STRUCTURED_BYTES: u8 = 32;
const NANOS_PER_SECOND: u32 = 1_000_000_000;
const ROOT_ITEM_LEGACY_SIZE: usize = 239;
const ROOT_ITEM_GENERATION_OFFSET: usize = 160;
const ROOT_ITEM_ROOT_DIRID_OFFSET: usize = 168;
const ROOT_ITEM_BYTENR_OFFSET: usize = 176;
const ROOT_ITEM_FLAGS_OFFSET: usize = 208;
const ROOT_ITEM_REFS_OFFSET: usize = 216;
const ROOT_ITEM_LEVEL_OFFSET: usize = 238;
const ROOT_ITEM_GENERATION_V2_OFFSET: usize = 239;
const ROOT_ITEM_UUID_OFFSET: usize = 247;
const ROOT_ITEM_PARENT_UUID_OFFSET: usize = 263;
const ROOT_ITEM_PARENT_UUID_END: usize = ROOT_ITEM_PARENT_UUID_OFFSET + 16;

fn read_u16(data: &[u8], off: usize) -> Option<u16> {
    let bytes = data.get(off..off + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], off: usize) -> Option<u32> {
    let bytes = data.get(off..off + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(data: &[u8], off: usize) -> Option<u64> {
    let bytes = data.get(off..off + 8)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn read_array_16(data: &[u8], off: usize) -> Option<[u8; 16]> {
    let bytes = data.get(off..off + 16)?;
    let mut out = [0_u8; 16];
    out.copy_from_slice(bytes);
    Some(out)
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
        let value = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.saturating_add(1);
        value
    }

    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes([
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
        ])
    }

    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes([
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
        ])
    }

    fn take_vec(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_u8()).collect()
    }

    fn next_array_16(&mut self) -> [u8; 16] {
        let mut out = [0_u8; 16];
        for byte in &mut out {
            *byte = self.next_u8();
        }
        out
    }
}

fn nonempty_bounded_bytes(cursor: &mut ByteCursor<'_>, max_len: u8) -> Vec<u8> {
    let len = 1 + usize::from(cursor.next_u8() % max_len);
    cursor.take_vec(len)
}

fn next_nsec(cursor: &mut ByteCursor<'_>) -> u32 {
    cursor.next_u32() % NANOS_PER_SECOND
}

fn build_inode_item(cursor: &mut ByteCursor<'_>) -> BtrfsInodeItem {
    BtrfsInodeItem {
        generation: cursor.next_u64(),
        size: cursor.next_u64(),
        nbytes: cursor.next_u64(),
        nlink: cursor.next_u32(),
        uid: cursor.next_u32(),
        gid: cursor.next_u32(),
        mode: cursor.next_u32(),
        rdev: cursor.next_u64(),
        flags: cursor.next_u64(),
        atime_sec: cursor.next_u64(),
        atime_nsec: next_nsec(cursor),
        ctime_sec: cursor.next_u64(),
        ctime_nsec: next_nsec(cursor),
        mtime_sec: cursor.next_u64(),
        mtime_nsec: next_nsec(cursor),
        otime_sec: cursor.next_u64(),
        otime_nsec: next_nsec(cursor),
    }
}

fn build_root_item(cursor: &mut ByteCursor<'_>) -> BtrfsRootItem {
    BtrfsRootItem {
        bytenr: cursor.next_u64().max(1),
        level: cursor.next_u8() % 8,
        generation: cursor.next_u64(),
        root_dirid: cursor.next_u64(),
        last_snapshot: cursor.next_u64(),
        flags: cursor.next_u64(),
        refs: u64::from(cursor.next_u32()),
        uuid: cursor.next_array_16(),
        parent_uuid: cursor.next_array_16(),
    }
}

fn build_dir_item(cursor: &mut ByteCursor<'_>) -> BtrfsDirItem {
    BtrfsDirItem {
        child_objectid: cursor.next_u64(),
        child_key_type: cursor.next_u8(),
        child_key_offset: cursor.next_u64(),
        file_type: cursor.next_u8(),
        name: nonempty_bounded_bytes(cursor, MAX_STRUCTURED_BYTES),
    }
}

fn build_root_ref(cursor: &mut ByteCursor<'_>) -> BtrfsRootRef {
    BtrfsRootRef {
        dirid: cursor.next_u64(),
        sequence: cursor.next_u64(),
        name: nonempty_bounded_bytes(cursor, MAX_STRUCTURED_BYTES),
    }
}

fn build_xattr_item(cursor: &mut ByteCursor<'_>) -> BtrfsXattrItem {
    let value_len = cursor.next_u8() % (MAX_STRUCTURED_BYTES + 1);
    BtrfsXattrItem {
        name: nonempty_bounded_bytes(cursor, MAX_STRUCTURED_BYTES),
        value: cursor.take_vec(usize::from(value_len)),
    }
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    let slot = bytes
        .get_mut(offset..offset + 8)
        .expect("write_u64 target range must fit synthesized payload");
    slot.copy_from_slice(&value.to_le_bytes());
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    let slot = bytes
        .get_mut(offset..offset + 2)
        .expect("write_u16 target range must fit synthesized payload");
    slot.copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    let slot = bytes
        .get_mut(offset..offset + 4)
        .expect("write_u32 target range must fit synthesized payload");
    slot.copy_from_slice(&value.to_le_bytes());
}

fn write_array_16(bytes: &mut [u8], offset: usize, value: [u8; 16]) {
    let slot = bytes
        .get_mut(offset..offset + 16)
        .expect("write_array_16 target range must fit synthesized payload");
    slot.copy_from_slice(&value);
}

fn root_item_to_bytes(item: &BtrfsRootItem, include_uuid_fields: bool) -> Vec<u8> {
    let refs = u32::try_from(item.refs).expect("generated ROOT_ITEM refs must fit u32");

    let len = if include_uuid_fields {
        ROOT_ITEM_PARENT_UUID_END
    } else {
        ROOT_ITEM_LEGACY_SIZE
    };
    let mut bytes = vec![0_u8; len];
    write_u64(&mut bytes, ROOT_ITEM_GENERATION_OFFSET, item.generation);
    write_u64(&mut bytes, ROOT_ITEM_ROOT_DIRID_OFFSET, item.root_dirid);
    write_u64(&mut bytes, ROOT_ITEM_BYTENR_OFFSET, item.bytenr);
    write_u64(&mut bytes, ROOT_ITEM_FLAGS_OFFSET, item.flags);
    write_u32(&mut bytes, ROOT_ITEM_REFS_OFFSET, refs);
    let level = bytes
        .get_mut(ROOT_ITEM_LEVEL_OFFSET)
        .expect("ROOT_ITEM level byte must fit synthesized payload");
    *level = item.level;

    if include_uuid_fields {
        write_u64(&mut bytes, ROOT_ITEM_GENERATION_V2_OFFSET, item.generation);
        write_array_16(&mut bytes, ROOT_ITEM_UUID_OFFSET, item.uuid);
        write_array_16(&mut bytes, ROOT_ITEM_PARENT_UUID_OFFSET, item.parent_uuid);
    }

    bytes
}

fn root_ref_to_bytes(item: &BtrfsRootRef) -> Vec<u8> {
    let name_len =
        u16::try_from(item.name.len()).expect("generated ROOT_REF name length must fit u16");

    let mut bytes = Vec::with_capacity(18 + item.name.len());
    bytes.extend_from_slice(&item.dirid.to_le_bytes());
    bytes.extend_from_slice(&item.sequence.to_le_bytes());
    bytes.extend_from_slice(&name_len.to_le_bytes());
    bytes.extend_from_slice(&item.name);
    bytes
}

fn xattr_item_to_bytes(item: &BtrfsXattrItem) -> Vec<u8> {
    let name_len =
        u16::try_from(item.name.len()).expect("generated XATTR_ITEM name length must fit u16");
    let value_len =
        u16::try_from(item.value.len()).expect("generated XATTR_ITEM value length must fit u16");

    let mut bytes = Vec::with_capacity(30 + item.name.len() + item.value.len());
    bytes.extend_from_slice(&[0_u8; 17]);
    bytes.extend_from_slice(&[0_u8; 8]);
    bytes.extend_from_slice(&value_len.to_le_bytes());
    bytes.extend_from_slice(&name_len.to_le_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&item.name);
    bytes.extend_from_slice(&item.value);
    bytes
}

fn build_inline_extent(cursor: &mut ByteCursor<'_>) -> BtrfsExtentData {
    let inline_len = cursor.next_u8() % (MAX_STRUCTURED_BYTES + 1);
    BtrfsExtentData::Inline {
        generation: cursor.next_u64(),
        ram_bytes: u64::from(inline_len),
        compression: BTRFS_COMPRESS_NONE,
        data: cursor.take_vec(usize::from(inline_len)),
    }
}

fn build_regular_extent(cursor: &mut ByteCursor<'_>) -> BtrfsExtentData {
    let extent_offset = u64::from(cursor.next_u8());
    let num_bytes = u64::from(cursor.next_u8());
    let disk_num_bytes = extent_offset + num_bytes;
    let disk_bytenr = if cursor.next_u8().is_multiple_of(2) {
        0
    } else {
        1 + u64::from(cursor.next_u8())
    };
    let extent_type = if cursor.next_u8().is_multiple_of(2) {
        BTRFS_FILE_EXTENT_REG
    } else {
        BTRFS_FILE_EXTENT_PREALLOC
    };

    BtrfsExtentData::Regular {
        generation: cursor.next_u64(),
        ram_bytes: disk_num_bytes,
        extent_type,
        compression: BTRFS_COMPRESS_NONE,
        disk_bytenr,
        disk_num_bytes,
        extent_offset,
        num_bytes,
    }
}

fn assert_root_item_invariants(data: &[u8], parsed: &BtrfsRootItem) {
    assert_eq!(parsed.generation, read_u64(data, 160).unwrap_or_default());
    assert_eq!(parsed.root_dirid, read_u64(data, 168).unwrap_or_default());
    assert_eq!(parsed.bytenr, read_u64(data, 176).unwrap_or_default());
    assert_eq!(parsed.flags, read_u64(data, 208).unwrap_or_default());
    assert_eq!(
        parsed.refs,
        u64::from(read_u32(data, 216).unwrap_or_default())
    );
    assert_ne!(
        parsed.bytenr, 0,
        "successful root items must carry a non-zero bytenr"
    );
    assert_eq!(Some(parsed.level), data.get(238).copied());

    let extended_fields_valid =
        data.len() >= 247 && read_u64(data, 239).unwrap_or_default() == parsed.generation;
    let expected_uuid = if extended_fields_valid {
        read_array_16(data, 247).unwrap_or([0_u8; 16])
    } else {
        [0_u8; 16]
    };
    let expected_parent_uuid = if extended_fields_valid {
        read_array_16(data, 263).unwrap_or([0_u8; 16])
    } else {
        [0_u8; 16]
    };
    assert_eq!(parsed.uuid, expected_uuid);
    assert_eq!(parsed.parent_uuid, expected_parent_uuid);
}

fn assert_root_ref_invariants(data: &[u8], parsed: &BtrfsRootRef) {
    let name_len = usize::from(read_u16(data, 16).unwrap_or_default());
    let name_end = 18 + name_len;

    assert_eq!(parsed.dirid, read_u64(data, 0).unwrap_or_default());
    assert_eq!(parsed.sequence, read_u64(data, 8).unwrap_or_default());
    assert_eq!(parsed.name.len(), name_len);
    assert_eq!(parsed.name.as_slice(), &data[18..name_end]);
}

fn assert_inode_item_invariants(data: &[u8], parsed: &BtrfsInodeItem) {
    assert_eq!(parsed.generation, read_u64(data, 0).unwrap_or_default());
    assert_eq!(parsed.size, read_u64(data, 16).unwrap_or_default());
    assert_eq!(parsed.nbytes, read_u64(data, 24).unwrap_or_default());
    assert_eq!(parsed.nlink, read_u32(data, 40).unwrap_or_default());
    assert_eq!(parsed.uid, read_u32(data, 44).unwrap_or_default());
    assert_eq!(parsed.gid, read_u32(data, 48).unwrap_or_default());
    assert_eq!(parsed.mode, read_u32(data, 52).unwrap_or_default());
    assert_eq!(parsed.rdev, read_u64(data, 56).unwrap_or_default());
    assert_eq!(parsed.atime_sec, read_u64(data, 112).unwrap_or_default());
    assert_eq!(parsed.atime_nsec, read_u32(data, 120).unwrap_or_default());
    assert_eq!(parsed.ctime_sec, read_u64(data, 124).unwrap_or_default());
    assert_eq!(parsed.ctime_nsec, read_u32(data, 132).unwrap_or_default());
    assert_eq!(parsed.mtime_sec, read_u64(data, 136).unwrap_or_default());
    assert_eq!(parsed.mtime_nsec, read_u32(data, 144).unwrap_or_default());
    assert_eq!(parsed.otime_sec, read_u64(data, 148).unwrap_or_default());
    assert_eq!(parsed.otime_nsec, read_u32(data, 156).unwrap_or_default());
}

fn assert_dir_item_invariants(data: &[u8], parsed: &[BtrfsDirItem]) {
    const HEADER: usize = 30;

    if parsed.is_empty() {
        assert!(
            data.is_empty(),
            "successful empty DIR_ITEM decode should only happen on an empty payload"
        );
        return;
    }

    let mut cur = 0_usize;
    for item in parsed {
        assert!(
            cur + HEADER <= data.len(),
            "successful parse must leave a full dir-item header at {cur}"
        );

        let data_len = usize::from(read_u16(data, cur + 25).unwrap_or_default());
        let name_len = usize::from(read_u16(data, cur + 27).unwrap_or_default());
        let name_start = cur + HEADER;
        let Some(name_end) = name_start.checked_add(name_len) else {
            return;
        };
        let Some(payload_end) = name_end.checked_add(data_len) else {
            return;
        };

        assert!(
            payload_end <= data.len(),
            "successful dir-item parse must stay within the payload"
        );
        assert_eq!(item.child_objectid, read_u64(data, cur).unwrap_or_default());
        assert_eq!(item.child_key_type, data[cur + 8]);
        assert_eq!(
            item.child_key_offset,
            read_u64(data, cur + 9).unwrap_or_default()
        );
        assert_eq!(item.file_type, data[cur + 29]);
        assert_eq!(item.name.as_slice(), &data[name_start..name_end]);

        cur = payload_end;
    }

    assert_eq!(
        cur,
        data.len(),
        "successful dir-item decode must consume the full concatenated payload"
    );
}

fn assert_xattr_item_invariants(data: &[u8], parsed: &[BtrfsXattrItem]) {
    const HEADER: usize = 30;

    if parsed.is_empty() {
        assert!(
            data.is_empty(),
            "successful empty XATTR_ITEM decode should only happen on an empty payload"
        );
        return;
    }

    let mut cur = 0_usize;
    for item in parsed {
        assert!(
            cur + HEADER <= data.len(),
            "successful parse must leave a full xattr-item header at {cur}"
        );

        let data_len = usize::from(read_u16(data, cur + 25).unwrap_or_default());
        let name_len = usize::from(read_u16(data, cur + 27).unwrap_or_default());
        let name_start = cur + HEADER;
        let Some(name_end) = name_start.checked_add(name_len) else {
            return;
        };
        let Some(value_end) = name_end.checked_add(data_len) else {
            return;
        };

        assert!(
            value_end <= data.len(),
            "successful xattr-item parse must stay within the payload"
        );
        assert_eq!(item.name.as_slice(), &data[name_start..name_end]);
        assert_eq!(item.value.as_slice(), &data[name_end..value_end]);

        cur = value_end;
    }

    assert_eq!(
        cur,
        data.len(),
        "successful xattr-item decode must consume the full concatenated payload"
    );
}

fn assert_extent_data_invariants(data: &[u8], parsed: &BtrfsExtentData) {
    let generation = read_u64(data, 0).unwrap_or_default();
    let ram_bytes = read_u64(data, 8).unwrap_or_default();
    let compression = data.get(16).copied().unwrap_or_default();
    let extent_type = data.get(20).copied().unwrap_or_default();

    match parsed {
        BtrfsExtentData::Inline {
            generation: parsed_generation,
            ram_bytes: parsed_ram_bytes,
            compression: parsed_compression,
            data: parsed_data,
        } => {
            assert_eq!(extent_type, BTRFS_FILE_EXTENT_INLINE);
            assert_eq!(*parsed_generation, generation);
            assert_eq!(*parsed_ram_bytes, ram_bytes);
            assert_eq!(*parsed_compression, compression);
            assert_eq!(parsed_data.as_slice(), &data[21..]);
        }
        BtrfsExtentData::Regular {
            generation: parsed_generation,
            ram_bytes: parsed_ram_bytes,
            extent_type: parsed_extent_type,
            compression: parsed_compression,
            disk_bytenr,
            disk_num_bytes,
            extent_offset,
            num_bytes,
        } => {
            assert!(matches!(
                extent_type,
                BTRFS_FILE_EXTENT_REG | BTRFS_FILE_EXTENT_PREALLOC
            ));
            assert_eq!(*parsed_generation, generation);
            assert_eq!(*parsed_ram_bytes, ram_bytes);
            assert_eq!(*parsed_extent_type, extent_type);
            assert_eq!(*parsed_compression, compression);
            assert_eq!(*disk_bytenr, read_u64(data, 21).unwrap_or_default());
            assert_eq!(*disk_num_bytes, read_u64(data, 29).unwrap_or_default());
            assert_eq!(*extent_offset, read_u64(data, 37).unwrap_or_default());
            assert_eq!(*num_bytes, read_u64(data, 45).unwrap_or_default());
        }
    }
}

fn expect_invalid_field<T: std::fmt::Debug>(
    result: Result<T, ParseError>,
    field: &'static str,
    reason: &'static str,
    context: &str,
) {
    match result {
        Err(ParseError::InvalidField {
            field: got_field,
            reason: got_reason,
        }) => {
            assert_eq!(got_field, field, "{context}: invalid field drifted");
            assert_eq!(got_reason, reason, "{context}: invalid reason drifted");
        }
        other => {
            assert!(
                matches!(&other, Err(ParseError::InvalidField { .. })),
                "{context}: expected InvalidField({field}, {reason}), got {other:?}"
            );
        }
    }
}

fn expect_insufficient_data<T: std::fmt::Debug>(
    result: Result<T, ParseError>,
    needed: usize,
    offset: usize,
    actual: usize,
    context: &str,
) {
    match result {
        Err(ParseError::InsufficientData {
            needed: got_needed,
            offset: got_offset,
            actual: got_actual,
        }) => {
            assert_eq!(got_needed, needed, "{context}: needed length drifted");
            assert_eq!(got_offset, offset, "{context}: error offset drifted");
            assert_eq!(got_actual, actual, "{context}: actual length drifted");
        }
        other => {
            assert!(
                matches!(&other, Err(ParseError::InsufficientData { .. })),
                "{context}: expected InsufficientData({needed}, {offset}, {actual}), got {other:?}"
            );
        }
    }
}

fn assert_extent_data_boundary_contracts(cursor: &mut ByteCursor<'_>) {
    let inline_len = usize::from(cursor.next_u8() % (MAX_STRUCTURED_BYTES + 1));
    let inline = BtrfsExtentData::Inline {
        generation: cursor.next_u64(),
        ram_bytes: u64::try_from(inline_len).expect("inline extent length must fit u64"),
        compression: BTRFS_COMPRESS_NONE,
        data: cursor.take_vec(inline_len),
    };
    let inline_bytes = inline.to_bytes();

    let mut inline_len_mismatch = inline_bytes.clone();
    write_u64(
        &mut inline_len_mismatch,
        8,
        u64::try_from(inline_len)
            .expect("inline extent length must fit u64")
            .saturating_add(1),
    );
    expect_invalid_field(
        parse_extent_data(&inline_len_mismatch),
        "extent_data.ram_bytes",
        "uncompressed inline length mismatch",
        "uncompressed inline ram_bytes mismatch",
    );

    let mut unsupported_compression = inline_bytes.clone();
    unsupported_compression[16] = 0xff;
    expect_invalid_field(
        parse_extent_data(&unsupported_compression),
        "extent_data.compression",
        "unsupported compression",
        "unsupported compression",
    );

    let mut encrypted_inline = inline_bytes;
    encrypted_inline[17] = 1;
    expect_invalid_field(
        parse_extent_data(&encrypted_inline),
        "extent_data.encryption",
        "unsupported encryption",
        "unsupported encryption",
    );

    let regular = BtrfsExtentData::Regular {
        generation: cursor.next_u64(),
        ram_bytes: 4096,
        extent_type: BTRFS_FILE_EXTENT_REG,
        compression: BTRFS_COMPRESS_NONE,
        disk_bytenr: 0x1000 + u64::from(cursor.next_u8()),
        disk_num_bytes: 4096,
        extent_offset: 0,
        num_bytes: 4096,
    };
    let regular_bytes = regular.to_bytes();

    expect_insufficient_data(
        parse_extent_data(&regular_bytes[..regular_bytes.len() - 1]),
        53,
        0,
        52,
        "truncated regular extent",
    );

    let mut trailing_regular = regular_bytes.clone();
    trailing_regular.push(cursor.next_u8());
    expect_invalid_field(
        parse_extent_data(&trailing_regular),
        "extent_data.length",
        "trailing bytes after fixed extent payload",
        "regular extent trailing bytes",
    );

    let mut other_encoded = regular_bytes.clone();
    write_u16(&mut other_encoded, 18, 1);
    expect_invalid_field(
        parse_extent_data(&other_encoded),
        "extent_data.other_encoding",
        "unsupported other encoding",
        "unsupported other encoding",
    );

    let mut unknown_type = vec![0_u8; 21];
    unknown_type[20] = 0xff;
    expect_invalid_field(
        parse_extent_data(&unknown_type),
        "extent_data.type",
        "unsupported extent type",
        "unknown extent type",
    );

    let out_of_range_disk_extent = BtrfsExtentData::Regular {
        generation: cursor.next_u64(),
        ram_bytes: 8192,
        extent_type: BTRFS_FILE_EXTENT_PREALLOC,
        compression: BTRFS_COMPRESS_NONE,
        disk_bytenr: 0x2000,
        disk_num_bytes: 4096,
        extent_offset: 4096,
        num_bytes: 4096,
    };
    expect_invalid_field(
        parse_extent_data(&out_of_range_disk_extent.to_bytes()),
        "extent_data.extent_offset+num_bytes",
        "source slice exceeds disk_num_bytes",
        "uncompressed extent disk source bound",
    );

    let overflow_tail = u64::from(cursor.next_u8());
    let compressed_overflow = BtrfsExtentData::Regular {
        generation: cursor.next_u64(),
        ram_bytes: 4096,
        extent_type: BTRFS_FILE_EXTENT_REG,
        compression: BTRFS_COMPRESS_ZSTD,
        disk_bytenr: 0x3000,
        disk_num_bytes: 2048,
        extent_offset: u64::MAX - overflow_tail,
        num_bytes: overflow_tail.saturating_add(1),
    };
    expect_invalid_field(
        parse_extent_data(&compressed_overflow.to_bytes()),
        "extent_data.extent_offset+num_bytes",
        "source slice arithmetic overflow",
        "compressed extent source arithmetic overflow",
    );

    let exceeds_ram_bytes = BtrfsExtentData::Regular {
        generation: cursor.next_u64(),
        ram_bytes: 4096,
        extent_type: BTRFS_FILE_EXTENT_REG,
        compression: BTRFS_COMPRESS_ZLIB,
        disk_bytenr: 0x4000,
        disk_num_bytes: 2048,
        extent_offset: 4000,
        num_bytes: 200,
    };
    expect_invalid_field(
        parse_extent_data(&exceeds_ram_bytes.to_bytes()),
        "extent_data.extent_offset+num_bytes",
        "source slice exceeds ram_bytes",
        "compressed extent ram_bytes bound",
    );

    let valid_compressed = BtrfsExtentData::Regular {
        generation: cursor.next_u64(),
        ram_bytes: 4096,
        extent_type: BTRFS_FILE_EXTENT_REG,
        compression: BTRFS_COMPRESS_LZO,
        disk_bytenr: 0x5000,
        disk_num_bytes: 2048,
        extent_offset: 1024,
        num_bytes: 3072,
    };
    assert_eq!(
        parse_extent_data(&valid_compressed.to_bytes())
            .expect("valid compressed extent boundary payload must parse"),
        valid_compressed,
        "compressed extent should accept source slices ending exactly at ram_bytes"
    );
}

fn assert_structured_roundtrips(data: &[u8]) {
    let mut cursor = ByteCursor::new(data);

    let inode = build_inode_item(&mut cursor);
    let inode_bytes = inode.to_bytes();
    let parsed_inode =
        parse_inode_item(&inode_bytes).expect("generated INODE_ITEM payload must parse");
    assert_eq!(
        parsed_inode, inode,
        "BtrfsInodeItem::to_bytes must round-trip through parse_inode_item"
    );
    let mut inode_with_tail = inode_bytes.clone();
    inode_with_tail.push(cursor.next_u8());
    assert!(
        parse_inode_item(&inode_with_tail).is_err(),
        "fixed-size inode items must reject trailing bytes"
    );
    assert!(
        parse_inode_item(&inode_bytes[..inode_bytes.len() - 1]).is_err(),
        "fixed-size inode items must reject short payloads"
    );

    let root_item = build_root_item(&mut cursor);
    let root_item_legacy_bytes = root_item_to_bytes(&root_item, false);
    let parsed_legacy_root_item =
        parse_root_item(&root_item_legacy_bytes).expect("generated legacy ROOT_ITEM must parse");
    assert_eq!(
        parsed_legacy_root_item,
        BtrfsRootItem {
            uuid: [0_u8; 16],
            parent_uuid: [0_u8; 16],
            ..root_item
        },
        "legacy ROOT_ITEM payload must parse the fixed fields and clear UUID fields"
    );

    let root_item_uuid_bytes = root_item_to_bytes(&root_item, true);
    let parsed_uuid_root_item =
        parse_root_item(&root_item_uuid_bytes).expect("generated UUID-era ROOT_ITEM must parse");
    assert_eq!(
        parsed_uuid_root_item, root_item,
        "UUID-era ROOT_ITEM payload must parse all structured fields"
    );

    let mut zero_bytenr = root_item_uuid_bytes.clone();
    write_u64(&mut zero_bytenr, ROOT_ITEM_BYTENR_OFFSET, 0);
    assert!(
        parse_root_item(&zero_bytenr).is_err(),
        "ROOT_ITEM parser must reject zero bytenr"
    );

    let mut bad_level = root_item_uuid_bytes.clone();
    let level = bad_level
        .get_mut(ROOT_ITEM_LEVEL_OFFSET)
        .expect("ROOT_ITEM level byte must exist in UUID-era payload");
    *level = 8;
    assert!(
        parse_root_item(&bad_level).is_err(),
        "ROOT_ITEM parser must reject levels above BTRFS_MAX_TREE_LEVEL"
    );

    let mut partial_generation_v2 = root_item_legacy_bytes;
    partial_generation_v2.push(cursor.next_u8());
    assert!(
        parse_root_item(&partial_generation_v2).is_err(),
        "ROOT_ITEM parser must reject partial generation_v2 extension fields"
    );
    let partial_uuid = root_item_uuid_bytes
        .get(..ROOT_ITEM_UUID_OFFSET + 1)
        .expect("UUID-era ROOT_ITEM payload must include partial UUID slice");
    assert!(
        parse_root_item(partial_uuid).is_err(),
        "ROOT_ITEM parser must reject partial uuid extension fields"
    );
    let partial_parent_uuid = root_item_uuid_bytes
        .get(..ROOT_ITEM_PARENT_UUID_OFFSET + 1)
        .expect("UUID-era ROOT_ITEM payload must include partial parent UUID slice");
    assert!(
        parse_root_item(partial_parent_uuid).is_err(),
        "ROOT_ITEM parser must reject partial parent_uuid extension fields"
    );

    let root_ref = build_root_ref(&mut cursor);
    let root_ref_bytes = root_ref_to_bytes(&root_ref);
    let parsed_root_ref =
        parse_root_ref(&root_ref_bytes).expect("generated ROOT_REF payload must parse");
    assert_eq!(
        parsed_root_ref, root_ref,
        "structured ROOT_REF payload must parse exactly"
    );
    let mut empty_root_ref_name = root_ref_bytes.clone();
    let name_len_bytes = empty_root_ref_name
        .get_mut(16..18)
        .expect("ROOT_REF name length field must exist");
    name_len_bytes.copy_from_slice(&0_u16.to_le_bytes());
    assert!(
        parse_root_ref(&empty_root_ref_name).is_err(),
        "ROOT_REF parser must reject empty names"
    );
    assert!(
        parse_root_ref(&root_ref_bytes[..root_ref_bytes.len() - 1]).is_err(),
        "ROOT_REF parser must reject truncated names"
    );
    let mut root_ref_with_tail = root_ref_bytes;
    root_ref_with_tail.push(cursor.next_u8());
    assert!(
        parse_root_ref(&root_ref_with_tail).is_err(),
        "ROOT_REF parser must reject unconsumed trailing bytes"
    );

    let dir_first = build_dir_item(&mut cursor);
    let dir_second = build_dir_item(&mut cursor);
    let dir_first_bytes = dir_first
        .try_to_bytes()
        .expect("generated first DIR_ITEM payload must serialize");
    let dir_second_bytes = dir_second
        .try_to_bytes()
        .expect("generated second DIR_ITEM payload must serialize");
    let parsed_single_dir =
        parse_dir_items(&dir_first_bytes).expect("generated single DIR_ITEM payload must parse");
    assert_eq!(
        parsed_single_dir,
        vec![dir_first.clone()],
        "single BtrfsDirItem::try_to_bytes payload must parse exactly"
    );
    let mut concatenated_dirs = dir_first_bytes.clone();
    concatenated_dirs.extend_from_slice(&dir_second_bytes);
    let parsed_dirs =
        parse_dir_items(&concatenated_dirs).expect("concatenated DIR_ITEM payloads must parse");
    assert_eq!(
        parsed_dirs,
        vec![dir_first, dir_second],
        "concatenated BtrfsDirItem payloads must parse in order"
    );
    let mut dir_with_tail = dir_first_bytes;
    dir_with_tail.push(cursor.next_u8());
    assert!(
        parse_dir_items(&dir_with_tail).is_err(),
        "dir-item parser must reject unconsumed trailing bytes"
    );

    let xattr_first = build_xattr_item(&mut cursor);
    let xattr_second = build_xattr_item(&mut cursor);
    let xattr_first_bytes = xattr_item_to_bytes(&xattr_first);
    let xattr_second_bytes = xattr_item_to_bytes(&xattr_second);
    let parsed_single_xattr = parse_xattr_items(&xattr_first_bytes)
        .expect("generated single XATTR_ITEM payload must parse");
    assert_eq!(
        parsed_single_xattr,
        vec![xattr_first.clone()],
        "single BtrfsXattrItem payload must parse exactly"
    );
    let mut concatenated_xattrs = xattr_first_bytes.clone();
    concatenated_xattrs.extend_from_slice(&xattr_second_bytes);
    let parsed_xattrs = parse_xattr_items(&concatenated_xattrs)
        .expect("concatenated XATTR_ITEM payloads must parse");
    assert_eq!(
        parsed_xattrs,
        vec![xattr_first, xattr_second],
        "concatenated BtrfsXattrItem payloads must parse in order"
    );
    let mut xattr_with_tail = xattr_first_bytes.clone();
    xattr_with_tail.push(cursor.next_u8());
    assert!(
        parse_xattr_items(&xattr_with_tail).is_err(),
        "xattr-item parser must reject unconsumed trailing bytes"
    );
    assert!(
        parse_xattr_items(&xattr_first_bytes[..xattr_first_bytes.len() - 1]).is_err(),
        "xattr-item parser must reject short payloads"
    );

    for extent in [
        build_inline_extent(&mut cursor),
        build_regular_extent(&mut cursor),
    ] {
        let extent_bytes = extent.to_bytes();
        let parsed_extent =
            parse_extent_data(&extent_bytes).expect("generated EXTENT_DATA payload must parse");
        assert_eq!(
            parsed_extent, extent,
            "BtrfsExtentData::to_bytes must round-trip through parse_extent_data"
        );
        if matches!(
            extent,
            BtrfsExtentData::Regular {
                extent_type: BTRFS_FILE_EXTENT_REG | BTRFS_FILE_EXTENT_PREALLOC,
                ..
            }
        ) {
            let mut extent_with_tail = extent_bytes;
            extent_with_tail.push(cursor.next_u8());
            assert!(
                parse_extent_data(&extent_with_tail).is_err(),
                "fixed regular/prealloc extent payloads must reject trailing bytes"
            );
        }
    }

    assert_extent_data_boundary_contracts(&mut cursor);
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    assert_structured_roundtrips(data);

    let root_item = parse_root_item(data);
    assert_eq!(
        root_item,
        parse_root_item(data),
        "root-item parsing should be deterministic for identical bytes"
    );
    if let Ok(parsed) = &root_item {
        assert_root_item_invariants(data, parsed);
    }

    let root_ref = parse_root_ref(data);
    assert_eq!(
        root_ref,
        parse_root_ref(data),
        "root-ref parsing should be deterministic for identical bytes"
    );
    if let Ok(parsed) = &root_ref {
        assert_root_ref_invariants(data, parsed);
    }

    let inode_item = parse_inode_item(data);
    assert_eq!(
        inode_item,
        parse_inode_item(data),
        "inode-item parsing should be deterministic for identical bytes"
    );
    if let Ok(parsed) = &inode_item {
        assert_inode_item_invariants(data, parsed);
    }

    let dir_items = parse_dir_items(data);
    assert_eq!(
        dir_items,
        parse_dir_items(data),
        "dir-item parsing should be deterministic for identical bytes"
    );
    if let Ok(parsed) = &dir_items {
        assert_dir_item_invariants(data, parsed);
    }

    let xattr_items = parse_xattr_items(data);
    assert_eq!(
        xattr_items,
        parse_xattr_items(data),
        "xattr-item parsing should be deterministic for identical bytes"
    );
    if let Ok(parsed) = &xattr_items {
        assert_xattr_item_invariants(data, parsed);
    }

    let extent_data = parse_extent_data(data);
    assert_eq!(
        extent_data,
        parse_extent_data(data),
        "extent-data parsing should be deterministic for identical bytes"
    );
    if let Ok(parsed) = &extent_data {
        assert_extent_data_invariants(data, parsed);
    }
});
