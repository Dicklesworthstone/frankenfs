//! Conformance Family B: ext4 `ext4_inode` on-disk format golden round-trip.
//!
//! The ext4 inode layout has two size flavors in common use: 128 bytes
//! (no extended area, legacy images) and 256 bytes (extended area with
//! nsec timestamps and checksum_hi). A single-byte drift in either layout
//! silently corrupts real ext4 images, so this suite freezes both sizes
//! via golden byte arrays and requires `parse -> encode -> parse` to be
//! bit-exact.
//!
//! Fixtures are inlined as hex literals so every byte is visible in the
//! git diff.
//!
//! Known divergences documented in `DISCREPANCIES.md`.

use ffs_inode::fuzz_serialize_inode;
use ffs_ondisk::ext4::Ext4Inode;

/// Bit-exact round-trip helper: parse(fixture) -> struct -> encode(struct)
/// must equal `fixture`, and parse again must equal the first parse.
fn assert_inode_bitexact(fixture_name: &str, inode_size: usize, fixture: &[u8]) {
    let decoded = Ext4Inode::parse_from_bytes(fixture).expect("parse");
    let reencoded = fuzz_serialize_inode(&decoded, inode_size);
    assert_eq!(
        reencoded.as_slice(),
        fixture,
        "{fixture_name}: encode(parse(fixture)) diverged from fixture\n\
         decoded: {decoded:?}"
    );
    let redecoded = Ext4Inode::parse_from_bytes(&reencoded).expect("reparse");
    assert_eq!(
        redecoded, decoded,
        "{fixture_name}: parse(encode(parse(fixture))) diverged from parse(fixture)"
    );
}

// 128-byte inode, regular file, extent-based

/// Golden 128-byte inode for a regular file. Layout fixed per `fs/ext4/ext4.h`:
/// - mode     = 0o100_644 (regular file, 0644 perms) @ 0x00
/// - uid_lo   = 1000 @ 0x02
/// - size_lo  = 4096 @ 0x04
/// - atime    = 0x1800_0000 @ 0x08
/// - ctime    = 0x1800_0000 @ 0x0C
/// - mtime    = 0x1800_0000 @ 0x10
/// - dtime    = 0 @ 0x14
/// - gid_lo   = 1000 @ 0x18
/// - links    = 1 @ 0x1A
/// - blocks   = 8 @ 0x1C (in 512-byte sectors)
/// - flags    = 0x0008_0000 (EXT4_EXTENTS_FL) @ 0x20
/// - version  = 0 @ 0x24
/// - i_block  = zeroed 60-byte extent-tree root region @ 0x28
/// - generation = 0 @ 0x64
/// - file_acl_lo = 0 @ 0x68
/// - size_hi  = 0 @ 0x6C
/// - (128-byte inode has no extended area)
///
/// Note: for 128-byte inodes the parser does not read past 0x80, so extra_isize
/// is zero and xattr_ibody is empty. For the encoder to produce exactly 128
/// bytes, we pass `inode_size=128`.
const GOLDEN_INODE_128_REGFILE: [u8; 128] = {
    let mut buf = [0u8; 128];
    // mode @ 0x00 = 0o100644 = 0x81A4
    buf[0x00] = 0xA4;
    buf[0x01] = 0x81;
    // uid_lo @ 0x02 = 1000 = 0x03E8
    buf[0x02] = 0xE8;
    buf[0x03] = 0x03;
    // size_lo @ 0x04 = 4096 = 0x1000
    buf[0x04] = 0x00;
    buf[0x05] = 0x10;
    buf[0x06] = 0x00;
    buf[0x07] = 0x00;
    // atime @ 0x08 = 0x1800_0000
    buf[0x0B] = 0x18;
    // ctime @ 0x0C
    buf[0x0F] = 0x18;
    // mtime @ 0x10
    buf[0x13] = 0x18;
    // dtime @ 0x14 = 0
    // gid_lo @ 0x18 = 1000
    buf[0x18] = 0xE8;
    buf[0x19] = 0x03;
    // links @ 0x1A = 1
    buf[0x1A] = 0x01;
    // blocks @ 0x1C = 8
    buf[0x1C] = 0x08;
    // flags @ 0x20 = 0x0008_0000 (EXT4_EXTENTS_FL)
    buf[0x22] = 0x08;
    // i_block region 0x28..0x64 stays zero.
    // (60 bytes of extent-tree root; parser just reads raw.)
    buf
};

#[test]
fn golden_ext4_inode_128_regfile_bitexact() {
    assert_inode_bitexact("128-byte regfile", 128, &GOLDEN_INODE_128_REGFILE);
}

#[test]
fn golden_ext4_inode_128_regfile_fields_match() {
    let decoded = Ext4Inode::parse_from_bytes(&GOLDEN_INODE_128_REGFILE).expect("parse");
    assert_eq!(decoded.mode, 0o100_644);
    assert_eq!(decoded.uid, 1000);
    assert_eq!(decoded.gid, 1000);
    assert_eq!(decoded.size, 4096);
    assert_eq!(decoded.links_count, 1);
    assert_eq!(decoded.blocks, 8);
    assert_eq!(decoded.flags, 0x0008_0000);
    assert_eq!(decoded.atime, 0x1800_0000);
    assert_eq!(decoded.ctime, 0x1800_0000);
    assert_eq!(decoded.mtime, 0x1800_0000);
    assert_eq!(decoded.dtime, 0);
    assert_eq!(decoded.extent_bytes.len(), 60);
    // 128-byte inode: no extended area.
    assert_eq!(decoded.extra_isize, 0);
    assert_eq!(decoded.ctime_extra, 0);
    assert_eq!(decoded.mtime_extra, 0);
    assert_eq!(decoded.atime_extra, 0);
    assert_eq!(decoded.crtime, 0);
    assert_eq!(decoded.checksum, 0);
    assert_eq!(decoded.xattr_ibody, [] as [u8; 0]);
}

// 256-byte inode, directory, extended area with nsec timestamps

/// Golden 256-byte inode for a directory:
/// - mode         = 0o040_755 (directory, 0755 perms) @ 0x00
/// - uid          = 0 (root)
/// - size         = 4096
/// - atime/ctime/mtime = 0x2000_0000
/// - links_count  = 2 (dir always starts at nlink=2: self + "..")
/// - blocks       = 8
/// - flags        = 0x0008_1000 (EXT4_INDEX_FL | EXT4_EXTENTS_FL)
/// - extra_isize  = 0x20 (32 bytes after 128-byte base; standard for 256-byte
///   inodes on recent mkfs.ext4)
/// - ctime_extra  = 0x4 (nsec granularity marker)
/// - mtime_extra  = 0x8
/// - atime_extra  = 0xC
/// - crtime       = 0x2000_0000
/// - crtime_extra = 0x10
/// - version_hi   = 0
/// - projid       = 0
const GOLDEN_INODE_256_DIR: [u8; 256] = {
    let mut buf = [0u8; 256];
    // mode = 0o040755 = 0x41ED
    buf[0x00] = 0xED;
    buf[0x01] = 0x41;
    // uid_lo = 0, size_lo = 4096
    buf[0x04] = 0x00;
    buf[0x05] = 0x10;
    // atime/ctime/mtime at 0x20000000
    buf[0x0B] = 0x20;
    buf[0x0F] = 0x20;
    buf[0x13] = 0x20;
    // dtime = 0 (no deletion)
    // gid_lo = 0
    // links = 2
    buf[0x1A] = 0x02;
    // blocks = 8
    buf[0x1C] = 0x08;
    // flags = 0x0008_1000 = EXT4_EXTENTS_FL | EXT4_INDEX_FL (htree)
    buf[0x20] = 0x00;
    buf[0x21] = 0x10;
    buf[0x22] = 0x08;
    // i_block @ 0x28..0x64 stays zero.
    // extra_isize @ 0x80 = 0x0020
    buf[0x80] = 0x20;
    buf[0x81] = 0x00;
    // checksum_hi @ 0x82 = 0 (not computed in fixture)
    // ctime_extra @ 0x84 = 0x4
    buf[0x84] = 0x04;
    // mtime_extra @ 0x88 = 0x8
    buf[0x88] = 0x08;
    // atime_extra @ 0x8C = 0xC
    buf[0x8C] = 0x0C;
    // crtime @ 0x90 = 0x20000000
    buf[0x93] = 0x20;
    // crtime_extra @ 0x94 = 0x10
    buf[0x94] = 0x10;
    // version_hi @ 0x98 = 0
    // projid @ 0x9C = 0
    // inline xattr area starts at 128 + extra_isize = 0xA0; stays zero.
    buf
};

#[test]
fn golden_ext4_inode_256_dir_bitexact() {
    assert_inode_bitexact("256-byte directory", 256, &GOLDEN_INODE_256_DIR);
}

#[test]
fn golden_ext4_inode_256_dir_fields_match() {
    let decoded = Ext4Inode::parse_from_bytes(&GOLDEN_INODE_256_DIR).expect("parse");
    assert_eq!(decoded.mode, 0o040_755);
    assert_eq!(decoded.size, 4096);
    assert_eq!(decoded.links_count, 2);
    assert_eq!(decoded.blocks, 8);
    assert_eq!(decoded.flags, 0x0008_1000);
    assert_eq!(decoded.extra_isize, 0x20);
    assert_eq!(decoded.ctime_extra, 0x4);
    assert_eq!(decoded.mtime_extra, 0x8);
    assert_eq!(decoded.atime_extra, 0xC);
    assert_eq!(decoded.crtime, 0x2000_0000);
    assert_eq!(decoded.crtime_extra, 0x10);
    // xattr region is all zeros, so ibody is 96 zero bytes.
    assert_eq!(decoded.xattr_ibody.len(), 256 - 128 - 32);
    assert!(decoded.xattr_ibody.iter().all(|&b| b == 0));
}

// 256-byte inode with split uid/gid (proves high halves are preserved)

/// Regression guard: many historical ext4 parser bugs dropped `uid_hi`/`gid_hi`
/// and returned truncated 16-bit uids. Real Linux systems use 32-bit uids
/// (e.g. LDAP environments with numeric uids > 65535). This fixture uses
/// uid = 0x0012_0003 and gid = 0x0034_0005 so both halves are populated.
const GOLDEN_INODE_256_HIGH_UID_GID: [u8; 256] = {
    let mut buf = [0u8; 256];
    // mode = 0o100644
    buf[0x00] = 0xA4;
    buf[0x01] = 0x81;
    // uid_lo = 0x0003 @ 0x02
    buf[0x02] = 0x03;
    buf[0x03] = 0x00;
    // size_lo = 0
    // timestamps = 0
    // gid_lo = 0x0005 @ 0x18
    buf[0x18] = 0x05;
    buf[0x19] = 0x00;
    // links = 1 @ 0x1A
    buf[0x1A] = 0x01;
    // blocks = 0
    // flags = 0
    // generation @ 0x64 = 0x1234_5678
    buf[0x64] = 0x78;
    buf[0x65] = 0x56;
    buf[0x66] = 0x34;
    buf[0x67] = 0x12;
    // uid_hi @ 0x78 = 0x0012
    buf[0x78] = 0x12;
    buf[0x79] = 0x00;
    // gid_hi @ 0x7A = 0x0034
    buf[0x7A] = 0x34;
    buf[0x7B] = 0x00;
    // extra_isize @ 0x80 = 0x20
    buf[0x80] = 0x20;
    buf
};

#[test]
fn golden_ext4_inode_256_high_uid_gid_bitexact() {
    assert_inode_bitexact("256-byte high uid/gid", 256, &GOLDEN_INODE_256_HIGH_UID_GID);
}

#[test]
fn golden_ext4_inode_256_high_uid_gid_preserved() {
    let decoded = Ext4Inode::parse_from_bytes(&GOLDEN_INODE_256_HIGH_UID_GID).expect("parse");
    assert_eq!(decoded.uid, 0x0012_0003, "full 32-bit uid");
    assert_eq!(decoded.gid, 0x0034_0005, "full 32-bit gid");
    assert_eq!(decoded.generation, 0x1234_5678);
}

// size > 4 GiB (size_hi used)

/// Regression guard: ext4 files > 4 GiB require `size_hi` at offset 0x6C.
/// If the parser drops `size_hi` or the encoder writes zero, large files
/// appear truncated at parse time.
#[test]
fn ext4_inode_size_above_4gib_roundtrips() {
    // 5 GiB size.
    let big_size: u64 = 5u64 * (1u64 << 30);
    let inode = Ext4Inode {
        mode: 0o100_644,
        uid: 1000,
        gid: 1000,
        size: big_size,
        links_count: 1,
        blocks: big_size / 512,
        flags: 0x0008_0000, // EXT4_EXTENTS_FL
        version: 0,
        generation: 0,
        file_acl: 0,
        atime: 0,
        ctime: 0,
        mtime: 0,
        dtime: 0,
        atime_extra: 0,
        ctime_extra: 0,
        mtime_extra: 0,
        crtime: 0,
        crtime_extra: 0,
        extra_isize: 0x20,
        checksum: 0,
        version_hi: 0,
        projid: 0,
        extent_bytes: vec![0u8; 60].into(),
        xattr_ibody: vec![0u8; 256 - 128 - 32],
        number: 0,
    };
    let encoded = fuzz_serialize_inode(&inode, 256);
    assert_eq!(encoded.len(), 256);
    // size_lo @ 0x04 must be low 32 bits
    let size_lo_be_u32 =
        u32::from_le_bytes([encoded[0x04], encoded[0x05], encoded[0x06], encoded[0x07]]);
    let size_hi_be_u32 =
        u32::from_le_bytes([encoded[0x6C], encoded[0x6D], encoded[0x6E], encoded[0x6F]]);
    assert_eq!(
        u64::from(size_lo_be_u32) | (u64::from(size_hi_be_u32) << 32),
        big_size,
        "size split across hi/lo must reconstitute"
    );
    let decoded = Ext4Inode::parse_from_bytes(&encoded).expect("parse");
    assert_eq!(decoded.size, big_size, "size round-trip diverged");
}

// Inode size boundaries (parser must reject < 128)

#[test]
fn ext4_inode_rejects_shorter_than_128_bytes() {
    for len in 0..128 {
        let err = Ext4Inode::parse_from_bytes(&vec![0u8; len]).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("InsufficientData"),
            "len={len}: expected InsufficientData, got {err:?}"
        );
    }
}

#[test]
fn ext4_inode_rejects_extra_isize_past_inode_boundary() {
    // extra_isize @ 0x80 = 200 would mean extended area goes to offset 328,
    // but inode size is 256. Parser must reject.
    let mut bad = [0u8; 256];
    bad[0x80] = 200; // extra_isize = 200
    let err = Ext4Inode::parse_from_bytes(&bad).unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("extra_isize"),
        "expected extra_isize rejection, got {err:?}"
    );
}

// Extent byte region preserved verbatim

/// The 60-byte i_block region at 0x28 contains either an extent-tree root or
/// inline file data. The inode layer must preserve those bytes verbatim so
/// higher layers (ffs-extent) can parse them without corruption.
#[test]
fn ext4_inode_extent_bytes_preserved_verbatim() {
    let mut raw = [0u8; 256];
    raw[0x00] = 0xA4; // mode low
    raw[0x01] = 0x81; // mode high (regfile)
    raw[0x1A] = 0x01; // links
    raw[0x80] = 0x20; // extra_isize

    // Fill i_block with a distinctive pattern
    for (i, byte) in raw[0x28..0x28 + 60].iter_mut().enumerate() {
        *byte = 0x40 + u8::try_from(i).expect("i_block fixture offset fits in u8");
    }

    let decoded = Ext4Inode::parse_from_bytes(&raw).expect("parse");
    assert_eq!(decoded.extent_bytes.len(), 60);
    for (i, byte) in decoded.extent_bytes.iter().enumerate() {
        assert_eq!(
            *byte,
            0x40 + u8::try_from(i).expect("i_block fixture offset fits in u8"),
            "extent_bytes[{i}] corrupted on parse"
        );
    }

    // Round-trip
    let reencoded = fuzz_serialize_inode(&decoded, 256);
    for (i, byte) in reencoded[0x28..0x28 + 60].iter().enumerate() {
        assert_eq!(
            *byte,
            0x40 + u8::try_from(i).expect("i_block fixture offset fits in u8"),
            "extent_bytes[{i}] corrupted on encode"
        );
    }
}
