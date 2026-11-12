#![no_main]

use ffs_inode::{encode_extra_timestamp, fuzz_serialize_inode};
use ffs_ondisk::Ext4Inode;
use ffs_types::{S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFMT, S_IFREG, S_IFSOCK};
use libfuzzer_sys::fuzz_target;

const MAX_RAW_BYTES: usize = 512;
const MAX_EXTENT_BYTES: usize = 60;
const MAX_EXTRA_ISIZE: usize = 64;
const EXTRA_ISIZE_CHOICES: [u16; 4] = [0, 28, 32, 64];

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

    fn next_index(&mut self, len: usize) -> usize {
        if len == 0 {
            0
        } else {
            usize::from(self.next_u16()) % len
        }
    }

    fn take_vec(&mut self, max_len: usize) -> Vec<u8> {
        let len = self.next_index(max_len.saturating_add(1));
        (0..len).map(|_| self.next_u8()).collect()
    }

    fn remainder(&self) -> &'a [u8] {
        self.data.get(self.pos..).unwrap_or(&[])
    }
}

#[derive(Clone, Copy)]
enum SeedMode {
    Raw,
    SyntheticRegular,
    SyntheticDirectory,
    SyntheticAllFileTypes,
    Truncated,
}

impl SeedMode {
    fn from_selector(selector: u8) -> Self {
        match selector % 5 {
            0 => Self::Raw,
            1 => Self::SyntheticRegular,
            2 => Self::SyntheticDirectory,
            3 => Self::SyntheticAllFileTypes,
            _ => Self::Truncated,
        }
    }
}

#[derive(Clone, Copy)]
struct FileTypeCase {
    name: &'static str,
    mode_bits: u16,
}

const FILE_TYPE_CASES: [FileTypeCase; 7] = [
    FileTypeCase {
        name: "regular",
        mode_bits: S_IFREG,
    },
    FileTypeCase {
        name: "directory",
        mode_bits: S_IFDIR,
    },
    FileTypeCase {
        name: "symlink",
        mode_bits: S_IFLNK,
    },
    FileTypeCase {
        name: "char-device",
        mode_bits: S_IFCHR,
    },
    FileTypeCase {
        name: "block-device",
        mode_bits: S_IFBLK,
    },
    FileTypeCase {
        name: "fifo",
        mode_bits: S_IFIFO,
    },
    FileTypeCase {
        name: "socket",
        mode_bits: S_IFSOCK,
    },
];

fn expected_encode_extra_timestamp(secs: i64, nsec: u32) -> u32 {
    (((secs.wrapping_sub(i64::from(secs as i32)) >> 32) & 0x3) as u32)
        | (nsec.min(999_999_999) << 2)
}

fn choose_inode_size(cursor: &mut ByteCursor<'_>) -> usize {
    if cursor.next_u8() & 1 == 0 {
        128
    } else {
        256
    }
}

fn choose_extra_isize(cursor: &mut ByteCursor<'_>, inode_size: usize) -> u16 {
    if inode_size <= 128 {
        return 0;
    }

    let max_extra = inode_size.saturating_sub(128).min(MAX_EXTRA_ISIZE);
    EXTRA_ISIZE_CHOICES[cursor.next_index(EXTRA_ISIZE_CHOICES.len())]
        .min(u16::try_from(max_extra).unwrap_or(u16::MAX))
}

fn build_synthetic_inode(
    cursor: &mut ByteCursor<'_>,
    mode_bits: u16,
    inode_size: usize,
) -> Ext4Inode {
    let extra_isize = choose_extra_isize(cursor, inode_size);
    let xattr_capacity = inode_size.saturating_sub(128 + usize::from(extra_isize));

    // The parser reads each extra-area field only when both
    //   extra_end = 128 + extra_isize
    // covers the field's tail AND inode_size is large enough. The
    // serializer writes them when only inode_size is large enough — so
    // an extra_isize too small to "advertise" a given field rounds the
    // serialized value back to zero on parse. Build the synthetic shape
    // to match the parser's read condition so the round-trip is
    // bijective for any valid (inode_size, extra_isize) pair.
    let extra_end: usize = 128 + usize::from(extra_isize);
    let advertise =
        |needed_end: usize| -> bool { extra_end >= needed_end && inode_size >= needed_end };

    let atime = cursor.next_u32();
    let ctime = cursor.next_u32();
    let mtime = cursor.next_u32();
    let dtime = cursor.next_u32();
    let crtime = if advertise(0x94) {
        cursor.next_u32()
    } else {
        0
    };

    // On disk, `blocks` and `file_acl` are split as lo (u32) + hi (u16) —
    // a 48-bit representation that drops bits 48..63 on serialize. Mask
    // the synthesized values down to 48 bits so the round-trip is
    // bijective regardless of the cursor-derived high bytes.
    const ON_DISK_48BIT_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;
    let raw_size = cursor.next_u64();
    let file_type = mode_bits & S_IFMT;
    let size = if matches!(file_type, S_IFREG | S_IFDIR) {
        raw_size
    } else {
        raw_size & u64::from(u32::MAX)
    };
    Ext4Inode {
        mode: mode_bits | (u16::from(cursor.next_u8()) & 0o777),
        uid: cursor.next_u32(),
        gid: cursor.next_u32(),
        size,
        links_count: cursor.next_u16(),
        blocks: cursor.next_u64() & ON_DISK_48BIT_MASK,
        flags: cursor.next_u32(),
        version: cursor.next_u32(),
        generation: cursor.next_u32(),
        file_acl: cursor.next_u64() & ON_DISK_48BIT_MASK,
        atime,
        ctime,
        mtime,
        dtime,
        atime_extra: if advertise(0x90) {
            expected_encode_extra_timestamp(cursor.next_u64() as i64, cursor.next_u32())
        } else {
            0
        },
        ctime_extra: if advertise(0x88) {
            expected_encode_extra_timestamp(cursor.next_u64() as i64, cursor.next_u32())
        } else {
            0
        },
        mtime_extra: if advertise(0x8C) {
            expected_encode_extra_timestamp(cursor.next_u64() as i64, cursor.next_u32())
        } else {
            0
        },
        crtime,
        crtime_extra: if advertise(0x98) {
            expected_encode_extra_timestamp(cursor.next_u64() as i64, cursor.next_u32())
        } else {
            0
        },
        extra_isize,
        // Match serialize_inode's behavior: it leaves the checksum slot
        // untouched (the production path writes it via
        // compute_and_set_checksum in a separate step), so the round-trip
        // through fuzz_serialize_inode reads back zero. Pin checksum to 0
        // here so verify_roundtrip stays bijective.
        checksum: {
            let _ = cursor.next_u32();
            0
        },
        version_hi: if advertise(0x9C) {
            cursor.next_u32()
        } else {
            0
        },
        projid: if advertise(0xA0) {
            cursor.next_u32()
        } else {
            0
        },
        // Ext4Inode::parse_from_bytes always returns extent_bytes as a
        // fixed 60-byte Vec (the i_block area). Match that shape exactly
        // so verify_roundtrip's serialize→parse cycle is bijective: a
        // shorter Vec here would silently round-trip back to 60 bytes
        // and trip the `parsed != inode` abort.
        extent_bytes: {
            let mut v = cursor.take_vec(MAX_EXTENT_BYTES);
            v.resize(MAX_EXTENT_BYTES, 0);
            v.into()
        },
        // The on-disk xattr_ibody fills the inode tail from
        // (128 + extra_isize) to inode_size, but only when
        // extra_isize > 0 — Ext4Inode::parse_from_bytes returns an
        // empty Vec when extra_isize == 0 (treating the tail as
        // unused). Match that semantic precisely so the round-trip
        // is bijective regardless of the extra_isize choice.
        xattr_ibody: if extra_isize > 0 {
            let mut v = cursor.take_vec(xattr_capacity);
            v.resize(xattr_capacity, 0);
            v
        } else {
            Vec::new()
        },
        number: 0,
    }
}

fn verify_roundtrip(inode: &Ext4Inode, inode_size: usize) -> Ext4Inode {
    let raw = fuzz_serialize_inode(inode, inode_size);
    let parsed = Ext4Inode::parse_from_bytes(&raw)
        .expect("serialized synthetic inode must parse successfully");
    assert!(
        &parsed == inode,
        "serialized inode must parse back to the same Ext4Inode"
    );
    let raw_again = fuzz_serialize_inode(&parsed, inode_size);
    assert_eq!(
        raw_again, raw,
        "inode serialize-parse-serialize cycle must be byte-stable"
    );
    parsed
}

fn assert_file_type_case(inode: &Ext4Inode, case: FileTypeCase) {
    assert_eq!(
        inode.file_type_mode(),
        case.mode_bits,
        "{} inode must preserve file type bits",
        case.name
    );

    let predicates = [
        ("regular", inode.is_regular(), case.mode_bits == S_IFREG),
        ("directory", inode.is_dir(), case.mode_bits == S_IFDIR),
        ("symlink", inode.is_symlink(), case.mode_bits == S_IFLNK),
        ("char-device", inode.is_chrdev(), case.mode_bits == S_IFCHR),
        ("block-device", inode.is_blkdev(), case.mode_bits == S_IFBLK),
        ("fifo", inode.is_fifo(), case.mode_bits == S_IFIFO),
        ("socket", inode.is_socket(), case.mode_bits == S_IFSOCK),
    ];

    let mut matched = 0_u8;
    for (predicate, actual, expected) in predicates {
        assert_eq!(
            actual, expected,
            "{} inode predicate {predicate} drifted",
            case.name
        );
        if actual {
            matched = matched.saturating_add(1);
        }
    }
    assert_eq!(
        matched, 1,
        "{} inode must match exactly one file-type predicate",
        case.name
    );
}

fn verify_synthetic_file_type(cursor: &mut ByteCursor<'_>, case: FileTypeCase) {
    let inode_size = choose_inode_size(cursor);
    let inode = build_synthetic_inode(cursor, case.mode_bits, inode_size);
    assert_file_type_case(&inode, case);
    let parsed = verify_roundtrip(&inode, inode_size);
    assert_file_type_case(&parsed, case);
}

fn verify_raw_bytes(raw: &[u8]) {
    if let Ok(mut parsed) = Ext4Inode::parse_from_bytes(raw) {
        // Choose inode_size to keep the round-trip bijective. The
        // serializer writes the extra area only when inode_size > 128,
        // and writes xattr_ibody only inside the [128 + extra_isize,
        // inode_size) window. If we picked inode_size = 128 but the
        // parsed inode has extra_isize > 0 or non-empty xattr_ibody,
        // serialize would silently drop those fields and the second
        // parse would observe extra_isize = 0 — diverging from the
        // first parse and tripping the abort.
        let needs_extra_area = parsed.extra_isize > 0 || !parsed.xattr_ibody.is_empty();
        let inode_size: usize = if needs_extra_area || raw.len() >= 256 {
            256
        } else {
            128
        };
        // The kernel/parser invariant is `extra_isize <= inode_size - 128`,
        // so a parsed extra_isize > 128 (read from raw > 256 with garbage
        // at offset 0x80) cannot be re-parsed at inode_size=256 — the
        // re-parse hits the "extra_isize extends beyond inode boundary"
        // rejection and the second parse aborts before equality even
        // gets a chance. Clamp to the chosen inode_size.
        let max_extra_isize = u16::try_from(inode_size.saturating_sub(128)).unwrap_or(u16::MAX);
        if parsed.extra_isize > max_extra_isize {
            parsed.extra_isize = max_extra_isize;
        }
        // parse_from_bytes returns xattr_ibody empty whenever extra_isize
        // is zero, regardless of inode_size; otherwise it reads
        // bytes[xattr_start..] to end-of-buffer, which after a
        // 256-byte serialize+parse always produces (inode_size -
        // xattr_start) bytes. Match that exact contract: empty Vec when
        // extra_isize == 0, fixed (inode_size - xattr_start) length
        // otherwise (truncating overflow from raw > 256, padding short
        // data with zeros).
        if parsed.extra_isize == 0 {
            parsed.xattr_ibody.clear();
        } else {
            let xattr_start: usize = 128 + usize::from(parsed.extra_isize);
            let max_xattr: usize = inode_size.saturating_sub(xattr_start);
            parsed.xattr_ibody.resize(max_xattr, 0);
        }
        // serialize_inode deliberately leaves the checksum_lo/checksum_hi
        // bytes (offsets 0x7C and 0x82) untouched — they are written by
        // compute_and_set_checksum in the caller's context, which the
        // bare fuzz_serialize_inode path does not invoke. Zero out the
        // parsed checksum so the round-trip is bijective: a non-zero
        // value here came from the raw input, gets dropped during
        // serialize, and reads back as zero — a guaranteed mismatch
        // otherwise.
        parsed.checksum = 0;
        verify_roundtrip(&parsed, inode_size);
    }
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = ByteCursor::new(data);
    let secs = cursor.next_u64() as i64;
    let nsec = cursor.next_u32();
    let encoded = encode_extra_timestamp(secs, nsec);
    assert_eq!(
        encoded,
        expected_encode_extra_timestamp(secs, nsec),
        "extra timestamp encoding must match the ext4 bit layout"
    );

    match SeedMode::from_selector(cursor.next_u8()) {
        SeedMode::Raw => {
            let raw: Vec<u8> = cursor
                .remainder()
                .iter()
                .copied()
                .take(MAX_RAW_BYTES)
                .collect();
            verify_raw_bytes(&raw);
        }
        SeedMode::SyntheticRegular => {
            let inode_size = choose_inode_size(&mut cursor);
            let inode = build_synthetic_inode(&mut cursor, S_IFREG, inode_size);
            verify_roundtrip(&inode, inode_size);
        }
        SeedMode::SyntheticDirectory => {
            let inode_size = choose_inode_size(&mut cursor);
            let inode = build_synthetic_inode(&mut cursor, S_IFDIR, inode_size);
            verify_roundtrip(&inode, inode_size);
        }
        SeedMode::SyntheticAllFileTypes => {
            for case in FILE_TYPE_CASES {
                verify_synthetic_file_type(&mut cursor, case);
            }
        }
        SeedMode::Truncated => {
            let mut raw: Vec<u8> = cursor
                .remainder()
                .iter()
                .copied()
                .take(MAX_RAW_BYTES)
                .collect();
            raw.truncate(cursor.next_index(raw.len().saturating_add(1)));
            verify_raw_bytes(&raw);
        }
    }
});
