//! Native ZFS gzip is a zlib stream, not an RFC 1952 gzip member.
//! Fixed RFC 1950/1951 vectors exercise framing without using a test encoder.
//! The dynamic DEFLATE payload is the "length extra" vector in zlib v1.3.1
//! test/infcover.c. Its zlib wrapper and Adler-32 are specified independently.
//! These are parser fixtures, not native pool/interchange execution evidence.

use super::{BlockPointer, Endian, MAX_BLOCK_BYTES, checksum, decompress};

// One final fixed-Huffman block: A, NUL, B; distance-three matches of
// 258 + 258 + 258 + 246 bytes; Z; END. This is (A NUL B) * 341 + Z.
// Adler-32 is 0xc3f7_aeda; the last byte of DEFLATE is at offset 14.
const FIXED: [u8; 19] = [
    0x78, 0x01, 0x73, 0x64, 0x70, 0x1a, 0x45, 0xa3, 0x68, 0x14, 0x8d, 0x4c, 0x14, 0x05, 0x00, 0xc3,
    0xf7, 0xae, 0xda,
];
const LOGICAL: usize = 1024;

// Published dynamic-Huffman DEFLATE stream: 516 zero bytes.
// Reference: https://github.com/madler/zlib/blob/v1.3.1/test/infcover.c
const DYNAMIC: [u8; 21] = [
    0x78, 0x01, 0xed, 0xc0, 0x01, 0x01, 0x00, 0x00, 0x00, 0x40, 0x20, 0xff, 0x57, 0x1b, 0x42, 0x2c,
    0x4f, 0x02, 0x04, 0x00, 0x01,
];

// Final stored block, LEN=11, NLEN=0xfff4, followed by native zlib Adler-32.
const STORED: [u8; 22] = [
    0x78, 0x01, 0x01, 0x0b, 0x00, 0xf4, 0xff, b's', b't', b'o', b'r', b'e', b'd', 0, b'd', b'a',
    b't', b'a', 0x1a, 0x12, 0x04, 0x2c,
];

fn expected() -> Vec<u8> {
    let mut bytes = [b'A', 0, b'B'].repeat(341);
    bytes.push(b'Z');
    bytes
}

fn pointer(words: [u64; 16], containing: Endian) -> BlockPointer {
    let raw: Vec<u8> = words
        .into_iter()
        .flat_map(|word| containing.encode(word))
        .collect();
    BlockPointer::parse(&raw, containing).unwrap()
}

fn physical_pointer(
    physical: &[u8],
    codec: u8,
    containing: Endian,
    payload: Endian,
) -> BlockPointer {
    assert_eq!(physical.len(), 512);
    let mut words = [0_u64; 16];
    words[0] = 1;
    words[1] = 8;
    words[6] = 1 // Two logical sectors, one physical sector.
        | (u64::from(codec) << 32)
        | (7 << 40)
        | (19 << 48)
        | (u64::from(payload == Endian::Little) << 63);
    words[10] = 42;
    words[12..].copy_from_slice(&checksum(physical, 7, payload).unwrap());
    pointer(words, containing)
}

fn embedded_pointer(
    packed: &[u8],
    logical: usize,
    codec: u8,
    containing: Endian,
    payload: Endian,
) -> BlockPointer {
    assert!(!packed.is_empty() && packed.len() <= 112);
    let mut words = [0_u64; 16];
    let mut chunks = packed.chunks(8);
    for (index, word) in words.iter_mut().enumerate() {
        if index != 6
            && index != 10
            && let Some(chunk) = chunks.next()
        {
            let mut bytes = [0; 8];
            bytes[..chunk.len()].copy_from_slice(chunk);
            *word = u64::from_le_bytes(bytes);
        }
    }
    words[6] = (logical as u64 - 1)
        | ((packed.len() as u64 - 1) << 25)
        | (u64::from(codec) << 32)
        | (1 << 39)
        | (19 << 48)
        | (u64::from(payload == Endian::Little) << 63);
    words[10] = 42;
    pointer(words, containing)
}

#[test]
fn gzip_all_native_levels_decode_fixed_dynamic_and_stored_deflate() {
    for codec in 5..=13 {
        assert_eq!(decompress(&FIXED, codec, LOGICAL).unwrap(), expected());
        assert_eq!(decompress(&DYNAMIC, codec, 516).unwrap(), vec![0; 516]);
        assert_eq!(decompress(&STORED, codec, 11).unwrap(), b"stored\0data");
    }
}

#[test]
fn gzip_requires_the_complete_zlib_stream_and_exact_logical_size() {
    for codec in 5..=13 {
        for (packed, length) in [
            (FIXED.as_slice(), LOGICAL),
            (DYNAMIC.as_slice(), 516),
            (STORED.as_slice(), 11),
        ] {
            for end in 0..packed.len() {
                assert!(decompress(&packed[..end], codec, length).is_err(), "{end}");
            }
            assert!(decompress(packed, codec, length - 1).is_err());
            assert!(decompress(packed, codec, length + 1).is_err());
        }
        // Enough bytes may already have been produced, but an absent or
        // damaged Adler-32 trailer must still prevent any successful read.
        let mut damaged = FIXED;
        damaged[18] ^= 1;
        assert!(decompress(&damaged, codec, LOGICAL).is_err());
        assert!(decompress(&FIXED, codec, 0).is_err());
        assert!(decompress(&FIXED, codec, MAX_BLOCK_BYTES + 1).is_err());
    }
    assert!(decompress(&vec![0; MAX_BLOCK_BYTES + 1], 5, LOGICAL).is_err());
}

#[test]
fn gzip_rejects_other_framing_dictionaries_and_invalid_deflate() {
    // A complete RFC 1952 member for "A" with correct CRC32 and ISIZE.
    let gzip_member = [
        0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3, 0x73, 4, 0, 0x8b, 0x9e, 0xd9, 0xd3, 1, 0, 0, 0,
    ];
    // Valid zlib header with FDICT and dictionary Adler-32 1.
    let dictionary = [0x78, 0x20, 0, 0, 0, 1, 3, 0, 0, 0, 0, 1];
    for codec in 5..=13 {
        assert!(decompress(&gzip_member, codec, 1).is_err());
        assert!(decompress(&FIXED[2..15], codec, LOGICAL).is_err());
        assert!(decompress(&dictionary, codec, 1).is_err());
        for packed in [
            &[0x78, 0x00][..], // Invalid header check bits.
            &[0x78, 0x01, 0x06, 0, 0, 0, 1][..], // Reserved DEFLATE block type.
            &[0x78, 0x01, 0, 0, 0, 0, 0][..], // Stored LEN/NLEN disagree.
            &[0x78, 0x01, 4, 0, 0xfe, 0xff][..], // Invalid Huffman code lengths.
        ] {
            assert!(decompress(packed, codec, LOGICAL).is_err());
        }
    }
}

#[test]
fn gzip_ends_at_the_first_stream_without_concatenating_allocation_padding() {
    let mut combined = FIXED.to_vec();
    combined.extend_from_slice(&FIXED);
    for codec in 5..=13 {
        assert_eq!(decompress(&combined, codec, LOGICAL).unwrap(), expected());
        assert!(decompress(&combined, codec, 2 * LOGICAL).is_err());
    }
    combined[18] ^= 1;
    assert!(decompress(&combined, 5, LOGICAL).is_err());
}

#[test]
fn gzip_physical_blocks_verify_all_psize_bytes_before_decoding() {
    for codec in 5..=13 {
        for containing in [Endian::Little, Endian::Big] {
            for payload in [Endian::Little, Endian::Big] {
                let mut physical = vec![0; 512];
                physical[..FIXED.len()].copy_from_slice(&FIXED);
                let bp = physical_pointer(&physical, codec, containing, payload);
                assert_eq!(bp.regular_dvas().unwrap().len(), 1);
                assert_eq!((bp.logical_bytes(), bp.physical_bytes()), (LOGICAL, 512));
                assert_eq!(bp.decode(&physical).unwrap(), expected());
                assert!(bp.decode(&physical[..511]).is_err());

                physical[511] = 0xa5;
                assert_eq!(decompress(&physical, codec, LOGICAL).unwrap(), expected());
                assert!(bp.decode(&physical).is_err());
                let updated = physical_pointer(&physical, codec, containing, payload);
                assert_eq!(updated.decode(&physical).unwrap(), expected());

                for sector_count in [0, 2] {
                    let mut wrong_size = updated.clone();
                    wrong_size.words[6] = (wrong_size.words[6] & !0xffff) | sector_count;
                    assert!(wrong_size.decode(&physical).is_err());
                }
                // Recomputing the outer checksum cannot legitimize a broken
                // inner zlib stream, even if all logical bytes were produced.
                physical[18] ^= 1;
                let damaged = physical_pointer(&physical, codec, containing, payload);
                assert!(damaged.regular_dvas().is_ok());
                assert!(damaged.decode(&physical).is_err());
            }
        }
    }
}

#[test]
fn gzip_embedded_blocks_decode_all_levels_and_both_byte_orders() {
    for codec in 5..=13 {
        for containing in [Endian::Little, Endian::Big] {
            for payload in [Endian::Little, Endian::Big] {
                for (packed, bytes) in [
                    (FIXED.as_slice(), expected()),
                    (DYNAMIC.as_slice(), vec![0; 516]),
                ] {
                    let bp = embedded_pointer(packed, bytes.len(), codec, containing, payload);
                    assert_eq!(bp.payload_order(), payload);
                    assert_eq!(bp.physical_bytes(), 0);
                    assert!(!bp.hole());
                    assert!(bp.regular_dvas().is_err());
                    assert_eq!(bp.decode_embedded().unwrap(), bytes);
                    assert_eq!(bp.decode(&[]).unwrap(), bytes);
                    assert!(bp.decode(packed).is_err());

                    let truncated = embedded_pointer(
                        &packed[..packed.len() - 1],
                        bytes.len(),
                        codec,
                        containing,
                        payload,
                    );
                    assert!(truncated.decode(&[]).is_err());
                    let overrun =
                        embedded_pointer(packed, bytes.len() - 1, codec, containing, payload);
                    assert!(overrun.decode(&[]).is_err());
                }
            }
        }
    }
}

#[test]
fn gzip_admission_does_not_enable_unimplemented_compression_ids() {
    let mut physical = vec![0; 512];
    physical[..FIXED.len()].copy_from_slice(&FIXED);
    for codec in [0, 1, 4, 17, 127] {
        assert!(decompress(&FIXED, codec, LOGICAL).is_err());
        let bp = physical_pointer(&physical, codec, Endian::Little, Endian::Little);
        assert!(bp.regular_dvas().is_err());
        assert!(bp.decode(&physical).is_err());
        let embedded = embedded_pointer(&FIXED, LOGICAL, codec, Endian::Little, Endian::Little);
        assert!(embedded.decode(&[]).is_err());
    }
}
