//! Native Zstandard framing fixtures, independent of this crate's encoder.
//! Reference bytes are published by Go go1.24.0 internal/zstd/zstd_test.go
//! ("hello" and "fuzz1") and Zstandard v1.5.7 tests/golden-decompression
//! (zeroSeq_2B.zst and rle-first-block.zst). Only their four-byte standard
//! magic is omitted below; native OpenZFS supplies its own eight-byte wrapper.
//! Parser fixtures are not native pool/interchange execution evidence.

use super::{BlockPointer, Endian, MAX_BLOCK_BYTES, checksum, decompress};
use ffs_types::ParseError;

const LOGICAL: usize = 1024;
const META: [u8; 4] = [3, 0, 0x28, 0xa5]; // Native level 3, producer 1.4.5.

// The 22-byte "fuzz1" output: three sequences with LL=2, ML=4,
// distance-one repeat offsets, then four final literals.
const PREFIX: [u8; 22] = [
    b'0', 0, 0, 0, 0, 0, b'0', 0, 0, 0, 0, 0, b'1', 0, 0, 0, 0, 0, b'0', b'0', b'0', b'0',
];
const SEQUENCES: [u8; 26] = [
    0x04, 0x58, 0x8d, 0x00, 0x00, 0x50, 0x30, 0x00, 0x30, 0x00, 0x31, 0x00, 0x30, 0x30, 0x30,
    0x30, 0x03, 0x54, 0x02, 0x00, 0x01, 0x01, 0x6d, 0xf9, 0xb7, 0x47,
];

// A native-style frame made from the same independently published sequence
// block: disable its content checksum, clear the block's last flag, and append
// a final RLE block with 1,002 A bytes (LE24 header = (1002 << 3) | 3).
const MIXED: [u8; 26] = [
    0x00, 0x58, 0x8c, 0x00, 0x00, 0x50, 0x30, 0x00, 0x30, 0x00, 0x31, 0x00, 0x30, 0x30, 0x30,
    0x30, 0x03, 0x54, 0x02, 0x00, 0x01, 0x01, 0x53, 0x1f, 0x00, b'A',
];

// Go's "hello": one raw block, single-segment content size and XXH64 trailer.
const RAW: [u8; 22] = [
    0x24, 0x0d, 0x69, 0x00, 0x00, b'h', b'e', b'l', b'l', b'o', b',', b' ', b'w', b'o', b'r',
    b'l', b'd', 0x0a, 0x4c, 0x1f, 0xf9, 0xf1,
];

// Compressed block containing 13 raw literals and a two-byte zero-sequence count.
const LITERALS: [u8; 21] = [
    0x00, 0x00, 0x85, 0x00, 0x00, 0x68, b'H', b'e', b'l', b'l', b'o', b' ', b'W', b'o', b'r',
    b'l', b'd', b'!', 0x0a, 0x80, 0x00,
];

// Upstream golden frame: eight 128-KiB RLE blocks yield 1 MiB of zeroes,
// with a four-byte content size and a verified content checksum.
const RLE: [u8; 41] = [
    0xa4, 0x00, 0x00, 0x10, 0x00,
    0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x00,
    0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x00,
    0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x00,
    0x02, 0x00, 0x10, 0x00, 0x03, 0x00, 0x10, 0x00,
    0xf1, 0x3e, 0x16, 0xe1,
];

fn expected() -> Vec<u8> {
    let mut bytes = PREFIX.to_vec();
    bytes.resize(LOGICAL, b'A');
    bytes
}

fn native(payload: &[u8], metadata: [u8; 4]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&metadata);
    bytes.extend_from_slice(payload);
    bytes
}

fn metadata_layouts(level: u8) -> [[u8; 4]; 4] {
    // The canonical LE and historical BE examples in OpenZFS zfs-2.3.0
    // include/sys/zstd/zstd.h, plus its other two explicit getter cases.
    [
        [level, 0xa5, 0x28, 0],
        [0xa5, 0x28, 0, level],
        [level, 0, 0x28, 0xa5],
        [0, 0x28, 0xa5, level],
    ]
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
    logical: usize,
    algorithm: u8,
    containing: Endian,
    payload: Endian,
) -> BlockPointer {
    assert_eq!(physical.len(), 512);
    assert!(logical.is_multiple_of(512));
    let mut words = [0_u64; 16];
    words[0] = 1;
    words[1] = 8;
    words[6] = (logical as u64 / 512 - 1)
        | (16 << 32)
        | (u64::from(algorithm) << 40)
        | (19 << 48)
        | (u64::from(payload == Endian::Little) << 63);
    words[10] = 42;
    words[12..].copy_from_slice(&checksum(physical, algorithm, payload).unwrap());
    pointer(words, containing)
}

fn embedded_pointer(
    packed: &[u8],
    logical: usize,
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
        | (16 << 32)
        | (1 << 39)
        | (19 << 48)
        | (u64::from(payload == Endian::Little) << 63);
    words[10] = 42;
    pointer(words, containing)
}

#[test]
fn zstd_published_vectors_cover_raw_compressed_sequences_and_multiblock_rle() {
    for (payload, bytes) in [
        (RAW.as_slice(), b"hello, world\n".to_vec()),
        (SEQUENCES.as_slice(), PREFIX.to_vec()),
        (LITERALS.as_slice(), b"Hello World!\n".to_vec()),
        (RLE.as_slice(), vec![0; 1024 * 1024]),
        (MIXED.as_slice(), expected()),
    ] {
        assert_eq!(decompress(&native(payload, META), 16, bytes.len()).unwrap(), bytes);
    }
}

#[test]
fn zstd_all_native_levels_and_four_historical_header_layouts_are_admitted() {
    for level in (1_u8..=19).chain(103..=123) {
        for metadata in metadata_layouts(level) {
            assert_eq!(decompress(&native(&MIXED, metadata), 16, LOGICAL).unwrap(), expected());
        }
    }
    for level in 0_u8..=255 {
        if !matches!(level, 1..=19 | 103..=123) {
            assert!(decompress(&native(&MIXED, [level, 0, 0x28, 0xa5]), 16, LOGICAL).is_err());
        }
    }
    // No producer-version cutoff: native readers treat this as information.
    for metadata in [[3, 0, 0x12, 0x34], [3, 0, 0xfe, 0xff]] {
        assert_eq!(decompress(&native(&MIXED, metadata), 16, LOGICAL).unwrap(), expected());
    }
    for metadata in [
        [0, 0, 0, 0],
        [3, 1, 0x28, 0xa5], // No zero byte, so no native layout is identified.
        [3, 0, 0, 0xa5], // First zero from the low end selects invalid level 0xa5.
    ] {
        assert!(decompress(&native(&MIXED, metadata), 16, LOGICAL).is_err());
    }
}

#[test]
fn zstd_requires_complete_native_length_frame_and_exact_logical_size() {
    for (payload, length) in [
        (RAW.as_slice(), 13),
        (SEQUENCES.as_slice(), PREFIX.len()),
        (LITERALS.as_slice(), 13),
        (RLE.as_slice(), 1024 * 1024),
        (MIXED.as_slice(), LOGICAL),
    ] {
        let packed = native(payload, META);
        for end in 0..packed.len() {
            assert!(decompress(&packed[..end], 16, length).is_err(), "{end}");
        }
        // Also truncate the frame while keeping the wrapper length consistent.
        for end in 0..payload.len() {
            assert!(decompress(&native(&payload[..end], META), 16, length).is_err(), "{end}");
        }
        assert!(decompress(&packed, 16, length - 1).is_err());
        assert!(decompress(&packed, 16, length + 1).is_err());
    }
    for length in [0_u32, 1, 25, 27, 34, u32::MAX] {
        let mut packed = native(&MIXED, META);
        packed[..4].copy_from_slice(&length.to_be_bytes());
        assert!(decompress(&packed, 16, LOGICAL).is_err());
    }
    let mut wrong_order = native(&MIXED, META);
    wrong_order[..4].copy_from_slice(&(MIXED.len() as u32).to_le_bytes());
    assert!(decompress(&wrong_order, 16, LOGICAL).is_err());
    assert!(decompress(&native(&MIXED, META), 16, 0).is_err());
    assert!(decompress(&native(&MIXED, META), 16, MAX_BLOCK_BYTES + 1).is_err());
    assert!(decompress(&vec![0; MAX_BLOCK_BYTES + 1], 16, LOGICAL).is_err());
}

#[test]
fn zstd_rejects_trailing_frames_inside_native_length_but_ignores_outer_padding() {
    let mut second_frame = vec![0x28, 0xb5, 0x2f, 0xfd];
    second_frame.extend_from_slice(&MIXED);
    for suffix in [&[0_u8][..], MIXED.as_slice(), second_frame.as_slice()] {
        let mut payload = MIXED.to_vec();
        payload.extend_from_slice(suffix);
        assert!(decompress(&native(&payload, META), 16, LOGICAL).is_err());
        assert!(decompress(&native(&payload, META), 16, 2 * LOGICAL).is_err());

        let mut padded = native(&MIXED, META);
        padded.extend_from_slice(suffix);
        assert_eq!(decompress(&padded, 16, LOGICAL).unwrap(), expected());
    }
}

#[test]
fn zstd_rejects_dictionary_requirements_wrong_framing_and_reserved_bits() {
    for (flag, width) in [(1, 1), (2, 2), (3, 4)] {
        for id in [0_u32, 7] {
            let mut payload = vec![flag, 0x58];
            payload.extend_from_slice(&id.to_le_bytes()[..width]);
            payload.extend_from_slice(&MIXED[2..]);
            let result = decompress(&native(&payload, META), 16, LOGICAL);
            if id == 0 {
                assert_eq!(result.unwrap(), expected());
            } else {
                assert!(result.is_err());
            }
        }
    }
    let mut standard = vec![0x28, 0xb5, 0x2f, 0xfd];
    standard.extend_from_slice(&MIXED);
    assert!(decompress(&native(&standard, META), 16, LOGICAL).is_err());
    for payload in [
        &[0x78, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01][..],
        &[0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0][..], // Skippable standard frame.
        &[0, 0, 1, 0, 0][..], // A complete empty raw frame cannot yield LSIZE.
    ] {
        assert!(decompress(&native(payload, META), 16, LOGICAL).is_err());
    }
    let mut reserved = MIXED;
    reserved[0] |= 0x08;
    assert!(decompress(&native(&reserved, META), 16, LOGICAL).is_err());
    reserved = MIXED;
    reserved[2] = (reserved[2] & !6) | 6; // Reserved block type.
    assert!(decompress(&native(&reserved, META), 16, LOGICAL).is_err());
    reserved = MIXED;
    reserved[21] = 0; // Missing compressed-sequence bitstream end marker.
    assert!(decompress(&native(&reserved, META), 16, LOGICAL).is_err());

    // The format requires decoders to ignore the unused FHD bit (bit 4).
    let mut unused = MIXED;
    unused[0] |= 0x10;
    assert_eq!(decompress(&native(&unused, META), 16, LOGICAL).unwrap(), expected());
}

#[test]
fn zstd_advertised_window_is_bounded_before_context_or_output_expansion() {
    for descriptor in [0, 0x6f, 0x70] { // 1 KiB, 15 MiB, exactly 16 MiB.
        let mut payload = MIXED;
        payload[1] = descriptor;
        assert_eq!(decompress(&native(&payload, META), 16, LOGICAL).unwrap(), expected());
    }
    for descriptor in [0x71, 0x78, 0xf8, 0xff] {
        let mut payload = MIXED;
        payload[1] = descriptor;
        assert!(matches!(
            decompress(&native(&payload, META), 16, LOGICAL),
            Err(ParseError::InvalidField {
                field: "zfs",
                reason: "Zstandard window exceeds read budget",
            })
        ));
    }
    // Single-segment windows equal content size, including 64-bit FCS values.
    for (descriptor, size, width) in [
        (0xa0, MAX_BLOCK_BYTES as u64 + 1, 4),
        (0xe0, 1_u64 << 40, 8),
    ] {
        let mut payload = vec![descriptor];
        payload.extend_from_slice(&size.to_le_bytes()[..width]);
        payload.extend_from_slice(&MIXED[2..]);
        assert!(matches!(
            decompress(&native(&payload, META), 16, LOGICAL),
            Err(ParseError::InvalidField {
                field: "zfs",
                reason: "Zstandard window exceeds read budget",
            })
        ));
    }
}

#[test]
fn zstd_content_size_encodings_must_match_lsize_in_single_or_multiple_segments() {
    for logical in [LOGICAL - 1, LOGICAL, LOGICAL + 1] {
        for (descriptor, width) in [(0x60, 2), (0xa0, 4), (0xe0, 8)] {
            let size = if width == 2 { logical - 256 } else { logical };
            let mut payload = vec![descriptor];
            payload.extend_from_slice(&(size as u64).to_le_bytes()[..width]);
            payload.extend_from_slice(&MIXED[2..]);
            let result = decompress(&native(&payload, META), 16, LOGICAL);
            if logical == LOGICAL {
                assert_eq!(result.unwrap(), expected());
            } else {
                assert!(result.is_err());
            }
        }
    }
    let mut multiple = vec![0x80, 0x58];
    multiple.extend_from_slice(&(LOGICAL as u32).to_le_bytes());
    multiple.extend_from_slice(&MIXED[2..]);
    assert_eq!(decompress(&native(&multiple, META), 16, LOGICAL).unwrap(), expected());
}

#[test]
fn zstd_physical_blocks_verify_all_psize_bytes_in_both_byte_orders() {
    let packed = native(&MIXED, META);
    for algorithm in [6, 7, 8, 11] {
        for containing in [Endian::Little, Endian::Big] {
            for payload in [Endian::Little, Endian::Big] {
                let mut physical = vec![0; 512];
                physical[..packed.len()].copy_from_slice(&packed);
                let bp = physical_pointer(&physical, LOGICAL, algorithm, containing, payload);
                assert_eq!(bp.regular_dvas().unwrap().len(), 1);
                assert_eq!(bp.decode(&physical).unwrap(), expected());
                assert!(bp.decode(&physical[..511]).is_err());

                physical[511] = 0xa5;
                assert_eq!(decompress(&physical, 16, LOGICAL).unwrap(), expected());
                assert!(bp.decode(&physical).is_err());
                let updated = physical_pointer(&physical, LOGICAL, algorithm, containing, payload);
                assert_eq!(updated.decode(&physical).unwrap(), expected());

                for sector_count in [0, 2] {
                    let mut wrong_size = updated.clone();
                    wrong_size.words[6] = (wrong_size.words[6] & !0xffff) | sector_count;
                    assert!(wrong_size.decode(&physical).is_err());
                }
                let mut unsupported = updated.clone();
                unsupported.words[6] = (unsupported.words[6] & !(0x7f << 32)) | (17 << 32);
                assert!(unsupported.regular_dvas().is_err());
                assert!(unsupported.decode(&physical).is_err());

                physical[0] = 0xff; // A valid outer checksum cannot fix c_len.
                let damaged = physical_pointer(&physical, LOGICAL, algorithm, containing, payload);
                assert!(damaged.regular_dvas().is_ok());
                assert!(damaged.decode(&physical).is_err());
            }
        }
    }
}

#[test]
fn zstd_content_checksum_failure_is_fatal_even_with_a_valid_physical_checksum() {
    let packed = native(&RLE, META);
    let mut physical = vec![0; 512];
    physical[..packed.len()].copy_from_slice(&packed);
    let bp = physical_pointer(&physical, 1024 * 1024, 7, Endian::Little, Endian::Little);
    assert_eq!(bp.decode(&physical).unwrap(), vec![0; 1024 * 1024]);
    physical[packed.len() - 1] ^= 1;
    let damaged = physical_pointer(&physical, 1024 * 1024, 7, Endian::Little, Endian::Little);
    assert!(damaged.regular_dvas().is_ok());
    assert!(damaged.decode(&physical).is_err());
}

#[test]
fn zstd_embedded_blocks_decode_native_headers_independently_of_both_orders() {
    for metadata in metadata_layouts(3) {
        let packed = native(&MIXED, metadata);
        for containing in [Endian::Little, Endian::Big] {
            for payload in [Endian::Little, Endian::Big] {
                let bp = embedded_pointer(&packed, LOGICAL, containing, payload);
                assert_eq!(bp.compression(), 16);
                assert_eq!(bp.payload_order(), payload);
                assert_eq!(bp.physical_bytes(), 0);
                assert!(!bp.hole());
                assert!(bp.regular_dvas().is_err());
                assert_eq!(bp.decode_embedded().unwrap(), expected());
                assert_eq!(bp.decode(&[]).unwrap(), expected());
                assert!(bp.decode(&packed).is_err());

                let truncated =
                    embedded_pointer(&packed[..packed.len() - 1], LOGICAL, containing, payload);
                assert!(truncated.decode(&[]).is_err());
                let wrong_size = embedded_pointer(&packed, LOGICAL - 1, containing, payload);
                assert!(wrong_size.decode(&[]).is_err());
            }
        }
    }
    let packed = native(&RLE, META);
    let bp = embedded_pointer(&packed, 1024 * 1024, Endian::Big, Endian::Little);
    assert_eq!(bp.decode(&[]).unwrap(), vec![0; 1024 * 1024]);
}
