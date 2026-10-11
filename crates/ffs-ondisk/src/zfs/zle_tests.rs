//! Fixed native ZLE streams, not a native pool/interchange result.
//! Reference: OpenZFS zfs-2.3.0 zle.c and zio_compress.c (parameter 64).

use super::{BlockPointer, Endian, MAX_BLOCK_BYTES, checksum, decompress};

// Three literals, five 192-byte zero runs, sixty zeroes, and one final literal.
// The literal group deliberately includes a zero byte.
const PACKED: [u8; 12] = [2, b'A', 0, b'B', 255, 255, 255, 255, 255, 123, 0, b'Z'];
const LOGICAL: usize = 1024;

fn expected() -> Vec<u8> {
    let mut bytes = vec![0; LOGICAL];
    bytes[..3].copy_from_slice(&[b'A', 0, b'B']);
    bytes[LOGICAL - 1] = b'Z';
    bytes
}

fn pointer(words: [u64; 16], containing: Endian) -> BlockPointer {
    let raw: Vec<u8> = words
        .into_iter()
        .flat_map(|word| containing.encode(word))
        .collect();
    BlockPointer::parse(&raw, containing).unwrap()
}

fn physical_pointer(physical: &[u8], containing: Endian, payload: Endian) -> BlockPointer {
    assert_eq!(physical.len(), 512);
    let mut words = [0_u64; 16];
    words[0] = 1; // One allocated sector.
    words[1] = 8;
    words[6] = 1 // Two logical sectors, one physical sector.
        | (14 << 32)
        | (7 << 40)
        | (19 << 48)
        | (u64::from(payload == Endian::Little) << 63);
    words[10] = 42;
    words[12..].copy_from_slice(&checksum(physical, 7, payload).unwrap());
    pointer(words, containing)
}

fn embedded_pointer(
    logical: usize,
    packed: usize,
    containing: Endian,
    payload: Endian,
) -> BlockPointer {
    assert!((1..=PACKED.len()).contains(&packed));
    let mut words = [0_u64; 16];
    // Fixed numeric words preserve the native payload packing independently
    // of the metadata and logical payload byte orders.
    words[0] = 0xffff_ffff_4200_4102;
    words[1] = 0x0000_0000_5a00_7bff;
    words[6] = (logical as u64 - 1)
        | ((packed as u64 - 1) << 25)
        | (14 << 32)
        | (1 << 39)
        | (19 << 48)
        | (u64::from(payload == Endian::Little) << 63);
    words[10] = 42;
    pointer(words, containing)
}

#[test]
fn zle_native_literal_and_zero_token_ranges_are_distinct() {
    for token in 0..=63_u8 {
        let literal: Vec<u8> = (0..=token).collect();
        let mut packed = vec![token];
        packed.extend_from_slice(&literal);
        assert_eq!(decompress(&packed, 14, literal.len()).unwrap(), literal);
    }
    for token in 64..=255_u8 {
        let length = usize::from(token) - 63;
        assert_eq!(decompress(&[token], 14, length).unwrap(), vec![0; length]);
    }
    assert_eq!(decompress(&PACKED, 14, LOGICAL).unwrap(), expected());
}

#[test]
fn zle_requires_complete_runs_within_the_declared_output_budget() {
    for end in 0..PACKED.len() {
        assert!(decompress(&PACKED[..end], 14, LOGICAL).is_err(), "{end}");
    }
    assert!(decompress(&[1, b'A', b'B'], 14, 1).is_err()); // Literal overrun.
    assert!(decompress(&[65], 14, 1).is_err()); // Two zeroes cannot fit.
    assert!(decompress(&[63, b'A'], 14, 64).is_err()); // Truncated literals.
    assert!(decompress(&PACKED, 14, LOGICAL - 2).is_err());
    assert!(decompress(&PACKED, 14, LOGICAL + 1).is_err());
    assert!(decompress(&PACKED, 14, 0).is_err());
    assert!(decompress(&PACKED, 14, MAX_BLOCK_BYTES + 1).is_err());
}

#[test]
fn zle_physical_dispatch_checks_padding_before_decoding_in_both_orders() {
    for containing in [Endian::Little, Endian::Big] {
        for payload in [Endian::Little, Endian::Big] {
            let mut physical = vec![0; 512];
            physical[..PACKED.len()].copy_from_slice(&PACKED);
            let bp = physical_pointer(&physical, containing, payload);
            assert_eq!(bp.regular_dvas().unwrap().len(), 1);
            assert_eq!((bp.logical_bytes(), bp.physical_bytes()), (LOGICAL, 512));
            assert_eq!(bp.decode(&physical).unwrap(), expected());
            assert!(bp.decode(&physical[..511]).is_err());

            // The native decoder stops at logical block end. Unconsumed
            // padding still participates in the physical block checksum.
            physical[511] = 63;
            assert_eq!(decompress(&physical, 14, LOGICAL).unwrap(), expected());
            assert!(bp.decode(&physical).is_err());
            let updated = physical_pointer(&physical, containing, payload);
            assert_eq!(updated.decode(&physical).unwrap(), expected());
        }
    }
}

#[test]
fn zle_bad_physical_streams_fail_after_valid_checksum_verification() {
    for containing in [Endian::Little, Endian::Big] {
        for payload in [Endian::Little, Endian::Big] {
            for token in [0_u8, 255] {
                // Zero tokens run out of source; 255 tokens overrun output.
                let physical = vec![token; 512];
                let bp = physical_pointer(&physical, containing, payload);
                assert!(bp.regular_dvas().is_ok());
                assert!(bp.decode(&physical).is_err());
            }
        }
    }
}

#[test]
fn zle_embedded_dispatch_uses_fixed_payload_words_without_a_physical_block() {
    for containing in [Endian::Little, Endian::Big] {
        for payload in [Endian::Little, Endian::Big] {
            let bp = embedded_pointer(LOGICAL, PACKED.len(), containing, payload);
            assert_eq!(bp.payload_order(), payload);
            assert_eq!(bp.physical_bytes(), 0);
            assert_eq!(bp.checksum_type(), 2);
            assert!(!bp.hole());
            assert!(bp.regular_dvas().is_err());
            assert_eq!(bp.decode_embedded().unwrap(), expected());
            assert_eq!(bp.decode(&[]).unwrap(), expected());
            assert!(bp.decode(&PACKED).is_err());
        }
    }
}

#[test]
fn zle_embedded_truncation_and_output_mismatches_are_errors() {
    for containing in [Endian::Little, Endian::Big] {
        for payload in [Endian::Little, Endian::Big] {
            for packed in 1..PACKED.len() {
                let bp = embedded_pointer(LOGICAL, packed, containing, payload);
                assert!(bp.decode_embedded().is_err(), "{packed}");
            }
            for logical in [LOGICAL - 2, LOGICAL + 1] {
                let bp = embedded_pointer(logical, PACKED.len(), containing, payload);
                assert!(bp.decode(&[]).is_err(), "{logical}");
            }
        }
    }
}
