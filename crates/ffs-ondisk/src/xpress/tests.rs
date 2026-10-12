use super::*;

// Published MS-XCA 3.2 byte vectors, retaining its sparse code-length table.
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/f59ff967-3032-4331-b108-0d2b4c09ee27
fn alphabet() -> Vec<u8> {
    let mut bytes = vec![0; 256];
    bytes[48] = 0x50;
    bytes[49..59].fill(0x55);
    bytes[59..62].copy_from_slice(&[0x45, 0x44, 0x04]);
    bytes[128] = 0x04;
    bytes.extend_from_slice(&[
        0xD8, 0x52, 0x3E, 0xD7, 0x94, 0x11, 0x5B, 0xE9, 0x19, 0x5F, 0xF9, 0xD6, 0x7C, 0xDF, 0x8D,
        0x04, 0, 0, 0, 0,
    ]);
    bytes
}

fn repeated_abc() -> Vec<u8> {
    let mut bytes = vec![0; 256];
    bytes[48] = 0x30;
    bytes[49] = 0x23;
    bytes[128] = 0x02;
    bytes[143] = 0x20;
    bytes.extend_from_slice(&[0xA8, 0xDC, 0, 0, 0xFF, 0x26, 0x01]);
    bytes
}

fn repeated_a(length: usize) -> Vec<u8> {
    // Two one-bit codes: literal A = 0 and (distance 1, long match) = 1.
    // The first little-endian word is 0100...; the second is lookahead.
    let mut bytes = vec![0; 256];
    bytes[32] = 0x10;
    bytes[135] = 0x10;
    bytes.extend_from_slice(&[0, 0x40, 0, 0]);
    let encoded_length = length - 4;
    if encoded_length < 270 {
        bytes.push(u8::try_from(encoded_length - 15).unwrap());
    } else {
        bytes.push(0xFF);
        bytes.extend_from_slice(&u16::try_from(encoded_length).unwrap().to_le_bytes());
    }
    bytes
}

#[test]
fn microsoft_published_literals_and_overlapping_long_match() {
    let literal = alphabet();
    let match_bytes = repeated_abc();
    let literal_before = literal.clone();
    let match_before = match_bytes.clone();
    assert_eq!(
        decompress_chunk(&literal, 26).unwrap(),
        b"abcdefghijklmnopqrstuvwxyz",
    );
    assert_eq!(
        decompress_chunk(&match_bytes, 300).unwrap(),
        b"abc".repeat(100),
    );
    assert_eq!(literal, literal_before);
    assert_eq!(match_bytes, match_before);
}

#[test]
fn native_byte_and_word_length_extensions_cover_wof_chunk_sizes() {
    for size in [19, 20, 273, 274, 4096, 8192, 16_384, 65_536] {
        assert_eq!(
            decompress_chunk(&repeated_a(size), size).unwrap(),
            vec![b'A'; size],
            "length {size}",
        );
    }
    // A 16-bit extended length smaller than 15 is explicitly invalid.
    let mut malformed = repeated_a(4096);
    malformed[261..263].copy_from_slice(&14_u16.to_le_bytes());
    assert!(decompress_chunk(&malformed, 4096).is_err());
}

#[test]
fn complete_canonical_trees_are_required_before_payload_decoding() {
    let mut bytes = vec![0; 260];
    assert!(decompress_chunk(&bytes, 1).is_err());
    bytes[0] = 0x01; // One one-bit code leaves half the tree undefined.
    assert!(decompress_chunk(&bytes, 1).is_err());
    bytes[0] = 0x11;
    bytes[1] = 0x01; // Three one-bit codes overfill the tree.
    assert!(decompress_chunk(&bytes, 1).is_err());
    bytes[1] = 0;
    assert_eq!(decompress_chunk(&bytes, 1).unwrap(), [0]);
}

#[test]
fn truncation_and_chunk_limits_never_return_partial_success() {
    let bytes = repeated_abc();
    for end in 0..bytes.len() {
        assert!(
            decompress_chunk(&bytes[..end], 300).is_err(),
            "length {end}"
        );
    }
    assert!(decompress_chunk(&bytes, 0).is_err());
    assert!(decompress_chunk(&bytes, MAX_OUTPUT_BYTES + 1).is_err());
    assert!(decompress_chunk(&vec![0; MAX_INPUT_BYTES + 1], 1).is_err());
    assert!(decompress_chunk(&bytes, 299).is_err());
    assert!(decompress_chunk(&repeated_a(4096), 4095).is_err());
}

#[test]
fn references_cannot_cross_a_chunk_or_its_expected_end() {
    let mut bytes = repeated_abc();
    // Canonical code 10 names the match; there are no preceding literals.
    bytes[256..260].copy_from_slice(&[0, 0x80, 0, 0]);
    assert!(decompress_chunk(&bytes, 300).is_err());

    // Successful earlier decoding must not create a cross-call dictionary.
    assert_eq!(
        decompress_chunk(&repeated_a(4096), 4096).unwrap().len(),
        4096
    );
    assert!(decompress_chunk(&bytes, 300).is_err());
    assert!(decompress_chunk(&repeated_abc(), 2).is_ok());
    assert!(decompress_chunk(&repeated_abc(), 4).is_err());
}

#[test]
fn uniform_nine_bit_codes_cover_distance_splits_and_word_refills() {
    for prefix in [1_usize, 2, 3, 15, 16, 17, 31, 32, 255, 256, 4095, 4096] {
        // A complete nine-bit canonical table makes each code equal its
        // symbol number. Pack literals followed by one length-three match
        // pointing at the first byte of the prefix; no sideband lengths.
        let literals: Vec<_> = (0..prefix).map(|at| (at % 251) as u8).collect();
        let distance_bits = usize::BITS - 1 - prefix.leading_zeros();
        let symbol = 256 + 16 * distance_bits;
        let mut bits = Vec::new();
        for value in literals
            .iter()
            .map(|value| u32::from(*value))
            .chain([symbol])
        {
            for shift in (0..9).rev() {
                bits.push((value >> shift) & 1);
            }
        }
        let suffix = prefix as u32 - (1 << distance_bits);
        for shift in (0..distance_bits).rev() {
            bits.push((suffix >> shift) & 1);
        }
        // Native lookahead words are present even after the last useful bit.
        bits.resize((bits.len() + 32).next_multiple_of(16), 0);
        let mut bytes = vec![0x99; 256];
        for word in bits.as_chunks::<16>().0 {
            let value = word
                .iter()
                .fold(0_u16, |value, bit| (value << 1) | *bit as u16);
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        let mut expected = literals;
        for at in 0..3 {
            expected.push(expected[at]);
        }
        assert_eq!(
            decompress_chunk(&bytes, prefix + 3).unwrap(),
            expected,
            "distance {prefix}",
        );
    }
}
