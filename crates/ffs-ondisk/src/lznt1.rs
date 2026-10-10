//! Bounded LZNT1 decoding for native NTFS compression units.
//!
//! Format: Microsoft [MS-XCA] section 2.5, especially buffers/chunks and
//! compressed words. This is a byte-slice decoder, not a filesystem driver.
//! Each chunk has an independent 4 KiB dictionary; a short intermediate chunk
//! is zero-padded to its next 4 KiB boundary. No missing final output is invented.

use ffs_types::ParseError;

const CHUNK_BYTES: usize = 4096;
/// Largest ordinary NTFS compression unit admitted by this decoder.
pub const MAX_UNIT_BYTES: usize = 65_536;
const MAX_INPUT_BYTES: usize = MAX_UNIT_BYTES + 2 * (MAX_UNIT_BYTES / CHUNK_BYTES) + 2;

fn invalid(reason: &'static str) -> ParseError {
    ParseError::InvalidField {
        field: "ntfs.lznt1",
        reason,
    }
}

/// Decode one physical compression-unit payload, including allocation padding.
///
/// `unit_bytes` is a trusted geometry-derived bound, not a size from a chunk
/// header. Output stops at that bound, an end marker, or the end of the input.
/// Bytes after a complete unit or an end marker are allocation slack, not another
/// unit. A lone trailing allocation byte cannot be a header and is ignored.
/// The caller MUST check the returned length against the unit's initialized
/// logical length: a short decode is not implicit zero-fill to EOF.
///
/// Malformed headers/tokens, cross-chunk references and output overruns fail
/// without returning partial bytes. Work and memory are bounded independently
/// of the file size. The input is never modified.
pub fn decompress_unit(input: &[u8], unit_bytes: usize) -> Result<Vec<u8>, ParseError> {
    if unit_bytes == 0 || unit_bytes > MAX_UNIT_BYTES {
        return Err(invalid("invalid decompression output bound"));
    }
    if input.len() < 2 || input.len() > MAX_INPUT_BYTES {
        return Err(invalid("invalid compressed input length"));
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(unit_bytes)
        .map_err(|_| invalid("cannot allocate bounded decompression buffer"))?;
    let mut at = 0;
    while at + 2 <= input.len() && output.len() < unit_bytes {
        let header = u16::from_le_bytes([input[at], input[at + 1]]);
        if header == 0 {
            break;
        }
        if header & 0x7000 != 0x3000 {
            return Err(invalid("invalid chunk signature"));
        }
        let size = usize::from(header & 0x0FFF) + 1;
        at += 2;
        let end = at + size;
        let chunk = input
            .get(at..end)
            .ok_or_else(|| invalid("truncated chunk payload"))?;
        // Padding is only implied by the presence of another real chunk, not
        // by the end marker or by the end of allocated input.
        let start = output.len().next_multiple_of(CHUNK_BYTES);
        if start >= unit_bytes {
            return Err(invalid("chunk starts outside output bound"));
        }
        output.resize(start, 0);
        let limit = (start + CHUNK_BYTES).min(unit_bytes);
        if header & 0x8000 == 0 {
            if chunk.len() > limit - start {
                return Err(invalid("raw chunk exceeds output bound"));
            }
            output.extend_from_slice(chunk);
        } else {
            decode_chunk(chunk, &mut output, start, limit)?;
        }
        at = end;
    }
    Ok(output)
}

fn decode_chunk(
    chunk: &[u8],
    output: &mut Vec<u8>,
    start: usize,
    limit: usize,
) -> Result<(), ParseError> {
    let mut at = 0;
    while at < chunk.len() {
        let flags = chunk[at];
        at += 1;
        if at == chunk.len() {
            return Err(invalid("flag group has no token"));
        }
        for bit in 0..8 {
            if at == chunk.len() {
                break; // Unused bits of the final flag byte are not tokens.
            }
            if flags & (1 << bit) == 0 {
                if output.len() == limit {
                    return Err(invalid("literal exceeds chunk output bound"));
                }
                output.push(chunk[at]);
                at += 1;
            } else {
                let pair = chunk
                    .get(at..at + 2)
                    .ok_or_else(|| invalid("truncated compressed word"))?;
                let word = usize::from(u16::from_le_bytes([pair[0], pair[1]]));
                at += 2;
                let produced = output.len() - start;
                let mut length_bits = 12;
                // At exactly 16 produced bytes a four-bit displacement can
                // still address the whole dictionary. The split changes at 17.
                let mut threshold = 16;
                while produced > threshold {
                    length_bits -= 1;
                    threshold *= 2;
                }
                let distance = (word >> length_bits) + 1;
                let length = (word & ((1 << length_bits) - 1)) + 3;
                if distance > produced {
                    return Err(invalid("compressed word references before this chunk"));
                }
                if length > limit - output.len() {
                    return Err(invalid("compressed word exceeds chunk output bound"));
                }
                // Deliberately forward-copy: LZ matches may read bytes emitted
                // earlier by this very match (distance can be less than length).
                for _ in 0..length {
                    output.push(output[output.len() - distance]);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(bytes: &[u8]) -> Vec<u8> {
        assert!(!bytes.is_empty() && bytes.len() <= CHUNK_BYTES);
        let mut result = (0x3000_u16 | u16::try_from(bytes.len() - 1).unwrap())
            .to_le_bytes()
            .to_vec();
        result.extend_from_slice(bytes);
        result
    }

    #[test]
    fn raw_chunks_short_chunks_and_end_markers() {
        assert_eq!(decompress_unit(&raw(b"abc"), 4096).unwrap(), b"abc");
        let mut input = raw(b"abc");
        input.extend_from_slice(&[0, 0, 0xFF, 0xFF]);
        assert_eq!(decompress_unit(&input, 4096).unwrap(), b"abc");
        let mut input = raw(b"abc");
        input.extend_from_slice(&raw(b"def"));
        let decoded = decompress_unit(&input, 8192).unwrap();
        assert_eq!(decoded.len(), 4099);
        assert_eq!(&decoded[..3], b"abc");
        assert!(decoded[3..4096].iter().all(|byte| *byte == 0));
        assert_eq!(&decoded[4096..], b"def");
        assert!(decompress_unit(&input, 4096).is_err());
    }

    #[test]
    fn overlapping_matches_and_independent_chunk_dictionaries() {
        let repeated = [0x03, 0xB0, 0x02, b'A', 0xFC, 0x0F];
        assert_eq!(decompress_unit(&repeated, 4096).unwrap(), vec![b'A'; 4096]);
        let mut two = repeated.to_vec();
        two.extend_from_slice(&[0x03, 0xB0, 0x02, b'B', 0xFC, 0x0F]);
        let decoded = decompress_unit(&two, 8192).unwrap();
        assert_eq!(&decoded[..4096], &[b'A'; 4096]);
        assert_eq!(&decoded[4096..], &[b'B'; 4096]);
        let mut bad = repeated.to_vec();
        bad.extend_from_slice(&[0x02, 0xB0, 0x01, 0, 0]);
        assert!(decompress_unit(&bad, 8192).is_err());
    }

    #[test]
    fn displacement_width_changes_after_powers_of_two() {
        // Literal-prefix lengths and independently specified words copying the
        // first three bytes. These catch the <= / < boundary in the split rule.
        for (length, word) in [
            (16, 0xF000_u16), (17, 0x8000), (32, 0xF800), (33, 0x8000),
            (256, 0xFF00), (257, 0x8000), (2048, 0xFFE0), (2049, 0x8000),
        ] {
            let prefix: Vec<_> = (0..length).map(|i| u8::try_from(i % 251).unwrap()).collect();
            let mut payload = Vec::new();
            for group in prefix.chunks_exact(8) {
                payload.push(0);
                payload.extend_from_slice(group);
            }
            let remainder = prefix.chunks_exact(8).remainder();
            payload.push(1 << remainder.len());
            payload.extend_from_slice(remainder);
            payload.extend_from_slice(&word.to_le_bytes());
            let mut encoded = (0xB000_u16 | u16::try_from(payload.len() - 1).unwrap())
                .to_le_bytes().to_vec();
            encoded.extend_from_slice(&payload);
            let mut expected = prefix.clone();
            expected.extend_from_slice(&prefix[..3]);
            assert_eq!(decompress_unit(&encoded, 4096).unwrap(), expected, "{length}");
        }
        // Reach dictionary position 4093 using one overlapping match, then
        // copy three bytes at distance 4093 with the four-bit length field.
        let last = [5, 0xB0, 6, b'A', 0xF9, 0x0F, 0xC0, 0xFF];
        assert_eq!(decompress_unit(&last, 4096).unwrap(), vec![b'A'; 4096]);
    }

    #[test]
    fn malformed_streams_never_return_partial_output() {
        for input in [
            vec![], vec![0], vec![0x02, 0x30, b'A'],
            vec![0x00, 0x20, b'A'], vec![0x00, 0xB0, 0],
            vec![0x01, 0xB0, 1, 0], vec![0x02, 0xB0, 1, 0, 0],
            vec![0x03, 0xB0, 2, b'A', 0, 0x10],
            vec![0x03, 0xB0, 2, b'A', 0xFF, 0x0F],
        ] {
            assert!(decompress_unit(&input, 4096).is_err(), "{input:x?}");
        }
        let source = [0x03, 0xB0, 2, b'A', 0xFC, 0x0F];
        assert!(decompress_unit(&source, 4095).is_err());
        assert!(decompress_unit(&source, 0).is_err());
        assert!(decompress_unit(&source, MAX_UNIT_BYTES + 1).is_err());
        assert!(decompress_unit(&vec![0; MAX_INPUT_BYTES + 1], 4096).is_err());
    }

    #[test]
    fn final_flags_and_allocation_slack_are_not_extra_data() {
        let literal = [3, 0xB0, 0x80, b'a', b'b', b'c'];
        assert_eq!(decompress_unit(&literal, 4096).unwrap(), b"abc");
        let mut full = [3, 0xB0, 2, b'A', 0xFC, 0x0F].to_vec();
        full.extend_from_slice(&[0xFF; 128]);
        assert_eq!(decompress_unit(&full, 4096).unwrap(), vec![b'A'; 4096]);
        let mut partial = raw(b"abc");
        partial.push(0xFF); // No complete following header fits this allocation.
        assert_eq!(decompress_unit(&partial, 4096).unwrap(), b"abc");
    }
}
