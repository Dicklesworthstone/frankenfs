//! Bounded XPRESS Huffman decoding for WOF file-provider chunks.
//!
//! Microsoft MS-XCA 2.2.4 specifies the canonical 512-symbol alphabet,
//! little-endian 16-bit input words, interleaved match lengths and forward
//! overlapping copies. Each call has an independent dictionary and a trusted
//! expected output size; it does not interpret WOF metadata or chunk offsets.
//!
//! https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/26db8e62-bbd8-472c-a09e-623f6de10f0b

use ffs_types::ParseError;

/// One native XPRESS Huffman block. WOF currently uses at most 16 KiB.
pub const MAX_OUTPUT_BYTES: usize = 65_536;
const TABLE_BYTES: usize = 256;
const TABLE_ENTRIES: usize = 1 << 15;
// Even a maximum-size all-literal block with 15-bit codes fits this bound.
const MAX_INPUT_BYTES: usize = TABLE_BYTES + 2 * MAX_OUTPUT_BYTES + 4;

fn invalid(reason: &'static str) -> ParseError {
    ParseError::InvalidField {
        field: "ntfs.xpress",
        reason,
    }
}

/// Reconstruct exactly expected_bytes from one XPRESS Huffman block.
///
/// No partial output is returned on a malformed code, truncated input,
/// dictionary underflow or output overrun. Native terminal/prefetch bits are
/// not additional file data once the caller's exact output length is complete.
/// The caller must bound and identify the physical chunk independently.
pub fn decompress_chunk(input: &[u8], expected_bytes: usize) -> Result<Vec<u8>, ParseError> {
    if expected_bytes == 0 || expected_bytes > MAX_OUTPUT_BYTES {
        return Err(invalid("invalid expected chunk length"));
    }
    if !(TABLE_BYTES + 4..=MAX_INPUT_BYTES).contains(&input.len()) {
        return Err(invalid(
            "compressed chunk length is outside the bounded profile",
        ));
    }
    let mut lengths = [0_u8; 512];
    for (pair, &byte) in lengths
        .as_chunks_mut::<2>()
        .0
        .iter_mut()
        .zip(&input[..TABLE_BYTES])
    {
        pair[0] = byte & 15;
        pair[1] = byte >> 4;
    }

    // A full canonical tree has exactly 32768 expanded entries. This checks
    // both oversubscribed and incomplete trees before any payload is decoded.
    let mut table = Vec::new();
    table
        .try_reserve_exact(TABLE_ENTRIES)
        .map_err(|_| invalid("cannot allocate bounded Huffman table"))?;
    for width in 1..=15 {
        let copies = 1_usize << (15 - width);
        for (symbol, &length) in lengths.iter().enumerate() {
            if length != width {
                continue;
            }
            let end = table.len() + copies;
            if end > TABLE_ENTRIES {
                return Err(invalid("oversubscribed Huffman code lengths"));
            }
            table.resize(end, symbol as u16);
        }
    }
    if table.len() != TABLE_ENTRIES {
        return Err(invalid("incomplete Huffman code lengths"));
    }

    let mut bits = InputBits::new(input)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(expected_bytes)
        .map_err(|_| invalid("cannot allocate bounded decoded chunk"))?;
    while output.len() < expected_bytes {
        let symbol = usize::from(table[(bits.next >> 17) as usize]);
        bits.take(lengths[symbol])?;
        if symbol < 256 {
            output.push(symbol as u8);
            continue;
        }

        let pair = symbol - 256;
        let distance_bits = (pair / 16) as u8;
        let mut length = pair % 16;
        if length == 15 {
            length = usize::from(bits.byte()?);
            if length == 255 {
                length = usize::from(bits.word()?);
                if length < 15 {
                    return Err(invalid("invalid extended match length"));
                }
            } else {
                length += 15;
            }
        }
        length += 3;
        let distance = (1_usize << distance_bits) + bits.take(distance_bits)? as usize;
        if distance > output.len() {
            return Err(invalid("match references before this chunk"));
        }
        if length > expected_bytes - output.len() {
            return Err(invalid("match exceeds expected chunk length"));
        }
        // Forward copying is required when a match overlaps its own output.
        for _ in 0..length {
            output.push(output[output.len() - distance]);
        }
    }
    Ok(output)
}

/// MS-XCA keeps at least 16 prefetched bits. Sideband length bytes are read
/// after that prefetch, before consuming/refilling the match's distance bits.
struct InputBits<'a> {
    input: &'a [u8],
    at: usize,
    next: u32,
    available: u8,
}

impl<'a> InputBits<'a> {
    fn new(input: &'a [u8]) -> Result<Self, ParseError> {
        let mut result = Self {
            input,
            at: TABLE_BYTES,
            next: 0,
            available: 32,
        };
        result.next = u32::from(result.word()?) << 16;
        result.next |= u32::from(result.word()?);
        Ok(result)
    }

    fn byte(&mut self) -> Result<u8, ParseError> {
        let value = *self
            .input
            .get(self.at)
            .ok_or_else(|| invalid("truncated match length"))?;
        self.at += 1;
        Ok(value)
    }

    fn word(&mut self) -> Result<u16, ParseError> {
        let raw = self
            .input
            .get(self.at..self.at + 2)
            .ok_or_else(|| invalid("truncated input word"))?;
        self.at += 2;
        Ok(u16::from_le_bytes([raw[0], raw[1]]))
    }

    fn take(&mut self, count: u8) -> Result<u32, ParseError> {
        if count == 0 {
            return Ok(0);
        }
        let value = self.next >> (32 - count);
        self.next <<= count;
        self.available -= count;
        if self.available < 16 {
            let word = u32::from(self.word()?);
            self.next |= word << (16 - self.available);
            self.available += 16;
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests;
