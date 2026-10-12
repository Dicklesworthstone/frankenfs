//! Bounded LZX decoding for independent WOF file-provider chunks.
//!
//! This is the 32 KiB WIM/System Compression variant: compact block headers,
//! three recent offsets, delta-coded Huffman lengths and fixed-size E8
//! postprocessing. CAB framing, larger windows and LZX DELTA are not admitted.
//! Native behavior references:
//! https://github.com/microsoft/go-winio/blob/v0.6.2/wim/lzx/lzx.go
//! https://github.com/torvalds/linux/blob/v6.17/fs/ntfs3/lib/lzx_decompress.c

use ffs_types::ParseError;

/// Native WOF LZX chunks have independent 32 KiB dictionaries.
pub const MAX_OUTPUT_BYTES: usize = 32_768;
const MAX_INPUT_BYTES: usize = 2 * MAX_OUTPUT_BYTES + 4096;
const MAIN_SYMBOLS: usize = 496;
const LENGTH_SYMBOLS: usize = 249;
const MAX_CODE_BITS: usize = 16;
const E8_FILE_SIZE: i32 = 12_000_000;

fn invalid(reason: &'static str) -> ParseError {
    ParseError::InvalidField {
        field: "ntfs.lzx",
        reason,
    }
}

/// Reconstruct one complete WIM/System Compression LZX chunk.
///
/// The caller supplies the exact logical length and separately validates its
/// physical chunk range. All blocks, matches and E8 translations complete
/// before output is returned. Code lengths and repeat offsets persist between
/// blocks in this call, but no dictionary state crosses a chunk boundary.
/// Terminal word-padding/prefetch bytes are not additional logical contents.
pub fn decompress_chunk(input: &[u8], expected_bytes: usize) -> Result<Vec<u8>, ParseError> {
    if !(1..=MAX_OUTPUT_BYTES).contains(&expected_bytes) {
        return Err(invalid("invalid expected chunk length"));
    }
    if !(2..=MAX_INPUT_BYTES).contains(&input.len()) {
        return Err(invalid(
            "compressed chunk length is outside the bounded profile",
        ));
    }
    let mut bits = InputBits::new(input);
    let mut main_lengths = [0_u8; MAIN_SYMBOLS];
    let mut length_lengths = [0_u8; LENGTH_SYMBOLS];
    let mut recent = [1_usize; 3];
    let mut output = Vec::new();
    output
        .try_reserve_exact(expected_bytes)
        .map_err(|_| invalid("cannot allocate bounded decoded chunk"))?;
    while output.len() < expected_bytes {
        let kind = bits.take(3)?;
        let size = if bits.take(1)? == 1 {
            MAX_OUTPUT_BYTES
        } else {
            bits.take(16)? as usize
        };
        if size == 0 || size > expected_bytes - output.len() {
            return Err(invalid("block exceeds the remaining logical chunk"));
        }
        let end = output.len() + size;
        match kind {
            1 | 2 => {
                let codes =
                    read_codes(&mut bits, &mut main_lengths, &mut length_lengths, kind == 2)?;
                decode_block(&mut bits, &codes, &mut recent, &mut output, end)?;
            }
            3 => {
                bits.align_raw()?;
                for offset in &mut recent {
                    let bytes = bits.raw(4)?;
                    let value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                    if value == 0 || value > MAX_OUTPUT_BYTES as u32 {
                        return Err(invalid("uncompressed block has an invalid repeat offset"));
                    }
                    *offset = value as usize;
                }
                output.extend_from_slice(bits.raw(size)?);
                // Odd raw blocks have a pad byte before the next block.
                // Final padding is not needed to reconstruct the exact output.
                if !size.is_multiple_of(2) && output.len() < expected_bytes {
                    bits.raw(1)?;
                }
            }
            _ => return Err(invalid("unknown LZX block type")),
        }
    }
    undo_e8(&mut output)?;
    Ok(output)
}

/// Read most-significant bits from little-endian 16-bit words. Loading only
/// the needed word makes native raw-block alignment independent of prefetch.
struct InputBits<'a> {
    input: &'a [u8],
    at: usize,
    word: u32,
    available: u8,
}

impl<'a> InputBits<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            at: 0,
            word: 0,
            available: 0,
        }
    }

    fn take(&mut self, mut count: u8) -> Result<u32, ParseError> {
        let mut result = 0;
        while count != 0 {
            if self.available == 0 {
                let bytes = self.raw(2)?;
                self.word = u32::from(u16::from_le_bytes([bytes[0], bytes[1]]));
                self.available = 16;
            }
            let used = count.min(self.available);
            self.available -= used;
            result = (result << used) | ((self.word >> self.available) & ((1_u32 << used) - 1));
            count -= used;
        }
        Ok(result)
    }

    fn raw(&mut self, count: usize) -> Result<&'a [u8], ParseError> {
        let end = self
            .at
            .checked_add(count)
            .ok_or_else(|| invalid("input byte range overflow"))?;
        let bytes = self
            .input
            .get(self.at..end)
            .ok_or_else(|| invalid("truncated LZX input"))?;
        self.at = end;
        Ok(bytes)
    }

    fn align_raw(&mut self) -> Result<(), ParseError> {
        // Native framing discards a complete word when already aligned.
        if self.available == 0 {
            self.raw(2)?;
        }
        self.available = 0;
        Ok(())
    }
}

/// Canonical ranges need space proportional to the alphabet, not 2^16 tables.
/// Decoding examines at most sixteen bits and rejects an unused empty tree.
struct Huffman {
    first: [u32; MAX_CODE_BITS + 1],
    offsets: [usize; MAX_CODE_BITS + 1],
    counts: [u16; MAX_CODE_BITS + 1],
    symbols: Vec<u16>,
}

impl Huffman {
    fn new(lengths: &[u8]) -> Result<Self, ParseError> {
        let mut result = Self {
            first: [0; MAX_CODE_BITS + 1],
            offsets: [0; MAX_CODE_BITS + 1],
            counts: [0; MAX_CODE_BITS + 1],
            symbols: Vec::new(),
        };
        for &length in lengths {
            if usize::from(length) > MAX_CODE_BITS {
                return Err(invalid("Huffman length exceeds sixteen bits"));
            }
            if length != 0 {
                result.counts[usize::from(length)] += 1;
            }
        }
        let mut code = 0;
        let mut total = 0;
        for width in 1..=MAX_CODE_BITS {
            code = (code + u32::from(result.counts[width - 1])) << 1;
            result.first[width] = code;
            result.offsets[width] = total;
            total += usize::from(result.counts[width]);
            if code + u32::from(result.counts[width]) > 1_u32 << width {
                return Err(invalid("oversubscribed Huffman code lengths"));
            }
        }
        if total != 0 && code + u32::from(result.counts[MAX_CODE_BITS]) != 1_u32 << MAX_CODE_BITS {
            return Err(invalid("incomplete Huffman code lengths"));
        }
        result
            .symbols
            .try_reserve_exact(total)
            .map_err(|_| invalid("cannot allocate bounded Huffman symbols"))?;
        for width in 1..=MAX_CODE_BITS {
            for (symbol, &length) in lengths.iter().enumerate() {
                if usize::from(length) == width {
                    result.symbols.push(symbol as u16);
                }
            }
        }
        Ok(result)
    }

    fn read(&self, bits: &mut InputBits<'_>) -> Result<usize, ParseError> {
        if self.symbols.is_empty() {
            return Err(invalid("payload uses an empty Huffman tree"));
        }
        let mut code = 0;
        for width in 1..=MAX_CODE_BITS {
            code = (code << 1) | bits.take(1)?;
            if let Some(index) = code.checked_sub(self.first[width])
                && index < u32::from(self.counts[width])
            {
                return Ok(usize::from(
                    self.symbols[self.offsets[width] + index as usize],
                ));
            }
        }
        Err(invalid("invalid Huffman code"))
    }
}

fn update_lengths(bits: &mut InputBits<'_>, lengths: &mut [u8]) -> Result<(), ParseError> {
    let mut pre_lengths = [0_u8; 20];
    for length in &mut pre_lengths {
        *length = bits.take(4)? as u8;
    }
    let precode = Huffman::new(&pre_lengths)?;
    let mut at = 0;
    while at < lengths.len() {
        let symbol = precode.read(bits)?;
        let (count, value) = match symbol {
            0..=16 => (1, (usize::from(lengths[at]) + 17 - symbol) % 17),
            17 => (bits.take(4)? as usize + 4, 0),
            18 => (bits.take(5)? as usize + 20, 0),
            19 => {
                let count = bits.take(1)? as usize + 4;
                let delta = precode.read(bits)?;
                if delta > 16 {
                    return Err(invalid("invalid repeated Huffman length delta"));
                }
                (count, (usize::from(lengths[at]) + 17 - delta) % 17)
            }
            _ => return Err(invalid("invalid precode symbol")),
        };
        if count > lengths.len() - at {
            return Err(invalid("Huffman length run exceeds its alphabet"));
        }
        lengths[at..at + count].fill(value as u8);
        at += count;
    }
    Ok(())
}

struct BlockCodes {
    main: Huffman,
    length: Huffman,
    aligned: Option<Huffman>,
}

fn read_codes(
    bits: &mut InputBits<'_>,
    main_lengths: &mut [u8; MAIN_SYMBOLS],
    length_lengths: &mut [u8; LENGTH_SYMBOLS],
    aligned: bool,
) -> Result<BlockCodes, ParseError> {
    let aligned = if aligned {
        let mut lengths = [0_u8; 8];
        for length in &mut lengths {
            *length = bits.take(3)? as u8;
        }
        Some(Huffman::new(&lengths)?)
    } else {
        None
    };
    update_lengths(bits, &mut main_lengths[..256])?;
    update_lengths(bits, &mut main_lengths[256..])?;
    let main = Huffman::new(main_lengths)?;
    update_lengths(bits, length_lengths)?;
    Ok(BlockCodes {
        main,
        length: Huffman::new(length_lengths)?,
        aligned,
    })
}

fn decode_block(
    bits: &mut InputBits<'_>,
    codes: &BlockCodes,
    recent: &mut [usize; 3],
    output: &mut Vec<u8>,
    end: usize,
) -> Result<(), ParseError> {
    while output.len() < end {
        let symbol = codes.main.read(bits)?;
        if symbol < 256 {
            output.push(symbol as u8);
            continue;
        }
        let pair = symbol - 256;
        let slot = pair / 8;
        let mut length = pair % 8;
        if length == 7 {
            length += codes.length.read(bits)?;
        }
        length += 2;
        let distance = if slot < 3 {
            // Native R2 reuse swaps with R0; it does not shift R1 down.
            recent.swap(0, slot);
            recent[0]
        } else {
            let extra = slot / 2 - 1;
            let base = if slot == 3 {
                3
            } else {
                (2 + slot % 2) << extra
            };
            let suffix = if let Some(aligned) = &codes.aligned
                && extra >= 3
            {
                ((bits.take((extra - 3) as u8)? as usize) << 3) + aligned.read(bits)?
            } else {
                bits.take(extra as u8)? as usize
            };
            let distance = base + suffix - 2;
            recent[2] = recent[1];
            recent[1] = recent[0];
            recent[0] = distance;
            distance
        };
        if distance == 0 || distance > output.len() {
            return Err(invalid("match references before this chunk"));
        }
        if length > end - output.len() {
            return Err(invalid("match exceeds its LZX block"));
        }
        for _ in 0..length {
            output.push(output[output.len() - distance]);
        }
    }
    Ok(())
}

fn undo_e8(output: &mut [u8]) -> Result<(), ParseError> {
    let end = output.len().saturating_sub(10);
    let mut at = 0;
    while at < end {
        if output[at] != 0xE8 {
            at += 1;
            continue;
        }
        let position =
            i32::try_from(at).map_err(|_| invalid("E8 position exceeds the bounded chunk"))?;
        let bytes = [
            output[at + 1],
            output[at + 2],
            output[at + 3],
            output[at + 4],
        ];
        let absolute = i32::from_le_bytes(bytes);
        if absolute >= -position && absolute < E8_FILE_SIZE {
            let relative = if absolute >= 0 {
                absolute - position
            } else {
                absolute + E8_FILE_SIZE
            };
            output[at + 1..at + 5].copy_from_slice(&relative.to_le_bytes());
        }
        at += 5;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
