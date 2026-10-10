//! Native ZFS label, uberblock and block decoding (OpenZFS 2.3 layout).
//!
//! Pure, bounded parsing. A checked uberblock is a candidate, NOT an imported
//! pool: topology, configuration, features and the complete MOS still matter.
//! Sources: OpenZFS spa.h, vdev_impl.h, uberblock_impl.h, zio_checksum.c.

pub mod nvlist;

use ffs_types::ParseError;
use sha2::{Digest, Sha256};

pub const LABEL_BYTES: u64 = 256 * 1024;
pub const LABEL_CONFIG_OFFSET: u64 = 16 * 1024;
pub const LABEL_CONFIG_BYTES: usize = 112 * 1024;
pub const UBERBLOCK_RING_OFFSET: u64 = 128 * 1024;
pub const UBERBLOCK_RING_BYTES: usize = 128 * 1024;
pub const DATA_OFFSET: u64 = 4 * 1024 * 1024;
/// Explicit read-profile bound; not the maximum size of the native format.
pub const MAX_BLOCK_BYTES: usize = 16 * 1024 * 1024;
const ECK_MAGIC: u64 = 0x0210_da7a_b10c_7a11;
const UBER_MAGIC: u64 = 0x00ba_b10c;

fn invalid(reason: &'static str) -> ParseError {
    ParseError::InvalidField { field: "zfs", reason }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian { Little, Big }

impl Endian {
    pub fn u64(self, bytes: &[u8], offset: usize) -> Result<u64, ParseError> {
        let end = offset.checked_add(8).ok_or_else(|| invalid("word offset overflow"))?;
        let raw: [u8; 8] = bytes.get(offset..end)
            .ok_or_else(|| invalid("truncated 64-bit word"))?
            .try_into().map_err(|_| invalid("truncated 64-bit word"))?;
        Ok(match self { Self::Little => u64::from_le_bytes(raw), Self::Big => u64::from_be_bytes(raw) })
    }
    #[must_use]
    pub const fn encode(self, word: u64) -> [u8; 8] {
        match self { Self::Little => word.to_le_bytes(), Self::Big => word.to_be_bytes() }
    }
}

/// Label positions use the selected leaf's length, never the enclosing image's.
pub fn label_offsets(leaf_bytes: u64) -> Result<[u64; 4], ParseError> {
    let aligned = leaf_bytes / LABEL_BYTES * LABEL_BYTES;
    if aligned < DATA_OFFSET + 2 * LABEL_BYTES {
        return Err(invalid("leaf is too short for labels and boot area"));
    }
    Ok([0, LABEL_BYTES, aligned - 2 * LABEL_BYTES, aligned - LABEL_BYTES])
}

pub fn uberblock_bytes(ashift: u8) -> Result<usize, ParseError> {
    if !(9..=16).contains(&ashift) { return Err(invalid("unsupported leaf ashift")); }
    Ok(1_usize << ashift.clamp(10, 13))
}

/// Native SHA256 represents the digest as four big-endian numeric words even
/// when the structure containing those words is stored little-endian.
fn sha_words(bytes: &[u8]) -> [u64; 4] {
    let digest = Sha256::digest(bytes);
    std::array::from_fn(|index| {
        let at = index * 8;
        u64::from_be_bytes(std::array::from_fn(|i| digest[at + i]))
    })
}

pub fn checksum(bytes: &[u8], algorithm: u8, order: Endian) -> Result<[u64; 4], ParseError> {
    if bytes.len() > MAX_BLOCK_BYTES { return Err(invalid("checksum input exceeds block budget")); }
    match algorithm {
        8 => Ok(sha_words(bytes)),
        7 => {
            if !bytes.len().is_multiple_of(4) { return Err(invalid("unaligned Fletcher4 input")); }
            let mut sum = [0_u64; 4];
            for word in bytes.chunks_exact(4) {
                let raw = [word[0], word[1], word[2], word[3]];
                let value = match order { Endian::Little => u32::from_le_bytes(raw), Endian::Big => u32::from_be_bytes(raw) };
                sum[0] = sum[0].wrapping_add(u64::from(value));
                for i in 1..4 { sum[i] = sum[i].wrapping_add(sum[i - 1]); }
            }
            Ok(sum)
        }
        6 => {
            if !bytes.len().is_multiple_of(16) { return Err(invalid("unaligned Fletcher2 input")); }
            let mut sum = [0_u64; 4];
            for words in bytes.chunks_exact(16) {
                sum[0] = sum[0].wrapping_add(order.u64(words, 0)?);
                sum[1] = sum[1].wrapping_add(order.u64(words, 8)?);
                sum[2] = sum[2].wrapping_add(sum[0]);
                sum[3] = sum[3].wrapping_add(sum[1]);
            }
            Ok(sum)
        }
        _ => Err(invalid("checksum is disabled, inherited or unsupported")),
    }
}

/// Verify an offset-salted label/uberblock checksum without modifying input.
/// `offset` is relative to the selected vdev, not the host file/partition base.
pub fn verify_label_checksum(bytes: &[u8], offset: u64) -> Result<Endian, ParseError> {
    if bytes.len() < 40 || bytes.len() > LABEL_CONFIG_BYTES {
        return Err(invalid("invalid embedded-checksum span"));
    }
    let tail = bytes.len() - 40;
    let order = if Endian::Little.u64(bytes, tail)? == ECK_MAGIC { Endian::Little }
        else if Endian::Big.u64(bytes, tail)? == ECK_MAGIC { Endian::Big }
        else { return Err(invalid("missing embedded checksum magic")); };
    let mut expected = [0; 4];
    for (i, value) in expected.iter_mut().enumerate() { *value = order.u64(bytes, tail + 8 + i * 8)?; }
    let mut hash = Sha256::new();
    hash.update(&bytes[..tail + 8]);
    hash.update(order.encode(offset));
    hash.update([0_u8; 24]);
    let digest = hash.finalize();
    let actual: [u64; 4] = std::array::from_fn(|index| {
        u64::from_be_bytes(std::array::from_fn(|i| digest[index * 8 + i]))
    });
    if expected != actual { return Err(invalid("label checksum or offset verifier mismatch")); }
    Ok(order)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dva {
    pub vdev: u32,
    pub offset: u64,
    pub allocated_bytes: u64,
    pub gang: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockPointer { words: [u64; 16] }

impl BlockPointer {
    pub fn parse(raw: &[u8], order: Endian) -> Result<Self, ParseError> {
        if raw.len() != 128 { return Err(invalid("block pointer must contain exactly 128 bytes")); }
        let mut words = [0; 16];
        for (i, word) in words.iter_mut().enumerate() { *word = order.u64(raw, i * 8)?; }
        let result = Self { words };
        if result.logical_bytes() > MAX_BLOCK_BYTES { return Err(invalid("logical block exceeds read budget")); }
        Ok(result)
    }
    #[must_use]
    pub fn logical_bytes(&self) -> usize {
        if self.embedded() { ((self.words[6] & 0x01ff_ffff) + 1) as usize }
        else { (((self.words[6] & 0xffff) + 1) * 512) as usize }
    }
    #[must_use]
    pub fn physical_bytes(&self) -> usize { ((((self.words[6] >> 16) & 0xffff) + 1) * 512) as usize }
    #[must_use]
    pub const fn embedded(&self) -> bool { self.words[6] & (1 << 39) != 0 }
    #[must_use]
    pub const fn protected(&self) -> bool { self.words[6] & (1 << 61) != 0 }
    #[must_use]
    pub fn hole(&self) -> bool { !self.embedded() && self.words[..6].iter().all(|word| *word == 0) }
    #[must_use]
    pub const fn compression(&self) -> u8 { ((self.words[6] >> 32) & 0x7f) as u8 }
    #[must_use]
    pub const fn checksum_type(&self) -> u8 { ((self.words[6] >> 40) & 0xff) as u8 }
    #[must_use]
    pub const fn object_type(&self) -> u8 { ((self.words[6] >> 48) & 0xff) as u8 }
    #[must_use]
    pub const fn level(&self) -> u8 { ((self.words[6] >> 56) & 0x1f) as u8 }
    #[must_use]
    pub const fn birth(&self) -> u64 { self.words[10] }
    #[must_use]
    pub const fn payload_order(&self) -> Endian {
        if self.words[6] >> 63 == 0 { Endian::Big } else { Endian::Little }
    }

    /// Admission for the ordinary unencrypted single-leaf block pipeline.
    /// Hole size requires DMU context; embedded/gang blocks use other pipelines.
    pub fn regular_dvas(&self) -> Result<Vec<Dva>, ParseError> {
        if self.embedded() || self.protected() || self.hole() {
            return Err(invalid("embedded, protected or context-sized hole block is not a regular block"));
        }
        if self.words[7] != 0 || self.words[8] != 0 || self.birth() == 0 {
            return Err(invalid("noncanonical regular block padding or birth"));
        }
        if self.physical_bytes() > self.logical_bytes() {
            return Err(invalid("physical block exceeds logical block size"));
        }
        if !matches!(self.checksum_type(), 6..=8) || !matches!(self.compression(), 2 | 3 | 15) {
            return Err(invalid("unsupported block checksum or compression"));
        }
        if self.compression() == 2 && self.physical_bytes() != self.logical_bytes() {
            return Err(invalid("uncompressed block sizes disagree"));
        }
        let mut result = Vec::new();
        let mut ended = false;
        for i in 0..3 {
            let first = self.words[i * 2];
            let second = self.words[i * 2 + 1];
            if first == 0 && second == 0 { ended = true; continue; }
            if ended || first & 0xff00_0000_ff00_0000 != 0 || first & 0x00ff_ffff == 0 {
                return Err(invalid("invalid or noncontiguous DVA slots"));
            }
            let offset = (second & 0x7fff_ffff_ffff_ffff).checked_mul(512)
                .ok_or_else(|| invalid("DVA offset overflow"))?;
            result.push(Dva { vdev: ((first >> 32) & 0x00ff_ffff) as u32,
                offset, allocated_bytes: (first & 0x00ff_ffff) * 512, gang: second >> 63 != 0 });
        }
        if result.is_empty() { return Err(invalid("regular block has no DVA")); }
        Ok(result)
    }

    /// Check physical bytes (including allocation padding inside PSIZE) before
    /// decoding. No partial or unchecked logical bytes escape on failure.
    pub fn decode(&self, physical: &[u8]) -> Result<Vec<u8>, ParseError> {
        self.regular_dvas()?;
        if physical.len() != self.physical_bytes() { return Err(invalid("short physical block")); }
        let expected = [self.words[12], self.words[13], self.words[14], self.words[15]];
        if checksum(physical, self.checksum_type(), self.payload_order())? != expected {
            return Err(invalid("physical block checksum mismatch"));
        }
        decompress(physical, self.compression(), self.logical_bytes())
    }
}

#[derive(Debug, Clone)]
pub struct Uberblock {
    pub order: Endian,
    pub version: u64,
    pub txg: u64,
    pub guid_sum: u64,
    pub timestamp: u64,
    pub root: BlockPointer,
}
impl Uberblock {
    pub fn parse(raw: &[u8], vdev_offset: u64) -> Result<Self, ParseError> {
        if !matches!(raw.len(), 1024 | 2048 | 4096 | 8192) { return Err(invalid("invalid uberblock slot size")); }
        let order = verify_label_checksum(raw, vdev_offset)?;
        if order.u64(raw, 0)? != UBER_MAGIC { return Err(invalid("invalid uberblock magic")); }
        let version = order.u64(raw, 8)?;
        let txg = order.u64(raw, 16)?;
        if !(1..=28).contains(&version) && version != 5000 { return Err(invalid("unsupported pool version")); }
        if txg == 0 { return Err(invalid("uninitialized uberblock")); }
        let root = BlockPointer::parse(&raw[40..168], order)?;
        if root.hole() || root.embedded() || root.protected() || root.object_type() != 11
            || root.level() != 0 || root.birth() == 0 || root.birth() > txg {
            return Err(invalid("uberblock has an invalid or unsupported MOS root pointer"));
        }
        Ok(Self { order, version, txg, guid_sum: order.u64(raw, 24)?, timestamp: order.u64(raw, 32)?, root })
    }
}

/// Decode only explicitly implemented native codecs, with exact output length.
pub fn decompress(input: &[u8], compression: u8, output_bytes: usize) -> Result<Vec<u8>, ParseError> {
    if output_bytes == 0 || output_bytes > MAX_BLOCK_BYTES || input.len() > MAX_BLOCK_BYTES {
        return Err(invalid("invalid transform size budget"));
    }
    let mut output = Vec::new();
    output.try_reserve_exact(output_bytes).map_err(|_| invalid("decompression allocation failed"))?;
    match compression {
        2 => {
            if input.len() != output_bytes { return Err(invalid("uncompressed length mismatch")); }
            output.extend_from_slice(input);
        }
        3 => {
            let mut at = 0;
            while output.len() < output_bytes {
                let map = *input.get(at).ok_or_else(|| invalid("truncated LZJB map"))?;
                at += 1;
                for bit in 0..8 {
                    if output.len() == output_bytes { break; }
                    let first = *input.get(at).ok_or_else(|| invalid("truncated LZJB token"))?;
                    at += 1;
                    if map & (1 << bit) == 0 { output.push(first); }
                    else {
                        let second = *input.get(at).ok_or_else(|| invalid("truncated LZJB match"))?;
                        at += 1;
                        let distance = ((usize::from(first) & 3) << 8) | usize::from(second);
                        let length = usize::from(first >> 2) + 3;
                        copy_match(&mut output, distance, length, output_bytes)?;
                    }
                }
            }
        }
        15 => {
            let header: [u8; 4] = input.get(..4).ok_or_else(|| invalid("missing ZFS LZ4 length"))?
                .try_into().map_err(|_| invalid("missing ZFS LZ4 length"))?;
            let packed = usize::try_from(u32::from_be_bytes(header)).map_err(|_| invalid("LZ4 length overflow"))?;
            let end = packed.checked_add(4).ok_or_else(|| invalid("LZ4 length overflow"))?;
            let data = input.get(4..end).filter(|data| !data.is_empty()).ok_or_else(|| invalid("truncated ZFS LZ4 input"))?;
            let mut at = 0;
            while at < data.len() {
                let token = data[at];
                at += 1;
                let literals = lz4_length(data, &mut at, usize::from(token >> 4))?;
                if literals > output_bytes - output.len() { return Err(invalid("LZ4 literals exceed output bound")); }
                let end = at.checked_add(literals).ok_or_else(|| invalid("LZ4 literal length overflow"))?;
                output.extend_from_slice(data.get(at..end).ok_or_else(|| invalid("truncated LZ4 literals"))?);
                at = end;
                if at == data.len() { break; }
                let pair = data.get(at..at + 2).ok_or_else(|| invalid("truncated LZ4 offset"))?;
                let distance = usize::from(u16::from_le_bytes([pair[0], pair[1]]));
                at += 2;
                let length = lz4_length(data, &mut at, usize::from(token & 15))?.checked_add(4)
                    .ok_or_else(|| invalid("LZ4 match length overflow"))?;
                copy_match(&mut output, distance, length, output_bytes)?;
            }
        }
        _ => return Err(invalid("unsupported compression algorithm")),
    }
    if output.len() != output_bytes { return Err(invalid("decompression did not reconstruct the complete logical block")); }
    Ok(output)
}

fn lz4_length(input: &[u8], at: &mut usize, mut length: usize) -> Result<usize, ParseError> {
    if length == 15 {
        loop {
            let next = *input.get(*at).ok_or_else(|| invalid("truncated LZ4 length extension"))?;
            *at += 1;
            length = length.checked_add(usize::from(next)).filter(|len| *len <= MAX_BLOCK_BYTES)
                .ok_or_else(|| invalid("LZ4 length exceeds read budget"))?;
            if next != 255 { break; }
        }
    }
    Ok(length)
}
fn copy_match(output: &mut Vec<u8>, distance: usize, length: usize, limit: usize) -> Result<(), ParseError> {
    if distance == 0 || distance > output.len() || length > limit - output.len() {
        return Err(invalid("invalid compression backreference or output overrun"));
    }
    for _ in 0..length { output.push(output[output.len() - distance]); }
    Ok(())
}

#[cfg(test)]
mod tests;
