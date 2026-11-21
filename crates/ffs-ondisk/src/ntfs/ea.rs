//! Native $EA_INFORMATION and $EA values, without interpreting their contents.
//!
//! Layout references: Microsoft FILE_FULL_EA_INFORMATION and Linux v6.17
//! fs/ntfs3/{ntfs.h,xattr.c}. On disk, an entry's first word is its padded
//! length, including the final entry. A zero final offset is also accepted;
//! unlike an API query, native names are retained as exact eight-bit bytes.

use super::{invalid, le16, le32};
use ffs_types::ParseError;
use std::collections::BTreeSet;

/// Bounded read profile; do not allocate from an unvalidated stream length.
pub const MAX_EA_BYTES: usize = 65_536;
pub const MAX_EA_NAME_BYTES: usize = 255;
pub const FILE_NEED_EA: u8 = 0x80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsEaInformation {
    /// Sum of entry sizes without their four-byte offsets or alignment padding.
    pub packed_bytes: u16,
    /// Number of entries carrying FILE_NEED_EA, not the total entry count.
    pub need_ea_count: u16,
    pub unpacked_bytes: u32,
}

impl NtfsEaInformation {
    pub fn parse(value: &[u8]) -> Result<Self, ParseError> {
        if value.len() != 8 {
            return Err(invalid(
                "ntfs.ea_information",
                "value must be exactly eight bytes",
            ));
        }
        let result = Self {
            packed_bytes: le16(value, 0)?,
            need_ea_count: le16(value, 2)?,
            unpacked_bytes: le32(value, 4)?,
        };
        if result.unpacked_bytes > MAX_EA_BYTES as u32 {
            return Err(invalid(
                "ntfs.ea_information",
                "EA value exceeds the 64 KiB budget",
            ));
        }
        Ok(result)
    }

    #[must_use]
    pub fn encode(&self) -> [u8; 8] {
        let mut out = [0_u8; 8];
        out[0..2].copy_from_slice(&self.packed_bytes.to_le_bytes());
        out[2..4].copy_from_slice(&self.need_ea_count.to_le_bytes());
        out[4..8].copy_from_slice(&self.unpacked_bytes.to_le_bytes());
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsEa {
    pub name: Vec<u8>,
    pub flags: u8,
    pub value: Vec<u8>,
}

impl NtfsEa {
    #[must_use]
    pub fn need_ea(&self) -> bool {
        self.flags & FILE_NEED_EA != 0
    }
}

/// Validate the complete logical value before returning any entry. Native
/// offsets include padding; packed lengths do not include offsets or padding.
/// Do not case-fold names, treat binary values as strings, or stop at a damaged
/// suffix. Exact duplicate names are ambiguous and therefore refused.
pub fn parse_extended_attributes(
    information: &NtfsEaInformation,
    value: &[u8],
) -> Result<Vec<NtfsEa>, ParseError> {
    if value.len() > MAX_EA_BYTES || value.len() as u64 != u64::from(information.unpacked_bytes) {
        return Err(invalid(
            "ntfs.ea",
            "logical size disagrees with EA_INFORMATION or exceeds budget",
        ));
    }
    let mut entries = Vec::new();
    let mut names = BTreeSet::new();
    let mut offset = 0;
    let mut packed_bytes = 0_usize;
    let mut need_ea_count = 0_usize;
    while offset < value.len() {
        let remaining = &value[offset..];
        if remaining.len() < 8 {
            return Err(invalid("ntfs.ea", "truncated entry header"));
        }
        let next = le32(remaining, 0)? as usize;
        let flags = remaining[4];
        let name_len = usize::from(remaining[5]);
        let value_len = usize::from(le16(remaining, 6)?);
        // Both lengths have fixed-width native bounds, so these additions
        // cannot overflow usize even on a 32-bit host.
        let name_end = 8 + name_len;
        let value_start = name_end + 1;
        let used = value_start + value_len;
        if flags & !FILE_NEED_EA != 0 || name_len == 0 || used > remaining.len() {
            return Err(invalid(
                "ntfs.ea",
                "invalid flags, empty name or truncated entry",
            ));
        }
        let length = if next == 0 {
            // Accept an unpadded or aligned final entry. A zero offset must
            // not turn a valid prefix followed by more records into success.
            if remaining.len() > used.next_multiple_of(4) {
                return Err(invalid(
                    "ntfs.ea",
                    "zero offset before the end of the EA value",
                ));
            }
            remaining.len()
        } else {
            if !next.is_multiple_of(4) || next < used || next > remaining.len() {
                return Err(invalid(
                    "ntfs.ea",
                    "entry offset overlaps data or leaves the EA value",
                ));
            }
            next
        };
        let name = &remaining[8..name_end];
        if name.contains(&0) || remaining[name_end] != 0 {
            return Err(invalid(
                "ntfs.ea",
                "embedded NUL or missing name terminator",
            ));
        }
        if !names.insert(name) {
            return Err(invalid("ntfs.ea", "duplicate native EA name"));
        }
        packed_bytes += used - 4;
        need_ea_count += usize::from(flags & FILE_NEED_EA != 0);
        entries.push(NtfsEa {
            name: name.to_vec(),
            flags,
            value: remaining[value_start..used].to_vec(),
        });
        offset += length;
    }
    if packed_bytes != usize::from(information.packed_bytes)
        || need_ea_count != usize::from(information.need_ea_count)
    {
        return Err(invalid(
            "ntfs.ea",
            "packed byte count or NEED_EA count disagrees with EA_INFORMATION",
        ));
    }
    Ok(entries)
}

/// Encode a set of native NTFS extended attributes into `($EA_INFORMATION, $EA)`
/// payload bytes, validating uniqueness, bounds, and round-trip parsing via
/// [`parse_extended_attributes`].
pub fn encode_extended_attributes(
    entries: &[NtfsEa],
) -> Result<(NtfsEaInformation, Vec<u8>), ParseError> {
    let mut names = BTreeSet::new();
    let mut out = Vec::new();
    let mut packed_bytes = 0_usize;
    let mut need_ea_count = 0_usize;

    for entry in entries {
        if entry.flags & !FILE_NEED_EA != 0
            || entry.name.is_empty()
            || entry.name.len() > MAX_EA_NAME_BYTES
            || entry.name.contains(&0)
        {
            return Err(invalid(
                "ntfs.ea",
                "invalid EA flags, name length, or embedded NUL",
            ));
        }
        if !names.insert(entry.name.as_slice()) {
            return Err(invalid("ntfs.ea", "duplicate native EA name"));
        }
        let name_len = u8::try_from(entry.name.len())
            .map_err(|_| invalid("ntfs.ea", "EA name length overflow"))?;
        let value_len = u16::try_from(entry.value.len())
            .map_err(|_| invalid("ntfs.ea", "EA value length exceeds u16"))?;
        let used = 8 + entry.name.len() + 1 + entry.value.len();
        let padded = used.next_multiple_of(4);
        if out.len() + padded > MAX_EA_BYTES {
            return Err(invalid("ntfs.ea", "encoded EA stream exceeds 64 KiB budget"));
        }
        let start = out.len();
        out.resize(start + padded, 0);
        out[start..start + 4].copy_from_slice(&(padded as u32).to_le_bytes());
        out[start + 4] = entry.flags;
        out[start + 5] = name_len;
        out[start + 6..start + 8].copy_from_slice(&value_len.to_le_bytes());
        out[start + 8..start + 8 + entry.name.len()].copy_from_slice(&entry.name);
        // Trailing NUL at start + 8 + name.len() is already 0.
        let val_start = start + 8 + entry.name.len() + 1;
        out[val_start..val_start + entry.value.len()].copy_from_slice(&entry.value);

        packed_bytes += used - 4;
        need_ea_count += usize::from(entry.need_ea());
    }
    let info = NtfsEaInformation {
        packed_bytes: u16::try_from(packed_bytes)
            .map_err(|_| invalid("ntfs.ea", "EA packed_bytes overflows u16"))?,
        need_ea_count: u16::try_from(need_ea_count)
            .map_err(|_| invalid("ntfs.ea", "EA need_ea_count overflows u16"))?,
        unpacked_bytes: u32::try_from(out.len())
            .map_err(|_| invalid("ntfs.ea", "EA unpacked_bytes overflows u32"))?,
    };
    let roundtrip = parse_extended_attributes(&info, &out)?;
    if roundtrip != entries {
        return Err(invalid("ntfs.ea", "encoded EA stream round-trip mismatch"));
    }
    Ok((info, out))
}

#[cfg(test)]
mod tests;
