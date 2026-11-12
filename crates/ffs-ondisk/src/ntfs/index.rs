//! Native FILE_NAME keys and $I30 directory index records.
//! Layout follows the NTFS 3.1 INDEX_ROOT/INDEX_BUFFER/INDEX_HDR structures.

use super::{NtfsReference, ParseError, invalid, le16, le32, le64, restore_record};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsFileName {
    pub parent: NtfsReference,
    pub namespace: u8,
    pub name: Vec<u16>,
}
impl NtfsFileName {
    pub fn parse(value: &[u8]) -> Result<Self, ParseError> {
        if value.len() < 66 {
            return Err(invalid("ntfs.file_name", "truncated FILE_NAME key"));
        }
        let length = usize::from(value[64]);
        if length == 0 || value[65] > 3 || value.len() != 66 + length * 2 {
            return Err(invalid(
                "ntfs.file_name",
                "invalid namespace or name length",
            ));
        }
        let mut name = Vec::with_capacity(length);
        for at in (66..value.len()).step_by(2) {
            let unit = le16(value, at)?;
            if matches!(unit, 0 | 0x2F | 0x5C) {
                return Err(invalid(
                    "ntfs.file_name",
                    "NUL or separator in path component",
                ));
            }
            name.push(unit);
        }
        Ok(Self {
            parent: NtfsReference::decode(le64(value, 0)?),
            namespace: value[65],
            name,
        })
    }

    /// Encode a complete NTFS `FILE_NAME` (`0x30`) attribute value (`66 + name.len() * 2` bytes)
    /// and verify that `NtfsFileName::parse` accepts it identically.
    #[allow(clippy::too_many_arguments)]
    pub fn encode(
        &self,
        created_filetime: u64,
        modified_filetime: u64,
        mft_changed_filetime: u64,
        accessed_filetime: u64,
        allocated_size: u64,
        data_size: u64,
        file_attributes: u32,
        reparse_or_ea: u32,
    ) -> Result<Vec<u8>, ParseError> {
        if self.name.is_empty() || self.name.len() > 255 || self.namespace > 3 {
            return Err(invalid(
                "ntfs.file_name",
                "name length outside 1..=255 or invalid namespace",
            ));
        }
        if self
            .name
            .iter()
            .any(|&unit| matches!(unit, 0 | 0x2F | 0x5C))
        {
            return Err(invalid(
                "ntfs.file_name",
                "NUL or separator in path component",
            ));
        }
        let parent_raw = self.parent.encode()?;
        let mut out = Vec::with_capacity(66 + self.name.len() * 2);
        out.extend_from_slice(&parent_raw.to_le_bytes());
        out.extend_from_slice(&created_filetime.to_le_bytes());
        out.extend_from_slice(&modified_filetime.to_le_bytes());
        out.extend_from_slice(&mft_changed_filetime.to_le_bytes());
        out.extend_from_slice(&accessed_filetime.to_le_bytes());
        out.extend_from_slice(&allocated_size.to_le_bytes());
        out.extend_from_slice(&data_size.to_le_bytes());
        out.extend_from_slice(&file_attributes.to_le_bytes());
        out.extend_from_slice(&reparse_or_ea.to_le_bytes());
        out.push(u8::try_from(self.name.len()).map_err(|_| invalid("ntfs.file_name", "overflow"))?);
        out.push(self.namespace);
        for &unit in &self.name {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        let parsed = Self::parse(&out)?;
        if parsed != *self {
            return Err(invalid("ntfs.file_name", "FILE_NAME roundtrip mismatch"));
        }
        Ok(out)
    }
}

/// Encode a leaf or internal `$I30` `INDEX_ENTRY` (`16 + aligned(key) [+ 8 child_vcn]`).
pub fn encode_index_entry(
    file_ref: NtfsReference,
    file_name_bytes: &[u8],
    child_vcn: Option<u64>,
) -> Result<Vec<u8>, ParseError> {
    let _ = NtfsFileName::parse(file_name_bytes)?;
    let key_len = u16::try_from(file_name_bytes.len())
        .map_err(|_| invalid("ntfs.index_entry", "key length overflow"))?;
    let ref_raw = file_ref.encode()?;
    let base_len = (16 + file_name_bytes.len() + 7) & !7;
    let total_len = base_len + usize::from(child_vcn.is_some()) * 8;
    let total_u16 = u16::try_from(total_len)
        .map_err(|_| invalid("ntfs.index_entry", "entry length overflow"))?;
    let entry_flags: u16 = u16::from(child_vcn.is_some());
    let mut entry = vec![0_u8; total_len];
    entry[0..8].copy_from_slice(&ref_raw.to_le_bytes());
    entry[8..10].copy_from_slice(&total_u16.to_le_bytes());
    entry[10..12].copy_from_slice(&key_len.to_le_bytes());
    entry[12..14].copy_from_slice(&entry_flags.to_le_bytes());
    entry[16..16 + file_name_bytes.len()].copy_from_slice(file_name_bytes);
    if let Some(vcn) = child_vcn {
        if vcn > i64::MAX as u64 {
            return Err(invalid("ntfs.index_entry", "negative child VCN"));
        }
        entry[total_len - 8..total_len].copy_from_slice(&vcn.to_le_bytes());
    }
    Ok(entry)
}

#[derive(Debug, Clone)]
pub struct NtfsIndexEntry {
    /// The terminal entry has no key but can still point to the rightmost child.
    pub key: Option<(NtfsReference, NtfsFileName)>,
    pub child_vcn: Option<u64>,
}
#[derive(Debug)]
pub struct NtfsIndexRoot {
    pub block_bytes: u32,
    /// For sub-cluster index blocks NTFS uses 512-byte VBN units, not BPB sectors.
    pub vcn_bytes: u32,
    pub entries: Vec<NtfsIndexEntry>,
}
impl NtfsIndexRoot {
    pub fn parse(value: &[u8], cluster_bytes: u32) -> Result<Self, ParseError> {
        if value.len() < 32 || le32(value, 0)? != 0x30 || le32(value, 4)? != 1 {
            return Err(invalid(
                "ntfs.index_root",
                "not a FILE_NAME-collated directory index",
            ));
        }
        let block_bytes = le32(value, 8)?;
        if !(512..=65_536).contains(&block_bytes)
            || !block_bytes.is_power_of_two()
            || cluster_bytes < 512
            || !cluster_bytes.is_power_of_two()
        {
            return Err(invalid("ntfs.index_root", "invalid block or cluster size"));
        }
        let vcn_bytes = if block_bytes < cluster_bytes {
            512
        } else {
            cluster_bytes
        };
        if u32::from(value[12]) * vcn_bytes != block_bytes {
            return Err(invalid(
                "ntfs.index_root",
                "index VBN units disagree with block size",
            ));
        }
        Ok(Self {
            block_bytes,
            vcn_bytes,
            entries: entries(value, 16, 32)?,
        })
    }
}

pub fn parse_index_block(raw: &[u8], expected_vcn: u64) -> Result<Vec<NtfsIndexEntry>, ParseError> {
    let value = restore_record(raw, b"INDX")?;
    let usa = usize::from(le16(&value, 4)?);
    let usa_end = usa + usize::from(le16(&value, 6)?) * 2;
    if usa < 40 || le64(&value, 16)? != expected_vcn {
        return Err(invalid(
            "ntfs.index_block",
            "invalid update-array position or VBN identity",
        ));
    }
    entries(&value, 24, usa_end)
}

pub(super) fn entries(
    value: &[u8],
    header: usize,
    minimum_entry: usize,
) -> Result<Vec<NtfsIndexEntry>, ParseError> {
    let offset = usize::try_from(le32(value, header)?)
        .map_err(|_| invalid("ntfs.index", "offset overflow"))?;
    let used = usize::try_from(le32(value, header + 4)?)
        .map_err(|_| invalid("ntfs.index", "length overflow"))?;
    let allocated = usize::try_from(le32(value, header + 8)?)
        .map_err(|_| invalid("ntfs.index", "length overflow"))?;
    let flags = le32(value, header + 12)?;
    if offset < 16
        || !offset.is_multiple_of(8)
        || !used.is_multiple_of(8)
        || used > allocated
        || allocated > value.len().saturating_sub(header)
        || offset
            .checked_add(header)
            .is_none_or(|start| start < minimum_entry)
        || offset.checked_add(16).is_none_or(|end| end > used)
        || flags > 1
    {
        return Err(invalid(
            "ntfs.index",
            "invalid entry, used or allocated boundaries",
        ));
    }
    let end = header + used;
    let mut at = header + offset;
    let mut result = Vec::new();
    loop {
        if at.checked_add(16).is_none_or(|next| next > end) {
            return Err(invalid("ntfs.index", "missing terminal entry"));
        }
        let length = usize::from(le16(value, at + 8)?);
        let key_bytes = usize::from(le16(value, at + 10)?);
        let entry_flags = le16(value, at + 12)?;
        let child = entry_flags & 1 != 0;
        let terminal = entry_flags & 2 != 0;
        if length < 16 + (if child { 8 } else { 0 })
            || !length.is_multiple_of(8)
            || at + length > end
            || entry_flags & !3 != 0
            || child != (flags == 1)
            || key_bytes > length - 16 - (if child { 8 } else { 0 })
        {
            return Err(invalid(
                "ntfs.index_entry",
                "invalid entry length, child or key bounds",
            ));
        }
        let child_vcn = if child {
            Some(le64(value, at + length - 8)?)
        } else {
            None
        };
        let key = if terminal {
            if key_bytes != 0 || at + length != end {
                return Err(invalid(
                    "ntfs.index_entry",
                    "terminal key or entries after terminator",
                ));
            }
            None
        } else {
            Some((
                NtfsReference::decode(le64(value, at)?),
                NtfsFileName::parse(&value[at + 16..at + 16 + key_bytes])?,
            ))
        };
        result.push(NtfsIndexEntry { key, child_vcn });
        if terminal {
            return Ok(result);
        }
        at += length;
    }
}

#[cfg(test)]
mod tests;
