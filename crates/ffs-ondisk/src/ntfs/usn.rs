//! Native NTFS `$Extend/$UsnJrnl` (`$Max` and `$J` `USN_RECORD_V2`) structures.
//!
//! Layout reference: Microsoft Win32 `USN_RECORD_V2` (major version 2, minor 0)
//! and NTFS `$Max` 32-byte metadata stream.
//!
//! Each USN record is 8-byte aligned and MUST NOT cross a 4 KiB (`USN_PAGE_BYTES`)
//! boundary inside `$J`: when a record would straddle a page boundary, the tail
//! of the page is zero-padded and the record starts at the next 4 KiB boundary.

use super::{NtfsReference, invalid, le16, le32, le64};
use ffs_types::ParseError;

pub const USN_PAGE_BYTES: u64 = 4096;
pub const USN_MAX_BYTES: usize = 32;
pub const USN_RECORD_V2_FIXED_BYTES: usize = 60;

pub const USN_REASON_DATA_OVERWRITE: u32 = 0x0000_0001;
pub const USN_REASON_DATA_EXTEND: u32 = 0x0000_0002;
pub const USN_REASON_DATA_TRUNCATION: u32 = 0x0000_0004;
pub const USN_REASON_NAMED_DATA_OVERWRITE: u32 = 0x0000_0010;
pub const USN_REASON_NAMED_DATA_EXTEND: u32 = 0x0000_0020;
pub const USN_REASON_NAMED_DATA_TRUNCATION: u32 = 0x0000_0040;
pub const USN_REASON_FILE_CREATE: u32 = 0x0000_0100;
pub const USN_REASON_FILE_DELETE: u32 = 0x0000_0200;
pub const USN_REASON_EA_CHANGE: u32 = 0x0000_0400;
pub const USN_REASON_SECURITY_CHANGE: u32 = 0x0000_0800;
pub const USN_REASON_RENAME_OLD_NAME: u32 = 0x0000_1000;
pub const USN_REASON_RENAME_NEW_NAME: u32 = 0x0000_2000;
pub const USN_REASON_BASIC_INFO_CHANGE: u32 = 0x0000_8000;
pub const USN_REASON_HARD_LINK_CHANGE: u32 = 0x0001_0000;
pub const USN_REASON_COMPRESSION_CHANGE: u32 = 0x0002_0000;
pub const USN_REASON_ENCRYPTION_CHANGE: u32 = 0x0004_0000;
pub const USN_REASON_OBJECT_ID_CHANGE: u32 = 0x0008_0000;
pub const USN_REASON_REPARSE_POINT_CHANGE: u32 = 0x0010_0000;
pub const USN_REASON_STREAM_CHANGE: u32 = 0x0020_0000;
pub const USN_REASON_CLOSE: u32 = 0x8000_0000;

/// 32-byte `$Extend/$UsnJrnl:$Max` resident attribute value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsnMaxData {
    pub maximum_size: u64,
    pub allocation_delta: u64,
    pub usn_id: u64,
    pub lowest_valid_usn: u64,
}

impl UsnMaxData {
    pub fn parse(raw: &[u8]) -> Result<Self, ParseError> {
        if raw.len() != USN_MAX_BYTES {
            return Err(invalid("ntfs.usn", "$Max stream must be exactly 32 bytes"));
        }
        let parsed = Self {
            maximum_size: le64(raw, 0)?,
            allocation_delta: le64(raw, 8)?,
            usn_id: le64(raw, 16)?,
            lowest_valid_usn: le64(raw, 24)?,
        };
        if parsed.maximum_size == 0
            || parsed.allocation_delta == 0
            || !parsed.lowest_valid_usn.is_multiple_of(8)
        {
            return Err(invalid(
                "ntfs.usn",
                "$Max has invalid size, allocation delta, or unaligned lowest_valid_usn",
            ));
        }
        Ok(parsed)
    }

    #[must_use]
    pub fn encode(&self) -> [u8; USN_MAX_BYTES] {
        let mut out = [0_u8; USN_MAX_BYTES];
        out[0..8].copy_from_slice(&self.maximum_size.to_le_bytes());
        out[8..16].copy_from_slice(&self.allocation_delta.to_le_bytes());
        out[16..24].copy_from_slice(&self.usn_id.to_le_bytes());
        out[24..32].copy_from_slice(&self.lowest_valid_usn.to_le_bytes());
        out
    }
}

/// One NTFS `USN_RECORD_V2` entry stored in `$Extend/$UsnJrnl:$J`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsnRecordV2 {
    pub file_ref: NtfsReference,
    pub parent_ref: NtfsReference,
    pub usn: u64,
    pub timestamp: u64,
    pub reason: u32,
    pub source_info: u32,
    pub security_id: u32,
    pub file_attributes: u32,
    pub name: Vec<u16>,
}

/// Compute the 8-byte-aligned `$J` offset for a record of `record_len` bytes,
/// advancing to the next 4 KiB page boundary if the record would cross a page edge.
#[must_use]
pub fn align_usn_offset(offset: u64, record_len: usize) -> u64 {
    let aligned = offset.next_multiple_of(8);
    let page_rem = USN_PAGE_BYTES - (aligned % USN_PAGE_BYTES);
    if (record_len as u64) > page_rem {
        aligned + page_rem
    } else {
        aligned
    }
}

impl UsnRecordV2 {
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        (USN_RECORD_V2_FIXED_BYTES + self.name.len() * 2).next_multiple_of(8)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ParseError> {
        if self.name.len() > 255 {
            return Err(invalid("ntfs.usn", "USN filename exceeds 255 UTF-16 units"));
        }
        let total = self.encoded_len();
        if total as u64 > USN_PAGE_BYTES {
            return Err(invalid("ntfs.usn", "USN record exceeds 4 KiB page size"));
        }
        let file_ref_raw = self.file_ref.encode()?;
        let parent_ref_raw = self.parent_ref.encode()?;
        let name_bytes = u16::try_from(self.name.len() * 2)
            .map_err(|_| invalid("ntfs.usn", "USN name byte length overflow"))?;
        let mut out = vec![0_u8; total];
        out[0..4].copy_from_slice(&(total as u32).to_le_bytes());
        out[4..6].copy_from_slice(&2_u16.to_le_bytes()); // major_version = 2
        out[6..8].copy_from_slice(&0_u16.to_le_bytes()); // minor_version = 0
        out[8..16].copy_from_slice(&file_ref_raw.to_le_bytes());
        out[16..24].copy_from_slice(&parent_ref_raw.to_le_bytes());
        out[24..32].copy_from_slice(&self.usn.to_le_bytes());
        out[32..40].copy_from_slice(&self.timestamp.to_le_bytes());
        out[40..44].copy_from_slice(&self.reason.to_le_bytes());
        out[44..48].copy_from_slice(&self.source_info.to_le_bytes());
        out[48..52].copy_from_slice(&self.security_id.to_le_bytes());
        out[52..56].copy_from_slice(&self.file_attributes.to_le_bytes());
        out[56..58].copy_from_slice(&name_bytes.to_le_bytes());
        out[58..60].copy_from_slice(&(USN_RECORD_V2_FIXED_BYTES as u16).to_le_bytes());
        for (i, &unit) in self.name.iter().enumerate() {
            out[USN_RECORD_V2_FIXED_BYTES + i * 2..USN_RECORD_V2_FIXED_BYTES + 2 + i * 2]
                .copy_from_slice(&unit.to_le_bytes());
        }
        Ok(out)
    }

    pub fn parse(raw: &[u8]) -> Result<(Self, usize), ParseError> {
        if raw.len() < USN_RECORD_V2_FIXED_BYTES {
            return Err(invalid("ntfs.usn", "truncated USN_RECORD_V2 header"));
        }
        let rec_len = usize::try_from(le32(raw, 0)?)
            .map_err(|_| invalid("ntfs.usn", "USN record length overflow"))?;
        let major = le16(raw, 4)?;
        let minor = le16(raw, 6)?;
        if major != 2 || minor != 0 {
            return Err(invalid("ntfs.usn", "unsupported USN record version (only v2.0 admitted)"));
        }
        if rec_len < USN_RECORD_V2_FIXED_BYTES
            || !rec_len.is_multiple_of(8)
            || rec_len > raw.len()
            || rec_len as u64 > USN_PAGE_BYTES
        {
            return Err(invalid("ntfs.usn", "invalid USN_RECORD_V2 record length"));
        }
        let file_ref = NtfsReference::parse(le64(raw, 8)?);
        let parent_ref = NtfsReference::parse(le64(raw, 16)?);
        let usn = le64(raw, 24)?;
        let timestamp = le64(raw, 32)?;
        let reason = le32(raw, 40)?;
        let source_info = le32(raw, 44)?;
        let security_id = le32(raw, 48)?;
        let file_attributes = le32(raw, 52)?;
        let name_len = usize::from(le16(raw, 56)?);
        let name_off = usize::from(le16(raw, 58)?);
        if name_off < USN_RECORD_V2_FIXED_BYTES
            || !name_len.is_multiple_of(2)
            || name_off + name_len > rec_len
        {
            return Err(invalid("ntfs.usn", "invalid USN_RECORD_V2 filename bounds"));
        }
        let name: Vec<u16> = raw[name_off..name_off + name_len]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        Ok((
            Self {
                file_ref,
                parent_ref,
                usn,
                timestamp,
                reason,
                source_info,
                security_id,
                file_attributes,
                name,
            },
            rec_len,
        ))
    }
}

/// Parse all `USN_RECORD_V2` entries in a contiguous `$J` slice starting at
/// logical offset `base_offset`, skipping zero-padding to 4 KiB page edges and
/// asserting `record.usn == absolute_offset` monotonicity.
pub fn parse_usn_journal_slice(
    base_offset: u64,
    bytes: &[u8],
) -> Result<Vec<UsnRecordV2>, ParseError> {
    if !base_offset.is_multiple_of(8) {
        return Err(invalid("ntfs.usn", "unaligned $J slice base offset"));
    }
    let mut records = Vec::new();
    let mut pos = 0_usize;
    while pos < bytes.len() {
        let abs_off = base_offset + pos as u64;
        let rem_in_page = (USN_PAGE_BYTES - (abs_off % USN_PAGE_BYTES)) as usize;
        if pos + 4 > bytes.len() {
            if bytes[pos..].iter().all(|&b| b == 0) {
                break;
            }
            return Err(invalid("ntfs.usn", "non-zero trailing bytes in $J"));
        }
        let rec_len = le32(bytes, pos)?;
        if rec_len == 0 {
            let skip = rem_in_page.min(bytes.len() - pos);
            if bytes[pos..pos + skip].iter().any(|&b| b != 0) {
                return Err(invalid("ntfs.usn", "non-zero bytes inside $J zero-pad tail"));
            }
            pos += skip;
            continue;
        }
        if usize::try_from(rec_len).is_ok_and(|n| n > rem_in_page) {
            return Err(invalid("ntfs.usn", "USN record crosses 4 KiB page boundary"));
        }
        let (record, consumed) = UsnRecordV2::parse(&bytes[pos..])?;
        if record.usn != abs_off {
            return Err(invalid("ntfs.usn", "USN record offset disagrees with record.usn"));
        }
        records.push(record);
        pos += consumed;
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usn_max_and_record_v2_roundtrip_with_page_boundary_alignment() {
        let max = UsnMaxData {
            maximum_size: 1_048_576,
            allocation_delta: 65_536,
            usn_id: 133_500_000_000_000_000,
            lowest_valid_usn: 0,
        };
        assert_eq!(UsnMaxData::parse(&max.encode()).unwrap(), max);
        assert!(UsnMaxData::parse(&[0_u8; 31]).is_err());

        let rec_a = UsnRecordV2 {
            file_ref: NtfsReference {
                record: 42,
                sequence: 3,
            },
            parent_ref: NtfsReference {
                record: 5,
                sequence: 5,
            },
            usn: 4040,
            timestamp: 133_500_000_000_000_000,
            reason: USN_REASON_FILE_CREATE | USN_REASON_CLOSE,
            source_info: 0,
            security_id: 256,
            file_attributes: 0x20,
            name: "hello.txt".encode_utf16().collect(),
        };
        let enc_a = rec_a.encode().unwrap();
        assert_eq!(enc_a.len(), 80); // 60 + 18 = 78 -> 80
        // 4040 + 80 = 4120 > 4096 => must align to 4096!
        let aligned = align_usn_offset(4040, enc_a.len());
        assert_eq!(aligned, 4096);

        let mut rec_aligned = rec_a;
        rec_aligned.usn = aligned;
        let enc_aligned = rec_aligned.encode().unwrap();
        let mut page_buf = vec![0_u8; 4096 + enc_aligned.len()];
        page_buf[4096..].copy_from_slice(&enc_aligned);
        let parsed = parse_usn_journal_slice(0, &page_buf).unwrap();
        assert_eq!(parsed, vec![rec_aligned]);
    }
}
