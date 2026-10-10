//! Bounded native ATTRIBUTE_LIST values, independent of their storage location.
//!
//! Layout: Microsoft ATTRIBUTE_LIST_ENTRY and Linux v6.12 ntfs3/ntfs.h.
//! The word at byte 24 identifies an attribute instance in the target record.
//! Repeated resident attributes (notably FILE_NAME hard links) are distinct
//! instances; type/name/VCN alone is therefore not a sufficient identity.

use super::{ATTRIBUTE_LIST, NtfsReference, invalid, le16, le32, le64};
use ffs_types::ParseError;
use std::collections::BTreeSet;

/// Resource limits of this reader, not maximum sizes of the native format.
pub const MAX_LIST_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_LIST_ENTRIES: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsAttributeListEntry {
    pub kind: u32,
    pub name: Vec<u16>,
    pub first_vcn: u64,
    pub reference: NtfsReference,
    pub id: u16,
}

/// Decode exactly the logical value. There is no end marker or zero-padding
/// sentinel: a truncated final entry must not turn into a successful prefix.
/// Preserve native names, including code units not representable as UTF-8.
/// Ordering/collation is not assumed; consumers validate the complete catalog.
pub fn parse_attribute_list(value: &[u8]) -> Result<Vec<NtfsAttributeListEntry>, ParseError> {
    if value.is_empty() || value.len() > MAX_LIST_BYTES {
        return Err(invalid("ntfs.attribute_list", "empty or over-budget value"));
    }
    let mut result = Vec::new();
    let mut identities = BTreeSet::new();
    let mut offset = 0;
    while offset < value.len() {
        if result.len() == MAX_LIST_ENTRIES {
            return Err(invalid("ntfs.attribute_list", "entry budget exceeded"));
        }
        let remaining = &value[offset..];
        let kind = le32(remaining, 0)?;
        let length = usize::from(le16(remaining, 4)?);
        if kind == 0
            || kind & 15 != 0
            || kind == ATTRIBUTE_LIST
            || length < 32
            || !length.is_multiple_of(8)
            || length > remaining.len()
        {
            return Err(invalid(
                "ntfs.attribute_list",
                "invalid type or entry boundary",
            ));
        }
        let entry = &remaining[..length];
        let name_length = usize::from(entry[6]);
        let name_start = usize::from(entry[7]);
        let name_end = name_start + name_length * 2;
        if name_length != 0
            && (name_start < 26 || !name_start.is_multiple_of(2) || name_end > length)
        {
            return Err(invalid(
                "ntfs.attribute_list",
                "name overlaps header or next entry",
            ));
        }
        let first_vcn = le64(entry, 8)?;
        if first_vcn > i64::MAX as u64 {
            return Err(invalid("ntfs.attribute_list", "negative starting VCN"));
        }
        let reference = NtfsReference::decode(le64(entry, 16)?);
        let id = le16(entry, 24)?;
        if !identities.insert((reference.record, id)) {
            return Err(invalid(
                "ntfs.attribute_list",
                "duplicate target attribute instance",
            ));
        }
        let mut name = Vec::with_capacity(name_length);
        if name_length != 0 {
            for at in (name_start..name_end).step_by(2) {
                name.push(le16(entry, at)?);
            }
        }
        result.push(NtfsAttributeListEntry {
            kind,
            name,
            first_vcn,
            reference,
            id,
        });
        offset += length;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(kind: u32, record: u64, id: u16, vcn: u64, name: &[u16]) -> Vec<u8> {
        let length = (26 + name.len() * 2).next_multiple_of(8);
        let mut value = vec![0; length];
        value[..4].copy_from_slice(&kind.to_le_bytes());
        value[4..6].copy_from_slice(&(length as u16).to_le_bytes());
        value[6] = name.len() as u8;
        value[7] = 26;
        value[8..16].copy_from_slice(&vcn.to_le_bytes());
        value[16..24].copy_from_slice(&(record | (7_u64 << 48)).to_le_bytes());
        value[24..26].copy_from_slice(&id.to_le_bytes());
        for (i, unit) in name.iter().enumerate() {
            value[26 + 2 * i..28 + 2 * i].copy_from_slice(&unit.to_le_bytes());
        }
        value
    }

    #[test]
    fn references_names_and_continuation_vcns_are_lossless() {
        let mut bytes = entry(0x80, 24, 3, 0, &[0xD800, 65]);
        bytes.extend(entry(0x80, 25, 0, 103, &[0xD800, 65]));
        let entries = parse_attribute_list(&bytes).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, [0xD800, 65]);
        assert_eq!(
            entries[0].reference,
            NtfsReference {
                record: 24,
                sequence: 7
            }
        );
        assert_eq!((entries[0].id, entries[1].first_vcn), (3, 103));
    }

    #[test]
    fn multiple_resident_file_names_do_not_collapse_into_one_attribute() {
        let mut bytes = entry(0x30, 24, 2, 0, &[]);
        bytes.extend(entry(0x30, 25, 2, 0, &[]));
        bytes.extend(entry(0x30, 25, 3, 0, &[]));
        assert_eq!(parse_attribute_list(&bytes).unwrap().len(), 3);
        bytes.extend(entry(0x80, 25, 3, 0, &[]));
        assert!(parse_attribute_list(&bytes).is_err());
    }

    #[test]
    fn malformed_entries_never_return_a_valid_prefix() {
        let valid = entry(0x80, 24, 1, 0, &[65, 66, 67, 68]);
        for end in 0..valid.len() {
            assert!(
                parse_attribute_list(&valid[..end]).is_err(),
                "truncation {end}"
            );
        }
        for (offset, byte) in [
            (0, 0),
            (0, 0x20),
            (0, 0x81),
            (4, 24),
            (4, 33),
            (6, 255),
            (7, 24),
            (7, 27),
            (15, 0x80),
        ] {
            let mut bad = valid.clone();
            bad[offset] = byte;
            assert!(parse_attribute_list(&bad).is_err(), "field {offset}");
        }
        let mut bad_tail = valid;
        bad_tail.extend_from_slice(&[0; 8]);
        assert!(parse_attribute_list(&bad_tail).is_err());
        assert!(parse_attribute_list(&vec![0; MAX_LIST_BYTES + 1]).is_err());
    }
}
