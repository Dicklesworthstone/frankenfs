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

/// Encode a canonical `$ATTRIBUTE_LIST` (`0x20`) byte payload from validated entries.
///
/// Enforces all structural invariants required by [`parse_attribute_list`]:
/// non-empty list within [`MAX_LIST_ENTRIES`] and [`MAX_LIST_BYTES`], valid
/// non-`0x20` 16-aligned attribute type codes, `name.len() <= 255`,
/// non-negative `first_vcn`, non-zero sequence numbers, and unique
/// `(reference.record, id)` target attribute instances.
pub fn encode_attribute_list(entries: &[NtfsAttributeListEntry]) -> Result<Vec<u8>, ParseError> {
    if entries.is_empty() || entries.len() > MAX_LIST_ENTRIES {
        return Err(invalid(
            "ntfs.attribute_list",
            "empty or over-budget entry count",
        ));
    }
    let mut identities = BTreeSet::new();
    let mut out = Vec::with_capacity(entries.len().saturating_mul(32));
    for entry in entries {
        if entry.kind == 0
            || entry.kind & 15 != 0
            || entry.kind == ATTRIBUTE_LIST
            || entry.kind == u32::MAX
        {
            return Err(invalid("ntfs.attribute_list", "invalid entry type code"));
        }
        let name_len = u8::try_from(entry.name.len()).map_err(|_| {
            invalid(
                "ntfs.attribute_list",
                "attribute name exceeds 255 UTF-16 units",
            )
        })?;
        if entry.first_vcn > i64::MAX as u64 {
            return Err(invalid("ntfs.attribute_list", "negative starting VCN"));
        }
        if entry.reference.sequence == 0 {
            return Err(invalid(
                "ntfs.attribute_list",
                "zero sequence number in target reference",
            ));
        }
        if !identities.insert((entry.reference.record, entry.id)) {
            return Err(invalid(
                "ntfs.attribute_list",
                "duplicate target attribute instance",
            ));
        }
        let raw_len = 26_usize
            .checked_add(entry.name.len().saturating_mul(2))
            .ok_or_else(|| invalid("ntfs.attribute_list", "entry length overflow"))?;
        let length = raw_len.max(32).next_multiple_of(8);
        let length_u16 = u16::try_from(length)
            .map_err(|_| invalid("ntfs.attribute_list", "entry length exceeds u16"))?;
        if out.len().saturating_add(length) > MAX_LIST_BYTES {
            return Err(invalid(
                "ntfs.attribute_list",
                "encoded list exceeds byte budget",
            ));
        }
        let start = out.len();
        out.resize(start + length, 0);
        let slot = &mut out[start..start + length];
        slot[0..4].copy_from_slice(&entry.kind.to_le_bytes());
        slot[4..6].copy_from_slice(&length_u16.to_le_bytes());
        slot[6] = name_len;
        slot[7] = 26;
        slot[8..16].copy_from_slice(&entry.first_vcn.to_le_bytes());
        slot[16..24].copy_from_slice(&entry.reference.encode()?.to_le_bytes());
        slot[24..26].copy_from_slice(&entry.id.to_le_bytes());
        for (idx, &unit) in entry.name.iter().enumerate() {
            let at = 26 + idx * 2;
            slot[at..at + 2].copy_from_slice(&unit.to_le_bytes());
        }
    }
    Ok(out)
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

    #[test]
    fn encode_attribute_list_round_trips_and_rejects_invalid_entries() {
        let entries = vec![
            NtfsAttributeListEntry {
                kind: 0x10,
                name: Vec::new(),
                first_vcn: 0,
                reference: NtfsReference {
                    record: 42,
                    sequence: 1,
                },
                id: 0,
            },
            NtfsAttributeListEntry {
                kind: 0x80,
                name: Vec::new(),
                first_vcn: 0,
                reference: NtfsReference {
                    record: 42,
                    sequence: 1,
                },
                id: 2,
            },
            NtfsAttributeListEntry {
                kind: 0x80,
                name: Vec::new(),
                first_vcn: 16,
                reference: NtfsReference {
                    record: 43,
                    sequence: 3,
                },
                id: 0,
            },
            NtfsAttributeListEntry {
                kind: 0x80,
                name: vec![u16::from(b'a'), u16::from(b'd'), u16::from(b's'), 0xD800],
                first_vcn: 0,
                reference: NtfsReference {
                    record: 43,
                    sequence: 3,
                },
                id: 1,
            },
        ];
        let encoded = encode_attribute_list(&entries).unwrap();
        assert_eq!(encoded.len() % 8, 0);
        let decoded = parse_attribute_list(&encoded).unwrap();
        assert_eq!(decoded, entries);

        assert!(encode_attribute_list(&[]).is_err());
        let mut self_kind = entries[..1].to_vec();
        self_kind[0].kind = ATTRIBUTE_LIST;
        assert!(encode_attribute_list(&self_kind).is_err());

        let mut dup = vec![entries[0].clone(), entries[0].clone()];
        dup[1].kind = 0x30;
        assert!(encode_attribute_list(&dup).is_err());

        let mut bad_seq = entries[..1].to_vec();
        bad_seq[0].reference.sequence = 0;
        assert!(encode_attribute_list(&bad_seq).is_err());

        let mut long_name = entries[..1].to_vec();
        long_name[0].name = vec![u16::from(b'x'); 256];
        assert!(encode_attribute_list(&long_name).is_err());

        let mut neg_vcn = entries[..1].to_vec();
        neg_vcn[0].first_vcn = (i64::MAX as u64) + 1;
        assert!(encode_attribute_list(&neg_vcn).is_err());
    }
}
