//! Bounded native reparse buffers. Unknown providers retain their exact payload
//! and optional GUID; recognizing a tag never authorizes interpreting its DATA.
//!
//! Layout sources: Microsoft [MS-FSCC] 2.1.2.2–2.1.2.5 and REPARSE_DATA_BUFFER:
//! https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_reparse_data_buffer
//! https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/b41f1cbf-10df-4a47-98d4-1c52a833d913

use super::{ParseError, bytes, invalid, le16, le32};

pub const MAX_REPARSE_BYTES: usize = 16 * 1024;
pub const SYMLINK_TAG: u32 = 0xA000_000C;
pub const MOUNT_POINT_TAG: u32 = 0xA000_0003;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtfsReparseData {
    SymbolicLink {
        substitute: Vec<u16>,
        print: Vec<u16>,
        relative: bool,
    },
    MountPoint {
        substitute: Vec<u16>,
        print: Vec<u16>,
    },
    Opaque(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsReparsePoint {
    pub tag: u32,
    /// Non-Microsoft tags use the GUID form. Bytes retain native GUID ordering.
    pub guid: Option<[u8; 16]>,
    pub data: NtfsReparseData,
}

impl NtfsReparsePoint {
    pub fn parse(raw: &[u8]) -> Result<Self, ParseError> {
        if !(8..=MAX_REPARSE_BYTES).contains(&raw.len()) {
            return Err(invalid("ntfs.reparse", "invalid reparse buffer length"));
        }
        let tag = le32(raw, 0)?;
        if tag <= 2 {
            return Err(invalid("ntfs.reparse", "reserved reparse tag"));
        }
        let header = if tag & 0x8000_0000 == 0 { 24 } else { 8 };
        if usize::from(le16(raw, 4)?) + header != raw.len() {
            return Err(invalid(
                "ntfs.reparse",
                "payload length does not cover the exact reparse value",
            ));
        }
        let guid = if header == 24 {
            Some(bytes(raw, 8)?)
        } else {
            None
        };
        // The reserved word is ignored, as required by MS-FSCC. Both strings
        // are byte ranges relative to PathBuffer, not to the outer header.
        let data = match tag {
            SYMLINK_TAG => {
                let flags = le32(raw, 16)?;
                if flags > 1 {
                    return Err(invalid("ntfs.reparse", "unknown symbolic-link flags"));
                }
                let (substitute, print) = paths(raw, 20)?;
                NtfsReparseData::SymbolicLink {
                    substitute,
                    print,
                    relative: flags == 1,
                }
            }
            MOUNT_POINT_TAG => {
                let (substitute, print) = paths(raw, 16)?;
                NtfsReparseData::MountPoint { substitute, print }
            }
            _ => NtfsReparseData::Opaque(raw[header..].to_vec()),
        };
        Ok(Self { tag, guid, data })
    }

    #[must_use]
    pub const fn is_name_surrogate(&self) -> bool {
        self.tag & 0x2000_0000 != 0
    }
}

fn paths(raw: &[u8], path_offset: usize) -> Result<(Vec<u16>, Vec<u16>), ParseError> {
    let path = raw
        .get(path_offset..)
        .filter(|path| path.len().is_multiple_of(2))
        .ok_or_else(|| invalid("ntfs.reparse", "truncated or odd-sized UTF-16 path buffer"))?;
    let string = |field| -> Result<Vec<u16>, ParseError> {
        let offset = usize::from(le16(raw, field)?);
        let length = usize::from(le16(raw, field + 2)?);
        if !offset.is_multiple_of(2) || !length.is_multiple_of(2) {
            return Err(invalid("ntfs.reparse", "unaligned UTF-16 name range"));
        }
        let value = path
            .get(offset..offset + length)
            .ok_or_else(|| invalid("ntfs.reparse", "name range outside path buffer"))?;
        let units: Vec<_> = value
            .as_chunks::<2>()
            .0
            .iter()
            .map(|unit| u16::from_le_bytes(*unit))
            .collect();
        if units.contains(&0) {
            return Err(invalid("ntfs.reparse", "embedded NUL in reparse name"));
        }
        Ok(units)
    };
    let substitute = string(8)?;
    if substitute.is_empty() {
        return Err(invalid("ntfs.reparse", "empty substitute name"));
    }
    // Names can be in either order or use the same range. Unpaired surrogates
    // are preserved for inspection; host presentation decides representability.
    Ok((substitute, string(12)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Explicit MS-FSCC offsets: display name comes first, and neither stored
    // range includes its optional terminator. The substitute is authoritative.
    fn symlink() -> Vec<u8> {
        let mut raw = vec![0; 20];
        raw[..4].copy_from_slice(&SYMLINK_TAG.to_le_bytes());
        raw[6..8].copy_from_slice(&0x1234_u16.to_le_bytes());
        raw[8..10].copy_from_slice(&10_u16.to_le_bytes());
        raw[10..12].copy_from_slice(&16_u16.to_le_bytes());
        raw[14..16].copy_from_slice(&8_u16.to_le_bytes());
        raw[16..20].copy_from_slice(&1_u32.to_le_bytes());
        for unit in "view\0..\\Ä.txt\0".encode_utf16() {
            raw.extend(unit.to_le_bytes());
        }
        let length = (raw.len() - 8) as u16;
        raw[4..6].copy_from_slice(&length.to_le_bytes());
        raw
    }

    #[test]
    fn reparse_names_use_native_byte_ranges_and_preserve_surrogates() {
        let raw = symlink();
        let point = NtfsReparsePoint::parse(&raw).unwrap();
        assert_eq!(point.tag, SYMLINK_TAG);
        assert!(point.is_name_surrogate());
        assert_eq!(point.guid, None);
        assert_eq!(
            point.data,
            NtfsReparseData::SymbolicLink {
                substitute: "..\\Ä.txt".encode_utf16().collect(),
                print: "view".encode_utf16().collect(),
                relative: true,
            }
        );
        let mut surrogate = raw;
        surrogate[36..38].copy_from_slice(&0xD800_u16.to_le_bytes());
        let NtfsReparseData::SymbolicLink { substitute, .. } =
            NtfsReparsePoint::parse(&surrogate).unwrap().data
        else {
            panic!("symlink");
        };
        assert!(substitute.contains(&0xD800));
    }

    #[test]
    fn reparse_rejects_truncated_unaligned_and_out_of_range_names() {
        let good = symlink();
        for end in 0..good.len() {
            assert!(
                NtfsReparsePoint::parse(&good[..end]).is_err(),
                "length {end}"
            );
        }
        for (offset, value) in [(8, 11_u16), (10, 15), (10, 0), (12, 0xFFFE), (14, 9)] {
            let mut bad = good.clone();
            bad[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
            assert!(NtfsReparsePoint::parse(&bad).is_err(), "offset {offset}");
        }
        let mut bad = good.clone();
        bad[16..20].copy_from_slice(&2_u32.to_le_bytes());
        assert!(NtfsReparsePoint::parse(&bad).is_err());
        let mut nul = good.clone();
        nul[30..32].fill(0);
        assert!(NtfsReparsePoint::parse(&nul).is_err());
        let mut slack = good;
        slack.push(0);
        assert!(NtfsReparsePoint::parse(&slack).is_err());
        assert!(NtfsReparsePoint::parse(&vec![0; MAX_REPARSE_BYTES + 1]).is_err());
    }

    #[test]
    fn reparse_junctions_and_unknown_guid_payloads_remain_inspectable() {
        let target: Vec<_> = "\\??\\C:\\data".encode_utf16().collect();
        let mut junction = vec![0; 16];
        junction[..4].copy_from_slice(&MOUNT_POINT_TAG.to_le_bytes());
        junction[4..6].copy_from_slice(&(8 + target.len() as u16 * 2).to_le_bytes());
        junction[10..12].copy_from_slice(&(target.len() as u16 * 2).to_le_bytes());
        for unit in &target {
            junction.extend(unit.to_le_bytes());
        }
        assert_eq!(
            NtfsReparsePoint::parse(&junction).unwrap().data,
            NtfsReparseData::MountPoint {
                substitute: target,
                print: Vec::new(),
            }
        );
        let mut unknown = vec![0; 27];
        unknown[..4].copy_from_slice(&0x1234_u32.to_le_bytes());
        unknown[4..6].copy_from_slice(&3_u16.to_le_bytes());
        unknown[8..24].copy_from_slice(&[0xAB; 16]);
        unknown[24..].copy_from_slice(&[0x00, 0xFF, 0x80]);
        let point = NtfsReparsePoint::parse(&unknown).unwrap();
        assert_eq!(point.guid, Some([0xAB; 16]));
        assert_eq!(point.data, NtfsReparseData::Opaque(vec![0x00, 0xFF, 0x80]));
        unknown[4..6].copy_from_slice(&19_u16.to_le_bytes());
        assert!(NtfsReparsePoint::parse(&unknown).is_err());
    }
}
