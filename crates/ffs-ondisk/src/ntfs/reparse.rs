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

    /// Encode this reparse point into its exact MS-FSCC binary buffer and
    /// verify round-trip parsing via [`Self::parse`].
    pub fn encode(&self) -> Result<Vec<u8>, ParseError> {
        if self.tag <= 2 {
            return Err(invalid("ntfs.reparse", "reserved reparse tag"));
        }
        let is_microsoft = self.tag & 0x8000_0000 != 0;
        let payload = match (&self.data, self.tag) {
            (
                NtfsReparseData::SymbolicLink {
                    substitute,
                    print,
                    relative,
                },
                SYMLINK_TAG,
            ) => {
                if self.guid.is_some() {
                    return Err(invalid("ntfs.reparse", "symlink tag must not carry a GUID"));
                }
                if substitute.is_empty() || substitute.contains(&0) || print.contains(&0) {
                    return Err(invalid("ntfs.reparse", "invalid symlink reparse target"));
                }
                let sub_bytes = u16::try_from(substitute.len() * 2)
                    .map_err(|_| invalid("ntfs.reparse", "symlink substitute overflow"))?;
                let print_bytes = u16::try_from(print.len() * 2)
                    .map_err(|_| invalid("ntfs.reparse", "symlink print name overflow"))?;
                // Store substitute + NUL then print + NUL inside PathBuffer (MS-FSCC canonical order).
                let print_off = u16::try_from(usize::from(sub_bytes) + 2)
                    .map_err(|_| invalid("ntfs.reparse", "symlink print offset overflow"))?;
                let mut body =
                    Vec::with_capacity(12 + usize::from(sub_bytes) + usize::from(print_bytes) + 4);
                body.extend_from_slice(&0_u16.to_le_bytes()); // SubstituteNameOffset
                body.extend_from_slice(&sub_bytes.to_le_bytes());
                body.extend_from_slice(&print_off.to_le_bytes());
                body.extend_from_slice(&print_bytes.to_le_bytes());
                body.extend_from_slice(&u32::from(*relative).to_le_bytes());
                for &u in substitute {
                    body.extend_from_slice(&u.to_le_bytes());
                }
                body.extend_from_slice(&0_u16.to_le_bytes());
                for &u in print {
                    body.extend_from_slice(&u.to_le_bytes());
                }
                body.extend_from_slice(&0_u16.to_le_bytes());
                body
            }
            (NtfsReparseData::MountPoint { substitute, print }, MOUNT_POINT_TAG) => {
                if self.guid.is_some() {
                    return Err(invalid(
                        "ntfs.reparse",
                        "mount point tag must not carry a GUID",
                    ));
                }
                if substitute.is_empty() || substitute.contains(&0) || print.contains(&0) {
                    return Err(invalid(
                        "ntfs.reparse",
                        "invalid mount point reparse target",
                    ));
                }
                let sub_bytes = u16::try_from(substitute.len() * 2)
                    .map_err(|_| invalid("ntfs.reparse", "mount point substitute overflow"))?;
                let print_bytes = u16::try_from(print.len() * 2)
                    .map_err(|_| invalid("ntfs.reparse", "mount point print name overflow"))?;
                let print_off = u16::try_from(usize::from(sub_bytes) + 2)
                    .map_err(|_| invalid("ntfs.reparse", "mount point print offset overflow"))?;
                let mut body =
                    Vec::with_capacity(8 + usize::from(sub_bytes) + usize::from(print_bytes) + 4);
                body.extend_from_slice(&0_u16.to_le_bytes());
                body.extend_from_slice(&sub_bytes.to_le_bytes());
                body.extend_from_slice(&print_off.to_le_bytes());
                body.extend_from_slice(&print_bytes.to_le_bytes());
                for &u in substitute {
                    body.extend_from_slice(&u.to_le_bytes());
                }
                body.extend_from_slice(&0_u16.to_le_bytes());
                for &u in print {
                    body.extend_from_slice(&u.to_le_bytes());
                }
                body.extend_from_slice(&0_u16.to_le_bytes());
                body
            }
            (NtfsReparseData::Opaque(bytes), tag)
                if tag != SYMLINK_TAG && tag != MOUNT_POINT_TAG =>
            {
                if is_microsoft && self.guid.is_some() {
                    return Err(invalid(
                        "ntfs.reparse",
                        "Microsoft reparse tag must not carry a GUID",
                    ));
                }
                if !is_microsoft && self.guid.is_none() {
                    return Err(invalid(
                        "ntfs.reparse",
                        "non-Microsoft reparse tag requires a 16-byte GUID",
                    ));
                }
                bytes.clone()
            }
            _ => {
                return Err(invalid(
                    "ntfs.reparse",
                    "reparse tag disagrees with reparse data variant",
                ));
            }
        };
        let header_len: usize = if is_microsoft { 8 } else { 24 };
        let total = header_len + payload.len();
        if total > MAX_REPARSE_BYTES {
            return Err(invalid(
                "ntfs.reparse",
                "encoded reparse buffer exceeds 16 KiB",
            ));
        }
        let data_len = u16::try_from(payload.len())
            .map_err(|_| invalid("ntfs.reparse", "reparse payload length overflow"))?;
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&self.tag.to_le_bytes());
        out.extend_from_slice(&data_len.to_le_bytes());
        out.extend_from_slice(&0_u16.to_le_bytes());
        if let Some(guid) = self.guid {
            out.extend_from_slice(&guid);
        }
        out.extend_from_slice(&payload);
        let parsed = Self::parse(&out)?;
        if parsed != *self {
            return Err(invalid(
                "ntfs.reparse",
                "encoded reparse buffer round-trip mismatch",
            ));
        }
        Ok(out)
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

        // Round-trip encode for symlink, mount point, and custom GUID opaque tag.
        let sym = NtfsReparsePoint {
            tag: SYMLINK_TAG,
            guid: None,
            data: NtfsReparseData::SymbolicLink {
                substitute: "..\\target.bin".encode_utf16().collect(),
                print: "..\\target.bin".encode_utf16().collect(),
                relative: true,
            },
        };
        assert_eq!(
            NtfsReparsePoint::parse(&sym.encode().unwrap()).unwrap(),
            sym
        );

        let mp = NtfsReparsePoint {
            tag: MOUNT_POINT_TAG,
            guid: None,
            data: NtfsReparseData::MountPoint {
                substitute: "\\??\\C:\\dir".encode_utf16().collect(),
                print: "C:\\dir".encode_utf16().collect(),
            },
        };
        assert_eq!(NtfsReparsePoint::parse(&mp.encode().unwrap()).unwrap(), mp);

        let opaque = NtfsReparsePoint {
            tag: 0x0000_1234,
            guid: Some([0x5A; 16]),
            data: NtfsReparseData::Opaque(vec![1, 2, 3, 4]),
        };
        assert_eq!(
            NtfsReparsePoint::parse(&opaque.encode().unwrap()).unwrap(),
            opaque
        );
    }
}
