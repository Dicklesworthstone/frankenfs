//! Native NTFS security descriptors, $SII index records and $SDS headers.
//!
//! Layout: Microsoft MS-DTYP self-relative security descriptors; NTFS 3.1
//! security indexes as documented by NTFS-3G 2022.10.3 and Linux NTFS3 v6.19.
//! This module validates structure and preserves native metadata. It does not
//! evaluate access, map SIDs to host users, or rewrite an ACL.

use crate::ntfs::restore_record;
use ffs_types::ParseError;
use std::fmt;

/// Explicit parser budget, not the maximum descriptor size of every producer.
pub const MAX_SECURITY_DESCRIPTOR_BYTES: usize = 128 * 1024;
pub const SDS_HEADER_BYTES: usize = 20;
pub const SDS_COPY_DISTANCE: u64 = 0x4_0000;

fn invalid(reason: &'static str) -> ParseError {
    ParseError::InvalidField {
        field: "ntfs.security",
        reason,
    }
}

fn bytes<const N: usize>(value: &[u8], offset: usize) -> Result<[u8; N], ParseError> {
    let end = offset
        .checked_add(N)
        .ok_or_else(|| invalid("security field offset overflow"))?;
    value
        .get(offset..end)
        .and_then(|part| part.try_into().ok())
        .ok_or_else(|| invalid("truncated security field"))
}

fn le16(value: &[u8], offset: usize) -> Result<u16, ParseError> {
    Ok(u16::from_le_bytes(bytes(value, offset)?))
}

fn le32(value: &[u8], offset: usize) -> Result<u32, ParseError> {
    Ok(u32::from_le_bytes(bytes(value, offset)?))
}

fn le64(value: &[u8], offset: usize) -> Result<u64, ParseError> {
    Ok(u64::from_le_bytes(bytes(value, offset)?))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsSid {
    pub authority: u64,
    pub subauthorities: Vec<u32>,
}

impl NtfsSid {
    fn prefix(value: &[u8]) -> Result<(Self, usize), ParseError> {
        if value.len() < 8 || value[0] != 1 || value[1] > 15 {
            return Err(invalid("invalid SID revision, count or header"));
        }
        let length = 8 + usize::from(value[1]) * 4;
        if length > value.len() {
            return Err(invalid("SID subauthorities exceed their container"));
        }
        let mut authority = 0_u64;
        for &byte in &value[2..8] {
            authority = (authority << 8) | u64::from(byte);
        }
        let mut subauthorities = Vec::with_capacity(usize::from(value[1]));
        for at in (8..length).step_by(4) {
            subauthorities.push(le32(value, at)?);
        }
        Ok((
            Self {
                authority,
                subauthorities,
            },
            length,
        ))
    }
}

impl fmt::Display for NtfsSid {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.authority > u64::from(u32::MAX) {
            write!(out, "S-1-0x{:012x}", self.authority)?;
        } else {
            write!(out, "S-1-{}", self.authority)?;
        }
        for subauthority in &self.subauthorities {
            write!(out, "-{subauthority}")?;
        }
        Ok(())
    }
}

/// An ACE in native order, retaining unimplemented layout bytes losslessly.
/// This is structural metadata, never an evaluated grant, deny or condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsAce {
    pub kind: u8,
    pub flags: u8,
    pub size: u16,
    /// None for an unrecognized layout; its entire body remains in opaque.
    pub mask: Option<u32>,
    pub sid: Option<NtfsSid>,
    pub object_flags: Option<u32>,
    pub object_type: Option<[u8; 16]>,
    pub inherited_object_type: Option<[u8; 16]>,
    /// Callback/claim data, extra native bytes, or the complete unknown body.
    pub opaque: Vec<u8>,
}

impl NtfsAce {
    fn parse(value: &[u8], revision: u8, system: bool) -> Result<Self, ParseError> {
        let kind = value[0];
        let ordinary = matches!(kind, 0 | 1 | 2 | 9 | 10 | 13 | 17 | 18 | 19);
        let object = matches!(kind, 5 | 6 | 7 | 11 | 12 | 15);
        let mut ace = Self {
            kind,
            flags: value[1],
            size: le16(value, 2)?,
            mask: None,
            sid: None,
            object_flags: None,
            object_type: None,
            inherited_object_type: None,
            opaque: Vec::new(),
        };
        if !ordinary && !object {
            ace.opaque = value[4..].to_vec();
            return Ok(ace);
        }
        let system_kind = matches!(kind, 2 | 7 | 13 | 15 | 17 | 18 | 19);
        if system_kind != system {
            return Err(invalid("ACE belongs to the other ACL kind"));
        }
        if object && revision != 4 {
            return Err(invalid("object ACE requires ACL revision 4"));
        }
        ace.mask = Some(le32(value, 4)?);
        let mut at = 8;
        if object {
            let flags = le32(value, 8)?;
            if flags & !3 != 0 {
                return Err(invalid("unknown object-ACE presence flags"));
            }
            ace.object_flags = Some(flags);
            at = 12;
            if flags & 1 != 0 {
                ace.object_type = Some(bytes(value, at)?);
                at += 16;
            }
            if flags & 2 != 0 {
                ace.inherited_object_type = Some(bytes(value, at)?);
                at += 16;
            }
        }
        let remaining = value
            .get(at..)
            .ok_or_else(|| invalid("missing ACE trustee SID"))?;
        let (sid, length) = NtfsSid::prefix(remaining)?;
        ace.sid = Some(sid);
        // MS-DTYP permits extra bytes after known ACE fields. Callback and
        // claim application data also remains opaque; no expression is run.
        ace.opaque = remaining[length..].to_vec();
        Ok(ace)
    }
}

/// `present == false` is an absent ACL; `present && offset == 0` is a
/// native NULL ACL. A present ACL with zero ACEs is a different state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsAcl {
    pub present: bool,
    pub offset: u32,
    pub revision: Option<u8>,
    pub ace_count: Option<u16>,
    pub size: Option<u16>,
    /// Parsed in stored order; inherited and deny ACEs are never reordered.
    pub aces: Vec<NtfsAce>,
    /// AclSize includes unused bytes after the counted ACEs.
    pub padding: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsSecurityDescriptor {
    pub control: u16,
    pub resource_manager_control: u8,
    pub owner: Option<NtfsSid>,
    pub group: Option<NtfsSid>,
    pub sacl: NtfsAcl,
    pub dacl: NtfsAcl,
}

impl NtfsSecurityDescriptor {
    pub fn parse(value: &[u8]) -> Result<Self, ParseError> {
        if !(20..=MAX_SECURITY_DESCRIPTOR_BYTES).contains(&value.len())
            || !value.len().is_multiple_of(4)
            || value[0] != 1
        {
            return Err(invalid("invalid security descriptor revision or length"));
        }
        let control = le16(value, 2)?;
        if control & 0x8000 == 0 {
            return Err(invalid("security descriptor is not self-relative"));
        }
        Ok(Self {
            control,
            resource_manager_control: value[1],
            owner: sid_at(value, le32(value, 4)?)?,
            group: sid_at(value, le32(value, 8)?)?,
            sacl: acl_at(value, le32(value, 12)?, control & 0x10 != 0, true)?,
            dacl: acl_at(value, le32(value, 16)?, control & 0x04 != 0, false)?,
        })
    }
}

fn component_offset(value: &[u8], offset: u32, minimum: usize) -> Result<usize, ParseError> {
    let offset = usize::try_from(offset).map_err(|_| invalid("component offset overflow"))?;
    if offset < 20
        || !offset.is_multiple_of(4)
        || offset
            .checked_add(minimum)
            .is_none_or(|end| end > value.len())
    {
        return Err(invalid("invalid security component offset or extent"));
    }
    Ok(offset)
}

fn sid_at(value: &[u8], offset: u32) -> Result<Option<NtfsSid>, ParseError> {
    if offset == 0 {
        return Ok(None);
    }
    let at = component_offset(value, offset, 8)?;
    NtfsSid::prefix(&value[at..]).map(|(sid, _)| Some(sid))
}

fn acl_at(value: &[u8], offset: u32, present: bool, system: bool) -> Result<NtfsAcl, ParseError> {
    if !present && offset != 0 {
        return Err(invalid("ACL offset is present without its control flag"));
    }
    if offset == 0 {
        return Ok(NtfsAcl {
            present,
            offset,
            revision: None,
            ace_count: None,
            size: None,
            aces: Vec::new(),
            padding: Vec::new(),
        });
    }
    let at = component_offset(value, offset, 8)?;
    let revision = value[at];
    let size = usize::from(le16(value, at + 2)?);
    let count = le16(value, at + 4)?;
    if !matches!(revision, 2 | 4)
        || value[at + 1] != 0
        || le16(value, at + 6)? != 0
        || size < 8
        || !size.is_multiple_of(4)
        || at + size > value.len()
        || usize::from(count) > (size - 8) / 4
    {
        return Err(invalid(
            "invalid ACL revision, reserved fields or declared extent",
        ));
    }
    let end = at + size;
    let mut cursor = at + 8;
    let mut aces = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        if cursor + 4 > end {
            return Err(invalid("ACL ACE count exceeds its declared extent"));
        }
        let length = usize::from(le16(value, cursor + 2)?);
        if length < 4 || !length.is_multiple_of(4) || cursor + length > end {
            return Err(invalid("invalid ACE size or boundary"));
        }
        aces.push(NtfsAce::parse(
            &value[cursor..cursor + length],
            revision,
            system,
        )?);
        cursor += length;
    }
    // AclSize includes reserved free space after the counted ACEs.
    Ok(NtfsAcl {
        present,
        offset,
        revision: Some(revision),
        ace_count: Some(count),
        size: Some(size as u16),
        aces,
        padding: value[cursor..end].to_vec(),
    })
}

/// Native rotate-and-add hash over complete little-endian 32-bit words.
/// This is an NTFS lookup/integrity field, not a cryptographic authenticator.
#[must_use]
pub fn security_hash(value: &[u8]) -> u32 {
    value.as_chunks::<4>().0.iter().fold(0_u32, |hash, word| {
        hash.rotate_left(3).wrapping_add(u32::from_le_bytes(*word))
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsSecurityHeader {
    pub hash: u32,
    pub security_id: u32,
    pub offset: u64,
    pub length: u32,
}

impl NtfsSecurityHeader {
    pub fn parse(value: &[u8]) -> Result<Self, ParseError> {
        let header = Self {
            hash: le32(value, 0)?,
            security_id: le32(value, 4)?,
            offset: le64(value, 8)?,
            length: le32(value, 16)?,
        };
        if header.security_id == 0
            || !(40..=MAX_SECURITY_DESCRIPTOR_BYTES as u32 + SDS_HEADER_BYTES as u32)
                .contains(&header.length)
            || !header.length.is_multiple_of(4)
            || !header.offset.is_multiple_of(16)
            || header.offset & SDS_COPY_DISTANCE != 0
            || header.offset % SDS_COPY_DISTANCE + u64::from(header.length) > SDS_COPY_DISTANCE
            || header
                .offset
                .checked_add(SDS_COPY_DISTANCE + u64::from(header.length))
                .is_none()
        {
            return Err(invalid("invalid SDS identity, primary offset or length"));
        }
        Ok(header)
    }

    pub fn descriptor<'a>(&self, entry: &'a [u8]) -> Result<&'a [u8], ParseError> {
        if entry.len() as u64 != u64::from(self.length) || Self::parse(entry)? != *self {
            return Err(invalid(
                "SDS entry does not match its security index header",
            ));
        }
        let descriptor = &entry[SDS_HEADER_BYTES..];
        if security_hash(descriptor) != self.hash {
            return Err(invalid("SDS security descriptor hash mismatch"));
        }
        Ok(descriptor)
    }
}

#[derive(Debug, Clone)]
pub struct NtfsSecurityIndexEntry {
    pub header: Option<NtfsSecurityHeader>,
    pub child_vcn: Option<u64>,
}

#[derive(Debug)]
pub struct NtfsSecurityIndexRoot {
    pub block_bytes: u32,
    pub vcn_bytes: u32,
    pub entries: Vec<NtfsSecurityIndexEntry>,
}

impl NtfsSecurityIndexRoot {
    pub fn parse(value: &[u8], cluster_bytes: u32) -> Result<Self, ParseError> {
        if value.len() < 32 || le32(value, 0)? != 0 || le32(value, 4)? != 0x10 {
            return Err(invalid("security index is not ULONG-collated $SII"));
        }
        let block_bytes = le32(value, 8)?;
        if !(512..=65_536).contains(&block_bytes)
            || !block_bytes.is_power_of_two()
            || !(512..=65_536).contains(&cluster_bytes)
            || !cluster_bytes.is_power_of_two()
        {
            return Err(invalid("invalid security index geometry"));
        }
        let vcn_bytes = if block_bytes < cluster_bytes {
            512
        } else {
            cluster_bytes
        };
        if u32::from(value[12]) * vcn_bytes != block_bytes {
            return Err(invalid("security index VBN units disagree with block size"));
        }
        Ok(Self {
            block_bytes,
            vcn_bytes,
            entries: index_entries(value, 16, 32)?,
        })
    }
}

pub fn parse_security_index_block(
    raw: &[u8],
    expected_vcn: u64,
) -> Result<Vec<NtfsSecurityIndexEntry>, ParseError> {
    let value = restore_record(raw, b"INDX")?;
    let usa = usize::from(le16(&value, 4)?);
    let usa_end = usa + usize::from(le16(&value, 6)?) * 2;
    if usa < 40 || le64(&value, 16)? != expected_vcn {
        return Err(invalid("invalid security INDX fixup position or VBN"));
    }
    index_entries(&value, 24, usa_end)
}

fn index_entries(
    value: &[u8],
    header: usize,
    minimum_entry: usize,
) -> Result<Vec<NtfsSecurityIndexEntry>, ParseError> {
    let offset = usize::try_from(le32(value, header)?)
        .map_err(|_| invalid("security index offset overflow"))?;
    let used = usize::try_from(le32(value, header + 4)?)
        .map_err(|_| invalid("security index length overflow"))?;
    let allocated = usize::try_from(le32(value, header + 8)?)
        .map_err(|_| invalid("security index allocation overflow"))?;
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
        return Err(invalid("invalid security index entry boundaries"));
    }
    let end = header + used;
    let mut at = header + offset;
    let mut result = Vec::new();
    let mut previous = None;
    loop {
        if at + 16 > end {
            return Err(invalid("missing security index terminal entry"));
        }
        let length = usize::from(le16(value, at + 8)?);
        let key_length = usize::from(le16(value, at + 10)?);
        let entry_flags = le16(value, at + 12)?;
        let child = entry_flags & 1 != 0;
        let terminal = entry_flags & 2 != 0;
        let child_bytes = if child { 8 } else { 0 };
        if length < 16 + child_bytes
            || !length.is_multiple_of(8)
            || at + length > end
            || entry_flags & !3 != 0
            || child != (flags == 1)
        {
            return Err(invalid(
                "invalid security index entry length or child flags",
            ));
        }
        let child_vcn = if child {
            Some(le64(value, at + length - 8)?)
        } else {
            None
        };
        let security = if terminal {
            if key_length != 0 || at + length != end {
                return Err(invalid("invalid security index terminal key or position"));
            }
            None
        } else {
            let data_offset = usize::from(le16(value, at)?);
            let data_length = usize::from(le16(value, at + 2)?);
            if key_length != 4
                || data_offset < 20
                || data_length != SDS_HEADER_BYTES
                || data_offset + data_length > length - child_bytes
                || le32(value, at + 4)? != 0
            {
                return Err(invalid("invalid $SII key or data boundaries"));
            }
            let security = NtfsSecurityHeader::parse(
                &value[at + data_offset..at + data_offset + data_length],
            )?;
            if le32(value, at + 16)? != security.security_id
                || previous.is_some_and(|old| old >= security.security_id)
            {
                return Err(invalid("mismatched or unordered $SII security identity"));
            }
            previous = Some(security.security_id);
            Some(security)
        };
        result.push(NtfsSecurityIndexEntry {
            header: security,
            child_vcn,
        });
        if terminal {
            return Ok(result);
        }
        at += length;
    }
}

#[cfg(test)]
mod tests;
