//! Native NTFS security descriptors, $SII/$SDH index records and $SDS headers.
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

/// Native security-index collation. Hash collisions are ordered by security ID,
/// not treated as duplicate descriptors or compared as little-endian bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtfsSecurityIndexKind {
    SecurityId,
    SecurityHash,
}

impl NtfsSecurityIndexKind {
    #[must_use]
    pub fn key(self, header: NtfsSecurityHeader) -> (u32, u32) {
        match self {
            Self::SecurityId => (header.security_id, 0),
            Self::SecurityHash => (header.hash, header.security_id),
        }
    }
}

impl NtfsSecurityIndexRoot {
    pub fn parse(value: &[u8], cluster_bytes: u32) -> Result<Self, ParseError> {
        Self::parse_with_kind(value, cluster_bytes, NtfsSecurityIndexKind::SecurityId)
    }

    pub fn parse_with_kind(
        value: &[u8],
        cluster_bytes: u32,
        kind: NtfsSecurityIndexKind,
    ) -> Result<Self, ParseError> {
        let collation = match kind {
            NtfsSecurityIndexKind::SecurityId => 0x10,
            NtfsSecurityIndexKind::SecurityHash => 0x12,
        };
        if value.len() < 32 || le32(value, 0)? != 0 || le32(value, 4)? != collation {
            return Err(invalid("security index has the wrong native collation"));
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
            entries: index_entries(value, 16, 32, kind)?,
        })
    }
}

pub fn parse_security_index_block(
    raw: &[u8],
    expected_vcn: u64,
) -> Result<Vec<NtfsSecurityIndexEntry>, ParseError> {
    parse_security_index_block_with_kind(raw, expected_vcn, NtfsSecurityIndexKind::SecurityId)
}

pub fn parse_security_index_block_with_kind(
    raw: &[u8],
    expected_vcn: u64,
    kind: NtfsSecurityIndexKind,
) -> Result<Vec<NtfsSecurityIndexEntry>, ParseError> {
    let value = restore_record(raw, b"INDX")?;
    let usa = usize::from(le16(&value, 4)?);
    let usa_end = usa + usize::from(le16(&value, 6)?) * 2;
    if usa < 40 || le64(&value, 16)? != expected_vcn {
        return Err(invalid("invalid security INDX fixup position or VBN"));
    }
    index_entries(&value, 24, usa_end, kind)
}

fn index_entries(
    value: &[u8],
    header: usize,
    minimum_entry: usize,
    kind: NtfsSecurityIndexKind,
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
            let expected_key_length = match kind {
                NtfsSecurityIndexKind::SecurityId => 4,
                NtfsSecurityIndexKind::SecurityHash => 8,
            };
            if key_length != expected_key_length
                || data_offset < 16 + expected_key_length
                || data_length != SDS_HEADER_BYTES
                || data_offset + data_length > length - child_bytes
                || le32(value, at + 4)? != 0
            {
                return Err(invalid("invalid security-index key or data boundaries"));
            }
            let security = NtfsSecurityHeader::parse(
                &value[at + data_offset..at + data_offset + data_length],
            )?;
            let key = match kind {
                NtfsSecurityIndexKind::SecurityId => (le32(value, at + 16)?, 0),
                NtfsSecurityIndexKind::SecurityHash => {
                    (le32(value, at + 16)?, le32(value, at + 20)?)
                }
            };
            if key != kind.key(security) || previous.is_some_and(|old| old >= key) {
                return Err(invalid("mismatched or unordered security-index identity"));
            }
            previous = Some(key);
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

/// Build a canonical MS-DTYP self-relative security descriptor for freshly
/// formatted NTFS volumes (Owner `S-1-5-32-544` Administrators, Group `S-1-5-18`
/// SYSTEM, DACL granting full control `0x001F_01FF` to SYSTEM and Administrators).
#[must_use]
pub fn build_default_ntfs_security_descriptor() -> Vec<u8> {
    // S-1-5-32-544 (BUILTIN\Administrators): 16 bytes
    const OWNER_SID: [u8; 16] = [
        0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00,
        0x00,
    ];
    // S-1-5-18 (NT AUTHORITY\SYSTEM): 12 bytes
    const GROUP_SID: [u8; 12] = [
        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
    ];
    // DACL: 8B header + 20B SYSTEM ACE + 24B Administrators ACE = 52 bytes
    let mut dacl = Vec::with_capacity(52);
    dacl.extend_from_slice(&[0x02, 0x00]); // revision 2, sbz1
    dacl.extend_from_slice(&52_u16.to_le_bytes()); // AclSize
    dacl.extend_from_slice(&2_u16.to_le_bytes()); // AceCount
    dacl.extend_from_slice(&0_u16.to_le_bytes()); // sbz2
    // ACE 1: ACCESS_ALLOWED (0), flags OBJECT_INHERIT | CONTAINER_INHERIT (0x03), size 20
    dacl.extend_from_slice(&[0x00, 0x03]);
    dacl.extend_from_slice(&20_u16.to_le_bytes());
    dacl.extend_from_slice(&0x001F_01FF_u32.to_le_bytes());
    dacl.extend_from_slice(&GROUP_SID);
    // ACE 2: ACCESS_ALLOWED (0), flags OBJECT_INHERIT | CONTAINER_INHERIT (0x03), size 24
    dacl.extend_from_slice(&[0x00, 0x03]);
    dacl.extend_from_slice(&24_u16.to_le_bytes());
    dacl.extend_from_slice(&0x001F_01FF_u32.to_le_bytes());
    dacl.extend_from_slice(&OWNER_SID);

    // Self-relative header (20B) + DACL (52B @ 20) + Owner SID (16B @ 72) + Group SID (12B @ 88) = 100B
    let mut sd = Vec::with_capacity(100);
    sd.extend_from_slice(&[0x01, 0x00]); // revision 1, sbz1
    // SE_SELF_RELATIVE (0x8000) | SE_DACL_PRESENT (0x0004)
    sd.extend_from_slice(&0x8004_u16.to_le_bytes());
    sd.extend_from_slice(&72_u32.to_le_bytes()); // owner_offset
    sd.extend_from_slice(&88_u32.to_le_bytes()); // group_offset
    sd.extend_from_slice(&0_u32.to_le_bytes()); // sacl_offset
    sd.extend_from_slice(&20_u32.to_le_bytes()); // dacl_offset
    sd.extend_from_slice(&dacl);
    sd.extend_from_slice(&OWNER_SID);
    sd.extend_from_slice(&GROUP_SID);
    sd
}

/// Encode primary and `+256 KiB` mirror copies of a `$Secure:$SDS` stream along
/// with their validated [`NtfsSecurityHeader`] descriptors.
///
/// # Errors
/// Returns [`ParseError`] if any descriptor fails validation, has `security_id == 0`,
/// or overflows the single `256 KiB` `$SDS` stripe window.
pub fn encode_sds_stream(
    entries: &[(u32, &[u8])],
) -> Result<(Vec<u8>, Vec<NtfsSecurityHeader>), ParseError> {
    if entries.is_empty() {
        return Err(invalid("SDS stream requires at least one descriptor"));
    }
    let mut primary = Vec::new();
    let mut headers = Vec::with_capacity(entries.len());
    for &(security_id, desc) in entries {
        if security_id == 0 {
            return Err(invalid("SDS security_id must be nonzero"));
        }
        NtfsSecurityDescriptor::parse(desc)?;
        let padded_desc_len = desc.len().next_multiple_of(4);
        let mut padded_desc = desc.to_vec();
        padded_desc.resize(padded_desc_len, 0);
        let total_len = SDS_HEADER_BYTES
            .checked_add(padded_desc_len)
            .ok_or_else(|| invalid("SDS entry length overflow"))?;
        let offset = u64::try_from(primary.len()).map_err(|_| invalid("SDS offset overflow"))?;
        let length =
            u32::try_from(total_len).map_err(|_| invalid("SDS entry length exceeds u32"))?;
        let hash = security_hash(&padded_desc);
        let header = NtfsSecurityHeader {
            hash,
            security_id,
            offset,
            length,
        };
        let mut encoded = Vec::with_capacity(total_len);
        encoded.extend_from_slice(&hash.to_le_bytes());
        encoded.extend_from_slice(&security_id.to_le_bytes());
        encoded.extend_from_slice(&offset.to_le_bytes());
        encoded.extend_from_slice(&length.to_le_bytes());
        encoded.extend_from_slice(&padded_desc);
        header.descriptor(&encoded)?;
        primary.extend_from_slice(&encoded);
        let aligned = primary.len().next_multiple_of(16);
        primary.resize(aligned, 0);
        if u64::try_from(primary.len()).is_ok_and(|len| len > SDS_COPY_DISTANCE) {
            return Err(invalid("SDS entries exceed single 256 KiB mirror stripe"));
        }
        headers.push(header);
    }

    let copy_dist =
        usize::try_from(SDS_COPY_DISTANCE).map_err(|_| invalid("SDS copy distance overflow"))?;
    let mut full = vec![0_u8; copy_dist + primary.len()];
    full[..primary.len()].copy_from_slice(&primary);
    full[copy_dist..copy_dist + primary.len()].copy_from_slice(&primary);
    Ok((full, headers))
}

/// Encode a resident `$SII` or `$SDH` `INDEX_ROOT` payload sorted by native key
/// order and verify it via [`NtfsSecurityIndexRoot::parse_with_kind`].
///
/// # Errors
/// Returns [`ParseError`] if geometry is invalid, headers contain duplicate keys,
/// or round-trip parsing fails.
pub fn encode_security_index_root(
    kind: NtfsSecurityIndexKind,
    headers: &[NtfsSecurityHeader],
    index_bytes: u32,
    cluster_bytes: u32,
) -> Result<Vec<u8>, ParseError> {
    if !(512..=65_536).contains(&index_bytes)
        || !index_bytes.is_power_of_two()
        || !(512..=65_536).contains(&cluster_bytes)
        || !cluster_bytes.is_power_of_two()
    {
        return Err(invalid("invalid security index geometry"));
    }
    let vcn_bytes = if index_bytes < cluster_bytes {
        512
    } else {
        cluster_bytes
    };
    let blocks_per_index = u8::try_from(index_bytes / vcn_bytes)
        .map_err(|_| invalid("security index VBN unit count overflow"))?;
    let collation: u32 = match kind {
        NtfsSecurityIndexKind::SecurityId => 0x10,
        NtfsSecurityIndexKind::SecurityHash => 0x12,
    };

    let mut sorted = headers.to_vec();
    sorted.sort_by_key(|h| kind.key(*h));

    let mut entries_bytes = Vec::new();
    for h in &sorted {
        let (key_bytes, data_offset, entry_len): (Vec<u8>, u16, u16) = match kind {
            NtfsSecurityIndexKind::SecurityId => {
                // 16B header + 4B key = 20, data at 20 (20B SDS header) => 40B (8-aligned)
                (h.security_id.to_le_bytes().to_vec(), 20, 40)
            }
            NtfsSecurityIndexKind::SecurityHash => {
                // 16B header + 8B key = 24, data at 24 (20B SDS header) => 44B -> 48B (8-aligned)
                let mut key = Vec::with_capacity(8);
                key.extend_from_slice(&h.hash.to_le_bytes());
                key.extend_from_slice(&h.security_id.to_le_bytes());
                (key, 24, 48)
            }
        };
        let key_len = u16::try_from(key_bytes.len())
            .map_err(|_| invalid("security index key length overflow"))?;
        let sds_len =
            u16::try_from(SDS_HEADER_BYTES).map_err(|_| invalid("SDS header length overflow"))?;
        let mut entry = vec![0_u8; usize::from(entry_len)];
        entry[0..2].copy_from_slice(&data_offset.to_le_bytes());
        entry[2..4].copy_from_slice(&sds_len.to_le_bytes());
        entry[8..10].copy_from_slice(&entry_len.to_le_bytes());
        entry[10..12].copy_from_slice(&key_len.to_le_bytes());
        entry[12..14].copy_from_slice(&0_u16.to_le_bytes()); // leaf entry flags = 0
        entry[16..16 + key_bytes.len()].copy_from_slice(&key_bytes);
        let d_off = usize::from(data_offset);
        entry[d_off..d_off + 4].copy_from_slice(&h.hash.to_le_bytes());
        entry[d_off + 4..d_off + 8].copy_from_slice(&h.security_id.to_le_bytes());
        entry[d_off + 8..d_off + 16].copy_from_slice(&h.offset.to_le_bytes());
        entry[d_off + 16..d_off + 20].copy_from_slice(&h.length.to_le_bytes());
        entries_bytes.extend_from_slice(&entry);
    }
    // Terminal leaf entry: 16 bytes, length=16, key_len=0, flags=2 (END).
    let mut term = [0_u8; 16];
    term[8..10].copy_from_slice(&16_u16.to_le_bytes());
    term[12..14].copy_from_slice(&2_u16.to_le_bytes());
    entries_bytes.extend_from_slice(&term);

    let used = u32::try_from(16 + entries_bytes.len())
        .map_err(|_| invalid("security index root size overflow"))?;
    let mut root = Vec::with_capacity(16 + usize::try_from(used).unwrap_or(0));
    root.extend_from_slice(&0_u32.to_le_bytes()); // attribute_type = 0 (view index)
    root.extend_from_slice(&collation.to_le_bytes());
    root.extend_from_slice(&index_bytes.to_le_bytes());
    root.push(blocks_per_index);
    root.extend_from_slice(&[0_u8; 3]);
    // INDEX_HEADER at offset 16: entries_offset=16, used, allocated=used, flags=0 (small)
    root.extend_from_slice(&16_u32.to_le_bytes());
    root.extend_from_slice(&used.to_le_bytes());
    root.extend_from_slice(&used.to_le_bytes());
    root.extend_from_slice(&0_u32.to_le_bytes());
    root.extend_from_slice(&entries_bytes);

    // Round-trip verify with the crate's own parser.
    let parsed = NtfsSecurityIndexRoot::parse_with_kind(&root, cluster_bytes, kind)?;
    if parsed.entries.len() != sorted.len() + 1 {
        return Err(invalid("encoded security index root round-trip mismatch"));
    }
    Ok(root)
}

#[cfg(test)]
mod tests;
