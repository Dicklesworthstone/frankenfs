//! Generic NTFS view-index (`attribute_type == 0`) parser and encoder.
//!
//! Shared by `$Secure::$SII` (`0x10` u32 LE), `$Secure::$SDH` (`0x12` `(u32, u32)` LE),
//! `$Extend/$ObjId::$O` (`0x11` raw bytes or `0x13` `[u32; 4]` LE), and
//! `$Extend/$Reparse::$R` (`0x13` `[u32; 3]` LE: `[tag, file_ref_lo, file_ref_hi]`).
//!
//! Layout: Microsoft NTFS `INDEX_ROOT` / `INDEX_BLOCK` (`INDX`) with `attr_type == 0`,
//! where each non-terminal entry stores `(data_offset: u16, data_length: u16, reserved: u32,
//! entry_length: u16, key_length: u16, flags: u16, reserved: u16, key[key_length],
//! data[data_length], optional child_vcn: u64)`.

use std::cmp::Ordering;

use super::{invalid, le16, le32, le64, protect_record, restore_record};
use ffs_types::ParseError;

const SECTOR_BYTES: usize = 512;
pub const COLLATION_U32: u32 = 0x10;
pub const COLLATION_RAW_BYTES: u32 = 0x11;
pub const COLLATION_U32_PAIR: u32 = 0x12;
pub const COLLATION_U32_SLICE: u32 = 0x13;

/// Supported NTFS view-index collation rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewCollation {
    /// `0x10` (`COLLATION_NTOFS_ULONG`): 4-byte little-endian `u32`.
    U32,
    /// `0x11` (`COLLATION_NTOFS_SID` / raw binary): lexicographic byte compare.
    RawBytes,
    /// `0x12` (`COLLATION_NTOFS_SECURITY_HASH`): 8-byte `(u32, u32)` LE pair.
    U32Pair,
    /// `0x13` (`COLLATION_NTOFS_ULONGS`): sequence of 4-byte little-endian `u32` words.
    U32Slice,
}

impl ViewCollation {
    pub fn from_raw(rule: u32) -> Result<Self, ParseError> {
        match rule {
            COLLATION_U32 => Ok(Self::U32),
            COLLATION_RAW_BYTES => Ok(Self::RawBytes),
            COLLATION_U32_PAIR => Ok(Self::U32Pair),
            COLLATION_U32_SLICE => Ok(Self::U32Slice),
            _ => Err(invalid(
                "ntfs.view_index",
                "unsupported view-index collation rule",
            )),
        }
    }

    #[must_use]
    pub const fn to_raw(self) -> u32 {
        match self {
            Self::U32 => COLLATION_U32,
            Self::RawBytes => COLLATION_RAW_BYTES,
            Self::U32Pair => COLLATION_U32_PAIR,
            Self::U32Slice => COLLATION_U32_SLICE,
        }
    }

    pub fn validate_key(self, key: &[u8]) -> Result<(), ParseError> {
        if key.is_empty() || key.len() > 4096 {
            return Err(invalid(
                "ntfs.view_index",
                "view-index key length out of bounds",
            ));
        }
        match self {
            Self::U32 if key.len() != 4 => Err(invalid(
                "ntfs.view_index",
                "u32 collation requires 4-byte key",
            )),
            Self::U32Pair if key.len() != 8 => Err(invalid(
                "ntfs.view_index",
                "u32-pair collation requires 8-byte key",
            )),
            Self::U32Slice if !key.len().is_multiple_of(4) => Err(invalid(
                "ntfs.view_index",
                "u32-slice collation requires 4-byte-aligned key",
            )),
            _ => Ok(()),
        }
    }

    #[must_use]
    pub fn compare_keys(self, left: &[u8], right: &[u8]) -> Ordering {
        match self {
            Self::U32 => {
                let a = left
                    .get(..4)
                    .and_then(|s| s.try_into().ok())
                    .map_or(0, u32::from_le_bytes);
                let b = right
                    .get(..4)
                    .and_then(|s| s.try_into().ok())
                    .map_or(0, u32::from_le_bytes);
                a.cmp(&b).then_with(|| left.cmp(right))
            }
            Self::RawBytes => left.cmp(right),
            Self::U32Pair => {
                let a0 = left
                    .get(..4)
                    .and_then(|s| s.try_into().ok())
                    .map_or(0, u32::from_le_bytes);
                let a1 = left
                    .get(4..8)
                    .and_then(|s| s.try_into().ok())
                    .map_or(0, u32::from_le_bytes);
                let b0 = right
                    .get(..4)
                    .and_then(|s| s.try_into().ok())
                    .map_or(0, u32::from_le_bytes);
                let b1 = right
                    .get(4..8)
                    .and_then(|s| s.try_into().ok())
                    .map_or(0, u32::from_le_bytes);
                (a0, a1).cmp(&(b0, b1)).then_with(|| left.cmp(right))
            }
            Self::U32Slice => {
                let (lc, lrem) = left.as_chunks::<4>();
                let (rc, rrem) = right.as_chunks::<4>();
                for (a, b) in lc.iter().zip(rc.iter()) {
                    let ord = u32::from_le_bytes(*a).cmp(&u32::from_le_bytes(*b));
                    if ord != Ordering::Equal {
                        return ord;
                    }
                }
                lc.len().cmp(&rc.len()).then_with(|| lrem.cmp(rrem))
            }
        }
    }
}

/// One decoded view-index entry. Terminal entries have `key.is_empty() && data.is_empty()`
/// and `is_terminal == true`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewIndexEntry {
    pub key: Vec<u8>,
    pub data: Vec<u8>,
    pub child_vcn: Option<u64>,
    pub is_terminal: bool,
}

/// Parsed view-index `INDEX_ROOT` (`0x90`) attribute payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewIndexRoot {
    pub collation: ViewCollation,
    pub block_bytes: u32,
    pub vcn_bytes: u32,
    pub has_external: bool,
    pub entries: Vec<ViewIndexEntry>,
}

/// Parse a view-index `INDEX_ROOT` (`attr_type == 0`), validating collation,
/// geometry, strict key ordering, and terminal markers.
pub fn parse_view_index_root(
    raw: &[u8],
    cluster_bytes: u32,
    expected_collation: Option<ViewCollation>,
) -> Result<ViewIndexRoot, ParseError> {
    if raw.len() < 32 || le32(raw, 0)? != 0 {
        return Err(invalid(
            "ntfs.view_index",
            "view-index root must declare attribute_type 0",
        ));
    }
    let collation = ViewCollation::from_raw(le32(raw, 4)?)?;
    if let Some(exp) = expected_collation
        && collation != exp
    {
        return Err(invalid(
            "ntfs.view_index",
            "view-index collation rule disagrees with expected schema",
        ));
    }
    let block_bytes = le32(raw, 8)?;
    if !(512..=65_536).contains(&block_bytes)
        || !block_bytes.is_power_of_two()
        || !(512..=65_536).contains(&cluster_bytes)
        || !cluster_bytes.is_power_of_two()
    {
        return Err(invalid("ntfs.view_index", "invalid view-index geometry"));
    }
    let vcn_bytes = if block_bytes < cluster_bytes {
        512
    } else {
        cluster_bytes
    };
    if u32::from(raw[12]) * vcn_bytes != block_bytes {
        return Err(invalid(
            "ntfs.view_index",
            "view-index VBN units disagree with block size",
        ));
    }
    let (has_external, entries) = parse_view_entries(raw, 16, 32, collation)?;
    Ok(ViewIndexRoot {
        collation,
        block_bytes,
        vcn_bytes,
        has_external,
        entries,
    })
}

/// Parse one USA-protected external view-index `INDX` block at `expected_vcn`.
pub fn parse_view_index_block(
    raw: &[u8],
    expected_vcn: u64,
    collation: ViewCollation,
) -> Result<(bool, Vec<ViewIndexEntry>), ParseError> {
    let restored = restore_record(raw, b"INDX")?;
    let usa = usize::from(le16(&restored, 4)?);
    let usa_end = usa + usize::from(le16(&restored, 6)?) * 2;
    if usa < 40 || le64(&restored, 16)? != expected_vcn {
        return Err(invalid(
            "ntfs.view_index",
            "invalid view-index INDX fixup position or VBN",
        ));
    }
    parse_view_entries(&restored, 24, usa_end, collation)
}

fn parse_view_entries(
    raw: &[u8],
    header: usize,
    minimum_entry: usize,
    collation: ViewCollation,
) -> Result<(bool, Vec<ViewIndexEntry>), ParseError> {
    let offset = usize::try_from(le32(raw, header)?)
        .map_err(|_| invalid("ntfs.view_index", "entries offset overflow"))?;
    let used = usize::try_from(le32(raw, header + 4)?)
        .map_err(|_| invalid("ntfs.view_index", "entries used overflow"))?;
    let allocated = usize::try_from(le32(raw, header + 8)?)
        .map_err(|_| invalid("ntfs.view_index", "entries allocated overflow"))?;
    let flags = le32(raw, header + 12)?;
    if offset < 16
        || !offset.is_multiple_of(8)
        || !used.is_multiple_of(8)
        || used > allocated
        || allocated > raw.len().saturating_sub(header)
        || offset
            .checked_add(header)
            .is_none_or(|start| start < minimum_entry)
        || offset.checked_add(16).is_none_or(|end| end > used)
        || flags > 1
    {
        return Err(invalid(
            "ntfs.view_index",
            "invalid view-index header boundaries",
        ));
    }
    let has_children = flags == 1;
    let end = header + used;
    let mut at = header + offset;
    let mut entries = Vec::new();
    let mut prev_key: Option<Vec<u8>> = None;

    loop {
        if at + 16 > end {
            return Err(invalid(
                "ntfs.view_index",
                "missing view-index terminal entry",
            ));
        }
        let length = usize::from(le16(raw, at + 8)?);
        let key_length = usize::from(le16(raw, at + 10)?);
        let entry_flags = le16(raw, at + 12)?;
        let child = entry_flags & 1 != 0;
        let terminal = entry_flags & 2 != 0;
        let child_bytes = if child { 8 } else { 0 };
        if length < 16 + child_bytes
            || !length.is_multiple_of(8)
            || at + length > end
            || entry_flags & !3 != 0
            || child != has_children
        {
            return Err(invalid(
                "ntfs.view_index",
                "invalid view-index entry length or child flag",
            ));
        }
        let child_vcn = if child {
            Some(le64(raw, at + length - 8)?)
        } else {
            None
        };
        if terminal {
            if key_length != 0 || at + length != end {
                return Err(invalid(
                    "ntfs.view_index",
                    "invalid view-index terminal entry position or key",
                ));
            }
            entries.push(ViewIndexEntry {
                key: Vec::new(),
                data: Vec::new(),
                child_vcn,
                is_terminal: true,
            });
            return Ok((has_children, entries));
        }
        let data_offset = usize::from(le16(raw, at)?);
        let data_length = usize::from(le16(raw, at + 2)?);
        if le32(raw, at + 4)? != 0
            || 16 + key_length > length - child_bytes
            || (data_length > 0
                && (data_offset < 16 + key_length
                    || data_offset + data_length > length - child_bytes))
        {
            return Err(invalid(
                "ntfs.view_index",
                "invalid view-index key or data bounds",
            ));
        }
        let key = raw[at + 16..at + 16 + key_length].to_vec();
        collation.validate_key(&key)?;
        if let Some(prev) = &prev_key
            && collation.compare_keys(prev, &key) != Ordering::Less
        {
            return Err(invalid(
                "ntfs.view_index",
                "view-index keys are not strictly ascending",
            ));
        }
        prev_key = Some(key.clone());
        let data = if data_length == 0 {
            Vec::new()
        } else {
            raw[at + data_offset..at + data_offset + data_length].to_vec()
        };
        entries.push(ViewIndexEntry {
            key,
            data,
            child_vcn,
            is_terminal: false,
        });
        at += length;
    }
}

/// Encode one non-terminal view-index entry (8-byte aligned), placing `data`
/// immediately after `key` (or `data_offset = 16 + key.len()` when `data.is_empty()`).
pub fn encode_view_index_entry(
    key: &[u8],
    data: &[u8],
    child_vcn: Option<u64>,
    collation: ViewCollation,
) -> Result<Vec<u8>, ParseError> {
    collation.validate_key(key)?;
    if data.len() > 4096 {
        return Err(invalid("ntfs.view_index", "view-index data exceeds 4 KiB"));
    }
    let data_offset = 16 + key.len();
    let child_bytes = if child_vcn.is_some() { 8 } else { 0 };
    let total_len = (data_offset + data.len() + child_bytes).next_multiple_of(8);
    let total_u16 = u16::try_from(total_len)
        .map_err(|_| invalid("ntfs.view_index", "view-index entry length overflow"))?;
    let key_u16 = u16::try_from(key.len())
        .map_err(|_| invalid("ntfs.view_index", "view-index key length overflow"))?;
    let data_off_u16 = u16::try_from(data_offset)
        .map_err(|_| invalid("ntfs.view_index", "view-index data offset overflow"))?;
    let data_len_u16 = u16::try_from(data.len())
        .map_err(|_| invalid("ntfs.view_index", "view-index data length overflow"))?;
    let mut buf = vec![0_u8; total_len];
    buf[0..2].copy_from_slice(&data_off_u16.to_le_bytes());
    buf[2..4].copy_from_slice(&data_len_u16.to_le_bytes());
    buf[8..10].copy_from_slice(&total_u16.to_le_bytes());
    buf[10..12].copy_from_slice(&key_u16.to_le_bytes());
    let flags: u16 = u16::from(child_vcn.is_some());
    buf[12..14].copy_from_slice(&flags.to_le_bytes());
    buf[16..16 + key.len()].copy_from_slice(key);
    if !data.is_empty() {
        buf[data_offset..data_offset + data.len()].copy_from_slice(data);
    }
    if let Some(vcn) = child_vcn {
        buf[total_len - 8..total_len].copy_from_slice(&vcn.to_le_bytes());
    }
    Ok(buf)
}

/// Encode a resident view-index `INDEX_ROOT` (`SMALL_INDEX` when `terminal_child_vcn == None`,
/// `LARGE_INDEX` when `Some(vcn)`), round-trip validated via [`parse_view_index_root`].
pub fn encode_view_index_root(
    collation: ViewCollation,
    block_bytes: u32,
    cluster_bytes: u32,
    encoded_entries: &[Vec<u8>],
    terminal_child_vcn: Option<u64>,
) -> Result<Vec<u8>, ParseError> {
    if !(512..=65_536).contains(&block_bytes)
        || !block_bytes.is_power_of_two()
        || !(512..=65_536).contains(&cluster_bytes)
        || !cluster_bytes.is_power_of_two()
    {
        return Err(invalid("ntfs.view_index", "invalid view-index geometry"));
    }
    let vcn_bytes = if block_bytes < cluster_bytes {
        512
    } else {
        cluster_bytes
    };
    let units = u8::try_from(block_bytes / vcn_bytes)
        .map_err(|_| invalid("ntfs.view_index", "view-index VBN units overflow"))?;
    let payload_len: usize = encoded_entries.iter().map(Vec::len).sum();
    let term_len: u16 = if terminal_child_vcn.is_some() { 24 } else { 16 };
    let hdr_used = 16 + payload_len + usize::from(term_len);
    let used_u32 = u32::try_from(hdr_used)
        .map_err(|_| invalid("ntfs.view_index", "view-index root size overflow"))?;
    let mut root = vec![0_u8; 16 + hdr_used];
    root[0..4].copy_from_slice(&0_u32.to_le_bytes());
    root[4..8].copy_from_slice(&collation.to_raw().to_le_bytes());
    root[8..12].copy_from_slice(&block_bytes.to_le_bytes());
    root[12] = units;
    root[16..20].copy_from_slice(&16_u32.to_le_bytes());
    root[20..24].copy_from_slice(&used_u32.to_le_bytes());
    root[24..28].copy_from_slice(&used_u32.to_le_bytes());
    let root_flags: u32 = u32::from(terminal_child_vcn.is_some());
    root[28..32].copy_from_slice(&root_flags.to_le_bytes());
    let mut pos = 32_usize;
    for ent in encoded_entries {
        root[pos..pos + ent.len()].copy_from_slice(ent);
        pos += ent.len();
    }
    root[pos + 8..pos + 10].copy_from_slice(&term_len.to_le_bytes());
    let term_flags: u16 = if terminal_child_vcn.is_some() { 3 } else { 2 };
    root[pos + 12..pos + 14].copy_from_slice(&term_flags.to_le_bytes());
    if let Some(vcn) = terminal_child_vcn {
        root[pos + 16..pos + 24].copy_from_slice(&vcn.to_le_bytes());
    }
    let _ = parse_view_index_root(&root, cluster_bytes, Some(collation))?;
    Ok(root)
}

/// Encode one USA-protected view-index `INDX` block (`block_bytes` long) at `vcn`,
/// round-trip validated via [`parse_view_index_block`].
pub fn encode_view_index_block(
    collation: ViewCollation,
    block_bytes: u32,
    vcn: u64,
    encoded_entries: &[Vec<u8>],
    terminal_child_vcn: Option<u64>,
) -> Result<Vec<u8>, ParseError> {
    let len = usize::try_from(block_bytes)
        .map_err(|_| invalid("ntfs.view_index", "view-index block_bytes overflow"))?;
    if !(512..=65_536).contains(&len) || !len.is_power_of_two() {
        return Err(invalid("ntfs.view_index", "invalid INDX block size"));
    }
    let usa_offset: u16 = 40;
    let usa_count = u16::try_from(len / SECTOR_BYTES + 1)
        .map_err(|_| invalid("ntfs.view_index", "INDX USA count overflow"))?;
    let raw_entries_off =
        (usize::from(usa_offset) + usize::from(usa_count) * 2).next_multiple_of(8);
    let rel_entries_off = raw_entries_off - 24;
    let allocated = len - 24;
    let payload_len: usize = encoded_entries.iter().map(Vec::len).sum();
    let term_len: u16 = if terminal_child_vcn.is_some() { 24 } else { 16 };
    let used = rel_entries_off + payload_len + usize::from(term_len);
    if used > allocated {
        return Err(invalid(
            "ntfs.view_index",
            "view-index entries overflow INDX block capacity",
        ));
    }
    let rel_entries_u32 = u32::try_from(rel_entries_off)
        .map_err(|_| invalid("ntfs.view_index", "INDX entries offset overflow"))?;
    let used_u32 =
        u32::try_from(used).map_err(|_| invalid("ntfs.view_index", "INDX used size overflow"))?;
    let allocated_u32 = u32::try_from(allocated)
        .map_err(|_| invalid("ntfs.view_index", "INDX allocated size overflow"))?;
    let mut buf = vec![0_u8; len];
    buf[0..4].copy_from_slice(b"INDX");
    buf[4..6].copy_from_slice(&usa_offset.to_le_bytes());
    buf[6..8].copy_from_slice(&usa_count.to_le_bytes());
    buf[16..24].copy_from_slice(&vcn.to_le_bytes());
    buf[24..28].copy_from_slice(&rel_entries_u32.to_le_bytes());
    buf[28..32].copy_from_slice(&used_u32.to_le_bytes());
    buf[32..36].copy_from_slice(&allocated_u32.to_le_bytes());
    let node_flags: u32 = u32::from(terminal_child_vcn.is_some());
    buf[36..40].copy_from_slice(&node_flags.to_le_bytes());

    let mut pos = raw_entries_off;
    for ent in encoded_entries {
        buf[pos..pos + ent.len()].copy_from_slice(ent);
        pos += ent.len();
    }
    buf[pos + 8..pos + 10].copy_from_slice(&term_len.to_le_bytes());
    let term_flags: u16 = if terminal_child_vcn.is_some() { 3 } else { 2 };
    buf[pos + 12..pos + 14].copy_from_slice(&term_flags.to_le_bytes());
    if let Some(child_vcn) = terminal_child_vcn {
        buf[pos + 16..pos + 24].copy_from_slice(&child_vcn.to_le_bytes());
    }
    // Seed USA token = 1 before applying multi-sector fixups.
    buf[usize::from(usa_offset)..usize::from(usa_offset) + 2].copy_from_slice(&1_u16.to_le_bytes());
    let protected = protect_record(&buf)?;
    let _ = parse_view_index_block(&protected, vcn, collation)?;
    Ok(protected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn view_index_roundtrips_all_four_collation_rules_and_rejects_misordered_keys() {
        // 1. $Reparse::$R (0x13 U32Slice, 12B key, empty data)
        let mut k1 = Vec::new();
        k1.extend_from_slice(&0x8000_0017_u32.to_le_bytes());
        k1.extend_from_slice(&0x0001_0000_0000_0024_u64.to_le_bytes());
        let mut k2 = Vec::new();
        k2.extend_from_slice(&0xA000_000C_u32.to_le_bytes());
        k2.extend_from_slice(&0x0001_0000_0000_0025_u64.to_le_bytes());
        let e1 = encode_view_index_entry(&k1, &[], None, ViewCollation::U32Slice).unwrap();
        let e2 = encode_view_index_entry(&k2, &[], None, ViewCollation::U32Slice).unwrap();
        let root = encode_view_index_root(
            ViewCollation::U32Slice,
            4096,
            4096,
            &[e1.clone(), e2.clone()],
            None,
        )
        .unwrap();
        let parsed = parse_view_index_root(&root, 4096, Some(ViewCollation::U32Slice)).unwrap();
        assert!(!parsed.has_external);
        assert_eq!(parsed.entries.len(), 3);
        assert_eq!(parsed.entries[0].key, k1);
        assert_eq!(parsed.entries[0].data, [] as [u8; 0]);
        assert_eq!(parsed.entries[1].key, k2);
        assert!(parsed.entries[2].is_terminal);

        // Misordered keys fail validation.
        assert!(
            encode_view_index_root(ViewCollation::U32Slice, 4096, 4096, &[e2, e1], None).is_err()
        );

        // 2. External INDX block with $ObjId::$O (0x11 RawBytes, 16B key, 56B data).
        let oid_a = [0x11_u8; 16];
        let oid_b = [0x22_u8; 16];
        let data_a = [0xAA_u8; 56];
        let data_b = [0xBB_u8; 56];
        let oe1 = encode_view_index_entry(&oid_a, &data_a, None, ViewCollation::RawBytes).unwrap();
        let oe2 = encode_view_index_entry(&oid_b, &data_b, None, ViewCollation::RawBytes).unwrap();
        let block =
            encode_view_index_block(ViewCollation::RawBytes, 4096, 0, &[oe1, oe2], None).unwrap();
        let (has_children, parsed_blk) =
            parse_view_index_block(&block, 0, ViewCollation::RawBytes).unwrap();
        assert!(!has_children);
        assert_eq!(parsed_blk.len(), 3);
        assert_eq!(parsed_blk[0].key, oid_a);
        assert_eq!(parsed_blk[0].data, data_a);
        assert_eq!(parsed_blk[1].key, oid_b);
        assert_eq!(parsed_blk[1].data, data_b);
        assert!(parse_view_index_block(&block, 1, ViewCollation::RawBytes).is_err());

        // 3. $SII (0x10 U32) & $SDH (0x12 U32Pair) ordering.
        assert_eq!(
            ViewCollation::U32.compare_keys(&256_u32.to_le_bytes(), &257_u32.to_le_bytes()),
            Ordering::Less
        );
        let mut p1 = Vec::new();
        p1.extend_from_slice(&0x0000_0010_u32.to_le_bytes());
        p1.extend_from_slice(&256_u32.to_le_bytes());
        let mut p2 = Vec::new();
        p2.extend_from_slice(&0x0000_0010_u32.to_le_bytes());
        p2.extend_from_slice(&257_u32.to_le_bytes());
        assert_eq!(
            ViewCollation::U32Pair.compare_keys(&p1, &p2),
            Ordering::Less
        );
    }
}
