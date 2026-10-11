//! Naming-policy admission for native snapshot maps. OpenZFS creates them with
//! U8_TEXTPREP_TOUPPER (2), even for a case-sensitive filesystem. The ASCII subset
//! has a version-independent normalization; non-ASCII normalized keys still need
//! the native Unicode tables. Never replace stored spelling or merge case pairs.

use super::{Endian, MICRO_TAG, ParseError, invalid, u16_at, u32_at};
use crate::zfs_dmu::{ZapEntry, microzap};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamePolicy {
    /// Existing generic metadata and ZPL naming admission stays unchanged.
    Unnormalized,
    /// Also admit TOUPPER-only maps, but only with ASCII stored keys.
    AsciiUppercase,
}

impl NamePolicy {
    pub(super) fn uppercase(self, flags: u64) -> Result<bool, ParseError> {
        match (self, flags) {
            (_, 0) => Ok(false),
            (Self::AsciiUppercase, 2) => Ok(true),
            _ => Err(invalid("unsupported ZAP normalization policy")),
        }
    }
}

/// Normalized micro-ZAP records have the same scalar/byte layout as ordinary
/// records but no stored per-entry hash. Validate policy and the complete key
/// repertoire before returning them. The original decoder is unchanged.
pub fn microzap_with_names(
    raw: &[u8],
    order: Endian,
    policy: NamePolicy,
) -> Result<Vec<ZapEntry>, ParseError> {
    if !(512..=131_072).contains(&raw.len())
        || !raw.len().is_multiple_of(512)
        || order.u64(raw, 0)? != MICRO_TAG
    {
        return Err(invalid("not an admitted micro-ZAP block"));
    }
    if !policy.uppercase(order.u64(raw, 16)?)? {
        return microzap(raw, order);
    }
    let mut names = BTreeSet::new();
    let mut entries = Vec::new();
    for record in raw[64..].as_chunks::<64>().0 {
        if record[14] == 0 {
            continue;
        }
        let length = record[14..]
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| invalid("unterminated normalized micro-ZAP name"))?;
        let name = &record[14..14 + length];
        if !name.is_ascii() || u16_at(record, 12, order)? != 0 {
            return Err(invalid("unsupported normalized micro-ZAP name or padding"));
        }
        if !names.insert(name.to_vec()) {
            return Err(invalid("duplicate normalized micro-ZAP stored name"));
        }
        entries.push(ZapEntry {
            name: name.to_vec(),
            value: order.u64(record, 0)?,
            collision: u32_at(record, 8, order)?,
        });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests;
