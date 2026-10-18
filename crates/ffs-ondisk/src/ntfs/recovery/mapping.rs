//! Native UpdateMappingPairs on a private FILE record.
//!
//! The log supplies a suffix beginning at an attribute-relative byte offset,
//! not a complete replacement attribute or a list of absolute clusters. Keep
//! the prefix, resize the attribute, and recompute highest VCN from the complete
//! resulting mapping. Size fields are changed by the separate SetSizes opcode.

use super::{NtfsAttribute, NtfsValue, ParseError, bad, le16, le32, put32, resize_attribute};
use crate::ntfs::{COMPRESSED, SPARSE, decode_mapping_pairs};

/// Count VCN coverage before calling the ordinary checked runlist decoder.
/// This does not trust the old highest VCN, which is precisely the field this
/// operation changes. LCN decoding and volume bounds remain in the shared
/// parser. The scan is bounded by the FILE record, not a native length claim.
fn highest_vcn(pairs: &[u8], first: u64) -> Result<u64, ParseError> {
    if first > i64::MAX as u64 {
        return Err(bad("negative lowest VCN in mapping-pairs update"));
    }
    let mut remaining = pairs;
    let mut end = first;
    loop {
        let (&header, tail) = remaining
            .split_first()
            .ok_or_else(|| bad("updated mapping pairs have no terminator"))?;
        if header == 0 {
            // Native empty nonresident DATA uses lowest=0, highest=-1.
            // An empty continuation would fabricate coverage for an extent.
            if end == first && first != 0 {
                return Err(bad("empty mapping-pairs continuation"));
            }
            return Ok(end.checked_sub(1).unwrap_or(u64::MAX));
        }
        let length_width = usize::from(header & 15);
        let delta_width = usize::from(header >> 4);
        if !(1..=8).contains(&length_width) || delta_width > 8 {
            return Err(bad("invalid updated mapping-pair widths"));
        }
        let width = length_width + delta_width;
        let pair = tail
            .get(..width)
            .ok_or_else(|| bad("truncated updated mapping pair"))?;
        let mut word = [0; 8];
        word[..length_width].copy_from_slice(&pair[..length_width]);
        let length = u64::from_le_bytes(word);
        if length == 0 || length > i64::MAX as u64 {
            return Err(bad("invalid updated mapping-pair length"));
        }
        end = end
            .checked_add(length)
            .filter(|end| *end <= (i64::MAX as u64) + 1)
            .ok_or_else(|| bad("updated VCN coverage overflows"))?;
        remaining = &tail[width..];
    }
}

pub(super) fn edit(
    data: &mut [u8],
    at: usize,
    size: usize,
    relative: usize,
    payload: &[u8],
    volume_clusters: u64,
) -> Result<(), ParseError> {
    if volume_clusters == 0 || volume_clusters > i64::MAX as u64 {
        return Err(bad("invalid mapping-pairs volume bound"));
    }
    let attr = NtfsAttribute::parse(&data[at..at + size], le32(data, at)?)?;
    let NtfsValue::NonResident(value) = attr.value else {
        return Err(bad("mapping-pairs update targets a resident attribute"));
    };
    let first = value.first_vcn;
    let sparse_allowed = attr.flags & (SPARSE | COMPRESSED) != 0;
    let mapping_at = usize::from(le16(data, at + 32)?);
    if relative < mapping_at || relative > size || payload.is_empty() {
        return Err(bad("mapping-pairs suffix has an invalid offset or is empty"));
    }
    let end = relative
        .checked_add(payload.len())
        .ok_or_else(|| bad("mapping-pairs suffix length overflows"))?;
    let new_size = end
        .checked_add(7)
        .map(|length| length & !7)
        .ok_or_else(|| bad("mapping-pairs alignment overflows"))?;
    let used = usize::try_from(le32(data, 24)?).map_err(|_| bad("used size overflow"))?;
    if used
        .checked_sub(size)
        .and_then(|length| length.checked_add(new_size))
        .is_none_or(|length| length > data.len())
    {
        return Err(bad("updated mapping pairs exceed FILE capacity"));
    }

    // Validate the exact prefix+logged suffix before resizing the FILE. Never
    // use newly zeroed alignment bytes to invent a missing native terminator.
    let mut replacement = data[at..at + relative].to_vec();
    replacement.extend_from_slice(payload);
    let pairs = &replacement[mapping_at..];
    let highest = highest_vcn(pairs, first)?;
    let runs = decode_mapping_pairs(pairs, first, highest, volume_clusters)?;
    if !sparse_allowed && runs.iter().any(|run| run.lcn.is_none()) {
        return Err(bad("ordinary updated mapping contains sparse holes"));
    }
    let mut physical = runs
        .iter()
        .filter_map(|run| run.lcn.map(|lcn| (lcn, lcn + run.clusters)))
        .collect::<Vec<_>>();
    // End additions were checked by decode_mapping_pairs against the bound.
    physical.sort_unstable();
    if physical.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(bad("updated mapping aliases its own physical clusters"));
    }
    replacement.resize(new_size, 0);
    put32(&mut replacement, 4, new_size)?;
    replacement[24..32].copy_from_slice(&highest.to_le_bytes());
    NtfsAttribute::parse(&replacement, le32(&replacement, 0)?)?;

    // Native FILE number, sequence, links, instance counter, names and size
    // fields survive unchanged. apply_file_edit validates/protects the complete
    // record and publishes it only as a private returned buffer.
    resize_attribute(data, at, size, new_size)?;
    data[at..at + new_size].copy_from_slice(&replacement);
    Ok(())
}

#[cfg(test)]
mod tests;
