//! Native $I30 recovery edits, shared by resident roots and protected INDX nodes.
//!
//! Operation framing follows Linux v6.17 fs/ntfs3/fslog.c, do_action. This is
//! local node validation, not collation, tree reachability, allocation ownership
//! or volume recovery. The caller supplies native identity and journal order.
//! No I/O or writes occur here; errors never modify the supplied source buffer.

use super::super::{NtfsAttribute, NtfsValue, ParseError, index, le16, le32, le64, restore_record};
use super::{FileEdit, FileEditResult, RecoveryPass, bad, protect, put32, resize_attribute};

const I30: [u16; 4] = [0x24, 0x49, 0x33, 0x30];
const ROOT_HEADER: usize = 16;
const BLOCK_HEADER: usize = 24;
const DUPLICATED_INFORMATION: usize = 56;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexOperation {
    AddEntry,
    DeleteEntry,
    SetChild,
    UpdateFileName,
    /// Native WriteEndOfIndexBuffer; not a resident-root operation.
    WriteEnd,
}

#[derive(Debug)]
pub struct IndexEdit<'a> {
    pub operation: IndexOperation,
    /// Native attr_off, relative to the beginning of the selected INDX buffer.
    /// The caller has already resolved record_off and the stream byte position.
    pub entry_offset: u16,
    pub data: &'a [u8],
}

/// Independent root framing. The volume's actual cluster/VBN geometry remains
/// a caller obligation; these operations never change the root's geometry.
fn root_header(value: &[u8]) -> Result<(), ParseError> {
    if value.len() < 32 || le32(value, 0)? != 0x30 || le32(value, 4)? != 1 {
        return Err(bad("directory recovery requires FILE_NAME collation"));
    }
    let block = le32(value, 8)?;
    let units = u32::from(value[12]);
    if !(512..=65_536).contains(&block)
        || !block.is_power_of_two()
        || !units.is_power_of_two()
        || units > block / 512
        || usize::try_from(le32(value, 24)?).ok() != Some(value.len() - ROOT_HEADER)
    {
        return Err(bad("invalid resident directory-index geometry"));
    }
    Ok(())
}

/// Find an existing, complete entry boundary, including the terminal entry.
/// An aligned offset into a key, padding or child pointer is never a target.
fn entry_at(value: &[u8], header: usize, wanted: usize) -> Result<(usize, u16), ParseError> {
    let mut at = header
        + usize::try_from(le32(value, header)?).map_err(|_| bad("index entry offset overflow"))?;
    let end = header
        + usize::try_from(le32(value, header + 4)?)
            .map_err(|_| bad("index used length overflow"))?;
    while at < end {
        let size = usize::from(le16(value, at + 8)?);
        if at == wanted {
            return Ok((size, le16(value, at + 12)?));
        }
        // The complete node was parsed before walking these boundaries.
        at = at
            .checked_add(size)
            .filter(|next| *next > at && *next <= end)
            .ok_or_else(|| bad("invalid directory-index entry boundary"))?;
    }
    Err(bad(
        "directory-index edit does not address an entry boundary",
    ))
}

/// All edits consume a private copy. Resident roots grow/shrink their allocation;
/// external nodes retain their fixed buffer capacity and only change used bytes.
fn edit_node(
    value: &mut Vec<u8>,
    header: usize,
    minimum_entry: usize,
    edit: &IndexEdit<'_>,
    growable: bool,
    limit: usize,
) -> Result<(), ParseError> {
    drop(index::entries(value, header, minimum_entry)?);
    let at = usize::from(edit.entry_offset);
    let (size, flags) = entry_at(value, header, at)?;
    let used =
        usize::try_from(le32(value, header + 4)?).map_err(|_| bad("index used length overflow"))?;
    let allocated =
        usize::try_from(le32(value, header + 8)?).map_err(|_| bad("index capacity overflow"))?;
    let end = header + used;
    let payload = edit.data;
    match edit.operation {
        IndexOperation::AddEntry => {
            if payload.len() < 16
                || !payload.len().is_multiple_of(8)
                || usize::from(le16(payload, 8)?) != payload.len()
                || le16(payload, 12)? & 2 != 0
            {
                return Err(bad("AddIndexEntry requires one complete nonterminal entry"));
            }
            let new_used = used
                .checked_add(payload.len())
                .ok_or_else(|| bad("index insertion length overflow"))?;
            if growable {
                let new_len = value
                    .len()
                    .checked_add(payload.len())
                    .filter(|length| *length <= limit)
                    .ok_or_else(|| bad("resident directory index exceeds FILE capacity"))?;
                value
                    .try_reserve_exact(payload.len())
                    .map_err(|_| bad("cannot reserve private directory-index buffer"))?;
                value.resize(new_len, 0);
                put32(value, header + 8, allocated + payload.len())?;
            } else if new_used > allocated {
                return Err(bad("external directory index has no room for entry"));
            }
            value.copy_within(at..end, at + payload.len());
            value[at..at + payload.len()].copy_from_slice(payload);
            put32(value, header + 4, new_used)?;
        }
        IndexOperation::DeleteEntry => {
            if !payload.is_empty() || flags & 2 != 0 {
                return Err(bad(
                    "DeleteIndexEntry cannot carry data or delete the terminator",
                ));
            }
            value.copy_within(at + size..end, at);
            value[end - size..end].fill(0);
            put32(value, header + 4, used - size)?;
            if growable {
                put32(value, header + 8, allocated - size)?;
                value.truncate(value.len() - size);
            }
        }
        IndexOperation::SetChild => {
            if flags & 1 == 0 || payload.len() != 8 || le64(payload, 0)? > i64::MAX as u64 {
                return Err(bad(
                    "SetIndexEntryVcn needs an existing child and a native VCN",
                ));
            }
            value[at + size - 8..at + size].copy_from_slice(payload);
        }
        IndexOperation::UpdateFileName => {
            if flags & 2 != 0 || payload.len() != DUPLICATED_INFORMATION {
                return Err(bad(
                    "UpdateFileName requires exactly the native duplicated information",
                ));
            }
            // Preserve the file reference, parent reference, name, namespace,
            // entry envelope and child pointer. Only FILE_NAME::dup is logged.
            let start = at + 16 + 8;
            value[start..start + DUPLICATED_INFORMATION].copy_from_slice(payload);
        }
        IndexOperation::WriteEnd => {
            if growable || payload.len() < 16 || !payload.len().is_multiple_of(8) {
                return Err(bad(
                    "WriteEndOfIndexBuffer needs a complete aligned entry suffix",
                ));
            }
            let new_end = at
                .checked_add(payload.len())
                .filter(|end| *end <= header + allocated)
                .ok_or_else(|| bad("index tail replacement exceeds buffer capacity"))?;
            value[at..new_end].copy_from_slice(payload);
            if new_end < end {
                value[new_end..end].fill(0);
            }
            put32(value, header + 4, new_end - header)?;
        }
    }
    // Validate every key and the sole terminal entry, not just the edited row.
    // A malformed inserted suffix therefore cannot escape as a partial result.
    drop(index::entries(value, header, minimum_entry)?);
    Ok(())
}

pub(super) fn edit_root(
    data: &mut [u8],
    at: usize,
    size: usize,
    edit: &FileEdit<'_>,
    operation: IndexOperation,
) -> Result<(), ParseError> {
    let attr = NtfsAttribute::parse(&data[at..at + size], le32(data, at)?)?;
    if attr.kind != 0x90 || attr.flags != 0 || attr.name.as_slice() != I30.as_slice() {
        return Err(bad(
            "root recovery requires an untransformed $I30 INDEX_ROOT",
        ));
    }
    let NtfsValue::Resident(value) = attr.value else {
        return Err(bad("INDEX_ROOT recovery requires resident storage"));
    };
    root_header(value)?;
    let old_len = value.len();
    let value_at = usize::from(le16(data, at + 20)?);
    let offset = usize::from(edit.attribute_offset)
        .checked_sub(value_at)
        .and_then(|offset| u16::try_from(offset).ok())
        .ok_or_else(|| bad("root entry offset enters the resident header"))?;
    let used = usize::try_from(le32(data, 24)?).map_err(|_| bad("FILE used length flower"))?;
    let limit = data
        .len()
        .checked_sub(used)
        .and_then(|free| old_len.checked_add(free))
        .ok_or_else(|| bad("invalid FILE capacity for root edit"))?;
    let mut value = value.to_vec();
    edit_node(
        &mut value,
        ROOT_HEADER,
        32,
        &IndexEdit {
            operation,
            entry_offset: offset,
            data: edit.data,
        },
        true,
        limit,
    )?;
    root_header(&value)?;
    let new_size = size
        .checked_sub(old_len)
        .and_then(|size| size.checked_add(value.len()))
        .ok_or_else(|| bad("resident index attribute size overflow"))?;
    resize_attribute(data, at, size, new_size)?;
    put32(data, at + 16, value.len())?;
    data[at + value_at..at + value_at + value.len()].copy_from_slice(&value);
    data[at + value_at + value.len()..at + new_size].fill(0);
    Ok(())
}

/// Edit one already allocated directory INDX block on a private byte copy.
///
/// Validate the complete input and result with the existing directory parser.
/// Native page LSNs make Redo idempotent. Undo does not invent a durable CLR.
/// expected_vcn is the native buffer VBN, not necessarily a cluster number.
/// Caller duties include $I30 identity, bitmap ownership, selected-volume bounds,
/// collation/tree relationships and complete recovery before publishing a view.
pub fn apply_index_edit(
    raw: &[u8],
    expected_vcn: u64,
    pass: RecoveryPass,
    edit: &IndexEdit<'_>,
) -> Result<FileEditResult, ParseError> {
    if !raw.len().is_power_of_two() {
        return Err(bad("directory-index buffer size is not a power of two"));
    }
    drop(index::parse_index_block(raw, expected_vcn)?);
    if let RecoveryPass::Redo(lsn) = pass {
        if lsn == 0 {
            return Err(bad("directory-index redo has an empty LSN"));
        }
        if le64(raw, 8)? >= lsn {
            return Ok(FileEditResult::AlreadyApplied);
        }
    }
    let mut value = restore_record(raw, b"INDX")?;
    let minimum = usize::from(le16(&value, 4)?) + usize::from(le16(&value, 6)?) * 2;
    edit_node(&mut value, BLOCK_HEADER, minimum, edit, false, raw.len())?;
    if let RecoveryPass::Redo(lsn) = pass {
        value[8..16].copy_from_slice(&lsn.to_le_bytes());
    }
    protect(&mut value)?;
    drop(index::parse_index_block(&value, expected_vcn)?);
    Ok(FileEditResult::Applied(value))
}

#[cfg(test)]
mod tests;
