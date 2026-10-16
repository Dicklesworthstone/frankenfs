//! Native FILE-record recovery edits on private, USA-protected byte buffers.
//!
//! Layout/operation reference: Linux v6.17 fs/ntfs3/fslog.c, do_action.
//! This module performs no I/O and supplies no writable-admission authority.
//! The caller must establish the target mapping, journal boundary and recovery
//! order. Undo deliberately does not invent an on-disk compensation LSN.

use super::{NtfsAttribute, NtfsFileRecord, NtfsValue, invalid, le16, le32, le64, restore_record};
use ffs_types::ParseError;

/// The native operations implemented for an already allocated FILE record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOperation {
    WriteEnd,
    CreateAttribute,
    DeleteAttribute,
    UpdateResident { resize: bool },
    SetSizes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryPass {
    /// Skip a record which already carries this LSN or a later one.
    Redo(u64),
    /// Apply the caller's validated reverse-LSN undo order once in memory.
    /// This does not persist a CLR and is not independently restartable.
    Undo,
}

#[derive(Debug)]
pub struct FileEdit<'a> {
    pub operation: FileOperation,
    pub record_offset: u16,
    pub attribute_offset: u16,
    pub data: &'a [u8],
}

#[derive(Debug, PartialEq, Eq)]
pub enum FileEditResult {
    AlreadyApplied,
    /// Complete protected record, with every USA saved word regenerated.
    Applied(Vec<u8>),
}

fn bad(reason: &'static str) -> ParseError {
    invalid("ntfs.recovery.file", reason)
}

fn put32(data: &mut [u8], at: usize, value: usize) -> Result<(), ParseError> {
    let value = u32::try_from(value).map_err(|_| bad("field length overflow"))?;
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

/// Require an actual attribute boundary, not an aligned address inside data.
/// The terminator is a legal insertion/end-replacement position only.
fn boundary(data: &[u8], wanted: usize, allow_end: bool) -> Result<usize, ParseError> {
    let mut at = usize::from(le16(data, 20)?);
    loop {
        let kind = le32(data, at)?;
        if kind == u32::MAX {
            return if allow_end && at == wanted {
                Ok(0)
            } else {
                Err(bad("target does not address an attribute"))
            };
        }
        let size = usize::try_from(le32(data, at + 4)?)
            .map_err(|_| bad("attribute size overflow"))?;
        if size < 24 || !size.is_multiple_of(8) {
            return Err(bad("invalid attribute boundary"));
        }
        if at == wanted {
            return Ok(size);
        }
        at = at.checked_add(size).ok_or_else(|| bad("attribute offset overflow"))?;
        if at > wanted {
            return Err(bad("target enters an attribute body"));
        }
    }
}

fn indexed(raw: &[u8]) -> Result<bool, ParseError> {
    if raw[8] != 0 {
        return Ok(false);
    }
    let flags = le16(raw, 22)?;
    if flags & !1 != 0 {
        return Err(bad("unknown resident attribute flags"));
    }
    Ok(flags == 1)
}

fn change_links(data: &mut [u8], add: bool) -> Result<(), ParseError> {
    let old = le16(data, 18)?;
    let new = if add { old.checked_add(1) } else { old.checked_sub(1) }
        .ok_or_else(|| bad("FILE_NAME link count overflow or underflow"))?;
    data[18..20].copy_from_slice(&new.to_le_bytes());
    Ok(())
}

fn resize_attribute(
    data: &mut [u8],
    at: usize,
    old: usize,
    new: usize,
) -> Result<(), ParseError> {
    let used = usize::try_from(le32(data, 24)?).map_err(|_| bad("used size overflow"))?;
    let end = at.checked_add(old).filter(|end| *end <= used)
        .ok_or_else(|| bad("old attribute exceeds used bytes"))?;
    let new_used = used.checked_sub(old).and_then(|size| size.checked_add(new))
        .filter(|size| *size <= data.len()).ok_or_else(|| bad("FILE record has no room"))?;
    data.copy_within(end..used, at + new);
    if new_used < used {
        data[new_used..used].fill(0);
    }
    put32(data, 24, new_used)?;
    if new != 0 {
        put32(data, at + 4, new)?;
    }
    Ok(())
}

fn edit_bytes(data: &mut [u8], edit: &FileEdit<'_>) -> Result<(), ParseError> {
    let at = usize::from(edit.record_offset);
    let relative = usize::from(edit.attribute_offset);
    let payload = edit.data;
    let insertion = matches!(edit.operation, FileOperation::CreateAttribute | FileOperation::WriteEnd);
    let size = boundary(data, at, insertion)?;
    match edit.operation {
        FileOperation::CreateAttribute => {
            if relative != 0 || payload.len() < 24 || !payload.len().is_multiple_of(8)
                || le32(payload, 4)? as u64 != payload.len() as u64
            {
                return Err(bad("invalid complete CreateAttribute payload"));
            }
            let kind = le32(payload, 0)?;
            if kind == 0 || kind == u32::MAX || !kind.is_multiple_of(16) {
                return Err(bad("invalid created attribute type"));
            }
            let attr = NtfsAttribute::parse(payload, kind)?;
            let id = attr.id;
            let next = le16(data, 40)?;
            let new_next = if next <= id {
                id.checked_add(1).ok_or_else(|| bad("attribute instance space exhausted"))?
            } else {
                next
            };
            let used = usize::try_from(le32(data, 24)?).map_err(|_| bad("used size overflow"))?;
            let new_used = used.checked_add(payload.len()).filter(|used| *used <= data.len())
                .ok_or_else(|| bad("created attribute exceeds FILE capacity"))?;
            data.copy_within(at..used, at + payload.len());
            data[at..at + payload.len()].copy_from_slice(payload);
            put32(data, 24, new_used)?;
            data[40..42].copy_from_slice(&new_next.to_le_bytes());
            if indexed(payload)? {
                change_links(data, true)?;
            }
        }
        FileOperation::DeleteAttribute => {
            if relative != 0 || !payload.is_empty() {
                return Err(bad("DeleteAttribute carries unexpected payload or offset"));
            }
            if indexed(&data[at..at + size])? {
                change_links(data, false)?;
            }
            resize_attribute(data, at, size, 0)?;
        }
        FileOperation::UpdateResident { resize } => {
            if data[at + 8] != 0 {
                return Err(bad("resident update targets a nonresident attribute"));
            }
            let value_at = usize::from(le16(data, at + 20)?);
            let value_size = usize::try_from(le32(data, at + 16)?)
                .map_err(|_| bad("resident value length overflow"))?;
            let value_end = value_at.checked_add(value_size)
                .ok_or_else(|| bad("resident value range overflow"))?;
            let end = relative.checked_add(payload.len())
                .ok_or_else(|| bad("resident edit length overflow"))?;
            // Never initialize a newly exposed gap from old allocation slack.
            // Header edits and value-to-header overlap need a different opcode.
            if relative < value_at || relative > value_end || (!resize && end > value_end) {
                return Err(bad("resident update is outside the initialized value"));
            }
            if resize {
                let new_size = end.checked_add(7).map(|size| size & !7)
                    .ok_or_else(|| bad("resident attribute alignment overflow"))?;
                resize_attribute(data, at, size, new_size)?;
                put32(data, at + 16, end - value_at)?;
                data[at + end..at + new_size].fill(0);
            }
            data[at + relative..at + end].copy_from_slice(payload);
        }
        FileOperation::WriteEnd => {
            if relative != 0 || payload.len() < 4 {
                return Err(bad("invalid WriteEndOfFileRecordSegment payload"));
            }
            let end = at.checked_add(payload.len()).filter(|end| *end <= data.len())
                .ok_or_else(|| bad("FILE tail replacement exceeds capacity"))?;
            let new_used = end.checked_add(7).map(|size| size & !7)
                .filter(|size| *size <= data.len()).ok_or_else(|| bad("FILE tail alignment overflow"))?;
            let old_used = usize::try_from(le32(data, 24)?).map_err(|_| bad("used size overflow"))?;
            data[at..end].copy_from_slice(payload);
            data[end..new_used.max(old_used)].fill(0);
            put32(data, 24, new_used)?;
        }
        FileOperation::SetSizes => {
            if relative != 0 || !matches!(payload.len(), 24 | 32) || data[at + 8] != 1
                || le64(data, at + 16)? != 0
            {
                return Err(bad("invalid SetNewAttributeSizes target or payload"));
            }
            let attr = NtfsAttribute::parse(&data[at..at + size], le32(data, at)?)?;
            let NtfsValue::NonResident(_) = attr.value else {
                return Err(bad("SetNewAttributeSizes needs nonresident storage"));
            };
            if le64(payload, 8)? > le64(payload, 16)? {
                return Err(bad("new initialized length exceeds new logical size"));
            }
            if payload.len() == 32 {
                if attr.flags & (super::SPARSE | super::COMPRESSED) == 0 || size < 72 {
                    return Err(bad("physical-size update needs an extended nonresident header"));
                }
                data[at + 64..at + 72].copy_from_slice(&payload[24..32]);
            }
            // Native NEW_ATTRIBUTE_SIZES is alloc, valid, data, total, not
            // the alloc, data, valid order used in an attribute header.
            data[at + 40..at + 48].copy_from_slice(&payload[..8]);
            data[at + 48..at + 56].copy_from_slice(&payload[16..24]);
            data[at + 56..at + 64].copy_from_slice(&payload[8..16]);
        }
    }
    Ok(())
}

fn protect(data: &mut [u8]) -> Result<(), ParseError> {
    let usa = usize::from(le16(data, 4)?);
    let count = usize::from(le16(data, 6)?);
    let old = le16(data, usa)?;
    let token = if old >= u16::MAX - 1 { 1 } else { old + 1 };
    data[usa..usa + 2].copy_from_slice(&token.to_le_bytes());
    for sector in 1..count {
        let end = sector * 512;
        let saved = [data[end - 2], data[end - 1]];
        data[usa + sector * 2..usa + sector * 2 + 2].copy_from_slice(&saved);
        data[end - 2..end].copy_from_slice(&token.to_le_bytes());
    }
    Ok(())
}

/// Apply one native recovery operation to a private FILE-record copy.
///
/// Both the complete input and the complete result must pass the ordinary FILE
/// parser. The caller's bytes remain unchanged even after a late parse failure.
/// A redo skip still checks the record's identity and update-sequence trailers;
/// it does not require an obsolete operation's target offset to remain valid.
/// This checks a record number, not volume-wide ownership or record allocation.
pub fn apply_file_edit(
    raw: &[u8],
    expected_record: u32,
    pass: RecoveryPass,
    edit: &FileEdit<'_>,
) -> Result<FileEditResult, ParseError> {
    let record = NtfsFileRecord::parse(raw)?;
    if record.number != expected_record || !record.in_use() {
        return Err(bad("recovery target is a different or unallocated FILE record"));
    }
    if let RecoveryPass::Redo(lsn) = pass {
        if lsn == 0 {
            return Err(bad("redo has an empty LSN"));
        }
        if le64(raw, 8)? >= lsn {
            return Ok(FileEditResult::AlreadyApplied);
        }
    }
    let mut result = restore_record(raw, b"FILE")?;
    edit_bytes(&mut result, edit)?;
    if let RecoveryPass::Redo(lsn) = pass {
        result[8..16].copy_from_slice(&lsn.to_le_bytes());
    }
    protect(&mut result)?;
    let checked = NtfsFileRecord::parse(&result)?;
    if checked.number != expected_record || !checked.in_use() {
        return Err(bad("recovery edit changed FILE record identity"));
    }
    Ok(FileEditResult::Applied(result))
}

#[cfg(test)]
mod tests;
