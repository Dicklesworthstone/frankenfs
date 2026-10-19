//! Semantic, all-or-nothing FILE replay for the public volatile overlay.
//!
//! The flat journal planner is not an ownership oracle. Bind every physical
//! claim to the current MFT, check allocation, and use the same FILE editor as
//! checkpoint-aware preflight. Never reinterpret unsupported opcodes as memcpy.
//! Only resident/INDEX_ROOT changes are published here: nonresident attributes
//! must survive byte-for-byte until allocation and bootstrap reconstruction are
//! integrated. This does not establish an authoritative durable journal tail.

use super::{Cx, NtfsVolume, Result, Source, Storage, Stream, checkpoint, corrupt, parse, unsupported};
use ffs_ondisk::ntfs::recovery::{
    FileEdit, FileEditResult, FileOperation, IndexOperation, RecoveryPass, apply_file_edit,
};
use ffs_ondisk::ntfs::{NtfsFileRecord, NtfsLogFilePlan, NtfsLogOp, NtfsRecoveryAction};
use std::collections::BTreeMap;

const MAX_ACTIONS: usize = 8192;
const MAX_CLAIMS: usize = 65_536;
const MAX_RECORDS: usize = 4096;
const MAX_BYTES: usize = 16 * 1024 * 1024;
const IO_BUDGET: u64 = 64 * 1024 * 1024;
const SECTOR: u64 = 512;

type Overlay = BTreeMap<u64, [u8; 512]>;

#[derive(Clone, Copy)]
struct Layout {
    cluster_bytes: u64,
    clusters: u64,
    record_bytes: usize,
    mft_initialized: u64,
    volume_bytes: u64,
}

trait Input {
    fn layout(&self) -> Layout;
    fn mapped_lcn(&self, vcn: u64) -> Result<u64>;
    fn allocated(&mut self, cx: &Cx, mft: bool, bit: u64) -> Result<bool>;
    fn file(&mut self, cx: &Cx, number: u32) -> Result<Vec<u8>>;
}

struct Native<'a> {
    volume: &'a NtfsVolume,
    mft_bitmap: Stream,
    clusters_bitmap: Stream,
    remaining: u64,
}

fn bitmap(stream: &Stream, bits: u64) -> Result<()> {
    if stream.size < bits.div_ceil(8) || stream.initialized != stream.size {
        return Err(corrupt(0, "incomplete semantic-replay allocation bitmap"));
    }
    match &stream.storage {
        Storage::Resident(_) => Ok(()),
        Storage::Mapped(runs) if runs.iter().all(|run| run.lcn.is_some()) => Ok(()),
        _ => Err(unsupported("semantic FILE replay needs plain allocation bitmaps")),
    }
}

impl<'a> Native<'a> {
    fn new(cx: &Cx, volume: &'a NtfsVolume) -> Result<Self> {
        let mft = volume.record(cx, 0, None)?;
        let mft_bitmap = volume.select_stream(cx, &mft, 0xB0, &[])?;
        bitmap(&mft_bitmap, volume.record_count())?;
        let allocation = volume.record(cx, 6, None)?;
        let clusters_bitmap = volume.data_stream(cx, &allocation, &[])?;
        bitmap(&clusters_bitmap, volume.geometry.cluster_count())?;
        Ok(Self { volume, mft_bitmap, clusters_bitmap, remaining: IO_BUDGET })
    }

    fn charge(&mut self, size: u64) -> Result<()> {
        self.remaining = self.remaining.checked_sub(size)
            .ok_or_else(|| unsupported("semantic FILE replay exceeds 64 MiB of target I/O"))?;
        Ok(())
    }
}

impl Input for Native<'_> {
    fn layout(&self) -> Layout {
        Layout {
            cluster_bytes: u64::from(self.volume.geometry.cluster_bytes()),
            clusters: self.volume.geometry.cluster_count(),
            record_bytes: self.volume.geometry.record_bytes() as usize,
            mft_initialized: self.volume.mft.initialized,
            volume_bytes: self.volume.geometry.volume_bytes(),
        }
    }

    fn mapped_lcn(&self, vcn: u64) -> Result<u64> {
        let Storage::Mapped(runs) = &self.volume.mft.storage else {
            return Err(corrupt(0, "semantic replay needs ordinary mapped MFT DATA"));
        };
        let index = runs.partition_point(|run| run.vcn <= vcn).checked_sub(1)
            .ok_or_else(|| corrupt(0, "semantic replay VCN precedes the MFT"))?;
        let run = &runs[index];
        let within = vcn - run.vcn;
        if within >= run.clusters {
            return Err(corrupt(0, "semantic replay VCN falls in an MFT mapping gap"));
        }
        run.lcn.and_then(|lcn| lcn.checked_add(within))
            .ok_or_else(|| corrupt(0, "sparse or overflowing semantic replay MFT mapping"))
    }

    fn allocated(&mut self, cx: &Cx, mft: bool, bit: u64) -> Result<bool> {
        self.charge(1)?;
        let stream = if mft { &self.mft_bitmap } else { &self.clusters_bitmap };
        let data = self.volume.read(cx, stream, bit / 8, 1)?;
        let byte = data.first().ok_or_else(|| corrupt(0, "short semantic replay bitmap read"))?;
        Ok(*byte & (1_u8 << (bit % 8)) != 0)
    }

    fn file(&mut self, cx: &Cx, number: u32) -> Result<Vec<u8>> {
        let size = self.layout().record_bytes;
        self.charge(size as u64)?;
        self.volume.read(cx, &self.volume.mft, u64::from(number) * size as u64, size)
    }
}

fn operation(action: &NtfsRecoveryAction) -> Result<FileOperation> {
    match action.op {
        NtfsLogOp::WriteEndOfFileRecordSegment => Ok(FileOperation::WriteEnd),
        NtfsLogOp::CreateAttribute => Ok(FileOperation::CreateAttribute),
        NtfsLogOp::DeleteAttribute => Ok(FileOperation::DeleteAttribute),
        NtfsLogOp::UpdateResidentValue => Ok(FileOperation::UpdateResident {
            resize: action.resident_resize,
        }),
        NtfsLogOp::AddIndexEntryRoot => Ok(FileOperation::IndexRoot(IndexOperation::AddEntry)),
        NtfsLogOp::DeleteIndexEntryRoot => Ok(FileOperation::IndexRoot(IndexOperation::DeleteEntry)),
        NtfsLogOp::SetIndexEntryVcnRoot => Ok(FileOperation::IndexRoot(IndexOperation::SetChild)),
        NtfsLogOp::UpdateFileNameRoot => Ok(FileOperation::IndexRoot(IndexOperation::UpdateFileName)),
        other => Err(unsupported(format!(
            "public NTFS overlay has no ownership-qualified semantic executor for {other:?}"
        ))),
    }
}

/// record_offset addresses an attribute INSIDE the FILE, not the FILE's start.
/// cluster_block_offset is in 512-byte units, even on larger-cluster volumes.
fn target(layout: Layout, action: &NtfsRecoveryAction) -> Result<u32> {
    if action.target_lcns.is_empty() {
        return Err(corrupt(0, "semantic FILE action has no native mapping claims"));
    }
    let offset = u64::from(action.cluster_block_offset) * SECTOR;
    let span = (action.target_lcns.len() as u64).checked_mul(layout.cluster_bytes)
        .ok_or_else(|| corrupt(0, "semantic FILE mapping span overflows"))?;
    let logical = action.target_vcn.checked_mul(layout.cluster_bytes)
        .and_then(|at| at.checked_add(offset))
        .ok_or_else(|| corrupt(0, "semantic FILE logical address overflows"))?;
    if offset.checked_add(layout.record_bytes as u64).is_none_or(|end| end > span)
        || !logical.is_multiple_of(layout.record_bytes as u64)
        || logical.checked_add(layout.record_bytes as u64)
            .is_none_or(|end| end > layout.mft_initialized)
    {
        return Err(corrupt(logical, "semantic FILE target exceeds initialized MFT geometry"));
    }
    let number = u32::try_from(logical / layout.record_bytes as u64)
        .map_err(|_| corrupt(logical, "semantic FILE record number overflows"))?;
    if number < 16 {
        return Err(unsupported("system FILE replay needs bootstrap and mirror reconstruction"));
    }
    Ok(number)
}

/// Preserve direct mappings AND resident ATTRIBUTE_LIST indirections until
/// allocation/ownership reconciliation is integrated. Compare attribute bytes,
/// not their containing offsets: a resident resize can move an unchanged map.
fn storage_metadata(record: &NtfsFileRecord) -> Result<BTreeMap<u16, Vec<u8>>> {
    let bytes = record.used_bytes();
    let mut at = usize::from(u16::from_le_bytes([bytes[20], bytes[21]]));
    let mut result = BTreeMap::new();
    for attr in record.attributes().map_err(|error| parse(&error))? {
        let length = u32::from_le_bytes(bytes[at + 4..at + 8].try_into()
            .map_err(|_| corrupt(0, "short FILE attribute length"))?) as usize;
        let end = at.checked_add(length).filter(|end| *end <= bytes.len())
            .ok_or_else(|| corrupt(0, "FILE attribute exceeds its restored record"))?;
        if attr.kind == ffs_ondisk::ntfs::ATTRIBUTE_LIST
            || matches!(attr.value, ffs_ondisk::ntfs::NtfsValue::NonResident(_))
        {
            result.insert(attr.id, bytes[at..end].to_vec());
        }
        at = end;
    }
    Ok(result)
}

fn execute(cx: &Cx, input: &mut impl Input, plan: &NtfsLogFilePlan) -> Result<Overlay> {
    checkpoint(cx)?;
    let layout = input.layout();
    if !(512..=65_536).contains(&layout.cluster_bytes) || !layout.cluster_bytes.is_power_of_two()
        || !(512..=65_536).contains(&layout.record_bytes) || !layout.record_bytes.is_power_of_two()
        || layout.clusters == 0 || layout.mft_initialized < layout.record_bytes as u64
        || layout.clusters.checked_mul(layout.cluster_bytes)
            .is_none_or(|bytes| bytes > layout.volume_bytes)
    {
        return Err(corrupt(0, "invalid semantic FILE replay geometry"));
    }
    let count = plan.redo_actions.len().checked_add(plan.undo_actions.len())
        .filter(|count| *count <= MAX_ACTIONS)
        .ok_or_else(|| unsupported("semantic FILE replay exceeds 8192 actions"))?;
    let mut actions = Vec::with_capacity(count);
    let mut claims = 0_usize;
    let mut payload_bytes = 0_usize;
    for (undo, batch) in [(false, &plan.redo_actions), (true, &plan.undo_actions)] {
        let mut previous = None;
        for action in batch {
            checkpoint(cx)?;
            if action.is_undo != undo || action.transaction_id == 0 || action.lsn == 0
                || action.lsn > plan.restart.current_lsn
                || previous.is_some_and(|lsn| if undo { action.lsn >= lsn } else { action.lsn <= lsn })
            {
                return Err(corrupt(0, "semantic FILE actions have invalid identity, boundary or order"));
            }
            previous = Some(action.lsn);
            claims = claims.checked_add(action.target_lcns.len()).filter(|count| *count <= MAX_CLAIMS)
                .ok_or_else(|| unsupported("semantic FILE replay exceeds 65536 mapping claims"))?;
            payload_bytes = payload_bytes.checked_add(action.data.len()).filter(|bytes| *bytes <= MAX_BYTES)
                .ok_or_else(|| unsupported("semantic FILE replay payloads exceed 16 MiB"))?;
            actions.push((action, operation(action)?, target(layout, action)?));
        }
    }
    // All unsupported opcodes are rejected before ANY target/bitmap reads.
    let mut owners = BTreeMap::new();
    for (action, _, number) in &actions {
        for (index, &lcn) in action.target_lcns.iter().enumerate() {
            checkpoint(cx)?;
            let vcn = action.target_vcn.checked_add(index as u64)
                .ok_or_else(|| corrupt(0, "semantic FILE VCN span overflows"))?;
            if lcn == 0 || lcn >= layout.clusters || input.mapped_lcn(vcn)? != lcn {
                return Err(corrupt(0, "journal claim disagrees with the current MFT map"));
            }
            if owners.insert(lcn, vcn).is_some_and(|old| old != vcn) {
                return Err(corrupt(0, "different MFT VCNs alias the same physical replay cluster"));
            }
            if !input.allocated(cx, false, lcn)? {
                return Err(corrupt(0, "semantic FILE action targets an unallocated cluster"));
            }
        }
        if !input.allocated(cx, true, u64::from(*number))? {
            return Err(corrupt(0, "semantic FILE action targets an unallocated MFT record"));
        }
    }
    let mut records: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    for (action, operation, number) in actions {
        checkpoint(cx)?;
        if !records.contains_key(&number) {
            if records.len() >= MAX_RECORDS
                || (records.len() + 1).checked_mul(layout.record_bytes).is_none_or(|bytes| bytes > MAX_BYTES)
            {
                return Err(unsupported("semantic FILE private stage exceeds 4096 records or 16 MiB"));
            }
            let raw = input.file(cx, number)?;
            if raw.len() != layout.record_bytes {
                return Err(corrupt(0, "short semantic FILE target read"));
            }
            let record = NtfsFileRecord::parse(&raw).map_err(|error| parse(&error))?;
            if record.number != number || !record.in_use() || record.sequence == 0 {
                return Err(corrupt(0, "semantic FILE target has the wrong identity or is not live"));
            }
            if record.base.record != 0 && record.base.sequence == 0 {
                return Err(corrupt(0, "semantic FILE extension has an invalid base reference"));
            }
            if record.base.sequence != 0 && record.base.record < 16 {
                return Err(unsupported("system FILE extension replay needs bootstrap reconstruction"));
            }
            let page_lsn = u64::from_le_bytes(raw[8..16].try_into()
                .map_err(|_| corrupt(0, "short semantic FILE page LSN"))?);
            if page_lsn > plan.restart.current_lsn {
                return Err(unsupported("FILE page is newer than the selected journal boundary"));
            }
            records.insert(number, raw);
        }
        let raw = records.get(&number).ok_or_else(|| corrupt(0, "semantic FILE stage lost a record"))?;
        let pass = if action.is_undo { RecoveryPass::Undo } else { RecoveryPass::Redo(action.lsn) };
        let edit = FileEdit {
            operation,
            record_offset: action.record_offset,
            attribute_offset: action.attribute_offset,
            data: &action.data,
        };
        match apply_file_edit(raw, number, pass, &edit).map_err(|error| parse(&error))? {
            FileEditResult::AlreadyApplied => {}
            FileEditResult::Applied(updated) => {
                let before = NtfsFileRecord::parse(raw).map_err(|error| parse(&error))?;
                let after = NtfsFileRecord::parse(&updated).map_err(|error| parse(&error))?;
                if storage_metadata(&before)? != storage_metadata(&after)? {
                    return Err(unsupported("public FILE replay cannot change allocation or attribute-list metadata"));
                }
                records.insert(number, updated);
            }
        }
    }
    let mut overlay = BTreeMap::new();
    // Export each sector through the actual MFT map, not first-LCN arithmetic.
    // No Source mutation occurs, including after late errors/cancellation.
    for (number, raw) in records {
        for (index, sector) in raw.chunks_exact(512).enumerate() {
            checkpoint(cx)?;
            let logical = u64::from(number) * layout.record_bytes as u64 + index as u64 * SECTOR;
            let vcn = logical / layout.cluster_bytes;
            let lcn = input.mapped_lcn(vcn)?;
            if owners.get(&lcn) != Some(&vcn) {
                return Err(corrupt(0, "MFT export no longer matches validated mapping claims"));
            }
            let physical = lcn.checked_mul(layout.cluster_bytes)
                .and_then(|at| at.checked_add(logical % layout.cluster_bytes))
                .filter(|at| at.checked_add(SECTOR).is_some_and(|end| end <= layout.volume_bytes))
                .ok_or_else(|| corrupt(0, "semantic FILE export exceeds the selected volume"))?;
            let bytes: [u8; 512] = sector.try_into().map_err(|_| corrupt(0, "short FILE export sector"))?;
            if overlay.insert(physical / SECTOR, bytes).is_some() {
                return Err(corrupt(physical, "semantic FILE records overlap in the exported overlay"));
            }
        }
    }
    checkpoint(cx)?;
    Ok(overlay)
}

pub(super) fn stage(cx: &Cx, volume: &NtfsVolume, plan: &NtfsLogFilePlan) -> Result<Overlay> {
    checkpoint(cx)?;
    if !volume.source.overlay.is_empty() || volume.logfile_recovery.is_some() {
        return Err(unsupported("recovery needs an unmodified native source, not a prior overlay"));
    }
    if plan.redo_actions.is_empty() && plan.undo_actions.is_empty() {
        return Ok(BTreeMap::new());
    }
    if plan.redo_actions.len().checked_add(plan.undo_actions.len())
        .is_none_or(|count| count > MAX_ACTIONS)
    {
        return Err(unsupported("semantic FILE replay exceeds 8192 actions"));
    }
    // Refuse unsupported families before opening allocation metadata as well.
    for action in plan.redo_actions.iter().chain(&plan.undo_actions) {
        checkpoint(cx)?;
        operation(action)?;
    }
    execute(cx, &mut Native::new(cx, volume)?, plan)
}

/// Reuse Source's range and capacity guards, retaining its old snapshot until
/// every sector and the final cancellation check succeeds. `&mut Source`
/// excludes readers during installation; no returned error exposes a prefix.
pub(super) fn publish(cx: &Cx, source: &mut Source, staged: Overlay) -> Result<()> {
    checkpoint(cx)?;
    let previous = std::mem::take(&mut source.overlay);
    let result = (|| {
        for (sector, bytes) in staged {
            let offset = sector.checked_mul(SECTOR)
                .ok_or_else(|| corrupt(0, "semantic FILE overlay sector overflows"))?;
            source.write_overlay(cx, offset, &bytes)?;
        }
        checkpoint(cx)
    })();
    if result.is_err() {
        source.overlay = previous;
    }
    result
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests;
}
