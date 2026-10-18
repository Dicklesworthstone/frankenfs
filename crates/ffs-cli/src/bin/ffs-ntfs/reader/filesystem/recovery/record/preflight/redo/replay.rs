//! Bounded, private MFT redo/undo execution through a selected restart boundary.
//!
//! No backing writes, native CLR publication or recovered-mount admission.
//! Unknown required operations abort the complete stage, never a partial view.

use super::super::super::super::super::super as reader;
use super::super::{
    LogRecord, checkpoint, corrupt, read_record, targets, u16_at, u64_at, unsupported,
};
use super::{Candidate, Plan, ReplayInput, ReplaySummary};
use ffs_ondisk::ntfs::recovery::{
    FileEdit, FileEditResult, FileOperation, IndexOperation, RecoveryPass, apply_file_edit,
};
use ffs_ondisk::ntfs::{DATA, NtfsFileRecord};
use reader::{Cx, NtfsVolume, Result, Storage, Stream, parse};
use std::collections::BTreeMap;

const MAX_RECORDS: usize = 4096;
const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_CLAIMS: usize = 65_536;
const TARGET_IO_BUDGET: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy)]
struct Layout {
    cluster_bytes: u64,
    record_bytes: usize,
    clusters: u64,
    mft_initialized: u64,
    mft_reference: u64,
    boundary_lsn: u64,
}

/// Only target reads are abstracted; identity, mapping, allocation and page-LSN
/// validation stays in the shared executor, including for injected-I/O tests.
trait MftInput {
    fn layout(&self) -> Layout;
    fn mapped_lcn(&self, vcn: u64) -> Result<u64>;
    fn allocated(&mut self, cx: &Cx, mft: bool, bit: u64) -> Result<bool>;
    fn read_record(&mut self, cx: &Cx, number: u32) -> Result<Vec<u8>>;
}

struct VolumeInput<'a> {
    volume: &'a NtfsVolume,
    layout: Layout,
    mft_bitmap: Stream,
    cluster_bitmap: Stream,
    remaining: u64,
}

fn bitmap(stream: &Stream, bits: u64) -> Result<()> {
    if stream.initialized != stream.size || stream.size < bits.div_ceil(8) {
        return Err(corrupt(0, "NTFS replay allocation bitmap is incomplete"));
    }
    match &stream.storage {
        Storage::Resident(_) => Ok(()),
        Storage::Mapped(runs) if runs.iter().all(|run| run.lcn.is_some()) => Ok(()),
        _ => Err(unsupported(
            "NTFS replay needs untransformed allocation bitmaps",
        )),
    }
}

impl<'a> VolumeInput<'a> {
    fn new(cx: &Cx, volume: &'a NtfsVolume, boundary_lsn: u64) -> Result<Self> {
        checkpoint(cx)?;
        let mft = volume.record(cx, 0, None)?;
        let mft_bitmap = volume.select_stream(cx, &mft, 0xB0, &[])?;
        bitmap(&mft_bitmap, volume.record_count())?;
        let allocation = volume.record(cx, 6, None)?;
        let cluster_bitmap = volume.data_stream(cx, &allocation, &[])?;
        bitmap(&cluster_bitmap, volume.geometry.cluster_count())?;
        Ok(Self {
            volume,
            layout: Layout {
                cluster_bytes: u64::from(volume.geometry.cluster_bytes()),
                record_bytes: volume.geometry.record_bytes() as usize,
                clusters: volume.geometry.cluster_count(),
                mft_initialized: volume.mft.initialized,
                mft_reference: u64::from(mft.sequence) << 48,
                boundary_lsn,
            },
            mft_bitmap,
            cluster_bitmap,
            remaining: TARGET_IO_BUDGET,
        })
    }

    fn charge(&mut self, bytes: u64) -> Result<()> {
        self.remaining = self
            .remaining
            .checked_sub(bytes)
            .ok_or_else(|| unsupported("NTFS replay target reads exceed 64 MiB"))?;
        Ok(())
    }
}

impl MftInput for VolumeInput<'_> {
    fn layout(&self) -> Layout {
        self.layout
    }

    fn mapped_lcn(&self, vcn: u64) -> Result<u64> {
        let Storage::Mapped(runs) = &self.volume.mft.storage else {
            return Err(corrupt(
                0,
                "NTFS replay MFT map is not ordinary nonresident DATA",
            ));
        };
        let index = runs
            .partition_point(|run| run.vcn <= vcn)
            .checked_sub(1)
            .ok_or_else(|| corrupt(0, "NTFS replay VCN precedes the MFT map"))?;
        let run = &runs[index];
        let within = vcn - run.vcn;
        if within >= run.clusters {
            return Err(corrupt(0, "NTFS replay VCN is outside the MFT map"));
        }
        run.lcn
            .and_then(|lcn| lcn.checked_add(within))
            .ok_or_else(|| corrupt(0, "NTFS replay MFT map is sparse or overflowing"))
    }

    fn allocated(&mut self, cx: &Cx, mft: bool, bit: u64) -> Result<bool> {
        self.charge(1)?;
        let stream = if mft {
            &self.mft_bitmap
        } else {
            &self.cluster_bitmap
        };
        let byte = self.volume.read(cx, stream, bit / 8, 1)?;
        let byte = byte
            .first()
            .ok_or_else(|| corrupt(0, "short NTFS replay bitmap read"))?;
        Ok(*byte & (1_u8 << (bit % 8)) != 0)
    }

    fn read_record(&mut self, cx: &Cx, number: u32) -> Result<Vec<u8>> {
        self.charge(self.layout.record_bytes as u64)?;
        self.volume.read(
            cx,
            &self.volume.mft,
            u64::from(number) * self.layout.record_bytes as u64,
            self.layout.record_bytes,
        )
    }
}

fn operation(record: &LogRecord, undo: bool, volume_clusters: u64) -> Result<FileOperation> {
    let opcode = if undo {
        record.summary.undo_op
    } else {
        record.summary.redo_op
    };
    match opcode {
        4 => Ok(FileOperation::WriteEnd),
        5 => Ok(FileOperation::CreateAttribute),
        6 => Ok(FileOperation::DeleteAttribute),
        7 => Ok(FileOperation::UpdateResident {
            resize: u16_at(&record.data, 6)? != u16_at(&record.data, 10)?,
        }),
        9 => Ok(FileOperation::UpdateMappingPairs { volume_clusters }),
        11 => Ok(FileOperation::SetSizes),
        0x0C => Ok(FileOperation::IndexRoot(IndexOperation::AddEntry)),
        0x0D => Ok(FileOperation::IndexRoot(IndexOperation::DeleteEntry)),
        0x11 => Ok(FileOperation::IndexRoot(IndexOperation::SetChild)),
        0x13 => Ok(FileOperation::IndexRoot(IndexOperation::UpdateFileName)),
        _ => Err(unsupported(format!(
            "NTFS private MFT replay does not implement required opcode {opcode:#04x}"
        ))),
    }
}

struct Action<'a> {
    record: &'a LogRecord,
    attribute: &'a targets::Attribute,
    lcns: Vec<u64>,
    pass: RecoveryPass,
    operation: FileOperation,
    payload: &'a [u8],
    number: u32,
}

fn target(
    layout: Layout,
    record: &LogRecord,
    attribute: &targets::Attribute,
    lcns: &[u64],
) -> Result<u32> {
    if attribute.reference != layout.mft_reference
        || attribute.kind != DATA
        || !attribute.name.is_empty()
        || attribute.index_bytes != 0
    {
        return Err(unsupported(
            "FILE replay requires the current unnamed $MFT DATA identity",
        ));
    }
    if lcns.is_empty() || lcns.len() != usize::from(u16_at(&record.data, 14)?) {
        return Err(corrupt(0, "FILE replay is missing native mapping claims"));
    }
    let vcn = u64_at(&record.data, 24)?;
    let offset = u64::from(u16_at(&record.data, 20)?) * 512;
    let bytes = lcns.len() as u64 * layout.cluster_bytes;
    let logical = vcn
        .checked_mul(layout.cluster_bytes)
        .and_then(|at| at.checked_add(offset))
        .ok_or_else(|| corrupt(0, "FILE replay logical target overflows"))?;
    if offset + layout.record_bytes as u64 > bytes
        || !logical.is_multiple_of(layout.record_bytes as u64)
        || logical
            .checked_add(layout.record_bytes as u64)
            .is_none_or(|end| end > layout.mft_initialized)
    {
        return Err(corrupt(
            0,
            "FILE replay target exceeds initialized MFT geometry",
        ));
    }
    let number = u32::try_from(logical / layout.record_bytes as u64)
        .map_err(|_| corrupt(0, "FILE replay record identity overflows"))?;
    // The current bootstrap and bitmap streams are immutable inputs. Mutating
    // their own metadata would require rebuilding those views before reuse.
    if number < 16 {
        return Err(unsupported(
            "NTFS system-record replay requires bootstrap-view reconstruction",
        ));
    }
    Ok(number)
}

fn validate_action(cx: &Cx, input: &mut impl MftInput, action: &Action<'_>) -> Result<()> {
    checkpoint(cx)?;
    let layout = input.layout();
    // Validate even a target already cached by an earlier action: cache hits
    // cannot exempt a changed mapping or incarnation from admission.
    if target(layout, action.record, action.attribute, &action.lcns)? != action.number {
        return Err(corrupt(0, "FILE replay target changed during admission"));
    }
    let vcn = u64_at(&action.record.data, 24)?;
    for (index, &lcn) in action.lcns.iter().enumerate() {
        checkpoint(cx)?;
        let vcn = vcn
            .checked_add(index as u64)
            .ok_or_else(|| corrupt(0, "FILE replay VCN overflows"))?;
        if lcn == 0 || lcn >= layout.clusters || input.mapped_lcn(vcn)? != lcn {
            return Err(corrupt(
                0,
                "journal target disagrees with the current MFT mapping",
            ));
        }
        if !input.allocated(cx, false, lcn)? {
            return Err(corrupt(
                0,
                "journal targets an unallocated physical MFT cluster",
            ));
        }
    }
    if !input.allocated(cx, true, u64::from(action.number))? {
        return Err(corrupt(0, "journal targets a free MFT record"));
    }
    checkpoint(cx)
}

struct Staged {
    records: BTreeMap<u32, Vec<u8>>,
    summary: ReplaySummary,
}

fn execute(
    cx: &Cx,
    input: &mut impl MftInput,
    plan: &Plan<'_>,
    undo_records: &[LogRecord],
    targets: &targets::State,
) -> Result<Staged> {
    checkpoint(cx)?;
    let layout = input.layout();
    if !(512..=65_536).contains(&layout.cluster_bytes)
        || !layout.cluster_bytes.is_power_of_two()
        || !(512..=65_536).contains(&layout.record_bytes)
        || !layout.record_bytes.is_power_of_two()
        || layout.boundary_lsn == 0
    {
        return Err(corrupt(0, "invalid FILE replay geometry or boundary"));
    }
    if plan.candidates.len() > MAX_RECORDS || undo_records.len() > MAX_RECORDS {
        return Err(unsupported("FILE replay exceeds the operation budget"));
    }
    let mut actions = Vec::new();
    let mut claims = 0_usize;
    for Candidate {
        record,
        attribute,
        lcns,
        payload,
    } in &plan.candidates
    {
        checkpoint(cx)?;
        claims = claims
            .checked_add(lcns.len())
            .filter(|claims| *claims <= MAX_CLAIMS)
            .ok_or_else(|| unsupported("FILE replay exceeds 65536 mapping claims"))?;
        actions.push(Action {
            record,
            attribute,
            lcns: lcns.clone(),
            payload,
            pass: RecoveryPass::Redo(record.lsn),
            operation: operation(record, false, layout.clusters)?,
            number: target(layout, record, attribute, lcns)?,
        });
    }
    let mut previous_undo = u64::MAX;
    for record in undo_records {
        checkpoint(cx)?;
        if record.lsn >= previous_undo {
            return Err(corrupt(
                0,
                "FILE replay undo is not strictly reverse chronological",
            ));
        }
        previous_undo = record.lsn;
        let slot = u32::from(u16_at(&record.data, 12)?);
        let attribute = targets
            .attributes
            .get(&slot)
            .filter(|attribute| attribute.opened <= record.lsn)
            .ok_or_else(|| unsupported("FILE undo target incarnation no longer survives"))?;
        let count = usize::from(u16_at(&record.data, 14)?);
        claims = claims
            .checked_add(count)
            .filter(|claims| *claims <= MAX_CLAIMS)
            .ok_or_else(|| unsupported("FILE redo/undo exceeds 65536 mapping claims"))?;
        let vcn = u64_at(&record.data, 24)?;
        let mut lcns = Vec::with_capacity(count);
        for index in 0..count {
            let vcn = vcn
                .checked_add(index as u64)
                .ok_or_else(|| corrupt(0, "FILE undo VCN overflows"))?;
            let lcn = targets
                .clusters
                .get(&(slot, vcn))
                .filter(|cluster| cluster.oldest <= record.lsn)
                .and_then(|cluster| cluster.lcn)
                .ok_or_else(|| unsupported("FILE undo spans retired or superseded allocation"))?;
            lcns.push(lcn);
        }
        let number = target(layout, record, attribute, &lcns)?;
        actions.push(Action {
            record,
            attribute,
            lcns,
            number,
            pass: RecoveryPass::Undo,
            operation: operation(record, true, layout.clusters)?,
            payload: targets::payload(record, true)?,
        });
    }
    // Reject every unsupported opcode and mapping before reading any target
    // FILE bytes. A later operation must never leave an earlier partial view.
    for action in &actions {
        if action.record.lsn == 0 || action.record.lsn > layout.boundary_lsn {
            return Err(corrupt(
                0,
                "FILE replay action is beyond its selected journal boundary",
            ));
        }
        validate_action(cx, input, action)?;
    }
    let mut stage = Staged {
        records: BTreeMap::new(),
        summary: ReplaySummary {
            records: 0,
            redo: 0,
            undo: 0,
            skipped: 0,
        },
    };
    let mut retained = 0_usize;
    for action in actions {
        checkpoint(cx)?;
        if !stage.records.contains_key(&action.number) {
            retained = retained
                .checked_add(layout.record_bytes)
                .filter(|bytes| *bytes <= MAX_BYTES)
                .ok_or_else(|| unsupported("FILE replay private records exceed 16 MiB"))?;
            if stage.records.len() == MAX_RECORDS {
                return Err(unsupported("FILE replay exceeds 4096 private records"));
            }
            let raw = input.read_record(cx, action.number)?;
            checkpoint(cx)?;
            if raw.len() != layout.record_bytes {
                return Err(corrupt(0, "short FILE replay target read"));
            }
            let record = NtfsFileRecord::parse(&raw).map_err(|error| parse(&error))?;
            if record.base.sequence != 0 && record.base.record < 16 {
                return Err(unsupported(
                    "NTFS system extension replay requires bootstrap reconstruction",
                ));
            }
            if u64_at(&raw, 8)? > layout.boundary_lsn {
                return Err(unsupported(
                    "FILE page is newer than the selected journal boundary",
                ));
            }
            stage.records.insert(action.number, raw);
        }
        let raw = stage
            .records
            .get(&action.number)
            .ok_or_else(|| corrupt(0, "FILE replay lost its private record"))?;
        let edit = FileEdit {
            operation: action.operation,
            record_offset: u16_at(&action.record.data, 16)?,
            attribute_offset: u16_at(&action.record.data, 18)?,
            data: action.payload,
        };
        match apply_file_edit(raw, action.number, action.pass, &edit)
            .map_err(|error| parse(&error))?
        {
            FileEditResult::AlreadyApplied => stage.summary.skipped += 1,
            FileEditResult::Applied(raw) => {
                stage.records.insert(action.number, raw);
                match action.pass {
                    RecoveryPass::Redo(_) => stage.summary.redo += 1,
                    RecoveryPass::Undo => stage.summary.undo += 1,
                }
            }
        }
        checkpoint(cx)?;
    }
    stage.summary.records = stage.records.len();
    checkpoint(cx)?;
    Ok(stage)
}

pub(super) fn stage(
    cx: &Cx,
    plan: &Plan<'_>,
    input: ReplayInput<'_>,
    read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>>,
) -> Result<ReplaySummary> {
    checkpoint(cx)?;
    if input.undo.prepared != 0 {
        return Err(unsupported(
            "prepared NTFS transactions need an external recovery decision",
        ));
    }
    for record in input.history {
        checkpoint(cx)?;
        if targets::changes_pages(record.summary.redo_op) && u16_at(&record.data, 14)? == 0 {
            return Err(unsupported(
                "required NTFS page operation has no replay mapping",
            ));
        }
    }
    let mut undo_records = Vec::new();
    let mut retained = 0_usize;
    for &(lsn, transaction, opcode) in &input.undo.undo {
        checkpoint(cx)?;
        let record = read_record(cx, input.restart, input.restart.file_size, lsn, read)?;
        if record.summary.transaction_id != transaction || record.summary.undo_op != opcode {
            return Err(corrupt(
                0,
                "NTFS undo application identity disagrees with Analysis",
            ));
        }
        retained = retained
            .checked_add(record.data.len())
            .filter(|bytes| *bytes <= MAX_BYTES)
            .ok_or_else(|| unsupported("FILE undo payloads exceed 16 MiB"))?;
        undo_records.push(record);
    }
    let mut volume = VolumeInput::new(cx, input.volume, input.restart.current_lsn)?;
    let staged = execute(cx, &mut volume, plan, &undo_records, input.targets)?;
    // Deliberately do not publish these bytes into NtfsVolume or a FUSE cache:
    // the newer durable log tail and other opcode families remain unimplemented.
    // Dropping this private stage is not a recovered-view or clean-volume claim.
    Ok(staged.summary)
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests;
    #[cfg(test)]
    mod directory_tests;
}
