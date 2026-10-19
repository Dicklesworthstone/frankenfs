//! Bounded, private MFT redo/undo execution through a selected restart boundary.
//!
//! No backing writes, native CLR publication or recovered-mount admission.
//! Unknown required operations abort the complete stage, never a partial view.

use super::super::super::super::super::super as reader;
use super::super::super::super as journal;
use super::super::super::tail;
use super::super::{
    LogRecord, analyze, checkpoint, corrupt, read_record, targets, u16_at, u64_at, unsupported,
};
use super::{Candidate, Plan, ReplayInput, ReplaySummary, build};
use ffs_ondisk::ntfs::recovery::{
    FileEdit, FileEditResult, FileOperation, IndexOperation, RecoveryPass, apply_file_edit,
};
use ffs_ondisk::ntfs::{
    DATA, NtfsFileRecord, NtfsLogFilePlan, NtfsLogOp, NtfsLogRestartArea, NtfsRecoveryAction,
};
use reader::{Cx, NtfsVolume, Result, Storage, Stream, parse};
use std::collections::{BTreeMap, BTreeSet};

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
    // Do not publish private records here. Public export consumes the same
    // analysis but still requires the allocation-preserving semantic publisher;
    // diagnostic preflight must not alter a volume or claim it is clean.
    Ok(staged.summary)
}

fn native_restart(restart: &journal::Restart) -> Result<NtfsLogRestartArea> {
    Ok(NtfsLogRestartArea {
        chkdsk_lsn: 0,
        system_page_size: restart.system_page,
        log_page_size: restart.log_page,
        major_version: i16::try_from(restart.version.0)
            .map_err(|_| corrupt(0, "native recovery version exceeds its wire field"))?,
        minor_version: i16::try_from(restart.version.1)
            .map_err(|_| corrupt(0, "native recovery version exceeds its wire field"))?,
        current_lsn: restart.current_lsn,
        oldest_lsn: restart.active_client_oldest_lsn.unwrap_or(0),
        client_restart_lsn: restart.active_client_restart_lsn.unwrap_or(0),
        // Only the private endpoint advances; native clean state is unchanged.
        flags: u16_at(&restart.area, 14)?,
        file_size: restart.file_size,
        record_header_length: restart.record_header_len,
        log_page_data_offset: restart.data_off,
    })
}

fn empty_plan(restart: &journal::Restart) -> Result<NtfsLogFilePlan> {
    Ok(NtfsLogFilePlan {
        restart: native_restart(restart)?,
        records_parsed: 0,
        committed_transactions: Vec::new(),
        aborted_transactions: Vec::new(),
        dirty_lcns: Vec::new(),
        redo_actions: Vec::new(),
        undo_actions: Vec::new(),
    })
}

#[derive(Default)]
struct ExportBudget {
    bytes: usize,
    claims: usize,
}

impl ExportBudget {
    fn action(
        &mut self,
        record: &LogRecord,
        undo: bool,
        lcns: Vec<u64>,
    ) -> Result<NtfsRecoveryAction> {
        let payload = targets::payload(record, undo)?;
        self.bytes = self
            .bytes
            .checked_add(payload.len())
            .filter(|bytes| *bytes <= MAX_BYTES)
            .ok_or_else(|| unsupported("native recovery export exceeds 16 MiB of payloads"))?;
        self.claims = self
            .claims
            .checked_add(lcns.len())
            .filter(|claims| *claims <= MAX_CLAIMS)
            .ok_or_else(|| unsupported("native recovery export exceeds 65536 mapping claims"))?;
        if lcns.len() != usize::from(u16_at(&record.data, 14)?) || lcns.is_empty() {
            return Err(corrupt(
                0,
                "native recovery export lost its complete target mapping",
            ));
        }
        Ok(NtfsRecoveryAction {
            lsn: record.lsn,
            transaction_id: record.summary.transaction_id,
            is_undo: undo,
            op: NtfsLogOp::from_raw(if undo {
                record.summary.undo_op
            } else {
                record.summary.redo_op
            }),
            target_vcn: u64_at(&record.data, 24)?,
            target_lcns: lcns,
            resident_resize: u16_at(&record.data, 6)? != u16_at(&record.data, 10)?,
            cluster_block_offset: u16_at(&record.data, 20)?,
            record_offset: u16_at(&record.data, 16)?,
            attribute_offset: u16_at(&record.data, 18)?,
            data: payload.to_vec(),
        })
    }
}

/// Export exactly the history already checked by native checkpoint Analysis
/// and private MFT execution. The public publisher separately limits edits to
/// allocation-preserving resident metadata; no raw physical fallback exists.
fn export(
    cx: &Cx,
    volume: &NtfsVolume,
    restart: &journal::Restart,
    read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>>,
) -> Result<NtfsLogFilePlan> {
    let tail_record = read_record(cx, restart, restart.file_size, restart.current_lsn, read)?;
    let analyzed = analyze(
        cx,
        restart,
        restart.file_size,
        &tail_record,
        read,
        Some(volume),
    )?;
    let targets = analyzed.targets.as_ref().ok_or_else(|| {
        unsupported("public NTFS recovery requires a native checkpoint target table")
    })?;
    if analyzed.report.prepared != 0 {
        return Err(unsupported(
            "prepared NTFS transactions need an external recovery decision",
        ));
    }
    let candidates = build(cx, targets, &analyzed.history)?;
    let mut budget = ExportBudget::default();
    let mut plan = empty_plan(restart)?;
    plan.records_parsed = analyzed.history.len();
    // Report live endpoint identities, not an invented historical commit list.
    (plan.committed_transactions, plan.aborted_transactions) = analyzed.state.transaction_ids();
    for candidate in &candidates.candidates {
        checkpoint(cx)?;
        plan.redo_actions
            .push(budget.action(candidate.record, false, candidate.lcns.clone())?);
    }
    for &(lsn, owner, opcode) in &analyzed.report.undo {
        checkpoint(cx)?;
        let record = read_record(cx, restart, restart.file_size, lsn, read)?;
        if record.summary.transaction_id != owner || record.summary.undo_op != opcode {
            return Err(corrupt(
                0,
                "native recovery export disagrees with undo Analysis",
            ));
        }
        let slot = u32::from(u16_at(&record.data, 12)?);
        if targets
            .attributes
            .get(&slot)
            .is_none_or(|attribute| attribute.opened > lsn)
        {
            return Err(unsupported("native undo target incarnation no longer survives"));
        }
        let count = usize::from(u16_at(&record.data, 14)?);
        let first = u64_at(&record.data, 24)?;
        let mut lcns = Vec::with_capacity(count);
        for index in 0..count {
            checkpoint(cx)?;
            let vcn = first
                .checked_add(index as u64)
                .ok_or_else(|| corrupt(0, "native undo export VCN overflows"))?;
            let lcn = targets
                .clusters
                .get(&(slot, vcn))
                .filter(|cluster| cluster.oldest <= lsn)
                .and_then(|cluster| cluster.lcn)
                .ok_or_else(|| unsupported("native undo export spans retired allocation"))?;
            lcns.push(lcn);
        }
        plan.undo_actions.push(budget.action(&record, true, lcns)?);
    }
    plan.dirty_lcns = plan
        .redo_actions
        .iter()
        .chain(&plan.undo_actions)
        .flat_map(|action| action.target_lcns.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    checkpoint(cx)?;
    Ok(plan)
}

impl NtfsVolume {
    /// None means the complete initialized journal was verified erased. Errors
    /// never become an empty plan, stale-checkpoint fallback or raw memcpy.
    pub(crate) fn native_recovery_plan(&self, cx: &Cx) -> Result<Option<NtfsLogFilePlan>> {
        checkpoint(cx)?;
        let record = self.record(cx, 2, None)?;
        let stream = self.data_stream(cx, &record, &[])?;
        journal::validate_storage(&stream)?;
        let length = stream.size;
        // Retain the public command's pre-I/O work bound. Native page/ring and
        // graph budgets apply independently after this complete stream check.
        if !(journal::MIN_LOG..=reader::MAX_READ as u64).contains(&length)
            || !length.is_multiple_of(journal::SECTOR as u64)
        {
            return Err(unsupported("native recovery journal exceeds its complete read profile"));
        }
        let mut source = |offset, size| self.read(cx, &stream, offset, size);
        let prefix = journal::read_exact(cx, length, 0, journal::SECTOR, &mut source)?;
        if prefix.iter().all(|byte| *byte == 0xFF) {
            journal::assess_volume(cx, length, source, None)?;
            return Ok(None);
        }
        let page = journal::page_size(journal::u32_at(&prefix, 16)?)?;
        let first = journal::restart(
            cx,
            journal::read_exact(cx, length, 0, page, &mut source)?,
            length,
        )?;
        let second = journal::restart(
            cx,
            journal::read_exact(cx, length, page as u64, page, &mut source)?,
            length,
        )?;
        let selected = journal::selection::choose(&first, &second)?;
        if selected.file_size != length {
            return Err(corrupt(
                0,
                "native restart size disagrees with complete journal DATA",
            ));
        }
        if selected.clean {
            checkpoint(cx)?;
            return empty_plan(selected).map(Some);
        }
        tail::with_latest(cx, selected, length, &mut source, |boundary, view| {
            let mut read = |offset, size| view(offset, size);
            export(cx, self, boundary, &mut read).map(Some)
        })
    }
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests;
    #[cfg(test)]
    mod directory_tests;
    #[cfg(test)]
    mod public_tests;
}
