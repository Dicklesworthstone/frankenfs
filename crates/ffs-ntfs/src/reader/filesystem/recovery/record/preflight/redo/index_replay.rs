//! Native replay of already allocated external $I30 directory nodes.
//!
//! Resolve checkpoint identities against the directory's real INDEX_ROOT,
//! INDEX_ALLOCATION and BITMAP before interpreting an operation. All buffers
//! are private. Allocation changes, tree-wide collation/reachability, system
//! directories and recovered-view publication are separate obligations.
//! Native addressing follows Linux v6.17 fs/ntfs3/fslog.c, do_action.

use super::super::super::super::super::super as reader;
use super::super::super::read_record;
use super::{
    Attribute, Candidate, Cx, LFS_CLIENT_RECORD, LogRecord, MAX_CLAIMS, MAX_PAYLOAD, MAX_RECORDS,
    NtfsVolume, Plan, ReplayInput, ReplaySummary, Result, checkpoint, corrupt, replay, targets,
    u16_at, u64_at, unsupported,
};
use ffs_ondisk::ntfs::index::{NtfsIndexRoot, parse_index_block};
use ffs_ondisk::ntfs::recovery::{
    FileEditResult, IndexEdit, IndexOperation, RecoveryPass, apply_index_edit,
};
use reader::{Storage, Stream, parse};
use std::collections::{BTreeMap, BTreeSet};

const I30: [u16; 4] = [0x24, 0x49, 0x33, 0x30];
const SECTOR: u64 = 512;
const IO_BUDGET: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy)]
struct Geometry {
    cluster_bytes: u64,
    clusters: u64,
    records: u64,
    boundary: u64,
}

#[derive(Clone, Copy)]
struct Shape {
    block_bytes: u32,
    vcn_bytes: u32,
    initialized: u64,
}

struct Directory {
    shape: Shape,
    allocation: Stream,
    bitmap: Stream,
}

trait Input {
    fn geometry(&self) -> Geometry;
    fn open(&mut self, cx: &Cx, attribute: &Attribute) -> Result<Shape>;
    fn mapped_lcn(&self, reference: u64, vcn: u64) -> Result<u64>;
    fn allocated(&mut self, cx: &Cx, reference: Option<u64>, mft: bool, bit: u64) -> Result<bool>;
    fn block(&mut self, cx: &Cx, reference: u64, offset: u64, size: usize) -> Result<Vec<u8>>;
}

struct Native<'a> {
    volume: &'a NtfsVolume,
    mft_bitmap: Stream,
    volume_bitmap: Stream,
    logfile: Stream,
    directories: BTreeMap<u64, Directory>,
    remaining: u64,
    boundary: u64,
}

fn plain(stream: &Stream, mapped: bool) -> Result<()> {
    if stream.initialized != stream.size {
        return Err(unsupported(
            "INDX recovery requires fully initialized metadata streams",
        ));
    }
    match &stream.storage {
        Storage::Mapped(runs) if !runs.is_empty() && runs.iter().all(|run| run.lcn.is_some()) => {
            Ok(())
        }
        Storage::Resident(_) if !mapped => Ok(()),
        _ => Err(unsupported(
            "INDX recovery metadata is sparse, transformed or not mapped",
        )),
    }
}

fn bitmap(stream: &Stream, bits: u64) -> Result<()> {
    plain(stream, false)?;
    if stream.size < bits.div_ceil(8) {
        return Err(corrupt(0, "INDX recovery allocation bitmap is truncated"));
    }
    Ok(())
}

fn contains(stream: &Stream, lcn: u64) -> bool {
    matches!(&stream.storage, Storage::Mapped(runs) if runs.iter().any(|run| {
        run.lcn.is_some_and(|start| lcn >= start && lcn - start < run.clusters)
    }))
}

impl<'a> Native<'a> {
    fn new(cx: &Cx, volume: &'a NtfsVolume, boundary: u64) -> Result<Self> {
        let mft = volume.record(cx, 0, None)?;
        let mft_bitmap = volume.select_stream(cx, &mft, 0xB0, &[])?;
        bitmap(&mft_bitmap, volume.record_count())?;
        let allocation = volume.record(cx, 6, None)?;
        let volume_bitmap = volume.data_stream(cx, &allocation, &[])?;
        bitmap(&volume_bitmap, volume.geometry.cluster_count())?;
        let log = volume.record(cx, 2, None)?;
        let logfile = volume.data_stream(cx, &log, &[])?;
        plain(&logfile, true)?;
        Ok(Self {
            volume,
            mft_bitmap,
            volume_bitmap,
            logfile,
            directories: BTreeMap::new(),
            remaining: IO_BUDGET,
            boundary,
        })
    }

    fn charge(&mut self, bytes: u64) -> Result<()> {
        self.remaining = self
            .remaining
            .checked_sub(bytes)
            .ok_or_else(|| unsupported("INDX recovery exceeds 64 MiB of target reads"))?;
        Ok(())
    }
}

impl Input for Native<'_> {
    fn geometry(&self) -> Geometry {
        Geometry {
            cluster_bytes: u64::from(self.volume.geometry.cluster_bytes()),
            clusters: self.volume.geometry.cluster_count(),
            records: self.volume.record_count(),
            boundary: self.boundary,
        }
    }

    fn open(&mut self, cx: &Cx, attribute: &Attribute) -> Result<Shape> {
        let reference = attribute.reference;
        if let Some(directory) = self.directories.get(&reference) {
            if directory.shape.block_bytes != attribute.index_bytes {
                return Err(corrupt(0, "different open slots disagree on INDX geometry"));
            }
            return Ok(directory.shape);
        }
        if self.directories.len() == MAX_RECORDS {
            return Err(unsupported("INDX recovery exceeds 4096 directories"));
        }
        self.charge(u64::from(self.volume.geometry.record_bytes()))?;
        let owner = ffs_ondisk::ntfs::NtfsReference::decode(reference);
        let record = self.volume.record(cx, owner.record, Some(owner.sequence))?;
        if !record.is_directory() || record.base.record != 0 || record.base.sequence != 0 {
            return Err(corrupt(
                0,
                "INDX recovery owner is not a base directory FILE",
            ));
        }
        if u64_at(record.used_bytes(), 8)? > self.boundary {
            return Err(unsupported(
                "INDX owner is newer than the selected journal boundary",
            ));
        }
        let root = self.volume.select_stream(cx, &record, 0x90, &I30)?;
        plain(&root, false)?;
        if !root.resident() || root.size > 65_536 {
            return Err(corrupt(
                0,
                "INDX recovery needs a bounded resident INDEX_ROOT",
            ));
        }
        self.charge(root.size)?;
        let bytes = self.volume.read(cx, &root, 0, root.size as usize)?;
        let root = NtfsIndexRoot::parse(&bytes, self.volume.geometry.cluster_bytes())
            .map_err(|error| parse(&error))?;
        if root.block_bytes != attribute.index_bytes {
            return Err(corrupt(
                0,
                "native open-attribute and INDEX_ROOT block sizes disagree",
            ));
        }
        let allocation = self.volume.select_stream(cx, &record, 0xA0, &I30)?;
        plain(&allocation, true)?;
        if allocation.size == 0 || !allocation.size.is_multiple_of(u64::from(root.block_bytes)) {
            return Err(corrupt(0, "INDEX_ALLOCATION ends inside an INDX block"));
        }
        let map = self.volume.select_stream(cx, &record, 0xB0, &I30)?;
        bitmap(&map, allocation.size / u64::from(root.block_bytes))?;
        let shape = Shape {
            block_bytes: root.block_bytes,
            vcn_bytes: root.vcn_bytes,
            initialized: allocation.initialized,
        };
        self.directories.insert(
            reference,
            Directory {
                shape,
                allocation,
                bitmap: map,
            },
        );
        checkpoint(cx)?;
        Ok(shape)
    }

    fn mapped_lcn(&self, reference: u64, vcn: u64) -> Result<u64> {
        let directory = self
            .directories
            .get(&reference)
            .ok_or_else(|| corrupt(0, "INDX recovery lost its opened directory"))?;
        let Storage::Mapped(runs) = &directory.allocation.storage else {
            return Err(corrupt(0, "INDX recovery lost its nonresident mapping"));
        };
        let index = runs
            .partition_point(|run| run.vcn <= vcn)
            .checked_sub(1)
            .ok_or_else(|| corrupt(0, "INDX VCN precedes the allocation stream"))?;
        let run = &runs[index];
        let within = vcn - run.vcn;
        let lcn = run
            .lcn
            .filter(|_| within < run.clusters)
            .and_then(|start| start.checked_add(within))
            .ok_or_else(|| corrupt(0, "INDX allocation has a mapping gap"))?;
        if [
            &self.volume.mft,
            &self.mft_bitmap,
            &self.volume_bitmap,
            &self.logfile,
            &directory.bitmap,
        ]
        .into_iter()
        .any(|stream| contains(stream, lcn))
        {
            return Err(corrupt(
                0,
                "INDX target aliases MFT, journal or allocation metadata",
            ));
        }
        Ok(lcn)
    }

    fn allocated(&mut self, cx: &Cx, reference: Option<u64>, mft: bool, bit: u64) -> Result<bool> {
        self.charge(1)?;
        let stream = if let Some(reference) = reference {
            &self
                .directories
                .get(&reference)
                .ok_or_else(|| corrupt(0, "INDX bitmap has no directory identity"))?
                .bitmap
        } else if mft {
            &self.mft_bitmap
        } else {
            &self.volume_bitmap
        };
        let value = self.volume.read(cx, stream, bit / 8, 1)?;
        let byte = value
            .first()
            .ok_or_else(|| corrupt(0, "short INDX allocation bitmap read"))?;
        checkpoint(cx)?;
        Ok(*byte & (1_u8 << (bit % 8)) != 0)
    }

    fn block(&mut self, cx: &Cx, reference: u64, offset: u64, size: usize) -> Result<Vec<u8>> {
        self.charge(size as u64)?;
        let stream = &self
            .directories
            .get(&reference)
            .ok_or_else(|| corrupt(0, "INDX read has no directory identity"))?
            .allocation;
        self.volume.read(cx, stream, offset, size)
    }
}

struct Action<'a> {
    record: &'a LogRecord,
    attribute: &'a Attribute,
    lcns: Vec<u64>,
    undo: bool,
}

fn index_target(attribute: &Attribute) -> bool {
    attribute.kind == 0xA0
}

fn operation(opcode: u16) -> Result<IndexOperation> {
    match opcode {
        0x0E => Ok(IndexOperation::AddEntry),
        0x0F => Ok(IndexOperation::DeleteEntry),
        0x10 => Ok(IndexOperation::WriteEnd),
        0x12 => Ok(IndexOperation::SetChild),
        0x14 => Ok(IndexOperation::UpdateFileName),
        _ => Err(unsupported(
            "native INDX opcode has no directory-node executor",
        )),
    }
}

fn identity(action: &Action<'_>, geometry: Geometry) -> Result<()> {
    let owner = ffs_ondisk::ntfs::NtfsReference::decode(action.attribute.reference);
    if !index_target(action.attribute)
        || action.attribute.name != I30
        || owner.sequence == 0
        || owner.record < 16
        || owner.record >= geometry.records
        || action.attribute.opened > action.record.lsn
    {
        return Err(unsupported(
            "INDX replay requires a surviving non-system $I30 directory identity",
        ));
    }
    if action.record.kind != LFS_CLIENT_RECORD
        || action.record.lsn == 0
        || action.record.lsn > geometry.boundary
        || action.record.summary.transaction_id == 0
        || action.lcns.is_empty()
        || action.lcns.len() != usize::from(u16_at(&action.record.data, 14)?)
    {
        return Err(corrupt(
            0,
            "invalid INDX replay record identity or mapping count",
        ));
    }
    let opcode = if action.undo {
        action.record.summary.undo_op
    } else {
        action.record.summary.redo_op
    };
    if u16_at(&action.record.data, if action.undo { 2 } else { 0 })? != opcode {
        return Err(corrupt(
            0,
            "INDX replay summary differs from its native opcode",
        ));
    }
    operation(opcode)?;
    targets::payload(action.record, action.undo)?;
    Ok(())
}

/// Native record_off selects the INDX buffer inside the logged transfer;
/// attr_off remains relative to that buffer, not to the containing cluster.
fn location(action: &Action<'_>, geometry: Geometry, shape: Shape) -> Result<u64> {
    let cluster = geometry.cluster_bytes;
    let block = u64::from(shape.block_bytes);
    if !(512..=65_536).contains(&block)
        || !block.is_power_of_two()
        || shape.block_bytes != action.attribute.index_bytes
        || u64::from(shape.vcn_bytes) != if block < cluster { 512 } else { cluster }
        || !shape.initialized.is_multiple_of(block)
    {
        return Err(corrupt(0, "invalid native INDX block/VBN geometry"));
    }
    let displacement = u64::from(u16_at(&action.record.data, 20)?) * SECTOR
        + u64::from(u16_at(&action.record.data, 16)?);
    let span = (action.lcns.len() as u64)
        .checked_mul(cluster)
        .ok_or_else(|| corrupt(0, "INDX transfer span overflows"))?;
    let logical = u64_at(&action.record.data, 24)?
        .checked_mul(cluster)
        .and_then(|start| start.checked_add(displacement))
        .ok_or_else(|| corrupt(0, "INDX logical target overflows"))?;
    if displacement.checked_add(block).is_none_or(|end| end > span)
        || !logical.is_multiple_of(block)
        || logical
            .checked_add(block)
            .is_none_or(|end| end > shape.initialized)
    {
        return Err(corrupt(
            logical,
            "INDX target exceeds its logged or initialized allocation",
        ));
    }
    Ok(logical)
}

fn node(
    cx: &Cx,
    input: &mut impl Input,
    reference: u64,
    shape: Shape,
    offset: u64,
    raw: &[u8],
) -> Result<()> {
    if raw.len() != shape.block_bytes as usize {
        return Err(corrupt(offset, "short INDX recovery target"));
    }
    let vbn = offset / u64::from(shape.vcn_bytes);
    let owner = ffs_ondisk::ntfs::NtfsReference::decode(reference);
    let mut children = BTreeSet::new();
    for entry in parse_index_block(raw, vbn).map_err(|error| parse(&error))? {
        checkpoint(cx)?;
        if let Some((file, name)) = entry.key {
            if name.parent != owner
                || file.sequence == 0
                || file.record >= input.geometry().records
                || !input.allocated(cx, None, true, file.record)?
            {
                return Err(corrupt(
                    offset,
                    "INDX key has a foreign parent or unallocated FILE reference",
                ));
            }
        }
        if let Some(child) = entry.child_vcn {
            let address = child
                .checked_mul(u64::from(shape.vcn_bytes))
                .ok_or_else(|| corrupt(offset, "INDX child VBN overflows"))?;
            let block = u64::from(shape.block_bytes);
            if child == vbn
                || !children.insert(child)
                || !address.is_multiple_of(block)
                || address
                    .checked_add(block)
                    .is_none_or(|end| end > shape.initialized)
                || !input.allocated(cx, Some(reference), false, address / block)?
            {
                return Err(corrupt(
                    offset,
                    "INDX child is self-referential, misaligned or unallocated",
                ));
            }
        }
    }
    checkpoint(cx)
}

struct Staged {
    blocks: BTreeMap<(u64, u64), Vec<u8>>,
    summary: ReplaySummary,
}

fn execute(cx: &Cx, input: &mut impl Input, actions: &[Action<'_>]) -> Result<Staged> {
    checkpoint(cx)?;
    let geometry = input.geometry();
    if !(512..=65_536).contains(&geometry.cluster_bytes)
        || !geometry.cluster_bytes.is_power_of_two()
        || geometry.clusters == 0
        || actions.len() > 2 * MAX_RECORDS
    {
        return Err(unsupported("INDX replay exceeds geometry or action limits"));
    }
    let mut claims = 0_usize;
    let mut bytes = 0_usize;
    let mut previous_redo = 0;
    let mut previous_undo = u64::MAX;
    let mut undo_started = false;
    // No directory or target I/O until EVERY operation and payload is bounded.
    for action in actions {
        checkpoint(cx)?;
        identity(action, geometry)?;
        if action.undo {
            undo_started = true;
            if action.record.lsn >= previous_undo {
                return Err(corrupt(0, "INDX loser undo is not reverse chronological"));
            }
            previous_undo = action.record.lsn;
        } else {
            if undo_started || action.record.lsn <= previous_redo {
                return Err(corrupt(0, "INDX redo is not chronological or follows undo"));
            }
            previous_redo = action.record.lsn;
        }
        claims = claims
            .checked_add(action.lcns.len())
            .filter(|count| *count <= MAX_CLAIMS)
            .ok_or_else(|| unsupported("INDX replay exceeds 65536 mapping claims"))?;
        bytes = bytes
            .checked_add(targets::payload(action.record, action.undo)?.len())
            .filter(|bytes| *bytes <= MAX_PAYLOAD)
            .ok_or_else(|| unsupported("INDX replay payloads exceed 16 MiB"))?;
    }
    let mut staged = Staged {
        blocks: BTreeMap::new(),
        summary: ReplaySummary {
            records: 0,
            redo: 0,
            undo: 0,
            skipped: 0,
        },
    };
    let mut retained = 0_usize;
    let mut physical = BTreeMap::new();
    for action in actions {
        checkpoint(cx)?;
        let reference = action.attribute.reference;
        let owner = ffs_ondisk::ntfs::NtfsReference::decode(reference);
        let shape = input.open(cx, action.attribute)?;
        let offset = location(action, geometry, shape)?;
        if !input.allocated(cx, None, true, owner.record)?
            || !input.allocated(
                cx,
                Some(reference),
                false,
                offset / u64::from(shape.block_bytes),
            )?
        {
            return Err(corrupt(
                offset,
                "INDX recovery targets an unallocated directory or index block",
            ));
        }
        let first = u64_at(&action.record.data, 24)?;
        for (index, &lcn) in action.lcns.iter().enumerate() {
            checkpoint(cx)?;
            let vcn = first
                .checked_add(index as u64)
                .ok_or_else(|| corrupt(offset, "INDX VCN claim overflows"))?;
            if lcn == 0
                || lcn >= geometry.clusters
                || input.mapped_lcn(reference, vcn)? != lcn
                || !input.allocated(cx, None, false, lcn)?
            {
                return Err(corrupt(
                    offset,
                    "INDX recovery mapping is stale, unallocated or outside the volume",
                ));
            }
            if physical
                .insert(lcn, (reference, vcn))
                .is_some_and(|previous| previous != (reference, vcn))
            {
                return Err(corrupt(
                    offset,
                    "different INDX streams or VCNs alias one physical cluster",
                ));
            }
        }
        let key = (reference, offset);
        if !staged.blocks.contains_key(&key) {
            retained = retained
                .checked_add(shape.block_bytes as usize)
                .filter(|bytes| *bytes <= MAX_PAYLOAD)
                .ok_or_else(|| unsupported("INDX replay staging exceeds 16 MiB"))?;
            if staged.blocks.len() == MAX_RECORDS {
                return Err(unsupported("INDX replay staging exceeds 4096 blocks"));
            }
            let raw = input.block(cx, reference, offset, shape.block_bytes as usize)?;
            node(cx, input, reference, shape, offset, &raw)?;
            if u64_at(&raw, 8)? > geometry.boundary {
                return Err(unsupported(
                    "INDX page is newer than the selected journal boundary",
                ));
            }
            staged.blocks.insert(key, raw);
        }
        let raw = staged
            .blocks
            .get(&key)
            .ok_or_else(|| corrupt(offset, "INDX replay lost its private block"))?;
        let opcode = if action.undo {
            action.record.summary.undo_op
        } else {
            action.record.summary.redo_op
        };
        let edit = IndexEdit {
            operation: operation(opcode)?,
            entry_offset: u16_at(&action.record.data, 18)?,
            data: targets::payload(action.record, action.undo)?,
        };
        let pass = if action.undo {
            RecoveryPass::Undo
        } else {
            RecoveryPass::Redo(action.record.lsn)
        };
        match apply_index_edit(raw, offset / u64::from(shape.vcn_bytes), pass, &edit)
            .map_err(|error| parse(&error))?
        {
            FileEditResult::AlreadyApplied => staged.summary.skipped += 1,
            FileEditResult::Applied(raw) => {
                node(cx, input, reference, shape, offset, &raw)?;
                staged.blocks.insert(key, raw);
                if action.undo {
                    staged.summary.undo += 1;
                } else {
                    staged.summary.redo += 1;
                }
            }
        }
    }
    staged.summary.records = staged.blocks.len();
    checkpoint(cx)?;
    Ok(staged)
}

/// Partition only execution targets; Analysis and native undo order are shared.
/// MFT and INDX buffers never escape until both private stages have succeeded.
pub(super) fn stage(
    cx: &Cx,
    plan: &Plan<'_>,
    input: ReplayInput<'_>,
    read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>>,
) -> Result<ReplaySummary> {
    let has_index = plan
        .candidates
        .iter()
        .any(|candidate| index_target(candidate.attribute))
        || input
            .undo
            .undo
            .iter()
            .any(|&(_, _, opcode)| matches!(opcode, 0x0E..=0x10 | 0x12 | 0x14));
    if !has_index {
        return replay::stage(cx, plan, input, read);
    }
    checkpoint(cx)?;
    if input.undo.prepared != 0 || input.undo.undo.len() > MAX_RECORDS {
        return Err(unsupported(
            "INDX undo requires resolved, bounded transaction Analysis",
        ));
    }
    for record in input.history {
        checkpoint(cx)?;
        if record.kind == LFS_CLIENT_RECORD
            && targets::changes_pages(record.summary.redo_op)
            && u16_at(&record.data, 14)? == 0
        {
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
        if record.kind != LFS_CLIENT_RECORD
            || record.summary.transaction_id != transaction
            || record.summary.undo_op != opcode
        {
            return Err(corrupt(
                0,
                "INDX undo identity disagrees with transaction Analysis",
            ));
        }
        retained = retained
            .checked_add(record.data.len())
            .filter(|bytes| *bytes <= MAX_PAYLOAD)
            .ok_or_else(|| unsupported("combined native undo records exceed 16 MiB"))?;
        undo_records.push(record);
    }
    let mut files = Plan {
        candidates: Vec::new(),
        obsolete: plan.obsolete,
        relocated: plan.relocated,
    };
    let mut actions = Vec::new();
    for candidate in &plan.candidates {
        if index_target(candidate.attribute) {
            actions.push(Action {
                record: candidate.record,
                attribute: candidate.attribute,
                lcns: candidate.lcns.clone(),
                undo: false,
            });
        } else {
            files.candidates.push(Candidate {
                record: candidate.record,
                attribute: candidate.attribute,
                lcns: candidate.lcns.clone(),
                payload: candidate.payload,
            });
        }
    }
    let mut file_undo = super::super::analysis::Report {
        active: input.undo.active,
        prepared: input.undo.prepared,
        committed: input.undo.committed,
        undo: Vec::new(),
    };
    let mut undo_claims = 0_usize;
    for record in &undo_records {
        let slot = u32::from(u16_at(&record.data, 12)?);
        let attribute = input
            .targets
            .attributes
            .get(&slot)
            .filter(|attribute| attribute.opened <= record.lsn)
            .ok_or_else(|| unsupported("native undo target incarnation no longer survives"))?;
        if !index_target(attribute) {
            file_undo.undo.push((
                record.lsn,
                record.summary.transaction_id,
                record.summary.undo_op,
            ));
            continue;
        }
        let count = usize::from(u16_at(&record.data, 14)?);
        undo_claims = undo_claims
            .checked_add(count)
            .filter(|claims| *claims <= MAX_CLAIMS)
            .ok_or_else(|| unsupported("INDX undo exceeds 65536 mapping claims"))?;
        let first = u64_at(&record.data, 24)?;
        let mut lcns = Vec::with_capacity(count);
        for index in 0..count {
            checkpoint(cx)?;
            let vcn = first
                .checked_add(index as u64)
                .ok_or_else(|| corrupt(0, "INDX undo VCN overflows"))?;
            lcns.push(
                input
                    .targets
                    .clusters
                    .get(&(slot, vcn))
                    .filter(|cluster| cluster.oldest <= record.lsn)
                    .and_then(|cluster| cluster.lcn)
                    .ok_or_else(|| {
                        unsupported("INDX undo spans retired or superseded allocation")
                    })?,
            );
        }
        actions.push(Action {
            record,
            attribute,
            lcns,
            undo: true,
        });
    }
    // Static index dispatch before target reads in either executor.
    let geometry = Geometry {
        cluster_bytes: u64::from(input.volume.geometry.cluster_bytes()),
        clusters: input.volume.geometry.cluster_count(),
        records: input.volume.record_count(),
        boundary: input.restart.current_lsn,
    };
    for action in &actions {
        identity(action, geometry)?;
    }
    let file_summary = if files.candidates.is_empty() && file_undo.undo.is_empty() {
        ReplaySummary {
            records: 0,
            redo: 0,
            undo: 0,
            skipped: 0,
        }
    } else {
        replay::stage(
            cx,
            &files,
            ReplayInput {
                undo: &file_undo,
                ..input
            },
            read,
        )?
    };
    let mut native = Native::new(cx, input.volume, input.restart.current_lsn)?;
    let indexes = execute(cx, &mut native, &actions)?;
    checkpoint(cx)?;
    Ok(ReplaySummary {
        records: file_summary.records + indexes.summary.records,
        redo: file_summary.redo + indexes.summary.redo,
        undo: file_summary.undo + indexes.summary.undo,
        skipped: file_summary.skipped + indexes.summary.skipped,
    })
}

#[cfg(test)]
mod tests;
