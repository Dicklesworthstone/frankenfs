//! Checkpoint dumps and retained transaction-graph preflight.
//!
//! Native layouts: Linux v6.17 fs/ntfs3/fslog.c (NTFS_RESTART,
//! RESTART_TABLE, TRANSACTION_ENTRY, DIR_PAGE_ENTRY, OPEN_ATTR_ENRTY).
//! No redo, undo, or backing writes occur here.
//! Chronological traversal includes interleaved records after checkpoint-start.
//! Transaction Analysis and loser undo planning do not make an image mountable.

mod analysis;
mod scan;
mod table;
mod targets;

use super::{
    Cx, LFS_CLIENT_RECORD, LFS_CLIENT_RESTART, LogRecord, Restart, Result, checkpoint,
    corrupt, read_record, u16_at, u32_at, u64_at, unsupported, validate_lsn_reference,
};
use std::collections::{BTreeMap, BTreeSet};
use table::RestartTable;

const MAX_REFERENCED_RECORDS: usize = 4096;

#[derive(Default)]
struct References {
    pending: Vec<(u64, u32)>,
    owners: BTreeMap<u64, u32>,
}

impl References {
    fn add(&mut self, restart: &Restart, lsn: u64, transaction: u32) -> Result<()> {
        if lsn == 0 {
            return Ok(());
        }
        validate_lsn_reference(restart, lsn, "transaction")?;
        if restart.active_client_oldest_lsn.is_some_and(|oldest| lsn < oldest) {
            return Err(unsupported(
                "$LogFile transaction history predates the retained client window",
            ));
        }
        if let Some(owner) = self.owners.get(&lsn) {
            if *owner != transaction {
                return Err(corrupt(0, "$LogFile record is claimed by different transactions"));
            }
            return Ok(());
        }
        if self.owners.len() >= MAX_REFERENCED_RECORDS {
            return Err(unsupported("$LogFile preflight exceeds 4096 referenced records"));
        }
        self.owners.insert(lsn, transaction);
        self.pending.push((lsn, transaction));
        Ok(())
    }

    fn links(&mut self, restart: &Restart, record: &LogRecord) -> Result<()> {
        self.add(restart, record.previous, record.summary.transaction_id)?;
        self.add(restart, record.undo_next, record.summary.transaction_id)
    }
}

#[derive(Clone, Copy)]
struct Dump {
    lsn_offset: usize,
    size_offset: usize,
    opcode: u16,
}

const ATTRIBUTES: Dump = Dump { lsn_offset: 16, size_offset: 48, opcode: 0x1D };
const NAMES: Dump = Dump { lsn_offset: 24, size_offset: 52, opcode: 0x1E };
const DIRTY: Dump = Dump { lsn_offset: 32, size_offset: 56, opcode: 0x1F };
const TRANSACTIONS: Dump = Dump { lsn_offset: 40, size_offset: 60, opcode: 0x20 };

fn load_dump(
    cx: &Cx,
    restart: &Restart,
    stream_length: u64,
    checkpoint_record: &LogRecord,
    spec: Dump,
    read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>>,
) -> Result<Option<Vec<u8>>> {
    checkpoint(cx)?;
    let lsn = u64_at(&checkpoint_record.data, spec.lsn_offset)?;
    let size = usize::try_from(u32_at(&checkpoint_record.data, spec.size_offset)?)
        .map_err(|_| corrupt(0, "$LogFile checkpoint dump size overflow"))?;
    if (lsn == 0) != (size == 0) {
        return Err(corrupt(0, "$LogFile checkpoint dump has an unpaired LSN/length"));
    }
    if lsn == 0 {
        return Ok(None);
    }
    if lsn >= checkpoint_record.lsn {
        return Err(corrupt(0, "$LogFile checkpoint dump does not precede its checkpoint"));
    }
    let record = read_record(cx, restart, stream_length, lsn, read)?;
    if record.kind != LFS_CLIENT_RECORD || record.summary.redo_op != spec.opcode {
        return Err(corrupt(0, "$LogFile checkpoint reference names the wrong dump record"));
    }
    let minimum = 32 + usize::from(u16_at(&record.data, 14)?).max(1) * 8;
    // AttributeNamesDump stores its array immediately after the variable LCN
    // header; unlike restart-table dumps, it need not carry a redo_off range.
    let start = if spec.opcode == NAMES.opcode {
        minimum
    } else {
        usize::from(u16_at(&record.data, 4)?)
    };
    let end = start
        .checked_add(size)
        .filter(|end| *end <= record.data.len())
        .ok_or_else(|| corrupt(0, "$LogFile checkpoint dump exceeds its client record"))?;
    if start < minimum || !start.is_multiple_of(8) {
        return Err(corrupt(0, "$LogFile checkpoint dump enters its native header"));
    }
    // Dump lengths are u32 in NTFS_RESTART. Do not truncate them to the u16
    // ordinary-update redo_len: large checkpoint tables can exceed 64 KiB.
    let mut result = crate::reader::buffer(size)?;
    result.copy_from_slice(&record.data[start..end]);
    checkpoint(cx)?;
    Ok(Some(result))
}

fn older_reference(restart: &Restart, lsn: u64, boundary: u64, label: &str) -> Result<()> {
    validate_lsn_reference(restart, lsn, label)?;
    if lsn > boundary {
        return Err(corrupt(0, format!("$LogFile {label} is newer than its checkpoint")));
    }
    Ok(())
}

fn attributes(cx: &Cx, restart: &Restart, table: &RestartTable<'_>, boundary: u64) -> Result<()> {
    if table.entry_size != 40 {
        return Err(unsupported("$LogFile open-attribute table needs the native 40-byte profile"));
    }
    for entry in table.entries.values() {
        checkpoint(cx)?;
        let kind = u32_at(entry, 8)?;
        if kind < 0x10 || kind > 0x100 || !kind.is_multiple_of(0x10) {
            return Err(unsupported("$LogFile checkpoint contains an unknown attribute type"));
        }
        if u64_at(entry, 16)? == 0 {
            return Err(corrupt(0, "$LogFile open attribute has an empty file reference"));
        }
        older_reference(restart, u64_at(entry, 24)?, boundary, "open-attribute")?;
    }
    Ok(())
}

fn names(cx: &Cx, data: &[u8], attributes: Option<&RestartTable<'_>>) -> Result<()> {
    let mut at = 0_usize;
    let mut seen = BTreeSet::new();
    loop {
        checkpoint(cx)?;
        let target = u32::from(u16_at(data, at)?);
        let bytes = usize::from(u16_at(data, at + 2)?);
        if target == 0 {
            if bytes != 0 || data[at + 4..].iter().any(|byte| *byte != 0) {
                return Err(corrupt(0, "invalid $LogFile attribute-name terminator"));
            }
            return Ok(());
        }
        if !bytes.is_multiple_of(2)
            || bytes > 510
            || attributes.is_none_or(|table| !table.entries.contains_key(&target))
            || !seen.insert(target)
        {
            return Err(corrupt(0, "invalid or duplicate $LogFile attribute-name reference"));
        }
        at = at.checked_add(4 + bytes)
            .filter(|end| *end <= data.len())
            .ok_or_else(|| corrupt(0, "truncated $LogFile UTF-16 attribute name"))?;
        // Names stay native UTF-16 bytes. Unpaired surrogates are not replaced,
        // normalized, interpreted as host paths, or used as process pointers.
    }
}

fn dirty_pages(
    cx: &Cx,
    restart: &Restart,
    table: &RestartTable<'_>,
    attributes: Option<&RestartTable<'_>>,
    boundary: u64,
) -> Result<()> {
    if table.entry_size < 40 {
        return Err(corrupt(0, "short $LogFile dirty-page table entries"));
    }
    for entry in table.entries.values() {
        checkpoint(cx)?;
        let target = u32_at(entry, 4)?;
        let clusters = u64::from(u32_at(entry, 12)?);
        let vcn = u64_at(entry, 16)?;
        let oldest = u64_at(entry, 24)?;
        if attributes.is_none_or(|table| !table.entries.contains_key(&target))
            || u32_at(entry, 8)? == 0
            || clusters == 0
            || clusters > (entry.len() as u64 - 32) / 8
            || vcn.checked_add(clusters).is_none()
            || oldest == 0
        {
            return Err(corrupt(0, "invalid $LogFile dirty-page target or LCN extent"));
        }
        older_reference(restart, oldest, boundary, "dirty-page")?;
        for cluster in 0..clusters {
            checkpoint(cx)?;
            let at = 32 + usize::try_from(cluster).map_err(|_| {
                corrupt(0, "$LogFile dirty-page cluster index overflow")
            })? * 8;
            if u64_at(entry, at)? > i64::MAX as u64 {
                return Err(corrupt(0, "negative $LogFile dirty-page LCN"));
            }
        }
    }
    Ok(())
}

fn transactions(
    cx: &Cx,
    restart: &Restart,
    table: &RestartTable<'_>,
    boundary: u64,
    references: &mut References,
) -> Result<()> {
    if table.entry_size != 40 {
        return Err(unsupported("$LogFile transaction table needs native 40-byte entries"));
    }
    for (&transaction, entry) in &table.entries {
        checkpoint(cx)?;
        if !(1..=3).contains(&entry[4]) {
            return Err(unsupported("unknown or uninitialized $LogFile transaction state"));
        }
        let first = u64_at(entry, 8)?;
        let previous = u64_at(entry, 16)?;
        let undo = u64_at(entry, 24)?;
        if (previous == 0 && (first != 0 || undo != 0))
            || (first != 0 && first > previous)
            || (undo != 0 && undo > previous)
        {
            return Err(corrupt(0, "$LogFile transaction checkpoint links are out of order"));
        }
        for reference in [first, previous, undo] {
            older_reference(restart, reference, boundary, "transaction-table")?;
            references.add(restart, reference, transaction)?;
        }
    }
    Ok(())
}

fn checkpoint_tables(
    cx: &Cx,
    restart: &Restart,
    stream_length: u64,
    record: &LogRecord,
    references: &mut References,
    read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>>,
) -> Result<(analysis::State, targets::State)> {
    let mut state = analysis::State::default();
    let mut targets = targets::State::default();
    let data = load_dump(cx, restart, stream_length, record, ATTRIBUTES, read)?;
    let attribute_table = data.as_deref()
        .map(|bytes| RestartTable::parse(cx, bytes)).transpose()?;
    if let Some(table) = &attribute_table {
        attributes(cx, restart, table, record.lsn)?;
        targets.seed_attributes(cx, table, record.lsn)?;
    }
    if let Some(data) = load_dump(cx, restart, stream_length, record, NAMES, read)? {
        names(cx, &data, attribute_table.as_ref())?;
        targets.seed_names(cx, &data)?;
    }
    if let Some(data) = load_dump(cx, restart, stream_length, record, DIRTY, read)? {
        let table = RestartTable::parse(cx, &data)?;
        dirty_pages(cx, restart, &table, attribute_table.as_ref(), record.lsn)?;
        targets.seed_dirty(cx, &table)?;
    }
    if let Some(data) = load_dump(cx, restart, stream_length, record, TRANSACTIONS, read)? {
        let table = RestartTable::parse(cx, &data)?;
        transactions(cx, restart, &table, record.lsn, references)?;
        state = analysis::State::from_table(cx, &table)?;
    }
    Ok((state, targets))
}

pub(super) fn validate(
    cx: &Cx,
    restart: &Restart,
    stream_length: u64,
    tail: &LogRecord,
    read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>>,
) -> Result<()> {
    checkpoint(cx)?;
    let mut references = References::default();
    let mut state = analysis::State::default();
    // Without a native checkpoint there is no complete open-attribute/dirty
    // target seed. Keep envelope/transaction inspection, but do not fabricate
    // an empty target table or claim target Analysis completed.
    let mut targets = None;
    let mut scan_start = restart.active_client_oldest_lsn
        .filter(|lsn| *lsn != 0).unwrap_or(tail.lsn);
    if tail.kind == LFS_CLIENT_RECORD {
        references.owners.insert(tail.lsn, tail.summary.transaction_id);
        references.links(restart, tail)?;
    }
    if let Some(lsn) = restart.active_client_restart_lsn.filter(|lsn| *lsn != 0) {
        let record = read_record(cx, restart, stream_length, lsn, read)?;
        if record.kind != LFS_CLIENT_RESTART {
            return Err(corrupt(0, "$LogFile client restart reference is not a checkpoint"));
        }
        let start = u64_at(&record.data, 8)?;
        older_reference(restart, start, record.lsn, "checkpoint-start")?;
        scan_start = if start == 0 { record.lsn } else { start };
        let (transactions, native_targets) =
            checkpoint_tables(cx, restart, stream_length, &record, &mut references, read)?;
        state = transactions;
        targets = Some(native_targets);
    } else if tail.kind == LFS_CLIENT_RESTART {
        // Validate even a checkpoint tail whose active-client pointer is absent.
        // Its absence is not interpreted as a fully initialized recovery state.
        let start = u64_at(&tail.data, 8)?;
        older_reference(restart, start, tail.lsn, "checkpoint-start")?;
        scan_start = if start == 0 { tail.lsn } else { start };
        let (transactions, native_targets) =
            checkpoint_tables(cx, restart, stream_length, tail, &mut references, read)?;
        state = transactions;
        targets = Some(native_targets);
    }
    // A transaction chain omits every other transaction. Read the physical
    // sequence as well, and check ownership of links from ALL encountered
    // records. The caller's shared I/O budget includes this entire pass.
    let history = scan::collect(cx, restart, stream_length, scan_start, read)?;
    for record in &history {
        checkpoint(cx)?;
        state.observe(cx, record)?;
        if let Some(targets) = &mut targets {
            targets.observe(cx, record)?;
        }
        if record.kind == LFS_CLIENT_RECORD {
            references.add(restart, record.lsn, record.summary.transaction_id)?;
            references.links(restart, record)?;
        }
    }
    while let Some((lsn, transaction)) = references.pending.pop() {
        checkpoint(cx)?;
        let record = read_record(cx, restart, stream_length, lsn, read)?;
        if record.kind != LFS_CLIENT_RECORD || record.summary.transaction_id != transaction {
            return Err(corrupt(0, "$LogFile predecessor belongs to a different transaction"));
        }
        references.links(restart, &record)?;
    }
    let report = state.finish(cx, restart, stream_length, read)?;
    let target_report = targets.as_ref().map(|targets| targets.finish(cx)).transpose()?;
    tracing::debug!(
        target: "ffs::ntfs::recovery",
        active_transactions = report.active,
        prepared_transactions = report.prepared,
        committed_transactions = report.committed,
        undo_operations = report.undo.len(),
        target_analysis = target_report.is_some(),
        mapped_dirty_clusters = target_report.map(|report| report.0),
        retired_dirty_clusters = target_report.map(|report| report.1),
        target_redo_start = target_report.and_then(|report| report.2),
        "Validated NTFS transaction Analysis through the selected restart; replay remains required"
    );
    checkpoint(cx)
}

#[cfg(test)]
mod tests;
