//! Transaction selection for the public, flat $LogFile parser.
//!
//! The mounted preflight has its own checkpoint-seeded Analysis. This API has
//! no such seed, so it requires complete transaction lifetimes in its retained
//! input. Native references: Linux v6.17 fs/ntfs3/fslog.c Analysis and Undo.
//! A returned action still needs target ownership and semantic replay checks;
//! this module does not establish an authoritative journal boundary or apply I/O.

use super::{NtfsLogOp, NtfsLogRecord, NtfsRecoveryAction, ParseError, invalid};
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

const MAX_RECORDS: usize = 65_536;
const MAX_SLOTS: usize = 4096;

#[derive(Debug)]
pub(super) struct Plan {
    /// Numeric IDs can occur in both lists when a forgotten winner's slot was
    /// subsequently reused by an active transaction. Actions retain their LSNs.
    pub(super) committed: Vec<u32>,
    pub(super) active: Vec<u32>,
    pub(super) undo_actions: Vec<NtfsRecoveryAction>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    Active,
    Prepared,
    Committed,
}

struct Transaction {
    status: Status,
    first: u64,
    last: u64,
    undo: u64,
}

fn bad(reason: &'static str) -> ParseError {
    invalid("ntfs.logfile.transactions", reason)
}

/// Recognizing an opcode does not implement its mapping/table/bitmap semantics.
/// In particular HotFix and DeleteDirtyClusters cannot be treated as Noop by
/// this flat physical-LCN planner. Keep unsupported work visible as an error.
fn supported(op: NtfsLogOp) -> Result<(), ParseError> {
    match op {
        NtfsLogOp::Unknown(_) => Err(bad("unknown native recovery operation")),
        NtfsLogOp::DeleteDirtyClusters
        | NtfsLogOp::HotFix
        | NtfsLogOp::OpenNonresidentAttribute
        | NtfsLogOp::OpenAttributeTableDump
        | NtfsLogOp::AttributeNamesDump
        | NtfsLogOp::DirtyPageTableDump
        | NtfsLogOp::TransactionTableDump => Err(bad(
            "native mapping/checkpoint context requires the checkpoint-aware recovery path",
        )),
        NtfsLogOp::SetBitsInNonresidentBitMap
        | NtfsLogOp::ClearBitsInNonresidentBitMap
        | NtfsLogOp::UpdateRecordDataRoot
        | NtfsLogOp::UpdateRecordDataAllocation
        | NtfsLogOp::UpdateRelativeDataInIndex
        | NtfsLogOp::UpdateRelativeDataInIndex2
        | NtfsLogOp::ZeroEndOfFileRecord => Err(bad(
            "native recovery operation has no flat-plan semantic executor",
        )),
        _ => Ok(()),
    }
}

fn same_lifetime(
    records: &BTreeMap<u64, &NtfsLogRecord>,
    link: u64,
    current: &NtfsLogRecord,
    first: u64,
) -> Result<(), ParseError> {
    if link == 0 {
        return Ok(());
    }
    if link < first || link >= current.this_lsn {
        return Err(bad("transaction link crosses a lifetime or moves forward"));
    }
    let target = records
        .get(&link)
        .ok_or_else(|| bad("transaction chain requires a missing retained record"))?;
    if target.transaction_id != current.transaction_id || target.record_type != 1 {
        return Err(bad("transaction link belongs to another native owner"));
    }
    Ok(())
}

pub(super) fn build(records: &[NtfsLogRecord]) -> Result<Plan, ParseError> {
    if records.len() > MAX_RECORDS {
        return Err(bad("transaction input exceeds 65536 records"));
    }
    let mut by_lsn = BTreeMap::new();
    let mut slots: BTreeMap<u32, Transaction> = BTreeMap::new();
    let mut identities = BTreeSet::new();
    let mut committed = BTreeSet::new();
    let mut previous_lsn = 0;
    for record in records {
        let lsn = record.this_lsn;
        let id = record.transaction_id;
        if lsn == 0 || lsn <= previous_lsn || id == 0 || record.record_type != 1 {
            return Err(bad("invalid or nonchronological native transaction record"));
        }
        previous_lsn = lsn;
        supported(record.redo_op)?;
        supported(record.undo_op)?;
        if !record.undo_op.patches_bytes()
            && !matches!(record.undo_op, NtfsLogOp::Noop | NtfsLogOp::CompensationLogRecord)
        {
            return Err(bad("native undo opcode is not an inverse operation or compensation marker"));
        }
        if identities.insert(id) && identities.len() > MAX_SLOTS {
            return Err(bad("transaction input exceeds 4096 distinct slots"));
        }
        if record.redo_op == NtfsLogOp::CompensationLogRecord {
            return Err(bad("compensation marker must be the native undo opcode"));
        }
        if record.redo_op.patches_bytes() && record.target_lcn == 0 {
            return Err(bad("native redo has no physical target"));
        }
        if let Some(transaction) = slots.get(&id) {
            if record.client_previous_lsn != transaction.last {
                return Err(bad("transaction previous link omits its retained predecessor"));
            }
            if transaction.status != Status::Active
                && !matches!(
                    record.redo_op,
                    NtfsLogOp::CommitTransaction | NtfsLogOp::ForgetTransaction
                )
            {
                return Err(bad("native transaction changes after prepare or commit"));
            }
            same_lifetime(&by_lsn, record.client_previous_lsn, record, transaction.first)?;
            same_lifetime(&by_lsn, record.client_undo_next_lsn, record, transaction.first)?;
        } else {
            // A reused table slot starts a new lifetime. A prefix omitted by
            // this parser also needs a checkpoint seed, not a fabricated root.
            if record.client_previous_lsn != 0 || record.client_undo_next_lsn != 0 {
                return Err(bad("new or reused transaction has an unresolved predecessor"));
            }
            slots.insert(
                id,
                Transaction {
                    status: Status::Active,
                    first: lsn,
                    last: 0,
                    undo: 0,
                },
            );
        }
        by_lsn.insert(lsn, record);
        if record.redo_op == NtfsLogOp::ForgetTransaction {
            // Forget records end both committed and fully rolled-back lives.
            // Forget by itself is NOT evidence that this transaction committed.
            slots.remove(&id);
            continue;
        }
        let transaction = slots
            .get_mut(&id)
            .ok_or_else(|| bad("transaction slot disappeared during Analysis"))?;
        transaction.last = lsn;
        transaction.undo = if record.undo_op == NtfsLogOp::CompensationLogRecord
            || record.redo_op == NtfsLogOp::EndTopLevelAction
        {
            record.client_undo_next_lsn
        } else {
            lsn
        };
        match record.redo_op {
            NtfsLogOp::PrepareTransaction => transaction.status = Status::Prepared,
            NtfsLogOp::CommitTransaction => {
                transaction.status = Status::Committed;
                committed.insert(id);
            }
            _ => {}
        }
    }

    let mut active = Vec::new();
    let mut pending = BinaryHeap::new();
    for (&id, transaction) in &slots {
        match transaction.status {
            Status::Prepared => {
                return Err(bad("prepared native transaction requires an external decision"));
            }
            Status::Active => {
                active.push(id);
                if transaction.undo != 0 {
                    pending.push((transaction.undo, id));
                }
            }
            Status::Committed => {}
        }
    }
    let mut undo_actions = Vec::new();
    let mut visited = BTreeSet::new();
    while let Some((lsn, id)) = pending.pop() {
        if visited.len() >= MAX_RECORDS || !visited.insert(lsn) {
            return Err(bad("undo chains revisit or exceed the retained record budget"));
        }
        let transaction = slots
            .get(&id)
            .ok_or_else(|| bad("undo refers to a missing transaction"))?;
        let record = *by_lsn
            .get(&lsn)
            .ok_or_else(|| bad("undo chain requires a missing retained record"))?;
        if lsn < transaction.first || lsn > transaction.last || record.transaction_id != id {
            return Err(bad("undo chain crosses its native transaction lifetime"));
        }
        if matches!(
            record.redo_op,
            NtfsLogOp::PrepareTransaction
                | NtfsLogOp::CommitTransaction
                | NtfsLogOp::ForgetTransaction
        ) {
            return Err(bad("loser undo crosses a resolved or in-doubt transaction"));
        }
        let next = record.client_undo_next_lsn;
        same_lifetime(&by_lsn, next, record, transaction.first)?;
        // CLRs and completed nested actions change the undo head. Never undo
        // their redo or resurrect the skipped operations by scanning by ID.
        if record.undo_op != NtfsLogOp::CompensationLogRecord
            && record.redo_op != NtfsLogOp::EndTopLevelAction
            && record.undo_op.patches_bytes()
        {
            if record.target_lcn == 0 {
                return Err(bad("native undo has no physical target"));
            }
            undo_actions.push(NtfsRecoveryAction {
                lsn,
                transaction_id: id,
                is_undo: true,
                op: record.undo_op,
                target_lcn: record.target_lcn,
                cluster_block_offset: record.cluster_block_offset,
                record_offset: record.record_offset,
                attribute_offset: record.attribute_offset,
                data: record.undo_data.clone(),
            });
        }
        if next != 0 {
            pending.push((next, id));
        }
    }
    Ok(Plan {
        committed: committed.into_iter().collect(),
        active,
        undo_actions,
    })
}

#[cfg(test)]
mod tests;
