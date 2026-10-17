//! Native transaction Analysis and a bounded, reverse-LSN loser undo plan.
//!
//! The NTFS transaction table is not a POSIX operation log. In particular,
//! CompensationLogRecord is identified by undo_op, and EndTopLevelAction
//! restores the native undo-next link. References: Linux v6.17 fs/ntfs3/fslog.c
//! TRANSACTION_ENTRY and the Analysis/Undo passes. No operation is applied here.

use super::{
    Cx, LFS_CLIENT_RECORD, LogRecord, Restart, Result, checkpoint, corrupt, read_record,
    table::RestartTable, u64_at, unsupported,
};
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

const MAX_TRANSACTIONS: usize = 4096;
const MAX_UNDO_RECORDS: usize = 4096;
const COMPENSATION: u16 = 0x01;
const END_TOP_LEVEL: u16 = 0x18;
const PREPARE: u16 = 0x19;
const COMMIT: u16 = 0x1A;
const FORGET: u16 = 0x1B;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Active,
    Prepared,
    Committed,
}

#[derive(Debug, Clone, Copy)]
struct Transaction {
    status: Status,
    first: u64,
    previous: u64,
    undo: u64,
    // A reused numeric table slot must not inherit the preceding transaction.
    retired_before: u64,
}

#[derive(Default)]
pub(super) struct State {
    transactions: BTreeMap<u32, Transaction>,
    retired: BTreeMap<u32, u64>,
    last_seen: u64,
}

/// A plan through the selected restart boundary, not an authorization token.
/// Prepared transactions are preserved as in-doubt, not silently aborted.
#[derive(Debug)]
pub(super) struct Report {
    pub(super) active: usize,
    pub(super) prepared: usize,
    pub(super) committed: usize,
    // LSN, transaction identity and native undo opcode, in descending LSN order.
    pub(super) undo: Vec<(u64, u32, u16)>,
}

impl State {
    pub(super) fn from_table(cx: &Cx, table: &RestartTable<'_>) -> Result<Self> {
        checkpoint(cx)?;
        if table.entry_size != 40 || table.entries.len() > MAX_TRANSACTIONS {
            return Err(unsupported(
                "$LogFile Analysis requires a bounded native transaction table",
            ));
        }
        let mut state = Self::default();
        for (&id, bytes) in &table.entries {
            checkpoint(cx)?;
            let status = match bytes.get(4).copied() {
                Some(1) => Status::Active,
                Some(2) => Status::Prepared,
                Some(3) => Status::Committed,
                _ => {
                    return Err(corrupt(
                        0,
                        "invalid checkpoint transaction state for Analysis",
                    ));
                }
            };
            state.transactions.insert(
                id,
                Transaction {
                    status,
                    first: u64_at(bytes, 8)?,
                    previous: u64_at(bytes, 16)?,
                    undo: u64_at(bytes, 24)?,
                    retired_before: 0,
                },
            );
        }
        Ok(state)
    }

    pub(super) fn observe(&mut self, cx: &Cx, record: &LogRecord) -> Result<()> {
        checkpoint(cx)?;
        if record.lsn == 0 || record.lsn <= self.last_seen {
            return Err(corrupt(
                0,
                "$LogFile Analysis input is not strictly chronological",
            ));
        }
        self.last_seen = record.lsn;
        if record.kind != LFS_CLIENT_RECORD {
            return Ok(());
        }
        let id = record.summary.transaction_id;
        if id == 0 {
            return Err(corrupt(0, "$LogFile update has no transaction identity"));
        }
        let redo = record.summary.redo_op;
        let compensation = record.summary.undo_op == COMPENSATION;
        if let Some(transaction) = self.transactions.get(&id) {
            // A fuzzy checkpoint table can already include later records than
            // checkpoint-start. Never rewind that entry while scanning the
            // preceding part of the checkpoint interval a second time.
            if record.lsn <= transaction.previous {
                return Ok(());
            }
            if transaction.status == Status::Committed && !matches!(redo, COMMIT | FORGET) {
                return Err(corrupt(
                    0,
                    "$LogFile modifies a committed transaction before forgetting it",
                ));
            }
        } else {
            if self.transactions.len() >= MAX_TRANSACTIONS {
                return Err(unsupported(
                    "$LogFile Analysis exceeds 4096 active transaction slots",
                ));
            }
            let retired_before = self.retired.get(&id).copied().unwrap_or(0);
            if retired_before != 0 && (record.previous != 0 || record.undo_next != 0) {
                return Err(corrupt(
                    0,
                    "$LogFile reused transaction slot inherits an old chain",
                ));
            }
            self.transactions.insert(
                id,
                Transaction {
                    status: Status::Active,
                    // Without a checkpoint seed, a nonzero predecessor establishes
                    // that this is not the transaction's first retained record.
                    first: if record.previous == 0 { record.lsn } else { 0 },
                    previous: 0,
                    undo: 0,
                    retired_before,
                },
            );
        }
        if redo == FORGET {
            self.transactions.remove(&id);
            self.retired.insert(id, record.lsn);
            if self.retired.len() > MAX_TRANSACTIONS {
                return Err(unsupported(
                    "$LogFile Analysis exceeds 4096 retired transaction slots",
                ));
            }
            return checkpoint(cx);
        }
        let transaction = self
            .transactions
            .get_mut(&id)
            .ok_or_else(|| corrupt(0, "$LogFile Analysis lost its transaction slot"))?;
        for link in [record.previous, record.undo_next] {
            if link != 0
                && (link <= transaction.retired_before
                    || (transaction.first != 0 && link < transaction.first))
            {
                return Err(corrupt(
                    0,
                    "$LogFile transaction link crosses an incarnation boundary",
                ));
            }
        }
        transaction.previous = record.lsn;
        transaction.undo = if compensation || redo == END_TOP_LEVEL {
            record.undo_next
        } else {
            record.lsn
        };
        match redo {
            PREPARE => transaction.status = Status::Prepared,
            COMMIT => transaction.status = Status::Committed,
            _ => {}
        }
        checkpoint(cx)
    }

    pub(super) fn finish(
        &self,
        cx: &Cx,
        restart: &Restart,
        stream_length: u64,
        read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>>,
    ) -> Result<Report> {
        self.plan(cx, |lsn| read_record(cx, restart, stream_length, lsn, read))
    }

    fn plan(&self, cx: &Cx, mut load: impl FnMut(u64) -> Result<LogRecord>) -> Result<Report> {
        checkpoint(cx)?;
        let mut report = Report {
            active: 0,
            prepared: 0,
            committed: 0,
            undo: Vec::new(),
        };
        let mut pending = BinaryHeap::new();
        for (&id, transaction) in &self.transactions {
            checkpoint(cx)?;
            match transaction.status {
                Status::Active => {
                    report.active += 1;
                    if transaction.undo != 0 {
                        pending.push((transaction.undo, id));
                    }
                }
                Status::Prepared => report.prepared += 1,
                Status::Committed => report.committed += 1,
            }
        }
        let mut seen = BTreeSet::new();
        while let Some((lsn, id)) = pending.pop() {
            checkpoint(cx)?;
            if seen.len() == MAX_UNDO_RECORDS {
                return Err(unsupported("$LogFile undo planning exceeds 4096 records"));
            }
            if !seen.insert(lsn) {
                return Err(corrupt(0, "$LogFile undo chains share or revisit a record"));
            }
            let transaction = self
                .transactions
                .get(&id)
                .ok_or_else(|| corrupt(0, "$LogFile undo refers to a missing transaction"))?;
            if lsn > transaction.previous
                || lsn <= transaction.retired_before
                || (transaction.first != 0 && lsn < transaction.first)
            {
                return Err(corrupt(
                    0,
                    "$LogFile undo LSN crosses its transaction lifetime",
                ));
            }
            let record = load(lsn)?;
            checkpoint(cx)?;
            if record.lsn != lsn
                || record.kind != LFS_CLIENT_RECORD
                || record.summary.transaction_id != id
            {
                return Err(corrupt(
                    0,
                    "$LogFile undo record has the wrong identity or owner",
                ));
            }
            if matches!(record.summary.redo_op, COMMIT | FORGET) {
                return Err(corrupt(
                    0,
                    "$LogFile loser undo chain crosses a committed or forgotten transaction",
                ));
            }
            let next = record.undo_next;
            if next != 0 && next >= lsn {
                return Err(corrupt(0, "$LogFile undo chain is cyclic or moves forward"));
            }
            // Compensation records already performed an undo; their redo may
            // still matter to the later Redo pass, but undo must never undo it.
            // EndTopLevelAction similarly skips a completed nested action.
            let opcode = record.summary.undo_op;
            let changes_metadata = matches!(opcode, 0x02..=0x09 | 0x0B..=0x16 | 0x21..=0x25);
            if changes_metadata && record.summary.redo_op != END_TOP_LEVEL {
                report.undo.push((lsn, id, opcode));
            }
            if next != 0 {
                pending.push((next, id));
            }
        }
        checkpoint(cx)?;
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::{LFS_CLIENT_RESTART, TailRecord};
    use super::*;
    use ffs_error::FfsError;

    fn record(lsn: u64, id: u32, redo: u16, undo: u16, previous: u64, next: u64) -> LogRecord {
        LogRecord {
            lsn,
            previous,
            undo_next: next,
            kind: LFS_CLIENT_RECORD,
            summary: TailRecord {
                transaction_id: id,
                redo_op: redo,
                undo_op: undo,
            },
            data: Vec::new(),
        }
    }

    fn observe(records: &[LogRecord]) -> State {
        let mut state = State::default();
        for record in records {
            state.observe(&Cx::for_testing(), record).unwrap();
        }
        state
    }

    fn plan(state: &State, records: &[LogRecord]) -> Result<Report> {
        state.plan(&Cx::for_testing(), |lsn| {
            let r = records
                .iter()
                .find(|r| r.lsn == lsn)
                .ok_or_else(|| corrupt(0, "missing test undo record"))?;
            Ok(record(
                r.lsn,
                r.summary.transaction_id,
                r.summary.redo_op,
                r.summary.undo_op,
                r.previous,
                r.undo_next,
            ))
        })
    }

    #[test]
    fn interleaved_winners_and_losers_produce_global_reverse_lsn_undo() {
        let records = [
            record(10, 24, 7, 7, 0, 0),
            record(20, 64, 7, 7, 0, 0),
            record(30, 104, 7, 7, 0, 0),
            record(40, 24, 7, 7, 10, 10),
            record(50, 64, COMMIT, 0, 20, 20),
            record(60, 104, 7, 7, 30, 30),
        ];
        let report = plan(&observe(&records), &records).unwrap();
        assert_eq!(
            (report.active, report.prepared, report.committed),
            (2, 0, 1)
        );
        assert_eq!(
            report.undo,
            [(60, 104, 7), (40, 24, 7), (30, 104, 7), (10, 24, 7)]
        );
    }

    #[test]
    fn compensation_uses_undo_opcode_and_does_not_repeat_completed_undo() {
        let records = [
            record(10, 24, 7, 7, 0, 0),
            record(20, 24, 7, 7, 10, 10),
            record(30, 24, 7, COMPENSATION, 20, 10),
        ];
        let report = plan(&observe(&records), &records).unwrap();
        assert_eq!(report.undo, [(10, 24, 7)]);
        let mut more = Vec::from(records);
        more.push(record(40, 24, 7, 7, 30, 30));
        assert_eq!(
            plan(&observe(&more), &more).unwrap().undo,
            [(40, 24, 7), (10, 24, 7)]
        );
    }

    #[test]
    fn top_level_completion_skips_the_completed_nested_action() {
        let records = [
            record(10, 24, 7, 7, 0, 0),
            record(20, 24, 7, 7, 10, 10),
            record(30, 24, END_TOP_LEVEL, 0, 20, 10),
        ];
        assert_eq!(
            plan(&observe(&records), &records).unwrap().undo,
            [(10, 24, 7)]
        );
    }

    #[test]
    fn prepared_transactions_remain_in_doubt_and_are_not_silently_aborted() {
        let records = [
            record(10, 24, 7, 7, 0, 0),
            record(20, 24, PREPARE, 0, 10, 10),
        ];
        let report = plan(&observe(&records), &records).unwrap();
        assert_eq!(
            (report.active, report.prepared, report.committed),
            (0, 1, 0)
        );
        assert!(report.undo.is_empty());
    }

    #[test]
    fn forget_and_slot_reuse_do_not_inherit_old_transaction_work() {
        let records = [
            record(10, 24, 7, 7, 0, 0),
            record(20, 24, COMMIT, 0, 10, 10),
            record(30, 24, FORGET, 0, 20, 0),
            record(40, 24, 7, 7, 0, 0),
        ];
        assert_eq!(
            plan(&observe(&records), &records).unwrap().undo,
            [(40, 24, 7)]
        );
        let mut state = observe(&records[..3]);
        assert!(
            state
                .observe(&Cx::for_testing(), &record(40, 24, 7, 7, 10, 10))
                .is_err()
        );
    }

    #[test]
    fn fuzzy_checkpoint_state_is_not_rewound_by_earlier_scanned_records() {
        let mut bytes = vec![0; 64];
        bytes[..2].copy_from_slice(&40_u16.to_le_bytes());
        bytes[2..4].copy_from_slice(&1_u16.to_le_bytes());
        bytes[4..6].copy_from_slice(&1_u16.to_le_bytes());
        bytes[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
        bytes[28] = 3;
        bytes[32..40].copy_from_slice(&10_u64.to_le_bytes());
        bytes[40..48].copy_from_slice(&30_u64.to_le_bytes());
        bytes[48..56].copy_from_slice(&30_u64.to_le_bytes());
        let cx = Cx::for_testing();
        let table = RestartTable::parse(&cx, &bytes).unwrap();
        let mut state = State::from_table(&cx, &table).unwrap();
        state.observe(&cx, &record(20, 24, 7, 7, 10, 10)).unwrap();
        state
            .observe(&cx, &record(30, 24, COMMIT, 0, 20, 20))
            .unwrap();
        let report = state
            .plan(&cx, |_| {
                panic!("committed checkpoint must not schedule undo")
            })
            .unwrap();
        assert_eq!(report.committed, 1);
        assert!(report.undo.is_empty());
    }

    #[test]
    fn checkpoint_only_active_transaction_schedules_its_retained_history() {
        let mut state = State::default();
        state.transactions.insert(
            24,
            Transaction {
                status: Status::Active,
                first: 10,
                previous: 20,
                undo: 20,
                retired_before: 0,
            },
        );
        let records = [record(10, 24, 7, 7, 0, 0), record(20, 24, 7, 7, 10, 10)];
        assert_eq!(
            plan(&state, &records).unwrap().undo,
            [(20, 24, 7), (10, 24, 7)]
        );
    }

    #[test]
    fn undo_owner_identity_cycles_and_retired_generations_are_refused() {
        for mutation in 0..4 {
            let records = [record(10, 24, 7, 7, 0, 0), record(20, 24, 7, 7, 10, 10)];
            let state = observe(&records);
            let result = state.plan(&Cx::for_testing(), |lsn| {
                Ok(match mutation {
                    0 => record(lsn, 64, 7, 7, 0, 0),
                    1 => record(lsn + 1, 24, 7, 7, 0, 0),
                    2 => record(lsn, 24, 7, 7, 0, lsn),
                    _ => record(lsn, 24, 7, 7, 0, 5),
                })
            });
            assert!(result.is_err());
        }
    }

    #[test]
    fn committed_transaction_cannot_resume_mutation_without_forget() {
        let records = [
            record(10, 24, 7, 7, 0, 0),
            record(20, 24, COMMIT, 0, 10, 10),
        ];
        let mut state = observe(&records);
        assert!(
            state
                .observe(&Cx::for_testing(), &record(30, 24, 7, 7, 20, 20))
                .is_err()
        );
    }

    #[test]
    fn restart_records_are_not_transaction_zero_and_ordering_is_strict() {
        let mut state = State::default();
        let mut restart = record(10, 0, 0, 0, 0, 0);
        restart.kind = LFS_CLIENT_RESTART;
        state.observe(&Cx::for_testing(), &restart).unwrap();
        assert!(state.transactions.is_empty());
        assert!(state.observe(&Cx::for_testing(), &restart).is_err());
        assert!(
            State::default()
                .observe(&Cx::for_testing(), &record(10, 0, 7, 7, 0, 0))
                .is_err()
        );
    }

    #[test]
    fn undo_cancellation_and_io_errors_never_return_partial_plans() {
        let records = [record(10, 24, 7, 7, 0, 0), record(20, 24, 7, 7, 10, 10)];
        let state = observe(&records);
        let mut calls = 0;
        let result = state.plan(&Cx::for_testing(), |lsn| {
            calls += 1;
            if calls == 2 {
                return Err(FfsError::Cancelled);
            }
            Ok(record(lsn, 24, 7, 7, 10, 10))
        });
        assert!(matches!(result, Err(FfsError::Cancelled)));
        assert_eq!(calls, 2);
        assert!(
            state
                .plan(&Cx::for_testing(), |_| Err(FfsError::Io(
                    std::io::Error::other("injected undo I/O failure")
                )))
                .is_err()
        );
    }

    #[test]
    fn undo_work_limit_is_checked_before_loading_another_record() {
        let last = MAX_UNDO_RECORDS as u64 + 1;
        let mut state = State::default();
        state.transactions.insert(
            24,
            Transaction {
                status: Status::Active,
                first: 1,
                previous: last,
                undo: last,
                retired_before: 0,
            },
        );
        let mut reads = 0;
        let result = state.plan(&Cx::for_testing(), |lsn| {
            reads += 1;
            Ok(record(lsn, 24, 7, 7, lsn - 1, lsn - 1))
        });
        assert!(matches!(result, Err(FfsError::UnsupportedFeature(_))));
        assert_eq!(reads, MAX_UNDO_RECORDS);
    }

    fn native_journal(reuse_committed: bool) -> (Restart, Vec<u8>) {
        let page_vbo = 34_u64 * 4096;
        let first = (1_u64 << 20) | (page_vbo + 64) / 8;
        let second = (1_u64 << 20) | (page_vbo + 152) / 8;
        let last = (1_u64 << 20) | (page_vbo + 240) / 8;
        let restart = Restart {
            system_page: 4096,
            log_page: 4096,
            version: (2, 0),
            clean: false,
            current_lsn: last,
            seq_num_bits: 44,
            file_size: 4 * 1024 * 1024,
            last_lsn_data_len: 40,
            record_header_len: 48,
            data_off: 64,
            active_client_seq: Some(9),
            active_client_oldest_lsn: Some(first),
            active_client_restart_lsn: None,
            area: Vec::new(),
        };
        let mut page = vec![0; 4096];
        page[..4].copy_from_slice(b"RCRD");
        page[4..6].copy_from_slice(&40_u16.to_le_bytes());
        page[6..8].copy_from_slice(&9_u16.to_le_bytes());
        page[8..16].copy_from_slice(&last.to_le_bytes());
        page[16..20].copy_from_slice(&1_u32.to_le_bytes());
        page[20..22].copy_from_slice(&1_u16.to_le_bytes());
        page[22..24].copy_from_slice(&1_u16.to_le_bytes());
        page[24..26].copy_from_slice(&328_u16.to_le_bytes());
        page[32..40].copy_from_slice(&last.to_le_bytes());
        for (at, lsn, id, op, previous) in [
            (64_usize, first, 24_u32, 7_u16, 0),
            (152, second, 24, COMMIT, first),
            (
                240,
                last,
                if reuse_committed { 24 } else { 64 },
                7,
                if reuse_committed { second } else { 0 },
            ),
        ] {
            page[at..at + 8].copy_from_slice(&lsn.to_le_bytes());
            page[at + 8..at + 16].copy_from_slice(&previous.to_le_bytes());
            page[at + 24..at + 28].copy_from_slice(&40_u32.to_le_bytes());
            page[at + 28..at + 30].copy_from_slice(&9_u16.to_le_bytes());
            page[at + 32..at + 36].copy_from_slice(&LFS_CLIENT_RECORD.to_le_bytes());
            page[at + 36..at + 40].copy_from_slice(&id.to_le_bytes());
            page[at + 48..at + 50].copy_from_slice(&op.to_le_bytes());
            page[at + 60..at + 62].copy_from_slice(&24_u16.to_le_bytes());
        }
        page[40..42].copy_from_slice(&0xCAFE_u16.to_le_bytes());
        for sector in 1..=8 {
            let at = sector * 512;
            let saved = [page[at - 2], page[at - 1]];
            page[40 + sector * 2..42 + sector * 2].copy_from_slice(&saved);
            page[at - 2..at].copy_from_slice(&0xCAFE_u16.to_le_bytes());
        }
        (restart, page)
    }

    #[test]
    fn actual_dirty_journal_path_enforces_analysis_after_protected_decoding() {
        for reuse_committed in [false, true] {
            let (restart, page) = native_journal(reuse_committed);
            let before = page.clone();
            let result = super::super::super::validate_dirty_tail(
                &Cx::for_testing(),
                &restart,
                restart.file_size,
                &mut |offset, size| {
                    assert_eq!((offset, size), (34 * 4096, 4096));
                    Ok(page.clone())
                },
            );
            if reuse_committed {
                assert!(matches!(result, Err(FfsError::Corruption { .. })));
            } else {
                result.unwrap();
            }
            assert_eq!(page, before, "Analysis cannot modify native image bytes");
        }
    }

    #[test]
    fn bookkeeping_undo_opcodes_do_not_become_page_mutations() {
        for opcode in [0, 0x0A, 0x17, PREPARE, 0x1C, 0x1D, 0x1E, 0x1F, 0x20] {
            let records = [record(10, 24, 7, opcode, 0, 0)];
            let report = plan(&observe(&records), &records).unwrap();
            assert!(report.undo.is_empty());
            assert_eq!(report.active, 1);
        }
    }
}
