//! Checkpoint-aware read-only audit regressions for native format and reopen.

use super::{Cx, ERASED_SCAN_LIMIT, Result, corrupt, inspect_logfile, u16_at};
use crate::transaction::NtfsLogStateSummary;
use ffs_error::FfsError;
use ffs_ondisk::ntfs::logfile_writer::{
    AppendedLogRecord, LFS_RECORD_CLIENT, LFS_RECORD_CLIENT_RESTART, NtfsCheckpointPayload,
    NtfsClientUpdateSpec, NtfsLogRingWriter, encode_attribute_names_dump,
    encode_client_update_payload, encode_open_attribute_entry, encode_restart_table,
};
use ffs_ondisk::ntfs::{NtfsLogOp, protect_record, restore_record};
use std::collections::BTreeMap;

const PAGE: usize = 4096;
const LOG: usize = 256 * 1024;

struct AuditLog {
    ring: NtfsLogRingWriter,
    bytes: Vec<u8>,
    page: usize,
}

impl AuditLog {
    fn new(page: usize, version: (u16, u16), length: usize) -> Self {
        Self {
            ring: NtfsLogRingWriter::new_fresh(
                u32::try_from(page).unwrap(),
                version,
                length as u64,
                1,
                1,
            )
            .unwrap(),
            bytes: vec![0xFF; length],
            page,
        }
    }

    fn append(
        &mut self,
        kind: u32,
        transaction: u32,
        previous: u64,
        payload: &[u8],
    ) -> AppendedLogRecord {
        let record = self
            .ring
            .append_raw_record(kind, transaction, previous, 0, payload)
            .unwrap();
        let start = usize::try_from(record.page_vbo).unwrap();
        self.bytes[start..start + record.protected_page.len()]
            .copy_from_slice(&record.protected_page);
        record
    }

    fn publish(&mut self, clean: bool) {
        for _ in 0..2 {
            let page = self.ring.build_next_rstr_page(clean).unwrap();
            let start = usize::try_from(page.page_vbo).unwrap();
            self.bytes[start..start + page.bytes.len()].copy_from_slice(&page.bytes);
        }
    }

    fn checkpoint(&mut self, payload: &[u8], clean: bool) -> AppendedLogRecord {
        let record = self.append(LFS_RECORD_CLIENT_RESTART, 0, 0, payload);
        self.publish(clean);
        record
    }

    fn edit_page(&mut self, offset: usize, signature: &[u8; 4], edit: impl FnOnce(&mut [u8])) {
        let mut page = restore_record(&self.bytes[offset..offset + self.page], signature).unwrap();
        edit(&mut page);
        self.bytes[offset..offset + self.page].copy_from_slice(&protect_record(&page).unwrap());
    }

    fn audit(&self) -> Result<NtfsLogStateSummary> {
        inspect_logfile(&Cx::for_testing(), self.bytes.len() as u64, |offset, size| {
            let start = usize::try_from(offset).unwrap();
            self.bytes
                .get(start..start + size)
                .map(<[u8]>::to_vec)
                .ok_or_else(|| corrupt(offset, "audit fixture read beyond journal"))
        })
    }
}

fn empty_checkpoint() -> [u8; 64] {
    NtfsCheckpointPayload::default().encode().unwrap()
}

fn client_payload(op: NtfsLogOp, data: Vec<u8>) -> Vec<u8> {
    encode_client_update_payload(&NtfsClientUpdateSpec {
        redo_op: op,
        undo_op: NtfsLogOp::Noop,
        target_attribute: 0,
        record_offset: 0,
        attribute_offset: 0,
        cluster_block_offset: 0,
        target_vcn: 0,
        target_lcns: Vec::new(),
        redo_data: data,
        undo_data: Vec::new(),
    })
    .unwrap()
}

fn checkpoint_with_tables(forget: bool) -> (AuditLog, AppendedLogRecord) {
    let mut log = AuditLog::new(PAGE, (1, 1), LOG);
    let entry = encode_open_attribute_entry(0x80, 0, (1_u64 << 48) | 16, 0);
    let attributes = encode_restart_table(40, &BTreeMap::from([(24, entry.to_vec())])).unwrap();
    let names = encode_attribute_names_dump(&BTreeMap::from([(
        24,
        "stream".encode_utf16().collect(),
    )]))
    .unwrap();
    let attribute_len = u32::try_from(attributes.len()).unwrap();
    let names_len = u32::try_from(names.len()).unwrap();
    let attribute_record = log.append(
        LFS_RECORD_CLIENT,
        24,
        0,
        &client_payload(NtfsLogOp::OpenAttributeTableDump, attributes),
    );
    let name_record = log.append(
        LFS_RECORD_CLIENT,
        24,
        attribute_record.lsn,
        &client_payload(NtfsLogOp::AttributeNamesDump, names),
    );
    if forget {
        log.append(
            LFS_RECORD_CLIENT,
            24,
            name_record.lsn,
            &client_payload(NtfsLogOp::ForgetTransaction, Vec::new()),
        );
    }
    let payload = NtfsCheckpointPayload {
        start_of_checkpoint_lsn: attribute_record.lsn,
        open_attribute_table_lsn: attribute_record.lsn,
        open_attribute_table_len: attribute_len,
        attribute_names_lsn: name_record.lsn,
        attribute_names_len: names_len,
        ..NtfsCheckpointPayload::default()
    }
    .encode()
    .unwrap();
    let checkpoint = log.checkpoint(&payload, true);
    (log, checkpoint)
}

#[test]
fn audit_accepts_native_empty_checkpoints_and_preserves_all_bytes() {
    for (page, version) in [
        (512, (1, 1)),
        (1024, (1, 1)),
        (2048, (1, 1)),
        (4096, (1, 1)),
        (4096, (2, 0)),
    ] {
        let mut log = AuditLog::new(page, version, LOG);
        let checkpoint = log.checkpoint(&empty_checkpoint(), true);
        let before = log.bytes.clone();
        let state = log.audit().unwrap();
        assert!(state.clean);
        assert!(!state.erased);
        assert_eq!(state.version, version);
        assert_eq!(state.page_size, u32::try_from(page).unwrap());
        assert_eq!(state.current_lsn, checkpoint.lsn);
        assert_eq!(state.oldest_lsn, checkpoint.lsn);
        assert_eq!(state.client_restart_lsn, checkpoint.lsn);
        assert_eq!(state.torn_rstr_slot, None);
        assert_eq!(log.bytes, before);
    }
}

#[test]
fn audit_keeps_the_full_formatter_journal_limit_with_bounded_reads() {
    let mut log = AuditLog::new(PAGE, (1, 1), ERASED_SCAN_LIMIT as usize);
    log.checkpoint(&empty_checkpoint(), true);
    let mut read_bytes = 0_u64;
    let state = inspect_logfile(&Cx::for_testing(), log.bytes.len() as u64, |offset, size| {
        assert!(size <= 65_536);
        read_bytes += size as u64;
        let start = usize::try_from(offset).unwrap();
        Ok(log.bytes[start..start + size].to_vec())
    })
    .unwrap();
    assert!(state.clean);
    assert_eq!(state.file_size, ERASED_SCAN_LIMIT);
    assert!(read_bytes >= ERASED_SCAN_LIMIT - 4 * PAGE as u64);
    assert!(read_bytes <= 2 * ERASED_SCAN_LIMIT + 3 * PAGE as u64);
}

#[test]
fn audit_decodes_open_attribute_and_name_tables_before_reporting_clean() {
    let (log, checkpoint) = checkpoint_with_tables(true);
    let before = log.bytes.clone();
    let state = log.audit().unwrap();
    assert!(state.clean);
    assert_eq!(state.current_lsn, checkpoint.lsn);
    assert_eq!(log.bytes, before);
}

#[test]
fn clean_flag_cannot_hide_checkpoint_damage_or_unfinished_transactions() {
    let (unfinished, _) = checkpoint_with_tables(false);
    assert!(matches!(unfinished.audit(), Err(FfsError::Corruption { .. })));

    let (mut bad_reference, checkpoint) = checkpoint_with_tables(true);
    bad_reference.edit_page(checkpoint.page_vbo as usize, b"RCRD", |page| {
        let payload = usize::from(checkpoint.record_offset) + 48;
        // A table length without its LSN must not be ignored by a flat scan.
        page[payload + 16..payload + 24].fill(0);
    });
    assert!(matches!(bad_reference.audit(), Err(FfsError::Corruption { .. })));

    let (mut torn, checkpoint) = checkpoint_with_tables(true);
    torn.bytes[checkpoint.page_vbo as usize + 511] ^= 1;
    assert!(matches!(torn.audit(), Err(FfsError::Corruption { .. })));
}

#[test]
fn audit_never_ignores_native_work_newer_than_a_clean_restart() {
    for newer_checkpoint in [false, true] {
        let mut log = AuditLog::new(PAGE, (1, 1), LOG);
        log.checkpoint(&empty_checkpoint(), true);
        if newer_checkpoint {
            log.append(LFS_RECORD_CLIENT_RESTART, 0, 0, &empty_checkpoint());
        } else {
            log.append(
                LFS_RECORD_CLIENT,
                24,
                0,
                &client_payload(NtfsLogOp::Noop, Vec::new()),
            );
        }
        assert!(matches!(log.audit(), Err(FfsError::Corruption { .. })));
    }
}

#[test]
fn dirty_audit_follows_newer_tail_and_refuses_unknown_newer_records() {
    let mut log = AuditLog::new(PAGE, (1, 1), LOG);
    log.checkpoint(&empty_checkpoint(), false);
    let update = log.append(
        LFS_RECORD_CLIENT,
        24,
        0,
        &client_payload(NtfsLogOp::Noop, Vec::new()),
    );
    let state = log.audit().unwrap();
    assert!(!state.clean);
    assert_eq!(state.current_lsn, update.lsn);

    let mut unknown = client_payload(NtfsLogOp::Noop, Vec::new());
    unknown[..2].copy_from_slice(&u16::MAX.to_le_bytes());
    log.append(LFS_RECORD_CLIENT, 24, update.lsn, &unknown);
    assert!(matches!(log.audit(), Err(FfsError::UnsupportedFeature(_))));
}

#[test]
fn only_a_real_restart_trailer_tear_is_reported_as_a_torn_copy() {
    for copy in 0..2 {
        let mut log = AuditLog::new(PAGE, (1, 1), LOG);
        log.checkpoint(&empty_checkpoint(), true);
        log.bytes[copy * PAGE + 511] ^= 1;
        let state = log.audit().unwrap();
        assert!(!state.clean);
        assert_eq!(state.torn_rstr_slot, Some(copy));
    }

    for field in 0..4 {
        let mut log = AuditLog::new(PAGE, (1, 1), LOG);
        log.checkpoint(&empty_checkpoint(), true);
        log.edit_page(PAGE, b"RSTR", |page| {
            let area = usize::from(u16_at(page, 24).unwrap());
            let client = area + usize::from(u16_at(page, area + 22).unwrap());
            match field {
                0 => page[28..30].copy_from_slice(&3_u16.to_le_bytes()),
                1 => page[area + 14..area + 16].copy_from_slice(&0x8000_u16.to_le_bytes()),
                2 => page[client + 32] = b'X',
                _ => page[area + 10..area + 12].copy_from_slice(&0_u16.to_le_bytes()),
            }
        });
        if field < 3 {
            assert!(matches!(log.audit(), Err(FfsError::UnsupportedFeature(_))));
        } else {
            assert!(matches!(log.audit(), Err(FfsError::Corruption { .. })));
        }
    }
}

#[test]
fn equal_lsn_restart_disagreement_is_not_an_empty_or_clean_journal() {
    let mut log = AuditLog::new(PAGE, (1, 1), LOG);
    log.checkpoint(&empty_checkpoint(), true);
    log.edit_page(PAGE, b"RSTR", |page| {
        let area = usize::from(u16_at(page, 24).unwrap());
        page[area + 14..area + 16].copy_from_slice(&0_u16.to_le_bytes());
    });
    assert!(matches!(log.audit(), Err(FfsError::UnsupportedFeature(_))));
}

#[test]
fn erased_audit_checks_the_entire_stream_and_propagates_read_failures() {
    let mut log = AuditLog::new(PAGE, (1, 1), LOG);
    let erased = log.audit().unwrap();
    assert!(erased.erased && erased.clean);
    log.bytes[LOG - 1] = 0;
    assert!(matches!(log.audit(), Err(FfsError::Corruption { .. })));

    let cx = Cx::for_testing();
    let mut reads = 0;
    let oversized = inspect_logfile(&cx, ERASED_SCAN_LIMIT + 512, |_, _| {
        reads += 1;
        Ok(Vec::new())
    });
    assert!(matches!(oversized, Err(FfsError::UnsupportedFeature(_))));
    assert_eq!(reads, 0);
    assert!(matches!(
        inspect_logfile(&cx, LOG as u64, |_, _| Err(FfsError::Cancelled)),
        Err(FfsError::Cancelled)
    ));
    assert!(matches!(
        inspect_logfile(&cx, LOG as u64, |_, _| {
            Err(std::io::Error::other("injected journal read failure").into())
        }),
        Err(FfsError::Io(_))
    ));
    assert!(matches!(
        inspect_logfile(&cx, LOG as u64, |_, size| Ok(vec![0xFF; size - 1])),
        Err(FfsError::Corruption { .. })
    ));
}
