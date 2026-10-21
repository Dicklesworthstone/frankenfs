use super::super::{PAGE_RECORD_END, validate_dirty_tail};
use super::*;

const PAGE: usize = 4096;
const LOG: u64 = 4 * 1024 * 1024;
const START: u64 = 34 * PAGE as u64;

struct Journal {
    restart: Restart,
    pages: BTreeMap<u64, Vec<u8>>,
}

impl Journal {
    fn new() -> Self {
        Self {
            restart: Restart {
                system_page: PAGE as u32,
                log_page: PAGE as u32,
                version: (2, 0),
                clean: false,
                current_lsn: 0,
                seq_num_bits: 44,
                file_size: LOG,
                last_lsn_data_len: 0,
                record_header_len: 48,
                data_off: 128,
                active_client_seq: Some(9),
                active_client_oldest_lsn: None,
                active_client_restart_lsn: None,
                area: Vec::new(),
            },
            pages: BTreeMap::new(),
        }
    }

    fn append(&mut self, kind: u32, transaction: u32, data: &[u8], prev: u64, undo: u64) -> u64 {
        assert!(data.len() < PAGE - 176);
        let offset = START + self.pages.len() as u64 * PAGE as u64;
        let lsn = (1_u64 << 20) | ((offset + 128) / 8);
        let mut page = vec![0; PAGE];
        page[..4].copy_from_slice(b"RCRD");
        page[4..6].copy_from_slice(&40_u16.to_le_bytes());
        page[6..8].copy_from_slice(&9_u16.to_le_bytes());
        page[8..16].copy_from_slice(&lsn.to_le_bytes());
        page[16..20].copy_from_slice(&PAGE_RECORD_END.to_le_bytes());
        page[20..22].copy_from_slice(&1_u16.to_le_bytes());
        page[22..24].copy_from_slice(&1_u16.to_le_bytes());
        let next = (176 + data.len()).next_multiple_of(8) as u16;
        page[24..26].copy_from_slice(&next.to_le_bytes());
        page[32..40].copy_from_slice(&lsn.to_le_bytes());
        let header = &mut page[128..176];
        header[..8].copy_from_slice(&lsn.to_le_bytes());
        header[8..16].copy_from_slice(&prev.to_le_bytes());
        header[16..24].copy_from_slice(&undo.to_le_bytes());
        header[24..28].copy_from_slice(&(data.len() as u32).to_le_bytes());
        header[28..30].copy_from_slice(&9_u16.to_le_bytes());
        header[32..36].copy_from_slice(&kind.to_le_bytes());
        header[36..40].copy_from_slice(&transaction.to_le_bytes());
        page[176..176 + data.len()].copy_from_slice(data);
        protect(&mut page);
        self.pages.insert(offset, page);
        self.restart.current_lsn = lsn;
        self.restart.last_lsn_data_len = data.len() as u32;
        self.restart.active_client_oldest_lsn.get_or_insert(lsn);
        if kind == LFS_CLIENT_RESTART {
            self.restart.active_client_restart_lsn = Some(lsn);
        }
        lsn
    }

    fn check(&self) -> Result<()> {
        let original = self.pages.clone();
        let result = validate_dirty_tail(
            &Cx::for_testing(),
            &self.restart,
            LOG,
            &mut |offset, size| {
                assert_eq!(size, PAGE);
                self.pages
                    .get(&offset)
                    .cloned()
                    .ok_or_else(|| corrupt(offset, "unexpected journal fixture read"))
            },
        )
        .map(|_| ());
        assert_eq!(self.pages, original, "preflight must not mutate the image");
        result
    }

    fn page_mut(&mut self, lsn: u64) -> &mut [u8] {
        let offset = super::super::lsn_to_vbo(lsn, 44).unwrap() & !(PAGE as u64 - 1);
        self.pages.get_mut(&offset).unwrap()
    }
}

fn protect(page: &mut [u8]) {
    let token = 0xCAFE_u16.to_le_bytes();
    page[40..42].copy_from_slice(&token);
    for sector in 1..=PAGE / 512 {
        let at = sector * 512;
        let saved = [page[at - 2], page[at - 1]];
        page[40 + sector * 2..42 + sector * 2].copy_from_slice(&saved);
        page[at - 2..at].copy_from_slice(&token);
    }
}

fn update(opcode: u16, payload: &[u8]) -> Vec<u8> {
    let mut data = vec![0; 40 + payload.len()];
    data[..2].copy_from_slice(&opcode.to_le_bytes());
    data[4..6].copy_from_slice(&40_u16.to_le_bytes());
    if !payload.is_empty() {
        data[6..8].copy_from_slice(&(payload.len() as u16).to_le_bytes());
        data[40..].copy_from_slice(payload);
    }
    if opcode == NAMES.opcode {
        data[4..8].fill(0);
    }
    if opcode == 7 {
        data[12..14].copy_from_slice(&24_u16.to_le_bytes());
    }
    data
}

fn single_entry(size: usize) -> Vec<u8> {
    let mut table = vec![0; 24 + size];
    table[..2].copy_from_slice(&(size as u16).to_le_bytes());
    table[2..4].copy_from_slice(&1_u16.to_le_bytes());
    table[4..6].copy_from_slice(&1_u16.to_le_bytes());
    table[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
    table
}

/// Full checkpoint with one native open attribute, raw UTF-16 name, dirty
/// extent, transaction-table entry, and referenced transaction update record.
fn checkpoint_fixture() -> (Journal, u64, [u64; 4]) {
    let mut journal = Journal::new();
    let first = journal.append(LFS_CLIENT_RECORD, 24, &update(7, b"original"), 0, 0);
    let mut attrs = single_entry(40);
    attrs[24 + 8..24 + 12].copy_from_slice(&0x80_u32.to_le_bytes());
    attrs[24 + 16..24 + 24].copy_from_slice(&((1_u64 << 48) | 5).to_le_bytes());
    let names = [24, 0, 4, 0, 0, 0xD8, b'a', 0, 0, 0, 0, 0];
    let mut dirty = single_entry(40);
    dirty[24 + 4..24 + 8].copy_from_slice(&24_u32.to_le_bytes());
    dirty[24 + 8..24 + 12].copy_from_slice(&512_u32.to_le_bytes());
    dirty[24 + 12..24 + 16].copy_from_slice(&1_u32.to_le_bytes());
    dirty[24 + 24..24 + 32].copy_from_slice(&first.to_le_bytes());
    dirty[24 + 32..24 + 40].copy_from_slice(&20_u64.to_le_bytes());
    let mut transactions = single_entry(40);
    transactions[24 + 4] = 1;
    for at in [8, 16, 24] {
        transactions[24 + at..24 + at + 8].copy_from_slice(&first.to_le_bytes());
    }
    let mut restart = vec![0; 64];
    restart[..4].copy_from_slice(&1_u32.to_le_bytes());
    restart[8..16].copy_from_slice(&first.to_le_bytes());
    let mut dumps = [0; 4];
    for (index, (spec, data)) in [
        (ATTRIBUTES, attrs.as_slice()),
        (NAMES, names.as_slice()),
        (DIRTY, dirty.as_slice()),
        (TRANSACTIONS, transactions.as_slice()),
    ]
    .into_iter()
    .enumerate()
    {
        let lsn = journal.append(LFS_CLIENT_RECORD, 64, &update(spec.opcode, data), 0, 0);
        dumps[index] = lsn;
        restart[spec.lsn_offset..spec.lsn_offset + 8].copy_from_slice(&lsn.to_le_bytes());
        restart[spec.size_offset..spec.size_offset + 4]
            .copy_from_slice(&(data.len() as u32).to_le_bytes());
    }
    journal.append(LFS_CLIENT_RESTART, 0, &restart, 0, 0);
    (journal, first, dumps)
}

#[test]
fn native_checkpoint_loads_all_dump_kinds_and_referenced_transaction() {
    let (journal, _, _) = checkpoint_fixture();
    journal.check().unwrap();
}

#[test]
fn predecessors_use_their_own_lsn_and_length_not_the_tail_metadata() {
    let mut journal = Journal::new();
    let first = journal.append(LFS_CLIENT_RECORD, 24, &update(0, &[]), 0, 0);
    let second = journal.append(LFS_CLIENT_RECORD, 24, &update(7, b"12345678"), first, first);
    journal.append(LFS_CLIENT_RECORD, 24, &update(0x1A, &[]), second, first);
    journal.check().unwrap();
}

#[test]
fn current_record_and_checkpoint_links_reject_self_future_and_wrong_locations() {
    for link in [0, 1, 2, 3] {
        let mut journal = Journal::new();
        let first = journal.append(LFS_CLIENT_RECORD, 24, &update(0, &[]), 0, 0);
        let bad = match link {
            0 => first,
            1 => first + 8,
            2 => (1_u64 << 20) | 1,
            _ => (1_u64 << 20) | (START / 8),
        };
        journal.page_mut(first)[136..144].copy_from_slice(&bad.to_le_bytes());
        assert!(journal.check().is_err());
    }
    let (mut journal, first, _) = checkpoint_fixture();
    journal.restart.active_client_restart_lsn = Some(first);
    assert!(journal.check().is_err());
}

#[test]
fn predecessor_client_and_transaction_ownership_are_checked_at_every_hop() {
    for mutation in 0..3 {
        let mut journal = Journal::new();
        let first = journal.append(LFS_CLIENT_RECORD, 24, &update(0, &[]), 0, 0);
        journal.append(LFS_CLIENT_RECORD, 24, &update(0, &[]), first, 0);
        let page = journal.page_mut(first);
        match mutation {
            0 => page[128 + 36..128 + 40].copy_from_slice(&64_u32.to_le_bytes()),
            1 => page[128 + 28..128 + 30].copy_from_slice(&10_u16.to_le_bytes()),
            _ => page[128..136].fill(0),
        }
        assert!(journal.check().is_err());
    }
}

#[test]
fn checkpoint_declared_sizes_kinds_and_transaction_owners_are_not_trusted() {
    for mutation in 0..4 {
        let (mut journal, first, dumps) = checkpoint_fixture();
        match mutation {
            0 => journal.page_mut(dumps[0])[176..178].fill(0),
            1 => {
                let tail = journal.restart.current_lsn;
                journal.page_mut(tail)[176 + 48..176 + 52].copy_from_slice(&2048_u32.to_le_bytes());
            }
            2 => journal.page_mut(first)[128 + 36..128 + 40].copy_from_slice(&64_u32.to_le_bytes()),
            _ => {
                let tail = journal.restart.current_lsn;
                journal.page_mut(tail)[176 + 48..176 + 52].fill(0);
            }
        }
        assert!(journal.check().is_err());
    }
}

#[test]
fn checkpoint_names_and_dirty_extents_require_allocated_attribute_slots() {
    for mutation in 0..5 {
        let (mut journal, _, dumps) = checkpoint_fixture();
        match mutation {
            0 => journal.page_mut(dumps[1])[216..218].copy_from_slice(&64_u16.to_le_bytes()),
            1 => journal.page_mut(dumps[1])[218..220].copy_from_slice(&3_u16.to_le_bytes()),
            2 => journal.page_mut(dumps[2])[216 + 24 + 4..216 + 24 + 8]
                .copy_from_slice(&64_u32.to_le_bytes()),
            3 => journal.page_mut(dumps[2])[216 + 24 + 12..216 + 24 + 16]
                .copy_from_slice(&2_u32.to_le_bytes()),
            _ => journal.page_mut(dumps[3])[216 + 24 + 4] = 255,
        }
        assert!(journal.check().is_err());
    }
}

#[test]
fn checkpoint_sector_tears_and_short_dump_reads_do_not_publish_partial_state() {
    let (mut journal, _, dumps) = checkpoint_fixture();
    journal.page_mut(dumps[0])[PAGE - 1] ^= 1;
    assert!(journal.check().is_err());
    let (journal, _, _) = checkpoint_fixture();
    let tail_page =
        super::super::lsn_to_vbo(journal.restart.current_lsn, 44).unwrap() & !(PAGE as u64 - 1);
    let result = validate_dirty_tail(
        &Cx::for_testing(),
        &journal.restart,
        LOG,
        &mut |offset, _| {
            let page = journal.pages[&offset].clone();
            if offset == tail_page {
                Ok(page)
            } else {
                Ok(page[..PAGE - 1].to_vec())
            }
        },
    );
    assert!(result.is_err());
}

#[test]
fn referenced_record_budget_and_shared_ownership_apply_before_graph_io() {
    let mut journal = Journal::new();
    journal.append(LFS_CLIENT_RECORD, 24, &update(0, &[]), 0, 0);
    journal.restart.file_size = 32 * 1024 * 1024;
    journal.restart.seq_num_bits = 41;
    // Give this synthetic address space its own consistent LSN sequence width.
    let first = (1_u64 << 23) | ((START + 128) / 8);
    journal.restart.active_client_oldest_lsn = Some(first);
    journal.restart.current_lsn = first + PAGE as u64 * MAX_REFERENCED_RECORDS as u64 / 8;
    let mut references = References::default();
    for index in 0..MAX_REFERENCED_RECORDS {
        references
            .add(&journal.restart, first + index as u64 * PAGE as u64 / 8, 24)
            .unwrap();
    }
    assert!(
        references
            .add(&journal.restart, journal.restart.current_lsn, 24)
            .is_err()
    );
    // Shared edges are deduplicated; conflicting owners are not.
    references.add(&journal.restart, first, 24).unwrap();
    assert_eq!(references.pending.len(), MAX_REFERENCED_RECORDS);
    assert!(references.add(&journal.restart, first, 64).is_err());
}
