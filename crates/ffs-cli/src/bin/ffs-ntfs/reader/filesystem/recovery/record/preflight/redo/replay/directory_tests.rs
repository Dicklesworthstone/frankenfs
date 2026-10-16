//! Exercise directory-root byte application through the same mapping/allocation
//! and private-stage executor used by production recovery preflight.
use super::*;
use super::super::build;
use super::super::super::targets::{Attribute, Cluster, State};
use super::super::super::super::{LFS_CLIENT_RECORD, TailRecord};
use ffs_ondisk::ntfs::{NtfsValue, index::NtfsIndexRoot};

const REFERENCE: u64 = 7_u64 << 48;

fn file() -> Vec<u8> {
    let mut raw = vec![0; 1024];
    raw[..4].copy_from_slice(b"FILE");
    for (at, value) in [(4, 48_u16), (6, 3), (16, 7), (18, 1), (20, 64), (22, 3), (40, 2)] {
        raw[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    for (at, value) in [(24, 152_u32), (28, 1024), (44, 42), (64, 0x90),
        (68, 80), (80, 48), (96, 0x30), (100, 1), (104, 4096),
        (112, 16), (116, 32), (120, 32), (144, u32::MAX)]
    {
        raw[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    raw[8..16].copy_from_slice(&10_u64.to_le_bytes());
    raw[73] = 4;
    raw[74..76].copy_from_slice(&24_u16.to_le_bytes());
    raw[78..80].copy_from_slice(&1_u16.to_le_bytes());
    raw[84..86].copy_from_slice(&32_u16.to_le_bytes());
    raw[88..96].copy_from_slice(&[b'$', 0, b'I', 0, b'3', 0, b'0', 0]);
    raw[108] = 8;
    raw[136..138].copy_from_slice(&16_u16.to_le_bytes());
    raw[140..142].copy_from_slice(&2_u16.to_le_bytes());
    let token = 0xCAFE_u16.to_le_bytes();
    raw[48..50].copy_from_slice(&token);
    for sector in 1..=2 {
        let end = sector * 512;
        let saved = [raw[end - 2], raw[end - 1]];
        raw[48 + 2 * sector..50 + 2 * sector].copy_from_slice(&saved);
        raw[end - 2..end].copy_from_slice(&token);
    }
    NtfsFileRecord::parse(&raw).unwrap();
    raw
}

fn row(name: u16) -> Vec<u8> {
    let mut data = vec![0; 88];
    data[..8].copy_from_slice(&((3_u64 << 48) | 99).to_le_bytes());
    data[8..10].copy_from_slice(&88_u16.to_le_bytes());
    data[10..12].copy_from_slice(&68_u16.to_le_bytes());
    data[16..24].copy_from_slice(&((7_u64 << 48) | 42).to_le_bytes());
    data[80] = 1;
    data[81] = 1;
    data[82..84].copy_from_slice(&name.to_le_bytes());
    data
}

fn update(lsn: u64, transaction: u32, offset: u16, redo_op: u16, undo_op: u16, payload: &[u8]) -> LogRecord {
    let end = (48 + payload.len()).next_multiple_of(8);
    let mut data = vec![0; end];
    for (at, value) in [(0, redo_op), (2, undo_op), (4, 48), (6, payload.len() as u16),
        (8, end as u16), (12, 24), (14, 2), (16, 64), (18, offset)]
    {
        data[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    for (at, value) in [(24, 84_u64), (32, 184), (40, 185)] {
        data[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    data[48..48 + payload.len()].copy_from_slice(payload);
    LogRecord { lsn, previous: 0, undo_next: 0, kind: LFS_CLIENT_RECORD,
        summary: TailRecord { transaction_id: transaction, redo_op, undo_op }, data }
}

fn targets() -> State {
    let mut targets = State::default();
    targets.attributes.insert(24, Attribute { reference: REFERENCE, kind: DATA,
        index_bytes: 0, opened: 10, name: Vec::new() });
    for vcn in [84, 85] {
        targets.clusters.insert((24, vcn), Cluster { oldest: 20, lcn: Some(vcn + 100) });
    }
    targets
}

struct Input {
    raw: Vec<u8>,
    reads: usize,
    mapping_delta: u64,
    allocated: bool,
}

impl Input {
    fn new() -> Self {
        Self { raw: file(), reads: 0, mapping_delta: 100, allocated: true }
    }
}

impl MftInput for Input {
    fn layout(&self) -> Layout {
        Layout { cluster_bytes: 512, record_bytes: 1024, clusters: 512,
            mft_initialized: 64 * 1024, mft_reference: REFERENCE, boundary_lsn: 100 }
    }
    fn mapped_lcn(&self, vcn: u64) -> Result<u64> { Ok(vcn + self.mapping_delta) }
    fn allocated(&mut self, _cx: &Cx, _mft: bool, _bit: u64) -> Result<bool> { Ok(self.allocated) }
    fn read_record(&mut self, _cx: &Cx, number: u32) -> Result<Vec<u8>> {
        assert_eq!(number, 42);
        self.reads += 1;
        Ok(self.raw.clone())
    }
}

fn names(raw: &[u8]) -> Vec<Vec<u16>> {
    let file = NtfsFileRecord::parse(raw).unwrap();
    let attrs = file.attributes().unwrap();
    let NtfsValue::Resident(value) = &attrs[0].value else { panic!("root must be resident") };
    NtfsIndexRoot::parse(value, 512).unwrap().entries.into_iter()
        .filter_map(|entry| entry.key.map(|(_, name)| name.name)).collect()
}

#[test]
fn interleaved_root_insertions_and_loser_undo_use_the_staged_directory() {
    let cx = Cx::for_testing();
    let targets = targets();
    let history = [update(20, 24, 64, 0x0C, 0x0D, &row(65)),
        update(30, 64, 152, 0x0C, 0x0D, &row(66))];
    let undo = [update(20, 24, 64, 0x0C, 0x0D, &row(65))];
    let plan = build(&cx, &targets, &history).unwrap();
    let mut input = Input::new();
    let before = input.raw.clone();
    let staged = execute(&cx, &mut input, &plan, &undo, &targets).unwrap();
    assert_eq!(names(&staged.records[&42]), vec![vec![66_u16]]);
    assert_eq!((staged.summary.redo, staged.summary.undo, input.reads), (2, 1, 1));
    assert_eq!(input.raw, before);
}

#[test]
fn directory_root_redo_is_idempotent_and_keeps_metadata_update_dispatch() {
    let cx = Cx::for_testing();
    let targets = targets();
    let history = [update(20, 24, 64, 0x0C, 0x0D, &row(65)),
        update(30, 24, 64, 0x13, 0, &[0xAB; 56])];
    let plan = build(&cx, &targets, &history).unwrap();
    let mut input = Input::new();
    let staged = execute(&cx, &mut input, &plan, &[], &targets).unwrap();
    input.raw = staged.records[&42].clone();
    let before = input.raw.clone();
    let again = execute(&cx, &mut input, &plan, &[], &targets).unwrap();
    assert_eq!(again.records[&42], before);
    assert_eq!((again.summary.redo, again.summary.skipped), (0, 2));
    assert_eq!(names(&again.records[&42]), vec![vec![65_u16]]);
}

#[test]
fn root_recovery_does_not_bypass_mft_mapping_or_allocation_checks() {
    let cx = Cx::for_testing();
    let targets = targets();
    let history = [update(20, 24, 64, 0x0C, 0x0D, &row(65))];
    let plan = build(&cx, &targets, &history).unwrap();
    for mismatch in [false, true] {
        let mut input = Input::new();
        if mismatch { input.mapping_delta += 1; } else { input.allocated = false; }
        assert!(execute(&cx, &mut input, &plan, &[], &targets).is_err());
        assert_eq!(input.reads, 0);
    }
}

#[test]
fn late_bad_directory_key_discards_the_entire_private_stage() {
    let cx = Cx::for_testing();
    let targets = targets();
    let history = [update(20, 24, 64, 0x0C, 0x0D, &row(65)),
        update(30, 64, 152, 0x0C, 0x0D, &row(0))];
    let plan = build(&cx, &targets, &history).unwrap();
    let mut input = Input::new();
    let before = input.raw.clone();
    assert!(execute(&cx, &mut input, &plan, &[], &targets).is_err());
    assert_eq!(input.reads, 1);
    assert_eq!(input.raw, before);
}
