use super::super::FfsError;
use super::*;
use ffs_ondisk::ntfs::{NtfsLogRestartArea, NtfsValue};
use std::collections::BTreeSet;

fn resident(id: u16, value: &[u8]) -> Vec<u8> {
    let mut attr = vec![0; (24 + value.len()).next_multiple_of(8)];
    let length = attr.len() as u32;
    attr[..4].copy_from_slice(&0x80_u32.to_le_bytes());
    attr[4..8].copy_from_slice(&length.to_le_bytes());
    attr[14..16].copy_from_slice(&id.to_le_bytes());
    attr[16..20].copy_from_slice(&(value.len() as u32).to_le_bytes());
    attr[20..22].copy_from_slice(&24_u16.to_le_bytes());
    attr[24..24 + value.len()].copy_from_slice(value);
    attr
}

fn file() -> Vec<u8> {
    let mut raw = vec![0xD3; 1024];
    raw[..64].fill(0);
    raw[..4].copy_from_slice(b"FILE");
    raw[4..6].copy_from_slice(&48_u16.to_le_bytes());
    raw[6..8].copy_from_slice(&3_u16.to_le_bytes());
    raw[8..16].copy_from_slice(&10_u64.to_le_bytes());
    raw[16..18].copy_from_slice(&7_u16.to_le_bytes());
    raw[18..20].copy_from_slice(&1_u16.to_le_bytes());
    raw[20..22].copy_from_slice(&64_u16.to_le_bytes());
    raw[22..24].copy_from_slice(&1_u16.to_le_bytes());
    raw[28..32].copy_from_slice(&1024_u32.to_le_bytes());
    raw[40..42].copy_from_slice(&3_u16.to_le_bytes());
    raw[44..48].copy_from_slice(&42_u32.to_le_bytes());
    let mut at = 64;
    for attr in [resident(1, b"original"), resident(2, b"neighbor")] {
        raw[at..at + attr.len()].copy_from_slice(&attr);
        at += attr.len();
    }
    raw[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    raw[at + 4..at + 8].fill(0);
    raw[24..28].copy_from_slice(&((at + 8) as u32).to_le_bytes());
    // Independent wire encoding. Both sector tails contain nonzero slack.
    let token = 0xCAFE_u16.to_le_bytes();
    raw[48..50].copy_from_slice(&token);
    for sector in 1..=2 {
        let end = sector * 512;
        let saved = [raw[end - 2], raw[end - 1]];
        raw[48 + sector * 2..50 + sector * 2].copy_from_slice(&saved);
        raw[end - 2..end].copy_from_slice(&token);
    }
    raw
}

struct Memory {
    layout: Layout,
    backing: Vec<u8>,
    free_clusters: BTreeSet<u64>,
    free_records: BTreeSet<u64>,
    bitmap_reads: usize,
    file_reads: usize,
    failure: Option<FfsError>,
}

impl Memory {
    fn new() -> Self {
        Self {
            layout: Layout {
                cluster_bytes: 512,
                clusters: 512,
                record_bytes: 1024,
                mft_initialized: 64 * 1024,
                volume_bytes: 512 * 512,
            },
            backing: file(),
            free_clusters: BTreeSet::new(),
            free_records: BTreeSet::new(),
            bitmap_reads: 0,
            file_reads: 0,
            failure: None,
        }
    }
}

impl Input for Memory {
    fn layout(&self) -> Layout {
        self.layout
    }
    fn mapped_lcn(&self, vcn: u64) -> Result<u64> {
        Ok(if vcn < 85 { vcn + 100 } else { vcn - 85 + 20 })
    }
    fn allocated(&mut self, _cx: &Cx, mft: bool, bit: u64) -> Result<bool> {
        self.bitmap_reads += 1;
        Ok(!(if mft {
            &self.free_records
        } else {
            &self.free_clusters
        })
        .contains(&bit))
    }
    fn file(&mut self, _cx: &Cx, number: u32) -> Result<Vec<u8>> {
        self.file_reads += 1;
        assert_eq!(number, 42);
        if let Some(error) = self.failure.take() {
            return Err(error);
        }
        Ok(self.backing.clone())
    }
}

fn update(lsn: u64, relative: u16, data: &[u8]) -> NtfsRecoveryAction {
    NtfsRecoveryAction {
        lsn,
        transaction_id: 24,
        is_undo: false,
        op: NtfsLogOp::UpdateResidentValue,
        target_vcn: 84,
        target_lcns: vec![184, 20],
        resident_resize: false,
        cluster_block_offset: 0,
        record_offset: 64,
        attribute_offset: relative,
        data: data.to_vec(),
    }
}

fn plan(redo: Vec<NtfsRecoveryAction>, undo: Vec<NtfsRecoveryAction>) -> NtfsLogFilePlan {
    NtfsLogFilePlan {
        restart: NtfsLogRestartArea {
            chkdsk_lsn: 0,
            system_page_size: 4096,
            log_page_size: 4096,
            major_version: 1,
            minor_version: 1,
            current_lsn: 100,
            oldest_lsn: 10,
            client_restart_lsn: 0,
            flags: 0,
            file_size: 4 * 1024 * 1024,
            record_header_length: 48,
            log_page_data_offset: 64,
        },
        records_parsed: redo.len() + undo.len(),
        committed_transactions: vec![24],
        aborted_transactions: Vec::new(),
        dirty_lcns: vec![184, 20],
        redo_actions: redo,
        undo_actions: undo,
    }
}

fn exported(overlay: &Overlay) -> Vec<u8> {
    let mut raw = overlay[&184].to_vec();
    raw.extend(overlay[&20]);
    raw
}

fn values(raw: &[u8]) -> Vec<Vec<u8>> {
    let record = NtfsFileRecord::parse(raw).unwrap();
    record
        .attributes()
        .unwrap()
        .iter()
        .map(|attr| {
            let NtfsValue::Resident(value) = &attr.value else {
                panic!("expected resident");
            };
            value.to_vec()
        })
        .collect()
}

#[test]
fn nonzero_attribute_offset_and_fragmented_mft_export_use_semantic_file_edits() {
    let mut input = Memory::new();
    let before = input.backing.clone();
    let result = execute(
        &Cx::for_testing(),
        &mut input,
        &plan(vec![update(20, 26, b"XX")], vec![]),
    )
    .unwrap();
    assert_eq!(result.keys().copied().collect::<Vec<_>>(), [20, 184]);
    let raw = exported(&result);
    assert_eq!(values(&raw), [b"orXXinal".to_vec(), b"neighbor".to_vec()]);
    assert_eq!(u64::from_le_bytes(raw[8..16].try_into().unwrap()), 20);
    assert_eq!(input.file_reads, 1);
    assert_eq!(input.backing, before);
}

#[test]
fn redo_all_then_undo_only_the_loser_keeps_an_independent_winner() {
    let mut input = Memory::new();
    let before = input.backing.clone();
    let first = update(20, 24, b"AAAA");
    let mut second = update(30, 28, b"BBBB");
    second.transaction_id = 64;
    let mut undo = update(20, 24, b"orig");
    undo.is_undo = true;
    let result = execute(
        &Cx::for_testing(),
        &mut input,
        &plan(vec![first, second], vec![undo]),
    )
    .unwrap();
    assert_eq!(
        values(&exported(&result)),
        [b"origBBBB".to_vec(), b"neighbor".to_vec()]
    );
    assert_eq!(
        input.file_reads, 1,
        "all operations consume the private updated record"
    );
    assert_eq!(input.backing, before);
}

#[test]
fn resident_growth_and_empty_payload_deletion_relocate_neighbors_and_fixups() {
    let mut input = Memory::new();
    let bytes: Vec<_> = (0_u16..601).map(|i| (i % 251) as u8).collect();
    let mut growth = update(20, 24, &bytes);
    growth.resident_resize = true;
    let result = execute(&Cx::for_testing(), &mut input, &plan(vec![growth], vec![])).unwrap();
    assert_eq!(values(&exported(&result)), [bytes, b"neighbor".to_vec()]);
    let mut deletion = update(30, 0, &[]);
    deletion.op = NtfsLogOp::DeleteAttribute;
    input.backing = exported(&result);
    let result = execute(
        &Cx::for_testing(),
        &mut input,
        &plan(vec![deletion], vec![]),
    )
    .unwrap();
    assert_eq!(values(&exported(&result)), [b"neighbor".to_vec()]);
}

#[test]
fn public_replay_creates_a_resident_attribute_instead_of_overwriting_the_next_one() {
    let mut action = update(20, 0, &resident(3, b"inserted"));
    action.op = NtfsLogOp::CreateAttribute;
    action.record_offset = 96;
    let mut input = Memory::new();
    let before = input.backing.clone();
    let result = execute(&Cx::for_testing(), &mut input, &plan(vec![action], vec![])).unwrap();
    assert_eq!(
        values(&exported(&result)),
        [
            b"original".to_vec(),
            b"inserted".to_vec(),
            b"neighbor".to_vec()
        ]
    );
    assert_eq!(input.backing, before);
}

#[test]
fn later_unsupported_raw_patch_is_refused_before_even_the_first_bitmap_read() {
    for op in [
        NtfsLogOp::UpdateNonresidentValue,
        NtfsLogOp::InitializeFileRecordSegment,
        NtfsLogOp::UpdateMappingPairs,
        NtfsLogOp::SetNewAttributeSizes,
        NtfsLogOp::Unknown(0xFF),
    ] {
        let mut input = Memory::new();
        let mut later = update(30, 24, b"bad");
        later.op = op;
        assert!(matches!(
            execute(
                &Cx::for_testing(),
                &mut input,
                &plan(vec![update(20, 24, b"good"), later], vec![])
            ),
            Err(FfsError::UnsupportedFeature(_))
        ));
        assert_eq!((input.bitmap_reads, input.file_reads), (0, 0));
    }
}

#[test]
fn every_mapping_claim_allocation_bit_and_system_target_is_checked_before_file_io() {
    for mutation in 0..6 {
        let mut input = Memory::new();
        let mut action = update(20, 24, b"new");
        match mutation {
            0 => action.target_lcns[1] = 185,
            1 => {
                input.free_clusters.insert(20);
            }
            2 => {
                input.free_records.insert(42);
            }
            3 => {
                action.target_vcn = 0;
                action.target_lcns = vec![100, 101];
            }
            4 => {
                action.target_lcns.pop();
            }
            _ => {
                input.layout.mft_initialized = 42 * 1024;
            }
        }
        assert!(execute(&Cx::for_testing(), &mut input, &plan(vec![action], vec![])).is_err());
        assert_eq!(input.file_reads, 0);
    }
}

#[test]
fn late_invalid_edit_torn_record_short_read_or_cancellation_cannot_return_an_overlay() {
    let cx = Cx::for_testing();
    for mutation in 0..7 {
        let mut input = Memory::new();
        let mut actions = vec![update(20, 24, b"good")];
        match mutation {
            0 => actions.push(update(30, 20, b"header")),
            1 => input.backing[1023] ^= 1,
            2 => {
                input.backing.pop();
            }
            3 => input.failure = Some(FfsError::Cancelled),
            4 => input.failure = Some(FfsError::Io(std::io::Error::other("read failure"))),
            5 => input.backing[44..48].copy_from_slice(&43_u32.to_le_bytes()),
            _ => input.backing[8..16].copy_from_slice(&101_u64.to_le_bytes()),
        }
        let before = input.backing.clone();
        let result = execute(&cx, &mut input, &plan(actions, vec![]));
        if mutation == 3 {
            assert!(matches!(result, Err(FfsError::Cancelled)));
        } else {
            assert!(result.is_err());
        }
        assert_eq!(input.backing, before);
    }
}

#[test]
fn repeated_redo_preserves_an_applied_page_even_when_the_old_attribute_offset_is_obsolete() {
    let cx = Cx::for_testing();
    let mut input = Memory::new();
    let first = execute(
        &cx,
        &mut input,
        &plan(vec![update(20, 24, b"changed!")], vec![]),
    )
    .unwrap();
    input.backing = exported(&first);
    let mut obsolete = update(20, 24, b"changed!");
    obsolete.record_offset = u16::MAX;
    let repeated = execute(&cx, &mut input, &plan(vec![obsolete], vec![])).unwrap();
    assert_eq!(first, repeated);
}

#[test]
fn nonresident_creation_is_not_an_unchecked_allocation_bypass() {
    let mut attr = vec![0; 72];
    attr[..4].copy_from_slice(&0x80_u32.to_le_bytes());
    attr[4..8].copy_from_slice(&72_u32.to_le_bytes());
    attr[8] = 1;
    attr[14..16].copy_from_slice(&3_u16.to_le_bytes());
    attr[32..34].copy_from_slice(&64_u16.to_le_bytes());
    attr[64..68].copy_from_slice(&[0x11, 1, 100, 0]);
    let mut action = update(20, 0, &attr);
    action.op = NtfsLogOp::CreateAttribute;
    action.record_offset = 96;
    let mut input = Memory::new();
    let before = input.backing.clone();
    assert!(matches!(
        execute(&Cx::for_testing(), &mut input, &plan(vec![action], vec![])),
        Err(FfsError::UnsupportedFeature(_))
    ));
    assert_eq!(input.backing, before);
}

#[test]
fn subcluster_sector_offsets_use_volume_relative_not_container_relative_addresses() {
    let mut input = Memory::new();
    input.layout.cluster_bytes = 4096;
    input.layout.volume_bytes = 4096 * 512;
    let mut action = update(20, 24, b"changed!");
    action.target_vcn = 10;
    action.target_lcns = vec![110];
    action.cluster_block_offset = 4;
    let result = execute(&Cx::for_testing(), &mut input, &plan(vec![action], vec![])).unwrap();
    let sector = (110 * 4096 + 4 * 512) / 512;
    assert_eq!(
        result.keys().copied().collect::<Vec<_>>(),
        [sector, sector + 1]
    );
    let mut raw = result[&sector].to_vec();
    raw.extend(result[&(sector + 1)]);
    assert_eq!(values(&raw), [b"changed!".to_vec(), b"neighbor".to_vec()]);
}

#[test]
fn reversed_pass_order_and_action_budgets_fail_before_target_reads() {
    let mut bad = update(20, 24, b"new");
    bad.is_undo = true;
    for invalid in [
        plan(vec![bad], vec![]),
        plan(vec![update(30, 24, b"x"), update(20, 24, b"y")], vec![]),
        plan(vec![update(20, 24, b"x"); MAX_ACTIONS + 1], vec![]),
    ] {
        let mut input = Memory::new();
        assert!(execute(&Cx::for_testing(), &mut input, &invalid).is_err());
        assert_eq!((input.bitmap_reads, input.file_reads), (0, 0));
    }
}

#[test]
fn publication_rolls_back_the_entire_snapshot_on_late_failure_and_never_calls_backing_io() {
    struct NoIo;
    impl ffs_block::ByteDevice for NoIo {
        fn len_bytes(&self) -> u64 {
            4096
        }
        fn read_exact_at(&self, _: &Cx, _: ffs_types::ByteOffset, _: &mut [u8]) -> Result<()> {
            panic!("complete overlay publication must not read backing");
        }
        fn write_all_at(&self, _: &Cx, _: ffs_types::ByteOffset, _: &[u8]) -> Result<()> {
            panic!("volatile overlay must not write backing");
        }
        fn sync(&self, _: &Cx) -> Result<()> {
            panic!("volatile overlay must not synchronize backing");
        }
    }
    let cx = Cx::for_testing();
    let mut source = Source {
        device: Box::new(NoIo),
        base: 0,
        length: 4096,
        overlay: BTreeMap::from([(3, [0x33; 512])]),
    };
    let before = source.overlay.clone();
    // Sector zero is installed first; the out-of-volume sector fails later.
    assert!(
        publish(
            &cx,
            &mut source,
            BTreeMap::from([(0, [0xAA; 512]), (8, [0xBB; 512])])
        )
        .is_err()
    );
    assert_eq!(source.overlay, before);
    let staged = BTreeMap::from([(0, [0xAA; 512]), (1, [0xBB; 512])]);
    publish(&cx, &mut source, staged.clone()).unwrap();
    assert_eq!(source.overlay, staged);
}

#[test]
fn resident_attribute_lists_cannot_bypass_nonresident_storage_admission() {
    let mut attr = resident(3, &[]);
    attr[..4].copy_from_slice(&ffs_ondisk::ntfs::ATTRIBUTE_LIST.to_le_bytes());
    let mut action = update(20, 0, &attr);
    action.op = NtfsLogOp::CreateAttribute;
    action.record_offset = 96;
    let mut input = Memory::new();
    let before = input.backing.clone();
    assert!(matches!(
        execute(&Cx::for_testing(), &mut input, &plan(vec![action], vec![])),
        Err(FfsError::UnsupportedFeature(_))
    ));
    assert_eq!(input.backing, before);
}
