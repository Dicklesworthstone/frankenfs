use super::super::super::super::{LFS_CLIENT_RECORD, TailRecord};
use super::super::super::targets::{Attribute, Cluster, State};
use super::super::build;
use super::*;
use ffs_ondisk::ntfs::NtfsValue;
use reader::FfsError;
use std::collections::BTreeSet;

mod mapping;

const REFERENCE: u64 = 7_u64 << 48;

fn file(number: u32, kind: u32, value: &[u8]) -> Vec<u8> {
    let mut raw = vec![0; 1024];
    raw[..4].copy_from_slice(b"FILE");
    raw[4..6].copy_from_slice(&48_u16.to_le_bytes());
    raw[6..8].copy_from_slice(&3_u16.to_le_bytes());
    raw[8..16].copy_from_slice(&10_u64.to_le_bytes());
    raw[16..18].copy_from_slice(&7_u16.to_le_bytes());
    raw[18..20].copy_from_slice(&1_u16.to_le_bytes());
    raw[20..22].copy_from_slice(&64_u16.to_le_bytes());
    raw[22..24].copy_from_slice(&1_u16.to_le_bytes());
    raw[28..32].copy_from_slice(&1024_u32.to_le_bytes());
    raw[40..42].copy_from_slice(&2_u16.to_le_bytes());
    raw[44..48].copy_from_slice(&number.to_le_bytes());
    let size = (24 + value.len()).next_multiple_of(8);
    raw[24..28].copy_from_slice(&u32::try_from(64 + size + 8).unwrap().to_le_bytes());
    raw[64..68].copy_from_slice(&kind.to_le_bytes());
    raw[68..72].copy_from_slice(&u32::try_from(size).unwrap().to_le_bytes());
    raw[78..80].copy_from_slice(&1_u16.to_le_bytes());
    raw[80..84].copy_from_slice(&u32::try_from(value.len()).unwrap().to_le_bytes());
    raw[84..86].copy_from_slice(&24_u16.to_le_bytes());
    raw[88..88 + value.len()].copy_from_slice(value);
    raw[64 + size..68 + size].copy_from_slice(&u32::MAX.to_le_bytes());
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

fn value(raw: &[u8]) -> Vec<u8> {
    let record = NtfsFileRecord::parse(raw).unwrap();
    let attrs = record.attributes().unwrap();
    let NtfsValue::Resident(value) = &attrs[0].value else {
        panic!("expected resident")
    };
    value.to_vec()
}

fn update(lsn: u64, relative: u16, redo: &[u8], undo: &[u8]) -> LogRecord {
    let undo_at = (48 + redo.len()).next_multiple_of(8);
    let mut data = vec![0; undo_at + undo.len()];
    data[..2].copy_from_slice(&7_u16.to_le_bytes());
    data[2..4].copy_from_slice(&7_u16.to_le_bytes());
    data[4..6].copy_from_slice(&48_u16.to_le_bytes());
    data[6..8].copy_from_slice(&u16::try_from(redo.len()).unwrap().to_le_bytes());
    data[8..10].copy_from_slice(&u16::try_from(undo_at).unwrap().to_le_bytes());
    data[10..12].copy_from_slice(&u16::try_from(undo.len()).unwrap().to_le_bytes());
    data[12..14].copy_from_slice(&24_u16.to_le_bytes());
    data[14..16].copy_from_slice(&2_u16.to_le_bytes());
    data[16..18].copy_from_slice(&64_u16.to_le_bytes());
    data[18..20].copy_from_slice(&relative.to_le_bytes());
    data[24..32].copy_from_slice(&84_u64.to_le_bytes());
    data[32..40].copy_from_slice(&184_u64.to_le_bytes());
    data[40..48].copy_from_slice(&185_u64.to_le_bytes());
    data[48..48 + redo.len()].copy_from_slice(redo);
    data[undo_at..].copy_from_slice(undo);
    LogRecord {
        lsn,
        previous: 0,
        undo_next: 0,
        kind: LFS_CLIENT_RECORD,
        summary: TailRecord {
            transaction_id: 24,
            redo_op: 7,
            undo_op: 7,
        },
        data,
    }
}

fn targets() -> State {
    let mut state = State::default();
    state.attributes.insert(
        24,
        Attribute {
            reference: REFERENCE,
            kind: DATA,
            index_bytes: 0,
            opened: 10,
            name: Vec::new(),
        },
    );
    for vcn in [84, 85] {
        state.clusters.insert(
            (24, vcn),
            Cluster {
                oldest: 20,
                lcn: Some(vcn + 100),
            },
        );
    }
    state
}

struct Input {
    layout: Layout,
    records: BTreeMap<u32, Vec<u8>>,
    free_clusters: BTreeSet<u64>,
    free_records: BTreeSet<u64>,
    mapping_delta: u64,
    reads: usize,
    failure: Option<FfsError>,
}

impl Input {
    fn new() -> Self {
        Self {
            layout: Layout {
                cluster_bytes: 512,
                record_bytes: 1024,
                clusters: 512,
                mft_initialized: 64 * 1024,
                mft_reference: REFERENCE,
                boundary_lsn: 100,
            },
            records: BTreeMap::from([(42, file(42, DATA, b"original"))]),
            free_clusters: BTreeSet::new(),
            free_records: BTreeSet::new(),
            mapping_delta: 100,
            reads: 0,
            failure: None,
        }
    }
}

impl MftInput for Input {
    fn layout(&self) -> Layout {
        self.layout
    }
    fn mapped_lcn(&self, vcn: u64) -> Result<u64> {
        Ok(vcn + self.mapping_delta)
    }
    fn allocated(&mut self, _cx: &Cx, mft: bool, bit: u64) -> Result<bool> {
        Ok(!(if mft {
            &self.free_records
        } else {
            &self.free_clusters
        })
        .contains(&bit))
    }
    fn read_record(&mut self, _cx: &Cx, number: u32) -> Result<Vec<u8>> {
        self.reads += 1;
        if let Some(error) = self.failure.take() {
            return Err(error);
        }
        self.records
            .get(&number)
            .cloned()
            .ok_or_else(|| corrupt(0, "fixture missing record"))
    }
}

#[test]
fn redo_then_loser_undo_preserves_an_independent_committed_update() {
    let cx = Cx::for_testing();
    let targets = targets();
    let records = [
        update(20, 24, b"AAAA", b"orig"),
        update(30, 28, b"BBBB", b"inal"),
    ];
    let undo = [update(20, 24, b"AAAA", b"orig")];
    let plan = build(&cx, &targets, &records).unwrap();
    let mut input = Input::new();
    let original = input.records.clone();
    let staged = execute(&cx, &mut input, &plan, &undo, &targets).unwrap();
    assert_eq!(value(&staged.records[&42]), b"origBBBB");
    assert_eq!(
        (
            staged.summary.redo,
            staged.summary.undo,
            staged.summary.skipped
        ),
        (2, 1, 0)
    );
    assert_eq!(
        input.reads, 1,
        "second operation must consume the staged record"
    );
    assert_eq!(input.records, original, "no backing record is mutated");
}

#[test]
fn rerunning_redo_skips_applied_pages_without_reinterpreting_old_offsets() {
    let cx = Cx::for_testing();
    let targets = targets();
    let records = [update(20, 24, b"changed!", b"original")];
    let plan = build(&cx, &targets, &records).unwrap();
    let mut input = Input::new();
    let first = execute(&cx, &mut input, &plan, &[], &targets).unwrap();
    input.records = first.records;
    let before = input.records.clone();
    let second = execute(&cx, &mut input, &plan, &[], &targets).unwrap();
    assert_eq!(second.records, before);
    assert_eq!((second.summary.redo, second.summary.skipped), (0, 1));
}

#[test]
fn hotfix_claims_are_checked_against_current_mapping_not_old_journal_lcns() {
    let cx = Cx::for_testing();
    let targets = targets();
    let mut record = update(20, 24, b"changed!", b"original");
    record.data[32..40].copy_from_slice(&44_u64.to_le_bytes());
    record.data[40..48].copy_from_slice(&45_u64.to_le_bytes());
    let records = [record];
    let plan = build(&cx, &targets, &records).unwrap();
    let staged = execute(&cx, &mut Input::new(), &plan, &[], &targets).unwrap();
    assert_eq!(value(&staged.records[&42]), b"changed!");
}

#[test]
fn wrong_stream_generation_mapping_or_allocation_fails_before_target_reads() {
    let cx = Cx::for_testing();
    for mutation in 0..6 {
        let mut targets = targets();
        let records = [update(20, 24, b"changed!", b"original")];
        let mut input = Input::new();
        match mutation {
            0 => targets.attributes.get_mut(&24).unwrap().reference ^= 1_u64 << 48,
            1 => targets.attributes.get_mut(&24).unwrap().name.push(97),
            2 => input.mapping_delta = 200,
            3 => {
                input.free_clusters.insert(185);
            }
            4 => {
                input.free_records.insert(42);
            }
            _ => input.layout.mft_initialized = 42 * 1024,
        }
        let plan = build(&cx, &targets, &records).unwrap();
        assert!(execute(&cx, &mut input, &plan, &[], &targets).is_err());
        assert_eq!(input.reads, 0);
    }
}

#[test]
fn unsupported_later_opcode_prevents_even_the_first_file_read() {
    let cx = Cx::for_testing();
    let targets = targets();
    let first = update(20, 24, b"changed!", b"original");
    let mut later = update(30, 24, b"changed!", b"original");
    // Mapping-pairs updates now execute. Keep this pre-I/O refusal control
    // on InitializeFileRecordSegment, which this executor still rejects.
    later.summary.redo_op = 2;
    later.data[..2].copy_from_slice(&2_u16.to_le_bytes());
    let records = [first, later];
    let plan = build(&cx, &targets, &records).unwrap();
    let mut input = Input::new();
    assert!(matches!(
        execute(&cx, &mut input, &plan, &[], &targets),
        Err(FfsError::UnsupportedFeature(_))
    ));
    assert_eq!(input.reads, 0);
}

#[test]
fn late_invalid_edit_discards_the_complete_private_stage() {
    let cx = Cx::for_testing();
    let targets = targets();
    let records = [
        update(20, 24, b"changed!", b"original"),
        update(30, 20, b"header!!", b"original"),
    ];
    let plan = build(&cx, &targets, &records).unwrap();
    let mut input = Input::new();
    let original = input.records.clone();
    assert!(execute(&cx, &mut input, &plan, &[], &targets).is_err());
    assert_eq!(input.records, original);
    assert_eq!(input.reads, 1);
}

#[test]
fn target_tears_short_reads_wrong_records_and_future_page_lsns_are_refused() {
    let cx = Cx::for_testing();
    let targets = targets();
    let records = [update(20, 24, b"changed!", b"original")];
    let plan = build(&cx, &targets, &records).unwrap();
    for mutation in 0..4 {
        let mut input = Input::new();
        let raw = input.records.get_mut(&42).unwrap();
        match mutation {
            0 => raw[1023] ^= 1,
            1 => raw.truncate(1023),
            2 => raw[44..48].copy_from_slice(&43_u32.to_le_bytes()),
            _ => raw[8..16].copy_from_slice(&101_u64.to_le_bytes()),
        }
        let original = input.records.clone();
        assert!(execute(&cx, &mut input, &plan, &[], &targets).is_err());
        assert_eq!(input.records, original);
    }
}

#[test]
fn io_and_cancellation_failures_do_not_become_skipped_successes() {
    let cx = Cx::for_testing();
    let targets = targets();
    let records = [update(20, 24, b"changed!", b"original")];
    let plan = build(&cx, &targets, &records).unwrap();
    for cancellation in [false, true] {
        let mut input = Input::new();
        input.failure = Some(if cancellation {
            FfsError::Cancelled
        } else {
            FfsError::Io(std::io::Error::other("injected target read"))
        });
        let result = execute(&cx, &mut input, &plan, &[], &targets);
        if cancellation {
            assert!(matches!(result, Err(FfsError::Cancelled)));
        } else {
            assert!(matches!(result, Err(FfsError::Io(_))));
        }
    }
}

#[test]
fn undo_rejects_retired_allocations_and_wrong_execution_order() {
    let cx = Cx::for_testing();
    let mut targets = targets();
    let records = [
        update(20, 24, b"changed!", b"original"),
        update(30, 24, b"changed!", b"original"),
    ];
    let mut input = Input::new();
    let plan = build(&cx, &targets, &records).unwrap();
    assert!(execute(&cx, &mut input, &plan, &records, &targets).is_err());
    assert_eq!(input.reads, 0);
    targets.clusters.get_mut(&(24, 85)).unwrap().lcn = None;
    let empty = Plan {
        candidates: Vec::new(),
        obsolete: 0,
        relocated: 0,
    };
    assert!(execute(&cx, &mut input, &empty, &records[..1], &targets).is_err());
    assert_eq!(input.reads, 0);
}

#[test]
fn operation_budget_is_checked_before_any_source_io() {
    let cx = Cx::for_testing();
    let targets = targets();
    let record = update(20, 24, b"changed!", b"original");
    let attribute = &targets.attributes[&24];
    let plan = Plan {
        candidates: (0..=MAX_RECORDS)
            .map(|_| Candidate {
                record: &record,
                attribute,
                lcns: vec![184, 185],
                payload: b"changed!",
            })
            .collect(),
        obsolete: 0,
        relocated: 0,
    };
    let mut input = Input::new();
    assert!(execute(&cx, &mut input, &plan, &[], &targets).is_err());
    assert_eq!(input.reads, 0);
}

#[test]
fn native_sector_offsets_cover_subcluster_records_and_multicluster_transfers() {
    let attributes = targets();
    let attribute = &attributes.attributes[&24];
    for cluster_bytes in [512_u64, 1024, 2048, 4096, 8192, 16_384, 32_768, 65_536] {
        let mut input = Input::new();
        input.layout.cluster_bytes = cluster_bytes;
        let logical = 42_u64 * 1024;
        let vcn = logical / cluster_bytes;
        let offset = logical % cluster_bytes;
        let count = (offset + 1024).div_ceil(cluster_bytes);
        let mut record = update(20, 24, b"changed!", b"original");
        record.data[24..32].copy_from_slice(&vcn.to_le_bytes());
        record.data[20..22].copy_from_slice(&u16::try_from(offset / 512).unwrap().to_le_bytes());
        record.data[14..16].copy_from_slice(&u16::try_from(count).unwrap().to_le_bytes());
        let lcns = vec![100; usize::try_from(count).unwrap()];
        assert_eq!(target(input.layout, &record, attribute, &lcns).unwrap(), 42);
        record.data[20..22]
            .copy_from_slice(&u16::try_from(offset / 512 + 1).unwrap().to_le_bytes());
        assert!(target(input.layout, &record, attribute, &lcns).is_err());
    }
    // The sector offset can cover several small clusters in a logged transfer;
    // it is not a byte offset constrained to the first physical cluster.
    let mut record = update(20, 24, b"changed!", b"original");
    record.data[24..32].copy_from_slice(&80_u64.to_le_bytes());
    record.data[20..22].copy_from_slice(&4_u16.to_le_bytes());
    record.data[14..16].copy_from_slice(&8_u16.to_le_bytes());
    assert_eq!(
        target(Input::new().layout, &record, attribute, &[100; 8]).unwrap(),
        42
    );
}

#[test]
fn bitmap_profiles_and_record_lifetimes_cannot_supply_fabricated_targets() {
    let mut stream = Stream {
        storage: Storage::Resident(vec![0xFF]),
        size: 1,
        initialized: 1,
        allocated: 0,
    };
    bitmap(&stream, 8).unwrap();
    assert!(bitmap(&stream, 9).is_err());
    stream.initialized = 0;
    assert!(bitmap(&stream, 1).is_err());
    let cx = Cx::for_testing();
    let targets = targets();
    let records = [update(20, 24, b"changed!", b"original")];
    let plan = build(&cx, &targets, &records).unwrap();
    let mut input = Input::new();
    input.records.get_mut(&42).unwrap()[32..40].copy_from_slice(&((7_u64 << 48) | 6).to_le_bytes());
    assert!(matches!(
        execute(&cx, &mut input, &plan, &[], &targets),
        Err(FfsError::UnsupportedFeature(_))
    ));
}

/// A real protected journal page: checkpoint with an open-MFT attribute dump,
/// one update, and its commit. No parser or executor is used to encode it.
fn journal(lcn: u64) -> (super::super::super::Restart, Vec<u8>) {
    let first = 34_u64 * 4096;
    let at = [64_usize, 216, 328, 440];
    let lsns = at.map(|offset| (1_u64 << 20) | ((first + offset as u64) / 8));
    let mut dump = vec![0; 104];
    dump[..2].copy_from_slice(&0x1D_u16.to_le_bytes());
    dump[4..6].copy_from_slice(&40_u16.to_le_bytes());
    dump[6..8].copy_from_slice(&64_u16.to_le_bytes());
    dump[40..42].copy_from_slice(&40_u16.to_le_bytes());
    dump[42..44].copy_from_slice(&1_u16.to_le_bytes());
    dump[44..46].copy_from_slice(&1_u16.to_le_bytes());
    dump[64..68].copy_from_slice(&u32::MAX.to_le_bytes());
    dump[72..76].copy_from_slice(&DATA.to_le_bytes());
    dump[80..88].copy_from_slice(&REFERENCE.to_le_bytes());
    let mut checkpoint = vec![0; 64];
    checkpoint[..4].copy_from_slice(&1_u32.to_le_bytes());
    checkpoint[8..16].copy_from_slice(&lsns[1].to_le_bytes());
    checkpoint[16..24].copy_from_slice(&lsns[0].to_le_bytes());
    checkpoint[48..52].copy_from_slice(&64_u32.to_le_bytes());
    let mut change = update(lsns[2], 24, b"changed!", b"original").data;
    change[32..40].copy_from_slice(&lcn.to_le_bytes());
    change[40..48].copy_from_slice(&(lcn + 1).to_le_bytes());
    let mut commit = vec![0; 40];
    commit[..2].copy_from_slice(&0x1A_u16.to_le_bytes());
    let mut page = vec![0; 4096];
    page[..4].copy_from_slice(b"RCRD");
    page[4..6].copy_from_slice(&40_u16.to_le_bytes());
    page[6..8].copy_from_slice(&9_u16.to_le_bytes());
    page[8..16].copy_from_slice(&lsns[3].to_le_bytes());
    page[16..20].copy_from_slice(&1_u32.to_le_bytes());
    page[20..22].copy_from_slice(&1_u16.to_le_bytes());
    page[22..24].copy_from_slice(&1_u16.to_le_bytes());
    page[24..26].copy_from_slice(&528_u16.to_le_bytes());
    page[32..40].copy_from_slice(&lsns[3].to_le_bytes());
    for (index, payload) in [dump, checkpoint, change, commit].iter().enumerate() {
        let start = at[index];
        page[start..start + 8].copy_from_slice(&lsns[index].to_le_bytes());
        page[start + 24..start + 28]
            .copy_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
        page[start + 28..start + 30].copy_from_slice(&9_u16.to_le_bytes());
        page[start + 32..start + 36]
            .copy_from_slice(&(if index == 1 { 2_u32 } else { 1 }).to_le_bytes());
        page[start + 36..start + 40]
            .copy_from_slice(&(if index == 1 { 0_u32 } else { 24 }).to_le_bytes());
        if index == 3 {
            page[start + 8..start + 16].copy_from_slice(&lsns[2].to_le_bytes());
        }
        page[start + 48..start + 48 + payload.len()].copy_from_slice(payload);
    }
    let token = 0xCAFE_u16.to_le_bytes();
    page[40..42].copy_from_slice(&token);
    for sector in 1..=8 {
        let end = sector * 512;
        let saved = [page[end - 2], page[end - 1]];
        page[40 + sector * 2..42 + sector * 2].copy_from_slice(&saved);
        page[end - 2..end].copy_from_slice(&token);
    }
    (
        super::super::super::Restart {
            system_page: 4096,
            log_page: 4096,
            version: (2, 0),
            clean: false,
            current_lsn: lsns[3],
            seq_num_bits: 44,
            file_size: 4 * 1024 * 1024,
            last_lsn_data_len: 40,
            record_header_len: 48,
            data_off: 64,
            active_client_seq: Some(9),
            active_client_oldest_lsn: Some(lsns[0]),
            active_client_restart_lsn: Some(lsns[1]),
            area: Vec::new(),
        },
        page,
    )
}

#[test]
fn concrete_volume_adapter_uses_selected_bounds_fragmented_mft_and_native_bitmaps() {
    use ffs_block::ByteDevice;
    use ffs_ondisk::ntfs::{NtfsGeometry, NtfsRun};
    use ffs_types::ByteOffset;
    use reader::Source;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct Device {
        bytes: Vec<u8>,
        writes: Arc<AtomicUsize>,
    }
    impl ByteDevice for Device {
        fn len_bytes(&self) -> u64 {
            self.bytes.len() as u64
        }
        fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
            let at = usize::try_from(offset.0).map_err(|_| corrupt(0, "fixture offset"))?;
            let source = self
                .bytes
                .get(at..at + out.len())
                .ok_or_else(|| corrupt(0, "fixture bounds"))?;
            out.copy_from_slice(source);
            Ok(())
        }
        fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _data: &[u8]) -> Result<()> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Err(FfsError::ReadOnly)
        }
        fn sync(&self, _cx: &Cx) -> Result<()> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Err(FfsError::ReadOnly)
        }
    }
    let cx = Cx::for_testing();
    let base = 4096_usize;
    let length = 512_usize * 512;
    let mut bytes = vec![0xCC; base + length + 4096];
    let mut boot = [0; 512];
    boot[3..11].copy_from_slice(b"NTFS    ");
    boot[11..13].copy_from_slice(&512_u16.to_le_bytes());
    boot[13] = 1;
    boot[40..48].copy_from_slice(&512_u64.to_le_bytes());
    boot[48..56].copy_from_slice(&128_u64.to_le_bytes());
    boot[56..64].copy_from_slice(&8_u64.to_le_bytes());
    boot[64] = 246;
    boot[68] = 244;
    boot[510..512].copy_from_slice(&0xAA55_u16.to_le_bytes());
    let geometry = NtfsGeometry::parse(&boot, length as u64).unwrap();
    // Construct an immutable reader view with a backwards-fragmented native
    // MFT map. This is an adapter test, not mount/bootstrap qualification.
    for (number, kind, value) in [
        (0, 0xB0, &[0xFF; 8][..]),
        (6, DATA, &[0xFF; 64][..]),
        (42, DATA, &b"original"[..]),
    ] {
        let vcn = number * 2;
        let lcn = if vcn < 64 { 128 + vcn } else { 32 + vcn - 64 };
        let at = base + lcn as usize * 512;
        bytes[at..at + 1024].copy_from_slice(&file(number, kind, value));
    }
    let writes = Arc::new(AtomicUsize::new(0));
    let volume = NtfsVolume {
        source: Source {
            device: Box::new(Device {
                bytes,
                writes: Arc::clone(&writes),
            }),
            base: base as u64,
            length: length as u64,
            overlay: std::collections::BTreeMap::new(),
        },
        geometry,
        mft: Stream {
            storage: Storage::Mapped(vec![
                NtfsRun {
                    vcn: 0,
                    clusters: 64,
                    lcn: Some(128),
                },
                NtfsRun {
                    vcn: 64,
                    clusters: 64,
                    lcn: Some(32),
                },
            ]),
            size: 64 * 1024,
            initialized: 64 * 1024,
            allocated: 64 * 1024,
        },
        volume_flags: 0,
        logfile_recovery: None,
    };
    let mut targets = targets();
    targets.clusters.get_mut(&(24, 84)).unwrap().lcn = Some(52);
    targets.clusters.get_mut(&(24, 85)).unwrap().lcn = Some(53);
    let records = [update(20, 24, b"changed!", b"original")];
    let plan = build(&cx, &targets, &records).unwrap();
    let mut input = VolumeInput::new(&cx, &volume, 100).unwrap();
    let staged = execute(&cx, &mut input, &plan, &[], &targets).unwrap();
    assert_eq!(value(&staged.records[&42]), b"changed!");
    assert_eq!(value(&input.read_record(&cx, 42).unwrap()), b"original");
    // Exercise the production journal -> checkpoint -> Analysis -> redo/undo
    // -> native volume stage. A bad logged LCN passes journal-only inspection
    // but must fail when the actual MFT map is present, proving this is wired.
    for lcn in [52, 62] {
        let (restart, page) = journal(lcn);
        let mut read = |offset, size| {
            assert_eq!((offset, size), (34 * 4096, 4096));
            Ok(page.clone())
        };
        super::super::super::super::validate_dirty_volume(
            &cx,
            &restart,
            restart.file_size,
            &mut read,
            None,
        )
        .unwrap();
        let result = super::super::super::super::validate_dirty_volume(
            &cx,
            &restart,
            restart.file_size,
            &mut read,
            Some(&volume),
        );
        if lcn == 52 {
            result.unwrap();
        } else {
            assert!(matches!(result, Err(FfsError::Corruption { .. })));
        }
    }
    assert_eq!(value(&input.read_record(&cx, 42).unwrap()), b"original");
    assert_eq!(writes.load(Ordering::SeqCst), 0);
}
