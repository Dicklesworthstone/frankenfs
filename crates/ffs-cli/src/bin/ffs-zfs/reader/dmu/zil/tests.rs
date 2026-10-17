//! Constructed native log blocks, not a kernel/OpenZFS interchange claim.
use super::super::super::{Leaf, Pool};
use super::storage::read_block;
use super::*;
use ffs_block::ByteDevice;
use ffs_ondisk::zfs::DATA_OFFSET;
use ffs_types::ByteOffset;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

mod indirect;
mod range_free;
mod topology;

const BASE: u64 = 4096;
const LENGTH: u64 = 64 * 1024 * 1024;
const FIRST: u64 = 0x10000;
const SECOND: u64 = 0x20000;
type Reads = Arc<Mutex<Vec<(u64, usize)>>>;

fn selection(txg: u64) -> Selection {
    Selection {
        dataset: 3,
        guid: 987,
        txg,
    }
}

struct Memory {
    blocks: BTreeMap<u64, Vec<u8>>,
    reads: Reads,
    cancelled_at: Option<u64>,
}
impl ByteDevice for Memory {
    fn len_bytes(&self) -> u64 {
        BASE + LENGTH + 4096
    }
    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        self.reads.lock().unwrap().push((offset.0, out.len()));
        if self.cancelled_at == Some(offset.0) {
            return Err(FfsError::Cancelled);
        }
        let bytes = self
            .blocks
            .get(&offset.0)
            .filter(|bytes| bytes.len() == out.len())
            .ok_or_else(|| FfsError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)))?;
        out.copy_from_slice(bytes);
        Ok(())
    }
    fn write_all_at(&self, _: &Cx, _: ByteOffset, _: &[u8]) -> Result<()> {
        panic!("ZIL inspection/recovery wrote backing storage")
    }
    fn sync(&self, _: &Cx) -> Result<()> {
        panic!("ZIL inspection/recovery flushed backing storage")
    }
}
fn config() -> VdevConfig {
    VdevConfig {
        pool_guid: 123,
        top_guid: 999,
        version: 5000,
        txg: 40,
        ashift: 9,
        id: 0,
        allocated_bytes: LENGTH - DATA_OFFSET - 2 * ffs_ondisk::zfs::LABEL_BYTES,
        read_features: Vec::new(),
        raidz_members: None,
    }
}
fn leaf(blocks: &[(u64, Vec<u8>)], cancelled_at: Option<u64>) -> (Pool, Reads) {
    let reads = Arc::default();
    let device = Memory {
        blocks: blocks
            .iter()
            .map(|(at, bytes)| (BASE + DATA_OFFSET + at, bytes.clone()))
            .collect(),
        reads: Arc::clone(&reads),
        cancelled_at,
    };
    let leaf = Leaf::from_device(&Cx::for_testing(), Box::new(device), BASE, LENGTH).unwrap();
    (leaf.into(), reads)
}
fn put(raw: &mut [u8], at: usize, value: u64, order: Endian) {
    raw[at..at + 8].copy_from_slice(&order.encode(value));
}
fn pointer(
    offset: u64,
    sequence: u64,
    algorithm: u8,
    bytes: usize,
    order: Endian,
    payload: Endian,
) -> Vec<u8> {
    let mut raw = vec![0; 128];
    let sectors = bytes as u64 / 512;
    put(&mut raw, 0, sectors, order);
    put(&mut raw, 8, offset / 512, order);
    put(
        &mut raw,
        48,
        (sectors - 1)
            | ((sectors - 1) << 16)
            | (2 << 32)
            | (u64::from(algorithm) << 40)
            | (9 << 48)
            | (u64::from(payload == Endian::Little) << 63),
        order,
    );
    put(&mut raw, 80, 40, order);
    for (index, value) in [11, 22, 3, sequence].into_iter().enumerate() {
        put(&mut raw, 96 + index * 8, value, order);
    }
    raw
}
fn header(pointer: &[u8], _order: Endian) -> Vec<u8> {
    let mut raw = vec![0; 192];
    raw[16..144].copy_from_slice(pointer);
    raw
}
fn record(kind: u64, txg: u64, seq: u64, offset: u64, data: &[u8], order: Endian) -> Vec<u8> {
    let size = if kind == 9 {
        (192 + data.len()).div_ceil(8) * 8
    } else {
        56
    };
    let mut raw = vec![0; size];
    for (at, value) in [
        (0, kind),
        (8, size as u64),
        (16, txg),
        (24, seq),
        (32, 7),
        (40, offset),
        (48, data.len() as u64),
    ] {
        put(&mut raw, at, value, order);
    }
    if kind == 9 {
        raw[192..192 + data.len()].copy_from_slice(data);
    }
    raw
}
fn seal(raw: &mut [u8], pointer: &Pointer) {
    let order = pointer.bp.payload_order();
    let modern = pointer.bp.checksum_type() == 9;
    let chain = if modern { 0 } else { raw.len() - CHAIN_BYTES };
    let covered = if modern {
        word(raw, 136, order).unwrap().div_ceil(4096) as usize * 4096
    } else {
        raw.len()
    };
    put(raw, chain + 144, ECK_MAGIC, order);
    for (index, value) in pointer.identity.into_iter().enumerate() {
        put(raw, chain + 152 + index * 8, value, order);
    }
    let sum = checksum(&raw[..covered], if modern { 7 } else { 6 }, order).unwrap();
    for (index, value) in sum.into_iter().enumerate() {
        put(raw, chain + 152 + index * 8, value, order);
    }
}
fn block(pointer_raw: &[u8], containing: Endian, next: &[u8], records: &[Vec<u8>]) -> Vec<u8> {
    let pointer = Pointer::parse(pointer_raw, containing, 3).unwrap().unwrap();
    let order = pointer.bp.payload_order();
    let modern = pointer.bp.checksum_type() == 9;
    let mut raw = vec![0; pointer.bp.physical_bytes()];
    let chain = if modern { 0 } else { raw.len() - CHAIN_BYTES };
    let used = records.iter().map(Vec::len).sum::<usize>();
    raw[chain + 8..chain + 136].copy_from_slice(next);
    put(
        &mut raw,
        chain + 136,
        (used + if modern { CHAIN_BYTES } else { 0 }) as u64,
        order,
    );
    let mut at = if modern { CHAIN_BYTES } else { 0 };
    for record in records {
        raw[at..at + record.len()].copy_from_slice(record);
        at += record.len();
    }
    seal(&mut raw, &pointer);
    raw
}

#[test]
fn native_log_variants_keep_byte_orders_and_distinguish_committed_records_from_prefix_tail() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        let other = if order == Endian::Little {
            Endian::Big
        } else {
            Endian::Little
        };
        for algorithm in [5, 9] {
            let first = pointer(FIRST, 1, algorithm, 4096, order, other);
            let next = pointer(SECOND, 2, algorithm, 4096, other, order);
            let raw = block(
                &first,
                order,
                &next,
                &[
                    record(9, 41, 1, 0, b"old", other),
                    record(9, 43, 2, 3, b"new\0bytes", other),
                    record(10, 43, 3, 8, &[], other),
                ],
            );
            let (leaf, reads) = leaf(&[(FIRST, raw), (SECOND, vec![0; 4096])], None);
            let log = scan(
                &cx,
                &leaf,
                &config(),
                &header(&first, order),
                order,
                selection(42),
            )
            .unwrap();
            assert_eq!(log.termination, Termination::UnverifiedTail);
            assert_eq!((log.verified_blocks, log.physical_work_bytes), (1, 8192));
            assert_eq!(
                log.records
                    .iter()
                    .map(|r| (r.sequence, r.pending))
                    .collect::<Vec<_>>(),
                [(1, false), (2, true), (3, true)]
            );
            assert_eq!(&log.records[1].raw[192..201], b"new\0bytes");
            assert_eq!(
                *reads.lock().unwrap(),
                [
                    (BASE + DATA_OFFSET + FIRST, 4096),
                    (BASE + DATA_OFFSET + SECOND, 4096)
                ]
            );
        }
    }
}

#[test]
fn claimed_boundaries_stop_before_unwritten_next_block_and_filter_replayed_intent() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        let first = pointer(FIRST, 1, 9, 4096, order, order);
        let next = pointer(SECOND, 2, 9, 4096, order, order);
        let raw = block(
            &first,
            order,
            &next,
            &[
                record(9, 42, 1, 0, b"committed", order),
                record(9, 43, 2, 0, b"replayed", order),
                record(9, 43, 3, 0, b"pending", order),
            ],
        );
        let (leaf, reads) = leaf(&[(FIRST, raw)], None);
        let mut hdr = header(&first, order);
        for (at, value) in [(0, 43), (8, 2), (144, 2), (152, 3), (160, 3)] {
            put(&mut hdr, at, value, order);
        }
        let log = scan(&cx, &leaf, &config(), &hdr, order, selection(44)).unwrap();
        assert_eq!(log.termination, Termination::ClaimedBoundary);
        assert_eq!(
            log.records.iter().map(|r| r.pending).collect::<Vec<_>>(),
            [false, false, true]
        );
        assert_eq!(*reads.lock().unwrap(), [(BASE + DATA_OFFSET + FIRST, 4096)]);
        put(&mut hdr, 160, 4, order);
        assert!(scan(&cx, &leaf, &config(), &hdr, order, selection(44)).is_err());
    }
}

#[test]
fn checksummed_bad_chain_links_and_record_spans_fail_without_partial_success() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for case in 0..6 {
            let first = pointer(FIRST, 1, 9, 4096, order, order);
            let mut next = pointer(SECOND, 2, 9, 4096, order, order);
            let mut record = record(9, 43, 1, 0, b"payload", order);
            match case {
                0 => put(&mut next, 96, 12, order),
                1 => put(&mut next, 112, 99, order),
                2 => put(&mut next, 120, 3, order),
                3 => put(&mut record, 8, 16, order),
                4 => put(&mut record, 8, 199, order),
                _ => put(&mut record, 24, 0, order),
            }
            let raw = block(&first, order, &next, &[record]);
            let (leaf, _) = leaf(&[(FIRST, raw)], None);
            assert!(
                matches!(
                    scan(
                        &cx,
                        &leaf,
                        &config(),
                        &header(&first, order),
                        order,
                        selection(42)
                    ),
                    Err(FfsError::Corruption { .. })
                ),
                "case {case}"
            );
        }
    }
}

#[test]
fn io_and_cancellation_are_not_checksum_tail_termination() {
    let cx = Cx::for_testing();
    let order = Endian::Little;
    let first = pointer(FIRST, 1, 9, 4096, order, order);
    let hdr = header(&first, order);
    let (missing, _) = leaf(&[], None);
    assert!(matches!(
        scan(&cx, &missing, &config(), &hdr, order, selection(42)),
        Err(FfsError::Io(_))
    ));
    let (cancelled, reads) = leaf(&[], Some(BASE + DATA_OFFSET + FIRST));
    assert!(matches!(
        scan(&cx, &cancelled, &config(), &hdr, order, selection(42)),
        Err(FfsError::Cancelled)
    ));
    assert_eq!(reads.lock().unwrap().len(), 1);
    let (unwritten, _) = leaf(&[(FIRST, vec![0; 4096])], None);
    assert_eq!(
        scan(&cx, &unwritten, &config(), &hdr, order, selection(42))
            .unwrap()
            .termination,
        Termination::UnverifiedTail
    );
    let mut claimed = hdr;
    for (at, value) in [(0, 43), (144, 1), (152, 3), (160, 1)] {
        put(&mut claimed, at, value, order);
    }
    assert!(matches!(
        scan(&cx, &unwritten, &config(), &claimed, order, selection(44)),
        Err(FfsError::Corruption { .. })
    ));
}

#[test]
fn replica_bounds_cycles_and_work_limits_are_checked_before_io() {
    let cx = Cx::for_testing();
    let order = Endian::Little;
    let mut first = pointer(FIRST, 1, 9, 4096, order, order);
    put(&mut first, 16, 8 | (1 << 32), order); // Later replica on foreign vdev.
    put(&mut first, 24, SECOND / 512, order);
    let ptr = Pointer::parse(&first, order, 3).unwrap().unwrap();
    let (leaf, reads) = leaf(&[], None);
    assert!(read_block(&cx, &leaf, &config(), &ptr, &mut ReadState::default()).is_err());
    assert!(reads.lock().unwrap().is_empty());
    first[16..32].fill(0);
    let ptr = Pointer::parse(&first, order, 3).unwrap().unwrap();
    let mut exhausted = ReadState::default();
    exhausted.physical_bytes = MAX_LOG_BYTES - 4095;
    assert!(matches!(
        read_block(&cx, &leaf, &config(), &ptr, &mut exhausted),
        Err(FfsError::UnsupportedFeature(_))
    ));
    assert!(reads.lock().unwrap().is_empty());
    let next = pointer(FIRST, 2, 9, 4096, order, order);
    let raw = block(
        &first,
        order,
        &next,
        &[record(9, 43, 1, 0, b"valid", order)],
    );
    let (cyclic, reads) = self::leaf(&[(FIRST, raw)], None);
    assert!(matches!(
        scan(
            &cx,
            &cyclic,
            &config(),
            &header(&first, order),
            order,
            selection(42)
        ),
        Err(FfsError::Corruption { .. })
    ));
    assert_eq!(reads.lock().unwrap().len(), 1);
}

#[test]
fn zilog2_verifies_rounded_used_prefix_not_unwritten_allocation_tail() {
    let order = Endian::Little;
    let first = pointer(FIRST, 1, 9, 8192, order, order);
    let next = pointer(SECOND, 2, 9, 4096, order, order);
    let mut raw = block(
        &first,
        order,
        &next,
        &[record(9, 43, 1, 0, b"valid", order)],
    );
    let ptr = Pointer::parse(&first, order, 3).unwrap().unwrap();
    assert!(ptr.checksum_valid(&raw).unwrap());
    raw[7000] ^= 1;
    assert!(ptr.checksum_valid(&raw).unwrap());
    raw[4095] ^= 1;
    assert!(!ptr.checksum_valid(&raw).unwrap());
}

#[test]
fn recovery_rejects_unsupported_pending_intent_and_invalid_copied_lengths() {
    let order = Endian::Little;
    for (kind, offset, data) in [
        (1, 0, b"".as_slice()),
        (20, 0, b""),
        (10, i64::MAX as u64, b"range"),
        (9, u64::MAX, b"bad"),
    ] {
        let raw = record(kind, 43, 1, offset, data, order);
        let r = IntentRecord {
            kind,
            txg: 43,
            sequence: 1,
            record_bytes: raw.len(),
            pending: true,
            order,
            raw,
        };
        assert!(edit(&r).is_err());
    }
    let mut raw = record(9, 43, 1, 0, b"small", order);
    put(&mut raw, 48, 1000, order);
    let r = IntentRecord {
        kind: 9,
        txg: 43,
        sequence: 1,
        record_bytes: raw.len(),
        pending: true,
        order,
        raw,
    };
    assert!(matches!(edit(&r), Err(FfsError::Corruption { .. })));
}

#[test]
fn recovered_ranges_match_full_file_model_after_overwrites_shrink_regrowth_and_sparse_extension() {
    let cx = Cx::for_testing();
    for pattern in 0_usize..256 {
        let mut edits = Vec::new();
        let mut oracle = b"abcdefghijklmnop".to_vec();
        for shift in [0, 2, 4, 6] {
            let edit = match (pattern >> shift) & 3 {
                0 => Edit::Truncate { object: 7, size: 3 },
                1 => Edit::Truncate {
                    object: 7,
                    size: 24,
                },
                2 => Edit::Write {
                    object: 7,
                    offset: 7,
                    data: b"XY\0Z",
                },
                _ => Edit::Write {
                    object: 7,
                    offset: 1,
                    data: b"changed",
                },
            };
            match &edit {
                Edit::Truncate { size, .. } => oracle.resize(*size as usize, 0),
                Edit::Free { offset, end, .. } => {
                    oracle.resize(oracle.len().max(*end as usize), 0);
                    oracle[*offset as usize..*end as usize].fill(0);
                }
                Edit::Write { offset, data, .. } => {
                    oracle.resize(oracle.len().max(*offset as usize + data.len()), 0);
                    oracle[*offset as usize..*offset as usize + data.len()].copy_from_slice(data);
                }
            }
            edits.push(edit);
        }
        assert_eq!(
            edits.iter().fold(16, |size, edit| edit.size_after(size)),
            oracle.len() as u64
        );
        for start in 0..=28 {
            for count in [0, 1, 3, 9, 32] {
                let length = oracle.len().saturating_sub(start).min(count);
                let mut bytes = vec![0; length];
                for (index, byte) in bytes.iter_mut().enumerate() {
                    if let Some(old) = b"abcdefghijklmnop".get(start + index) {
                        *byte = *old;
                    }
                }
                apply(&cx, &mut bytes, start as u64, 16, &edits).unwrap();
                let expected = if start >= oracle.len() {
                    &[]
                } else {
                    &oracle[start..start + length]
                };
                assert_eq!(
                    bytes, expected,
                    "pattern={pattern} start={start} count={count}"
                );
            }
        }
    }
}

fn data_pointer(bytes: &[u8], offset: u64, kind: u8, birth: u64) -> Vec<u8> {
    let order = Endian::Little;
    let mut raw = pointer(offset, 0, 7, bytes.len(), order, order);
    let property = word(&raw, 48, order).unwrap();
    put(
        &mut raw,
        48,
        (property & !(0xff << 48)) | (u64::from(kind) << 48),
        order,
    );
    put(&mut raw, 80, birth, order);
    for (index, value) in checksum(bytes, 7, order).unwrap().into_iter().enumerate() {
        put(&mut raw, 96 + index * 8, value, order);
    }
    raw
}

fn dnode(kind: u8, size: usize, pointer: &[u8], bonus_type: u8, bonus: &[u8]) -> Vec<u8> {
    let mut raw = vec![0; 512];
    raw[0] = kind;
    raw[1] = 12;
    raw[2] = 1;
    raw[3] = 1;
    raw[4] = bonus_type;
    raw[7] = 1;
    raw[8..10].copy_from_slice(&((size / 512) as u16).to_le_bytes());
    raw[10..12].copy_from_slice(&(bonus.len() as u16).to_le_bytes());
    raw[64..192].copy_from_slice(pointer);
    raw[192..192 + bonus.len()].copy_from_slice(bonus);
    raw
}

fn micro(name: &[u8], value: u64) -> Vec<u8> {
    let mut bytes = vec![0; 512];
    put(&mut bytes, 0, (1_u64 << 63) + 3, Endian::Little);
    put(&mut bytes, 64, value, Endian::Little);
    bytes[78..78 + name.len()].copy_from_slice(name);
    bytes
}

fn file_metadata(directory: bool, size: u64) -> Vec<u8> {
    let mut raw = vec![0; 264];
    for (at, value) in [
        (64, 2),
        (72, ((if directory { 4 } else { 8 }) << 12) | 0o644),
        (80, size),
        (88, 2),
        (96, if directory { 2 } else { 1 }),
    ] {
        put(&mut raw, at, value, Endian::Little);
    }
    raw
}

/// Real Objects -> checked MOS -> DSL -> object set -> ZPL -> file recovery,
/// backed by constructed blocks, with no private field override of ZPL state.
fn recovery_graph(unsupported_namespace: bool) -> (Objects, Reads) {
    use ffs_ondisk::zfs_dmu::Dnode;
    let order = Endian::Little;
    let first = pointer(FIRST, 1, 9, 4096, order, order);
    let next = pointer(SECOND, 2, 9, 4096, order, order);
    let mut records = vec![
        record(9, 43, 1, 2, b"NEW", order),
        record(10, 43, 2, 8, &[], order),
        record(9, 43, 3, 12, b"!", order),
    ];
    if unsupported_namespace {
        records.push(record(1, 43, 4, 0, &[], order));
    }
    let log = block(&first, order, &next, &records);
    let mut file = vec![0; 512];
    file[..16].copy_from_slice(b"abcdefghijklmnop");
    let mut master = micro(b"ROOT", 2);
    put(&mut master, 128, 4, order);
    master[142..149].copy_from_slice(b"VERSION");
    let directory = micro(b"file", (8_u64 << 60) | 7);
    let mut table = vec![0; 16384];
    table[512..1024].copy_from_slice(&dnode(
        21,
        512,
        &data_pointer(&master, 0x4c000, 21, 37),
        0,
        &[],
    ));
    table[1024..1536].copy_from_slice(&dnode(
        20,
        512,
        &data_pointer(&directory, 0x4c200, 20, 37),
        17,
        &file_metadata(true, 3),
    ));
    table[7 * 512..8 * 512].copy_from_slice(&dnode(
        19,
        512,
        &data_pointer(&file, 0x4c400, 19, 37),
        17,
        &file_metadata(false, 16),
    ));
    let mut os = vec![0; 1024];
    os[..512].copy_from_slice(&dnode(
        10,
        16384,
        &data_pointer(&table, 0x48000, 10, 38),
        0,
        &[],
    ));
    os[512..704].copy_from_slice(&header(&first, order));
    put(&mut os, 704, 2, order);
    let pool_directory = micro(b"root_dataset", 2);
    let mut directory_bonus = vec![0; 256];
    put(&mut directory_bonus, 8, 3, order);
    let mut dataset_bonus = vec![0; 320];
    for (at, value) in [(0, 2), (56, 5), (72, 16384), (112, 987), (120, 4)] {
        put(&mut dataset_bonus, at, value, order);
    }
    dataset_bonus[128..256].copy_from_slice(&data_pointer(&os, 0x45000, 11, 39));
    let mut mos = vec![0; 16384];
    mos[512..1024].copy_from_slice(&dnode(
        1,
        512,
        &data_pointer(&pool_directory, 0x44000, 1, 39),
        0,
        &[],
    ));
    mos[1024..1536].copy_from_slice(&dnode(12, 512, &[0; 128], 12, &directory_bonus));
    mos[1536..2048].copy_from_slice(&dnode(16, 512, &[0; 128], 16, &dataset_bonus));
    let meta = dnode(10, 16384, &data_pointer(&mos, 0x40000, 10, 40), 0, &[]);
    let (leaf, reads) = leaf(
        &[
            (FIRST, log),
            (SECOND, vec![0; 4096]),
            (0x40000, mos),
            (0x44000, pool_directory),
            (0x45000, os),
            (0x48000, table),
            (0x4c000, master),
            (0x4c200, directory),
            (0x4c400, file),
        ],
        None,
    );
    let objects = Objects {
        pool: leaf,
        config: config(),
        txg: 42,
        root_birth: 42,
        meta: Dnode::parse(&meta, order).unwrap(),
        cache: std::collections::VecDeque::new(),
        cached_bytes: 0,
    };
    (objects, reads)
}

#[test]
fn existing_file_recovery_is_wired_through_native_mos_zpl_and_explicit_prefix_authorization() {
    let cx = Cx::for_testing();
    let (mut objects, reads) = recovery_graph(false);
    let error = objects
        .read_with_intent_log(&cx, &[], b"/file", 0, 100, false)
        .err()
        .unwrap();
    assert!(matches!(error, FfsError::UnsupportedFeature(_)));
    assert!(error.to_string().contains("prefix-recovery authorization"));
    assert!(
        !reads
            .lock()
            .unwrap()
            .iter()
            .any(|(at, _)| *at == BASE + DATA_OFFSET + 0x4c400)
    );
    let recovered = objects
        .read_with_intent_log(&cx, &[], b"/file", 0, 100, true)
        .unwrap();
    assert_eq!(recovered.bytes, b"abNEWfgh\0\0\0\0!");
    assert_eq!((recovered.file_size, recovered.applied_records), (13, 3));
    assert_eq!(recovered.log.termination, Termination::UnverifiedTail);
    let part = objects
        .read_with_intent_log(&cx, &[], b"/file", 4, 7, true)
        .unwrap();
    assert_eq!(part.bytes, &recovered.bytes[4..11]);
    let eof = objects
        .read_with_intent_log(&cx, &[], b"/file", 13, 1, true)
        .unwrap();
    assert_eq!(eof.bytes, [] as [u8; 0]);
    // Ordinary readers still see the selected committed root; recovery did not
    // poison a DMU cache, change ZPL metadata, or mutate the backing device.
    let mut committed = objects.zpl(&cx, &[]).unwrap();
    let number = committed.resolve(&cx, b"/file").unwrap();
    assert_eq!(
        committed.read(&cx, number, 0, 100).unwrap(),
        b"abcdefghijklmnop"
    );
    assert_eq!(committed.stat(&cx, number).unwrap().0.size, 16);
    assert!(
        reads.lock().unwrap().iter().all(|(at, count)| {
            *at >= BASE + DATA_OFFSET && *at + *count as u64 <= BASE + LENGTH
        })
    );
}

#[test]
fn pending_namespace_blocks_file_recovery_before_loading_payload_and_work_is_bounded() {
    let cx = Cx::for_testing();
    let (mut objects, reads) = recovery_graph(true);
    let error = objects
        .read_with_intent_log(&cx, &[], b"/file", 0, 100, true)
        .err()
        .unwrap();
    assert!(matches!(error, FfsError::UnsupportedFeature(_)));
    assert!(error.to_string().contains("pending namespace"));
    assert!(
        !reads
            .lock()
            .unwrap()
            .iter()
            .any(|(at, _)| *at == BASE + DATA_OFFSET + 0x4c400)
    );
    let mut work = MAX_RECOVERY_WORK_BYTES;
    charge_recovery(&mut work, MAX_RECOVERY_WORK_BYTES).unwrap();
    assert_eq!(work, 0);
    assert!(matches!(
        charge_recovery(&mut work, 1),
        Err(FfsError::UnsupportedFeature(_))
    ));
    assert_eq!(work, 0);
}

#[test]
fn native_embedded_checksums_match_independent_closed_form_fletcher_vectors() {
    // Values computed independently with Python's integer sums and binomial
    // coefficients, not with the sequential ffs-ondisk checksum implementation.
    // This is a fixed layout/checksum vector, not a native pool capture.
    for (algorithm, order, expected) in [
        (
            5,
            Endian::Little,
            [
                9_225_911_249_059_144_401_u64,
                148_859_008_194_477_065,
                20_415_476_278_831_204,
                446_577_024_583_484_117,
            ],
        ),
        (
            5,
            Endian::Big,
            [
                8_532_757_150_060_446_043,
                148_859_008_194_477_065,
                15_358_256_057_691_948_012,
                446_577_024_583_484_117,
            ],
        ),
        (
            9,
            Endian::Little,
            [
                6_922_290_034,
                6_781_722_369_370,
                3_328_605_371_134_847,
                1_091_294_087_630_784_666,
            ],
        ),
        (
            9,
            Endian::Big,
            [
                6_669_913_601,
                6_372_747_763_356,
                3_050_325_511_120_534,
                975_252_070_626_246_001,
            ],
        ),
    ] {
        let first = pointer(FIRST, 1, algorithm, 4096, order, order);
        let next = pointer(SECOND, 2, algorithm, 4096, order, order);
        let raw = block(
            &first,
            order,
            &next,
            &[record(9, 43, 1, 0, b"valid", order)],
        );
        let at = if algorithm == 9 { 152 } else { 4096 - 32 };
        let actual: [u64; 4] =
            std::array::from_fn(|index| word(&raw, at + index * 8, order).unwrap());
        assert_eq!(actual, expected);
        assert!(
            Pointer::parse(&first, order, 3)
                .unwrap()
                .unwrap()
                .checksum_valid(&raw)
                .unwrap()
        );
    }
}
