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
type Faults = Arc<Mutex<BTreeMap<u64, Fault>>>;

enum Fault {
    Checksum,
    Io,
    Cancelled,
    Replacement(Vec<u8>),
}

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
    faults: Faults,
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
        if let Some(fault) = self.faults.lock().unwrap().get(&offset.0) {
            match fault {
                Fault::Checksum => out[0] ^= 1,
                Fault::Io => {
                    return Err(FfsError::Io(std::io::Error::from(
                        std::io::ErrorKind::UnexpectedEof,
                    )));
                }
                Fault::Cancelled => return Err(FfsError::Cancelled),
                Fault::Replacement(replacement) => {
                    assert_eq!(replacement.len(), out.len());
                    out.copy_from_slice(replacement);
                }
            }
        }
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
    leaf_with_faults(blocks, cancelled_at, Arc::default())
}

fn leaf_with_faults(
    blocks: &[(u64, Vec<u8>)],
    cancelled_at: Option<u64>,
    faults: Faults,
) -> (Pool, Reads) {
    let reads = Arc::default();
    let device = Memory {
        blocks: blocks
            .iter()
            .map(|(at, bytes)| (BASE + DATA_OFFSET + at, bytes.clone()))
            .collect(),
        reads: Arc::clone(&reads),
        cancelled_at,
        faults,
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
                Edit::Indirect {
                    offset, data, end, ..
                } => {
                    let visible = oracle.len().max(*end as usize);
                    oracle.resize(oracle.len().max(*offset as usize + data.len()), 0);
                    oracle[*offset as usize..*offset as usize + data.len()].copy_from_slice(data);
                    oracle.truncate(visible);
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

fn data_pointer(bytes: &[u8], offset: u64, kind: u8, birth: u64, order: Endian) -> Vec<u8> {
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

fn dnode(
    kind: u8,
    size: usize,
    pointer: &[u8],
    bonus_type: u8,
    bonus: &[u8],
    order: Endian,
) -> Vec<u8> {
    let mut raw = vec![0; 512];
    raw[0] = kind;
    raw[1] = 12;
    raw[2] = 1;
    raw[3] = 1;
    raw[4] = bonus_type;
    raw[7] = 1;
    let encoded_size = match order {
        Endian::Little => ((size / 512) as u16).to_le_bytes(),
        Endian::Big => ((size / 512) as u16).to_be_bytes(),
    };
    let encoded_bonus = match order {
        Endian::Little => (bonus.len() as u16).to_le_bytes(),
        Endian::Big => (bonus.len() as u16).to_be_bytes(),
    };
    raw[8..10].copy_from_slice(&encoded_size);
    raw[10..12].copy_from_slice(&encoded_bonus);
    raw[64..192].copy_from_slice(pointer);
    raw[192..192 + bonus.len()].copy_from_slice(bonus);
    raw
}

fn micro(name: &[u8], value: u64, order: Endian) -> Vec<u8> {
    let mut bytes = vec![0; 512];
    put(&mut bytes, 0, (1_u64 << 63) + 3, order);
    put(&mut bytes, 64, value, order);
    bytes[78..78 + name.len()].copy_from_slice(name);
    bytes
}

fn file_metadata(directory: bool, size: u64, order: Endian) -> Vec<u8> {
    let mut raw = vec![0; 264];
    for (at, value) in [
        (64, 2),
        (72, ((if directory { 4 } else { 8 }) << 12) | 0o644),
        (80, size),
        (88, 2),
        (96, if directory { 2 } else { 1 }),
    ] {
        put(&mut raw, at, value, order);
    }
    raw
}

/// Real Objects -> checked MOS -> DSL -> object set -> ZPL -> file recovery,
/// backed by constructed blocks, with no private field override of ZPL state.
fn recovery_graph(unsupported_namespace: bool) -> (Objects, Reads) {
    let order = Endian::Little;
    let mut records = vec![
        record(9, 43, 1, 2, b"NEW", order),
        record(10, 43, 2, 8, &[], order),
        record(9, 43, 3, 12, b"!", order),
    ];
    if unsupported_namespace {
        records.push(record(1, 43, 4, 0, &[], order));
    }
    let (objects, reads, _) = recovery_graph_log(order, 9, &records, false, None, &[]);
    (objects, reads)
}

fn recovery_graph_log(
    order: Endian,
    algorithm: u8,
    records: &[Vec<u8>],
    claimed: bool,
    cancelled_at: Option<u64>,
    extra: &[(u64, Vec<u8>)],
) -> (Objects, Reads, Faults) {
    use ffs_ondisk::zfs_dmu::Dnode;
    let first = pointer(FIRST, 1, algorithm, 4096, order, order);
    let next = pointer(SECOND, 2, algorithm, 4096, order, order);
    let tail = pointer(0x30000, 3, algorithm, 4096, order, order);
    let split = if claimed {
        records.len() / 2
    } else {
        records.len()
    };
    let log = block(&first, order, &next, &records[..split]);
    let mut file = vec![0; 512];
    file[..16].copy_from_slice(b"abcdefghijklmnop");
    let mut master = micro(b"ROOT", 2, order);
    put(&mut master, 128, 4, order);
    master[142..149].copy_from_slice(b"VERSION");
    let mut directory = micro(b"file", (8_u64 << 60) | 7, order);
    put(&mut directory, 128, (8_u64 << 60) | 7, order);
    directory[142..147].copy_from_slice(b"alias");
    let mut base_file_metadata = file_metadata(false, 16, order);
    put(&mut base_file_metadata, 96, 2, order);
    let mut table = vec![0; 16384];
    table[512..1024].copy_from_slice(&dnode(
        21,
        512,
        &data_pointer(&master, 0x4c000, 21, 37, order),
        0,
        &[],
        order,
    ));
    table[1024..1536].copy_from_slice(&dnode(
        20,
        512,
        &data_pointer(&directory, 0x4c200, 20, 37, order),
        17,
        &file_metadata(true, 4, order),
        order,
    ));
    table[7 * 512..8 * 512].copy_from_slice(&dnode(
        19,
        512,
        &data_pointer(&file, 0x4c400, 19, 37, order),
        17,
        &base_file_metadata,
        order,
    ));
    let mut os = vec![0; 1024];
    os[..512].copy_from_slice(&dnode(
        10,
        16384,
        &data_pointer(&table, 0x48000, 10, 38, order),
        0,
        &[],
        order,
    ));
    os[512..704].copy_from_slice(&header(&first, order));
    if claimed {
        // A persisted claim at TXG42 follows previously synced TXG41. Claim
        // includes the allocated terminal pointer even though its LWB is not
        // readable; native parse remembers max block before attempting I/O.
        for (at, value) in [
            (512, 42),
            (656, 3),
            (664, 3),
            (
                672,
                records
                    .last()
                    .map_or(0, |row| word(row, 24, order).unwrap()),
            ),
        ] {
            put(&mut os, at, value, order);
        }
    }
    put(&mut os, 704, 2, order);
    let pool_directory = micro(b"root_dataset", 2, order);
    let mut directory_bonus = vec![0; 256];
    put(&mut directory_bonus, 8, 3, order);
    let mut dataset_bonus = vec![0; 320];
    for (at, value) in [(0, 2), (56, 5), (72, 16384), (112, 987), (120, 4)] {
        put(&mut dataset_bonus, at, value, order);
    }
    dataset_bonus[128..256].copy_from_slice(&data_pointer(
        &os,
        0x45000,
        11,
        if claimed { 42 } else { 39 },
        order,
    ));
    let mut mos = vec![0; 16384];
    mos[512..1024].copy_from_slice(&dnode(
        1,
        512,
        &data_pointer(&pool_directory, 0x44000, 1, 39, order),
        0,
        &[],
        order,
    ));
    mos[1024..1536].copy_from_slice(&dnode(12, 512, &[0; 128], 12, &directory_bonus, order));
    mos[1536..2048].copy_from_slice(&dnode(16, 512, &[0; 128], 16, &dataset_bonus, order));
    let meta = dnode(
        10,
        16384,
        &data_pointer(&mos, 0x40000, 10, if claimed { 42 } else { 40 }, order),
        0,
        &[],
        order,
    );
    let faults = Arc::default();
    let mut blocks = vec![
        (FIRST, log),
        (
            SECOND,
            if claimed {
                block(&next, order, &tail, &records[split..])
            } else {
                vec![0; 4096]
            },
        ),
        (0x40000, mos),
        (0x44000, pool_directory),
        (0x45000, os),
        (0x48000, table),
        (0x4c000, master),
        (0x4c200, directory),
        (0x4c400, file),
    ];
    blocks.extend_from_slice(extra);
    let (leaf, reads) = leaf_with_faults(&blocks, cancelled_at, Arc::clone(&faults));
    let objects = Objects {
        pool: leaf,
        config: config(),
        txg: 42,
        root_birth: 42,
        meta: Dnode::parse(&meta, order).unwrap(),
        cache: std::collections::VecDeque::new(),
        cached_bytes: 0,
    };
    (objects, reads, faults)
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

fn create_record(
    kind: u64,
    seq: u64,
    parent: u64,
    object: u64,
    name: &[u8],
    order: Endian,
) -> Vec<u8> {
    let mut raw = vec![0; (105 + name.len()).next_multiple_of(8)];
    let length = raw.len() as u64;
    for (at, value) in [
        (0, kind),
        (8, length),
        (16, 43),
        (24, seq),
        (32, parent),
        (40, object),
        (48, if kind == 2 { 0o040_755 } else { 0o100_644 }),
        (56, 1000),
        (64, 1000),
        (72, 43),
        (80, 1_700_000_000),
    ] {
        put(&mut raw, at, value, order);
    }
    raw[104..104 + name.len()].copy_from_slice(name);
    raw
}

fn remove_record(kind: u64, seq: u64, parent: u64, name: &[u8], order: Endian) -> Vec<u8> {
    let mut raw = vec![0; (41 + name.len()).next_multiple_of(8)];
    let length = raw.len() as u64;
    for (at, value) in [(0, kind), (8, length), (16, 43), (24, seq), (32, parent)] {
        put(&mut raw, at, value, order);
    }
    raw[40..40 + name.len()].copy_from_slice(name);
    raw
}

fn rename_record(
    seq: u64,
    source: u64,
    destination: u64,
    from: &[u8],
    to: &[u8],
    order: Endian,
) -> Vec<u8> {
    let mut raw = vec![0; (50 + from.len() + to.len()).next_multiple_of(8)];
    let length = raw.len() as u64;
    for (at, value) in [
        (0, 8),
        (8, length),
        (16, 43),
        (24, seq),
        (32, source),
        (40, destination),
    ] {
        put(&mut raw, at, value, order);
    }
    raw[48..48 + from.len()].copy_from_slice(from);
    raw[49 + from.len()..49 + from.len() + to.len()].copy_from_slice(to);
    raw
}

fn link_record(seq: u64, parent: u64, object: u64, name: &[u8], order: Endian) -> Vec<u8> {
    let mut raw = vec![0; (49 + name.len()).next_multiple_of(8)];
    let length = raw.len() as u64;
    for (at, value) in [
        (0, 7),
        (8, length),
        (16, 43),
        (24, seq),
        (32, parent),
        (40, object),
    ] {
        put(&mut raw, at, value, order);
    }
    raw[48..48 + name.len()].copy_from_slice(name);
    raw
}

fn seven_operation_records(order: Endian) -> Vec<Vec<u8>> {
    let mut write = record(9, 43, 4, 0, b"hello-zil-world", order);
    put(&mut write, 32, 9, order);
    let mut truncate = record(10, 43, 5, 9, &[], order);
    put(&mut truncate, 32, 9, order);
    vec![
        create_record(2, 1, 2, 8, b"made", order),
        create_record(2, 2, 2, 10, b"gone_dir", order),
        create_record(1, 3, 8, 9, b"file", order),
        write,
        truncate,
        rename_record(6, 8, 8, b"file", b"renamed", order),
        create_record(1, 7, 2, 11, b"gone", order),
        remove_record(5, 8, 2, b"gone", order),
        remove_record(6, 9, 2, b"gone_dir", order),
    ]
}

fn names(view: &mut super::super::zpl::Zpl, cx: &Cx, object: u64) -> Vec<Vec<u8>> {
    let mut names: Vec<_> = view
        .list(cx, object)
        .unwrap()
        .into_iter()
        .map(|entry| entry.name)
        .collect();
    names.sort();
    names
}

#[test]
fn native_seven_operation_replay_uses_selected_mos_and_is_repeatable_without_source_writes() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for algorithm in [5, 9] {
            for claimed in [false, true] {
                let records = seven_operation_records(order);
                let (mut objects, reads, _) =
                    recovery_graph_log(order, algorithm, &records, claimed, None, &[]);
                let mut view = objects.zpl(&cx, &[]).unwrap();
                assert_eq!(
                    names(&mut view, &cx, 2),
                    [b"alias".to_vec(), b"file".to_vec()]
                );
                let first = view.replay_zil(&cx).unwrap();
                assert_eq!(first.records_replayed, 9);
                assert_eq!(first.blocks_visited, if claimed { 2 } else { 1 });
                assert_eq!(
                    objects.intent_log(&cx, &[]).unwrap().termination,
                    if claimed {
                        Termination::ClaimedBoundary
                    } else {
                        Termination::UnverifiedTail
                    }
                );
                assert_eq!((first.last_txg, first.last_seq), (43, 9));
                for _ in 0..2 {
                    assert_eq!(
                        names(&mut view, &cx, 2),
                        [b"alias".to_vec(), b"file".to_vec(), b"made".to_vec()]
                    );
                    assert_eq!(names(&mut view, &cx, 8), [b"renamed".to_vec()]);
                    assert_eq!(view.resolve(&cx, b"/made/renamed").unwrap(), 9);
                    assert_eq!(view.read(&cx, 9, 0, 64).unwrap(), b"hello-zil");
                    for path in [b"/made/file".as_slice(), b"/gone", b"/gone_dir"] {
                        assert!(matches!(
                            view.resolve(&cx, path),
                            Err(FfsError::NotFound(_))
                        ));
                    }
                    let root = view.stat(&cx, 2).unwrap().0;
                    let dir = view.stat(&cx, 8).unwrap().0;
                    let file = view.stat(&cx, 9).unwrap().0;
                    assert_eq!((root.size, root.links), (5, 3));
                    assert_eq!((dir.size, dir.links, dir.parent), (3, 2, 2));
                    assert_eq!(
                        (file.size, file.links, file.parent, file.generation),
                        (9, 1, 8, 43)
                    );
                    assert_eq!(view.replay_zil(&cx).unwrap(), first);
                }
                let mut committed = objects.zpl(&cx, &[]).unwrap();
                assert_eq!(
                    names(&mut committed, &cx, 2),
                    [b"alias".to_vec(), b"file".to_vec()]
                );
                assert_eq!(committed.read(&cx, 7, 0, 64).unwrap(), b"abcdefghijklmnop");
                assert!(
                    reads
                        .lock()
                        .unwrap()
                        .iter()
                        .all(|(at, count)| *at >= BASE + DATA_OFFSET
                            && *at + *count as u64 <= BASE + LENGTH)
                );
            }
        }
    }
}

#[test]
fn native_replay_failures_preserve_the_entire_previously_published_view() {
    let cx = Cx::for_testing();
    let order = Endian::Little;
    let records = seven_operation_records(order);
    let (mut objects, _, faults) = recovery_graph_log(order, 9, &records, true, None, &[]);
    let mut view = objects.zpl(&cx, &[]).unwrap();
    let stats = view.replay_zil(&cx).unwrap();
    let second = pointer(SECOND, 2, 9, 4096, order, order);
    let tail = pointer(0x30000, 3, 9, 4096, order, order);
    let mut bad_sequence = records[4..].to_vec();
    put(&mut bad_sequence[0], 24, 1, order);
    let mut wrong_identity = tail.clone();
    put(&mut wrong_identity, 96, 12, order);
    let mut bad_late_operation = records[4..].to_vec();
    *bad_late_operation.last_mut().unwrap() = remove_record(6, 9, 2, b"made", order);
    let failures = [
        Fault::Checksum,
        Fault::Io,
        Fault::Cancelled,
        Fault::Replacement(block(&second, order, &tail, &bad_sequence)),
        Fault::Replacement(block(&second, order, &wrong_identity, &records[4..])),
        Fault::Replacement(block(&second, order, &tail, &bad_late_operation)),
    ];
    for fault in failures {
        faults
            .lock()
            .unwrap()
            .insert(BASE + DATA_OFFSET + SECOND, fault);
        assert!(view.replay_zil(&cx).is_err());
        assert_eq!(view.zil_replay_stats(), Some(&stats));
        assert_eq!(
            names(&mut view, &cx, 2),
            [b"alias".to_vec(), b"file".to_vec(), b"made".to_vec()]
        );
        assert_eq!(view.read(&cx, 9, 0, 64).unwrap(), b"hello-zil");
        assert_eq!(view.resolve(&cx, b"/made/renamed").unwrap(), 9);
    }
    faults.lock().unwrap().clear();
    assert_eq!(view.replay_zil(&cx).unwrap(), stats);
}

#[test]
fn native_namespace_transitions_preserve_hardlinks_tombstones_and_directory_parents() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        let mut write = record(9, 43, 6, 0, b"Y", order);
        put(&mut write, 32, 11, order);
        let mut free = record(10, 43, 11, 1, &[], order);
        put(&mut free, 32, 11, order);
        put(&mut free, 48, 4, order);
        let mut after = record(9, 43, 12, 8, b"Z", order);
        put(&mut after, 32, 11, order);
        let records = vec![
            create_record(1, 1, 2, 8, b"replacement", order),
            rename_record(2, 2, 2, b"replacement", b"file", order),
            remove_record(5, 3, 2, b"file", order),
            create_record(1, 4, 2, 11, b"file", order),
            rename_record(5, 2, 2, b"file", b"file", order),
            write,
            create_record(2, 7, 2, 9, b"made", order),
            create_record(2, 8, 9, 10, b"child", order),
            rename_record(9, 9, 2, b"child", b"moved", order),
            remove_record(6, 10, 2, b"made", order),
            free,
            after,
        ];
        let (mut objects, _, _) = recovery_graph_log(order, 9, &records, true, None, &[]);
        let mut view = objects.zpl(&cx, &[]).unwrap();
        view.replay_zil(&cx).unwrap();
        assert_eq!(
            names(&mut view, &cx, 2),
            [b"alias".to_vec(), b"file".to_vec(), b"moved".to_vec()]
        );
        assert_eq!(view.resolve(&cx, b"/file").unwrap(), 11);
        assert_eq!(view.resolve(&cx, b"/alias").unwrap(), 7);
        assert_eq!(view.stat(&cx, 7).unwrap().0.links, 1);
        assert_eq!(view.read(&cx, 7, 0, 64).unwrap(), b"abcdefghijklmnop");
        assert_eq!(view.read(&cx, 11, 0, 64).unwrap(), b"Y\0\0\0\0\0\0\0Z");
        assert_eq!(view.stat(&cx, 10).unwrap().0.parent, 2);
        let root = view.stat(&cx, 2).unwrap().0;
        assert_eq!((root.size, root.links), (5, 3));
        assert!(matches!(
            view.resolve(&cx, b"/made"),
            Err(FfsError::NotFound(_))
        ));
    }
}

#[test]
fn native_hard_link_replay_shares_existing_and_created_files_across_directories() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for algorithm in [5, 9] {
            for claimed in [false, true] {
                let mut write = record(9, 43, 7, 0, b"shared", order);
                put(&mut write, 32, 9, order);
                let mut append = record(9, 43, 10, 6, b"!", order);
                put(&mut append, 32, 9, order);
                let records = [
                    create_record(2, 1, 2, 8, b"links", order),
                    link_record(2, 2, 7, b"third", order),
                    link_record(3, 8, 7, b"base", order),
                    remove_record(5, 4, 2, b"file", order),
                    remove_record(5, 5, 2, b"alias", order),
                    create_record(1, 6, 2, 9, b"fresh", order),
                    write,
                    link_record(8, 8, 9, b"fresh", order),
                    remove_record(5, 9, 2, b"fresh", order),
                    append,
                    rename_record(11, 2, 8, b"third", b"moved", order),
                ];
                let (mut objects, _, _) =
                    recovery_graph_log(order, algorithm, &records, claimed, None, &[]);
                let mut view = objects.zpl(&cx, &[]).unwrap();
                let stats = view.replay_zil(&cx).unwrap();
                assert_eq!(stats.records_replayed, 11);
                for _ in 0..2 {
                    assert_eq!(names(&mut view, &cx, 2), [b"links".to_vec()]);
                    assert_eq!(
                        names(&mut view, &cx, 8),
                        [b"base".to_vec(), b"fresh".to_vec(), b"moved".to_vec()]
                    );
                    for path in [b"/links/base".as_slice(), b"/links/moved"] {
                        let object = view.resolve(&cx, path).unwrap();
                        assert_eq!(object, 7);
                        assert_eq!(view.read(&cx, object, 0, 64).unwrap(), b"abcdefghijklmnop");
                    }
                    assert_eq!(view.resolve(&cx, b"/links/fresh").unwrap(), 9);
                    assert_eq!(view.read(&cx, 9, 0, 64).unwrap(), b"shared!");
                    let root = view.stat(&cx, 2).unwrap().0;
                    let directory = view.stat(&cx, 8).unwrap().0;
                    let original = view.stat(&cx, 7).unwrap().0;
                    let created = view.stat(&cx, 9).unwrap().0;
                    assert_eq!((root.size, root.links), (3, 3));
                    assert_eq!((directory.size, directory.links), (5, 2));
                    assert_eq!(
                        (original.links, original.parent, original.generation),
                        (2, 8, 2)
                    );
                    assert_eq!(
                        (created.links, created.parent, created.generation),
                        (1, 8, 43)
                    );
                    assert_eq!(view.replay_zil(&cx).unwrap(), stats);
                }
                // A new committed view and the backing storage are unchanged.
                let mut committed = objects.zpl(&cx, &[]).unwrap();
                assert_eq!(
                    names(&mut committed, &cx, 2),
                    [b"alias".to_vec(), b"file".to_vec()]
                );
                assert_eq!(committed.stat(&cx, 7).unwrap().0.links, 2);
                assert_eq!(committed.read(&cx, 7, 0, 64).unwrap(), b"abcdefghijklmnop");
            }
        }
    }
}

#[test]
fn native_hard_link_replay_keeps_symlink_identity_and_survives_original_unlink() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        let mut symlink = create_record(4, 1, 2, 8, b"symbolic\0file", order);
        put(&mut symlink, 48, 0o120_777, order);
        let records = [
            symlink,
            link_record(2, 2, 8, b"other", order),
            remove_record(5, 3, 2, b"symbolic", order),
        ];
        let (mut objects, _, _) = recovery_graph_log(order, 9, &records, true, None, &[]);
        let mut view = objects.zpl(&cx, &[]).unwrap();
        view.replay_zil(&cx).unwrap();
        assert_eq!(view.readlink(&cx, 8).unwrap(), b"file");
        let metadata = view.stat(&cx, 8).unwrap().0;
        assert_eq!(metadata.kind, ffs_ondisk::zfs_zpl::Kind::Symlink);
        assert_eq!((metadata.links, metadata.size), (1, 4));
        assert_eq!(
            names(&mut view, &cx, 2),
            [b"alias".to_vec(), b"file".to_vec(), b"other".to_vec()]
        );
    }
}

#[test]
fn native_hard_link_rejections_never_publish_a_partial_recovered_namespace() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for (parent, target, name) in [
            (2, 2, b"new".as_slice()),
            (2, 8, b"new"),
            (2, 9, b"new"),
            (2, 20, b"new"),
            (2, 0, b"new"),
            (2, 1_u64 << 48, b"new"),
            (7, 7, b"new"),
            (2, 7, b"file"),
            (2, 7, b"surviving"),
            (2, 7, b".."),
            (2, 7, b"bad/name"),
        ] {
            let records = [
                create_record(2, 1, 2, 8, b"made", order),
                link_record(2, 2, 7, b"surviving", order),
                create_record(1, 3, 2, 9, b"gone", order),
                remove_record(5, 4, 2, b"gone", order),
                link_record(5, parent, target, name, order),
            ];
            let (mut objects, _, _) = recovery_graph_log(order, 9, &records, true, None, &[]);
            let mut view = objects.zpl(&cx, &[]).unwrap();
            assert!(
                view.replay_zil(&cx).is_err(),
                "parent={parent} target={target} name={name:?}"
            );
            assert!(view.zil_replay_stats().is_none());
            assert_eq!(
                names(&mut view, &cx, 2),
                [b"alias".to_vec(), b"file".to_vec()]
            );
            assert_eq!(view.stat(&cx, 7).unwrap().0.links, 2);
            assert_eq!(view.read(&cx, 7, 0, 64).unwrap(), b"abcdefghijklmnop");
        }
    }
}

#[test]
fn native_namespace_late_rejections_never_publish_earlier_valid_operations() {
    let cx = Cx::for_testing();
    let order = Endian::Little;
    let prefix = vec![
        create_record(2, 1, 2, 8, b"made", order),
        create_record(2, 2, 8, 9, b"child", order),
    ];
    let mut invalid_range = record(10, 43, 3, i64::MAX as u64, &[], order);
    put(&mut invalid_range, 48, 1, order);
    let mut unknown = remove_record(5, 3, 2, b"file", order);
    put(&mut unknown, 0, 1_u64 << 63 | 5, order);
    for last in [
        rename_record(3, 2, 9, b"made", b"cycle", order),
        remove_record(6, 3, 2, b"made", order),
        remove_record(5, 3, 2, b"made", order),
        rename_record(3, 2, 8, b"absent", b"other", order),
        invalid_range,
        unknown,
    ] {
        let mut records = prefix.clone();
        records.push(last);
        let (mut objects, _, _) = recovery_graph_log(order, 9, &records, true, None, &[]);
        let mut view = objects.zpl(&cx, &[]).unwrap();
        assert!(view.replay_zil(&cx).is_err());
        assert!(view.zil_replay_stats().is_none());
        assert_eq!(
            names(&mut view, &cx, 2),
            [b"alias".to_vec(), b"file".to_vec()]
        );
        assert!(matches!(
            view.resolve(&cx, b"/made"),
            Err(FfsError::NotFound(_))
        ));
        assert_eq!(view.read(&cx, 7, 0, 64).unwrap(), b"abcdefghijklmnop");
    }
}

#[test]
fn native_namespace_range_free_preserves_tail_extends_eof_and_propagates_surviving_base_errors() {
    let cx = Cx::for_testing();
    let order = Endian::Little;
    let mut free = record(10, 43, 2, 20, &[], order);
    put(&mut free, 48, 2, order);
    let records = [record(9, 43, 1, 2, b"NEW", order), free];
    let (mut objects, reads, faults) = recovery_graph_log(order, 9, &records, true, None, &[]);
    let mut view = objects.zpl(&cx, &[]).unwrap();
    view.replay_zil(&cx).unwrap();
    assert_eq!(view.stat(&cx, 7).unwrap().0.size, 22);
    for fault in [Fault::Checksum, Fault::Io, Fault::Cancelled] {
        faults
            .lock()
            .unwrap()
            .insert(BASE + DATA_OFFSET + 0x4c400, fault);
        reads.lock().unwrap().clear();
        assert_eq!(view.read(&cx, 7, 2, 3).unwrap(), b"NEW");
        assert!(
            !reads
                .lock()
                .unwrap()
                .iter()
                .any(|(at, _)| *at == BASE + DATA_OFFSET + 0x4c400)
        );
        assert!(view.read(&cx, 7, 0, 64).is_err());
    }
    faults.lock().unwrap().clear();
    assert_eq!(
        view.read(&cx, 7, 0, 64).unwrap(),
        b"abNEWfghijklmnop\0\0\0\0\0\0"
    );
}
