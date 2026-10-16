//! Native TX_TRUNCATE range semantics over constructed logs, not live replay.
use super::*;
use super::super::indirect::{Plan, edits};

fn free_record(offset: u64, length: u64, sequence: u64, order: Endian) -> Record {
    let mut raw = record(10, 43, sequence, offset, &[], order);
    put(&mut raw, 48, length, order);
    Record { kind: 10, txg: 43, sequence, record_bytes: raw.len(), pending: true, order, raw }
}

#[test]
fn native_range_free_keeps_the_tail_and_extends_eof_in_both_byte_orders() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for (offset, length) in [(2, 5), (0, 16), (12, 8), (16, 3), (20, 5)] {
            let records = [free_record(offset, length, 1, order)];
            Plan::new(&cx, &records).unwrap();
            let data = BTreeMap::new();
            let changes = edits(&cx, &records, &data, 7).unwrap();
            let size = changes[0].size_after(16);
            assert_eq!(size, 16.max(offset + length));
            let mut expected = b"abcdefghijklmnop".to_vec();
            expected.resize(size as usize, 0);
            expected[offset as usize..(offset + length) as usize].fill(0);
            let actual = super::super::recovery::read(&cx, 16, 0, size as usize, &changes, |at, count| {
                Ok(b"abcdefghijklmnop"[at as usize..at as usize + count].to_vec())
            }).unwrap();
            assert_eq!(actual, expected, "offset={offset} length={length}");
            assert!(edits(&cx, &records, &data, 99).unwrap().is_empty());
        }
        let row = free_record(3, 0, 1, order);
        assert!(matches!(edit(&row).unwrap(), Edit::Truncate { size: 3, .. }));
    }
}

#[test]
fn malformed_range_free_records_are_rejected_before_any_payload_read() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for case in 0..6 {
            let mut row = free_record(2, 5, 1, order);
            match case {
                0 => row.raw.resize(48, 0),
                1 => row.raw.resize(64, 0),
                2 => put(&mut row.raw, 32, 0, order),
                3 => put(&mut row.raw, 32, 1_u64 << 48, order),
                4 => put(&mut row.raw, 40, i64::MAX as u64, order),
                _ => put(&mut row.raw, 48, u64::MAX, order),
            }
            assert!(matches!(Plan::new(&cx, &[row]), Err(FfsError::Corruption { .. })), "case {case}");
        }
        let records = [free_record(i64::MAX as u64 - 1, 1, 1, order)];
        Plan::new(&cx, &records).unwrap();
        let data = BTreeMap::new();
        let changes = edits(&cx, &records, &data, 7).unwrap();
        assert_eq!(changes[0].size_after(16), i64::MAX as u64);
    }
}

#[test]
fn mixed_range_free_write_and_truncate_sequences_match_materialized_files() {
    let cx = Cx::for_testing();
    let original = b"abcdefghijklmnop";
    for pattern in 0_usize..1296 {
        let mut digits = pattern;
        let mut changes = Vec::new();
        let mut expected = original.to_vec();
        for _ in 0..4 {
            let change = match digits % 6 {
                0 => Edit::Truncate { object: 7, size: 3 },
                1 => Edit::Truncate { object: 7, size: 24 },
                2 => Edit::Write { object: 7, offset: 7, data: b"XY\0Z" },
                3 => Edit::Write { object: 7, offset: 1, data: b"changed" },
                4 => Edit::Free { object: 7, offset: 2, end: 7 },
                _ => Edit::Free { object: 7, offset: 20, end: 25 },
            };
            digits /= 6;
            match &change {
                Edit::Write { offset, data, .. } => {
                    expected.resize(expected.len().max(*offset as usize + data.len()), 0);
                    expected[*offset as usize..*offset as usize + data.len()].copy_from_slice(data);
                }
                Edit::Truncate { size, .. } => expected.resize(*size as usize, 0),
                Edit::Free { offset, end, .. } => {
                    expected.resize(expected.len().max(*end as usize), 0);
                    expected[*offset as usize..*end as usize].fill(0);
                }
            }
            changes.push(change);
        }
        let size = changes.iter().fold(16, |size, change| change.size_after(size));
        assert_eq!(size, expected.len() as u64);
        for start in 0..=28 {
            for count in [0, 1, 5, 32] {
                let length = expected.len().saturating_sub(start).min(count);
                let actual = super::super::recovery::read(&cx, 16, start as u64, length, &changes, |at, count| {
                    Ok(original[at as usize..at as usize + count].to_vec())
                }).unwrap();
                let from = start.min(expected.len());
                assert_eq!(actual, expected[from..from + length], "pattern={pattern}, start={start}, count={count}");
            }
        }
    }
}

struct LogOverlay {
    original: Leaf,
    log: Vec<u8>,
    reads: Reads,
    failure: u8,
}
impl ByteDevice for LogOverlay {
    fn len_bytes(&self) -> u64 { self.original.device.len_bytes() }
    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, out: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        self.reads.lock().unwrap().push((at.0, out.len()));
        if at.0 == BASE + DATA_OFFSET + FIRST {
            if out.len() != self.log.len() { return Err(corrupt("invalid test log read size")); }
            out.copy_from_slice(&self.log);
            return Ok(());
        }
        if at.0 == BASE + DATA_OFFSET + 0x4c400 {
            match self.failure {
                1 => { out.fill(0); return Ok(()); }
                2 => return Err(FfsError::Cancelled),
                _ => {}
            }
        }
        self.original.device.read_exact_at(cx, at, out)
    }
    fn write_all_at(&self, _: &Cx, _: ByteOffset, _: &[u8]) -> Result<()> { panic!("range-free recovery wrote an image") }
    fn sync(&self, _: &Cx) -> Result<()> { panic!("range-free recovery flushed an image") }
}
fn graph(offset: u64, length: u64, failure: u8) -> (Objects, Reads) {
    let (mut objects, _) = recovery_graph(false);
    let order = Endian::Little;
    let first = pointer(FIRST, 1, 9, 4096, order, order);
    let next = pointer(SECOND, 2, 9, 4096, order, order);
    let log = block(&first, order, &next, &[
        free_record(offset, length, 1, order).raw,
        record(9, 43, 2, 4, b"!", order),
    ]);
    let reads = Arc::default();
    let device = LogOverlay { original: objects.pool.leaves()[0].clone(), log,
        reads: Arc::clone(&reads), failure };
    objects.pool = Leaf::from_device(&Cx::for_testing(), Box::new(device), BASE, LENGTH).unwrap().into();
    (objects, reads)
}

#[test]
fn native_mos_recovery_discards_freed_damage_but_preserves_required_failures_and_consent() {
    let cx = Cx::for_testing();
    for failure in 0..=2 {
        let (mut objects, reads) = graph(0, 20, failure);
        assert!(objects.read_with_intent_log(&cx, &[], b"/file", 0, 32, false).is_err());
        let recovered = objects.read_with_intent_log(&cx, &[], b"/file", 0, 32, true).unwrap();
        let mut expected = vec![0; 20];
        expected[4] = b'!';
        assert_eq!(recovered.bytes, expected);
        assert_eq!((recovered.file_size, recovered.applied_records), (20, 2));
        assert!(!reads.lock().unwrap().iter().any(|(at, _)| *at == BASE + DATA_OFFSET + 0x4c400));
        let mut normal = objects.zpl(&cx, &[]).unwrap();
        let object = normal.resolve(&cx, b"/file").unwrap();
        assert_eq!(normal.stat(&cx, object).unwrap().0.size, 16);
        let result = normal.read(&cx, object, 0, 16);
        match failure {
            0 => assert_eq!(result.unwrap(), b"abcdefghijklmnop"),
            1 => assert!(result.is_err()),
            _ => assert!(matches!(result, Err(FfsError::Cancelled))),
        }
        let (mut partial, _) = graph(2, 5, failure);
        let result = partial.read_with_intent_log(&cx, &[], b"/file", 0, 32, true);
        match failure {
            0 => assert_eq!(result.unwrap().bytes, b"ab\0\0!\0\0hijklmnop"),
            1 => assert!(result.is_err()),
            _ => assert!(matches!(result, Err(FfsError::Cancelled))),
        }
    }
}

#[test]
fn huge_freed_ranges_have_request_sized_work_and_do_not_resurrect_retired_data() {
    let cx = Cx::for_testing();
    let end = (1_u64 << 60) + 19;
    let changes = [Edit::Free { object: 7, offset: 0, end },
        Edit::Truncate { object: 7, size: 3 },
        Edit::Free { object: 7, offset: end - 1, end }];
    assert_eq!(changes.iter().fold(16, |size, edit| edit.size_after(size)), end);
    for start in [0, 8, end - 9] {
        assert_eq!(super::super::recovery::read(&cx, 16, start, 9, &changes,
            |_, _| panic!("freed bytes do not require base I/O")).unwrap(), [0; 9]);
    }
    let changes: Vec<_> = (0..9).map(|_| Edit::Free {
        object: 7, offset: 0, end: MAX_READ_BYTES as u64,
    }).collect();
    assert!(matches!(super::super::recovery::read(&cx, MAX_READ_BYTES as u64, 0, MAX_READ_BYTES,
        &changes, |_, _| panic!("work budget must be checked first")), Err(FfsError::UnsupportedFeature(_))));
}
