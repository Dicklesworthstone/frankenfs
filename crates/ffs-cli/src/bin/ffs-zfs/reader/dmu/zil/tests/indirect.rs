//! Constructed native BP/log/MOS coverage, not native OpenZFS execution.
use super::super::indirect::{Plan, edits};
use super::*;

const PAYLOAD: u64 = 0x60000;

fn data_bp(physical: &[u8], logical: usize, codec: u64, order: Endian, payload: Endian) -> Vec<u8> {
    let mut raw = pointer(PAYLOAD, 0, 7, physical.len(), order, payload);
    let prop = (logical as u64 / 512 - 1)
        | ((physical.len() as u64 / 512 - 1) << 16)
        | (codec << 32)
        | (7 << 40)
        | (19 << 48)
        | (u64::from(payload == Endian::Little) << 63);
    put(&mut raw, 48, prop, order);
    put(&mut raw, 80, 43, order);
    for (index, value) in checksum(physical, 7, payload)
        .unwrap()
        .into_iter()
        .enumerate()
    {
        put(&mut raw, 96 + index * 8, value, order);
    }
    raw
}

fn indirect(bp: &[u8], offset: u64, length: u64, order: Endian) -> IntentRecord {
    let mut raw = vec![0; 192];
    for (at, value) in [
        (0, 9),
        (8, 192),
        (16, 43),
        (24, 1),
        (32, 7),
        (40, offset),
        (48, length),
        (56, u64::MAX),
    ] {
        put(&mut raw, at, value, order);
    }
    raw[64..192].copy_from_slice(bp);
    IntentRecord {
        kind: 9,
        txg: 43,
        sequence: 1,
        record_bytes: 192,
        pending: true,
        order,
        raw,
    }
}

#[test]
fn indirect_data_keeps_each_native_byte_order_and_decodes_before_overlay() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for payload in [Endian::Little, Endian::Big] {
            for compressed in [false, true] {
                let expected = vec![b'K'; 512];
                let physical = if compressed {
                    let mut bytes = vec![0; 512];
                    bytes[..16].copy_from_slice(&[
                        0, 0, 0, 12, 0x1f, b'K', 1, 0, 255, 232, 0x50, b'K', b'K', b'K', b'K', b'K',
                    ]);
                    bytes
                } else {
                    expected.clone()
                };
                let bp = data_bp(
                    &physical,
                    512,
                    if compressed { 15 } else { 2 },
                    order,
                    payload,
                );
                let records = [indirect(&bp, 512, 512, order)];
                let plan = Plan::new(&cx, &records).unwrap();
                let (pool, reads) = leaf(&[(PAYLOAD, physical)], None);
                let data = plan.load(&cx, &pool, &config(), 7).unwrap();
                assert_eq!(data.get(&0).unwrap(), &expected);
                assert_eq!(
                    *reads.lock().unwrap(),
                    [(BASE + DATA_OFFSET + PAYLOAD, 512)]
                );
                let changes = edits(&cx, &records, &data, 7).unwrap();
                let actual = super::super::recovery::read(&cx, 0, 0, 1024, &changes, |_, _| {
                    panic!("sparse extension has no old bytes")
                })
                .unwrap();
                assert_eq!(&actual[..512], &[0; 512]);
                assert_eq!(&actual[512..], expected.as_slice());
                assert_eq!(changes[0].size_after(0), 1024);
            }
        }
    }
}

#[test]
fn crossing_indirect_ranges_and_bad_native_identity_fail_during_admission() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        let bp = data_bp(&[b'R'; 512], 512, 2, order, order);
        for case in 0..6 {
            let mut row = indirect(&bp, 0, 512, order);
            match case {
                0 => put(&mut row.raw, 40, 1, order),
                1 => put(&mut row.raw, 48, 513, order),
                2 => put(&mut row.raw, 48, 0, order),
                3 => put(&mut row.raw, 32, 1_u64 << 48, order),
                4 => put(&mut row.raw, 64 + 80, 0, order),
                _ => {
                    let property = word(&row.raw, 64 + 48, order).unwrap();
                    put(
                        &mut row.raw,
                        64 + 48,
                        (property & !(0xff << 48)) | (20 << 48),
                        order,
                    );
                }
            }
            assert!(Plan::new(&cx, &[row]).is_err(), "case {case}");
        }
        let good = indirect(&bp, 0, 512, order);
        let raw = record(1, 43, 2, 0, &[], order);
        let namespace = IntentRecord {
            kind: 1,
            txg: 43,
            sequence: 2,
            record_bytes: raw.len(),
            pending: true,
            order,
            raw,
        };
        assert!(matches!(
            Plan::new(&cx, &[good, namespace]),
            Err(FfsError::UnsupportedFeature(_))
        ));
    }
}

#[test]
fn partial_indirect_restores_checked_block_prefix_with_exact_logged_eof() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        let mut bytes = vec![b'R'; 512];
        bytes[..8].copy_from_slice(b"PREFIX!!");
        let bp = data_bp(&bytes, 512, 2, order, order);
        let rows = [indirect(&bp, 513, 7, order)];
        let plan = Plan::new(&cx, &rows).unwrap();
        let (pool, _) = leaf(&[(PAYLOAD, bytes.clone())], None);
        let payloads = plan.load(&cx, &pool, &config(), 7).unwrap();
        let changes = edits(&cx, &rows, &payloads, 7).unwrap();
        assert_eq!(changes[0].size_after(0), 520);
        assert_eq!(changes[0].size_after(800), 800);
        // lr_blkoff is deliberately u64::MAX in this real record. The checked
        // payload begins at block offset512, not user offset513 or blkoff.
        let actual = super::super::recovery::read(&cx, 0, 508, 12, &changes, |_, _| {
            panic!("new sparse bytes")
        })
        .unwrap();
        assert_eq!(actual, b"\0\0\0\0PREFIX!!");
        let hidden = super::super::recovery::read(&cx, 800, 520, 4, &changes, |_, _| {
            panic!("checked indirect block replaces these bytes")
        })
        .unwrap();
        assert_eq!(hidden, b"RRRR");
        let mut bad = indirect(&bp, i64::MAX as u64 - 2, 3, order);
        put(&mut bad.raw, 40, i64::MAX as u64, order);
        assert!(Plan::new(&cx, &[bad]).is_err());
    }
}

#[test]
fn native_namespace_replay_reads_full_and_partial_indirect_payloads_without_clipping_sparse_files()
{
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for partial in [false, true] {
            let bytes = vec![b'R'; 512];
            let offset = 32 * 1024 * 1024 + if partial { 1 } else { 0 };
            let length = if partial { 7 } else { 512 };
            let write = indirect(
                &data_bp(&bytes, 512, 2, order, order),
                offset,
                length,
                order,
            );
            let records = vec![
                write.raw,
                record(9, 43, 2, offset + length + 2, b"!", order),
            ];
            let (mut objects, reads, faults) =
                recovery_graph_log(order, 9, &records, true, None, &[(PAYLOAD, bytes)]);
            let mut view = objects.zpl(&cx, &[]).unwrap();
            let stats = view.replay_zil(&cx).unwrap();
            assert_eq!(stats.records_replayed, 2);
            assert_eq!(view.stat(&cx, 7).unwrap().0.size, offset + length + 3);
            assert_eq!(view.read(&cx, 7, 0, 16).unwrap(), b"abcdefghijklmnop");
            let start = offset - offset % 512;
            let visible = (offset + length - start) as usize;
            let mut expected = vec![b'R'; visible];
            expected.extend_from_slice(b"\0\0!");
            assert_eq!(view.read(&cx, 7, start, 1024).unwrap(), expected);
            assert!(
                reads
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|(_, count)| *count <= 16384)
            );
            for fault in [Fault::Checksum, Fault::Io, Fault::Cancelled] {
                faults
                    .lock()
                    .unwrap()
                    .insert(BASE + DATA_OFFSET + PAYLOAD, fault);
                assert!(view.replay_zil(&cx).is_err());
                assert_eq!(view.zil_replay_stats(), Some(&stats));
                assert_eq!(view.read(&cx, 7, start, 1024).unwrap(), expected);
            }
            let mut committed = objects.zpl(&cx, &[]).unwrap();
            assert_eq!(committed.stat(&cx, 7).unwrap().0.size, 16);
        }
    }
}

#[test]
fn indirect_payload_failures_never_fall_back_to_committed_data_or_a_log_tail() {
    let cx = Cx::for_testing();
    let order = Endian::Little;
    let bp = data_bp(&[b'R'; 512], 512, 2, order, order);
    let records = [indirect(&bp, 0, 512, order)];
    let plan = Plan::new(&cx, &records).unwrap();
    for cancelled in [false, true] {
        let (pool, reads) = leaf(
            &[(PAYLOAD, vec![0; 512])],
            cancelled.then_some(BASE + DATA_OFFSET + PAYLOAD),
        );
        let result = plan.load(&cx, &pool, &config(), 7);
        assert!(result.is_err());
        if cancelled {
            assert!(matches!(result, Err(FfsError::Cancelled)));
        }
        assert_eq!(reads.lock().unwrap().len(), 1);
    }
    assert!(edits(&cx, &records, &BTreeMap::new(), 7).is_err());
    let (pool, reads) = leaf(&[], None);
    assert!(plan.load(&cx, &pool, &config(), 99).unwrap().is_empty());
    assert!(
        edits(&cx, &records, &BTreeMap::new(), 99)
            .unwrap()
            .is_empty()
    );
    assert!(reads.lock().unwrap().is_empty());
}

#[test]
fn indirect_data_budget_is_preflighted_across_all_selected_writes() {
    let cx = Cx::for_testing();
    let order = Endian::Little;
    let mut bp = pointer(PAYLOAD, 0, 7, MAX_BLOCK_BYTES, order, order);
    let prop = word(&bp, 48, order).unwrap();
    put(&mut bp, 48, (prop & !(0xff << 48)) | (19 << 48), order);
    let records: Vec<_> = (0..5)
        .map(|_| indirect(&bp, 0, MAX_BLOCK_BYTES as u64, order))
        .collect();
    let plan = Plan::new(&cx, &records).unwrap();
    let (pool, reads) = leaf(&[], None);
    assert!(matches!(
        plan.load(&cx, &pool, &config(), 7),
        Err(FfsError::UnsupportedFeature(_))
    ));
    assert!(reads.lock().unwrap().is_empty());
    let (objects, reads) = recovery_graph(false);
    assert!(matches!(
        plan.load_all(&cx, &objects),
        Err(FfsError::UnsupportedFeature(_))
    ));
    assert!(reads.lock().unwrap().is_empty());
}

struct Overlay {
    original: Leaf,
    replacements: BTreeMap<u64, Vec<u8>>,
    reads: Reads,
}
impl ByteDevice for Overlay {
    fn len_bytes(&self) -> u64 {
        self.original.device.len_bytes()
    }
    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, out: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        self.reads.lock().unwrap().push((at.0, out.len()));
        if let Some(bytes) = self.replacements.get(&at.0) {
            if bytes.len() != out.len() {
                return Err(corrupt("short replacement test block"));
            }
            out.copy_from_slice(bytes);
            return Ok(());
        }
        self.original.device.read_exact_at(cx, at, out)
    }
    fn write_all_at(&self, _: &Cx, _: ByteOffset, _: &[u8]) -> Result<()> {
        panic!("recovery wrote backing storage")
    }
    fn sync(&self, _: &Cx) -> Result<()> {
        panic!("recovery flushed backing storage")
    }
}
fn overlay(original: &Pool, replacements: Vec<(u64, Vec<u8>)>) -> (Leaf, Reads) {
    let reads = Arc::default();
    let device = Overlay {
        original: original.leaves()[0].clone(),
        replacements: replacements
            .into_iter()
            .map(|(at, bytes)| (BASE + DATA_OFFSET + at, bytes))
            .collect(),
        reads: Arc::clone(&reads),
    };
    (
        Leaf::from_device(&Cx::for_testing(), Box::new(device), BASE, LENGTH).unwrap(),
        reads,
    )
}

#[test]
fn native_indirect_recovery_survives_replaced_base_damage_and_preserves_root_cache() {
    let cx = Cx::for_testing();
    let order = Endian::Little;
    for damaged_base in [false, true] {
        let (mut objects, _) = recovery_graph(false);
        let first = pointer(FIRST, 1, 9, 4096, order, order);
        let next = pointer(SECOND, 2, 9, 4096, order, order);
        let bytes = vec![b'R'; 512];
        let write = indirect(&data_bp(&bytes, 512, 2, order, order), 0, 512, order);
        let log = block(
            &first,
            order,
            &next,
            &[
                write.raw,
                record(9, 43, 2, 10, b"NEW", order),
                record(10, 43, 3, 100, &[], order),
            ],
        );
        let mut patches = vec![(FIRST, log), (PAYLOAD, bytes)];
        if damaged_base {
            patches.push((0x4c400, vec![0; 512]));
        }
        let (member, reads) = overlay(&objects.pool, patches);
        objects.pool = member.into();
        let recovered = objects
            .read_with_intent_log(&cx, &[], b"/file", 0, 1024, true)
            .unwrap();
        let mut expected = vec![b'R'; 100];
        expected[10..13].copy_from_slice(b"NEW");
        assert_eq!(recovered.bytes, expected);
        assert_eq!((recovered.file_size, recovered.applied_records), (100, 3));
        assert_eq!(recovered.log.records[0].record_bytes, 192);
        assert!(
            !reads
                .lock()
                .unwrap()
                .iter()
                .any(|(at, _)| *at == BASE + DATA_OFFSET + 0x4c400)
        );
        let mut committed = objects.zpl(&cx, &[]).unwrap();
        let object = committed.resolve(&cx, b"/file").unwrap();
        assert_eq!(committed.stat(&cx, object).unwrap().0.size, 16);
        let normal = committed.read(&cx, object, 0, 100);
        if damaged_base {
            assert!(normal.is_err());
        } else {
            assert_eq!(normal.unwrap(), b"abcdefghijklmnop");
        }
    }
}

#[test]
fn indirect_recovery_uses_verified_mirror_alternatives_and_keeps_prefix_consent() {
    let cx = Cx::for_testing();
    let order = Endian::Little;
    let (mut objects, _) = recovery_graph(false);
    let bytes = vec![b'R'; 512];
    let write = indirect(&data_bp(&bytes, 512, 2, order, order), 0, 512, order);
    let first = pointer(FIRST, 1, 9, 4096, order, order);
    let next = pointer(SECOND, 2, 9, 4096, order, order);
    let log = block(&first, order, &next, &[write.raw]);
    let (bad, bad_reads) = overlay(
        &objects.pool,
        vec![(FIRST, log.clone()), (PAYLOAD, vec![0; 512])],
    );
    let (good, good_reads) = overlay(&objects.pool, vec![(FIRST, log), (PAYLOAD, bytes.clone())]);
    objects.pool = Pool::from_leaves(vec![bad, good]).unwrap();
    assert!(
        objects
            .read_with_intent_log(&cx, &[], b"/file", 0, 512, false)
            .is_err()
    );
    for reads in [&bad_reads, &good_reads] {
        assert!(
            !reads
                .lock()
                .unwrap()
                .iter()
                .any(|(at, _)| *at == BASE + DATA_OFFSET + PAYLOAD)
        );
    }
    let recovered = objects
        .read_with_intent_log(&cx, &[], b"/file", 0, 512, true)
        .unwrap();
    assert_eq!(recovered.bytes, bytes);
    for reads in [&bad_reads, &good_reads] {
        assert_eq!(
            reads
                .lock()
                .unwrap()
                .iter()
                .filter(|(at, _)| *at == BASE + DATA_OFFSET + PAYLOAD)
                .count(),
            1
        );
    }
}
