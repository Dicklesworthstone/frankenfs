//! Newly exposed bytes are initialized even when native allocation extends past EOF.

use super::*;

const OLD_SIZE: u64 = 1237;
const PAYLOAD: &[u8] = b"new-data";
const TIME: Timestamp = Timestamp {
    seconds: 1_735_000_000,
    nanos: 37,
};

#[derive(Debug, Clone, Copy)]
enum Growth {
    Truncate(u64),
    Write(u64),
    EmptyWrite(u64),
}

impl Growth {
    fn apply(self, cx: &Cx, engine: &mut ZfsTransactionEngine) -> Result<()> {
        let dataset = [b"data".to_vec()];
        match self {
            Self::Truncate(size) => {
                engine.truncate_file(cx, &dataset, 4, size, TIME, ZfsDataChecksum::Fletcher4)
            }
            Self::Write(offset) => engine.write_file_data(
                cx,
                &dataset,
                4,
                offset,
                PAYLOAD,
                TIME,
                ZfsDataChecksum::Fletcher4,
            ),
            Self::EmptyWrite(offset) => engine.write_file_data(
                cx,
                &dataset,
                4,
                offset,
                &[],
                TIME,
                ZfsDataChecksum::Fletcher4,
            ),
        }
        .into_result()
        .map(|_| ())
    }

    fn expected(self, original: &[u8]) -> Vec<u8> {
        let mut bytes = original[..OLD_SIZE as usize].to_vec();
        match self {
            Self::Truncate(size) | Self::EmptyWrite(size) => bytes.resize(size as usize, 0),
            Self::Write(offset) => {
                bytes.resize(offset as usize, 0);
                bytes.extend_from_slice(PAYLOAD);
            }
        }
        bytes
    }
}

fn durable_head(cx: &Cx, devices: &[FaultableMemberDevice]) -> ffs_zfs::Zpl {
    let leaves = devices
        .iter()
        .map(|device| {
            let fresh = device.fresh_from_durable();
            let length = fresh.len_bytes();
            Leaf::from_device(cx, Box::new(fresh), 0, length).unwrap()
        })
        .collect();
    Pool::from_leaves(leaves)
        .unwrap()
        .import_objects(cx, Some(POOL_GUID))
        .unwrap()
        .zpl(cx, &[b"data".to_vec()])
        .unwrap()
}

#[test]
fn growth_zeroes_allocated_tails_across_native_record_geometries() {
    let cx = Cx::for_testing();
    for (zpl_version, mirror_width, ashift, recordsize) in [(4, 1, 9, 4096), (5, 2, 12, 131_072)] {
        let built = build_clean_zfs_pool(&PoolFixtureSpec {
            zpl_version,
            mirror_width,
            ashift,
            hello_size: Some(OLD_SIZE),
            deadlist_mode: DeadlistMode::NativeDeadlist,
            user_accounting: true,
            data_properties: vec![(b"recordsize", recordsize)],
            ..PoolFixtureSpec::default()
        });
        // The checksum-valid compressed block contains nonzero bytes beyond
        // logical EOF. Its matching writer must not rely on zero-padded input.
        assert!(
            built.snap_hello_expected[OLD_SIZE as usize..]
                .iter()
                .all(|&b| b != 0)
        );
        for operation in [
            Growth::Truncate(3000),
            Growth::Truncate(8193),
            Growth::EmptyWrite(3000),
            Growth::Write(2000),
            Growth::Write(8199),
            Growth::Write(131_099),
        ] {
            let devices: Vec<_> = built
                .members
                .iter()
                .cloned()
                .map(FaultableMemberDevice::new)
                .collect();
            let mut engine = open_engine_on_devices(
                &cx,
                &devices,
                default_write_opts(built.pool_guid, built.initial_slot),
            )
            .unwrap();
            operation.apply(&cx, &mut engine).unwrap();
            let expected = operation.expected(&built.snap_hello_expected);
            drop(engine);
            let mut head = durable_head(&cx, &devices);
            assert_eq!(head.stat(&cx, 4).unwrap().0.size, expected.len() as u64);
            assert_eq!(
                head.read(&cx, 4, 0, expected.len() + 1).unwrap(),
                expected,
                "{zpl_version}/{recordsize}/{operation:?}"
            );
            assert_eq!(head.read(&cx, 5, 0, 4096).unwrap(), vec![0x5A; 4096]);
            let mut snapshot = head.open_snapshot(&cx, b"before").unwrap();
            assert_eq!(snapshot.stat(&cx, 4).unwrap().0.size, OLD_SIZE);
            assert_eq!(
                snapshot.read(&cx, 4, 0, 4096).unwrap(),
                built.snap_hello_expected[..OLD_SIZE as usize]
            );
            assert_pool_scrub_and_allocation_clean(&cx, &devices, POOL_GUID, None);
        }
    }
}

#[test]
fn growth_from_zero_eof_reclaims_uninitialized_allocated_blocks() {
    let cx = Cx::for_testing();
    for zpl_version in [4, 5] {
        let (mut engine, devices) = file_range_fixture(
            &cx,
            &PoolFixtureSpec {
                zpl_version,
                hello_size: Some(0),
                deadlist_mode: DeadlistMode::NativeDeadlist,
                user_accounting: true,
                data_properties: vec![(b"recordsize", 4096)],
                ..PoolFixtureSpec::default()
            },
        );
        Growth::Truncate(8193).apply(&cx, &mut engine).unwrap();
        let mut head = durable_head(&cx, &devices);
        assert_eq!(head.read(&cx, 4, 0, 8193).unwrap(), vec![0; 8193]);
        assert_eq!(head.stat(&cx, 4).unwrap().1, 0);
        let mut snapshot = head.open_snapshot(&cx, b"before").unwrap();
        assert_eq!(snapshot.stat(&cx, 4).unwrap().0.size, 0);
        assert!(snapshot.read(&cx, 4, 0, 4096).unwrap().is_empty());
        assert_pool_scrub_and_allocation_clean(&cx, &devices, POOL_GUID, None);
    }
}

#[test]
fn sparse_growth_initializes_old_tail_without_materializing_logical_holes() {
    const FAR: u64 = (1_u64 << 45) + 4096;
    let cx = Cx::for_testing();
    let (mut engine, devices) = file_range_fixture(
        &cx,
        &PoolFixtureSpec {
            hello_size: Some(OLD_SIZE),
            deadlist_mode: DeadlistMode::NativeDeadlist,
            user_accounting: true,
            data_properties: vec![(b"recordsize", 4096)],
            ..PoolFixtureSpec::default()
        },
    );
    Growth::Truncate(FAR).apply(&cx, &mut engine).unwrap();
    Growth::Write(FAR + 4096).apply(&cx, &mut engine).unwrap();
    drop(engine);
    let mut head = durable_head(&cx, &devices);
    let (metadata, allocation) = head.stat(&cx, 4).unwrap();
    assert_eq!(metadata.size, FAR + 4096 + PAYLOAD.len() as u64);
    assert!(
        allocation < 1024 * 1024,
        "sparse gap consumed {allocation} bytes"
    );
    assert_eq!(head.read(&cx, 4, OLD_SIZE, 8192).unwrap(), vec![0; 8192]);
    assert_eq!(head.read(&cx, 4, FAR - 4096, 8192).unwrap(), vec![0; 8192]);
    assert_eq!(head.read(&cx, 4, FAR + 4096, 64).unwrap(), PAYLOAD);
    let mut snapshot = head.open_snapshot(&cx, b"before").unwrap();
    assert_eq!(snapshot.stat(&cx, 4).unwrap().0.size, OLD_SIZE);
    assert_eq!(
        snapshot.read(&cx, 4, 0, 4096).unwrap(),
        b"SNAPDATA".repeat(512)[..OLD_SIZE as usize]
    );
    assert_pool_scrub_and_allocation_clean(&cx, &devices, POOL_GUID, None);
}

#[test]
fn growth_persistence_cuts_never_publish_stored_bytes_past_old_eof() {
    let cx = Cx::for_testing();
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        mirror_width: 2,
        hello_size: Some(OLD_SIZE),
        deadlist_mode: DeadlistMode::NativeDeadlist,
        data_properties: vec![(b"recordsize", 4096)],
        ..PoolFixtureSpec::default()
    });
    for operation in [Growth::Truncate(8193), Growth::Write(8199)] {
        let probe_devices: Vec<_> = built
            .members
            .iter()
            .cloned()
            .map(FaultableMemberDevice::new)
            .collect();
        let mut probe = open_engine_on_devices(
            &cx,
            &probe_devices,
            default_write_opts(built.pool_guid, built.initial_slot),
        )
        .unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&events);
        probe.with_fault_hook(move |event| {
            captured.lock().unwrap().push(event.clone());
            Ok(())
        });
        operation.apply(&cx, &mut probe).unwrap();
        let events = events.lock().unwrap().clone();
        let acknowledged = events
            .iter()
            .find(|event| event.stage == ZfsPersistenceStage::BeforeAcknowledge)
            .unwrap()
            .seq;
        let first_publication = events
            .iter()
            .find(|event| matches!(event.stage, ZfsPersistenceStage::UberblockWrite { .. }))
            .unwrap()
            .seq;
        drop(probe);
        drop(probe_devices);
        let expected = operation.expected(&built.snap_hello_expected);
        for cut in events {
            for reorder in [false, true] {
                let devices: Vec<_> = built
                    .members
                    .iter()
                    .cloned()
                    .map(FaultableMemberDevice::new)
                    .collect();
                let mut engine = open_engine_on_devices(
                    &cx,
                    &devices,
                    default_write_opts(built.pool_guid, built.initial_slot),
                )
                .unwrap();
                let sequence = cut.seq;
                engine.with_fault_hook(move |event| {
                    if event.seq == sequence {
                        Err(FfsError::Cancelled)
                    } else {
                        Ok(())
                    }
                });
                assert_eq!(
                    operation.apply(&cx, &mut engine).is_ok(),
                    sequence >= acknowledged,
                    "{operation:?}/{:?}",
                    cut.stage
                );
                drop(engine);
                for device in &devices {
                    let mut media = device.state.lock().unwrap();
                    if reorder {
                        media.crash_reorder_and_drop_half_unsynced();
                    } else {
                        media.crash_drop_unsynced();
                    }
                }
                let mut head = durable_head(&cx, &devices);
                let metadata = head.stat(&cx, 4).unwrap().0;
                let committed = metadata.size == expected.len() as u64;
                if committed {
                    assert_eq!(head.read(&cx, 4, 0, expected.len() + 1).unwrap(), expected);
                } else {
                    assert_eq!(metadata.size, OLD_SIZE);
                    assert_eq!(
                        head.read(&cx, 4, 0, expected.len() + 1).unwrap(),
                        built.snap_hello_expected[..OLD_SIZE as usize]
                    );
                }
                if sequence <= first_publication {
                    assert!(!committed);
                }
                if sequence >= acknowledged {
                    assert!(committed);
                }
                let mut snapshot = head.open_snapshot(&cx, b"before").unwrap();
                assert_eq!(snapshot.stat(&cx, 4).unwrap().0.size, OLD_SIZE);
                assert_eq!(
                    snapshot.read(&cx, 4, 0, 4096).unwrap(),
                    built.snap_hello_expected[..OLD_SIZE as usize]
                );
                assert_pool_scrub_and_allocation_clean(&cx, &devices, POOL_GUID, None);
            }
        }
    }
}
