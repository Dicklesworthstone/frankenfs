//! Empty trailing-vdev removal preserves a directly reopenable native topology.

use super::*;
use ffs_zfs::{
    AllocClass, ZfsCreateVdevKind, ZfsCreateVdevSpec, ZfsPoolCreateSpec, create_pool_on_devices,
};

fn removal_devices(count: usize) -> Vec<FaultableMemberDevice> {
    (0..count)
        .map(|_| FaultableMemberDevice::new(vec![0; 12 * 1024 * 1024]))
        .collect()
}

fn removal_boxes(devices: &[FaultableMemberDevice]) -> Vec<Box<dyn ByteDevice>> {
    devices
        .iter()
        .cloned()
        .map(|device| Box::new(device) as Box<dyn ByteDevice>)
        .collect()
}

fn removal_pool(cx: &Cx, devices: &[FaultableMemberDevice]) -> Pool {
    Pool::from_wide_leaves(
        devices
            .iter()
            .map(|device| {
                let copy = device.fresh_from_durable();
                let len = copy.len_bytes();
                Leaf::from_device(cx, Box::new(copy), 0, len).unwrap()
            })
            .collect(),
    )
    .unwrap()
}

fn removal_read(cx: &Cx, mos: &mut ffs_zfs::Objects, expected: &[u8]) {
    let mut zpl = mos.zpl(cx, &[]).unwrap();
    let object = zpl.resolve(cx, b"/keep.bin").unwrap();
    assert_eq!(zpl.read(cx, object, 0, expected.len()).unwrap(), expected);
}

fn removal_clean(cx: &Cx, mos: &mut ffs_zfs::Objects) {
    let scrub = mos.scrub(cx, ScrubLimits::default()).unwrap();
    assert!(scrub.is_clean(), "{:?}", scrub.issues);
    let allocation = mos.allocation(cx, AllocationLimits::default()).unwrap();
    assert_eq!(
        allocation.allocated_bytes + allocation.free_bytes,
        allocation.mapped_bytes
    );
    let scrub = mos
        .zpl(cx, &[])
        .unwrap()
        .scrub(cx, ScrubLimits::default())
        .unwrap();
    assert!(scrub.is_clean(), "{:?}", scrub.issues);
}

fn removal_seed(cx: &Cx, engine: &mut ZfsTransactionEngine) -> (u64, Vec<u8>) {
    let root = engine
        .open_read_objects(cx)
        .unwrap()
        .zpl(cx, &[])
        .unwrap()
        .resolve(cx, b"/")
        .unwrap();
    let timestamp = Timestamp {
        seconds: 1_735_014_000,
        nanos: 0,
    };
    let (file, _) = engine
        .create_file(
            cx,
            &[],
            root,
            b"keep.bin",
            0o600,
            0,
            0,
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    let payload: Vec<_> = (0..65_536)
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect();
    engine
        .write_file_data(
            cx,
            &[],
            file,
            0,
            &payload,
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    (file, payload)
}

#[test]
#[allow(clippy::too_many_lines)]
fn empty_vdev_removal_disconnects_shuffled_leaf_and_mirror_sources() {
    for (target_width, source_width) in [(1, 1), (2, 1), (1, 2), (2, 2)] {
        let cx = Cx::for_testing();
        let pool_guid =
            0x5245_4D4F_5645_1000 + u64::try_from(10 * target_width + source_width).unwrap();
        let devices = removal_devices(target_width + source_width);
        let kind = |width| {
            if width == 1 {
                ZfsCreateVdevKind::Leaf
            } else {
                ZfsCreateVdevKind::Mirror { width }
            }
        };
        let mut spec = ZfsPoolCreateSpec::single_leaf("empty_remove", pool_guid);
        spec.vdevs[0].kind = kind(target_width);
        spec.vdevs.push(ZfsCreateVdevSpec {
            kind: kind(source_width),
            alloc_class: AllocClass::Normal,
        });
        let created = create_pool_on_devices(&cx, removal_boxes(&devices), &spec).unwrap();
        let mut supplied = devices.clone();
        supplied.rotate_right(source_width);
        let mut engine = open_engine_on_devices(
            &cx,
            &supplied,
            default_write_opts(pool_guid, created.initial_slot),
        )
        .unwrap();
        let (file, payload) = removal_seed(&cx, &mut engine);
        let timestamp = Timestamp {
            seconds: 1_735_014_001,
            nanos: 0,
        };
        engine
            .create_snapshot(&cx, &[], b"before_remove", timestamp)
            .into_result()
            .unwrap();
        let source_before: Vec<_> = devices[target_width..]
            .iter()
            .map(FaultableMemberDevice::durable_snapshot)
            .collect();
        let io_before: Vec<_> = devices
            .iter()
            .map(|device| device.state.lock().unwrap().unprotected_io)
            .collect();

        let trace_start = engine.persistence_events().len();
        let (report, token) = engine
            .remove_vdev(&cx, 1, 0, &[])
            .into_result()
            .expect("authoritative-empty source removal");
        let events = &engine.persistence_events()[trace_start..];
        let final_label_barrier = events
            .iter()
            .rposition(|event| {
                matches!(event.stage, ZfsPersistenceStage::LabelConfigBarrier { .. })
            })
            .expect("successful removal must synchronize its survivor labels");
        let acknowledgement = events
            .iter()
            .position(|event| matches!(event.stage, ZfsPersistenceStage::AckPublished))
            .expect("successful removal must publish one acknowledgement");
        assert!(acknowledgement > final_label_barrier);
        assert_eq!(
            events
                .iter()
                .filter(|event| { matches!(event.stage, ZfsPersistenceStage::AckPublished) })
                .count(),
            1,
        );
        assert!(report.completed);
        assert_eq!(report.bytes_evacuated, 0);
        assert_eq!(report.extents_evacuated, 0);
        assert_eq!(report.indirect_mapping_object, 0);
        assert_eq!(report.indirect_births_object, 0);
        assert_eq!(engine.storage_identity().member_guids.len(), target_width);
        for (index, device) in devices.iter().enumerate() {
            let media = device.state.lock().unwrap();
            assert_eq!(media.protection_depth, 0);
            assert_eq!(media.unprotected_io, io_before[index]);
        }
        for (device, before) in devices[target_width..].iter().zip(source_before) {
            assert_eq!(
                device.durable_snapshot(),
                before,
                "source must not be rewritten"
            );
            // Physically remove all source contents. No old source handles or
            // cached metadata may be needed by any subsequent operation.
            device.state.lock().unwrap().durable.fill(0);
        }
        let survivors = &devices[..target_width];
        let mut pinned = removal_pool(&cx, survivors)
            .objects(&cx, 0, token.published_slot(), pool_guid)
            .unwrap();
        removal_read(&cx, &mut pinned, &payload);
        removal_clean(&cx, &mut pinned);
        let mut snapshot = pinned.zpl_snapshot(&cx, &[], b"before_remove").unwrap();
        let snapshot_file = snapshot.resolve(&cx, b"/keep.bin").unwrap();
        assert_eq!(
            snapshot.read(&cx, snapshot_file, 0, payload.len()).unwrap(),
            payload
        );
        let mut automatic = removal_pool(&cx, survivors)
            .import_objects(&cx, Some(pool_guid))
            .unwrap();
        removal_read(&cx, &mut automatic, &payload);

        // Continuing through the same owner and a fresh writable owner must
        // both retire ordinary native DVAs without any removed-vdev free path.
        let replacement = b"survivor-only-write";
        engine
            .write_file_data(
                &cx,
                &[],
                file,
                0,
                replacement,
                timestamp,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .unwrap();
        engine
            .truncate_file(
                &cx,
                &[],
                file,
                replacement.len() as u64,
                timestamp,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .unwrap();
        let mut restarted = open_engine_on_devices(
            &cx,
            survivors,
            default_write_opts(pool_guid, engine.committed_slot()),
        )
        .unwrap();
        removal_read(
            &cx,
            &mut restarted.open_read_objects(&cx).unwrap(),
            replacement,
        );
        restarted
            .destroy_snapshot(&cx, &[], b"before_remove", false)
            .into_result()
            .unwrap();
        let root = restarted
            .open_read_objects(&cx)
            .unwrap()
            .zpl(&cx, &[])
            .unwrap()
            .resolve(&cx, b"/")
            .unwrap();
        restarted
            .unlink_entry(&cx, &[], root, b"keep.bin", false, timestamp)
            .into_result()
            .unwrap();
        removal_clean(&cx, &mut restarted.open_read_objects(&cx).unwrap());
    }
}

#[test]
fn empty_vdev_removal_refuses_extent_claims_nontrailing_source_and_checkpoint_without_writes() {
    let cx = Cx::for_testing();
    let pool_guid = 0x5245_4D4F_5645_2000;
    let devices = removal_devices(3);
    let mut spec = ZfsPoolCreateSpec::single_leaf("refused_remove", pool_guid);
    spec.vdevs.extend((0..2).map(|_| ZfsCreateVdevSpec {
        kind: ZfsCreateVdevKind::Leaf,
        alloc_class: AllocClass::Normal,
    }));
    let created = create_pool_on_devices(&cx, removal_boxes(&devices), &spec).unwrap();
    let mut engine = open_engine_on_devices(
        &cx,
        &devices,
        default_write_opts(pool_guid, created.initial_slot),
    )
    .unwrap();
    let _ = removal_seed(&cx, &mut engine);
    let snapshots: Vec<_> = devices
        .iter()
        .map(FaultableMemberDevice::durable_snapshot)
        .collect();
    let writes: Vec<_> = devices
        .iter()
        .map(FaultableMemberDevice::write_calls)
        .collect();
    for (source, target, extents) in [
        (2, 0, vec![(0, 4096)]),
        (2, 0, vec![(0, 4096), (0, 4096)]),
        (2, 0, vec![(u64::MAX - 4095, 4096)]),
        (1, 0, vec![]),
        (0, 2, vec![]),
        (2, 2, vec![]),
    ] {
        assert!(
            engine
                .remove_vdev(&cx, source, target, &extents)
                .is_not_committed()
        );
    }
    for ((device, snapshot), writes) in devices.iter().zip(snapshots).zip(writes) {
        assert_eq!(device.durable_snapshot(), snapshot);
        assert_eq!(device.write_calls(), writes);
    }
    engine.checkpoint_create(&cx).into_result().unwrap();
    let snapshots: Vec<_> = devices
        .iter()
        .map(FaultableMemberDevice::durable_snapshot)
        .collect();
    let writes: Vec<_> = devices
        .iter()
        .map(FaultableMemberDevice::write_calls)
        .collect();
    assert!(engine.remove_vdev(&cx, 2, 0, &[]).is_not_committed());
    for ((device, snapshot), writes) in devices.iter().zip(snapshots).zip(writes) {
        assert_eq!(device.durable_snapshot(), snapshot);
        assert_eq!(device.write_calls(), writes);
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn empty_vdev_removal_cancellation_and_prepublication_failure_preserve_old_pool() {
    let cx = Cx::for_testing();
    let pool_guid = 0x5245_4D4F_5645_3000;
    let devices = removal_devices(2);
    let mut spec = ZfsPoolCreateSpec::single_leaf("cancel_remove", pool_guid);
    spec.vdevs.push(ZfsCreateVdevSpec {
        kind: ZfsCreateVdevKind::Leaf,
        alloc_class: AllocClass::Normal,
    });
    let created = create_pool_on_devices(&cx, removal_boxes(&devices), &spec).unwrap();
    let mut engine = open_engine_on_devices(
        &cx,
        &devices,
        default_write_opts(pool_guid, created.initial_slot),
    )
    .unwrap();
    let (_, payload) = removal_seed(&cx, &mut engine);
    let old_slot = engine.committed_slot();
    let snapshots: Vec<_> = devices
        .iter()
        .map(FaultableMemberDevice::durable_snapshot)
        .collect();
    let cancelled = Cx::for_testing();
    cancelled.cancel_with(asupersync::types::CancelKind::User, Some("before removal"));
    assert!(engine.remove_vdev(&cancelled, 1, 0, &[]).is_not_committed());
    for (device, snapshot) in devices.iter().zip(&snapshots) {
        assert_eq!(&device.durable_snapshot(), snapshot);
    }
    engine.with_fault_hook(|event| {
        if matches!(event.stage, ZfsPersistenceStage::MosSpaceMapBarrier { .. }) {
            return Err(FfsError::Cancelled);
        }
        Ok(())
    });
    assert!(matches!(
        engine.remove_vdev(&cx, 1, 0, &[]),
        ZfsTxOutcome::NotCommitted(FfsError::Cancelled)
    ));
    assert!(!engine.requires_recovery());
    assert_eq!(engine.committed_slot(), old_slot);
    assert_eq!(engine.storage_identity().member_guids.len(), 2);
    assert_eq!(devices[1].durable_snapshot(), snapshots[1]);
    for device in &devices {
        device.state.lock().unwrap().crash_drop_unsynced();
    }
    let mut old = removal_pool(&cx, &devices)
        .objects(&cx, 0, old_slot, pool_guid)
        .unwrap();
    removal_read(&cx, &mut old, &payload);
    removal_clean(&cx, &mut old);
    engine.clear_fault_hook();
    let (_, token) = engine.remove_vdev(&cx, 1, 0, &[]).into_result().unwrap();
    let mut after = removal_pool(&cx, &devices[..1])
        .objects(&cx, 0, token.published_slot(), pool_guid)
        .unwrap();
    removal_read(&cx, &mut after, &payload);
    removal_clean(&cx, &mut after);
}

#[test]
#[allow(clippy::too_many_lines)]
fn empty_vdev_removal_partial_label_publication_is_uncertain_and_poisons_owner() {
    let cx = Cx::for_testing();
    let pool_guid = 0x5245_4D4F_5645_4000;
    let devices = removal_devices(2);
    let mut spec = ZfsPoolCreateSpec::single_leaf("label_cut_remove", pool_guid);
    spec.vdevs.push(ZfsCreateVdevSpec {
        kind: ZfsCreateVdevKind::Leaf,
        alloc_class: AllocClass::Normal,
    });
    let created = create_pool_on_devices(&cx, removal_boxes(&devices), &spec).unwrap();
    let mut engine = open_engine_on_devices(
        &cx,
        &devices,
        default_write_opts(pool_guid, created.initial_slot),
    )
    .unwrap();
    let (file, payload) = removal_seed(&cx, &mut engine);
    let source = devices[1].durable_snapshot();
    let trace_start = engine.persistence_events().len();
    engine.with_fault_hook(|event| {
        if matches!(
            event.stage,
            ZfsPersistenceStage::LabelConfigWrite { label: 2, .. }
        ) {
            return Err(FfsError::Cancelled);
        }
        Ok(())
    });
    assert!(matches!(
        engine.remove_vdev(&cx, 1, 0, &[]),
        ZfsTxOutcome::Uncertain { .. }
    ));
    assert!(engine.requires_recovery());
    assert!(
        !engine.persistence_events()[trace_start..]
            .iter()
            .any(|event| {
                matches!(
                    event.stage,
                    ZfsPersistenceStage::BeforeAcknowledge | ZfsPersistenceStage::AckPublished
                )
            }),
        "a partial topology-label cohort must not acknowledge removal"
    );
    assert_eq!(devices[1].durable_snapshot(), source);
    let writes = devices[0].write_calls();
    engine.clear_fault_hook();
    assert!(
        engine
            .write_file_data(
                &cx,
                &[],
                file,
                0,
                b"must not write",
                Timestamp {
                    seconds: 1_735_014_002,
                    nanos: 0
                },
                ZfsDataChecksum::Fletcher4,
            )
            .is_not_committed()
    );
    assert_eq!(devices[0].write_calls(), writes);
    assert_eq!(devices[0].state.lock().unwrap().protection_depth, 0);

    // The source cannot be released on an uncertain outcome. Until generic
    // topology-cohort recovery exists, a partial survivor-label set may refuse
    // automatic import; any view that does open must preserve the acknowledged file.
    for device in &devices {
        device.state.lock().unwrap().crash_drop_unsynced();
    }
    for members in [&devices[..], &devices[..1]] {
        if let Ok(mut recovered) = removal_pool(&cx, members).import_objects(&cx, Some(pool_guid)) {
            removal_read(&cx, &mut recovered, &payload);
        }
    }
    assert_eq!(devices[1].durable_snapshot(), source);
}
