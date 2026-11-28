//! Native OpenZFS `zfs-2.4.0` advanced topology integration & fault-cut tests:
//! - dRAID1/2/3 creation, native COW writes, cross-row reads, distributed spare
//!   resolution, and read-only degraded survivor erasure recovery (`1..=nparity`).
//! - Resumable RAIDZ1/2/3 width expansion (`org.openzfs:raidz_expansion`) with
//!   chunked reflow, `ub_raidz_reflow_info` persistence, and crash cuts.
//! - Unallocated removal-extent refusal and native indirect mapping split/cycle
//!   resolution. Empty-vdev lifecycle coverage lives in `removal.rs`.
//! - Allocation classes (`special`, `log`, `spares`), `l2cache` isolation, and
//!   fail-closed missing required `special`/`dedup` class refusal.
//! - OpenZFS `zfs-2.4.0` feature manifest enforcement (`dynamic_gang_header`,
//!   `com.oracle:*`, versions `29..=4999` refused without mutation).

use super::*;
use ffs_ondisk::zfs::draid::DraidConfig;
use ffs_ondisk::zfs::features::{
    OPENZFS_PINNED_RELEASE, PoolVersionProfile, classify_pool_version, is_oracle_feature,
    is_supported_label_feature,
};
use ffs_ondisk::zfs::indirect::{
    IndirectBirthEntry, IndirectBirthsPhys, IndirectMappingEntry, IndirectMappingPhys,
    IndirectMappingTable, resolve_indirect_recursive,
};
use ffs_ondisk::zfs::nvlist::Value as NvValue;
use ffs_zfs::{
    AllocClass, IndirectVdevMap, PoolTopology, ZfsCreateVdevKind, ZfsCreateVdevSpec,
    ZfsPoolCreateSpec, create_pool_on_devices,
};

fn blank_devs(count: usize, size_bytes: u64) -> Vec<FaultableMemberDevice> {
    (0..count)
        .map(|_| FaultableMemberDevice::new(vec![0_u8; usize::try_from(size_bytes).unwrap()]))
        .collect()
}

fn boxed_devs(devs: &[FaultableMemberDevice]) -> Vec<Box<dyn ByteDevice>> {
    devs.iter()
        .cloned()
        .map(|d| Box::new(d) as Box<dyn ByteDevice>)
        .collect()
}

fn leaves_from_devs(cx: &Cx, devs: &[FaultableMemberDevice]) -> Vec<Leaf> {
    devs.iter()
        .cloned()
        .map(|d| {
            let len = d.len_bytes();
            Leaf::from_device(cx, Box::new(d), 0, len).unwrap()
        })
        .collect()
}

fn open_wide_engine(
    cx: &Cx,
    devs: &[FaultableMemberDevice],
    pool_guid: u64,
    slot: usize,
) -> Result<ZfsTransactionEngine> {
    ZfsTransactionEngine::from_devices(cx, boxed_devs(devs), default_write_opts(pool_guid, slot))
}

fn read_zpl_file(
    cx: &Cx,
    mos: &mut ffs_zfs::Objects,
    dataset: &[Vec<u8>],
    path: &[u8],
    len: usize,
) -> Result<Vec<u8>> {
    let mut zpl = mos.zpl(cx, dataset)?;
    let obj = zpl.resolve(cx, path)?;
    zpl.read(cx, obj, 0, len)
}

fn routing_fixture(
    cx: &Cx,
    pool_guid: u64,
    kinds: Vec<ZfsCreateVdevKind>,
) -> (Vec<FaultableMemberDevice>, ffs_zfs::ZfsPoolCreateReport) {
    let members = kinds
        .iter()
        .map(|kind| match kind {
            ZfsCreateVdevKind::Leaf => 1,
            ZfsCreateVdevKind::Mirror { width } | ZfsCreateVdevKind::Raidz { width, .. } => *width,
            ZfsCreateVdevKind::Draid { children, .. } => *children,
        })
        .sum();
    let devs = blank_devs(members, 12 * 1024 * 1024);
    let spec = ZfsPoolCreateSpec {
        pool_name: "native_routes".to_owned(),
        pool_guid,
        ashift: 12,
        hostid: 0x4646_5331,
        hostname: "frankenfs-test".to_owned(),
        vdevs: kinds
            .into_iter()
            .map(|kind| ZfsCreateVdevSpec {
                kind,
                alloc_class: AllocClass::Normal,
            })
            .collect(),
        spare_count: 0,
        exported: true,
    };
    let report = create_pool_on_devices(cx, boxed_devs(&devs), &spec).unwrap();
    (devs, report)
}

fn routing_payload() -> Vec<u8> {
    let mut state = 0xFEED_BEEF_0123_4567_u64;
    (0..196_781)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect()
}

fn create_routing_file(cx: &Cx, engine: &mut ZfsTransactionEngine, payload: &[u8]) -> (u64, usize) {
    let ts = Timestamp {
        seconds: 1_735_020_000,
        nanos: 0,
    };
    let (file, _) = engine
        .create_file(
            cx,
            &[],
            5,
            b"route.bin",
            0o644,
            0,
            0,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .expect("create file through native member routing");
    let (_, token) = engine
        .write_file_data(cx, &[], file, 0, payload, ts, ZfsDataChecksum::Fletcher4)
        .into_result()
        .expect("write through native member routing");
    (file, token.published_slot())
}

fn assert_routing_file(
    cx: &Cx,
    devs: &[FaultableMemberDevice],
    pool_guid: u64,
    slot: usize,
    payload: &[u8],
) {
    let pool = Pool::from_wide_leaves(leaves_from_devs(cx, devs)).unwrap();
    let mut mos = pool.objects(cx, 0, slot, pool_guid).unwrap();
    assert_eq!(
        read_zpl_file(cx, &mut mos, &[], b"/route.bin", payload.len()).unwrap(),
        payload
    );
}

#[test]
fn shuffled_native_members_preserve_raidz_and_draid_writes_after_reopen() {
    let cx = Cx::for_testing();
    for parity in 1..=3 {
        for kind in [
            ZfsCreateVdevKind::Raidz {
                parity,
                width: parity + 2,
            },
            ZfsCreateVdevKind::Draid {
                ndata: 2,
                nparity: parity,
                children: parity + 3,
                nspares: 1,
                ngroups: 1,
            },
        ] {
            let pool_guid = 0xA110_C011_0000_0000 + u64::try_from(parity).unwrap();
            let (devs, report) = routing_fixture(&cx, pool_guid, vec![kind]);
            let mut supplied = devs.clone();
            supplied.rotate_right(1);
            let mut duplicate = supplied.clone();
            duplicate[0] = duplicate[1].clone();
            let calls: Vec<_> = devs
                .iter()
                .map(FaultableMemberDevice::write_calls)
                .collect();
            assert!(open_wide_engine(&cx, &duplicate, pool_guid, report.initial_slot).is_err());
            assert_eq!(
                devs.iter()
                    .map(FaultableMemberDevice::write_calls)
                    .collect::<Vec<_>>(),
                calls,
                "duplicate or missing native members must fail before writing"
            );
            let mut engine = open_wide_engine(&cx, &supplied, pool_guid, report.initial_slot)
                .expect("shuffled native children must admit writes");
            let mut payload = routing_payload();
            let (file, slot) = create_routing_file(&cx, &mut engine, &payload);
            drop(engine);

            // Fresh devices retain only durable bytes, then reopen in a different order.
            let durable: Vec<_> = devs
                .iter()
                .map(FaultableMemberDevice::fresh_from_durable)
                .collect();
            assert_routing_file(&cx, &durable, pool_guid, slot, &payload);
            let mut reopened = open_wide_engine(&cx, &durable, pool_guid, slot).unwrap();
            let patch = vec![0x63; 8_193];
            let (_, token) = reopened
                .write_file_data(
                    &cx,
                    &[],
                    file,
                    4_093,
                    &patch,
                    Timestamp {
                        seconds: 1_735_020_001,
                        nanos: 0,
                    },
                    ZfsDataChecksum::Fletcher4,
                )
                .into_result()
                .unwrap();
            payload[4_093..4_093 + patch.len()].copy_from_slice(&patch);
            let mut reversed = durable;
            reversed.reverse();
            assert_routing_file(&cx, &reversed, pool_guid, token.published_slot(), &payload);
        }
    }
}

#[test]
fn shuffled_multivdev_writes_preserve_unselected_devices() {
    let cx = Cx::for_testing();
    for kind in [
        ZfsCreateVdevKind::Leaf,
        ZfsCreateVdevKind::Mirror { width: 2 },
        ZfsCreateVdevKind::Raidz {
            parity: 1,
            width: 3,
        },
        ZfsCreateVdevKind::Draid {
            ndata: 2,
            nparity: 1,
            children: 4,
            nspares: 1,
            ngroups: 1,
        },
    ] {
        let pool_guid = 0xA110_C011_0000_0020;
        let (devs, report) = routing_fixture(&cx, pool_guid, vec![kind, ZfsCreateVdevKind::Leaf]);
        let unselected = devs.last().unwrap();
        let before = unselected.durable_snapshot();
        let mut supplied = devs.clone();
        supplied.reverse();
        let mut engine = open_wide_engine(&cx, &supplied, pool_guid, report.initial_slot)
            .expect("shuffled multi-vdev writer");
        let payload = routing_payload();
        let (_, slot) = create_routing_file(&cx, &mut engine, &payload);
        assert_routing_file(&cx, &devs, pool_guid, slot, &payload);
        let data = usize::try_from(DATA_OFFSET).unwrap()
            ..before.len() - usize::try_from(2 * LABEL_BYTES).unwrap();
        assert_eq!(
            &unselected.durable_snapshot()[data.clone()],
            &before[data],
            "allocator writes must never reach another top-level vdev's data area"
        );

        // Replacement cannot publish a multi-vdev topology yet: refuse before copying.
        let calls: Vec<_> = devs
            .iter()
            .map(FaultableMemberDevice::write_calls)
            .collect();
        let replacement = blank_devs(1, 12 * 1024 * 1024).pop().unwrap();
        let leaf = leaves_from_devs(&cx, std::slice::from_ref(&replacement))
            .pop()
            .unwrap();
        assert!(engine.replace_member(&cx, 0, leaf).is_not_committed());
        assert_eq!(replacement.write_calls(), 0);
        assert_eq!(
            devs.iter()
                .map(FaultableMemberDevice::write_calls)
                .collect::<Vec<_>>(),
            calls
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn shuffled_member_replacement_preserves_native_columns_and_child_guids() {
    let cx = Cx::for_testing();
    for kind in [
        ZfsCreateVdevKind::Mirror { width: 2 },
        ZfsCreateVdevKind::Raidz {
            parity: 1,
            width: 3,
        },
        ZfsCreateVdevKind::Draid {
            ndata: 2,
            nparity: 1,
            children: 4,
            nspares: 1,
            ngroups: 1,
        },
    ] {
        let is_mirror = matches!(kind, ZfsCreateVdevKind::Mirror { .. });
        let pool_guid = 0xA110_C011_0000_0040;
        let (mut devs, report) = routing_fixture(&cx, pool_guid, vec![kind]);
        let mut supplied = devs.clone();
        supplied.reverse();
        let mut engine = open_wide_engine(&cx, &supplied, pool_guid, report.initial_slot).unwrap();
        let payload = routing_payload();
        create_routing_file(&cx, &mut engine, &payload);
        let source = supplied[0].durable_snapshot();
        let data = usize::try_from(DATA_OFFSET).unwrap()
            ..source.len() - usize::try_from(2 * LABEL_BYTES).unwrap();
        if !is_mirror {
            assert_ne!(
                &source[data.clone()],
                &supplied[1].durable_snapshot()[data.clone()],
                "parity siblings must contain distinct columns in this regression"
            );
        }
        let replacement = blank_devs(1, 12 * 1024 * 1024).pop().unwrap();
        engine.with_fault_hook(|event| {
            if matches!(
                event.stage,
                ZfsPersistenceStage::ChildBlocksWrite { .. }
                    | ZfsPersistenceStage::DatasetMetadataWrite { .. }
                    | ZfsPersistenceStage::MosSpaceMapWrite { .. }
                    | ZfsPersistenceStage::MosRootWrite { .. }
            ) {
                return Err(FfsError::Io(std::io::Error::other(
                    "stop after member copy, before first staged write",
                )));
            }
            Ok(())
        });
        let leaf = leaves_from_devs(&cx, std::slice::from_ref(&replacement))
            .pop()
            .unwrap();
        assert!(engine.replace_member(&cx, 0, leaf).is_not_committed());
        assert_eq!(
            &replacement.durable_snapshot()[data.clone()],
            &source[data],
            "replacement must retain the selected native column, not a parity sibling"
        );

        engine.with_fault_hook(|_| Ok(()));
        let leaf = leaves_from_devs(&cx, std::slice::from_ref(&replacement))
            .pop()
            .unwrap();
        let (_, token) = engine.replace_member(&cx, 0, leaf).into_result().unwrap();
        let target = devs.len() - 1;
        devs[target] = replacement;
        let durable: Vec<_> = devs
            .iter()
            .map(FaultableMemberDevice::fresh_from_durable)
            .collect();
        assert_routing_file(&cx, &durable, pool_guid, token.published_slot(), &payload);
        open_wide_engine(&cx, &durable, pool_guid, token.published_slot())
            .expect("replacement must leave a complete native GUID topology");
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn draid1_draid2_draid3_create_write_read_and_degraded_erasure_recovery() {
    let cx = Cx::for_testing();
    let ts = Timestamp {
        seconds: 1_735_000_000,
        nanos: 0,
    };

    for (nparity, children, ndata, nspares, pool_guid) in [
        (
            1_usize,
            4_usize,
            2_usize,
            1_usize,
            0xD0A1_D001_0000_0001_u64,
        ),
        (
            2_usize,
            5_usize,
            2_usize,
            1_usize,
            0xD0A1_D002_0000_0002_u64,
        ),
        (
            3_usize,
            6_usize,
            2_usize,
            1_usize,
            0xD0A1_D003_0000_0003_u64,
        ),
    ] {
        let devs = blank_devs(children, 12 * 1024 * 1024);
        let spec = ZfsPoolCreateSpec {
            pool_name: format!("draid{nparity}_pool"),
            pool_guid,
            ashift: 12,
            hostid: 0x4646_5331,
            hostname: "frankenfs-test".to_owned(),
            vdevs: vec![ZfsCreateVdevSpec {
                kind: ZfsCreateVdevKind::Draid {
                    ndata,
                    nparity,
                    children,
                    nspares,
                    ngroups: 1,
                },
                alloc_class: AllocClass::Normal,
            }],
            spare_count: 0,
            exported: true,
        };
        let report = create_pool_on_devices(&cx, boxed_devs(&devs), &spec)
            .expect("dRAID pool creation must succeed");
        assert_eq!(report.member_count, children);
        assert_eq!(report.pool_guid, pool_guid);

        // Verify distributed spare mapping is valid across permutation rows.
        let cfg = DraidConfig::new(children, ndata, nparity, nspares, 1, 12).unwrap();
        let spare0 = cfg.spare_child_id(0, 0).unwrap();
        assert!(spare0 < children);

        // Open native TXG writer on the dRAID pool and commit a multi-block file!
        let mut engine = open_wide_engine(&cx, &devs, pool_guid, report.initial_slot)
            .expect("open dRAID writer");
        let (file_obj, _) = engine
            .create_file(
                &cx,
                &[],
                5,
                b"draid_data.bin",
                0o644,
                0,
                0,
                ts,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .expect("create file on dRAID");
        let payload: Vec<u8> = (0..(24 * 1024))
            .map(|i| u8::try_from((i * 17 + nparity * 31) & 0xFF).unwrap())
            .collect();
        let (_, tok) = engine
            .write_file_data(
                &cx,
                &[],
                file_obj,
                0,
                &payload,
                ts,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .expect("write multi-block file on dRAID");
        let final_slot = tok.published_slot();

        // Full-complement readback must match bit-for-bit!
        let pool = Pool::from_wide_leaves(leaves_from_devs(&cx, &devs)).unwrap();
        let mut mos = pool.objects(&cx, 0, final_slot, pool_guid).unwrap();
        let read_back =
            read_zpl_file(&cx, &mut mos, &[], b"/draid_data.bin", payload.len()).unwrap();
        assert_eq!(read_back, payload);

        // Extract physical child GUIDs from label 0 of each member.
        let child_guids: Vec<u64> = leaves_from_devs(&cx, &devs)
            .iter()
            .map(|l| l.label(&cx, 0).unwrap().config.unsigned("guid").unwrap())
            .collect();

        // Drop `nparity` members simultaneously and verify read-only dRAID erasure recovery!
        let survivor_leaves = leaves_from_devs(&cx, &devs[nparity..]);
        let missing_guids: Vec<u64> = child_guids[..nparity].to_vec();
        let degraded = Pool::from_draid_survivors(&cx, survivor_leaves, missing_guids)
            .expect("dRAID survivor pool with nparity missing must open RO");
        let mut deg_mos = degraded.objects(&cx, 0, final_slot, pool_guid).unwrap();
        let recovered = read_zpl_file(&cx, &mut deg_mos, &[], b"/draid_data.bin", payload.len())
            .expect("dRAID P/Q/R erasure recovery must reconstruct payload");
        assert_eq!(
            recovered, payload,
            "dRAID{nparity} degraded recovery payload mismatch"
        );

        // Negative control 1: exceeding parity (`nparity + 1` missing) MUST fail closed!
        if nparity + 1 < children {
            let too_few_leaves = leaves_from_devs(&cx, &devs[nparity + 1..]);
            let too_many_missing: Vec<u64> = child_guids[..=nparity].to_vec();
            let err = Pool::from_draid_survivors(&cx, too_few_leaves, too_many_missing)
                .and_then(|p| p.objects(&cx, 0, final_slot, pool_guid));
            assert!(
                err.is_err(),
                "dRAID{nparity} with {} missing members must fail closed",
                nparity + 1
            );
        }

        // Negative control 2: native writer MUST NEVER admit a degraded dRAID pool!
        assert!(
            open_wide_engine(&cx, &devs[1..], pool_guid, final_slot).is_err(),
            "native writer must refuse degraded dRAID member set"
        );
    }

    // Pre-I/O check_draid_survivors validation controls.
    assert!(Pool::check_draid_survivors(3, &[0]).is_err());
    assert!(Pool::check_draid_survivors(3, &[11, 11]).is_err());
    assert!(Pool::check_draid_survivors(3, &[11, 12, 13, 14]).is_err());
}

fn expansion_leaf(cx: &Cx, device: &FaultableMemberDevice) -> Leaf {
    Leaf::from_device(cx, Box::new(device.clone()), 0, device.len_bytes()).unwrap()
}

fn durable_expansion_devices(devices: &[FaultableMemberDevice]) -> Vec<FaultableMemberDevice> {
    devices
        .iter()
        .map(|device| FaultableMemberDevice::new(device.durable_snapshot()))
        .collect()
}

fn reopen_expansion(
    cx: &Cx,
    devices: &[FaultableMemberDevice],
    pool_guid: u64,
    target_slot: usize,
    previous_slot: usize,
) -> ZfsTransactionEngine {
    let calls: Vec<_> = devices
        .iter()
        .map(FaultableMemberDevice::write_calls)
        .collect();
    let mut options = default_write_opts(pool_guid, target_slot);
    options.reconcile_torn_uberblocks = true;
    match ZfsTransactionEngine::from_devices(cx, boxed_devs(devices), options) {
        Ok(engine) => engine,
        Err(error) if target_slot != previous_slot => {
            assert_eq!(
                devices
                    .iter()
                    .map(FaultableMemberDevice::write_calls)
                    .collect::<Vec<_>>(),
                calls,
                "failed successor admission must remain read-only: {error}",
            );
            options.slot = previous_slot;
            ZfsTransactionEngine::from_devices(cx, boxed_devs(devices), options)
                .expect("reopen the proven predecessor when no successor survived")
        }
        Err(error) => panic!("reopen expansion authority: {error}"),
    }
}

fn expansion_is_active(cx: &Cx, engine: &ZfsTransactionEngine) -> bool {
    let mut mos = engine.open_read_objects(cx).unwrap();
    let config = mos.load_mos_config_nvlist(cx).unwrap();
    let Some(NvValue::Lists(tops)) = config.list("vdev_tree").unwrap().fields.get("children")
    else {
        panic!("native expansion top-level array");
    };
    tops[0].fields.contains_key("raidz_expanding")
}

fn finish_expansion(
    cx: &Cx,
    engine: &mut ZfsTransactionEngine,
    new_disk: &FaultableMemberDevice,
) -> usize {
    for _ in 0..512 {
        if !expansion_is_active(cx, engine) {
            return engine.committed_slot();
        }
        let (report, token) = engine
            .expand_raidz(cx, expansion_leaf(cx, new_disk), 65_536, 1)
            .into_result()
            .expect("resume bounded native reflow");
        assert!(report.chunks_processed <= 1);
        if report.completed {
            assert!(!expansion_is_active(cx, engine));
            return token.published_slot();
        }
    }
    panic!("bounded native reflow did not finish");
}

#[test]
#[allow(clippy::too_many_lines)]
fn raidz_expansion_resumable_chunked_reflow_and_fault_cut_safety() {
    let cx = Cx::for_testing();
    let ts = Timestamp {
        seconds: 1_735_001_000,
        nanos: 0,
    };
    for parity in 1..=3_usize {
        let old_width = parity + 2;
        let pool_guid = 0x5241_4944_5A45_5800_u64 + parity as u64;
        let (devs, created) = routing_fixture(
            &cx,
            pool_guid,
            vec![ZfsCreateVdevKind::Raidz {
                parity,
                width: old_width,
            }],
        );
        let mut supplied = devs.clone();
        supplied.rotate_right(1);
        let mut engine = open_wide_engine(&cx, &supplied, pool_guid, created.initial_slot).unwrap();
        let original = routing_payload();
        let (file, _) = create_routing_file(&cx, &mut engine, &original);
        engine
            .create_snapshot(&cx, &[], b"before_expand", ts)
            .into_result()
            .unwrap();
        let current: Vec<_> = original.iter().map(|byte| byte ^ 0xA7).collect();
        engine
            .write_file_data(&cx, &[], file, 0, &current, ts, ZfsDataChecksum::Fletcher4)
            .into_result()
            .unwrap();

        let calls: Vec<_> = devs
            .iter()
            .map(FaultableMemberDevice::write_calls)
            .collect();
        let tiny = FaultableMemberDevice::new(vec![0; 6 * 1024 * 1024]);
        assert!(
            engine
                .expand_raidz(&cx, expansion_leaf(&cx, &tiny), 65_536, 1)
                .is_not_committed()
        );
        assert_eq!(tiny.write_calls(), 0);
        assert_eq!(
            devs.iter()
                .map(FaultableMemberDevice::write_calls)
                .collect::<Vec<_>>(),
            calls
        );

        let free_before = engine.free_bytes();
        let new_disk = FaultableMemberDevice::new(vec![0; 12 * 1024 * 1024]);
        let (bootstrap, token) = engine
            .expand_raidz(&cx, expansion_leaf(&cx, &new_disk), 65_536, 1)
            .into_result()
            .expect("publish active first-expansion topology");
        assert_eq!(
            (bootstrap.old_width, bootstrap.new_width, bootstrap.parity),
            (old_width, old_width + 1, parity)
        );
        assert_eq!(bootstrap.chunks_processed, 0);
        assert!(!bootstrap.completed);
        let bootstrap_slot = token.published_slot();
        let mut all = devs;
        all.push(new_disk);
        let calls: Vec<_> = all.iter().map(FaultableMemberDevice::write_calls).collect();
        assert!(
            engine
                .write_file_data(
                    &cx,
                    &[],
                    file,
                    0,
                    b"must wait",
                    ts,
                    ZfsDataChecksum::Fletcher4,
                )
                .is_not_committed(),
            "foreground TXG must not change the scratch source"
        );
        assert_eq!(
            all.iter()
                .map(FaultableMemberDevice::write_calls)
                .collect::<Vec<_>>(),
            calls
        );
        let replacement = FaultableMemberDevice::new(vec![0; 12 * 1024 * 1024]);
        assert!(
            engine
                .replace_member(&cx, 0, expansion_leaf(&cx, &replacement),)
                .is_not_committed(),
            "replacement cannot omit active native scratch authority"
        );
        assert_eq!(
            replacement.write_calls(),
            0,
            "active expansion refusal must precede the physical member copy"
        );
        assert!(
            engine
                .scrub_start(&cx, ffs_zfs::ZfsScanLimits::default(),)
                .is_not_committed(),
            "scan repair must pause before physical healing"
        );
        assert_eq!(
            all.iter()
                .map(FaultableMemberDevice::write_calls)
                .collect::<Vec<_>>(),
            calls
        );

        let (progress, _) = engine
            .expand_raidz(&cx, expansion_leaf(&cx, &all[old_width]), 65_536, 1)
            .into_result()
            .unwrap();
        assert_eq!(progress.chunks_processed, 1);
        assert!(!progress.completed);
        drop(engine);
        // Reopen loses only harmless phase-local progress. All current and
        // snapshot-owned bytes remain reachable from the selected native root.
        let durable = durable_expansion_devices(&all);
        let mut shuffled = durable.clone();
        shuffled.rotate_left(2);
        let mut engine =
            reopen_expansion(&cx, &shuffled, pool_guid, bootstrap_slot, bootstrap_slot);
        let mut mos = engine.open_read_objects(&cx).unwrap();
        assert_eq!(
            read_zpl_file(&cx, &mut mos, &[], b"/route.bin", current.len()).unwrap(),
            current
        );
        let final_slot = finish_expansion(&cx, &mut engine, &durable[old_width]);
        assert!(
            engine.free_bytes() > free_before,
            "completed expansion must add allocatable capacity"
        );
        let acknowledgement = engine
            .persistence_events()
            .iter()
            .find(|event| {
                event.operation == "zfs_pool_expand_raidz_complete"
                    && event.stage == ZfsPersistenceStage::AckPublished
            })
            .expect("completion acknowledgement");
        let last_label_barrier = engine
            .persistence_events()
            .iter()
            .filter(|event| {
                event.txg == acknowledgement.txg
                    && matches!(event.stage, ZfsPersistenceStage::LabelConfigBarrier { .. })
            })
            .map(|event| event.seq)
            .max()
            .unwrap();
        assert!(
            last_label_barrier < acknowledgement.seq,
            "topology acknowledgement follows every configuration barrier"
        );

        let durable = durable_expansion_devices(&durable);
        let mut shuffled = durable.clone();
        shuffled.reverse();
        let mut engine = reopen_expansion(&cx, &shuffled, pool_guid, final_slot, final_slot);
        assert!(!expansion_is_active(&cx, &engine));
        let mut mos = engine.open_read_objects(&cx).unwrap();
        assert_eq!(
            read_zpl_file(&cx, &mut mos, &[], b"/route.bin", current.len()).unwrap(),
            current
        );

        // The overwritten version is owned only by a snapshot. A head-only
        // block walk cannot find it, but raw allocated-prefix reflow preserves it.
        engine
            .create_clone(&cx, &[], b"before_expand", &[], b"recovered", &[], ts)
            .into_result()
            .expect("post-expansion clone reads snapshot metadata");
        let mut mos = engine.open_read_objects(&cx).unwrap();
        assert_eq!(
            read_zpl_file(
                &cx,
                &mut mos,
                &[b"recovered".to_vec()],
                b"/route.bin",
                original.len(),
            )
            .unwrap(),
            original
        );

        let updated: Vec<_> = current.iter().map(|byte| byte.wrapping_add(11)).collect();
        engine
            .write_file_data(&cx, &[], file, 0, &updated, ts, ZfsDataChecksum::Fletcher4)
            .into_result()
            .expect("new-width foreground COW after expansion");
        let mut mos = engine.open_read_objects(&cx).unwrap();
        assert_eq!(
            read_zpl_file(&cx, &mut mos, &[], b"/route.bin", updated.len()).unwrap(),
            updated
        );
    }
}

#[test]
fn raidz_expansion_refuses_checkpoint_before_touching_scratch_or_new_member() {
    let cx = Cx::for_testing();
    let pool_guid = 0x5241_4944_4348_4B50_u64;
    let (devs, created) = routing_fixture(
        &cx,
        pool_guid,
        vec![ZfsCreateVdevKind::Raidz {
            parity: 1,
            width: 3,
        }],
    );
    let mut engine = open_wide_engine(&cx, &devs, pool_guid, created.initial_slot).unwrap();
    create_routing_file(&cx, &mut engine, &routing_payload());
    engine.checkpoint_create(&cx).into_result().unwrap();
    let calls: Vec<_> = devs
        .iter()
        .map(FaultableMemberDevice::write_calls)
        .collect();
    let new_disk = FaultableMemberDevice::new(vec![0; 12 * 1024 * 1024]);
    assert!(
        engine
            .expand_raidz(&cx, expansion_leaf(&cx, &new_disk), 65_536, 1,)
            .is_not_committed()
    );
    assert_eq!(new_disk.write_calls(), 0);
    assert_eq!(
        devs.iter()
            .map(FaultableMemberDevice::write_calls)
            .collect::<Vec<_>>(),
        calls
    );
}

struct ExpansionLabelReadFailure {
    inner: FaultableMemberDevice,
    remaining: std::sync::atomic::AtomicUsize,
    failure_bytes: usize,
    cancelled: bool,
}

impl ByteDevice for ExpansionLabelReadFailure {
    fn len_bytes(&self) -> u64 {
        self.inner.len_bytes()
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, bytes: &mut [u8]) -> Result<()> {
        if bytes.len() == self.failure_bytes
            && self
                .remaining
                .fetch_update(
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst,
                    |remaining| remaining.checked_sub(1),
                )
                .is_ok()
        {
            return Err(if self.cancelled {
                FfsError::Cancelled
            } else {
                FfsError::Io(std::io::Error::other(
                    "injected new-child label read failure",
                ))
            });
        }
        self.inner.read_exact_at(cx, offset, bytes)
    }

    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, bytes: &[u8]) -> Result<()> {
        self.inner.write_all_at(cx, offset, bytes)
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        self.inner.sync(cx)
    }

    fn begin_durability_commit(&self, cx: &Cx) -> Result<()> {
        self.inner.begin_durability_commit(cx)
    }

    fn complete_durability_commit(&self) {
        self.inner.complete_durability_commit();
    }

    fn abort_durability_commit(&self) {
        self.inner.abort_durability_commit();
    }
}

#[test]
fn raidz_expansion_new_child_requires_readable_native_ownership_evidence() {
    let cx = Cx::for_testing();
    let pool_guid = 0x5241_4944_4C41_424C_u64;
    let (devices, created) = routing_fixture(
        &cx,
        pool_guid,
        vec![ZfsCreateVdevKind::Raidz {
            parity: 1,
            width: 3,
        }],
    );
    let mut engine = open_wide_engine(&cx, &devices, pool_guid, created.initial_slot).unwrap();
    let calls: Vec<_> = devices
        .iter()
        .map(FaultableMemberDevice::write_calls)
        .collect();

    for (cancelled, failure_bytes) in [
        (false, LABEL_CONFIG_BYTES),
        (true, LABEL_CONFIG_BYTES),
        (false, UBERBLOCK_RING_BYTES),
        (true, UBERBLOCK_RING_BYTES),
    ] {
        // Configuration or ring reads fail transiently on an existing member.
        // Treating those failures as empty labels would overwrite its identity
        // as soon as writes and subsequent reads recover.
        let foreign = FaultableMemberDevice::new(devices[0].durable_snapshot());
        let len = foreign.len_bytes();
        let leaf = Leaf::from_device(
            &cx,
            Box::new(ExpansionLabelReadFailure {
                inner: foreign.clone(),
                remaining: std::sync::atomic::AtomicUsize::new(4),
                failure_bytes,
                cancelled,
            }),
            0,
            len,
        )
        .unwrap();
        let outcome = engine.expand_raidz(&cx, leaf, 65_536, 1);
        if cancelled {
            assert!(matches!(
                outcome,
                ZfsTxOutcome::NotCommitted(FfsError::Cancelled)
            ));
        } else {
            assert!(matches!(
                outcome,
                ZfsTxOutcome::NotCommitted(FfsError::Io(_))
            ));
        }
        assert_eq!(foreign.write_calls(), 0);
    }

    for checksum_valid in [false, true] {
        let mut bytes = vec![0_u8; 12 * 1024 * 1024];
        let offset = label_offsets(bytes.len() as u64).unwrap()[2] + LABEL_CONFIG_OFFSET;
        let start = offset as usize;
        let raw = &mut bytes[start..start + LABEL_CONFIG_BYTES];
        if checksum_valid {
            // A checksum-valid empty nvlist is malformed native metadata, not
            // evidence that the device is blank and can be overwritten.
            let packed = ffs_ondisk::zfs::nvlist::NvList {
                fields: BTreeMap::new(),
            }
            .encode_xdr()
            .unwrap();
            raw[..packed.len()].copy_from_slice(&packed);
            stamp_label_checksum(raw, offset, Endian::Little).unwrap();
        } else {
            raw[0] = 0xA5;
        }
        let unknown = FaultableMemberDevice::new(bytes);
        assert!(
            engine
                .expand_raidz(&cx, expansion_leaf(&cx, &unknown), 65_536, 1,)
                .is_not_committed()
        );
        assert_eq!(unknown.write_calls(), 0);
    }
    assert_eq!(
        devices
            .iter()
            .map(FaultableMemberDevice::write_calls)
            .collect::<Vec<_>>(),
        calls
    );
}

#[test]
fn raidz_expansion_rejects_uberblock_evidence_on_an_unlabeled_new_child() {
    let cx = Cx::for_testing();
    let pool_guid = 0x5241_4944_5249_4E47_u64;
    let (devices, created) = routing_fixture(
        &cx,
        pool_guid,
        vec![ZfsCreateVdevKind::Raidz {
            parity: 1,
            width: 3,
        }],
    );
    let mut engine = open_wide_engine(&cx, &devices, pool_guid, created.initial_slot).unwrap();
    let calls: Vec<_> = devices
        .iter()
        .map(FaultableMemberDevice::write_calls)
        .collect();
    let foreign = devices[0].durable_snapshot();
    let source = expansion_leaf(&cx, &devices[0]);
    let offsets = label_offsets(foreign.len() as u64).unwrap();
    for (index, offset) in offsets.into_iter().enumerate() {
        let label = source.label(&cx, index).unwrap();
        source
            .uberblock(&cx, &label, created.initial_slot)
            .expect("fixture has a verified foreign uberblock in each ring");
        let start = (offset + UBERBLOCK_RING_OFFSET) as usize;
        let end = start + UBERBLOCK_RING_BYTES;
        let mut bytes = vec![0_u8; foreign.len()];
        bytes[start..end].copy_from_slice(&foreign[start..end]);
        let candidate = FaultableMemberDevice::new(bytes);
        assert!(
            engine
                .expand_raidz(&cx, expansion_leaf(&cx, &candidate), 65_536, 1,)
                .is_not_committed(),
            "zero configs cannot hide existing uberblocks in ring {index}"
        );
        assert_eq!(candidate.write_calls(), 0);
    }
    assert_eq!(
        devices
            .iter()
            .map(FaultableMemberDevice::write_calls)
            .collect::<Vec<_>>(),
        calls
    );
}

#[derive(Debug, Clone, Copy)]
enum ExpansionCrashCut {
    ScratchWrite,
    ScratchBarrier,
    ScratchAuthorityWrite,
    ScratchAuthorityBarrier,
    CopyWrite,
    CopyBarrier,
    CopyCancelled,
    DataAuthorityWrite,
    DataAuthorityBarrier,
    CompletionRootBarrier,
    CompletionRootCancelled,
    CompletionUberblockBarrier,
    CompletionLabelWrite,
    CompletionSeedBarrier,
    AuthorityAcknowledgement,
}

impl ExpansionCrashCut {
    fn matches(self, event: &ffs_zfs::ZfsPersistenceEvent) -> bool {
        let operation = event.operation.as_str();
        match self {
            Self::ScratchWrite => {
                operation == "zfs_pool_expand_raidz_scratch"
                    && matches!(
                        event.stage,
                        ZfsPersistenceStage::ReflowChunkWrite { member_index: 2 }
                    )
            }
            Self::ScratchBarrier => {
                operation == "zfs_pool_expand_raidz_scratch"
                    && matches!(
                        event.stage,
                        ZfsPersistenceStage::ReflowChunkBarrier { member_index: 2 }
                    )
            }
            Self::ScratchAuthorityWrite => {
                operation == "zfs_pool_expand_raidz_scratch_authority"
                    && matches!(
                        event.stage,
                        ZfsPersistenceStage::UberblockWrite {
                            member_index: 1,
                            label: 0,
                            ..
                        }
                    )
            }
            Self::ScratchAuthorityBarrier => {
                operation == "zfs_pool_expand_raidz_scratch_authority"
                    && matches!(
                        event.stage,
                        ZfsPersistenceStage::UberblockBarrier {
                            member_index: 1,
                            wave: 1
                        }
                    )
            }
            Self::CopyWrite => {
                operation == "zfs_pool_expand_raidz_copy"
                    && matches!(
                        event.stage,
                        ZfsPersistenceStage::ReflowChunkWrite { member_index: 2 }
                    )
            }
            Self::CopyBarrier | Self::CopyCancelled => {
                operation == "zfs_pool_expand_raidz_copy"
                    && matches!(
                        event.stage,
                        ZfsPersistenceStage::ReflowChunkBarrier { member_index: 2 }
                    )
            }
            Self::DataAuthorityWrite => {
                operation == "zfs_pool_expand_raidz_data_authority"
                    && matches!(
                        event.stage,
                        ZfsPersistenceStage::UberblockWrite {
                            member_index: 1,
                            label: 0,
                            ..
                        }
                    )
            }
            Self::DataAuthorityBarrier => {
                operation == "zfs_pool_expand_raidz_data_authority"
                    && matches!(
                        event.stage,
                        ZfsPersistenceStage::UberblockBarrier {
                            member_index: 1,
                            wave: 1
                        }
                    )
            }
            Self::CompletionRootBarrier | Self::CompletionRootCancelled => {
                operation == "zfs_pool_expand_raidz_complete"
                    && matches!(
                        event.stage,
                        ZfsPersistenceStage::MosRootBarrier { member_index: 1 }
                    )
            }
            Self::CompletionUberblockBarrier => {
                operation == "zfs_pool_expand_raidz_complete"
                    && matches!(
                        event.stage,
                        ZfsPersistenceStage::UberblockBarrier {
                            member_index: 1,
                            wave: 1
                        }
                    )
            }
            Self::CompletionLabelWrite => {
                operation == "zfs_pool_expand_raidz_labels"
                    && matches!(
                        event.stage,
                        ZfsPersistenceStage::LabelConfigWrite {
                            member_index: 1,
                            label: 2
                        }
                    )
            }
            Self::CompletionSeedBarrier => {
                operation == "zfs_pool_expand_raidz_seed"
                    && matches!(
                        event.stage,
                        ZfsPersistenceStage::LabelConfigBarrier {
                            member_index: 0,
                            wave: 1
                        }
                    )
            }
            Self::AuthorityAcknowledgement => {
                operation == "zfs_pool_expand_raidz_data_authority"
                    && matches!(event.stage, ZfsPersistenceStage::BeforeAcknowledge)
            }
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn raidz_expansion_reopens_every_scratch_and_completion_authority_cut() {
    let cx = Cx::for_testing();
    let pool_guid = 0x5241_4944_4355_5453_u64;
    let (mut initial, created) = routing_fixture(
        &cx,
        pool_guid,
        vec![ZfsCreateVdevKind::Raidz {
            parity: 1,
            width: 3,
        }],
    );
    let mut engine = open_wide_engine(&cx, &initial, pool_guid, created.initial_slot).unwrap();
    let payload = routing_payload();
    let (file, _) = create_routing_file(&cx, &mut engine, &payload);
    let new_disk = FaultableMemberDevice::new(vec![0; 12 * 1024 * 1024]);
    let (_, token) = engine
        .expand_raidz(&cx, expansion_leaf(&cx, &new_disk), 1024 * 1024, 8)
        .into_result()
        .unwrap();
    initial.push(new_disk);
    let bootstrap_slot = token.published_slot();
    drop(engine);
    let baseline = durable_expansion_devices(&initial);

    for cut in [
        ExpansionCrashCut::ScratchWrite,
        ExpansionCrashCut::ScratchBarrier,
        ExpansionCrashCut::ScratchAuthorityWrite,
        ExpansionCrashCut::ScratchAuthorityBarrier,
        ExpansionCrashCut::CopyWrite,
        ExpansionCrashCut::CopyBarrier,
        ExpansionCrashCut::CopyCancelled,
        ExpansionCrashCut::DataAuthorityWrite,
        ExpansionCrashCut::DataAuthorityBarrier,
        ExpansionCrashCut::CompletionRootBarrier,
        ExpansionCrashCut::CompletionRootCancelled,
        ExpansionCrashCut::CompletionUberblockBarrier,
        ExpansionCrashCut::CompletionLabelWrite,
        ExpansionCrashCut::CompletionSeedBarrier,
        ExpansionCrashCut::AuthorityAcknowledgement,
    ] {
        let devices = durable_expansion_devices(&baseline);
        let mut supplied = devices.clone();
        supplied.rotate_right(1);
        let mut engine =
            reopen_expansion(&cx, &supplied, pool_guid, bootstrap_slot, bootstrap_slot);
        let fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = fired.clone();
        engine.with_fault_hook(move |event| {
            if cut.matches(event) && !observed.swap(true, std::sync::atomic::Ordering::SeqCst) {
                return Err(
                    if matches!(
                        cut,
                        ExpansionCrashCut::CopyCancelled
                            | ExpansionCrashCut::CompletionRootCancelled
                    ) {
                        FfsError::Cancelled
                    } else {
                        FfsError::Io(std::io::Error::other(format!("expansion cut {cut:?}")))
                    },
                );
            }
            Ok(())
        });
        let (target_slot, previous_slot) = loop {
            let previous = engine.committed_slot();
            let outcome =
                engine.expand_raidz(&cx, expansion_leaf(&cx, &devices[3]), 1024 * 1024, 8);
            if fired.load(std::sync::atomic::Ordering::SeqCst) {
                if matches!(cut, ExpansionCrashCut::AuthorityAcknowledgement) {
                    assert!(
                        outcome.is_committed(),
                        "a lost acknowledgement cannot undo authority"
                    );
                } else {
                    assert!(!outcome.is_committed(), "fault must be observed at {cut:?}");
                }
                if matches!(
                    cut,
                    ExpansionCrashCut::CompletionSeedBarrier
                        | ExpansionCrashCut::CompletionRootBarrier
                        | ExpansionCrashCut::CompletionRootCancelled
                ) {
                    assert!(
                        engine.requires_recovery(),
                        "completion has changed an admitted member's labels before the failed TXG"
                    );
                    assert!(outcome.is_not_committed());
                    assert_eq!(engine.committed_slot(), previous);
                    if matches!(cut, ExpansionCrashCut::CompletionRootCancelled) {
                        assert!(matches!(
                            &outcome,
                            ZfsTxOutcome::NotCommitted(FfsError::Cancelled)
                        ));
                    }
                    let writes: Vec<_> = devices
                        .iter()
                        .map(FaultableMemberDevice::write_calls)
                        .collect();
                    engine.with_fault_hook(|_| Ok(()));
                    assert!(
                        engine
                            .expand_raidz(&cx, expansion_leaf(&cx, &devices[3]), 1024 * 1024, 8)
                            .is_not_committed(),
                        "a fresh request cannot reuse the unreconciled completion owner"
                    );
                    assert!(
                        engine
                            .write_file_data(
                                &cx,
                                &[],
                                file,
                                0,
                                b"must recover",
                                Timestamp {
                                    seconds: 1_735_001_001,
                                    nanos: 0
                                },
                                ZfsDataChecksum::Fletcher4,
                            )
                            .is_not_committed()
                    );
                    assert_eq!(
                        devices
                            .iter()
                            .map(FaultableMemberDevice::write_calls)
                            .collect::<Vec<_>>(),
                        writes,
                        "recovery fencing precedes every subsequent physical write"
                    );
                }
                if matches!(cut, ExpansionCrashCut::CompletionLabelWrite) {
                    assert!(
                        !engine.persistence_events().iter().any(|event| {
                            event.operation == "zfs_pool_expand_raidz_complete"
                                && event.stage == ZfsPersistenceStage::AckPublished
                        }),
                        "torn completion labels must never acknowledge the topology"
                    );
                }
                let target = match &outcome {
                    ZfsTxOutcome::Uncertain { target_slot, .. } => {
                        assert!(engine.requires_recovery());
                        *target_slot
                    }
                    ZfsTxOutcome::Committed { token, .. } => token.published_slot(),
                    ZfsTxOutcome::NotCommitted(_) => previous,
                };
                break (target, previous);
            }
            let (report, _) = outcome.into_result().expect("reach requested reflow phase");
            assert!(
                !report.completed,
                "cut {cut:?} did not occur before completion"
            );
        };
        drop(engine);
        // Constructing fresh devices from only durable bytes discards every
        // unsynced write, including a partially published same-TXG timestamp.
        let recovered = durable_expansion_devices(&devices);
        let mut shuffled = recovered.clone();
        shuffled.reverse();
        let mut engine = reopen_expansion(&cx, &shuffled, pool_guid, target_slot, previous_slot);
        let mut mos = engine.open_read_objects(&cx).unwrap();
        assert_eq!(
            read_zpl_file(&cx, &mut mos, &[], b"/route.bin", payload.len()).unwrap(),
            payload,
            "selected root must read exact data after {cut:?}",
        );
        let slot = finish_expansion(&cx, &mut engine, &recovered[3]);
        let final_images = durable_expansion_devices(&recovered);
        assert_routing_file(&cx, &final_images, pool_guid, slot, &payload);
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn raidz_expansion_bootstrap_cut_preserves_coherent_config_ownership() {
    let cx = Cx::for_testing();
    let pool_guid = 0x5241_4944_424F_4F54_u64;
    let (initial, created) = routing_fixture(
        &cx,
        pool_guid,
        vec![ZfsCreateVdevKind::Raidz {
            parity: 1,
            width: 3,
        }],
    );
    let mut engine = open_wide_engine(&cx, &initial, pool_guid, created.initial_slot).unwrap();
    let payload = routing_payload();
    let (_, previous_slot) = create_routing_file(&cx, &mut engine, &payload);
    drop(engine);
    let baseline = durable_expansion_devices(&initial);
    for cut_labels in [false, true] {
        let mut devices = durable_expansion_devices(&baseline);
        let mut engine = open_wide_engine(&cx, &devices, pool_guid, previous_slot).unwrap();
        let new_disk = FaultableMemberDevice::new(vec![0; 12 * 1024 * 1024]);
        engine.with_fault_hook(move |event| {
            let cut = if cut_labels {
                event.operation == "zfs_pool_expand_raidz_labels"
                    && matches!(
                        event.stage,
                        ZfsPersistenceStage::LabelConfigBarrier {
                            member_index: 1,
                            wave: 1,
                        }
                    )
            } else {
                event.operation == "zfs_pool_expand_raidz_bootstrap"
                    && matches!(
                        event.stage,
                        ZfsPersistenceStage::UberblockBarrier {
                            member_index: 1,
                            wave: 1,
                        }
                    )
            };
            if cut {
                return Err(FfsError::Io(std::io::Error::other("bootstrap config cut")));
            }
            Ok(())
        });
        let target_slot = match engine.expand_raidz(&cx, expansion_leaf(&cx, &new_disk), 65_536, 1)
        {
            ZfsTxOutcome::Uncertain { target_slot, .. } => target_slot,
            other => panic!("bootstrap publication must be uncertain: {other:?}"),
        };
        assert!(
            !engine.persistence_events().iter().any(|event| {
                event.operation == "zfs_pool_expand_raidz_bootstrap"
                    && event.stage == ZfsPersistenceStage::AckPublished
            }),
            "torn bootstrap labels must never acknowledge the topology"
        );
        devices.push(new_disk);
        drop(engine);
        let recovered = durable_expansion_devices(&devices);
        // A successor uberblock is evidence against falling back to an older
        // geometry even when the newly added member is now absent.
        let old_only = Pool::from_wide_leaves(leaves_from_devs(&cx, &recovered[..3])).unwrap();
        assert!(old_only.root(&cx, 0, previous_slot, pool_guid).is_err());
        let recovered = if cut_labels {
            recovered
        } else {
            // Retain only label0's old-generation physical identity on member2.
            // The successor configuration and newest UB are on other members.
            let mut images: Vec<_> = recovered
                .iter()
                .map(FaultableMemberDevice::durable_snapshot)
                .collect();
            let offsets = label_offsets(images[2].len() as u64).unwrap();
            for offset in &offsets[1..] {
                let start = (*offset + LABEL_CONFIG_OFFSET) as usize;
                images[2][start] ^= 0x5A;
            }
            let damaged: Vec<_> = images.into_iter().map(FaultableMemberDevice::new).collect();
            let identity_start = (offsets[0] + LABEL_CONFIG_OFFSET) as usize;
            let identity_range = identity_start..identity_start + LABEL_CONFIG_BYTES;
            let identity_bytes = damaged[2].durable_snapshot()[identity_range.clone()].to_vec();
            let identity_leaf = expansion_leaf(&cx, &damaged[2]);
            assert!(identity_leaf.label(&cx, 0).is_ok());
            for label in 1..4 {
                assert!(identity_leaf.label(&cx, label).is_err());
            }

            // Persist a torn first configuration rewrite. A fixed [0,1] first
            // wave destroys this member's last verified GUID; adaptive waves
            // write [1,2] first and preserve label0 until replacements sync.
            damaged[2].set_fault(DeviceFault::TornWriteOnCall {
                call_index: 0,
                keep_prefix_bytes: LABEL_CONFIG_BYTES - 40,
            });
            let mut options = default_write_opts(pool_guid, target_slot);
            options.reconcile_torn_uberblocks = true;
            let attempt = ZfsTransactionEngine::from_devices(&cx, boxed_devs(&damaged), options);
            assert!(matches!(attempt, Err(FfsError::Io(_))));
            assert_eq!(damaged[2].write_calls(), 1);
            for (member, device) in damaged.iter().enumerate() {
                let mut state = device.state.lock().unwrap();
                if member == 2 {
                    state.crash_flush_volatile();
                } else {
                    state.crash_drop_unsynced();
                }
            }
            assert_eq!(
                &damaged[2].durable_snapshot()[identity_range],
                identity_bytes.as_slice(),
                "reconciliation must retain the last physical identity until a replacement wave is durable",
            );
            durable_expansion_devices(&damaged)
        };
        let mut engine = reopen_expansion(&cx, &recovered, pool_guid, target_slot, previous_slot);
        let mut mos = engine.open_read_objects(&cx).unwrap();
        assert_eq!(
            read_zpl_file(&cx, &mut mos, &[], b"/route.bin", payload.len()).unwrap(),
            payload
        );
        let slot = finish_expansion(&cx, &mut engine, &recovered[3]);
        assert_routing_file(&cx, &recovered, pool_guid, slot, &payload);
    }
}

#[test]
fn device_removal_refuses_unallocated_claims_and_keeps_indirect_split_resolution() {
    let cx = Cx::for_testing();
    let pool_guid = 0x5245_4D4F_5645_0001_u64;
    let devs = blank_devs(2, 12 * 1024 * 1024);
    let spec = ZfsPoolCreateSpec {
        pool_name: "remove_pool".to_owned(),
        pool_guid,
        ashift: 12,
        hostid: 0x4646_5331,
        hostname: "frankenfs-test".to_owned(),
        vdevs: vec![
            ZfsCreateVdevSpec {
                kind: ZfsCreateVdevKind::Leaf,
                alloc_class: AllocClass::Normal,
            },
            ZfsCreateVdevSpec {
                kind: ZfsCreateVdevKind::Leaf,
                alloc_class: AllocClass::Normal,
            },
        ],
        spare_count: 0,
        exported: true,
    };
    let report = create_pool_on_devices(&cx, boxed_devs(&devs), &spec).unwrap();

    // Seed two distinct 4 KiB blocks onto vdev 1 at DATA_OFFSET + 0 and DATA_OFFSET + 4096.
    let blk_a = vec![0x3C_u8; 4096];
    let blk_b = vec![0xC3_u8; 4096];
    devs[1]
        .write_all_at(&cx, ByteOffset(DATA_OFFSET), &blk_a)
        .unwrap();
    devs[1]
        .write_all_at(&cx, ByteOffset(DATA_OFFSET + 4096), &blk_b)
        .unwrap();
    devs[1].sync(&cx).unwrap();

    let mut engine = open_wide_engine(&cx, &devs, pool_guid, report.initial_slot).unwrap();

    // Negative control: same source & target vdev refused.
    assert!(
        engine
            .remove_vdev(&cx, 1, 1, &[(0, 4096)])
            .is_not_committed()
    );

    // Raw writes did not allocate either range in vdev 1's native space maps.
    // They cannot authorize copying or changing topology.
    let snapshots: Vec<_> = devs
        .iter()
        .map(FaultableMemberDevice::durable_snapshot)
        .collect();
    let writes: Vec<_> = devs
        .iter()
        .map(FaultableMemberDevice::write_calls)
        .collect();
    assert!(
        engine
            .remove_vdev(&cx, 1, 0, &[(0, 4096), (4096, 4096)])
            .is_not_committed()
    );
    for ((device, before), count) in devs.iter().zip(snapshots).zip(writes) {
        assert_eq!(device.durable_snapshot(), before);
        assert_eq!(device.write_calls(), count);
    }

    // Keep split-span native mapping resolution covered independently of the
    // removal API's stricter ownership admission.
    let split = IndirectMappingTable::new(
        1,
        IndirectMappingPhys {
            max_offset: 8192,
            bytes_mapped: 8192,
            num_entries: 2,
            counts_object: 0,
        },
        vec![
            IndirectMappingEntry {
                src_offset: 0,
                marked: false,
                dst: Dva {
                    vdev: 0,
                    offset: 16_384,
                    allocated_bytes: 4096,
                    gang: false,
                },
            },
            IndirectMappingEntry {
                src_offset: 4096,
                marked: false,
                dst: Dva {
                    vdev: 0,
                    offset: 32_768,
                    allocated_bytes: 4096,
                    gang: false,
                },
            },
        ],
        vec![IndirectBirthEntry {
            offset: 8192,
            phys_birth_txg: 5,
        }],
    )
    .unwrap();
    let mut indirect = IndirectVdevMap::default();
    indirect.insert(1, split);
    let resolved = indirect
        .resolve_dva(
            &Dva {
                vdev: 1,
                offset: 0,
                allocated_bytes: 8192,
                gang: false,
            },
            8192,
        )
        .unwrap();
    assert_eq!(resolved.len(), 2);
    assert_eq!(resolved[0].offset, 16_384);
    assert_eq!(resolved[1].offset, 32_768);
    assert!(
        resolved
            .iter()
            .all(|span| span.vdev == 0 && span.allocated_bytes == 4096)
    );

    // Negative control: self-referential / cyclic indirect chains MUST fail closed!
    let t1 = IndirectMappingTable::new(
        1,
        IndirectMappingPhys {
            max_offset: 8192,
            bytes_mapped: 4096,
            num_entries: 1,
            counts_object: 0,
        },
        vec![IndirectMappingEntry {
            src_offset: 0,
            marked: false,
            dst: Dva {
                vdev: 2,
                offset: 0,
                allocated_bytes: 4096,
                gang: false,
            },
        }],
        vec![IndirectBirthEntry {
            offset: 4096,
            phys_birth_txg: 5,
        }],
    )
    .unwrap();
    let t2 = IndirectMappingTable::new(
        2,
        IndirectMappingPhys {
            max_offset: 8192,
            bytes_mapped: 4096,
            num_entries: 1,
            counts_object: 0,
        },
        vec![IndirectMappingEntry {
            src_offset: 0,
            marked: false,
            dst: Dva {
                vdev: 1,
                offset: 0,
                allocated_bytes: 4096,
                gang: false,
            },
        }],
        vec![IndirectBirthEntry {
            offset: 4096,
            phys_birth_txg: 6,
        }],
    )
    .unwrap();
    let _ = IndirectBirthsPhys { count: 1 };
    let mut tables = BTreeMap::new();
    tables.insert(1_u32, t1);
    tables.insert(2_u32, t2);
    assert!(
        resolve_indirect_recursive(&tables, 1, 0, 4096).is_err(),
        "cyclic indirect vdev mapping must fail closed"
    );
}

#[test]
fn allocation_classes_special_log_spares_and_fail_closed_missing_class() {
    let cx = Cx::for_testing();
    let pool_guid = 0xA110_C0C1_A555_0001_u64;
    // 1 Normal + 1 Special + 1 Log + 1 Hot Spare = 4 backing devices.
    let devs = blank_devs(4, 12 * 1024 * 1024);
    let spec = ZfsPoolCreateSpec {
        pool_name: "alloc_class_pool".to_owned(),
        pool_guid,
        ashift: 12,
        hostid: 0x4646_5331,
        hostname: "frankenfs-test".to_owned(),
        vdevs: vec![
            ZfsCreateVdevSpec {
                kind: ZfsCreateVdevKind::Leaf,
                alloc_class: AllocClass::Normal,
            },
            ZfsCreateVdevSpec {
                kind: ZfsCreateVdevKind::Leaf,
                alloc_class: AllocClass::Special,
            },
            ZfsCreateVdevSpec {
                kind: ZfsCreateVdevKind::Leaf,
                alloc_class: AllocClass::Log,
            },
        ],
        spare_count: 1,
        exported: true,
    };
    let report = create_pool_on_devices(&cx, boxed_devs(&devs), &spec).unwrap();
    assert_eq!(report.member_count, 3);
    assert_eq!(report.spare_count, 1);

    // Load MOS config via data devices (excluding hot spare) and validate PoolTopology!
    let data_leaves = leaves_from_devs(&cx, &devs[..3]);
    let pool = Pool::from_wide_leaves(data_leaves.clone()).unwrap();
    let mut mos = pool
        .objects(&cx, 0, report.initial_slot, pool_guid)
        .unwrap();
    let mos_cfg = mos.load_mos_config_nvlist(&cx).unwrap();

    let supplied_guids: Vec<u64> = data_leaves
        .iter()
        .map(|l| l.label(&cx, 0).unwrap().config.unsigned("guid").unwrap())
        .collect();
    let topo = PoolTopology::from_mos_config(&mos_cfg, &supplied_guids)
        .expect("PoolTopology must parse Normal + Special + Log + Spare");
    assert_eq!(topo.guid_sum, report.guid_sum);
    assert_eq!(topo.top_vdevs.len(), 3);
    assert_eq!(topo.top_vdevs[0].alloc_class, AllocClass::Normal);
    assert_eq!(topo.top_vdevs[1].alloc_class, AllocClass::Special);
    assert_eq!(topo.top_vdevs[2].alloc_class, AllocClass::Log);
    assert_eq!(topo.spares.len(), 1);
    assert_eq!(topo.l2cache.len(), 0);
    topo.validate_required_classes_present()
        .expect("complete Special + Normal topology must validate");

    // Negative control: omitting the required `Special` vdev MUST fail closed!
    assert!(
        PoolTopology::from_mos_config(&mos_cfg, &[supplied_guids[0], supplied_guids[2]]).is_err(),
        "missing required Special allocation class must fail closed (never optional cache!)"
    );
}

#[test]
fn openzfs_2_4_feature_manifest_refuses_unsupported_and_oracle_features() {
    assert_eq!(OPENZFS_PINNED_RELEASE, "zfs-2.4.0");
    assert_eq!(
        classify_pool_version(28),
        PoolVersionProfile::HistoricalSunIllumos
    );
    assert_eq!(
        classify_pool_version(5000),
        PoolVersionProfile::OpenZfsFeatureFlags
    );
    assert_eq!(
        classify_pool_version(31),
        PoolVersionProfile::ProprietaryOracle
    );
    assert!(is_oracle_feature("com.oracle:encryption"));
    assert!(!is_supported_label_feature(
        "com.klarasystems:dynamic_gang_header"
    ));
    assert!(is_supported_label_feature("org.openzfs:draid"));
    assert!(is_supported_label_feature("org.openzfs:raidz_expansion"));
    assert!(is_supported_label_feature("com.delphix:device_removal"));

    // Planted refusal control: pool with active `com.klarasystems:dynamic_gang_header`
    // MUST be refused by native writer without mutating backing media!
    let cx = Cx::for_testing();
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        additional_read_features: vec![(b"com.klarasystems:dynamic_gang_header", 1)],
        ..PoolFixtureSpec::default()
    });
    let devs: Vec<_> = built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let before = devs[0].durable_snapshot();
    assert!(
        open_engine_on_devices(
            &cx,
            &devs,
            default_write_opts(built.pool_guid, built.initial_slot),
        )
        .is_err(),
        "active com.klarasystems:dynamic_gang_header must fail closed"
    );
    assert_eq!(devs[0].durable_snapshot(), before);
}
