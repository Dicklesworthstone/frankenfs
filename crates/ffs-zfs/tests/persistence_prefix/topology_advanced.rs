//! Native OpenZFS `zfs-2.4.0` advanced topology integration & fault-cut tests:
//! - dRAID1/2/3 creation, native COW writes, cross-row reads, distributed spare
//!   resolution, and read-only degraded survivor erasure recovery (`1..=nparity`).
//! - Resumable RAIDZ1/2/3 width expansion (`org.openzfs:raidz_expansion`) with
//!   chunked reflow, `ub_raidz_reflow_info` persistence, and crash cuts.
//! - Top-level vdev removal (`com.delphix:device_removal` + `obsolete_counts`)
//!   with genuine OpenZFS `IndirectMappingPhys`/`IndirectMappingEntry` +
//!   `IndirectBirthEntry` evacuation and chained/split resolution.
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

#[test]
fn raidz_expansion_resumable_chunked_reflow_and_fault_cut_safety() {
    let cx = Cx::for_testing();
    let ts = Timestamp {
        seconds: 1_735_001_000,
        nanos: 0,
    };
    let pool_guid = 0x5241_4944_5A45_5850_u64;
    let devs = blank_devs(3, 12 * 1024 * 1024);
    let spec = ZfsPoolCreateSpec {
        pool_name: "raidz_exp_pool".to_owned(),
        pool_guid,
        ashift: 12,
        hostid: 0x4646_5331,
        hostname: "frankenfs-test".to_owned(),
        vdevs: vec![ZfsCreateVdevSpec {
            kind: ZfsCreateVdevKind::Raidz {
                parity: 1,
                width: 3,
            },
            alloc_class: AllocClass::Normal,
        }],
        spare_count: 0,
        exported: true,
    };
    let report = create_pool_on_devices(&cx, boxed_devs(&devs), &spec).unwrap();
    let mut supplied = devs.clone();
    supplied.rotate_right(1);
    let mut engine = open_wide_engine(&cx, &supplied, pool_guid, report.initial_slot).unwrap();

    let (fid, _) = engine
        .create_file(
            &cx,
            &[],
            5,
            b"pre_expand.bin",
            0o644,
            0,
            0,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    let payload = vec![0xA5_u8; 12_288];
    let (_, tok) = engine
        .write_file_data(&cx, &[], fid, 0, &payload, ts, ZfsDataChecksum::Fletcher4)
        .into_result()
        .unwrap();

    // Negative control: undersized expansion disk must fail closed without mutating pool!
    let snap_before: Vec<Vec<u8>> = devs
        .iter()
        .map(FaultableMemberDevice::durable_snapshot)
        .collect();
    let tiny_disk = FaultableMemberDevice::new(vec![0_u8; 6 * 1024 * 1024]);
    let tiny_leaf = Leaf::from_device(&cx, Box::new(tiny_disk), 0, 6 * 1024 * 1024).unwrap();
    assert!(
        engine
            .expand_raidz(&cx, tiny_leaf, 65_536, 1)
            .is_not_committed(),
        "undersized RAIDZ expansion disk must be refused"
    );
    for (idx, (d, prev)) in devs.iter().zip(&snap_before).enumerate() {
        assert_eq!(
            &d.durable_snapshot(),
            prev,
            "refused expand_raidz mutated member {idx}"
        );
    }

    // Fault-cut safety: fault at ReflowChunkBarrier must leave prior committed TXG intact!
    let new_disk = FaultableMemberDevice::new(vec![0_u8; 12 * 1024 * 1024]);
    let cut_leaf = Leaf::from_device(&cx, Box::new(new_disk.clone()), 0, 12 * 1024 * 1024).unwrap();
    engine.with_fault_hook(|ev| {
        if matches!(ev.stage, ZfsPersistenceStage::ReflowChunkBarrier { .. }) {
            return Err(FfsError::Io(std::io::Error::other(
                "injected reflow barrier fault",
            )));
        }
        Ok(())
    });
    assert!(
        engine
            .expand_raidz(&cx, cut_leaf, 65_536, 1)
            .is_not_committed(),
        "pre-uberblock reflow barrier fault must report NotCommitted"
    );
    engine.with_fault_hook(|_| Ok(()));

    // Resumable chunked expansion (`max_chunks_per_txg = 1`) until completed!
    let _ = tok;
    let mut chunks = 0_usize;
    let mut last_slot;
    loop {
        let leaf4 =
            Leaf::from_device(&cx, Box::new(new_disk.clone()), 0, 12 * 1024 * 1024).unwrap();
        let (rep, t) = engine
            .expand_raidz(&cx, leaf4, 65_536, 1)
            .into_result()
            .expect("chunked RAIDZ expansion must commit");
        assert_eq!((rep.old_width, rep.new_width, rep.parity), (3, 4, 1));
        last_slot = t.published_slot();
        chunks += 1;
        if rep.completed {
            break;
        }
        assert!(chunks < 128, "reflow failed to converge");
    }
    assert!(chunks >= 1);

    // Verify `org.openzfs:raidz_expansion` feature, `raidz_expand_txgs`, AND
    // end-to-end 4-disk expanded RAIDZ readback of pre-expansion `/pre_expand.bin`!
    let mut expanded_devs = devs;
    expanded_devs.push(new_disk);
    let pool = Pool::from_wide_leaves(leaves_from_devs(&cx, &expanded_devs)).unwrap();
    let mut mos = pool.objects(&cx, 0, last_slot, pool_guid).unwrap();
    let cfg = mos.load_mos_config_nvlist(&cx).unwrap();
    let Some(NvValue::Lists(tops)) = cfg.list("vdev_tree").unwrap().fields.get("children") else {
        panic!("expected top-level children in MOS config");
    };
    let primary_top = &tops[0];
    assert!(
        primary_top.fields.contains_key("raidz_expand_txgs"),
        "completed expand_raidz must record raidz_expand_txgs in MOS config"
    );
    let read_back = read_zpl_file(&cx, &mut mos, &[], b"/pre_expand.bin", payload.len())
        .expect("pre-expansion file must read back cleanly across all 4 expanded RAIDZ disks");
    assert_eq!(read_back, payload);
}

#[test]
fn device_removal_indirect_vdev_evacuation_and_chained_split_resolution() {
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

    // Evacuate vdev 1 -> vdev 0!
    let (rem_rep, tok) = engine
        .remove_vdev(&cx, 1, 0, &[(0, 4096), (4096, 4096)])
        .into_result()
        .expect("remove_vdev evacuation must commit");
    assert_eq!(rem_rep.removed_vdev_id, 1);
    assert_eq!(rem_rep.target_vdev_id, 0);
    assert_eq!(rem_rep.extents_evacuated, 2);
    assert_eq!(rem_rep.bytes_evacuated, 8192);
    assert!(rem_rep.completed);

    // Verify IndirectVdevMap loads directly from MOS and resolves split spans to exact bytes on vdev 0!
    let pool = Pool::from_wide_leaves(leaves_from_devs(&cx, &devs)).unwrap();
    let mut mos = pool
        .objects(&cx, 0, tok.published_slot(), pool_guid)
        .unwrap();
    let mos_cfg = mos.load_mos_config_nvlist(&cx).unwrap();
    let ind_map = IndirectVdevMap::load_from_mos(&cx, &mut mos, &mos_cfg)
        .expect("load persisted indirect vdev map from MOS");
    let resolved = ind_map
        .resolve_dva(
            &Dva {
                vdev: 1,
                offset: 0,
                allocated_bytes: 8192,
                gang: false,
            },
            8192,
        )
        .expect("split-span indirect resolution must succeed");
    assert_eq!(resolved.len(), 2);
    let mut reassembled = Vec::new();
    for seg in &resolved {
        assert_eq!(seg.vdev, 0);
        let mut buf = vec![0_u8; usize::try_from(seg.allocated_bytes).unwrap()];
        devs[0]
            .read_exact_at(&cx, ByteOffset(DATA_OFFSET + seg.offset), &mut buf)
            .unwrap();
        reassembled.extend_from_slice(&buf);
    }
    let mut expected = blk_a;
    expected.extend_from_slice(&blk_b);
    assert_eq!(reassembled, expected);

    // Negative control: removing the last remaining normal vdev (`vdev 0`) is strictly refused!
    assert!(
        engine
            .remove_vdev(&cx, 0, 1, &[(0, 4096)])
            .is_not_committed(),
        "removing last remaining normal vdev must be refused"
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
