//! Native writable ZVOL lifecycle, DMU indirect shrink, persistence-prefix crash-cut,
//! exclusive volume-manager lease/epoch invalidation, and safe-Rust NBD frontend tests.

use super::*;
use ffs_zfs::{
    NbdServerConfig, ZfsPropertySetValue, ZfsVolumeManager, ZfsZvolCreateOptions, ZfsZvolNbdClient,
    ZfsZvolNbdServer, ZvolAckKind, ZvolSyncPolicy,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

fn assert_zvol_and_pool_clean(
    cx: &Cx,
    devs: &[FaultableMemberDevice],
    pool_guid: u64,
    slot: usize,
    zvol_dataset: Option<&[Vec<u8>]>,
) {
    let _ = assert_pool_scrub_and_allocation_clean(cx, devs, pool_guid, Some(slot));
    if let Some(ds) = zvol_dataset {
        let leaves: Vec<Leaf> = devs
            .iter()
            .cloned()
            .map(|d| {
                let len = d.len_bytes();
                Leaf::from_device(cx, Box::new(d), 0, len).unwrap()
            })
            .collect();
        let pool = Pool::from_leaves(leaves).unwrap();
        let mut mos = pool.objects(cx, 0, slot, pool_guid).unwrap();
        let zvol = mos.zvol(cx, ds, None).unwrap();
        let scrub = zvol.scrub(cx, ScrubLimits::default()).unwrap();
        assert!(scrub.is_clean(), "ZVOL scrub reported errors: {scrub:?}");
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn zvol_lifecycle_create_rmw_discard_shrink_snapshot_clone_destroy_and_properties() {
    let cx = Cx::for_testing();
    let ts = Timestamp {
        seconds: 1_726_000_000,
        nanos: 0,
    };

    for (mirror_width, ashift, volblocksize) in [(1, 9, 4096_u32), (2, 12, 16_384_u32)] {
        let built = build_clean_zfs_pool(&PoolFixtureSpec {
            mirror_width,
            ashift,
            image_bytes: 24 * 1024 * 1024,
            deadlist_mode: DeadlistMode::NativeDeadlist,
            ..PoolFixtureSpec::default()
        });
        let devices: Vec<_> = built
            .members
            .into_iter()
            .map(FaultableMemberDevice::new)
            .collect();
        let mut engine = open_engine_on_devices(
            &cx,
            &devices,
            default_write_opts(built.pool_guid, built.initial_slot),
        )
        .unwrap();
        let parent_ds = vec![b"data".to_vec()];
        let vol_ds = vec![b"data".to_vec(), b"disk0".to_vec()];

        // 1. Thick-provisioned ZVOL exceeding pool capacity fails upfront (`NoSpace`).
        let oos = engine.zvol_create(
            &cx,
            &parent_ds,
            b"too_big",
            &ZfsZvolCreateOptions {
                volsize: 64 * 1024 * 1024,
                volblocksize,
                sparse: false,
                initial_props: Vec::new(),
                timestamp: ts,
            },
        );
        assert!(matches!(oos, ZfsTxOutcome::NotCommitted(FfsError::NoSpace)));

        // 2. Create thick-provisioned ZVOL (`refreservation = volsize`) with valid ZVOL props.
        let initial_volsize = 512 * 1024;
        let (created, tok) = engine
            .zvol_create(
                &cx,
                &parent_ds,
                b"disk0",
                &ZfsZvolCreateOptions {
                    volsize: initial_volsize,
                    volblocksize,
                    sparse: false,
                    initial_props: vec![
                        ("snapdev".to_owned(), ZfsPropertySetValue::Number(1)),
                        ("sync".to_owned(), ZfsPropertySetValue::Number(1)),
                        ("logbias".to_owned(), ZfsPropertySetValue::Number(1)),
                        ("volthreading".to_owned(), ZfsPropertySetValue::Number(1)),
                        (
                            "app:tier".to_owned(),
                            ZfsPropertySetValue::Text(b"nvme".to_vec()),
                        ),
                    ],
                    timestamp: ts,
                },
            )
            .into_result()
            .expect("zvol_create");
        assert_eq!(created.volsize, initial_volsize);
        assert_eq!(created.volblocksize, volblocksize as usize);
        assert!(!created.readonly);
        assert_zvol_and_pool_clean(
            &cx,
            &devices,
            built.pool_guid,
            tok.published_slot(),
            Some(&vol_ds),
        );

        // 3. Cannot nest a child dataset, ZVOL, or clone beneath a ZVOL (`EINVAL`).
        for bad_child in [
            engine.create_dataset(&cx, &vol_ds, b"sub", &[], ts),
            engine
                .zvol_create(
                    &cx,
                    &vol_ds,
                    b"subvol",
                    &ZfsZvolCreateOptions {
                        volsize: u64::from(volblocksize) * 4,
                        volblocksize,
                        sparse: true,
                        initial_props: Vec::new(),
                        timestamp: ts,
                    },
                )
                .into_result()
                .map_or_else(ZfsTxOutcome::NotCommitted, |(i, t)| {
                    ZfsTxOutcome::Committed {
                        value: i.head_object,
                        token: t,
                    }
                }),
        ] {
            assert!(matches!(
                bad_child,
                ZfsTxOutcome::NotCommitted(FfsError::RequestRejected {
                    errno: libc::EINVAL,
                    ..
                })
            ));
        }

        // 4. Reject filesystem-only and immutable `volblocksize` properties on ZVOL.
        for bad_prop in ["quota", "refquota", "recordsize", "atime", "volblocksize"] {
            let res =
                engine.set_property(&cx, &vol_ds, bad_prop, ZfsPropertySetValue::Number(16_384));
            assert!(
                matches!(
                    res,
                    ZfsTxOutcome::NotCommitted(FfsError::RequestRejected {
                        errno: libc::EINVAL,
                        ..
                    })
                ),
                "expected EINVAL setting {bad_prop} on ZVOL"
            );
        }

        // 5. Reject zvol_destroy / zvol_snapshot on a ZPL filesystem dataset.
        assert!(matches!(
            engine.zvol_destroy(&cx, &parent_ds),
            ZfsTxOutcome::NotCommitted(FfsError::RequestRejected {
                errno: libc::EINVAL,
                ..
            })
        ));
        assert!(matches!(
            engine.zvol_snapshot(&cx, &parent_ds, b"bad", ts),
            ZfsTxOutcome::NotCommitted(FfsError::RequestRejected {
                errno: libc::EINVAL,
                ..
            })
        ));

        // 6. Sparse read returns zeros; destination buffer preserved on out-of-bounds / unaligned error!
        let mut buf = vec![0xAA_u8; 1024];
        assert!(
            engine
                .zvol_read_at(&cx, &vol_ds, None, 13, &mut buf)
                .is_err()
        );
        assert!(buf.iter().all(|&b| b == 0xAA));
        assert!(
            engine
                .zvol_read_at(&cx, &vol_ds, None, initial_volsize - 512, &mut buf)
                .is_err()
        );
        assert!(buf.iter().all(|&b| b == 0xAA));
        engine
            .zvol_read_at(&cx, &vol_ds, None, 0, &mut buf)
            .unwrap();
        assert!(buf.iter().all(|&b| b == 0));

        // 7. Sub-volblocksize 512B RMW write + cross-block SHA-256 write.
        let sector_a = vec![0x5A_u8; 512];
        let (rcpt1, _) = engine
            .zvol_write_at(&cx, &vol_ds, 512, &sector_a, ZfsDataChecksum::Fletcher4)
            .into_result()
            .unwrap();
        assert!(rcpt1.tx_published && rcpt1.token.is_some());

        let cross_off = u64::from(volblocksize) - 512;
        let cross_len = (volblocksize as usize) * 2 + 1024;
        let cross_data: Vec<u8> = (0..cross_len)
            .map(|i| ((i * 13 + 7) & 0xFF) as u8)
            .collect();
        let (rcpt2, _) = engine
            .zvol_write_at(
                &cx,
                &vol_ds,
                cross_off,
                &cross_data,
                ZfsDataChecksum::Sha256,
            )
            .into_result()
            .unwrap();
        assert!(rcpt2.committed_txg > rcpt1.committed_txg);

        let mut verify_sector = vec![0_u8; 1024];
        engine
            .zvol_read_at(&cx, &vol_ds, None, 0, &mut verify_sector)
            .unwrap();
        assert_eq!(&verify_sector[..512], &vec![0_u8; 512][..]);
        assert_eq!(&verify_sector[512..], &sector_a[..]);

        let mut verify_cross = vec![0_u8; cross_len];
        engine
            .zvol_read_at(&cx, &vol_ds, None, cross_off, &mut verify_cross)
            .unwrap();
        assert_eq!(verify_cross, cross_data);

        let used_before_discard = engine
            .zvol_info(&cx, &vol_ds, None)
            .unwrap()
            .dnode_used_bytes;
        assert!(used_before_discard > 0);

        // 8. Snapshot before discard/overwrite/shrink, then clone from snapshot.
        let (_, snap_tok) = engine
            .zvol_snapshot(&cx, &vol_ds, b"vsnap1", ts)
            .into_result()
            .unwrap();
        assert_zvol_and_pool_clean(
            &cx,
            &devices,
            built.pool_guid,
            snap_tok.published_slot(),
            Some(&vol_ds),
        );

        // 9. Discard one full volblocksize + partial tail; verify zeroed reads while snapshot preserves old bytes.
        let discard_start = u64::from(volblocksize);
        let discard_len = u64::from(volblocksize) + 512;
        let (_, disc_tok) = engine
            .zvol_discard(
                &cx,
                &vol_ds,
                discard_start,
                discard_len,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .unwrap();
        assert_zvol_and_pool_clean(
            &cx,
            &devices,
            built.pool_guid,
            disc_tok.published_slot(),
            Some(&vol_ds),
        );
        let mut head_after_disc = vec![0xFF_u8; discard_len as usize];
        engine
            .zvol_read_at(&cx, &vol_ds, None, discard_start, &mut head_after_disc)
            .unwrap();
        assert!(head_after_disc.iter().all(|&b| b == 0));

        // Snapshot still returns exact pre-discard bytes!
        let mut snap_cross = vec![0_u8; cross_len];
        engine
            .zvol_read_at(&cx, &vol_ds, Some(b"vsnap1"), cross_off, &mut snap_cross)
            .unwrap();
        assert_eq!(snap_cross, cross_data);

        // 10. Clone ZVOL from `@vsnap1`, mutate clone, resize original ZVOL grow -> shrink.
        let clone_ds = vec![b"data".to_vec(), b"disk0_clone".to_vec()];
        engine
            .create_clone(&cx, &vol_ds, b"vsnap1", &parent_ds, b"disk0_clone", &[], ts)
            .into_result()
            .unwrap();
        let mut clone_read = vec![0_u8; cross_len];
        engine
            .zvol_read_at(&cx, &clone_ds, None, cross_off, &mut clone_read)
            .unwrap();
        assert_eq!(clone_read, cross_data);
        let clone_sector = vec![0xC3_u8; 512];
        engine
            .zvol_write_at(&cx, &clone_ds, 0, &clone_sector, ZfsDataChecksum::Fletcher4)
            .into_result()
            .unwrap();

        // Grow then shrink original ZVOL.
        engine
            .zvol_resize(&cx, &vol_ds, initial_volsize * 2)
            .into_result()
            .unwrap();
        assert_eq!(
            engine.zvol_info(&cx, &vol_ds, None).unwrap().volsize,
            initial_volsize * 2
        );
        let shrunk_size = u64::from(volblocksize) * 2;
        let (_, shrink_tok) = engine
            .zvol_resize(&cx, &vol_ds, shrunk_size)
            .into_result()
            .unwrap();
        assert_eq!(
            engine.zvol_info(&cx, &vol_ds, None).unwrap().volsize,
            shrunk_size
        );
        assert_zvol_and_pool_clean(
            &cx,
            &devices,
            built.pool_guid,
            shrink_tok.published_slot(),
            Some(&vol_ds),
        );

        // 11. Readonly ZVOL refuses write/discard/resize with ReadOnly.
        engine
            .set_property(&cx, &vol_ds, "readonly", ZfsPropertySetValue::Number(1))
            .into_result()
            .unwrap();
        assert!(matches!(
            engine.zvol_write_at(&cx, &vol_ds, 0, &sector_a, ZfsDataChecksum::Fletcher4),
            ZfsTxOutcome::NotCommitted(FfsError::ReadOnly)
        ));
        assert!(matches!(
            engine.zvol_discard(&cx, &vol_ds, 0, 512, ZfsDataChecksum::Fletcher4),
            ZfsTxOutcome::NotCommitted(FfsError::ReadOnly)
        ));
        assert!(matches!(
            engine.zvol_resize(&cx, &vol_ds, shrunk_size * 2),
            ZfsTxOutcome::NotCommitted(FfsError::ReadOnly)
        ));
        engine
            .set_property(&cx, &vol_ds, "readonly", ZfsPropertySetValue::Number(0))
            .into_result()
            .unwrap();

        // 12. Destroy clone, snapshot, and original ZVOL — verify zero leaked blocks!
        engine.zvol_destroy(&cx, &clone_ds).into_result().unwrap();
        engine
            .destroy_snapshot(&cx, &vol_ds, b"vsnap1", false)
            .into_result()
            .unwrap();
        let (_, destroy_tok) = engine.zvol_destroy(&cx, &vol_ds).into_result().unwrap();
        assert_zvol_and_pool_clean(
            &cx,
            &devices,
            built.pool_guid,
            destroy_tok.published_slot(),
            None,
        );
    }
}

#[test]
fn zvol_shrink_retires_boundary_indirect_pointers_and_large_blocks_feature_refcount() {
    let cx = Cx::for_testing();
    let ts = Timestamp {
        seconds: 1_726_100_000,
        nanos: 0,
    };
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        image_bytes: 24 * 1024 * 1024,
        ashift: 9,
        ..PoolFixtureSpec::default()
    });
    let devices: Vec<_> = built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut engine = open_engine_on_devices(
        &cx,
        &devices,
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .unwrap();
    let parent_ds = vec![b"data".to_vec()];
    let vol_ds = vec![b"data".to_vec(), b"indirect_vol".to_vec()];

    // volblocksize = 512B, volsize = 256 * 512B = 128 KiB -> writing block 200 forces levels = 2!
    engine
        .zvol_create(
            &cx,
            &parent_ds,
            b"indirect_vol",
            &ZfsZvolCreateOptions {
                volsize: 256 * 512,
                volblocksize: 512,
                sparse: true,
                initial_props: Vec::new(),
                timestamp: ts,
            },
        )
        .into_result()
        .unwrap();

    // Write block 0, block 5, block 150, block 200 (multi-level indirect block!).
    for bid in [0_u64, 5, 150, 200] {
        let blk = vec![(bid as u8).wrapping_add(1); 512];
        engine
            .zvol_write_at(&cx, &vol_ds, bid * 512, &blk, ZfsDataChecksum::Fletcher4)
            .into_result()
            .unwrap();
    }
    // Block-aligned shrink with EMPTY dirty_leaves to 8 * 512B = 4096B (max_block = 7).
    // Must COW the level-1 boundary indirect block, zero slots > 7, and retire blocks 150 & 200!
    let (_, shrink_tok) = engine
        .zvol_resize(&cx, &vol_ds, 8 * 512)
        .into_result()
        .unwrap();
    assert_zvol_and_pool_clean(
        &cx,
        &devices,
        built.pool_guid,
        shrink_tok.published_slot(),
        Some(&vol_ds),
    );
    let mut check0 = vec![0_u8; 512];
    let mut check5 = vec![0_u8; 512];
    engine
        .zvol_read_at(&cx, &vol_ds, None, 0, &mut check0)
        .unwrap();
    engine
        .zvol_read_at(&cx, &vol_ds, None, 5 * 512, &mut check5)
        .unwrap();
    assert_eq!(check0, vec![1_u8; 512]);
    assert_eq!(check5, vec![6_u8; 512]);

    // Without `org.open-zfs:large_blocks` enabled on the pool, 256K volblocksize refuses cleanly!
    let lb_denied = engine.zvol_create(
        &cx,
        &parent_ds,
        b"bigblk_denied",
        &ZfsZvolCreateOptions {
            volsize: 1024 * 1024,
            volblocksize: 262_144,
            sparse: true,
            initial_props: Vec::new(),
            timestamp: ts,
        },
    );
    assert!(matches!(
        lb_denied,
        ZfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(_))
    ));

    // With `org.open-zfs:large_blocks` enabled, verify refcount 0 -> 1 -> 2 -> 1 -> 0!
    let lb_built = build_clean_zfs_pool(&PoolFixtureSpec {
        image_bytes: 24 * 1024 * 1024,
        ashift: 9,
        additional_read_features: vec![(b"org.open-zfs:large_blocks", 0)],
        ..PoolFixtureSpec::default()
    });
    let lb_devs: Vec<_> = lb_built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut lb_eng = open_engine_on_devices(
        &cx,
        &lb_devs,
        default_write_opts(lb_built.pool_guid, lb_built.initial_slot),
    )
    .unwrap();
    let lb_ds = vec![b"data".to_vec(), b"bigblk_vol".to_vec()];
    let (_, lb_tok) = lb_eng
        .zvol_create(
            &cx,
            &parent_ds,
            b"bigblk_vol",
            &ZfsZvolCreateOptions {
                volsize: 1024 * 1024,
                volblocksize: 262_144,
                sparse: true,
                initial_props: Vec::new(),
                timestamp: ts,
            },
        )
        .into_result()
        .unwrap();
    assert_zvol_and_pool_clean(
        &cx,
        &lb_devs,
        lb_built.pool_guid,
        lb_tok.published_slot(),
        Some(&lb_ds),
    );
    lb_eng
        .zvol_snapshot(&cx, &lb_ds, b"s_lb", ts)
        .into_result()
        .unwrap();
    {
        let mut mos = lb_eng.open_read_objects(&cx).unwrap();
        let rf = mos.zap(&cx, 10).unwrap();
        let lb = rf
            .iter()
            .find(|e| e.name == b"org.open-zfs:large_blocks")
            .unwrap();
        assert_eq!(lb.value, 2);
    }
    lb_eng
        .destroy_snapshot(&cx, &lb_ds, b"s_lb", false)
        .into_result()
        .unwrap();
    let (_, lb_del_tok) = lb_eng.zvol_destroy(&cx, &lb_ds).into_result().unwrap();
    {
        let mut mos = lb_eng.open_read_objects(&cx).unwrap();
        let rf = mos.zap(&cx, 10).unwrap();
        let lb = rf
            .iter()
            .find(|e| e.name == b"org.open-zfs:large_blocks")
            .unwrap();
        assert_eq!(lb.value, 0);
    }
    assert_zvol_and_pool_clean(
        &cx,
        &lb_devs,
        lb_built.pool_guid,
        lb_del_tok.published_slot(),
        None,
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn zvol_persistence_prefix_fault_cuts_across_all_stages() {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum CrashState {
        NotCommitted,
        UncertainPredecessor,
        UncertainTarget,
    }

    let cx = Cx::for_testing();
    let ts = Timestamp {
        seconds: 1_726_200_000,
        nanos: 0,
    };
    let parent_ds = vec![b"data".to_vec()];
    let vol_ds = vec![b"data".to_vec(), b"cut_vol".to_vec()];
    let new_vol_ds = vec![b"data".to_vec(), b"cut_new".to_vec()];

    // Build a pool with an existing populated ZVOL so we can fault-cut write, discard, resize, destroy.
    let base_built = build_clean_zfs_pool(&PoolFixtureSpec {
        image_bytes: 20 * 1024 * 1024,
        ashift: 9,
        ..PoolFixtureSpec::default()
    });
    let base_dev = FaultableMemberDevice::new(base_built.members[0].clone());
    let (pre_slot, pre_txg) = {
        let mut eng = open_engine_on_devices(
            &cx,
            std::slice::from_ref(&base_dev),
            default_write_opts(base_built.pool_guid, base_built.initial_slot),
        )
        .unwrap();
        eng.zvol_create(
            &cx,
            &parent_ds,
            b"cut_vol",
            &ZfsZvolCreateOptions {
                volsize: 256 * 1024,
                volblocksize: 4096,
                sparse: true,
                initial_props: Vec::new(),
                timestamp: ts,
            },
        )
        .into_result()
        .unwrap();
        let (_, tok) = eng
            .zvol_write_at(
                &cx,
                &vol_ds,
                0,
                &vec![0x33_u8; 16_384],
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .unwrap();
        (tok.published_slot(), tok.committed_txg())
    };
    let base_snapshot = base_dev.durable_snapshot();

    type ZvolStageSpec = (&'static str, fn(&ZfsPersistenceStage) -> bool, CrashState);
    let stages: Vec<ZvolStageSpec> = vec![
        (
            "ChildBlocksWrite",
            |s| matches!(s, ZfsPersistenceStage::ChildBlocksWrite { .. }),
            CrashState::NotCommitted,
        ),
        (
            "ChildBlocksBarrier",
            |s| matches!(s, ZfsPersistenceStage::ChildBlocksBarrier { .. }),
            CrashState::NotCommitted,
        ),
        (
            "DatasetMetadataWrite",
            |s| matches!(s, ZfsPersistenceStage::DatasetMetadataWrite { .. }),
            CrashState::NotCommitted,
        ),
        (
            "DatasetMetadataBarrier",
            |s| matches!(s, ZfsPersistenceStage::DatasetMetadataBarrier { .. }),
            CrashState::NotCommitted,
        ),
        (
            "MosSpaceMapWrite",
            |s| matches!(s, ZfsPersistenceStage::MosSpaceMapWrite { .. }),
            CrashState::NotCommitted,
        ),
        (
            "MosRootWrite",
            |s| matches!(s, ZfsPersistenceStage::MosRootWrite { .. }),
            CrashState::NotCommitted,
        ),
        (
            "UberblockWriteWave2",
            |s| matches!(s, ZfsPersistenceStage::UberblockWrite { label: 2, .. }),
            CrashState::UncertainTarget,
        ),
        (
            "UberblockBarrierWave1",
            |s| matches!(s, ZfsPersistenceStage::UberblockBarrier { wave: 1, .. }),
            CrashState::UncertainPredecessor,
        ),
    ];

    for op in ["create", "write", "discard", "resize_shrink", "destroy"] {
        for &(stage_name, matcher, expected_state) in &stages {
            let dev = FaultableMemberDevice::new(base_snapshot.clone());
            let mut eng = open_engine_on_devices(
                &cx,
                std::slice::from_ref(&dev),
                default_write_opts(base_built.pool_guid, pre_slot),
            )
            .unwrap();
            let tripped = Arc::new(AtomicBool::new(false));
            let tripped_hook = Arc::clone(&tripped);
            eng.with_fault_hook(move |ev| {
                if matcher(&ev.stage) && !tripped_hook.swap(true, Ordering::SeqCst) {
                    return Err(FfsError::Io(std::io::Error::other(format!(
                        "injected cut at {stage_name}"
                    ))));
                }
                Ok(())
            });

            let outcome: ZfsTxOutcome<u64> = match op {
                "create" => match eng.zvol_create(
                    &cx,
                    &parent_ds,
                    b"cut_new",
                    &ZfsZvolCreateOptions {
                        volsize: 64 * 1024,
                        volblocksize: 4096,
                        sparse: true,
                        initial_props: Vec::new(),
                        timestamp: ts,
                    },
                ) {
                    ZfsTxOutcome::Committed { value, token } => ZfsTxOutcome::Committed {
                        value: value.head_object,
                        token,
                    },
                    ZfsTxOutcome::NotCommitted(e) => ZfsTxOutcome::NotCommitted(e),
                    ZfsTxOutcome::Uncertain {
                        reason,
                        target_txg,
                        target_slot,
                    } => ZfsTxOutcome::Uncertain {
                        reason,
                        target_txg,
                        target_slot,
                    },
                },
                "write" => match eng.zvol_write_at(
                    &cx,
                    &vol_ds,
                    512,
                    &vec![0x77_u8; 512],
                    ZfsDataChecksum::Fletcher4,
                ) {
                    ZfsTxOutcome::Committed { token, .. } => {
                        ZfsTxOutcome::Committed { value: 512, token }
                    }
                    ZfsTxOutcome::NotCommitted(e) => ZfsTxOutcome::NotCommitted(e),
                    ZfsTxOutcome::Uncertain {
                        reason,
                        target_txg,
                        target_slot,
                    } => ZfsTxOutcome::Uncertain {
                        reason,
                        target_txg,
                        target_slot,
                    },
                },
                "discard" => {
                    match eng.zvol_discard(&cx, &vol_ds, 0, 4096, ZfsDataChecksum::Fletcher4) {
                        ZfsTxOutcome::Committed { token, .. } => {
                            ZfsTxOutcome::Committed { value: 4096, token }
                        }
                        ZfsTxOutcome::NotCommitted(e) => ZfsTxOutcome::NotCommitted(e),
                        ZfsTxOutcome::Uncertain {
                            reason,
                            target_txg,
                            target_slot,
                        } => ZfsTxOutcome::Uncertain {
                            reason,
                            target_txg,
                            target_slot,
                        },
                    }
                }
                "resize_shrink" => eng.zvol_resize(&cx, &vol_ds, 8192),
                "destroy" => eng.zvol_destroy(&cx, &vol_ds),
                _ => unreachable!(),
            };

            if !tripped.load(Ordering::SeqCst) {
                // `destroy` has no `ChildBlocks` bucket writes, so those hooks won't fire.
                assert!(outcome.is_committed());
                continue;
            }

            let crashed = dev.fresh_from_durable();
            let is_uncertain = expected_state != CrashState::NotCommitted;
            let published = expected_state == CrashState::UncertainTarget;
            let expected_txg = pre_txg + u64::from(published);
            let recovered_slot = if is_uncertain {
                let ZfsTxOutcome::Uncertain {
                    target_txg,
                    target_slot,
                    ..
                } = outcome
                else {
                    panic!("{op} cut at {stage_name} must report Uncertain");
                };
                assert!(eng.requires_recovery());
                assert_eq!(target_txg, pre_txg + 1, "{op} cut at {stage_name}");
                if published {
                    // The first wave reached its barrier before the second wave's write hook.
                    target_slot
                } else {
                    // Hooks run before their I/O. At the first wave's barrier hook, both
                    // new Uberblocks are still volatile and disappear on this crash.
                    let mut absent_opts = default_write_opts(base_built.pool_guid, target_slot);
                    absent_opts.reconcile_torn_uberblocks = true;
                    assert!(
                        matches!(
                            open_engine_on_devices(
                                &cx,
                                std::slice::from_ref(&crashed),
                                absent_opts,
                            ),
                            Err(FfsError::Corruption { detail, .. })
                                if detail == "explicitly selected (label, slot) does not contain a valid Uberblock"
                        ),
                        "{op} cut at {stage_name} must reject the absent target slot"
                    );
                    pre_slot
                }
            } else {
                assert!(
                    matches!(outcome, ZfsTxOutcome::NotCommitted(_)),
                    "{op} cut at {stage_name} must report NotCommitted"
                );
                pre_slot
            };

            // Native import must independently select exactly the durable root before
            // explicit writer reconciliation heals any split label copies.
            assert_eq!(
                assert_pool_scrub_and_allocation_clean(
                    &cx,
                    std::slice::from_ref(&crashed),
                    base_built.pool_guid,
                    None,
                ),
                expected_txg,
                "{op} cut at {stage_name} recovered the wrong native root"
            );
            let mut opts = default_write_opts(base_built.pool_guid, recovered_slot);
            opts.reconcile_torn_uberblocks = is_uncertain;
            let recovered = open_engine_on_devices(&cx, std::slice::from_ref(&crashed), opts)
                .unwrap_or_else(|error| panic!("{op} cut at {stage_name}: {error:?}"));
            assert_eq!(recovered.committed_txg(), expected_txg);
            assert_eq!(recovered.committed_slot(), recovered_slot);

            let destroyed = published && op == "destroy";
            if destroyed {
                assert!(matches!(
                    recovered.zvol_info(&cx, &vol_ds, None),
                    Err(FfsError::NotFound(_))
                ));
            } else {
                let size = if published && op == "resize_shrink" {
                    8192
                } else {
                    256 * 1024
                };
                let info = recovered.zvol_info(&cx, &vol_ds, None).unwrap();
                assert_eq!(info.volsize, size, "{op} cut at {stage_name}");
                assert_eq!(info.volblocksize, 4096);
                let mut expected = vec![0_u8; size as usize];
                let initialized = expected.len().min(16_384);
                expected[..initialized].fill(0x33);
                if published && op == "write" {
                    expected[512..1024].fill(0x77);
                } else if published && op == "discard" {
                    expected[..4096].fill(0);
                }
                let mut check = vec![0xAA_u8; expected.len()];
                recovered
                    .zvol_read_at(&cx, &vol_ds, None, 0, &mut check)
                    .unwrap();
                assert_eq!(check, expected, "{op} cut at {stage_name}");
            }
            assert_zvol_and_pool_clean(
                &cx,
                std::slice::from_ref(&crashed),
                base_built.pool_guid,
                recovered_slot,
                (!destroyed).then_some(vol_ds.as_slice()),
            );

            if published && op == "create" {
                let info = recovered.zvol_info(&cx, &new_vol_ds, None).unwrap();
                assert_eq!(info.volsize, 64 * 1024);
                assert_eq!(info.volblocksize, 4096);
                let mut check = vec![0xAA_u8; 64 * 1024];
                recovered
                    .zvol_read_at(&cx, &new_vol_ds, None, 0, &mut check)
                    .unwrap();
                assert!(check.iter().all(|&byte| byte == 0));
                assert_zvol_and_pool_clean(
                    &cx,
                    std::slice::from_ref(&crashed),
                    base_built.pool_guid,
                    recovered_slot,
                    Some(&new_vol_ds),
                );
            } else {
                assert!(matches!(
                    recovered.zvol_info(&cx, &new_vol_ds, None),
                    Err(FfsError::NotFound(_))
                ));
            }
        }
    }
}

#[test]
fn zvol_volume_manager_enforces_exclusive_leases_and_epoch_invalidation() {
    let cx = Cx::for_testing();
    let ts = Timestamp {
        seconds: 1_726_300_000,
        nanos: 0,
    };
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        image_bytes: 16 * 1024 * 1024,
        ashift: 9,
        ..PoolFixtureSpec::default()
    });
    let devices: Vec<_> = built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let engine = open_engine_on_devices(
        &cx,
        &devices,
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .unwrap();
    let mgr = ZfsVolumeManager::new(engine);
    let parent_ds = vec![b"data".to_vec()];
    let vol_ds = vec![b"data".to_vec(), b"leased".to_vec()];

    let (info, _) = mgr
        .zvol_create(
            &cx,
            &parent_ds,
            b"leased",
            &ZfsZvolCreateOptions {
                volsize: 64 * 1024,
                volblocksize: 4096,
                sparse: true,
                initial_props: Vec::new(),
                timestamp: ts,
            },
        )
        .into_result()
        .unwrap();

    let mut s1 = mgr
        .open_writable_session(
            &cx,
            &vol_ds,
            ZvolSyncPolicy::Always,
            true,
            ZfsDataChecksum::Fletcher4,
        )
        .unwrap();

    // Second writable open fails with EBUSY.
    assert!(matches!(
        mgr.open_writable_session(
            &cx,
            &vol_ds,
            ZvolSyncPolicy::Always,
            true,
            ZfsDataChecksum::Fletcher4,
        ),
        Err(FfsError::RequestRejected {
            errno: libc::EBUSY,
            ..
        })
    ));

    // Destroy while open fails with EBUSY.
    assert!(matches!(
        mgr.zvol_destroy(&cx, &vol_ds),
        ZfsTxOutcome::NotCommitted(FfsError::RequestRejected {
            errno: libc::EBUSY,
            ..
        })
    ));

    // Resize bumps epoch -> s1 immediately fails closed with ESTALE!
    mgr.zvol_resize(&cx, &vol_ds, 128 * 1024)
        .into_result()
        .unwrap();
    let mut buf = [0_u8; 512];
    assert!(matches!(
        s1.read_at(&cx, 0, &mut buf),
        Err(FfsError::RequestRejected {
            errno: libc::ESTALE,
            ..
        })
    ));
    assert!(matches!(
        s1.write_at(&cx, 0, &buf, false),
        Err(FfsError::RequestRejected {
            errno: libc::ESTALE,
            ..
        })
    ));
    drop(s1);

    // Fresh session after drop succeeds; explicit revoke_handles invalidates it too.
    let mut s2 = mgr
        .open_writable_session(
            &cx,
            &vol_ds,
            ZvolSyncPolicy::Always,
            true,
            ZfsDataChecksum::Fletcher4,
        )
        .unwrap();
    mgr.revoke_handles(info.dataset_guid).unwrap();
    assert!(matches!(
        s2.flush(&cx),
        Err(FfsError::RequestRejected {
            errno: libc::ESTALE,
            ..
        })
    ));
    drop(s2);

    // Now destroy succeeds and `into_engine` releases cleanly.
    mgr.zvol_destroy(&cx, &vol_ds).into_result().unwrap();
    let _engine = mgr.into_engine().unwrap();
}

#[test]
#[allow(clippy::too_many_lines)]
fn zvol_nbd_unix_tcp_always_readonly_flush_barrier_and_revocation() {
    let cx = Cx::for_testing();
    let ts = Timestamp {
        seconds: 1_726_400_000,
        nanos: 0,
    };
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        image_bytes: 20 * 1024 * 1024,
        ashift: 9,
        ..PoolFixtureSpec::default()
    });
    let dev = FaultableMemberDevice::new(built.members[0].clone());
    let engine = open_engine_on_devices(
        &cx,
        std::slice::from_ref(&dev),
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .unwrap();
    let mgr = ZfsVolumeManager::new(engine);
    let parent_ds = vec![b"data".to_vec()];
    let vol_ds = vec![b"data".to_vec(), b"nbd0".to_vec()];

    let (vol_info, _) = mgr
        .zvol_create(
            &cx,
            &parent_ds,
            b"nbd0",
            &ZfsZvolCreateOptions {
                volsize: 256 * 1024,
                volblocksize: 4096,
                sparse: true,
                initial_props: Vec::new(),
                timestamp: ts,
            },
        )
        .into_result()
        .unwrap();

    let tmp = tempfile::tempdir().unwrap();

    // 1. Unix socket NBD with ZvolSyncPolicy::Always + framing verification + ByteDevice impl.
    let sock_always = tmp.path().join("zvol-always.sock");
    let sess = mgr
        .open_writable_session(
            &cx,
            &vol_ds,
            ZvolSyncPolicy::Always,
            true,
            ZfsDataChecksum::Fletcher4,
        )
        .unwrap();
    let mut server = ZfsZvolNbdServer::bind_session_unix(
        &sock_always,
        sess,
        NbdServerConfig {
            export_name: "data/nbd0".to_owned(),
            once: false,
        },
    )
    .unwrap();
    let srv_cx = Cx::for_testing();
    let srv_cx_stop = srv_cx.clone();
    let handle = thread::spawn(move || server.serve(&srv_cx));

    assert_eq!(
        ZfsZvolNbdClient::list_exports_unix(&cx, &sock_always).unwrap(),
        vec!["data/nbd0".to_owned()]
    );
    assert!(matches!(
        ZfsZvolNbdClient::connect_unix(&cx, &sock_always, "data/wrong"),
        Err(FfsError::NotFound(_))
    ));

    let client = ZfsZvolNbdClient::connect_unix(&cx, &sock_always, "data/nbd0").unwrap();
    assert_eq!(client.info().size_bytes, 256 * 1024);
    assert_eq!(client.info().min_block_bytes, 512);
    assert_eq!(client.info().preferred_block_bytes, 4096);
    assert!(!client.info().is_read_only());
    assert!(
        client.info().supports_flush()
            && client.info().supports_fua()
            && client.info().supports_trim()
    );

    // Rejected unaligned WRITE must drain its 512B payload so framing stays intact!
    let sector = vec![0xAB_u8; 512];
    assert!(client.write_at(&cx, 13, &sector, false).is_err());

    // Subsequent writes, FUA write, TRIM, FLUSH, and ByteDevice reads on SAME connection succeed!
    client.write_at(&cx, 512, &sector, false).unwrap();
    let blk_data = vec![0xCD_u8; 8192];
    client.write_at(&cx, 4096, &blk_data, true).unwrap();
    client.trim(&cx, 4096, 4096).unwrap();
    client.flush(&cx).unwrap();

    let mut check = vec![0_u8; 12_288];
    client
        .read_exact_at(&cx, ByteOffset(0), &mut check)
        .unwrap();
    assert_eq!(&check[..512], &vec![0_u8; 512][..]);
    assert_eq!(&check[512..1024], &sector[..]);
    assert_eq!(&check[4096..8192], &vec![0_u8; 4096][..]);
    assert_eq!(&check[8192..12_288], &vec![0xCD_u8; 4096][..]);
    client.disconnect(&cx).unwrap();

    srv_cx_stop.cancel_with(asupersync::types::CancelKind::User, Some("done"));
    let audit = handle.join().unwrap().unwrap();
    assert!(audit.iter().any(|e| {
        e.cmd == "WRITE" && e.ack_kind == ZvolAckKind::DurableTxg && e.token.is_some()
    }));

    // Verify snapshot + strictly read-only TCP NBD export (`NBD_EPERM` draining payload).
    mgr.zvol_snapshot(&cx, &vol_ds, b"s1", ts)
        .into_result()
        .unwrap();
    let snap_slot = mgr.committed_slot().unwrap();
    let ro_dev = dev.fresh_from_durable();
    let ro_leaf = Leaf::from_device(&cx, Box::new(ro_dev), 0, dev.len_bytes()).unwrap();
    let mut ro_mos = ro_leaf.objects(&cx, 0, snap_slot, built.pool_guid).unwrap();
    let ro_zvol = ro_mos.zvol(&cx, &vol_ds, Some(b"s1")).unwrap();
    let mut ro_srv = ZfsZvolNbdServer::bind_readonly_tcp(
        "127.0.0.1:0",
        ro_zvol,
        NbdServerConfig {
            export_name: "data/nbd0@s1".to_owned(),
            once: true,
        },
    )
    .unwrap();
    let ro_addr = ro_srv.local_tcp_addr().unwrap().unwrap();
    let ro_cx = Cx::for_testing();
    let ro_handle = thread::spawn(move || ro_srv.serve(&ro_cx));

    let ro_client = ZfsZvolNbdClient::connect_tcp(&cx, ro_addr, "data/nbd0@s1").unwrap();
    assert!(ro_client.info().is_read_only());
    assert!(matches!(
        ro_client.write_at(&cx, 512, &vec![0xEE_u8; 512], false),
        Err(FfsError::ReadOnly)
    ));
    let mut ro_read = vec![0_u8; 512];
    ro_client.read_at(&cx, 512, &mut ro_read).unwrap();
    assert_eq!(ro_read, sector);
    ro_client.disconnect(&cx).unwrap();
    let ro_audit = ro_handle.join().unwrap().unwrap();
    assert!(
        ro_audit
            .iter()
            .any(|e| e.cmd == "WRITE" && e.nbd_error == ffs_zfs::zvol_nbd::NBD_EPERM)
    );

    // 2. `ZvolSyncPolicy::FlushBarrier`: disconnect without FLUSH drops uncommitted writes cleanly!
    let sock_fb = tmp.path().join("zvol-fb.sock");
    let fb_sess = mgr
        .open_writable_session(
            &cx,
            &vol_ds,
            ZvolSyncPolicy::FlushBarrier,
            true,
            ZfsDataChecksum::Fletcher4,
        )
        .unwrap();
    let mut fb_srv = ZfsZvolNbdServer::bind_session_unix(
        &sock_fb,
        fb_sess,
        NbdServerConfig {
            export_name: "data/nbd0".to_owned(),
            once: false,
        },
    )
    .unwrap();
    let fb_cx = Cx::for_testing();
    let fb_cx_stop = fb_cx.clone();
    let fb_handle = thread::spawn(move || fb_srv.serve(&fb_cx));

    // Client 1 writes without FUA/FLUSH, observes read-your-own-writes, then disconnects!
    let c1 = ZfsZvolNbdClient::connect_unix(&cx, &sock_fb, "data/nbd0").unwrap();
    let volatile_pat = vec![0x99_u8; 512];
    c1.write_at(&cx, 16_384, &volatile_pat, false).unwrap();
    let mut ryow = vec![0_u8; 512];
    c1.read_at(&cx, 16_384, &mut ryow).unwrap();
    assert_eq!(ryow, volatile_pat);
    c1.disconnect(&cx).unwrap();

    // Client 2 reconnects: uncommitted volatile writes MUST be gone (zeros)!
    let c2 = ZfsZvolNbdClient::connect_unix(&cx, &sock_fb, "data/nbd0").unwrap();
    let mut after_drop = vec![0xFF_u8; 512];
    c2.read_at(&cx, 16_384, &mut after_drop).unwrap();
    assert_eq!(after_drop, vec![0_u8; 512]);
    // Now write + explicit FLUSH -> durable!
    let durable_pat = vec![0x42_u8; 512];
    c2.write_at(&cx, 16_384, &durable_pat, false).unwrap();
    c2.flush(&cx).unwrap();

    // A FUA TRIM commits the preceding staged write and its discarded sector.
    let trim_base = 32_768;
    c2.write_at(&cx, trim_base, &[0x75; 4096], false).unwrap();
    c2.trim_with_fua(&cx, trim_base + 512, 512, true).unwrap();

    // Live epoch revocation while client is connected -> next request fails closed (`NBD_EIO`)!
    mgr.revoke_handles(vol_info.dataset_guid).unwrap();
    assert!(c2.read_at(&cx, 16_384, &mut after_drop).is_err());
    c2.disconnect(&cx).unwrap();

    fb_cx_stop.cancel_with(asupersync::types::CancelKind::User, Some("done"));
    let fb_audit = fb_handle.join().unwrap().unwrap();
    assert!(fb_audit.iter().any(|e| {
        e.cmd == "WRITE" && e.ack_kind == ZvolAckKind::StagedVolatile && e.token.is_none()
    }));
    assert!(fb_audit.iter().any(|e| {
        e.cmd == "FLUSH" && e.ack_kind == ZvolAckKind::DurableTxg && e.token.is_some()
    }));
    assert!(fb_audit.iter().any(|e| {
        e.cmd == "TRIM" && e.fua && e.ack_kind == ZvolAckKind::DurableTxg && e.token.is_some()
    }));

    // Fresh reopen from durable snapshot proves flushed pattern survived and scrub/allocation are clean!
    let final_slot = mgr.committed_slot().unwrap();
    let fresh = dev.fresh_from_durable();
    let reopened = open_engine_on_devices(
        &cx,
        std::slice::from_ref(&fresh),
        default_write_opts(built.pool_guid, final_slot),
    )
    .unwrap();
    let mut persisted = vec![0_u8; 512];
    reopened
        .zvol_read_at(&cx, &vol_ds, None, 16_384, &mut persisted)
        .unwrap();
    assert_eq!(persisted, durable_pat);
    let mut trimmed = [0_u8; 4096];
    reopened
        .zvol_read_at(&cx, &vol_ds, None, trim_base, &mut trimmed)
        .unwrap();
    let mut expected = [0x75; 4096];
    expected[512..1024].fill(0);
    assert_eq!(trimmed, expected);
    assert_zvol_and_pool_clean(
        &cx,
        std::slice::from_ref(&fresh),
        built.pool_guid,
        final_slot,
        Some(&vol_ds),
    );
}
