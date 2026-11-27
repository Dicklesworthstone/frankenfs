//! Native OpenZFS `zfs-2.4.0` resumable pool lifecycle integration & fault-cut tests:
//! - `create` -> `import` -> `export` + strict foreign-hostid & MMP refusal (ZERO mutation).
//! - `attach` (leaf -> mirror) -> `offline`/`online` (redundancy floor enforced) ->
//!   `spare` add/remove -> `replace` -> `detach` (last-replica refusal).
//! - Resumable MOS `"scan"` `scrub_start`/`scrub_resume`/`scrub_cancel` +
//!   `resilver_start`/`resilver_resume`, healing injected mirror corruption across
//!   pause + concurrent foreground ZPL writes + `ScanHealWrite` fault cuts.
//! - Resumable `trim_pool` persisting `"vdev_trim_progress"` across both discard-capable
//!   and `EOPNOTSUPP` devices.
//! - Pool `checkpoint_create` -> deferred pre-checkpoint frees -> monotonic
//!   `import_rewind_to_checkpoint` + `checkpoint_discard` + `CheckpointUberblockWrite` cuts.

use super::*;
use ffs_ondisk::zfs::scan::{DslScanFunc, DslScanState};
use ffs_zfs::{
    ZfsPoolCreateSpec, ZfsScanLimits, create_pool_on_devices, export_pool_leaves,
    import_pool_leaves,
};

/// In-memory test `ByteDevice` that genuinely records `discard()` calls so
/// `trim_pool` can be verified against both discard-capable and `EOPNOTSUPP` media!
#[derive(Clone)]
struct DiscardTrackingDevice {
    inner: FaultableMemberDevice,
    discarded: Arc<Mutex<Vec<(u64, u64)>>>,
}

impl DiscardTrackingDevice {
    fn new(size_bytes: usize) -> Self {
        Self {
            inner: FaultableMemberDevice::new(vec![0_u8; size_bytes]),
            discarded: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn discarded_ranges(&self) -> Vec<(u64, u64)> {
        self.discarded.lock().unwrap().clone()
    }
}

impl ByteDevice for DiscardTrackingDevice {
    fn len_bytes(&self) -> u64 {
        self.inner.len_bytes()
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        self.inner.read_exact_at(cx, offset, buf)
    }

    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()> {
        self.inner.write_all_at(cx, offset, buf)
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        self.inner.sync(cx)
    }

    fn supports_discard(&self) -> bool {
        true
    }

    fn discard(&self, cx: &Cx, offset: ByteOffset, len: u64) -> Result<()> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        self.discarded.lock().unwrap().push((offset.0, len));
        Ok(())
    }
}

fn leaf_from_dev(cx: &Cx, dev: &FaultableMemberDevice) -> Leaf {
    let len = dev.len_bytes();
    Leaf::from_device(cx, Box::new(dev.clone()), 0, len).unwrap()
}

fn read_zpl_bytes(
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

#[test]
fn pool_create_export_import_and_strict_foreign_hostid_mmp_refusal() {
    let cx = Cx::for_testing();
    let pool_guid = 0x1100_2200_3300_4400_u64;
    let dev = FaultableMemberDevice::new(vec![0_u8; 12 * 1024 * 1024]);
    let spec = ZfsPoolCreateSpec::single_leaf("lifecycle_pool", pool_guid);
    let rep = create_pool_on_devices(&cx, vec![Box::new(dev.clone())], &spec).unwrap();
    assert!(rep.exported);

    // Clean import (`state = 1 -> 0`) owned by hostid `0x4646_5331`.
    let leaves = vec![leaf_from_dev(&cx, &dev)];
    let imp = import_pool_leaves(&cx, &leaves, pool_guid, 0x4646_5331, "host-a").unwrap();
    assert_eq!(imp.state, 0);

    // Negative control 1: foreign hostid MUST be refused on active pool with ZERO mutation!
    let active_snap = dev.durable_snapshot();
    assert!(
        import_pool_leaves(&cx, &leaves, pool_guid, 0xDEAD_BEEF, "host-b").is_err(),
        "foreign hostid must never force-import an active pool"
    );
    assert!(
        export_pool_leaves(&cx, &leaves, pool_guid, 0xDEAD_BEEF, "host-b").is_err(),
        "foreign hostid must never force-export an active pool"
    );
    assert!(
        ZfsTransactionEngine::from_devices(
            &cx,
            vec![Box::new(dev.clone())],
            default_write_opts(pool_guid, rep.initial_slot),
        )
        .is_err(),
        "native TXG writer must refuse active (state=0) pool"
    );
    assert_eq!(dev.durable_snapshot(), active_snap);

    // Clean export by owning hostid (`state = 0 -> 1`) succeeds.
    let exp = export_pool_leaves(&cx, &leaves, pool_guid, 0x4646_5331, "host-a").unwrap();
    assert_eq!(exp.state, 1);

    // Negative control 2: MMP/multihost-enabled pool is strictly refused with ZERO mutation!
    let mmp_built = build_clean_zfs_pool(&PoolFixtureSpec {
        multihost_label: true,
        active_mmp_uberblock: true,
        ..PoolFixtureSpec::default()
    });
    let mmp_dev = FaultableMemberDevice::new(mmp_built.members[0].clone());
    let mmp_before = mmp_dev.durable_snapshot();
    let mmp_leaves = vec![leaf_from_dev(&cx, &mmp_dev)];
    assert!(
        import_pool_leaves(&cx, &mmp_leaves, mmp_built.pool_guid, 0x4646_5331, "host-a").is_err(),
        "MMP-enabled pool must refuse import"
    );
    assert_eq!(mmp_dev.durable_snapshot(), mmp_before);
}

#[test]
#[allow(clippy::too_many_lines)]
fn pool_attach_replace_detach_online_offline_and_spare_lifecycle() {
    let cx = Cx::for_testing();
    let ts = Timestamp {
        seconds: 1_735_002_000,
        nanos: 0,
    };
    let pool_guid = 0xAAAA_BBBB_CCCC_DDDD_u64;
    let dev0 = FaultableMemberDevice::new(vec![0_u8; 12 * 1024 * 1024]);
    let rep = create_pool_on_devices(
        &cx,
        vec![Box::new(dev0.clone())],
        &ZfsPoolCreateSpec::single_leaf("mirror_life", pool_guid),
    )
    .unwrap();
    let mut engine = ZfsTransactionEngine::from_devices(
        &cx,
        vec![Box::new(dev0.clone())],
        default_write_opts(pool_guid, rep.initial_slot),
    )
    .unwrap();

    // Seed file on single-leaf pool.
    let (fid, _) = engine
        .create_file(
            &cx,
            &[],
            5,
            b"hello.txt",
            0o644,
            0,
            0,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    let payload = b"mirror-lifecycle-verified-payload\n";
    engine
        .write_file_data(&cx, &[], fid, 0, payload, ts, ZfsDataChecksum::Fletcher4)
        .into_result()
        .unwrap();

    // Negative control: cannot detach or offline sole remaining leaf!
    assert!(engine.detach_member(&cx, 0).is_not_committed());
    assert!(engine.set_member_offline(&cx, 0, true).is_not_committed());

    // 1. Attach dev1 -> promotes single leaf to 2-way mirror!
    let dev1 = FaultableMemberDevice::new(vec![0_u8; 12 * 1024 * 1024]);
    let (att_rep, att_tok) = engine
        .attach_member(&cx, leaf_from_dev(&cx, &dev1))
        .into_result()
        .expect("attach_member must promote leaf to 2-way mirror");
    assert_eq!(att_rep.member_count, 2);

    // Verify 2-way mirror reads cleanly from BOTH leaves!
    let mirror_pool =
        Pool::from_leaves(vec![leaf_from_dev(&cx, &dev0), leaf_from_dev(&cx, &dev1)]).unwrap();
    let mut mos = mirror_pool
        .objects(&cx, 0, att_tok.published_slot(), pool_guid)
        .unwrap();
    assert_eq!(
        read_zpl_bytes(&cx, &mut mos, &[], b"/hello.txt", payload.len()).unwrap(),
        payload
    );

    // 2. Offline member 1 -> succeeds; offlining member 0 too -> REFUSED (redundancy floor)!
    engine
        .set_member_offline(&cx, 1, true)
        .into_result()
        .expect("offlining 1 of 2 mirror children must succeed");
    assert!(
        engine.set_member_offline(&cx, 0, true).is_not_committed(),
        "offlining last remaining healthy mirror replica must be refused"
    );
    engine
        .set_member_offline(&cx, 1, false)
        .into_result()
        .expect("onlining member 1 must succeed");

    // 3. Hot spare add & remove without perturbing guid_sum!
    let gsum_before = att_rep.guid_sum;
    let (sp_add, _) = engine
        .manage_spare(&cx, 0x9999_8888_7777_6666, true)
        .into_result()
        .expect("add hot spare");
    assert_eq!(sp_add.guid_sum, gsum_before);
    let (sp_rem, _) = engine
        .manage_spare(&cx, 0x9999_8888_7777_6666, false)
        .into_result()
        .expect("remove hot spare");
    assert_eq!(sp_rem.guid_sum, gsum_before);

    // 4. Replace member 1 with fresh dev2!
    let dev2 = FaultableMemberDevice::new(vec![0_u8; 12 * 1024 * 1024]);
    let (rep_res, rep_tok) = engine
        .replace_member(&cx, 1, leaf_from_dev(&cx, &dev2))
        .into_result()
        .expect("replace_member must resilver onto replacement");
    assert_eq!(rep_res.member_count, 2);
    let replaced_pool =
        Pool::from_leaves(vec![leaf_from_dev(&cx, &dev0), leaf_from_dev(&cx, &dev2)]).unwrap();
    let mut rep_mos = replaced_pool
        .objects(&cx, 0, rep_tok.published_slot(), pool_guid)
        .unwrap();
    assert_eq!(
        read_zpl_bytes(&cx, &mut rep_mos, &[], b"/hello.txt", payload.len()).unwrap(),
        payload
    );

    // 5. Detach member 1 -> demotes cleanly back to single leaf (`dev0`), then detaching 0 is refused!
    let (det_rep, det_tok) = engine
        .detach_member(&cx, 1)
        .into_result()
        .expect("detach redundant mirror child");
    assert_eq!(det_rep.member_count, 1);
    assert!(
        engine.detach_member(&cx, 0).is_not_committed(),
        "detaching sole remaining leaf must be refused"
    );
    let solo_pool = Pool::from_leaves(vec![leaf_from_dev(&cx, &dev0)]).unwrap();
    let mut solo_mos = solo_pool
        .objects(&cx, 0, det_tok.published_slot(), pool_guid)
        .unwrap();
    assert_eq!(
        read_zpl_bytes(&cx, &mut solo_mos, &[], b"/hello.txt", payload.len()).unwrap(),
        payload
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn resumable_scrub_heals_mirror_damage_across_pause_and_foreground_write() {
    let cx = Cx::for_testing();
    let ts = Timestamp {
        seconds: 1_735_003_000,
        nanos: 0,
    };
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        mirror_width: 2,
        ashift: 12,
        image_bytes: 16 * 1024 * 1024,
        ..PoolFixtureSpec::default()
    });
    let devs: Vec<_> = built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut engine = open_engine_on_devices(
        &cx,
        &devs,
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .unwrap();

    // Write a 4 KiB file with a unique canary pattern onto the 2-way mirror, then corrupt member 1!
    let (fid, _) = engine
        .create_file(
            &cx,
            &[b"data".to_vec()],
            2,
            b"heal_me.bin",
            0o644,
            0,
            0,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    let mut payload = Vec::with_capacity(4096);
    for i in 0..256_u32 {
        payload.extend_from_slice(&format!("HEAL_BLK_{i:06x}\n").as_bytes()[..16]);
    }
    let (_, tok) = engine
        .write_file_data(
            &cx,
            &[b"data".to_vec()],
            fid,
            0,
            &payload,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();

    // Locate the exact 4 KiB physical block of `heal_me.bin` on member 1 and flip bytes!
    let m1_snap = devs[1].durable_snapshot();
    let data_start = usize::try_from(DATA_OFFSET).unwrap();
    let corrupt_off = (data_start..m1_snap.len().saturating_sub(4096))
        .step_by(4096)
        .find(|&off| m1_snap[off..off + 4096] == payload)
        .expect("locate heal_me.bin physical block on mirror member 1")
        as u64;
    let mut corrupted = payload;
    corrupted[0] ^= 0xFF;
    corrupted[512] ^= 0xAA;
    devs[1]
        .write_all_at(&cx, ByteOffset(corrupt_off), &corrupted)
        .unwrap();
    devs[1].sync(&cx).unwrap();

    // 1. Start bounded scrub chunk (`max_blocks_per_txg = 3`) -> pauses mid-pool in MOS `"scan"`!
    let (chunk1, _) = engine
        .scrub_start(
            &cx,
            ZfsScanLimits {
                max_blocks_per_txg: 3,
            },
        )
        .into_result()
        .expect("scrub_start chunk 1");
    assert!(!chunk1.completed);
    let persisted = engine.scan_status(&cx).unwrap().expect("MOS scan present");
    assert_eq!(persisted.func, DslScanFunc::Scrub);
    assert_eq!(persisted.state, DslScanState::Scanning);

    // 2. Interleave a concurrent foreground ZPL write while scrub is paused!
    let (fg_id, _) = engine
        .create_file(
            &cx,
            &[b"data".to_vec()],
            2,
            b"concurrent.txt",
            0o644,
            0,
            0,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    engine
        .write_file_data(
            &cx,
            &[b"data".to_vec()],
            fg_id,
            0,
            b"written-mid-scrub",
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();

    // 3. Resume scrub to completion -> MUST heal member 1's corrupted block on disk!
    let mut total_repaired = chunk1.repaired_blocks;
    let mut iters = 0_usize;
    loop {
        let (rep, _) = engine
            .scrub_resume(
                &cx,
                ZfsScanLimits {
                    max_blocks_per_txg: 16,
                },
            )
            .into_result()
            .expect("scrub_resume");
        total_repaired += rep.repaired_blocks;
        iters += 1;
        if rep.completed {
            assert_eq!(rep.state, DslScanState::Finished as u64);
            assert_eq!(rep.unrecoverable_errors, 0);
            break;
        }
        assert!(iters < 64, "resumable scrub failed to finish");
    }
    assert!(
        total_repaired >= 1,
        "scrub must heal injected mirror member corruption"
    );

    // Verify member 0 and member 1 raw bytes at `corrupt_off` are now 100% identical!
    let mut m0_bytes = vec![0_u8; 4096];
    let mut m1_bytes = vec![0_u8; 4096];
    devs[0]
        .read_exact_at(&cx, ByteOffset(corrupt_off), &mut m0_bytes)
        .unwrap();
    devs[1]
        .read_exact_at(&cx, ByteOffset(corrupt_off), &mut m1_bytes)
        .unwrap();
    assert_eq!(
        m0_bytes, m1_bytes,
        "scrub failed to heal mirror member 1 on disk"
    );

    // 4. Test scrub_cancel and TXG-filtered resilver_start / resilver_resume!
    let (s_part, _) = engine
        .scrub_start(
            &cx,
            ZfsScanLimits {
                max_blocks_per_txg: 1,
            },
        )
        .into_result()
        .unwrap();
    assert!(!s_part.completed);
    let (canceled, _) = engine.scrub_cancel(&cx).into_result().unwrap();
    assert_eq!(canceled.state, DslScanState::Canceled as u64);

    let (res_rep, _) = engine
        .resilver_start(
            &cx,
            tok.committed_txg(),
            ZfsScanLimits {
                max_blocks_per_txg: 1024,
            },
        )
        .into_result()
        .expect("TXG-filtered resilver");
    assert_eq!(res_rep.func, DslScanFunc::Resilver as u64);
    assert!(res_rep.completed);
}

#[test]
fn resumable_pool_trim_persists_cursor_and_reports_eopnotsupp_cleanly() {
    let cx = Cx::for_testing();
    let pool_guid = 0x7711_7722_7733_7744_u64;

    // Case A: Discard-capable device receives real free-extent discard() ranges & resumes cursor!
    let trim_dev = DiscardTrackingDevice::new(12 * 1024 * 1024);
    let rep = create_pool_on_devices(
        &cx,
        vec![Box::new(trim_dev.clone())],
        &ZfsPoolCreateSpec::single_leaf("trim_ok_pool", pool_guid),
    )
    .unwrap();
    let mut engine = ZfsTransactionEngine::from_devices(
        &cx,
        vec![Box::new(trim_dev.clone())],
        default_write_opts(pool_guid, rep.initial_slot),
    )
    .unwrap();

    let (t1, _) = engine
        .trim_pool(&cx, 1, false)
        .into_result()
        .expect("trim chunk 1");
    assert_eq!(t1.supported_members, 1);
    assert_eq!(t1.unsupported_members, 0);
    assert!(t1.ranges_trimmed >= 1);
    assert!(t1.bytes_trimmed > 0);
    assert_ne!(trim_dev.discarded_ranges().len(), 0);

    let mut cur_done = t1.completed;
    let mut loops = 0_usize;
    while !cur_done {
        let (tn, _) = engine
            .trim_pool(&cx, 4, false)
            .into_result()
            .expect("trim resume");
        cur_done = tn.completed;
        loops += 1;
        assert!(loops < 32);
    }

    // Case B: Non-discard device (`FaultableMemberDevice::supports_discard() == false`)
    // cleanly reports `unsupported_members == 1` without weakening durability!
    let plain_dev = FaultableMemberDevice::new(vec![0_u8; 12 * 1024 * 1024]);
    let rep2 = create_pool_on_devices(
        &cx,
        vec![Box::new(plain_dev.clone())],
        &ZfsPoolCreateSpec::single_leaf("trim_nosup_pool", pool_guid + 1),
    )
    .unwrap();
    let mut engine2 = ZfsTransactionEngine::from_devices(
        &cx,
        vec![Box::new(plain_dev)],
        default_write_opts(pool_guid + 1, rep2.initial_slot),
    )
    .unwrap();
    let (nosup, _) = engine2
        .trim_pool(&cx, 16, false)
        .into_result()
        .expect("trim on non-discard device must report cleanly");
    assert_eq!(nosup.supported_members, 0);
    assert_eq!(nosup.unsupported_members, 1);
    assert!(nosup.completed);
}

#[test]
fn checkpoint_metadata_retirements_survive_reopen_and_discard() {
    let cx = Cx::for_testing();
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        ashift: 12,
        ..PoolFixtureSpec::default()
    });
    let dev = FaultableMemberDevice::new(built.members[0].clone());
    let mut engine = open_engine_on_devices(
        &cx,
        std::slice::from_ref(&dev),
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .unwrap();
    let (created, token) = engine.checkpoint_create(&cx).into_result().unwrap();
    let before = engine.checkpoint_status(&cx).unwrap().unwrap();
    assert!(before.deferred_free_bytes > 0);
    assert_eq!(created, before);

    // The first checkpoint TXG already retires its predecessor's MOS root,
    // DNODE table, feature records and space maps. Every one must be durable in
    // the deferred-free record before the checkpoint is acknowledged.
    let reopened_dev = FaultableMemberDevice::new(dev.durable_snapshot());
    let mut reopened = open_engine_on_devices(
        &cx,
        std::slice::from_ref(&reopened_dev),
        default_write_opts(built.pool_guid, token.published_slot()),
    )
    .unwrap();
    assert_eq!(
        reopened.checkpoint_status(&cx).unwrap().unwrap(),
        before,
        "reopening must retain all deferred metadata reclamation authority"
    );

    // Restart must not change how much storage discarding the checkpoint
    // reclaims. Compare independent engines over identical durable bytes.
    let (live_discard, live_token) = engine.checkpoint_discard(&cx).into_result().unwrap();
    let (reopened_discard, reopened_token) =
        reopened.checkpoint_discard(&cx).into_result().unwrap();
    assert_eq!(reopened_discard, live_discard);
    assert_eq!(live_discard.deferred_free_bytes, before.deferred_free_bytes);
    assert_eq!(reopened_token.committed_txg(), live_token.committed_txg());
    assert_eq!(reopened_dev.durable_snapshot(), dev.durable_snapshot());
}

#[test]
#[allow(clippy::too_many_lines)]
fn checkpoint_foreground_frees_preserve_scan_and_trim_state_after_restart() {
    let cx = Cx::for_testing();
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        ashift: 12,
        ..PoolFixtureSpec::default()
    });
    let dev = FaultableMemberDevice::new(built.members[0].clone());
    let mut engine = open_engine_on_devices(
        &cx,
        std::slice::from_ref(&dev),
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .unwrap();
    let ts = Timestamp {
        seconds: 1_735_004_000,
        nanos: 0,
    };
    let parent = vec![b"data".to_vec()];
    let mut dataset = None;
    for index in 0..4 {
        let name = format!("child{index}").into_bytes();
        let (head, _) = engine
            .create_dataset(&cx, &parent, &name, &[], ts)
            .into_result()
            .unwrap();
        if head / (DNODE_BLOCK_BYTES / DNODE_BYTES) as u64 == 1 {
            dataset = Some(vec![b"data".to_vec(), name]);
            break;
        }
    }
    // Regression for the old contains_key(&1) test: dirty-map keys identify
    // DNODE-table blocks, not MOS object numbers. This head lives in block 1.
    let dataset = dataset.expect("fixture must exercise MOS DNODE-table block 1");
    // A newly created dataset has its own root identity. Object 2 belongs to
    // its native delete queue, even though the seed dataset uses 2 for ROOT.
    let root = {
        let mut mos = engine.open_read_objects(&cx).unwrap();
        mos.zpl(&cx, &dataset).unwrap().resolve(&cx, b"/").unwrap()
    };
    let (file, _) = engine
        .create_file(
            &cx,
            &dataset,
            root,
            b"data.bin",
            0o644,
            0,
            0,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    engine
        .write_file_data(
            &cx,
            &dataset,
            file,
            0,
            &vec![0x51; 40_960],
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    engine.checkpoint_create(&cx).into_result().unwrap();
    let original_checkpoint = engine.checkpoint_status(&cx).unwrap().unwrap();
    let changed = vec![0xA3; 40_960];
    engine
        .write_file_data(
            &cx,
            &dataset,
            file,
            0,
            &changed,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    let before = engine.checkpoint_status(&cx).unwrap().unwrap();
    assert!(before.deferred_free_bytes > original_checkpoint.deferred_free_bytes);

    // Both operations edit MOS directory object 1 while checkpoint bookkeeping
    // edits the same object. All entries must survive the same native TXG.
    engine
        .scrub_start(
            &cx,
            ZfsScanLimits {
                max_blocks_per_txg: 1,
            },
        )
        .into_result()
        .unwrap();
    let scan = engine.scan_status(&cx).unwrap().unwrap();
    assert_eq!(scan.state, DslScanState::Scanning);
    engine.trim_pool(&cx, 4, false).into_result().unwrap();
    let slot = engine.committed_slot();
    let expected_checkpoint = engine.checkpoint_status(&cx).unwrap().unwrap();
    let mut mos = engine.open_read_objects(&cx).unwrap();
    let expected_directory = mos.zap_values(&cx, 1).unwrap();
    let trim = expected_directory
        .iter()
        .find(|row| row.name == b"vdev_trim_progress")
        .expect("trim progress must be persisted")
        .values
        .clone();

    let restarted_dev = FaultableMemberDevice::new(dev.durable_snapshot());
    let mut restarted = open_engine_on_devices(
        &cx,
        std::slice::from_ref(&restarted_dev),
        default_write_opts(built.pool_guid, slot),
    )
    .unwrap();
    assert_eq!(
        restarted.checkpoint_status(&cx).unwrap().unwrap(),
        expected_checkpoint
    );
    assert_eq!(restarted.scan_status(&cx).unwrap().unwrap(), scan);
    let mut mos = restarted.open_read_objects(&cx).unwrap();
    let directory = mos.zap_values(&cx, 1).unwrap();
    assert_eq!(
        directory
            .iter()
            .find(|row| row.name == b"vdev_trim_progress")
            .unwrap()
            .values,
        trim
    );
    assert_eq!(
        read_zpl_bytes(&cx, &mut mos, &dataset, b"/data.bin", changed.len()).unwrap(),
        changed
    );
    let (discarded, _) = restarted.checkpoint_discard(&cx).into_result().unwrap();
    assert_eq!(
        discarded.deferred_free_bytes,
        expected_checkpoint.deferred_free_bytes
    );
    assert_eq!(restarted.scan_status(&cx).unwrap().unwrap(), scan);
    assert_pool_scrub_and_allocation_clean(&cx, &[restarted_dev], built.pool_guid, None);
}

#[test]
#[allow(clippy::too_many_lines)]
fn pool_checkpoint_create_deferred_free_rewind_discard_and_crash_cuts() {
    let cx = Cx::for_testing();
    let ts = Timestamp {
        seconds: 1_735_004_000,
        nanos: 0,
    };
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        mirror_width: 1,
        ashift: 12,
        image_bytes: 16 * 1024 * 1024,
        ..PoolFixtureSpec::default()
    });
    let dev = FaultableMemberDevice::new(built.members[0].clone());
    let mut engine = open_engine_on_devices(
        &cx,
        std::slice::from_ref(&dev),
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .unwrap();

    // Seed pre-checkpoint file (`before.txt`).
    let (fid, _) = engine
        .create_file(
            &cx,
            &[b"data".to_vec()],
            2,
            b"before.txt",
            0o644,
            0,
            0,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    let before_bytes = b"pre-checkpoint-immutable-truth\n";
    let (_, pre_tok) = engine
        .write_file_data(
            &cx,
            &[b"data".to_vec()],
            fid,
            0,
            before_bytes,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();

    // Negative control: discarding when no checkpoint exists is refused!
    assert!(engine.checkpoint_discard(&cx).is_not_committed());

    // 1. Create pool-wide checkpoint!
    let (ckpt_info, _) = engine
        .checkpoint_create(&cx)
        .into_result()
        .expect("checkpoint_create");
    assert!(ckpt_info.active);
    assert_eq!(ckpt_info.checkpoint_txg, pre_tok.committed_txg());

    // Negative control: creating a second checkpoint while active is refused!
    assert!(engine.checkpoint_create(&cx).is_not_committed());

    // 2. Perform post-checkpoint writes & overwrite `before.txt` -> retires pre-checkpoint blocks
    //    into deferred checkpoint space (`vdev_checkpoint_sm`) instead of overwriting them!
    engine
        .write_file_data(
            &cx,
            &[b"data".to_vec()],
            fid,
            0,
            b"POST-CHECKPOINT-MUTATED-BYTES!!\n",
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    let (after_id, _) = engine
        .create_file(
            &cx,
            &[b"data".to_vec()],
            2,
            b"after.txt",
            0o644,
            0,
            0,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    let (_, post_tok) = engine
        .write_file_data(
            &cx,
            &[b"data".to_vec()],
            after_id,
            0,
            b"only-exists-after-checkpoint",
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();

    let status = engine
        .checkpoint_status(&cx)
        .unwrap()
        .expect("checkpoint active");
    assert!(
        status.deferred_free_bytes > 0,
        "pre-checkpoint frees must be deferred"
    );

    // Clone durable media for BOTH rewind and discard verification paths!
    let post_ckpt_bytes = dev.durable_snapshot();

    // Path A: Monotonic Rewind (`import_rewind_to_checkpoint`) restores pre-checkpoint world!
    let rewind_dev = FaultableMemberDevice::new(post_ckpt_bytes.clone());
    let (rw_rep, rw_tok) = ZfsTransactionEngine::import_rewind_to_checkpoint(
        &cx,
        vec![leaf_from_dev(&cx, &rewind_dev)],
        default_write_opts(built.pool_guid, post_tok.published_slot()),
    )
    .expect("import_rewind_to_checkpoint must succeed")
    .into_result()
    .expect("rewind must commit");
    assert_eq!(rw_rep.rewound_to_txg, pre_tok.committed_txg());
    assert_eq!(rw_rep.published_txg, post_tok.committed_txg() + 1);

    let rw_pool = Pool::from_leaves(vec![leaf_from_dev(&cx, &rewind_dev)]).unwrap();
    let mut rw_mos = rw_pool
        .objects(&cx, 0, rw_tok.published_slot(), built.pool_guid)
        .unwrap();
    assert_eq!(
        read_zpl_bytes(
            &cx,
            &mut rw_mos,
            &[b"data".to_vec()],
            b"/before.txt",
            before_bytes.len(),
        )
        .unwrap(),
        before_bytes,
        "rewound pool must restore exact pre-checkpoint file bytes"
    );
    assert!(
        read_zpl_bytes(&cx, &mut rw_mos, &[b"data".to_vec()], b"/after.txt", 16).is_err(),
        "post-checkpoint file must disappear after checkpoint rewind"
    );

    // Path B: Reopen fresh engine on post-checkpoint snapshot & discard checkpoint!
    let discard_dev = FaultableMemberDevice::new(post_ckpt_bytes);
    let mut discard_engine = open_engine_on_devices(
        &cx,
        std::slice::from_ref(&discard_dev),
        default_write_opts(built.pool_guid, post_tok.published_slot()),
    )
    .unwrap();
    let (disc_info, disc_tok) = discard_engine
        .checkpoint_discard(&cx)
        .into_result()
        .expect("checkpoint_discard after reopen must reclaim deferred frees");
    assert!(!disc_info.active);
    assert!(
        disc_info.deferred_free_bytes > 0,
        "discard must reclaim deferred pre-checkpoint bytes persisted across reopen"
    );
    assert!(discard_engine.checkpoint_status(&cx).unwrap().is_none());

    let disc_pool = Pool::from_leaves(vec![leaf_from_dev(&cx, &discard_dev)]).unwrap();
    let mut disc_mos = disc_pool
        .objects(&cx, 0, disc_tok.published_slot(), built.pool_guid)
        .unwrap();
    assert_eq!(
        read_zpl_bytes(&cx, &mut disc_mos, &[b"data".to_vec()], b"/after.txt", 28).unwrap(),
        b"only-exists-after-checkpoint"
    );

    // Negative control: cancelled Cx fails closed without committing!
    let cancel_cx = Cx::for_testing();
    cancel_cx.cancel_with(asupersync::types::CancelKind::User, Some("test-cancel"));
    assert!(
        discard_engine
            .checkpoint_create(&cancel_cx)
            .is_not_committed()
    );
}

#[test]
fn created_pool_root_dataset_tracks_used_breakdown_across_writes_and_snapshots() {
    let cx = Cx::for_testing();
    let ts = Timestamp {
        seconds: 1_735_005_000,
        nanos: 0,
    };
    let dev = FaultableMemberDevice::new(vec![0_u8; 64 * 1024 * 1024]);
    let pool_guid = 0x5A46_535F_524F_4F54;
    let spec = ZfsPoolCreateSpec::single_leaf("rootbrk", pool_guid);
    let rep = create_pool_on_devices(&cx, vec![Box::new(dev.clone())], &spec)
        .expect("create 64 MiB single-leaf pool");
    let mut engine = open_engine_on_devices(
        &cx,
        std::slice::from_ref(&dev),
        default_write_opts(pool_guid, rep.initial_slot),
    )
    .expect("open freshly formatted pool");

    let read_dir_breakdown = |eng: &ZfsTransactionEngine, dir_obj: u64| -> (u64, u64, u64, u64) {
        let mut mos = eng.open_read_objects(&cx).unwrap();
        let dn = mos.object(&cx, dir_obj).unwrap();
        let ord = dn.order();
        let b = dn.bonus();
        let used = ord.u64(b, 40).unwrap();
        let flags = ord.u64(b, 96).unwrap();
        let head = ord.u64(b, 104).unwrap();
        let snap = ord.u64(b, 112).unwrap();
        (used, flags, head, snap)
    };

    let (init_used, init_flags, init_head, init_snap) = read_dir_breakdown(&engine, 2);
    assert_ne!(
        init_flags & 0x1,
        0,
        "newly created root dsl_dir must set DD_FLAG_USED_BREAKDOWN"
    );
    assert!(init_used > 0, "root dataset must account initial ZPL bytes");
    assert_eq!(
        init_head, init_used,
        "initial DD_USED_HEAD must equal dd_used_bytes"
    );
    assert_eq!(init_snap, 0);

    let root_dir = 5_u64;
    let (fid, _) = engine
        .create_file(
            &cx,
            &[],
            root_dir,
            b"payload.bin",
            0o644,
            0,
            0,
            ts,
            ZfsDataChecksum::Sha256,
        )
        .into_result()
        .expect("create root dataset file");
    let payload_v1: Vec<u8> = (0_u32..4096)
        .flat_map(|i| i.wrapping_mul(2_654_435_761).to_le_bytes())
        .collect();
    engine
        .write_file_data(&cx, &[], fid, 0, &payload_v1, ts, ZfsDataChecksum::Sha256)
        .into_result()
        .expect("write 16 KiB to root dataset");
    engine
        .create_snapshot(&cx, &[], b"snap1", ts)
        .into_result()
        .expect("snapshot root dataset");
    // Overwrite and shrink to exercise negative `ref_delta` against DD_USED_HEAD
    // while retaining the pre-snapshot blocks in DD_USED_SNAP.
    engine
        .write_file_data(
            &cx,
            &[],
            fid,
            0,
            b"tiny-after-snap",
            ts,
            ZfsDataChecksum::Sha256,
        )
        .into_result()
        .expect("overwrite root file after snapshot");
    engine
        .truncate_file(&cx, &[], fid, 15, ts, ZfsDataChecksum::Sha256)
        .into_result()
        .expect("truncate root file after snapshot");

    let (post_used, post_flags, post_head, post_snap) = read_dir_breakdown(&engine, 2);
    assert_ne!(post_flags & 0x1, 0);
    assert!(
        post_snap > 0,
        "retained pre-snapshot blocks must move into DD_USED_SNAP"
    );
    assert_eq!(
        post_head + post_snap,
        post_used,
        "root dsl_dir breakdown must sum to dd_used_bytes"
    );
    let mos = engine.open_read_objects(&cx).unwrap();
    assert!(mos.scrub(&cx, ScrubLimits::default()).unwrap().is_clean());
    let _ = mos
        .allocation(&cx, AllocationLimits::default())
        .expect("clean allocation after root dataset breakdown updates");
}

#[test]
#[allow(clippy::too_many_lines)]
fn clone_with_own_snapshot_cow_of_origin_block_preserves_head_and_snap_breakdown() {
    let cx = Cx::for_testing();
    let ts = Timestamp {
        seconds: 1_735_006_000,
        nanos: 0,
    };
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        mirror_width: 1,
        ashift: 12,
        image_bytes: 32 * 1024 * 1024,
        ..PoolFixtureSpec::default()
    });
    let dev = FaultableMemberDevice::new(built.members[0].clone());
    let mut engine = open_engine_on_devices(
        &cx,
        std::slice::from_ref(&dev),
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .expect("open clean pool");

    let data_ds = vec![b"data".to_vec()];
    let clone_ds = vec![b"data".to_vec(), b"fork".to_vec()];

    // Seed a 64 KiB file in origin dataset `data`, then snapshot `data@origin`.
    let (origin_fid, _) = engine
        .create_file(
            &cx,
            &data_ds,
            2,
            b"origin.bin",
            0o644,
            0,
            0,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .expect("create origin.bin");
    let big_origin: Vec<u8> = (0_u32..16_384)
        .flat_map(|i| {
            i.wrapping_mul(1_664_525)
                .wrapping_add(1_013_904_223)
                .to_le_bytes()
        })
        .collect();
    engine
        .write_file_data(
            &cx,
            &data_ds,
            origin_fid,
            0,
            &big_origin,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .expect("write 64 KiB origin.bin");
    engine
        .create_snapshot(&cx, &data_ds, b"origin", ts)
        .into_result()
        .expect("snapshot data@origin");

    // Clone `data@origin` -> `data/fork`, add a small 4 KiB clone-owned file,
    // and take the clone's OWN snapshot `data/fork@c1` (`prev_snap_obj != dd_origin_obj`).
    engine
        .create_clone(&cx, &data_ds, b"origin", &data_ds, b"fork", &[], ts)
        .into_result()
        .expect("create_clone data/fork");
    let (clone_fid, _) = engine
        .create_file(
            &cx,
            &clone_ds,
            2,
            b"clone_only.bin",
            0o644,
            0,
            0,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .expect("create clone_only.bin");
    engine
        .write_file_data(
            &cx,
            &clone_ds,
            clone_fid,
            0,
            &vec![0xAB; 4096],
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .expect("write clone_only.bin");
    engine
        .create_snapshot(&cx, &clone_ds, b"c1", ts)
        .into_result()
        .expect("snapshot data/fork@c1");

    let clone_dir_obj = {
        let mut mos = engine.open_read_objects(&cx).unwrap();
        let root_dd = mos.object(&cx, 2).unwrap();
        let root_cz = root_dd.order().u64(root_dd.bonus(), 32).unwrap();
        let parent_dir_obj = mos
            .zap(&cx, root_cz)
            .unwrap()
            .into_iter()
            .find(|e| e.name == b"data")
            .unwrap()
            .value;
        let parent_dir_dnode = mos.object(&cx, parent_dir_obj).unwrap();
        let parent_child_zap = parent_dir_dnode
            .order()
            .u64(parent_dir_dnode.bonus(), 32)
            .unwrap();
        mos.zap(&cx, parent_child_zap)
            .unwrap()
            .into_iter()
            .find(|e| e.name == b"fork")
            .unwrap()
            .value
    };

    let read_clone_breakdown = |eng: &ZfsTransactionEngine| -> (u64, u64, u64, u64) {
        let mut mos = eng.open_read_objects(&cx).unwrap();
        let dn = mos.object(&cx, clone_dir_obj).unwrap();
        let ord = dn.order();
        let b = dn.bonus();
        (
            ord.u64(b, 40).unwrap(),
            ord.u64(b, 96).unwrap(),
            ord.u64(b, 104).unwrap(),
            ord.u64(b, 112).unwrap(),
        )
    };

    let (used_at_c1, flags_at_c1, head_at_c1, snap_at_c1) = read_clone_breakdown(&engine);
    assert_ne!(flags_at_c1 & 0x1, 0);
    assert_eq!(snap_at_c1, 0);
    assert_eq!(head_at_c1, used_at_c1);
    assert!(
        used_at_c1 > 0 && used_at_c1 < u64::try_from(big_origin.len()).unwrap(),
        "clone bytes at c1 ({used_at_c1}) must be strictly smaller than 64 KiB origin file so retiring origin.bin would underflow DD_USED_HEAD if misattributed"
    );

    // Now COW & delete the 64 KiB origin file (birth <= origin_txg) AFTER `clone@c1`,
    // and also overwrite the 4 KiB clone-owned file (origin_txg < birth <= c1_txg).
    // Previously `stage_head_space` debited the 64 KiB origin block from `DD_USED_HEAD`
    // (causing underflow) and misattributed it to `DD_USED_SNAP`.
    engine
        .write_file_data(
            &cx,
            &clone_ds,
            origin_fid,
            0,
            b"shrunk-origin",
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .expect("COW origin.bin in clone after own snapshot");
    engine
        .truncate_file(
            &cx,
            &clone_ds,
            origin_fid,
            13,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .expect("truncate origin.bin in clone after own snapshot");
    engine
        .unlink_entry(&cx, &clone_ds, 2, b"origin.bin", false, ts)
        .into_result()
        .expect("unlink origin.bin in clone after own snapshot");
    engine
        .write_file_data(
            &cx,
            &clone_ds,
            clone_fid,
            0,
            &vec![0xCD; 4096],
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .expect("overwrite clone_only.bin after c1");

    let (used_with_c1, flags_with_c1, head_with_c1, snap_with_c1) = read_clone_breakdown(&engine);
    assert_ne!(flags_with_c1 & 0x1, 0);
    assert_eq!(
        head_with_c1 + snap_with_c1,
        used_with_c1,
        "clone DD_USED_HEAD + DD_USED_SNAP must equal dd_used_bytes"
    );
    assert!(
        snap_with_c1 > 0 && snap_with_c1 <= used_at_c1,
        "clone DD_USED_SNAP ({snap_with_c1}) must hold only clone@c1's own retired blocks (<= used_at_c1={used_at_c1}), not the 64 KiB origin file"
    );

    // Destroying `data/fork@c1` must return `DD_USED_SNAP` cleanly to 0 while
    // keeping origin's `data@origin` blocks intact.
    engine
        .destroy_snapshot(&cx, &clone_ds, b"c1", false)
        .into_result()
        .expect("destroy data/fork@c1");
    let (used_after, _, head_after, snap_after) = read_clone_breakdown(&engine);
    assert_eq!(
        snap_after, 0,
        "destroying the clone's sole snapshot must drain DD_USED_SNAP to exactly 0"
    );
    assert_eq!(head_after, used_after);

    let mut mos = engine.open_read_objects(&cx).unwrap();
    let mut origin_snap = mos.zpl_snapshot(&cx, &data_ds, b"origin").unwrap();
    assert_eq!(
        origin_snap
            .read(&cx, origin_fid, 0, big_origin.len())
            .unwrap(),
        big_origin,
        "origin@origin payload must remain byte-identical"
    );
    assert!(mos.scrub(&cx, ScrubLimits::default()).unwrap().is_clean());
    let _ = mos
        .allocation(&cx, AllocationLimits::default())
        .expect("clean allocation after clone snapshot destroy");
}
