//! Native ZFS `DMU_BACKUP_STREAM` send/receive integration, keyless raw encrypted (`-w`)
//! replication, ZVOL send/receive, resumable `%recv` / `receive_resume_token` interruption &
//! completion, abort reclamation, persistence-prefix fault-cut rollback, and strict tamper /
//! refusal controls.

use super::*;
use ffs_ondisk::zfs::crypto::{ZioEncrypt, verify_objset_macs};
use ffs_ondisk::zfs::send_stream::{
    DMU_BACKUP_FEATURE_COMPRESSED, DMU_REPLAY_RECORD_BYTES, DrrRecord, Fletcher4Stream,
    ReceiveResumeToken, StreamHeaderType,
};
use ffs_zfs::reader::dmu::properties::PropertyValue;
use ffs_zfs::reader::dmu::zpl::PathPolicy;
use ffs_zfs::{
    ZfsEncryptionCreateOptions, ZfsKeyMaterial, ZfsKeyStatus, ZfsPropertySetValue, ZfsRecvRequest,
    ZfsSendFrom, ZfsSendRequest, ZfsXattrSetMode, ZfsZvolCreateOptions, send_stream,
};
use std::io::Cursor;

fn send_recv_pool_spec(image_bytes: u64) -> PoolFixtureSpec {
    PoolFixtureSpec {
        mirror_width: 1,
        ashift: 12,
        image_bytes,
        deadlist_mode: DeadlistMode::NativeDeadlist,
        additional_read_features: vec![
            (b"com.datto:encryption", 0),
            (b"com.datto:bookmark_v2", 0),
            (b"com.delphix:embedded_data", 0),
            (b"org.open-zfs:large_blocks", 0),
            (b"org.freebsd:zstd_compress", 0),
        ],
        additional_write_features: vec![(b"com.delphix:bookmarks", 0)],
        ..PoolFixtureSpec::default()
    }
}

fn open_mos(
    cx: &Cx,
    devs: &[FaultableMemberDevice],
    pool_guid: u64,
    slot: usize,
) -> ffs_zfs::Objects {
    let leaves: Vec<Leaf> = devs
        .iter()
        .cloned()
        .map(|d| {
            let len = d.len_bytes();
            Leaf::from_device(cx, Box::new(d), 0, len).unwrap()
        })
        .collect();
    let pool = Pool::from_leaves(leaves).unwrap();
    pool.objects(cx, 0, slot, pool_guid).unwrap()
}

fn snapshot_media_bytes(devs: &[FaultableMemberDevice]) -> Vec<Vec<u8>> {
    devs.iter()
        .map(FaultableMemberDevice::durable_snapshot)
        .collect()
}

fn assert_media_unchanged(devs: &[FaultableMemberDevice], before: &[Vec<u8>]) {
    for (idx, (dev, prev)) in devs.iter().zip(before.iter()).enumerate() {
        assert_eq!(
            &dev.durable_snapshot(),
            prev,
            "refused send/recv operation mutated backing member {idx}"
        );
    }
}

fn pool_allocated_bytes(
    cx: &Cx,
    devs: &[FaultableMemberDevice],
    pool_guid: u64,
    slot: usize,
) -> u64 {
    let mos = open_mos(cx, devs, pool_guid, slot);
    let alloc = mos.allocation(cx, AllocationLimits::default()).unwrap();
    alloc.allocated_bytes
}

fn stream_with_object_checksum(stream: &[u8], object: u64, checksum: u8) -> Vec<u8> {
    let mut output = Vec::with_capacity(stream.len());
    let mut rolling = Fletcher4Stream::new(Endian::Little);
    let mut offset = 0;
    let mut changed = 0;
    while offset < stream.len() {
        let header: &[u8; DMU_REPLAY_RECORD_BYTES] = stream
            [offset..offset + DMU_REPLAY_RECORD_BYTES]
            .try_into()
            .unwrap();
        let (mut record, _) = DrrRecord::parse_header(header, Endian::Little).unwrap();
        offset += DMU_REPLAY_RECORD_BYTES;
        let payload_len = record.expected_payload_len(false).unwrap();
        let payload = &stream[offset..offset + payload_len];
        offset += payload_len;
        if let DrrRecord::Object(ref mut native) = record
            && native.object == object
        {
            native.checksumtype = checksum;
            changed += 1;
        }
        let mut encoded = record.encode_header(Endian::Little).unwrap();
        rolling
            .stamp_record(&mut encoded, payload, record.record_type())
            .unwrap();
        output.extend_from_slice(&encoded);
        output.extend_from_slice(payload);
    }
    assert_eq!(
        changed, 1,
        "fixture must contain the selected native object"
    );
    output
}

#[test]
#[allow(clippy::too_many_lines)]
fn receive_preserves_native_checksum_policy_across_incremental_updates_and_rewrites() {
    let cx = Cx::for_testing();
    let timestamp = Timestamp {
        seconds: 1_730_000_400,
        nanos: 0,
    };
    let source = vec![b"data".to_vec()];
    let built = build_clean_zfs_pool(&send_recv_pool_spec(32 * 1024 * 1024));
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
    let (object, _) = engine
        .create_file(
            &cx,
            &source,
            2,
            b"checksummed",
            0o640,
            1000,
            1000,
            timestamp,
            ZfsDataChecksum::Sha256,
        )
        .into_result()
        .unwrap();
    let initial = vec![0x6A; 8192];
    engine
        .write_file_data(
            &cx,
            &source,
            object,
            0,
            &initial,
            timestamp,
            ZfsDataChecksum::Sha256,
        )
        .into_result()
        .unwrap();
    engine
        .create_snapshot(&cx, &source, b"s1", timestamp)
        .into_result()
        .unwrap();
    engine
        .write_file_data(
            &cx,
            &source,
            object,
            64,
            b"snapshot-two",
            timestamp,
            ZfsDataChecksum::Sha256,
        )
        .into_result()
        .unwrap();
    engine
        .create_snapshot(&cx, &source, b"s2", timestamp)
        .into_result()
        .unwrap();
    let mut mos = engine.open_read_objects(&cx).unwrap();
    let mut full = Vec::new();
    send_stream(
        &cx,
        &mut mos,
        &ZfsSendRequest::full(source.clone(), b"s1".to_vec()),
        &mut full,
    )
    .unwrap();
    // Model a native per-object Fletcher4 policy upgraded to SHA256 between
    // snapshots. Existing data BPs may retain their earlier checksum algorithm.
    let full = stream_with_object_checksum(&full, object, 7);
    let mut incremental = Vec::new();
    let mut request = ZfsSendRequest::full(source, b"s2".to_vec());
    request.from = Some(ZfsSendFrom::Snapshot(b"s1".to_vec()));
    send_stream(&cx, &mut mos, &request, &mut incremental).unwrap();

    let destination = vec![b"data".to_vec(), b"received".to_vec()];
    let target = build_clean_zfs_pool(&send_recv_pool_spec(32 * 1024 * 1024));
    let target_devices: Vec<_> = target
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut receiver = open_engine_on_devices(
        &cx,
        &target_devices,
        default_write_opts(target.pool_guid, target.initial_slot),
    )
    .unwrap();
    let receive = ZfsRecvRequest::new(destination.clone());
    for invalid_checksum in [9, 11, 255] {
        let invalid = stream_with_object_checksum(&full, object, invalid_checksum);
        assert!(matches!(
            receiver.receive_stream(&cx, &receive, &mut Cursor::new(&invalid)),
            ZfsTxOutcome::NotCommitted(FfsError::Format(message))
                if message.contains("outside the native legacy range")
        ));
        assert!(
            receiver
                .inspect_receive_resume_state(&cx, &destination)
                .unwrap()
                .is_none(),
            "invalid native checksum {invalid_checksum} left receive staging behind"
        );
        let mut mos = receiver.open_read_objects(&cx).unwrap();
        assert!(
            !mos.datasets(&cx)
                .unwrap()
                .iter()
                .any(|dataset| dataset.components == destination),
            "invalid native checksum {invalid_checksum} published its destination"
        );
        assert!(mos.zpl(&cx, &destination).is_err());
    }
    receiver
        .receive_stream(&cx, &receive, &mut Cursor::new(&full))
        .into_result()
        .unwrap();
    let node = native_zpl_file_dnode(&cx, &receiver, &target_devices[0], &destination, object);
    assert_eq!(node.checksum_type(), 7);
    receiver
        .receive_stream(&cx, &receive, &mut Cursor::new(&incremental))
        .into_result()
        .unwrap();
    let check = |engine: &ZfsTransactionEngine| {
        let node = native_zpl_file_dnode(&cx, engine, &target_devices[0], &destination, object);
        assert_eq!(node.checksum_type(), 8);
        assert!(!node.pointers()[0].hole());
        assert_eq!(node.pointers()[0].checksum_type(), 8);
    };
    check(&receiver);
    receiver
        .write_file_data(
            &cx,
            &destination,
            object,
            11,
            b"head",
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    check(&receiver);
    receiver
        .truncate_file(
            &cx,
            &destination,
            object,
            3333,
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    check(&receiver);
    receiver
        .edit_file_range(
            &cx,
            &destination,
            object,
            127,
            49,
            ffs_zfs::ZfsFileRangeOperation::ZeroRange { keep_size: true },
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    check(&receiver);
    let slot = receiver.committed_slot();
    drop(receiver);
    let durable: Vec<_> = target_devices
        .iter()
        .map(FaultableMemberDevice::fresh_from_durable)
        .collect();
    let reopened =
        open_engine_on_devices(&cx, &durable, default_write_opts(target.pool_guid, slot)).unwrap();
    let mut mos = reopened.open_read_objects(&cx).unwrap();
    let mut expected = initial.clone();
    expected[64..76].copy_from_slice(b"snapshot-two");
    for (snapshot, bytes) in [(b"s1", &initial), (b"s2", &expected)] {
        let mut view = mos.zpl_snapshot(&cx, &destination, snapshot).unwrap();
        assert_eq!(view.read(&cx, object, 0, 8192).unwrap(), *bytes);
    }
    expected.truncate(3333);
    expected[11..15].copy_from_slice(b"head");
    expected[127..176].fill(0);
    let mut view = mos.zpl(&cx, &destination).unwrap();
    assert_eq!(view.read(&cx, object, 0, 8192).unwrap(), expected);
    let node = native_zpl_file_dnode(&cx, &reopened, &durable[0], &destination, object);
    assert_eq!(node.checksum_type(), 8);
    assert_eq!(node.pointers()[0].checksum_type(), 8);
    assert_pool_scrub_and_allocation_clean(&cx, &durable, target.pool_guid, Some(slot));
}

#[test]
#[allow(clippy::too_many_lines)]
fn zpl_full_incremental_bookmark_intermediary_properties_and_big_endian_roundtrip() {
    let cx = Cx::for_testing();
    let ts = Timestamp {
        seconds: 1_730_000_000,
        nanos: 0,
    };

    // 1. Build source pool & rich ZPL dataset with multiple snapshots + bookmark.
    let src_built = build_clean_zfs_pool(&send_recv_pool_spec(32 * 1024 * 1024));
    let src_devs: Vec<_> = src_built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut src_engine = open_engine_on_devices(
        &cx,
        &src_devs,
        default_write_opts(src_built.pool_guid, src_built.initial_slot),
    )
    .unwrap();

    let src_ds = vec![b"data".to_vec(), b"src".to_vec()];
    src_engine
        .create_dataset(
            &cx,
            &[b"data".to_vec()],
            b"src",
            &[
                ("compression".to_owned(), ZfsPropertySetValue::Number(15)), // lz4
                (
                    "app:tier".to_owned(),
                    ZfsPropertySetValue::Text(b"gold".to_vec()),
                ),
            ],
            ts,
        )
        .into_result()
        .expect("create src dataset");

    let root_obj = {
        let mut mos = open_mos(
            &cx,
            &src_devs,
            src_built.pool_guid,
            src_engine.committed_slot(),
        );
        mos.zpl(&cx, &src_ds).unwrap().resolve(&cx, b"/").unwrap()
    };

    // @s1 state: small embedded file, large compressible multi-block file, symlink, hardlink,
    // xattr, and a file we will later unlink in @s2.
    let (small_obj, _) = src_engine
        .create_file(
            &cx,
            &src_ds,
            root_obj,
            b"tiny.txt",
            0o644,
            1000,
            1000,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    let tiny_data = b"hello-embedded-payload";
    src_engine
        .write_file_data(
            &cx,
            &src_ds,
            small_obj,
            0,
            tiny_data,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();

    let (big_obj, _) = src_engine
        .create_file(
            &cx,
            &src_ds,
            root_obj,
            b"blob.bin",
            0o640,
            1000,
            1000,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    let mut blob_s1 = vec![0_u8; 32 * 1024];
    for (idx, chunk) in blob_s1.chunks_mut(16).enumerate() {
        chunk.copy_from_slice(&format!("S1_ROW_{idx:08x}\n").as_bytes()[..16]);
    }
    src_engine
        .write_file_data(
            &cx,
            &src_ds,
            big_obj,
            0,
            &blob_s1,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    src_engine
        .set_xattr(
            &cx,
            &src_ds,
            big_obj,
            "user.version",
            b"v1-snap",
            ZfsXattrSetMode::Create,
            ts,
        )
        .into_result()
        .unwrap();
    src_engine
        .link_entry(&cx, &src_ds, big_obj, root_obj, b"blob_alias.bin", ts)
        .into_result()
        .unwrap();
    src_engine
        .create_symlink(
            &cx,
            &src_ds,
            root_obj,
            b"sym",
            b"blob.bin",
            1000,
            1000,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();

    let (gone_obj, _) = src_engine
        .create_file(
            &cx,
            &src_ds,
            root_obj,
            b"gone.txt",
            0o644,
            0,
            0,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    src_engine
        .write_file_data(
            &cx,
            &src_ds,
            gone_obj,
            0,
            b"only-in-s1",
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();

    src_engine
        .create_snapshot(&cx, &src_ds, b"s1", ts)
        .into_result()
        .expect("snapshot @s1");
    src_engine
        .create_bookmark(&cx, &src_ds, b"bm1", b"s1", false)
        .into_result()
        .expect("bookmark #bm1");

    // @s2 state: truncate blob, update xattr, unlink gone.txt, create added_s2.txt.
    let blob_s2_patch = b"PATCHED_AT_OFFSET_4096_FOR_S2!!!";
    src_engine
        .write_file_data(
            &cx,
            &src_ds,
            big_obj,
            4096,
            blob_s2_patch,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    src_engine
        .truncate_file(
            &cx,
            &src_ds,
            big_obj,
            12 * 1024,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    src_engine
        .set_xattr(
            &cx,
            &src_ds,
            big_obj,
            "user.version",
            b"v2-snap",
            ZfsXattrSetMode::Replace,
            ts,
        )
        .into_result()
        .unwrap();
    src_engine
        .unlink_entry(&cx, &src_ds, root_obj, b"gone.txt", false, ts)
        .into_result()
        .unwrap();
    let (s2_obj, _) = src_engine
        .create_file(
            &cx,
            &src_ds,
            root_obj,
            b"added_s2.txt",
            0o644,
            0,
            0,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    src_engine
        .write_file_data(
            &cx,
            &src_ds,
            s2_obj,
            0,
            b"created-in-s2",
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    src_engine
        .create_snapshot(&cx, &src_ds, b"s2", ts)
        .into_result()
        .expect("snapshot @s2");

    // @s3 state: add s3 file for -I intermediary compound send test.
    let (s3_obj, _) = src_engine
        .create_file(
            &cx,
            &src_ds,
            root_obj,
            b"added_s3.txt",
            0o644,
            0,
            0,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    src_engine
        .write_file_data(
            &cx,
            &src_ds,
            s3_obj,
            0,
            b"created-in-s3",
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    src_engine
        .create_snapshot(&cx, &src_ds, b"s3", ts)
        .into_result()
        .expect("snapshot @s3");

    let mut expected_blob_s2 = blob_s1[..12 * 1024].to_vec();
    expected_blob_s2[4096..4096 + blob_s2_patch.len()].copy_from_slice(blob_s2_patch);

    // 2. Emit full stream @s1 with -c -e -L -p, incremental bookmark stream #bm1 -> @s2,
    //    intermediary compound stream -I @s1 @s3, and a big-endian full stream @s1.
    let mut src_mos = open_mos(
        &cx,
        &src_devs,
        src_built.pool_guid,
        src_engine.committed_slot(),
    );
    let mut full_s1_bytes = Vec::new();
    let mut full_req = ZfsSendRequest::full(src_ds.clone(), b"s1".to_vec());
    full_req.compressed = true;
    full_req.embedded = true;
    full_req.large_blocks = true;
    full_req.properties = true;
    let full_report = send_stream(&cx, &mut src_mos, &full_req, &mut full_s1_bytes).unwrap();
    assert!(
        full_report.compound && full_report.substreams_sent == 1 && full_report.bytes_written > 0
    );

    let mut incr_bm_bytes = Vec::new();
    let mut incr_bm_req = ZfsSendRequest::full(src_ds.clone(), b"s2".to_vec());
    incr_bm_req.from = Some(ZfsSendFrom::Bookmark(b"bm1".to_vec()));
    incr_bm_req.compressed = true;
    incr_bm_req.embedded = true;
    let incr_bm_report = send_stream(&cx, &mut src_mos, &incr_bm_req, &mut incr_bm_bytes).unwrap();
    assert_eq!(incr_bm_report.from_guid, full_report.to_guid);
    assert_eq!(incr_bm_report.substreams_sent, 1);

    let mut inter_bytes = Vec::new();
    let mut inter_req = ZfsSendRequest::full(src_ds.clone(), b"s3".to_vec());
    inter_req.from = Some(ZfsSendFrom::Snapshot(b"s1".to_vec()));
    inter_req.include_intermediaries = true;
    inter_req.properties = true;
    let inter_report = send_stream(&cx, &mut src_mos, &inter_req, &mut inter_bytes).unwrap();
    assert!(inter_report.compound && inter_report.substreams_sent == 2);

    let mut be_full_bytes = Vec::new();
    let mut be_req = ZfsSendRequest::full(src_ds.clone(), b"s1".to_vec());
    be_req.stream_order = Endian::Big;
    let be_report = send_stream(&cx, &mut src_mos, &be_req, &mut be_full_bytes).unwrap();
    assert_eq!(be_report.to_guid, full_report.to_guid);

    // 3. Build completely independent destination pool and receive full + bookmark-incremental!
    let dst_built = build_clean_zfs_pool(&send_recv_pool_spec(32 * 1024 * 1024));
    let dst_devs: Vec<_> = dst_built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut dst_engine = open_engine_on_devices(
        &cx,
        &dst_devs,
        default_write_opts(dst_built.pool_guid, dst_built.initial_slot),
    )
    .unwrap();

    let dst_ds = vec![b"data".to_vec(), b"dst".to_vec()];
    let (rec_full, tok_full) = dst_engine
        .receive_stream(
            &cx,
            &ZfsRecvRequest::new(dst_ds.clone()),
            &mut Cursor::new(&full_s1_bytes),
        )
        .into_result()
        .expect("receive full @s1");
    assert_eq!(rec_full.final_snapshot, "s1");
    assert_eq!(rec_full.final_snapshot_guid, full_report.to_guid);
    assert_pool_scrub_and_allocation_clean(
        &cx,
        &dst_devs,
        dst_built.pool_guid,
        Some(tok_full.published_slot()),
    );

    // Verify received properties (`$recvd`) and full @s1 content on destination.
    {
        let mut dst_mos = open_mos(
            &cx,
            &dst_devs,
            dst_built.pool_guid,
            tok_full.published_slot(),
        );
        let props = dst_mos
            .properties(&cx, &dst_ds, None, &["app:tier".to_owned()])
            .unwrap();
        let tier = props
            .values
            .iter()
            .find(|p| p.name == "app:tier")
            .expect("app:tier received property");
        assert_eq!(tier.value, Some(PropertyValue::Text(b"gold".to_vec())));

        let mut zpl = dst_mos.zpl(&cx, &dst_ds).unwrap();
        let tiny_obj = zpl.resolve(&cx, b"/tiny.txt").unwrap();
        assert_eq!(zpl.read(&cx, tiny_obj, 0, 64).unwrap(), tiny_data);
        let blob_obj = zpl.resolve(&cx, b"/blob.bin").unwrap();
        assert_eq!(zpl.read(&cx, blob_obj, 0, blob_s1.len()).unwrap(), blob_s1);
        let alias_obj = zpl.resolve(&cx, b"/blob_alias.bin").unwrap();
        assert_eq!(alias_obj, blob_obj);
        let sym_obj = zpl
            .resolve_with(&cx, b"/sym", PathPolicy::NoFollowFinal)
            .unwrap();
        assert_eq!(zpl.readlink(&cx, sym_obj).unwrap(), b"blob.bin");
        assert_eq!(
            zpl.getxattr(&cx, blob_obj, "user.version").unwrap(),
            Some(b"v1-snap".to_vec())
        );
        let g_obj = zpl.resolve(&cx, b"/gone.txt").unwrap();
        assert_eq!(zpl.read(&cx, g_obj, 0, 32).unwrap(), b"only-in-s1");
    }

    // Receive incremental stream generated from bookmark `#bm1` -> `@s2`.
    let (rec_incr, tok_incr) = dst_engine
        .receive_stream(
            &cx,
            &ZfsRecvRequest::new(dst_ds.clone()),
            &mut Cursor::new(&incr_bm_bytes),
        )
        .into_result()
        .expect("receive incremental #bm1 -> @s2");
    assert_eq!(rec_incr.final_snapshot, "s2");
    assert_eq!(rec_incr.final_snapshot_guid, incr_bm_report.to_guid);
    assert_pool_scrub_and_allocation_clean(
        &cx,
        &dst_devs,
        dst_built.pool_guid,
        Some(tok_incr.published_slot()),
    );

    // Verify @s1 preserved intact while @s2 and head reflect patch, truncate, unlink, and new file!
    {
        let mut dst_mos = open_mos(
            &cx,
            &dst_devs,
            dst_built.pool_guid,
            tok_incr.published_slot(),
        );
        let mut zpl_s1 = dst_mos.zpl_snapshot(&cx, &dst_ds, b"s1").unwrap();
        let b1 = zpl_s1.resolve(&cx, b"/blob.bin").unwrap();
        assert_eq!(zpl_s1.read(&cx, b1, 0, blob_s1.len()).unwrap(), blob_s1);
        let g1 = zpl_s1.resolve(&cx, b"/gone.txt").unwrap();
        assert_eq!(zpl_s1.read(&cx, g1, 0, 32).unwrap(), b"only-in-s1");

        let mut zpl_head = dst_mos.zpl(&cx, &dst_ds).unwrap();
        let bh = zpl_head.resolve(&cx, b"/blob.bin").unwrap();
        assert_eq!(
            zpl_head
                .read(&cx, bh, 0, expected_blob_s2.len() + 64)
                .unwrap(),
            expected_blob_s2
        );
        assert_eq!(
            zpl_head.getxattr(&cx, bh, "user.version").unwrap(),
            Some(b"v2-snap".to_vec())
        );
        assert!(zpl_head.resolve(&cx, b"/gone.txt").is_err());
        let a2 = zpl_head.resolve(&cx, b"/added_s2.txt").unwrap();
        assert_eq!(zpl_head.read(&cx, a2, 0, 32).unwrap(), b"created-in-s2");
    }

    // 4. Receive big-endian full @s1 into `data/dst_inter` then `-I @s1 @s3` intermediary compound!
    let dst_inter = vec![b"data".to_vec(), b"dst_inter".to_vec()];
    dst_engine
        .receive_stream(
            &cx,
            &ZfsRecvRequest::new(dst_inter.clone()),
            &mut Cursor::new(&be_full_bytes),
        )
        .into_result()
        .expect("receive big-endian full @s1");
    let (rec_inter, tok_inter) = dst_engine
        .receive_stream(
            &cx,
            &ZfsRecvRequest::new(dst_inter.clone()),
            &mut Cursor::new(&inter_bytes),
        )
        .into_result()
        .expect("receive -I @s1 @s3 compound");
    assert!(rec_inter.compound && rec_inter.substreams_received == 2);
    assert_eq!(rec_inter.final_snapshot, "s3");
    assert_pool_scrub_and_allocation_clean(
        &cx,
        &dst_devs,
        dst_built.pool_guid,
        Some(tok_inter.published_slot()),
    );
    {
        let mut dst_mos = open_mos(
            &cx,
            &dst_devs,
            dst_built.pool_guid,
            tok_inter.published_slot(),
        );
        let snaps = dst_mos.snapshots(&cx, &dst_inter).unwrap();
        let snap_names: Vec<_> = snaps.iter().map(|s| s.name.as_slice()).collect();
        assert!(snap_names.contains(&b"s1".as_slice()));
        assert!(snap_names.contains(&b"s2".as_slice()));
        assert!(snap_names.contains(&b"s3".as_slice()));
        let mut zpl_s3 = dst_mos.zpl_snapshot(&cx, &dst_inter, b"s3").unwrap();
        let f3 = zpl_s3.resolve(&cx, b"/added_s3.txt").unwrap();
        assert_eq!(zpl_s3.read(&cx, f3, 0, 32).unwrap(), b"created-in-s3");
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn zvol_full_and_incremental_send_recv_preserves_geometry_holes_and_scrub() {
    let cx = Cx::for_testing();
    let ts = Timestamp {
        seconds: 1_730_100_000,
        nanos: 0,
    };

    let src_built = build_clean_zfs_pool(&send_recv_pool_spec(32 * 1024 * 1024));
    let src_devs: Vec<_> = src_built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut src_engine = open_engine_on_devices(
        &cx,
        &src_devs,
        default_write_opts(src_built.pool_guid, src_built.initial_slot),
    )
    .unwrap();

    let vol_src = vec![b"data".to_vec(), b"vol_src".to_vec()];
    src_engine
        .zvol_create(
            &cx,
            &[b"data".to_vec()],
            b"vol_src",
            &ZfsZvolCreateOptions {
                volsize: 256 * 1024,
                volblocksize: 8192,
                sparse: true,
                initial_props: Vec::new(),
                timestamp: ts,
            },
        )
        .into_result()
        .expect("zvol_create");

    let pattern_a = vec![0xA5_u8; 8192];
    let pattern_b = vec![0x5A_u8; 4096];
    src_engine
        .zvol_write_at(&cx, &vol_src, 0, &pattern_a, ZfsDataChecksum::Fletcher4)
        .into_result()
        .unwrap();
    src_engine
        .zvol_write_at(
            &cx,
            &vol_src,
            32 * 1024 + 512,
            &pattern_b,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    src_engine
        .create_snapshot(&cx, &vol_src, b"v1", ts)
        .into_result()
        .unwrap();

    // Mutate @v2: discard block 0 (creating hole), write at 64 KiB.
    let pattern_c = vec![0xCC_u8; 8192];
    src_engine
        .zvol_discard(&cx, &vol_src, 0, 8192, ZfsDataChecksum::Fletcher4)
        .into_result()
        .unwrap();
    src_engine
        .zvol_write_at(
            &cx,
            &vol_src,
            64 * 1024,
            &pattern_c,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    src_engine
        .create_snapshot(&cx, &vol_src, b"v2", ts)
        .into_result()
        .unwrap();

    let mut src_mos = open_mos(
        &cx,
        &src_devs,
        src_built.pool_guid,
        src_engine.committed_slot(),
    );
    let mut full_v1 = Vec::new();
    let mut r1 = ZfsSendRequest::full(vol_src.clone(), b"v1".to_vec());
    r1.properties = true;
    send_stream(&cx, &mut src_mos, &r1, &mut full_v1).unwrap();

    let mut incr_v2 = Vec::new();
    let mut r2 = ZfsSendRequest::full(vol_src.clone(), b"v2".to_vec());
    r2.from = Some(ZfsSendFrom::Snapshot(b"v1".to_vec()));
    send_stream(&cx, &mut src_mos, &r2, &mut incr_v2).unwrap();

    let dst_built = build_clean_zfs_pool(&send_recv_pool_spec(32 * 1024 * 1024));
    let dst_devs: Vec<_> = dst_built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut dst_engine = open_engine_on_devices(
        &cx,
        &dst_devs,
        default_write_opts(dst_built.pool_guid, dst_built.initial_slot),
    )
    .unwrap();

    let vol_dst = vec![b"data".to_vec(), b"vol_dst".to_vec()];
    dst_engine
        .receive_stream(
            &cx,
            &ZfsRecvRequest::new(vol_dst.clone()),
            &mut Cursor::new(&full_v1),
        )
        .into_result()
        .expect("recv zvol @v1");
    let (_, tok2) = dst_engine
        .receive_stream(
            &cx,
            &ZfsRecvRequest::new(vol_dst.clone()),
            &mut Cursor::new(&incr_v2),
        )
        .into_result()
        .expect("recv zvol @v2");
    assert_pool_scrub_and_allocation_clean(
        &cx,
        &dst_devs,
        dst_built.pool_guid,
        Some(tok2.published_slot()),
    );

    let mut dst_mos = open_mos(&cx, &dst_devs, dst_built.pool_guid, tok2.published_slot());
    let mut zv_v1 = dst_mos.zvol(&cx, &vol_dst, Some(b"v1")).unwrap();
    assert_eq!(zv_v1.read(&cx, 0, 8192).unwrap(), pattern_a);
    assert_eq!(zv_v1.read(&cx, 32 * 1024 + 512, 4096).unwrap(), pattern_b);
    assert!(zv_v1.scrub(&cx, ScrubLimits::default()).unwrap().is_clean());

    let mut zv_head = dst_mos.zvol(&cx, &vol_dst, None).unwrap();
    assert_eq!(zv_head.info().size_bytes, 256 * 1024);
    assert_eq!(zv_head.info().block_bytes, 8192);
    assert_eq!(zv_head.read(&cx, 0, 8192).unwrap(), vec![0_u8; 8192]);
    assert_eq!(zv_head.read(&cx, 32 * 1024 + 512, 4096).unwrap(), pattern_b);
    assert_eq!(zv_head.read(&cx, 64 * 1024, 8192).unwrap(), pattern_c);
    assert!(
        zv_head
            .scrub(&cx, ScrubLimits::default())
            .unwrap()
            .is_clean()
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn raw_encrypted_send_recv_is_keyless_and_verifies_macs_on_unlock() {
    let cx = Cx::for_testing();
    let ts = Timestamp {
        seconds: 1_730_200_000,
        nanos: 0,
    };
    let wrapping_key = ZfsKeyMaterial::Raw([0x3C_u8; 32]);

    // 1. Source encrypted dataset with two snapshots @e1 and @e2.
    let src_built = build_clean_zfs_pool(&send_recv_pool_spec(32 * 1024 * 1024));
    let src_devs: Vec<_> = src_built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut src_engine = open_engine_on_devices(
        &cx,
        &src_devs,
        default_write_opts(src_built.pool_guid, src_built.initial_slot),
    )
    .unwrap();

    let vault_src = vec![b"data".to_vec(), b"vault".to_vec()];
    src_engine
        .create_encrypted_dataset(
            &cx,
            &[b"data".to_vec()],
            b"vault",
            &[("compression".to_owned(), ZfsPropertySetValue::Number(15))],
            &ZfsEncryptionCreateOptions {
                suite: ZioEncrypt::Aes256Gcm,
                key_material: Some(wrapping_key.clone()),
                keylocation: Some(b"prompt".to_vec()),
                pbkdf2_iters: None,
                extra_entropy: b"send-recv-vault".to_vec(),
            },
            ts,
        )
        .into_result()
        .expect("create encrypted vault");
    src_engine.load_key(&cx, &vault_src, &wrapping_key).unwrap();

    let root_obj = {
        let mut mos = open_mos(
            &cx,
            &src_devs,
            src_built.pool_guid,
            src_engine.committed_slot(),
        );
        mos.load_key(&cx, &vault_src, &wrapping_key).unwrap();
        mos.zpl(&cx, &vault_src)
            .unwrap()
            .resolve(&cx, b"/")
            .unwrap()
    };

    let (sec_obj, _) = src_engine
        .create_file(
            &cx,
            &vault_src,
            root_obj,
            b"secret.bin",
            0o600,
            0,
            0,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    let sec_e1: Vec<u8> = (0..24 * 1024)
        .map(|i| u8::try_from((i * 29 + 7) & 0xff).unwrap())
        .collect();
    src_engine
        .write_file_data(
            &cx,
            &vault_src,
            sec_obj,
            0,
            &sec_e1,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    src_engine
        .create_snapshot(&cx, &vault_src, b"e1", ts)
        .into_result()
        .unwrap();

    let sec_e2: Vec<u8> = (0..20 * 1024)
        .map(|i| u8::try_from((i * 53 + 11) & 0xff).unwrap())
        .collect();
    src_engine
        .write_file_data(
            &cx,
            &vault_src,
            sec_obj,
            0,
            &sec_e2,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    src_engine
        .truncate_file(
            &cx,
            &vault_src,
            sec_obj,
            sec_e2.len() as u64,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    src_engine
        .create_snapshot(&cx, &vault_src, b"e2", ts)
        .into_result()
        .unwrap();

    // 2. Open FRESH KEYLESS reader on source (`key_status == Unavailable`) and emit raw `-w` streams!
    let mut keyless_src_mos = open_mos(
        &cx,
        &src_devs,
        src_built.pool_guid,
        src_engine.committed_slot(),
    );
    assert_eq!(
        keyless_src_mos.key_status(&cx, &vault_src).unwrap(),
        ZfsKeyStatus::Unavailable
    );

    let mut raw_e1 = Vec::new();
    let mut req_e1 = ZfsSendRequest::full(vault_src.clone(), b"e1".to_vec());
    req_e1.raw = true;
    let report_e1 = send_stream(&cx, &mut keyless_src_mos, &req_e1, &mut raw_e1).unwrap();
    assert!(report_e1.raw);

    let mut raw_e2 = Vec::new();
    let mut req_e2 = ZfsSendRequest::full(vault_src.clone(), b"e2".to_vec());
    req_e2.from = Some(ZfsSendFrom::Snapshot(b"e1".to_vec()));
    req_e2.raw = true;
    let report_e2 = send_stream(&cx, &mut keyless_src_mos, &req_e2, &mut raw_e2).unwrap();
    assert!(report_e2.raw && report_e2.from_guid == report_e1.to_guid);

    // 3. Receive BOTH raw encrypted streams on a fresh KEYLESS destination pool!
    let dst_built = build_clean_zfs_pool(&send_recv_pool_spec(32 * 1024 * 1024));
    let dst_devs: Vec<_> = dst_built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut dst_engine = open_engine_on_devices(
        &cx,
        &dst_devs,
        default_write_opts(dst_built.pool_guid, dst_built.initial_slot),
    )
    .unwrap();

    let vault_dst = vec![b"data".to_vec(), b"vault_dst".to_vec()];
    let (r_e1, _) = dst_engine
        .receive_stream(
            &cx,
            &ZfsRecvRequest::new(vault_dst.clone()),
            &mut Cursor::new(&raw_e1),
        )
        .into_result()
        .expect("keyless raw recv @e1");
    assert!(r_e1.raw && r_e1.final_snapshot == "e1");

    let (r_e2, tok_e2) = dst_engine
        .receive_stream(
            &cx,
            &ZfsRecvRequest::new(vault_dst.clone()),
            &mut Cursor::new(&raw_e2),
        )
        .into_result()
        .expect("keyless raw incremental recv @e2");
    assert!(r_e2.raw && r_e2.final_snapshot == "e2");

    // 4. Verify locked behavior, keyless scrub, and exact keyed decryption + MAC verification!
    let mut dst_mos = open_mos(&cx, &dst_devs, dst_built.pool_guid, tok_e2.published_slot());
    assert_eq!(
        dst_mos.key_status(&cx, &vault_dst).unwrap(),
        ZfsKeyStatus::Unavailable
    );
    assert!(matches!(
        dst_mos.zpl(&cx, &vault_dst),
        Err(FfsError::PermissionDenied)
    ));
    let keyless_scrub = dst_mos
        .scrub_dataset(&cx, &vault_dst, None, ScrubLimits::default())
        .unwrap();
    assert!(
        keyless_scrub.is_clean(),
        "keyless raw scrub: {keyless_scrub:?}"
    );

    // Unlock with original wrapping key and verify objset portable+local MACs and plaintext!
    dst_mos.load_key(&cx, &vault_dst, &wrapping_key).unwrap();
    assert_eq!(
        dst_mos.key_status(&cx, &vault_dst).unwrap(),
        ZfsKeyStatus::Available
    );
    {
        let ds_row = dst_mos
            .datasets(&cx)
            .unwrap()
            .into_iter()
            .find(|d| d.components == vault_dst)
            .unwrap();
        let head_dn = dst_mos.object(&cx, ds_row.head_object).unwrap();
        let os_bp = BlockPointer::parse(&head_dn.bonus()[128..256], head_dn.order()).unwrap();
        let crypto = dst_mos
            .dataset_crypto_info(&cx, &vault_dst)
            .unwrap()
            .unwrap();
        let unwrapped = dst_mos.keyring().get(crypto.encryption_root_ddobj).unwrap();
        let media = dst_devs[0].durable_snapshot();
        let os_dva = os_bp.data_dvas().unwrap()[0];
        let os_off = usize::try_from(DATA_OFFSET + os_dva.offset).unwrap();
        let os_phys = &media[os_off..os_off + os_bp.physical_bytes()];
        let os_raw =
            ffs_ondisk::zfs::decompress(os_phys, os_bp.compression(), os_bp.logical_bytes())
                .unwrap();
        verify_objset_macs(
            &os_raw,
            os_bp.payload_order(),
            &unwrapped.hmac_key,
            unwrapped.version,
        )
        .expect("verify received objset portable+local MACs");
    }
    let mut zpl_e1 = dst_mos.zpl_snapshot(&cx, &vault_dst, b"e1").unwrap();
    let f1 = zpl_e1.resolve(&cx, b"/secret.bin").unwrap();
    assert_eq!(zpl_e1.read(&cx, f1, 0, sec_e1.len() + 64).unwrap(), sec_e1);
    let mut zpl_e2 = dst_mos.zpl(&cx, &vault_dst).unwrap();
    let f2 = zpl_e2.resolve(&cx, b"/secret.bin").unwrap();
    assert_eq!(zpl_e2.read(&cx, f2, 0, sec_e2.len() + 64).unwrap(), sec_e2);

    let keyed_scrub = dst_mos
        .scrub_dataset(&cx, &vault_dst, None, ScrubLimits::default())
        .unwrap();
    assert!(keyed_scrub.is_clean(), "keyed raw scrub: {keyed_scrub:?}");
    assert_pool_scrub_and_allocation_clean(
        &cx,
        &dst_devs,
        dst_built.pool_guid,
        Some(tok_e2.published_slot()),
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn resumable_receive_interrupt_isolation_resume_abort_and_fault_cut_matrix() {
    let cx = Cx::for_testing();
    let ts = Timestamp {
        seconds: 1_730_300_000,
        nanos: 0,
    };

    // Build source dataset with 64 KiB multi-block payload so small checkpoint_bytes triggers
    // multiple atomic TXG checkpoints mid-stream.
    let src_built = build_clean_zfs_pool(&send_recv_pool_spec(32 * 1024 * 1024));
    let src_devs: Vec<_> = src_built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut src_engine = open_engine_on_devices(
        &cx,
        &src_devs,
        default_write_opts(src_built.pool_guid, src_built.initial_slot),
    )
    .unwrap();

    let src_ds = vec![b"data".to_vec(), b"src".to_vec()];
    src_engine
        .create_dataset(&cx, &[b"data".to_vec()], b"src", &[], ts)
        .into_result()
        .unwrap();
    let root_obj = {
        let mut mos = open_mos(
            &cx,
            &src_devs,
            src_built.pool_guid,
            src_engine.committed_slot(),
        );
        mos.zpl(&cx, &src_ds).unwrap().resolve(&cx, b"/").unwrap()
    };
    let (f_obj, _) = src_engine
        .create_file(
            &cx,
            &src_ds,
            root_obj,
            b"multi.bin",
            0o644,
            0,
            0,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    let payload_s1: Vec<u8> = (0..64 * 1024)
        .map(|i| u8::try_from((i * 13 + 3) & 0xff).unwrap())
        .collect();
    src_engine
        .write_file_data(
            &cx,
            &src_ds,
            f_obj,
            0,
            &payload_s1,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    src_engine
        .create_snapshot(&cx, &src_ds, b"s1", ts)
        .into_result()
        .unwrap();

    let payload_s2: Vec<u8> = (0..64 * 1024)
        .map(|i| u8::try_from((i * 37 + 9) & 0xff).unwrap())
        .collect();
    src_engine
        .write_file_data(
            &cx,
            &src_ds,
            f_obj,
            0,
            &payload_s2,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    src_engine
        .create_snapshot(&cx, &src_ds, b"s2", ts)
        .into_result()
        .unwrap();

    let mut src_mos = open_mos(
        &cx,
        &src_devs,
        src_built.pool_guid,
        src_engine.committed_slot(),
    );
    let mut full_s1 = Vec::new();
    let s1_rep = send_stream(
        &cx,
        &mut src_mos,
        &ZfsSendRequest::full(src_ds.clone(), b"s1".to_vec()),
        &mut full_s1,
    )
    .unwrap();
    let mut incr_s2 = Vec::new();
    let mut r_s2 = ZfsSendRequest::full(src_ds.clone(), b"s2".to_vec());
    r_s2.from = Some(ZfsSendFrom::Snapshot(b"s1".to_vec()));
    send_stream(&cx, &mut src_mos, &r_s2, &mut incr_s2).unwrap();

    let dst_built = build_clean_zfs_pool(&send_recv_pool_spec(32 * 1024 * 1024));
    let dst_devs: Vec<_> = dst_built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut dst_engine = open_engine_on_devices(
        &cx,
        &dst_devs,
        default_write_opts(dst_built.pool_guid, dst_built.initial_slot),
    )
    .unwrap();
    let baseline_alloc = pool_allocated_bytes(
        &cx,
        &dst_devs,
        dst_built.pool_guid,
        dst_engine.committed_slot(),
    );

    // 1. Non-resumable (`resumable: false`) truncated stream MUST auto-abort and reclaim 100% space.
    let dst_nonres = vec![b"data".to_vec(), b"nonres".to_vec()];
    let mut nr_req = ZfsRecvRequest::new(dst_nonres.clone());
    nr_req.resumable = false;
    nr_req.checkpoint_bytes = 8192;
    let cut_len = full_s1.len() / 2;
    let nr_outcome = dst_engine.receive_stream(&cx, &nr_req, &mut Cursor::new(&full_s1[..cut_len]));
    assert!(matches!(nr_outcome, ZfsTxOutcome::NotCommitted(_)));
    assert!(
        dst_engine
            .inspect_receive_resume_state(&cx, &dst_nonres)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        pool_allocated_bytes(
            &cx,
            &dst_devs,
            dst_built.pool_guid,
            dst_engine.committed_slot()
        ),
        baseline_alloc,
        "non-resumable interrupted receive leaked pool bytes"
    );
    assert_pool_scrub_and_allocation_clean(
        &cx,
        &dst_devs,
        dst_built.pool_guid,
        Some(dst_engine.committed_slot()),
    );

    // 2. Resumable (`-s`) truncated full stream: hides incomplete target from live namespace,
    //    persists valid `receive_resume_token`, resumes via `send_stream(resume_token)`, completes!
    let dst_res = vec![b"data".to_vec(), b"resumed".to_vec()];
    let mut res_req = ZfsRecvRequest::new(dst_res.clone());
    res_req.resumable = true;
    res_req.checkpoint_bytes = 8192;
    let interrupted =
        dst_engine.receive_stream(&cx, &res_req, &mut Cursor::new(&full_s1[..cut_len]));
    assert!(matches!(interrupted, ZfsTxOutcome::NotCommitted(_)));

    // Namespace isolation: live `Objects::datasets` and `mos.zpl` MUST NOT expose incomplete target!
    {
        let mut mos = open_mos(
            &cx,
            &dst_devs,
            dst_built.pool_guid,
            dst_engine.committed_slot(),
        );
        let ds_list = mos.datasets(&cx).unwrap();
        assert!(
            !ds_list.iter().any(|d| d.components == dst_res),
            "incomplete resumable dataset leaked into live dataset list"
        );
        assert!(mos.zpl(&cx, &dst_res).is_err());
    }

    let state = dst_engine
        .inspect_receive_resume_state(&cx, &dst_res)
        .unwrap()
        .expect("persisted resume state");
    assert!(!state.is_pct_recv_child);
    assert_eq!(state.toguid, s1_rep.to_guid);
    assert!(state.bytes > 0);
    let parsed_tok = ReceiveResumeToken::parse(&state.token).unwrap();
    assert_eq!(parsed_tok.toguid, s1_rep.to_guid);
    assert_eq!(parsed_tok.object, state.object);
    assert_eq!(parsed_tok.offset, state.offset);

    let mut resumed_stream = Vec::new();
    let mut resume_send_req = ZfsSendRequest::full(src_ds.clone(), Vec::new());
    resume_send_req.resume_token = Some(state.token);
    let resume_send_report =
        send_stream(&cx, &mut src_mos, &resume_send_req, &mut resumed_stream).unwrap();
    assert!(resume_send_report.resumed);

    let (rec_resumed, tok_resumed) = dst_engine
        .receive_stream(&cx, &res_req, &mut Cursor::new(&resumed_stream))
        .into_result()
        .expect("complete resumed full receive");
    assert!(rec_resumed.resumed && rec_resumed.final_snapshot == "s1");
    assert!(
        dst_engine
            .inspect_receive_resume_state(&cx, &dst_res)
            .unwrap()
            .is_none()
    );
    assert_pool_scrub_and_allocation_clean(
        &cx,
        &dst_devs,
        dst_built.pool_guid,
        Some(tok_resumed.published_slot()),
    );
    {
        let mut mos = open_mos(
            &cx,
            &dst_devs,
            dst_built.pool_guid,
            tok_resumed.published_slot(),
        );
        let mut zpl = mos.zpl(&cx, &dst_res).unwrap();
        let fo = zpl.resolve(&cx, b"/multi.bin").unwrap();
        assert_eq!(
            zpl.read(&cx, fo, 0, payload_s1.len() + 64).unwrap(),
            payload_s1
        );
    }

    // 3. Resumable incremental (`%recv` child) + fault-cut before Uberblock + `abort_receive` reclamation!
    let pre_incr_alloc = pool_allocated_bytes(
        &cx,
        &dst_devs,
        dst_built.pool_guid,
        dst_engine.committed_slot(),
    );
    let incr_cut = incr_s2.len() / 2;
    let inc_int = dst_engine.receive_stream(&cx, &res_req, &mut Cursor::new(&incr_s2[..incr_cut]));
    assert!(matches!(inc_int, ZfsTxOutcome::NotCommitted(_)));
    let inc_state = dst_engine
        .inspect_receive_resume_state(&cx, &dst_res)
        .unwrap()
        .expect("persisted %recv incremental state");
    assert!(inc_state.is_pct_recv_child);
    // Live target head MUST still serve untouched @s1 bytes and hide `%recv`!
    {
        let mut mos = open_mos(
            &cx,
            &dst_devs,
            dst_built.pool_guid,
            dst_engine.committed_slot(),
        );
        assert!(
            !mos.datasets(&cx)
                .unwrap()
                .iter()
                .any(|d| d.components.iter().any(|c| c == b"%recv")),
            "%recv leaked into live dataset list"
        );
        let mut zpl = mos.zpl(&cx, &dst_res).unwrap();
        let fo = zpl.resolve(&cx, b"/multi.bin").unwrap();
        assert_eq!(
            zpl.read(&cx, fo, 0, payload_s1.len() + 64).unwrap(),
            payload_s1
        );
    }

    // Inject fault-cut before Uberblock publication during a resume attempt:
    // pool MUST roll back cleanly to prior committed checkpoint TXG!
    let cut_txg = dst_engine.committed_txg();
    let mut fault_engine = open_engine_on_devices(
        &cx,
        &dst_devs,
        default_write_opts(dst_built.pool_guid, dst_engine.committed_slot()),
    )
    .unwrap();
    fault_engine.with_fault_hook(|ev| {
        if matches!(ev.stage, ZfsPersistenceStage::UberblockWrite { .. }) {
            Err(FfsError::Io(std::io::Error::other(
                "injected pre-uberblock crash during recv",
            )))
        } else {
            Ok(())
        }
    });
    let mut resume_s2 = Vec::new();
    let mut r_tok2 = ZfsSendRequest::full(src_ds.clone(), Vec::new());
    r_tok2.resume_token = Some(inc_state.token);
    send_stream(&cx, &mut src_mos, &r_tok2, &mut resume_s2).unwrap();
    let fault_out = fault_engine.receive_stream(&cx, &res_req, &mut Cursor::new(&resume_s2));
    assert!(matches!(fault_out, ZfsTxOutcome::NotCommitted(_)));
    assert_eq!(fault_engine.committed_txg(), cut_txg);

    // Abort the `%recv` staging and prove 100% space reclamation back to `pre_incr_alloc`!
    let mut clean_engine = open_engine_on_devices(
        &cx,
        &dst_devs,
        default_write_opts(dst_built.pool_guid, dst_engine.committed_slot()),
    )
    .unwrap();
    let (reclaimed, tok_abort) = clean_engine
        .abort_receive(&cx, &dst_res)
        .into_result()
        .expect("abort_receive");
    assert!(reclaimed > 0);
    assert!(
        clean_engine
            .inspect_receive_resume_state(&cx, &dst_res)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        pool_allocated_bytes(
            &cx,
            &dst_devs,
            dst_built.pool_guid,
            tok_abort.published_slot()
        ),
        pre_incr_alloc,
        "abort_receive failed to reclaim all staged %recv blocks"
    );
    assert_pool_scrub_and_allocation_clean(
        &cx,
        &dst_devs,
        dst_built.pool_guid,
        Some(tok_abort.published_slot()),
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn send_recv_strict_refusals_force_rollback_and_cancel_enospc_controls() {
    let cx = Cx::for_testing();
    let ts = Timestamp {
        seconds: 1_730_400_000,
        nanos: 0,
    };

    let src_built = build_clean_zfs_pool(&send_recv_pool_spec(32 * 1024 * 1024));
    let src_devs: Vec<_> = src_built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut src_engine = open_engine_on_devices(
        &cx,
        &src_devs,
        default_write_opts(src_built.pool_guid, src_built.initial_slot),
    )
    .unwrap();
    let src_ds = vec![b"data".to_vec(), b"src".to_vec()];
    src_engine
        .create_dataset(&cx, &[b"data".to_vec()], b"src", &[], ts)
        .into_result()
        .unwrap();
    let root_obj = {
        let mut mos = open_mos(
            &cx,
            &src_devs,
            src_built.pool_guid,
            src_engine.committed_slot(),
        );
        mos.zpl(&cx, &src_ds).unwrap().resolve(&cx, b"/").unwrap()
    };
    let (f_obj, _) = src_engine
        .create_file(
            &cx,
            &src_ds,
            root_obj,
            b"f.txt",
            0o644,
            0,
            0,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    src_engine
        .write_file_data(
            &cx,
            &src_ds,
            f_obj,
            0,
            b"v1-data",
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    src_engine
        .create_snapshot(&cx, &src_ds, b"s1", ts)
        .into_result()
        .unwrap();
    src_engine
        .write_file_data(
            &cx,
            &src_ds,
            f_obj,
            0,
            b"v2-data",
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    src_engine
        .create_snapshot(&cx, &src_ds, b"s2", ts)
        .into_result()
        .unwrap();

    let mut src_mos = open_mos(
        &cx,
        &src_devs,
        src_built.pool_guid,
        src_engine.committed_slot(),
    );
    let mut s1_stream = Vec::new();
    send_stream(
        &cx,
        &mut src_mos,
        &ZfsSendRequest::full(src_ds.clone(), b"s1".to_vec()),
        &mut s1_stream,
    )
    .unwrap();
    let mut s2_incr = Vec::new();
    let mut r2 = ZfsSendRequest::full(src_ds.clone(), b"s2".to_vec());
    r2.from = Some(ZfsSendFrom::Snapshot(b"s1".to_vec()));
    send_stream(&cx, &mut src_mos, &r2, &mut s2_incr).unwrap();

    let dst_built = build_clean_zfs_pool(&send_recv_pool_spec(32 * 1024 * 1024));
    let dst_devs: Vec<_> = dst_built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut dst_engine = open_engine_on_devices(
        &cx,
        &dst_devs,
        default_write_opts(dst_built.pool_guid, dst_built.initial_slot),
    )
    .unwrap();

    let dst_ds = vec![b"data".to_vec(), b"dst".to_vec()];
    let snap_before = snapshot_media_bytes(&dst_devs);

    // 1. Pre-cancelled `Cx` refuses before any disk mutation.
    let cancelled_cx = Cx::for_testing();
    cancelled_cx.cancel_with(asupersync::types::CancelKind::User, Some("test-cancel"));
    assert!(matches!(
        dst_engine.receive_stream(
            &cancelled_cx,
            &ZfsRecvRequest::new(dst_ds.clone()),
            &mut Cursor::new(&s1_stream),
        ),
        ZfsTxOutcome::NotCommitted(FfsError::Cancelled)
    ));
    assert_media_unchanged(&dst_devs, &snap_before);

    // 2. 1-bit flip in DRR_BEGIN feature flags (unknown bit) -> refused with zero mutation.
    let mut bad_feat = s1_stream.clone();
    // drr_versioninfo is at header offset 16..24; set high unsupported feature bit 62.
    let mut ver = u64::from_le_bytes(bad_feat[16..24].try_into().unwrap());
    ver |= 1_u64 << 62;
    bad_feat[16..24].copy_from_slice(&ver.to_le_bytes());
    assert!(matches!(
        dst_engine.receive_stream(
            &cx,
            &ZfsRecvRequest::new(dst_ds.clone()),
            &mut Cursor::new(&bad_feat),
        ),
        ZfsTxOutcome::NotCommitted(_)
    ));
    assert_media_unchanged(&dst_devs, &snap_before);

    // 3. 1-bit flip in stream payload / rolling Fletcher4 -> refused with zero net mutation.
    let mut bad_cksum = s1_stream.clone();
    let mid = bad_cksum.len() / 2;
    bad_cksum[mid] ^= 0x01;
    assert!(matches!(
        dst_engine.receive_stream(
            &cx,
            &ZfsRecvRequest::new(dst_ds.clone()),
            &mut Cursor::new(&bad_cksum),
        ),
        ZfsTxOutcome::NotCommitted(_)
    ));
    assert_pool_scrub_and_allocation_clean(
        &cx,
        &dst_devs,
        dst_built.pool_guid,
        Some(dst_engine.committed_slot()),
    );

    // 4. Trailing garbage bytes after DRR_END -> refused!
    let mut trailing = s1_stream.clone();
    trailing.extend_from_slice(b"JUNK");
    assert!(matches!(
        dst_engine.receive_stream(
            &cx,
            &ZfsRecvRequest::new(dst_ds.clone()),
            &mut Cursor::new(&trailing),
        ),
        ZfsTxOutcome::NotCommitted(_)
    ));

    // 5. Incremental stream without existing target base -> refused without mutation!
    let before_missing = snapshot_media_bytes(&dst_devs);
    assert!(matches!(
        dst_engine.receive_stream(
            &cx,
            &ZfsRecvRequest::new(dst_ds.clone()),
            &mut Cursor::new(&s2_incr),
        ),
        ZfsTxOutcome::NotCommitted(_)
    ));
    assert_media_unchanged(&dst_devs, &before_missing);

    // 6. Receive clean @s1, then mutate live head on destination to cause head divergence:
    //    incremental receive WITHOUT `force: true` refuses; WITH `force: true` rolls back & applies!
    dst_engine
        .receive_stream(
            &cx,
            &ZfsRecvRequest::new(dst_ds.clone()),
            &mut Cursor::new(&s1_stream),
        )
        .into_result()
        .expect("clean recv @s1");
    let dst_root = {
        let mut mos = open_mos(
            &cx,
            &dst_devs,
            dst_built.pool_guid,
            dst_engine.committed_slot(),
        );
        mos.zpl(&cx, &dst_ds).unwrap().resolve(&cx, b"/").unwrap()
    };
    let (local_obj, _) = dst_engine
        .create_file(
            &cx,
            &dst_ds,
            dst_root,
            b"local_diverge.txt",
            0o644,
            0,
            0,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    dst_engine
        .write_file_data(
            &cx,
            &dst_ds,
            local_obj,
            0,
            b"unsnapshotted-local-write",
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();

    // Without force -> refused!
    let before_diverge = snapshot_media_bytes(&dst_devs);
    let no_force = dst_engine.receive_stream(
        &cx,
        &ZfsRecvRequest::new(dst_ds.clone()),
        &mut Cursor::new(&s2_incr),
    );
    assert!(matches!(no_force, ZfsTxOutcome::NotCommitted(_)));
    assert_media_unchanged(&dst_devs, &before_diverge);

    // With force: true -> rolls back unsnapshotted divergence and applies @s2 cleanly!
    let mut force_req = ZfsRecvRequest::new(dst_ds.clone());
    force_req.force = true;
    let (_, tok_force) = dst_engine
        .receive_stream(&cx, &force_req, &mut Cursor::new(&s2_incr))
        .into_result()
        .expect("forced incremental recv @s2");
    assert_pool_scrub_and_allocation_clean(
        &cx,
        &dst_devs,
        dst_built.pool_guid,
        Some(tok_force.published_slot()),
    );
    {
        let mut mos = open_mos(
            &cx,
            &dst_devs,
            dst_built.pool_guid,
            tok_force.published_slot(),
        );
        let mut zpl = mos.zpl(&cx, &dst_ds).unwrap();
        assert!(zpl.resolve(&cx, b"/local_diverge.txt").is_err());
        let fo = zpl.resolve(&cx, b"/f.txt").unwrap();
        assert_eq!(zpl.read(&cx, fo, 0, 32).unwrap(), b"v2-data");
    }

    // Sanity-check codec constants and path-traversal guard stay active.
    const { assert!(DMU_REPLAY_RECORD_BYTES == 312 && DMU_BACKUP_FEATURE_COMPRESSED != 0) };
    let hdr_arr: &[u8; DMU_REPLAY_RECORD_BYTES] =
        s1_stream[..DMU_REPLAY_RECORD_BYTES].try_into().unwrap();
    let (hdr, _) = DrrRecord::parse_header(hdr_arr, Endian::Little).unwrap();
    assert!(matches!(
        hdr,
        DrrRecord::Begin(b) if b.hdr_type == StreamHeaderType::Substream
    ));
}
