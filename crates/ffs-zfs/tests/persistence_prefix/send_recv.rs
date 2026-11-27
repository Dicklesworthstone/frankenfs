//! Native ZFS `DMU_BACKUP_STREAM` send/receive integration, keyless raw encrypted (`-w`)
//! replication, ZVOL send/receive, resumable `%recv` / `receive_resume_token` interruption &
//! completion, abort reclamation, persistence-prefix fault-cut rollback, and strict tamper /
//! refusal controls.

use super::*;
use ffs_ondisk::zfs::crypto::{ZioEncrypt, verify_objset_macs};
use ffs_ondisk::zfs::send_stream::{
    DMU_BACKUP_FEATURE_COMPRESSED, DMU_REPLAY_RECORD_BYTES, DrrRecord, Fletcher4Stream,
    ReceiveResumeToken, StreamCryptoKeydata, StreamHeaderType, StreamMetaDnode,
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
            (b"org.illumos:sha512", 0),
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

fn assert_received_feature_owners(
    cx: &Cx,
    mos: &mut ffs_zfs::Objects,
    object: u64,
    expected: [bool; 2],
) {
    let node = mos.object(cx, object).unwrap();
    let entries = if node.object_type() == 196 {
        mos.zap(cx, object).unwrap()
    } else {
        assert!(!expected.contains(&true), "feature owner is not zapified");
        Vec::new()
    };
    for (feature, active) in [
        b"org.open-zfs:large_blocks".as_slice(),
        b"org.illumos:sha512".as_slice(),
    ]
    .into_iter()
    .zip(expected)
    {
        assert_eq!(
            entries
                .iter()
                .find(|entry| entry.name == feature)
                .map(|entry| entry.value),
            active.then_some(0),
            "unexpected ownership of {} on dataset object {object}",
            String::from_utf8_lossy(feature)
        );
    }
}

// Independent compound-header wire oracle derived from OpenZFS zfs-2.3.1,
// lib/libzfs/libzfs_sendrecv.c: send_prelim_records/send_conclusion_record.
// libzfs terminates BEGIN + nvlist with an END carrying that prefix's Fletcher4
// and a zero trailer. It emits a second, all-zero-checksum END after substreams.
fn native_compound_end(prefix: &[u8], order: Endian) -> [u8; DMU_REPLAY_RECORD_BYTES] {
    assert!(prefix.len().is_multiple_of(4));
    let mut checksum = [0_u64; 4];
    for word in prefix.as_chunks::<4>().0 {
        let word = match order {
            Endian::Little => u32::from_le_bytes(*word),
            Endian::Big => u32::from_be_bytes(*word),
        };
        checksum[0] = checksum[0].wrapping_add(u64::from(word));
        checksum[1] = checksum[1].wrapping_add(checksum[0]);
        checksum[2] = checksum[2].wrapping_add(checksum[1]);
        checksum[3] = checksum[3].wrapping_add(checksum[2]);
    }
    let mut end = [0_u8; DMU_REPLAY_RECORD_BYTES];
    end[..4].copy_from_slice(&match order {
        Endian::Little => 5_u32.to_le_bytes(),
        Endian::Big => 5_u32.to_be_bytes(),
    });
    for (index, word) in checksum.into_iter().enumerate() {
        end[8 + index * 8..16 + index * 8].copy_from_slice(&order.encode(word));
    }
    end
}

fn assert_native_compound_header(stream: &[u8]) -> usize {
    use ffs_ondisk::zfs::nvlist::{NvList, Value};
    let payload_len = u32::from_le_bytes(stream[4..8].try_into().unwrap()) as usize;
    let header_end = DMU_REPLAY_RECORD_BYTES + payload_len;
    assert_eq!(
        &stream[header_end..header_end + DMU_REPLAY_RECORD_BYTES],
        native_compound_end(&stream[..header_end], Endian::Little),
        "native compound header END must precede the first substream"
    );
    let nvl = NvList::parse_exact(&stream[DMU_REPLAY_RECORD_BYTES..header_end]).unwrap();
    assert_eq!(nvl.fields["not_recursive"], Value::Boolean(true));
    let fss = nvl.list("fss").unwrap();
    assert_eq!(fss.fields.len(), 1);
    let Value::List(dataset) = fss.fields.values().next().unwrap() else {
        panic!("compound dataset must be an nvlist");
    };
    assert_eq!(dataset.unsigned("parentfromsnap"), Some(0));
    assert_eq!(
        &stream[stream.len() - DMU_REPLAY_RECORD_BYTES..],
        native_compound_end(&[], Endian::Little),
        "native final package END must retain a zero checksum and trailer"
    );
    header_end + DMU_REPLAY_RECORD_BYTES
}

fn native_compound_package(payload: &[u8], substreams: &[u8]) -> Vec<u8> {
    let mut native = vec![0_u8; DMU_REPLAY_RECORD_BYTES];
    native[4..8].copy_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
    native[8..16].copy_from_slice(&0x0000_0002_f5ba_cbac_u64.to_le_bytes());
    native[16..24].copy_from_slice(&2_u64.to_le_bytes());
    let toname = b"ffstestpool/data@wire";
    native[56..56 + toname.len()].copy_from_slice(toname);
    native.extend_from_slice(payload);
    native.extend_from_slice(&native_compound_end(&native, Endian::Little));
    native.extend_from_slice(substreams);
    native.extend_from_slice(&native_compound_end(&[], Endian::Little));
    native
}

#[test]
#[allow(clippy::too_many_lines)]
fn compound_native_header_checksum_is_validated_before_any_backing_write() {
    use ffs_ondisk::zfs::nvlist::{NvList, Value};
    let cx = Cx::for_testing();
    let timestamp = Timestamp {
        seconds: 1_730_000_499,
        nanos: 0,
    };
    let source = vec![b"data".to_vec()];
    let built = build_clean_zfs_pool(&send_recv_pool_spec(32 * 1024 * 1024));
    let source_devices: Vec<_> = built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut sender = open_engine_on_devices(
        &cx,
        &source_devices,
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .unwrap();
    sender
        .create_snapshot(&cx, &source, b"wire", timestamp)
        .into_result()
        .unwrap();
    let mut mos = sender.open_read_objects(&cx).unwrap();
    let mut plain = Vec::new();
    let mut request = ZfsSendRequest::full(source.clone(), b"wire".to_vec());
    let report = send_stream(&cx, &mut mos, &request, &mut plain).unwrap();
    request.properties = true;
    let mut generated = Vec::new();
    send_stream(&cx, &mut mos, &request, &mut generated).unwrap();
    let substream_at = assert_native_compound_header(&generated);
    assert_eq!(
        &generated[substream_at..generated.len() - DMU_REPLAY_RECORD_BYTES],
        plain
    );

    // Construct a libzfs-shaped package independently of the production sender.
    // Only the already checksummed ordinary substream comes from send_stream.
    let dataset = NvList {
        fields: BTreeMap::from([
            ("name".into(), Value::String("ffstestpool/data".into())),
            ("parentfromsnap".into(), Value::Unsigned(0)),
            (
                "props".into(),
                Value::List(NvList {
                    fields: BTreeMap::from([(
                        "app:received".into(),
                        Value::String("native".into()),
                    )]),
                }),
            ),
            (
                "snaps".into(),
                Value::List(NvList {
                    fields: BTreeMap::from([("wire".into(), Value::Unsigned(report.to_guid))]),
                }),
            ),
        ]),
    };
    let payload = NvList {
        fields: BTreeMap::from([
            ("not_recursive".into(), Value::Boolean(true)),
            ("tosnap".into(), Value::String("wire".into())),
            (
                "fss".into(),
                Value::List(NvList {
                    fields: BTreeMap::from([("dataset".into(), Value::List(dataset))]),
                }),
            ),
        ]),
    }
    .encode_xdr()
    .unwrap();
    let native = native_compound_package(&payload, &plain);
    let header_end = DMU_REPLAY_RECORD_BYTES + payload.len();

    let target = build_clean_zfs_pool(&send_recv_pool_spec(32 * 1024 * 1024));
    let devices: Vec<_> = target
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut receiver = open_engine_on_devices(
        &cx,
        &devices,
        default_write_opts(target.pool_guid, target.initial_slot),
    )
    .unwrap();
    let destination = vec![b"data".to_vec(), b"received".to_vec()];
    let receive = ZfsRecvRequest::new(destination.clone());
    let before = snapshot_media_bytes(&devices);
    let writes: Vec<_> = devices
        .iter()
        .map(FaultableMemberDevice::write_calls)
        .collect();
    let initial_txg = receiver.committed_txg();
    for case in 0..10 {
        let mut bad = native.clone();
        match case {
            0 => bad.truncate(header_end),
            1 => bad.truncate(header_end + DMU_REPLAY_RECORD_BYTES - 1),
            2 => bad[header_end + 8] ^= 1,
            3 => bad[56] ^= 1,
            4 => bad[header_end..header_end + 4].copy_from_slice(&0_u32.to_le_bytes()),
            5 => bad[header_end + 40] = 1,
            6 => bad[header_end + 280] = 1,
            7 => bad[23] |= 0x40,
            8 => {
                bad = [
                    &native[..header_end],
                    &native[header_end + DMU_REPLAY_RECORD_BYTES..],
                ]
                .concat();
            }
            9 => {
                let value = payload
                    .windows(6)
                    .position(|bytes| bytes == b"native")
                    .unwrap();
                bad[DMU_REPLAY_RECORD_BYTES + value] ^= 1;
            }
            _ => unreachable!(),
        }
        assert!(
            matches!(
                receiver.receive_stream(&cx, &receive, &mut Cursor::new(bad)),
                ZfsTxOutcome::NotCommitted(_)
            ),
            "malformed compound header case {case} was accepted"
        );
        assert_eq!(receiver.committed_txg(), initial_txg);
        assert_eq!(
            devices
                .iter()
                .map(FaultableMemberDevice::write_calls)
                .collect::<Vec<_>>(),
            writes,
            "case {case} wrote before compound header validation"
        );
        assert_media_unchanged(&devices, &before);
    }
    for case in 0..6 {
        let mut metadata = NvList::parse_exact(&payload).unwrap();
        if case == 0 {
            metadata.fields.remove("not_recursive");
        } else if case == 1 {
            metadata
                .fields
                .insert("not_recursive".into(), Value::Boolean(false));
        } else {
            let Value::List(fss) = metadata.fields.get_mut("fss").unwrap() else {
                unreachable!();
            };
            if case == 2 {
                let other = fss.fields["dataset"].clone();
                fss.fields.insert("second-dataset".into(), other);
            } else {
                let Value::List(dataset) = fss.fields.get_mut("dataset").unwrap() else {
                    unreachable!();
                };
                if case == 3 {
                    dataset
                        .fields
                        .insert("name".into(), Value::String("ffstestpool/other".into()));
                } else if case == 4 {
                    let Value::List(snaps) = dataset.fields.get_mut("snaps").unwrap() else {
                        unreachable!();
                    };
                    snaps
                        .fields
                        .insert("wire".into(), Value::Unsigned(report.to_guid ^ 1));
                } else {
                    dataset.fields.remove("snaps");
                }
            }
        }
        // Recompute the native header checksum: this must exercise dataset
        // admission, not accidentally pass because of the checksum gate.
        let bad = native_compound_package(&metadata.encode_xdr().unwrap(), &plain);
        assert!(
            matches!(
                receiver.receive_stream(&cx, &receive, &mut Cursor::new(bad)),
                ZfsTxOutcome::NotCommitted(_)
            ),
            "compound metadata case {case} was accepted"
        );
        assert_eq!(receiver.committed_txg(), initial_txg);
        assert_eq!(
            devices
                .iter()
                .map(FaultableMemberDevice::write_calls)
                .collect::<Vec<_>>(),
            writes
        );
        assert_media_unchanged(&devices, &before);
    }
    let unrelated = restamp_substream(&plain, false, |mut record, payload| {
        if let DrrRecord::Begin(begin) = &mut record {
            begin.toname = b"ffstestpool/other@wire".to_vec();
        }
        Some((record, payload))
    });
    let mixed_source = native_compound_package(&[], &unrelated);
    assert!(matches!(
        receiver.receive_stream(&cx, &receive, &mut Cursor::new(mixed_source)),
        ZfsTxOutcome::NotCommitted(FfsError::Corruption { .. })
    ));
    assert_eq!(
        devices
            .iter()
            .map(FaultableMemberDevice::write_calls)
            .collect::<Vec<_>>(),
        writes
    );
    assert_media_unchanged(&devices, &before);
    let (recv_report, token) = receiver
        .receive_stream(&cx, &receive, &mut Cursor::new(&native))
        .into_result()
        .expect("native package framing must be accepted");
    assert_eq!(recv_report.records_applied, report.records_written + 3);
    assert_eq!(recv_report.stream_bytes_read, native.len() as u64);
    let mut reopened = open_mos(&cx, &devices, target.pool_guid, token.published_slot());
    let properties = reopened
        .properties(&cx, &destination, None, &["app:received".into()])
        .unwrap();
    assert_eq!(
        properties.values[0].value,
        Some(PropertyValue::Text(b"native".to_vec()))
    );
    let expected = mos
        .zpl_snapshot(&cx, &source, b"wire")
        .unwrap()
        .read(&cx, 4, 0, 8192)
        .unwrap();
    assert_eq!(
        reopened
            .zpl_snapshot(&cx, &destination, b"wire")
            .unwrap()
            .read(&cx, 4, 0, 8192)
            .unwrap(),
        expected
    );
    assert_pool_scrub_and_allocation_clean(
        &cx,
        &devices,
        target.pool_guid,
        Some(token.published_slot()),
    );
    // Native `-I` without property gathering can have a zero-length package
    // nvlist. Keep that path, still bound to the outer source dataset.
    let plain_destination = vec![b"data".to_vec(), b"without-properties".to_vec()];
    receiver
        .receive_stream(
            &cx,
            &ZfsRecvRequest::new(plain_destination.clone()),
            &mut Cursor::new(native_compound_package(&[], &plain)),
        )
        .into_result()
        .unwrap();
    let mut reopened = receiver.open_read_objects(&cx).unwrap();
    assert_eq!(
        reopened
            .zpl_snapshot(&cx, &plain_destination, b"wire")
            .unwrap()
            .read(&cx, 4, 0, 8192)
            .unwrap(),
        expected
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn compressed_zstd_receive_retains_native_blocks_and_owners_across_resume_and_abort() {
    const ZSTD: &[u8] = b"org.freebsd:zstd_compress";
    let cx = Cx::for_testing();
    let timestamp = Timestamp {
        seconds: 1_730_000_501,
        nanos: 0,
    };
    let source = vec![b"data".to_vec()];
    let destination = vec![b"data".to_vec(), b"zstd-received".to_vec()];
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        ashift: 9,
        ..send_recv_pool_spec(32 * 1024 * 1024)
    });
    let source_devices: Vec<_> = built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut sender = open_engine_on_devices(
        &cx,
        &source_devices,
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .unwrap();
    for (property, value) in [("compression", 16 | (5 << 7)), ("recordsize", 4096)] {
        sender
            .set_property(&cx, &source, property, ZfsPropertySetValue::Number(value))
            .into_result()
            .unwrap();
    }
    let first = vec![0xA6; 5 * 4096];
    sender
        .write_file_data(
            &cx,
            &source,
            4,
            0,
            &first,
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    sender
        .create_snapshot(&cx, &source, b"z1", timestamp)
        .into_result()
        .unwrap();
    let mut second = first.clone();
    second[4096..8192].fill(0xB7);
    sender
        .write_file_data(
            &cx,
            &source,
            4,
            4096,
            &second[4096..8192],
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    sender
        .create_snapshot(&cx, &source, b"z2", timestamp)
        .into_result()
        .unwrap();
    let mut source_mos = sender.open_read_objects(&cx).unwrap();
    let mut full = Vec::new();
    let mut send = ZfsSendRequest::full(source.clone(), b"z1".to_vec());
    send.compressed = true;
    send_stream(&cx, &mut source_mos, &send, &mut full).unwrap();
    let mut incremental = Vec::new();
    send.to_snapshot = b"z2".to_vec();
    send.from = Some(ZfsSendFrom::Snapshot(b"z1".to_vec()));
    send_stream(&cx, &mut source_mos, &send, &mut incremental).unwrap();
    for (stream, expected_records) in [(&full, 5), (&incremental, 1)] {
        let mut offset = 0;
        let mut compressed_records = 0;
        while offset < stream.len() {
            let header = stream[offset..offset + DMU_REPLAY_RECORD_BYTES]
                .try_into()
                .unwrap();
            let (record, _) = DrrRecord::parse_header(header, Endian::Little).unwrap();
            offset += DMU_REPLAY_RECORD_BYTES + record.expected_payload_len(false).unwrap();
            if let DrrRecord::Write(write) = record
                && write.object == 4
            {
                assert_eq!(write.compressiontype, 16);
                compressed_records += 1;
            }
        }
        assert_eq!(compressed_records, expected_records);
    }

    let target = build_clean_zfs_pool(&PoolFixtureSpec {
        ashift: 9,
        ..send_recv_pool_spec(32 * 1024 * 1024)
    });
    let devices: Vec<_> = target
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut receiver = open_engine_on_devices(
        &cx,
        &devices,
        default_write_opts(target.pool_guid, target.initial_slot),
    )
    .unwrap();
    let mut receive = ZfsRecvRequest::new(destination.clone());
    receive.resumable = true;
    receive.checkpoint_bytes = 1;
    for (stream, is_incremental, before_count, after_count, expected) in [
        (full.as_slice(), false, 0, 2, &first),
        (incremental.as_slice(), true, 2, 3, &second),
    ] {
        let incomplete = &stream[..stream.len() - DMU_REPLAY_RECORD_BYTES];
        for abort in [true, false] {
            assert!(matches!(
                receiver.receive_stream(&cx, &receive, &mut Cursor::new(incomplete)),
                ZfsTxOutcome::NotCommitted(_)
            ));
            let state = receiver
                .inspect_receive_resume_state(&cx, &destination)
                .unwrap()
                .unwrap();
            assert_eq!(state.is_pct_recv_child, is_incremental);
            assert!(state.compressok);
            let mut mos = receiver.open_read_objects(&cx).unwrap();
            let feature_count = mos
                .zap(&cx, 10)
                .unwrap()
                .into_iter()
                .find(|entry| entry.name == ZSTD)
                .unwrap()
                .value;
            assert_eq!(feature_count, before_count + 1);
            if is_incremental {
                assert_eq!(
                    mos.zpl(&cx, &destination)
                        .unwrap()
                        .read(&cx, 4, 0, first.len())
                        .unwrap(),
                    first
                );
            }
            if abort {
                receiver
                    .abort_receive(&cx, &destination)
                    .into_result()
                    .unwrap();
                let mut mos = receiver.open_read_objects(&cx).unwrap();
                assert_eq!(
                    mos.zap(&cx, 10)
                        .unwrap()
                        .into_iter()
                        .find(|entry| entry.name == ZSTD)
                        .unwrap()
                        .value,
                    before_count
                );
            } else {
                let mut resume = ZfsSendRequest::full(source.clone(), Vec::new());
                resume.resume_token = Some(state.token);
                resume.compressed = true;
                let mut remaining = Vec::new();
                send_stream(&cx, &mut source_mos, &resume, &mut remaining).unwrap();
                receiver
                    .receive_stream(&cx, &receive, &mut Cursor::new(remaining))
                    .into_result()
                    .unwrap();
            }
        }
        assert_native_dataset_feature(&cx, &receiver, &destination, ZSTD, true, after_count);
        let node = native_zpl_file_dnode(&cx, &receiver, &devices[0], &destination, 4);
        assert_eq!(node.compress_type(), 0);
        let leaves = native_plain_leaf_pointers(&devices[0], &node);
        assert_eq!(leaves.len(), 5);
        assert!(leaves.iter().all(|pointer| pointer.compression() == 16));
        let mut mos = receiver.open_read_objects(&cx).unwrap();
        assert_eq!(
            mos.zpl(&cx, &destination)
                .unwrap()
                .read(&cx, 4, 0, expected.len())
                .unwrap(),
            *expected
        );
        assert_pool_scrub_and_allocation_clean(
            &cx,
            &devices,
            target.pool_guid,
            Some(receiver.committed_slot()),
        );
    }
    let slot = receiver.committed_slot();
    drop(receiver);
    let durable: Vec<_> = devices
        .iter()
        .map(FaultableMemberDevice::fresh_from_durable)
        .collect();
    let mut reopened =
        open_engine_on_devices(&cx, &durable, default_write_opts(target.pool_guid, slot)).unwrap();
    assert_native_dataset_feature(&cx, &reopened, &destination, ZSTD, true, 3);
    let mut mos = reopened.open_read_objects(&cx).unwrap();
    assert_eq!(
        mos.zpl_snapshot(&cx, &destination, b"z1")
            .unwrap()
            .read(&cx, 4, 0, first.len())
            .unwrap(),
        first
    );
    assert_eq!(
        mos.zpl_snapshot(&cx, &destination, b"z2")
            .unwrap()
            .read(&cx, 4, 0, second.len())
            .unwrap(),
        second
    );
    for (snapshot, remaining) in [(b"z1".as_slice(), 2), (b"z2".as_slice(), 1)] {
        reopened
            .destroy_snapshot(&cx, &destination, snapshot, false)
            .into_result()
            .unwrap();
        assert_native_dataset_feature(&cx, &reopened, &destination, ZSTD, true, remaining);
    }
    reopened
        .destroy_dataset(&cx, &destination)
        .into_result()
        .unwrap();
    assert_native_dataset_feature(&cx, &reopened, &source, ZSTD, false, 0);
    assert_pool_scrub_and_allocation_clean(
        &cx,
        &durable,
        target.pool_guid,
        Some(reopened.committed_slot()),
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn receive_feature_owners_survive_checkpoints_resume_abort_and_destruction() {
    let cx = Cx::for_testing();
    let timestamp = Timestamp {
        seconds: 1_730_000_500,
        nanos: 0,
    };
    let source = vec![b"data".to_vec()];
    let built = build_clean_zfs_pool(&send_recv_pool_spec(64 * 1024 * 1024));
    let source_devices: Vec<_> = built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut sender = open_engine_on_devices(
        &cx,
        &source_devices,
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .unwrap();
    for (name, value) in [("recordsize", 262_144), ("checksum", 11)] {
        sender
            .set_property(&cx, &source, name, ZfsPropertySetValue::Number(value))
            .into_result()
            .unwrap();
    }
    let (object, _) = sender
        .create_file(
            &cx,
            &source,
            2,
            b"payload",
            0o640,
            1000,
            1000,
            timestamp,
            ZfsDataChecksum::Inherit,
        )
        .into_result()
        .unwrap();
    let first: Vec<u8> = (0..524_288)
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect();
    sender
        .write_file_data(
            &cx,
            &source,
            object,
            0,
            &first,
            timestamp,
            ZfsDataChecksum::Inherit,
        )
        .into_result()
        .unwrap();
    sender
        .create_snapshot(&cx, &source, b"s1", timestamp)
        .into_result()
        .unwrap();
    let mut second = first.clone();
    second[262_144..262_151].copy_from_slice(b"changed");
    sender
        .write_file_data(
            &cx,
            &source,
            object,
            262_144,
            b"changed",
            timestamp,
            ZfsDataChecksum::Inherit,
        )
        .into_result()
        .unwrap();
    sender
        .create_snapshot(&cx, &source, b"s2", timestamp)
        .into_result()
        .unwrap();

    let mut source_mos = sender.open_read_objects(&cx).unwrap();
    let mut request = ZfsSendRequest::full(source.clone(), b"s1".to_vec());
    request.large_blocks = true;
    let mut full = Vec::new();
    send_stream(&cx, &mut source_mos, &request, &mut full).unwrap();
    let mut request = ZfsSendRequest::full(source.clone(), b"s2".to_vec());
    request.large_blocks = true;
    request.from = Some(ZfsSendFrom::Snapshot(b"s1".to_vec()));
    let mut incremental = Vec::new();
    send_stream(&cx, &mut source_mos, &request, &mut incremental).unwrap();
    request.large_blocks = false;
    let mut downconverted_incremental = Vec::new();
    assert!(matches!(
        send_stream(
            &cx,
            &mut source_mos,
            &request,
            &mut downconverted_incremental
        ),
        Err(FfsError::UnsupportedFeature(_))
    ));
    // The sender refuses unsupported splitting. A separately checksummed hostile
    // stream still exercises receiver admission when the native flag is removed.
    let downconverted_incremental =
        restamp_substream(&incremental, false, |mut record, payload| {
            if let DrrRecord::Begin(begin) = &mut record {
                assert!(
                    begin
                        .features
                        .contains(ffs_ondisk::zfs::send_stream::DMU_BACKUP_FEATURE_LARGE_BLOCKS)
                );
                begin.features = ffs_ondisk::zfs::send_stream::SendFeatureFlags::from_bits(
                    begin.features.bits()
                        & !ffs_ondisk::zfs::send_stream::DMU_BACKUP_FEATURE_LARGE_BLOCKS,
                );
            }
            Some((record, payload))
        });

    {
        let missing = b"org.open-zfs:large_blocks".as_slice();
        let mut specification = send_recv_pool_spec(32 * 1024 * 1024);
        specification
            .additional_read_features
            .retain(|(name, _)| *name != missing);
        let refused = build_clean_zfs_pool(&specification);
        let refused_devices: Vec<_> = refused
            .members
            .into_iter()
            .map(FaultableMemberDevice::new)
            .collect();
        let mut receiver = open_engine_on_devices(
            &cx,
            &refused_devices,
            default_write_opts(refused.pool_guid, refused.initial_slot),
        )
        .unwrap();
        let destination = vec![b"data".to_vec(), b"unsupported".to_vec()];
        let request = ZfsRecvRequest::new(destination.clone());
        let feature = std::str::from_utf8(missing).unwrap();
        assert!(matches!(
            receiver.receive_stream(&cx, &request, &mut Cursor::new(&full)),
            ZfsTxOutcome::NotCommitted(error) if error.to_string().contains(feature)
        ));
        assert!(
            receiver
                .inspect_receive_resume_state(&cx, &destination)
                .unwrap()
                .is_none()
        );
        assert!(
            !receiver
                .open_read_objects(&cx)
                .unwrap()
                .datasets(&cx)
                .unwrap()
                .iter()
                .any(|row| row.components == destination)
        );
        assert_pool_scrub_and_allocation_clean(
            &cx,
            &refused_devices,
            refused.pool_guid,
            Some(receiver.committed_slot()),
        );
    }

    let target = build_clean_zfs_pool(&send_recv_pool_spec(64 * 1024 * 1024));
    let devices: Vec<_> = target
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut receiver = open_engine_on_devices(
        &cx,
        &devices,
        default_write_opts(target.pool_guid, target.initial_slot),
    )
    .unwrap();
    let baseline = dsl_block_feature_counts(&cx, &receiver);
    assert_eq!(&baseline[..2], &[0, 0]);
    let destination = vec![b"data".to_vec(), b"received".to_vec()];
    let mut receive = ZfsRecvRequest::new(destination.clone());
    receive.resumable = true;
    receive.checkpoint_bytes = 1;

    // Ordinary uncompressed WRITE records carry plaintext, so receive applies
    // dn_checksum=inherit (Fletcher4 here), independently of the sender's SHA512
    // BPs. Only the actually emitted large-block feature becomes owned.
    for (stream, is_incremental, before_count, after_count, expected) in [
        (full.as_slice(), false, 0, 2, &first),
        (incremental.as_slice(), true, 2, 3, &second),
    ] {
        let before = dsl_block_feature_counts(&cx, &receiver);
        assert_eq!(&before[..2], &[before_count, 0]);
        if is_incremental {
            let media = snapshot_media_bytes(&devices);
            assert!(matches!(
                receiver.receive_stream(&cx, &receive, &mut Cursor::new(&downconverted_incremental)),
                ZfsTxOutcome::NotCommitted(error) if error.to_string().contains("large-block support")
            ));
            assert_media_unchanged(&devices, &media);
        }
        // Drop only DRR_END. Every data record reaches a durable checkpoint;
        // the incomplete owner must exist independently of final publication.
        let incomplete = &stream[..stream.len() - DMU_REPLAY_RECORD_BYTES];
        for abort in [true, false] {
            assert!(matches!(
                receiver.receive_stream(&cx, &receive, &mut Cursor::new(incomplete)),
                ZfsTxOutcome::NotCommitted(_)
            ));
            let state = receiver
                .inspect_receive_resume_state(&cx, &destination)
                .unwrap()
                .expect("incomplete receive must retain its checkpoint");
            assert_eq!(state.is_pct_recv_child, is_incremental);
            assert_eq!(
                &dsl_block_feature_counts(&cx, &receiver)[..2],
                &[before_count + 1, 0],
                "checkpoint lost or double-counted its feature ownership"
            );
            if is_incremental {
                let mut mos = receiver.open_read_objects(&cx).unwrap();
                assert_eq!(
                    mos.zpl(&cx, &destination)
                        .unwrap()
                        .read(&cx, object, 0, first.len())
                        .unwrap(),
                    first
                );
            }
            if abort {
                receiver
                    .abort_receive(&cx, &destination)
                    .into_result()
                    .unwrap();
                assert_eq!(dsl_block_feature_counts(&cx, &receiver), before);
            } else {
                let mut resume = ZfsSendRequest::full(source.clone(), Vec::new());
                resume.resume_token = Some(state.token);
                resume.large_blocks = true;
                let mut remaining = Vec::new();
                send_stream(&cx, &mut source_mos, &resume, &mut remaining).unwrap();
                receiver
                    .receive_stream(&cx, &receive, &mut Cursor::new(&remaining))
                    .into_result()
                    .unwrap();
            }
        }
        assert_eq!(
            &dsl_block_feature_counts(&cx, &receiver)[..2],
            &[after_count, 0]
        );
        assert!(
            receiver
                .inspect_receive_resume_state(&cx, &destination)
                .unwrap()
                .is_none()
        );
        let mut mos = receiver.open_read_objects(&cx).unwrap();
        let head = mos
            .datasets(&cx)
            .unwrap()
            .into_iter()
            .find(|row| row.components == destination)
            .unwrap()
            .head_object;
        let head_node = mos.object(&cx, head).unwrap();
        let snapshot = head_node.order().u64(head_node.bonus(), 8).unwrap();
        assert_received_feature_owners(&cx, &mut mos, head, [true, false]);
        assert_received_feature_owners(&cx, &mut mos, snapshot, [true, false]);
        assert_eq!(
            mos.zpl(&cx, &destination)
                .unwrap()
                .read(&cx, object, 0, expected.len())
                .unwrap(),
            *expected
        );
    }

    let slot = receiver.committed_slot();
    drop(receiver);
    let durable: Vec<_> = devices
        .iter()
        .map(FaultableMemberDevice::fresh_from_durable)
        .collect();
    let mut reopened =
        open_engine_on_devices(&cx, &durable, default_write_opts(target.pool_guid, slot)).unwrap();
    assert_eq!(&dsl_block_feature_counts(&cx, &reopened)[..2], &[3, 0]);
    reopened
        .destroy_snapshot(&cx, &destination, b"s1", false)
        .into_result()
        .unwrap();
    assert_eq!(&dsl_block_feature_counts(&cx, &reopened)[..2], &[2, 0]);
    reopened
        .destroy_snapshot(&cx, &destination, b"s2", false)
        .into_result()
        .unwrap();
    assert_eq!(&dsl_block_feature_counts(&cx, &reopened)[..2], &[1, 0]);
    reopened
        .destroy_dataset(&cx, &destination)
        .into_result()
        .unwrap();
    assert_eq!(dsl_block_feature_counts(&cx, &reopened), baseline);
    assert_pool_scrub_and_allocation_clean(
        &cx,
        &durable,
        target.pool_guid,
        Some(reopened.committed_slot()),
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn forced_receive_releases_features_owned_only_by_the_replaced_head() {
    let cx = Cx::for_testing();
    let timestamp = Timestamp {
        seconds: 1_730_000_600,
        nanos: 0,
    };
    let source = vec![b"data".to_vec()];
    let built = build_clean_zfs_pool(&send_recv_pool_spec(32 * 1024 * 1024));
    let source_devices: Vec<_> = built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut sender = open_engine_on_devices(
        &cx,
        &source_devices,
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .unwrap();
    let (object, _) = sender
        .create_file(
            &cx,
            &source,
            2,
            b"kept",
            0o640,
            1000,
            1000,
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    sender
        .write_file_data(
            &cx,
            &source,
            object,
            0,
            b"source version one",
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    sender
        .create_snapshot(&cx, &source, b"s1", timestamp)
        .into_result()
        .unwrap();
    sender
        .write_file_data(
            &cx,
            &source,
            object,
            0,
            b"source version two",
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    sender
        .create_snapshot(&cx, &source, b"s2", timestamp)
        .into_result()
        .unwrap();
    let mut source_mos = sender.open_read_objects(&cx).unwrap();
    let mut request = ZfsSendRequest::full(source.clone(), b"s1".to_vec());
    request.large_blocks = true;
    let mut full = Vec::new();
    send_stream(&cx, &mut source_mos, &request, &mut full).unwrap();
    let mut request = ZfsSendRequest::full(source, b"s2".to_vec());
    request.large_blocks = true;
    request.from = Some(ZfsSendFrom::Snapshot(b"s1".to_vec()));
    let mut incremental = Vec::new();
    send_stream(&cx, &mut source_mos, &request, &mut incremental).unwrap();

    let target = build_clean_zfs_pool(&send_recv_pool_spec(32 * 1024 * 1024));
    let devices: Vec<_> = target
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut receiver = open_engine_on_devices(
        &cx,
        &devices,
        default_write_opts(target.pool_guid, target.initial_slot),
    )
    .unwrap();
    let destination = vec![b"data".to_vec(), b"replace".to_vec()];
    let mut receive = ZfsRecvRequest::new(destination.clone());
    receiver
        .receive_stream(&cx, &receive, &mut Cursor::new(&full))
        .into_result()
        .unwrap();
    assert_eq!(
        &dsl_block_feature_counts(&cx, &receiver)[..2],
        &[0, 0],
        "a stream capability flag alone must not acquire feature ownership"
    );
    for (name, value) in [("recordsize", 262_144), ("checksum", 11)] {
        receiver
            .set_property(&cx, &destination, name, ZfsPropertySetValue::Number(value))
            .into_result()
            .unwrap();
    }
    let root = receiver
        .open_read_objects(&cx)
        .unwrap()
        .zpl(&cx, &destination)
        .unwrap()
        .resolve(&cx, b"/")
        .unwrap();
    let (discarded, _) = receiver
        .create_file(
            &cx,
            &destination,
            root,
            b"discarded",
            0o600,
            1000,
            1000,
            timestamp,
            ZfsDataChecksum::Inherit,
        )
        .into_result()
        .unwrap();
    let head_only = vec![0xCE; 262_161];
    receiver
        .write_file_data(
            &cx,
            &destination,
            discarded,
            0,
            &head_only,
            timestamp,
            ZfsDataChecksum::Inherit,
        )
        .into_result()
        .unwrap();
    let before = dsl_block_feature_counts(&cx, &receiver);
    assert_eq!(&before[..2], &[1, 1]);

    receive.force = true;
    receiver
        .receive_stream(&cx, &receive, &mut Cursor::new(&incremental))
        .into_result()
        .unwrap();
    let after = dsl_block_feature_counts(&cx, &receiver);
    assert_eq!(
        &after[..2],
        &[0, 0],
        "clone swap retained discarded-head feature ownership"
    );
    assert_eq!(
        after[2], before[2],
        "an already zapified target retains exactly one extensible owner"
    );
    let mut mos = receiver.open_read_objects(&cx).unwrap();
    let head = mos
        .datasets(&cx)
        .unwrap()
        .into_iter()
        .find(|row| row.components == destination)
        .unwrap()
        .head_object;
    let head_node = mos.object(&cx, head).unwrap();
    let snapshot = head_node.order().u64(head_node.bonus(), 8).unwrap();
    assert_received_feature_owners(&cx, &mut mos, head, [false, false]);
    assert_received_feature_owners(&cx, &mut mos, snapshot, [false, false]);
    let mut view = mos.zpl(&cx, &destination).unwrap();
    assert_eq!(
        view.read(&cx, object, 0, 64).unwrap(),
        b"source version two"
    );
    assert!(view.resolve(&cx, b"/discarded").is_err());
    assert_pool_scrub_and_allocation_clean(
        &cx,
        &devices,
        target.pool_guid,
        Some(receiver.committed_slot()),
    );
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

fn checked_substream_records(stream: &[u8], raw: bool) -> Vec<(usize, DrrRecord, Vec<u8>)> {
    let mut records = Vec::new();
    let mut rolling = Fletcher4Stream::new(Endian::Little);
    let mut offset = 0;
    while offset < stream.len() {
        let start = offset;
        let header = stream[offset..offset + DMU_REPLAY_RECORD_BYTES]
            .try_into()
            .unwrap();
        let (record, _) = DrrRecord::parse_header(header, Endian::Little).unwrap();
        offset += DMU_REPLAY_RECORD_BYTES;
        let length = record.expected_payload_len(raw).unwrap();
        let payload = stream[offset..offset + length].to_vec();
        offset += length;
        rolling
            .verify_record(header, &payload, record.record_type(), true)
            .unwrap();
        records.push((start, record, payload));
    }
    assert_eq!(offset, stream.len());
    records
}

fn restamp_substream(
    stream: &[u8],
    raw: bool,
    mut edit: impl FnMut(DrrRecord, Vec<u8>) -> Option<(DrrRecord, Vec<u8>)>,
) -> Vec<u8> {
    let mut output = Vec::new();
    let mut rolling = Fletcher4Stream::new(Endian::Little);
    for (_, record, payload) in checked_substream_records(stream, raw) {
        let Some((record, payload)) = edit(record, payload) else {
            continue;
        };
        assert_eq!(record.expected_payload_len(raw).unwrap(), payload.len());
        let mut header = record.encode_header(Endian::Little).unwrap();
        rolling
            .stamp_record(&mut header, &payload, record.record_type())
            .unwrap();
        output.extend_from_slice(&header);
        output.extend_from_slice(&payload);
    }
    // These adversarial streams retain correct per-record and final checksums.
    // A checksum rejection must not accidentally stand in for payload checks.
    checked_substream_records(&output, raw);
    output
}

fn restamp_raw_keydata(
    stream: &[u8],
    mut edit: impl FnMut(&mut ffs_ondisk::zfs::nvlist::NvList),
) -> Vec<u8> {
    let mut changed = 0;
    let output = restamp_substream(stream, true, |mut record, mut payload| {
        if let DrrRecord::Begin(begin) = &mut record {
            let mut keydata = ffs_ondisk::zfs::nvlist::NvList::parse_exact(&payload).unwrap();
            edit(&mut keydata);
            payload = keydata.encode_xdr().unwrap();
            begin.payload_len = u32::try_from(payload.len()).unwrap();
            changed += 1;
        }
        Some((record, payload))
    });
    assert_eq!(changed, 1);
    output
}

fn raw_stream_keydata(stream: &[u8]) -> StreamCryptoKeydata {
    let (_, record, payload) = checked_substream_records(stream, true)
        .into_iter()
        .next()
        .unwrap();
    assert!(matches!(record, DrrRecord::Begin(_)));
    let envelope = ffs_ondisk::zfs::nvlist::NvList::parse_exact(&payload).unwrap();
    assert_eq!(envelope.fields.len(), 1);
    let keydata = envelope.list("crypt_keydata").unwrap();
    for (name, length) in [
        ("DSL_CRYPTO_IV", 12),
        ("DSL_CRYPTO_MAC", 16),
        ("DSL_CRYPTO_MASTER_KEY_1", 32),
        ("DSL_CRYPTO_HMAC_KEY_1", 64),
        ("portable_mac", 32),
    ] {
        let Some(ffs_ondisk::zfs::nvlist::Value::UnsignedBytes(bytes)) = keydata.fields.get(name)
        else {
            panic!("native raw header field {name} must use DATA_TYPE_UINT8_ARRAY (26)");
        };
        assert_eq!(bytes.len(), length, "native {name} length");
    }
    assert!(
        keydata
            .unsigned("to_ivset_guid")
            .is_some_and(|value| value != 0)
    );
    assert!(keydata.unsigned("from_ivset_guid").is_some());
    StreamCryptoKeydata::from_nvlist(&envelope).unwrap()
}

fn raw_dataset_objectset(
    cx: &Cx,
    mos: &mut ffs_zfs::Objects,
    device: &FaultableMemberDevice,
    dataset: &[Vec<u8>],
    snapshot: Option<&[u8]>,
) -> (BlockPointer, ObjectSet) {
    let object = if let Some(snapshot) = snapshot {
        mos.snapshots(cx, dataset)
            .unwrap()
            .into_iter()
            .find(|row| row.name == snapshot)
            .unwrap()
            .object
    } else {
        // Public dataset inventory intentionally hides incomplete receives.
        // Inspect the native DSL path so checkpoints can be checked without
        // making private staging visible through the filesystem namespace.
        let mut directory = mos
            .zap_values(cx, 1)
            .unwrap()
            .into_iter()
            .find(|entry| entry.name == b"root_dataset")
            .unwrap()
            .scalar()
            .unwrap();
        for component in dataset {
            let node = mos.object(cx, directory).unwrap();
            let children = node.order().u64(node.bonus(), 32).unwrap();
            directory = mos
                .zap_values(cx, children)
                .unwrap()
                .into_iter()
                .find(|entry| entry.name == *component)
                .unwrap()
                .scalar()
                .unwrap();
        }
        let node = mos.object(cx, directory).unwrap();
        node.order().u64(node.bonus(), 8).unwrap()
    };
    let node = mos.object(cx, object).unwrap();
    let pointer = BlockPointer::parse(&node.bonus()[128..256], node.order()).unwrap();
    let media = device.durable_snapshot();
    let offset = usize::try_from(DATA_OFFSET + pointer.data_dvas().unwrap()[0].offset).unwrap();
    let raw = ffs_ondisk::zfs::decompress(
        &media[offset..offset + pointer.physical_bytes()],
        pointer.compression(),
        pointer.logical_bytes(),
    )
    .unwrap();
    let objectset = ObjectSet::parse(&raw, pointer.payload_order()).unwrap();
    (pointer, objectset)
}

struct RecvDnodeReadFaultDevice {
    member: FaultableMemberDevice,
    fault: Arc<Mutex<Option<(u64, FfsError)>>>,
}

impl ByteDevice for RecvDnodeReadFaultDevice {
    fn len_bytes(&self) -> u64 {
        self.member.len_bytes()
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let mut fault = self.fault.lock().unwrap();
        if fault.as_ref().is_some_and(|(at, _)| *at == offset.0) {
            return Err(fault.take().unwrap().1);
        }
        drop(fault);
        self.member.read_exact_at(cx, offset, buf)
    }

    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()> {
        self.member.write_all_at(cx, offset, buf)
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        self.member.sync(cx)
    }

    fn begin_durability_commit(&self, cx: &Cx) -> Result<()> {
        self.member.begin_durability_commit(cx)
    }

    fn complete_durability_commit(&self) {
        self.member.complete_durability_commit();
    }

    fn abort_durability_commit(&self) {
        self.member.abort_durability_commit();
    }
}

#[allow(clippy::too_many_lines)]
fn assert_receive_dnode_read_failure_preserves_checkpoint(corruption: bool) {
    use ffs_ondisk::zfs::send_stream::DrrFreeObjects;

    let cx = Cx::for_testing();
    let timestamp = Timestamp {
        seconds: 1_730_000_709,
        nanos: 0,
    };
    let source = vec![b"data".to_vec()];
    let destination = vec![b"data".to_vec(), b"read_fault".to_vec()];
    let built = build_clean_zfs_pool(&send_recv_pool_spec(32 * 1024 * 1024));
    let source_devices: Vec<_> = built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut sender = open_engine_on_devices(
        &cx,
        &source_devices,
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .unwrap();
    let before = vec![0x51; 4096];
    let after = vec![0xA7; 4096];
    sender
        .write_file_data(
            &cx,
            &source,
            4,
            0,
            &before,
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    sender
        .create_snapshot(&cx, &source, b"base", timestamp)
        .into_result()
        .unwrap();
    sender
        .write_file_data(
            &cx,
            &source,
            4,
            0,
            &after,
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    sender
        .create_snapshot(&cx, &source, b"next", timestamp)
        .into_result()
        .unwrap();
    let mut source_mos = sender.open_read_objects(&cx).unwrap();
    let mut full = Vec::new();
    send_stream(
        &cx,
        &mut source_mos,
        &ZfsSendRequest::full(source.clone(), b"base".to_vec()),
        &mut full,
    )
    .unwrap();
    let mut send = ZfsSendRequest::full(source, b"next".to_vec());
    send.from = Some(ZfsSendFrom::Snapshot(b"base".to_vec()));
    let mut incremental = Vec::new();
    send_stream(&cx, &mut source_mos, &send, &mut incremental).unwrap();

    let target = build_clean_zfs_pool(&send_recv_pool_spec(32 * 1024 * 1024));
    let baseline_devices: Vec<_> = target
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    assert_eq!(baseline_devices.len(), 1);
    let mut baseline = open_engine_on_devices(
        &cx,
        &baseline_devices,
        default_write_opts(target.pool_guid, target.initial_slot),
    )
    .unwrap();
    baseline
        .receive_stream(
            &cx,
            &ZfsRecvRequest::new(destination.clone()),
            &mut Cursor::new(&full),
        )
        .into_result()
        .unwrap();
    let baseline_slot = baseline.committed_slot();
    let baseline_media = snapshot_media_bytes(&baseline_devices);
    let mut mos = baseline.open_read_objects(&cx).unwrap();
    let (_, objectset) =
        raw_dataset_objectset(&cx, &mut mos, &baseline_devices[0], &destination, None);
    assert_eq!(objectset.meta.levels(), 1);
    let table = &objectset.meta.pointers()[0];
    let table_dvas = table.data_dvas().unwrap();
    assert_eq!(table_dvas.len(), 1, "fault must exhaust all block copies");
    let table_offset = DATA_OFFSET + table_dvas[0].offset;
    let table_start = usize::try_from(table_offset).unwrap();
    let table_bytes = ffs_ondisk::zfs::decompress(
        &baseline_media[0][table_start..table_start + table.physical_bytes()],
        table.compression(),
        table.logical_bytes(),
    )
    .unwrap();
    assert!(
        ffs_ondisk::zfs_dmu::dnode_at(&table_bytes, 31, table.payload_order())
            .unwrap()
            .is_none()
    );

    for case in ["object", "write", "freeobjects"] {
        // Each correctly checksummed probe reaches one lookup before any other
        // record can cache or stage its dnode table. FREEOBJECTS names an absent
        // slot: an unreadable table must not masquerade as an absent object.
        let mut selected = false;
        let probe = restamp_substream(&incremental, false, |record, payload| match record {
            DrrRecord::Begin(_) | DrrRecord::End(_) => Some((record, payload)),
            DrrRecord::Object(object) if object.object == 4 && case == "object" => {
                selected = true;
                Some((DrrRecord::Object(object), payload))
            }
            DrrRecord::Write(write) if write.object == 4 && case == "write" && !selected => {
                selected = true;
                Some((DrrRecord::Write(write), payload))
            }
            DrrRecord::Object(object) if object.object == 4 && case == "freeobjects" => {
                selected = true;
                Some((
                    DrrRecord::FreeObjects(DrrFreeObjects {
                        firstobj: 31,
                        numobjs: 1,
                        toguid: object.toguid,
                    }),
                    Vec::new(),
                ))
            }
            _ => None,
        });
        assert!(selected, "{case}: source record missing");
        assert_eq!(checked_substream_records(&probe, false).len(), 3);

        let devices: Vec<_> = baseline_media
            .iter()
            .cloned()
            .map(FaultableMemberDevice::new)
            .collect();
        let fault = Arc::new(Mutex::new(None));
        let device = RecvDnodeReadFaultDevice {
            member: devices[0].clone(),
            fault: Arc::clone(&fault),
        };
        let mut receiver = ZfsTransactionEngine::from_devices(
            &cx,
            vec![Box::new(device)],
            default_write_opts(target.pool_guid, baseline_slot),
        )
        .unwrap();
        let checkpoint = Arc::new(Mutex::new(None));
        let checkpoint_for_hook = Arc::clone(&checkpoint);
        let fault_for_hook = Arc::clone(&fault);
        let member_for_hook = devices[0].clone();
        let diagnostic = "injected receive dnode read failure";
        let mut error = Some(if corruption {
            FfsError::Corruption {
                block: table_offset,
                detail: diagnostic.into(),
            }
        } else {
            FfsError::Io(std::io::Error::other(diagnostic))
        });
        receiver.with_fault_hook(move |event| {
            if event.operation == "recv_begin" && event.stage == ZfsPersistenceStage::AckPublished {
                *checkpoint_for_hook.lock().unwrap() = Some((
                    event.txg,
                    member_for_hook.write_calls(),
                    member_for_hook.durable_snapshot(),
                ));
                *fault_for_hook.lock().unwrap() = Some((table_offset, error.take().unwrap()));
            }
            Ok(())
        });
        let mut receive = ZfsRecvRequest::new(destination.clone());
        receive.resumable = true;
        match receiver.receive_stream(&cx, &receive, &mut Cursor::new(&probe)) {
            ZfsTxOutcome::NotCommitted(error) => assert!(
                error.to_string().contains(diagnostic),
                "{case}: original metadata read error was replaced: {error}"
            ),
            outcome => panic!("{case}: unreadable dnode was accepted: {outcome:?}"),
        }
        assert!(fault.lock().unwrap().is_none(), "{case}: fault not reached");
        let (checkpoint_txg, checkpoint_writes, checkpoint_media) =
            checkpoint.lock().unwrap().take().unwrap();
        assert_eq!(receiver.committed_txg(), checkpoint_txg, "{case}");
        assert_eq!(devices[0].write_calls(), checkpoint_writes, "{case}");
        assert_eq!(devices[0].durable_snapshot(), checkpoint_media, "{case}");

        // Reopen only durable bytes: failed preparation must leave the original
        // head and the zero-progress receive checkpoint usable and abortable.
        let fresh_devices: Vec<_> = devices
            .iter()
            .map(FaultableMemberDevice::fresh_from_durable)
            .collect();
        let mut fresh = open_engine_on_devices(
            &cx,
            &fresh_devices,
            default_write_opts(target.pool_guid, receiver.committed_slot()),
        )
        .unwrap();
        let state = fresh
            .inspect_receive_resume_state(&cx, &destination)
            .unwrap()
            .unwrap();
        assert_eq!((state.object, state.offset, state.bytes), (0, 0, 0));
        assert!(state.is_pct_recv_child);
        let mut fresh_mos = fresh.open_read_objects(&cx).unwrap();
        assert_eq!(
            fresh_mos
                .zpl(&cx, &destination)
                .unwrap()
                .read(&cx, 4, 0, before.len())
                .unwrap(),
            before
        );
        assert_eq!(fresh_mos.snapshots(&cx, &destination).unwrap().len(), 1);
        fresh
            .abort_receive(&cx, &destination)
            .into_result()
            .unwrap();
        // Without a read error the absent FREEOBJECTS slot remains a legal
        // no-op; the other cases retry the complete original incremental.
        let recovery = if case == "freeobjects" {
            &probe
        } else {
            &incremental
        };
        fresh
            .receive_stream(&cx, &receive, &mut Cursor::new(recovery))
            .into_result()
            .unwrap();
        let expected = if case == "freeobjects" {
            &before
        } else {
            &after
        };
        let mut fresh_mos = fresh.open_read_objects(&cx).unwrap();
        assert_eq!(
            fresh_mos
                .zpl(&cx, &destination)
                .unwrap()
                .read(&cx, 4, 0, expected.len())
                .unwrap(),
            *expected
        );
        assert!(
            fresh_mos
                .zpl(&cx, &destination)
                .unwrap()
                .scrub(&cx, ScrubLimits::default())
                .unwrap()
                .is_clean()
        );
        assert!(
            fresh
                .inspect_receive_resume_state(&cx, &destination)
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn incremental_receive_dnode_io_failure_preserves_checkpoint() {
    assert_receive_dnode_read_failure_preserves_checkpoint(false);
}

#[test]
fn incremental_receive_dnode_corruption_preserves_checkpoint() {
    assert_receive_dnode_read_failure_preserves_checkpoint(true);
}

#[test]
#[allow(clippy::too_many_lines)]
fn malformed_plain_compressed_records_preserve_the_last_durable_checkpoint() {
    use ffs_ondisk::zfs::send_stream::DrrWriteEmbedded;

    let cx = Cx::for_testing();
    let timestamp = Timestamp {
        seconds: 1_730_000_710,
        nanos: 0,
    };
    let source = vec![b"data".to_vec()];
    let destination = vec![b"data".to_vec(), b"validated".to_vec()];
    let spec = PoolFixtureSpec {
        ashift: 9,
        ..send_recv_pool_spec(32 * 1024 * 1024)
    };
    let built = build_clean_zfs_pool(&spec);
    let source_devices: Vec<_> = built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut sender = open_engine_on_devices(
        &cx,
        &source_devices,
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .unwrap();
    for (name, value) in [("recordsize", 4096), ("compression", 15)] {
        sender
            .set_property(&cx, &source, name, ZfsPropertySetValue::Number(value))
            .into_result()
            .unwrap();
    }
    let content = vec![0xA6; 3 * 4096];
    sender
        .write_file_data(
            &cx,
            &source,
            4,
            0,
            &content,
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    sender
        .create_snapshot(&cx, &source, b"validated", timestamp)
        .into_result()
        .unwrap();
    let mut source_mos = sender.open_read_objects(&cx).unwrap();
    let mut request = ZfsSendRequest::full(source.clone(), b"validated".to_vec());
    request.compressed = true;
    request.embedded = true;
    let mut stream = Vec::new();
    send_stream(&cx, &mut source_mos, &request, &mut stream).unwrap();
    stream = restamp_substream(&stream, false, |mut record, payload| {
        if let DrrRecord::Begin(begin) = &mut record {
            begin.features = begin
                .features
                .with(ffs_ondisk::zfs::send_stream::DMU_BACKUP_FEATURE_ZSTD);
        }
        Some((record, payload))
    });
    let second_record = checked_substream_records(&stream, false).into_iter().find(|(_, record, _)| {
        matches!(record, DrrRecord::Write(write) if write.object == 4 && write.offset == 4096)
    }).unwrap().0;
    let target = build_clean_zfs_pool(&spec);
    let mut receive = ZfsRecvRequest::new(destination.clone());
    receive.resumable = true;
    receive.checkpoint_bytes = 1;
    let baseline_devices: Vec<_> = target
        .members
        .iter()
        .cloned()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut baseline = open_engine_on_devices(
        &cx,
        &baseline_devices,
        default_write_opts(target.pool_guid, target.initial_slot),
    )
    .unwrap();
    assert!(matches!(
        baseline.receive_stream(&cx, &receive, &mut Cursor::new(&stream[..second_record])),
        ZfsTxOutcome::NotCommitted(_)
    ));
    let expected_state = baseline
        .inspect_receive_resume_state(&cx, &destination)
        .unwrap()
        .unwrap();
    let expected_txg = baseline.committed_txg();
    assert_eq!(expected_state.object, 4);
    assert_eq!(expected_state.offset, 4096);
    for case in 0..8 {
        let mut changed = 0;
        let malformed = restamp_substream(&stream, false, |mut record, mut payload| {
            if let DrrRecord::Write(write) = &mut record
                && write.object == 4
                && write.offset == 4096
            {
                changed += 1;
                match case {
                    0..=2 => {
                        write.compressiontype = [15, 5, 16][case];
                        payload.fill(0);
                        if case == 0 {
                            payload[..4].copy_from_slice(&u32::MAX.to_be_bytes());
                        }
                    }
                    3 => write.logical_size = 8192,
                    4 => write.logical_size = ffs_ondisk::zfs::MAX_BLOCK_BYTES as u64 + 512,
                    5 => write.offset = u64::MAX - 4095,
                    6 | 7 => {
                        let embedded = DrrWriteEmbedded {
                            object: write.object,
                            offset: write.offset,
                            length: write.logical_size,
                            toguid: write.toguid,
                            compression: 15,
                            etype: 0,
                            lsize: if case == 6 { 4096 } else { 8192 },
                            psize: 8,
                        };
                        payload = vec![0xFF; 8];
                        record = DrrRecord::WriteEmbedded(embedded);
                    }
                    _ => unreachable!(),
                }
            }
            if let DrrRecord::Begin(begin) = &mut record {
                begin.features = begin
                    .features
                    .with(ffs_ondisk::zfs::send_stream::DMU_BACKUP_FEATURE_ZSTD);
            }
            Some((record, payload))
        });
        assert_eq!(changed, 1);
        let devices: Vec<_> = target
            .members
            .iter()
            .cloned()
            .map(FaultableMemberDevice::new)
            .collect();
        let mut receiver = open_engine_on_devices(
            &cx,
            &devices,
            default_write_opts(target.pool_guid, target.initial_slot),
        )
        .unwrap();
        match receiver.receive_stream(&cx, &receive, &mut Cursor::new(&malformed)) {
            ZfsTxOutcome::NotCommitted(error) => assert!(
                !error.to_string().contains("Fletcher4"),
                "case {case}: {error}"
            ),
            other => panic!("malformed compressed record {case} was accepted: {other:?}"),
        }
        assert_eq!(
            receiver.committed_txg(),
            expected_txg,
            "case {case} advanced durability"
        );
        let state = receiver
            .inspect_receive_resume_state(&cx, &destination)
            .unwrap()
            .unwrap();
        assert_eq!(
            state, expected_state,
            "case {case} advanced resume position"
        );
        let slot = receiver.committed_slot();
        drop(receiver);
        let durable: Vec<_> = devices
            .iter()
            .map(FaultableMemberDevice::fresh_from_durable)
            .collect();
        let mut reopened =
            open_engine_on_devices(&cx, &durable, default_write_opts(target.pool_guid, slot))
                .unwrap();
        assert_eq!(
            reopened
                .inspect_receive_resume_state(&cx, &destination)
                .unwrap(),
            Some(expected_state.clone())
        );
        if case % 2 == 0 {
            let mut resume = ZfsSendRequest::full(source.clone(), Vec::new());
            resume.resume_token = Some(state.token);
            resume.compressed = true;
            resume.embedded = true;
            let mut remaining = Vec::new();
            send_stream(&cx, &mut source_mos, &resume, &mut remaining).unwrap();
            reopened
                .receive_stream(&cx, &receive, &mut Cursor::new(remaining))
                .into_result()
                .unwrap();
            let mut mos = reopened.open_read_objects(&cx).unwrap();
            assert_eq!(
                mos.zpl(&cx, &destination)
                    .unwrap()
                    .read(&cx, 4, 0, content.len())
                    .unwrap(),
                content
            );
        } else {
            reopened
                .abort_receive(&cx, &destination)
                .into_result()
                .unwrap();
            assert!(
                reopened
                    .inspect_receive_resume_state(&cx, &destination)
                    .unwrap()
                    .is_none()
            );
            assert!(
                !reopened
                    .open_read_objects(&cx)
                    .unwrap()
                    .datasets(&cx)
                    .unwrap()
                    .iter()
                    .any(|row| row.components == destination)
            );
        }
        assert_pool_scrub_and_allocation_clean(
            &cx,
            &durable,
            target.pool_guid,
            Some(reopened.committed_slot()),
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn compressed_send_exports_logical_metadata_and_native_untyped_sa_spills() {
    let cx = Cx::for_testing();
    let timestamp = Timestamp {
        seconds: 1_730_000_711,
        nanos: 0,
    };
    let source = vec![b"data".to_vec()];
    let destination = vec![b"data".to_vec(), b"native-spill".to_vec()];
    let spec = PoolFixtureSpec {
        ashift: 9,
        ..send_recv_pool_spec(32 * 1024 * 1024)
    };
    let built = build_clean_zfs_pool(&spec);
    let source_devices: Vec<_> = built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut sender = open_engine_on_devices(
        &cx,
        &source_devices,
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .unwrap();
    let xattr = vec![0x6A; 12 * 1024];
    sender
        .set_xattr(
            &cx,
            &source,
            4,
            "user.native-spill",
            &xattr,
            ZfsXattrSetMode::Create,
            timestamp,
        )
        .into_result()
        .unwrap();
    sender
        .rename_entry(
            &cx,
            &source,
            2,
            b"hello.txt",
            2,
            b"renamed",
            Some(4),
            timestamp,
        )
        .into_result()
        .unwrap();
    sender
        .create_snapshot(&cx, &source, b"wire", timestamp)
        .into_result()
        .unwrap();
    let node = native_zpl_file_dnode(&cx, &sender, &source_devices[0], &source, 4);
    let spill = node.spill().unwrap();
    assert_eq!(node.bonus_type(), 44);
    assert_eq!(spill.compression(), 15);
    assert!(spill.physical_bytes() < spill.logical_bytes());
    let directory = native_zpl_file_dnode(&cx, &sender, &source_devices[0], &source, 2);
    assert!(
        native_plain_leaf_pointers(&source_devices[0], &directory)
            .iter()
            .any(|pointer| pointer.compression() == 15)
    );
    let source_media = source_devices[0].durable_snapshot();
    let physical_offset =
        usize::try_from(DATA_OFFSET + spill.regular_dvas().unwrap()[0].offset).unwrap();
    let compressed_spill =
        source_media[physical_offset..physical_offset + spill.physical_bytes()].to_vec();
    let logical_spill =
        ffs_ondisk::zfs::decompress(&compressed_spill, 15, spill.logical_bytes()).unwrap();
    let mut source_mos = sender.open_read_objects(&cx).unwrap();
    let mut request = ZfsSendRequest::full(source.clone(), b"wire".to_vec());
    request.compressed = true;
    let mut stream = Vec::new();
    send_stream(&cx, &mut source_mos, &request, &mut stream).unwrap();
    let mut saw_directory = false;
    let mut saw_spill = false;
    for (_, record, payload) in checked_substream_records(&stream, false) {
        match record {
            DrrRecord::Write(write) if write.object == 2 => {
                saw_directory = true;
                assert_eq!(write.compressiontype, 0);
                assert_eq!(write.compressed_size, 0);
                assert_eq!(payload.len() as u64, write.logical_size);
            }
            DrrRecord::Spill(record) if record.object == 4 => {
                saw_spill = true;
                assert_eq!(
                    record.object_type, 0,
                    "native DRR_SPILL leaves this field unused"
                );
                assert_eq!(
                    record.compressiontype, 0,
                    "-c does not compress nonraw spills"
                );
                assert_eq!(record.compressed_size, 0);
                assert_eq!(record.salt, [0; 8]);
                assert_eq!(record.iv, [0; 12]);
                assert_eq!(record.mac, [0; 16]);
                assert_eq!(payload, logical_spill);
            }
            _ => {}
        }
    }
    assert!(saw_directory && saw_spill);
    let target = build_clean_zfs_pool(&spec);
    let devices: Vec<_> = target
        .members
        .iter()
        .cloned()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut receiver = open_engine_on_devices(
        &cx,
        &devices,
        default_write_opts(target.pool_guid, target.initial_slot),
    )
    .unwrap();
    receiver
        .receive_stream(
            &cx,
            &ZfsRecvRequest::new(destination.clone()),
            &mut Cursor::new(&stream),
        )
        .into_result()
        .unwrap();
    let slot = receiver.committed_slot();
    drop(receiver);
    let durable: Vec<_> = devices
        .iter()
        .map(FaultableMemberDevice::fresh_from_durable)
        .collect();
    let reopened =
        open_engine_on_devices(&cx, &durable, default_write_opts(target.pool_guid, slot)).unwrap();
    let mut mos = reopened.open_read_objects(&cx).unwrap();
    let mut view = mos.zpl(&cx, &destination).unwrap();
    assert_eq!(view.resolve(&cx, b"/renamed").unwrap(), 4);
    assert_eq!(
        view.getxattr(&cx, 4, "user.native-spill").unwrap(),
        Some(xattr)
    );
    assert_eq!(
        view.read(&cx, 4, 0, 4096).unwrap(),
        built.snap_hello_expected
    );
    assert_pool_scrub_and_allocation_clean(&cx, &durable, target.pool_guid, Some(slot));

    let mut changed = 0;
    let malformed = restamp_substream(&stream, false, |mut record, mut payload| {
        if let DrrRecord::Spill(spill) = &mut record
            && spill.object == 4
        {
            changed += 1;
            spill.compressiontype = 15;
            spill.compressed_size = compressed_spill.len() as u64;
            payload = compressed_spill.clone();
        }
        Some((record, payload))
    });
    assert_eq!(changed, 1);
    let rejected_devices: Vec<_> = target
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut rejected = open_engine_on_devices(
        &cx,
        &rejected_devices,
        default_write_opts(target.pool_guid, target.initial_slot),
    )
    .unwrap();
    assert!(matches!(
        rejected.receive_stream(
            &cx,
            &ZfsRecvRequest::new(destination.clone()),
            &mut Cursor::new(malformed)
        ),
        ZfsTxOutcome::NotCommitted(_)
    ));
    assert!(
        !rejected
            .open_read_objects(&cx)
            .unwrap()
            .datasets(&cx)
            .unwrap()
            .iter()
            .any(|row| row.components == destination)
    );
    assert_pool_scrub_and_allocation_clean(
        &cx,
        &rejected_devices,
        target.pool_guid,
        Some(rejected.committed_slot()),
    );
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
    let invalid_compression = restamp_substream(&full, false, |mut record, payload| {
        if let DrrRecord::Object(node) = &mut record
            && node.object == object
        {
            node.compress = 255;
        }
        Some((record, payload))
    });
    assert!(matches!(
        receiver.receive_stream(&cx, &receive, &mut Cursor::new(invalid_compression)),
        ZfsTxOutcome::NotCommitted(FfsError::Format(message)) if message.contains("compression selector")
    ));
    assert!(
        receiver
            .inspect_receive_resume_state(&cx, &destination)
            .unwrap()
            .is_none()
    );
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
    // Incremental streams may omit DRR_OBJECT for an existing object. Validate
    // writes against the actual staging dnode, not only objects seen on the wire.
    let mut removed = 0;
    let without_object = restamp_substream(&incremental, false, |record, payload| {
        if matches!(&record, DrrRecord::Object(node) if node.object == object) {
            removed += 1;
            None
        } else {
            Some((record, payload))
        }
    });
    assert_eq!(removed, 1);
    let write_start = checked_substream_records(&without_object, false)
        .into_iter()
        .find(|(_, record, _)| matches!(record, DrrRecord::Write(write) if write.object == object))
        .unwrap()
        .0;
    let mut resumable = ZfsRecvRequest::new(destination.clone());
    resumable.resumable = true;
    resumable.checkpoint_bytes = 1;
    let control_txg = receiver.committed_txg();
    assert!(matches!(
        receiver.receive_stream(
            &cx,
            &resumable,
            &mut Cursor::new(&without_object[..write_start])
        ),
        ZfsTxOutcome::NotCommitted(_)
    ));
    let expected_commits = receiver.committed_txg() - control_txg;
    let expected_state = receiver
        .inspect_receive_resume_state(&cx, &destination)
        .unwrap()
        .unwrap();
    receiver
        .abort_receive(&cx, &destination)
        .into_result()
        .unwrap();
    for case in 0..3 {
        let mut changed = 0;
        let invalid = restamp_substream(&without_object, false, |mut record, mut payload| {
            if let DrrRecord::Write(write) = &mut record
                && write.object == object
            {
                changed += 1;
                match case {
                    0 => {
                        write.logical_size /= 2;
                        payload.truncate(usize::try_from(write.logical_size).unwrap());
                    }
                    1 => write.offset = 512,
                    2 => write.object_type = 23,
                    _ => unreachable!(),
                }
            }
            Some((record, payload))
        });
        assert_eq!(changed, 1);
        let before = receiver.committed_txg();
        assert!(
            matches!(
                receiver.receive_stream(&cx, &resumable, &mut Cursor::new(invalid)),
                ZfsTxOutcome::NotCommitted(_)
            ),
            "existing-object geometry case {case}"
        );
        assert_eq!(
            receiver.committed_txg() - before,
            expected_commits,
            "invalid existing-object write reached a checkpoint"
        );
        assert_eq!(
            receiver
                .inspect_receive_resume_state(&cx, &destination)
                .unwrap(),
            Some(expected_state.clone())
        );
        let mut view = receiver
            .open_read_objects(&cx)
            .unwrap()
            .zpl(&cx, &destination)
            .unwrap();
        assert_eq!(view.read(&cx, object, 0, initial.len()).unwrap(), initial);
        receiver
            .abort_receive(&cx, &destination)
            .into_result()
            .unwrap();
    }
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
fn zpl_full_incremental_bookmark_intermediary_properties_and_foreign_order_refusal() {
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
    //    intermediary compound stream -I @s1 @s3, and refuse unconverted foreign-order metadata.
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
    assert!(matches!(
        send_stream(&cx, &mut src_mos, &be_req, &mut be_full_bytes),
        Err(FfsError::UnsupportedFeature(_))
    ));

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

    // 4. Receive native-order full @s1 into `data/dst_inter` then `-I @s1 @s3` intermediary compound.
    let dst_inter = vec![b"data".to_vec(), b"dst_inter".to_vec()];
    dst_engine
        .receive_stream(
            &cx,
            &ZfsRecvRequest::new(dst_inter.clone()),
            &mut Cursor::new(&full_s1_bytes),
        )
        .into_result()
        .expect("receive native-order full @s1");
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

    // 1. Source encrypted dataset with data snapshots and an unchanged @e3-empty.
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
            &[
                ("compression".to_owned(), ZfsPropertySetValue::Number(15)),
                (
                    "recordsize".to_owned(),
                    ZfsPropertySetValue::Number(262_144),
                ),
                ("checksum".to_owned(), ZfsPropertySetValue::Number(11)),
            ],
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
            ZfsDataChecksum::Inherit,
        )
        .into_result()
        .unwrap();
    let sec_e1: Vec<u8> = (0..320 * 1024)
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
            ZfsDataChecksum::Inherit,
        )
        .into_result()
        .unwrap();
    let secret_xattr = vec![0xD8; 12 * 1024];
    src_engine
        .set_xattr(
            &cx,
            &vault_src,
            sec_obj,
            "user.raw-spill",
            &secret_xattr,
            ZfsXattrSetMode::Create,
            ts,
        )
        .into_result()
        .unwrap();

    // Grow beyond the three direct metadata leaves, then free every upper
    // object. The source retains its two-level metadata tree and high-water
    // mark even though only table zero remains allocated. Raw receive must
    // reproduce that authenticated shape rather than infer it from OBJECTs.
    for index in 0..96 {
        let name = format!("meta-shape-{index:03}");
        src_engine
            .create_file(
                &cx,
                &vault_src,
                root_obj,
                name.as_bytes(),
                0o600,
                0,
                0,
                ts,
                ZfsDataChecksum::Inherit,
            )
            .into_result()
            .unwrap();
    }
    for index in 0..96 {
        let name = format!("meta-shape-{index:03}");
        src_engine
            .unlink_entry(&cx, &vault_src, root_obj, name.as_bytes(), false, ts)
            .into_result()
            .unwrap();
    }
    assert_pool_scrub_and_allocation_clean(
        &cx,
        &src_devs,
        src_built.pool_guid,
        Some(src_engine.committed_slot()),
    );
    src_engine
        .create_snapshot(&cx, &vault_src, b"e1", ts)
        .into_result()
        .unwrap();

    let sec_e2: Vec<u8> = (0..300 * 1024)
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
            ZfsDataChecksum::Inherit,
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
            ZfsDataChecksum::Inherit,
        )
        .into_result()
        .unwrap();
    src_engine
        .create_snapshot(&cx, &vault_src, b"e2", ts)
        .into_result()
        .unwrap();
    src_engine
        .create_snapshot(&cx, &vault_src, b"e3-empty", ts)
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

    let (_, source_e1) = raw_dataset_objectset(
        &cx,
        &mut keyless_src_mos,
        &src_devs[0],
        &vault_src,
        Some(b"e1"),
    );
    assert!(source_e1.meta.levels() >= 2);
    assert!(source_e1.meta.max_block() >= 3);
    assert!(
        source_e1.meta.pointers()[1..]
            .iter()
            .all(BlockPointer::hole)
    );
    let meta_indirect = &source_e1.meta.pointers()[0];
    assert_eq!(meta_indirect.level(), 1);
    let allocated_meta_leaves: Vec<_> = {
        let source_media = src_devs[0].durable_snapshot();
        let meta_offset =
            usize::try_from(DATA_OFFSET + meta_indirect.data_dvas().unwrap()[0].offset).unwrap();
        let meta_payload = ffs_ondisk::zfs::decompress(
            &source_media[meta_offset..meta_offset + meta_indirect.physical_bytes()],
            meta_indirect.compression(),
            meta_indirect.logical_bytes(),
        )
        .unwrap();
        meta_payload
            .as_chunks::<128>()
            .0
            .iter()
            .enumerate()
            .filter_map(|(block, bytes)| {
                let pointer = BlockPointer::parse(bytes, meta_indirect.payload_order()).unwrap();
                (!pointer.hole()).then_some(block)
            })
            .collect()
    };
    assert_eq!(
        allocated_meta_leaves,
        vec![0],
        "source must retain sparse overheight with no allocated upper metadata leaves"
    );
    let mut raw_e1 = Vec::new();
    let mut req_e1 = ZfsSendRequest::full(vault_src.clone(), b"e1".to_vec());
    req_e1.raw = true;
    req_e1.large_blocks = true;
    let report_e1 = send_stream(&cx, &mut keyless_src_mos, &req_e1, &mut raw_e1).unwrap();
    assert!(report_e1.raw);
    let keydata_e1 = raw_stream_keydata(&raw_e1);
    assert_eq!(
        keydata_e1.meta_dnode,
        StreamMetaDnode::from_dnode(&source_e1.meta).unwrap()
    );
    assert_eq!(keydata_e1.portable_mac, source_e1.portable_mac().unwrap());
    let mut raw_spills = 0;
    for (_, record, _) in checked_substream_records(&raw_e1, true) {
        if let DrrRecord::Spill(spill) = record
            && spill.object == sec_obj
        {
            assert_eq!(
                spill.object_type, 0,
                "native raw SPILL also leaves its type field unused"
            );
            assert_eq!(spill.compressiontype, 15);
            assert!(spill.compressed_size < spill.length);
            raw_spills += 1;
        }
    }
    assert_eq!(raw_spills, 1);

    let mut raw_e2 = Vec::new();
    let mut req_e2 = ZfsSendRequest::full(vault_src.clone(), b"e2".to_vec());
    req_e2.from = Some(ZfsSendFrom::Snapshot(b"e1".to_vec()));
    req_e2.raw = true;
    req_e2.large_blocks = true;
    let report_e2 = send_stream(&cx, &mut keyless_src_mos, &req_e2, &mut raw_e2).unwrap();
    assert!(report_e2.raw && report_e2.from_guid == report_e1.to_guid);
    let keydata_e2 = raw_stream_keydata(&raw_e2);
    let (_, source_e2) = raw_dataset_objectset(
        &cx,
        &mut keyless_src_mos,
        &src_devs[0],
        &vault_src,
        Some(b"e2"),
    );
    assert_eq!(
        keydata_e2.meta_dnode,
        StreamMetaDnode::from_dnode(&source_e2.meta).unwrap()
    );
    assert_eq!(keydata_e2.from_ivset_guid, Some(keydata_e1.to_ivset_guid));
    let mut req_e3 = ZfsSendRequest::full(vault_src.clone(), b"e3-empty".to_vec());
    req_e3.from = Some(ZfsSendFrom::Snapshot(b"e2".to_vec()));
    req_e3.raw = true;
    let mut raw_e3 = Vec::new();
    send_stream(&cx, &mut keyless_src_mos, &req_e3, &mut raw_e3).unwrap();
    let records_e3 = checked_substream_records(&raw_e3, true);
    assert_eq!(
        records_e3.len(),
        2,
        "unchanged snapshot must emit only BEGIN and END"
    );
    assert!(matches!(records_e3[1].1, DrrRecord::End(_)));
    let keydata_e3 = raw_stream_keydata(&raw_e3);
    assert_eq!(keydata_e3.meta_dnode, keydata_e2.meta_dnode);
    assert_eq!(keydata_e3.from_ivset_guid, Some(keydata_e2.to_ivset_guid));

    // Raw compressed WRITE records retain the source BP algorithm and logical
    // geometry. Refuse either missing feature without publishing the dataset.
    for missing in [
        b"org.open-zfs:large_blocks".as_slice(),
        b"org.illumos:sha512".as_slice(),
    ] {
        let mut specification = send_recv_pool_spec(32 * 1024 * 1024);
        specification
            .additional_read_features
            .retain(|(name, _)| *name != missing);
        let refused = build_clean_zfs_pool(&specification);
        let devices: Vec<_> = refused
            .members
            .into_iter()
            .map(FaultableMemberDevice::new)
            .collect();
        let mut receiver = open_engine_on_devices(
            &cx,
            &devices,
            default_write_opts(refused.pool_guid, refused.initial_slot),
        )
        .unwrap();
        let destination = vec![b"data".to_vec(), b"unsupported_raw".to_vec()];
        let request = ZfsRecvRequest::new(destination.clone());
        let feature = std::str::from_utf8(missing).unwrap();
        assert!(matches!(
            receiver.receive_stream(&cx, &request, &mut Cursor::new(&raw_e1)),
            ZfsTxOutcome::NotCommitted(error) if error.to_string().contains(feature)
        ));
        assert!(
            receiver
                .inspect_receive_resume_state(&cx, &destination)
                .unwrap()
                .is_none()
        );
        assert!(
            !receiver
                .open_read_objects(&cx)
                .unwrap()
                .datasets(&cx)
                .unwrap()
                .iter()
                .any(|row| row.components == destination)
        );
        assert_pool_scrub_and_allocation_clean(
            &cx,
            &devices,
            refused.pool_guid,
            Some(receiver.committed_slot()),
        );
    }

    // 3. Receive the raw encrypted streams on a fresh KEYLESS destination pool.
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
    let mut receive = ZfsRecvRequest::new(vault_dst.clone());
    receive.resumable = true;
    receive.checkpoint_bytes = 1;
    let before_missing_keydata = snapshot_media_bytes(&dst_devs);
    let missing_keydata = restamp_substream(&raw_e1, true, |mut record, mut payload| {
        if let DrrRecord::Begin(begin) = &mut record {
            begin.payload_len = 0;
            payload.clear();
        }
        Some((record, payload))
    });
    assert!(matches!(
        dst_engine.receive_stream(&cx, &receive, &mut Cursor::new(missing_keydata)),
        ZfsTxOutcome::NotCommitted(_)
    ));
    assert_media_unchanged(&dst_devs, &before_missing_keydata);
    assert!(
        dst_engine
            .inspect_receive_resume_state(&cx, &vault_dst)
            .unwrap()
            .is_none()
    );
    for (field, value) in [
        ("mdn_nlevels", None),
        ("mdn_blksz", Some(8192)),
        ("mdn_nlevels", Some(8)),
        ("to_ivset_guid", Some(0)),
    ] {
        let invalid = restamp_raw_keydata(&raw_e1, |envelope| {
            use ffs_ondisk::zfs::nvlist::Value;
            let Some(Value::List(keydata)) = envelope.fields.get_mut("crypt_keydata") else {
                panic!("missing source keydata")
            };
            if let Some(value) = value {
                keydata
                    .fields
                    .insert(field.to_owned(), Value::Unsigned(value));
            } else {
                assert!(keydata.fields.remove(field).is_some());
            }
        });
        let before = snapshot_media_bytes(&dst_devs);
        assert!(
            matches!(
                dst_engine.receive_stream(&cx, &receive, &mut Cursor::new(invalid)),
                ZfsTxOutcome::NotCommitted(_)
            ),
            "invalid raw field {field}={value:?}"
        );
        assert_media_unchanged(&dst_devs, &before);
        assert!(
            dst_engine
                .inspect_receive_resume_state(&cx, &vault_dst)
                .unwrap()
                .is_none()
        );
    }
    for malformed_range in 0..3 {
        let mut changed = false;
        let mut malformed = Vec::new();
        let mut rolling = Fletcher4Stream::new(Endian::Little);
        for (_, mut record, payload) in checked_substream_records(&raw_e1, true) {
            let mut raw_patch = None;
            if let DrrRecord::ObjectRange(range) = &mut record
                && !changed
            {
                match malformed_range {
                    0 => raw_patch = Some((8_usize, 1_u64)),
                    1 => raw_patch = Some((16_usize, u64::MAX)),
                    2 => range.flags ^= ffs_ondisk::zfs::send_stream::DRR_RAW_BYTESWAP,
                    _ => unreachable!(),
                }
                changed = true;
            }
            let mut header = record.encode_header(Endian::Little).unwrap();
            if let Some((offset, value)) = raw_patch {
                header[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            }
            rolling
                .stamp_record(&mut header, &payload, record.record_type())
                .unwrap();
            malformed.extend_from_slice(&header);
            malformed.extend_from_slice(&payload);
        }
        assert!(changed);
        assert!(matches!(
            dst_engine.receive_stream(
                &cx,
                &ZfsRecvRequest::new(vault_dst.clone()),
                &mut Cursor::new(malformed)
            ),
            ZfsTxOutcome::NotCommitted(_)
        ));
        assert!(
            dst_engine
                .inspect_receive_resume_state(&cx, &vault_dst)
                .unwrap()
                .is_none()
        );
        assert!(
            !dst_engine
                .open_read_objects(&cx)
                .unwrap()
                .datasets(&cx)
                .unwrap()
                .iter()
                .any(|row| row.components == vault_dst)
        );
        assert_pool_scrub_and_allocation_clean(
            &cx,
            &dst_devs,
            dst_built.pool_guid,
            Some(dst_engine.committed_slot()),
        );
    }
    assert!(matches!(
        dst_engine.receive_stream(
            &cx,
            &receive,
            &mut Cursor::new(&raw_e1[..raw_e1.len() - DMU_REPLAY_RECORD_BYTES]),
        ),
        ZfsTxOutcome::NotCommitted(_)
    ));
    assert_eq!(&dsl_block_feature_counts(&cx, &dst_engine)[..2], &[1, 1]);
    let mut checkpoint_mos = dst_engine.open_read_objects(&cx).unwrap();
    let (_, checkpoint_objset) =
        raw_dataset_objectset(&cx, &mut checkpoint_mos, &dst_devs[0], &vault_dst, None);
    assert_eq!(
        StreamMetaDnode::from_dnode(&checkpoint_objset.meta).unwrap(),
        keydata_e1.meta_dnode
    );
    let state = dst_engine
        .inspect_receive_resume_state(&cx, &vault_dst)
        .unwrap()
        .expect("raw feature-bearing checkpoint");
    let mut resume = ZfsSendRequest::full(vault_src.clone(), Vec::new());
    resume.resume_token = Some(state.token.clone());
    resume.raw = true;
    resume.large_blocks = true;
    let mut resumed_e1 = Vec::new();
    send_stream(&cx, &mut keyless_src_mos, &resume, &mut resumed_e1).unwrap();
    assert_eq!(
        raw_stream_keydata(&resumed_e1).meta_dnode,
        keydata_e1.meta_dnode
    );
    let changed_resume_geometry = restamp_raw_keydata(&resumed_e1, |envelope| {
        use ffs_ondisk::zfs::nvlist::Value;
        let Some(Value::List(keydata)) = envelope.fields.get_mut("crypt_keydata") else {
            panic!("missing source keydata")
        };
        keydata.fields.insert(
            "mdn_nlevels".to_owned(),
            Value::Unsigned(u64::from(keydata_e1.meta_dnode.levels) + 1),
        );
    });
    let before_geometry = snapshot_media_bytes(&dst_devs);
    assert!(matches!(
        dst_engine.receive_stream(&cx, &receive, &mut Cursor::new(changed_resume_geometry)),
        ZfsTxOutcome::NotCommitted(_)
    ));
    assert_media_unchanged(&dst_devs, &before_geometry);
    let downgraded = restamp_substream(&resumed_e1, true, |mut record, payload| {
        if let DrrRecord::Begin(begin) = &mut record {
            begin.features = ffs_ondisk::zfs::send_stream::SendFeatureFlags::from_bits(
                begin.features.bits() & !ffs_ondisk::zfs::send_stream::DMU_BACKUP_FEATURE_RAW,
            );
        }
        Some((record, payload))
    });
    let checkpoint_media = snapshot_media_bytes(&dst_devs);
    assert!(matches!(
        dst_engine.receive_stream(&cx, &receive, &mut Cursor::new(downgraded)),
        ZfsTxOutcome::NotCommitted(_)
    ));
    assert_media_unchanged(&dst_devs, &checkpoint_media);
    assert_eq!(
        dst_engine
            .inspect_receive_resume_state(&cx, &vault_dst)
            .unwrap(),
        Some(state)
    );
    let (r_e1, _) = dst_engine
        .receive_stream(&cx, &receive, &mut Cursor::new(&resumed_e1))
        .into_result()
        .expect("keyless raw recv @e1");
    assert!(r_e1.raw && r_e1.final_snapshot == "e1");
    assert_eq!(&dsl_block_feature_counts(&cx, &dst_engine)[..2], &[2, 2]);
    let mut full_mos = dst_engine.open_read_objects(&cx).unwrap();
    let (_, full_objset) =
        raw_dataset_objectset(&cx, &mut full_mos, &dst_devs[0], &vault_dst, None);
    assert_eq!(
        StreamMetaDnode::from_dnode(&full_objset.meta).unwrap(),
        keydata_e1.meta_dnode
    );

    for case in 0..5 {
        let invalid = restamp_raw_keydata(&raw_e2, |envelope| {
            use ffs_ondisk::zfs::nvlist::Value;
            let Some(Value::List(keydata)) = envelope.fields.get_mut("crypt_keydata") else {
                panic!("missing source keydata")
            };
            match case {
                0 => {
                    let guid = keydata.unsigned("DSL_CRYPTO_GUID").unwrap();
                    keydata
                        .fields
                        .insert("DSL_CRYPTO_GUID".to_owned(), Value::Unsigned(guid ^ 1));
                }
                1 => {
                    assert!(keydata.fields.remove("from_ivset_guid").is_some());
                }
                2 => {
                    keydata
                        .fields
                        .insert("from_ivset_guid".to_owned(), Value::Unsigned(0));
                }
                3 => {
                    let ivset = keydata.unsigned("from_ivset_guid").unwrap();
                    keydata
                        .fields
                        .insert("from_ivset_guid".to_owned(), Value::Unsigned(ivset ^ 1));
                }
                4 => {
                    keydata
                        .fields
                        .insert("mdn_indblkshift".to_owned(), Value::Unsigned(16));
                }
                _ => unreachable!(),
            }
        });
        let before = snapshot_media_bytes(&dst_devs);
        assert!(
            matches!(
                dst_engine.receive_stream(
                    &cx,
                    &ZfsRecvRequest::new(vault_dst.clone()),
                    &mut Cursor::new(invalid)
                ),
                ZfsTxOutcome::NotCommitted(_)
            ),
            "raw identity case {case}"
        );
        assert_media_unchanged(&dst_devs, &before);
    }
    let mut plain_source = src_engine.open_read_objects(&cx).unwrap();
    plain_source
        .load_key(&cx, &vault_src, &wrapping_key)
        .unwrap();
    let mut plain_request = ZfsSendRequest::full(vault_src.clone(), b"e2".to_vec());
    plain_request.from = Some(ZfsSendFrom::Snapshot(b"e1".to_vec()));
    plain_request.large_blocks = true;
    let mut plain_incremental = Vec::new();
    send_stream(
        &cx,
        &mut plain_source,
        &plain_request,
        &mut plain_incremental,
    )
    .unwrap();
    let before_plain = snapshot_media_bytes(&dst_devs);
    assert!(matches!(
        dst_engine.receive_stream(
            &cx,
            &ZfsRecvRequest::new(vault_dst.clone()),
            &mut Cursor::new(plain_incremental)
        ),
        ZfsTxOutcome::NotCommitted(_)
    ));
    assert_media_unchanged(&dst_devs, &before_plain);

    let (r_e2, tok_e2) = dst_engine
        .receive_stream(
            &cx,
            &ZfsRecvRequest::new(vault_dst.clone()),
            &mut Cursor::new(&raw_e2),
        )
        .into_result()
        .expect("keyless raw incremental recv @e2");
    assert!(r_e2.raw && r_e2.final_snapshot == "e2");
    assert_eq!(&dsl_block_feature_counts(&cx, &dst_engine)[..2], &[3, 3]);
    let mut before_empty_mos =
        open_mos(&cx, &dst_devs, dst_built.pool_guid, tok_e2.published_slot());
    let (before_empty_root, before_empty_objset) =
        raw_dataset_objectset(&cx, &mut before_empty_mos, &dst_devs[0], &vault_dst, None);
    assert_eq!(
        StreamMetaDnode::from_dnode(&before_empty_objset.meta).unwrap(),
        keydata_e2.meta_dnode
    );
    let (empty_report, tok_e3) = dst_engine
        .receive_stream(
            &cx,
            &ZfsRecvRequest::new(vault_dst.clone()),
            &mut Cursor::new(&raw_e3),
        )
        .into_result()
        .unwrap();
    assert_eq!(empty_report.final_snapshot, "e3-empty");
    let mut after_empty_mos = dst_engine.open_read_objects(&cx).unwrap();
    let (after_empty_root, after_empty_objset) =
        raw_dataset_objectset(&cx, &mut after_empty_mos, &dst_devs[0], &vault_dst, None);
    assert!(
        after_empty_root.birth() > before_empty_root.birth(),
        "even an empty raw stream must publish its ObjectSet authentication metadata"
    );
    assert_eq!(
        StreamMetaDnode::from_dnode(&after_empty_objset.meta).unwrap(),
        keydata_e3.meta_dnode
    );
    assert_eq!(
        after_empty_objset.portable_mac(),
        Some(keydata_e3.portable_mac)
    );
    assert_eq!(after_empty_objset.local_mac(), Some([0; 32]));
    assert_eq!(after_empty_objset.flags & 1, 0);
    assert_eq!(&dsl_block_feature_counts(&cx, &dst_engine)[..2], &[4, 4]);

    // 4. Verify locked behavior, keyless scrub, and exact keyed decryption + MAC verification!
    let fresh_dst: Vec<_> = dst_devs
        .iter()
        .map(FaultableMemberDevice::fresh_from_durable)
        .collect();
    let mut dst_mos = open_mos(
        &cx,
        &fresh_dst,
        dst_built.pool_guid,
        tok_e3.published_slot(),
    );
    let (_, reopened_os) =
        raw_dataset_objectset(&cx, &mut dst_mos, &fresh_dst[0], &vault_dst, None);
    assert_eq!(
        StreamMetaDnode::from_dnode(&reopened_os.meta).unwrap(),
        keydata_e3.meta_dnode
    );
    assert_eq!(reopened_os.portable_mac(), Some(keydata_e3.portable_mac));
    assert_eq!(reopened_os.local_mac(), Some([0; 32]));
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
    assert_eq!(
        dst_mos
            .zpl(&cx, &vault_dst)
            .unwrap()
            .getxattr(&cx, sec_obj, "user.raw-spill")
            .unwrap(),
        Some(secret_xattr)
    );
    {
        let ds_row = dst_mos
            .datasets(&cx)
            .unwrap()
            .into_iter()
            .find(|d| d.components == vault_dst)
            .unwrap();
        let head_dn = dst_mos.object(&cx, ds_row.head_object).unwrap();
        let snapshot = head_dn.order().u64(head_dn.bonus(), 8).unwrap();
        assert_received_feature_owners(&cx, &mut dst_mos, ds_row.head_object, [true, true]);
        assert_received_feature_owners(&cx, &mut dst_mos, snapshot, [true, true]);
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
        Some(tok_e3.published_slot()),
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

#[test]
#[allow(clippy::too_many_lines)]
fn received_dataset_sets_used_breakdown_flag_and_tracks_head_and_snap() {
    let cx = Cx::for_testing();
    let ts = Timestamp {
        seconds: 1_735_007_000,
        nanos: 0,
    };
    let src_built = build_clean_zfs_pool(&send_recv_pool_spec(32 * 1024 * 1024));
    let dst_built = build_clean_zfs_pool(&send_recv_pool_spec(32 * 1024 * 1024));
    let src_dev = FaultableMemberDevice::new(src_built.members[0].clone());
    let dst_dev = FaultableMemberDevice::new(dst_built.members[0].clone());
    let mut src_engine = open_engine_on_devices(
        &cx,
        std::slice::from_ref(&src_dev),
        default_write_opts(src_built.pool_guid, src_built.initial_slot),
    )
    .expect("open source pool");
    let mut dst_engine = open_engine_on_devices(
        &cx,
        std::slice::from_ref(&dst_dev),
        default_write_opts(dst_built.pool_guid, dst_built.initial_slot),
    )
    .expect("open destination pool");

    let src_ds = vec![b"data".to_vec()];
    let dst_ds = vec![b"data".to_vec(), b"replica".to_vec()];

    let (fid, _) = src_engine
        .create_file(
            &cx,
            &src_ds,
            2,
            b"payload.bin",
            0o644,
            0,
            0,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .expect("create payload.bin");
    let payload: Vec<u8> = (0_u32..4096)
        .flat_map(|i| i.wrapping_mul(2_654_435_761).to_le_bytes())
        .collect();
    src_engine
        .write_file_data(
            &cx,
            &src_ds,
            fid,
            0,
            &payload,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .expect("write payload.bin");
    src_engine
        .create_snapshot(&cx, &src_ds, b"s1", ts)
        .into_result()
        .expect("snapshot data@s1");

    let mut stream = Vec::new();
    let src_mos = open_mos(
        &cx,
        std::slice::from_ref(&src_dev),
        src_built.pool_guid,
        src_engine.committed_slot(),
    );
    send_stream(
        &cx,
        &src_mos,
        &ZfsSendRequest::full(src_ds, b"s1".to_vec()),
        &mut stream,
    )
    .expect("send full stream");

    dst_engine
        .receive_stream(
            &cx,
            &ZfsRecvRequest::new(dst_ds.clone()),
            &mut Cursor::new(&stream),
        )
        .into_result()
        .expect("receive full stream into data/replica");

    let read_replica_breakdown = |eng: &ZfsTransactionEngine| -> (u64, u64, u64, u64) {
        let mut mos = eng.open_read_objects(&cx).unwrap();
        let row = mos
            .datasets(&cx)
            .unwrap()
            .into_iter()
            .find(|r| r.components == dst_ds)
            .expect("find received dataset");
        let dn = mos.object(&cx, row.directory_object).unwrap();
        let ord = dn.order();
        let b = dn.bonus();
        (
            ord.u64(b, 40).unwrap(),
            ord.u64(b, 96).unwrap(),
            ord.u64(b, 104).unwrap(),
            ord.u64(b, 112).unwrap(),
        )
    };

    let (used_after_recv, flags_after_recv, head_after_recv, snap_after_recv) =
        read_replica_breakdown(&dst_engine);
    assert_ne!(
        flags_after_recv & 0x1,
        0,
        "received dataset dsl_dir must set DD_FLAG_USED_BREAKDOWN"
    );
    assert!(used_after_recv > 0);
    assert_eq!(
        head_after_recv, used_after_recv,
        "immediately after full receive promotion, DD_USED_HEAD must equal dd_used_bytes"
    );
    assert_eq!(
        snap_after_recv, 0,
        "immediately after full receive promotion, DD_USED_SNAP must be 0"
    );

    // Deleting the received file immediately after full receive must shrink
    // DD_USED_HEAD without underflow and shift its retained blocks into DD_USED_SNAP.
    let dst_root = {
        let mut mos = dst_engine.open_read_objects(&cx).unwrap();
        mos.zpl(&cx, &dst_ds).unwrap().resolve(&cx, b"/").unwrap()
    };
    dst_engine
        .unlink_entry(&cx, &dst_ds, dst_root, b"payload.bin", false, ts)
        .into_result()
        .expect("unlink payload.bin immediately after full receive");

    let (used_post_unlink, flags_post_unlink, head_post_unlink, snap_post_unlink) =
        read_replica_breakdown(&dst_engine);
    assert_ne!(flags_post_unlink & 0x1, 0);
    assert!(
        head_post_unlink < head_after_recv,
        "unlinking received payload must reduce DD_USED_HEAD"
    );
    assert!(
        snap_post_unlink > 0,
        "retiring received snapshot blocks must credit DD_USED_SNAP"
    );
    assert_eq!(
        head_post_unlink + snap_post_unlink,
        used_post_unlink,
        "received dataset DD_USED_HEAD + DD_USED_SNAP must equal dd_used_bytes"
    );

    // Now send an incremental @s1 -> @s2 where payload.bin is replaced by a larger file,
    // force-receive onto the diverged replica, and verify DD_USED_HEAD/DD_USED_SNAP
    // reconcile cleanly AND destroying @s1 drains DD_USED_SNAP to exactly 0!
    src_engine
        .unlink_entry(&cx, &src_ds, 2, b"payload.bin", false, ts)
        .into_result()
        .expect("unlink payload.bin in source for s2");
    let (fid2, _) = src_engine
        .create_file(
            &cx,
            &src_ds,
            2,
            b"v2.bin",
            0o644,
            0,
            0,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .expect("create v2.bin");
    src_engine
        .write_file_data(
            &cx,
            &src_ds,
            fid2,
            0,
            &vec![0x7C; 24 * 1024],
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .expect("write v2.bin");
    src_engine
        .create_snapshot(&cx, &src_ds, b"s2", ts)
        .into_result()
        .expect("snapshot data@s2");

    let mut incr_stream = Vec::new();
    let src_mos2 = open_mos(
        &cx,
        std::slice::from_ref(&src_dev),
        src_built.pool_guid,
        src_engine.committed_slot(),
    );
    send_stream(
        &cx,
        &src_mos2,
        &ZfsSendRequest::incremental(
            src_ds,
            ZfsSendFrom::Snapshot(b"s1".to_vec()),
            b"s2".to_vec(),
        ),
        &mut incr_stream,
    )
    .expect("send incremental s1 -> s2");

    let mut force_req = ZfsRecvRequest::new(dst_ds.clone());
    force_req.force = true;
    dst_engine
        .receive_stream(&cx, &force_req, &mut Cursor::new(&incr_stream))
        .into_result()
        .expect("forced incremental receive s1 -> s2");

    let (used_after_s2, _, head_after_s2, snap_after_s2) = read_replica_breakdown(&dst_engine);
    assert!(head_after_s2 > 0 && snap_after_s2 > 0);
    assert_eq!(
        head_after_s2 + snap_after_s2,
        used_after_s2,
        "after incremental receive, DD_USED_HEAD + DD_USED_SNAP must equal dd_used_bytes"
    );

    dst_engine
        .destroy_snapshot(&cx, &dst_ds, b"s1", false)
        .into_result()
        .expect("destroy @s1 after incremental receive");
    let (used_no_s1, _, head_no_s1, snap_no_s1) = read_replica_breakdown(&dst_engine);
    assert_eq!(
        snap_no_s1, 0,
        "destroying @s1 must drain DD_USED_SNAP to exactly 0"
    );
    assert_eq!(head_no_s1, used_no_s1);

    assert_pool_scrub_and_allocation_clean(
        &cx,
        std::slice::from_ref(&dst_dev),
        dst_built.pool_guid,
        Some(dst_engine.committed_slot()),
    );
}
