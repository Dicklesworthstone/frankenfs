//! Mounted privilege removal must publish with the data it makes unprivileged.

use super::*;

#[derive(Debug, Clone, Copy)]
enum DataMutation {
    Write,
    Truncate,
    OpenTruncate,
    PunchHole,
    ZeroRange,
    ZeroKeepSize,
    Copy,
}

const DATA_MUTATIONS: [DataMutation; 7] = [
    DataMutation::Write,
    DataMutation::Truncate,
    DataMutation::OpenTruncate,
    DataMutation::PunchHole,
    DataMutation::ZeroRange,
    DataMutation::ZeroKeepSize,
    DataMutation::Copy,
];

impl DataMutation {
    fn apply(self, fs: &ZfsFs, cx: &Cx, ino: InodeNumber, source: InodeNumber) -> Result<()> {
        let mut scope = RequestScope::empty();
        match self {
            Self::Write => fs
                .write(cx, &mut scope, ino, 4, b"changed")
                .map(|written| assert_eq!(written, 7)),
            Self::Truncate => fs
                .setattr(
                    cx,
                    &mut scope,
                    ino,
                    &SetAttrRequest {
                        size: Some(5),
                        ..SetAttrRequest::default()
                    },
                )
                .map(|attr| assert_eq!(attr.size, 5)),
            Self::OpenTruncate => {
                let (handle, _) = fs.open(cx, &mut scope, ino, libc::O_WRONLY | libc::O_TRUNC)?;
                fs.release(
                    cx,
                    &mut scope,
                    ReleaseRequest {
                        ino,
                        fh: handle,
                        flags: libc::O_WRONLY | libc::O_TRUNC,
                        lock_owner: None,
                        flush: false,
                    },
                )
            }
            Self::PunchHole => fs.fallocate(
                cx,
                &mut scope,
                ino,
                4,
                4,
                libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
            ),
            Self::ZeroRange | Self::ZeroKeepSize => {
                let size = fs.getattr(cx, &mut scope, ino)?.size;
                let flags = libc::FALLOC_FL_ZERO_RANGE
                    | if matches!(self, Self::ZeroKeepSize) {
                        libc::FALLOC_FL_KEEP_SIZE
                    } else {
                        0
                    };
                fs.fallocate(cx, &mut scope, ino, size - 4, 8, flags)
            }
            Self::Copy => fs
                .copy_file_range(cx, &mut scope, source, 0, ino, 2, 7)
                .map(|copied| assert_eq!(copied, 7)),
        }
    }

    fn expected(self, original: &[u8]) -> Vec<u8> {
        let mut bytes = original.to_vec();
        match self {
            Self::Write => bytes[4..11].copy_from_slice(b"changed"),
            Self::Truncate => bytes.truncate(5),
            Self::OpenTruncate => bytes.clear(),
            Self::PunchHole => bytes[4..8].fill(0),
            Self::ZeroRange => {
                let size = bytes.len();
                bytes.resize(size + 4, 0);
                bytes[size - 4..].fill(0);
            }
            Self::ZeroKeepSize => {
                let size = bytes.len();
                bytes[size - 4..].fill(0);
            }
            Self::Copy => bytes[2..9].fill(0x5A),
        }
        bytes
    }
}

fn durable_head(cx: &Cx, devices: &[FaultableMemberDevice]) -> ffs_zfs::Zpl {
    let leaves = devices
        .iter()
        .map(|device| {
            let fresh = device.fresh_from_durable();
            let len = fresh.len_bytes();
            Leaf::from_device(cx, Box::new(fresh), 0, len).unwrap()
        })
        .collect();
    let pool = Pool::from_leaves(leaves).unwrap();
    let mut objects = pool.import_objects(cx, Some(POOL_GUID)).unwrap();
    objects.zpl(cx, &[b"data".to_vec()]).unwrap()
}

fn native_acl_snapshot(cx: &Cx, devices: &[FaultableMemberDevice]) -> (Vec<u8>, Option<Vec<u8>>) {
    let device = devices[0].fresh_from_durable();
    let len = device.len_bytes();
    let leaf = Leaf::from_device(cx, Box::new(device), 0, len).unwrap();
    let mut objects = leaf.import_objects(cx, Some(POOL_GUID)).unwrap();
    let head = objects.object(cx, 18).unwrap();
    let root = BlockPointer::parse(&head.bonus()[128..256], head.order()).unwrap();
    let image = devices[0].durable_snapshot();
    let read_block = |pointer: &BlockPointer| {
        let dva = pointer.regular_dvas().unwrap()[0];
        let start = usize::try_from(DATA_OFFSET + dva.offset).unwrap();
        ffs_ondisk::zfs::decompress(
            &image[start..start + pointer.physical_bytes()],
            pointer.compression(),
            pointer.logical_bytes(),
        )
        .unwrap()
    };
    let objectset = ObjectSet::parse(&read_block(&root), root.payload_order()).unwrap();
    assert_eq!(objectset.meta.levels(), 1);
    let table_pointer = &objectset.meta.pointers()[0];
    let table = read_block(table_pointer);
    let order = table_pointer.payload_order();
    let owner = ffs_ondisk::zfs_dmu::dnode_at(&table, 4, order)
        .unwrap()
        .unwrap();
    let acl = if owner.bonus_type() == 17 {
        owner.bonus()[176..264].to_vec()
    } else {
        assert_eq!(owner.bonus_type(), 44);
        let spill = read_block(owner.spill().unwrap());
        // This fixture stores the complete ZPL_ZNODE_ACL in SA layout 5.
        assert_eq!(
            u16::from_le_bytes(spill[4..6].try_into().unwrap()) & 0x03ff,
            5
        );
        spill[8..96].to_vec()
    };
    let external = owner.order().u64(&acl, 0).unwrap();
    let external_bytes = if external == 0 {
        None
    } else {
        let node = ffs_ondisk::zfs_dmu::dnode_at(&table, usize::try_from(external).unwrap(), order)
            .unwrap()
            .unwrap();
        assert_eq!(node.object_type(), 33);
        assert_eq!(node.levels(), 1);
        Some(read_block(&node.pointers()[0]))
    };
    (acl, external_bytes)
}

#[test]
fn mounted_setid_data_mutations_clear_privileges_and_survive_native_reopen() {
    let cx = Cx::for_testing();
    for (zpl_version, mirror_width) in [(4, 1), (5, 2)] {
        for (mode, cleared_mode) in [
            (0o4755, 0o755),
            (0o2755, 0o755),
            (0o6755, 0o755),
            (0o6666, 0o2666),
        ] {
            let built = build_clean_zfs_pool(&PoolFixtureSpec {
                zpl_version,
                mirror_width,
                hello_mode: mode,
                deadlist_mode: DeadlistMode::NativeDeadlist,
                ..PoolFixtureSpec::default()
            });
            for operation in DATA_MUTATIONS {
                let devices: Vec<_> = built
                    .members
                    .iter()
                    .cloned()
                    .map(FaultableMemberDevice::new)
                    .collect();
                let engine = open_engine_on_devices(
                    &cx,
                    &devices,
                    default_write_opts(built.pool_guid, built.initial_slot),
                )
                .unwrap();
                let fs = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
                let file = lookup(&fs, &cx, ROOT, "hello.txt");
                let source = lookup(&fs, &cx, ROOT, "keep.bin");
                assert_eq!(file.perm, mode);
                let before_empty = io_counts(&devices);
                assert_eq!(
                    fs.write(&cx, &mut RequestScope::empty(), file.ino, 0, b"")
                        .unwrap(),
                    0
                );
                assert_eq!(io_counts(&devices), before_empty);
                assert_eq!(lookup(&fs, &cx, ROOT, "hello.txt").perm, mode);

                if matches!(
                    operation,
                    DataMutation::PunchHole | DataMutation::ZeroKeepSize
                ) {
                    let flags = libc::FALLOC_FL_KEEP_SIZE
                        | if matches!(operation, DataMutation::PunchHole) {
                            libc::FALLOC_FL_PUNCH_HOLE
                        } else {
                            libc::FALLOC_FL_ZERO_RANGE
                        };
                    fs.fallocate(
                        &cx,
                        &mut RequestScope::empty(),
                        file.ino,
                        file.size + 32,
                        16,
                        flags,
                    )
                    .unwrap();
                    // A range wholly beyond EOF with KEEP_SIZE exposes no new data.
                    assert_eq!(lookup(&fs, &cx, ROOT, "hello.txt").perm, mode);
                    assert_eq!(read(&fs, &cx, file.ino), built.snap_hello_expected);
                }

                operation.apply(&fs, &cx, file.ino, source.ino).unwrap();
                let expected = operation.expected(&built.snap_hello_expected);
                let current = lookup(&fs, &cx, ROOT, "hello.txt");
                assert_eq!(
                    (current.perm, current.size),
                    (cleared_mode, expected.len() as u64),
                    "{operation:?}, mode {mode:o}, ZPL {zpl_version}"
                );
                assert_eq!(read(&fs, &cx, file.ino), expected);
                assert_eq!(current.generation, file.generation);
                assert_eq!((current.uid, current.gid), (file.uid, file.gid));
                assert!(fs.last_durable_token().unwrap().is_some());
                drop(fs);
                for device in &devices {
                    device.state.lock().unwrap().crash_drop_unsynced();
                }
                let mut reopened = durable_head(&cx, &devices);
                let metadata = reopened.stat(&cx, 4).unwrap().0;
                assert_eq!(metadata.mode & 0o7777, u64::from(cleared_mode));
                assert_eq!(metadata.size, expected.len() as u64);
                assert_eq!(reopened.read(&cx, 4, 0, 8192).unwrap(), expected);
            }
        }
    }
}

#[test]
fn mounted_setid_clearing_preserves_native_acl_bytes_and_default_permission_policy() {
    let cx = Cx::for_testing();
    for (zpl_version, auxiliary) in [
        (4, AuxiliaryOwnership::EmbeddedAcl),
        (4, AuxiliaryOwnership::ExternalAcl),
        (5, AuxiliaryOwnership::EmbeddedAcl),
        (5, AuxiliaryOwnership::ExternalAcl),
    ] {
        let (engine, devices) = writer_fixture(
            &cx,
            &PoolFixtureSpec {
                zpl_version,
                hello_mode: 0o6666,
                auxiliary_ownership: Some((4, auxiliary)),
                deadlist_mode: DeadlistMode::NativeDeadlist,
                ..PoolFixtureSpec::default()
            },
        );
        let original_acl = native_acl_snapshot(&cx, &devices);
        assert_eq!(
            original_acl.1.is_some(),
            auxiliary == AuxiliaryOwnership::ExternalAcl
        );
        let original_flags = durable_head(&cx, &devices).stat(&cx, 4).unwrap().0.flags;
        let fs = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
        let mut scope = RequestScope::empty();
        let file = lookup(&fs, &cx, ROOT, "hello.txt");
        let original = read(&fs, &cx, file.ino);
        let before = io_counts(&devices);
        for attrs in [
            SetAttrRequest {
                mode: Some(0o664),
                size: Some(0),
                ..SetAttrRequest::default()
            },
            SetAttrRequest {
                mode: Some(0o1666),
                size: Some(0),
                ..SetAttrRequest::default()
            },
            SetAttrRequest {
                mode: Some(0o666),
                uid: Some(file.uid + 1),
                size: Some(0),
                ..SetAttrRequest::default()
            },
            SetAttrRequest {
                mode: Some(0o666),
                gid: Some(file.gid + 1),
                size: Some(0),
                ..SetAttrRequest::default()
            },
        ] {
            assert_eq!(
                fs.setattr(&cx, &mut scope, file.ino, &attrs)
                    .unwrap_err()
                    .to_errno(),
                libc::EOPNOTSUPP
            );
        }
        assert_eq!(io_counts(&devices), before);
        assert_eq!(read(&fs, &cx, file.ino), original);
        assert_eq!(lookup(&fs, &cx, ROOT, "hello.txt").perm, 0o6666);

        // FUSE's group-member rule drops SUID while retaining non-executable SGID.
        let attr = fs
            .setattr(
                &cx,
                &mut scope,
                file.ino,
                &SetAttrRequest {
                    mode: Some(0o2666),
                    ..SetAttrRequest::default()
                },
            )
            .unwrap();
        assert_eq!(attr.perm, 0o2666);
        assert_eq!(native_acl_snapshot(&cx, &devices), original_acl);
        // A caller outside the file's group also drops non-executable SGID.
        let attr = fs
            .setattr(
                &cx,
                &mut scope,
                file.ino,
                &SetAttrRequest {
                    mode: Some(0o666),
                    size: Some(8),
                    ..SetAttrRequest::default()
                },
            )
            .unwrap();
        assert_eq!((attr.perm, attr.size), (0o666, 8));
        assert_eq!(read(&fs, &cx, file.ino), &original[..8]);
        assert_eq!(native_acl_snapshot(&cx, &devices), original_acl);
        let before_restore = io_counts(&devices);
        assert_eq!(
            fs.setattr(
                &cx,
                &mut scope,
                file.ino,
                &SetAttrRequest {
                    mode: Some(0o2666),
                    ..SetAttrRequest::default()
                }
            )
            .unwrap_err()
            .to_errno(),
            libc::EOPNOTSUPP
        );
        if auxiliary == AuxiliaryOwnership::ExternalAcl {
            // External ACL ownership is retained, so final reclamation still refuses it.
            assert_eq!(
                fs.unlink(&cx, &mut scope, ROOT, OsStr::new("hello.txt"))
                    .unwrap_err()
                    .to_errno(),
                libc::EOPNOTSUPP
            );
        }
        assert_eq!(io_counts(&devices), before_restore);
        drop(fs);
        let mut reopened = durable_head(&cx, &devices);
        let metadata = reopened.stat(&cx, 4).unwrap().0;
        assert_eq!((metadata.mode & 0o7777, metadata.size), (0o666, 8));
        assert_eq!(metadata.flags, original_flags);
        assert_eq!(reopened.read(&cx, 4, 0, 8192).unwrap(), &original[..8]);
    }
}

#[test]
fn mounted_setid_data_mutations_still_refuse_native_capabilities_without_writes() {
    let cx = Cx::for_testing();
    for zpl_version in [4, 5] {
        let (engine, devices) = writer_fixture(
            &cx,
            &PoolFixtureSpec {
                zpl_version,
                hello_mode: 0o6755,
                auxiliary_ownership: Some((4, AuxiliaryOwnership::CapabilityXattr)),
                deadlist_mode: DeadlistMode::NativeDeadlist,
                ..PoolFixtureSpec::default()
            },
        );
        let fs = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
        let file = lookup(&fs, &cx, ROOT, "hello.txt");
        let source = lookup(&fs, &cx, ROOT, "keep.bin");
        let original = read(&fs, &cx, file.ino);
        let mut scope = RequestScope::empty();
        let (handle, _) = fs.open(&cx, &mut scope, file.ino, libc::O_RDONLY).unwrap();
        release(&fs, &cx, file.ino, handle);
        let before = io_counts(&devices);
        for operation in DATA_MUTATIONS {
            assert_eq!(
                operation
                    .apply(&fs, &cx, file.ino, source.ino)
                    .unwrap_err()
                    .to_errno(),
                libc::EOPNOTSUPP,
                "{operation:?}"
            );
        }
        assert_eq!(
            fs.setattr(
                &cx,
                &mut scope,
                file.ino,
                &SetAttrRequest {
                    mode: Some(0o755),
                    size: Some(0),
                    ..SetAttrRequest::default()
                }
            )
            .unwrap_err()
            .to_errno(),
            libc::EOPNOTSUPP
        );
        assert_eq!(io_counts(&devices), before);
        assert_eq!(lookup(&fs, &cx, ROOT, "hello.txt").perm, 0o6755);
        assert_eq!(read(&fs, &cx, file.ino), original);
        assert!(fs.last_durable_token().unwrap().is_none());
        let (next_handle, _) = fs.open(&cx, &mut scope, file.ino, libc::O_RDONLY).unwrap();
        assert_eq!(next_handle, handle + 1);
        release(&fs, &cx, file.ino, next_handle);
    }
}

#[test]
fn explicit_native_editors_preserve_setid_and_compound_truncate_honors_clear_request() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let timestamp = Timestamp {
        seconds: 1_715_000_000,
        nanos: 0,
    };
    for zpl_version in [4, 5] {
        let (mut engine, devices) = writer_fixture(
            &cx,
            &PoolFixtureSpec {
                zpl_version,
                hello_mode: 0o6755,
                deadlist_mode: DeadlistMode::NativeDeadlist,
                ..PoolFixtureSpec::default()
            },
        );
        engine
            .write_file_data(
                &cx,
                &dataset,
                4,
                0,
                b"native edit",
                timestamp,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .unwrap();
        assert_eq!(
            durable_head(&cx, &devices).stat(&cx, 4).unwrap().0.mode & 0o7777,
            0o6755
        );
        engine
            .edit_file_range(
                &cx,
                &dataset,
                4,
                4,
                4,
                ffs_zfs::ZfsFileRangeOperation::PunchHole,
                timestamp,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .unwrap();
        engine
            .truncate_file(&cx, &dataset, 4, 16, timestamp, ZfsDataChecksum::Fletcher4)
            .into_result()
            .unwrap();
        assert_eq!(
            durable_head(&cx, &devices).stat(&cx, 4).unwrap().0.mode & 0o7777,
            0o6755
        );
        engine
            .set_posix_attributes(
                &cx,
                &dataset,
                4,
                &ffs_zfs::ZfsPosixSetAttr {
                    mode: Some(0o6755),
                    size: Some(5),
                    uid: Some(2000),
                    gid: Some(2001),
                    clear_suid_sgid: true,
                    ..ffs_zfs::ZfsPosixSetAttr::default()
                },
                timestamp,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .unwrap();
        let metadata = durable_head(&cx, &devices).stat(&cx, 4).unwrap().0;
        assert_eq!((metadata.mode & 0o7777, metadata.size), (0o755, 5));
        assert_eq!((metadata.uid, metadata.gid), (2000, 2001));
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn mounted_setid_persistence_cuts_never_publish_changed_data_with_old_privileges() {
    let cx = Cx::for_testing();
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        mirror_width: 2,
        hello_mode: 0o6755,
        with_sa_spill: true,
        deadlist_mode: DeadlistMode::NativeDeadlist,
        ..PoolFixtureSpec::default()
    });
    for operation in [
        DataMutation::Write,
        DataMutation::Truncate,
        DataMutation::PunchHole,
    ] {
        let probe_devices: Vec<_> = built
            .members
            .iter()
            .cloned()
            .map(FaultableMemberDevice::new)
            .collect();
        let mut engine = open_engine_on_devices(
            &cx,
            &probe_devices,
            default_write_opts(built.pool_guid, built.initial_slot),
        )
        .unwrap();
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&recorded);
        engine.with_fault_hook(move |event| {
            captured.lock().unwrap().push(event.clone());
            Ok(())
        });
        let fs = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
        let file = lookup(&fs, &cx, ROOT, "hello.txt");
        let source = lookup(&fs, &cx, ROOT, "keep.bin");
        operation.apply(&fs, &cx, file.ino, source.ino).unwrap();
        let events = recorded.lock().unwrap().clone();
        let first_publication = events
            .iter()
            .find(|event| matches!(event.stage, ZfsPersistenceStage::UberblockWrite { .. }))
            .unwrap()
            .seq;
        let durable = events
            .iter()
            .find(|event| event.stage == ZfsPersistenceStage::BeforeAcknowledge)
            .unwrap()
            .seq;
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
                let fs = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
                let file = lookup(&fs, &cx, ROOT, "hello.txt");
                let source = lookup(&fs, &cx, ROOT, "keep.bin");
                let result = operation.apply(&fs, &cx, file.ino, source.ino);
                assert_eq!(
                    result.is_ok(),
                    sequence >= durable,
                    "{operation:?}: {:?}",
                    cut.stage
                );
                drop(fs);
                for device in &devices {
                    let mut media = device.state.lock().unwrap();
                    if reorder {
                        media.crash_reorder_and_drop_half_unsynced();
                    } else {
                        media.crash_drop_unsynced();
                    }
                }
                let mut reopened = durable_head(&cx, &devices);
                let metadata = reopened.stat(&cx, 4).unwrap().0;
                let bytes = reopened.read(&cx, 4, 0, 8192).unwrap();
                let committed = metadata.mode & 0o7777 == 0o755;
                if committed {
                    assert_eq!(bytes, expected, "{operation:?}: {:?}", cut.stage);
                    assert_eq!(metadata.size, expected.len() as u64);
                } else {
                    assert_eq!(metadata.mode & 0o7777, 0o6755);
                    assert_eq!(
                        bytes, built.snap_hello_expected,
                        "{operation:?}: {:?}",
                        cut.stage
                    );
                    assert_eq!(metadata.size, built.snap_hello_expected.len() as u64);
                }
                if sequence <= first_publication {
                    assert!(!committed);
                }
                if sequence >= durable {
                    assert!(committed);
                }
                let mut snapshot = reopened.open_snapshot(&cx, b"before").unwrap();
                assert_eq!(snapshot.stat(&cx, 4).unwrap().0.mode & 0o7777, 0o6755);
                assert_eq!(
                    snapshot.read(&cx, 4, 0, 8192).unwrap(),
                    built.snap_hello_expected
                );
                assert_pool_scrub_and_allocation_clean(&cx, &devices, POOL_GUID, None);
            }
        }
    }
}

fn sa_capability_fixture(mode: u16, retained: &[u8]) -> PoolFixtureSpec {
    // Linux VFS_CAP_REVISION_2 with effective CAP_NET_RAW. The fixture writes
    // this reserved key directly; the public xattr setter must never admit it.
    let mut capability = vec![0_u8; 20];
    capability[..4].copy_from_slice(&0x0200_0001_u32.to_le_bytes());
    capability[4..8].copy_from_slice(&(1_u32 << 13).to_le_bytes());
    PoolFixtureSpec {
        hello_mode: mode,
        hello_sa_xattrs: BTreeMap::from([
            ("security.capability".to_owned(), capability),
            ("user.retained".to_owned(), retained.to_vec()),
        ]),
        auxiliary_ownership: Some((4, AuxiliaryOwnership::EmbeddedAcl)),
        deadlist_mode: DeadlistMode::NativeDeadlist,
        user_accounting: true,
        ..PoolFixtureSpec::default()
    }
}

/// Read the native owner's bonus and spill from durable physical bytes. This
/// deliberately avoids the filesystem's capability-admission helper: a stale
/// capability must not become invisible merely because that helper is wrong.
fn native_sa_owner_bytes(
    cx: &Cx,
    engine: &ZfsTransactionEngine,
    device: &FaultableMemberDevice,
    dataset_object: u64,
) -> (Dnode, Vec<u8>) {
    let mut mos = engine.open_read_objects(cx).unwrap();
    let dataset = mos.object(cx, dataset_object).unwrap();
    let root = BlockPointer::parse(&dataset.bonus()[128..256], dataset.order()).unwrap();
    let image = device.durable_snapshot();
    let read = |pointer: &BlockPointer| {
        let dva = pointer.regular_dvas().unwrap()[0];
        let start = usize::try_from(DATA_OFFSET + dva.offset).unwrap();
        ffs_ondisk::zfs::decompress(
            &image[start..start + pointer.physical_bytes()],
            pointer.compression(),
            pointer.logical_bytes(),
        )
        .unwrap()
    };
    let objectset = ObjectSet::parse(&read(&root), root.payload_order()).unwrap();
    assert_eq!(objectset.meta.levels(), 1);
    let pointer = &objectset.meta.pointers()[0];
    let owner = ffs_ondisk::zfs_dmu::dnode_at(&read(pointer), 4, pointer.payload_order())
        .unwrap()
        .unwrap();
    assert_eq!(owner.bonus_type(), 44);
    let mut bytes = owner.bonus().to_vec();
    if let Some(spill) = owner.spill() {
        bytes.extend_from_slice(&read(spill));
    }
    (owner, bytes)
}

fn assert_native_sa_capability(bytes: &[u8], expected: bool) {
    let key = b"security.capability";
    assert_eq!(
        bytes.windows(key.len()).any(|window| window == key),
        expected,
        "the native SA bytes must agree with the published privilege state"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn sa_capability_data_mutations_clear_privileges_with_data_and_preserve_snapshots() {
    let cx = Cx::for_testing();
    for (ashift, mirror_width, retained) in [
        (9, 1, vec![0xD5; 16]),
        (12, 2, vec![0xD5; 2048]),
    ] {
        // Capability-only executables are common; clearing must not depend on
        // whether the inode also happens to carry set-ID permission bits.
        for mode in [0o755, 0o6755] {
            let built = build_clean_zfs_pool(&PoolFixtureSpec {
                ashift,
                mirror_width,
                ..sa_capability_fixture(mode, &retained)
            });
            for operation in DATA_MUTATIONS {
                let devices: Vec<_> = built
                    .members
                    .iter()
                    .cloned()
                    .map(FaultableMemberDevice::new)
                    .collect();
                let engine = open_engine_on_devices(
                    &cx,
                    &devices,
                    default_write_opts(built.pool_guid, built.initial_slot),
                )
                .unwrap();
                let (original_node, original_raw) =
                    native_sa_owner_bytes(&cx, &engine, &devices[0], 18);
                assert_native_sa_capability(&original_raw, true);
                // Fixture layout 11 stores XATTR(8), ZNODE_ACL(88), PROJID(8)
                // before DXATTR in the spill. Preserve the complete ACL bytes.
                let acl_start = original_node.bonus().len() + 16;
                let original_acl = original_raw[acl_start..acl_start + 88].to_vec();
                let fs = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
                let file = lookup(&fs, &cx, ROOT, "hello.txt");
                let source = lookup(&fs, &cx, ROOT, "keep.bin");
                let no_op_counts = io_counts(&devices);
                assert_eq!(
                    fs.write(&cx, &mut RequestScope::empty(), file.ino, 0, b"")
                        .unwrap(),
                    0
                );
                assert_eq!(io_counts(&devices), no_op_counts);
                operation.apply(&fs, &cx, file.ino, source.ino).unwrap();
                let expected = operation.expected(&built.snap_hello_expected);
                assert_eq!(read(&fs, &cx, file.ino), expected);
                assert_eq!(
                    fs.getxattr(&cx, file.ino, "user.retained").unwrap(),
                    Some(retained.clone())
                );
                let token = fs.last_durable_token().unwrap().unwrap();
                drop(fs);
                let fresh: Vec<_> = devices
                    .iter()
                    .map(FaultableMemberDevice::fresh_from_durable)
                    .collect();
                let reopened = open_engine_on_devices(
                    &cx,
                    &fresh,
                    default_write_opts(built.pool_guid, token.published_slot()),
                )
                .unwrap();
                let (_, raw) = native_sa_owner_bytes(&cx, &reopened, &fresh[0], 18);
                assert_native_sa_capability(&raw, false);
                assert!(raw.windows(88).any(|window| window == original_acl));
                assert_eq!(
                    native_sa_owner_bytes(&cx, &reopened, &fresh[0], 21).1,
                    original_raw,
                    "snapshot SA capability, ACL and user xattrs stay byte-for-byte intact"
                );
                let mut head = file_range_head(&cx, &reopened);
                assert_eq!(head.read(&cx, 4, 0, expected.len() + 1).unwrap(), expected);
                assert_eq!(head.stat(&cx, 4).unwrap().0.mode & 0o7777, 0o755);
                assert_eq!(head.getxattr(&cx, 4, "user.retained").unwrap(), Some(retained.clone()));
                let mut snapshot = head.open_snapshot(&cx, b"before").unwrap();
                assert_eq!(
                    snapshot.read(&cx, 4, 0, built.snap_hello_expected.len()).unwrap(),
                    built.snap_hello_expected
                );
                assert_eq!(snapshot.stat(&cx, 4).unwrap().0.mode & 0o7777, u64::from(mode));
                assert_eq!(snapshot.getxattr(&cx, 4, "user.retained").unwrap(), Some(retained.clone()));
                assert_pool_scrub_and_allocation_clean(
                    &cx,
                    &fresh,
                    built.pool_guid,
                    Some(token.published_slot()),
                );
            }
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn sa_capability_explicit_removal_preserves_unrelated_metadata_and_is_idempotent() {
    let cx = Cx::for_testing();
    let retained = b"unrelated value";
    let (engine, devices) = writer_fixture(&cx, &sa_capability_fixture(0o6755, retained));
    let (original_node, original_raw) = native_sa_owner_bytes(&cx, &engine, &devices[0], 18);
    let acl_start = original_node.bonus().len() + 16;
    let original_acl = original_raw[acl_start..acl_start + 88].to_vec();
    let fs = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
    let file = lookup(&fs, &cx, ROOT, "hello.txt");
    let original_data = read(&fs, &cx, file.ino);
    let mut scope = RequestScope::empty();
    for name in ["security.capability", "user.security.capability"] {
        let before = io_counts(&devices);
        assert!(fs.setxattr(
            &cx,
            &mut scope,
            file.ino,
            name,
            b"forged",
            ffs_core::XattrSetMode::Create,
        ).is_err());
        assert_eq!(io_counts(&devices), before);
    }
    assert!(fs.removexattr(&cx, &mut scope, file.ino, "security.capability").unwrap());
    assert_eq!(read(&fs, &cx, file.ino), original_data);
    assert_eq!(lookup(&fs, &cx, ROOT, "hello.txt").perm, 0o6755);
    assert_eq!(fs.getxattr(&cx, file.ino, "user.retained").unwrap(), Some(retained.to_vec()));
    let stable = io_counts(&devices);
    assert!(!fs.removexattr(&cx, &mut scope, file.ino, "security.capability").unwrap());
    assert_eq!(io_counts(&devices), stable);
    let token = fs.last_durable_token().unwrap().unwrap();
    drop(fs);
    let fresh: Vec<_> = devices.iter().map(FaultableMemberDevice::fresh_from_durable).collect();
    let reopened = open_engine_on_devices(
        &cx,
        &fresh,
        default_write_opts(POOL_GUID, token.published_slot()),
    ).unwrap();
    let (node, raw) = native_sa_owner_bytes(&cx, &reopened, &fresh[0], 18);
    assert_eq!(node.pointers(), original_node.pointers(), "preclear does not rewrite file data");
    assert_native_sa_capability(&raw, false);
    assert!(raw.windows(88).any(|window| window == original_acl));
    assert_eq!(native_sa_owner_bytes(&cx, &reopened, &fresh[0], 21).1, original_raw);
    assert_pool_scrub_and_allocation_clean(&cx, &fresh, POOL_GUID, Some(token.published_slot()));
}

#[test]
#[allow(clippy::too_many_lines)]
fn sa_capability_native_policy_distinguishes_noops_growth_and_owner_changes() {
    use ffs_zfs::{ZfsFileRangeOperation::PunchHole, ZfsPosixSetAttr};

    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let timestamp = Timestamp { seconds: 1_730_100_100, nanos: 27 };
    for owner_change in [false, true] {
        let (mut engine, devices) =
            writer_fixture(&cx, &sa_capability_fixture(0o6755, b"retained"));
        let (_, original_raw) = native_sa_owner_bytes(&cx, &engine, &devices[0], 18);
        let original_size = file_range_head(&cx, &engine).stat(&cx, 4).unwrap().0.size;
        // The explicit ordinary native API preserves its trusted-caller policy.
        engine.write_file_data(
            &cx, &dataset, 4, 0, b"same", timestamp, ZfsDataChecksum::Fletcher4,
        ).into_result().unwrap();
        engine.edit_file_range(
            &cx, &dataset, 4, 2, 1, PunchHole, timestamp, ZfsDataChecksum::Fletcher4,
        ).into_result().unwrap();
        engine.write_file_data_clearing_setid(
            &cx, &dataset, 4, 0, b"", timestamp, ZfsDataChecksum::Fletcher4,
        ).into_result().unwrap();
        engine.edit_file_range_clearing_setid(
            &cx, &dataset, 4, original_size + 20, 8, PunchHole, timestamp, ZfsDataChecksum::Fletcher4,
        ).into_result().unwrap();
        engine.set_posix_attributes(
            &cx,
            &dataset,
            4,
            &ZfsPosixSetAttr { mtime: Some(timestamp), ..ZfsPosixSetAttr::default() },
            timestamp,
            ZfsDataChecksum::Fletcher4,
        ).into_result().unwrap();
        assert_native_sa_capability(&native_sa_owner_bytes(&cx, &engine, &devices[0], 18).1, true);
        assert_eq!(file_range_head(&cx, &engine).stat(&cx, 4).unwrap().0.mode & 0o7777, 0o6755);
        let previous_txg = engine.committed_txg();
        let (_, token) = if owner_change {
            engine.set_posix_attributes(
                &cx,
                &dataset,
                4,
                &ZfsPosixSetAttr {
                    uid: Some(2001),
                    gid: Some(3001),
                    ..ZfsPosixSetAttr::default()
                },
                timestamp,
                ZfsDataChecksum::Fletcher4,
            ).into_result().unwrap()
        } else {
            // An empty native write beyond EOF really extends this API's file.
            // It must remove privileges despite carrying no payload bytes.
            engine.write_file_data_clearing_setid(
                &cx, &dataset, 4, original_size + 17, b"", timestamp, ZfsDataChecksum::Fletcher4,
            ).into_result().unwrap()
        };
        assert_eq!(token.committed_txg(), previous_txg + 1);
        assert_native_sa_capability(&native_sa_owner_bytes(&cx, &engine, &devices[0], 18).1, false);
        assert_eq!(native_sa_owner_bytes(&cx, &engine, &devices[0], 21).1, original_raw);
        let mut head = file_range_head(&cx, &engine);
        let metadata = head.stat(&cx, 4).unwrap().0;
        assert_eq!(metadata.mode & 0o7777, 0o755);
        assert_eq!(head.getxattr(&cx, 4, "user.retained").unwrap(), Some(b"retained".to_vec()));
        if owner_change {
            assert_eq!((metadata.uid, metadata.gid, metadata.size), (2001, 3001, original_size));
        } else {
            assert_eq!(metadata.size, original_size + 17);
            assert_eq!(head.read(&cx, 4, original_size, 17).unwrap(), vec![0; 17]);
        }
        drop(engine);
        let fresh: Vec<_> = devices.iter().map(FaultableMemberDevice::fresh_from_durable).collect();
        let reopened = open_engine_on_devices(
            &cx, &fresh, default_write_opts(POOL_GUID, token.published_slot()),
        ).unwrap();
        assert_native_sa_capability(&native_sa_owner_bytes(&cx, &reopened, &fresh[0], 18).1, false);
        assert_pool_scrub_and_allocation_clean(&cx, &fresh, POOL_GUID, Some(token.published_slot()));
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn shadowed_directory_capability_refuses_data_and_preclear_without_writes() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let timestamp = Timestamp { seconds: 1_730_100_101, nanos: 29 };
    let spec = PoolFixtureSpec {
        auxiliary_ownership: Some((4, AuxiliaryOwnership::CapabilityXattr)),
        ..sa_capability_fixture(0o755, b"shadowed")
    };
    let (mut engine, devices) = writer_fixture(&cx, &spec);
    let (_, original_raw) = native_sa_owner_bytes(&cx, &engine, &devices[0], 18);
    assert_native_sa_capability(&original_raw, true);
    assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, |writer| {
        writer.write_file_data_clearing_setid(
            &cx, &dataset, 4, 0, b"changed", timestamp, ZfsDataChecksum::Fletcher4,
        )
    });
    assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, |writer| {
        writer.write_file_data_clearing_setid(
            &cx, &dataset, 4, 5000, b"", timestamp, ZfsDataChecksum::Fletcher4,
        )
    });
    assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, |writer| {
        writer.edit_file_range_clearing_setid(
            &cx, &dataset, 4, 0, 4, ffs_zfs::ZfsFileRangeOperation::PunchHole,
            timestamp, ZfsDataChecksum::Fletcher4,
        )
    });
    assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, |writer| {
        writer.set_posix_attributes(
            &cx, &dataset, 4,
            &ffs_zfs::ZfsPosixSetAttr { uid: Some(2001), ..ffs_zfs::ZfsPosixSetAttr::default() },
            timestamp, ZfsDataChecksum::Fletcher4,
        )
    });
    assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, |writer| {
        writer.remove_xattr(&cx, &dataset, 4, "security.capability", timestamp)
    });
    let fs = ZfsFs::with_writer(&cx, engine, dataset.to_vec()).unwrap();
    let file = lookup(&fs, &cx, ROOT, "hello.txt");
    let source = lookup(&fs, &cx, ROOT, "keep.bin");
    let stable_io = io_counts(&devices);
    let stable_bytes = devices[0].durable_snapshot();
    for operation in DATA_MUTATIONS {
        assert_eq!(operation.apply(&fs, &cx, file.ino, source.ino).unwrap_err().to_errno(), libc::EOPNOTSUPP);
        assert_eq!(io_counts(&devices), stable_io);
    }
    assert_eq!(
        fs.removexattr(&cx, &mut RequestScope::empty(), file.ino, "security.capability")
            .unwrap_err().to_errno(),
        libc::EOPNOTSUPP
    );
    assert_eq!(io_counts(&devices), stable_io);
    assert_eq!(devices[0].durable_snapshot(), stable_bytes);
    assert_eq!(read(&fs, &cx, file.ino), b"SNAPDATA".repeat(512));
}

#[test]
#[allow(clippy::too_many_lines)]
fn sa_capability_crash_prefixes_publish_privilege_removal_with_each_data_mutation() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let timestamp = Timestamp { seconds: 1_730_100_102, nanos: 31 };
    let (seed, devices) =
        writer_fixture(&cx, &sa_capability_fixture(0o6755, b"crash-retained"));
    let pre_slot = seed.committed_slot();
    let pre_txg = seed.committed_txg();
    let (_, original_raw) = native_sa_owner_bytes(&cx, &seed, &devices[0], 18);
    let original = file_range_head(&cx, &seed).read(&cx, 4, 0, 8192).unwrap();
    let initial = devices[0].durable_snapshot();
    drop(seed);
    drop(devices);
    for operation in 0..3_u8 {
        let mut expected = original.clone();
        match operation {
            0 => expected[..4].copy_from_slice(b"safe"),
            1 => expected[4..8].fill(0),
            2 => expected.truncate(5),
            _ => unreachable!(),
        }
        for stage in 0..6_u8 {
            let devices = vec![FaultableMemberDevice::new(initial.clone())];
            let mut engine = open_engine_on_devices(
                &cx, &devices, default_write_opts(POOL_GUID, pre_slot),
            ).unwrap();
            let tripped = Arc::new(AtomicBool::new(false));
            let hook_tripped = Arc::clone(&tripped);
            engine.with_fault_hook(move |event| {
                let cut = matches!(
                    (stage, event.stage),
                    (0, ZfsPersistenceStage::ChildBlocksWrite { .. })
                        | (1, ZfsPersistenceStage::DatasetMetadataBarrier { .. })
                        | (2, ZfsPersistenceStage::MosSpaceMapBarrier { .. })
                        | (3, ZfsPersistenceStage::MosRootBarrier { .. })
                        | (4, ZfsPersistenceStage::UberblockWrite { label: 2, .. })
                        | (5, ZfsPersistenceStage::BeforeAcknowledge)
                );
                if cut {
                    hook_tripped.store(true, Ordering::SeqCst);
                    Err(FfsError::Cancelled)
                } else {
                    Ok(())
                }
            });
            let outcome = match operation {
                0 => engine.write_file_data_clearing_setid(
                    &cx, &dataset, 4, 0, b"safe", timestamp, ZfsDataChecksum::Fletcher4,
                ),
                1 => engine.edit_file_range_clearing_setid(
                    &cx, &dataset, 4, 4, 4, ffs_zfs::ZfsFileRangeOperation::PunchHole,
                    timestamp, ZfsDataChecksum::Fletcher4,
                ),
                2 => engine.set_posix_attributes(
                    &cx, &dataset, 4,
                    &ffs_zfs::ZfsPosixSetAttr {
                        size: Some(5), clear_suid_sgid: true,
                        ..ffs_zfs::ZfsPosixSetAttr::default()
                    },
                    timestamp, ZfsDataChecksum::Fletcher4,
                ),
                _ => unreachable!(),
            };
            assert!(tripped.load(Ordering::SeqCst), "missed capability cut {operation}/{stage}");
            let published = stage >= 4;
            let slot = match outcome {
                ZfsTxOutcome::NotCommitted(FfsError::Cancelled) if !published => pre_slot,
                ZfsTxOutcome::Uncertain { target_txg, target_slot, .. } if stage == 4 => {
                    assert_eq!(target_txg, pre_txg + 1);
                    assert!(engine.requires_recovery());
                    target_slot
                }
                ZfsTxOutcome::Committed { value, token } if stage == 5 => {
                    assert_eq!(value, expected.len() as u64);
                    assert_eq!(token.committed_txg(), pre_txg + 1);
                    token.published_slot()
                }
                other => panic!("unexpected capability outcome {operation}/{stage}: {other:?}"),
            };
            drop(engine);
            let fresh: Vec<_> = devices.iter().map(FaultableMemberDevice::fresh_from_durable).collect();
            let mut options = default_write_opts(POOL_GUID, slot);
            options.reconcile_torn_uberblocks = stage == 4;
            let reopened = open_engine_on_devices(&cx, &fresh, options).unwrap();
            assert_eq!(reopened.committed_txg(), pre_txg + u64::from(published));
            let mut head = file_range_head(&cx, &reopened);
            assert_eq!(
                head.read(&cx, 4, 0, original.len() + 1).unwrap(),
                if published { expected.clone() } else { original.clone() }
            );
            assert_eq!(head.stat(&cx, 4).unwrap().0.mode & 0o7777, if published { 0o755 } else { 0o6755 });
            assert_eq!(head.getxattr(&cx, 4, "user.retained").unwrap(), Some(b"crash-retained".to_vec()));
            let (_, raw) = native_sa_owner_bytes(&cx, &reopened, &fresh[0], 18);
            assert_native_sa_capability(&raw, !published);
            assert_eq!(native_sa_owner_bytes(&cx, &reopened, &fresh[0], 21).1, original_raw);
            let mut snapshot = head.open_snapshot(&cx, b"before").unwrap();
            assert_eq!(snapshot.read(&cx, 4, 0, original.len()).unwrap(), original);
            assert_eq!(snapshot.getxattr(&cx, 4, "user.retained").unwrap(), Some(b"crash-retained".to_vec()));
            assert_pool_scrub_and_allocation_clean(&cx, &fresh, POOL_GUID, Some(slot));
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn sa_capability_only_xattr_can_be_removed_without_leaking_its_spill() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let timestamp = Timestamp { seconds: 1_730_100_103, nanos: 33 };
    for write in [false, true] {
        let mut spec = sa_capability_fixture(0o755, b"unused");
        spec.hello_sa_xattrs.remove("user.retained");
        spec.auxiliary_ownership = None;
        let (mut engine, devices) = writer_fixture(&cx, &spec);
        let (original_node, original_raw) = native_sa_owner_bytes(&cx, &engine, &devices[0], 18);
        assert_native_sa_capability(&original_raw, true);
        let mut expected = file_range_head(&cx, &engine).read(&cx, 4, 0, 8192).unwrap();
        let (_, token) = if write {
            expected[..4].copy_from_slice(b"safe");
            engine.write_file_data_clearing_setid(
                &cx, &dataset, 4, 0, b"safe", timestamp, ZfsDataChecksum::Fletcher4,
            ).into_result().unwrap()
        } else {
            engine.remove_xattr(
                &cx, &dataset, 4, "security.capability", timestamp,
            ).into_result().unwrap()
        };
        drop(engine);
        let fresh: Vec<_> = devices.iter().map(FaultableMemberDevice::fresh_from_durable).collect();
        let reopened = open_engine_on_devices(
            &cx, &fresh, default_write_opts(POOL_GUID, token.published_slot()),
        ).unwrap();
        let (node, raw) = native_sa_owner_bytes(&cx, &reopened, &fresh[0], 18);
        assert_native_sa_capability(&raw, false);
        assert!(node.spill().is_none(), "an empty xattr map fits the ordinary SA bonus");
        if !write {
            assert_eq!(node.pointers(), original_node.pointers());
            assert_eq!(
                node.used_bytes(),
                original_node.used_bytes() - bp_allocated_bytes(original_node.spill().unwrap())
            );
        }
        let mut head = file_range_head(&cx, &reopened);
        assert!(head.listxattr(&cx, 4).unwrap().is_empty());
        assert_eq!(head.read(&cx, 4, 0, expected.len() + 1).unwrap(), expected);
        assert_eq!(native_sa_owner_bytes(&cx, &reopened, &fresh[0], 21).1, original_raw);
        assert_pool_scrub_and_allocation_clean(&cx, &fresh, POOL_GUID, Some(token.published_slot()));
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn sa_capability_same_owner_chown_still_removes_file_privileges() {
    let cx = Cx::for_testing();
    let (engine, devices) = writer_fixture(&cx, &sa_capability_fixture(0o6755, b"same owner"));
    let (original_node, original_raw) = native_sa_owner_bytes(&cx, &engine, &devices[0], 18);
    let acl_start = original_node.bonus().len() + 16;
    let original_acl = original_raw[acl_start..acl_start + 88].to_vec();
    let fs = ZfsFs::with_writer_options(
        &cx,
        engine,
        vec![b"data".to_vec()],
        ffs_zfs::ZfsMountWriteOptions { allow_mode_and_owner_setattr: true },
    ).unwrap();
    let file = lookup(&fs, &cx, ROOT, "hello.txt");
    let original_data = read(&fs, &cx, file.ino);
    let updated = fs.setattr(
        &cx,
        &mut RequestScope::empty(),
        file.ino,
        &SetAttrRequest {
            uid: Some(file.uid),
            gid: Some(file.gid),
            ..SetAttrRequest::default()
        },
    ).unwrap();
    assert_eq!((updated.uid, updated.gid), (file.uid, file.gid));
    assert_eq!(updated.perm, 0o755);
    assert_eq!(read(&fs, &cx, file.ino), original_data);
    let token = fs.last_durable_token().unwrap().unwrap();
    drop(fs);
    let fresh: Vec<_> = devices.iter().map(FaultableMemberDevice::fresh_from_durable).collect();
    let reopened = open_engine_on_devices(
        &cx, &fresh, default_write_opts(POOL_GUID, token.published_slot()),
    ).unwrap();
    let (node, raw) = native_sa_owner_bytes(&cx, &reopened, &fresh[0], 18);
    assert_eq!(node.pointers(), original_node.pointers());
    assert_native_sa_capability(&raw, false);
    assert!(raw.windows(88).any(|window| window == original_acl));
    assert_eq!(file_range_head(&cx, &reopened).getxattr(&cx, 4, "user.retained").unwrap(), Some(b"same owner".to_vec()));
    assert_eq!(native_sa_owner_bytes(&cx, &reopened, &fresh[0], 21).1, original_raw);
    assert_pool_scrub_and_allocation_clean(&cx, &fresh, POOL_GUID, Some(token.published_slot()));
}

#[test]
#[allow(clippy::too_many_lines)]
fn native_openzfs_zdb_oracle_verifies_sa_capabilities_and_private_xattr_reclamation() {
    let Some((zdb, ld_path)) = discover_zdb() else {
        assert!(!require_oracles_enabled(), "FFS_REQUIRE_ORACLES=1 requires zdb");
        eprintln!(
            "SKIP|suite=ffs-zfs::persistence_prefix|test=native_openzfs_zdb_oracle_verifies_sa_capabilities_and_private_xattr_reclamation|reason=missing_zdb"
        );
        return;
    };
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let timestamp = Timestamp { seconds: 1_730_100_104, nanos: 35 };
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("capability_pool.img");
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        pool_name: "ffscapzdb".to_owned(),
        member_path_override: Some(image.to_string_lossy().into_owned()),
        image_bytes: 64 * 1024 * 1024,
        auxiliary_ownership: Some((4, AuxiliaryOwnership::XattrDirectory)),
        ..sa_capability_fixture(0o6755, b"native retained")
    });
    std::fs::write(&image, &built.members[0]).unwrap();
    // Qualify the independently packed original SA/private-directory graph
    // before using the production writer as well as each resulting lifetime.
    run_zdb_check(&zdb, ld_path.as_deref(), dir.path(), "ffscapzdb", &image);
    let mut engine = ZfsTransactionEngine::open_files(
        &cx,
        &[image.as_path()],
        default_write_opts(built.pool_guid, built.initial_slot),
    ).unwrap();
    let (_, written) = engine.write_file_data_clearing_setid(
        &cx, &dataset, 4, 0, b"native unprivileged", timestamp, ZfsDataChecksum::Fletcher4,
    ).into_result().unwrap();
    let bytes = FaultableMemberDevice::new(std::fs::read(&image).unwrap());
    assert_native_sa_capability(&native_sa_owner_bytes(&cx, &engine, &bytes, 18).1, false);
    assert_native_sa_capability(&native_sa_owner_bytes(&cx, &engine, &bytes, 21).1, true);
    drop(bytes);
    assert_eq!(file_range_head(&cx, &engine).stat(&cx, 4).unwrap().0.mode & 0o7777, 0o755);
    drop(engine);
    run_zdb_check(&zdb, ld_path.as_deref(), dir.path(), "ffscapzdb", &image);

    let mut engine = ZfsTransactionEngine::open_files(
        &cx,
        &[image.as_path()],
        default_write_opts(built.pool_guid, written.published_slot()),
    ).unwrap();
    let identity = ZfsUnlinkedObject {
        object: 4,
        generation: file_range_head(&cx, &engine).stat(&cx, 4).unwrap().0.generation,
    };
    let (_, retained) = engine.unlink_open_file(
        &cx, &dataset, 2, b"hello.txt", identity, timestamp,
    ).into_result().unwrap();
    assert_eq!(engine.pending_unlinks(&cx, &dataset).unwrap(), vec![identity]);
    drop(engine);
    run_zdb_check(&zdb, ld_path.as_deref(), dir.path(), "ffscapzdb", &image);

    let mut engine = ZfsTransactionEngine::open_files(
        &cx,
        &[image.as_path()],
        default_write_opts(built.pool_guid, retained.published_slot()),
    ).unwrap();
    engine.reap_unlinked_file(&cx, &dataset, identity).into_result().unwrap();
    assert!(engine.pending_unlinks(&cx, &dataset).unwrap().is_empty());
    let mut head = file_range_head(&cx, &engine);
    for object in [4, 13, 14] {
        assert!(matches!(head.stat(&cx, object), Err(FfsError::NotFound(_))));
    }
    let mut snapshot = head.open_snapshot(&cx, b"before").unwrap();
    assert_eq!(snapshot.getxattr(&cx, 4, "user.retained").unwrap(), Some(b"native retained".to_vec()));
    assert_eq!(snapshot.read(&cx, 4, 0, built.snap_hello_expected.len()).unwrap(), built.snap_hello_expected);
    drop(snapshot);
    drop(head);
    drop(engine);
    run_zdb_check(&zdb, ld_path.as_deref(), dir.path(), "ffscapzdb", &image);
}
