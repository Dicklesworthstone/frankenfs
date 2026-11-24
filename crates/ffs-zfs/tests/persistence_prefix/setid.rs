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

fn capability_xattrs() -> BTreeMap<String, Vec<u8>> {
    // Linux VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECTIVE, permitted
    // CAP_NET_BIND_SERVICE. The native writer treats the payload as opaque.
    let mut capability = vec![0_u8; 20];
    capability[..4].copy_from_slice(&0x0200_0001_u32.to_le_bytes());
    capability[4..8].copy_from_slice(&0x400_u32.to_le_bytes());
    BTreeMap::from([
        ("security.capability".to_owned(), capability),
        ("user.keep".to_owned(), b"retained".to_vec()),
        ("security.keep".to_owned(), b"opaque".to_vec()),
    ])
}

#[test]
#[allow(clippy::too_many_lines)]
fn mounted_capabilities_removed_atomically_with_each_data_mutation() {
    let cx = Cx::for_testing();
    for (zpl_version, in_spill, auxiliary) in [
        (5, false, None),
        (5, true, None),
        (5, true, Some((4, AuxiliaryOwnership::XattrDirectory))),
        (5, true, Some((4, AuxiliaryOwnership::CapabilityXattr))),
        (4, false, Some((4, AuxiliaryOwnership::CapabilityXattr))),
    ] {
        let original_mode = if zpl_version == 4 { 0o755 } else { 0o6755 };
        let built = build_clean_zfs_pool(&PoolFixtureSpec {
            zpl_version,
            ashift: if zpl_version == 4 { 9 } else { 12 },
            mirror_width: if zpl_version == 4 { 1 } else { 2 },
            hello_mode: original_mode,
            hello_sa_xattrs: if zpl_version == 5 {
                capability_xattrs()
            } else {
                BTreeMap::new()
            },
            hello_sa_xattrs_in_spill: in_spill,
            auxiliary_ownership: auxiliary,
            auxiliary_capability_with_retained_value: auxiliary
                == Some((4, AuxiliaryOwnership::CapabilityXattr)),
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
                default_write_opts(POOL_GUID, built.initial_slot),
            )
            .unwrap();
            assert!(
                durable_head(&cx, &devices)
                    .has_file_capabilities(&cx, 4)
                    .unwrap()
            );
            let fs = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
            let file = lookup(&fs, &cx, ROOT, "hello.txt");
            let source = lookup(&fs, &cx, ROOT, "keep.bin");
            let mut scope = RequestScope::empty();
            let before = io_counts(&devices);
            assert_eq!(
                fs.write(&cx, &mut scope, file.ino, file.size + 32, b"")
                    .unwrap(),
                0
            );
            assert_eq!(
                fs.copy_file_range(&cx, &mut scope, source.ino, 0, file.ino, 0, 0)
                    .unwrap(),
                0
            );
            assert_eq!(io_counts(&devices), before);
            // KEEP_SIZE entirely beyond EOF changes no bytes and retains capabilities.
            fs.fallocate(
                &cx,
                &mut scope,
                file.ino,
                file.size + 32,
                16,
                libc::FALLOC_FL_ZERO_RANGE | libc::FALLOC_FL_KEEP_SIZE,
            )
            .unwrap();
            assert!(
                durable_head(&cx, &devices)
                    .has_file_capabilities(&cx, 4)
                    .unwrap()
            );
            assert_eq!(read(&fs, &cx, file.ino), built.snap_hello_expected);
            let prior_txg = fs
                .last_durable_token()
                .unwrap()
                .map_or(INITIAL_TXG, |token| token.committed_txg());
            operation.apply(&fs, &cx, file.ino, source.ino).unwrap();
            let token = fs.last_durable_token().unwrap().unwrap();
            assert_eq!(token.committed_txg(), prior_txg + 1, "{operation:?}");
            let current = lookup(&fs, &cx, ROOT, "hello.txt");
            let expected = operation.expected(&built.snap_hello_expected);
            assert_eq!((current.perm, current.size), (0o755, expected.len() as u64));
            assert_eq!(
                (current.uid, current.gid, current.generation),
                (file.uid, file.gid, file.generation)
            );
            assert_eq!(read(&fs, &cx, file.ino), expected);
            drop(fs);
            let mut reopened = durable_head(&cx, &devices);
            assert!(!reopened.has_file_capabilities(&cx, 4).unwrap());
            if zpl_version == 5 {
                assert_eq!(
                    reopened.getxattr(&cx, 4, "user.keep").unwrap().as_deref(),
                    Some(b"retained".as_slice())
                );
            }
            assert_eq!(reopened.read(&cx, 4, 0, 8192).unwrap(), expected);
            if auxiliary.is_some() {
                assert_eq!(
                    reopened
                        .getxattr(&cx, 4, "user.retained")
                        .unwrap()
                        .as_deref(),
                    Some(b"private value survives namespace changes".as_slice())
                );
            }
            let mut snapshot = reopened.open_snapshot(&cx, b"before").unwrap();
            assert!(snapshot.has_file_capabilities(&cx, 4).unwrap());
            assert_eq!(
                snapshot.stat(&cx, 4).unwrap().0.mode & 0o7777,
                u64::from(original_mode)
            );
            assert_eq!(
                snapshot.read(&cx, 4, 0, 8192).unwrap(),
                built.snap_hello_expected
            );
            assert_pool_scrub_and_allocation_clean(
                &cx,
                &devices,
                POOL_GUID,
                Some(token.published_slot()),
            );
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn directory_capability_removal_retires_only_its_value_and_debits_its_native_owners() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    for shadow in [false, true] {
        for retained in [false, true] {
            let (engine, devices) = writer_fixture(
                &cx,
                &PoolFixtureSpec {
                    mirror_width: 2,
                    ashift: 12,
                    hello_mode: 0o6755,
                    hello_sa_xattrs: if shadow {
                        capability_xattrs()
                    } else {
                        BTreeMap::new()
                    },
                    auxiliary_ownership: Some((4, AuxiliaryOwnership::CapabilityXattr)),
                    auxiliary_xattr_owner_ids: Some((2001, 3001)),
                    auxiliary_capability_with_retained_value: retained,
                    project_accounting: true,
                    additional_write_features: vec![(b"org.zfsonlinux:project_quota", 1)],
                    deadlist_mode: DeadlistMode::NativeDeadlist,
                    ..PoolFixtureSpec::default()
                },
            );
            let before = native_accounting_snapshot(&cx, &engine, &devices[0]).1;
            let value = native_zpl_file_dnode(&cx, &engine, &devices[0], &dataset, 14);
            let charged_bytes = value.used_bytes() + DNODE_BYTES as u64;
            let fs = ZfsFs::with_writer(&cx, engine, dataset.to_vec()).unwrap();
            let file = lookup(&fs, &cx, ROOT, "hello.txt");
            let original = read(&fs, &cx, file.ino);
            let mut scope = RequestScope::empty();
            assert!(
                fs.removexattr(&cx, &mut scope, file.ino, "security.capability")
                    .unwrap()
            );
            let token = fs.last_durable_token().unwrap().unwrap();
            assert_eq!(token.committed_txg(), INITIAL_TXG + 1);
            assert_eq!(lookup(&fs, &cx, ROOT, "hello.txt").perm, 0o6755);
            assert_eq!(read(&fs, &cx, file.ino), original);
            let removed_io = io_counts(&devices);
            assert!(
                !fs.removexattr(&cx, &mut scope, file.ino, "security.capability")
                    .unwrap()
            );
            assert_eq!(
                io_counts(&devices),
                removed_io,
                "absent capabilities require no TXG"
            );
            drop(fs);

            let fresh: Vec<_> = devices
                .iter()
                .map(FaultableMemberDevice::fresh_from_durable)
                .collect();
            let mut reopened = open_engine_on_devices(
                &cx,
                &fresh,
                default_write_opts(POOL_GUID, token.published_slot()),
            )
            .unwrap();
            let after = native_accounting_snapshot(&cx, &reopened, &fresh[0]).1;
            for (index, owner) in [(0, b"7d1".as_slice()), (1, b"bb9".as_slice())] {
                let mut object_key = b"obj-".to_vec();
                object_key.extend_from_slice(owner);
                assert_eq!(
                    after[index].get(owner).copied().unwrap_or(0),
                    before[index][owner] - charged_bytes,
                );
                assert_eq!(
                    after[index].get(&object_key).copied().unwrap_or(0),
                    before[index][&object_key] - 1,
                );
            }
            assert_eq!(
                after[2][b"obj-0".as_slice()],
                before[2][b"obj-0".as_slice()] - 1
            );
            let directory = native_zpl_file_dnode(&cx, &reopened, &fresh[0], &dataset, 13);
            let metadata = Metadata::legacy(directory.bonus(), directory.order()).unwrap();
            assert_eq!(
                (metadata.parent, metadata.links, metadata.size),
                (4, 2, 2 + u64::from(retained))
            );
            let mut head = reopened
                .open_read_objects(&cx)
                .unwrap()
                .zpl(&cx, &dataset)
                .unwrap();
            assert!(!head.has_file_capabilities(&cx, 4).unwrap());
            assert!(matches!(head.stat(&cx, 14), Err(FfsError::NotFound(_))));
            assert_eq!(
                head.getxattr(&cx, 4, "user.retained").unwrap(),
                retained.then(|| b"private value survives namespace changes".to_vec()),
            );
            let mut snapshot = head.open_snapshot(&cx, b"before").unwrap();
            assert!(snapshot.has_file_capabilities(&cx, 4).unwrap());
            assert_eq!(snapshot.read(&cx, 4, 0, 8192).unwrap(), original);
            assert_pool_scrub_and_allocation_clean(
                &cx,
                &fresh,
                POOL_GUID,
                Some(token.published_slot()),
            );

            // The surviving directory and unrelated values still have their
            // normal final-link lifecycle, including the empty-directory case.
            let (_, token) = reopened
                .unlink_entry(
                    &cx,
                    &dataset,
                    2,
                    b"hello.txt",
                    false,
                    Timestamp {
                        seconds: 1_715_000_911,
                        nanos: 0,
                    },
                )
                .into_result()
                .unwrap();
            let mut final_head = durable_head(&cx, &fresh);
            for object in [4, 13, 14, 15] {
                assert!(matches!(
                    final_head.stat(&cx, object),
                    Err(FfsError::NotFound(_))
                ));
            }
            assert!(
                final_head
                    .open_snapshot(&cx, b"before")
                    .unwrap()
                    .has_file_capabilities(&cx, 4)
                    .unwrap()
            );
            assert_pool_scrub_and_allocation_clean(
                &cx,
                &fresh,
                POOL_GUID,
                Some(token.published_slot()),
            );
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn malformed_directory_capability_graphs_refuse_atomic_removal_before_writes() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let timestamp = Timestamp {
        seconds: 1_715_000_912,
        nanos: 0,
    };
    for fault in [
        XattrOwnershipFault::DirectoryParent,
        XattrOwnershipFault::DirectoryPublic,
        XattrOwnershipFault::DirectoryLinks,
        XattrOwnershipFault::DirectorySize,
        XattrOwnershipFault::DirectoryNested,
        XattrOwnershipFault::ValueParent,
        XattrOwnershipFault::ValuePublic,
        XattrOwnershipFault::ValueLinks,
        XattrOwnershipFault::ValueAlias,
        XattrOwnershipFault::DuplicateValue,
        XattrOwnershipFault::DotName,
        XattrOwnershipFault::ValueNested,
        XattrOwnershipFault::ValueExternalAcl,
        XattrOwnershipFault::OversizedValue,
    ] {
        let (mut engine, devices) = writer_fixture(
            &cx,
            &PoolFixtureSpec {
                hello_mode: 0o6755,
                hello_sa_xattrs: capability_xattrs(),
                auxiliary_ownership: Some((4, AuxiliaryOwnership::CapabilityXattr)),
                auxiliary_xattr_fault: Some(fault),
                deadlist_mode: DeadlistMode::NativeDeadlist,
                ..PoolFixtureSpec::default()
            },
        );
        let before: Vec<_> = devices
            .iter()
            .map(FaultableMemberDevice::durable_snapshot)
            .collect();
        let errno = if matches!(
            fault,
            XattrOwnershipFault::ValueExternalAcl | XattrOwnershipFault::OversizedValue
        ) {
            libc::EOPNOTSUPP
        } else {
            libc::EIO
        };
        assert_native_write_refused(&mut engine, &devices, errno, |writer| {
            writer.write_file_data_clearing_privileges(
                &cx,
                &dataset,
                4,
                0,
                b"must not publish",
                timestamp,
                ZfsDataChecksum::Inherit,
            )
        });
        assert_native_write_refused(&mut engine, &devices, errno, |writer| {
            writer.set_posix_attributes(
                &cx,
                &dataset,
                4,
                &ffs_zfs::ZfsPosixSetAttr {
                    size: Some(0),
                    mode: Some(0o600),
                    uid: Some(2000),
                    clear_suid_sgid: true,
                    clear_file_capabilities: true,
                    ..ffs_zfs::ZfsPosixSetAttr::default()
                },
                timestamp,
                ZfsDataChecksum::Inherit,
            )
        });
        for (device, original) in devices.iter().zip(before) {
            assert_eq!(device.durable_snapshot(), original, "{fault:?}");
        }
    }
}

#[test]
fn sa_capability_kernel_removal_and_unchanged_size_truncate() {
    let cx = Cx::for_testing();
    for in_spill in [false, true] {
        for explicit_removal in [false, true] {
            // A capability-only map exercises removal of the complete DXATTR
            // attribute, including retirement of a now-unneeded SA spill.
            let mut xattrs = capability_xattrs();
            xattrs.retain(|name, _| name == "security.capability");
            let (engine, devices) = writer_fixture(
                &cx,
                &PoolFixtureSpec {
                    hello_mode: 0o6755,
                    hello_sa_xattrs: xattrs,
                    hello_sa_xattrs_in_spill: in_spill,
                    deadlist_mode: DeadlistMode::NativeDeadlist,
                    ..PoolFixtureSpec::default()
                },
            );
            let fs = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
            let file = lookup(&fs, &cx, ROOT, "hello.txt");
            let original = read(&fs, &cx, file.ino);
            let mut scope = RequestScope::empty();
            let before = io_counts(&devices);
            assert!(
                fs.setattr(
                    &cx,
                    &mut scope,
                    file.ino,
                    &SetAttrRequest {
                        size: Some(0),
                        uid: Some(2000),
                        ..SetAttrRequest::default()
                    }
                )
                .is_err()
            );
            assert!(
                fs.fallocate(
                    &cx,
                    &mut scope,
                    file.ino,
                    u64::MAX,
                    8,
                    libc::FALLOC_FL_ZERO_RANGE
                )
                .is_err()
            );
            assert_eq!(io_counts(&devices), before);
            assert!(
                durable_head(&cx, &devices)
                    .has_file_capabilities(&cx, 4)
                    .unwrap()
            );
            fs.setattr(
                &cx,
                &mut scope,
                file.ino,
                &SetAttrRequest {
                    mtime: Some(UNIX_EPOCH + Duration::from_secs(1_715_000_000)),
                    ..SetAttrRequest::default()
                },
            )
            .unwrap();
            assert!(
                durable_head(&cx, &devices)
                    .has_file_capabilities(&cx, 4)
                    .unwrap()
            );
            if explicit_removal {
                assert!(
                    fs.removexattr(&cx, &mut scope, file.ino, "security.capability")
                        .unwrap()
                );
                assert_eq!(lookup(&fs, &cx, ROOT, "hello.txt").perm, 0o6755);
            } else {
                let updated = fs
                    .setattr(
                        &cx,
                        &mut scope,
                        file.ino,
                        &SetAttrRequest {
                            size: Some(file.size),
                            ..SetAttrRequest::default()
                        },
                    )
                    .unwrap();
                assert_eq!(updated.perm, 0o755);
            }
            let token = fs.last_durable_token().unwrap().unwrap();
            let after = io_counts(&devices);
            assert!(
                !fs.removexattr(&cx, &mut scope, file.ino, "security.capability")
                    .unwrap()
            );
            assert_eq!(io_counts(&devices), after);
            assert_eq!(fs.last_durable_token().unwrap().unwrap(), token);
            assert_eq!(read(&fs, &cx, file.ino), original);
            let mut reopened = durable_head(&cx, &devices);
            assert!(!reopened.has_file_capabilities(&cx, 4).unwrap());
            assert!(
                reopened
                    .open_snapshot(&cx, b"before")
                    .unwrap()
                    .has_file_capabilities(&cx, 4)
                    .unwrap()
            );
            assert_pool_scrub_and_allocation_clean(
                &cx,
                &devices,
                POOL_GUID,
                Some(token.published_slot()),
            );
        }
    }
}

#[test]
fn native_sa_capability_policies_and_compound_setattr_are_explicit() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let timestamp = Timestamp {
        seconds: 1_715_000_000,
        nanos: 0,
    };
    let (mut engine, devices) = writer_fixture(
        &cx,
        &PoolFixtureSpec {
            hello_mode: 0o6755,
            hello_sa_xattrs: capability_xattrs(),
            deadlist_mode: DeadlistMode::NativeDeadlist,
            ..PoolFixtureSpec::default()
        },
    );
    let original = durable_head(&cx, &devices).stat(&cx, 4).unwrap().0;
    engine
        .write_file_data_clearing_privileges(
            &cx,
            &dataset,
            4,
            original.size + 100,
            b"",
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    let unchanged = durable_head(&cx, &devices).stat(&cx, 4).unwrap().0;
    assert_eq!(
        (unchanged.size, unchanged.mode, unchanged.times),
        (original.size, original.mode, original.times)
    );
    assert!(
        durable_head(&cx, &devices)
            .has_file_capabilities(&cx, 4)
            .unwrap()
    );
    engine
        .write_file_data_clearing_setid(
            &cx,
            &dataset,
            4,
            0,
            b"native",
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    assert!(
        durable_head(&cx, &devices)
            .has_file_capabilities(&cx, 4)
            .unwrap()
    );
    assert_eq!(
        durable_head(&cx, &devices).stat(&cx, 4).unwrap().0.mode & 0o7777,
        0o755
    );
    engine
        .set_posix_attributes(
            &cx,
            &dataset,
            4,
            &ffs_zfs::ZfsPosixSetAttr {
                size: Some(5),
                mode: Some(0o6755),
                uid: Some(2000),
                gid: Some(2001),
                clear_suid_sgid: true,
                clear_file_capabilities: true,
                ..ffs_zfs::ZfsPosixSetAttr::default()
            },
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    let mut head = durable_head(&cx, &devices);
    let metadata = head.stat(&cx, 4).unwrap().0;
    assert_eq!(
        (
            metadata.size,
            metadata.mode & 0o7777,
            metadata.uid,
            metadata.gid
        ),
        (5, 0o755, 2000, 2001)
    );
    assert_eq!(head.read(&cx, 4, 0, 8192).unwrap(), b"nativ");
    assert!(!head.has_file_capabilities(&cx, 4).unwrap());
    assert_eq!(
        head.getxattr(&cx, 4, "user.keep").unwrap().as_deref(),
        Some(b"retained".as_slice())
    );
}

#[test]
fn malformed_capability_directory_shadow_refuses_all_mutations_without_partial_changes() {
    let cx = Cx::for_testing();
    let (engine, devices) = writer_fixture(
        &cx,
        &PoolFixtureSpec {
            hello_mode: 0o6755,
            hello_sa_xattrs: capability_xattrs(),
            auxiliary_ownership: Some((4, AuxiliaryOwnership::CapabilityXattr)),
            auxiliary_xattr_fault: Some(XattrOwnershipFault::ValueLinks),
            deadlist_mode: DeadlistMode::NativeDeadlist,
            ..PoolFixtureSpec::default()
        },
    );
    let fs = ZfsFs::with_writer_options(
        &cx,
        engine,
        vec![b"data".to_vec()],
        ffs_zfs::ZfsMountWriteOptions {
            allow_mode_and_owner_setattr: true,
        },
    )
    .unwrap();
    let file = lookup(&fs, &cx, ROOT, "hello.txt");
    let source = lookup(&fs, &cx, ROOT, "keep.bin");
    let original = read(&fs, &cx, file.ino);
    let before = io_counts(&devices);
    for operation in DATA_MUTATIONS {
        assert_eq!(
            operation
                .apply(&fs, &cx, file.ino, source.ino)
                .unwrap_err()
                .to_errno(),
            libc::EIO,
            "{operation:?}"
        );
    }
    let mut scope = RequestScope::empty();
    assert_eq!(
        fs.removexattr(&cx, &mut scope, file.ino, "security.capability")
            .unwrap_err()
            .to_errno(),
        libc::EIO
    );
    assert_eq!(
        fs.setattr(
            &cx,
            &mut scope,
            file.ino,
            &SetAttrRequest {
                size: Some(0),
                mode: Some(0o600),
                uid: Some(2000),
                gid: Some(2001),
                ..SetAttrRequest::default()
            }
        )
        .unwrap_err()
        .to_errno(),
        libc::EIO
    );
    assert_eq!(io_counts(&devices), before);
    assert_eq!(lookup(&fs, &cx, ROOT, "hello.txt"), file);
    assert_eq!(read(&fs, &cx, file.ino), original);
    assert!(fs.last_durable_token().unwrap().is_none());
    assert!(
        durable_head(&cx, &devices)
            .has_file_capabilities(&cx, 4)
            .unwrap()
    );
}

#[test]
fn sa_capability_owner_requests_clear_privileges_even_for_unchanged_ids() {
    let cx = Cx::for_testing();
    for directory_shadow in [false, true] {
        for (uid, gid) in [
            (Some(1000), None),
            (None, Some(1000)),
            (Some(2000), Some(2001)),
        ] {
            let (engine, devices) = writer_fixture(
                &cx,
                &PoolFixtureSpec {
                    hello_mode: 0o6755,
                    hello_sa_xattrs: capability_xattrs(),
                    auxiliary_ownership: directory_shadow
                        .then_some((4, AuxiliaryOwnership::CapabilityXattr)),
                    deadlist_mode: DeadlistMode::NativeDeadlist,
                    ..PoolFixtureSpec::default()
                },
            );
            let fs = ZfsFs::with_writer_options(
                &cx,
                engine,
                vec![b"data".to_vec()],
                ffs_zfs::ZfsMountWriteOptions {
                    allow_mode_and_owner_setattr: true,
                },
            )
            .unwrap();
            let file = lookup(&fs, &cx, ROOT, "hello.txt");
            let original = read(&fs, &cx, file.ino);
            let attr = fs
                .setattr(
                    &cx,
                    &mut RequestScope::empty(),
                    file.ino,
                    &SetAttrRequest {
                        uid,
                        gid,
                        // A compound chmod must commit with both capability stores
                        // cleared, including an owner request with unchanged IDs.
                        mode: directory_shadow.then_some(0o600),
                        ..SetAttrRequest::default()
                    },
                )
                .unwrap();
            assert_eq!(
                (attr.perm, attr.uid, attr.gid),
                (
                    if directory_shadow { 0o600 } else { 0o755 },
                    uid.unwrap_or(file.uid),
                    gid.unwrap_or(file.gid)
                )
            );
            assert_eq!(
                fs.last_durable_token().unwrap().unwrap().committed_txg(),
                INITIAL_TXG + 1
            );
            assert_eq!(read(&fs, &cx, file.ino), original);
            let mut head = durable_head(&cx, &devices);
            assert!(!head.has_file_capabilities(&cx, 4).unwrap());
            assert!(
                head.open_snapshot(&cx, b"before")
                    .unwrap()
                    .has_file_capabilities(&cx, 4)
                    .unwrap()
            );
        }
    }
}

#[test]
fn sa_capability_clearing_preserves_native_flag_admission() {
    let cx = Cx::for_testing();
    for flag in [
        0x0000_0001_0000_0000,
        0x0000_0010_0000_0000,
        0x0000_0040_0000_0000,
    ] {
        let (engine, devices) = writer_fixture(
            &cx,
            &PoolFixtureSpec {
                hello_mode: 0o6755,
                hello_sa_xattrs: capability_xattrs(),
                zpl_flags: BTreeMap::from([(4, flag)]),
                deadlist_mode: DeadlistMode::NativeDeadlist,
                ..PoolFixtureSpec::default()
            },
        );
        let fs = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
        let file = lookup(&fs, &cx, ROOT, "hello.txt");
        let source = lookup(&fs, &cx, ROOT, "keep.bin");
        let original = read(&fs, &cx, file.ino);
        let before = io_counts(&devices);
        for operation in DATA_MUTATIONS {
            assert!(
                operation.apply(&fs, &cx, file.ino, source.ino).is_err(),
                "{operation:?}, {flag:x}"
            );
        }
        assert_eq!(
            fs.removexattr(
                &cx,
                &mut RequestScope::empty(),
                file.ino,
                "security.capability"
            )
            .unwrap_err()
            .to_errno(),
            libc::EPERM
        );
        assert_eq!(io_counts(&devices), before);
        assert_eq!(lookup(&fs, &cx, ROOT, "hello.txt"), file);
        assert_eq!(read(&fs, &cx, file.ino), original);
        assert!(
            durable_head(&cx, &devices)
                .has_file_capabilities(&cx, 4)
                .unwrap()
        );
        if flag == 0x0000_0040_0000_0000 {
            // APPENDONLY authorizes extending data; capability removal must not
            // accidentally import the ordinary xattr setter's stricter denial.
            fs.write(
                &cx,
                &mut RequestScope::empty(),
                file.ino,
                file.size,
                b"appended",
            )
            .unwrap();
            let mut head = durable_head(&cx, &devices);
            assert!(!head.has_file_capabilities(&cx, 4).unwrap());
            assert_eq!(head.read(&cx, 4, file.size, 8).unwrap(), b"appended");
            assert_eq!(head.stat(&cx, 4).unwrap().0.mode & 0o7777, 0o755);
        }
    }
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
fn mounted_setid_data_mutations_refuse_malformed_private_capabilities_without_writes() {
    let cx = Cx::for_testing();
    for zpl_version in [4, 5] {
        let (engine, devices) = writer_fixture(
            &cx,
            &PoolFixtureSpec {
                zpl_version,
                hello_mode: 0o6755,
                auxiliary_ownership: Some((4, AuxiliaryOwnership::CapabilityXattr)),
                auxiliary_xattr_fault: Some(XattrOwnershipFault::ValueLinks),
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
                libc::EIO,
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
            libc::EIO
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
fn mounted_setid_persistence_cuts_never_publish_changed_data_with_old_privileges() {
    data_privilege_persistence_cuts(false, false);
}

#[test]
fn mounted_sa_capability_persistence_cuts_keep_data_and_privileges_atomic() {
    data_privilege_persistence_cuts(true, false);
}

#[test]
fn mounted_directory_capability_persistence_cuts_keep_both_stores_and_data_atomic() {
    data_privilege_persistence_cuts(true, true);
}

#[allow(clippy::too_many_lines)]
fn data_privilege_persistence_cuts(capabilities: bool, directory_capabilities: bool) {
    let cx = Cx::for_testing();
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        mirror_width: 2,
        hello_mode: 0o6755,
        with_sa_spill: !capabilities,
        hello_sa_xattrs: if capabilities {
            capability_xattrs()
        } else {
            BTreeMap::new()
        },
        hello_sa_xattrs_in_spill: capabilities,
        auxiliary_ownership: directory_capabilities
            .then_some((4, AuxiliaryOwnership::CapabilityXattr)),
        auxiliary_capability_with_retained_value: directory_capabilities,
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
                if capabilities {
                    assert_eq!(
                        reopened.has_file_capabilities(&cx, 4).unwrap(),
                        !committed,
                        "{operation:?}: {:?}",
                        cut.stage
                    );
                    assert_eq!(
                        reopened.getxattr(&cx, 4, "user.keep").unwrap().as_deref(),
                        Some(b"retained".as_slice())
                    );
                }
                if directory_capabilities {
                    assert_eq!(
                        reopened
                            .getxattr(&cx, 4, "user.retained")
                            .unwrap()
                            .as_deref(),
                        Some(b"private value survives namespace changes".as_slice())
                    );
                }
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
                if capabilities {
                    assert!(snapshot.has_file_capabilities(&cx, 4).unwrap());
                }
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
