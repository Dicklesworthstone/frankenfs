//! Native project inheritance persists new SA layouts and accounting together.
//! These constructed-pool tests are not an OpenZFS kernel interoperability run.

use super::*;
use ffs_ondisk::zfs_zpl::acl::{AceKind, NativeAcl, Principal};
use ffs_zfs::Objects;

const INHERIT: u64 = 1 << 46;
const PRESENT: u64 = 1 << 47;
const TIME: Timestamp = Timestamp {
    seconds: 1_715_000_630,
    nanos: 17,
};

fn spec() -> PoolFixtureSpec {
    PoolFixtureSpec {
        deadlist_mode: DeadlistMode::NativeDeadlist,
        project_accounting: true,
        // Both parents store MTIME and project ID in a compressed SA spill.
        // Only /sub inherits: root's explicit ID must not assign its children.
        directory_projects: BTreeMap::from([(2, 77), (6, 42)]),
        zpl_flags: BTreeMap::from([(6, INHERIT)]),
        additional_write_features: vec![(b"org.zfsonlinux:project_quota", 1)],
        ..PoolFixtureSpec::default()
    }
}

fn metadata(cx: &Cx, engine: &ZfsTransactionEngine, object: u64) -> Metadata {
    engine
        .open_read_objects(cx)
        .unwrap()
        .zpl(cx, &[b"data".to_vec()])
        .unwrap()
        .stat(cx, object)
        .unwrap()
        .0
}

fn inheritable_acl_fixture(order: Endian, in_spill: bool, extra_named: u64) -> NativeAclFixture {
    // Native FUID-v1 records, encoded independently of the new ACL codec.
    let mut entries = vec![
        (1_u16, 0x0003_u16, 0x0000_0022_u32, Some(77_u64)),
        (0, 0x1003, 0x001e_01bf, None),
        (0, 0x2043, 0x0012_00a9, None),
        (0, 0x4003, 0x0012_00a9, None),
        (0, 0x0001, 0x0000_0001, Some(88)),
        (1, 0x0046, 0x0000_0020, Some(99)),
    ];
    entries.extend((0..extra_named).map(|index| (0, 0x0003, 3, Some(5000 + index))));
    let mut aces = Vec::new();
    for (kind, flags, mask, who) in &entries {
        match order {
            Endian::Little => {
                aces.extend_from_slice(&kind.to_le_bytes());
                aces.extend_from_slice(&flags.to_le_bytes());
                aces.extend_from_slice(&mask.to_le_bytes());
            }
            Endian::Big => {
                aces.extend_from_slice(&kind.to_be_bytes());
                aces.extend_from_slice(&flags.to_be_bytes());
                aces.extend_from_slice(&mask.to_be_bytes());
            }
        }
        if let Some(who) = who {
            aces.extend_from_slice(&order.encode(*who));
        }
    }
    NativeAclFixture {
        count: entries.len() as u64,
        aces,
        in_spill,
    }
}

fn inherited_acl_spec(order: Endian, spilled: bool) -> PoolFixtureSpec {
    PoolFixtureSpec {
        zpl_contents_order: Some(order),
        directory_acls: BTreeMap::from([(
            6,
            inheritable_acl_fixture(order, spilled, if spilled { 12 } else { 0 }),
        )]),
        zpl_flags: BTreeMap::from([(6, INHERIT | 0x2)]),
        root_properties: vec![(b"aclinherit", 5), (b"aclmode", 3)],
        ..spec()
    }
}

/// Decode persisted SA attributes through the actual dataset registration and
/// layout ZAPs, including layouts first published by the operation under test.
fn stored_acl(
    cx: &Cx,
    mos: &mut Objects,
    device: &FaultableMemberDevice,
    object: u64,
) -> (NativeAcl, bool) {
    let head = mos.object(cx, 18).unwrap();
    let root = BlockPointer::parse(&head.bonus()[128..256], head.order()).unwrap();
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
    let node = |number: u64| {
        let number = usize::try_from(number).unwrap();
        let slots = DNODE_BLOCK_BYTES / DNODE_BYTES;
        let pointer = &objectset.meta.pointers()[number / slots];
        ffs_ondisk::zfs_dmu::dnode_at(&read(pointer), number % slots, pointer.payload_order())
            .unwrap()
            .unwrap()
    };
    let zap = |number| {
        let dnode = node(number);
        let pointers = native_plain_leaf_pointers(device, &dnode);
        let header = ffs_ondisk::zfs_zap::FatHeader::parse(
            &read(&pointers[0]),
            pointers[0].payload_order(),
            dnode.max_block(),
        )
        .unwrap();
        assert!(header.table_blocks().is_empty());
        let table = header
            .embedded_table(&read(&pointers[0]), pointers[0].payload_order())
            .unwrap();
        header
            .routes(&table, dnode.max_block())
            .unwrap()
            .into_iter()
            .flat_map(|route| {
                let pointer = &pointers[usize::try_from(route.block).unwrap()];
                header
                    .leaf(&read(pointer), pointer.payload_order(), route)
                    .unwrap()
            })
            .collect::<Vec<_>>()
    };
    let registry = SaRegistry::from_zaps(&zap(9), &zap(10)).unwrap();
    let dnode = node(object);
    let spill = dnode.spill().map(read);
    let attributes = registry.decode(dnode.bonus(), spill.as_deref()).unwrap();
    (attributes.native_acl().unwrap().unwrap(), spill.is_some())
}

#[test]
#[allow(clippy::too_many_lines)]
fn native_acl_inheritance_preserves_named_denials_projects_and_descendants_after_reopen() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    for (order, spilled) in [(Endian::Little, false), (Endian::Big, true)] {
        let built = build_clean_zfs_pool(&inherited_acl_spec(order, spilled));
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
        let (_, initial) = native_accounting_snapshot(&cx, &engine, &devices[0]);
        let file = engine
            .create_file(
                &cx,
                &dataset,
                6,
                b"acl-file",
                0o666,
                1000,
                1000,
                TIME,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .unwrap()
            .0;
        let (directory, token) = engine
            .mkdir(&cx, &dataset, 6, b"acl-dir", 0o777, 1000, 1000, TIME)
            .into_result()
            .unwrap();
        assert_eq!(metadata(&cx, &engine, file).mode & 0o7777, 0o644);
        assert_eq!(metadata(&cx, &engine, directory).mode & 0o7777, 0o755);
        for object in [file, directory] {
            assert_eq!(
                metadata(&cx, &engine, object).flags & (INHERIT | PRESENT),
                INHERIT | PRESENT
            );
        }
        let (file_acl, file_spill) = stored_acl(
            &cx,
            &mut engine.open_read_objects(&cx).unwrap(),
            &devices[0],
            file,
        );
        assert_eq!(file_spill, spilled);
        assert_eq!(file_acl.aces()[0].principal, Principal::User(77));
        assert_eq!(file_acl.aces()[0].kind, AceKind::Deny);
        assert_eq!(file_acl.aces()[0].access_mask, 0x22);
        assert_eq!(file_acl.aces()[0].flags, 0x80);
        assert!(!file_acl.has_inheritable_aces());
        assert!(
            file_acl
                .aces()
                .iter()
                .all(|ace| ace.principal != Principal::Group(99))
        );
        let (directory_acl, directory_spill) = stored_acl(
            &cx,
            &mut engine.open_read_objects(&cx).unwrap(),
            &devices[0],
            directory,
        );
        assert_eq!(directory_spill, spilled);
        assert_eq!(
            directory_acl
                .aces()
                .iter()
                .find(|ace| ace.principal == Principal::User(88))
                .unwrap()
                .flags,
            0x89
        );
        assert_eq!(
            directory_acl
                .aces()
                .iter()
                .find(|ace| ace.principal == Principal::Group(99))
                .unwrap()
                .flags,
            0x80
        );
        let (_, created) = native_accounting_snapshot(&cx, &engine, &devices[0]);
        assert_eq!(
            created[2][b"obj-2a".as_slice()],
            initial[2][b"obj-2a".as_slice()] + 2
        );
        if spilled {
            assert!(
                native_zpl_file_dnode(&cx, &engine, &devices[0], &dataset, file).used_bytes() > 0
            );
            assert!(created[2][b"2a".as_slice()] > initial[2][b"2a".as_slice()]);
        }
        drop(engine);
        let fresh: Vec<_> = devices
            .iter()
            .map(FaultableMemberDevice::fresh_from_durable)
            .collect();
        let mut engine = open_engine_on_devices(
            &cx,
            &fresh,
            default_write_opts(built.pool_guid, token.published_slot()),
        )
        .unwrap();
        assert_eq!(
            stored_acl(
                &cx,
                &mut engine.open_read_objects(&cx).unwrap(),
                &fresh[0],
                file
            )
            .0,
            file_acl
        );
        let (grandchild, _) = engine
            .create_file(
                &cx,
                &dataset,
                directory,
                b"grandchild",
                0o666,
                1000,
                1000,
                TIME,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .unwrap();
        let (grandchild_acl, _) = stored_acl(
            &cx,
            &mut engine.open_read_objects(&cx).unwrap(),
            &fresh[0],
            grandchild,
        );
        assert_eq!(grandchild_acl, file_acl);
        engine
            .set_posix_attributes(
                &cx,
                &dataset,
                file,
                &ffs_zfs::ZfsPosixSetAttr {
                    uid: Some(77),
                    ..ffs_zfs::ZfsPosixSetAttr::default()
                },
                TIME,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .unwrap();
        assert_eq!(metadata(&cx, &engine, file).mode & 0o7777, 0o444);
        assert_eq!(
            stored_acl(
                &cx,
                &mut engine.open_read_objects(&cx).unwrap(),
                &fresh[0],
                file
            )
            .0,
            file_acl
        );
        engine
            .set_posix_attributes(
                &cx,
                &dataset,
                directory,
                &ffs_zfs::ZfsPosixSetAttr {
                    mode: Some(0o750),
                    ..ffs_zfs::ZfsPosixSetAttr::default()
                },
                TIME,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .unwrap();
        let (chmod_acl, _) = stored_acl(
            &cx,
            &mut engine.open_read_objects(&cx).unwrap(),
            &fresh[0],
            directory,
        );
        assert!(chmod_acl.aces().contains(&directory_acl.aces()[0]));
        assert!(chmod_acl.has_inheritable_aces());
        let mut mos = engine.open_read_objects(&cx).unwrap();
        let mut snapshot = mos
            .zpl(&cx, &dataset)
            .unwrap()
            .open_snapshot(&cx, b"before")
            .unwrap();
        assert!(matches!(
            snapshot.resolve(&cx, b"/sub/acl-file"),
            Err(FfsError::NotFound(_))
        ));
        assert_eq!(
            snapshot
                .read(&cx, 4, 0, built.snap_hello_expected.len())
                .unwrap(),
            built.snap_hello_expected
        );
        assert_pool_scrub_and_allocation_clean(&cx, &fresh, built.pool_guid, None);
    }
}

#[test]
fn native_acl_profiles_and_restricted_chmod_refuse_before_backing_writes() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    for variant in 0..5 {
        let mut fixture = inherited_acl_spec(Endian::Little, true);
        let acl = fixture.directory_acls.get_mut(&6).unwrap();
        match variant {
            0 => acl.aces[0..2].copy_from_slice(&5_u16.to_le_bytes()), // object ACE
            1 => {
                let _ = acl.aces.pop();
            } // truncated named FUID
            2 => acl.count += 1,
            3 => fixture.data_properties = vec![(b"aclinherit", 2)],
            _ => fixture.data_properties = vec![(b"aclmode", 1)],
        }
        let built = build_clean_zfs_pool(&fixture);
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
        assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, |writer| {
            writer.create_file(
                &cx,
                &dataset,
                6,
                b"blocked",
                0o666,
                1000,
                1000,
                TIME,
                ZfsDataChecksum::Fletcher4,
            )
        });
        assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, |writer| {
            writer.mkdir(&cx, &dataset, 6, b"blocked-dir", 0o777, 1000, 1000, TIME)
        });
    }
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        data_properties: vec![(b"aclmode", 4)],
        ..inherited_acl_spec(Endian::Little, true)
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
    let file = engine
        .create_file(
            &cx,
            &dataset,
            6,
            b"protected",
            0o666,
            1000,
            1000,
            TIME,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap()
        .0;
    let original = stored_acl(
        &cx,
        &mut engine.open_read_objects(&cx).unwrap(),
        &devices[0],
        file,
    );
    assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, |writer| {
        writer.set_posix_attributes(
            &cx,
            &dataset,
            file,
            &ffs_zfs::ZfsPosixSetAttr {
                mode: Some(0o600),
                ..ffs_zfs::ZfsPosixSetAttr::default()
            },
            TIME,
            ZfsDataChecksum::Fletcher4,
        )
    });
    assert_eq!(
        stored_acl(
            &cx,
            &mut engine.open_read_objects(&cx).unwrap(),
            &devices[0],
            file
        ),
        original
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn inherited_creation_survives_reopen_and_charges_descendants_to_their_project() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let built = build_clean_zfs_pool(&spec());
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
    let (_, initial) = native_accounting_snapshot(&cx, &engine, &devices[0]);
    let file = engine
        .create_file(
            &cx,
            &dataset,
            6,
            b"file",
            0o604,
            1000,
            1000,
            TIME,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap()
        .0;
    let (directory, token) = engine
        .mkdir(&cx, &dataset, 6, b"nested", 0o750, 1000, 1000, TIME)
        .into_result()
        .unwrap();
    for (object, kind) in [(file, Kind::Regular), (directory, Kind::Directory)] {
        let child = metadata(&cx, &engine, object);
        assert_eq!(child.kind, kind);
        assert_eq!(child.parent, 6);
        assert_eq!(child.flags & (INHERIT | PRESENT), INHERIT | PRESENT);
        assert_eq!((child.uid, child.gid), (1000, 1000));
    }
    let (_, created) = native_accounting_snapshot(&cx, &engine, &devices[0]);
    assert_eq!(
        created[2][b"obj-2a".as_slice()],
        initial[2][b"obj-2a".as_slice()] + 2
    );
    assert_eq!(
        created[2][b"obj-0".as_slice()],
        initial[2][b"obj-0".as_slice()]
    );
    assert_eq!(created[2][b"0".as_slice()], initial[2][b"0".as_slice()]);

    // A fresh writer has no in-memory SA registration or project ID from the
    // first create. Its subsequent child creation must recover both from disk.
    drop(engine);
    let fresh: Vec<_> = devices
        .iter()
        .map(FaultableMemberDevice::fresh_from_durable)
        .collect();
    let mut engine = open_engine_on_devices(
        &cx,
        &fresh,
        default_write_opts(built.pool_guid, token.published_slot()),
    )
    .unwrap();
    let descendant = engine
        .create_file(
            &cx,
            &dataset,
            directory,
            b"child",
            0o640,
            1000,
            1000,
            TIME,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap()
        .0;
    let child = metadata(&cx, &engine, descendant);
    assert_eq!(child.parent, directory);
    assert_eq!(child.flags & (INHERIT | PRESENT), INHERIT | PRESENT);
    let (_, empty) = native_accounting_snapshot(&cx, &engine, &fresh[0]);
    assert_eq!(
        empty[2][b"obj-2a".as_slice()],
        initial[2][b"obj-2a".as_slice()] + 3
    );
    let payload = b"project owner survives a cold reopen";
    engine
        .write_file_data(
            &cx,
            &dataset,
            descendant,
            0,
            payload,
            TIME,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    let (_, written) = native_accounting_snapshot(&cx, &engine, &fresh[0]);
    assert!(written[2][b"2a".as_slice()] > empty[2][b"2a".as_slice()]);
    assert_eq!(written[2][b"0".as_slice()], empty[2][b"0".as_slice()]);
    assert_eq!(
        written[2][b"obj-2a".as_slice()],
        empty[2][b"obj-2a".as_slice()]
    );
    engine
        .truncate_file(
            &cx,
            &dataset,
            descendant,
            0,
            TIME,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    let (_, truncated) = native_accounting_snapshot(&cx, &engine, &fresh[0]);
    assert_eq!(truncated[2], empty[2]);
    engine
        .unlink_entry(&cx, &dataset, directory, b"child", false, TIME)
        .into_result()
        .unwrap();
    let (_, removed) = native_accounting_snapshot(&cx, &engine, &fresh[0]);
    assert_eq!(
        removed[2][b"obj-2a".as_slice()],
        created[2][b"obj-2a".as_slice()]
    );
    assert_eq!(removed[2][b"2a".as_slice()], created[2][b"2a".as_slice()]);

    let (default_file, token) = engine
        .create_file(
            &cx,
            &dataset,
            2,
            b"default",
            0o644,
            1000,
            1000,
            TIME,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    assert_eq!(
        metadata(&cx, &engine, default_file).flags & (INHERIT | PRESENT),
        0
    );
    let (_, final_counters) = native_accounting_snapshot(&cx, &engine, &fresh[0]);
    assert_eq!(
        final_counters[2][b"obj-0".as_slice()],
        initial[2][b"obj-0".as_slice()] + 1
    );
    assert_eq!(
        final_counters[2][b"obj-4d".as_slice()],
        initial[2][b"obj-4d".as_slice()]
    );
    assert_eq!(
        final_counters[2][b"obj-2a".as_slice()],
        created[2][b"obj-2a".as_slice()]
    );
    let mut mos = engine.open_read_objects(&cx).unwrap();
    let mut head = mos.zpl(&cx, &dataset).unwrap();
    assert_eq!(head.resolve(&cx, b"/sub/file").unwrap(), file);
    assert_eq!(head.stat(&cx, file).unwrap().0.mode & 0o7777, 0o604);
    assert_eq!(head.resolve(&cx, b"/sub/nested").unwrap(), directory);
    assert!(matches!(
        head.resolve(&cx, b"/sub/nested/child"),
        Err(FfsError::NotFound(_))
    ));
    let mut snapshot = head.open_snapshot(&cx, b"before").unwrap();
    assert!(matches!(
        snapshot.resolve(&cx, b"/sub/file"),
        Err(FfsError::NotFound(_))
    ));
    assert!(matches!(
        snapshot.resolve(&cx, b"/sub/nested"),
        Err(FfsError::NotFound(_))
    ));
    assert_eq!(
        snapshot
            .read(&cx, 4, 0, built.snap_hello_expected.len())
            .unwrap(),
        built.snap_hello_expected
    );
    assert_pool_scrub_and_allocation_clean(
        &cx,
        &fresh,
        built.pool_guid,
        Some(token.published_slot()),
    );
}

#[test]
fn project_creation_refuses_incomplete_profiles_and_inheritable_native_acls() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let base = spec();
    for fixture in [
        PoolFixtureSpec {
            zpl_version: 4,
            directory_projects: BTreeMap::new(),
            ..base.clone()
        },
        PoolFixtureSpec {
            directory_projects: BTreeMap::new(),
            ..base.clone()
        },
        PoolFixtureSpec {
            project_accounting: false,
            ..base.clone()
        },
        PoolFixtureSpec {
            additional_write_features: Vec::new(),
            ..base.clone()
        },
        PoolFixtureSpec {
            // Native ZFS_INHERIT_ACE requires ACL propagation, not synthesis
            // of a mode-only child ACL. Refusal must precede all backing I/O.
            zpl_flags: BTreeMap::from([(6, INHERIT | 0x2)]),
            ..base.clone()
        },
        PoolFixtureSpec {
            additional_write_features: vec![(b"org.zfsonlinux:project_quota", 0)],
            ..base
        },
    ] {
        let built = build_clean_zfs_pool(&fixture);
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
        assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, |writer| {
            writer.create_file(
                &cx,
                &dataset,
                6,
                b"blocked",
                0o644,
                1000,
                1000,
                TIME,
                ZfsDataChecksum::Fletcher4,
            )
        });
        assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, |writer| {
            writer.mkdir(&cx, &dataset, 6, b"blocked-dir", 0o755, 1000, 1000, TIME)
        });
    }
}

#[test]
fn native_acl_inheritance_refuses_creation_without_project_inheritance() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    for zpl_version in [4, 5] {
        for parent in [2, 6] {
            let built = build_clean_zfs_pool(&PoolFixtureSpec {
                zpl_version,
                deadlist_mode: DeadlistMode::NativeDeadlist,
                // ACL inheritance must be enforced even when project quota
                // and ZFS_PROJINHERIT have never been enabled.
                zpl_flags: BTreeMap::from([(parent, 0x2)]),
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
            assert_eq!(metadata(&cx, &engine, parent).flags & (INHERIT | 0x2), 0x2);
            assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, |writer| {
                writer.create_file(
                    &cx,
                    &dataset,
                    parent,
                    b"blocked-file",
                    0o666,
                    1000,
                    1000,
                    TIME,
                    ZfsDataChecksum::Fletcher4,
                )
            });
            assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, |writer| {
                writer.mkdir(
                    &cx,
                    &dataset,
                    parent,
                    b"blocked-directory",
                    0o777,
                    1000,
                    1000,
                    TIME,
                )
            });

            // OpenZFS does not inherit ACEs onto symlinks. Refusal must not
            // turn an inheritable-ACL directory into a wholly read-only tree.
            let (link, token) = engine
                .create_symlink(
                    &cx,
                    &dataset,
                    parent,
                    b"permitted-link",
                    b"../hello.txt",
                    1000,
                    1000,
                    TIME,
                    ZfsDataChecksum::Fletcher4,
                )
                .into_result()
                .unwrap();
            assert_eq!(metadata(&cx, &engine, link).flags & 0x2, 0);
            drop(engine);
            let fresh: Vec<_> = devices
                .iter()
                .map(FaultableMemberDevice::fresh_from_durable)
                .collect();
            let engine = open_engine_on_devices(
                &cx,
                &fresh,
                default_write_opts(built.pool_guid, token.published_slot()),
            )
            .unwrap();
            let mut mos = engine.open_read_objects(&cx).unwrap();
            let mut head = mos.zpl(&cx, &dataset).unwrap();
            assert_eq!(head.stat(&cx, parent).unwrap().0.flags & 0x2, 0x2);
            assert_eq!(head.readlink(&cx, link).unwrap(), b"../hello.txt");
            let prefix = if parent == 2 { "" } else { "/sub" };
            for name in ["blocked-file", "blocked-directory"] {
                assert!(matches!(
                    head.resolve(&cx, format!("{prefix}/{name}").as_bytes()),
                    Err(FfsError::NotFound(_))
                ));
            }
            assert_pool_scrub_and_allocation_clean(
                &cx,
                &fresh,
                built.pool_guid,
                Some(token.published_slot()),
            );
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn inherited_mkdir_publication_cuts_keep_sa_namespace_and_project_accounting_atomic() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        mirror_width: 2,
        ..inherited_acl_spec(Endian::Little, true)
    });
    let initial = built.members;
    let probe_devices: Vec<_> = initial
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
    let (_, old_counters) = native_accounting_snapshot(&cx, &probe, &probe_devices[0]);
    let created = probe
        .mkdir(&cx, &dataset, 6, b"atomic", 0o750, 1000, 1000, TIME)
        .into_result()
        .unwrap()
        .0;
    let (_, new_counters) = native_accounting_snapshot(&cx, &probe, &probe_devices[0]);
    let (new_acl, spilled) = stored_acl(
        &cx,
        &mut probe.open_read_objects(&cx).unwrap(),
        &probe_devices[0],
        created,
    );
    assert!(spilled);
    assert!(new_acl.has_inheritable_aces());
    assert_eq!(
        new_counters[2][b"obj-2a".as_slice()],
        old_counters[2][b"obj-2a".as_slice()] + 1
    );
    assert_eq!(
        new_counters[2][b"obj-0".as_slice()],
        old_counters[2][b"obj-0".as_slice()]
    );
    let events = probe.persistence_events().to_vec();
    let first_publish = events
        .iter()
        .find(|event| matches!(event.stage, ZfsPersistenceStage::UberblockWrite { .. }))
        .unwrap()
        .seq;
    let acknowledged = events
        .iter()
        .find(|event| event.stage == ZfsPersistenceStage::BeforeAcknowledge)
        .unwrap()
        .seq;
    for cut in events {
        for reorder in [false, true] {
            let devices: Vec<_> = initial
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
            let outcome = engine.mkdir(&cx, &dataset, 6, b"atomic", 0o750, 1000, 1000, TIME);
            if sequence <= first_publish {
                assert!(
                    matches!(outcome, ZfsTxOutcome::NotCommitted(_)),
                    "{:?}",
                    cut.stage
                );
            } else if sequence < acknowledged {
                assert!(
                    matches!(outcome, ZfsTxOutcome::Uncertain { .. }),
                    "{:?}",
                    cut.stage
                );
            } else {
                assert!(outcome.is_committed(), "{:?}", cut.stage);
            }
            for device in &devices {
                let mut media = device.state.lock().unwrap();
                if reorder {
                    media.crash_reorder_and_drop_half_unsynced();
                } else {
                    media.crash_drop_unsynced();
                }
            }
            let leaves = devices
                .iter()
                .map(|device| {
                    let fresh = device.fresh_from_durable();
                    let len = fresh.len_bytes();
                    Leaf::from_device(&cx, Box::new(fresh), 0, len).unwrap()
                })
                .collect();
            let pool = Pool::from_leaves(leaves).unwrap();
            let mut mos = pool.import_objects(&cx, Some(built.pool_guid)).unwrap();
            assert!([INITIAL_TXG, INITIAL_TXG + 1].contains(&mos.txg));
            let published = mos.txg == INITIAL_TXG + 1;
            if sequence <= first_publish {
                assert!(!published);
            }
            if sequence >= acknowledged {
                assert!(published);
            }

            // Read counters from the same freshly imported objectset root as
            // the namespace. No writable-engine cache survives the cut.
            let head_node = mos.object(&cx, 18).unwrap();
            let pointer =
                BlockPointer::parse(&head_node.bonus()[128..256], head_node.order()).unwrap();
            let image = devices[0].durable_snapshot();
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
            let objectset = ObjectSet::parse(&read(&pointer), pointer.payload_order()).unwrap();
            let accounting = objectset
                .embedded_dnode(OBJSET_PROJECTUSED_OFFSET, pointer.payload_order())
                .unwrap()
                .unwrap();
            let counter_pointer = &accounting.pointers()[0];
            let actual: BTreeMap<_, _> = ffs_ondisk::zfs_dmu::microzap(
                &read(counter_pointer),
                counter_pointer.payload_order(),
            )
            .unwrap()
            .into_iter()
            .map(|entry| (entry.name, entry.value))
            .collect();
            assert_eq!(
                actual,
                if published {
                    new_counters[2].clone()
                } else {
                    old_counters[2].clone()
                }
            );
            if published {
                let (actual_acl, spilled) = stored_acl(&cx, &mut mos, &devices[0], created);
                assert!(spilled);
                assert_eq!(actual_acl, new_acl);
            }
            let mut head = mos.zpl(&cx, &dataset).unwrap();
            if published {
                assert_eq!(head.resolve(&cx, b"/sub/atomic").unwrap(), created);
                let child = head.stat(&cx, created).unwrap().0;
                assert_eq!(child.flags & (INHERIT | PRESENT), INHERIT | PRESENT);
                assert_eq!((child.kind, child.parent), (Kind::Directory, 6));
                assert_eq!(child.mode & 0o7777, 0o755);
                assert_ne!(child.flags & 0x2, 0);
            } else {
                assert!(matches!(
                    head.resolve(&cx, b"/sub/atomic"),
                    Err(FfsError::NotFound(_))
                ));
            }
            assert_pool_scrub_and_allocation_clean(&cx, &devices, built.pool_guid, None);
        }
    }
}
