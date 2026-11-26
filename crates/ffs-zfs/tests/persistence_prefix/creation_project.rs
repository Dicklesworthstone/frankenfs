//! Native project inheritance persists new SA layouts and accounting together.
//! These constructed-pool tests are not an OpenZFS kernel interoperability run.

use super::*;

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
        ..spec()
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
            let mut head = mos.zpl(&cx, &dataset).unwrap();
            if published {
                assert_eq!(head.resolve(&cx, b"/sub/atomic").unwrap(), created);
                let child = head.stat(&cx, created).unwrap().0;
                assert_eq!(child.flags & (INHERIT | PRESENT), INHERIT | PRESENT);
                assert_eq!((child.kind, child.parent), (Kind::Directory, 6));
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
