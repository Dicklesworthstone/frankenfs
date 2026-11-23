//! Project ownership is a namespace boundary, not a reason to reject an entire
//! writable directory. These constructed pools exercise the native TXG path;
//! they do not claim execution against an OpenZFS kernel.

use super::*;

const PROJECT_INHERIT: u64 = 1 << 46;
const PROJECT_PRESENT: u64 = 1 << 47;
const NOW: Timestamp = Timestamp {
    seconds: 1_715_000_620,
    nanos: 91,
};

fn project_pool(
    cx: &Cx,
    spec: &PoolFixtureSpec,
) -> (Vec<FaultableMemberDevice>, ZfsTransactionEngine, Vec<u8>) {
    let built = build_clean_zfs_pool(spec);
    let devices: Vec<_> = built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let engine = open_engine_on_devices(
        cx,
        &devices,
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .unwrap();
    (devices, engine, built.snap_hello_expected)
}

fn project_spec(subdirectory_project: u64, file_project: u64) -> PoolFixtureSpec {
    PoolFixtureSpec {
        deadlist_mode: DeadlistMode::NativeDeadlist,
        project_accounting: true,
        sa_project_id: Some(file_project),
        // A project ID alone does not make the root an inheriting directory.
        directory_projects: BTreeMap::from([(2, 77), (6, subdirectory_project)]),
        zpl_flags: BTreeMap::from([(6, PROJECT_INHERIT)]),
        additional_write_features: vec![(b"org.zfsonlinux:project_quota", 1)],
        ..PoolFixtureSpec::default()
    }
}

fn metadata(cx: &Cx, engine: &ZfsTransactionEngine, object: u64) -> Metadata {
    let mut mos = engine.open_read_objects(cx).unwrap();
    mos.zpl(cx, &[b"data".to_vec()])
        .unwrap()
        .stat(cx, object)
        .unwrap()
        .0
}

fn identity(cx: &Cx, engine: &ZfsTransactionEngine, object: u64) -> ZfsObjectIdentity {
    ZfsObjectIdentity {
        object,
        generation: metadata(cx, engine, object).generation,
    }
}

#[test]
fn project_namespace_link_preserves_flags_and_rename_inherits_without_reassigning_owner() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let (devices, mut engine, payload) = project_pool(&cx, &project_spec(42, 42));
    let original = metadata(&cx, &engine, 4);
    assert_eq!(original.flags & PROJECT_INHERIT, 0);
    assert_ne!(original.flags & PROJECT_PRESENT, 0);

    // Existing same-project objects may acquire another name. Hard linking
    // must not alter the object's inheritance policy merely to admit the name.
    assert_eq!(
        engine
            .link_entry(&cx, &dataset, 4, 6, b"alias", NOW)
            .into_result()
            .unwrap()
            .0,
        4
    );
    let linked = metadata(&cx, &engine, 4);
    assert_eq!(linked.links, original.links + 1);
    assert_eq!(linked.flags, original.flags);

    engine
        .rename_entry(&cx, &dataset, 2, b"hello.txt", 6, b"moved", Some(4), NOW)
        .into_result()
        .unwrap();
    let moved = metadata(&cx, &engine, 4);
    assert_eq!(moved.flags, original.flags | PROJECT_INHERIT);
    assert_eq!((moved.parent, moved.links), (6, linked.links));
    assert_eq!(moved.generation, original.generation);

    // Moving out of an inheriting tree neither changes the existing project
    // owner nor clears the object's inherited flag. Root's project 77 is not
    // an admission constraint because its own PROJINHERIT flag is absent.
    let (_, token) = engine
        .rename_entry(&cx, &dataset, 6, b"moved", 2, b"final", Some(4), NOW)
        .into_result()
        .unwrap();
    drop(engine);
    let fresh: Vec<_> = devices
        .iter()
        .map(FaultableMemberDevice::fresh_from_durable)
        .collect();
    let reopened = open_engine_on_devices(
        &cx,
        &fresh,
        default_write_opts(POOL_GUID, token.published_slot()),
    )
    .unwrap();
    let final_meta = metadata(&cx, &reopened, 4);
    assert_eq!(final_meta.flags, original.flags | PROJECT_INHERIT);
    assert_eq!((final_meta.parent, final_meta.links), (2, linked.links));
    assert_eq!(final_meta.generation, original.generation);
    assert_eq!(final_meta.times[1], original.times[1]);
    let mut mos = reopened.open_read_objects(&cx).unwrap();
    let mut head = mos.zpl(&cx, &dataset).unwrap();
    assert_eq!(head.resolve(&cx, b"/final").unwrap(), 4);
    assert_eq!(head.resolve(&cx, b"/sub/alias").unwrap(), 4);
    assert!(matches!(
        head.resolve(&cx, b"/hello.txt"),
        Err(FfsError::NotFound(_))
    ));
    assert!(matches!(
        head.resolve(&cx, b"/sub/moved"),
        Err(FfsError::NotFound(_))
    ));
    assert_eq!(head.read(&cx, 4, 0, payload.len()).unwrap(), payload);
    let mut snapshot = head.open_snapshot(&cx, b"before").unwrap();
    assert_eq!(snapshot.resolve(&cx, b"/hello.txt").unwrap(), 4);
    let historical = snapshot.stat(&cx, 4).unwrap().0;
    assert_eq!(historical.flags, original.flags);
    assert_eq!(historical.links, original.links);
    assert_eq!(snapshot.read(&cx, 4, 0, payload.len()).unwrap(), payload);
    assert_pool_scrub_and_allocation_clean(&cx, &fresh, POOL_GUID, None);
}

#[test]
fn project_namespace_rejects_foreign_and_default_owners_before_backing_writes() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let (devices, mut engine, payload) = project_pool(&cx, &project_spec(42, 43));
    let within = engine
        .create_file(
            &cx,
            &dataset,
            6,
            b"within",
            0o644,
            1000,
            1000,
            NOW,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap()
        .0;
    let within_identity = identity(&cx, &engine, within);
    let foreign_identity = identity(&cx, &engine, 4);
    let default_identity = identity(&cx, &engine, 5);
    let original_foreign = metadata(&cx, &engine, 4);
    let original_default = metadata(&cx, &engine, 5);

    // Both a different nonzero project and the implicit default project must
    // be refused. A missing project field is not a wildcard.
    for (object, name) in [(4, b"hello.txt".as_slice()), (5, b"keep.bin".as_slice())] {
        assert_native_write_refused(&mut engine, &devices, libc::EXDEV, |writer| {
            writer.link_entry(&cx, &dataset, object, 6, b"foreign-link", NOW)
        });
        assert_native_write_refused(&mut engine, &devices, libc::EXDEV, |writer| {
            writer.rename_entry(
                &cx,
                &dataset,
                2,
                name,
                6,
                b"foreign-move",
                Some(object),
                NOW,
            )
        });
    }
    assert_native_write_refused(&mut engine, &devices, libc::EXDEV, |writer| {
        writer.exchange_entries(
            &cx,
            &dataset,
            2,
            b"hello.txt",
            6,
            b"within",
            foreign_identity,
            within_identity,
            NOW,
        )
    });
    // Forward movement into plain root is legal; the reverse exchange edge
    // would move default-project keep.bin into project 42 and must reject the
    // complete transaction. No half exchange or project reassignment is valid.
    assert_native_write_refused(&mut engine, &devices, libc::EXDEV, |writer| {
        writer.exchange_entries(
            &cx,
            &dataset,
            6,
            b"within",
            2,
            b"keep.bin",
            within_identity,
            default_identity,
            NOW,
        )
    });
    assert_eq!(metadata(&cx, &engine, 4), original_foreign);
    assert_eq!(metadata(&cx, &engine, 5), original_default);
    let mut mos = engine.open_read_objects(&cx).unwrap();
    let mut head = mos.zpl(&cx, &dataset).unwrap();
    assert_eq!(head.resolve(&cx, b"/hello.txt").unwrap(), 4);
    assert_eq!(head.resolve(&cx, b"/keep.bin").unwrap(), 5);
    assert_eq!(head.resolve(&cx, b"/sub/within").unwrap(), within);
    assert_eq!(head.read(&cx, 4, 0, payload.len()).unwrap(), payload);
    assert_pool_scrub_and_allocation_clean(&cx, &devices, POOL_GUID, None);
}

#[test]
#[allow(clippy::too_many_lines)]
fn project_namespace_exchange_preserves_identity_and_destination_inheritance_on_reopen() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let (devices, mut engine, payload) = project_pool(&cx, &project_spec(42, 42));
    let within = engine
        .create_file(
            &cx,
            &dataset,
            6,
            b"within",
            0o640,
            1001,
            1002,
            NOW,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap()
        .0;
    engine
        .write_file_data(
            &cx,
            &dataset,
            within,
            0,
            b"same project, different object",
            NOW,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    let source = identity(&cx, &engine, 4);
    let target = identity(&cx, &engine, within);
    let original_source = metadata(&cx, &engine, 4);
    let original_target = metadata(&cx, &engine, within);
    let (_, token) = engine
        .exchange_entries(
            &cx,
            &dataset,
            2,
            b"hello.txt",
            6,
            b"within",
            source,
            target,
            NOW,
        )
        .into_result()
        .unwrap();
    assert_native_write_refused(&mut engine, &devices, libc::ESTALE, |writer| {
        writer.exchange_entries(
            &cx,
            &dataset,
            2,
            b"hello.txt",
            6,
            b"within",
            source,
            target,
            NOW,
        )
    });
    drop(engine);
    let fresh: Vec<_> = devices
        .iter()
        .map(FaultableMemberDevice::fresh_from_durable)
        .collect();
    let reopened = open_engine_on_devices(
        &cx,
        &fresh,
        default_write_opts(POOL_GUID, token.published_slot()),
    )
    .unwrap();
    let after_source = metadata(&cx, &reopened, 4);
    let after_target = metadata(&cx, &reopened, within);
    assert_eq!(after_source.flags, original_source.flags | PROJECT_INHERIT);
    assert_eq!(after_target.flags, original_target.flags);
    assert_eq!((after_source.parent, after_target.parent), (6, 2));
    for (before, after) in [
        (&original_source, &after_source),
        (&original_target, &after_target),
    ] {
        assert_eq!(
            (
                after.generation,
                after.links,
                after.size,
                after.uid,
                after.gid
            ),
            (
                before.generation,
                before.links,
                before.size,
                before.uid,
                before.gid
            )
        );
    }
    let mut mos = reopened.open_read_objects(&cx).unwrap();
    let mut head = mos.zpl(&cx, &dataset).unwrap();
    assert_eq!(head.resolve(&cx, b"/hello.txt").unwrap(), within);
    assert_eq!(head.resolve(&cx, b"/sub/within").unwrap(), 4);
    assert_eq!(head.read(&cx, 4, 0, payload.len()).unwrap(), payload);
    assert_eq!(
        head.read(&cx, within, 0, 128).unwrap(),
        b"same project, different object"
    );
    assert_pool_scrub_and_allocation_clean(&cx, &fresh, POOL_GUID, None);
}

#[test]
fn project_namespace_symlinks_use_default_owner_and_rename_checks_that_owner() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    for inherited_project in [0, 42] {
        let (devices, mut engine, _) = project_pool(&cx, &project_spec(inherited_project, 42));
        let (_, before_counters) = native_accounting_snapshot(&cx, &engine, &devices[0]);
        let link = engine
            .create_symlink(
                &cx,
                &dataset,
                6,
                b"link",
                b"../hello.txt",
                1000,
                1000,
                NOW,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .unwrap()
            .0;
        let created = metadata(&cx, &engine, link);
        assert_eq!(created.kind, Kind::Symlink);
        assert_eq!(created.flags & (PROJECT_INHERIT | PROJECT_PRESENT), 0);
        let (_, after_counters) = native_accounting_snapshot(&cx, &engine, &devices[0]);
        assert_eq!(
            after_counters[2][b"obj-0".as_slice()],
            before_counters[2][b"obj-0".as_slice()] + 1,
            "native symlink allocation belongs to the default project"
        );
        if inherited_project != 0 {
            assert_eq!(
                after_counters[2][b"obj-2a".as_slice()],
                before_counters[2][b"obj-2a".as_slice()]
            );
        }
        engine
            .rename_entry(&cx, &dataset, 6, b"link", 2, b"moved-link", Some(link), NOW)
            .into_result()
            .unwrap();
        let final_path = if inherited_project == 0 {
            engine
                .rename_entry(
                    &cx,
                    &dataset,
                    2,
                    b"moved-link",
                    6,
                    b"returned-link",
                    Some(link),
                    NOW,
                )
                .into_result()
                .unwrap();
            let renamed = metadata(&cx, &engine, link);
            assert_eq!(renamed.flags, created.flags | PROJECT_INHERIT);
            b"/sub/returned-link".as_slice()
        } else {
            assert_native_write_refused(&mut engine, &devices, libc::EXDEV, |writer| {
                writer.rename_entry(
                    &cx,
                    &dataset,
                    2,
                    b"moved-link",
                    6,
                    b"returned-link",
                    Some(link),
                    NOW,
                )
            });
            b"/moved-link".as_slice()
        };
        let fresh: Vec<_> = devices
            .iter()
            .map(FaultableMemberDevice::fresh_from_durable)
            .collect();
        let reopened = open_engine_on_devices(
            &cx,
            &fresh,
            default_write_opts(POOL_GUID, engine.committed_slot()),
        )
        .unwrap();
        let mut mos = reopened.open_read_objects(&cx).unwrap();
        let mut head = mos.zpl(&cx, &dataset).unwrap();
        assert_eq!(head.resolve(&cx, final_path).unwrap(), link);
        assert_eq!(head.readlink(&cx, link).unwrap(), b"../hello.txt");
        assert_pool_scrub_and_allocation_clean(&cx, &fresh, POOL_GUID, None);
    }
}
