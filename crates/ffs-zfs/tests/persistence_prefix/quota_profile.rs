//! Owner usage accounting does not silently authorize writes past native limits.

use super::*;

const OWNER_QUOTA_KEYS: [&[u8]; 6] = [
    b"userquota@",
    b"groupquota@",
    b"projectquota@",
    b"userobjquota@",
    b"groupobjquota@",
    b"projectobjquota@",
];
const TIME: Timestamp = Timestamp {
    seconds: 1_715_000_640,
    nanos: 43,
};

fn project_spec() -> PoolFixtureSpec {
    PoolFixtureSpec {
        deadlist_mode: DeadlistMode::NativeDeadlist,
        project_accounting: true,
        sa_project_id: Some(42),
        directory_projects: BTreeMap::from([(6, 42)]),
        zpl_flags: BTreeMap::from([(6, 1 << 46)]),
        additional_write_features: vec![(b"org.zfsonlinux:project_quota", 1)],
        ..PoolFixtureSpec::default()
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn owner_quota_profiles_preserve_reads_and_refuse_mutations_before_backing_writes() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    for key in OWNER_QUOTA_KEYS {
        let (mut engine, devices) = file_range_fixture(
            &cx,
            &PoolFixtureSpec {
                owner_quota_objects: vec![(key, 11)],
                ..project_spec()
            },
        );
        let mut head = file_range_head(&cx, &engine);
        let slot = engine.committed_slot();
        let original = head.stat(&cx, 4).unwrap();
        let payload = head.read(&cx, 4, 0, 8192).unwrap();
        assert_eq!(payload, b"SNAPDATA".repeat(512));
        assert_eq!(head.resolve(&cx, b"/sub").unwrap(), 6);
        let (_, original_counters) = native_accounting_snapshot(&cx, &engine, &devices[0]);

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
        // The central guard also protects existing files and plain parents;
        // refusing inherited creation alone would still bypass byte limits.
        assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, |writer| {
            writer.write_file_data(
                &cx,
                &dataset,
                4,
                0,
                b"over quota",
                TIME,
                ZfsDataChecksum::Fletcher4,
            )
        });
        assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, |writer| {
            writer.truncate_file(&cx, &dataset, 4, 8192, TIME, ZfsDataChecksum::Fletcher4)
        });
        assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, |writer| {
            writer.rename_entry(&cx, &dataset, 2, b"hello.txt", 2, b"renamed", Some(4), TIME)
        });
        let (_, counters) = native_accounting_snapshot(&cx, &engine, &devices[0]);
        assert_eq!(counters, original_counters);
        drop(engine);
        let fresh: Vec<_> = devices
            .iter()
            .map(FaultableMemberDevice::fresh_from_durable)
            .collect();
        let reopened =
            open_engine_on_devices(&cx, &fresh, default_write_opts(POOL_GUID, slot)).unwrap();
        let mut head = file_range_head(&cx, &reopened);
        assert_eq!(head.stat(&cx, 4).unwrap(), original);
        assert_eq!(head.resolve(&cx, b"/hello.txt").unwrap(), 4);
        assert_eq!(head.read(&cx, 4, 0, 8192).unwrap(), payload);
        for name in [b"/sub/blocked".as_slice(), b"/sub/blocked-dir", b"/renamed"] {
            assert!(matches!(
                head.resolve(&cx, name),
                Err(FfsError::NotFound(_))
            ));
        }
        assert_pool_scrub_and_allocation_clean(&cx, &fresh, POOL_GUID, None);
    }
}

#[test]
fn absent_or_zero_owner_quota_references_admit_accounted_project_creation() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    for owner_quota_objects in [
        Vec::new(),
        OWNER_QUOTA_KEYS.into_iter().map(|key| (key, 0)).collect(),
    ] {
        let (mut engine, devices) = file_range_fixture(
            &cx,
            &PoolFixtureSpec {
                owner_quota_objects,
                ..project_spec()
            },
        );
        let (_, before) = native_accounting_snapshot(&cx, &engine, &devices[0]);
        let (created, token) = engine
            .create_file(
                &cx,
                &dataset,
                6,
                b"allowed",
                0o640,
                1000,
                1000,
                TIME,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .unwrap();
        let (_, after) = native_accounting_snapshot(&cx, &engine, &devices[0]);
        assert_eq!(
            after[2][b"obj-2a".as_slice()],
            before[2][b"obj-2a".as_slice()] + 1
        );
        assert_eq!(
            after[2][b"obj-0".as_slice()],
            before[2][b"obj-0".as_slice()]
        );
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
        let mut head = file_range_head(&cx, &reopened);
        assert_eq!(head.resolve(&cx, b"/sub/allowed").unwrap(), created);
        let flags = head.stat(&cx, created).unwrap().0.flags;
        assert_eq!(flags & ((1 << 46) | (1 << 47)), (1 << 46) | (1 << 47));
        assert_pool_scrub_and_allocation_clean(&cx, &fresh, POOL_GUID, None);
    }
}
