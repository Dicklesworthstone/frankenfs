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
fn owner_quota_profiles_reject_new_objects_and_byte_growth_before_backing_writes() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    for (index, key) in OWNER_QUOTA_KEYS.into_iter().enumerate() {
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

        assert_native_write_refused(&mut engine, &devices, libc::EDQUOT, |writer| {
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
        assert_native_write_refused(&mut engine, &devices, libc::EDQUOT, |writer| {
            writer.mkdir(&cx, &dataset, 6, b"blocked-dir", 0o755, 1000, 1000, TIME)
        });
        // Object limits do not prohibit allocating bytes in an existing file.
        // Byte limits also apply to files outside an inheriting directory.
        if index < 3 {
            // Deterministic incompressible bytes so default `compression=on`
            // still allocates 8 KiB past the byte-quota ceiling.
            let mut prng = 0x51A7_A701_u32;
            let growth_bytes: Vec<u8> = (0..8192)
                .map(|_| {
                    prng ^= prng << 13;
                    prng ^= prng >> 17;
                    prng ^= prng << 5;
                    prng.to_le_bytes()[0]
                })
                .collect();
            assert_native_write_refused(&mut engine, &devices, libc::EDQUOT, |writer| {
                writer.write_file_data(
                    &cx,
                    &dataset,
                    4,
                    4096,
                    &growth_bytes,
                    TIME,
                    ZfsDataChecksum::Fletcher4,
                )
            });
        }
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
        for name in [b"/sub/blocked".as_slice(), b"/sub/blocked-dir"] {
            assert!(matches!(
                head.resolve(&cx, name),
                Err(FfsError::NotFound(_))
            ));
        }
        assert_pool_scrub_and_allocation_clean(&cx, &fresh, POOL_GUID, None);
    }
}

fn accounted_spec() -> PoolFixtureSpec {
    PoolFixtureSpec {
        deadlist_mode: DeadlistMode::NativeDeadlist,
        project_accounting: true,
        additional_write_features: vec![(b"org.zfsonlinux:project_quota", 1)],
        ..PoolFixtureSpec::default()
    }
}

fn create_empty(cx: &Cx, engine: &mut ZfsTransactionEngine, name: &[u8]) -> ZfsTxOutcome<u64> {
    engine.create_file(
        cx,
        &[b"data".to_vec()],
        2,
        name,
        0o644,
        1000,
        1000,
        TIME,
        ZfsDataChecksum::Fletcher4,
    )
}

#[test]
#[allow(clippy::too_many_lines)]
fn owner_quota_all_six_limits_charge_empty_files_and_allow_exact_boundary_reuse() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let baseline = {
        let (engine, devices) = file_range_fixture(&cx, &accounted_spec());
        native_accounting_snapshot(&cx, &engine, &devices[0]).1
    };
    for (index, key) in OWNER_QUOTA_KEYS.into_iter().enumerate() {
        let owner_index = index % 3;
        let owner = if owner_index == 2 {
            b"0".as_slice()
        } else {
            b"3e8"
        };
        let usage_key = if index < 3 {
            owner.to_vec()
        } else {
            [b"obj-".as_slice(), owner].concat()
        };
        let increment = if index < 3 { 512 } else { 1 };
        let limit = baseline[owner_index][&usage_key] + increment;
        let (mut engine, devices) = file_range_fixture(
            &cx,
            &PoolFixtureSpec {
                owner_quota_objects: vec![(key, 11)],
                owner_quota_entries: BTreeMap::from([(11, vec![(owner, limit)])]),
                ..accounted_spec()
            },
        );
        let (file, _) = create_empty(&cx, &mut engine, b"quota-one")
            .into_result()
            .unwrap();
        let (_, after) = native_accounting_snapshot(&cx, &engine, &devices[0]);
        assert_eq!(after[owner_index][&usage_key], limit);
        for dimension in 0..3 {
            let owner = if dimension == 2 {
                b"0".as_slice()
            } else {
                b"3e8"
            };
            assert_eq!(after[dimension][owner], baseline[dimension][owner] + 512);
        }
        assert_eq!(file_range_head(&cx, &engine).stat(&cx, file).unwrap().1, 0);
        assert_native_write_refused(&mut engine, &devices, libc::EDQUOT, |writer| {
            create_empty(&cx, writer, b"quota-two")
        });

        // Zero net usage is admissible at the limit. Logical sparse growth
        // must not be confused with additional native physical byte charges.
        engine
            .rename_entry(
                &cx,
                &dataset,
                2,
                b"quota-one",
                2,
                b"quota-renamed",
                Some(file),
                TIME,
            )
            .into_result()
            .unwrap();
        engine
            .truncate_file(&cx, &dataset, file, 4096, TIME, ZfsDataChecksum::Fletcher4)
            .into_result()
            .unwrap();
        assert_eq!(
            file_range_head(&cx, &engine)
                .read(&cx, file, 0, 4096)
                .unwrap(),
            vec![0; 4096]
        );
        if index < 3 {
            assert_native_write_refused(&mut engine, &devices, libc::EDQUOT, |writer| {
                writer.write_file_data(
                    &cx,
                    &dataset,
                    file,
                    0,
                    b"x",
                    TIME,
                    ZfsDataChecksum::Fletcher4,
                )
            });
        } else {
            engine
                .write_file_data(
                    &cx,
                    &dataset,
                    file,
                    0,
                    b"allowed bytes",
                    TIME,
                    ZfsDataChecksum::Fletcher4,
                )
                .into_result()
                .unwrap();
            let (_, counters) = native_accounting_snapshot(&cx, &engine, &devices[0]);
            assert_eq!(counters[owner_index][&usage_key], limit);
        }

        engine
            .unlink_entry(&cx, &dataset, 2, b"quota-renamed", false, TIME)
            .into_result()
            .unwrap();
        let (_, reclaimed) = native_accounting_snapshot(&cx, &engine, &devices[0]);
        assert_eq!(reclaimed, baseline);
        let (replacement, token) = create_empty(&cx, &mut engine, b"quota-two")
            .into_result()
            .unwrap();
        let (_, committed) = native_accounting_snapshot(&cx, &engine, &devices[0]);
        drop(engine);
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
        assert_eq!(
            native_accounting_snapshot(&cx, &reopened, &fresh[0]).1,
            committed
        );
        let mut head = file_range_head(&cx, &reopened);
        assert_eq!(head.resolve(&cx, b"/quota-two").unwrap(), replacement);
        assert!(matches!(
            head.resolve(&cx, b"/quota-renamed"),
            Err(FfsError::NotFound(_))
        ));
        assert_native_write_refused(&mut reopened, &fresh, libc::EDQUOT, |writer| {
            create_empty(&cx, writer, b"quota-three")
        });
        assert_pool_scrub_and_allocation_clean(&cx, &fresh, POOL_GUID, None);
    }
}

#[test]
fn owner_quota_allows_net_reclamation_while_already_above_byte_and_object_limits() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    for key in OWNER_QUOTA_KEYS {
        let (mut engine, devices) = file_range_fixture(
            &cx,
            &PoolFixtureSpec {
                owner_quota_objects: vec![(key, 11)],
                ..accounted_spec()
            },
        );
        let before = native_accounting_snapshot(&cx, &engine, &devices[0]).1;
        engine
            .truncate_file(&cx, &dataset, 5, 0, TIME, ZfsDataChecksum::Fletcher4)
            .into_result()
            .unwrap();
        let after = native_accounting_snapshot(&cx, &engine, &devices[0]).1;
        for index in 0..3 {
            let owner = if index == 2 { b"0".as_slice() } else { b"3e8" };
            let count = [b"obj-".as_slice(), owner].concat();
            assert_eq!(after[index][owner], before[index][owner] - 4096);
            assert_eq!(after[index][&count], before[index][&count]);
        }
        engine
            .unlink_entry(&cx, &dataset, 2, b"keep.bin", false, TIME)
            .into_result()
            .unwrap();
        let reclaimed = native_accounting_snapshot(&cx, &engine, &devices[0]).1;
        for index in 0..3 {
            let owner = if index == 2 { b"0".as_slice() } else { b"3e8" };
            let count = [b"obj-".as_slice(), owner].concat();
            assert_eq!(reclaimed[index][owner], after[index][owner] - 512);
            assert_eq!(reclaimed[index][&count], after[index][&count] - 1);
        }
    }
}

// Native key and non-inheritance oracle: OpenZFS zfs-2.3.0
// module/zcommon/zfs_prop.c and module/zfs/dsl_dir.c. These fixtures encode
// the imported counts and property names directly, independently of the writer.
fn native_dsl_limit_spec() -> PoolFixtureSpec {
    PoolFixtureSpec {
        additional_write_features: vec![(b"com.joyent:filesystem_limits", 1)],
        dsl_counts: BTreeMap::from([(2, [1, 0]), (17, [0, 0])]),
        ..PoolFixtureSpec::default()
    }
}

fn native_dsl_counts(cx: &Cx, engine: &ZfsTransactionEngine, dataset: &[Vec<u8>]) -> [u64; 2] {
    let mut mos = engine.open_read_objects(cx).unwrap();
    // The public dataset list intentionally hides inconsistent receive heads.
    // Walk the native directory catalog so durable staging counts are checked too.
    let mut directory = mos
        .zap_values(cx, 1)
        .unwrap()
        .iter()
        .find(|row| row.name == b"root_dataset")
        .unwrap()
        .scalar()
        .unwrap();
    for component in dataset {
        let node = mos.object(cx, directory).unwrap();
        let children = node.order().u64(node.bonus(), 32).unwrap();
        directory = mos
            .zap_values(cx, children)
            .unwrap()
            .iter()
            .find(|row| row.name == *component)
            .unwrap()
            .scalar()
            .unwrap();
    }
    let rows = mos.zap_values(cx, directory).unwrap();
    [
        b"com.joyent:filesystem_count".as_slice(),
        b"com.joyent:snapshot_count".as_slice(),
    ]
    .map(|key| {
        rows.iter()
            .find(|row| row.name == key)
            .unwrap()
            .scalar()
            .unwrap()
    })
}

#[test]
fn dsl_native_count_limits_enforce_canonical_local_and_received_properties() {
    let cx = Cx::for_testing();
    let data = [b"data".to_vec()];
    let child = [b"data".to_vec(), b"child".to_vec()];
    for properties in [
        vec![
            (b"filesystem_limit".as_slice(), 2),
            (b"snapshot_limit".as_slice(), 1),
        ],
        vec![
            (b"filesystem_limit$recvd".as_slice(), 2),
            (b"snapshot_limit$recvd".as_slice(), 1),
        ],
        vec![
            (b"filesystem_limit".as_slice(), 2),
            (b"snapshot_limit".as_slice(), 1),
            (b"filesystem_limit$recvd".as_slice(), 0),
            (b"snapshot_limit$recvd".as_slice(), 0),
        ],
    ] {
        let (mut engine, devices) = file_range_fixture(
            &cx,
            &PoolFixtureSpec {
                root_properties: properties,
                ..native_dsl_limit_spec()
            },
        );
        engine
            .create_dataset(&cx, &data, b"child", &[], TIME)
            .into_result()
            .unwrap();
        assert_eq!(native_dsl_counts(&cx, &engine, &[]), [2, 0]);
        assert_eq!(native_dsl_counts(&cx, &engine, &data), [1, 0]);
        assert_eq!(native_dsl_counts(&cx, &engine, &child), [0, 0]);
        engine
            .create_snapshot(&cx, &child, b"one", TIME)
            .into_result()
            .unwrap();
        assert_eq!(native_dsl_counts(&cx, &engine, &[]), [2, 1]);
        assert_eq!(native_dsl_counts(&cx, &engine, &data), [1, 1]);
        assert_eq!(native_dsl_counts(&cx, &engine, &child), [0, 1]);
        assert_native_write_refused(&mut engine, &devices, libc::EDQUOT, |writer| {
            writer.create_dataset(&cx, &data, b"blocked", &[], TIME)
        });
        assert_native_write_refused(&mut engine, &devices, libc::EDQUOT, |writer| {
            writer.create_snapshot(&cx, &child, b"blocked", TIME)
        });

        engine
            .destroy_snapshot(&cx, &child, b"one", false)
            .into_result()
            .unwrap();
        engine.destroy_dataset(&cx, &child).into_result().unwrap();
        assert_eq!(native_dsl_counts(&cx, &engine, &[]), [1, 0]);
        assert_eq!(native_dsl_counts(&cx, &engine, &data), [0, 0]);
        let (_, token) = engine
            .create_dataset(&cx, &data, b"replacement", &[], TIME)
            .into_result()
            .unwrap();
        drop(engine);
        let durable: Vec<_> = devices
            .iter()
            .map(FaultableMemberDevice::fresh_from_durable)
            .collect();
        let reopened = open_engine_on_devices(
            &cx,
            &durable,
            default_write_opts(POOL_GUID, token.published_slot()),
        )
        .unwrap();
        assert_eq!(native_dsl_counts(&cx, &reopened, &[]), [2, 0]);
        assert_eq!(native_dsl_counts(&cx, &reopened, &data), [1, 0]);
        assert_pool_scrub_and_allocation_clean(
            &cx,
            &durable,
            POOL_GUID,
            Some(token.published_slot()),
        );
    }
}

#[test]
fn dsl_native_count_limits_distinguish_unknown_keys_from_corrupt_native_values() {
    let cx = Cx::for_testing();
    let data = [b"data".to_vec()];
    // The Joyent namespace belongs to the counters, not the native properties.
    let (mut engine, _) = file_range_fixture(
        &cx,
        &PoolFixtureSpec {
            dsl_property_entries: BTreeMap::from([(
                16,
                [
                    b"com.joyent:filesystem_limit".as_slice(),
                    b"com.joyent:snapshot_limit".as_slice(),
                ]
                .map(|name| RawZapEntry {
                    name: name.to_vec(),
                    integer_bytes: 1,
                    values: vec![u64::from(b'0'), 0],
                    collision: 0,
                })
                .to_vec(),
            )]),
            ..native_dsl_limit_spec()
        },
    );
    engine
        .create_dataset(&cx, &data, b"allowed", &[], TIME)
        .into_result()
        .unwrap();
    engine
        .create_snapshot(&cx, &data, b"allowed", TIME)
        .into_result()
        .unwrap();
    assert_eq!(native_dsl_counts(&cx, &engine, &[]), [2, 1]);

    for (property, is_filesystem) in [
        (b"filesystem_limit".as_slice(), true),
        (b"snapshot_limit".as_slice(), false),
        (b"filesystem_limit$recvd".as_slice(), true),
        (b"snapshot_limit$recvd".as_slice(), false),
    ] {
        let (mut engine, devices) = file_range_fixture(
            &cx,
            &PoolFixtureSpec {
                dsl_property_entries: BTreeMap::from([(
                    16,
                    vec![RawZapEntry {
                        name: property.to_vec(),
                        integer_bytes: 8,
                        values: vec![0, 1],
                        collision: 0,
                    }],
                )]),
                ..native_dsl_limit_spec()
            },
        );
        assert_native_write_refused(&mut engine, &devices, libc::EIO, |writer| {
            if is_filesystem {
                writer.create_dataset(&cx, &data, b"blocked", &[], TIME)
            } else {
                writer.create_snapshot(&cx, &data, b"blocked", TIME)
            }
        });
        assert_native_write_refused(&mut engine, &devices, libc::EIO, |writer| {
            writer.set_property(
                &cx,
                &[],
                if is_filesystem {
                    "filesystem_limit"
                } else {
                    "snapshot_limit"
                },
                ffs_zfs::ZfsPropertySetValue::Number(1),
            )
        });
    }
}

#[test]
fn dsl_native_count_limits_propagate_property_catalog_read_errors() {
    let cx = Cx::for_testing();
    let data = [b"data".to_vec()];
    let (mut engine, devices) = file_range_fixture(
        &cx,
        &PoolFixtureSpec {
            root_properties: vec![(b"snapshot_limit", 0)],
            ..native_dsl_limit_spec()
        },
    );
    let property_offset = {
        let mut mos = engine.open_read_objects(&cx).unwrap();
        let property_node = mos.object(&cx, 16).unwrap();
        usize::try_from(DATA_OFFSET + property_node.pointers()[0].regular_dvas().unwrap()[0].offset)
            .unwrap()
    };
    // Corrupt the ancestor's catalog after admission. Snapshot creation reads
    // the owning dataset's properties separately; the ancestor read used to be
    // swallowed and treated as an absent limit.
    devices[0].state.lock().unwrap().durable[property_offset + 64] ^= 1;
    assert_native_write_refused(&mut engine, &devices, libc::EIO, |writer| {
        writer.create_snapshot(&cx, &data, b"blocked", TIME)
    });
}

#[test]
fn dsl_native_count_limits_reject_overflow_underflow_and_missing_tracking() {
    let cx = Cx::for_testing();
    let data = [b"data".to_vec()];
    let (mut engine, devices) = file_range_fixture(
        &cx,
        &PoolFixtureSpec {
            dsl_counts: BTreeMap::from([(2, [1, u64::MAX]), (17, [0, u64::MAX])]),
            ..native_dsl_limit_spec()
        },
    );
    assert_native_write_refused(&mut engine, &devices, libc::EIO, |writer| {
        writer.create_snapshot(&cx, &data, b"overflow", TIME)
    });

    let (mut engine, devices) = file_range_fixture(
        &cx,
        &PoolFixtureSpec {
            deadlist_mode: DeadlistMode::NativeDeadlist,
            dsl_counts: BTreeMap::from([(2, [1, 1]), (17, [0, 0])]),
            ..native_dsl_limit_spec()
        },
    );
    assert_native_write_refused(&mut engine, &devices, libc::EIO, |writer| {
        writer.destroy_snapshot(&cx, &data, b"before", false)
    });

    for tracked in [BTreeMap::from([(2, [1, 0])]), BTreeMap::new()] {
        let (mut engine, devices) = file_range_fixture(
            &cx,
            &PoolFixtureSpec {
                dsl_counts: tracked,
                data_properties: vec![(b"snapshot_limit", 0)],
                ..native_dsl_limit_spec()
            },
        );
        assert_native_write_refused(&mut engine, &devices, libc::EIO, |writer| {
            writer.create_snapshot(&cx, &data, b"missing", TIME)
        });
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn dsl_native_count_limits_preserve_shared_ancestors_above_limits_during_subtree_moves() {
    use ffs_zfs::ZfsPropertySetValue::Number;

    let cx = Cx::for_testing();
    let data = [b"data".to_vec()];
    let left = [b"data".to_vec(), b"left".to_vec()];
    let right = [b"data".to_vec(), b"right".to_vec()];
    let tree = [b"data".to_vec(), b"left".to_vec(), b"tree".to_vec()];
    let nested = [
        b"data".to_vec(),
        b"left".to_vec(),
        b"tree".to_vec(),
        b"nested".to_vec(),
    ];
    let moved = [b"data".to_vec(), b"right".to_vec(), b"moved".to_vec()];
    let moved_nested = [
        b"data".to_vec(),
        b"right".to_vec(),
        b"moved".to_vec(),
        b"nested".to_vec(),
    ];
    let (mut engine, devices) = file_range_fixture(&cx, &native_dsl_limit_spec());
    for (parent, name) in [
        (data.as_slice(), b"left".as_slice()),
        (data.as_slice(), b"right".as_slice()),
        (left.as_slice(), b"tree".as_slice()),
        (tree.as_slice(), b"nested".as_slice()),
    ] {
        engine
            .create_dataset(&cx, parent, name, &[], TIME)
            .into_result()
            .unwrap();
    }
    engine
        .create_snapshot(&cx, &tree, b"one", TIME)
        .into_result()
        .unwrap();
    engine
        .create_snapshot(&cx, &nested, b"two", TIME)
        .into_result()
        .unwrap();
    assert_eq!(native_dsl_counts(&cx, &engine, &[]), [5, 2]);
    assert_eq!(native_dsl_counts(&cx, &engine, &data), [4, 2]);
    // OpenZFS allows lowering a count limit below existing usage. Moving a
    // subtree between these siblings consumes no new capacity at their shared
    // ancestors, so their now-zero ceilings must not refuse the move.
    for ancestor in [data.as_slice(), &[]] {
        for property in ["filesystem_limit", "snapshot_limit"] {
            engine
                .set_property(&cx, ancestor, property, Number(0))
                .into_result()
                .unwrap();
        }
    }
    engine
        .set_property(&cx, &right, "filesystem_limit", Number(1))
        .into_result()
        .unwrap();
    assert_native_write_refused(&mut engine, &devices, libc::EDQUOT, |writer| {
        writer.rename_dataset(&cx, &tree, &moved)
    });
    engine
        .set_property(&cx, &right, "filesystem_limit", Number(2))
        .into_result()
        .unwrap();
    engine
        .set_property(&cx, &right, "snapshot_limit", Number(1))
        .into_result()
        .unwrap();
    assert_native_write_refused(&mut engine, &devices, libc::EDQUOT, |writer| {
        writer.rename_dataset(&cx, &tree, &moved)
    });
    engine
        .set_property(&cx, &right, "snapshot_limit", Number(2))
        .into_result()
        .unwrap();
    let (_, token) = engine
        .rename_dataset(&cx, &tree, &moved)
        .into_result()
        .unwrap();
    let durable: Vec<_> = devices
        .iter()
        .map(FaultableMemberDevice::fresh_from_durable)
        .collect();
    drop(engine);
    let reopened = open_engine_on_devices(
        &cx,
        &durable,
        default_write_opts(POOL_GUID, token.published_slot()),
    )
    .unwrap();
    for (dataset, expected) in [
        (&[][..], [5, 2]),
        (data.as_slice(), [4, 2]),
        (left.as_slice(), [0, 0]),
        (right.as_slice(), [2, 2]),
        (moved.as_slice(), [1, 2]),
        (moved_nested.as_slice(), [0, 1]),
    ] {
        assert_eq!(
            native_dsl_counts(&cx, &reopened, dataset),
            expected,
            "{dataset:?}"
        );
    }
    let rows = reopened
        .open_read_objects(&cx)
        .unwrap()
        .datasets(&cx)
        .unwrap();
    assert!(!rows.iter().any(|row| row.components == tree));
    assert!(rows.iter().any(|row| row.components == moved_nested));
    assert_pool_scrub_and_allocation_clean(&cx, &durable, POOL_GUID, Some(token.published_slot()));
}

#[test]
fn dsl_native_count_limits_merge_clone_and_deferred_snapshot_destruction() {
    let cx = Cx::for_testing();
    let data = [b"data".to_vec()];
    let source = [b"data".to_vec(), b"source".to_vec()];
    let clone = [b"data".to_vec(), b"clone".to_vec()];
    let (mut engine, devices) = file_range_fixture(&cx, &native_dsl_limit_spec());
    engine
        .create_dataset(&cx, &data, b"source", &[], TIME)
        .into_result()
        .unwrap();
    engine
        .create_snapshot(&cx, &source, b"base", TIME)
        .into_result()
        .unwrap();
    engine
        .create_clone(&cx, &source, b"base", &data, b"clone", &[], TIME)
        .into_result()
        .unwrap();
    engine
        .destroy_snapshot(&cx, &source, b"base", true)
        .into_result()
        .unwrap();
    assert_eq!(native_dsl_counts(&cx, &engine, &[]), [3, 1]);
    assert_eq!(native_dsl_counts(&cx, &engine, &data), [2, 1]);
    let (_, token) = engine.destroy_dataset(&cx, &clone).into_result().unwrap();
    drop(engine);
    let durable: Vec<_> = devices
        .iter()
        .map(FaultableMemberDevice::fresh_from_durable)
        .collect();
    let reopened = open_engine_on_devices(
        &cx,
        &durable,
        default_write_opts(POOL_GUID, token.published_slot()),
    )
    .unwrap();
    assert_eq!(native_dsl_counts(&cx, &reopened, &[]), [2, 0]);
    assert_eq!(native_dsl_counts(&cx, &reopened, &data), [1, 0]);
    assert_eq!(native_dsl_counts(&cx, &reopened, &source), [0, 0]);
    assert!(
        reopened
            .open_read_objects(&cx)
            .unwrap()
            .zpl_snapshot(&cx, &source, b"base")
            .is_err()
    );
    assert_pool_scrub_and_allocation_clean(&cx, &durable, POOL_GUID, Some(token.published_slot()));
}

#[test]
#[allow(clippy::too_many_lines)]
fn dsl_native_count_limits_restore_received_values_and_unlimited_defaults() {
    use ffs_zfs::ZfsPropertySetValue::Number;

    let cx = Cx::for_testing();
    let data = [b"data".to_vec()];
    for received in [false, true] {
        let mut properties = vec![
            (b"filesystem_limit".as_slice(), 1),
            (b"snapshot_limit".as_slice(), 0),
        ];
        if received {
            properties.extend([
                (b"filesystem_limit$recvd".as_slice(), 0),
                (b"snapshot_limit$recvd".as_slice(), 0),
            ]);
        }
        let (mut engine, devices) = file_range_fixture(
            &cx,
            &PoolFixtureSpec {
                root_properties: properties,
                ..native_dsl_limit_spec()
            },
        );
        for property in ["filesystem_limit", "snapshot_limit"] {
            engine
                .inherit_property(&cx, &[], property)
                .into_result()
                .unwrap();
        }
        if received {
            assert_native_write_refused(&mut engine, &devices, libc::EDQUOT, |writer| {
                writer.create_dataset(&cx, &data, b"blocked", &[], TIME)
            });
            assert_native_write_refused(&mut engine, &devices, libc::EDQUOT, |writer| {
                writer.create_snapshot(&cx, &data, b"blocked", TIME)
            });
        }
        let rows = engine
            .open_read_objects(&cx)
            .unwrap()
            .zap_values(&cx, 16)
            .unwrap();
        for property in [b"filesystem_limit".as_slice(), b"snapshot_limit".as_slice()] {
            assert!(!rows.iter().any(|row| row.name == property));
        }
        assert!(!rows.iter().any(|row| row.name.ends_with(b"$inherit")));
        if received {
            for property in ["filesystem_limit", "snapshot_limit"] {
                engine
                    .set_property(&cx, &[], property, Number(u64::MAX))
                    .into_result()
                    .unwrap();
            }
        }
        engine
            .create_dataset(&cx, &data, b"allowed", &[], TIME)
            .into_result()
            .unwrap();
        engine
            .create_snapshot(&cx, &data, b"allowed", TIME)
            .into_result()
            .unwrap();
        assert_eq!(native_dsl_counts(&cx, &engine, &[]), [2, 1]);
    }

    for spec in [
        PoolFixtureSpec::default(),
        PoolFixtureSpec {
            additional_write_features: vec![(b"com.joyent:filesystem_limits", 0)],
            ..PoolFixtureSpec::default()
        },
    ] {
        let (mut engine, devices) = file_range_fixture(&cx, &spec);
        let (head, _) = engine
            .create_dataset(&cx, &data, b"untracked", &[], TIME)
            .into_result()
            .unwrap();
        let mut mos = engine.open_read_objects(&cx).unwrap();
        let head_node = mos.object(&cx, head).unwrap();
        let directory = head_node.order().u64(head_node.bonus(), 0).unwrap();
        assert_eq!(mos.object(&cx, directory).unwrap().object_type(), 12);
        for property in ["filesystem_limit", "snapshot_limit"] {
            assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, |writer| {
                writer.set_property(&cx, &data, property, Number(0))
            });
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn dsl_native_count_limits_receive_snapshots_and_private_staging_follow_native_accounting() {
    use ffs_zfs::{ZfsPropertySetValue::Number, ZfsRecvOutcome, ZfsRecvRequest, ZfsSendFrom};
    use std::io::Cursor;

    let cx = Cx::for_testing();
    let data = vec![b"data".to_vec()];
    let target = vec![b"data".to_vec(), b"received".to_vec()];
    let (mut sender, _) = file_range_fixture(
        &cx,
        &PoolFixtureSpec {
            ashift: 12,
            image_bytes: 32 * 1024 * 1024,
            deadlist_mode: DeadlistMode::NativeDeadlist,
            ..PoolFixtureSpec::default()
        },
    );
    sender
        .create_snapshot(&cx, &data, b"first", TIME)
        .into_result()
        .unwrap();
    let mut full = Vec::new();
    ffs_zfs::send_stream(
        &cx,
        &mut sender.open_read_objects(&cx).unwrap(),
        &ffs_zfs::ZfsSendRequest::full(data.clone(), b"first".to_vec()),
        &mut full,
    )
    .unwrap();
    sender
        .write_file_data(
            &cx,
            &data,
            4,
            0,
            b"updated",
            TIME,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    sender
        .create_snapshot(&cx, &data, b"second", TIME)
        .into_result()
        .unwrap();
    let mut send = ffs_zfs::ZfsSendRequest::full(data.clone(), b"second".to_vec());
    send.from = Some(ZfsSendFrom::Snapshot(b"first".to_vec()));
    let mut incremental = Vec::new();
    ffs_zfs::send_stream(
        &cx,
        &mut sender.open_read_objects(&cx).unwrap(),
        &send,
        &mut incremental,
    )
    .unwrap();

    for incremental_case in [false, true] {
        let (mut receiver, devices) = file_range_fixture(
            &cx,
            &PoolFixtureSpec {
                ashift: 12,
                image_bytes: 32 * 1024 * 1024,
                root_properties: vec![
                    (b"filesystem_limit", 2),
                    (b"snapshot_limit", u64::from(incremental_case)),
                ],
                ..native_dsl_limit_spec()
            },
        );
        let mut receive = ZfsRecvRequest::new(target.clone());
        receive.resumable = true;
        if incremental_case {
            receiver
                .receive_stream(&cx, &receive, &mut Cursor::new(&full))
                .into_result()
                .unwrap();
            assert_eq!(native_dsl_counts(&cx, &receiver, &[]), [2, 1]);
            assert_eq!(native_dsl_counts(&cx, &receiver, &target), [0, 1]);
        }
        let stream = if incremental_case {
            &incremental
        } else {
            &full
        };
        let progress = match receiver.receive_stream(&cx, &receive, &mut Cursor::new(stream)) {
            ZfsRecvOutcome::Interrupted {
                reason,
                progress,
                cleanup_error,
            } => {
                assert_eq!(reason.to_errno(), libc::EDQUOT);
                assert!(cleanup_error.is_none());
                assert_eq!(progress.substreams_received, 0);
                progress
            }
            outcome => panic!("expected snapshot limit interruption, got {outcome:?}"),
        };
        drop(receiver);
        let durable: Vec<_> = devices
            .iter()
            .map(FaultableMemberDevice::fresh_from_durable)
            .collect();
        let mut reopened = open_engine_on_devices(
            &cx,
            &durable,
            default_write_opts(POOL_GUID, progress.durable_token.published_slot()),
        )
        .unwrap();
        let resume = reopened
            .inspect_receive_resume_state(&cx, &target)
            .unwrap()
            .unwrap();
        assert_eq!(resume.is_pct_recv_child, incremental_case);
        let snapshots = u64::from(incremental_case);
        // OpenZFS dmu_recv_begin_sync creates %recv through dsl_dir_create_sync:
        // its persisted count includes the private child, while
        // recv_begin_check_existing_impl exempts it from filesystem LIMIT
        // admission. The temporary count therefore exceeds the limit of two.
        assert_eq!(
            native_dsl_counts(&cx, &reopened, &[]),
            [if incremental_case { 3 } else { 2 }, snapshots]
        );
        assert_eq!(
            native_dsl_counts(&cx, &reopened, &data),
            [if incremental_case { 2 } else { 1 }, snapshots]
        );
        assert_eq!(
            native_dsl_counts(&cx, &reopened, &target),
            [u64::from(incremental_case), snapshots]
        );
        let unpublished = if incremental_case {
            b"second".as_slice()
        } else {
            b"first".as_slice()
        };
        assert!(
            reopened
                .open_read_objects(&cx)
                .unwrap()
                .zpl_snapshot(&cx, &target, unpublished)
                .is_err()
        );
        let (_, cleanup) = reopened.abort_receive(&cx, &target).into_result().unwrap();
        assert!(
            reopened
                .inspect_receive_resume_state(&cx, &target)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            native_dsl_counts(&cx, &reopened, &[]),
            [if incremental_case { 2 } else { 1 }, snapshots]
        );
        assert_eq!(
            native_dsl_counts(&cx, &reopened, &data),
            [u64::from(incremental_case), snapshots]
        );
        assert_pool_scrub_and_allocation_clean(
            &cx,
            &durable,
            POOL_GUID,
            Some(cleanup.published_slot()),
        );
        if incremental_case {
            assert_eq!(native_dsl_counts(&cx, &reopened, &target), [0, 1]);
            reopened
                .set_property(&cx, &[], "snapshot_limit", Number(2))
                .into_result()
                .unwrap();
            let (_, token) = reopened
                .receive_stream(&cx, &receive, &mut Cursor::new(&incremental))
                .into_result()
                .unwrap();
            assert_eq!(native_dsl_counts(&cx, &reopened, &[]), [2, 2]);
            assert_eq!(native_dsl_counts(&cx, &reopened, &data), [1, 2]);
            assert_eq!(native_dsl_counts(&cx, &reopened, &target), [0, 2]);
            let mut mos = reopened.open_read_objects(&cx).unwrap();
            let mut snapshot = mos.zpl_snapshot(&cx, &target, b"second").unwrap();
            assert_eq!(snapshot.read(&cx, 4, 0, 7).unwrap(), b"updated");
            assert_pool_scrub_and_allocation_clean(
                &cx,
                &durable,
                POOL_GUID,
                Some(token.published_slot()),
            );
        }
    }
}

#[test]
fn owner_quota_chown_checks_the_destination_and_preserves_unchanged_dimensions() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    for (key, dimension, is_objects) in [
        (b"userquota@".as_slice(), 0, false),
        (b"groupquota@", 1, false),
        (b"userobjquota@", 0, true),
        (b"groupobjquota@", 1, true),
    ] {
        for admitted in [false, true] {
            let destination = if dimension == 0 {
                b"7d0".as_slice()
            } else {
                b"bb8"
            };
            let limit = if !admitted {
                0
            } else if is_objects {
                1
            } else {
                4096 + 512
            };
            let (mut engine, devices) = file_range_fixture(
                &cx,
                &PoolFixtureSpec {
                    owner_quota_objects: vec![(key, 11)],
                    owner_quota_entries: BTreeMap::from([(11, vec![(destination, limit)])]),
                    ..accounted_spec()
                },
            );
            let before = native_accounting_snapshot(&cx, &engine, &devices[0]).1;
            let attrs = ffs_zfs::ZfsPosixSetAttr {
                uid: (dimension == 0).then_some(2000),
                gid: (dimension == 1).then_some(3000),
                ..ffs_zfs::ZfsPosixSetAttr::default()
            };
            if !admitted {
                assert_native_write_refused(&mut engine, &devices, libc::EDQUOT, |writer| {
                    writer.set_posix_attributes(
                        &cx,
                        &dataset,
                        5,
                        &attrs,
                        TIME,
                        ZfsDataChecksum::Fletcher4,
                    )
                });
                assert_eq!(
                    native_accounting_snapshot(&cx, &engine, &devices[0]).1,
                    before
                );
                continue;
            }
            engine
                .set_posix_attributes(&cx, &dataset, 5, &attrs, TIME, ZfsDataChecksum::Fletcher4)
                .into_result()
                .unwrap();
            let after = native_accounting_snapshot(&cx, &engine, &devices[0]).1;
            assert_eq!(after[dimension][destination], 4096 + 512);
            assert_eq!(
                after[dimension][b"3e8".as_slice()],
                before[dimension][b"3e8".as_slice()] - 4096 - 512
            );
            let count = [b"obj-".as_slice(), destination].concat();
            assert_eq!(after[dimension][&count], 1);
            for index in 0..3 {
                if index != dimension {
                    assert_eq!(after[index], before[index]);
                }
            }
        }
    }
}

#[test]
fn owner_quota_empty_tables_allow_writes_but_malformed_keys_and_incomplete_usage_refuse() {
    let cx = Cx::for_testing();
    for key in OWNER_QUOTA_KEYS {
        let (mut engine, _) = file_range_fixture(
            &cx,
            &PoolFixtureSpec {
                owner_quota_objects: vec![(key, 11)],
                owner_quota_entries: BTreeMap::from([(11, Vec::new())]),
                ..accounted_spec()
            },
        );
        create_empty(&cx, &mut engine, b"unlimited")
            .into_result()
            .unwrap();
    }
    for key in [b"03e8".as_slice(), b"3E8", b"obj-3e8", b"fffffffffffffffff"] {
        let (mut engine, devices) = file_range_fixture(
            &cx,
            &PoolFixtureSpec {
                owner_quota_objects: vec![(b"userquota@", 11)],
                owner_quota_entries: BTreeMap::from([(11, vec![(key, u64::MAX)])]),
                ..accounted_spec()
            },
        );
        assert_native_write_refused(&mut engine, &devices, libc::EIO, |writer| {
            create_empty(&cx, writer, b"malformed")
        });
    }
    let (mut engine, devices) = file_range_fixture(
        &cx,
        &PoolFixtureSpec {
            owner_quota_objects: vec![(b"userquota@", 11)],
            owner_quota_entries: BTreeMap::from([(11, Vec::new())]),
            deadlist_mode: DeadlistMode::NativeDeadlist,
            ..PoolFixtureSpec::default()
        },
    );
    assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, |writer| {
        create_empty(&cx, writer, b"unaccounted")
    });
}

#[test]
fn owner_quota_missing_and_understated_existing_usage_refuses_before_backing_writes() {
    let cx = Cx::for_testing();
    for (dimension, quota) in OWNER_QUOTA_KEYS[..3].iter().copied().enumerate() {
        let keys = if dimension == 2 {
            [b"0".as_slice(), b"obj-0"]
        } else {
            [b"3e8".as_slice(), b"obj-3e8"]
        };
        for key in keys {
            for value in [None, Some(0), Some(1)] {
                let (mut engine, devices) = file_range_fixture(
                    &cx,
                    &PoolFixtureSpec {
                        owner_quota_objects: vec![(quota, 11)],
                        owner_quota_entries: BTreeMap::from([(11, vec![(keys[0], u64::MAX)])]),
                        owner_usage_overrides: vec![(dimension, key, value)],
                        ..accounted_spec()
                    },
                );
                assert_native_write_refused(&mut engine, &devices, libc::EIO, |writer| {
                    create_empty(&cx, writer, b"understated")
                });
            }
        }
    }
}

#[test]
fn owner_quota_mixed_objectset_order_preserves_reads_and_refuses_mutations() {
    let cx = Cx::for_testing();
    let (mut engine, devices) = file_range_fixture(
        &cx,
        &PoolFixtureSpec {
            zpl_order: Some(Endian::Big),
            owner_quota_objects: vec![(b"userquota@", 11)],
            owner_quota_entries: BTreeMap::from([(11, vec![(b"3e8".as_slice(), u64::MAX)])]),
            ..accounted_spec()
        },
    );
    let mut head = file_range_head(&cx, &engine);
    assert_eq!(head.read(&cx, 4, 0, 8192).unwrap(), b"SNAPDATA".repeat(512));
    assert_eq!(head.resolve(&cx, b"/keep.bin").unwrap(), 5);
    assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, |writer| {
        create_empty(&cx, writer, b"mixed-order")
    });
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

#[derive(Debug, PartialEq, Eq)]
struct DatasetSpace {
    used: u64,
    referenced: u64,
    unique: u64,
    quota: u64,
    reservation: u64,
}

fn dataset_space(cx: &Cx, engine: &ZfsTransactionEngine, dataset: &[Vec<u8>]) -> DatasetSpace {
    let mut mos = engine.open_read_objects(cx).unwrap();
    let row = mos
        .datasets(cx)
        .unwrap()
        .into_iter()
        .find(|row| row.components == dataset)
        .unwrap();
    let head = mos.object(cx, row.head_object).unwrap();
    let directory = mos.object(cx, row.directory_object).unwrap();
    DatasetSpace {
        used: directory.order().u64(directory.bonus(), 40).unwrap(),
        referenced: head.order().u64(head.bonus(), 72).unwrap(),
        unique: head.order().u64(head.bonus(), 96).unwrap(),
        quota: directory.order().u64(directory.bonus(), 64).unwrap(),
        reservation: directory.order().u64(directory.bonus(), 72).unwrap(),
    }
}

fn received_space_fixture(
    cx: &Cx,
    property: &'static str,
    received: u64,
) -> (ZfsTransactionEngine, Vec<FaultableMemberDevice>) {
    let key = match property {
        "quota" => b"quota$recvd".as_slice(),
        "refquota" => b"refquota$recvd".as_slice(),
        "reservation" => b"reservation$recvd".as_slice(),
        "refreservation" => b"refreservation$recvd".as_slice(),
        _ => panic!("unexpected space property"),
    };
    file_range_fixture(
        cx,
        &PoolFixtureSpec {
            // A local unlimited/zero value masks the received value until the
            // administrative operation clears that override.
            data_properties: vec![(property.as_bytes(), 0), (key, received)],
            deadlist_mode: DeadlistMode::NativeDeadlist,
            ..PoolFixtureSpec::default()
        },
    )
}

#[test]
fn snapshot_preserves_other_heads_reserved_space_before_publication() {
    use ffs_zfs::ZfsPropertySetValue::Number;

    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let (mut engine, devices) = file_range_fixture(
        &cx,
        &PoolFixtureSpec {
            deadlist_mode: DeadlistMode::NativeDeadlist,
            data_properties: vec![(b"compression", 2)],
            ..PoolFixtureSpec::default()
        },
    );
    let checksum = ZfsDataChecksum::Fletcher4;
    let (file, _) = engine
        .create_file(&cx, &dataset, 2, b"promised", 0o644, 0, 0, TIME, checksum)
        .into_result()
        .unwrap();
    let payload = vec![0x37; 1024 * 1024];
    engine
        .write_file_data(&cx, &dataset, file, 0, &payload, TIME, checksum)
        .into_result()
        .unwrap();
    let child = dataset_space(&cx, &engine, &dataset);
    engine
        .set_property(&cx, &dataset, "refreservation", Number(child.unique))
        .into_result()
        .unwrap();
    assert!(child.unique > 512 * 1024);
    let root = dataset_space(&cx, &engine, &[]);
    let root_reserved = root.unique + engine.free_bytes() - 256 * 1024;
    engine
        .set_property(&cx, &[], "refreservation", Number(root_reserved))
        .into_result()
        .unwrap();
    let before = dataset_space(&cx, &engine, &dataset);
    assert!(
        engine.free_bytes() > before.unique,
        "raw free space alone would allow the snapshot"
    );
    assert_native_write_refused(&mut engine, &devices, libc::ENOSPC, |writer| {
        writer.create_snapshot(&cx, &dataset, b"shared", TIME)
    });
    assert_eq!(dataset_space(&cx, &engine, &dataset), before);
    engine
        .inherit_property(&cx, &[], "refreservation")
        .into_result()
        .unwrap();
    let (_, token) = engine
        .create_snapshot(&cx, &dataset, b"shared", TIME)
        .into_result()
        .unwrap();
    drop(engine);
    let durable: Vec<_> = devices
        .iter()
        .map(FaultableMemberDevice::fresh_from_durable)
        .collect();
    let reopened = open_engine_on_devices(
        &cx,
        &durable,
        default_write_opts(POOL_GUID, token.published_slot()),
    )
    .unwrap();
    let after = dataset_space(&cx, &reopened, &dataset);
    assert_eq!(after.unique, 0);
    assert_eq!(after.used, before.used + before.unique);
    let mut mos = reopened.open_read_objects(&cx).unwrap();
    let mut snapshot = mos.zpl_snapshot(&cx, &dataset, b"shared").unwrap();
    assert_eq!(snapshot.read(&cx, file, 0, 4096).unwrap(), payload[..4096]);
}

#[test]
fn reserved_file_growth_and_truncation_preserve_saturated_ancestor_charges() {
    use ffs_core::{FsOps, RequestScope};
    use ffs_types::InodeNumber;
    use ffs_zfs::{ZfsFs, ZfsPropertySetValue::Number};

    let cx = Cx::for_testing();
    let parent = [b"data".to_vec()];
    let dataset = [b"data".to_vec(), b"child".to_vec()];
    for property in ["reservation", "refreservation"] {
        let (mut engine, devices) = file_range_fixture(
            &cx,
            &PoolFixtureSpec {
                deadlist_mode: DeadlistMode::NativeDeadlist,
                ..PoolFixtureSpec::default()
            },
        );
        engine
            .create_dataset(
                &cx,
                &parent,
                b"child",
                &[("compression".into(), Number(2))],
                TIME,
            )
            .into_result()
            .unwrap();
        let checksum = ZfsDataChecksum::Fletcher4;
        let (file, _) = engine
            .create_file(&cx, &dataset, 3, b"bytes", 0o644, 0, 0, TIME, checksum)
            .into_result()
            .unwrap();
        let target = dataset_space(&cx, &engine, &dataset);
        let reserve = target.used.max(target.unique) + 256 * 1024;
        engine
            .set_property(&cx, &dataset, property, Number(reserve))
            .into_result()
            .unwrap();
        // All remaining space allowed by the parent quota belongs to this child.
        let parent_used = dataset_space(&cx, &engine, &parent).used;
        engine
            .set_property(&cx, &parent, "quota", Number(parent_used))
            .into_result()
            .unwrap();
        let before = dataset_space(&cx, &engine, &dataset);
        let payload = vec![0x35; 64 * 1024];
        engine
            .write_file_data(&cx, &dataset, file, 0, &payload, TIME, checksum)
            .into_result()
            .unwrap();
        let after = dataset_space(&cx, &engine, &dataset);
        assert!(after.unique > before.unique);
        assert_eq!(dataset_space(&cx, &engine, &parent).used, parent_used);
        if property == "reservation" {
            assert_eq!(after.used - before.used, after.unique - before.unique);
        } else {
            assert_eq!(after.used, before.used);
        }
        assert_native_write_refused(&mut engine, &devices, libc::EDQUOT, |writer| {
            writer.write_file_data(
                &cx,
                &dataset,
                file,
                0,
                &vec![0x97; 512 * 1024],
                TIME,
                checksum,
            )
        });
        let (_, token) = engine
            .truncate_file(&cx, &dataset, file, 0, TIME, checksum)
            .into_result()
            .unwrap();
        drop(engine);
        let durable: Vec<_> = devices
            .iter()
            .map(FaultableMemberDevice::fresh_from_durable)
            .collect();
        let reopened = open_engine_on_devices(
            &cx,
            &durable,
            default_write_opts(POOL_GUID, token.published_slot()),
        )
        .unwrap();
        let shrunk = dataset_space(&cx, &reopened, &dataset);
        assert!(shrunk.unique < after.unique);
        assert_eq!(dataset_space(&cx, &reopened, &parent).used, parent_used);
        let available = if property == "reservation" {
            assert_eq!(after.used - shrunk.used, after.unique - shrunk.unique);
            reserve - shrunk.used
        } else {
            assert_eq!(shrunk.used, before.used);
            reserve - shrunk.unique
        };
        let fs = ZfsFs::with_writer(&cx, reopened, dataset.to_vec()).unwrap();
        let stat = fs
            .statfs(&cx, &mut RequestScope::empty(), InodeNumber(1))
            .unwrap();
        assert_eq!(
            stat.blocks_available,
            available / u64::from(stat.fragment_size)
        );
        assert_pool_scrub_and_allocation_clean(&cx, &durable, POOL_GUID, None);
    }
}

#[test]
fn received_space_properties_reject_invalid_effective_limits_without_writes() {
    use ffs_zfs::ZfsPropertySetValue::Number;

    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let mib = 1024 * 1024;
    // The effective value, including a received fallback, must satisfy the
    // same native constraints as an explicit property update.
    for (property, received, setup, errno) in [
        ("quota", 1, None, libc::EDQUOT),
        ("refquota", 1, None, libc::EDQUOT),
        ("quota", mib, Some(("reservation", 2 * mib)), libc::EDQUOT),
        (
            "refquota",
            mib,
            Some(("refreservation", 2 * mib)),
            libc::EDQUOT,
        ),
        ("reservation", 2 * mib, Some(("quota", mib)), libc::EDQUOT),
        (
            "refreservation",
            2 * mib,
            Some(("refquota", mib)),
            libc::EDQUOT,
        ),
        ("reservation", 64 * mib, None, libc::ENOSPC),
        ("refreservation", 64 * mib, None, libc::ENOSPC),
    ] {
        let (mut engine, devices) = received_space_fixture(&cx, property, received);
        if let Some((name, value)) = setup {
            engine
                .set_property(&cx, &dataset, name, Number(value))
                .into_result()
                .unwrap();
        }
        let before = dataset_space(&cx, &engine, &dataset);
        let parent_before = dataset_space(&cx, &engine, &[]);
        let free_before = engine.free_bytes();
        assert_native_write_refused(&mut engine, &devices, errno, |writer| {
            writer.inherit_property(&cx, &dataset, property)
        });
        assert_eq!(dataset_space(&cx, &engine, &dataset), before, "{property}");
        assert_eq!(
            dataset_space(&cx, &engine, &[]),
            parent_before,
            "{property}"
        );
        assert_eq!(engine.free_bytes(), free_before, "{property}");
        assert!(!engine.requires_recovery());
        let props = engine
            .open_read_objects(&cx)
            .unwrap()
            .properties(&cx, &dataset, None, &[property.to_owned()])
            .unwrap();
        assert_eq!(
            props.values[0].value,
            Some(ffs_zfs::reader::dmu::properties::PropertyValue::Number(0))
        );
        assert_eq!(
            props.values[0].source,
            ffs_zfs::reader::dmu::properties::PropertySource::Local
        );
    }
}

#[test]
fn received_space_reservations_respect_ancestor_quotas_before_publication() {
    use ffs_zfs::ZfsPropertySetValue::Number;

    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    for property in ["reservation", "refreservation"] {
        let (mut engine, devices) = received_space_fixture(&cx, property, 2 * 1024 * 1024);
        let parent = dataset_space(&cx, &engine, &[]);
        engine
            .set_property(&cx, &[], "quota", Number(parent.used + 128 * 1024))
            .into_result()
            .unwrap();
        let child_before = dataset_space(&cx, &engine, &dataset);
        let parent_before = dataset_space(&cx, &engine, &[]);
        assert_native_write_refused(&mut engine, &devices, libc::EDQUOT, |writer| {
            writer.inherit_property(&cx, &dataset, property)
        });
        assert_eq!(dataset_space(&cx, &engine, &dataset), child_before);
        assert_eq!(dataset_space(&cx, &engine, &[]), parent_before);
    }
}

#[test]
fn received_space_properties_restore_valid_limits_and_accounting_after_restart() {
    use ffs_zfs::ZfsPropertySetValue::Number;
    use ffs_zfs::reader::dmu::properties::{PropertySource, PropertyValue};

    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    for property in ["quota", "refquota", "reservation", "refreservation"] {
        for received in [0, 1024 * 1024] {
            let (mut engine, devices) = received_space_fixture(&cx, property, received);
            if received == 0 {
                engine
                    .set_property(&cx, &dataset, property, Number(1024 * 1024))
                    .into_result()
                    .unwrap();
            }
            let before = dataset_space(&cx, &engine, &dataset);
            let parent_before = dataset_space(&cx, &engine, &[]);
            let (_, token) = engine
                .inherit_property(&cx, &dataset, property)
                .into_result()
                .unwrap();
            drop(engine);
            let durable: Vec<_> = devices
                .iter()
                .map(FaultableMemberDevice::fresh_from_durable)
                .collect();
            let reopened = open_engine_on_devices(
                &cx,
                &durable,
                default_write_opts(POOL_GUID, token.published_slot()),
            )
            .unwrap();
            let mut mos = reopened.open_read_objects(&cx).unwrap();
            let properties = mos
                .properties(&cx, &dataset, None, &[property.to_owned()])
                .unwrap();
            assert_eq!(properties.values[0].source, PropertySource::Received);
            assert_eq!(
                properties.values[0].value,
                Some(PropertyValue::Number(received))
            );
            let after = dataset_space(&cx, &reopened, &dataset);
            let parent_after = dataset_space(&cx, &reopened, &[]);
            match property {
                "quota" => {
                    assert_eq!(after.quota, received);
                    assert_eq!(after.used, before.used);
                    assert_eq!(parent_after, parent_before);
                }
                "refquota" => {
                    assert_eq!(after, before);
                    assert_eq!(parent_after, parent_before);
                }
                "reservation" => {
                    assert_eq!(after.reservation, received);
                    assert_eq!(after.used, before.used);
                    assert_eq!(
                        parent_after.used + before.reservation.saturating_sub(before.used),
                        parent_before.used + received.saturating_sub(before.used)
                    );
                }
                "refreservation" => {
                    let old: u64 = if received == 0 { 1024 * 1024 } else { 0 };
                    let previous_charge = old.saturating_sub(before.unique);
                    let restored_charge = received.saturating_sub(before.unique);
                    assert_eq!(after.used + previous_charge, before.used + restored_charge);
                    assert_eq!(
                        parent_after.used + previous_charge,
                        parent_before.used + restored_charge
                    );
                }
                _ => unreachable!(),
            }
            assert_eq!(after.referenced, before.referenced);
            assert_eq!(after.unique, before.unique);
            assert_pool_scrub_and_allocation_clean(&cx, &durable, POOL_GUID, None);
        }
    }
}
