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
            assert_native_write_refused(&mut engine, &devices, libc::EDQUOT, |writer| {
                writer.write_file_data(
                    &cx,
                    &dataset,
                    4,
                    4096,
                    &[0xA7; 8192],
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
