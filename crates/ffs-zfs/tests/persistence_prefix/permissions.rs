//! A native execute-access shortcut must agree with the regenerated mode ACL.
//! These constructed pools exercise serialization and cold reopen, not kernel
//! permission enforcement or an OpenZFS interoperability run.

use super::*;

const ACL_TRIVIAL: u64 = 0x4;
const NO_EXECS_DENIED: u64 = 0x100;
const TIME: Timestamp = Timestamp {
    seconds: 1_715_000_650,
    nanos: 43,
};

#[test]
#[allow(clippy::too_many_lines)]
fn chmod_execute_shortcut_tracks_all_permission_classes_across_cold_reopen() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    for (zpl_version, spilled, mirror_width, ashift) in
        [(4, false, 1, 9), (5, false, 1, 9), (5, true, 2, 12)]
    {
        let built = build_clean_zfs_pool(&PoolFixtureSpec {
            zpl_version,
            mirror_width,
            ashift,
            deadlist_mode: DeadlistMode::NativeDeadlist,
            hello_mode: 0o755,
            // Both initial modes are 0755, so their native shortcut is valid.
            // The other bits must survive every permission transition.
            zpl_flags: BTreeMap::from([(4, NO_EXECS_DENIED | 0x408), (6, NO_EXECS_DENIED | 0x408)]),
            with_sa_spill_timestamps: spilled,
            sa_project_id: spilled.then_some(42),
            directory_projects: if spilled {
                BTreeMap::from([(6, 42)])
            } else {
                BTreeMap::new()
            },
            project_accounting: spilled,
            additional_write_features: if spilled {
                vec![(b"org.zfsonlinux:project_quota", 1)]
            } else {
                Vec::new()
            },
            ..PoolFixtureSpec::default()
        });
        let mut devices: Vec<_> = built
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
        let (original, historical) = {
            let mut mos = engine.open_read_objects(&cx).unwrap();
            let mut head = mos.zpl(&cx, &dataset).unwrap();
            let current = [head.stat(&cx, 4).unwrap().0, head.stat(&cx, 6).unwrap().0];
            assert_eq!(current[0].kind, Kind::Regular);
            assert_eq!(current[1].kind, Kind::Directory);
            let mut snapshot = head.open_snapshot(&cx, b"before").unwrap();
            let historical = [
                snapshot.stat(&cx, 4).unwrap().0,
                snapshot.stat(&cx, 6).unwrap().0,
            ];
            (current, historical)
        };

        // The expected shortcut is independent of the implementation's mask:
        // owner-only, group-only, other-only and no execution must all revoke
        // it; all-class execution restores it. Each state survives a reopen.
        for (mode, shortcut) in [
            (0o700, false),
            (0o111, true),
            (0o070, false),
            (0o755, true),
            (0o007, false),
            (0o000, false),
        ] {
            for object in [4, 6] {
                engine
                    .set_posix_attributes(
                        &cx,
                        &dataset,
                        object,
                        &ffs_zfs::ZfsPosixSetAttr {
                            mode: Some(mode),
                            ..ffs_zfs::ZfsPosixSetAttr::default()
                        },
                        TIME,
                        ZfsDataChecksum::Fletcher4,
                    )
                    .into_result()
                    .unwrap();
            }
            let slot = engine.committed_slot();
            drop(engine);
            devices = devices
                .iter()
                .map(FaultableMemberDevice::fresh_from_durable)
                .collect();
            engine =
                open_engine_on_devices(&cx, &devices, default_write_opts(built.pool_guid, slot))
                    .unwrap();
            let mut mos = engine.open_read_objects(&cx).unwrap();
            let mut head = mos.zpl(&cx, &dataset).unwrap();
            for (object, before) in [4, 6].into_iter().zip(&original) {
                let current = head.stat(&cx, object).unwrap().0;
                assert_eq!(
                    current.flags & NO_EXECS_DENIED != 0,
                    shortcut,
                    "ZPL v{zpl_version}, spill={spilled}, object={object}, mode={mode:o}"
                );
                let mut expected = before.clone();
                expected.mode = (before.mode & !0o7777) | u64::from(mode);
                expected.flags = (before.flags | ACL_TRIVIAL) & !NO_EXECS_DENIED;
                if shortcut {
                    expected.flags |= NO_EXECS_DENIED;
                }
                expected.times[2] = TIME;
                assert_eq!(current, expected, "chmod changed unrelated metadata");
            }
            assert_eq!(head.resolve(&cx, b"/hello.txt").unwrap(), 4);
            assert_eq!(head.resolve(&cx, b"/sub").unwrap(), 6);
            assert_eq!(
                head.read(&cx, 4, 0, built.snap_hello_expected.len())
                    .unwrap(),
                built.snap_hello_expected
            );
            let mut snapshot = head.open_snapshot(&cx, b"before").unwrap();
            assert_eq!(snapshot.stat(&cx, 4).unwrap().0, historical[0]);
            assert_eq!(snapshot.stat(&cx, 6).unwrap().0, historical[1]);
            assert_eq!(
                snapshot
                    .read(&cx, 4, 0, built.snap_hello_expected.len())
                    .unwrap(),
                built.snap_hello_expected
            );
        }
        assert_pool_scrub_and_allocation_clean(
            &cx,
            &devices,
            built.pool_guid,
            Some(engine.committed_slot()),
        );
    }
}
